//! Fetching the page, and the guard that has to hold at the moment of connect.
//!
//! # Why the textual check in `vet` is not enough
//!
//! `vet` reads the URL. A URL is a *name*, and a name resolves to an address at
//! connect time, whoever controls the name. `preview.example.com` can have an A
//! record pointing at `169.254.169.254`, and every string-level check in the
//! world passes it.
//!
//! So this resolves the host itself, drops every address that is inside the
//! deployment, and then **connects to the address it checked** rather than to
//! the name. Connecting by name again would re-resolve, and the second answer
//! does not have to match the first — that is DNS rebinding, and it is the
//! standard way past a checker that validates one lookup and connects with
//! another.
//!
//! # Everything here is bounded
//!
//! A preview is work a stranger asks the server to do against a host the
//! stranger chose. Untimed, unbounded and unlimited, that is an open proxy and
//! a memory exhaustion primitive in one. So: a whole-fetch timeout, a byte cap
//! on the response, a redirect cap with every hop re-checked, and a cap on how
//! many fetches run at once, since the socket count is the resource a client
//! can multiply for free.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;

use crate::{Refusal, is_private_addr, vet};

/// What a fetch may cost.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The whole fetch, resolution and redirects included.
    pub timeout: Duration,
    /// How much of the body is read. The rest is dropped, not refused.
    pub bytes: usize,
    /// How many `3xx` hops are followed.
    pub redirects: u8,
    /// How many fetches may be in flight across all clients.
    pub concurrency: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            // The metadata lives in `<head>`, so this is generous for the job:
            // pages that need more than a quarter of a megabyte to reach the
            // end of their head are not pages whose title is worth waiting for.
            bytes: 256 * 1024,
            redirects: 3,
            // Sockets are the resource a client multiplies for free, and a
            // preview is slow enough that a handful of them held open is a
            // meaningful amount of the server's outbound capacity.
            concurrency: 8,
        }
    }
}

/// Why a page did not come back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The URL itself is not one we fetch.
    Refused(Refusal),
    /// The name does not resolve.
    Unresolvable,
    /// It resolves, and every address is inside the deployment.
    ///
    /// Distinct from [`Refusal::PrivateAddress`] on purpose: this is the case
    /// the string check *cannot* see, so an operator reading a log needs to be
    /// able to tell the two apart.
    ResolvesInside,
    /// The host would not talk to us.
    Unreachable,
    /// It answered, with something that is not a page.
    NotHtml,
    /// It answered with an error status.
    Status(u16),
    /// It redirected further than we follow.
    TooManyRedirects,
    /// It took too long.
    TimedOut,
    /// Too many previews are already in flight.
    Busy,
}

impl FetchError {
    /// What the client is told.
    ///
    /// Deliberately vaguer than the variants: the difference between "this
    /// resolves to a private address" and "this does not resolve" is a fact
    /// about the server's network that a stranger asking for previews should
    /// not be able to map out one URL at a time. The operator's log has the
    /// distinction; the client gets the outcome.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Refused(refusal) => refusal.reason(),
            Self::Unresolvable | Self::ResolvesInside | Self::Unreachable => {
                "that link could not be reached"
            }
            Self::NotHtml => "that link is not a page",
            Self::Status(_) => "that link did not load",
            Self::TooManyRedirects => "that link redirects too many times",
            Self::TimedOut => "that link took too long",
            Self::Busy => "too many previews at once; try again",
        }
    }
}

/// A page, as far as it was read.
#[derive(Debug, Clone)]
pub struct Page {
    /// Where it ended up, which is not where we started if it redirected.
    pub url: String,
    /// The HTML, possibly truncated at the byte cap.
    pub html: String,
}

/// Fetches pages, subject to [`Limits`].
#[derive(Debug, Clone)]
pub struct Fetcher {
    tls: Arc<ClientConfig>,
    limits: Limits,
    permits: Arc<Semaphore>,
    /// Test-only: connect to loopback anyway.
    ///
    /// `cfg(test)`, so it is not a configuration knob and no operator can
    /// switch the guard off by accident. The HTTP exchange itself — statuses,
    /// redirects, the byte cap, the content-type refusal — is the part of this
    /// file that runs against a stranger's server, and it cannot be exercised
    /// at all without a server, and a test server is on loopback.
    #[cfg(test)]
    allow_private: bool,
}

impl Fetcher {
    /// A fetcher trusting the Mozilla root bundle.
    ///
    /// Bundled roots rather than the platform store, because this must behave
    /// the same in a container, in CI and on a developer's laptop; a preview
    /// that works for one operator and not another, for reasons in
    /// `/etc/ssl`, is a bug report nobody can act on.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        // The provider is named rather than taken from the process default.
        // `ClientConfig::builder()` panics when no default is installed, and
        // whether one is depends on which *other* component happened to start
        // first — a preview service that works or panics according to the
        // deployment's start-up order is not a service.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_or_else(
                |_| unreachable!("ring supports the default protocol versions"),
                |builder| builder.with_root_certificates(roots).with_no_client_auth(),
            );
        Self {
            tls: Arc::new(tls),
            limits,
            permits: Arc::new(Semaphore::new(limits.concurrency)),
            #[cfg(test)]
            allow_private: false,
        }
    }

    /// The same fetcher, willing to talk to loopback. Tests only.
    #[cfg(test)]
    fn against_loopback(limits: Limits) -> Self {
        Self {
            allow_private: true,
            ..Self::new(limits)
        }
    }

    /// Fetch `url`, following redirects within the limits.
    ///
    /// # Errors
    ///
    /// [`FetchError`], which the caller turns into a `PreviewError`. Every
    /// failure is one, including the ones that are really successes for the
    /// guard: a refusal is not an exception here, it is the common case for a
    /// chat message full of links.
    pub async fn fetch(&self, url: &str) -> Result<Page, FetchError> {
        // Taken before the timeout starts, and released when this returns: a
        // request that waits for a permit and then gets a fraction of the
        // timeout would fail in a way that depends on the server's load rather
        // than on the link.
        let Ok(_permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Err(FetchError::Busy);
        };
        tokio::time::timeout(self.limits.timeout, self.follow(url))
            .await
            .unwrap_or(Err(FetchError::TimedOut))
    }

    /// The redirect loop. Every hop is a fresh, fully checked fetch.
    async fn follow(&self, url: &str) -> Result<Page, FetchError> {
        let mut current = url.to_owned();
        for _ in 0..=self.limits.redirects {
            // Re-vetted on every hop, and this is the whole reason redirects
            // are followed here rather than by asking a library to do it: a
            // public URL that 302s to `http://169.254.169.254/` is the SSRF
            // attempt, and a redirect follower that checks only the first URL
            // is the vulnerability.
            if !self.private_is_allowed() {
                vet(&current).map_err(FetchError::Refused)?;
            }
            match self.once(&current).await? {
                Hop::Page(page) => return Ok(page),
                Hop::Redirect(next) => current = join(&current, &next),
            }
        }
        Err(FetchError::TooManyRedirects)
    }

    /// One request, with no redirect following.
    async fn once(&self, url: &str) -> Result<Hop, FetchError> {
        let (https, host, port, path) = split(url).map_err(FetchError::Refused)?;
        let address = self.resolve(&host, port).await?;

        let stream = TcpStream::connect(address)
            .await
            .map_err(|_| FetchError::Unreachable)?;
        let request = Request::builder()
            .method("GET")
            .uri(&path)
            .header("host", &host)
            .header(
                "user-agent",
                concat!("Starling/", env!("CARGO_PKG_VERSION")),
            )
            // Asked for by name, so a server that has both a page and an API at
            // one URL sends the page.
            .header("accept", "text/html,application/xhtml+xml")
            .body(Empty::<Bytes>::new())
            .map_err(|_| FetchError::Unreachable)?;

        let response = if https {
            let name = ServerName::try_from(host.clone())
                .map_err(|_| FetchError::Refused(Refusal::Malformed))?;
            let tls = TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, stream)
                .await
                .map_err(|_| FetchError::Unreachable)?;
            self.send(TokioIo::new(tls), request).await?
        } else {
            self.send(TokioIo::new(stream), request).await?
        };

        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            return location.map_or(Err(FetchError::Status(status.as_u16())), |next| {
                Ok(Hop::Redirect(next))
            });
        }
        if status != StatusCode::OK {
            return Err(FetchError::Status(status.as_u16()));
        }
        let is_html = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|kind| {
                let kind = kind.to_ascii_lowercase();
                kind.starts_with("text/html") || kind.starts_with("application/xhtml")
            });
        if !is_html {
            // Refused rather than parsed hopefully. A preview of a 4 GB video
            // is a 4 GB download for a title we were never going to find, and
            // the byte cap only bounds the damage rather than avoiding it.
            return Err(FetchError::NotHtml);
        }

        let body = self.read_capped(response.into_body()).await;
        Ok(Hop::Page(Page {
            url: url.to_owned(),
            // Lossy, because a page in a charset we did not ask about is a page
            // whose title is still worth reading. The alternative is refusing a
            // preview over one malformed byte in an advert halfway down.
            html: String::from_utf8_lossy(&body).into_owned(),
        }))
    }

    /// Drive one HTTP/1.1 exchange over an established stream.
    async fn send<S>(
        &self,
        io: TokioIo<S>,
        request: Request<Empty<Bytes>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, FetchError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|_| FetchError::Unreachable)?;
        // The connection has to be driven for the request to make progress. It
        // ends on its own with the response, and the outer timeout is what
        // stops a server that keeps it open saying nothing.
        drop(tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "the preview target closed the connection");
            }
        }));
        sender
            .send_request(request)
            .await
            .map_err(|_| FetchError::Unreachable)
    }

    /// Read at most [`Limits::bytes`], then stop.
    ///
    /// Truncated rather than refused: `<head>` is at the front, so a cut-off
    /// body usually still holds everything a preview needs, and a page that
    /// happens to be long is not a page a user should be denied a title for.
    async fn read_capped(&self, mut body: hyper::body::Incoming) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < self.limits.bytes {
            let Some(Ok(frame)) = body.frame().await else {
                break;
            };
            if let Some(chunk) = frame.data_ref() {
                let room = self.limits.bytes - out.len();
                out.extend_from_slice(&chunk[..room.min(chunk.len())]);
            }
        }
        out
    }
}

impl Fetcher {
    /// Whether this fetcher will talk to an address inside the deployment.
    ///
    /// Always false outside tests, and the compiler is what enforces it: the
    /// field it reads only exists under `cfg(test)`.
    const fn private_is_allowed(&self) -> bool {
        #[cfg(test)]
        {
            self.allow_private
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// The address to connect to, having refused the ones inside.
    #[cfg(not(test))]
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, FetchError> {
        resolve_public(host, port).await
    }

    /// The same, with the test-only escape hatch. There is no build in which
    /// both of these exist, so the release binary has no path to `resolve_any`
    /// at all — not a flag that defaults to off, an absence.
    #[cfg(test)]
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, FetchError> {
        if self.allow_private {
            resolve_any(host, port).await
        } else {
            resolve_public(host, port).await
        }
    }
}

/// One step of the redirect loop.
enum Hop {
    Page(Page),
    Redirect(String),
}

/// `(https, host, port, path)`.
fn split(url: &str) -> Result<(bool, String, u16, String), Refusal> {
    let (https, rest) = url.strip_prefix("https://").map_or_else(
        || {
            url.strip_prefix("http://")
                .map_or(Err(Refusal::Scheme), |rest| Ok((false, rest)))
        },
        |rest| Ok((true, rest)),
    )?;

    let (authority, path) = match rest.find('/') {
        Some(cut) => rest.split_at(cut),
        None => (rest, "/"),
    };
    // Credentials are dropped rather than sent on: `user:pass@host` in a chat
    // link is either an attempt to confuse the host check or somebody's
    // password, and neither should reach the far end from here.
    let authority = authority.split('@').next_back().unwrap_or(authority);

    let (host, port) = if let Some(literal) = authority.strip_prefix('[') {
        // An IPv6 literal keeps its brackets for the Host header and loses them
        // for the resolver, which wants an address and not a URL fragment.
        let (inside, after) = literal.split_once(']').ok_or(Refusal::Malformed)?;
        (
            inside.to_owned(),
            after
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(if https { 443 } else { 80 }),
        )
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (
                host.to_owned(),
                port.parse().map_err(|_| Refusal::Malformed)?,
            ),
            None => (authority.to_owned(), if https { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        return Err(Refusal::Malformed);
    }
    Ok((https, host, port, path.to_owned()))
}

/// Resolve `host` to any address at all. Tests only, see `allow_private`.
#[cfg(test)]
async fn resolve_any(host: &str, port: u16) -> Result<SocketAddr, FetchError> {
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| FetchError::Unresolvable)?
        .next()
        .ok_or(FetchError::Unresolvable)
}

/// Resolve `host` and return an address that is out on the internet.
///
/// The gate the string check cannot be: a name resolves to whatever its owner
/// says, and the answer is what we are about to connect to.
async fn resolve_public(host: &str, port: u16) -> Result<SocketAddr, FetchError> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| FetchError::Unresolvable)?
        .collect();
    if resolved.is_empty() {
        return Err(FetchError::Unresolvable);
    }
    resolved
        .into_iter()
        .find(|address| !is_private_addr(address.ip()))
        .ok_or(FetchError::ResolvesInside)
}

/// Resolve `location` against the URL it came from.
///
/// Only the two forms that matter: an absolute URL, and an absolute path.
/// A relative path is joined onto the parent directory, which is the last case
/// worth handling; anything stranger will fail `vet` on the next hop, which is
/// the right outcome for a redirect nobody can read.
fn join(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_owned();
    }
    // Every slice here goes through `get`, and not because of a lint: `base`
    // is a URL we were sent and `location` is a header the far end wrote, so a
    // byte index that lands inside a multi-byte character is a panic reachable
    // from a redirect. The fallbacks are the whole string or "/", which produce
    // a URL that fails `vet` on the next hop — a refused preview instead of a
    // downed service.
    let scheme_end = base.find("://").map_or(0, |at| at + 3);
    let after_scheme = base.get(scheme_end..).unwrap_or_default();
    let authority_end = scheme_end + after_scheme.find('/').unwrap_or(after_scheme.len());
    let origin = base.get(..authority_end).unwrap_or(base);
    if location.starts_with('/') {
        return format!("{origin}{location}");
    }
    let path = base.get(authority_end..).unwrap_or("/");
    let directory = path
        .rfind('/')
        .and_then(|at| path.get(..=at))
        .unwrap_or("/");
    format!("{origin}{directory}{location}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_splits_into_the_parts_a_connection_needs() {
        assert_eq!(
            split("https://example.org/a/b?c=d"),
            Ok((true, "example.org".to_owned(), 443, "/a/b?c=d".to_owned()))
        );
        assert_eq!(
            split("http://example.org:8080"),
            Ok((false, "example.org".to_owned(), 8080, "/".to_owned()))
        );
    }

    #[test]
    fn credentials_are_dropped_rather_than_forwarded() {
        // Two reasons, and either alone would be enough: they are a filter
        // bypass (`example.org@127.0.0.1`), and when they are real they are
        // somebody's password in a chat message.
        let (_, host, _, _) = split("http://user:secret@example.org/").expect("splits");
        assert_eq!(host, "example.org");
    }

    #[test]
    fn an_ipv6_literal_keeps_its_address_and_loses_its_brackets() {
        // The resolver wants an address; the brackets are URL syntax. Getting
        // this wrong turns `[::1]` into the host `[`, which parses as no
        // address at all and therefore skips every private-range check.
        assert_eq!(
            split("http://[2606:4700::1111]:8080/x"),
            Ok((false, "2606:4700::1111".to_owned(), 8080, "/x".to_owned()))
        );
    }

    #[test]
    fn a_redirect_resolves_against_where_it_came_from() {
        assert_eq!(
            join("https://example.org/a/b", "https://other.example/c"),
            "https://other.example/c"
        );
        assert_eq!(
            join("https://example.org/a/b", "/c"),
            "https://example.org/c"
        );
        assert_eq!(
            join("https://example.org/a/b", "c"),
            "https://example.org/a/c"
        );
    }

    #[tokio::test]
    async fn a_name_that_resolves_inside_the_deployment_is_refused() {
        // The case the textual check cannot see, which is the whole reason this
        // module exists: `localhost` is a name, and it resolves to loopback.
        // Any name can.
        assert_eq!(
            resolve_public("localhost", 80).await,
            Err(FetchError::ResolvesInside)
        );
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_says_so() {
        let outcome = resolve_public("no-such-host.invalid", 80).await;
        assert_eq!(outcome, Err(FetchError::Unresolvable));
    }

    #[test]
    fn what_the_client_is_told_does_not_map_the_network() {
        // A stranger must not be able to tell "this name does not exist" from
        // "this name is a machine inside the deployment" — that is a port scan
        // with extra steps.
        assert_eq!(
            FetchError::ResolvesInside.reason(),
            FetchError::Unresolvable.reason()
        );
    }
}

#[cfg(test)]
mod exchange {
    //! The HTTP exchange, against a server that answers on loopback.
    //!
    //! Everything here needs a *server*, and a test server is on loopback,
    //! which the guard refuses — correctly. So these use the `cfg(test)`
    //! fetcher that skips the address check, and nothing else about the
    //! pipeline is stubbed: real sockets, real HTTP/1.1, real redirects.

    use super::*;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::{Response, body::Incoming};
    use std::convert::Infallible;

    /// Serve `answer` for each request, and hand back the URL to fetch.
    ///
    /// The port is whatever the OS gives us, because a fixed one makes the
    /// suite fail whenever a developer happens to be running something on it.
    async fn serving<F>(answer: F) -> String
    where
        F: Fn(&str) -> Response<Full<Bytes>> + Send + Sync + Clone + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("bound").port();
        drop(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                drop(tokio::spawn(answering(stream, answer.clone())));
            }
        }));
        format!("http://127.0.0.1:{port}")
    }

    /// One connection, answered by `answer` until the peer goes away.
    async fn answering<F>(stream: TcpStream, answer: F)
    where
        F: Fn(&str) -> Response<Full<Bytes>> + Send + Sync + Clone + 'static,
    {
        let service = service_fn(move |request: Request<Incoming>| {
            let answer = answer.clone();
            async move { Ok::<_, Infallible>(answer(request.uri().path())) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }

    fn html(body: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(body.to_owned())))
            .expect("a response")
    }

    fn redirect(to: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(302)
            .header("location", to)
            .body(Full::new(Bytes::new()))
            .expect("a response")
    }

    #[tokio::test]
    async fn a_page_comes_back_and_parses() {
        let base = serving(|_| html("<head><title>Hello</title></head>")).await;
        let page = Fetcher::against_loopback(Limits::default())
            .fetch(&base)
            .await
            .expect("fetched");
        assert_eq!(crate::parse::card(&page.html).title, "Hello");
    }

    #[tokio::test]
    async fn a_redirect_is_followed_and_the_final_url_is_the_one_reported() {
        // A shortened link previewed as the shortener tells the reader nothing,
        // which is the whole reason `Page::url` is where it ended up.
        let base = serving(|path| {
            if path == "/end" {
                html("<head><title>Arrived</title></head>")
            } else {
                redirect("/end")
            }
        })
        .await;

        let page = Fetcher::against_loopback(Limits::default())
            .fetch(&format!("{base}/short"))
            .await
            .expect("fetched");
        assert!(page.url.ends_with("/end"), "got {}", page.url);
        assert_eq!(crate::parse::card(&page.html).title, "Arrived");
    }

    #[tokio::test]
    async fn a_redirect_loop_ends_rather_than_spinning() {
        let base = serving(|_| redirect("/again")).await;
        assert_eq!(
            Fetcher::against_loopback(Limits::default())
                .fetch(&base)
                .await
                .expect_err("cannot arrive"),
            FetchError::TooManyRedirects
        );
    }

    #[tokio::test]
    async fn something_that_is_not_a_page_is_refused_before_it_is_downloaded() {
        // The byte cap bounds the damage; refusing on content-type avoids it.
        // A preview of a video file is a download for a title that was never
        // going to be there.
        let base = serving(|_| {
            Response::builder()
                .header("content-type", "video/mp4")
                .body(Full::new(Bytes::from_static(b"\x00\x00\x00\x18ftyp")))
                .expect("a response")
        })
        .await;

        assert_eq!(
            Fetcher::against_loopback(Limits::default())
                .fetch(&base)
                .await
                .expect_err("not a page"),
            FetchError::NotHtml
        );
    }

    #[tokio::test]
    async fn an_error_status_is_not_parsed_as_a_page() {
        let base = serving(|_| {
            Response::builder()
                .status(404)
                .header("content-type", "text/html")
                .body(Full::new(Bytes::from_static(b"<title>Not Found</title>")))
                .expect("a response")
        })
        .await;

        assert_eq!(
            Fetcher::against_loopback(Limits::default())
                .fetch(&base)
                .await
                .expect_err("404"),
            FetchError::Status(404)
        );
    }

    #[tokio::test]
    async fn a_long_page_is_cut_at_the_cap_and_still_previews() {
        // Truncation is the ordinary case for anything large, not an edge one:
        // the title is at the front, so the cut costs nothing that matters.
        let base = serving(|_| {
            let mut body = String::from("<head><title>Short Title</title>");
            body.push_str(&r#"<meta name="x" content="padding">"#.repeat(4000));
            html(&body)
        })
        .await;

        let limits = Limits {
            bytes: 4096,
            ..Limits::default()
        };
        let page = Fetcher::against_loopback(limits)
            .fetch(&base)
            .await
            .expect("fetched");
        assert!(page.html.len() <= 4096, "read {} bytes", page.html.len());
        assert_eq!(crate::parse::card(&page.html).title, "Short Title");
    }

    #[tokio::test]
    async fn a_server_that_never_answers_times_out() {
        // Held open and silent is the cheapest attack on a fetcher: it costs
        // the far end nothing and holds one of our permits until the timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("bound").port();
        drop(tokio::spawn(async move {
            let accepted = listener.accept().await;
            // Accepted, and then silence, forever.
            std::future::pending::<()>().await;
            drop(accepted);
        }));

        let limits = Limits {
            timeout: Duration::from_millis(150),
            ..Limits::default()
        };
        assert_eq!(
            Fetcher::against_loopback(limits)
                .fetch(&format!("http://127.0.0.1:{port}/"))
                .await
                .expect_err("silence"),
            FetchError::TimedOut
        );
    }

    #[tokio::test]
    async fn only_so_many_fetches_run_at_once() {
        // The permit is what stops one client turning a channel full of links
        // into a channel full of sockets.
        let limits = Limits {
            concurrency: 1,
            timeout: Duration::from_millis(500),
            ..Limits::default()
        };
        let fetcher = Fetcher::against_loopback(limits);
        let base = serving(|_| html("<head><title>Slow</title></head>")).await;

        let held = Arc::clone(&fetcher.permits)
            .try_acquire_owned()
            .expect("the one permit");
        assert_eq!(
            fetcher.fetch(&base).await.expect_err("no permit left"),
            FetchError::Busy
        );
        drop(held);
        assert!(fetcher.fetch(&base).await.is_ok(), "and it recovers");
    }
}
