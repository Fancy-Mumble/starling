//! The only way out of the browser.
//!
//! A browser given a URL does its own DNS and opens its own sockets, and that
//! undoes every property the fetch path has: `vet` reads a name, the browser
//! resolves it again, and the second answer does not have to match the first.
//! Worse, a page is not one request. It is a document and then whatever that
//! document asks for, each a fresh name the guard never saw.
//!
//! So the browser is started with `--proxy-server` pointing here and
//! `--proxy-bypass-list=<-loopback>` so that not even `localhost` escapes it.
//! Chrome hands a proxy the *name*, unresolved, and every request in the render
//! arrives on this listener: the document, the redirect it follows, the script
//! on a CDN and the tracker beside it. Each one is vetted, resolved to a public
//! address and connected **to that address**, which is the step a name-based
//! check cannot do.
//!
//! TLS is untouched: `CONNECT` splices bytes, so the browser negotiates with
//! the origin end to end. That is not incidental. The reason a browser is worth
//! spending at all is that its handshake is a browser's, and a proxy that
//! terminated TLS would replace the one fingerprint the render was for.
//!
//! # What this is not
//!
//! It listens on loopback, on an ephemeral port, for the life of the service,
//! and it does not authenticate: Chrome has no way to carry a credential on a
//! `CONNECT` that does not involve a prompt. Anything else already running as a
//! local user can therefore use it as an egress proxy. It cannot be used to
//! reach anything *inside* the deployment - that is the guard, and it is the
//! part that matters - so on a host running this service in its own container,
//! which is the deployment this service is shaped for, the exposure is that a
//! process which could already open its own socket can open one through here
//! instead.

use std::net::SocketAddr;
use std::sync::Arc;

use starling_outbound::{FetchError, Refusal, vet};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// The largest request head this will read before giving up on a client.
///
/// A `CONNECT` line and a handful of headers. A peer that sends more than this
/// without a blank line is not a browser asking for a page.
const MAX_HEAD: usize = 8 * 1024;

/// Ports a render may reach. The web, and nothing else.
///
/// Not a general-purpose proxy: a browser fetching a page uses these two, and
/// leaving the rest open would make this a way to reach a mail or database port
/// on a public address, which no preview ever needs.
const ALLOWED_PORTS: &[u16] = &[80, 443];

/// A listener the browser is pointed at.
#[derive(Debug)]
pub struct Guarded {
    listener: TcpListener,
    address: SocketAddr,
    tunnels: Arc<Semaphore>,
}

/// What one request through the proxy was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// `CONNECT host:port`, the shape every https request takes.
    Tunnel {
        /// The name the browser asked for, unresolved.
        host: String,
        /// The port it asked for.
        port: u16,
    },
    /// An absolute-form request, the shape a plain http request takes. The
    /// bytes are forwarded as they arrived: an origin server is required to
    /// accept an absolute-form target, and rewriting it would mean parsing and
    /// re-emitting a request a stranger's browser composed.
    Absolute {
        /// The name the browser asked for, unresolved.
        host: String,
        /// The port it asked for.
        port: u16,
    },
}

impl Head {
    /// Where this request wants to go.
    const fn target(&self) -> (&String, u16) {
        match self {
            Self::Tunnel { host, port } | Self::Absolute { host, port } => (host, *port),
        }
    }
}

/// Why a request through the proxy was not forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// Not a request this proxy serves.
    Unreadable,
    /// A port that is not the web.
    Port(u16),
    /// The guard refused the target by name.
    Refused(Refusal),
    /// The guard refused it at the moment of connect, or the far end would not
    /// answer.
    Unreachable(FetchError),
}

impl Guarded {
    /// Bind an ephemeral loopback port.
    ///
    /// # Errors
    ///
    /// The bind failing, which on loopback means the process is out of sockets.
    pub async fn bind(tunnels: usize) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        Ok(Self {
            listener,
            address,
            tunnels: Arc::new(Semaphore::new(tunnels.max(1))),
        })
    }

    /// What to write in `--proxy-server`.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Accept until the process ends.
    ///
    /// Never returns. Errors on one connection are that connection's problem:
    /// a proxy that stopped accepting because one browser tab misbehaved would
    /// take the whole service with it.
    pub async fn serve(self) {
        loop {
            let Ok((stream, peer)) = self.listener.accept().await else {
                continue;
            };
            // Belt and braces over binding loopback: an address that is not
            // loopback here means the bind moved, and forwarding for a stranger
            // is the one thing this must never do.
            if !peer.ip().is_loopback() {
                continue;
            }
            let tunnels = Arc::clone(&self.tunnels);
            drop(tokio::spawn(async move {
                let Ok(_permit) = tunnels.try_acquire_owned() else {
                    // The render is bounded elsewhere; this is the backstop for
                    // a page that opens two hundred sockets, and dropping the
                    // socket is what a proxy at capacity has to say.
                    return;
                };
                if let Err(denied) = handle(stream).await {
                    tracing::debug!(?denied, "render proxy refused a request");
                }
            }));
        }
    }
}

/// Serve one connection: read the head, vet it, splice it.
async fn handle(mut client: TcpStream) -> Result<(), Denied> {
    let (head, buffered) = read_head(&mut client).await?;
    let (host, port) = head.target();
    if !ALLOWED_PORTS.contains(&port) {
        refuse(&mut client, "403 Forbidden").await;
        return Err(Denied::Port(port));
    }
    // Vetted as a URL, which is what the deny list reads: the same check the
    // fetch path runs, on the same shape of input, so the two cannot drift.
    let scheme = if port == 443 { "https" } else { "http" };
    if let Err(refusal) = vet(&format!("{scheme}://{host}:{port}/")) {
        refuse(&mut client, "403 Forbidden").await;
        return Err(Denied::Refused(refusal));
    }

    let mut upstream = match connect(host, port).await {
        Ok(stream) => stream,
        Err(error) => {
            refuse(&mut client, "502 Bad Gateway").await;
            return Err(Denied::Unreachable(error));
        }
    };

    match head {
        Head::Tunnel { .. } => {
            // The browser now speaks TLS through this socket to the origin, and
            // this end sees ciphertext. That is the point.
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return Ok(());
            }
        }
        Head::Absolute { .. } => {
            // The head we already consumed goes on first, verbatim.
            if upstream.write_all(&buffered).await.is_err() {
                return Ok(());
            }
        }
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// The guarded connect.
#[cfg(not(any(test, feature = "loopback")))]
async fn connect(host: &str, port: u16) -> Result<TcpStream, FetchError> {
    starling_outbound::connect_public(host, port).await
}

/// The test-only one. Loopback is where a test server lives, and refusing
/// loopback is what the rest of this file is for; the two cannot both be true
/// in one build, so the test build has its own.
#[cfg(any(test, feature = "loopback"))]
async fn connect(host: &str, port: u16) -> Result<TcpStream, FetchError> {
    starling_outbound::connect_any(host, port).await
}

/// Say no in a way a browser will render as a failed request rather than hang.
async fn refuse(client: &mut TcpStream, status: &str) {
    let _ = client
        .write_all(format!("HTTP/1.1 {status}\r\nconnection: close\r\n\r\n").as_bytes())
        .await;
}

/// Read up to the blank line and say what was asked for.
async fn read_head(client: &mut TcpStream) -> Result<(Head, Vec<u8>), Denied> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let read = client
            .read(&mut chunk)
            .await
            .map_err(|_| Denied::Unreadable)?;
        if read == 0 {
            return Err(Denied::Unreadable);
        }
        buffer.extend_from_slice(chunk.get(..read).unwrap_or_default());
        if find_blank_line(&buffer).is_some() {
            break;
        }
        if buffer.len() > MAX_HEAD {
            return Err(Denied::Unreadable);
        }
    }
    let head = parse_head(&buffer).ok_or(Denied::Unreadable)?;
    Ok((head, buffer))
}

/// Where the head ends, if it has ended.
fn find_blank_line(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Read the request line: `CONNECT host:443` or `GET http://host/path`.
fn parse_head(buffer: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(buffer).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(target, 443)?;
        return Some(Head::Tunnel { host, port });
    }
    // Absolute form. Anything else is a browser talking to this listener as if
    // it were an origin server, which it is not.
    let (rest, default_port) = target
        .strip_prefix("http://")
        .map(|rest| (rest, 80_u16))
        .or_else(|| target.strip_prefix("https://").map(|rest| (rest, 443)))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = split_authority(authority, default_port)?;
    Some(Head::Absolute { host, port })
}

/// `host`, `host:port`, `[::1]` or `[::1]:port`.
fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    // Credentials never reach the far end from here, exactly as in the fetch
    // path: `user:pass@host` is either confusion or somebody's password.
    let authority = authority.split('@').next_back().unwrap_or(authority);
    if let Some(literal) = authority.strip_prefix('[') {
        let (inside, after) = literal.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .map_or(Some(default_port), |text| text.parse().ok())?;
        return Some((inside.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_owned(), port.parse().ok()?)),
        None => Some((authority.to_owned(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connect_line_names_a_host_and_a_port() {
        let head = parse_head(b"CONNECT www.example.org:443 HTTP/1.1\r\nhost: x\r\n\r\n");
        assert_eq!(
            head,
            Some(Head::Tunnel {
                host: "www.example.org".to_owned(),
                port: 443,
            })
        );
    }

    #[test]
    fn a_plain_request_arrives_in_absolute_form() {
        // What Chrome sends through a proxy for an `http://` URL, and the only
        // other shape this listener ever sees.
        let head =
            parse_head(b"GET http://example.org/a?b=c HTTP/1.1\r\nhost: example.org\r\n\r\n");
        assert_eq!(
            head,
            Some(Head::Absolute {
                host: "example.org".to_owned(),
                port: 80,
            })
        );
    }

    #[test]
    fn an_origin_form_request_is_not_a_proxy_request() {
        // Somebody pointing a browser at this port directly. It is not an
        // origin server and must not answer as one.
        assert_eq!(parse_head(b"GET /index.html HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn credentials_in_the_authority_do_not_reach_the_host_check() {
        let head = parse_head(b"CONNECT user:pw@evil.example:443 HTTP/1.1\r\n\r\n");
        assert_eq!(
            head,
            Some(Head::Tunnel {
                host: "evil.example".to_owned(),
                port: 443,
            })
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_address_and_loses_its_brackets() {
        let head = parse_head(b"CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n");
        assert_eq!(
            head,
            Some(Head::Tunnel {
                host: "2606:4700::1111".to_owned(),
                port: 443,
            })
        );
    }

    #[test]
    fn the_deny_list_is_reached_through_the_same_url_check_the_fetch_uses() {
        // The wiring, not the list: the list is tested where it lives. What
        // this asserts is that a `CONNECT` to the metadata service is refused
        // by the same function that refuses the URL of one.
        assert_eq!(
            vet("http://169.254.169.254:80/"),
            Err(Refusal::PrivateAddress)
        );
        assert_eq!(vet("https://127.0.0.1:443/"), Err(Refusal::PrivateAddress));
    }

    #[test]
    fn only_the_web_ports_are_forwarded() {
        assert!(ALLOWED_PORTS.contains(&80));
        assert!(ALLOWED_PORTS.contains(&443));
        assert!(!ALLOWED_PORTS.contains(&25), "a mail port is not a page");
        assert!(!ALLOWED_PORTS.contains(&5432), "nor is a database");
    }
}
