//! `link-preview`: previews fetched by the server, never by the client.
//!
//! A preview fetched by the viewer turns every chat link into a way to probe
//! that viewer's network and learn their address. Fetching here moves both to
//! the server, which is the point, and makes the SSRF guard the server's
//! problem, where it can actually be enforced.
//!
//! The guard is a deny list of destinations no legitimate preview target ever
//! lives on: loopback, link-local, and the private ranges that hold a cloud
//! metadata service.

pub mod fetch;
pub mod parse;

use std::sync::Arc;
use std::time::Duration;

pub use fetch::{FetchError, Fetcher, Limits};

use prost::Message as _;
use starling_proto_fancy::fancy::feature::{
    LinkPreviewEnvelope, Preview, PreviewError, PreviewRequest, link_preview_envelope,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// Why a URL will not be fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not `http` or `https`.
    Scheme,
    /// A host that resolves (or is written as) an address inside the
    /// deployment rather than out on the internet.
    PrivateAddress,
    /// No host at all.
    Malformed,
}

impl Refusal {
    /// What the client is told.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Scheme => "only http and https links are previewed",
            Self::PrivateAddress => "that address is inside the server's network",
            Self::Malformed => "that is not a URL",
        }
    }
}

/// Whether `url` may be fetched.
///
/// # Errors
///
/// [`Refusal`] naming which rule it broke, so a client can say something more
/// useful than "no preview".
pub fn vet(url: &str) -> Result<(), Refusal> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or(Refusal::Scheme)?;
    let authority = rest
        .split('/')
        .next()
        .map(|authority| authority.split('@').next_back().unwrap_or(authority))
        .filter(|authority| !authority.is_empty())
        .ok_or(Refusal::Malformed)?;
    // An IPv6 literal is bracketed precisely so its own colons cannot be
    // mistaken for the port separator, `[::1]:8080`. Stripping the port by
    // splitting on the first `:` instead treats `[::1]` as the malformed host
    // `[`, which is not a recognised address and so was never checked against
    // the private-range deny list, a bracketed loopback or link-local
    // literal would sail straight through.
    let host = if let Some(literal) = authority.strip_prefix('[') {
        literal.split(']').next().unwrap_or(literal)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        return Err(Refusal::Malformed);
    }

    if is_private(host) {
        return Err(Refusal::PrivateAddress);
    }
    Ok(())
}

/// Whether a host names something inside the deployment.
///
/// Textual rather than resolved, deliberately: this is the first gate, and the
/// second is [`fetch`] refusing to connect to a private address. Both, not
/// either, a DNS name can resolve to 169.254.169.254 whatever it looks like.
fn is_private(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    let Ok(address) = host.parse::<std::net::IpAddr>() else {
        // A name, not an address. It passes this gate and is caught by the
        // connect-time check.
        return false;
    };
    is_private_addr(address)
}

/// Whether an address is inside the deployment.
///
/// The one predicate, used by the URL check *and* by the resolver check, so
/// there is no second list of ranges to keep in step with this one.
pub(crate) fn is_private_addr(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // 169.254.169.254 is the cloud metadata service, and the single
                // most valuable SSRF target there is.
                || v4.octets()[..2] == [169, 254]
                // Carrier-grade NAT (100.64.0.0/10) and the benchmarking range
                // (198.18.0.0/15): neither is the public internet, and both are
                // routable inside a deployment. Both are written as the ranges
                // they are, 198.18.0.0/15 spans 198.18 *and* 198.19, and
                // reading it as a /16 leaves half of it fetchable.
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
                || v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1])
        }
        std::net::IpAddr::V6(v6) => {
            // An IPv4-mapped address is an IPv4 address wearing a hat:
            // `::ffff:127.0.0.1` connects to loopback, and a check that reads
            // only the v6 predicates lets it through. This was the hole.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_addr(std::net::IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7, the unique-local range, and fe80::/10, link-local.
                // The v6 equivalents of everything above, and until now the v6
                // arm checked neither.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The service.
#[derive(Debug)]
pub struct LinkPreviewService {
    fanout: Fanout,
    logger: Logger,
    fetcher: Fetcher,
}

impl ClientService for LinkPreviewService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::LinkPreview.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = LinkPreviewEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable LinkPreviewEnvelope"
            );
            return Actions::new();
        };
        let Some(link_preview_envelope::Body::Request(request)) = envelope.body else {
            return Actions::new();
        };

        // One answer per URL, and the caps are per request: a message with
        // forty links is forty fetches, and a client that sends one is not
        // doing anything a client is not allowed to do.
        let mut actions = Actions::new();
        for url in &request.urls {
            match vet(url) {
                Err(refusal) => actions.push(self.refuse(&inbound, &request.request_id, url, refusal)),
                Ok(()) => {
                    // The fetch happens off this handler and the answer arrives
                    // through the fanout. A preview is a request to a host
                    // somebody else chose: it takes as long as that host takes,
                    // and awaiting it here would hold this connection's frame
                    // handler for seconds while a stranger's server decides.
                    self.spawn_fetch(
                        inbound.conn,
                        PreviewRequest {
                            request_id: request.request_id.clone(),
                            urls: vec![url.clone()],
                        },
                    );
                }
            }
        }
        actions
    }
}

impl LinkPreviewService {
    /// Tell the client why a URL will not be fetched, and the operator when it
    /// is the kind of refusal worth knowing about.
    fn refuse(
        &self,
        inbound: &Inbound,
        request_id: &str,
        url: &str,
        refusal: Refusal,
    ) -> starling_proto_fancy::control::ServerAction {
        // A client asking the server to fetch a loopback or metadata address is
        // an SSRF attempt, whether or not it knows it. The guard already
        // refuses; this is what makes it visible, and it records the session so
        // a repeat offender is attributable.
        if matches!(refusal, Refusal::PrivateAddress) {
            tracing::warn!(
                session = inbound.session,
                url = %url,
                "link preview refused: the target is inside the deployment"
            );
            self.logger.log(
                LogEvent::warning(Category::Security, "link preview refused: private address")
                    .with("session", inbound.session)
                    .with("url", url.to_owned()),
            );
        } else {
            tracing::debug!(
                session = inbound.session,
                reason = refusal.reason(),
                "link preview refused"
            );
        }
        to_conn(
            inbound.conn,
            ServiceKind::LinkPreview.outer_type(),
            LinkPreviewEnvelope {
                body: Some(link_preview_envelope::Body::Error(PreviewError {
                    request_id: request_id.to_owned(),
                    // Named, so a client with several links in one message can
                    // say which of them it could not preview.
                    reason: format!("{url}: {}", refusal.reason()),
                })),
            }
            .encode_to_vec(),
        )
    }
}

impl LinkPreviewService {
    /// Fetch in the background and push the answer when it arrives.
    fn spawn_fetch(&self, conn: u64, request: PreviewRequest) {
        let fetcher = self.fetcher.clone();
        let fanout = self.fanout.clone();
        let logger = self.logger.clone();
        let outer = ServiceKind::LinkPreview.outer_type();
        drop(tokio::spawn(async move {
            let url = request.urls.first().cloned().unwrap_or_default();
            let body = match fetcher.fetch(&url).await {
                Ok(page) => {
                    let card = parse::card(&page.html);
                    link_preview_envelope::Body::Preview(Preview {
                        request_id: request.request_id,
                        // Where it *ended up*: a preview of a shortened link
                        // that shows the shortener has told the reader nothing.
                        url: page.url,
                        title: card.title,
                        description: card.description,
                        site: card.site,
                        // Left empty, and this is the honest state rather than
                        // an oversight: `image_key` names an object in the
                        // files service, and nothing here stores one yet.
                        // Putting the remote URL in it would send every viewer
                        // to fetch it, which is the network probe this whole
                        // service exists to prevent.
                        image_key: String::new(),
                    })
                }
                Err(error) => {
                    // Logged with the detail the client is not given: the
                    // difference between "does not resolve" and "resolves to a
                    // machine inside the deployment" is a fact about the
                    // network, and an operator needs it while a stranger
                    // mapping the estate one URL at a time must not have it.
                    if matches!(error, FetchError::ResolvesInside) {
                        logger.log(
                            LogEvent::warning(
                                Category::Security,
                                "link preview refused: the name resolves inside the deployment",
                            )
                            .with("url", url.clone()),
                        );
                    }
                    tracing::debug!(url = %url, ?error, "link preview failed");
                    link_preview_envelope::Body::Error(PreviewError {
                        request_id: request.request_id,
                        reason: format!("{url}: {}", error.reason()),
                    })
                }
            };
            fanout.push(to_conn(
                conn,
                outer,
                LinkPreviewEnvelope { body: Some(body) }.encode_to_vec(),
            ));
        }));
    }
}

impl Serve for LinkPreviewService {
    const NAME: &'static str = "link-preview";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        // Every limit is an operator's to raise, and every default is chosen to
        // be the one a server can leave alone. They bound work a *stranger*
        // asks for against a host the stranger picked, so the defaults are
        // deliberately mean.
        let service = ctx.service();
        let default = Limits::default();
        let limits = Limits {
            timeout: service
                .option::<u64>("preview_timeout_ms")
                .map_or(default.timeout, Duration::from_millis),
            bytes: service
                .option::<usize>("preview_max_bytes")
                .unwrap_or(default.bytes),
            redirects: service
                .option::<u8>("preview_redirects")
                .unwrap_or(default.redirects),
            concurrency: service
                .option::<usize>("preview_concurrency")
                .unwrap_or(default.concurrency)
                // Zero would mean "never fetch anything", silently, and an
                // operator who wants that switches the service off.
                .max(1),
        };
        Ok(Arc::new(Self {
            fanout: Fanout::default(),
            logger: ctx.logger,
            fetcher: Fetcher::new(limits),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cloud_metadata_address_is_refused() {
        // The single most valuable SSRF target in any cloud deployment.
        assert_eq!(
            vet("http://169.254.169.254/latest/meta-data/"),
            Err(Refusal::PrivateAddress)
        );
    }

    #[test]
    fn loopback_and_private_ranges_are_refused() {
        for url in [
            "http://127.0.0.1/admin",
            "http://localhost:8080/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://[::1]/",
        ] {
            assert!(vet(url).is_err(), "{url} must be refused");
        }
    }

    #[test]
    fn an_ipv4_address_wearing_an_ipv6_hat_is_still_loopback() {
        // `::ffff:127.0.0.1` is an IPv4-mapped IPv6 address: it connects to
        // 127.0.0.1, and a check that reads only the v6 predicates
        // (`is_loopback`, `is_unspecified`) says it is public. It was the hole.
        for url in [
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[::ffff:10.0.0.1]/",
        ] {
            assert_eq!(
                vet(url),
                Err(Refusal::PrivateAddress),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn the_ipv6_private_ranges_are_refused_as_well_as_the_ipv4_ones() {
        // fc00::/7 is where a deployment's own machines live on v6, and
        // fe80::/10 is the link. Neither was checked.
        for url in ["http://[fd00::1]/", "http://[fe80::1]/"] {
            assert_eq!(
                vet(url),
                Err(Refusal::PrivateAddress),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn carrier_grade_nat_and_the_benchmark_range_are_not_the_internet() {
        assert_eq!(vet("http://100.64.0.1/"), Err(Refusal::PrivateAddress));
        assert_eq!(vet("http://198.18.0.1/"), Err(Refusal::PrivateAddress));
        // The neighbours of both, which are ordinary public addresses and must
        // stay fetchable, a guard that is too wide is a feature that does not
        // work, and nobody reports it as a security bug.
        assert!(vet("http://100.63.255.255/").is_ok());
        assert!(vet("http://100.128.0.1/").is_ok());
        assert_eq!(vet("http://198.19.255.255/"), Err(Refusal::PrivateAddress));
        assert!(vet("http://198.20.0.1/").is_ok());
    }

    #[test]
    fn a_non_http_scheme_is_refused_rather_than_attempted() {
        assert_eq!(vet("file:///etc/passwd"), Err(Refusal::Scheme));
        assert_eq!(vet("gopher://example.org/"), Err(Refusal::Scheme));
    }

    #[test]
    fn an_ordinary_public_url_passes() {
        assert!(vet("https://example.org/article").is_ok());
    }

    #[test]
    fn credentials_in_the_authority_do_not_hide_the_host() {
        // http://example.org@127.0.0.1/ is a classic filter bypass.
        assert_eq!(
            vet("http://example.org@127.0.0.1/"),
            Err(Refusal::PrivateAddress)
        );
    }
}
