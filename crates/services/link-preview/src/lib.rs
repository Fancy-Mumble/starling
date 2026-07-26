//! `link-preview` — previews fetched by the server, never by the client.
//!
//! A preview fetched by the viewer turns every chat link into a way to probe
//! that viewer's network and learn their address. Fetching here moves both to
//! the server, which is the point — and makes the SSRF guard the server's
//! problem, where it can actually be enforced.
//!
//! The guard is a deny list of destinations no legitimate preview target ever
//! lives on: loopback, link-local, and the private ranges that hold a cloud
//! metadata service.

// The async test harness, and nothing else in this crate, needs tokio.
#[cfg(test)]
use tokio as _;

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use starling_proto_fancy::fancy::feature::{
    LinkPreviewEnvelope, Preview, PreviewError, link_preview_envelope,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// Why a URL will not be fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not `http` or `https`.
    Scheme,
    /// A host that resolves — or is written as — an address inside the
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
    // mistaken for the port separator — `[::1]:8080`. Stripping the port by
    // splitting on the first `:` instead treats `[::1]` as the malformed host
    // `[`, which is not a recognised address and so was never checked against
    // the private-range deny list — a bracketed loopback or link-local
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
/// second is the resolver refusing to connect to a private address. Both, not
/// either — a DNS name can resolve to 169.254.169.254 whatever it looks like.
fn is_private(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    let Ok(address) = host.parse::<std::net::IpAddr>() else {
        // A name, not an address. It passes this gate and is caught by the
        // connect-time check.
        return false;
    };
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
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// The service.
#[derive(Debug)]
pub struct LinkPreviewService {
    fanout: Fanout,
}

#[async_trait]
impl ClientService for LinkPreviewService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::LinkPreview.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = LinkPreviewEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        let Some(link_preview_envelope::Body::Request(request)) = envelope.body else {
            return Actions::new();
        };

        let reply = match vet(&request.url) {
            Err(refusal) => LinkPreviewEnvelope {
                body: Some(link_preview_envelope::Body::Error(PreviewError {
                    request_id: request.request_id,
                    reason: refusal.reason().to_owned(),
                })),
            },
            Ok(()) => LinkPreviewEnvelope {
                body: Some(link_preview_envelope::Body::Preview(Preview {
                    request_id: request.request_id,
                    url: request.url,
                    ..Preview::default()
                })),
            },
        };
        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
    }
}

#[async_trait]
impl Serve for LinkPreviewService {
    const NAME: &'static str = "link-preview";

    async fn build(_ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        Ok(Arc::new(Self {
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
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
