//! The routing table: two bytes in, a service name out.
//!
//! Built from the TOML at startup, so **a new service is a configuration block
//! and not a gateway release**. This binary links no service's generated stubs
//! and knows none of their schemas; what it knows is that type 1006 goes to
//! whatever the operator called `pchat`.
//!
//! Types 100-999 are burned (`docs/PROTOCOL-COMPATIBILITY.md` §2): they shipped
//! in released Fancy clients under an interleaved layout, so a message with one
//! of those numbers is from a stale client and must never land on a new
//! service, which would read it as something else entirely.

use std::collections::HashMap;

use starling_proto_fancy::types::OuterType;
use starling_runtime::config::Config;
use starling_runtime::tier::Tier;

/// Where one wire type goes.
#[derive(Debug, Clone)]
pub struct Route {
    /// The service's configuration key, which is also its log name.
    pub service: String,
    /// What the gateway does while it is down.
    pub tier: Tier,
    /// Which rate-limit bucket this route is charged to.
    pub bucket: String,
}

/// Every route, resolved once.
#[derive(Debug, Clone, Default)]
pub struct Router {
    routes: HashMap<u16, Route>,
}

impl Router {
    /// Build the table from configuration.
    ///
    /// A disabled service contributes nothing, so switching one off is a
    /// supported deployment rather than a hole: its types simply have no route,
    /// and an inbound frame for them is refused the same way an unknown type is.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let mut routes = HashMap::new();
        for (name, service) in &config.services {
            if !service.enabled {
                continue;
            }
            for type_id in &service.types {
                let _ = routes.insert(
                    *type_id,
                    Route {
                        service: name.clone(),
                        tier: service.tier,
                        bucket: service
                            .limits
                            .clone()
                            .unwrap_or_else(|| "control".to_owned()),
                    },
                );
            }
        }
        Self { routes }
    }

    /// Where `type_id` goes, if anywhere.
    ///
    /// A burned type resolves to nothing even if a service claims it, because
    /// the claim would be a configuration mistake with a silent failure mode.
    #[must_use]
    pub fn route(&self, type_id: u16) -> Option<&Route> {
        if !OuterType::classify(type_id).routable() {
            return None;
        }
        self.routes.get(&type_id)
    }

    /// Every service with at least one route, for attaching to.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .routes
            .values()
            .map(|route| route.service.clone())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// How many types are routed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether nothing is routed, which is a misconfiguration rather than a
    /// quiet server.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn router() -> Router {
        Router::from_config(&Config::with_defaults(Path::new("/run/starling")))
    }

    #[test]
    fn an_upstream_type_routes_to_the_service_that_owns_it() {
        // TextMessage is 11 and belongs to text; UDPTunnel is 1 and belongs to
        // voice, because the tunnel is the UDP-blocked fallback for audio.
        let router = router();
        assert_eq!(router.route(11).map(|r| r.service.as_str()), Some("text"));
        assert_eq!(router.route(1).map(|r| r.service.as_str()), Some("voice"));
    }

    #[test]
    fn a_service_envelope_routes_on_its_outer_type_alone() {
        let router = router();
        assert_eq!(
            router.route(1006).map(|r| r.service.as_str()),
            Some("pchat")
        );
        assert_eq!(
            router.route(1015).map(|r| r.service.as_str()),
            Some("social")
        );
    }

    #[test]
    fn a_burned_type_has_no_route_even_if_something_claims_it() {
        // 120 was WebRtcSignal in the interleaved layout. A stale client's
        // message must not land on a service that would misread it.
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        if let Some(screenshare) = config.services.get_mut("screenshare") {
            screenshare.types.push(120);
        }
        assert!(Router::from_config(&config).route(120).is_none());
    }

    #[test]
    fn screen_share_signalling_is_charged_to_its_own_bucket() {
        // On murmur's single 1/s bucket this silently ate the SDP offer.
        assert_eq!(
            router().route(1008).map(|r| r.bucket.as_str()),
            Some("signalling")
        );
        // `ChannelState`(7) still falls back to `control`, which is what makes
        // the assertion above about *routing* rather than about everything
        // having drifted onto its own bucket.
        assert_eq!(
            router().route(7).map(|r| r.bucket.as_str()),
            Some("control")
        );
    }

    #[test]
    fn the_two_human_driven_routes_have_their_own_buckets() {
        // `TextMessage`(11) used to assert `control` here, and that was the
        // bug: a person typing eight messages lost the sixth to murmur's 1/s,
        // and an ACL editor opening a thirty-channel tree lost most of its
        // queries. Both were measured in an e2e run before being moved.
        assert_eq!(router().route(11).map(|r| r.bucket.as_str()), Some("chat"));
        assert_eq!(router().route(13).map(|r| r.bucket.as_str()), Some("acl"));
    }

    #[test]
    fn a_disabled_service_leaves_its_types_unrouted() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        if let Some(audit) = config.services.get_mut("audit") {
            audit.enabled = false;
        }
        let router = Router::from_config(&config);
        assert!(router.route(1012).is_none());
        assert!(!router.services().contains(&"audit".to_owned()));
    }
}
