//! What the gateway does when a dependency is down.
//!
//! `tier` is not documentation, the gateway reads it and behaves accordingly
//! (`docs/ARCHITECTURE.md` §4).
//!
//! | Tier | Down means |
//! |---|---|
//! | `essential` | reject logins |
//! | `core` | that feature is dead; the server runs |
//! | `optional` | nobody notices |
//!
//! There is a documented gap in this taxonomy, and it is worth stating here so
//! nobody tries to close it by adding a tier: the gateway's session store fits
//! neither answer, because its failure is *deferred and amplifying* rather than
//! immediate. It is therefore not a service at all and has no tier, see
//! `docs/ARCHITECTURE.md` §5.

use serde::{Deserialize, Serialize};

/// How badly a service being down matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Logins are rejected while it is unhealthy.
    Essential,
    /// The feature it owns is dead; everything else keeps working.
    #[default]
    Core,
    /// Nobody notices.
    Optional,
}

impl Tier {
    /// Whether a client may still complete a handshake while this is down.
    #[must_use]
    pub const fn admits_logins(self) -> bool {
        !matches!(self, Self::Essential)
    }

    /// Whether inbound frames for this service should be shed at the door.
    ///
    /// Shedding an optional service's traffic is invisible; shedding an
    /// essential one's is a login failure, which is the outcome the tier
    /// already promises.
    #[must_use]
    pub const fn sheddable(self) -> bool {
        matches!(self, Self::Optional | Self::Core)
    }

    /// The name used in configuration and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Essential => "essential",
            Self::Core => "core",
            Self::Optional => "optional",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_essential_service_being_down_stops_a_login() {
        assert!(!Tier::Essential.admits_logins());
        assert!(Tier::Core.admits_logins());
        assert!(Tier::Optional.admits_logins());
    }

    #[test]
    fn essential_traffic_is_never_shed_at_the_door() {
        // Shedding it would turn a slow authority into a wrong answer rather
        // than a refused login, which is the one outcome the tier rules out.
        assert!(!Tier::Essential.sheddable());
        assert!(Tier::Core.sheddable());
        assert!(Tier::Optional.sheddable());
    }

    #[test]
    fn a_tier_reads_from_the_lowercase_name_an_operator_writes() {
        let parsed: Tier = toml::from_str::<toml::Value>("t = \"optional\"")
            .ok()
            .and_then(|v| v.get("t").cloned())
            .and_then(|v| v.try_into().ok())
            .unwrap_or_default();
        assert_eq!(parsed, Tier::Optional);
    }
}
