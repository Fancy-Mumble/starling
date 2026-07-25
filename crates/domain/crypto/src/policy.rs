//! Choosing a suite for a peer (Abstract Factory).

use tracing::debug;

use starling_gate::{Capability, Gate};

use crate::PeerCapabilities;
use crate::suite::{FancySuite, LegacySuite, SecuritySuite};

/// Decides which [`SecuritySuite`] a peer gets.
///
/// # Contract
///
/// 1. [`Self::negotiate`] must be **total**: every peer gets a suite, or the
///    policy explicitly refuses it. There is no "no security" outcome.
/// 2. A policy must never hand a peer a suite it cannot speak. Selecting on
///    announced capabilities only — never on a guess — is what guarantees this.
/// 3. [`Self::refuses`] must agree with [`Self::negotiate`]: a peer that is
///    refused gets `None`, and one that is not gets `Some`.
pub trait SecurityPolicy: std::fmt::Debug + Send + Sync {
    /// A short name for logs and the admin API.
    fn name(&self) -> &'static str;

    /// Pick a suite, or `None` to refuse the connection.
    fn negotiate(&self, peer: &PeerCapabilities) -> Option<Box<dyn SecuritySuite>>;

    /// Whether this policy refuses `peer` outright.
    fn refuses(&self, peer: &PeerCapabilities) -> bool {
        self.negotiate(peer).is_none()
    }
}

/// The default: give every peer the strongest suite it can actually speak.
///
/// Stock clients keep working exactly as they do against murmur; Fancy clients
/// are held to modern primitives. Nobody is refused, which is what makes this
/// safe to enable by default.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompatibilityFirst;

impl SecurityPolicy for CompatibilityFirst {
    fn name(&self) -> &'static str {
        "compatibility-first"
    }

    fn negotiate(&self, peer: &PeerCapabilities) -> Option<Box<dyn SecuritySuite>> {
        // Version-gated, not `is_fancy()`. A Fancy 0.1.0 client announces the
        // extensions but predates the modern cipher; handing it `FancySuite`
        // would give it a suite it cannot speak.
        let gate = Gate::for_peer(peer.fancy_version);
        let suite: Box<dyn SecuritySuite> = if gate.allows(Capability::ModernVoiceCrypto) {
            Box::new(FancySuite)
        } else {
            Box::new(LegacySuite)
        };
        debug!(
            policy = self.name(),
            suite = suite.name(),
            fancy = ?gate.version().map(|v| v.to_string()),
            "negotiated security suite"
        );
        Some(suite)
    }
}

/// Refuse anything that cannot do the modern suite.
///
/// **Opt-in.** For deployments that control their client fleet and would rather
/// turn away a legacy client than carry OCB2. Enabling this breaks stock Mumble
/// clients *by design*, which is why it is never the default and why the
/// refusal is explicit rather than a silent downgrade.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModernOnly;

impl SecurityPolicy for ModernOnly {
    fn name(&self) -> &'static str {
        "modern-only"
    }

    fn negotiate(&self, peer: &PeerCapabilities) -> Option<Box<dyn SecuritySuite>> {
        // Same gate as `CompatibilityFirst`, opposite outcome: a peer that
        // cannot do the modern cipher is refused rather than downgraded. Checking
        // `is_fancy()` here would have admitted a 0.1.0 client and then handed it
        // a suite it cannot speak, which is worse than refusing it.
        let gate = Gate::for_peer(peer.fancy_version);
        if !gate.allows(Capability::ModernVoiceCrypto) {
            debug!(
                policy = self.name(),
                announced = ?gate.version().map(|v| v.to_string()),
                required = %Capability::ModernVoiceCrypto.since(),
                "refusing a peer that cannot negotiate the modern suite"
            );
            return None;
        }
        Some(Box::new(FancySuite))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TlsFloor;
    use starling_gate::Capability;
    use starling_proto::Version;

    fn stock() -> PeerCapabilities {
        PeerCapabilities {
            version: Version::new(1, 5, 0),
            fancy_version: None,
        }
    }

    /// A client at the version that introduced the modern cipher.
    fn fancy_current() -> PeerCapabilities {
        PeerCapabilities {
            version: Version::new(1, 6, 0),
            fancy_version: Some(Capability::ModernVoiceCrypto.since().to_wire()),
        }
    }

    /// A Fancy client from before the modern cipher existed.
    ///
    /// The case the old `is_fancy()` check got wrong: it announces the Fancy
    /// extensions, so it was handed a suite it cannot speak.
    fn fancy_previous() -> PeerCapabilities {
        PeerCapabilities {
            version: Version::new(1, 6, 0),
            fancy_version: Some(starling_gate::FancyVersion::new(0, 3, 0).to_wire()),
        }
    }

    fn policies() -> Vec<Box<dyn SecurityPolicy>> {
        vec![Box::new(CompatibilityFirst), Box::new(ModernOnly)]
    }

    /// The contract every policy must satisfy.
    fn assert_policy_contract(policy: &dyn SecurityPolicy) {
        for peer in [
            stock(),
            fancy_previous(),
            fancy_current(),
            PeerCapabilities::unknown(),
        ] {
            // 3. refuses() and negotiate() must agree.
            assert_eq!(
                policy.refuses(&peer),
                policy.negotiate(&peer).is_none(),
                "{}: refuses() disagrees with negotiate()",
                policy.name()
            );
            // 2. A non-Fancy peer must never be handed the Fancy suite.
            if let Some(suite) = policy.negotiate(&peer)
                && !peer.is_fancy()
            {
                assert!(
                    suite.is_baseline(),
                    "{} gave a stock peer the {} suite",
                    policy.name(),
                    suite.name()
                );
            }
        }
    }

    #[test]
    fn every_policy_satisfies_the_contract() {
        for policy in policies() {
            assert_policy_contract(policy.as_ref());
        }
    }

    #[test]
    fn the_default_policy_never_refuses_anyone() {
        // Refusing by default would break the shipped stock client, which the
        // acceptance rule forbids.
        let policy = CompatibilityFirst;
        for peer in [
            stock(),
            fancy_previous(),
            fancy_current(),
            PeerCapabilities::unknown(),
        ] {
            assert!(!policy.refuses(&peer));
        }
    }

    #[test]
    fn a_stock_client_gets_the_legacy_suite() {
        let suite = CompatibilityFirst
            .negotiate(&stock())
            .expect("stock clients must be accepted");
        assert!(suite.is_baseline());
        assert_eq!(suite.tls_floor(), TlsFloor::Tls12);
        assert_eq!(suite.voice_cipher().wire_id(), 0);
    }

    #[test]
    fn a_current_fancy_client_gets_the_modern_suite() {
        let suite = CompatibilityFirst
            .negotiate(&fancy_current())
            .expect("fancy clients must be accepted");
        assert!(!suite.is_baseline());
        assert_eq!(suite.tls_floor(), TlsFloor::Tls13);
    }

    #[test]
    fn a_fancy_client_older_than_the_cipher_keeps_the_legacy_suite() {
        // The regression the gate fixes. This peer announces Fancy support, so
        // the old `is_fancy()` branch gave it `FancySuite` and a cipher it
        // predates. Version-gating hands it the baseline instead.
        let suite = CompatibilityFirst
            .negotiate(&fancy_previous())
            .expect("an older fancy client is still served");
        assert!(
            suite.is_baseline(),
            "0.3.0 predates the modern cipher and must not be given it"
        );
        assert_eq!(suite.voice_cipher().wire_id(), 0);
    }

    #[test]
    fn a_peer_that_announced_nothing_gets_the_baseline_not_the_modern_suite() {
        // Failing open would hand a suite the peer cannot speak; failing closed
        // by refusing would break clients that simply sent a sparse Version.
        let suite = CompatibilityFirst
            .negotiate(&PeerCapabilities::unknown())
            .expect("an unknown peer is still served");
        assert!(suite.is_baseline());
    }

    #[test]
    fn modern_only_refuses_stock_clients_explicitly_rather_than_downgrading() {
        // A silent downgrade would defeat the entire point of the policy.
        assert!(ModernOnly.refuses(&stock()));
        assert!(ModernOnly.refuses(&PeerCapabilities::unknown()));
    }

    #[test]
    fn modern_only_accepts_a_current_fancy_client() {
        let suite = ModernOnly
            .negotiate(&fancy_current())
            .expect("a current fancy client must be accepted");
        assert_eq!(suite.tls_floor(), TlsFloor::Tls13);
    }

    #[test]
    fn modern_only_refuses_a_fancy_client_that_predates_the_cipher() {
        // Refusing is right: admitting it and handing over a suite it cannot
        // speak would fail later, and less legibly.
        assert!(ModernOnly.refuses(&fancy_previous()));
    }

    #[test]
    fn policies_are_usable_behind_a_trait_object() {
        // The seam the listener depends on.
        let chosen: Vec<_> = policies()
            .iter()
            .map(|p| p.negotiate(&stock()).map(|s| s.name()))
            .collect();
        assert_eq!(chosen, vec![Some("legacy (stock Mumble)"), None]);
    }
}
