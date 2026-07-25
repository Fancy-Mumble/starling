//! Security suites — the Abstract Factory's product families.

use crate::cipher::{Ocb2Aes128Spec, VoiceCipherSpec, XChaCha20Poly1305Spec};
use crate::tls::TlsFloor;

/// A coherent family of security choices for one peer.
///
/// The primitives here are chosen *together*: pairing a TLS 1.3 floor with a
/// legacy voice cipher would be security theatre, and pairing a modern voice
/// cipher with a client that cannot negotiate it would simply not work. Bundling
/// them into a suite means a caller cannot mix and match by accident.
///
/// # Contract
///
/// A suite must be usable end-to-end by any peer it is selected for. A
/// [`SecurityPolicy`](super::SecurityPolicy) that hands a suite to a peer that
/// cannot speak it is a bug in the policy, not in the suite.
pub trait SecuritySuite: std::fmt::Debug + Send + Sync {
    /// Human-readable name, for logs and the admin API.
    fn name(&self) -> &'static str;

    /// The oldest TLS version peers on this suite may negotiate.
    fn tls_floor(&self) -> TlsFloor;

    /// The UDP voice cipher this suite uses.
    fn voice_cipher(&self) -> &dyn VoiceCipherSpec;

    /// Whether this suite is safe to offer a peer that announced nothing.
    ///
    /// Exactly one suite may answer `true`, and it is the one every stock
    /// Mumble client receives.
    fn is_baseline(&self) -> bool {
        false
    }
}

/// What stock Mumble clients get: exactly what murmur would give them.
///
/// This suite exists so that "compatible with the shipped client" is a named,
/// tested thing rather than an accident of defaults. It is the only place in the
/// server where a legacy primitive is chosen, and it says why.
#[derive(Debug, Clone, Copy, Default)]
pub struct LegacySuite;

impl SecuritySuite for LegacySuite {
    fn name(&self) -> &'static str {
        "legacy (stock Mumble)"
    }

    fn tls_floor(&self) -> TlsFloor {
        // 1.2, not 1.3: some stock clients are built against OpenSSL versions
        // predating TLS 1.3, and locking them out would break the acceptance
        // rule. Still stricter than murmur's TLS 1.0.
        TlsFloor::Tls12
    }

    fn voice_cipher(&self) -> &dyn VoiceCipherSpec {
        &Ocb2Aes128Spec
    }

    fn is_baseline(&self) -> bool {
        true
    }
}

/// What Fancy Mumble clients get: modern primitives throughout.
///
/// Selected only for peers that announced a Fancy version, so raising anything
/// here can never lock out a stock client.
#[derive(Debug, Clone, Copy, Default)]
pub struct FancySuite;

impl SecuritySuite for FancySuite {
    fn name(&self) -> &'static str {
        "modern (Fancy Mumble)"
    }

    fn tls_floor(&self) -> TlsFloor {
        TlsFloor::Tls13
    }

    fn voice_cipher(&self) -> &dyn VoiceCipherSpec {
        &XChaCha20Poly1305Spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::CipherStanding;

    fn all() -> Vec<Box<dyn SecuritySuite>> {
        vec![Box::new(LegacySuite), Box::new(FancySuite)]
    }

    /// The contract every suite must satisfy.
    fn assert_suite_contract(suite: &dyn SecuritySuite) {
        assert!(!suite.name().is_empty());
        // A suite must name a usable cipher, whatever its standing.
        assert!(suite.voice_cipher().key_len() >= 16);
    }

    #[test]
    fn every_suite_satisfies_the_contract() {
        for suite in all() {
            assert_suite_contract(suite.as_ref());
        }
    }

    #[test]
    fn exactly_one_suite_is_the_baseline() {
        // Two baselines would make the fallback for an unknown peer ambiguous;
        // none would leave it undefined.
        let baselines: Vec<_> = all()
            .iter()
            .filter(|s| s.is_baseline())
            .map(|s| s.name())
            .collect();
        assert_eq!(baselines, vec!["legacy (stock Mumble)"]);
    }

    #[test]
    fn the_baseline_suite_is_the_one_stock_clients_can_speak() {
        let suite = LegacySuite;
        assert_eq!(suite.tls_floor(), TlsFloor::Tls12);
        assert_eq!(suite.voice_cipher().wire_id(), 0, "stock clients assume 0");
    }

    #[test]
    fn the_fancy_suite_is_strictly_stronger_than_the_baseline() {
        // The whole point of the upgrade path. If this ever stops holding, the
        // two suites have no reason to be separate.
        assert!(FancySuite.tls_floor() > LegacySuite.tls_floor());
        assert!(
            FancySuite.voice_cipher().standing() > LegacySuite.voice_cipher().standing(),
            "the modern suite must not use a legacy cipher"
        );
    }

    #[test]
    fn the_fancy_suite_uses_no_legacy_primitive() {
        assert_eq!(FancySuite.voice_cipher().standing(), CipherStanding::Modern);
        assert_eq!(FancySuite.tls_floor(), TlsFloor::Tls13);
    }

    #[test]
    fn suites_choose_distinct_ciphers() {
        assert_ne!(
            LegacySuite.voice_cipher().wire_id(),
            FancySuite.voice_cipher().wire_id()
        );
    }
}
