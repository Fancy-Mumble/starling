//! Per-peer security negotiation (Abstract Factory + Strategy).
//!
//! # The problem
//!
//! Mumble's transport security is showing its age. Two specifics:
//!
//! * **OCB2-AES128**, the UDP voice cipher, has a practical forgery attack
//!   (Inoue-Iwata-Minematsu-Poettering, CRYPTO 2019). Mumble's framing limits
//!   the exposure, but it is not a cipher anyone would choose today.
//! * murmur accepts **TLS 1.0 and later** (`Server.cpp:1671`).
//!
//! Starling cannot simply fix either: the acceptance rule is that the shipped
//! **stock Mumble client must keep working** (`SERVER-COVERAGE.md`). What it can
//! do is stop treating "what the oldest client needs" as "what every client
//! gets".
//!
//! # The design
//!
//! Security choices come in coherent *families*, a TLS floor and a voice cipher
//! that make sense together. That is an Abstract Factory:
//!
//! ```text
//!   PeerCapabilities ──► SecurityPolicy (Strategy) ──► SecuritySuite (product family)
//!                          │                             ├── tls_floor()  -> TlsFloor
//!                          ├── CompatibilityFirst        └── voice_cipher() -> &dyn VoiceCipherSpec
//!                          └── ModernOnly
//!
//!   SecuritySuite: LegacySuite (TLS 1.2+, OCB2-AES128)
//!                  FancySuite  (TLS 1.3,  ChaCha20-Poly1305)
//! ```
//!
//! A stock client announces no Fancy version, gets [`LegacySuite`], and behaves
//! exactly as it does against murmur. A Fancy client announces one, gets
//! [`FancySuite`], and is held to modern primitives. Neither branch is a special
//! case in a handler, the negotiation happens once and the result is carried on
//! the connection.
//!
//! Note that rustls does not implement TLS 1.0 or 1.1 **at all**, so Starling's
//! floor is 1.2 even in the most permissive configuration. That is already a
//! meaningful improvement over murmur, for free.
//!
//! # Status
//!
//! Both suites are negotiated, recorded and implemented: [`ocb2`] for the
//! legacy branch, [`modern`] and [`voice`] for the Fancy one, with the TLS
//! floor enforced either way.

mod cipher;
pub mod identity;
pub mod keys;
pub mod modern;
pub mod ocb2;
pub mod peer_cert;
mod policy;
pub mod profile;
pub mod session;
pub mod stream;
mod suite;
mod tls;
pub mod voice;

pub use cipher::{Ocb2Aes128Spec, VoiceCipherSpec, XChaCha20Poly1305Spec};
pub use keys::{
    KeyGenerationFailed, LegacyKeys, MalformedKeys, OCB2_KEY_LEN, ResyncRequest, VoiceKeys,
    VoiceSecrets,
};
pub use modern::XChaCha20Voice;
pub use ocb2::Ocb2;
pub use peer_cert::{AcceptAnyClientCertificate, PeerCertificate};
pub use policy::{CompatibilityFirst, ModernOnly, SecurityPolicy};
pub use profile::{
    CompatibilityFirstProfiles, ModernOnlyProfiles, ProfileError, ProfileFactory, VoiceProfile,
    spec_for,
};
pub use session::{MASTER_KEY_LEN, SALT_LEN, VoiceError, VoiceSession};
pub use stream::{CryptStats, VoiceCipher};
pub use suite::{FancySuite, LegacySuite, SecuritySuite};
pub use tls::TlsFloor;
pub use voice::{CounterExhausted, Direction, PacketCounter, Rejected, Sequence, SequenceWindow};

use starling_proto::Version;

/// What a peer told us it can do.
///
/// Built from the `Version` message, which is the only thing a client sends
/// before any security decision has to be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerCapabilities {
    /// The Mumble version the peer announced.
    pub version: Version,
    /// The Fancy extension version, if the peer announced one.
    ///
    /// Presence is the signal that the peer understands the modern suite. It is
    /// deliberately *not* inferred from the Mumble version: a fork could ship
    /// Mumble 1.6 without the Fancy extensions.
    pub fancy_version: Option<u64>,
}

impl PeerCapabilities {
    /// Capabilities for a peer that announced nothing (the safe default).
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            version: Version::new(0, 0, 0),
            fancy_version: None,
        }
    }

    /// Whether the peer understands Fancy Mumble extensions.
    #[must_use]
    pub fn is_fancy(&self) -> bool {
        self.fancy_version.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_peer_is_not_treated_as_fancy() {
        // Failing open here would hand a stock client a suite it cannot speak.
        assert!(!PeerCapabilities::unknown().is_fancy());
    }

    #[test]
    fn fancy_support_comes_from_the_fancy_version_not_the_mumble_version() {
        // A fork could ship Mumble 1.6 without the extensions.
        let modern_but_stock = PeerCapabilities {
            version: Version::new(1, 6, 0),
            fancy_version: None,
        };
        assert!(!modern_but_stock.is_fancy());

        let old_but_fancy = PeerCapabilities {
            version: Version::new(1, 4, 0),
            fancy_version: Some(Version::new(0, 3, 0).encode_v2()),
        };
        assert!(old_but_fancy.is_fancy());
    }
}
