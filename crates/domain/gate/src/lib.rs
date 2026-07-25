//! `starling-gate` — what a peer is allowed to be given.
//!
//! One table maps each capability to the Fancy Mumble version that introduced
//! it. Everything that varies by client version asks this crate; nothing decides
//! for itself.
//!
//! # The bug this exists to stop
//!
//! Negotiation used to branch on `peer.is_fancy()` — *does this client announce
//! any Fancy version at all*. That handed a Fancy 0.1.0 client the modern cipher
//! suite, because the check could not tell 0.1.0 from 0.4.0. Announcing the
//! extension is not the same as implementing a capability added later.
//!
//! # Absent means oldest, never newest
//!
//! A peer with no `fancy_version` is a stock Mumble client. It gets the fallback
//! for everything: [`Gate::allows`] is `false` for every capability, so a new
//! capability is opt-in by construction and cannot be handed to a client that
//! never claimed it.

pub mod version;
pub mod voice;

pub use version::FancyVersion;
pub use voice::{AudioCodec, CipherChoice, MumbleVersion, UdpFormat, PROTOBUF_UDP_SINCE};

/// Declare capabilities and the version that introduced each.
///
/// Mirrors the client's `fancy_message_support!` table deliberately: two tables
/// in two crates will drift, and the least-bad mitigation is that they are
/// recognisably the same shape and each cites the other.
macro_rules! capabilities {
    ($($(#[$doc:meta])* ($major:literal, $minor:literal, $patch:literal) $variant:ident),* $(,)?) => {
        /// Something a client can only be given from a particular version.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum Capability {
            $($(#[$doc])* $variant,)*
        }

        impl Capability {
            /// The first version that has it.
            #[must_use]
            pub const fn since(self) -> FancyVersion {
                match self {
                    $(Self::$variant => FancyVersion::new($major, $minor, $patch),)*
                }
            }

            /// Every capability, for diagnostics and exhaustiveness tests.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[$(Self::$variant,)*]
            }

            /// A stable name for logs and the admin API.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => ::core::stringify!($variant),)*
                }
            }
        }
    };
}

capabilities! {
    /// Fancy extension message types (100+) understood natively, rather than
    /// tunnelled through `PluginDataTransmission`.
    ///
    /// Matches the client's `FANCY_NATIVE_MIN_VERSION`.
    (0, 2, 12) NativeFancyMessages,

    /// Modern voice encryption instead of Mumble's OCB2-AES128.
    ///
    /// OCB2 has a practical forgery attack (Inoue, Iwata, Minematsu and
    /// Poettering, CRYPTO 2019). Mumble's framing limits the exposure, but it is
    /// not a cipher anyone would choose today, so a client that can do better is
    /// given better and one that cannot keeps working.
    ///
    /// A breaking change on the wire, which is why it lands on a minor bump.
    (0, 4, 0) ModernVoiceCrypto,
}

/// What one peer may be given, decided from the version it announced.
///
/// Cheap to construct and copy: build one per peer at handshake and consult it,
/// rather than passing a raw `Option<u64>` around and re-deriving the answer at
/// each decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gate {
    announced: Option<FancyVersion>,
}

impl Gate {
    /// The gate for a peer that announced `fancy_version` in its `Version`
    /// message. `None` is a stock Mumble client.
    #[must_use]
    pub const fn for_peer(fancy_version: Option<u64>) -> Self {
        Self {
            announced: match fancy_version {
                Some(encoded) => Some(FancyVersion::from_wire(encoded)),
                None => None,
            },
        }
    }

    /// A gate that allows nothing: a stock client.
    #[must_use]
    pub const fn stock() -> Self {
        Self { announced: None }
    }

    /// Whether the peer announced the Fancy extensions at all.
    ///
    /// Rarely the right question. Prefer [`Self::allows`], which distinguishes
    /// *which* Fancy version; this exists for logging and for the handshake,
    /// which genuinely only needs to know whether to reply with a version.
    #[must_use]
    pub const fn is_fancy(&self) -> bool {
        self.announced.is_some()
    }

    /// The version the peer announced, if any.
    #[must_use]
    pub const fn version(&self) -> Option<FancyVersion> {
        self.announced
    }

    /// Whether the peer is new enough for `capability`.
    ///
    /// `false` for a stock client, always: absent means oldest.
    #[must_use]
    pub fn allows(&self, capability: Capability) -> bool {
        self.announced
            .is_some_and(|announced| announced >= capability.since())
    }

    /// Which voice cipher this peer gets.
    ///
    /// The whole point of the gate, in one call: a peer that cannot do the modern
    /// cipher is given the one every Mumble client has always assumed, rather
    /// than one it cannot speak.
    #[must_use]
    pub fn voice_cipher(&self) -> CipherChoice {
        if self.allows(Capability::ModernVoiceCrypto) {
            CipherChoice::XChaCha20Poly1305
        } else {
            CipherChoice::Ocb2Aes128
        }
    }

    /// Every capability this peer has, for one log line at handshake.
    #[must_use]
    pub fn granted(&self) -> Vec<Capability> {
        Capability::all()
            .iter()
            .copied()
            .filter(|c| self.allows(*c))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stock_client_is_allowed_nothing() {
        // The property that makes a new capability safe to add: a client that
        // never claimed it cannot be handed it.
        let stock = Gate::stock();
        assert!(!stock.is_fancy());
        for capability in Capability::all() {
            assert!(
                !stock.allows(*capability),
                "{} was granted to a stock client",
                capability.name()
            );
        }
        assert!(stock.granted().is_empty());
    }

    #[test]
    fn an_absent_version_is_the_same_as_stock() {
        assert_eq!(Gate::for_peer(None), Gate::stock());
    }

    #[test]
    fn an_old_fancy_client_does_not_get_a_newer_capability() {
        // The bug this crate exists for: 0.1.0 announces Fancy support but
        // predates both capabilities.
        let old = Gate::for_peer(Some(FancyVersion::new(0, 1, 0).to_wire()));
        assert!(old.is_fancy(), "it did announce Fancy support");
        assert!(!old.allows(Capability::NativeFancyMessages));
        assert!(!old.allows(Capability::ModernVoiceCrypto));
    }

    #[test]
    fn the_introducing_version_itself_qualifies() {
        // `>=`, not `>`: the release that adds a capability has it.
        for capability in Capability::all() {
            let exact = Gate::for_peer(Some(capability.since().to_wire()));
            assert!(
                exact.allows(*capability),
                "{} excluded the version that introduced it",
                capability.name()
            );
        }
    }

    #[test]
    fn the_current_client_gets_the_modern_cipher() {
        // `mumble-protocol` 0.4.0, which is the bump that carries the breaking
        // voice-crypto change.
        let current = Gate::for_peer(Some(FancyVersion::new(0, 4, 0).to_wire()));
        assert!(current.allows(Capability::ModernVoiceCrypto));
        assert!(current.allows(Capability::NativeFancyMessages));
    }

    #[test]
    fn the_previous_client_keeps_ocb2() {
        // 0.3.0 shipped before the new cipher existed, so it must keep getting
        // the legacy one rather than a suite it cannot speak.
        let previous = Gate::for_peer(Some(FancyVersion::new(0, 3, 0).to_wire()));
        assert!(previous.allows(Capability::NativeFancyMessages));
        assert!(
            !previous.allows(Capability::ModernVoiceCrypto),
            "0.3.0 must not be given a 0.4.0 capability"
        );
    }

    #[test]
    fn a_future_client_keeps_everything() {
        let future = Gate::for_peer(Some(FancyVersion::new(9, 0, 0).to_wire()));
        assert_eq!(future.granted().len(), Capability::all().len());
    }

    #[test]
    fn every_capability_has_a_distinct_name() {
        let mut names: Vec<_> = Capability::all().iter().map(|c| c.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two capabilities share a name");
    }
}
