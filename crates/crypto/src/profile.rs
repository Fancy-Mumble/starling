//! Building one peer's voice profile (Abstract Factory).
//!
//! A peer is not "modern" or "legacy" — it sits somewhere on two independent
//! axes, and the products it needs must agree with each other:
//!
//! | Axis | Threshold | Product |
//! |---|---|---|
//! | Mumble protocol version | 1.5.0 | [`UdpFormat`] |
//! | Fancy version | 0.4.0 | [`VoiceCipherSpec`] |
//!
//! [`VoiceProfile`] is the product family; [`ProfileFactory`] is the factory that
//! chooses one. The factory is a trait so a deployment can refuse a combination
//! it does not want to serve — [`ModernOnlyProfiles`] does exactly that — without
//! the connection code learning a second way to decide.
//!
//! # Why a family rather than two independent lookups
//!
//! Because they constrain each other. A pre-1.5.0 client cannot carry a
//! negotiated cipher id in its framing: the legacy packet type *is* the codec,
//! with no room for a cipher field. So "legacy framing plus modern cipher" is not
//! a combination the wire can express, and a factory that returned the two
//! separately would let a caller build it. [`VoiceProfile::new`] cannot.

use starling_gate::{CipherChoice, Gate, MumbleVersion, UdpFormat};

use crate::cipher::{Ocb2Aes128Spec, VoiceCipherSpec, XChaCha20Poly1305Spec};

/// The specification for a [`CipherChoice`].
///
/// The only place a descriptor becomes an implementation, which is what keeps
/// `starling-gate` free of cryptography.
#[must_use]
pub fn spec_for(choice: CipherChoice) -> Box<dyn VoiceCipherSpec> {
    match choice {
        CipherChoice::Ocb2Aes128 => Box::new(Ocb2Aes128Spec),
        CipherChoice::XChaCha20Poly1305 => Box::new(XChaCha20Poly1305Spec),
    }
}

/// Who encrypts the audio.
///
/// Framing and confidentiality were bundled while UDP was the only transport,
/// because UDP answers both the same way: we frame it, we encrypt it. They are
/// two questions, and a transport that provides its own encryption — QUIC, under
/// TLS 1.3 — answers them differently.
///
/// Mumble voice is server-relayed, so the application cipher protects exactly the
/// client-to-server hop that QUIC would. Running both would encrypt twice for no
/// added guarantee.
#[derive(Debug)]
pub enum Confidentiality {
    /// The application encrypts: a cipher negotiated per peer.
    ///
    /// Carries the choice as well as the spec because the two are one decision:
    /// the spec is what the packet path needs and the choice is what the key
    /// generator needs, and re-deriving either from the other means a comparison
    /// that can be got wrong.
    Application {
        /// Which cipher was negotiated.
        choice: CipherChoice,
        /// What it reports about itself.
        spec: Box<dyn VoiceCipherSpec>,
    },

    /// The transport already encrypts, so the application must not.
    Transport,
}

impl Confidentiality {
    /// The negotiated cipher, or `None` when the transport provides it.
    #[must_use]
    pub fn cipher(&self) -> Option<&dyn VoiceCipherSpec> {
        match self {
            Self::Application { spec, .. } => Some(spec.as_ref()),
            Self::Transport => None,
        }
    }
}

/// Everything the voice path needs to serve one peer.
///
/// Built once at handshake and carried on the connection, so no packet-time code
/// re-derives it from version numbers.
#[derive(Debug)]
pub struct VoiceProfile {
    format: UdpFormat,
    confidentiality: Confidentiality,
}

impl VoiceProfile {
    /// Build a profile, enforcing that the two axes agree.
    ///
    /// # Errors
    ///
    /// [`ProfileError::UnrepresentableCombination`] when the framing cannot carry
    /// the cipher. This is not defensive programming: the legacy packet type is
    /// the codec, so there is nowhere to put a cipher id, and a peer given this
    /// pairing would fail to decode its first packet.
    pub fn new(format: UdpFormat, choice: CipherChoice) -> Result<Self, ProfileError> {
        if format == UdpFormat::Legacy && choice != CipherChoice::Ocb2Aes128 {
            return Err(ProfileError::UnrepresentableCombination { format, choice });
        }
        Ok(Self {
            format,
            confidentiality: Confidentiality::Application {
                choice,
                spec: spec_for(choice),
            },
        })
    }

    /// A profile for a transport that encrypts on our behalf.
    ///
    /// No cipher is negotiated and no keys are exchanged: `CryptSetup` and the
    /// packet counter are UDP concerns, and a transport with its own encryption
    /// has neither.
    #[must_use]
    pub fn transport_encrypted(format: UdpFormat) -> Self {
        Self {
            format,
            confidentiality: Confidentiality::Transport,
        }
    }

    /// The UDP framing to speak to this peer.
    #[must_use]
    pub fn format(&self) -> UdpFormat {
        self.format
    }

    /// Which cipher this peer's key material must be generated for.
    ///
    /// Derived from the negotiated spec rather than stored beside it, so the
    /// two cannot disagree — a stored tag is a second source of truth about the
    /// same decision.
    #[must_use]
    pub fn cipher_choice(&self) -> Option<CipherChoice> {
        match &self.confidentiality {
            Confidentiality::Application { choice, .. } => Some(*choice),
            // A transport that encrypts on our behalf needs no key material from
            // us. `None` says so; a default would have the caller generate keys
            // nothing will ever use.
            Confidentiality::Transport => None,
        }
    }

    /// Who encrypts this peer's audio.
    #[must_use]
    pub fn confidentiality(&self) -> &Confidentiality {
        &self.confidentiality
    }

    /// The cipher to encrypt with, or `None` when the transport does it.
    #[must_use]
    pub fn cipher(&self) -> Option<&dyn VoiceCipherSpec> {
        self.confidentiality.cipher()
    }
}

/// Why a peer could not be given a voice profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The framing cannot carry the cipher.
    #[error("{format:?} framing cannot carry {choice:?}: the legacy packet type is the codec")]
    UnrepresentableCombination {
        /// The framing involved.
        format: UdpFormat,
        /// The cipher that does not fit it.
        choice: CipherChoice,
    },

    /// The policy declines to serve this peer at all.
    #[error("this deployment does not serve {format:?} framing with {choice:?}")]
    Refused {
        /// The framing involved.
        format: UdpFormat,
        /// The cipher involved.
        choice: CipherChoice,
    },
}

/// Chooses the product family for a peer.
///
/// A trait so a deployment can install a stricter factory without the connection
/// code changing: it asks for a profile and either gets one or a reason.
pub trait ProfileFactory: std::fmt::Debug + Send + Sync {
    /// A short name for logs and the admin API.
    fn name(&self) -> &'static str;

    /// Build the profile for a peer.
    ///
    /// # Errors
    ///
    /// [`ProfileError`] when the peer cannot be served.
    fn build(&self, mumble: MumbleVersion, gate: Gate) -> Result<VoiceProfile, ProfileError>;
}

/// The default: serve everyone the best their two versions allow.
///
/// A 1.2-era client gets legacy framing and OCB2 and works exactly as it does
/// against murmur. A Fancy 0.4 client on 1.6 gets protobuf framing and
/// XChaCha20-Poly1305. Nobody is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompatibilityFirstProfiles;

impl ProfileFactory for CompatibilityFirstProfiles {
    fn name(&self) -> &'static str {
        "compatibility-first"
    }

    fn build(&self, mumble: MumbleVersion, gate: Gate) -> Result<VoiceProfile, ProfileError> {
        let format = mumble.udp_format();
        // A legacy peer gets OCB2 whatever its Fancy version claims: the framing
        // is the binding constraint, and downgrading here is what keeps the
        // combination representable rather than erroring at packet time.
        let choice = match format {
            UdpFormat::Legacy => CipherChoice::Ocb2Aes128,
            UdpFormat::Protobuf => gate.voice_cipher(),
        };
        VoiceProfile::new(format, choice)
    }
}

/// Refuse anything that cannot do the modern cipher.
///
/// **Opt-in**, for deployments that control their client fleet. Refusing is the
/// point: a silent downgrade would defeat it.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModernOnlyProfiles;

impl ProfileFactory for ModernOnlyProfiles {
    fn name(&self) -> &'static str {
        "modern-only"
    }

    fn build(&self, mumble: MumbleVersion, gate: Gate) -> Result<VoiceProfile, ProfileError> {
        let format = mumble.udp_format();
        let choice = gate.voice_cipher();
        if format != UdpFormat::Protobuf || choice != CipherChoice::XChaCha20Poly1305 {
            return Err(ProfileError::Refused { format, choice });
        }
        VoiceProfile::new(format, choice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_gate::{Capability, FancyVersion};

    fn fancy(major: u16, minor: u16, patch: u16) -> Gate {
        Gate::for_peer(Some(FancyVersion::new(major, minor, patch).to_wire()))
    }

    /// The client matrix that actually exists in the wild.
    fn matrix() -> Vec<(&'static str, MumbleVersion, Gate)> {
        vec![
            (
                "Mumble 1.2 stock",
                MumbleVersion::new(1, 2, 0),
                Gate::stock(),
            ),
            (
                "Mumble 1.4 stock",
                MumbleVersion::new(1, 4, 0),
                Gate::stock(),
            ),
            (
                "Mumble 1.5 stock",
                MumbleVersion::new(1, 5, 0),
                Gate::stock(),
            ),
            (
                "Mumble 1.6 stock",
                MumbleVersion::new(1, 6, 0),
                Gate::stock(),
            ),
            (
                "Fancy 0.3 on 1.6",
                MumbleVersion::new(1, 6, 0),
                fancy(0, 3, 0),
            ),
            (
                "Fancy 0.4 on 1.6",
                MumbleVersion::new(1, 6, 0),
                fancy(0, 4, 0),
            ),
        ]
    }

    #[test]
    fn compatibility_first_serves_every_client_in_the_matrix() {
        for (name, mumble, gate) in matrix() {
            assert!(
                CompatibilityFirstProfiles.build(mumble, gate).is_ok(),
                "{name} was refused by the default factory"
            );
        }
    }

    #[test]
    fn pre_1_5_clients_get_legacy_framing_and_ocb2() {
        for (name, mumble, gate) in matrix() {
            if mumble.udp_format() != UdpFormat::Legacy {
                continue;
            }
            let profile = CompatibilityFirstProfiles
                .build(mumble, gate)
                .expect("legacy clients are served");
            assert_eq!(profile.format(), UdpFormat::Legacy, "{name}");
            assert_eq!(
                profile.cipher().expect("application cipher").wire_id(),
                0,
                "{name} must get OCB2"
            );
        }
    }

    #[test]
    fn only_a_current_fancy_client_gets_the_modern_cipher() {
        let modern = CompatibilityFirstProfiles
            .build(MumbleVersion::new(1, 6, 0), fancy(0, 4, 0))
            .expect("served");
        assert_eq!(modern.cipher().expect("application cipher").wire_id(), 1);

        for (name, mumble, gate) in matrix() {
            if gate.allows(Capability::ModernVoiceCrypto) {
                continue;
            }
            let profile = CompatibilityFirstProfiles
                .build(mumble, gate)
                .expect("served");
            assert_eq!(
                profile.cipher().expect("application cipher").wire_id(),
                0,
                "{name} must keep OCB2"
            );
        }
    }

    #[test]
    fn a_legacy_peer_claiming_a_modern_fancy_version_is_downgraded_not_broken() {
        // Possible in practice: a Fancy build on an old protocol base. The
        // framing wins, because it is the axis with no room to carry a cipher id.
        let profile = CompatibilityFirstProfiles
            .build(MumbleVersion::new(1, 4, 0), fancy(0, 4, 0))
            .expect("still served");
        assert_eq!(profile.format(), UdpFormat::Legacy);
        assert_eq!(
            profile.cipher().expect("application cipher").wire_id(),
            0,
            "legacy framing cannot carry a negotiated cipher"
        );
    }

    #[test]
    fn the_unrepresentable_combination_cannot_be_constructed() {
        // The factory downgrades rather than producing this, but the constructor
        // is what makes it impossible for any other caller too.
        let err = VoiceProfile::new(UdpFormat::Legacy, CipherChoice::XChaCha20Poly1305)
            .expect_err("legacy framing has nowhere to put a cipher id");
        assert!(matches!(
            err,
            ProfileError::UnrepresentableCombination { .. }
        ));
    }

    #[test]
    fn modern_only_refuses_everything_but_a_current_fancy_client() {
        for (name, mumble, gate) in matrix() {
            let served = ModernOnlyProfiles.build(mumble, gate).is_ok();
            let expected = mumble.udp_format() == UdpFormat::Protobuf
                && gate.allows(Capability::ModernVoiceCrypto);
            assert_eq!(served, expected, "{name}");
        }
    }

    #[test]
    fn factories_are_usable_behind_a_trait_object() {
        // The seam the connection code depends on.
        let factories: Vec<Box<dyn ProfileFactory>> = vec![
            Box::new(CompatibilityFirstProfiles),
            Box::new(ModernOnlyProfiles),
        ];
        let stock = (MumbleVersion::new(1, 6, 0), Gate::stock());
        let outcomes: Vec<_> = factories
            .iter()
            .map(|f| f.build(stock.0, stock.1).is_ok())
            .collect();
        assert_eq!(outcomes, vec![true, false]);
    }
}
