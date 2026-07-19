//! The two version axes that decide how voice reaches a peer.
//!
//! They are independent, and conflating them is the classic Mumble porting bug:
//!
//! | Axis | Threshold | Decides |
//! |---|---|---|
//! | Mumble protocol version | **1.5.0** | which UDP wire format |
//! | Fancy version | **0.4.0** | which voice cipher |
//!
//! A stock Mumble 1.6 client is modern on the first axis and absent on the
//! second. A Fancy 0.4 client running on a 1.4-era protocol would be the
//! reverse. Deciding both from one number would get one of them wrong.
//!
//! Descriptors, not implementations: this crate returns an enum and stays
//! dependency-free. `starling-crypto` maps [`CipherChoice`] onto a
//! `VoiceCipherSpec`, which is why the dependency runs crypto -> gate and not
//! the other way.

/// The UDP audio wire format a peer speaks.
///
/// Upstream calls the boundary `PROTOBUF_INTRODUCTION_VERSION`
/// (`src/MumbleProtocol.h`) and treats it as the *only* thing the protocol
/// version still decides: its `protocolVersionsAreCompatible` compares nothing
/// but which side of 1.5.0 each peer falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UdpFormat {
    /// Pre-1.5.0: a hand-rolled binary framing with a type byte per codec.
    ///
    /// Upstream's `LegacyUDPMessageType` has five variants, CELT alpha, Ping,
    /// Speex, CELT beta, Opus, because the codec was part of the packet type
    /// rather than a field. Any client older than 1.5.0 speaks only this, which
    /// includes every Mumble release from 1.2 through 1.4.
    Legacy,

    /// 1.5.0 and later: protobuf-framed audio with the codec as a field.
    Protobuf,
}

/// The audio codec a packet carries.
///
/// Ordered worst-to-best so "prefer the best both sides have" is a `max()`.
/// Upstream's `AudioCodec` enum, with the release that introduced each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AudioCodec {
    /// Mumble 0.7.0 era. Long dead, still in the legacy framing.
    CeltAlpha,
    /// Mumble 0.11.0 era.
    CeltBeta,
    /// Never widely used for voice by the time Opus existed.
    Speex,
    /// The only codec any current client negotiates.
    Opus,
}

/// Which voice cipher a peer gets.
///
/// A descriptor rather than a spec so this crate needs no cryptography
/// dependency; `starling-crypto::for_choice` turns it into a spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CipherChoice {
    /// OCB2-AES128, what every stock Mumble client assumes without negotiating.
    Ocb2Aes128,
    /// XChaCha20-Poly1305 + HKDF-SHA256, for Fancy 0.4.0 and later.
    XChaCha20Poly1305,
}

/// The Mumble release that replaced the hand-rolled UDP framing with protobuf.
///
/// Upstream: `PROTOBUF_INTRODUCTION_VERSION` in `src/MumbleProtocol.h`.
pub const PROTOBUF_UDP_SINCE: MumbleVersion = MumbleVersion::new(1, 5, 0);

/// A Mumble protocol version, in the v2 encoding.
///
/// Separate from [`FancyVersion`](crate::FancyVersion) despite sharing the
/// encoding: they are different numbers with different thresholds, and one type
/// for both invites comparing a Mumble version against a Fancy threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MumbleVersion(u64);

impl MumbleVersion {
    /// Build from parts.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self(((major as u64) << 48) | ((minor as u64) << 32) | ((patch as u64) << 16))
    }

    /// Wrap a value received on the wire.
    #[must_use]
    pub const fn from_wire(encoded: u64) -> Self {
        Self(encoded)
    }

    /// The wire encoding.
    #[must_use]
    pub const fn to_wire(self) -> u64 {
        self.0
    }

    /// The parts.
    #[must_use]
    pub const fn parts(self) -> (u16, u16, u16) {
        (
            ((self.0 >> 48) & 0xFFFF) as u16,
            ((self.0 >> 32) & 0xFFFF) as u16,
            ((self.0 >> 16) & 0xFFFF) as u16,
        )
    }

    /// The UDP framing this version speaks.
    #[must_use]
    pub const fn udp_format(self) -> UdpFormat {
        if self.0 >= PROTOBUF_UDP_SINCE.0 {
            UdpFormat::Protobuf
        } else {
            UdpFormat::Legacy
        }
    }

    /// Whether two peers can exchange audio without transcoding the framing.
    ///
    /// Upstream's `protocolVersionsAreCompatible`: the only thing that matters is
    /// whether both sides are on the same side of 1.5.0.
    #[must_use]
    pub const fn framing_matches(self, other: Self) -> bool {
        matches!(
            (self.udp_format(), other.udp_format()),
            (UdpFormat::Legacy, UdpFormat::Legacy) | (UdpFormat::Protobuf, UdpFormat::Protobuf)
        )
    }
}

impl std::fmt::Display for MumbleVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.parts();
        write!(f, "{major}.{minor}.{patch}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_release_before_1_5_speaks_the_legacy_framing() {
        // The versions that actually exist in the wild, not just the boundary.
        for (major, minor, patch) in [(1, 2, 0), (1, 2, 19), (1, 3, 0), (1, 4, 0), (1, 4, 287)] {
            assert_eq!(
                MumbleVersion::new(major, minor, patch).udp_format(),
                UdpFormat::Legacy,
                "{major}.{minor}.{patch} predates protobuf UDP"
            );
        }
    }

    #[test]
    fn the_introducing_release_itself_is_protobuf() {
        // `>=`, matching upstream's comparison against the threshold.
        assert_eq!(PROTOBUF_UDP_SINCE.udp_format(), UdpFormat::Protobuf);
        assert_eq!(
            MumbleVersion::new(1, 5, 0).udp_format(),
            UdpFormat::Protobuf
        );
        assert_eq!(
            MumbleVersion::new(1, 6, 0).udp_format(),
            UdpFormat::Protobuf
        );
    }

    #[test]
    fn an_unknown_version_falls_back_to_the_legacy_framing() {
        // A client that announced nothing decodes as 0.0.0. Guessing protobuf
        // would make its first voice packet undecodable; guessing legacy is the
        // format every client has ever understood.
        assert_eq!(MumbleVersion::from_wire(0).udp_format(), UdpFormat::Legacy);
    }

    #[test]
    fn framing_compatibility_only_asks_which_side_of_1_5() {
        let old = MumbleVersion::new(1, 4, 0);
        let older = MumbleVersion::new(1, 2, 0);
        let new = MumbleVersion::new(1, 5, 0);
        let newer = MumbleVersion::new(1, 6, 0);

        assert!(old.framing_matches(older), "both legacy");
        assert!(new.framing_matches(newer), "both protobuf");
        assert!(!old.framing_matches(new), "across the boundary");
        assert!(!newer.framing_matches(older), "across the boundary");
    }

    #[test]
    fn codecs_order_worst_to_best() {
        // So "prefer the best available" is a max() rather than a match.
        assert!(AudioCodec::Opus > AudioCodec::Speex);
        assert!(AudioCodec::Speex > AudioCodec::CeltBeta);
        assert!(AudioCodec::CeltBeta > AudioCodec::CeltAlpha);
    }

    #[test]
    fn the_two_axes_are_independent() {
        // A stock 1.6 client: modern framing, no Fancy crypto. The pairing that
        // a single version number could not express.
        let stock_modern = MumbleVersion::new(1, 6, 0);
        assert_eq!(stock_modern.udp_format(), UdpFormat::Protobuf);
        assert!(!crate::Gate::stock().allows(crate::Capability::ModernVoiceCrypto));
    }
}
