//! Mumble version encodings.
//!
//! Mumble carries a version three ways in one `Version` message:
//!
//! | Field | Encoding | Why |
//! |---|---|---|
//! | `version_v1` | `(major << 16) \| (minor << 8) \| patch`, `u32` | Legacy. Patch is capped at 255. |
//! | `version_v2` | `(major << 48) \| (minor << 32) \| (patch << 16)`, `u64` | Current. Added because patch levels exceeded 255 (mumble-voip/mumble#5827). |
//! | `fancy_version` | same layout as v2, `u64` | Fancy fork extension. Presence on both sides means Fancy messages are understood. |
//!
//! Starling sends all three: v1 and v2 so stock clients work, `fancy_version` so
//! the FancyMumble client enables its extensions.

use crate::proto::tcp;

/// A Mumble `major.minor.patch` version.
///
/// `Default` is `0.0.0`, which fails every `>=` feature gate, the safe
/// direction for a peer that has not told us what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Version {
    /// Major component (the **1** in 1.6.0).
    pub major: u16,
    /// Minor component (the **6** in 1.6.0).
    pub minor: u16,
    /// Patch component (the **0** in 1.6.0).
    pub patch: u16,
}

impl Version {
    /// Construct a version from its components.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Legacy v1 encoding: `(major << 16) | (minor << 8) | patch`.
    ///
    /// Lossy above patch 255; that is exactly why v2 exists. Kept because
    /// pre-1.5 clients read only this field.
    #[must_use]
    pub const fn encode_v1(self) -> u32 {
        ((self.major as u32) << 16) | ((self.minor as u32) << 8) | (self.patch as u32)
    }

    /// Current v2 encoding: `(major << 48) | (minor << 32) | (patch << 16)`.
    #[must_use]
    pub const fn encode_v2(self) -> u64 {
        ((self.major as u64) << 48) | ((self.minor as u64) << 32) | ((self.patch as u64) << 16)
    }

    /// Decode a v2-encoded version.
    #[must_use]
    pub const fn decode_v2(v: u64) -> Self {
        Self::new(
            ((v >> 48) & 0xFFFF) as u16,
            ((v >> 32) & 0xFFFF) as u16,
            ((v >> 16) & 0xFFFF) as u16,
        )
    }

    /// Decode a legacy v1-encoded version.
    #[must_use]
    pub const fn decode_v1(v: u32) -> Self {
        Self::new(
            ((v >> 16) & 0xFFFF) as u16,
            ((v >> 8) & 0xFF) as u16,
            (v & 0xFF) as u16,
        )
    }

    /// Read a peer's version from a `Version` message, preferring v2.
    ///
    /// A client that sends only `version_v1` (pre-1.5) still resolves correctly;
    /// one that sends neither is reported as `0.0.0`, which fails every
    /// `>=` feature gate, the safe direction.
    #[must_use]
    pub fn from_message(msg: &tcp::Version) -> Self {
        match (msg.version_v2, msg.version_v1) {
            (Some(v2), _) => Self::decode_v2(v2),
            (None, Some(v1)) => Self::decode_v1(v1),
            (None, None) => Self::new(0, 0, 0),
        }
    }
}

/// The Mumble version Starling implements.
///
/// One constant, because a server reports its version on two unrelated paths,
/// the `Version` message at the top of the handshake, and the UDP ping a server
/// browser sends before connecting at all, and the two disagreeing is a bug
/// nothing fails on. Both paths encode *this*.
pub const MUMBLE_VERSION: Version = Version::new(1, 6, 0);

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_matches_the_documented_layout() {
        assert_eq!(Version::new(1, 6, 0).encode_v1(), 0x0001_0600);
        assert_eq!(Version::decode_v1(0x0001_0600), Version::new(1, 6, 0));
    }

    #[test]
    fn v2_matches_the_documented_layout() {
        assert_eq!(Version::new(1, 6, 0).encode_v2(), 0x0001_0006_0000_0000);
        assert_eq!(
            Version::decode_v2(0x0001_0006_0000_0000),
            Version::new(1, 6, 0)
        );
    }

    #[test]
    fn the_announced_version_is_encoded_at_the_documented_offsets() {
        // A v2 version written as a literal is off by sixteen bits if the patch
        // shift is forgotten, and the result is a plausible-looking number that
        // decodes to a completely different release: 0x0001_0006_0000 is 0.1.6,
        // not 1.6.0. Nothing on either path fails on that, the handshake
        // completes and the ping is answered, so it is asserted here.
        assert_eq!(MUMBLE_VERSION.encode_v2(), 0x0001_0006_0000_0000);
        assert_eq!(
            Version::decode_v2(MUMBLE_VERSION.encode_v2()),
            MUMBLE_VERSION
        );
        assert_eq!(MUMBLE_VERSION.to_string(), "1.6.0");
    }

    #[test]
    fn v2_survives_patch_levels_v1_cannot_represent() {
        let v = Version::new(1, 6, 300);
        assert_eq!(Version::decode_v2(v.encode_v2()), v);
        // The whole reason v2 exists: v1 truncates patch to 8 bits.
        assert_ne!(Version::decode_v1(v.encode_v1()), v);
    }

    #[test]
    fn v2_is_preferred_over_v1_when_both_are_present() {
        let msg = tcp::Version {
            version_v1: Some(Version::new(1, 2, 3).encode_v1()),
            version_v2: Some(Version::new(1, 6, 300).encode_v2()),
            ..Default::default()
        };
        assert_eq!(Version::from_message(&msg), Version::new(1, 6, 300));
    }

    #[test]
    fn legacy_client_sending_only_v1_still_resolves() {
        let msg = tcp::Version {
            version_v1: Some(Version::new(1, 2, 3).encode_v1()),
            ..Default::default()
        };
        assert_eq!(Version::from_message(&msg), Version::new(1, 2, 3));
    }

    #[test]
    fn absent_version_fails_feature_gates_rather_than_passing_them() {
        let v = Version::from_message(&tcp::Version::default());
        assert_eq!(v, Version::new(0, 0, 0));
        assert!(v < Version::new(1, 2, 2));
    }

    #[test]
    fn ordering_is_by_component_not_encoding() {
        assert!(Version::new(1, 6, 0) > Version::new(1, 5, 9));
        assert!(Version::new(1, 2, 2) > Version::new(1, 2, 1));
        assert!(Version::new(2, 0, 0) > Version::new(1, 99, 99));
    }
}
