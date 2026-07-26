//! The Fancy Mumble version encoding.
//!
//! Mumble's v2 scheme: `(major << 48) | (minor << 32) | (patch << 16)`. The
//! client encodes it identically in `fancy-utils`; the layout is wire-visible in
//! `Version.fancy_version`, so neither side may change it independently.

/// A Fancy Mumble extension version.
///
/// A newtype rather than a bare `u64` because the encoding is not obvious and a
/// raw number invites comparing a decoded value against an encoded one. Ordering
/// is derived, which is sound: the encoding is monotonic in (major, minor, patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FancyVersion(u64);

impl FancyVersion {
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
}

impl std::fmt::Display for FancyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.parts();
        write!(f, "{major}.{minor}.{patch}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_round_trip() {
        for (a, b, c) in [(0, 0, 0), (0, 2, 12), (0, 4, 0), (1, 6, 0), (65535, 1, 2)] {
            assert_eq!(FancyVersion::new(a, b, c).parts(), (a, b, c));
        }
    }

    #[test]
    fn the_encoding_matches_the_clients() {
        // `fancy_utils::version::fancy_version_encode(0, 2, 12)`. Hard-coded so a
        // change on either side fails here rather than at a peer's decoder.
        // The literal the client's `fancy_version_encode(0, 2, 12)` produces.
        // Spelled out rather than recomputed, so a change to either side's shift
        // arithmetic fails here instead of at a peer's decoder.
        assert_eq!(FancyVersion::new(0, 2, 12).to_wire(), 0x0000_0002_000C_0000);
        assert_eq!(FancyVersion::new(0, 4, 0).to_wire(), 0x0000_0004_0000_0000);
    }

    #[test]
    fn ordering_follows_the_version() {
        assert!(FancyVersion::new(0, 4, 0) > FancyVersion::new(0, 3, 0));
        assert!(FancyVersion::new(0, 2, 12) > FancyVersion::new(0, 2, 11));
        assert!(FancyVersion::new(1, 0, 0) > FancyVersion::new(0, 99, 99));
    }

    #[test]
    fn it_displays_as_dotted_parts() {
        assert_eq!(FancyVersion::new(0, 4, 0).to_string(), "0.4.0");
    }
}
