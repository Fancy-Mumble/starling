//! The permission bit set.
//!
//! Values are transcribed from `vendor/server/src/ACL.h:21`, including the Fancy
//! fork's additions. They are **wire-visible** — sent in `ServerSync.permissions`
//! and `PermissionQuery.permissions` — so they must never be renumbered.
//!
//! It lives in the contract crate rather than in `starling-permissions` because
//! it is not policy: every service that *enforces* a permission needs to name
//! the bit it is asking for, and none of them should have to depend on the ACL
//! engine to do it. The engine that evaluates these stays in
//! `starling-permissions`.

use bitflags::bitflags;

bitflags! {
    /// A set of channel permissions.
    ///
    /// Declared with `bitflags` so that the set of flags has exactly one
    /// definition. The hand-rolled version needed two parallel lists — a
    /// `NAMED` table and an `ALL` union — that had to be updated whenever a
    /// permission was added, and silently under-reported when they were not.
    /// [`Self::all`] and [`Self::iter_names`] are generated from the
    /// declaration below, so they cannot drift from it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Perm: u32 {
        /// Modify the channel's ACLs and properties.
        const WRITE = 0x1;
        /// Pass through the channel to reach its children.
        const TRAVERSE = 0x2;
        /// Join the channel.
        const ENTER = 0x4;
        /// Transmit audio into the channel.
        const SPEAK = 0x8;
        /// Mute or deafen other users.
        const MUTE_DEAFEN = 0x10;
        /// Move other users between channels.
        const MOVE = 0x20;
        /// Create a sub-channel.
        const MAKE_CHANNEL = 0x40;
        /// Link channels together.
        const LINK_CHANNEL = 0x80;
        /// Whisper into the channel.
        const WHISPER = 0x100;
        /// Send chat messages to the channel.
        const TEXT_MESSAGE = 0x200;
        /// Create a temporary sub-channel.
        const MAKE_TEMP_CHANNEL = 0x400;
        /// Listen to the channel without joining it.
        const LISTEN = 0x800;
        /// Delete other users' messages.
        const DELETE_MESSAGE = 0x1000;
        /// Subscribe to push notifications (Fancy).
        const SUBSCRIBE_PUSH = 0x2000;
        /// Upload files (Fancy).
        const SHARE_FILES = 0x4000;
        /// Upload publicly reachable files (Fancy).
        const SHARE_FILES_PUBLIC = 0x8000;

        // -- Root-channel-only permissions --------------------------------

        /// Kick users from the server.
        const KICK = 0x10000;
        /// Ban users from the server.
        const BAN = 0x20000;
        /// Register other users.
        const REGISTER = 0x40000;
        /// Register oneself.
        const SELF_REGISTER = 0x80000;
        /// Reset another user's comment or avatar.
        const RESET_USER_CONTENT = 0x100000;
        /// Hold persistent-chat group keys (Fancy).
        const KEY_OWNER = 0x200000;
        /// Manage server emotes (Fancy).
        const MANAGE_EMOTES = 0x400000;
        /// Read the registered-user list.
        const READ_REGISTER = 0x800000;

        /// See a channel flagged hidden (Fancy).
        ///
        /// Sits in the root-only numeric range only because the low channel bits
        /// are exhausted. It is **not** root-only: root-only-ness is decided by
        /// the evaluation code, not the bit value (`ACL.h:50`).
        const SEE_CHANNEL = 0x1000000;
    }
}

impl Perm {
    /// No permissions.
    pub const NONE: Self = Self::empty();

    /// Every permission.
    ///
    /// Generated from the declaration above, so it covers every flag by
    /// construction. It excludes `ACL.h`'s `Cached` marker (`0x8000000`)
    /// because that bit is internal bookkeeping and is deliberately not
    /// declared here; it must never reach a client.
    pub const ALL: Self = Self::all();

    /// What every subject starts with, before any ACL entry is applied.
    ///
    /// murmur's `ChanACL::effectivePermissions` seeds the walk with exactly
    /// these (`vendor/server/src/ACL.cpp:130`) rather than with nothing, and the
    /// difference is the whole behaviour of an unconfigured server: starting
    /// from empty means a fresh server grants **nobody** anything — no talking,
    /// no text, not even entering a channel — and every client shows every
    /// action greyed out with no ACL to point at as the cause.
    ///
    /// An operator takes permissions *away* from here with a deny entry. That
    /// direction is what makes a default set safe: it is the same set murmur has
    /// had for twenty years, and it contains nothing administrative.
    pub const DEFAULT: Self = Self::TRAVERSE
        .union(Self::ENTER)
        .union(Self::SPEAK)
        .union(Self::WHISPER)
        .union(Self::TEXT_MESSAGE)
        .union(Self::LISTEN);

    /// What the SuperUser is granted, before any ACL is consulted.
    ///
    /// Everything **except speaking and whispering**
    /// (`vendor/server/src/ACL.cpp:106`). That exclusion is deliberate upstream
    /// and worth keeping: the administrator account exists to administer, and an
    /// operator who logs in as SuperUser to fix something should not silently be
    /// transmitting into whatever channel they land in.
    pub const SUPERUSER: Self = Self::ALL.difference(Self::SPEAK).difference(Self::WHISPER);
}

impl Perm {
    /// A human-readable list of the permissions in this set.
    ///
    /// "Permission denied" without naming the permission is a support ticket;
    /// this is what a `PermissionDenied` reason carries instead.
    #[must_use]
    pub fn describe(self) -> String {
        let names: Vec<&str> = self.iter_names().map(|(name, _)| name).collect();
        if names.is_empty() {
            "no permission".to_owned()
        } else {
            names.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_values_match_the_cpp_header() {
        // Wire-visible constants: renumbering these silently breaks every
        // client's permission display. Spot-check the boundaries.
        assert_eq!(Perm::WRITE.bits(), 0x1);
        assert_eq!(Perm::SHARE_FILES_PUBLIC.bits(), 0x8000);
        assert_eq!(Perm::KICK.bits(), 0x10000);
        assert_eq!(Perm::READ_REGISTER.bits(), 0x800000);
        assert_eq!(Perm::SEE_CHANNEL.bits(), 0x1000000);
    }

    #[test]
    fn all_covers_every_named_permission() {
        for (name, bit) in Perm::all().iter_names() {
            assert!(Perm::ALL.contains(bit), "Perm::ALL is missing {name}");
        }
    }

    #[test]
    fn named_permissions_are_distinct_single_bits() {
        let mut count = 0;
        for (name, bit) in Perm::all().iter_names() {
            assert_eq!(
                bit.bits().count_ones(),
                1,
                "{name} should be a single bit, got {:#x}",
                bit.bits()
            );
            count += 1;
        }
        assert_eq!(
            Perm::ALL.bits().count_ones(),
            count,
            "two named permissions share a bit"
        );
    }

    #[test]
    fn all_does_not_set_the_cached_marker_bit() {
        assert_eq!(Perm::ALL.bits() & 0x8000000, 0);
    }

    #[test]
    fn contains_requires_every_requested_bit() {
        let held = Perm::ENTER.union(Perm::SPEAK);
        assert!(held.contains(Perm::ENTER));
        assert!(held.contains(Perm::ENTER.union(Perm::SPEAK)));
        assert!(!held.contains(Perm::ENTER.union(Perm::WRITE)));
    }

    #[test]
    fn contains_none_is_always_true() {
        assert!(Perm::NONE.contains(Perm::NONE));
        assert!(Perm::ALL.contains(Perm::NONE));
    }

    #[test]
    fn difference_clears_only_the_named_bits() {
        let held = Perm::ALL.difference(Perm::SPEAK);
        assert!(!held.contains(Perm::SPEAK));
        assert!(held.contains(Perm::ENTER));
    }

    /// Unknown bits arrive from the wire; they must not be silently kept.
    #[test]
    fn undeclared_bits_are_dropped_on_the_way_in() {
        let cached_marker = 0x8000_0000 | Perm::SPEAK.bits();
        let parsed = Perm::from_bits_truncate(cached_marker);
        assert_eq!(parsed, Perm::SPEAK);
    }
}
