//! The channel entity.

use crate::ids::ChannelId;

/// A single channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    /// This channel's id. [`ROOT_CHANNEL`](crate::ids::ROOT_CHANNEL) for the root.
    pub id: ChannelId,
    /// The parent channel, or `None` for the root.
    ///
    /// The Fancy fork also has *detached* channels (out-of-tree, e.g. friend
    /// chats) which are parentless without being the root. Nothing here
    /// creates one yet, so `None` currently means "root" and callers may treat
    /// it that way; when detached channels land, every such caller is a site
    /// that has to learn the difference.
    pub parent: Option<ChannelId>,
    /// Display name.
    pub name: String,
    /// Channel description, possibly HTML.
    pub description: String,
    /// Sort position within the parent. Ties are broken by name.
    pub position: i32,
    /// Whether the channel disappears once its last occupant leaves.
    pub temporary: bool,
    /// Occupant cap, or `0` for "no limit" (murmur's convention).
    pub max_users: u32,
    /// Child channels, in insertion order. Sorting is a presentation concern.
    pub children: Vec<ChannelId>,
}

impl Channel {
    /// Create a channel with default properties.
    #[must_use]
    pub fn new(id: ChannelId, parent: Option<ChannelId>, name: impl Into<String>) -> Self {
        Self {
            id,
            parent,
            name: name.into(),
            description: String::new(),
            position: 0,
            temporary: false,
            max_users: 0,
            children: Vec::new(),
        }
    }

    /// Whether this channel is the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.id == crate::ids::ROOT_CHANNEL
    }

    /// Whether the channel is at capacity given its current occupancy.
    ///
    /// `max_users == 0` means unlimited, matching murmur.
    #[must_use]
    pub fn is_full(&self, occupants: usize) -> bool {
        is_full(self.max_users, occupants)
    }
}

/// Whether a channel with cap `max_users` is full at `occupants`.
///
/// A free function because the rule has **two** callers holding two different
/// channel types (this entity and the proto record the live tree is made of)
/// and it was previously written out in both. `GAP-ANALYSIS.md` C4 records what
/// that cost: the rule was modelled here, covered by tests here, and the tree
/// that clients actually enter had its own copy. A rule with two homes is a
/// rule that is eventually enforced in one of them.
///
/// `max_users == 0` is **unlimited**, which is murmur's convention and the
/// reading that is wrong in the direction nobody notices: taken literally it
/// would lock every channel nobody has given an explicit limit.
#[must_use]
pub const fn is_full(max_users: u32, occupants: usize) -> bool {
    max_users != 0 && occupants >= max_users as usize
}

/// Whether a channel is full, taking the server-wide ceiling into account.
///
/// murmur's `isChannelFull` (`vendor/server/src/murmur/Server.cpp:2799`), and
/// the shape of it is the part worth stating: the channel's own `max_users` and
/// the server's `usersperchannel` are **not** two ceilings to satisfy, they are
/// a value and its fallback. A channel that carries its own limit is governed
/// by that limit alone, even where it is the looser of the two, because an
/// operator who set a room to 30 on a server whose default is 5 meant that room
/// to hold 30.
///
/// `bypass` is the caller's answer to "does this user hold `Write` here". murmur
/// exempts them first, before either number is read: the authority to edit a
/// room includes the authority to be in it, and without the exemption an
/// operator can lock themselves out of the channel whose limit they need to
/// raise.
#[must_use]
pub const fn is_full_for(
    max_users: u32,
    users_per_channel: u32,
    occupants: usize,
    bypass: bool,
) -> bool {
    if bypass {
        return false;
    }
    if max_users != 0 {
        return is_full(max_users, occupants);
    }
    is_full(users_per_channel, occupants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ROOT_CHANNEL;

    #[test]
    fn a_new_channel_has_no_children_and_no_limit() {
        let channel = Channel::new(ChannelId(1), Some(ROOT_CHANNEL), "Lobby");
        assert!(channel.children.is_empty());
        assert_eq!(channel.max_users, 0);
        assert!(!channel.temporary);
    }

    #[test]
    fn only_channel_zero_is_the_root() {
        assert!(Channel::new(ROOT_CHANNEL, None, "Root").is_root());
        assert!(!Channel::new(ChannelId(1), Some(ROOT_CHANNEL), "Lobby").is_root());
    }

    #[test]
    fn a_zero_max_users_means_unlimited_not_closed() {
        // The obvious-looking reading (0 occupants allowed) would lock every
        // channel that has not been given an explicit limit.
        let channel = Channel::new(ChannelId(1), Some(ROOT_CHANNEL), "Lobby");
        assert!(!channel.is_full(0));
        assert!(!channel.is_full(10_000));
    }

    #[test]
    fn a_channels_own_limit_replaces_the_server_wide_one_rather_than_capping_it() {
        // The reading that looks safer and is wrong: `min(30, 5)`. An operator
        // who raised one room to 30 on a server defaulting to 5 would find it
        // still holding five people, with nothing on screen to explain it.
        assert!(!is_full_for(30, 5, 20, false), "the room's own limit wins");
        assert!(is_full_for(30, 5, 30, false));
        // And the server-wide one applies only where the room is silent.
        assert!(is_full_for(0, 5, 5, false));
        assert!(!is_full_for(0, 5, 4, false));
    }

    #[test]
    fn no_limit_anywhere_means_no_limit() {
        assert!(!is_full_for(0, 0, 10_000, false));
    }

    #[test]
    fn write_lets_a_user_past_a_full_channel() {
        // Without this an operator cannot enter the room whose limit they are
        // being asked to raise.
        assert!(is_full_for(2, 0, 2, false));
        assert!(!is_full_for(2, 0, 2, true));
        assert!(!is_full_for(0, 1, 99, true));
    }

    #[test]
    fn a_channel_is_full_at_its_limit_not_past_it() {
        let mut channel = Channel::new(ChannelId(1), Some(ROOT_CHANNEL), "Lobby");
        channel.max_users = 2;
        assert!(!channel.is_full(1));
        assert!(channel.is_full(2), "the limit is inclusive");
        assert!(channel.is_full(3));
    }
}
