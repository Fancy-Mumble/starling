//! The connected-user storage boundary (Repository).

use crate::ids::{ChannelId, SessionId};
use crate::user::User;

/// Read/write access to connected users and their channel membership.
///
/// # Contract
///
/// The channel-membership index is the implementation's responsibility, not the
/// caller's:
///
/// 1. After [`Self::insert`], the user appears in
///    [`Self::in_channel`] for their channel.
/// 2. After [`Self::remove`], they appear in no channel.
/// 3. [`Self::move_to`] is the **only** way to change a user's channel; it
///    updates both the user and the index atomically.
/// 4. A channel with no members must not be retained in the index — otherwise a
///    server that has churned through temporary channels leaks entries forever.
///
/// Mutable access is deliberately narrow ([`Self::get_mut`] cannot re-index), so
/// invariant 3 cannot be broken by a caller reaching for the obvious field.
pub trait UserRegistry: std::fmt::Debug {
    /// Add a user and index them into their channel.
    fn insert(&mut self, user: User);

    /// Remove a user, returning them if they were present.
    fn remove(&mut self, session: SessionId) -> Option<User>;

    /// Look up a user.
    fn get(&self, session: SessionId) -> Option<&User>;

    /// Mutable access that cannot invalidate the channel index.
    ///
    /// Changing `User::channel` through this borrow is a bug; use
    /// [`Self::move_to`].
    fn get_mut(&mut self, session: SessionId) -> Option<&mut User>;

    /// Move a user to another channel, keeping the index consistent.
    ///
    /// Returns the previous channel, or `None` if the session is unknown.
    fn move_to(&mut self, session: SessionId, target: ChannelId) -> Option<ChannelId>;

    /// The sessions currently in `channel`.
    fn in_channel(&self, channel: ChannelId) -> Vec<SessionId>;

    /// Every connected session id.
    fn sessions(&self) -> Vec<SessionId>;

    /// Every connected user.
    fn all(&self) -> Vec<&User>;

    /// How many users are connected.
    fn len(&self) -> usize;

    /// Find a connected user by name.
    ///
    /// Case-sensitive, matching murmur: it uses this to detect the
    /// reconnect collision it resolves by kicking the stale session
    /// (`Messages.cpp:404`).
    fn find_by_name(&self, name: &str) -> Option<&User>;

    /// Whether no users are connected.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
