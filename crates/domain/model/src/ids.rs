//! Identifier newtypes.
//!
//! Values, not collaborators: every type here is a `u32` wrapper with no state
//! and no behaviour beyond comparison and display. Allocating a [`SessionId`] is
//! a different job with different state, and lives in [`crate::session`].

/// The channel every server has and no one can delete.
pub const ROOT_CHANNEL: ChannelId = ChannelId(0);

/// A connected client's session id, unique for the lifetime of the connection.
///
/// Session ids are **recycled** after a user disconnects (see
/// [`SessionAllocator`](crate::session::SessionAllocator)), so they identify a
/// *connection*, never a person. Use [`UserId`] for anything that must outlive a
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct SessionId(pub u32);

/// A channel's id. [`ROOT_CHANNEL`] is always `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChannelId(pub u32);

/// A *registered* user's persistent id.
///
/// Signed because murmur uses `-1` for "not registered"; that is modelled here
/// as `Option<UserId>` at the call sites, with `UserId(0)` reserved for
/// SuperUser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct UserId(pub u32);

impl UserId {
    /// The built-in administrator account, which bypasses ACL evaluation.
    pub const SUPERUSER: Self = Self(0);

    /// Whether this is the SuperUser account.
    #[must_use]
    pub const fn is_superuser(self) -> bool {
        self.0 == Self::SUPERUSER.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superuser_is_user_zero() {
        assert!(UserId::SUPERUSER.is_superuser());
        assert!(!UserId(1).is_superuser());
    }
}
