//! The registered-account id.
//!
//! Owned here because userdata is the account authority
//! (`docs/ARCHITECTURE.md` §4). A *connected session* is a different thing
//! with a different lifetime (see `SessionId` in `starling-session-view`)
//! and a user need not be registered to hold one.

/// A *registered* user's persistent id.
///
/// Signed because murmur uses `-1` for "not registered"; that is modelled here
/// as `Option<UserId>` at the call sites, with `UserId(0)` reserved for
/// SuperUser.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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

impl std::fmt::Display for UserId {
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
