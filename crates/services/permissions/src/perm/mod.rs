//! The permission bit set.
//!
//! [`Perm`] is wire-visible — it is sent in `ServerSync.permissions` and
//! `PermissionQuery.permissions` — so the values are transcribed from
//! `vendor/server/src/ACL.h:21` and must never be renumbered.
//!
//! The *policy* that evaluates it is [`crate::evaluate`]. It lives outside this
//! module because evaluation needs the ancestor chain, the ACL entries and the
//! group memberships, and a trait taking only ids would have to fetch them —
//! which is how murmur's `ACLCache` ends up threaded through everything.

// The bits themselves are the wire contract and live with it, so a
// service enforcing a permission can name one without depending on this
// crate. Re-exported so `crate::perm::Perm` still resolves here.
pub use starling_proto_fancy::perm::Perm;

/// Evaluates what a subject may do.
///
/// # Contract
///
/// Implementations are **total and side-effect free**: this runs on the hot
/// path of every check and must never block or fail. A check that could return
/// "don't know" would force every caller to invent a fallback, and the safe
/// fallback — deny — would be indistinguishable from a real denial in the logs.
pub trait Permissions: std::fmt::Debug + Send + Sync {
    /// The permissions granted in `channel`.
    fn effective(&self, channel: u32) -> Perm;
}

/// The Null Object: everything is permitted.
///
/// Kept because it is what makes a deployment without ACLs — a single-room
/// server, a test fixture — work without a special case anywhere else.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Permissions for AllowAll {
    fn effective(&self, _channel: u32) -> Perm {
        Perm::all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_null_policy_grants_everything_including_permissions_added_later() {
        // `Perm::all()` is generated from the declaration, so a new permission
        // cannot silently fall out of the allow-all policy.
        assert_eq!(AllowAll.effective(0), Perm::all());
    }
}
