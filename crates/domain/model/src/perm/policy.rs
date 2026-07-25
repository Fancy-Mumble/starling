//! The permission-evaluation policy (Strategy + Null Object).

use crate::ids::{ChannelId, UserId};
use crate::perm::Perm;

/// Decides what a user may do in a channel.
///
/// # Contract
///
/// Implementations must be **total and side-effect free**: `effective` is called
/// on the hot path of every permission check and must never block, allocate
/// unboundedly, or fail. A permission check that could return "don't know" would
/// force every caller to invent a fallback, and the safe fallback (deny) would be
/// indistinguishable from a real denial in the logs.
///
/// `user` is the registered account id, or `None` for an anonymous connection.
/// [`UserId::SUPERUSER`] must always receive [`Perm::ALL`].
///
/// # An implementation must not fetch
///
/// **Phase 2 gate.** Real evaluation is not a function of these two ids. murmur
/// (`src/ACL.cpp:104`) walks the ancestor chain from root to target, reads the
/// ACL list and `InheritACL` flag on each, and resolves group membership. An
/// implementation given only ids has to fetch all of that — and
/// [`ChannelStore`](crate::channel::ChannelStore) becomes SQL-backed in Phase 2,
/// so fetching here means a blocking query inside the single writer, stalling
/// every session (`docs/STORAGE.md` §7).
///
/// So the signature has to change before the real evaluator lands: it takes the
/// ancestor chain, ACL entries and group memberships as an argument, assembled by
/// the state service from stores it already owns. Two consequences:
///
/// - the evaluator stays pure, which is what makes an in-process call from the
///   state service legitimate rather than a bus bypass
///   (`docs/ARCHITECTURE.md` §6.2);
/// - the memo cache belongs to the **state service**, which owns the tree and
///   therefore knows when to invalidate it. Hiding a mutable cache behind a
///   "side-effect free" trait is how murmur's `ACLCache` ends up threaded
///   through every call site.
///
/// The types that argument needs (ACL entries, groups) do not exist yet; there is
/// no ACL storage in Phase 0. This note is the constraint, not the design.
pub trait Permissions: std::fmt::Debug + Send + Sync + 'static {
    /// The effective permissions `user` holds in `channel`.
    fn effective(&self, user: Option<UserId>, channel: ChannelId) -> Perm;

    /// Whether `user` holds all of `needed` in `channel`.
    ///
    /// Provided so implementations only have to define [`Self::effective`], and
    /// so callers read as a question rather than a bit test.
    fn allows(&self, user: Option<UserId>, channel: ChannelId, needed: Perm) -> bool {
        self.effective(user, channel).contains(needed)
    }
}

/// Grants every permission to everyone (Null Object).
///
/// **MVP only.** A working policy that lets the handshake and handlers be built
/// and tested before the ACL subsystem exists; it is not a security policy.
/// Phase 2 replaces it with the real evaluator — inherited ACLs, group
/// membership, access tokens and the permission cache — and no caller changes,
/// because they all go through [`Permissions`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Permissions for AllowAll {
    fn effective(&self, _user: Option<UserId>, _channel: ChannelId) -> Perm {
        Perm::ALL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy that denies everything, used to prove `allows` is not hardcoded.
    #[derive(Debug)]
    struct DenyAll;

    impl Permissions for DenyAll {
        fn effective(&self, _user: Option<UserId>, _channel: ChannelId) -> Perm {
            Perm::NONE
        }
    }

    /// The contract every implementation must satisfy, checked generically.
    fn assert_policy_contract(policy: &dyn Permissions) {
        // `allows` must agree with `effective` for both implementations.
        let held = policy.effective(None, ChannelId(0));
        assert!(
            policy.allows(None, ChannelId(0), held),
            "a policy must grant exactly what it reports as effective"
        );
        assert!(
            policy.allows(None, ChannelId(0), Perm::NONE),
            "every policy must grant the empty permission set"
        );
    }

    #[test]
    fn allow_all_satisfies_the_policy_contract() {
        assert_policy_contract(&AllowAll);
    }

    #[test]
    fn deny_all_satisfies_the_policy_contract() {
        assert_policy_contract(&DenyAll);
    }

    #[test]
    fn allow_all_grants_everything_regardless_of_user_or_channel() {
        let policy = AllowAll;
        assert!(policy.allows(None, ChannelId(0), Perm::ALL));
        assert!(policy.allows(Some(UserId(7)), ChannelId(42), Perm::WRITE));
    }

    #[test]
    fn allows_is_derived_from_effective_not_assumed() {
        // If `allows` were hardcoded to true, this would pass wrongly.
        assert!(!DenyAll.allows(Some(UserId(1)), ChannelId(0), Perm::SPEAK));
    }

    #[test]
    fn policies_are_usable_behind_a_trait_object() {
        // The whole point of the seam: callers hold `&dyn Permissions`.
        let policies: Vec<Box<dyn Permissions>> = vec![Box::new(AllowAll), Box::new(DenyAll)];
        let granted: Vec<_> = policies
            .iter()
            .map(|p| p.allows(None, ChannelId(0), Perm::SPEAK))
            .collect();
        assert_eq!(granted, vec![true, false]);
    }
}
