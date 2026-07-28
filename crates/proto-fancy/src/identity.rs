//! Who an account is, and the one rule everything reading `account` must know.
//!
//! # `account` alone is not an identity
//!
//! Mumble numbers registered users from zero and uses **`-1` for "not
//! registered"** (`vendor/server/src/Group.cpp:154` resolves the `@auth` group as
//! `iId >= 0`). A `uint64` on the wire cannot carry `-1`, so registration travels
//! as a **separate boolean** and `account` is meaningful only when it is set.
//!
//! That is not a stylistic preference. When the two were conflated, `account = 0`
//! meant both *the SuperUser* and *an anonymous guest*, and three components
//! disagreed about which:
//!
//! * `starling-userdata` reserved `0` for the SuperUser,
//! * `starling-permissions` granted every permission to account `1`,
//! * the handshake flattened an absent account to `0` and treated `!= 0` as
//!   registered.
//!
//! The result was that an ordinary registered user held every permission on the
//! server while the actual administrator could be locked out by its own ACL
//! table. Both directions were invisible: nothing failed, nothing logged.
//!
//! So this module is the *only* place the pair is interpreted. A caller that
//! wants to know who someone is asks [`account`]; one that has an answer to put
//! on the wire uses [`wire`]. Neither is a free-floating comparison against a
//! magic number, which is what let the three definitions drift apart.

/// The built-in administrator's account id.
///
/// Zero, as murmur has it. It bypasses ACL evaluation entirely — an ACL table
/// that has locked its own administrator out is a server nobody can repair — so
/// **every check against it must also require registration**, or every
/// unregistered guest becomes an administrator. Use [`is_superuser`] rather than
/// comparing to this directly.
pub const SUPERUSER: u64 = 0;

/// The name the SuperUser authenticates under.
///
/// Fixed, and matched case-insensitively by the account lookup, because every
/// Mumble client offers it as the administrator login. A server that spelled it
/// differently would have an administrator nobody can find.
pub const SUPERUSER_NAME: &str = "SuperUser";

/// The account a subject holds, or `None` when it is not registered.
///
/// The one place `(registered, id)` is turned back into a decision.
#[must_use]
pub const fn account(registered: bool, id: u64) -> Option<u64> {
    if registered { Some(id) } else { None }
}

/// The `(account, registered)` pair to put on the wire.
///
/// The inverse of [`account`], so the two fields are always written together and
/// cannot drift apart at a call site that only remembered one of them.
#[must_use]
pub const fn wire(account: Option<u64>) -> (u64, bool) {
    match account {
        Some(id) => (id, true),
        // Zero rather than a sentinel: readers must consult `registered`, and a
        // magic number in this field is what invited the original confusion.
        None => (0, false),
    }
}

/// Whether this subject is the SuperUser.
///
/// Requires registration, which is the whole point: `id == SUPERUSER` alone is
/// true for every anonymous guest, because an absent account is written as zero.
#[must_use]
pub const fn is_superuser(registered: bool, id: u64) -> bool {
    registered && id == SUPERUSER
}

/// Whether this subject is in murmur's `@auth` group.
///
/// `iId >= 0` upstream, which is exactly "registered" — **not** "has a session".
/// Every connected client has a session, so reading it that way puts anonymous
/// guests in `@auth` and hands them whatever an operator granted to registered
/// users.
#[must_use]
pub const fn is_authenticated(registered: bool) -> bool {
    registered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unregistered_subject_is_not_the_superuser() {
        // The bug this module exists for. An absent account is written as zero,
        // and zero is the SuperUser's id, so a check that forgets registration
        // makes every anonymous guest an administrator.
        assert!(!is_superuser(false, 0));
        assert!(!is_superuser(false, SUPERUSER));
    }

    #[test]
    fn the_registered_superuser_is_the_superuser() {
        assert!(is_superuser(true, SUPERUSER));
    }

    #[test]
    fn an_ordinary_registered_user_is_not_the_superuser() {
        // The other direction of the same bug: account 1 held every permission
        // on the server because a constant said so.
        assert!(!is_superuser(true, 1));
        assert!(!is_superuser(true, 42));
    }

    #[test]
    fn an_absent_account_survives_a_round_trip_as_absent() {
        // If this ever collapsed to `Some(0)`, a guest would become the
        // SuperUser one layer further on.
        for original in [None, Some(SUPERUSER), Some(1), Some(u64::MAX)] {
            let (id, registered) = wire(original);
            assert_eq!(account(registered, id), original, "{original:?}");
        }
    }

    #[test]
    fn only_a_registered_subject_is_in_the_auth_group() {
        assert!(is_authenticated(true));
        assert!(!is_authenticated(false));
    }
}
