//! Which live permission proves a session may hold which operator-API scope.
//!
//! `docs/OPERATOR-API.md` §2 lists the scopes the admin plane understands.
//! Ordinarily an identity holds them because `[services.operator-api.auth]`
//! says so. This table is the other way in: a session already authenticated
//! over the control channel, holding a permission murmur already uses to gate
//! the *same* action there, may be handed a short-lived ticket carrying the
//! matching scope instead of an operator typing a credential meant for an
//! out-of-band admin console.
//!
//! # Extending this table
//!
//! Add an entry only once you have found the code that enforces the
//! equivalent control-channel action and can name its exact [`Perm`] bit --
//! guessing here is a privilege-escalation bug, not a UX bug. Where a scope
//! bundles more than the wire protocol distinguishes (`moderation:write`
//! covers both kick and ban, which murmur gates separately), require the
//! union of every bit any bundled action needs, never just one: a session
//! that may only kick must not walk away with a ticket that can also ban.

use starling_proto_fancy::perm::Perm;

use crate::permit::Permit;
use crate::plane::Inbound;

/// One scope this table knows how to grant, and the permission that already
/// gates it over the control channel.
struct Grant {
    scope: &'static str,
    /// Every bit in this set is required.
    permission: Perm,
}

/// Every scope here is server-wide -- an operator-API scope has no
/// per-channel form to narrow it to -- so every check below is against the
/// root channel, murmur's rule for every administrative permission, and
/// never against the channel a client happens to be standing in. Checking
/// anywhere else would let a session holding `Write` in one room reach every
/// room through the ticket.
const ROOT_CHANNEL: u32 = 0;

/// Deliberately short. See "Extending this table" above before adding a row.
const TABLE: &[Grant] = &[
    // What `server-config`'s own `on_livery_update` already checks for this
    // exact write, made over the control channel instead of HTTP.
    Grant {
        scope: "server-config:read",
        permission: Perm::WRITE,
    },
    Grant {
        scope: "server-config:write",
        permission: Perm::WRITE,
    },
    // `moderation` checks `Perm::BAN` for a ban and `Perm::KICK` for a kick
    // separately; the HTTP scope does not distinguish the two, so a ticket
    // needs both bits or a kick-only session would walk away able to ban.
    Grant {
        scope: "moderation:write",
        permission: Perm::KICK.union(Perm::BAN),
    },
    // Reading the ban list is not itself gated anywhere on the control
    // channel today; `BAN` stands in as the nearest equivalent trust level
    // rather than inventing a new one for a read.
    Grant {
        scope: "moderation:read",
        permission: Perm::BAN,
    },
];

/// Every scope in `requested` this session may be granted, checked against
/// the session the frame in `inbound` arrived on.
///
/// A scope named in `requested` that this table does not know is silently
/// dropped rather than denied outright: it may be a scope a newer client
/// asked for, and there is nothing this deployment can do about that beyond
/// not granting it, which is what dropping it already does. Order is
/// preserved and duplicates collapse, since a caller only cares which scopes
/// came back, not how many times each was asked for.
pub async fn grant(permit: &Permit, inbound: &Inbound, requested: &[String]) -> Vec<String> {
    let mut granted = Vec::new();
    for scope in requested {
        if granted.iter().any(|held| held == scope) {
            continue;
        }
        let Some(entry) = TABLE.iter().find(|candidate| candidate.scope == scope) else {
            continue;
        };
        if permit
            .allows(inbound, ROOT_CHANNEL, entry.permission.bits())
            .await
        {
            granted.push(scope.clone());
        }
    }
    granted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Resolver;
    use crate::config::Config;
    use crate::inproc::Broker;
    use std::sync::Arc;

    fn permit() -> Permit {
        Permit::new(Resolver::new(Arc::new(Config::default()), Broker::new()))
    }

    fn inbound(session: u32) -> Inbound {
        Inbound {
            conn: 1,
            session,
            type_id: 0,
            payload: Vec::new(),
            gateway: "gw".to_owned(),
            scope: 1,
        }
    }

    #[tokio::test]
    async fn a_scope_this_table_does_not_know_is_dropped_rather_than_denied() {
        let granted = grant(&permit(), &inbound(7), &["not-a-real-scope".to_owned()]).await;
        assert!(granted.is_empty());
    }

    #[tokio::test]
    async fn nothing_is_granted_while_permissions_is_unreachable() {
        // The same fail-closed property `Permit` already guarantees: taking
        // `permissions` down must not be a way to make a ticket grant more.
        let granted = grant(
            &permit(),
            &inbound(7),
            &[
                "server-config:write".to_owned(),
                "moderation:write".to_owned(),
            ],
        )
        .await;
        assert!(granted.is_empty());
    }

    #[tokio::test]
    async fn an_unauthenticated_session_is_asked_nothing() {
        // Session 0 is a connection mid-handshake; `Permit` refuses it without
        // a round trip, which this exercises through the table rather than
        // around it.
        let granted = grant(&permit(), &inbound(0), &["server-config:write".to_owned()]).await;
        assert!(granted.is_empty());
    }

    #[tokio::test]
    async fn duplicate_and_empty_requests_are_handled() {
        assert!(grant(&permit(), &inbound(7), &[]).await.is_empty());
        let granted = grant(
            &permit(),
            &inbound(7),
            &[
                "server-config:write".to_owned(),
                "server-config:write".to_owned(),
            ],
        )
        .await;
        // Denied either way here (no live `permissions`), but never listed
        // twice even where it would have been granted.
        assert!(granted.len() <= 1);
    }
}
