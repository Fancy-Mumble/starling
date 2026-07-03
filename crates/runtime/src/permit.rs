//! The permission check a service performs before acting on a client's frame.
//!
//! # Why this is a type and not four lines in each service
//!
//! Enforcement that is written out at every call site is enforcement that gets
//! forgotten at one of them, and the one that is forgotten is not visibly
//! different from the others. So there is one way to ask, it is short enough
//! that writing it out is never tempting, and it fails closed.
//!
//! # Two rules, both of which are the whole point
//!
//! **The identity is never the caller's to state.** This asks
//! [`CheckSession`][cs], which takes the session id the frame arrived on and
//! resolves who that is inside `permissions`. The older `Check` takes a
//! `Subject`, and a caller that builds one carelessly can assert
//! `account = 0, registered = true` and be told it is the SuperUser. Nothing
//! enforcing a *client's* action should be able to do that, including by
//! mistake.
//!
//! **Anything that is not an explicit grant is a denial.** An unreachable
//! `permissions`, a refused call, a malformed reply, a session that has gone —
//! every one of them denies. That is the direction the architecture already
//! commits to: *a stale deny is safe; a stale grant is a security bug*
//! (`docs/ARCHITECTURE.md` §4). It also means a service cannot be talked into
//! allowing something by taking `permissions` down.
//!
//! [cs]: starling_proto_fancy::permissions::SessionCheckRequest

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::control::ServerAction;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::SessionCheckRequest;
use starling_proto_fancy::permissions::permissions_client::PermissionsClient;

use crate::channel::Resolver;
use crate::plane::Inbound;

/// Asks `permissions` whether a client may do something, and denies otherwise.
#[derive(Debug, Clone)]
pub struct Permit {
    resolver: Resolver,
}

impl Permit {
    /// A guard that asks through `resolver`.
    #[must_use]
    pub const fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }

    /// Whether the client on `inbound`'s session holds `permission` in
    /// `channel`.
    ///
    /// `permission` is a [`Perm`] bit set; **every** bit in it is required.
    ///
    /// Denies on any failure, including `permissions` being unreachable. A
    /// caller therefore never has to decide what an error means, which is the
    /// decision that gets made wrong.
    ///
    /// [`Perm`]: https://docs.rs/starling-permissions
    pub async fn allows(&self, inbound: &Inbound, channel: u32, permission: u32) -> bool {
        self.allows_session(inbound.scope, inbound.session, channel, permission)
            .await
    }

    /// The same check, for a caller that has a session id but no frame.
    pub async fn allows_session(
        &self,
        scope: u32,
        session: u32,
        channel: u32,
        permission: u32,
    ) -> bool {
        self.allows_session_with_tokens(scope, session, channel, permission, Vec::new())
            .await
    }

    /// The same check, carrying access tokens that apply to it and nothing else.
    ///
    /// A client sends a channel's password *with* the request to enter it
    /// (`UserState.temporary_access_tokens`, `Messages.cpp:1133`) rather than
    /// storing it on the session. Passing them here keeps that scope: the token
    /// opens the door it was sent for and is not written anywhere that would let
    /// it open the next one.
    pub async fn allows_session_with_tokens(
        &self,
        scope: u32,
        session: u32,
        channel: u32,
        permission: u32,
        temporary_tokens: Vec<String>,
    ) -> bool {
        // A session of zero is a client that has not finished its handshake.
        // `permissions` would resolve it to nobody and deny; refusing here
        // saves the round trip and says why.
        if session == 0 || permission == 0 {
            return false;
        }

        let Ok(transport) = self.resolver.channel("permissions") else {
            tracing::warn!(
                session,
                channel,
                permission,
                "permissions is unreachable; denying"
            );
            return false;
        };

        let answer = PermissionsClient::new(transport)
            .check_session(SessionCheckRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
                session,
                channel,
                permission,
                temporary_tokens,
            })
            .await;

        match answer {
            Ok(decision) => decision.into_inner().allowed,
            Err(status) => {
                // Reported rather than swallowed: a permission system that is
                // failing closed looks exactly like one that is working, and
                // the difference matters to whoever is being refused.
                tracing::warn!(
                    session,
                    channel,
                    permission,
                    %status,
                    "the permission check failed; denying"
                );
                false
            }
        }
    }
}

/// Upstream `PermissionDenied`.
const PERMISSION_DENIED: u16 = 12;

/// Tell the client its action was refused, and which permission it lacked.
///
/// Sent rather than dropped. A refusal the client never hears is the failure
/// murmur's own `PermissionDenied` exists to prevent: the action silently does
/// nothing, the user retries, and the only record is a server log they cannot
/// see. It is also the difference between "you may not do that here" and the
/// server appearing broken.
///
/// `DenyType::Permission` with the missing bits, which is what a Mumble client
/// renders as a named permission rather than a generic error.
#[must_use]
pub fn permission_denied(inbound: &Inbound, missing: Perm, channel: u32) -> ServerAction {
    use prost::Message as _;
    let denied = starling_proto::proto::tcp::PermissionDenied {
        permission: Some(missing.bits()),
        channel_id: Some(channel),
        session: Some(inbound.session),
        reason: Some(missing.describe()),
        r#type: Some(starling_proto::proto::tcp::permission_denied::DenyType::Permission as i32),
        name: None,
    };
    crate::plane::to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

/// Tell the client its action was refused for a reason that is **not** a
/// missing permission — a limit it met, a name it may not use.
///
/// murmur's `PERM_DENIED_TYPE`, and the distinction matters at the other end: a
/// client told `Permission` renders "you lack the X permission", which is a
/// lie when the truth is "this channel is full" or "the tree may not get
/// deeper". Those are conditions an operator can change and a user can wait
/// out, and a client that names them correctly is the difference between a
/// retry and a bug report.
///
/// The `reason` string is carried as well as the type, because every one of
/// these types post-dates some client version, and one that does not know the
/// enum renders the text.
#[must_use]
pub fn refused(
    inbound: &Inbound,
    kind: starling_proto::proto::tcp::permission_denied::DenyType,
    channel: u32,
    reason: &str,
) -> ServerAction {
    use prost::Message as _;
    let denied = starling_proto::proto::tcp::PermissionDenied {
        permission: None,
        channel_id: Some(channel),
        session: Some(inbound.session),
        reason: Some(reason.to_owned()),
        r#type: Some(kind as i32),
        name: None,
    };
    crate::plane::to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::inproc::Broker;
    use std::path::Path;
    use std::sync::Arc;

    fn permit() -> Permit {
        let config = Config::with_defaults(Path::new("/run/starling"));
        Permit::new(Resolver::new(Arc::new(config), Broker::new()))
    }

    #[tokio::test]
    async fn a_client_that_has_not_authenticated_is_denied_without_asking() {
        // Session zero is a connection mid-handshake. It has no identity to
        // resolve, so there is nothing a round trip could discover.
        assert!(!permit().allows_session(1, 0, 0, 0x40).await);
    }

    #[tokio::test]
    async fn asking_for_no_permission_is_refused() {
        // A caller that computed a mask and got zero has asked to authorise
        // nothing. Answering yes would let an empty mask stand in for a grant.
        assert!(!permit().allows_session(1, 7, 0, 0).await);
    }

    #[tokio::test]
    async fn an_unreachable_permissions_service_denies() {
        // The property the whole type exists for: taking `permissions` down
        // must not be a way to make everything permitted. The default config
        // points at a socket nothing is serving.
        assert!(!permit().allows_session(1, 7, 0, 0x40).await);
    }
}
