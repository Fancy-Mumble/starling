//! `PermissionQuery` — answering "what may I do in this channel?"
//!
//! Wire type 20. A client sends it when the user opens a channel's context menu,
//! and greys out the actions the answer says are unavailable. murmur handles it in
//! `Messages.cpp:3307`, delegating to `Server::sendClientPermission`
//! (`Server.cpp:2404`).
//!
//! # This crate exists to test the architecture
//!
//! It is a whole server feature that the MVP did not have, and it adds **no**
//! logic to any existing crate: it implements [`Handler`] and is registered at
//! the composition root. Everything it needs — the state to read, the permission
//! evaluator, the way to describe a reply — arrives through traits it does not
//! own.
//!
//! What it is *not* able to do is the point: it cannot mutate the channel tree,
//! evict a session, or write to a socket, because [`Authority`] does not offer
//! those. A feature is bounded by the trait it is handed, not by review.

use starling_api::{Access, Authority, ConnId, Effects, Feature, Handler, Recipients};
use starling_model::{ChannelId, Perm};
use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType};
use tracing::debug;

/// Answers a client's permission query for one channel.
#[derive(Debug, Default)]
pub struct PermissionQueryHandler;

impl Handler for PermissionQueryHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::PermissionQuery
    }

    fn access(&self) -> Access {
        // murmur guards with `MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated)`.
        Access::Authenticated
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::PermissionQuery(query) = msg else {
            return Effects::none();
        };
        let Some(session) = state.session_of(conn) else {
            return Effects::none();
        };
        let Some(channel) = query.channel_id.map(ChannelId) else {
            return Effects::none();
        };

        // An unknown channel is silently ignored, exactly as murmur does
        // (`Messages.cpp:3313`). A client can ask about a channel that was
        // removed between its menu opening and the query arriving; answering
        // `PermissionDenied` would turn a race into a visible error.
        if !state.channels().contains(channel) {
            debug!(%session, %channel, "permission query for an unknown channel");
            return Effects::none();
        }

        let user = state.users().get(session).and_then(|u| u.user_id);
        let permissions = state.permissions().effective(user, channel);

        let mut fx = Effects::none();
        let _ = fx.send(
            Recipients::Session(session),
            ControlMessage::PermissionQuery(tcp::PermissionQuery {
                channel_id: Some(channel.0),
                permissions: Some(permissions.bits()),
                // `flush` tells the client to discard everything it has cached.
                // Only a server-side ACL change warrants that; answering one
                // question must not invalidate the answers to the others.
                flush: None,
            }),
        );
        fx
    }
}

/// The feature, as the host sees it.
#[derive(Debug, Default)]
pub struct PermissionQueryFeature;

impl Feature for PermissionQueryFeature {
    fn name(&self) -> &'static str {
        "permission-query"
    }

    fn handlers(&self) -> Vec<Box<dyn Handler>> {
        vec![Box::new(PermissionQueryHandler)]
    }
}

// The only wiring. No binary names this crate.
starling_api::register_feature!(PermissionQueryFeature);

/// Every permission this build can report.
///
/// Exposed so an admin surface can describe the bitfield without importing
/// `starling-model`'s internals.
#[must_use]
pub fn reportable() -> Perm {
    Perm::ALL
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_api::{Effect, ServerConfig, Sessions, World};
    use starling_model::{Permissions, UserId, ROOT_CHANNEL};
    use starling_server::ServerState;

    /// A state with one authenticated user, as the dispatcher would have it.
    fn state_with_user() -> (ServerState, ConnId) {
        let mut state = ServerState::new(ServerConfig::default());
        let conn = ConnId(1);
        state.add_connection(conn, "127.0.0.1:1234".parse().expect("test addr"));
        let session = state.assign_session(conn).expect("pool has ids");
        state
            .users_mut()
            .insert(starling_model::User::new(session, "tester", ROOT_CHANNEL));
        (state, conn)
    }

    fn query(channel: Option<u32>) -> ControlMessage {
        ControlMessage::PermissionQuery(tcp::PermissionQuery {
            channel_id: channel,
            ..Default::default()
        })
    }

    fn answered(fx: &Effects) -> Option<tcp::PermissionQuery> {
        fx.as_slice().iter().find_map(|e| match e {
            Effect::Send { msg, .. } => match msg.as_ref() {
                ControlMessage::PermissionQuery(q) => Some(*q),
                _ => None,
            },
            _ => None,
        })
    }

    #[test]
    fn it_registers_for_wire_type_20() {
        assert_eq!(
            PermissionQueryHandler.handles(),
            TcpMessageType::PermissionQuery
        );
        assert_eq!(PermissionQueryHandler.handles().id(), 20);
    }

    #[test]
    fn an_anonymous_peer_cannot_reach_it() {
        // The dispatcher enforces this centrally; declaring it is what makes the
        // guard apply.
        assert_eq!(PermissionQueryHandler.access(), Access::Authenticated);
    }

    #[test]
    fn a_known_channel_is_answered_with_its_effective_permissions() {
        let (mut state, conn) = state_with_user();
        let fx = PermissionQueryHandler.handle(&mut state, conn, query(Some(ROOT_CHANNEL.0)));

        let answer = answered(&fx).expect("a query must be answered");
        assert_eq!(answer.channel_id, Some(ROOT_CHANNEL.0));
        // The MVP policy is `AllowAll`, so this is `Perm::ALL`; the point is that
        // the answer comes from the evaluator rather than from this handler.
        assert_eq!(answer.permissions, Some(Perm::ALL.bits()));
    }

    #[test]
    fn the_answer_comes_from_the_installed_policy_not_from_this_handler() {
        #[derive(Debug)]
        struct SpeakOnly;
        impl Permissions for SpeakOnly {
            fn effective(&self, _user: Option<UserId>, _channel: ChannelId) -> Perm {
                Perm::SPEAK
            }
        }

        let (state, conn) = state_with_user();
        let mut state = state.with_permissions(Box::new(SpeakOnly));
        let fx = PermissionQueryHandler.handle(&mut state, conn, query(Some(ROOT_CHANNEL.0)));

        assert_eq!(
            answered(&fx).expect("answered").permissions,
            Some(Perm::SPEAK.bits())
        );
    }

    #[test]
    fn an_unknown_channel_is_ignored_rather_than_refused() {
        let (mut state, conn) = state_with_user();
        let fx = PermissionQueryHandler.handle(&mut state, conn, query(Some(9999)));
        assert!(
            fx.is_empty(),
            "a channel removed mid-race must not produce PermissionDenied"
        );
    }

    #[test]
    fn a_query_without_a_channel_is_ignored() {
        let (mut state, conn) = state_with_user();
        assert!(PermissionQueryHandler
            .handle(&mut state, conn, query(None))
            .is_empty());
    }

    #[test]
    fn the_answer_goes_only_to_the_asker() {
        let (mut state, conn) = state_with_user();
        let session = Sessions::session_of(&state, conn).expect("session");
        let fx = PermissionQueryHandler.handle(&mut state, conn, query(Some(ROOT_CHANNEL.0)));

        let to = fx.as_slice().iter().find_map(|e| match e {
            Effect::Send { to, .. } => Some(*to),
            _ => None,
        });
        assert_eq!(to, Some(Recipients::Session(session)));
    }

    #[test]
    fn flush_is_never_set_when_answering_one_question() {
        let (mut state, conn) = state_with_user();
        let fx = PermissionQueryHandler.handle(&mut state, conn, query(Some(ROOT_CHANNEL.0)));
        assert_eq!(answered(&fx).expect("answered").flush, None);
    }
}
