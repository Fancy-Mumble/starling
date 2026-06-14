//! `QueryUsers` — resolving registered user ids to names and back.
//!
//! Wire type 14. The client uses it to render an ACL editor: it has ids from a
//! stored ACL and needs names, or has a typed name and needs an id. murmur
//! handles it in `Messages.cpp:2990`.
//!
//! # Second feature, to measure the marginal cost
//!
//! `permission-query` was the first crate built against `starling-api`. This one
//! exists to answer whether the *second* is cheaper — i.e. whether the seam is a
//! seam or was a one-off. It touches no existing crate.

use starling_api::{Access, Authority, ConnId, Effects, Feature, Handler, Recipients};
use starling_model::Perm;
use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType};

/// Answers id/name lookups for registered users.
#[derive(Debug, Default)]
pub struct QueryUsersHandler;

impl Handler for QueryUsersHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::QueryUsers
    }

    fn access(&self) -> Access {
        Access::Authenticated
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::QueryUsers(query) = msg else {
            return Effects::none();
        };
        let Some(session) = state.session_of(conn) else {
            return Effects::none();
        };

        // murmur requires Write somewhere in the tree before it will enumerate
        // accounts (`Messages.cpp:2995`): the reply is a directory of registered
        // users, which is not public information.
        let asker = state.users().get(session).and_then(|u| u.user_id);
        if !state.permissions().allows(asker, ROOT, Perm::WRITE) {
            return Effects::none();
        }

        // Phase 0 has no account store, so only *connected* registered users can
        // be resolved. That is a smaller answer than murmur's, never a wrong one:
        // an unresolvable id is simply omitted, which is also what murmur does
        // for an unknown id.
        let mut reply = tcp::QueryUsers::default();
        for id in &query.ids {
            if let Some(user) = state
                .users()
                .all()
                .into_iter()
                .find(|u| u.user_id.is_some_and(|uid| uid.0 == *id))
            {
                reply.ids.push(*id);
                reply.names.push(user.name.clone());
            }
        }
        for name in &query.names {
            if let Some(user) = state.users().find_by_name(name)
                && let Some(uid) = user.user_id
            {
                reply.ids.push(uid.0);
                reply.names.push(user.name.clone());
            }
        }

        let mut fx = Effects::none();
        let _ = fx.send(
            Recipients::Session(session),
            ControlMessage::QueryUsers(reply),
        );
        fx
    }
}

/// The channel whose `Write` permission gates the directory.
const ROOT: starling_model::ChannelId = starling_model::ROOT_CHANNEL;

/// The feature, as the host sees it.
#[derive(Debug, Default)]
pub struct QueryUsersFeature;

impl Feature for QueryUsersFeature {
    fn name(&self) -> &'static str {
        "query-users"
    }

    fn handlers(&self) -> Vec<Box<dyn Handler>> {
        vec![Box::new(QueryUsersHandler)]
    }
}

starling_api::register_feature!(QueryUsersFeature);

#[cfg(test)]
mod tests {
    use super::*;
    use starling_api::{Effect, ServerConfig, Sessions, World};
    use starling_model::{ChannelId, Permissions, ROOT_CHANNEL, User, UserId};
    use starling_server::ServerState;

    fn state_with_registered_user() -> (ServerState, ConnId) {
        let mut state = ServerState::new(ServerConfig::default());
        let conn = ConnId(1);
        state.add_connection(conn, "127.0.0.1:1234".parse().expect("test addr"));
        let session = state.assign_session(conn).expect("pool has ids");
        let mut user = User::new(session, "registered", ROOT_CHANNEL);
        user.user_id = Some(UserId(7));
        state.users_mut().insert(user);
        (state, conn)
    }

    fn ask(ids: Vec<u32>, names: Vec<String>) -> ControlMessage {
        ControlMessage::QueryUsers(tcp::QueryUsers { ids, names })
    }

    fn reply(fx: &Effects) -> Option<tcp::QueryUsers> {
        fx.as_slice().iter().find_map(|e| match e {
            Effect::Send { msg, .. } => match msg.as_ref() {
                ControlMessage::QueryUsers(q) => Some(q.clone()),
                _ => None,
            },
            _ => None,
        })
    }

    #[test]
    fn it_registers_for_wire_type_14() {
        assert_eq!(QueryUsersHandler.handles().id(), 14);
    }

    #[test]
    fn an_id_resolves_to_a_name() {
        let (mut state, conn) = state_with_registered_user();
        let fx = QueryUsersHandler.handle(&mut state, conn, ask(vec![7], vec![]));
        let answer = reply(&fx).expect("answered");
        assert_eq!(answer.ids, vec![7]);
        assert_eq!(answer.names, vec!["registered".to_owned()]);
    }

    #[test]
    fn a_name_resolves_to_an_id() {
        let (mut state, conn) = state_with_registered_user();
        let fx = QueryUsersHandler.handle(&mut state, conn, ask(vec![], vec!["registered".into()]));
        assert_eq!(reply(&fx).expect("answered").ids, vec![7]);
    }

    #[test]
    fn an_unknown_id_is_omitted_rather_than_guessed() {
        let (mut state, conn) = state_with_registered_user();
        let fx = QueryUsersHandler.handle(&mut state, conn, ask(vec![999], vec![]));
        assert!(reply(&fx).expect("answered").ids.is_empty());
    }

    #[test]
    fn without_write_anywhere_the_directory_is_not_readable() {
        #[derive(Debug)]
        struct NoWrite;
        impl Permissions for NoWrite {
            fn effective(&self, _user: Option<UserId>, _channel: ChannelId) -> Perm {
                Perm::ALL.difference(Perm::WRITE)
            }
        }

        let (state, conn) = state_with_registered_user();
        let mut state = state.with_permissions(Box::new(NoWrite));
        let fx = QueryUsersHandler.handle(&mut state, conn, ask(vec![7], vec![]));
        assert!(
            fx.is_empty(),
            "the registered-user list is not public information"
        );
    }

    #[test]
    fn the_reply_goes_only_to_the_asker() {
        let (mut state, conn) = state_with_registered_user();
        let session = Sessions::session_of(&state, conn).expect("session");
        let fx = QueryUsersHandler.handle(&mut state, conn, ask(vec![7], vec![]));
        let to = fx.as_slice().iter().find_map(|e| match e {
            Effect::Send { to, .. } => Some(*to),
            _ => None,
        });
        assert_eq!(to, Some(Recipients::Session(session)));
    }
}
