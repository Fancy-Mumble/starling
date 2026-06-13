//! `TextMessage` — chat fan-out.

use starling_log::{Category, LogEvent};
use starling_model::{ChannelId, Perm, SessionId};
use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType};
use tracing::warn;

use starling_api::Authority;
use starling_api::Handler;
use starling_api::{ConnId, Effects, Recipients};

/// Relays chat messages to their addressees.
///
/// Mumble lets one message address several targets at once: `channel_id`
/// (everyone in those channels), `tree_id` (a channel and its descendants) and
/// `session` (direct messages).
///
/// The server rewrites `actor` to the *real* sender before relaying — without
/// that, any client could forge messages from anyone, which is why the field is
/// overwritten rather than validated.
///
/// Phase 0 implements `channel_id` and `session`. `tree_id` needs the recursive
/// descendant walk plus per-channel permission checks, and lands with ACL
/// evaluation in Phase 2.
#[derive(Debug, Default)]
pub struct TextMessageHandler;

impl Handler for TextMessageHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::TextMessage
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::TextMessage(msg) = msg else {
            return Effects::none();
        };
        let Some(sender) = state.session_of(conn) else {
            return Effects::none();
        };

        if let Some(denial) = refuse(state, sender, &msg) {
            return denial;
        }

        if !msg.tree_id.is_empty() {
            warn!(
                %sender,
                "tree_id addressing not implemented (Phase 2); those recipients were skipped"
            );
        }

        relay(sender, msg)
    }
}

/// Build the fan-out for an accepted message.
fn relay(sender: SessionId, msg: tcp::TextMessage) -> Effects {
    let relayed = tcp::TextMessage {
        // Authoritative: never trust the client's claim about who it is.
        actor: Some(sender.0),
        message: msg.message,
        session: msg.session.clone(),
        channel_id: msg.channel_id.clone(),
        // Never forwarded: this build did not expand it, so passing it on would
        // ask recipients to expand it themselves and invent a different set.
        tree_id: Vec::new(),
        ..Default::default()
    };

    let mut fx = Effects::none();

    // Channel addressing: everyone in the channel except the sender, who
    // already rendered it locally.
    for channel in &msg.channel_id {
        let _ = fx.send(
            Recipients::ChannelExcept(ChannelId(*channel), sender),
            ControlMessage::TextMessage(relayed.clone()),
        );
    }

    // Direct addressing.
    for target in &msg.session {
        let _ = fx.send(
            Recipients::Session(SessionId(*target)),
            ControlMessage::TextMessage(relayed.clone()),
        );
    }

    fx
}

/// Refuse the message, or `None` to allow it.
fn refuse(state: &dyn Authority, sender: SessionId, msg: &tcp::TextMessage) -> Option<Effects> {
    let length = msg.message.len();
    let limit = state.limits().max_text_message_length as usize;
    if limit > 0 && length > limit {
        return Some(denied(
            sender,
            tcp::permission_denied::DenyType::TextTooLong,
            format!("Message is {length} bytes; the limit is {limit}"),
        ));
    }

    let user_id = state.users().get(sender).and_then(|u| u.user_id);
    for channel in &msg.channel_id {
        if !state
            .permissions()
            .allows(user_id, ChannelId(*channel), Perm::TEXT_MESSAGE)
        {
            return Some(denied(
                sender,
                tcp::permission_denied::DenyType::Permission,
                "You are not permitted to send messages to that channel".to_owned(),
            ));
        }
    }
    None
}

fn denied(sender: SessionId, kind: tcp::permission_denied::DenyType, reason: String) -> Effects {
    let mut fx = Effects::none();
    let _ = fx.log(
        LogEvent::notice(Category::Permission, "text message refused")
            .with("session", sender.0)
            .with("reason", reason.clone()),
    );
    let _ = fx.send(
        Recipients::Session(sender),
        ControlMessage::PermissionDenied(tcp::PermissionDenied {
            r#type: Some(kind as i32),
            reason: Some(reason),
            ..Default::default()
        }),
    );
    fx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServerState;
    use starling_api::Effect;
    use starling_api::Limits;
    use starling_api::ServerConfig;
    use starling_api::{Sessions, World};
    use starling_model::{User, ROOT_CHANNEL};
    use std::net::SocketAddr;

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    fn join(state: &mut ServerState, id: u64, name: &str) -> (ConnId, SessionId) {
        let conn = ConnId(id);
        state.add_connection(conn, addr());
        let session = state.assign_session(conn).expect("pool has ids");
        state
            .users_mut()
            .insert(User::new(session, name, ROOT_CHANNEL));
        (conn, session)
    }

    fn send(state: &mut dyn Authority, conn: ConnId, msg: tcp::TextMessage) -> Effects {
        TextMessageHandler.handle(state, conn, ControlMessage::TextMessage(msg))
    }

    fn relayed(fx: &Effects) -> Vec<(Recipients, tcp::TextMessage)> {
        fx.as_slice()
            .iter()
            .filter_map(|e| match e {
                Effect::Send { to, msg } => match msg.as_ref() {
                    ControlMessage::TextMessage(t) => Some((*to, t.clone())),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_channel_message_reaches_the_channel_but_not_the_sender() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                channel_id: vec![ROOT_CHANNEL.0],
                message: "hello".into(),
                ..Default::default()
            },
        );

        let sends = relayed(&fx);
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, Recipients::ChannelExcept(ROOT_CHANNEL, session));
        assert_eq!(sends[0].1.message, "hello");
    }

    #[test]
    fn the_actor_is_overwritten_so_senders_cannot_be_forged() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");
        let (_, victim) = join(&mut state, 2, "bob");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                // Alice claims to be Bob.
                actor: Some(victim.0),
                channel_id: vec![ROOT_CHANNEL.0],
                message: "I am bob".into(),
                ..Default::default()
            },
        );

        assert_eq!(
            relayed(&fx)[0].1.actor,
            Some(session.0),
            "the server must relabel the message with the real sender"
        );
    }

    #[test]
    fn a_direct_message_goes_only_to_its_target() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, _) = join(&mut state, 1, "alice");
        let (_, bob) = join(&mut state, 2, "bob");
        let (_, carol) = join(&mut state, 3, "carol");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                session: vec![bob.0],
                message: "psst".into(),
                ..Default::default()
            },
        );

        let sends = relayed(&fx);
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, Recipients::Session(bob));
        assert!(!sends
            .iter()
            .any(|(to, _)| *to == Recipients::Session(carol)));
    }

    #[test]
    fn an_over_length_message_is_denied_rather_than_truncated() {
        let mut state = ServerState::new(ServerConfig {
            limits: Limits {
                max_text_message_length: 10,
                ..Default::default()
            },
            ..Default::default()
        });
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                channel_id: vec![ROOT_CHANNEL.0],
                message: "a".repeat(11),
                ..Default::default()
            },
        );

        assert!(relayed(&fx).is_empty(), "nothing should be relayed");

        // The wire effects, ignoring the log record they are accompanied by.
        let wire: Vec<_> = fx
            .as_slice()
            .iter()
            .filter(|e| !matches!(e, Effect::Log(_)))
            .collect();
        match wire.as_slice() {
            [Effect::Send { to, msg }] => {
                assert_eq!(*to, Recipients::Session(session));
                match msg.as_ref() {
                    ControlMessage::PermissionDenied(d) => assert_eq!(
                        d.r#type,
                        Some(tcp::permission_denied::DenyType::TextTooLong as i32)
                    ),
                    other => panic!("expected PermissionDenied, got {other:?}"),
                }
            }
            other => panic!("expected a single denial, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_message_is_recorded_in_the_server_log() {
        let mut state = ServerState::new(ServerConfig {
            limits: Limits {
                max_text_message_length: 10,
                ..Default::default()
            },
            ..Default::default()
        });
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                channel_id: vec![ROOT_CHANNEL.0],
                message: "a".repeat(11),
                ..Default::default()
            },
        );

        let logged = fx.logged();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].message, "text message refused");
        assert_eq!(
            logged[0].field("session"),
            Some(&starling_log::FieldValue::Uint(u64::from(session.0)))
        );
    }

    #[test]
    fn a_message_exactly_at_the_limit_is_allowed() {
        let mut state = ServerState::new(ServerConfig {
            limits: Limits {
                max_text_message_length: 10,
                ..Default::default()
            },
            ..Default::default()
        });
        let (conn, _) = join(&mut state, 1, "alice");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                channel_id: vec![ROOT_CHANNEL.0],
                message: "a".repeat(10),
                ..Default::default()
            },
        );
        assert_eq!(relayed(&fx).len(), 1);
    }

    #[test]
    fn a_denied_permission_blocks_the_relay() {
        #[derive(Debug)]
        struct NoText;
        impl starling_model::Permissions for NoText {
            fn effective(&self, _: Option<starling_model::UserId>, _: ChannelId) -> Perm {
                Perm::ALL.difference(Perm::TEXT_MESSAGE)
            }
        }

        let mut state =
            ServerState::new(ServerConfig::default()).with_permissions(Box::new(NoText));
        let (conn, _) = join(&mut state, 1, "alice");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                channel_id: vec![ROOT_CHANNEL.0],
                message: "hello".into(),
                ..Default::default()
            },
        );
        assert!(relayed(&fx).is_empty());
    }

    #[test]
    fn tree_id_recipients_are_dropped_not_silently_treated_as_channel_id() {
        // Phase 0 does not walk the tree. It must not quietly deliver to the
        // wrong set instead - that would look like it worked.
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, _) = join(&mut state, 1, "alice");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                tree_id: vec![ROOT_CHANNEL.0],
                message: "hello tree".into(),
                ..Default::default()
            },
        );
        assert!(relayed(&fx).is_empty());
    }

    #[test]
    fn the_relayed_message_never_carries_tree_id_onward() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, _) = join(&mut state, 1, "alice");

        let fx = send(
            &mut state,
            conn,
            tcp::TextMessage {
                channel_id: vec![ROOT_CHANNEL.0],
                tree_id: vec![ROOT_CHANNEL.0],
                message: "hi".into(),
                ..Default::default()
            },
        );
        assert!(relayed(&fx)[0].1.tree_id.is_empty());
    }

    #[test]
    fn a_connection_without_a_session_relays_nothing() {
        let mut state = ServerState::new(ServerConfig::default());
        state.add_connection(ConnId(9), addr());
        let fx = send(
            &mut state,
            ConnId(9),
            tcp::TextMessage {
                channel_id: vec![ROOT_CHANNEL.0],
                message: "hi".into(),
                ..Default::default()
            },
        );
        assert!(fx.is_empty());
    }
}
