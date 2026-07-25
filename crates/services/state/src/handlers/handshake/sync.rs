//! The tail of session establishment: tree push, roster, and sync.

use starling_model::{SessionId, ROOT_CHANNEL};
use starling_proto::proto::tcp;
use starling_proto::ControlMessage;
use tracing::warn;

use crate::handlers::serialize;
use starling_api::Authority;
use starling_api::{ConnId, Effects, Recipients};

/// Step 2: the negotiated codec.
///
/// Opus-only. CELT has been dead since Mumble 1.3, the e2e fixture sets
/// `opusthreshold=0`, and a CELT fallback would be untested code on a path no
/// current client takes.
pub(super) fn codec_version(state: &dyn Authority, conn: ConnId) -> Effects {
    if !state.connection(conn).is_some_and(|c| c.opus) {
        warn!(%conn, "client did not announce Opus support; it will not be able to talk");
    }

    let mut fx = Effects::none();
    let _ = fx.send(
        Recipients::Connection(conn),
        ControlMessage::CodecVersion(tcp::CodecVersion {
            alpha: 0,
            beta: 0,
            prefer_alpha: true,
            opus: Some(true),
        }),
    );
    fx
}

/// Step 3: the channel tree, parents before children.
pub(super) fn channel_tree(state: &dyn Authority, conn: ConnId) -> Effects {
    let mut fx = Effects::none();
    for channel in state.channels().breadth_first() {
        let _ = fx.send(
            Recipients::Connection(conn),
            ControlMessage::ChannelState(serialize::channel_state(channel)),
        );
    }
    fx
}

/// Steps 4–5: announce the newcomer, then describe everyone else to them.
pub(super) fn user_states(state: &dyn Authority, session: SessionId) -> Effects {
    let mut fx = Effects::none();

    let Some(newcomer) = state.users().get(session) else {
        return fx;
    };

    // 4. To everyone including the newcomer: the client needs its own UserState
    //    before ServerSync so it can resolve its own session.
    let _ = fx.send(
        Recipients::All,
        ControlMessage::UserState(serialize::user_state(newcomer)),
    );

    // 5. Everyone else, only to the newcomer.
    for other in state.users().all().iter().filter(|u| u.session != session) {
        let _ = fx.send(
            Recipients::Session(session),
            ControlMessage::UserState(serialize::user_state(other)),
        );
    }
    fx
}

/// Steps 6–8: `ServerSync`, `ServerConfig`, `SuggestConfig`.
pub(super) fn server_sync(state: &dyn Authority, session: SessionId) -> Effects {
    let limits = state.limits();
    let user_id = state.users().get(session).and_then(|u| u.user_id);
    let permissions = state.permissions().effective(user_id, ROOT_CHANNEL);

    let mut fx = Effects::none();
    let _ = fx.send(
        Recipients::Session(session),
        ControlMessage::ServerSync(tcp::ServerSync {
            session: Some(session.0),
            max_bandwidth: Some(limits.max_bandwidth),
            welcome_text: (!limits.welcome_text.is_empty()).then(|| limits.welcome_text.clone()),
            permissions: Some(u64::from(permissions.bits())),
        }),
    );
    let _ = fx.send(
        Recipients::Session(session),
        ControlMessage::ServerConfig(tcp::ServerConfig {
            // max_bandwidth and welcome_text belong to ServerSync; repeating
            // them here is what murmur does *not* do (Messages.cpp:808).
            max_bandwidth: None,
            welcome_text: None,
            allow_html: Some(limits.allow_html),
            message_length: Some(limits.max_text_message_length),
            image_message_length: Some(limits.max_image_message_length),
            max_users: Some(limits.max_users),
            recording_allowed: Some(limits.allow_recording),
            ..Default::default()
        }),
    );
    let _ = fx.send(
        Recipients::Session(session),
        ControlMessage::SuggestConfig(tcp::SuggestConfig::default()),
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
    use starling_model::User;

    fn state() -> ServerState {
        ServerState::new(ServerConfig {
            register_name: "Starling Test".into(),
            limits: Limits {
                welcome_text: "hello".into(),
                max_bandwidth: 320_000,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn join(state: &mut dyn Authority, session: u32, name: &str) -> SessionId {
        let session = SessionId(session);
        state
            .users_mut()
            .insert(User::new(session, name, ROOT_CHANNEL));
        session
    }

    fn first<T>(fx: &Effects, pick: impl Fn(&ControlMessage) -> Option<T>) -> T {
        fx.as_slice()
            .iter()
            .find_map(|e| match e {
                Effect::Send { msg, .. } => pick(msg),
                _ => None,
            })
            .expect("expected message was not sent")
    }

    #[test]
    fn the_codec_is_advertised_as_opus() {
        let mut state = state();
        state.add_connection(ConnId(1), "127.0.0.1:1".parse().expect("addr"));
        let codec = first(&codec_version(&state, ConnId(1)), |m| match m {
            ControlMessage::CodecVersion(c) => Some(*c),
            _ => None,
        });
        assert_eq!(codec.opus, Some(true));
    }

    #[test]
    fn the_channel_tree_is_sent_parents_first() {
        let mut state = state();
        let a = state
            .channels_mut()
            .insert(ROOT_CHANNEL, "A")
            .expect("root exists");
        let b = state.channels_mut().insert(a, "B").expect("a exists");

        let ids: Vec<_> = channel_tree(&state, ConnId(1))
            .as_slice()
            .iter()
            .filter_map(|e| match e {
                Effect::Send { msg, .. } => match msg.as_ref() {
                    ControlMessage::ChannelState(c) => c.channel_id,
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(ids, vec![ROOT_CHANNEL.0, a.0, b.0]);
    }

    #[test]
    fn the_root_channel_is_named_after_register_name() {
        let state = state();
        let channel = first(&channel_tree(&state, ConnId(1)), |m| match m {
            ControlMessage::ChannelState(c) => Some(c.clone()),
            _ => None,
        });
        assert_eq!(channel.name.as_deref(), Some("Starling Test"));
        assert_eq!(channel.parent, None);
    }

    #[test]
    fn the_newcomer_is_broadcast_but_incumbents_go_only_to_them() {
        let mut state = state();
        let _alice = join(&mut state, 1, "alice");
        let bob = join(&mut state, 2, "bob");

        let sends: Vec<_> = user_states(&state, bob)
            .as_slice()
            .iter()
            .filter_map(|e| match e {
                Effect::Send { to, msg } => match msg.as_ref() {
                    ControlMessage::UserState(u) => Some((*to, u.name.clone())),
                    _ => None,
                },
                _ => None,
            })
            .collect();

        assert_eq!(
            sends,
            vec![
                (Recipients::All, Some("bob".into())),
                (Recipients::Session(bob), Some("alice".into())),
            ]
        );
    }

    #[test]
    fn user_states_for_an_unknown_session_produce_nothing() {
        let state = state();
        assert!(user_states(&state, SessionId(99)).is_empty());
    }

    #[test]
    fn server_sync_carries_the_clients_own_session_and_welcome_text() {
        let mut state = state();
        let alice = join(&mut state, 1, "alice");

        let sync = first(&server_sync(&state, alice), |m| match m {
            ControlMessage::ServerSync(s) => Some(s.clone()),
            _ => None,
        });
        assert_eq!(sync.session, Some(alice.0));
        assert_eq!(sync.welcome_text.as_deref(), Some("hello"));
        assert_eq!(sync.max_bandwidth, Some(320_000));
    }

    #[test]
    fn an_empty_welcome_text_is_omitted_rather_than_sent_blank() {
        let mut state = ServerState::new(ServerConfig::default());
        let alice = join(&mut state, 1, "alice");
        let sync = first(&server_sync(&state, alice), |m| match m {
            ControlMessage::ServerSync(s) => Some(s.clone()),
            _ => None,
        });
        assert_eq!(sync.welcome_text, None);
    }

    #[test]
    fn server_config_reports_the_configured_limits() {
        let mut state = ServerState::new(ServerConfig {
            limits: Limits {
                max_text_message_length: 131_072,
                max_image_message_length: 10_485_760,
                max_users: 100,
                allow_html: true,
                ..Default::default()
            },
            ..Default::default()
        });
        let alice = join(&mut state, 1, "alice");

        let config = first(&server_sync(&state, alice), |m| match m {
            ControlMessage::ServerConfig(c) => Some(c.clone()),
            _ => None,
        });
        assert_eq!(config.message_length, Some(131_072));
        assert_eq!(config.image_message_length, Some(10_485_760));
        assert_eq!(config.max_users, Some(100));
        assert_eq!(config.allow_html, Some(true));
    }

    #[test]
    fn the_sync_tail_ends_with_suggest_config() {
        let mut state = state();
        let alice = join(&mut state, 1, "alice");
        let names: Vec<_> = server_sync(&state, alice)
            .as_slice()
            .iter()
            .filter_map(|e| match e {
                Effect::Send { msg, .. } => Some(msg.name()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["ServerSync", "ServerConfig", "SuggestConfig"]);
    }
}
