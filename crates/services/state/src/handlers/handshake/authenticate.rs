//! `Authenticate` — the entry point to session establishment.

use starling_log::{Category, LogEvent};
use starling_model::{User, ROOT_CHANNEL};
use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType, Version};
use tracing::{info, warn};

use crate::handlers::handshake::sync;
use starling_api::Authority;
use starling_api::{Access, Handler};
use starling_api::{ConnId, Effects, Recipients};

/// Longest username accepted.
///
/// Phase 2 replaces the whole check with murmur's configurable `username`
/// regex; until then this is a bound, not a policy.
const MAX_USERNAME_LEN: usize = 512;

/// Establishes a session, or refuses with a reason.
#[derive(Debug, Default)]
pub struct AuthenticateHandler;

impl Handler for AuthenticateHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::Authenticate
    }

    fn access(&self) -> Access {
        // This is the message that *creates* the session.
        Access::Anonymous
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::Authenticate(msg) = msg else {
            return Effects::none();
        };

        if state.is_authenticated(conn) {
            // murmur treats a second Authenticate as an access-token update
            // (Messages.cpp:303). Tokens need ACLs, so Phase 2 implements it.
            warn!(%conn, "repeat Authenticate ignored (access tokens land in Phase 2)");
            return Effects::none();
        }

        // Security negotiation comes first: a peer the policy refuses must not
        // reach the credential check, let alone consume a session id.
        let Some(suite) = state.suite_for(conn) else {
            return Rejection::UNSUPPORTED_SECURITY.into_effects(conn);
        };

        let username = msg.username.unwrap_or_default();
        let password = msg.password.unwrap_or_default();

        if let Some(rejection) = Rejection::evaluate(state, &username, &password) {
            return rejection.into_effects(conn);
        }

        let Some(session) = state.assign_session(conn) else {
            return Rejection::SERVER_FULL_NO_SESSIONS.into_effects(conn);
        };

        let (version, fancy) = record_client_capabilities(state, conn, msg.opus.unwrap_or(false));

        let mut user = User::new(session, username.clone(), ROOT_CHANNEL);
        user.version = version;
        user.fancy_version = fancy;
        state.users_mut().insert(user);

        info!(
            %conn,
            %session,
            username,
            %version,
            security = suite.name(),
            tls = suite.tls_floor().label(),
            voice_cipher = suite.voice_cipher().name(),
            "session established"
        );

        let mut fx = Effects::none();
        let _ = fx.log(
            LogEvent::info(Category::Session, "session established")
                .with("session", session.0)
                .with("username", username)
                .with("version", version.to_string())
                .with("security", suite.name())
                .with("tls", suite.tls_floor().label())
                .with("voice_cipher", suite.voice_cipher().name()),
        );
        let _ = fx.extend(sync::codec_version(state, conn));
        let _ = fx.extend(sync::channel_tree(state, conn));
        let _ = fx.extend(sync::user_states(state, session));
        let _ = fx.extend(sync::server_sync(state, session));
        // After `ServerSync`, as murmur does: the client needs its own session
        // id before it can make sense of a key that belongs to it.
        let _ = fx.extend(super::keying::crypt_setup(state, conn));
        // The new user changes who hears whom, so the voice path needs the
        // rebuilt view — including for everyone already connected.
        let _ = fx.voice(starling_api::VoiceUpdate::Rebuild);
        fx
    }
}

/// Store what the client told us about itself, and read back what we knew.
fn record_client_capabilities(
    state: &mut dyn Authority,
    conn: ConnId,
    opus: bool,
) -> (Version, Option<u64>) {
    if let Some(c) = state.connection_mut(conn) {
        c.opus = opus;
    }
    state
        .connection(conn)
        .map_or((Version::new(0, 0, 0), None), |c| {
            (c.version, c.fancy_version)
        })
}

/// A refusal to establish a session.
struct Rejection {
    kind: tcp::reject::RejectType,
    reason: &'static str,
}

impl Rejection {
    const SERVER_FULL_NO_SESSIONS: Self = Self {
        kind: tcp::reject::RejectType::ServerFull,
        reason: "No session slots available",
    };

    /// The configured security policy will not serve this client.
    ///
    /// Only reachable under a non-default policy (`ModernOnly`). Reported as
    /// `WrongVersion` because that is the reject type stock clients render as
    /// "this server needs a different client", which is exactly the situation.
    const UNSUPPORTED_SECURITY: Self = Self {
        kind: tcp::reject::RejectType::WrongVersion,
        reason: "This server requires a client that supports its security policy",
    };

    /// Reasons to refuse, in murmur's order (`Messages.cpp:376`).
    fn evaluate(state: &dyn Authority, username: &str, password: &str) -> Option<Self> {
        if !is_valid_username(username) {
            return Some(Self {
                kind: tcp::reject::RejectType::InvalidUsername,
                reason: "Invalid username",
            });
        }
        if !state.password_accepted(password) {
            return Some(Self {
                kind: tcp::reject::RejectType::WrongServerPw,
                reason: "Invalid server password",
            });
        }
        if state.users().find_by_name(username).is_some() {
            // murmur kicks the older session instead (Messages.cpp:404).
            // Refusing the newcomer is the conservative choice while there is no
            // certificate-based identity to decide which session is genuine.
            return Some(Self {
                kind: tcp::reject::RejectType::UsernameInUse,
                reason: "Username already in use",
            });
        }
        if state.is_full() {
            return Some(Self {
                kind: tcp::reject::RejectType::ServerFull,
                reason: "Server is full",
            });
        }
        None
    }

    /// Send the reason, *then* close: a bare reset gives the user nothing.
    fn into_effects(self, conn: ConnId) -> Effects {
        warn!(%conn, reason = self.reason, "authentication refused");
        let mut fx = Effects::none();
        let _ = fx.log(
            LogEvent::warning(Category::Security, "authentication refused")
                .with("reason", self.reason)
                .with("reject_type", self.kind.as_str_name()),
        );
        let _ = fx.send(
            Recipients::Connection(conn),
            ControlMessage::Reject(tcp::Reject {
                r#type: Some(self.kind as i32),
                reason: Some(self.reason.into()),
            }),
        );
        let _ = fx.disconnect(conn, self.reason);
        fx
    }
}

/// Whether a username is acceptable.
///
/// Non-empty, length-bounded, no control characters, and no surrounding
/// whitespace — enough that a hostile name cannot corrupt logs or client
/// rendering, or impersonate another user by padding.
fn is_valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_USERNAME_LEN
        && !name.chars().any(char::is_control)
        && name.trim() == name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::handshake::VersionHandler;
    use crate::state::ServerState;
    use starling_api::Effect;
    use starling_api::Limits;
    use starling_api::ServerConfig;
    use starling_api::{Sessions, World};
    use std::net::SocketAddr;

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    fn state() -> ServerState {
        ServerState::new(ServerConfig {
            register_name: "Starling Test".into(),
            limits: Limits {
                max_users: 4,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn connect(state: &mut ServerState, id: u64) -> ConnId {
        let conn = ConnId(id);
        state.add_connection(conn, addr());
        let _ = VersionHandler.handle(
            state,
            conn,
            ControlMessage::Version(tcp::Version {
                version_v2: Some(Version::new(1, 6, 0).encode_v2()),
                ..Default::default()
            }),
        );
        conn
    }

    fn authenticate(state: &mut dyn Authority, conn: ConnId, name: &str) -> Effects {
        AuthenticateHandler.handle(
            state,
            conn,
            ControlMessage::Authenticate(tcp::Authenticate {
                username: Some(name.into()),
                opus: Some(true),
                ..Default::default()
            }),
        )
    }

    fn sent_names(fx: &Effects) -> Vec<&'static str> {
        fx.as_slice()
            .iter()
            .filter_map(|e| match e {
                Effect::Send { msg, .. } => Some(msg.name()),
                _ => None,
            })
            .collect()
    }

    fn was_rejected(fx: &Effects) -> bool {
        fx.as_slice()
            .iter()
            .any(|e| matches!(e, Effect::Disconnect { .. }))
    }

    #[test]
    fn establishment_emits_messages_in_the_documented_order() {
        let mut state = state();
        let conn = connect(&mut state, 1);
        assert_eq!(
            sent_names(&authenticate(&mut state, conn, "alice")),
            vec![
                "CodecVersion",
                "ChannelState", // root only
                "UserState",    // the newcomer, broadcast
                "ServerSync",
                "ServerConfig",
                "SuggestConfig",
                // Last, and after `ServerSync`: a client needs its own session
                // id before it can make sense of a key that belongs to it.
                "CryptSetup",
            ]
        );
    }

    #[test]
    fn the_handshake_keys_the_voice_path() {
        // Without `CryptSetup` a Mumble client never opens its UDP socket, and
        // every frame falls back to a TCP tunnel for the life of the session.
        let mut state = state();
        let conn = connect(&mut state, 1);
        let fx = authenticate(&mut state, conn, "alice");

        assert!(sent_names(&fx).contains(&"CryptSetup"));
        assert!(
            fx.as_slice().iter().any(|effect| matches!(
                effect,
                Effect::Voice(starling_api::VoiceUpdate::Attach(_))
            )),
            "the keys went to the client but not to the voice service"
        );
    }

    #[test]
    fn the_client_version_recorded_earlier_survives_onto_the_user() {
        let mut state = state();
        let conn = connect(&mut state, 1);
        let _ = authenticate(&mut state, conn, "alice");

        let session = state.session_of(conn).expect("session assigned");
        assert_eq!(
            state.users().get(session).expect("user").version,
            Version::new(1, 6, 0)
        );
    }

    #[test]
    fn a_wrong_server_password_is_rejected_and_disconnected() {
        let mut state = ServerState::new(ServerConfig {
            server_password: "hunter2".into(),
            ..Default::default()
        });
        let conn = connect(&mut state, 1);
        let fx = AuthenticateHandler.handle(
            &mut state,
            conn,
            ControlMessage::Authenticate(tcp::Authenticate {
                username: Some("alice".into()),
                password: Some("wrong".into()),
                ..Default::default()
            }),
        );

        // The wire effects, ignoring the log record those are accompanied by.
        let wire: Vec<_> = fx
            .as_slice()
            .iter()
            .filter(|e| !matches!(e, Effect::Log(_)))
            .collect();
        match wire.as_slice() {
            [Effect::Send { msg, .. }, Effect::Disconnect { .. }] => match msg.as_ref() {
                ControlMessage::Reject(r) => assert_eq!(
                    r.r#type,
                    Some(tcp::reject::RejectType::WrongServerPw as i32)
                ),
                other => panic!("expected Reject, got {other:?}"),
            },
            other => panic!("expected Reject then Disconnect, got {other:?}"),
        }
        assert!(
            state.users().is_empty(),
            "a rejected peer must not be added"
        );
    }

    #[test]
    fn a_refusal_is_recorded_in_the_server_log() {
        // An operator investigating a lockout needs the refusal, not just the
        // successes.
        let mut state = ServerState::new(ServerConfig {
            server_password: "hunter2".into(),
            ..Default::default()
        });
        let conn = connect(&mut state, 1);
        let fx = AuthenticateHandler.handle(
            &mut state,
            conn,
            ControlMessage::Authenticate(tcp::Authenticate {
                username: Some("alice".into()),
                password: Some("wrong".into()),
                ..Default::default()
            }),
        );

        let logged = fx.logged();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].message, "authentication refused");
        assert_eq!(logged[0].category, Category::Security);
    }

    #[test]
    fn an_established_session_is_recorded_with_its_negotiated_security() {
        let mut state = state();
        let conn = connect(&mut state, 1);
        let fx = authenticate(&mut state, conn, "alice");

        let logged = fx.logged();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].message, "session established");
        assert!(logged[0].field("security").is_some());
        assert!(logged[0].field("voice_cipher").is_some());
    }

    #[test]
    fn the_correct_server_password_is_accepted() {
        let mut state = ServerState::new(ServerConfig {
            server_password: "hunter2".into(),
            ..Default::default()
        });
        let conn = connect(&mut state, 1);
        let fx = AuthenticateHandler.handle(
            &mut state,
            conn,
            ControlMessage::Authenticate(tcp::Authenticate {
                username: Some("alice".into()),
                password: Some("hunter2".into()),
                ..Default::default()
            }),
        );
        assert!(!was_rejected(&fx));
        assert_eq!(state.users().len(), 1);
    }

    #[test]
    fn invalid_usernames_are_rejected() {
        for (name, why) in [
            ("", "empty"),
            ("bad\u{0}name", "control character"),
            (" leading", "untrimmed"),
            ("trailing ", "untrimmed"),
            (&"x".repeat(MAX_USERNAME_LEN + 1), "too long"),
        ] {
            let mut state = state();
            let conn = connect(&mut state, 1);
            assert!(
                was_rejected(&authenticate(&mut state, conn, name)),
                "{why} username should be rejected"
            );
            assert!(state.users().is_empty());
        }
    }

    #[test]
    fn a_username_exactly_at_the_limit_is_accepted() {
        let mut state = state();
        let conn = connect(&mut state, 1);
        let name = "x".repeat(MAX_USERNAME_LEN);
        assert!(!was_rejected(&authenticate(&mut state, conn, &name)));
    }

    #[test]
    fn a_duplicate_username_is_refused_without_disturbing_the_incumbent() {
        let mut state = state();
        let alice = connect(&mut state, 1);
        let _ = authenticate(&mut state, alice, "alice");

        let impostor = connect(&mut state, 2);
        assert!(was_rejected(&authenticate(&mut state, impostor, "alice")));
        assert_eq!(state.users().len(), 1, "the incumbent must be untouched");
    }

    #[test]
    fn a_full_server_refuses_rather_than_over_admitting() {
        let mut state = ServerState::new(ServerConfig {
            limits: Limits {
                max_users: 1,
                ..Default::default()
            },
            ..Default::default()
        });
        let first = connect(&mut state, 1);
        let _ = authenticate(&mut state, first, "alice");

        let second = connect(&mut state, 2);
        assert!(was_rejected(&authenticate(&mut state, second, "bob")));
        assert_eq!(state.users().len(), 1);
    }

    #[test]
    fn a_rejected_connection_does_not_consume_a_session_id() {
        let mut state = state();
        let conn = connect(&mut state, 1);
        let before = state.sessions_available();
        let _ = authenticate(&mut state, conn, "");
        assert_eq!(state.sessions_available(), before);
    }

    #[test]
    fn a_repeat_authenticate_does_not_allocate_a_second_session() {
        let mut state = state();
        let conn = connect(&mut state, 1);
        let _ = authenticate(&mut state, conn, "alice");
        let available = state.sessions_available();

        let fx = authenticate(&mut state, conn, "alice-again");
        assert!(fx.is_empty());
        assert_eq!(state.sessions_available(), available);
        assert_eq!(state.users().len(), 1);
    }

    #[test]
    fn the_handler_is_reachable_before_authentication() {
        assert_eq!(AuthenticateHandler.access(), Access::Anonymous);
    }
}
