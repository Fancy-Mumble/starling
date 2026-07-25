//! `UserState` — self-mute/deaf, recording, and channel moves.
//!
//! Phase 0 implements only the changes a user may make **to themselves**.
//! Administrative changes — `mute`, `deaf` and `suppress` applied *to someone
//! else*, priority speaker, registration, and moving other users — need ACL
//! evaluation and arrive in Phase 2.
//!
//! # Self-service is not administrative
//!
//! `comment` and `texture` look administrative and are not. murmur asks for
//! `SelfRegister` when the target is the sender and `Register` otherwise
//! (`Messages.cpp:177`), so setting your own avatar or comment is an ordinary
//! thing a user does — and refusing it broke real clients, which set both while
//! restoring a profile on connect.
//!
//! The distinction that matters is *whose* state is being changed, not which
//! field. `mute` and `deaf` are administrative because they are the moderator's
//! versions of `self_mute` and `self_deaf`; a user silencing themselves sends
//! the `self_` pair and is always allowed.
//!
//! The security-relevant rule is that the *actor* comes from the connection,
//! never from the message. `UserState.session` names the user being changed; a
//! client that names someone else is asking to modify another user, which is an
//! administrative action and is refused.

use starling_log::{Category, LogEvent};
use starling_model::{ChannelId, SessionId};
use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType};
use tracing::warn;

use starling_api::Authority;
use starling_api::Handler;
use starling_api::{ConnId, Effects, Recipients};

/// Applies self-state changes and broadcasts the result.
#[derive(Debug, Default)]
pub struct UserStateHandler;

impl Handler for UserStateHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::UserState
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::UserState(msg) = msg else {
            return Effects::none();
        };
        let Some(actor) = state.session_of(conn) else {
            return Effects::none();
        };

        // Absent `session` means "me" (the client's usual shorthand).
        if msg.session.map_or(actor, SessionId) != actor {
            return denied(
                actor,
                "Changing another user's state requires administrative permissions",
            );
        }
        if let Some(field) = administrative_field(&msg) {
            // Naming the field is the whole point. "That change requires
            // administrative permissions" told an operator nothing about which
            // of eight fields was at fault, and cost real time on a client that
            // was silently refused during connect.
            // The whole message at `debug`, because the field name alone still
            // does not say which *client action* sent it — and a refusal during
            // connect is invisible in the client's own log beyond a generic
            // "permission denied".
            warn!(%actor, field, "administrative user state change refused");
            tracing::debug!(%actor, ?msg, "the refused user state message");
            return denied(
                actor,
                &format!("Changing `{field}` requires administrative permissions (Phase 2)"),
            );
        }
        if msg.recording.is_some() && !state.limits().allow_recording {
            return denied(actor, "Recording is not allowed on this server");
        }

        apply(state, actor, &msg)
    }
}

/// Apply the accepted changes, folding them into one broadcast so clients see a
/// single atomic update rather than a flicker of intermediate states.
fn apply(state: &mut dyn Authority, actor: SessionId, msg: &tcp::UserState) -> Effects {
    // Validate the move before mutating anything, so a bad target cannot leave
    // half the change applied.
    let target_channel = match msg.channel_id.map(ChannelId) {
        Some(channel) if !state.channels().contains(channel) => {
            warn!(%actor, %channel, "move to a non-existent channel refused");
            return denied(actor, "That channel does not exist");
        }
        other => other,
    };

    let mut announcement = Announcement::by(actor);

    if let Some(user) = state.users_mut().get_mut(actor) {
        announcement.apply_self_flags(user, msg);
    } else {
        return Effects::none();
    }

    if let Some(channel) = target_channel {
        if state.users_mut().move_to(actor, channel).is_some() {
            announcement.moved_to(channel);
        }
    }

    let Some(changed) = announcement.finish() else {
        return Effects::none();
    };

    let mut fx = Effects::none();
    let _ = fx.send(Recipients::All, ControlMessage::UserState(changed));
    fx
}

/// What changed about a user, accumulated as it is applied.
///
/// A struct because the message under construction *is* state: it used to be a
/// `&mut tcp::UserState` out-parameter plus a `bool` return, so a caller had to
/// remember to thread both and to combine the flags with `|=`. Here the
/// accumulator is a field and "did anything change" is [`Self::finish`] returning
/// `None`.
#[derive(Debug)]
struct Announcement {
    changed: tcp::UserState,
    any: bool,
}

impl Announcement {
    /// An empty announcement attributed to `actor`.
    fn by(actor: SessionId) -> Self {
        Self {
            changed: tcp::UserState {
                session: Some(actor.0),
                actor: Some(actor.0),
                ..Default::default()
            },
            any: false,
        }
    }

    /// Apply mute/deaf/recording to the user, recording what changed.
    ///
    /// Kept apart from [`apply`] so that stays about sequencing and this stays
    /// about the mute/deaf interaction rules.
    fn apply_self_flags(&mut self, user: &mut starling_model::User, msg: &tcp::UserState) {
        if let Some(self_mute) = msg.self_mute {
            user.self_mute = self_mute;
            // Unmuting also undeafens: staying deafened while unmuted is a state
            // the client cannot represent.
            if !self_mute && user.self_deaf {
                user.self_deaf = false;
                self.changed.self_deaf = Some(false);
            }
            self.changed.self_mute = Some(self_mute);
            self.any = true;
        }

        if let Some(self_deaf) = msg.self_deaf {
            user.self_deaf = self_deaf;
            // Deafening implies muting.
            if self_deaf && !user.self_mute {
                user.self_mute = true;
                self.changed.self_mute = Some(true);
            }
            self.changed.self_deaf = Some(self_deaf);
            self.any = true;
        }

        if let Some(recording) = msg.recording {
            user.recording = recording;
            self.changed.recording = Some(recording);
            self.any = true;
        }
    }

    /// Record a channel move.
    fn moved_to(&mut self, channel: ChannelId) {
        self.changed.channel_id = Some(channel.0);
        self.any = true;
    }

    /// The message to broadcast, or `None` if nothing actually changed.
    fn finish(self) -> Option<tcp::UserState> {
        self.any.then_some(self.changed)
    }
}

/// The first field the message sets that only an administrator may set.
///
/// Returns the field's name rather than a bare `bool` so the refusal can say
/// which one — the caller has no other way to find out, and neither has anyone
/// reading the log afterwards.
///
/// `comment` and `texture` are deliberately absent: they are self-service, and
/// listing them here refused clients doing something entirely ordinary. See the
/// module docs.
fn administrative_field(msg: &tcp::UserState) -> Option<&'static str> {
    // The moderator counterparts of `self_mute` and `self_deaf`. A user
    // silencing themselves sends the `self_` pair, which is always allowed.
    if msg.mute.is_some() {
        return Some("mute");
    }
    if msg.deaf.is_some() {
        return Some("deaf");
    }
    if msg.suppress.is_some() {
        return Some("suppress");
    }
    if msg.priority_speaker.is_some() {
        return Some("priority_speaker");
    }
    if msg.user_id.is_some() {
        return Some("user_id");
    }
    None
}

fn denied(actor: SessionId, reason: &str) -> Effects {
    let mut fx = Effects::none();
    let _ = fx.log(
        LogEvent::notice(Category::Permission, "user state change refused")
            .with("session", actor.0)
            .with("reason", reason.to_owned()),
    );
    let _ = fx.send(
        Recipients::Session(actor),
        ControlMessage::PermissionDenied(tcp::PermissionDenied {
            r#type: Some(tcp::permission_denied::DenyType::Permission as i32),
            reason: Some(reason.to_owned()),
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

    fn update(state: &mut dyn Authority, conn: ConnId, msg: tcp::UserState) -> Effects {
        UserStateHandler.handle(state, conn, ControlMessage::UserState(msg))
    }

    fn broadcast(fx: &Effects) -> Option<tcp::UserState> {
        fx.as_slice().iter().find_map(|e| match e {
            Effect::Send {
                to: Recipients::All,
                msg,
            } => match msg.as_ref() {
                ControlMessage::UserState(u) => Some(u.clone()),
                _ => None,
            },
            _ => None,
        })
    }

    fn is_denial(fx: &Effects) -> bool {
        fx.as_slice().iter().any(|e| match e {
            Effect::Send { msg, .. } => matches!(msg.as_ref(), ControlMessage::PermissionDenied(_)),
            _ => false,
        })
    }

    #[test]
    fn self_mute_is_applied_and_broadcast() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                self_mute: Some(true),
                ..Default::default()
            },
        );

        assert!(state.users().get(session).expect("user").self_mute);
        let sent = broadcast(&fx).expect("change must be broadcast");
        assert_eq!(sent.session, Some(session.0));
        assert_eq!(sent.self_mute, Some(true));
    }

    #[test]
    fn deafening_implies_muting() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                self_deaf: Some(true),
                ..Default::default()
            },
        );

        let user = state.users().get(session).expect("user");
        assert!(user.self_deaf && user.self_mute);
        assert_eq!(
            broadcast(&fx).expect("broadcast").self_mute,
            Some(true),
            "the implied mute must be told to clients"
        );
    }

    #[test]
    fn unmuting_also_undeafens() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");
        let _ = update(
            &mut state,
            conn,
            tcp::UserState {
                self_deaf: Some(true),
                ..Default::default()
            },
        );

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                self_mute: Some(false),
                ..Default::default()
            },
        );

        let user = state.users().get(session).expect("user");
        assert!(!user.self_mute && !user.self_deaf);
        assert_eq!(broadcast(&fx).expect("broadcast").self_deaf, Some(false));
    }

    #[test]
    fn changing_another_user_is_refused() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, _) = join(&mut state, 1, "alice");
        let (_, bob) = join(&mut state, 2, "bob");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                session: Some(bob.0),
                self_mute: Some(true),
                ..Default::default()
            },
        );

        assert!(is_denial(&fx));
        assert!(
            !state.users().get(bob).expect("bob").self_mute,
            "bob must be untouched"
        );
    }

    #[test]
    fn administrative_fields_are_refused_not_silently_ignored() {
        for (label, msg) in [
            (
                "mute",
                tcp::UserState {
                    mute: Some(true),
                    ..Default::default()
                },
            ),
            (
                "suppress",
                tcp::UserState {
                    suppress: Some(true),
                    ..Default::default()
                },
            ),
            (
                "user_id",
                tcp::UserState {
                    user_id: Some(1),
                    ..Default::default()
                },
            ),
        ] {
            let mut state = ServerState::new(ServerConfig::default());
            let (conn, _) = join(&mut state, 1, "alice");
            assert!(
                is_denial(&update(&mut state, conn, msg)),
                "{label} should be refused"
            );
        }
    }

    #[test]
    fn a_user_can_move_to_an_existing_channel() {
        let mut state = ServerState::new(ServerConfig::default());
        let lobby = state
            .channels_mut()
            .insert(ROOT_CHANNEL, "Lobby")
            .expect("root exists");
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                channel_id: Some(lobby.0),
                ..Default::default()
            },
        );

        assert_eq!(state.users().get(session).expect("user").channel, lobby);
        assert_eq!(state.users().in_channel(lobby), vec![session]);
        assert_eq!(broadcast(&fx).expect("broadcast").channel_id, Some(lobby.0));
    }

    #[test]
    fn moving_to_a_nonexistent_channel_is_refused() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                channel_id: Some(4242),
                ..Default::default()
            },
        );

        assert!(is_denial(&fx));
        assert_eq!(
            state.users().get(session).expect("user").channel,
            ROOT_CHANNEL,
            "a failed move must not relocate the user"
        );
    }

    #[test]
    fn a_bad_move_does_not_half_apply_an_accompanying_flag_change() {
        // Validation happens before any mutation, so the mute in this message
        // must not survive the refused move.
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                channel_id: Some(4242),
                self_mute: Some(true),
                ..Default::default()
            },
        );

        assert!(is_denial(&fx));
        assert!(!state.users().get(session).expect("user").self_mute);
    }

    #[test]
    fn a_move_and_a_flag_change_arrive_as_one_broadcast() {
        let mut state = ServerState::new(ServerConfig::default());
        let lobby = state
            .channels_mut()
            .insert(ROOT_CHANNEL, "Lobby")
            .expect("root exists");
        let (conn, _) = join(&mut state, 1, "alice");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                channel_id: Some(lobby.0),
                self_mute: Some(true),
                ..Default::default()
            },
        );

        assert_eq!(fx.len(), 1, "clients must not see an intermediate state");
        let sent = broadcast(&fx).expect("broadcast");
        assert_eq!(sent.channel_id, Some(lobby.0));
        assert_eq!(sent.self_mute, Some(true));
    }

    #[test]
    fn recording_is_refused_when_the_server_disallows_it() {
        let mut state = ServerState::new(ServerConfig {
            limits: Limits {
                allow_recording: false,
                ..Default::default()
            },
            ..Default::default()
        });
        let (conn, session) = join(&mut state, 1, "alice");

        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                recording: Some(true),
                ..Default::default()
            },
        );

        assert!(is_denial(&fx));
        assert!(!state.users().get(session).expect("user").recording);
    }

    #[test]
    fn recording_is_applied_when_the_server_allows_it() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, session) = join(&mut state, 1, "alice");
        let fx = update(
            &mut state,
            conn,
            tcp::UserState {
                recording: Some(true),
                ..Default::default()
            },
        );
        assert!(state.users().get(session).expect("user").recording);
        assert_eq!(broadcast(&fx).expect("broadcast").recording, Some(true));
    }

    #[test]
    fn a_message_that_changes_nothing_produces_no_broadcast() {
        let mut state = ServerState::new(ServerConfig::default());
        let (conn, _) = join(&mut state, 1, "alice");
        assert!(update(&mut state, conn, tcp::UserState::default()).is_empty());
    }
}
