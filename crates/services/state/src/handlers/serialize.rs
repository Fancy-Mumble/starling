//! Model → wire serialisation.
//!
//! Kept in one place because several handlers emit the same shapes: `UserState`
//! is sent at join, on every self-state change and on every move, and
//! `ChannelState` at join and on every channel edit. Two copies of these would
//! drift, and the drift would be a protocol bug.

use starling_model::{Channel, User};
use starling_proto::proto::tcp;

/// Serialise a user into a full `UserState`.
///
/// Optional booleans are emitted only when `true`: Mumble treats an absent field
/// as "unchanged", so writing `Some(false)` everywhere would be correct but
/// noticeably larger on a busy server, and murmur does the same
/// (`Messages.cpp:671`).
#[must_use]
pub fn user_state(user: &User) -> tcp::UserState {
    tcp::UserState {
        session: Some(user.session.0),
        name: Some(user.name.clone()),
        user_id: user.user_id.map(|id| id.0),
        channel_id: Some(user.channel.0),
        mute: user.mute.then_some(true),
        deaf: user.deaf.then_some(true),
        suppress: user.suppress.then_some(true),
        self_mute: user.self_mute.then_some(true),
        self_deaf: user.self_deaf.then_some(true),
        recording: user.recording.then_some(true),
        hash: user.cert_hash.clone(),
        ..Default::default()
    }
}

/// Serialise a channel into a `ChannelState`.
#[must_use]
pub fn channel_state(channel: &Channel) -> tcp::ChannelState {
    let mut msg = tcp::ChannelState {
        channel_id: Some(channel.id.0),
        parent: channel.parent.map(|p| p.0),
        name: Some(channel.name.clone()),
        position: Some(channel.position),
        max_users: Some(channel.max_users),
        description: (!channel.description.is_empty()).then(|| channel.description.clone()),
        ..Default::default()
    };
    set_legacy_temporary(&mut msg, channel.temporary);
    msg
}

/// Write the proto-deprecated `temporary` flag, which stock clients still need.
///
/// See `PORTING-PLAN.md` §9 for why this suppression exists.
#[expect(
    deprecated,
    reason = "the only temporary-channel signal stock clients understand"
)]
fn set_legacy_temporary(msg: &mut tcp::ChannelState, temporary: bool) {
    msg.temporary = Some(temporary);
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_model::{ChannelId, SessionId, UserId, ROOT_CHANNEL};

    fn user() -> User {
        User::new(SessionId(7), "alice", ROOT_CHANNEL)
    }

    #[test]
    fn a_default_user_emits_no_state_flags() {
        let msg = user_state(&user());
        assert_eq!(msg.session, Some(7));
        assert_eq!(msg.name.as_deref(), Some("alice"));
        assert_eq!(msg.channel_id, Some(ROOT_CHANNEL.0));
        // Absent, not `Some(false)`: absent means "unchanged" on the wire.
        assert_eq!(msg.mute, None);
        assert_eq!(msg.self_mute, None);
        assert_eq!(msg.recording, None);
    }

    #[test]
    fn set_flags_are_emitted_as_true() {
        let mut u = user();
        u.self_mute = true;
        u.recording = true;
        let msg = user_state(&u);
        assert_eq!(msg.self_mute, Some(true));
        assert_eq!(msg.recording, Some(true));
        assert_eq!(msg.self_deaf, None, "unset flags stay absent");
    }

    #[test]
    fn an_anonymous_user_has_no_user_id() {
        assert_eq!(user_state(&user()).user_id, None);
    }

    #[test]
    fn a_registered_user_carries_its_account_id() {
        let mut u = user();
        u.user_id = Some(UserId(42));
        assert_eq!(user_state(&u).user_id, Some(42));
    }

    #[test]
    fn the_root_channel_is_serialised_without_a_parent() {
        let msg = channel_state(&Channel::new(ROOT_CHANNEL, None, "Root"));
        assert_eq!(msg.channel_id, Some(0));
        assert_eq!(msg.parent, None);
        assert_eq!(msg.name.as_deref(), Some("Root"));
    }

    #[test]
    fn a_child_channel_carries_its_parent() {
        let msg = channel_state(&Channel::new(ChannelId(3), Some(ROOT_CHANNEL), "Lobby"));
        assert_eq!(msg.parent, Some(ROOT_CHANNEL.0));
    }

    #[test]
    fn an_empty_description_is_omitted_rather_than_sent_blank() {
        // Sending an empty description would clear a description the client
        // already holds from a blob hash.
        assert_eq!(
            channel_state(&Channel::new(ChannelId(1), None, "x")).description,
            None
        );
    }

    #[test]
    fn a_present_description_is_sent() {
        let mut channel = Channel::new(ChannelId(1), Some(ROOT_CHANNEL), "Lobby");
        channel.description = "hello".into();
        assert_eq!(
            channel_state(&channel).description.as_deref(),
            Some("hello")
        );
    }
}
