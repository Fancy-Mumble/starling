//! `VoiceTarget` — registering a whisper or shout slot.
//!
//! Wire type 19. The client says "target 3 means these users and this channel",
//! and afterwards sends audio at target 3. The audio header has five bits, so
//! there are thirty usable slots per session; 0 is normal speech and 31 is the
//! server loopback, and neither can be reassigned.
//!
//! # Why the authority handles this and not the voice service
//!
//! The slots decide *who hears whom*, which is the authority's subject. The
//! voice service is told the result the same way it is told about channel
//! membership: through a rebuilt view. Letting the client register targets
//! directly with the voice service would put an unauthenticated,
//! unpermission-checked write on the packet path.
//!
//! # What is not checked yet
//!
//! murmur verifies the speaker may *whisper* into each target channel before
//! accepting it (`Messages.cpp`, `ChanACL::Whisper`). There is no ACL evaluation
//! in Starling yet, so a target is accepted as written. That is a permissive
//! gap, recorded in `docs/GAP-ANALYSIS.md` under A1 — not a silent one.

use starling_api::{Access, Authority, ConnId, Effects, Handler, VoiceUpdate};
use starling_log::{Category, LogEvent};
use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType};
use tracing::debug;

/// Records a client's whisper and shout targets.
#[derive(Debug, Default)]
pub struct VoiceTargetHandler;

impl Handler for VoiceTargetHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::VoiceTarget
    }

    fn access(&self) -> Access {
        // A target names sessions and channels, so it means nothing before the
        // peer has a session of its own.
        Access::Authenticated
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::VoiceTarget(msg) = msg else {
            return Effects::none();
        };
        let Some(session) = state.session_of(conn) else {
            return Effects::none();
        };

        // The wire field is a `u32` and the header has five bits for it. A slot
        // that cannot fit is refused rather than truncated: truncating would
        // silently point the client at somebody else's target.
        let Some(slot) = msg.id.and_then(|id| u8::try_from(id).ok()) else {
            debug!(%conn, %session, id = ?msg.id, "voice target slot out of range");
            return Effects::none();
        };

        let registered = state.set_voice_target(session, slot, &msg.targets);
        if !registered {
            debug!(%conn, %session, slot, "voice target refused");
            return Effects::none();
        }

        debug!(%conn, %session, slot, groups = msg.targets.len(), "voice target registered");

        let mut fx = Effects::none();
        let _ = fx.log(
            LogEvent::info(Category::Session, "voice target registered")
                .with("session", session.0)
                .with("target", u64::from(slot)),
        );
        // The slot changes who hears this speaker, which is the view the voice
        // service routes from.
        let _ = fx.voice(VoiceUpdate::Rebuild);
        fx
    }
}

/// One entry of a `VoiceTarget` message, in the authority's own terms.
///
/// Mirrors `tcp::voice_target::Target` without the protobuf `Option` wrappers,
/// so the state layer does not have to unwrap them at every use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetGroup {
    /// Sessions to whisper to.
    pub sessions: Vec<u32>,
    /// A channel to shout into, if this entry names one.
    pub channel: Option<u32>,
    /// Whether the shout carries into linked channels.
    pub links: bool,
    /// Whether the shout carries into sub-channels.
    pub children: bool,
}

impl From<&tcp::voice_target::Target> for TargetGroup {
    fn from(target: &tcp::voice_target::Target) -> Self {
        Self {
            sessions: target.session.clone(),
            channel: target.channel_id,
            // Absent means false, which is also protobuf 3's default — stated
            // rather than relied on, because the two agreeing is a coincidence.
            links: target.links.unwrap_or(false),
            children: target.children.unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServerState;
    use starling_api::{ServerConfig, Sessions};
    use starling_model::SessionId;

    /// A state with one authenticated connection.
    fn authenticated() -> (ServerState, ConnId, SessionId) {
        let mut state = ServerState::new(ServerConfig::default());
        let conn = ConnId(1);
        state.add_connection(conn, "203.0.113.7:50000".parse().expect("address"));
        let session = state.assign_session(conn).expect("session");
        (state, conn, session)
    }

    fn register(state: &mut ServerState, conn: ConnId, id: Option<u32>) -> Effects {
        VoiceTargetHandler.handle(
            state,
            conn,
            ControlMessage::VoiceTarget(tcp::VoiceTarget {
                id,
                targets: vec![tcp::voice_target::Target {
                    session: vec![7],
                    ..Default::default()
                }],
            }),
        )
    }

    fn rebuilt(fx: &Effects) -> bool {
        fx.as_slice()
            .iter()
            .any(|effect| matches!(effect, starling_api::Effect::Voice(VoiceUpdate::Rebuild)))
    }

    #[test]
    fn a_legal_slot_is_registered_and_republished() {
        let (mut state, conn, session) = authenticated();
        let fx = register(&mut state, conn, Some(3));

        assert!(rebuilt(&fx), "the voice path was not told");
        assert!(state.voice_target(session, 3).is_some());
    }

    #[test]
    fn every_legal_slot_is_accepted() {
        let (mut state, conn, _) = authenticated();
        for slot in 1..=30 {
            assert!(
                rebuilt(&register(&mut state, conn, Some(slot))),
                "slot {slot} was refused"
            );
        }
    }

    #[test]
    fn the_reserved_slots_are_refused() {
        // 0 is normal speech and 31 is the loopback probe. Accepting either
        // would break the client rather than the request.
        let (mut state, conn, _) = authenticated();
        for slot in [0, 31] {
            assert!(
                register(&mut state, conn, Some(slot)).is_empty(),
                "slot {slot} was accepted"
            );
        }
    }

    #[test]
    fn a_slot_beyond_a_byte_is_refused_not_truncated() {
        // The attack truncation enables: ask for slot 259, get slot 3, and now
        // the client is pointed at a target it never registered.
        let (mut state, conn, _) = authenticated();
        assert!(register(&mut state, conn, Some(259)).is_empty());
    }

    #[test]
    fn a_message_with_no_slot_is_refused() {
        let (mut state, conn, _) = authenticated();
        assert!(register(&mut state, conn, None).is_empty());
    }

    #[test]
    fn an_unauthenticated_connection_registers_nothing() {
        // A target names sessions and channels; before authentication there is
        // no session for it to belong to.
        let mut state = ServerState::new(ServerConfig::default());
        let conn = ConnId(1);
        state.add_connection(conn, "127.0.0.1:1".parse().expect("address"));
        assert!(register(&mut state, conn, Some(3)).is_empty());
    }

    #[test]
    fn an_empty_target_clears_the_slot() {
        let (mut state, conn, session) = authenticated();
        let _ = register(&mut state, conn, Some(3));

        let _ = VoiceTargetHandler.handle(
            &mut state,
            conn,
            ControlMessage::VoiceTarget(tcp::VoiceTarget {
                id: Some(3),
                targets: Vec::new(),
            }),
        );
        assert!(state.voice_target(session, 3).is_none());
    }

    #[test]
    fn the_protobuf_flags_survive_conversion() {
        // Both default to false and protobuf 3 also defaults them to false, so
        // a conversion that dropped them would look correct until someone used
        // a linked shout.
        let group = TargetGroup::from(&tcp::voice_target::Target {
            session: vec![1, 2],
            channel_id: Some(9),
            links: Some(true),
            children: Some(true),
            ..Default::default()
        });
        assert_eq!(group.sessions, vec![1, 2]);
        assert_eq!(group.channel, Some(9));
        assert!(group.links);
        assert!(group.children);
    }

    #[test]
    fn absent_protobuf_flags_are_false() {
        let group = TargetGroup::from(&tcp::voice_target::Target::default());
        assert!(!group.links);
        assert!(!group.children);
        assert_eq!(group.channel, None);
    }
}
