//! The adapter between the authority's contract and this service.
//!
//! `starling-api` defines what the state service can say about voice in plain
//! data; this turns those statements into commands for the voice task. All of
//! the crate's knowledge about ciphers, codecs and indexes lives on this side of
//! the seam, which is what lets the authority stay ignorant of every one.
//!
//! # Why control does not share the audio mailbox
//!
//! Audio drops when its mailbox is full, and that is correct — a frame that
//! waits is a frame that arrives too late. An *attach* that drops leaves a peer
//! permanently mute, and a *publish* that drops leaves the routing view stale.
//! Those must not share a queue with something designed to overflow, so they
//! have their own, and it is unbounded: the messages are rare, and the failure
//! mode of dropping one is far worse than the memory of keeping it.

use bytes::Bytes;
use starling_api::{
    AudienceView, AudioSink, AudioSource, ConnId, Datagrams, FrameSink, VoiceKeying, VoiceLink,
};
use starling_crypto::ocb2::{Block, Ocb2};
use starling_crypto::{VoiceCipher, VoiceSecrets, XChaCha20Voice};
use tokio::sync::mpsc;

use crate::routing::RoutingSnapshot;
use crate::service::{ControlCommand, VoiceHandle};
use crate::targets::{ShoutTarget, VoiceTarget};

/// Turns the authority's statements into voice commands.
///
/// Holds only channel senders, so cloning it is free and dropping one does not
/// stop the service.
#[derive(Debug, Clone)]
pub struct VoiceBridge {
    control: mpsc::UnboundedSender<ControlCommand>,
    audio: VoiceHandle,
}

impl VoiceBridge {
    /// Wrap a handle to a running voice service.
    #[must_use]
    pub fn new(control: mpsc::UnboundedSender<ControlCommand>, audio: VoiceHandle) -> Self {
        Self { control, audio }
    }
}

impl VoiceBridge {
    /// Tell the service how to send datagrams, once the socket has bound.
    ///
    /// `None` leaves everything tunnelling over TCP, which is what a server
    /// whose voice port could not bind should do rather than refusing to start.
    pub fn use_datagrams(&self, datagrams: Option<Box<dyn Datagrams>>) {
        if let Some(datagrams) = datagrams {
            let _ = self.control.send(ControlCommand::UseDatagrams(datagrams));
        }
    }
}

impl VoiceLink for VoiceBridge {
    fn connected(&self, conn: ConnId, sink: Box<dyn FrameSink>) {
        let _ = self.control.send(ControlCommand::Connected { conn, sink });
    }

    fn attach(&self, keying: Box<VoiceKeying>) {
        // The one place the negotiated cipher becomes a running one. Both arms
        // take the *server's* role: what this end sends under is what the other
        // end expects, and reversing either produces a handshake that looks
        // perfect and a session in which no packet ever authenticates.
        let cipher: Box<dyn VoiceCipher> = match &keying.secrets {
            VoiceSecrets::Legacy(keys) => Box::new(Ocb2::new(
                *keys.key(),
                Block(*keys.client_nonce()),
                Block(*keys.server_nonce()),
            )),
            VoiceSecrets::Modern(keys) => Box::new(XChaCha20Voice::for_server(keys)),
        };
        let _ = self.control.send(ControlCommand::Attach {
            conn: keying.conn,
            session: keying.session,
            host: keying.host,
            format: keying.format,
            cipher,
        });
    }

    fn detach(&self, conn: ConnId) {
        let _ = self.control.send(ControlCommand::Detach { conn });
    }

    fn publish(&self, view: Box<AudienceView>) {
        let _ = self
            .control
            .send(ControlCommand::Publish(Box::new(snapshot_from(&view))));
    }
}

impl AudioSink for VoiceBridge {
    fn deliver(&self, from: AudioSource, frame: Bytes) {
        self.audio.deliver(from, frame);
    }
}

/// Build the packet path's indexed view from the authority's flat lists.
///
/// The conversion the seam exists for: `AudienceView` is the shape that is
/// cheap for the authority to produce, and `RoutingSnapshot` is the shape that
/// is cheap to answer "who hears this" from. Neither crate has to know both.
fn snapshot_from(view: &AudienceView) -> RoutingSnapshot {
    let mut snapshot = RoutingSnapshot::new();
    for (session, channel) in &view.members {
        snapshot = snapshot.with_member(*session, *channel);
    }
    for (session, channel) in &view.listeners {
        snapshot = snapshot.with_listener(*session, *channel);
    }
    for session in &view.deaf {
        snapshot = snapshot.with_deaf(*session);
    }
    for session in &view.silenced {
        snapshot = snapshot.with_silenced(*session);
    }
    for (one, other) in &view.links {
        snapshot = snapshot.with_link(*one, *other);
    }
    for (child, parent) in &view.parents {
        snapshot = snapshot.with_parent(*child, *parent);
    }
    for (session, slot, target) in &view.targets {
        let mut built = VoiceTarget::new();
        for whispered in &target.sessions {
            built = built.whispering_to(*whispered);
        }
        for shout in &target.shouts {
            built = built.shouting_to(ShoutTarget {
                channel: shout.channel,
                include_links: shout.links,
                include_children: shout.children,
            });
        }
        snapshot = snapshot.with_target(*session, *slot, built);
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Target;
    use starling_model::{ChannelId, SessionId};

    const LOBBY: ChannelId = ChannelId(0);
    const ANNEX: ChannelId = ChannelId(1);
    const ALICE: SessionId = SessionId(1);
    const BOB: SessionId = SessionId(2);

    fn lobby_view() -> AudienceView {
        AudienceView {
            members: vec![(ALICE, LOBBY), (BOB, LOBBY)],
            ..AudienceView::default()
        }
    }

    #[test]
    fn members_become_an_audience() {
        let snapshot = snapshot_from(&lobby_view());
        assert_eq!(snapshot.recipients(ALICE, Target::Normal), vec![BOB]);
    }

    #[test]
    fn a_deafened_session_is_carried_across() {
        let snapshot = snapshot_from(&AudienceView {
            deaf: vec![BOB],
            ..lobby_view()
        });
        assert!(snapshot.recipients(ALICE, Target::Normal).is_empty());
    }

    #[test]
    fn a_silenced_session_is_carried_across() {
        let snapshot = snapshot_from(&AudienceView {
            silenced: vec![ALICE],
            ..lobby_view()
        });
        assert!(!snapshot.may_speak(ALICE));
    }

    #[test]
    fn a_listener_is_carried_across() {
        let snapshot = snapshot_from(&AudienceView {
            listeners: vec![(SessionId(9), LOBBY)],
            ..lobby_view()
        });
        assert!(snapshot
            .recipients(ALICE, Target::Normal)
            .contains(&SessionId(9)));
    }

    #[test]
    fn the_channel_tree_is_carried_across() {
        // Links and parents only matter for shouts, so their absence would go
        // unnoticed until someone used a `VoiceTarget`.
        let snapshot = snapshot_from(&AudienceView {
            members: vec![(ALICE, LOBBY), (BOB, ANNEX)],
            links: vec![(LOBBY, ANNEX)],
            parents: vec![(ANNEX, LOBBY)],
            ..AudienceView::default()
        })
        .with_target(
            ALICE,
            3,
            VoiceTarget::new().shouting_to(ShoutTarget {
                channel: LOBBY,
                include_links: true,
                include_children: false,
            }),
        );
        assert!(snapshot
            .recipients(ALICE, Target::Whisper(3))
            .contains(&BOB));
    }

    #[test]
    fn an_empty_view_routes_to_nobody() {
        let snapshot = snapshot_from(&AudienceView::default());
        assert!(snapshot.recipients(ALICE, Target::Normal).is_empty());
    }
}
