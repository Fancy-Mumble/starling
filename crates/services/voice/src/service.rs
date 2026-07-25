//! The voice service: one task, one mailbox, no locks.
//!
//! Audio needs its own lane, and this is it. The state service is a single
//! writer whose hold time is bounded by whatever the slowest handler does;
//! `crates/kernel/bus/RESULTS.md` §3.3 measured a 25 ms hold making 5% of
//! packets miss their frame. Putting audio behind that queue is the one design
//! mistake that cannot be fixed later without moving it back out.
//!
//! # Why an actor rather than shared state behind a lock
//!
//! The alternative is an `RwLock` over the peer table, taken on every packet by
//! every reader task. That is murmur's design, and it works — but every peer's
//! cipher needs `&mut`, so the read lock would have to become a write lock or
//! each peer would need its own inner lock. One owner and a channel is less
//! machinery for the same guarantee, and it makes [`Router`] a plain synchronous
//! type that tests without a runtime.
//!
//! # Two lanes, because they need opposite failure modes
//!
//! Audio is bounded and drops when full: a frame that waits is a frame that
//! arrives after the moment it was for. Control — attach, detach, publish — is
//! unbounded and never drops: a lost attach leaves a peer permanently mute, and
//! a lost publish leaves the routing view stale forever.
//!
//! One queue cannot be both. Sharing it would mean either dropping an attach
//! under audio load or letting a backlog of stale audio build up, and the first
//! failure is invisible until someone complains they cannot be heard.

use std::collections::HashMap;
use std::net::IpAddr;

use bytes::Bytes;
use starling_api::{AudioSink, AudioSource, ConnId, Datagrams, FrameSink};
use starling_crypto::VoiceCipher;
use starling_gate::UdpFormat;
use starling_model::SessionId;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::packet::ServerDetails;
use crate::peer::VoicePeer;
use crate::router::{Router, RouterStats};
use crate::routing::RoutingSnapshot;

/// How many frames may wait for the voice task.
///
/// Two frames per peer at a few hundred peers. Deep enough to ride out a
/// scheduling hiccup, shallow enough that a backlog is discarded rather than
/// played late — a frame that waits 200 ms in a queue is not audio any more.
const MAILBOX_DEPTH: usize = 1024;

/// One frame of audio, on the lane that is allowed to drop it.
#[derive(Debug)]
pub struct AudioCommand {
    /// Which transport delivered it.
    pub from: AudioSource,
    /// The bytes as they arrived.
    pub frame: Bytes,
}

/// Everything that must not be dropped.
///
/// `Box`ed where a variant would otherwise dominate the enum's size.
#[derive(Debug)]
pub enum ControlCommand {
    /// A connection completed its TLS handshake.
    ///
    /// Arrives before the keys do, because the sink exists from the handshake
    /// and the keys only from authentication.
    Connected {
        /// The new connection.
        conn: ConnId,
        /// Where to tunnel its audio when UDP does not work.
        sink: Box<dyn FrameSink>,
    },

    /// A peer authenticated and may now carry audio.
    Attach {
        /// The connection.
        conn: ConnId,
        /// The session it will be named by.
        session: SessionId,
        /// Where its control connection came from, to narrow attribution.
        host: IpAddr,
        /// The audio wire format it negotiated.
        format: UdpFormat,
        /// Its cipher, already keyed.
        cipher: Box<dyn VoiceCipher>,
    },

    /// A peer went away.
    Detach {
        /// The connection that ended.
        conn: ConnId,
    },

    /// Membership, mute state, listeners or targets changed.
    Publish(Box<RoutingSnapshot>),

    /// The voice port bound; here is how to send on it.
    UseDatagrams(Box<dyn Datagrams>),

    /// Report the current counters back to the caller.
    Stats(tokio::sync::oneshot::Sender<RouterStats>),
}

/// Cheap, cloneable handle to the voice task's audio lane.
#[derive(Debug, Clone)]
pub struct VoiceHandle {
    audio: mpsc::Sender<AudioCommand>,
    control: mpsc::UnboundedSender<ControlCommand>,
}

impl VoiceHandle {
    /// The control lane, for the bridge to hold.
    #[must_use]
    pub fn control(&self) -> mpsc::UnboundedSender<ControlCommand> {
        self.control.clone()
    }

    /// Send a control command.
    ///
    /// # Errors
    ///
    /// The command back, if the task has stopped.
    pub fn send(
        &self,
        command: ControlCommand,
    ) -> Result<(), mpsc::error::SendError<ControlCommand>> {
        self.control.send(command)
    }

    /// Replace the routing view.
    ///
    /// # Errors
    ///
    /// The command back, if the task has stopped.
    pub fn publish(
        &self,
        snapshot: RoutingSnapshot,
    ) -> Result<(), mpsc::error::SendError<ControlCommand>> {
        self.send(ControlCommand::Publish(Box::new(snapshot)))
    }

    /// The current counters.
    ///
    /// A barrier for the **control** lane only: every attach, detach and publish
    /// queued before it has been applied by the time it answers. Audio in flight
    /// has not, because the two lanes are deliberately independent — that is the
    /// whole point of splitting them, and it means a caller watching for the
    /// effect of a frame has to look again rather than assume.
    ///
    /// # Errors
    ///
    /// `None` if the task has stopped before answering.
    pub async fn stats(&self) -> Option<RouterStats> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.control.send(ControlCommand::Stats(tx)).ok()?;
        rx.await.ok()
    }
}

impl AudioSink for VoiceHandle {
    fn deliver(&self, from: AudioSource, frame: Bytes) {
        // `try_send`, never `send`. Awaiting here would push back on the socket
        // reader, which would delay every *other* peer's audio to hold one
        // frame nobody can play by the time it arrives.
        let _ = self.audio.try_send(AudioCommand { from, frame });
    }
}

/// The voice task.
#[derive(Debug)]
pub struct VoiceService {
    audio: mpsc::Receiver<AudioCommand>,
    control: mpsc::UnboundedReceiver<ControlCommand>,
    router: Router,
    /// Sinks for connections that have not authenticated yet.
    ///
    /// A connection's tunnel arrives at the TLS handshake and its keys only at
    /// authentication, so one of them has to wait for the other. Holding the
    /// sink is cheaper than holding the keys, which would mean key material
    /// sitting in a map for as long as a peer takes to log in.
    pending: HashMap<ConnId, Box<dyn FrameSink>>,
}

impl VoiceService {
    /// Build the task and its handle.
    ///
    /// `datagrams` is how sealed audio leaves; a `NoDatagrams` here gives a
    /// server whose voice works only through the tunnel, which is a legitimate
    /// configuration and the one every test uses.
    #[must_use]
    pub fn new(datagrams: Box<dyn Datagrams>, details: ServerDetails) -> (Self, VoiceHandle) {
        let (audio_tx, audio) = mpsc::channel(MAILBOX_DEPTH);
        let (control_tx, control) = mpsc::unbounded_channel();
        (
            Self {
                audio,
                control,
                router: Router::new(datagrams, details),
                pending: HashMap::new(),
            },
            VoiceHandle {
                audio: audio_tx,
                control: control_tx,
            },
        )
    }

    /// Run until every handle is dropped.
    pub async fn run(mut self) {
        debug!("voice service started");
        loop {
            tokio::select! {
                // Control first, deliberately. A biased select means a burst of
                // audio can never starve an attach, and the control lane is
                // empty almost always so the bias costs nothing.
                biased;

                command = self.control.recv() => match command {
                    Some(command) => self.control(command),
                    None => break,
                },

                command = self.audio.recv() => match command {
                    Some(AudioCommand { from, frame }) => self.router.accept(from, &frame),
                    None => break,
                },
            }
        }
        debug!(peers = self.router.attached(), "voice service stopped");
    }

    /// Apply one control command. Synchronous, which is what keeps the lane fast.
    fn control(&mut self, command: ControlCommand) {
        match command {
            ControlCommand::Connected { conn, sink } => {
                let _ = self.pending.insert(conn, sink);
            }

            ControlCommand::Attach {
                conn,
                session,
                host,
                format,
                cipher,
            } => {
                // No sink means the connection dropped between the handshake and
                // authentication, which is a race the network makes routine.
                let Some(sink) = self.pending.remove(&conn) else {
                    debug!(%conn, "voice attach for a connection that already went away");
                    return;
                };
                debug!(%conn, %session, "voice path attached");
                self.router
                    .attach(VoicePeer::new(conn, session, format, cipher, sink), host);
            }

            ControlCommand::Detach { conn } => {
                let _ = self.pending.remove(&conn);
                self.router.detach(conn);
            }

            ControlCommand::Publish(snapshot) => self.router.publish(*snapshot),

            ControlCommand::UseDatagrams(datagrams) => self.router.use_datagrams(datagrams),

            ControlCommand::Stats(reply) => {
                // The receiver may have given up; that is not an error here.
                let _ = reply.send(self.router.stats());
            }
        }
    }
}

/// How often the counters are reported.
const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// Report the voice counters until every handle is dropped.
///
/// On a timer rather than per packet: every counter here can be driven by a
/// hostile peer, and a log line per datagram is a denial of service anyone with
/// the port number can trigger.
///
/// It reports even when nothing is wrong, which is deliberate. A server carrying
/// no audio and a server carrying audio perfectly are indistinguishable from
/// silence, and "0 routed, 2 peers attached" is the line that says which — the
/// exact question that went unanswered while a wildcard bind was quietly
/// dropping every datagram.
pub async fn report_periodically(handle: VoiceHandle) {
    let mut ticker = tokio::time::interval(REPORT_EVERY);
    // The first tick fires immediately and would only ever report zeroes.
    let _ = ticker.tick().await;

    let mut previous = RouterStats::default();
    loop {
        let _ = ticker.tick().await;
        let Some(stats) = handle.stats().await else {
            return; // the service has stopped
        };

        if stats.attached == 0 && stats.routed == previous.routed {
            continue; // nobody connected and nothing happened
        }

        if stats.unattributed > previous.unattributed || stats.dropped > previous.dropped {
            warn!(
                peers = stats.attached,
                routed = stats.routed,
                delivered = stats.delivered,
                unattributed = stats.unattributed,
                dropped = stats.dropped,
                malformed = stats.malformed,
                speakers = ?stats.by_speaker,
                "voice: packets are being discarded"
            );
        } else {
            info!(
                peers = stats.attached,
                routed = stats.routed,
                delivered = stats.delivered,
                speakers = ?stats.by_speaker,
                "voice"
            );
        }
        previous = stats;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{RecordingDatagrams, TestPeer};
    use starling_model::ChannelId;

    const LOBBY: ChannelId = ChannelId(0);
    const ALICE: SessionId = SessionId(1);
    const BOB: SessionId = SessionId(2);

    fn details() -> ServerDetails {
        ServerDetails {
            version: 1,
            users: 0,
            max_users: 10,
            max_bandwidth: 72_000,
        }
    }

    fn host() -> IpAddr {
        "203.0.113.7".parse().expect("test address")
    }

    /// Wait for the router to have routed `expected` frames.
    ///
    /// Audio and control are separate lanes, so `stats` is not a barrier for a
    /// frame still in flight. Polling with a deadline is the honest way to wait
    /// for one: a bare `stats` would race, and a sleep would be slower and still
    /// race on a loaded machine.
    async fn routed(handle: &VoiceHandle, expected: u64) -> u64 {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            let stats = handle.stats().await.expect("the service stopped");
            if stats.routed >= expected || tokio::time::Instant::now() > deadline {
                return stats.routed;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn audio_flows_through_the_task_to_a_listener() {
        // The whole service, end to end, without a socket.
        let sent = RecordingDatagrams::new();
        let (service, handle) = VoiceService::new(Box::new(sent.clone()), details());
        let task = tokio::spawn(service.run());

        let mut alice = TestPeer::new(ConnId(1), ALICE, UdpFormat::Protobuf);
        let bob = TestPeer::new(ConnId(2), BOB, UdpFormat::Protobuf);
        for peer in [&alice, &bob] {
            peer.join(&handle, host());
        }
        handle
            .publish(
                RoutingSnapshot::new()
                    .with_member(ALICE, LOBBY)
                    .with_member(BOB, LOBBY),
            )
            .expect("publish");

        handle.deliver(
            AudioSource::Tunnel(ConnId(1)),
            alice.speak_tunnelled(b"through the bus"),
        );

        assert_eq!(routed(&handle, 1).await, 1);
        assert_eq!(bob.tunnelled().len(), 1);

        drop(handle);
        task.await.expect("the task must not panic");
    }

    #[tokio::test]
    async fn the_task_stops_when_every_handle_is_dropped() {
        let (service, handle) = VoiceService::new(Box::new(RecordingDatagrams::new()), details());
        let task = tokio::spawn(service.run());
        drop(handle);
        task.await.expect("the task must stop cleanly");
    }

    #[tokio::test]
    async fn a_detached_peer_stops_receiving() {
        let (service, handle) = VoiceService::new(Box::new(RecordingDatagrams::new()), details());
        let task = tokio::spawn(service.run());

        let mut alice = TestPeer::new(ConnId(1), ALICE, UdpFormat::Protobuf);
        let bob = TestPeer::new(ConnId(2), BOB, UdpFormat::Protobuf);
        for peer in [&alice, &bob] {
            peer.join(&handle, host());
        }
        handle
            .publish(
                RoutingSnapshot::new()
                    .with_member(ALICE, LOBBY)
                    .with_member(BOB, LOBBY),
            )
            .expect("publish");
        handle
            .send(ControlCommand::Detach { conn: ConnId(2) })
            .expect("detach");

        handle.deliver(
            AudioSource::Tunnel(ConnId(1)),
            alice.speak_tunnelled(b"nobody home"),
        );

        // `routed` still counts one: the snapshot has not caught up, because
        // the authority republishes on its own schedule. `delivered` is the
        // honest measure — nothing was handed to a transport.
        assert_eq!(routed(&handle, 1).await, 1);
        assert_eq!(handle.stats().await.expect("stats").delivered, 0);
        assert!(bob.tunnelled().is_empty());

        drop(handle);
        task.await.expect("the task must not panic");
    }

    #[tokio::test]
    async fn a_peer_that_vanished_before_authenticating_is_not_attached() {
        // The race the network makes routine: TLS completes, then the socket
        // drops before `Authenticate` arrives.
        let (service, handle) = VoiceService::new(Box::new(RecordingDatagrams::new()), details());
        let task = tokio::spawn(service.run());

        let alice = TestPeer::new(ConnId(1), ALICE, UdpFormat::Protobuf);
        handle
            .send(ControlCommand::Detach { conn: ConnId(1) })
            .expect("detach");
        alice.attach_to(&handle, host());

        // Nothing to assert but the absence of a panic and a live service.
        assert!(handle.stats().await.is_some());
        drop(handle);
        task.await.expect("the task must not panic");
    }

    #[tokio::test]
    async fn a_burst_of_audio_cannot_starve_an_attach() {
        // The reason control has its own lane. Fill the audio mailbox past its
        // depth, then attach: the attach must still land.
        let (service, handle) = VoiceService::new(Box::new(RecordingDatagrams::new()), details());
        for _ in 0..MAILBOX_DEPTH * 2 {
            handle.deliver(AudioSource::Tunnel(ConnId(9)), Bytes::from_static(b"noise"));
        }

        let task = tokio::spawn(service.run());
        let alice = TestPeer::new(ConnId(1), ALICE, UdpFormat::Protobuf);
        alice.join(&handle, host());

        assert_eq!(handle.stats().await.expect("stats").attached, 1);
        drop(handle);
        task.await.expect("the task must not panic");
    }

    #[tokio::test]
    async fn delivering_to_a_stopped_task_is_not_a_panic() {
        // A connection task can outlive the service during shutdown.
        let (service, handle) = VoiceService::new(Box::new(RecordingDatagrams::new()), details());
        drop(service);
        handle.deliver(AudioSource::Tunnel(ConnId(1)), Bytes::from_static(b"late"));
        assert_eq!(handle.stats().await, None);
    }
}
