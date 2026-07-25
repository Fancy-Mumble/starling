//! The single authoritative state actor.
//!
//! [`ServerCore`] owns [`ServerState`] outright and runs in one task. Nothing
//! else can reach server state, so there are no locks, no lock ordering, and no
//! re-entrancy hazards — see `PORTING-PLAN.md` §2.3 for why that is the central
//! design decision of this port.
//!
//! Connections interact with it only by sending [`Command`]s (Command pattern),
//! and hear back only through their own outbound queue. The core itself depends
//! on [`Outbound`] and [`Dispatcher`], never on concrete transports or a `match`
//! over message types.

mod broadcast;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use starling_log::{Category, LogEvent, Logger};
use starling_proto::ControlMessage;
use starling_proto::proto::tcp;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::dispatch::Dispatcher;
use crate::handlers;
use crate::state::ServerState;
use starling_api::ServerConfig;
use starling_api::{AudienceView, ConnId, Effect, Effects, Recipients};
use starling_api::{FrameSink, NoOutbound, Outbound};
use starling_api::{NoVoice, VoiceLink, VoiceUpdate};
use starling_api::{Sessions, World};

/// How many frames may be queued for one connection before it is considered
/// stuck.
///
/// A client that cannot keep up is disconnected rather than allowed to apply
/// backpressure to the core — one slow peer must never stall the server. murmur
/// has the same policy; here it is explicit instead of emergent.
const OUTBOUND_QUEUE_DEPTH: usize = 128;

/// How many commands may be in flight to the core.
const COMMAND_QUEUE_DEPTH: usize = 1024;

/// Something a connection asks the core to do.
#[derive(Debug)]
pub enum Command {
    /// A TLS handshake completed; the connection is ready for traffic.
    Connected {
        /// The new connection's id.
        conn: ConnId,
        /// Peer address.
        addr: SocketAddr,
        /// Where to write this connection's outbound frames.
        sink: Box<dyn FrameSink>,
        /// A second handle to the same destination, for tunnelled audio.
        ///
        /// Two rather than one because the voice service writes to a connection
        /// without going through the state actor — that is the whole reason it
        /// is a separate service. Both are channel senders onto one queue, so
        /// the frames still interleave correctly on the socket.
        audio_sink: Box<dyn FrameSink>,
    },
    /// A control message arrived.
    Message {
        /// Which connection sent it.
        conn: ConnId,
        /// The decoded message.
        msg: Box<ControlMessage>,
    },
    /// The socket closed, for any reason.
    Disconnected {
        /// Which connection ended.
        conn: ConnId,
    },
}

/// Cheap, cloneable handle used by connection tasks to reach the core.
#[derive(Debug, Clone)]
pub struct ServerHandle {
    tx: mpsc::Sender<Command>,
    next_conn: Arc<AtomicU64>,
}

impl ServerHandle {
    /// Allocate an id for a newly accepted connection.
    ///
    /// Monotonic and never reused, unlike a session id: a connection id that
    /// could alias a previous connection would let a late message from a dead
    /// socket land on a live one.
    pub fn next_conn_id(&self) -> ConnId {
        ConnId(self.next_conn.fetch_add(1, Ordering::Relaxed))
    }

    /// The queue depth connection write tasks should use.
    #[must_use]
    pub const fn outbound_queue_depth() -> usize {
        OUTBOUND_QUEUE_DEPTH
    }

    /// Send a command to the core.
    ///
    /// Returns `Err` only once the core has shut down, which means the process
    /// is going away and the caller should stop.
    pub async fn send(&self, cmd: Command) -> Result<(), mpsc::error::SendError<Command>> {
        self.tx.send(cmd).await
    }
}

/// The state actor.
#[derive(Debug)]
pub struct ServerCore {
    state: ServerState,
    dispatcher: Dispatcher,
    outbound: Box<dyn Outbound + Send>,
    voice: Box<dyn VoiceLink>,
    logger: Logger,
    rx: mpsc::Receiver<Command>,
}

impl ServerCore {
    /// Create the core with the default handler set, and a handle for
    /// connection tasks.
    #[must_use]
    pub fn new(config: ServerConfig) -> (Self, ServerHandle) {
        let (logger, shutdown) = Logger::disabled();
        // The caller did not supply a logger, so nothing should outlive this
        // core's records; leaking the handle would keep a writer thread alive
        // after the core is gone.
        drop(shutdown);
        Self::with_parts(
            ServerState::new(config),
            handlers::default_dispatcher(),
            Box::new(NoOutbound),
            Box::new(NoVoice),
            logger,
        )
    }

    /// Create the core from explicit collaborators.
    ///
    /// The composition root uses this to install a different store, permission
    /// policy or transport; tests use it to install a recording [`Outbound`].
    #[must_use]
    pub fn with_parts(
        state: ServerState,
        dispatcher: Dispatcher,
        outbound: Box<dyn Outbound + Send>,
        voice: Box<dyn VoiceLink>,
        logger: Logger,
    ) -> (Self, ServerHandle) {
        let (tx, rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let core = Self {
            state,
            dispatcher,
            outbound,
            voice,
            logger,
            rx,
        };
        let handle = ServerHandle {
            tx,
            next_conn: Arc::new(AtomicU64::new(1)),
        };
        (core, handle)
    }

    /// Run until every handle is dropped.
    pub async fn run(mut self) {
        info!(
            port = self.state.config.port,
            max_users = self.state.config.limits.max_users,
            handlers = self.dispatcher.len(),
            "server core running"
        );
        self.logger.log(
            LogEvent::info(Category::Server, "server started")
                .with("port", self.state.config.port)
                .with("max_users", self.state.config.limits.max_users)
                .with("name", self.state.config.register_name.clone()),
        );
        while let Some(cmd) = self.rx.recv().await {
            self.handle(cmd);
        }
        self.logger
            .log(LogEvent::notice(Category::Server, "server stopped"));
        info!("server core stopped");
    }

    fn handle(&mut self, cmd: Command) {
        match cmd {
            Command::Connected {
                conn,
                addr,
                sink,
                audio_sink,
            } => self.on_connect(conn, addr, sink, audio_sink),
            Command::Message { conn, msg } => {
                let effects = self.dispatcher.dispatch(&mut self.state, conn, *msg);
                self.apply(effects);
            }
            Command::Disconnected { conn } => self.on_disconnect(conn),
        }
    }

    fn on_connect(
        &mut self,
        conn: ConnId,
        addr: SocketAddr,
        sink: Box<dyn FrameSink>,
        audio_sink: Box<dyn FrameSink>,
    ) {
        debug!(%conn, %addr, "connection established");
        self.state.add_connection(conn, addr);
        self.outbound.register(conn, sink);
        // Before the keys, which only arrive at authentication. The voice
        // service needs both, and this is the half that exists now.
        self.voice.connected(conn, audio_sink);
        // murmur sends its Version the moment TLS completes, before reading
        // anything (Server.cpp:1668).
        self.apply(handlers::handshake::server_version(conn));
    }

    fn on_disconnect(&mut self, conn: ConnId) {
        self.outbound.disconnect(conn);
        self.voice.detach(conn);
        let Some(session) = self.state.remove_connection(conn) else {
            debug!(%conn, "unauthenticated connection closed");
            return;
        };

        info!(%conn, %session, "session ended");
        // The user is already out of the registry, so this cannot reach them.
        let mut fx = Effects::none();
        let _ = fx.send(
            Recipients::All,
            ControlMessage::UserRemove(tcp::UserRemove {
                session: session.0,
                ..Default::default()
            }),
        );
        let _ = fx.log(
            LogEvent::info(Category::Session, "session ended")
                .with("session", session.0)
                .with("remaining_users", self.state.users().len()),
        );
        // The user is out of the registry, so the rebuilt view no longer
        // contains them. Without this, audio keeps being routed to a session
        // whose connection is gone until somebody else happens to move.
        let _ = fx.voice(VoiceUpdate::Rebuild);
        self.apply(fx);
    }

    /// Tell the voice path what changed.
    ///
    /// The rebuild reads the authority this core already owns, which is why a
    /// handler can ask for one without assembling the whole view itself — a
    /// mute toggle would otherwise have to walk every connected user.
    fn on_voice(&mut self, update: VoiceUpdate) {
        match update {
            VoiceUpdate::Attach(keying) => self.voice.attach(keying),
            VoiceUpdate::Rebuild => self.voice.publish(Box::new(self.audience())),
        }
    }

    /// Who can hear whom, as the voice path's contract wants it.
    ///
    /// Flat lists, because `starling-api` must not name `starling-voice`'s
    /// indexed snapshot. The voice service builds its own indexes, which is the
    /// only place that knows what they need to be indexed for.
    fn audience(&self) -> AudienceView {
        let mut view = AudienceView::default();
        for user in self.state.users().all() {
            view.members.push((user.session, user.channel));

            // Deaf implies silent on the *receive* side only; a deafened user
            // may still speak, which is how a moderator mutes without muting.
            if user.deaf || user.self_deaf {
                view.deaf.push(user.session);
            }
            // murmur folds all three into one check at the top of `processMsg`,
            // because the packet path must not care which of them applies.
            if user.mute || user.self_mute || user.suppress {
                view.silenced.push(user.session);
            }
        }

        // The channel tree, for shouts that carry into sub-channels. Channel
        // *links* are not here because nothing can create one yet — that is
        // `docs/GAP-ANALYSIS.md` C4, and an empty list is the honest answer
        // rather than a silently missing feature.
        for channel in self.state.channels().breadth_first() {
            if let Some(parent) = channel.parent {
                view.parents.push((channel.id, parent));
            }
        }

        for (session, slot, target) in self.state.voice_targets() {
            view.targets.push((session, slot, target.clone()));
        }
        view
    }

    /// Carry out a handler's effects, in order.
    fn apply(&mut self, effects: Effects) {
        for effect in effects {
            match effect {
                Effect::Send { to, msg } => {
                    broadcast::Broadcast::new(&self.state, self.outbound.as_mut()).send(to, &msg);
                }
                Effect::Disconnect { conn, reason } => {
                    debug!(%conn, reason, "closing connection");
                    self.outbound.disconnect(conn);
                }
                Effect::Log(event) => self.logger.log(*event),
                Effect::Voice(update) => self.on_voice(update),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{RecordingVoice, SharedVoice, TestRegistry, TestSink};
    use bytes::{Bytes, BytesMut};
    use starling_api::Sessions;
    use starling_proto::{Version, codec};

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    /// A core wired to recording collaborators, and the voice link it holds.
    ///
    /// The link is returned separately because the core owns it as a
    /// `Box<dyn VoiceLink>` and there is no way back out — which is the point of
    /// the trait, and why the double records through shared state.
    fn core_with_voice(config: ServerConfig) -> (ServerCore, Arc<RecordingVoice>) {
        let (logger, shutdown) = Logger::disabled();
        drop(shutdown);
        let voice = Arc::new(RecordingVoice::default());
        let core = ServerCore::with_parts(
            ServerState::new(config),
            handlers::default_dispatcher(),
            Box::new(TestRegistry::new()),
            Box::new(SharedVoice(Arc::clone(&voice))),
            logger,
        )
        .0;
        (core, voice)
    }

    #[test]
    fn a_login_keys_the_voice_path() {
        // Without this a client completes its handshake and can never be heard,
        // which looks like a network problem rather than a server bug.
        let (mut core, voice) = core_with_voice(ServerConfig::default());
        let _rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");

        assert_eq!(voice.attached(), vec![ConnId(1)]);
        assert!(
            !voice.published().is_empty(),
            "the routing view was not sent"
        );
    }

    #[test]
    fn a_disconnect_detaches_and_republishes() {
        // Both halves matter: the peer's cipher has to go, and the view has to
        // stop naming them or audio keeps being routed to a dead connection.
        let (mut core, voice) = core_with_voice(ServerConfig::default());
        let _rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");
        core.handle(Command::Disconnected { conn: ConnId(1) });

        assert_eq!(voice.detached(), vec![ConnId(1)]);
        let last = voice.published().pop().expect("a view was published");
        assert!(
            last.members.is_empty(),
            "the departed user is still routable"
        );
    }

    #[test]
    fn the_published_view_reports_who_may_speak() {
        // The packet path drops a silenced speaker before building a recipient
        // list, so this flag is the whole of mute enforcement for audio.
        let (mut core, voice) = core_with_voice(ServerConfig::default());
        let _rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");

        let session = core.state.session_of(ConnId(1)).expect("session");
        if let Some(user) = core.state.users_mut().get_mut(session) {
            user.self_mute = true;
        }
        core.apply({
            let mut fx = Effects::none();
            let _ = fx.voice(VoiceUpdate::Rebuild);
            fx
        });

        let last = voice.published().pop().expect("a view was published");
        assert_eq!(last.silenced, vec![session]);
    }

    /// A core wired to a transport that records, which is what these tests
    /// assert against. `ServerCore::new` installs [`NoOutbound`] — it must not
    /// invent a transport — so a test that inspects delivery has to inject one.
    fn core(config: ServerConfig) -> ServerCore {
        let (logger, shutdown) = Logger::disabled();
        drop(shutdown);
        ServerCore::with_parts(
            ServerState::new(config),
            handlers::default_dispatcher(),
            Box::new(TestRegistry::new()),
            Box::new(RecordingVoice::default()),
            logger,
        )
        .0
    }

    /// Drain a connection's outbound queue into decoded messages.
    fn drain(rx: &mut mpsc::Receiver<Bytes>) -> Vec<ControlMessage> {
        let mut out = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            let mut buf = BytesMut::from(&frame[..]);
            while let Ok(Some(msg)) = codec::decode(&mut buf) {
                out.push(msg);
            }
        }
        out
    }

    fn connect(core: &mut ServerCore, conn: ConnId) -> mpsc::Receiver<Bytes> {
        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        connect_to(core, conn, tx);
        rx
    }

    /// Connect a client whose frames land in `tx`.
    ///
    /// Two sinks onto one queue, exactly as the listener sends them: the state
    /// service writes control messages through one and the voice service writes
    /// tunnelled audio through the other, and both reach the same socket.
    fn connect_to(core: &mut ServerCore, conn: ConnId, tx: mpsc::Sender<Bytes>) {
        core.handle(Command::Connected {
            conn,
            addr: addr(),
            sink: Box::new(TestSink::new(tx.clone())),
            audio_sink: Box::new(TestSink::new(tx)),
        });
    }

    fn authenticate(core: &mut ServerCore, conn: ConnId, name: &str) {
        core.handle(Command::Message {
            conn,
            msg: Box::new(ControlMessage::Version(tcp::Version {
                version_v2: Some(Version::new(1, 6, 0).encode_v2()),
                ..Default::default()
            })),
        });
        core.handle(Command::Message {
            conn,
            msg: Box::new(ControlMessage::Authenticate(tcp::Authenticate {
                username: Some(name.into()),
                opus: Some(true),
                ..Default::default()
            })),
        });
    }

    #[test]
    fn version_is_sent_the_moment_a_connection_is_established() {
        let mut core = core(ServerConfig::default());
        let mut rx = connect(&mut core, ConnId(1));

        match drain(&mut rx).as_slice() {
            [ControlMessage::Version(v)] => {
                assert_eq!(v.version_v2, Some(crate::MUMBLE_VERSION.encode_v2()));
            }
            other => panic!("expected exactly a Version, got {other:?}"),
        }
    }

    #[test]
    fn a_full_handshake_ends_with_sync_and_config() {
        let mut core = core(ServerConfig::default());
        let mut rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");

        let names: Vec<_> = drain(&mut rx).iter().map(ControlMessage::name).collect();
        assert_eq!(
            names,
            vec![
                "Version",
                "CodecVersion",
                "ChannelState",
                "UserState",
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
    fn a_text_message_reaches_the_other_client_and_not_the_sender() {
        let mut core = core(ServerConfig::default());
        let mut alice_rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");
        let mut bob_rx = connect(&mut core, ConnId(2));
        authenticate(&mut core, ConnId(2), "bob");
        let _ = drain(&mut alice_rx);
        let _ = drain(&mut bob_rx);

        core.handle(Command::Message {
            conn: ConnId(1),
            msg: Box::new(ControlMessage::TextMessage(tcp::TextMessage {
                channel_id: vec![0],
                message: "hello".into(),
                ..Default::default()
            })),
        });

        let bob: Vec<_> = drain(&mut bob_rx)
            .into_iter()
            .filter_map(|m| match m {
                ControlMessage::TextMessage(t) => Some(t.message),
                _ => None,
            })
            .collect();
        assert_eq!(bob, vec!["hello".to_owned()]);

        let alice_texts = drain(&mut alice_rx)
            .into_iter()
            .filter(|m| matches!(m, ControlMessage::TextMessage(_)))
            .count();
        assert_eq!(
            alice_texts, 0,
            "the sender must not receive its own message"
        );
    }

    #[test]
    fn the_second_client_learns_about_the_first() {
        let mut core = core(ServerConfig::default());
        let _alice_rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");
        let mut bob_rx = connect(&mut core, ConnId(2));
        authenticate(&mut core, ConnId(2), "bob");

        let names: Vec<_> = drain(&mut bob_rx)
            .into_iter()
            .filter_map(|m| match m {
                ControlMessage::UserState(u) => u.name,
                _ => None,
            })
            .collect();
        assert!(names.contains(&"alice".to_owned()));
        assert!(names.contains(&"bob".to_owned()));
    }

    #[test]
    fn disconnecting_broadcasts_user_remove_to_the_survivors() {
        let mut core = core(ServerConfig::default());
        let _alice_rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");
        let mut bob_rx = connect(&mut core, ConnId(2));
        authenticate(&mut core, ConnId(2), "bob");
        let _ = drain(&mut bob_rx);

        let alice_session = core
            .state
            .session_of(ConnId(1))
            .expect("alice authenticated");
        core.handle(Command::Disconnected { conn: ConnId(1) });

        let removed: Vec<_> = drain(&mut bob_rx)
            .into_iter()
            .filter_map(|m| match m {
                ControlMessage::UserRemove(r) => Some(r.session),
                _ => None,
            })
            .collect();
        assert_eq!(removed, vec![alice_session.0]);
    }

    #[test]
    fn an_unauthenticated_disconnect_broadcasts_nothing() {
        let mut core = core(ServerConfig::default());
        let _rx = connect(&mut core, ConnId(1));
        let mut bob_rx = connect(&mut core, ConnId(2));
        authenticate(&mut core, ConnId(2), "bob");
        let _ = drain(&mut bob_rx);

        core.handle(Command::Disconnected { conn: ConnId(1) });
        assert!(drain(&mut bob_rx).is_empty());
    }

    #[test]
    fn a_disconnect_frees_the_username_for_reuse() {
        let mut core = core(ServerConfig::default());
        let _rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");
        core.handle(Command::Disconnected { conn: ConnId(1) });

        let mut rx = connect(&mut core, ConnId(2));
        authenticate(&mut core, ConnId(2), "alice");
        assert!(
            !drain(&mut rx)
                .iter()
                .any(|m| matches!(m, ControlMessage::Reject(_))),
            "the name should be free once the first session ended"
        );
    }

    #[test]
    fn a_rejected_connection_receives_the_reason_before_being_dropped() {
        let mut core = core(ServerConfig {
            server_password: "hunter2".into(),
            ..Default::default()
        });
        let mut rx = connect(&mut core, ConnId(1));
        core.handle(Command::Message {
            conn: ConnId(1),
            msg: Box::new(ControlMessage::Authenticate(tcp::Authenticate {
                username: Some("alice".into()),
                password: Some("wrong".into()),
                ..Default::default()
            })),
        });

        assert!(
            drain(&mut rx)
                .iter()
                .any(|m| matches!(m, ControlMessage::Reject(_)))
        );
        assert!(
            !core.outbound.is_connected(ConnId(1)),
            "the connection should have been dropped after the Reject"
        );
    }

    #[test]
    fn a_stalled_client_is_dropped_rather_than_stalling_the_core() {
        let mut core = core(ServerConfig::default());

        // A queue of depth 1 that we never drain: the handshake overruns it.
        let (tx, _rx) = mpsc::channel(1);
        connect_to(&mut core, ConnId(1), tx);
        authenticate(&mut core, ConnId(1), "alice");

        assert!(
            !core.outbound.is_connected(ConnId(1)),
            "a client that cannot keep up must be dropped"
        );
    }

    #[test]
    fn an_unknown_message_type_does_not_take_the_connection_down() {
        let mut core = core(ServerConfig::default());
        let mut rx = connect(&mut core, ConnId(1));
        authenticate(&mut core, ConnId(1), "alice");
        let _ = drain(&mut rx);

        core.handle(Command::Message {
            conn: ConnId(1),
            msg: Box::new(ControlMessage::Opaque {
                type_id: 120, // WebRtcSignal
                payload: Bytes::from_static(b"fancy"),
            }),
        });
        assert!(core.outbound.is_connected(ConnId(1)));
    }

    #[test]
    fn connection_ids_are_never_reused() {
        let (_core, handle) = ServerCore::new(ServerConfig::default());
        let first = handle.next_conn_id();
        let second = handle.next_conn_id();
        assert_ne!(first, second);
        assert!(second.0 > first.0);
    }
}
