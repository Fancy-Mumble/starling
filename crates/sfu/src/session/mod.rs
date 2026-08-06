//! Broadcast session management for the SFU.
//!
//! Each [`BroadcastSession`] represents one active screen share: a single
//! inbound WebRTC connection from the broadcaster and zero or more outbound
//! connections to viewers.  The SFU forwards RTP packets from the inbound
//! peer to all outbound peers without re-encoding.

mod broadcast;
mod forward;
mod helpers;
mod runtime;

pub use broadcast::BroadcastSession;

use std::sync::Mutex;

use tokio::sync::mpsc;
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SOCKET_BUF_SIZE: usize = 2 * 1024 * 1024;
const UDP_BUF_SIZE: usize = 2000;
const TICK_INTERVAL: Duration = Duration::from_millis(5);
const STATS_INTERVAL: Duration = Duration::from_secs(5);
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(2);
const REMB_INTERVAL: Duration = Duration::from_secs(1);
const REMB_BITRATE_BPS: u64 = 50_000_000;
const PLI_MIN_INTERVAL: Duration = Duration::from_secs(1);
const MAX_BATCH_DRAIN: usize = 200;
const ICE_UFRAG_LEN: usize = 8;
const ICE_PASS_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Opaque handle to the SFU runtime.
#[derive(Debug)]
pub struct SfuHandle {
    cmd_tx: mpsc::UnboundedSender<SfuCommand>,
    event_rx: Mutex<mpsc::UnboundedReceiver<SfuEvent>>,
    _runtime_thread: std::thread::JoinHandle<()>,
}

/// Events produced by the SFU that the server should act on.
#[derive(Debug)]
pub enum SfuEvent {
    /// An offer has been answered, and somebody has to deliver the answer.
    ///
    /// The SFU has no way to reach a client; the control plane does. That split
    /// is why this is an event rather than a return value.
    SdpAnswer {
        /// The session the answer should be delivered to.
        target_session: u32,
        /// The broadcaster whose stream the answer is for.
        /// Equal to `target_session` when this is the broadcaster's own answer.
        broadcaster_session: u32,
        /// The answer, carrying this server's single ICE candidate.
        sdp: String,
    },
    /// A broadcast is over, however it ended.
    SessionEnded {
        /// Whose it was.
        broadcaster_session: u32,
    },
}

/// The SFU could not be started at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError(pub String);

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the SFU runtime thread could not be started: {}", self.0)
    }
}

impl std::error::Error for StartError {}

/// Configuration for the SFU.
#[derive(Debug, Clone)]
pub struct SfuConfig {
    /// UDP port for WebRTC media (0 = OS-assigned).
    pub udp_port: u16,
    /// Public IP address for ICE candidates in SDP answers.
    pub public_ip: std::net::IpAddr,
}

// ---------------------------------------------------------------------------
// Internal command type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum SfuCommand {
    CreateSession {
        broadcaster_session: u32,
    },
    BroadcasterOffer {
        broadcaster_session: u32,
        sdp: String,
    },
    ViewerOffer {
        broadcaster_session: u32,
        viewer_session: u32,
        sdp: String,
    },
    AddIceCandidate {
        client_session: u32,
    },
    DestroySession {
        broadcaster_session: u32,
    },
    Shutdown,
}

// ---------------------------------------------------------------------------
// SfuHandle - public command interface
// ---------------------------------------------------------------------------

impl SfuHandle {
    /// Start the runtime on a thread of its own.
    ///
    /// Its own thread and its own tokio runtime, deliberately: this one handles
    /// UDP media at frame rate, and sharing workers with the control plane
    /// would let a slow control task jitter every viewer.
    ///
    /// # Errors
    ///
    /// [`StartError`] when the thread or the runtime cannot be created. It used
    /// to `expect` on both, which turns "this host is out of threads" into a
    /// panic on somebody else's stack, and a media server that cannot start is
    /// a server that should go on serving everything else.
    pub fn start(config: SfuConfig) -> Result<Self, StartError> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let thread = std::thread::Builder::new()
            .name("sfu-runtime".into())
            .spawn(move || {
                let built = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build();
                let Ok(rt) = built else {
                    // Nothing to report to, this being a bare thread: the
                    // handle's commands go nowhere from here, which is the
                    // same thing that happens when the socket cannot bind.
                    tracing::error!("SFU: could not create its tokio runtime");
                    return;
                };

                rt.block_on(async {
                    let Some(mut runtime) = runtime::SfuRuntime::new(config) else {
                        return;
                    };
                    runtime.run(cmd_rx, event_tx).await;
                });
            })
            .map_err(|error| StartError(error.to_string()))?;

        Ok(Self {
            cmd_tx,
            event_rx: Mutex::new(event_rx),
            _runtime_thread: thread,
        })
    }

    /// Open a broadcast, before any offer arrives for it.
    pub fn create_session(&self, broadcaster_session: u32) {
        let _r = self.cmd_tx.send(SfuCommand::CreateSession {
            broadcaster_session,
        });
    }

    /// The broadcaster's own offer: the stream coming *in*.
    pub fn broadcaster_offer(&self, broadcaster_session: u32, sdp: String) {
        let _r = self.cmd_tx.send(SfuCommand::BroadcasterOffer {
            broadcaster_session,
            sdp,
        });
    }

    /// A viewer's offer: one of the streams going *out*.
    pub fn viewer_offer(&self, broadcaster_session: u32, viewer_session: u32, sdp: String) {
        let _r = self.cmd_tx.send(SfuCommand::ViewerOffer {
            broadcaster_session,
            viewer_session,
            sdp,
        });
    }

    /// Accepted and ignored, because this server is ICE-lite.
    ///
    /// Kept rather than removed: a peer that trickles anyway is not an
    /// error, and dropping the candidate is the correct behaviour for a
    /// server whose own candidate already rode in the answer.
    pub fn add_ice_candidate(
        &self,
        _broadcaster_session: u32,
        client_session: u32,
        _candidate_json: String,
    ) {
        let _r = self
            .cmd_tx
            .send(SfuCommand::AddIceCandidate { client_session });
    }

    /// End a broadcast and drop every peer attached to it.
    pub fn destroy_session(&self, broadcaster_session: u32) {
        let _r = self.cmd_tx.send(SfuCommand::DestroySession {
            broadcaster_session,
        });
    }

    /// The next event, if one is waiting. Never blocks.
    #[must_use]
    pub fn poll_event(&self) -> Option<SfuEvent> {
        self.event_rx
            .lock()
            .ok()
            .and_then(|mut rx| rx.try_recv().ok())
    }

    /// Stop the runtime.
    pub fn shutdown(&self) {
        let _r = self.cmd_tx.send(SfuCommand::Shutdown);
    }
}
