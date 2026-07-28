//! One client connection: two bounded queues, two policies.
//!
//! | Lane | Full means |
//! |---|---|
//! | control | **disconnect that client** |
//! | audio | drop the oldest, and count it |
//!
//! The asymmetry is the point. Dropping a control message desyncs that client
//! permanently and silently — it renders the wrong world forever with nothing
//! in any log — and unbounded queueing is a memory `DoS`. Disconnecting is the
//! only outcome both bounded and honest, and reconnect already re-syncs from
//! scratch. A late audio frame, by contrast, is worthless.
//!
//! Everything lost is counted (`docs/ARCHITECTURE.md` §5), which is why both
//! policies increment rather than just act.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::{Notify, mpsc};

/// Which queue a frame belongs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Everything that carries state. Loss is not survivable.
    Control,
    /// Tunnelled audio. Lateness is worse than loss.
    Audio,
}

/// Why a frame could not be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// The control queue is full; this client must be disconnected.
    ControlOverflow,
    /// The client is already gone.
    Closed,
}

/// The gateway's handle on one connected client.
#[derive(Debug)]
pub struct ClientHandle {
    /// The connection id, minted at accept.
    pub conn: u64,
    /// The session, once session-lifecycle reports one. 0 until then.
    session: AtomicU32,
    /// The Fancy version the client announced, 0 for a stock client.
    fancy_version: AtomicU32,
    /// The resume token, which is what the replay ring is keyed by.
    pub token: String,
    control: mpsc::Sender<Bytes>,
    audio: Arc<Mutex<VecDeque<Bytes>>>,
    audio_wake: Arc<Notify>,
    audio_capacity: usize,
    dropped_audio: Arc<AtomicU32>,
    close: Arc<Notify>,
}

impl ClientHandle {
    /// The session this connection belongs to, or 0 before the handshake.
    #[must_use]
    pub fn session(&self) -> u32 {
        self.session.load(Ordering::Acquire)
    }

    /// Record the session session-lifecycle assigned.
    pub fn set_session(&self, session: u32) {
        self.session.store(session, Ordering::Release);
    }

    /// Whether the peer announced a Fancy version.
    ///
    /// It decides two things a legacy client must not be given: a throttle
    /// notice, and a resume sequence number.
    #[must_use]
    pub fn is_fancy(&self) -> bool {
        self.fancy_version.load(Ordering::Acquire) != 0
    }

    /// Record the announced Fancy version, truncated to its low word.
    pub fn set_fancy(&self, version: u64) {
        self.fancy_version
            .store((version & u64::from(u32::MAX)) as u32, Ordering::Release);
    }

    /// Queue a frame.
    ///
    /// # Errors
    ///
    /// [`QueueError::ControlOverflow`] when the control queue is full, which
    /// the caller turns into a disconnect. Audio never returns an error: it
    /// drops the oldest frame and counts it.
    pub fn send(&self, lane: Lane, frame: Bytes) -> Result<(), QueueError> {
        match lane {
            Lane::Control => match self.control.try_send(frame) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => Err(QueueError::ControlOverflow),
                Err(mpsc::error::TrySendError::Closed(_)) => Err(QueueError::Closed),
            },
            Lane::Audio => {
                if let Ok(mut queue) = self.audio.lock() {
                    while queue.len() >= self.audio_capacity {
                        let _ = queue.pop_front();
                        let _ = self.dropped_audio.fetch_add(1, Ordering::Relaxed);
                    }
                    queue.push_back(frame);
                }
                self.audio_wake.notify_one();
                Ok(())
            }
        }
    }

    /// How many audio frames this client has lost to a full queue.
    #[must_use]
    pub fn dropped_audio(&self) -> u32 {
        self.dropped_audio.load(Ordering::Relaxed)
    }

    /// Take the next audio frame, if there is one.
    #[must_use]
    pub fn pop_audio(&self) -> Option<Bytes> {
        self.audio
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front())
    }

    /// Wait until an audio frame may be available.
    pub async fn audio_ready(&self) {
        self.audio_wake.notified().await;
    }

    /// Ask this connection to end.
    ///
    /// A service that kicks or bans somebody, and the handshake evicting a
    /// ghost, both need the socket *closed* — forgetting the registry entry
    /// leaves the client connected, still able to send, and still rendered by
    /// everyone else because no service was ever told the session ended.
    ///
    /// `notify_one` rather than `notify_waiters`: it stores a permit when
    /// nothing is waiting yet, so a close that races the read loop reaching its
    /// `select!` still lands instead of being dropped on the floor.
    pub fn close(&self) {
        self.close.notify_one();
    }

    /// Resolves once [`Self::close`] has been called.
    pub async fn closed(&self) {
        self.close.notified().await;
    }
}

/// Build a handle and the control receiver its writer task drains.
#[must_use]
pub fn channel(
    conn: u64,
    token: String,
    control_queue: usize,
    audio_queue: usize,
) -> (Arc<ClientHandle>, mpsc::Receiver<Bytes>) {
    let (tx, rx) = mpsc::channel(control_queue.max(1));
    let handle = Arc::new(ClientHandle {
        conn,
        session: AtomicU32::new(0),
        fancy_version: AtomicU32::new(0),
        token,
        control: tx,
        audio: Arc::new(Mutex::new(VecDeque::new())),
        audio_wake: Arc::new(Notify::new()),
        audio_capacity: audio_queue.max(1),
        dropped_audio: Arc::new(AtomicU32::new(0)),
        close: Arc::new(Notify::new()),
    });
    (handle, rx)
}

/// Every connected client, by connection and by session.
///
/// Two indexes because the two halves of the system address differently:
/// services speak sessions, the wire speaks connections.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    conns: Arc<Mutex<HashMap<u64, Arc<ClientHandle>>>>,
    sessions: Arc<Mutex<HashMap<u32, u64>>>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new connection.
    pub fn insert(&self, handle: Arc<ClientHandle>) {
        if let Ok(mut conns) = self.conns.lock() {
            let _ = conns.insert(handle.conn, handle);
        }
    }

    /// Bind a session to a connection.
    pub fn bind_session(&self, session: u32, conn: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.insert(session, conn);
        }
        if let Some(handle) = self.by_conn(conn) {
            handle.set_session(session);
        }
    }

    /// Forget a connection and any session bound to it.
    pub fn remove(&self, conn: u64) {
        let session = self.by_conn(conn).map(|handle| handle.session());
        if let Ok(mut conns) = self.conns.lock() {
            let _ = conns.remove(&conn);
        }
        if let (Some(session), Ok(mut sessions)) = (session, self.sessions.lock())
            && session != 0
        {
            let _ = sessions.remove(&session);
        }
    }

    /// The handle for a connection.
    #[must_use]
    pub fn by_conn(&self, conn: u64) -> Option<Arc<ClientHandle>> {
        self.conns
            .lock()
            .ok()
            .and_then(|conns| conns.get(&conn).cloned())
    }

    /// The handle for a session, if this gateway holds it.
    ///
    /// Returning `None` is the normal case in a multi-pod deployment: a
    /// service broadcasts, and the pod that does not hold the session ignores
    /// the frame.
    #[must_use]
    pub fn by_session(&self, session: u32) -> Option<Arc<ClientHandle>> {
        let conn = self
            .sessions
            .lock()
            .ok()
            .and_then(|s| s.get(&session).copied())?;
        self.by_conn(conn)
    }

    /// Every authenticated client this gateway holds.
    #[must_use]
    pub fn authenticated(&self) -> Vec<Arc<ClientHandle>> {
        self.conns
            .lock()
            .map(|conns| {
                conns
                    .values()
                    .filter(|handle| handle.session() != 0)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many connections are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.conns.lock().map(|c| c.len()).unwrap_or_default()
    }

    /// Whether nobody is connected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_control_queue_reports_overflow_rather_than_dropping() {
        // Dropping would desync that client permanently and silently.
        let (handle, _rx) = channel(1, "tok".to_owned(), 2, 4);
        assert!(handle.send(Lane::Control, Bytes::from_static(b"a")).is_ok());
        assert!(handle.send(Lane::Control, Bytes::from_static(b"b")).is_ok());
        assert_eq!(
            handle.send(Lane::Control, Bytes::from_static(b"c")),
            Err(QueueError::ControlOverflow)
        );
    }

    #[test]
    fn a_full_audio_queue_drops_the_oldest_and_counts_it() {
        // A late audio frame is worthless, so the newest is the one to keep.
        let (handle, _rx) = channel(1, "tok".to_owned(), 4, 2);
        for byte in [1_u8, 2, 3] {
            assert!(
                handle
                    .send(Lane::Audio, Bytes::copy_from_slice(&[byte]))
                    .is_ok()
            );
        }
        assert_eq!(handle.dropped_audio(), 1);
        assert_eq!(handle.pop_audio(), Some(Bytes::copy_from_slice(&[2])));
        assert_eq!(handle.pop_audio(), Some(Bytes::copy_from_slice(&[3])));
    }

    #[test]
    fn a_session_resolves_to_the_connection_that_owns_it() {
        let registry = Registry::new();
        let (handle, _rx) = channel(42, "tok".to_owned(), 4, 4);
        registry.insert(handle);
        registry.bind_session(7, 42);
        assert_eq!(registry.by_session(7).map(|h| h.conn), Some(42));
        assert_eq!(registry.authenticated().len(), 1);
    }

    #[test]
    fn a_session_this_gateway_does_not_hold_is_simply_absent() {
        // The normal case with several pods: a service broadcasts and the pod
        // without the session ignores it.
        assert!(Registry::new().by_session(9).is_none());
    }

    #[test]
    fn removing_a_connection_forgets_its_session_too() {
        let registry = Registry::new();
        let (handle, _rx) = channel(42, "tok".to_owned(), 4, 4);
        registry.insert(handle);
        registry.bind_session(7, 42);
        registry.remove(42);
        assert!(registry.by_session(7).is_none());
        assert!(registry.is_empty());
    }
}
