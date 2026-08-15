//! One client connection: two bounded queues, two policies.
//!
//! | Lane | Full means |
//! |---|---|
//! | control | **disconnect that client** |
//! | audio | drop the oldest, and count it |
//!
//! The asymmetry is the point. Dropping a control message desyncs that client
//! permanently and silently, it renders the wrong world forever with nothing
//! in any log, and unbounded queueing is a memory `DoS`. Disconnecting is the
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
use starling_runtime::pressure::Gauge;
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

/// One frame on its way to a client, split where it stops being shared.
///
/// A broadcast encodes its payload **once** and hands the same refcounted
/// buffer to every recipient (`PROTOCOL-REDESIGN.md` §4, Z4). The header cannot
/// be shared the same way once resume exists, because the sequence number in it
/// is per connection, so the two are carried separately and joined at the
/// socket rather than concatenated per recipient.
///
/// That is the whole reason this type exists. Building a combined buffer per
/// client would copy the payload once per recipient, which for a thousand
/// clients receiving one avatar is a thousand copies of 128 KiB to carry eight
/// bytes of difference.
#[derive(Debug, Clone)]
pub struct Outbound {
    /// `type ‖ len`, and `‖ seq` for a peer that negotiated resume. Six or
    /// fourteen bytes, and never shared.
    pub prefix: Bytes,
    /// The encoded message. Shared across every recipient of one broadcast.
    pub payload: Bytes,
}

impl Outbound {
    /// One frame whose bytes are already joined.
    ///
    /// The prefix is empty rather than absent: audio is never sequenced, and a
    /// caller that has already built a complete frame has nothing to split.
    #[must_use]
    pub fn whole(frame: Bytes) -> Self {
        Self {
            prefix: Bytes::new(),
            payload: frame,
        }
    }

    /// What this costs the queue: both halves, since both are written.
    #[must_use]
    pub fn len(&self) -> usize {
        self.prefix.len() + self.payload.len()
    }

    /// Whether there is nothing to write.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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
    /// Whether this peer's frames carry a sequence number.
    ///
    /// Off until the peer announces `resume` in its `Hello` and
    /// session-lifecycle turns it on, because a client that is not expecting
    /// eight extra bytes reads them as the start of its payload, and a stock
    /// Mumble client never announces anything, so it never gets them.
    sequenced: Arc<std::sync::atomic::AtomicBool>,
    /// Whether this peer's control stream may be compressed.
    ///
    /// Off unless it announced `zstd`, for the same reason the sequence is:
    /// a peer that receives a type it cannot parse is a peer that cannot read
    /// its own connection, and a stock Mumble client announces nothing.
    compresses: Arc<std::sync::atomic::AtomicBool>,
    control: mpsc::Sender<Outbound>,
    audio: Arc<Mutex<VecDeque<Outbound>>>,
    audio_wake: Arc<Notify>,
    audio_capacity: usize,
    dropped_audio: Arc<AtomicU32>,
    close: Arc<Notify>,
    /// Bytes currently sitting in the control queue.
    ///
    /// Maintained by [`Self::send`] and [`Self::control_sent`], so the bound is
    /// on memory rather than on a message count that says nothing about it.
    queued_control: Arc<std::sync::atomic::AtomicUsize>,
    /// The control lane's occupancy, shared by every client.
    ///
    /// Shared deliberately: a per-client gauge would be a registry entry per
    /// connection, which on a server with a thousand clients is a thousand rows
    /// nobody reads. One gauge watching all of them answers the question an
    /// operator actually has, "is anybody close to being disconnected for
    /// this", see `Gauge::observe`.
    pressure: Gauge,
    /// The ceiling those bytes may reach before the client is disconnected.
    control_budget: usize,
    /// Raised when the connection is ending and the writer should flush what
    /// is already queued before the socket goes.
    ///
    /// Separate from [`Self::close`], which wakes the *read* loop. The two are
    /// the opposite halves of one shutdown: the reader must stop at once, and
    /// the writer must not, a disconnect is nearly always preceded by the one
    /// frame that explains it (`Reject` on a refused login, `UserRemove` on a
    /// kick), and tearing the socket down first delivers the disconnect and
    /// loses the reason.
    drain: Arc<Notify>,
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

    /// Whether this peer's frames carry a sequence number.
    #[must_use]
    pub fn sequenced(&self) -> bool {
        self.sequenced.load(Ordering::Acquire)
    }

    /// Whether this peer's control stream may be compressed.
    #[must_use]
    pub fn compresses(&self) -> bool {
        self.compresses.load(Ordering::Acquire)
    }

    /// Allow (or stop) compressing this peer's control stream.
    pub fn set_compresses(&self, on: bool) {
        self.compresses.store(on, Ordering::Release);
    }

    /// Begin (or stop) sequencing this peer's frames.
    ///
    /// Turned on only once the peer has announced `resume`, and never for a
    /// stock client: the eight bytes are unannounced to anything that did not
    /// ask, and a client that is not expecting them reads them as payload.
    pub fn set_sequenced(&self, on: bool) {
        self.sequenced.store(on, Ordering::Release);
    }

    /// Queue a frame.
    ///
    /// # Errors
    ///
    /// `QueueError::ControlOverflow` when the control queue is full, which
    /// the caller turns into a disconnect. Audio never returns an error: it
    /// drops the oldest frame and counts it.
    pub fn send(&self, lane: Lane, frame: Outbound) -> Result<(), QueueError> {
        match lane {
            Lane::Control => {
                // Counted in **bytes**, not just messages. The channel bounds
                // the queue at 4096 frames, which says nothing about memory: a
                // `UserState` is forty bytes and an avatar is up to
                // `image_message_length`, 128 KiB by default. Four thousand of
                // those is half a gigabyte queued for one client that has
                // stopped reading its socket, and it only takes a few such
                // clients to take the gateway down, with image sharing being
                // exactly the workload that produces them.
                //
                // Overflowing on bytes disconnects that client, which is the
                // same policy the frame bound already has and is documented in
                // this module's header: dropping a control frame desyncs a
                // client permanently and silently, so disconnecting is the only
                // outcome that is both bounded and honest.
                let len = frame.len();
                let queued = self.queued_control.load(Ordering::Relaxed);
                if queued.saturating_add(len) > self.control_budget {
                    self.pressure.reject();
                    return Err(QueueError::ControlOverflow);
                }
                match self.control.try_send(frame) {
                    Ok(()) => {
                        let total = self.queued_control.fetch_add(len, Ordering::Relaxed) + len;
                        // Observed rather than accumulated: the budget is *per
                        // client*, so the number worth watching is the client
                        // closest to its own bound, not the sum across clients
                        // which has no ceiling to be a fraction of.
                        self.pressure.observe(total as u64);
                        Ok(())
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        self.pressure.reject();
                        Err(QueueError::ControlOverflow)
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => Err(QueueError::Closed),
                }
            }
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

    /// Account for a control frame the writer has taken off the queue.
    ///
    /// Called by the writer once the bytes are on their way out, which is what
    /// keeps [`Self::send`]'s budget a measure of what is *queued* rather than
    /// of everything ever sent.
    pub fn control_sent(&self, len: usize) {
        let _ = self
            .queued_control
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |queued| {
                Some(queued.saturating_sub(len))
            });
    }

    /// Bytes waiting in this client's control queue, for tests and metrics.
    #[must_use]
    pub fn queued_control_bytes(&self) -> usize {
        self.queued_control.load(Ordering::Relaxed)
    }

    /// How many audio frames this client has lost to a full queue.
    #[must_use]
    pub fn dropped_audio(&self) -> u32 {
        self.dropped_audio.load(Ordering::Relaxed)
    }

    /// Take the next audio frame, if there is one.
    #[must_use]
    pub fn pop_audio(&self) -> Option<Outbound> {
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
    /// ghost, both need the socket *closed*, forgetting the registry entry
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

    /// Tell the writer to flush what is queued and then stop.
    ///
    /// Called as the connection is torn down, *before* the writer task is
    /// waited on. Without it the writer is simply aborted, and a client that
    /// was refused, kicked or banned is disconnected without ever receiving
    /// the message that says why, murmur flushes for the same reason
    /// (`forceFlush()` before `disconnectSocket()`, `Messages.cpp:1424`).
    pub fn drain(&self) {
        self.drain.notify_one();
    }

    /// Resolves once [`Self::drain`] has been called.
    pub async fn draining(&self) {
        self.drain.notified().await;
    }
}

/// Build a handle and the control receiver its writer task drains.
#[must_use]
pub(crate) fn channel(
    conn: u64,
    token: String,
    control_queue: usize,
    audio_queue: usize,
    control_budget: usize,
    pressure: Gauge,
) -> (Arc<ClientHandle>, mpsc::Receiver<Outbound>) {
    let (tx, rx) = mpsc::channel(control_queue.max(1));
    let handle = Arc::new(ClientHandle {
        conn,
        session: AtomicU32::new(0),
        fancy_version: AtomicU32::new(0),
        token,
        control: tx,
        sequenced: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        compresses: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        audio: Arc::new(Mutex::new(VecDeque::new())),
        audio_wake: Arc::new(Notify::new()),
        audio_capacity: audio_queue.max(1),
        queued_control: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        control_budget: control_budget.max(1),
        pressure,
        dropped_audio: Arc::new(AtomicU32::new(0)),
        close: Arc::new(Notify::new()),
        drain: Arc::new(Notify::new()),
    });
    (handle, rx)
}

/// What the control lane's occupancy gauge is called.
///
/// Named once because three places need to agree: the gateway that creates it,
/// the dashboard that draws it, and the test that asserts it is reported. Its
/// declared capacity is the configured `[gateway] control_bytes` — the same
/// ceiling each client is disconnected for exceeding, not the aggregate across
/// clients, because the budget is per client.
pub(crate) const CONTROL_QUEUE_GAUGE: &str = "control queue (worst client)";

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
    use starling_runtime::pressure::Pressure;

    // The default control-lane byte budget (`GatewayConfig::control_bytes`),
    // used here as the fixture these queue tests were written against.
    const CONTROL_BYTE_BUDGET: usize = 4 * 1024 * 1024;
    fn control_budget() -> u64 {
        CONTROL_BYTE_BUDGET as u64
    }

    /// A handle whose gauge nothing reads.
    ///
    /// Most of these tests are about the queue, not about how it is reported,
    /// and threading a `Pressure` through each one would put the noun under
    /// test in fifth place behind four arguments nobody is asserting on.
    fn channel(
        conn: u64,
        token: String,
        control_queue: usize,
        audio_queue: usize,
    ) -> (Arc<ClientHandle>, mpsc::Receiver<Outbound>) {
        super::channel(
            conn,
            token,
            control_queue,
            audio_queue,
            CONTROL_BYTE_BUDGET,
            Pressure::new().gauge(CONTROL_QUEUE_GAUGE, control_budget()),
        )
    }

    #[test]
    fn a_full_control_queue_reports_overflow_rather_than_dropping() {
        // Dropping would desync that client permanently and silently.
        let (handle, _rx) = channel(1, "tok".to_owned(), 2, 4);
        assert!(
            handle
                .send(Lane::Control, Outbound::whole(Bytes::from_static(b"a")))
                .is_ok()
        );
        assert!(
            handle
                .send(Lane::Control, Outbound::whole(Bytes::from_static(b"b")))
                .is_ok()
        );
        assert_eq!(
            handle.send(Lane::Control, Outbound::whole(Bytes::from_static(b"c"))),
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
                    .send(
                        Lane::Audio,
                        Outbound::whole(Bytes::copy_from_slice(&[byte]))
                    )
                    .is_ok()
            );
        }
        assert_eq!(handle.dropped_audio(), 1);
        assert_eq!(
            handle.pop_audio().map(|f| f.payload),
            Some(Bytes::copy_from_slice(&[2]))
        );
        assert_eq!(
            handle.pop_audio().map(|f| f.payload),
            Some(Bytes::copy_from_slice(&[3]))
        );
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

    #[test]
    fn a_client_cannot_queue_unbounded_memory_under_a_bounded_frame_count() {
        // The bound the frame count never provided. At the shipped 4096 frames
        // and a 128 KiB `image_message_length`, one client that has stopped
        // reading holds half a gigabyte, and heavy image sharing is exactly
        // the workload that produces such clients.
        //
        // The frame count here is deliberately huge so that *only* the byte
        // budget can stop it.
        let (handle, _rx) = channel(1, "tok".to_owned(), 100_000, 4);
        let blob = Bytes::from(vec![0_u8; 128 * 1024]);

        let mut queued = 0_usize;
        for _ in 0..100_000 {
            if handle
                .send(Lane::Control, Outbound::whole(blob.clone()))
                .is_err()
            {
                break;
            }
            queued += blob.len();
        }

        assert!(
            queued <= CONTROL_BYTE_BUDGET,
            "queued {queued} bytes against a {CONTROL_BYTE_BUDGET}-byte budget"
        );
        assert!(
            queued > 0,
            "the budget refused everything; a client must be able to be sent an avatar"
        );
        assert_eq!(handle.queued_control_bytes(), queued);
    }

    #[test]
    fn the_control_lane_reports_its_occupancy_and_its_refusals() {
        // The counter beside this one ("clients disconnected for control
        // overflow") only ever moves after somebody has been disconnected. The
        // gauge is the interval before that, the client at 90% of its budget,
        // still connected, about to not be.
        let pressure = Pressure::new();
        let gauge = pressure.gauge(CONTROL_QUEUE_GAUGE, control_budget());
        let (handle, _rx) =
            super::channel(1, "tok".to_owned(), 100_000, 4, CONTROL_BYTE_BUDGET, gauge);
        let blob = Bytes::from(vec![0_u8; 128 * 1024]);

        while handle
            .send(Lane::Control, Outbound::whole(blob.clone()))
            .is_ok()
        {}

        let load = pressure
            .sample()
            .into_iter()
            .find(|load| load.name == CONTROL_QUEUE_GAUGE)
            .expect("the gateway registered its gauge");

        assert_eq!(load.capacity, control_budget());
        assert!(
            load.utilisation() >= Some(90),
            "a client that filled its budget reported only {:?}",
            load.utilisation()
        );
        assert!(
            load.rejected >= 1,
            "the frame that was refused was not counted"
        );
    }

    #[test]
    fn a_client_that_drains_stops_showing_as_pressure() {
        // The peak is per interval, so a client that filled up and recovered
        // must not keep the gauge pinned for the rest of the server's life,
        // a dashboard that never comes back down is one nobody believes.
        let pressure = Pressure::new();
        let gauge = pressure.gauge(CONTROL_QUEUE_GAUGE, control_budget());
        let (handle, mut rx) = super::channel(1, "tok".to_owned(), 16, 4, CONTROL_BYTE_BUDGET, gauge);

        handle
            .send(
                Lane::Control,
                Outbound::whole(Bytes::from(vec![0_u8; 2048])),
            )
            .expect("queued");
        assert_eq!(pressure.sample()[0].peak, 2048);

        let taken = rx.try_recv().expect("the writer takes it");
        handle.control_sent(taken.len());
        assert_eq!(pressure.sample()[0].peak, 0, "the gauge stayed pinned");
    }

    #[test]
    fn draining_the_queue_returns_the_budget() {
        // Without the credit the budget is a lifetime total rather than a
        // measure of what is queued, so a long-lived, perfectly healthy client
        // is eventually disconnected for bytes it received hours ago.
        let (handle, mut rx) = channel(1, "tok".to_owned(), 16, 4);
        let frame = Bytes::from(vec![0_u8; 1024]);
        handle
            .send(Lane::Control, Outbound::whole(frame.clone()))
            .expect("queued");
        assert_eq!(handle.queued_control_bytes(), 1024);

        let taken = rx.try_recv().expect("the writer takes it");
        handle.control_sent(taken.len());
        assert_eq!(handle.queued_control_bytes(), 0);

        // And the room is genuinely reusable, not merely reported as free.
        for _ in 0..8 {
            handle
                .send(Lane::Control, Outbound::whole(frame.clone()))
                .expect("reusable");
            let taken = rx.try_recv().expect("drained");
            handle.control_sent(taken.len());
        }
        assert_eq!(handle.queued_control_bytes(), 0);
    }

    #[test]
    fn audio_is_still_bounded_by_frames_and_still_drops_rather_than_disconnects() {
        // The asymmetry this module exists for must survive the change: a late
        // voice frame is worthless, so audio drops the oldest and counts it,
        // while control disconnects. Audio frames are all one size, so a frame
        // count bounds their memory perfectly well.
        let (handle, _rx) = channel(1, "tok".to_owned(), 16, 2);
        for _ in 0..10 {
            handle
                .send(Lane::Audio, Outbound::whole(Bytes::from_static(b"frame")))
                .expect("audio never reports overflow");
        }
        assert!(handle.dropped_audio() > 0, "the oldest should have gone");
        assert_eq!(
            handle.queued_control_bytes(),
            0,
            "audio is not charged here"
        );
    }
}
