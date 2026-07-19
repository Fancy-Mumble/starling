//! The sequence number and its replay ring.
//!
//! Restart a gateway holding ten thousand clients and every one reconnects and
//! pulls a full flood of every `ChannelState` and `UserState` at once, a
//! self-inflicted `DDoS` on `metadata` and `session-view`. With a sequence number
//! per session a Fancy client replays only the gap.
//!
//! Three things about this are deliberate and are all in
//! `docs/ARCHITECTURE.md` §5:
//!
//! * **it is not a service and has no tier.** No client reaches it, it has no
//!   message type, and it is never scaled independently: it is the gateway's own
//!   durable state, externalised so a pod can die. It is reported in readiness
//!   as a *warning*, never as unready.
//! * **legacy clients can never resume**, so staggered drain and jittered
//!   reconnect hints are required regardless. This store optimises a path that
//!   must already survive without it.
//! * **it sits on the control hot path.** The gateway stamps the sequence, so a
//!   naive implementation writes on every outbound frame. This one buffers in
//!   the ring and a crash loses the tail, which is harmless: the client simply
//!   resumes from further back.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

/// How many bytes of replay one session may hold.
///
/// The ring used to be bounded in **frames only**, which counts a 40-byte
/// `UserState` and a 128 KiB avatar the same. At the shipped 256 frames and the
/// default `image_message_length` that is 32 MiB per session, 32 GiB across a
/// thousand clients, for a feature whose whole job is to save a reconnect some
/// work.
///
/// A byte budget is the bound that actually describes the memory. 256 KiB holds
/// hundreds of ordinary control frames, which is what a resume replays.
const DEFAULT_BYTE_BUDGET: usize = 256 * 1024;

/// How long a ring outlives its last use.
///
/// Rings must survive a disconnect (resuming after one is the entire point)
/// so they cannot be freed when the socket closes. But nothing freed them
/// *ever*: `forget` had no callers, so every session that had ever connected
/// kept its ring for the life of the process. Ten minutes is far longer than a
/// reconnect and far shorter than a leak.
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// One stamped outbound frame.
///
/// The payload is [`Bytes`], not `Vec<u8>`: a broadcast stamps the *same*
/// payload once per recipient, and with an owned copy each that is one
/// allocation and one memcpy per client per frame. Refcounted, a thousand
/// recipients share one buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequenced {
    /// Monotonic per session, starting at 1.
    pub seq: u64,
    /// The wire type.
    pub type_id: u16,
    /// The payload, verbatim.
    pub payload: Bytes,
}

/// What a resuming client is told.
#[derive(Debug, Clone, PartialEq)]
pub enum ResumeOutcome {
    /// Replay these, in order.
    Replay(Vec<Sequenced>),
    /// The gap is longer than the ring: re-sync from scratch.
    ///
    /// Said explicitly rather than by sending a short replay, because a client
    /// that believes it caught up and did not renders the wrong world forever
    /// with nothing in any log.
    FullResyncRequired,
    /// No such session, or it has expired.
    Unknown,
}

/// Per-session sequence numbers and their replay rings.
///
/// In-memory here. The design calls for this to outlive the pod so a resuming
/// client can land on another one; the interface is the same either way, which
/// is why the storage decision (frames or events) can still be made without
/// touching a caller.
#[derive(Debug, Clone, Default)]
pub struct ResumeStore {
    sessions: Arc<Mutex<HashMap<String, Ring>>>,
    ring_size: usize,
    /// Bytes one session's ring may hold. See [`DEFAULT_BYTE_BUDGET`].
    byte_budget: usize,
    /// How long a ring outlives its last use. See [`DEFAULT_TTL`].
    ttl: Duration,
}

#[derive(Debug)]
struct Ring {
    next_seq: u64,
    frames: VecDeque<Sequenced>,
    /// Running total of `frames`' payload sizes, so the budget costs no walk.
    bytes: usize,
    /// The lowest sequence still replayable.
    ///
    /// Tracked rather than read off the front of the ring, because the ring can
    /// be *empty* and still have a floor: one frame larger than the whole
    /// budget is dropped outright, and a client asking for anything at or below
    /// it has to be told to resync rather than handed a replay with a hole in
    /// it. That hole is the failure this module's own header warns about, a
    /// client that believes it caught up and did not.
    floor: u64,
    /// Last stamp or resume, for eviction.
    touched: Instant,
}

impl ResumeStore {
    /// A store keeping `ring_size` frames per session, under the default byte
    /// budget and TTL.
    #[must_use]
    pub fn new(ring_size: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ring_size: ring_size.max(1),
            byte_budget: DEFAULT_BYTE_BUDGET,
            ttl: DEFAULT_TTL,
        }
    }

    /// The same store with an explicit budget and TTL, for tests.
    #[must_use]
    pub fn with_limits(ring_size: usize, byte_budget: usize, ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ring_size: ring_size.max(1),
            byte_budget: byte_budget.max(1),
            ttl,
        }
    }

    /// Stamp an outbound frame and remember it.
    ///
    /// Returns the sequence number, which the gateway puts on the wire for a
    /// Fancy client and discards for a legacy one.
    /// `payload` is [`Bytes`] so that a broadcast shares one buffer across
    /// every recipient's ring rather than copying it per client.
    pub fn stamp(&self, token: &str, type_id: u16, payload: &Bytes) -> u64 {
        let Ok(mut sessions) = self.sessions.lock() else {
            return 0;
        };
        let now = Instant::now();

        // Amortised eviction, here rather than on a timer: this is the only
        // path that runs often enough to keep the store bounded, and a sweep
        // task would be a second thing to own for a map that is already locked.
        Self::evict_expired(&mut sessions, self.ttl, now);

        // `get_mut` first: the common case is a ring that exists, and
        // `entry(token.to_owned())` allocates a `String` on *every* stamp,
        // once per recipient per broadcast, just to look one up.
        let ring = if let Some(ring) = sessions.get_mut(token) {
            ring
        } else {
            sessions.entry(token.to_owned()).or_insert_with(|| Ring {
                next_seq: 1,
                frames: VecDeque::new(),
                bytes: 0,
                floor: 1,
                touched: now,
            })
        };

        let seq = ring.next_seq;
        ring.next_seq += 1;
        ring.touched = now;

        // One frame bigger than the whole budget: keeping it would evict
        // everything else to hold a single avatar, and a resume cannot be
        // served from it anyway. Dropped, and the floor moves past it so a
        // client that needs it is told to resync rather than sent a replay
        // missing exactly the frame it asked about.
        if payload.len() > self.byte_budget {
            ring.frames.clear();
            ring.bytes = 0;
            ring.floor = seq + 1;
            return seq;
        }

        ring.bytes += payload.len();
        ring.frames.push_back(Sequenced {
            seq,
            type_id,
            payload: payload.clone(),
        });
        while ring.frames.len() > self.ring_size || ring.bytes > self.byte_budget {
            let Some(dropped) = ring.frames.pop_front() else {
                break;
            };
            ring.bytes = ring.bytes.saturating_sub(dropped.payload.len());
            ring.floor = dropped.seq + 1;
        }
        seq
    }

    /// Drop rings nothing has touched within `ttl`.
    fn evict_expired(sessions: &mut HashMap<String, Ring>, ttl: Duration, now: Instant) {
        // Cheap when nothing has expired, which is the usual case: the closure
        // is a subtraction per session and this runs on the control path, not
        // the audio one.
        sessions.retain(|_, ring| now.duration_since(ring.touched) < ttl);
    }

    /// What to do for a client resuming from `last_seq`.
    #[must_use]
    pub fn resume(&self, token: &str, last_seq: u64) -> ResumeOutcome {
        let Ok(mut sessions) = self.sessions.lock() else {
            return ResumeOutcome::Unknown;
        };
        let Some(ring) = sessions.get_mut(token) else {
            return ResumeOutcome::Unknown;
        };
        // A client that resumed is a client still here; the ring should not
        // then expire out from under a second reconnect.
        ring.touched = Instant::now();

        // The floor, not the front of the ring. An oversized frame is dropped
        // without leaving anything at the front to read a sequence off, and
        // trusting `next_seq` there would report the gap as replayable.
        let oldest = ring.frames.front().map_or(ring.floor, |frame| frame.seq);
        if last_seq + 1 < oldest {
            return ResumeOutcome::FullResyncRequired;
        }
        ResumeOutcome::Replay(
            ring.frames
                .iter()
                .filter(|frame| frame.seq > last_seq)
                .cloned()
                .collect(),
        )
    }

    /// Forget a session, once it can no longer resume.
    pub fn forget(&self, token: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.remove(token);
        }
    }

    /// How many sessions are held, for the readiness warning.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or_default()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes one session's ring is holding, for the tests and the admin surface.
    ///
    /// The number an operator needs to answer "why is the gateway using that
    /// much memory": the ring is per session and invisible from everywhere
    /// else.
    #[must_use]
    pub fn bytes_held(&self, token: &str) -> usize {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(token).map(|ring| ring.bytes))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resuming_client_replays_only_the_gap() {
        // The whole point: not a full flood of every ChannelState again.
        let store = ResumeStore::new(16);
        for i in 0..5_u8 {
            let _ = store.stamp("tok", 7, &Bytes::copy_from_slice(&[i]));
        }
        let ResumeOutcome::Replay(frames) = store.resume("tok", 3) else {
            panic!("a client three frames behind must replay");
        };
        assert_eq!(frames.len(), 2);
        assert_eq!(frames.first().map(|f| f.seq), Some(4));
    }

    #[test]
    fn a_gap_longer_than_the_ring_says_so_rather_than_replaying_a_hole() {
        // Sending a short replay would leave the client rendering the wrong
        // world forever, with nothing in any log.
        let store = ResumeStore::new(4);
        for i in 0..10_u8 {
            let _ = store.stamp("tok", 7, &Bytes::copy_from_slice(&[i]));
        }
        assert_eq!(store.resume("tok", 1), ResumeOutcome::FullResyncRequired);
    }

    #[test]
    fn sequence_numbers_are_per_session_and_start_at_one() {
        let store = ResumeStore::new(4);
        assert_eq!(store.stamp("a", 7, &Bytes::new()), 1);
        assert_eq!(store.stamp("b", 7, &Bytes::new()), 1);
        assert_eq!(store.stamp("a", 7, &Bytes::new()), 2);
    }

    #[test]
    fn an_unknown_session_is_distinguishable_from_an_empty_one() {
        let store = ResumeStore::new(4);
        assert_eq!(store.resume("nobody", 0), ResumeOutcome::Unknown);
        let _ = store.stamp("somebody", 7, &Bytes::new());
        assert!(matches!(
            store.resume("somebody", 1),
            ResumeOutcome::Replay(frames) if frames.is_empty()
        ));
    }

    /// A payload of `n` bytes.
    fn payload(n: usize) -> Bytes {
        Bytes::from(vec![0xAB_u8; n])
    }

    #[test]
    fn one_session_cannot_hold_more_than_its_byte_budget() {
        // The bound that was missing. The ring was capped in *frames*, so a
        // client trading avatars held 256 x image_message_length, 32 MiB each,
        // 32 GiB across a thousand of them, for a reconnect optimisation.
        let store = ResumeStore::with_limits(256, 64 * 1024, Duration::from_secs(600));
        for _ in 0..200 {
            let _ = store.stamp("tok", 7, &payload(8 * 1024));
        }
        assert!(
            store.bytes_held("tok") <= 64 * 1024,
            "held {} bytes against a 64 KiB budget",
            store.bytes_held("tok")
        );
    }

    #[test]
    fn a_frame_larger_than_the_budget_is_dropped_rather_than_evicting_everything() {
        // An avatar bigger than the whole ring. Keeping it would throw away
        // every ordinary frame to hold one blob that a resume cannot use
        // anyway; the client can simply ask for it again.
        let store = ResumeStore::with_limits(256, 16 * 1024, Duration::from_secs(600));
        let _ = store.stamp("tok", 7, &payload(100));
        let seq = store.stamp("tok", 23, &payload(64 * 1024));
        assert_eq!(store.bytes_held("tok"), 0, "the oversized frame was kept");

        // And the client is told to resync rather than handed a replay with a
        // hole where that frame was. Asking from before it must not produce a
        // short, plausible-looking replay.
        assert_eq!(
            store.resume("tok", seq - 1),
            ResumeOutcome::FullResyncRequired,
            "a gap must be reported, not papered over"
        );
    }

    #[test]
    fn a_ring_nothing_has_touched_is_eventually_freed() {
        // `forget` existed and had no callers, so every session that had ever
        // connected kept its ring for the life of the process. Rings cannot be
        // freed on disconnect (surviving one is the whole point) so the
        // bound has to be a TTL.
        let store = ResumeStore::with_limits(16, 64 * 1024, Duration::from_millis(50));
        let _ = store.stamp("old", 7, &payload(10));
        assert_eq!(store.len(), 1);

        std::thread::sleep(Duration::from_millis(80));
        // Eviction is amortised onto the next stamp rather than a timer.
        let _ = store.stamp("new", 7, &payload(10));

        assert_eq!(store.len(), 1, "the expired ring was not freed");
        assert_eq!(store.resume("old", 0), ResumeOutcome::Unknown);
    }

    #[test]
    fn a_resuming_client_keeps_its_ring_alive() {
        // Resuming is use. A ring that expired between two reconnects would
        // send a client that *is* still there through a full resync.
        let store = ResumeStore::with_limits(16, 64 * 1024, Duration::from_millis(80));
        let _ = store.stamp("tok", 7, &payload(10));

        std::thread::sleep(Duration::from_millis(50));
        let _ = store.resume("tok", 0);
        std::thread::sleep(Duration::from_millis(50));
        let _ = store.stamp("other", 7, &payload(10));

        assert_ne!(
            store.resume("tok", 0),
            ResumeOutcome::Unknown,
            "a ring in active use was evicted"
        );
    }

    #[test]
    fn a_broadcast_shares_one_buffer_across_every_recipient() {
        // The per-recipient copy. `stamp` took a slice and owned a fresh `Vec`,
        // so one broadcast to a thousand clients made a thousand copies of the
        // same payload. Refcounted, the buffer is shared, which is only
        // observable as the pointer being the same one.
        let store = ResumeStore::with_limits(16, 64 * 1024, Duration::from_secs(600));
        let shared = payload(4096);
        for who in 0..50 {
            let _ = store.stamp(&format!("client-{who}"), 7, &shared);
        }

        let ResumeOutcome::Replay(frames) = store.resume("client-7", 0) else {
            panic!("expected a replay");
        };
        assert_eq!(
            frames[0].payload.as_ptr(),
            shared.as_ptr(),
            "the payload was copied per recipient rather than shared"
        );
    }
}
