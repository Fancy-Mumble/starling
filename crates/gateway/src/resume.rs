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
use std::sync::atomic::{AtomicU64, Ordering};
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
    sessions: Arc<Mutex<Sessions>>,
    ring_size: usize,
    /// Bytes one session's ring may hold. See [`DEFAULT_BYTE_BUDGET`].
    byte_budget: usize,
    /// How long a ring outlives its last use. See [`DEFAULT_TTL`].
    ttl: Duration,
    /// Whether to keep anything at all. See [`ResumeStore::from_config`].
    enabled: bool,
    /// Ring entries every sweep has looked at, for the test that holds the
    /// sweep to a bound and for the gauge that will report it.
    swept: Arc<AtomicU64>,
}

/// The rings, and when they were last swept.
///
/// One lock over both. The sweep clock is read on the same path that takes this
/// lock and nothing else needs it, so a second lock would only add an ordering
/// to get wrong.
#[derive(Debug, Default)]
struct Sessions {
    rings: HashMap<String, Ring>,
    /// `None` until the first sweep.
    last_sweep: Option<Instant>,
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
            sessions: Arc::new(Mutex::new(Sessions::default())),
            ring_size: ring_size.max(1),
            byte_budget: DEFAULT_BYTE_BUDGET,
            ttl: DEFAULT_TTL,
            enabled: true,
            swept: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The store an operator asked for.
    ///
    /// The constructor the gateway uses. [`ResumeStore::new`] hardcoded
    /// [`DEFAULT_TTL`] and nothing passed `gateway.resume.ttl` through, so the
    /// documented default of two minutes was silently ten, and
    /// `gateway.resume.enabled = false` set a health warning and changed no
    /// behaviour. Both keys are now the ones in the file.
    #[must_use]
    pub fn from_config(config: &starling_runtime::config::ResumeConfig) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Sessions::default())),
            ring_size: config.ring.max(1),
            byte_budget: DEFAULT_BYTE_BUDGET,
            ttl: config.ttl.get(),
            enabled: config.enabled,
            swept: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The same store with an explicit budget and TTL, for tests.
    #[must_use]
    pub fn with_limits(ring_size: usize, byte_budget: usize, ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Sessions::default())),
            ring_size: ring_size.max(1),
            byte_budget: byte_budget.max(1),
            ttl,
            enabled: true,
            swept: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Whether resume is on at all.
    ///
    /// Read by the gateway before it tells a peer its frames are sequenced: a
    /// sequence number on the wire that no ring is keeping is a client that
    /// will ask to resume and be told to start over.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Ring entries every sweep has visited so far.
    ///
    /// The cost this module has to keep bounded, exposed so a test can hold it
    /// to a bound rather than time it, and so the gauge work can report it.
    #[must_use]
    pub fn swept(&self) -> u64 {
        self.swept.load(Ordering::Relaxed)
    }

    /// Stamp an outbound frame and remember it.
    ///
    /// Returns the sequence number, which the gateway puts on the wire for a
    /// Fancy client and discards for a legacy one.
    /// `payload` is [`Bytes`] so that a broadcast shares one buffer across
    /// every recipient's ring rather than copying it per client.
    pub fn stamp(&self, token: &str, type_id: u16, payload: &Bytes) -> u64 {
        // Nothing kept, nothing to key: the operator turned resume off, and
        // this is the path that would otherwise allocate a ring per session
        // whether or not anything could ever replay from it.
        if !self.enabled {
            return 0;
        }
        let Ok(mut sessions) = self.sessions.lock() else {
            return 0;
        };
        let now = Instant::now();

        // Amortised eviction, here rather than on a timer: this is the only
        // path that runs often enough to keep the store bounded, and a sweep
        // task would be a second thing to own for a map that is already locked.
        //
        // Rate-limited, because this runs once per *recipient* per broadcast
        // and used to sweep every session each time: one message to a thousand
        // clients was a million comparisons under one lock, and the sweep can
        // find nothing new until a ring has had `ttl` of silence anyway.
        self.sweep_due(&mut sessions, now);

        // `get_mut` first: the common case is a ring that exists, and
        // `entry(token.to_owned())` allocates a `String` on *every* stamp,
        // once per recipient per broadcast, just to look one up.
        let ring = if let Some(ring) = sessions.rings.get_mut(token) {
            ring
        } else {
            sessions
                .rings
                .entry(token.to_owned())
                .or_insert_with(|| Ring {
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

    /// Drop rings nothing has touched within `ttl`, at most once per `ttl / 4`.
    ///
    /// Quartered rather than halved so a ring outlives its TTL by at most a
    /// quarter of it, and exactness does not depend on the schedule anyway:
    /// [`ResumeStore::resume`] checks a ring's own age, so a ring still here
    /// because the sweep has not come round is not a ring that can be resumed
    /// from.
    fn sweep_due(&self, sessions: &mut Sessions, now: Instant) {
        if let Some(last) = sessions.last_sweep
            && now.saturating_duration_since(last) < self.ttl / 4
        {
            return;
        }
        sessions.last_sweep = Some(now);
        let _ = self
            .swept
            .fetch_add(sessions.rings.len() as u64, Ordering::Relaxed);
        sessions
            .rings
            .retain(|_, ring| now.saturating_duration_since(ring.touched) < self.ttl);
    }

    /// What to do for a client resuming from `last_seq`.
    #[must_use]
    pub fn resume(&self, token: &str, last_seq: u64) -> ResumeOutcome {
        let Ok(mut sessions) = self.sessions.lock() else {
            return ResumeOutcome::Unknown;
        };
        let Some(ring) = sessions.rings.get_mut(token) else {
            return ResumeOutcome::Unknown;
        };
        let now = Instant::now();
        // Checked here rather than left to the sweep, so how long a ring
        // survives is the TTL an operator configured and not however long it
        // took the next sweep to come round.
        if now.saturating_duration_since(ring.touched) >= self.ttl {
            return ResumeOutcome::Unknown;
        }
        // A client that resumed is a client still here; the ring should not
        // then expire out from under a second reconnect.
        ring.touched = now;

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
            let _ = sessions.rings.remove(token);
        }
    }

    /// How many sessions are held, for the readiness warning.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .map(|s| s.rings.len())
            .unwrap_or_default()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes every ring is holding together.
    ///
    /// What actually bounds this store's memory: the session count says how
    /// many rings exist and nothing about how large they are, and one client
    /// with avatars in its ring costs what a hundred idle ones do.
    #[must_use]
    pub fn bytes_total(&self) -> usize {
        self.sessions
            .lock()
            .map(|sessions| sessions.rings.values().map(|ring| ring.bytes).sum())
            .unwrap_or_default()
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
            .and_then(|sessions| sessions.rings.get(token).map(|ring| ring.bytes))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defect 3: the sweep used to run in full on every stamp.
    ///
    /// Counted rather than timed. A wall-clock assertion here would be a flake
    /// on a loaded machine and would say nothing about *why* it was slow; the
    /// number of ring entries the sweeps looked at is the cost itself.
    #[test]
    fn stamping_does_not_sweep_the_whole_store_every_time() {
        let store = ResumeStore::with_limits(16, 64 * 1024, Duration::from_secs(600));
        let payload = Bytes::from_static(b"x");
        for session in 0..1_000 {
            let _ = store.stamp(&format!("tok-{session}"), 7, &payload);
        }
        let after_fill = store.swept();

        // A thousand stamps into a store already holding a thousand sessions:
        // the shape of one broadcast to a full server, which is exactly where
        // this was quadratic.
        for session in 0..1_000 {
            let _ = store.stamp(&format!("tok-{session}"), 7, &payload);
        }

        let swept = store.swept() - after_fill;
        assert!(
            swept < 4_000,
            "1 000 stamps swept {swept} ring entries; the whole-store sweep this \
             replaced would have visited about a million"
        );
    }

    /// Defect 3, the other half: a rate-limited sweep still has to sweep.
    #[test]
    fn a_ring_nothing_touches_is_still_evicted() {
        let store = ResumeStore::with_limits(16, 64 * 1024, Duration::from_millis(40));
        let _ = store.stamp("stale", 7, &Bytes::from_static(b"x"));
        assert_eq!(store.len(), 1);

        std::thread::sleep(Duration::from_millis(60));
        // Somebody else's traffic, which is what drives the sweep.
        let _ = store.stamp("live", 7, &Bytes::from_static(b"x"));

        assert_eq!(store.len(), 1, "the stale ring must be gone");
        assert!(
            store.bytes_held("live") > 0,
            "and the live one must be what is left"
        );
    }

    /// Defect 3: expiry is the operator's TTL, not the sweep's schedule.
    #[test]
    fn an_expired_ring_cannot_be_resumed_from_even_before_it_is_swept() {
        let store = ResumeStore::with_limits(16, 64 * 1024, Duration::from_millis(30));
        let _ = store.stamp("tok", 7, &Bytes::from_static(b"x"));
        std::thread::sleep(Duration::from_millis(50));

        // Nothing has stamped since, so no sweep has run and the ring is still
        // in the map. It must still be unresumable.
        assert_eq!(store.resume("tok", 0), ResumeOutcome::Unknown);
    }

    /// Defect 4: `gateway.resume.ttl` was hardcoded and never read.
    #[test]
    fn the_configured_ttl_is_the_one_the_store_uses() {
        let config = starling_runtime::config::ResumeConfig {
            enabled: true,
            ring: 32,
            ttl: starling_runtime::config::HumanDuration::secs(5),
        };
        let store = ResumeStore::from_config(&config);
        assert_eq!(store.ttl, Duration::from_secs(5));
        assert_eq!(store.ring_size, 32);
    }

    /// Defect 4: `enabled = false` set a health warning and nothing else.
    #[test]
    fn a_disabled_store_keeps_nothing() {
        let config = starling_runtime::config::ResumeConfig {
            enabled: false,
            ..Default::default()
        };
        let store = ResumeStore::from_config(&config);

        assert!(!store.enabled(), "the gateway asks before it sequences");
        for i in 0..100_u8 {
            assert_eq!(
                store.stamp("tok", 7, &Bytes::copy_from_slice(&[i])),
                0,
                "a disabled store must not hand out sequence numbers"
            );
        }
        assert!(
            store.is_empty(),
            "a disabled store must not allocate a ring"
        );
        assert_eq!(store.resume("tok", 0), ResumeOutcome::Unknown);
    }

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

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    /// Everything the ring promises, checked against one store.
    ///
    /// Gathered in one place because they are not independent: the byte total
    /// is what bounds memory, the floor is what makes a replay honest, and a
    /// store that satisfied one while breaking another would still be wrong.
    fn assert_invariants(store: &ResumeStore, token: &str) -> Result<(), TestCaseError> {
        let sessions = store.sessions.lock().expect("not poisoned");
        let Some(ring) = sessions.rings.get(token) else {
            return Ok(());
        };

        let summed: usize = ring.frames.iter().map(|frame| frame.payload.len()).sum();
        prop_assert_eq!(ring.bytes, summed, "the running byte total must be exact");
        prop_assert!(
            ring.frames.len() <= store.ring_size,
            "the ring must not exceed its frame count"
        );
        prop_assert!(
            ring.bytes <= store.byte_budget || ring.frames.is_empty(),
            "the ring must not exceed its byte budget while holding anything"
        );
        if let Some(front) = ring.frames.front() {
            prop_assert!(
                ring.floor <= front.seq,
                "the floor must not be past the oldest frame kept"
            );
        }
        // Sequence numbers strictly increase, with no gaps inside the ring.
        for pair in ring.frames.iter().collect::<Vec<_>>().windows(2) {
            if let [earlier, later] = pair {
                prop_assert!(earlier.seq < later.seq, "sequence numbers must increase");
            }
        }
        Ok(())
    }

    proptest! {
        /// No sequence of stamps can break the ring's own accounting.
        #[test]
        fn stamping_keeps_every_invariant(
            sizes in prop::collection::vec(0_usize..2048, 1..64),
            ring_size in 1_usize..16,
            budget in 64_usize..4096,
        ) {
            let store = ResumeStore::with_limits(ring_size, budget, Duration::from_secs(600));
            let mut last = 0;
            for size in &sizes {
                let seq = store.stamp("tok", 7, &Bytes::from(vec![0_u8; *size]));
                prop_assert!(seq > last, "sequence numbers must strictly increase");
                last = seq;
                assert_invariants(&store, "tok")?;
            }
        }

        /// A replay is contiguous, in order, and never crosses the floor.
        ///
        /// The property behind the module's own warning: a client handed a
        /// replay with a hole believes it caught up and renders the wrong world
        /// forever, with nothing in any log.
        #[test]
        fn a_replay_is_a_contiguous_run(
            count in 1_usize..64,
            ring_size in 1_usize..32,
            from in 0_u64..70,
        ) {
            let store = ResumeStore::with_limits(ring_size, 1 << 20, Duration::from_secs(600));
            for _ in 0..count {
                let _ = store.stamp("tok", 7, &Bytes::from_static(b"xy"));
            }

            match store.resume("tok", from) {
                ResumeOutcome::Replay(frames) => {
                    for pair in frames.windows(2) {
                        if let [earlier, later] = pair {
                            prop_assert_eq!(
                                earlier.seq + 1,
                                later.seq,
                                "a replay with a gap is worse than a resync"
                            );
                        }
                    }
                    if let Some(first) = frames.first() {
                        prop_assert!(first.seq > from, "a client is not sent what it has");
                    }
                }
                // Both are honest answers; only a holed replay is not.
                ResumeOutcome::FullResyncRequired | ResumeOutcome::Unknown => {}
            }
        }

        /// Defect 3 as a property: the sweep cost does not scale with the store.
        #[test]
        fn sweeping_does_not_scale_with_the_number_of_sessions(
            sessions in 1_usize..200,
        ) {
            let store = ResumeStore::with_limits(8, 1 << 16, Duration::from_secs(600));
            for session in 0..sessions {
                let _ = store.stamp(&format!("tok-{session}"), 7, &Bytes::from_static(b"x"));
            }
            let after_fill = store.swept();
            for session in 0..sessions {
                let _ = store.stamp(&format!("tok-{session}"), 7, &Bytes::from_static(b"x"));
            }
            // The old code swept every session on every stamp, which is
            // `sessions * sessions`. Anything linear is fine; quadratic is not.
            prop_assert!(
                store.swept() - after_fill <= (sessions * 4) as u64,
                "{} entries swept for {} stamps",
                store.swept() - after_fill,
                sessions
            );
        }
    }
}
