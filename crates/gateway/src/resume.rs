//! The sequence number and its replay ring.
//!
//! Restart a gateway holding ten thousand clients and every one reconnects and
//! pulls a full flood of every `ChannelState` and `UserState` at once — a
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

/// One stamped outbound frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequenced {
    /// Monotonic per session, starting at 1.
    pub seq: u64,
    /// The wire type.
    pub type_id: u16,
    /// The payload, verbatim.
    pub payload: Vec<u8>,
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
/// is why the storage decision — frames or events — can still be made without
/// touching a caller.
#[derive(Debug, Clone, Default)]
pub struct ResumeStore {
    sessions: Arc<Mutex<HashMap<String, Ring>>>,
    ring_size: usize,
}

#[derive(Debug)]
struct Ring {
    next_seq: u64,
    frames: VecDeque<Sequenced>,
}

impl ResumeStore {
    /// A store keeping `ring_size` frames per session.
    #[must_use]
    pub fn new(ring_size: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ring_size: ring_size.max(1),
        }
    }

    /// Stamp an outbound frame and remember it.
    ///
    /// Returns the sequence number, which the gateway puts on the wire for a
    /// Fancy client and discards for a legacy one.
    pub fn stamp(&self, token: &str, type_id: u16, payload: &[u8]) -> u64 {
        let Ok(mut sessions) = self.sessions.lock() else {
            return 0;
        };
        let ring = sessions.entry(token.to_owned()).or_insert_with(|| Ring {
            next_seq: 1,
            frames: VecDeque::new(),
        });
        let seq = ring.next_seq;
        ring.next_seq += 1;
        ring.frames.push_back(Sequenced {
            seq,
            type_id,
            payload: payload.to_vec(),
        });
        while ring.frames.len() > self.ring_size {
            let _ = ring.frames.pop_front();
        }
        seq
    }

    /// What to do for a client resuming from `last_seq`.
    #[must_use]
    pub fn resume(&self, token: &str, last_seq: u64) -> ResumeOutcome {
        let Ok(sessions) = self.sessions.lock() else {
            return ResumeOutcome::Unknown;
        };
        let Some(ring) = sessions.get(token) else {
            return ResumeOutcome::Unknown;
        };
        let oldest = ring.frames.front().map_or(ring.next_seq, |frame| frame.seq);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resuming_client_replays_only_the_gap() {
        // The whole point: not a full flood of every ChannelState again.
        let store = ResumeStore::new(16);
        for i in 0..5_u8 {
            let _ = store.stamp("tok", 7, &[i]);
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
            let _ = store.stamp("tok", 7, &[i]);
        }
        assert_eq!(store.resume("tok", 1), ResumeOutcome::FullResyncRequired);
    }

    #[test]
    fn sequence_numbers_are_per_session_and_start_at_one() {
        let store = ResumeStore::new(4);
        assert_eq!(store.stamp("a", 7, b""), 1);
        assert_eq!(store.stamp("b", 7, b""), 1);
        assert_eq!(store.stamp("a", 7, b""), 2);
    }

    #[test]
    fn an_unknown_session_is_distinguishable_from_an_empty_one() {
        let store = ResumeStore::new(4);
        assert_eq!(store.resume("nobody", 0), ResumeOutcome::Unknown);
        let _ = store.stamp("somebody", 7, b"");
        assert!(matches!(
            store.resume("somebody", 1),
            ResumeOutcome::Replay(frames) if frames.is_empty()
        ));
    }
}
