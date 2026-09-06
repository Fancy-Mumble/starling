//! The FIFO in-memory [`SessionSource`].

use std::collections::{HashSet, VecDeque};

use super::SessionSource;
use crate::ids::SessionId;

/// FIFO pool of session ids.
///
/// Mirrors murmur (`Server.cpp:244`): ids `1..max_users * 2` are enqueued at
/// startup and returned to the *back* of the queue on disconnect
/// (`Server.cpp:1881`). The FIFO discipline matters, it maximises the time
/// before an id is reused, which keeps a reconnecting client from colliding
/// with stale references to its previous session. An exhausted pool refuses the
/// connection rather than growing (`Server.cpp:1625`).
#[derive(Debug)]
pub struct SessionAllocator {
    /// One past the highest id ever handed out. Ids at or above this and below
    /// `limit` have never been used and cost nothing to hold.
    next: u32,
    /// One past the highest id this pool may ever hand out.
    limit: u32,
    /// Ids handed back, in the order they were returned.
    free: VecDeque<u32>,
    /// Ids currently held by a session.
    ///
    /// What makes [`SessionSource::release`] able to refuse. Bounded by the
    /// number of *connected* users rather than by `max_users`, so it is small
    /// on a server configured for a crowd that has not arrived.
    live: HashSet<u32>,
}

impl SessionAllocator {
    /// Build a pool sized for `max_users`, matching murmur's `max_users * 2`.
    ///
    /// The range is counted, not materialised. Murmur enqueues every id at
    /// startup and this used to copy that literally, which made a mistyped
    /// `max_users` a multi-gigabyte allocation at boot: `4_000_000_000` is a
    /// plausible typo and 32 GB of `VecDeque`. Handing ids out on demand gives
    /// the same sequence for a pool that costs what it is using.
    #[must_use]
    pub fn new(max_users: u32) -> Self {
        Self {
            next: 1,
            limit: max_users.saturating_mul(2),
            free: VecDeque::new(),
            live: HashSet::new(),
        }
    }
}

impl SessionSource for SessionAllocator {
    fn allocate(&mut self) -> Option<SessionId> {
        // Never-used ids first, then returned ones oldest-first. Together that
        // is murmur's single FIFO: a released id goes behind every id still
        // waiting to be handed out for the first time.
        let id = if self.next < self.limit {
            let id = self.next;
            self.next += 1;
            id
        } else {
            self.free.pop_front()?
        };
        let _ = self.live.insert(id);
        Some(SessionId(id))
    }

    fn release(&mut self, id: SessionId) {
        // Checked, not trusted. This used to push whatever it was given, so a
        // double release put one id in the queue twice and the pool handed the
        // same session number to two connected users -- who would then be each
        // other as far as every `session`-keyed message is concerned.
        if self.live.remove(&id.0) {
            self.free.push_back(id.0);
        }
    }

    fn available(&self) -> usize {
        let unused = self.limit.saturating_sub(self.next) as usize;
        unused + self.free.len()
    }
}

impl SessionAllocator {
    /// Ids currently held by a session.
    ///
    /// Exact, not `size - available`: the two agree, and this reads the set
    /// that actually decides whether a release is accepted.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.live.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The [`SessionSource`] contract, asserted against any implementation.
    fn assert_source_contract(source: &mut dyn SessionSource) {
        let mut seen = Vec::new();
        while let Some(id) = source.allocate() {
            assert_ne!(id, SessionId(0), "0 is the wire's 'no session' value");
            assert!(!seen.contains(&id), "{id} was handed out twice");
            seen.push(id);
        }
        // 1. Exhaustion reports itself rather than fabricating an id.
        assert_eq!(source.allocate(), None);
        assert_eq!(source.available(), 0);

        // 2. A released id becomes available again.
        if let Some(first) = seen.first().copied() {
            source.release(first);
            assert_eq!(source.available(), 1);
            assert_eq!(source.allocate(), Some(first));
        }
    }

    #[test]
    fn the_fifo_allocator_satisfies_the_source_contract() {
        assert_source_contract(&mut SessionAllocator::new(4));
    }

    #[test]
    fn ids_start_at_one_so_zero_stays_an_invalid_session() {
        let mut pool = SessionAllocator::new(10);
        assert_eq!(pool.allocate(), Some(SessionId(1)));
    }

    #[test]
    fn pool_is_sized_at_twice_max_users() {
        // 1..(5 * 2) == 1..10 == 9 ids, matching murmur's loop bounds.
        assert_eq!(SessionAllocator::new(5).available(), 9);
    }

    #[test]
    fn released_ids_go_to_the_back_not_the_front() {
        let mut pool = SessionAllocator::new(3); // ids 1..6
        let first = pool.allocate().expect("pool has ids");
        let second = pool.allocate().expect("pool has ids");
        pool.release(first);
        // If release pushed to the front we would get `first` back immediately,
        // which is exactly the reuse murmur's FIFO avoids.
        assert_eq!(pool.allocate(), Some(SessionId(3)));
        assert_ne!(second, SessionId(3));
    }

    #[test]
    fn exhausted_pool_returns_none_rather_than_reusing() {
        let mut pool = SessionAllocator::new(1); // 1..2 -> a single id
        assert_eq!(pool.allocate(), Some(SessionId(1)));
        assert_eq!(pool.allocate(), None);
    }

    /// Defect 18: `release` pushed anything it was handed.
    #[test]
    fn releasing_an_id_twice_does_not_hand_it_to_two_users() {
        let mut pool = SessionAllocator::new(3); // ids 1..6
        let held = pool.allocate().expect("pool has ids");

        pool.release(held);
        pool.release(held);
        pool.release(held);

        let mut seen = Vec::new();
        while let Some(id) = pool.allocate() {
            assert!(
                !seen.contains(&id),
                "{id} was handed out twice; two connected users would share a \
                 session number"
            );
            seen.push(id);
        }
    }

    /// Defect 18: an id nobody holds cannot be returned into circulation.
    #[test]
    fn releasing_an_id_that_was_never_allocated_is_ignored() {
        let mut pool = SessionAllocator::new(2); // ids 1..4
        let before = pool.available();

        pool.release(SessionId(9_999));
        pool.release(SessionId(2));

        assert_eq!(
            pool.available(),
            before,
            "an id the pool never handed out must not appear in it"
        );
    }

    /// Defect 18: the pool used to materialise every id at construction.
    #[test]
    fn a_huge_max_users_costs_nothing_until_the_users_arrive() {
        // 32 GB of `VecDeque` under the old constructor, which ran at boot from
        // a number an operator typed.
        let mut pool = SessionAllocator::new(u32::MAX);

        assert_eq!(pool.allocate(), Some(SessionId(1)));
        assert_eq!(pool.allocate(), Some(SessionId(2)));
        assert!(pool.available() > 1_000_000);
    }

    #[test]
    fn zero_max_users_does_not_underflow() {
        // saturating_mul guards the `1..0` range that would otherwise panic in
        // debug on `0 * 2` arithmetic elsewhere.
        assert_eq!(SessionAllocator::new(0).available(), 0);
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    /// What a caller can do to the pool.
    #[derive(Debug, Clone)]
    enum Step {
        Allocate,
        /// Release an id the pool has handed out, by position among those held.
        ReleaseHeld(usize),
        /// Release an id nobody holds, which the pool must ignore.
        ReleaseStray(u32),
    }

    fn steps() -> impl Strategy<Value = Vec<Step>> {
        prop::collection::vec(
            prop_oneof![
                3 => Just(Step::Allocate),
                2 => (0_usize..32).prop_map(Step::ReleaseHeld),
                1 => (0_u32..64).prop_map(Step::ReleaseStray),
            ],
            1..200,
        )
    }

    proptest! {
        /// Defect 18 as a property: no sequence yields two live holders of one id.
        ///
        /// The consequence if it did is not subtle. Every `session`-keyed
        /// message -- a move, a mute, a text, a kick -- addresses a number, so
        /// two users sharing one would each receive the other's, and a
        /// moderator kicking one would kick whichever the server looked up.
        #[test]
        fn no_sequence_hands_one_id_to_two_holders(max_users in 1_u32..24, steps in steps()) {
            let mut pool = SessionAllocator::new(max_users);
            let mut live: Vec<SessionId> = Vec::new();

            for step in steps {
                match step {
                    Step::Allocate => {
                        if let Some(id) = pool.allocate() {
                            prop_assert!(
                                !live.contains(&id),
                                "{id} was handed out while already held"
                            );
                            prop_assert_ne!(id, SessionId(0), "0 is the wire's 'no session'");
                            live.push(id);
                        }
                    }
                    Step::ReleaseHeld(at) => {
                        if !live.is_empty() {
                            let id = live.remove(at % live.len());
                            pool.release(id);
                            // Releasing twice is the double-release this guards.
                            pool.release(id);
                        }
                    }
                    Step::ReleaseStray(id) => {
                        let id = SessionId(id);
                        if !live.contains(&id) {
                            pool.release(id);
                        }
                    }
                }
            }

            // Whatever remains available, taking all of it must not collide
            // with anything still held.
            while let Some(id) = pool.allocate() {
                prop_assert!(!live.contains(&id), "{id} was handed out while held");
                live.push(id);
            }
        }

        /// The pool never hands out more ids than it was sized for.
        #[test]
        fn the_pool_never_exceeds_its_configured_size(max_users in 0_u32..64) {
            let mut pool = SessionAllocator::new(max_users);
            let mut handed = 0_u32;
            while pool.allocate().is_some() {
                handed += 1;
                prop_assert!(handed <= max_users.saturating_mul(2), "the pool grew");
            }
            prop_assert_eq!(handed, max_users.saturating_mul(2).saturating_sub(1));
        }

        /// Defect 18's other half: construction costs nothing per configured user.
        #[test]
        fn construction_is_independent_of_max_users(max_users in 0_u32..u32::MAX) {
            // Would have been a `VecDeque` of `max_users * 2` before, which at
            // the top of this range is tens of gigabytes at boot.
            let pool = SessionAllocator::new(max_users);
            prop_assert_eq!(
                pool.available(),
                max_users.saturating_mul(2).saturating_sub(1) as usize
            );
        }
    }
}
