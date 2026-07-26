//! The FIFO in-memory [`SessionSource`].

use std::collections::VecDeque;

use super::SessionSource;
use crate::ids::SessionId;

/// FIFO pool of session ids.
///
/// Mirrors murmur (`Server.cpp:244`): ids `1..max_users * 2` are enqueued at
/// startup and returned to the *back* of the queue on disconnect
/// (`Server.cpp:1881`). The FIFO discipline matters — it maximises the time
/// before an id is reused, which keeps a reconnecting client from colliding
/// with stale references to its previous session. An exhausted pool refuses the
/// connection rather than growing (`Server.cpp:1625`).
#[derive(Debug)]
pub struct SessionAllocator {
    free: VecDeque<u32>,
}

impl SessionAllocator {
    /// Build a pool sized for `max_users`, matching murmur's `max_users * 2`.
    #[must_use]
    pub fn new(max_users: u32) -> Self {
        Self {
            free: (1..max_users.saturating_mul(2)).collect(),
        }
    }
}

impl SessionSource for SessionAllocator {
    fn allocate(&mut self) -> Option<SessionId> {
        self.free.pop_front().map(SessionId)
    }

    fn release(&mut self, id: SessionId) {
        self.free.push_back(id.0);
    }

    fn available(&self) -> usize {
        self.free.len()
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

    #[test]
    fn zero_max_users_does_not_underflow() {
        // saturating_mul guards the `1..0` range that would otherwise panic in
        // debug on `0 * 2` arithmetic elsewhere.
        assert_eq!(SessionAllocator::new(0).available(), 0);
    }
}
