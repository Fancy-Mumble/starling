//! Ban ids: minted from the clock, never twice.
//!
//! A ban's id is the millisecond it was issued, which the operator API hands
//! back to lift it by. Two bans in one millisecond are ordinary, a kick-ban of
//! a user on two devices writes one per device and a written list adds several
//! at once, and the table's key is `(server_id, id)`, so the second insert
//! failed and that ban was never stored.

use std::sync::atomic::{AtomicU64, Ordering};

/// The last id handed out.
#[derive(Debug, Default)]
pub(crate) struct BanIds {
    last: AtomicU64,
}

impl BanIds {
    /// `now_ms`, or one past the last id when that is not later.
    pub(crate) fn next(&self, now_ms: u64) -> u64 {
        let mut last = self.last.load(Ordering::Relaxed);
        loop {
            let id = now_ms.max(last.saturating_add(1));
            match self
                .last
                .compare_exchange_weak(last, id, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return id,
                Err(seen) => last = seen,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_in_one_millisecond_are_still_distinct_and_rising() {
        let ids = BanIds::default();
        let first = ids.next(1_000);
        let second = ids.next(1_000);
        assert_eq!(first, 1_000);
        assert_eq!(second, 1_001);
        assert_eq!(ids.next(5_000), 5_000, "the clock wins once it is ahead");
    }
}
