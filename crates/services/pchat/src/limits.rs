//! Per-connection budgets for the persistent-chat operations.
//!
//! The module doc claimed this service owned rate limiting; it did not have
//! any. The gateway's limiter is per connection and per route, which stops a
//! client flooding the socket but says nothing about how often that client may
//! write to the archive or ask the database to page through it.
//!
//! Three buckets rather than one, for the reason [`starling_runtime::ratelimit`]
//! gives: a burst of key management must not exhaust the budget a conversation
//! needs. They are separate because they cost different things, a fetch is a
//! database scan, a message is an insert, and key management is neither but is
//! the half of the wire that decides who can read a channel.
//!
//! Keyed on the **connection**, not the session: a session id is recycled, and
//! the plane reports a departure as a conn (`ClientService::closed`), so this is
//! the identity that can actually be evicted when the client goes away.

use std::collections::HashMap;
use std::sync::Mutex;

use starling_runtime::ids::now_ms;
use starling_runtime::ratelimit::{Rate, TokenBucket};

/// What a client is asking for, for the purpose of budgeting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    /// Store one message.
    Message,
    /// Page through the archive.
    Fetch,
    /// Anything that is relayed: keys, reactions, pins, receipts, deletes.
    Manage,
}

impl Op {
    /// Sustained rate and burst.
    ///
    /// Sized for a person typing rather than a client syncing: the burst
    /// absorbs a paste or a reconnect, the rate is what a conversation needs.
    const fn budget(self) -> (f64, u32) {
        match self {
            Self::Message => (2.0, 20),
            Self::Fetch => (0.5, 10),
            Self::Manage => (2.0, 30),
        }
    }
}

/// Every live connection's buckets.
#[derive(Debug, Default)]
pub(crate) struct Limits {
    buckets: Mutex<HashMap<(u64, Op), TokenBucket>>,
}

impl Limits {
    /// No connections, no buckets.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether `conn` may perform `op` now, spending a token if so.
    ///
    /// A poisoned lock allows: refusing every request because a mutex broke
    /// turns a bookkeeping fault into an outage, and the limiter is a budget
    /// rather than an authorisation.
    pub(crate) fn allow(&self, conn: u64, op: Op) -> bool {
        let Ok(mut buckets) = self.buckets.lock() else {
            return true;
        };
        let now = now_ms();
        let (rate, burst) = op.budget();
        buckets
            .entry((conn, op))
            .or_insert_with(|| TokenBucket::new(Rate::per_second(rate), burst, now))
            .take(now)
            .is_ok()
    }

    /// Drop everything held for `conn`.
    ///
    /// Without this the map grows one entry per (connection, operation) for the
    /// life of the process, the same defect the C++ limiter had, where the
    /// eviction method existed and nothing ever called it.
    pub(crate) fn forget(&self, conn: u64) {
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.retain(|(held, _), _| *held != conn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_and_then_the_budget_runs_out() {
        let limits = Limits::new();
        let (_, burst) = Op::Fetch.budget();
        for _ in 0..burst {
            assert!(limits.allow(1, Op::Fetch));
        }
        assert!(!limits.allow(1, Op::Fetch), "the bucket should be empty");
    }

    #[test]
    fn exhausting_one_operation_leaves_the_others_alone() {
        // The reason there are three buckets: syncing keys must not cost
        // somebody the ability to send a message.
        let limits = Limits::new();
        let (_, burst) = Op::Manage.budget();
        for _ in 0..burst {
            let _ = limits.allow(1, Op::Manage);
        }
        assert!(!limits.allow(1, Op::Manage));
        assert!(limits.allow(1, Op::Message));
    }

    #[test]
    fn one_connection_cannot_spend_anothers_budget() {
        let limits = Limits::new();
        let (_, burst) = Op::Fetch.budget();
        for _ in 0..burst {
            let _ = limits.allow(1, Op::Fetch);
        }
        assert!(!limits.allow(1, Op::Fetch));
        assert!(limits.allow(2, Op::Fetch));
    }

    #[test]
    fn a_departed_connection_takes_its_buckets_with_it() {
        // Asserted through behaviour rather than a length: an exhausted bucket
        // that allows again is the same evidence the map no longer holds it,
        // and it does not require exposing the map to say so.
        let limits = Limits::new();
        let (_, burst) = Op::Fetch.budget();
        for _ in 0..burst {
            let _ = limits.allow(1, Op::Fetch);
        }
        assert!(!limits.allow(1, Op::Fetch));

        limits.forget(1);
        assert!(limits.allow(1, Op::Fetch));
    }
}
