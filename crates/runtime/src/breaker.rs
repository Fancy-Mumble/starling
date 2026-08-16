//! A circuit breaker per service, because deadlines alone fail slowly.
//!
//! A saturated service otherwise makes every caller wait its full deadline and
//! *then* fail, burning gateway capacity throughout, the gateway spends five
//! seconds per request discovering something it learned five seconds ago. Trip
//! the breaker and shed at the door instead (`docs/ARCHITECTURE.md` §5).
//!
//! Shedding uses the same [`Tier`](crate::tier::Tier) the readiness logic does:
//! an unhealthy essential service rejects logins, an unhealthy optional one is
//! invisible.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// What a breaker is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Calls pass.
    Closed,
    /// Calls are shed without being attempted.
    Open,
    /// One call is allowed through to find out whether the service is back.
    HalfOpen,
}

/// Failure accounting for one service.
///
/// Time is passed in rather than read, so the behaviour is testable without
/// sleeping and a caller that already has a timestamp does not take another.
#[derive(Debug, Clone)]
pub struct Breaker {
    failures: Arc<AtomicU64>,
    opened_at_ms: Arc<AtomicU64>,
    /// Consecutive failures before it trips, as the operator has it now.
    ///
    /// Shared and atomic rather than copied, because a breaker tripping too
    /// eagerly is diagnosed on a running server: the gateway sheds essential
    /// traffic nobody meant it to shed, and the operator needs the threshold
    /// moved without restarting the process holding every client.
    threshold: Arc<AtomicU64>,
    cooldown_ms: Arc<AtomicU64>,
}

impl Breaker {
    /// Trip after `threshold` consecutive failures, and shed for `cooldown_ms`.
    #[must_use]
    pub fn new(threshold: u32, cooldown_ms: u64) -> Self {
        Self {
            failures: Arc::new(AtomicU64::new(0)),
            opened_at_ms: Arc::new(AtomicU64::new(0)),
            threshold: Arc::new(AtomicU64::new(u64::from(threshold.max(1)))),
            cooldown_ms: Arc::new(AtomicU64::new(cooldown_ms)),
        }
    }

    /// Adopt new numbers, without disturbing the failures already counted.
    ///
    /// A breaker mid-cooldown keeps its clock: lowering the cooldown lets it
    /// try again sooner, which is what an operator shortening it means, and
    /// resetting the count instead would hide a service that is still failing.
    pub fn retune(&self, threshold: u32, cooldown_ms: u64) {
        self.threshold
            .store(u64::from(threshold.max(1)), Ordering::Relaxed);
        self.cooldown_ms.store(cooldown_ms, Ordering::Relaxed);
    }

    /// Consecutive failures before it trips.
    #[must_use]
    pub fn threshold(&self) -> u64 {
        self.threshold.load(Ordering::Relaxed)
    }

    /// How long a tripped breaker sheds for.
    #[must_use]
    pub fn cooldown_ms(&self) -> u64 {
        self.cooldown_ms.load(Ordering::Relaxed)
    }

    /// What the breaker would do to a call made now.
    #[must_use]
    pub fn state(&self, now_ms: u64) -> BreakerState {
        let opened_at = self.opened_at_ms.load(Ordering::Acquire);
        if opened_at == 0 {
            return BreakerState::Closed;
        }
        if now_ms.saturating_sub(opened_at) >= self.cooldown_ms() {
            BreakerState::HalfOpen
        } else {
            BreakerState::Open
        }
    }

    /// Whether a call may be attempted.
    #[must_use]
    pub fn allows(&self, now_ms: u64) -> bool {
        !matches!(self.state(now_ms), BreakerState::Open)
    }

    /// Record a success, which closes the breaker.
    pub fn succeeded(&self) {
        self.failures.store(0, Ordering::Release);
        self.opened_at_ms.store(0, Ordering::Release);
    }

    /// Record a failure, tripping the breaker at the threshold.
    pub fn failed(&self, now_ms: u64) {
        let count = self.failures.fetch_add(1, Ordering::AcqRel) + 1;
        if count >= self.threshold() {
            // `now_ms + 1` because zero is the "never opened" sentinel and a
            // breaker tripping at time zero must still read as open.
            self.opened_at_ms.store(now_ms.max(1), Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_breaker_trips_only_at_the_threshold() {
        let breaker = Breaker::new(3, 1000);
        breaker.failed(10);
        breaker.failed(10);
        assert!(breaker.allows(10), "two failures is not a pattern");
        breaker.failed(10);
        assert!(!breaker.allows(10), "the third must trip it");
    }

    #[test]
    fn a_tripped_breaker_sheds_without_waiting_for_a_deadline() {
        // This is the entire point: the caller learns immediately rather than
        // after five seconds of holding capacity open.
        let breaker = Breaker::new(1, 5_000);
        breaker.failed(100);
        assert_eq!(breaker.state(200), BreakerState::Open);
    }

    #[test]
    fn after_the_cooldown_one_call_is_let_through_to_probe() {
        let breaker = Breaker::new(1, 1_000);
        breaker.failed(100);
        assert_eq!(breaker.state(1_101), BreakerState::HalfOpen);
        assert!(breaker.allows(1_101));
    }

    #[test]
    fn a_success_closes_the_breaker_and_forgets_the_failures() {
        let breaker = Breaker::new(2, 1_000);
        breaker.failed(0);
        breaker.succeeded();
        breaker.failed(0);
        assert!(breaker.allows(0), "the counter must have been reset");
    }
}
