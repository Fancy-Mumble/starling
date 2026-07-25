//! The metrics boundary.
//!
//! Same shape as `starling-log`'s `LogSink`: a priority scheme nobody can
//! observe is a priority scheme nobody can confirm. Where the numbers *go* is a
//! strategy — atomics today, Prometheus or OpenTelemetry later, nothing at all
//! in a benchmark that must not pay for counting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Records what a lane did.
///
/// # Contract
///
/// 1. **Never blocks and never fails.** Metrics are diagnostics, never control
///    flow; a recorder that could stall would turn observability into an
///    outage.
/// 2. Recording is called on the hot path, so an implementation that cannot be
///    cheap should sample rather than slow the queue down.
/// 3. Readers may return stale values. Exactness is not worth synchronisation
///    here.
pub trait Metrics: Send + Sync + std::fmt::Debug {
    /// An envelope was accepted into the queue.
    fn offered(&self);
    /// An envelope was handed to a receiver after waiting `waited`.
    fn delivered(&self, waited: Duration);
    /// An envelope was discarded by `DropOldest`.
    fn dropped(&self);
    /// A send was refused because the lane was full.
    fn rejected(&self);
    /// A producer had to wait for space.
    fn blocked(&self);
    /// The queue reached `depth`.
    fn depth(&self, depth: usize);

    /// A snapshot for logs and the admin API.
    fn snapshot(&self) -> Snapshot;
}

/// A point-in-time read of one lane's counters.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Snapshot {
    /// Envelopes accepted.
    pub offered: u64,
    /// Envelopes delivered.
    pub delivered: u64,
    /// Envelopes discarded by `DropOldest`.
    pub dropped: u64,
    /// Sends refused because the lane was full.
    pub rejected: u64,
    /// Times a producer waited for space.
    pub blocked: u64,
    /// Deepest the queue has been.
    pub high_water: u64,
    /// Mean queue wait, microseconds.
    pub mean_wait_us: f64,
    /// Worst queue wait, microseconds.
    pub max_wait_us: f64,
}

/// Atomic counters. The default.
#[derive(Debug, Default)]
pub struct AtomicMetrics {
    offered: AtomicU64,
    delivered: AtomicU64,
    dropped: AtomicU64,
    rejected: AtomicU64,
    blocked: AtomicU64,
    high_water: AtomicU64,
    wait_nanos_total: AtomicU64,
    wait_nanos_max: AtomicU64,
}

impl Metrics for AtomicMetrics {
    fn offered(&self) {
        let _ = self.offered.fetch_add(1, Ordering::Relaxed);
    }
    fn delivered(&self, waited: Duration) {
        let _ = self.delivered.fetch_add(1, Ordering::Relaxed);
        let nanos = waited.as_nanos() as u64;
        let _ = self.wait_nanos_total.fetch_add(nanos, Ordering::Relaxed);
        let _ = self.wait_nanos_max.fetch_max(nanos, Ordering::Relaxed);
    }
    fn dropped(&self) {
        let _ = self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    fn rejected(&self) {
        let _ = self.rejected.fetch_add(1, Ordering::Relaxed);
    }
    fn blocked(&self) {
        let _ = self.blocked.fetch_add(1, Ordering::Relaxed);
    }
    fn depth(&self, depth: usize) {
        let _ = self.high_water.fetch_max(depth as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Snapshot {
        let delivered = self.delivered.load(Ordering::Relaxed);
        Snapshot {
            offered: self.offered.load(Ordering::Relaxed),
            delivered,
            dropped: self.dropped.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            high_water: self.high_water.load(Ordering::Relaxed),
            mean_wait_us: if delivered == 0 {
                0.0
            } else {
                self.wait_nanos_total.load(Ordering::Relaxed) as f64 / delivered as f64 / 1000.0
            },
            max_wait_us: self.wait_nanos_max.load(Ordering::Relaxed) as f64 / 1000.0,
        }
    }
}

/// Counts nothing. For benchmarks that must not pay for observability, and for
/// deployments that do not want it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMetrics;

impl Metrics for NoMetrics {
    fn offered(&self) {}
    fn delivered(&self, _: Duration) {}
    fn dropped(&self) {}
    fn rejected(&self) {}
    fn blocked(&self) {}
    fn depth(&self, _: usize) {}
    fn snapshot(&self) -> Snapshot {
        Snapshot::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The [`Metrics`] contract, asserted against any implementation.
    fn assert_metrics_contract(m: &dyn Metrics) {
        // 1. Every method is callable and none can fail.
        m.offered();
        m.delivered(Duration::from_micros(10));
        m.dropped();
        m.rejected();
        m.blocked();
        m.depth(5);
        let _ = m.snapshot();
    }

    #[test]
    fn atomic_metrics_satisfy_the_contract() {
        assert_metrics_contract(&AtomicMetrics::default());
    }

    #[test]
    fn no_metrics_satisfies_the_contract() {
        assert_metrics_contract(&NoMetrics);
    }

    #[test]
    fn a_fresh_recorder_reports_zero_rather_than_nonsense() {
        let s = AtomicMetrics::default().snapshot();
        assert_eq!(s.offered, 0);
        assert_eq!(s.mean_wait_us, 0.0, "must not divide by zero");
    }

    #[test]
    fn mean_wait_averages_over_deliveries() {
        let m = AtomicMetrics::default();
        m.delivered(Duration::from_micros(100));
        m.delivered(Duration::from_micros(300));
        assert!((m.snapshot().mean_wait_us - 200.0).abs() < 1.0);
    }

    #[test]
    fn max_wait_keeps_the_worst_not_the_last() {
        let m = AtomicMetrics::default();
        m.delivered(Duration::from_micros(500));
        m.delivered(Duration::from_micros(10));
        assert!((m.snapshot().max_wait_us - 500.0).abs() < 1.0);
    }

    #[test]
    fn high_water_keeps_the_peak_not_the_current_depth() {
        let m = AtomicMetrics::default();
        m.depth(50);
        m.depth(3);
        assert_eq!(m.snapshot().high_water, 50);
    }

    #[test]
    fn each_failure_mode_is_counted_separately() {
        // "It dropped something" is not a diagnosis; which policy fired is.
        let m = AtomicMetrics::default();
        m.dropped();
        m.rejected();
        m.blocked();
        let s = m.snapshot();
        assert_eq!((s.dropped, s.rejected, s.blocked), (1, 1, 1));
    }

    #[test]
    fn no_metrics_stays_empty_however_much_it_is_told() {
        let m = NoMetrics;
        for _ in 0..1000 {
            m.offered();
        }
        assert_eq!(m.snapshot(), Snapshot::default());
    }
}
