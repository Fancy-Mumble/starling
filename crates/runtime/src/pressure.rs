//! How full a service's queues are, which is the question counters cannot
//! answer.
//!
//! [`Metrics`](crate::metrics::Metrics) counts what already happened: frames
//! dropped, clients disconnected, requests refused. That is the right shape for
//! a refusal and the wrong shape for a queue, because by the time a refusal is
//! counted the decision has been made. An operator watching a server fill up
//! wants the interval *before* that, the queue at 80% of its budget, climbing.
//!
//! So this holds **occupancy**: how much of a bounded thing is in use right
//! now, against what it is bounded by.
//!
//! # Why a peak, and why reading it resets it
//!
//! Instantaneous occupancy read every few seconds misses everything. A service
//! that hits its budget for 200 ms between two five-second polls is a service
//! that refused requests and looks idle in both samples, and that is precisely
//! the event worth seeing.
//!
//! So each gauge also keeps the high-water mark since it was last read, and
//! reading it clears it. That makes a sample mean "the worst this got during
//! the interval you are drawing", which is what a dashboard's bar should be,
//! and it is why exactly one reader may exist. The collector is that reader.
//!
//! # Why capacity is optional
//!
//! Some bounded things have a number (the gateway's control lane is 4 MiB) and
//! some are bounded only by the machine (a service's in-flight RPCs). A
//! capacity of zero means "no declared limit", and a dashboard must show those
//! as a count rather than a percentage, inventing a denominator would turn an
//! unknown into a reassuring number.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// One bounded thing's occupancy, sampled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Load {
    /// What the gauge is called, in an operator's words.
    pub name: String,
    /// In use at the moment of reading.
    pub used: u64,
    /// The high-water mark since the previous read.
    pub peak: u64,
    /// What it is bounded by; zero when nothing declares a limit.
    pub capacity: u64,
    /// How many times this queue has refused something, cumulatively.
    ///
    /// Cumulative rather than per-interval because it is the one number that
    /// must never be lost by a reader that missed a poll: a refusal is a
    /// request somebody made that the server did not serve.
    pub rejected: u64,
}

impl Load {
    /// How full it is, 0-100, or `None` when nothing declares a limit.
    ///
    /// Uses [`Self::peak`], not [`Self::used`]: the question a dashboard asks
    /// is "did this run out", and the instant of the poll is the least likely
    /// moment for it to have done so.
    #[must_use]
    pub fn utilisation(&self) -> Option<u8> {
        if self.capacity == 0 {
            return None;
        }
        let percent = self.peak.saturating_mul(100) / self.capacity;
        Some(u8::try_from(percent.min(100)).unwrap_or(100))
    }
}

/// A named occupancy gauge, cheap enough for a hot path.
///
/// Cloning shares the counters, so a service hands one to whatever fills the
/// queue and keeps nothing.
#[derive(Debug, Clone)]
pub struct Gauge(Arc<Counters>);

#[derive(Debug)]
struct Counters {
    used: AtomicU64,
    peak: AtomicU64,
    capacity: AtomicU64,
    rejected: AtomicU64,
}

impl Gauge {
    fn new(capacity: u64) -> Self {
        Self(Arc::new(Counters {
            used: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            capacity: AtomicU64::new(capacity),
            rejected: AtomicU64::new(0),
        }))
    }

    /// Set the current occupancy, raising the peak if this is a new high.
    pub fn set(&self, used: u64) {
        self.0.used.store(used, Ordering::Relaxed);
        let _ = self.0.peak.fetch_max(used, Ordering::Relaxed);
    }

    /// Add to the current occupancy.
    pub fn add(&self, n: u64) {
        let used = self.0.used.fetch_add(n, Ordering::Relaxed) + n;
        let _ = self.0.peak.fetch_max(used, Ordering::Relaxed);
    }

    /// Remove from the current occupancy, saturating at zero.
    ///
    /// Saturating rather than wrapping because an unbalanced release is a bug
    /// that should read as an empty queue, not as one holding 18 quintillion
    /// items, a wrapped gauge discredits every other number beside it.
    pub fn release(&self, n: u64) {
        let _ = self
            .0
            .used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(n))
            });
    }

    /// Record a reading of something whose current value lives elsewhere.
    ///
    /// [`Self::add`] and [`Self::release`] own the number; this only watches
    /// one. That is the right shape when many things share one bound and the
    /// interesting figure is the worst of them, the gateway's control lane is
    /// budgeted **per client**, so "the aggregate across clients" has no
    /// meaningful percentage while "the client closest to its budget" is
    /// exactly the number that predicts the next disconnect.
    ///
    /// [`Load::peak`] is then the worst reading in the interval, which is what
    /// a dashboard should draw. [`Load::used`] is merely the most recent
    /// reading, and with several reporters that is whichever spoke last, true,
    /// but not a total, and not to be presented as one.
    pub fn observe(&self, value: u64) {
        self.0.used.store(value, Ordering::Relaxed);
        let _ = self.0.peak.fetch_max(value, Ordering::Relaxed);
    }

    /// Record that this queue refused something.
    pub fn reject(&self) {
        let _ = self.0.rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Change the declared limit, for a bound that is configured rather than
    /// constant.
    pub fn set_capacity(&self, capacity: u64) {
        self.0.capacity.store(capacity, Ordering::Relaxed);
    }

    /// Occupancy in use right now, without disturbing the peak.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.0.used.load(Ordering::Relaxed)
    }

    /// Read the gauge and clear its peak.
    ///
    /// The peak resets so the next sample describes the next interval; see the
    /// module docs for why exactly one reader may call this.
    fn sample(&self, name: &str) -> Load {
        Load {
            name: name.to_owned(),
            used: self.0.used.load(Ordering::Relaxed),
            peak: self.0.peak.swap(0, Ordering::Relaxed),
            capacity: self.0.capacity.load(Ordering::Relaxed),
            rejected: self.0.rejected.load(Ordering::Relaxed),
        }
    }
}

/// Every occupancy gauge in one service.
///
/// Shaped like [`Metrics`](crate::metrics::Metrics) deliberately: same
/// create-on-first-mention rule, for the same reason, a gauge that has to be
/// declared up front is a gauge that exists in the code and is missing from the
/// registry, and nobody notices until the queue it describes overflows.
#[derive(Debug, Clone, Default)]
pub struct Pressure {
    gauges: Arc<Mutex<BTreeMap<String, Gauge>>>,
}

impl Pressure {
    /// A service with nothing bounded yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The gauge called `name`, bounded by `capacity`, creating it on first
    /// mention.
    ///
    /// Pass `0` for something bounded only by the machine.
    #[must_use]
    pub fn gauge(&self, name: &str, capacity: u64) -> Gauge {
        let mut gauges = match self.gauges.lock() {
            Ok(gauges) => gauges,
            // A poisoned registry must not take the process down: this is
            // diagnostics, and losing it is not worth losing the server.
            Err(poisoned) => poisoned.into_inner(),
        };
        gauges
            .entry(name.to_owned())
            .or_insert_with(|| Gauge::new(capacity))
            .clone()
    }

    /// Every gauge, sampled, clearing each peak.
    ///
    /// Sorted, because it is a `BTreeMap`: a dashboard whose rows reorder on
    /// every poll is a dashboard nobody can read.
    #[must_use]
    pub fn sample(&self) -> Vec<Load> {
        let gauges = match self.gauges.lock() {
            Ok(gauges) => gauges,
            Err(poisoned) => poisoned.into_inner(),
        };
        gauges
            .iter()
            .map(|(name, gauge)| gauge.sample(name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gauge_remembers_the_peak_not_the_moment_it_was_read() {
        // The whole reason this type exists. A queue that filled and drained
        // between two polls is invisible to instantaneous occupancy, and it is
        // the only interval anybody wants to know about.
        let pressure = Pressure::new();
        let queue = pressure.gauge("control queue", 100);

        queue.add(90);
        queue.release(90);
        assert_eq!(queue.used(), 0, "the queue really did drain");

        let sample = &pressure.sample()[0];
        assert_eq!(sample.used, 0);
        assert_eq!(sample.peak, 90, "the spike was lost");
        assert_eq!(sample.utilisation(), Some(90));
    }

    #[test]
    fn reading_clears_the_peak_so_a_sample_describes_its_own_interval() {
        // Without the reset, one spike would sit at the top of every future
        // sample and the plot would read as a server that never recovered.
        let pressure = Pressure::new();
        let queue = pressure.gauge("q", 10);

        queue.add(8);
        queue.release(8);
        assert_eq!(pressure.sample()[0].peak, 8);
        assert_eq!(
            pressure.sample()[0].peak,
            0,
            "the peak outlived its interval"
        );
    }

    #[test]
    fn an_unbalanced_release_reads_as_empty_rather_than_enormous() {
        // Releasing more than was taken is a bug in the caller. It must not
        // wrap: a gauge reading 18446744073709551615 discredits every honest
        // number printed beside it.
        let pressure = Pressure::new();
        let queue = pressure.gauge("q", 10);

        queue.add(1);
        queue.release(5);
        assert_eq!(queue.used(), 0);
    }

    #[test]
    fn no_declared_capacity_means_no_percentage() {
        // In-flight RPCs are bounded by the machine, not by a number. Showing
        // "62% full" against a denominator nobody chose would be inventing
        // reassurance.
        let pressure = Pressure::new();
        let inflight = pressure.gauge("in flight", 0);
        inflight.add(37);

        let sample = &pressure.sample()[0];
        assert_eq!(sample.peak, 37);
        assert_eq!(sample.utilisation(), None);
    }

    #[test]
    fn utilisation_is_capped_rather_than_reported_above_full() {
        // A gauge whose capacity was lowered after the fact can read over its
        // bound. 140% is a number no bar chart can draw.
        let pressure = Pressure::new();
        let queue = pressure.gauge("q", 10);
        queue.add(14);

        assert_eq!(pressure.sample()[0].utilisation(), Some(100));
    }

    #[test]
    fn refusals_accumulate_across_reads() {
        // Unlike the peak: a refusal is a request the server did not serve, and
        // a reader that missed a poll must not lose it.
        let pressure = Pressure::new();
        let queue = pressure.gauge("q", 1);

        queue.reject();
        assert_eq!(pressure.sample()[0].rejected, 1);
        queue.reject();
        assert_eq!(pressure.sample()[0].rejected, 2);
    }

    #[test]
    fn observing_keeps_the_worst_reading_not_the_last() {
        // Several clients share one per-client budget, so the gauge watches
        // rather than owns. The number that predicts the next disconnect is
        // the client closest to its bound, not whichever reported last.
        let pressure = Pressure::new();
        let worst = pressure.gauge("control queue (worst client)", 1000);

        worst.observe(900);
        worst.observe(20);

        let sample = &pressure.sample()[0];
        assert_eq!(sample.peak, 900, "the client that was nearly full was lost");
        assert_eq!(
            sample.used, 20,
            "`used` is the latest reading, as documented"
        );
        assert_eq!(sample.utilisation(), Some(90));
    }

    #[test]
    fn the_same_name_is_the_same_gauge() {
        // Two call sites filling one queue must not produce two half-pictures.
        let pressure = Pressure::new();
        pressure.gauge("q", 10).add(3);
        pressure.gauge("q", 10).add(4);

        let sampled = pressure.sample();
        assert_eq!(sampled.len(), 1);
        assert_eq!(sampled[0].used, 7);
    }
}
