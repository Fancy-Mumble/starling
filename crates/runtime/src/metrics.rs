//! Counters, and the rule that nothing lost is lost silently.
//!
//! **Everything lost is counted** (`docs/ARCHITECTURE.md` §5): audio frames
//! dropped, clients disconnected for control overflow, requests expired,
//! messages throttled. A number that only exists in a log line nobody greps is
//! not a measurement.
//!
//! One further lesson, carried over from the bus experiments: **the failure
//! mode was refusal, not latency**, 392 of 400 slow publications were refused
//! outright rather than delayed. So watch refusals, not percentiles, and make
//! refusals the easiest thing in here to find.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A named counter that can be incremented from anywhere.
#[derive(Debug, Clone)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    /// Add `n`.
    pub fn add(&self, n: u64) {
        let _ = self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Add one.
    pub fn inc(&self) {
        self.add(1);
    }

    /// The current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Every counter in one process.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    counters: Arc<Mutex<BTreeMap<String, Counter>>>,
}

impl Metrics {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The counter called `name`, creating it if this is the first mention.
    ///
    /// Counters are created on demand rather than declared up front so a metric
    /// cannot exist in the code and be missing from the registry, the failure
    /// where a drop is counted into a counter nobody exports.
    #[must_use]
    pub fn counter(&self, name: &str) -> Counter {
        let mut counters = match self.counters.lock() {
            Ok(counters) => counters,
            // A poisoned registry must not take the process down: metrics are
            // diagnostics, and losing them is not worth losing the server.
            Err(poisoned) => poisoned.into_inner(),
        };
        counters
            .entry(name.to_owned())
            .or_insert_with(|| Counter(Arc::new(AtomicU64::new(0))))
            .clone()
    }

    /// Every counter, as name and value.
    ///
    /// # Why this is safe to call from anywhere, unlike `Pressure::sample`
    ///
    /// A counter is cumulative and reading it changes nothing, so **any number
    /// of readers may take this**: a Prometheus scrape, the health collector
    /// and a test can all read the same registry and none of them takes
    /// anything from the others.
    ///
    /// [`crate::pressure::Pressure::sample`] is the opposite and the asymmetry
    /// is easy to miss: it *clears the peak*, so exactly one reader may call
    /// it, and a second one silently steals intervals from the first. When
    /// wiring a new consumer, counters can be shared and gauges cannot.
    #[must_use]
    pub fn sample(&self) -> Vec<(String, u64)> {
        let counters = match self.counters.lock() {
            Ok(counters) => counters,
            Err(poisoned) => poisoned.into_inner(),
        };
        counters
            .iter()
            .map(|(name, counter)| (name.clone(), counter.get()))
            .collect()
    }

    /// The registry in Prometheus text format.
    #[must_use]
    pub fn render(&self) -> String {
        let counters = match self.counters.lock() {
            Ok(counters) => counters,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut out = String::new();
        for (name, counter) in counters.iter() {
            out.push_str(&format!(
                "# TYPE {name} counter\n{name} {}\n",
                counter.get()
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_handles_to_one_name_count_the_same_thing() {
        // Otherwise a drop counted in one module is invisible in another's
        // export, which is the silent-loss failure this module exists to stop.
        let metrics = Metrics::new();
        metrics.counter("starling_audio_frames_dropped").inc();
        metrics.counter("starling_audio_frames_dropped").add(2);
        assert_eq!(metrics.counter("starling_audio_frames_dropped").get(), 3);
    }

    #[test]
    fn a_sample_is_repeatable_because_counters_are_cumulative() {
        // The property that lets `/metrics` and the health collector read the
        // same registry. `Pressure::sample` does not have it, which is the
        // distinction most likely to be miscopied.
        let metrics = Metrics::new();
        metrics.counter("starling_frames_routed").add(7);

        let first = metrics.sample();
        let second = metrics.sample();
        assert_eq!(first, second, "reading a counter must not consume it");
        assert_eq!(
            first,
            vec![("starling_frames_routed".to_owned(), 7)],
            "and it must report what was counted"
        );
    }

    #[test]
    fn the_export_names_every_counter_that_has_been_touched() {
        let metrics = Metrics::new();
        metrics
            .counter("starling_control_overflow_disconnects")
            .inc();
        let rendered = metrics.render();
        assert!(rendered.contains("starling_control_overflow_disconnects 1"));
        assert!(rendered.contains("# TYPE"));
    }
}
