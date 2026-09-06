//! The soak harness: sample a running deployment, then say what it means.
//!
//! Two halves, deliberately separate. [`sample`] and [`Sampler`] observe;
//! [`assess`] judges. Splitting them is what lets the judgement be unit-tested
//! against hand-built runs -- every threshold in [`assess::Budget`] has a test
//! that constructs the defect it exists to catch, which is the only way to know
//! a check works before waiting six hours for one that does not.
//!
//! The out-of-process driver (`scripts/soak.sh`) reads the same JSONL through
//! `/metrics` and `/proc/<pid>`, and shares this assessment module, so a
//! nightly and a per-PR smoke test disagree about scale and about nothing else.

pub mod assess;
pub mod drive;
pub mod sample;
pub mod scenario;

use std::time::Instant;

pub use assess::{Budget, Failure, Report, assess, render, to_jsonl};
pub use drive::{Live, run};
pub use sample::{GaugeSample, Phase, Sample, Stats};
pub use scenario::{Rng, Scenario};

use crate::Deployment;

/// Takes samples of a deployment, from inside its own process.
///
/// In-process rather than through `/metrics`, because this is where the *state*
/// assertions live: the task count and the per-gauge occupancy are readable
/// here with no scrape latency and no HTTP server in the path. The resource
/// assertions belong to the out-of-process driver, since resident memory
/// measured inside a test binary that also holds every client is not the
/// server's resident memory.
#[derive(Debug)]
pub struct Sampler {
    started: Instant,
    /// Errors already seen and forgiven, so a budget is not spent twice on the
    /// same record as the ring is re-read each sample.
    allowed: Vec<String>,
}

impl Sampler {
    /// Start the clock. Every sample's `elapsed_s` is measured from here.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            allowed: Vec::new(),
        }
    }

    /// Forgive error records whose message contains any of `messages`.
    ///
    /// Matched against the message rather than the service, so an entry names
    /// one call site rather than waving through a whole service, which is the
    /// convention `Deployment::stop_allowing` already uses.
    #[must_use]
    pub fn allowing(mut self, messages: &[&str]) -> Self {
        self.allowed
            .extend(messages.iter().map(|m| (*m).to_owned()));
        self
    }

    /// Observe the whole deployment, once.
    pub async fn sample(
        &self,
        deployment: &Deployment,
        phase: Phase,
        cycle: u64,
        clients: u64,
    ) -> Sample {
        let overview = deployment.overview().await;

        let mut gauges = std::collections::BTreeMap::new();
        let mut counters = std::collections::BTreeMap::new();
        for service in &overview.services {
            for load in &service.load {
                let _previous = gauges.insert(
                    sample::key(&service.service, &load.name),
                    GaugeSample {
                        used: load.used,
                        peak: load.peak,
                        capacity: load.capacity,
                        rejected: load.rejected,
                    },
                );
            }
            for counter in &service.counters {
                let _previous =
                    counters.insert(sample::key(&service.service, &counter.name), counter.value);
            }
        }

        let records = deployment.records();
        let errors = records
            .iter()
            .filter(|record| record.severity >= starling_runtime::log::Severity::Error)
            .filter(|record| {
                !self
                    .allowed
                    .iter()
                    .any(|allowed| record.message.contains(allowed.as_str()))
            })
            .count() as u64;

        Sample {
            elapsed_s: sample::seconds(self.started.elapsed()),
            phase,
            cycle,
            clients,
            process: starling_runtime::process::stats().map(Stats::from),
            // `num_alive_tasks` counts every task the runtime owns, the client
            // side of this test included. That is fine for a *difference*
            // against a baseline taken the same way, which is all the budget
            // asserts, and it is the only figure available from inside.
            tasks: tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks() as u64,
            gauges,
            counters,
            records: records.len() as u64,
            errors,
        }
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}
