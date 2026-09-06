//! One observation of a running deployment.
//!
//! Everything a longevity assertion needs, in one struct, taken at one instant:
//! the process's own resident memory and descriptors, the runtime's task count,
//! and every gauge and counter the collector can reach. Sampling all of it
//! together matters -- a leak diagnosed from RSS taken at 12:00 and a gauge
//! taken at 12:05 attributes growth to whatever moved in between.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use starling_runtime::process::ProcessStats;

/// One bounded thing, as the collector reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GaugeSample {
    /// In use at the instant of the read.
    pub used: u64,
    /// The high-water mark since the previous read.
    ///
    /// Read once and destroyed: [`starling_runtime::pressure::Gauge::sample`]
    /// clears the peak, so this is the only reader. A second one would see
    /// zeroes and conclude the server was idle.
    pub peak: u64,
    /// What bounds it, or zero when nothing declares a limit.
    pub capacity: u64,
    /// Cumulative refusals.
    pub rejected: u64,
}

/// A whole deployment, at one instant.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Sample {
    /// Seconds since the run began. The x-axis of every slope.
    pub elapsed_s: f64,
    /// Which phase the run was in, so the report can split warm-up from steady.
    pub phase: Phase,
    /// Which load cycle this sample belongs to; zero for the baseline.
    ///
    /// A run drives load, quiesces, and does it again. Comparing the second
    /// idle sample against the first is the one leak check with no tuned
    /// constant in it: whatever a server allocates once on first use -- a
    /// connection pool filling, a lazily started worker -- is already paid for
    /// by then, and anything that grows between two identical cycles grows
    /// every cycle.
    pub cycle: u64,
    /// How many virtual clients were connected. The denominator for the
    /// descriptor bound, and the reason a sample is not comparable to one taken
    /// at a different population.
    pub clients: u64,
    /// Resident bytes, descriptors and threads, or `None` off Linux.
    pub process: Option<Stats>,
    /// Tasks the tokio runtime has alive.
    ///
    /// Not a process property: a task is a future the runtime owns, and a
    /// server that leaks one per connection leaks nothing the kernel can see
    /// until it also leaks the socket.
    pub tasks: u64,
    /// Every gauge in the deployment, keyed `service.gauge`.
    pub gauges: BTreeMap<String, GaugeSample>,
    /// Every counter in the deployment, keyed `service.counter`.
    pub counters: BTreeMap<String, u64>,
    /// Records written so far.
    pub records: u64,
    /// Error-severity records, which a soak budgets at zero outside an
    /// allow-list.
    pub errors: u64,
}

/// `ProcessStats` in a form that serialises, so a report is diffable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Stats {
    /// Resident set size, in bytes.
    pub resident_bytes: u64,
    /// Open file descriptors.
    pub open_fds: u64,
    /// The descriptor ceiling, or zero when it could not be read.
    pub max_fds: u64,
    /// Threads in this process.
    pub threads: u64,
}

impl From<ProcessStats> for Stats {
    fn from(stats: ProcessStats) -> Self {
        Self {
            resident_bytes: stats.resident_bytes,
            open_fds: stats.open_fds,
            max_fds: stats.max_fds,
            threads: stats.threads,
        }
    }
}

/// Which part of the run a sample belongs to.
///
/// The assertions differ by phase and mixing them is the classic way to
/// conclude a server leaks: a cold process filling its caches has a steep RSS
/// slope that says nothing at all about hour six.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Started, idle, nothing connected. What everything else is measured
    /// against.
    ///
    /// Its own phase rather than "the first sample", because the first sample
    /// of a run that forgot to take one before connecting clients is a sample
    /// of a loaded server, and every level assertion below would then be
    /// comparing load against load and passing.
    #[default]
    Baseline,
    /// Caches filling, pools growing, connections arriving. Measured, never
    /// asserted on.
    Warmup,
    /// Steady load. The window every slope is fitted over.
    Steady,
    /// Every client disconnected, no traffic, settling.
    Draining,
    /// Settled and idle. One sample, and the most informative one in the run.
    Quiesced,
}

/// The name a gauge or counter is filed under, `service.thing`.
///
/// A bare gauge name is ambiguous: several services declare `inbound`, and a
/// soak that adds their occupancies together cannot say which one failed to
/// drain.
#[must_use]
pub fn key(service: &str, name: &str) -> String {
    format!("{service}.{name}")
}

/// Least-squares fit of `y` against `x`, returning `(slope, r_squared)`.
///
/// Both numbers, because either alone misleads. A slope with no correlation is
/// noise fitted to a line, and a tight correlation on a slope of zero is a flat
/// server. A leak is the conjunction: linear, and going up.
///
/// Returns `None` for fewer than three points or a degenerate x, where the
/// honest answer is that nothing was measured.
#[must_use]
pub fn fit(x: &[f64], y: &[f64]) -> Option<(f64, f64)> {
    if x.len() != y.len() || x.len() < 3 {
        return None;
    }
    let n = x.len() as f64;
    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;

    let mut sxx = 0.0;
    let mut sxy = 0.0;
    let mut syy = 0.0;
    for (xi, yi) in x.iter().zip(y) {
        let dx = xi - mean_x;
        let dy = yi - mean_y;
        sxx += dx * dx;
        sxy += dx * dy;
        syy += dy * dy;
    }
    if sxx <= f64::EPSILON {
        return None;
    }
    let slope = sxy / sxx;
    // A perfectly flat y has no variance to explain. Calling that a perfect fit
    // is the useful convention here: it is exactly the shape a passing soak has.
    let r_squared = if syy <= f64::EPSILON {
        1.0
    } else {
        (sxy * sxy) / (sxx * syy)
    };
    Some((slope, r_squared))
}

/// The median of `values`, which does not have to be sorted.
///
/// Median rather than mean throughout, because one sample taken during a flood
/// test moves a mean and does not move this.
#[must_use]
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

/// Seconds, as a sample records them.
#[must_use]
pub fn seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_straight_line_fits_exactly() {
        let x = [0.0, 1.0, 2.0, 3.0];
        let y = [10.0, 12.0, 14.0, 16.0];
        let (slope, r2) = fit(&x, &y).expect("four points fit");
        assert!((slope - 2.0).abs() < 1e-9, "slope {slope}");
        assert!((r2 - 1.0).abs() < 1e-9, "r2 {r2}");
    }

    #[test]
    fn noise_around_a_flat_line_has_a_small_slope_and_no_correlation() {
        // The shape a healthy server has: RSS wobbling by a megabyte either
        // way. A leak check that fires on this is a leak check nobody trusts.
        let x = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0];
        let y = [100.0, 101.0, 99.0, 101.0, 99.0, 100.0];
        let (slope, r2) = fit(&x, &y).expect("six points fit");
        assert!(slope.abs() < 0.2, "slope {slope}");
        assert!(r2 < 0.2, "r2 {r2}");
    }

    #[test]
    fn a_flat_line_is_a_perfect_fit_rather_than_a_division_by_zero() {
        let x = [0.0, 1.0, 2.0];
        let y = [7.0, 7.0, 7.0];
        let (slope, r2) = fit(&x, &y).expect("three points fit");
        assert!(slope.abs() < 1e-9);
        assert!((r2 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn two_points_are_not_a_trend() {
        assert!(fit(&[0.0, 1.0], &[0.0, 1.0]).is_none());
    }

    #[test]
    fn a_single_spike_moves_the_mean_and_not_the_median() {
        let steady = [100.0, 101.0, 99.0, 100.0, 900.0];
        assert!((median(&steady) - 100.0).abs() < 1e-9);
    }
}
