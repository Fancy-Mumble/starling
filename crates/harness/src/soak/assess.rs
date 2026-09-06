//! Turning a run's samples into a verdict.
//!
//! Every check here answers a question about *longevity* rather than about
//! correctness, and each one is written so that a healthy server passes it
//! without a tuned constant. Where a threshold is unavoidable it is stated as a
//! field on [`Budget`] with the reasoning beside it, so a failing soak can be
//! argued with rather than silenced by editing a literal in the middle of a
//! function.
//!
//! The ordering is deliberate: `quiesce` first, because a level assertion on
//! an idle server is the one result that is never ambiguous.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::sample::{Phase, Sample, fit, median};

/// A check that did not pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// Which check, in a name a CI log can be grepped for.
    pub check: String,
    /// What was measured against what was allowed, in one line.
    pub detail: String,
}

impl Failure {
    fn new(check: &str, detail: String) -> Self {
        Self {
            check: check.to_owned(),
            detail,
        }
    }
}

/// What a run is allowed to do.
///
/// Every field is a bound on *growth*, not on absolute size. A server that uses
/// 800 MB steadily is fine; one that uses 200 MB and climbs is not.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    /// Bytes per hour of resident growth, fitted over the steady window.
    ///
    /// About two megabytes. Below that a six-hour run cannot distinguish a leak
    /// from an allocator holding freed pages, so a tighter bound would only
    /// produce flakes.
    pub rss_slope_bytes_per_hour: f64,
    /// How long the steady window must be before a slope is fitted at all.
    ///
    /// Twenty minutes. A megabyte of warm-up bleed over fifty seconds
    /// extrapolates to seventy megabytes an hour with an excellent correlation,
    /// and it is not a leak -- it is a process that has not finished starting.
    /// Reporting "not measured" for a short run is honest; reporting a slope
    /// from it is not, and a check that fails on every smoke test is a check
    /// somebody deletes.
    pub rss_slope_min_window_s: f64,
    /// How well the growth must fit a line before it counts.
    ///
    /// A leak is linear; load noise is not. Without this a run that happened to
    /// end during a flood test reads as a leak.
    pub rss_slope_r_squared: f64,
    /// Peak resident, as a multiple of the steady median.
    pub rss_peak_multiple: f64,
    /// What an idle server may still hold, as a multiple of its own baseline.
    ///
    /// The single most informative number in the file. "Grew under load" is
    /// ambiguous; "did not come back down when idle" is not.
    pub quiesced_rss_multiple: f64,
    /// Descriptors an idle server may still hold above a **cold** baseline.
    ///
    /// Generous, and deliberately so. An all-in-one deployment is twenty-three
    /// services, and the first client through the door makes every one of them
    /// open the handles it had deferred: measured here, eighteen descriptors and
    /// thirty-six tasks, identically at six, twelve and twenty-four clients. A
    /// flat cost, not a per-client one, and no bound against a cold baseline can
    /// tell the two apart.
    ///
    /// So this catches only a gross regression -- a leak large enough to clear
    /// the startup cost outright. `cycles` is what catches a leak, and it
    /// needs no constant at all.
    pub quiesced_fd_slack: u64,
    /// Descriptors allowed per live connection during the run.
    pub fds_per_connection: u64,
    /// A flat allowance on top of that, for listeners, databases and logs.
    pub fd_overhead: u64,
    /// Tasks an idle server may still have alive above a cold baseline.
    ///
    /// See [`Budget::quiesced_fd_slack`] for why this is not tight.
    pub quiesced_task_slack: u64,
    /// Threads the process may gain after start-up.
    ///
    /// Zero. A thread started per unit of work and never joined is the shape of
    /// the SFU's `std::thread`, and it is invisible in every other number here.
    pub thread_growth: u64,
    /// What any gauge may still hold when idle.
    ///
    /// Also zero, and the reason this harness exists: a per-connection map that
    /// never has its entry removed is a leak that RSS will not show for weeks.
    pub quiesced_gauge_slack: u64,
    /// How full anything may get, 0-100.
    ///
    /// A soak that passes at 99% occupancy fails at 1.01x the load, so this is
    /// a capacity assertion rather than a correctness one.
    pub peak_percent: u8,
    /// Error-severity records allowed outside the allow-list.
    pub errors: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            rss_slope_bytes_per_hour: 2.0 * 1024.0 * 1024.0,
            rss_slope_min_window_s: 20.0 * 60.0,
            rss_slope_r_squared: 0.7,
            rss_peak_multiple: 3.0,
            quiesced_rss_multiple: 1.15,
            quiesced_fd_slack: 32,
            fds_per_connection: 4,
            fd_overhead: 64,
            quiesced_task_slack: 64,
            thread_growth: 0,
            quiesced_gauge_slack: 0,
            peak_percent: 90,
            errors: 0,
        }
    }
}

/// A gauge that legitimately holds state after the last client leaves.
///
/// Retention is not the same as leaking, and a check that cannot tell them
/// apart is a check somebody turns off. What separates them is a *mechanism*
/// that eventually clears the entry and a bound on how long it takes, so each
/// entry here names both.
///
/// Deliberately a short, argued list. "The soak is noisy so we ignore some
/// gauges" is how a leak check stops working; every line below is a claim a
/// reviewer can check against the code it cites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retained {
    /// The gauge's full `service.name` key.
    pub gauge: &'static str,
    /// What clears it, and how long that takes.
    pub why: &'static str,
}

/// The gauges a quiesced deployment is allowed to still hold.
pub const RETAINED: &[Retained] = &[
    Retained {
        gauge: "gateway.resume.sessions",
        why: "resume exists precisely to outlive a disconnect;               `ResumeStore::evict_expired` drops a ring after `gateway.resume.ttl`,               two minutes by default, which is longer than any quiesce window               worth waiting through",
    },
    Retained {
        gauge: "gateway.resume.bytes",
        why: "the byte total of the same rings, cleared by the same sweep",
    },
];

/// Counters that must not move at all, by suffix.
///
/// A restart or a panic during a soak is not a budget to be spent; it is the
/// event the run exists to catch.
const HARD_ZERO: &[&str] = &["service_restarts", "panics"];

/// Counters whose *rate* is asserted rather than whose count is.
///
/// A drop is not automatically a fault -- a rate limiter dropping a flood is
/// working. A drop rate that climbs over six hours is a degradation, and the
/// absolute count hides it because it only ever goes up.
const RATE_WATCHED: &[&str] = &["dropped", "refused", "throttled", "rejected"];

/// Everything a run produced, and what it means.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Report {
    /// The seed the run was driven with, printed at start-up so a failure
    /// reproduces.
    pub seed: u64,
    /// Every sample, in order.
    pub samples: Vec<Sample>,
    /// What was asserted.
    pub budget: Budget,
    /// Checks that did not pass. Empty is a green run.
    pub failures: Vec<Failure>,
    /// The five gauges furthest from their baseline when idle, worst first.
    ///
    /// Reported whether or not the run failed: a gauge creeping by two entries
    /// is not a failure yet and is exactly what a reviewer wants to see before
    /// it is.
    pub worst_gauges: Vec<(String, i64)>,
}

/// The cold idle server, before any client connected.
///
/// Every level assertion in this file is against this sample, and it is the
/// reason [`Phase::Baseline`] exists rather than "sample zero": comparing an
/// idle server against the *first loaded* sample passes on any leak large
/// enough to have already happened by then.
fn baseline(samples: &[Sample]) -> Option<&Sample> {
    samples.iter().find(|s| s.phase == Phase::Baseline)
}

/// The settled sample at the end, if the run got that far.
fn quiesced(samples: &[Sample]) -> Option<&Sample> {
    samples.iter().rev().find(|s| s.phase == Phase::Quiesced)
}

fn steady(samples: &[Sample]) -> Vec<&Sample> {
    samples
        .iter()
        .filter(|s| s.phase == Phase::Steady)
        .collect()
}

/// Assert everything, and say what failed.
///
/// Returns every failure rather than the first, because a run takes six hours
/// and a report naming one of four problems costs a day per problem.
#[must_use]
pub fn assess(samples: &[Sample], budget: Budget, allowed_errors: u64) -> Report {
    let mut failures = Vec::new();

    failures.extend(quiesce(samples, budget));
    failures.extend(cycles(samples));
    failures.extend(memory_slope(samples, budget));
    failures.extend(descriptors(samples, budget));
    failures.extend(tasks_and_threads(samples, budget));
    failures.extend(gauges(samples, budget));
    failures.extend(counters(samples));
    failures.extend(logs(samples, budget, allowed_errors));

    Report {
        seed: 0,
        samples: samples.to_vec(),
        budget,
        failures,
        worst_gauges: worst_gauges(samples),
    }
}

/// The level assertion: did an idle server come back to where it started.
///
/// Unambiguous in a way no assertion under load is, which is also what makes a
/// ninety-second per-PR smoke test viable -- a level needs two samples, and a
/// slope needs an hour of them.
fn quiesce(samples: &[Sample], budget: Budget) -> Vec<Failure> {
    let (Some(base), Some(idle)) = (baseline(samples), quiesced(samples)) else {
        return vec![Failure::new(
            "quiesce",
            "the run never reached a quiesced sample; nothing was asserted".to_owned(),
        )];
    };

    let (Some(base_stats), Some(idle_stats)) = (base.process, idle.process) else {
        // Off Linux there is no `/proc`, and inventing a figure would be worse
        // than reporting none: the gauge and task checks below still run.
        return Vec::new();
    };

    let allowed = base_stats.resident_bytes as f64 * budget.quiesced_rss_multiple;
    if (idle_stats.resident_bytes as f64) > allowed {
        return vec![Failure::new(
            "quiesce.rss",
            format!(
                "idle again at {} MiB, having started at {} MiB; \
                 the allowance is {:.0} MiB ({}x baseline)",
                idle_stats.resident_bytes / (1024 * 1024),
                base_stats.resident_bytes / (1024 * 1024),
                allowed / (1024.0 * 1024.0),
                budget.quiesced_rss_multiple,
            ),
        )];
    }
    Vec::new()
}

/// The assertion with no tuned constant in it: does an idle server hold more
/// after the second load cycle than after the first.
///
/// Every other level check compares an idle server against a *cold* one, and
/// has to allow for whatever a server pays once on first use: a connection pool
/// filling, a lazily started worker, an arena that never shrinks. Measured
/// here, that flat cost was the same eighteen descriptors and thirty-six tasks
/// at six, twelve and twenty-four clients -- fixed, not per-client, and so not
/// a leak. Allowing for it means a constant, and a constant tuned until the
/// suite passes is a constant that will be tuned again.
///
/// Two cycles removes the need for one. The first pays the startup cost; the
/// second pays nothing new unless something is genuinely accumulating, so the
/// allowance between them is **zero** for descriptors, tasks and gauges. A leak
/// of one entry per connection fails this at any population; a pool that warmed
/// once passes it at every population.
///
/// Compared between *consecutive* cycles rather than first against last, which
/// costs nothing in strength -- any growth anywhere still fails -- and names the
/// cycle it appeared at. That mattered: the first version of this check reported
/// "227 descriptors after cycle 6 against 225 after cycle 1", which is true of a
/// leak and equally true of one connection opened once, and telling those apart
/// took two runs and a photograph of `/proc/<pid>/fd`. "Between cycles 2 and 3"
/// would have said which it was on the first run.
///
/// A one-time cost inside the run is the one thing this cannot judge, so the
/// answer is to keep them out of the run: see the service
/// `crates/starling/tests/soak.rs` excludes, and why.
fn cycles(samples: &[Sample]) -> Vec<Failure> {
    let idle: Vec<&Sample> = samples
        .iter()
        .filter(|sample| sample.phase == Phase::Quiesced)
        .collect();
    // One cycle. Not a failure -- a smoke run may deliberately be one -- but
    // nothing here was measured, and the checks against the baseline are what
    // stand in for it.
    let mut failures = Vec::new();
    for (a, b) in idle.iter().zip(idle.iter().skip(1)) {
        failures.extend(between(a, b));
    }
    failures
}

/// What grew between two settled samples one cycle apart.
fn between(a: &Sample, b: &Sample) -> Vec<Failure> {
    let mut failures = Vec::new();
    let (cycle, was) = (b.cycle, a.cycle);

    if let (Some(before), Some(after)) = (a.process, b.process) {
        if after.open_fds > before.open_fds {
            failures.push(Failure::new(
                "cycle.descriptors",
                format!(
                    "{} descriptors idle after cycle {cycle}, against {} after cycle {was}; \
                     a cost paid once does not grow between two cycles",
                    after.open_fds, before.open_fds,
                ),
            ));
        }
        if after.threads > before.threads {
            failures.push(Failure::new(
                "cycle.threads",
                format!(
                    "{} threads idle after cycle {cycle}, against {} after cycle {was}",
                    after.threads, before.threads,
                ),
            ));
        }
    }
    if b.tasks > a.tasks {
        failures.push(Failure::new(
            "cycle.tasks",
            format!(
                "{} tasks alive after cycle {cycle}, against {} after cycle {was}",
                b.tasks, a.tasks,
            ),
        ));
    }
    for (name, gauge) in &b.gauges {
        if RETAINED.iter().any(|retained| retained.gauge == name) {
            continue;
        }
        let held = a.gauges.get(name).map_or(0, |g| g.used);
        if gauge.used > held {
            failures.push(Failure::new(
                "cycle.gauges",
                format!(
                    "{name} holds {} idle after cycle {cycle}, against {held} after cycle {was}",
                    gauge.used,
                ),
            ));
        }
    }
    failures
}

/// The trend assertion: is resident memory climbing, linearly, under load.
fn memory_slope(samples: &[Sample], budget: Budget) -> Vec<Failure> {
    let window = steady(samples);
    let points: Vec<(f64, f64)> = window
        .iter()
        .filter_map(|s| s.process.map(|p| (s.elapsed_s, p.resident_bytes as f64)))
        .collect();
    if points.len() < 3 {
        // Not a failure. A short run has no trend to fit, and saying so is
        // better than fitting two points and calling it one.
        return Vec::new();
    }
    let x: Vec<f64> = points.iter().map(|p| p.0).collect();
    let y: Vec<f64> = points.iter().map(|p| p.1).collect();
    let span = x.last().copied().unwrap_or(0.0) - x.first().copied().unwrap_or(0.0);

    let mut failures = Vec::new();
    if span >= budget.rss_slope_min_window_s
        && let Some((slope, r_squared)) = fit(&x, &y)
    {
        let per_hour = slope * 3600.0;
        if per_hour > budget.rss_slope_bytes_per_hour && r_squared > budget.rss_slope_r_squared {
            failures.push(Failure::new(
                "memory.slope",
                format!(
                    "resident memory is growing {:.2} MiB/h with r^2 {r_squared:.2}; \
                     the allowance is {:.2} MiB/h",
                    per_hour / (1024.0 * 1024.0),
                    budget.rss_slope_bytes_per_hour / (1024.0 * 1024.0),
                ),
            ));
        }
    }

    let peak = y.iter().copied().fold(f64::MIN, f64::max);
    let mid = median(&y);
    if mid > 0.0 && peak > mid * budget.rss_peak_multiple {
        failures.push(Failure::new(
            "memory.peak",
            format!(
                "peaked at {:.0} MiB against a steady median of {:.0} MiB, \
                 which is more than {}x",
                peak / (1024.0 * 1024.0),
                mid / (1024.0 * 1024.0),
                budget.rss_peak_multiple,
            ),
        ));
    }
    failures
}

/// Descriptors, both while running and once idle.
fn descriptors(samples: &[Sample], budget: Budget) -> Vec<Failure> {
    let Some(base) = baseline(samples).and_then(|s| s.process) else {
        return Vec::new();
    };
    let mut failures = Vec::new();

    for sample in samples {
        let Some(stats) = sample.process else {
            continue;
        };
        let allowed = base
            .open_fds
            .saturating_add(budget.fds_per_connection.saturating_mul(sample.clients))
            .saturating_add(budget.fd_overhead);
        if stats.open_fds > allowed {
            failures.push(Failure::new(
                "descriptors.live",
                format!(
                    "{} descriptors at t+{:.0}s with {} clients; \
                     the allowance is {allowed}",
                    stats.open_fds, sample.elapsed_s, sample.clients,
                ),
            ));
            // One report, not one per sample: a descriptor leak trips every
            // sample after the first and a hundred identical lines bury the
            // rest of the report.
            break;
        }
    }

    if let Some(idle) = quiesced(samples).and_then(|s| s.process) {
        let allowed = base.open_fds.saturating_add(budget.quiesced_fd_slack);
        if idle.open_fds > allowed {
            failures.push(Failure::new(
                "descriptors.quiesced",
                format!(
                    "{} descriptors still open with nothing connected, \
                     having started at {}; the allowance is {allowed}",
                    idle.open_fds, base.open_fds,
                ),
            ));
        }
    }
    failures
}

/// Tasks that outlive their connection, and threads that are never joined.
fn tasks_and_threads(samples: &[Sample], budget: Budget) -> Vec<Failure> {
    let Some(base) = baseline(samples) else {
        return Vec::new();
    };
    let mut failures = Vec::new();

    if let Some(idle) = quiesced(samples) {
        let allowed = base.tasks.saturating_add(budget.quiesced_task_slack);
        if idle.tasks > allowed {
            failures.push(Failure::new(
                "tasks.quiesced",
                format!(
                    "{} tasks still alive with nothing connected, having started \
                     at {}; the allowance is {allowed}",
                    idle.tasks, base.tasks,
                ),
            ));
        }
    }

    // Threads are asserted against every sample, not just the idle one. A pool
    // that spawns a thread per stream and never joins it is at its worst under
    // load, and by the time the run quiesces the count may have come back down
    // while the threads themselves are still parked.
    if let Some(base_stats) = base.process {
        let allowed = base_stats.threads.saturating_add(budget.thread_growth);
        let worst = samples
            .iter()
            .filter_map(|s| s.process.map(|p| (s.elapsed_s, p.threads)))
            .max_by_key(|&(_, threads)| threads);
        if let Some((at, threads)) = worst
            && threads > allowed
        {
            failures.push(Failure::new(
                "threads.growth",
                format!(
                    "{threads} threads at t+{at:.0}s, having started at {}; \
                     the allowance is {allowed}",
                    base_stats.threads,
                ),
            ));
        }
    }
    failures
}

/// Every bounded thing: did it drain, and did it come close to full.
///
/// This is where defects 3, 4, 8, 9 and 18 stop being opinions. A per-viewer
/// map that never has its entry removed shows here as a gauge that is not zero
/// when nothing is connected, named, long before RSS notices.
fn gauges(samples: &[Sample], budget: Budget) -> Vec<Failure> {
    let mut failures = Vec::new();

    for sample in samples {
        for (name, gauge) in &sample.gauges {
            if gauge.capacity == 0 {
                continue;
            }
            let percent = gauge.peak.saturating_mul(100) / gauge.capacity;
            if percent > u64::from(budget.peak_percent) {
                failures.push(Failure::new(
                    "gauges.headroom",
                    format!(
                        "{name} peaked at {percent}% of {} at t+{:.0}s; \
                         a soak that passes this full fails at 1.01x the load",
                        gauge.capacity, sample.elapsed_s,
                    ),
                ));
            }
        }
    }
    failures.dedup_by(|a, b| a.check == b.check && a.detail == b.detail);

    let (Some(base), Some(idle)) = (baseline(samples), quiesced(samples)) else {
        return failures;
    };
    for (name, gauge) in &idle.gauges {
        if RETAINED.iter().any(|retained| retained.gauge == name) {
            continue;
        }
        let was = base.gauges.get(name).map_or(0, |g| g.used);
        let allowed = was.saturating_add(budget.quiesced_gauge_slack);
        if gauge.used > allowed {
            failures.push(Failure::new(
                "gauges.quiesced",
                format!(
                    "{name} still holds {} with nothing connected, \
                     having started at {was}",
                    gauge.used,
                ),
            ));
        }
    }
    failures
}

/// The five gauges furthest from where they started, worst first.
fn worst_gauges(samples: &[Sample]) -> Vec<(String, i64)> {
    let (Some(base), Some(idle)) = (baseline(samples), quiesced(samples)) else {
        return Vec::new();
    };
    let mut drift: Vec<(String, i64)> = idle
        .gauges
        .iter()
        .map(|(name, gauge)| {
            let was = base.gauges.get(name).map_or(0, |g| g.used);
            let delta = i64::try_from(gauge.used).unwrap_or(i64::MAX)
                - i64::try_from(was).unwrap_or(i64::MAX);
            (name.clone(), delta)
        })
        .collect();
    drift.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    drift.truncate(5);
    drift
}

/// The highest value each counter reached, over every sample.
///
/// Not `samples.last().counters`. Counters are cumulative so the last value is
/// the largest, but the last *sample* need not carry every key: a service that
/// was restarted, or a phase whose sweep raced a shutdown, leaves a hole, and
/// reading the final sample alone silently skips whatever is missing from it.
/// A check that quietly examines nothing is worse than no check.
fn highest(samples: &[Sample]) -> BTreeMap<&str, u64> {
    let mut highest: BTreeMap<&str, u64> = BTreeMap::new();
    for sample in samples {
        for (name, value) in &sample.counters {
            let slot = highest.entry(name.as_str()).or_default();
            *slot = (*slot).max(*value);
        }
    }
    highest
}

/// Counters: the ones that must not move, and the ones that must not accelerate.
fn counters(samples: &[Sample]) -> Vec<Failure> {
    let Some(base) = baseline(samples) else {
        return Vec::new();
    };
    let mut failures = Vec::new();

    let seen = highest(samples);
    for (name, value) in &seen {
        let was = base.counters.get(*name).copied().unwrap_or(0);
        let delta = value.saturating_sub(was);
        if delta > 0 && HARD_ZERO.iter().any(|suffix| name.ends_with(suffix)) {
            failures.push(Failure::new(
                "counters.hard-zero",
                format!("{name} moved by {delta} during the run"),
            ));
        }
    }

    // The rate check. A cumulative counter only ever rises, so its absolute
    // value says nothing; what matters is whether the rate is climbing. The
    // second derivative, approximated by the rate over the first half of the
    // steady window against the rate over the second.
    let window = steady(samples);
    if window.len() >= 6 {
        let half = window.len() / 2;
        for name in seen.keys().copied() {
            if !RATE_WATCHED.iter().any(|suffix| name.ends_with(suffix)) {
                continue;
            }
            let rate = |slice: &[&Sample]| -> Option<f64> {
                let first = slice.first()?;
                let last = slice.last()?;
                let span = last.elapsed_s - first.elapsed_s;
                if span <= 0.0 {
                    return None;
                }
                let a = first.counters.get(name).copied().unwrap_or(0);
                let b = last.counters.get(name).copied().unwrap_or(0);
                Some(b.saturating_sub(a) as f64 / span)
            };
            let (Some(early), Some(late)) = (rate(&window[..half]), rate(&window[half..])) else {
                continue;
            };
            // A floor before the ratio: going from one drop an hour to three is
            // a tripled rate and is not a degradation of anything.
            if early >= 0.01 && late > early * 2.0 {
                failures.push(Failure::new(
                    "counters.rate",
                    format!(
                        "{name} is accelerating: {early:.3}/s over the first half \
                         of the steady window, {late:.3}/s over the second"
                    ),
                ));
            }
        }
    }
    failures
}

/// The log ring: errors, and a record count that does not grow with the load.
fn logs(samples: &[Sample], budget: Budget, allowed_errors: u64) -> Vec<Failure> {
    let Some(last) = samples.last() else {
        return Vec::new();
    };
    let allowed = budget.errors.saturating_add(allowed_errors);
    if last.errors > allowed {
        return vec![Failure::new(
            "logs.errors",
            format!(
                "{} error-severity records; the allowance is {allowed}",
                last.errors
            ),
        )];
    }
    Vec::new()
}

/// Render a report the way a CI log should read it.
///
/// Deliberately not `Debug`: a six-hour run has hundreds of samples and dumping
/// them into a terminal buries the four lines that say what went wrong. The
/// samples go to the JSONL artifact; this goes to the log.
#[must_use]
pub fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "soak: seed {}, {} samples\n",
        report.seed,
        report.samples.len()
    ));

    if let (Some(base), Some(idle)) = (baseline(&report.samples), quiesced(&report.samples))
        && let (Some(b), Some(i)) = (base.process, idle.process)
    {
        out.push_str(&format!(
            "  resident {} MiB -> {} MiB idle, descriptors {} -> {}, tasks {} -> {}\n",
            b.resident_bytes / (1024 * 1024),
            i.resident_bytes / (1024 * 1024),
            b.open_fds,
            i.open_fds,
            base.tasks,
            idle.tasks,
        ));
    }

    let idle: Vec<&Sample> = report
        .samples
        .iter()
        .filter(|s| s.phase == Phase::Quiesced)
        .collect();
    if idle.len() > 1 {
        out.push_str("  idle after each cycle:\n");
        for sample in idle {
            let (fds, threads) = sample.process.map_or((0, 0), |p| (p.open_fds, p.threads));
            out.push_str(&format!(
                "    cycle {:<3} descriptors {fds:<6} tasks {:<6} threads {threads}\n",
                sample.cycle, sample.tasks,
            ));
        }
    }

    if !report.worst_gauges.is_empty() {
        out.push_str("  gauges furthest from baseline when idle:\n");
        for (name, delta) in &report.worst_gauges {
            out.push_str(&format!("    {name:<44} {delta:+}\n"));
        }
    }

    if report.failures.is_empty() {
        out.push_str("  every check passed\n");
    } else {
        out.push_str(&format!("  {} check(s) failed:\n", report.failures.len()));
        for failure in &report.failures {
            out.push_str(&format!("    [{}] {}\n", failure.check, failure.detail));
        }
    }
    out
}

/// Every sample as one JSON object per line.
///
/// JSONL rather than one JSON document so a killed run still leaves a readable
/// artifact, and so `soak-compare.py` can stream it.
#[must_use]
pub fn to_jsonl(samples: &[Sample]) -> String {
    let mut out = String::new();
    for sample in samples {
        if let Ok(line) = serde_json::to_string(sample) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Every gauge in a sample, as a map, for a caller building one by hand.
#[must_use]
pub fn gauge_map(sample: &Sample) -> BTreeMap<String, u64> {
    sample
        .gauges
        .iter()
        .map(|(name, gauge)| (name.clone(), gauge.used))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::sample::{GaugeSample, Stats};
    use super::*;

    fn sample(elapsed: f64, phase: Phase, resident_mib: u64, fds: u64, tasks: u64) -> Sample {
        cycle_sample(elapsed, phase, 1, resident_mib, fds, tasks)
    }

    fn cycle_sample(
        elapsed: f64,
        phase: Phase,
        cycle: u64,
        resident_mib: u64,
        fds: u64,
        tasks: u64,
    ) -> Sample {
        Sample {
            elapsed_s: elapsed,
            phase,
            cycle,
            clients: match phase {
                Phase::Steady => 100,
                // Half-connected: a warm-up sample is taken while clients are
                // still arriving, and the descriptor bound has to hold there
                // too or it only ever describes the easy part of the run.
                Phase::Warmup => 60,
                Phase::Baseline | Phase::Draining | Phase::Quiesced => 0,
            },
            process: Some(Stats {
                resident_bytes: resident_mib * 1024 * 1024,
                open_fds: fds,
                max_fds: 65536,
                threads: 24,
            }),
            tasks,
            ..Sample::default()
        }
    }

    /// A run with nothing wrong with it, to fail every check against.
    ///
    /// Shaped like a real one: a cold idle server, a warm-up, a steady window
    /// wobbling by a megabyte either way, then a drain and one settled sample.
    fn healthy() -> Vec<Sample> {
        let mut samples = vec![
            sample(0.0, Phase::Baseline, 80, 40, 100),
            sample(30.0, Phase::Warmup, 150, 300, 700),
        ];
        for i in 0..12_u64 {
            let at = 60.0 + i as f64 * 30.0;
            // Wobbling by a megabyte either way, which is what a real server does.
            let rss = if i % 2 == 0 { 200 } else { 201 };
            samples.push(sample(at, Phase::Steady, rss, 460, 900));
        }
        samples.push(sample(500.0, Phase::Draining, 190, 60, 150));
        samples.push(sample(600.0, Phase::Quiesced, 88, 44, 102));
        samples
    }

    /// Two identical cycles, which is what a real run does.
    fn two_cycles(second_fds: u64, second_tasks: u64) -> Vec<Sample> {
        let mut samples = vec![cycle_sample(0.0, Phase::Baseline, 0, 80, 40, 100)];
        for cycle in 1..=2_u64 {
            let base = (cycle as f64 - 1.0) * 600.0;
            samples.push(cycle_sample(
                base + 30.0,
                Phase::Warmup,
                cycle,
                150,
                300,
                700,
            ));
            for i in 0..6_u64 {
                samples.push(cycle_sample(
                    base + 60.0 + i as f64 * 30.0,
                    Phase::Steady,
                    cycle,
                    200,
                    460,
                    900,
                ));
            }
            // The first cycle pays the one-time cost; the second must not pay
            // it again.
            let (fds, tasks) = if cycle == 1 {
                (58, 136)
            } else {
                (second_fds, second_tasks)
            };
            samples.push(cycle_sample(
                base + 400.0,
                Phase::Quiesced,
                cycle,
                88,
                fds,
                tasks,
            ));
        }
        samples
    }

    #[test]
    fn two_identical_cycles_that_pay_a_startup_cost_once_are_green() {
        // The case a flat allowance against a cold baseline cannot express:
        // eighteen descriptors and thirty-six tasks appear the moment any load
        // arrives, at every population, and never grow again.
        let report = assess(&two_cycles(58, 136), Budget::default(), 0);
        assert!(
            !report
                .failures
                .iter()
                .any(|f| f.check.starts_with("cycle.")),
            "a cost paid once must not read as a leak: {}",
            render(&report)
        );
    }

    #[test]
    fn a_cost_paid_again_on_the_second_cycle_is_a_leak_with_no_constant_to_argue_about() {
        let report = assess(&two_cycles(76, 172), Budget::default(), 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.check == "cycle.descriptors"),
            "{}",
            render(&report)
        );
        assert!(
            report.failures.iter().any(|f| f.check == "cycle.tasks"),
            "{}",
            render(&report)
        );
    }

    #[test]
    fn a_single_cycle_run_asserts_nothing_about_cycles_rather_than_passing_falsely() {
        let report = assess(&healthy(), Budget::default(), 0);
        assert!(
            !report
                .failures
                .iter()
                .any(|f| f.check.starts_with("cycle.")),
            "one cycle has nothing to compare against"
        );
    }

    #[test]
    fn a_healthy_run_passes_every_check() {
        let report = assess(&healthy(), Budget::default(), 0);
        assert!(
            report.failures.is_empty(),
            "a healthy run must be green: {}",
            render(&report)
        );
    }

    #[test]
    fn memory_that_does_not_come_back_down_when_idle_is_caught() {
        let mut samples = healthy();
        // Baseline was 200 MiB steady; the *baseline* here is the first steady
        // sample, so 1.15x is 230.
        let last = samples.len() - 1;
        samples[last] = sample(600.0, Phase::Quiesced, 400, 44, 102);
        let report = assess(&samples, Budget::default(), 0);
        assert!(
            report.failures.iter().any(|f| f.check == "quiesce.rss"),
            "the quiesce check must catch it: {}",
            render(&report)
        );
    }

    #[test]
    fn a_linear_climb_under_load_is_caught_and_noise_is_not() {
        let mut leaking = vec![
            sample(0.0, Phase::Baseline, 80, 40, 100),
            sample(30.0, Phase::Warmup, 150, 300, 700),
        ];
        for i in 0..24_u64 {
            let at = 60.0 + i as f64 * 300.0;
            // 8 MiB/h: two hours of samples climbing steadily.
            let rss = 200 + i * 2 / 3;
            leaking.push(sample(at, Phase::Steady, rss, 460, 900));
        }
        leaking.push(sample(8000.0, Phase::Quiesced, 88, 44, 102));
        let report = assess(&leaking, Budget::default(), 0);
        assert!(
            report.failures.iter().any(|f| f.check == "memory.slope"),
            "a linear climb must be caught: {}",
            render(&report)
        );

        let report = assess(&healthy(), Budget::default(), 0);
        assert!(
            !report.failures.iter().any(|f| f.check == "memory.slope"),
            "a wobble must not be: {}",
            render(&report)
        );
    }

    #[test]
    fn a_window_too_short_for_a_trend_reports_nothing_rather_than_a_false_one() {
        // A megabyte of warm-up bleed over fifty seconds extrapolates to
        // seventy megabytes an hour with an excellent correlation. It is not a
        // leak, and a smoke test that fails on it every time is a check
        // somebody deletes.
        let mut short = vec![
            sample(0.0, Phase::Baseline, 80, 40, 100),
            sample(10.0, Phase::Warmup, 150, 300, 700),
        ];
        for i in 0..5_u64 {
            short.push(sample(
                20.0 + i as f64 * 10.0,
                Phase::Steady,
                200 + i,
                460,
                900,
            ));
        }
        short.push(sample(90.0, Phase::Quiesced, 88, 44, 102));

        let report = assess(&short, Budget::default(), 0);
        assert!(
            !report.failures.iter().any(|f| f.check == "memory.slope"),
            "fifty seconds is not a trend: {}",
            render(&report)
        );
    }

    #[test]
    fn descriptors_still_open_with_nothing_connected_are_caught() {
        let mut samples = healthy();
        let last = samples.len() - 1;
        samples[last] = sample(600.0, Phase::Quiesced, 88, 300, 102);
        let report = assess(&samples, Budget::default(), 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.check == "descriptors.quiesced"),
            "{}",
            render(&report)
        );
    }

    #[test]
    fn a_gauge_that_never_drains_is_named_rather_than_merely_counted() {
        // Defect 8's shape: `social.watches` grows with every connection and
        // nothing removes the entry. RSS would take weeks to show this.
        let mut samples = healthy();
        for s in &mut samples {
            let entries = if s.phase == Phase::Steady { 100 } else { 0 };
            let _previous = s.gauges.insert(
                "social.watches".to_owned(),
                GaugeSample {
                    used: entries,
                    peak: entries,
                    capacity: 0,
                    rejected: 0,
                },
            );
        }
        let last = samples.len() - 1;
        let _previous = samples[last].gauges.insert(
            "social.watches".to_owned(),
            GaugeSample {
                used: 1200,
                peak: 1200,
                capacity: 0,
                rejected: 0,
            },
        );

        let report = assess(&samples, Budget::default(), 0);
        let failure = report
            .failures
            .iter()
            .find(|f| f.check == "gauges.quiesced")
            .expect("the gauge check must fire");
        assert!(
            failure.detail.contains("social.watches"),
            "the report must name the gauge, not just the count: {}",
            failure.detail
        );
        assert_eq!(
            report.worst_gauges.first().map(|g| g.0.as_str()),
            Some("social.watches"),
            "and it must lead the drift list"
        );
    }

    #[test]
    fn a_retained_gauge_is_exempt_and_its_neighbours_are_not() {
        // The risk with an exemption list is that it is read as a prefix and
        // quietly covers a gauge nobody argued for. `gateway.resume.sessions`
        // is on the list; `gateway.resume.evicted` is not, and must still fail.
        let mut samples = healthy();
        let last = samples.len() - 1;
        for name in ["gateway.resume.sessions", "gateway.resume.evicted"] {
            let _previous = samples[last].gauges.insert(
                name.to_owned(),
                GaugeSample {
                    used: 40,
                    peak: 40,
                    capacity: 0,
                    rejected: 0,
                },
            );
        }

        let report = assess(&healthy(), Budget::default(), 0);
        assert!(report.failures.is_empty(), "the fixture must start green");

        let report = assess(&samples, Budget::default(), 0);
        let quiesced: Vec<&str> = report
            .failures
            .iter()
            .filter(|f| f.check == "gauges.quiesced")
            .map(|f| f.detail.as_str())
            .collect();
        assert_eq!(quiesced.len(), 1, "exactly one of the two: {quiesced:?}");
        assert!(
            quiesced[0].contains("gateway.resume.evicted"),
            "the unargued one is the one that must fail: {quiesced:?}"
        );
    }

    #[test]
    fn every_retained_gauge_says_what_clears_it() {
        // The list is only defensible if each line is. An empty `why` is an
        // exemption nobody can review, which is the failure mode this whole
        // mechanism exists to avoid.
        for retained in RETAINED {
            assert!(
                retained.why.len() > 40,
                "{} is exempt without an argument",
                retained.gauge
            );
            assert!(
                retained.gauge.contains('.'),
                "{} is not a service-qualified key, so it would match nothing",
                retained.gauge
            );
        }
    }

    #[test]
    fn a_gauge_running_at_ninety_nine_percent_fails_before_the_load_rises() {
        let mut samples = healthy();
        let _previous = samples[4].gauges.insert(
            "gateway.pending-handshakes".to_owned(),
            GaugeSample {
                used: 990,
                peak: 990,
                capacity: 1000,
                rejected: 0,
            },
        );
        let report = assess(&samples, Budget::default(), 0);
        assert!(
            report.failures.iter().any(|f| f.check == "gauges.headroom"),
            "{}",
            render(&report)
        );
    }

    #[test]
    fn a_restart_during_the_run_is_never_a_budget() {
        let mut samples = healthy();
        let last = samples.len() - 1;
        let _previous = samples[last]
            .counters
            .insert("gateway.service_restarts".to_owned(), 1);
        let report = assess(&samples, Budget::default(), 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.check == "counters.hard-zero"),
            "{}",
            render(&report)
        );
    }

    #[test]
    fn a_drop_rate_that_climbs_is_caught_and_a_steady_one_is_not() {
        let mut climbing = healthy();
        for (i, s) in climbing
            .iter_mut()
            .filter(|s| s.phase == Phase::Steady)
            .enumerate()
        {
            // Flat for the first half, then quadratic.
            let n = i as u64;
            let dropped = if n < 6 { n } else { 6 + (n - 6) * 20 };
            let _previous = s
                .counters
                .insert("voice.frames_dropped".to_owned(), dropped);
        }
        let report = assess(&climbing, Budget::default(), 0);
        assert!(
            report.failures.iter().any(|f| f.check == "counters.rate"),
            "{}",
            render(&report)
        );

        let mut steady_drops = healthy();
        for (i, s) in steady_drops
            .iter_mut()
            .filter(|s| s.phase == Phase::Steady)
            .enumerate()
        {
            let _previous = s
                .counters
                .insert("voice.frames_dropped".to_owned(), i as u64 * 30);
        }
        let report = assess(&steady_drops, Budget::default(), 0);
        assert!(
            !report.failures.iter().any(|f| f.check == "counters.rate"),
            "a constant drop rate is not a degradation: {}",
            render(&report)
        );
    }

    #[test]
    fn a_run_that_never_quiesced_says_so_rather_than_passing() {
        // The failure mode that matters most: a harness bug that skips the
        // quiesce phase must not read as a green run.
        let truncated: Vec<Sample> = healthy()
            .into_iter()
            .filter(|s| s.phase != Phase::Quiesced)
            .collect();
        let report = assess(&truncated, Budget::default(), 0);
        assert!(
            report.failures.iter().any(|f| f.check == "quiesce"),
            "{}",
            render(&report)
        );
    }

    #[test]
    fn a_thread_started_per_stream_and_never_joined_is_caught() {
        let mut samples = healthy();
        if let Some(stats) = samples[6].process.as_mut() {
            stats.threads = 300;
        }
        let report = assess(&samples, Budget::default(), 0);
        assert!(
            report.failures.iter().any(|f| f.check == "threads.growth"),
            "{}",
            render(&report)
        );
    }

    #[test]
    fn the_report_renders_without_the_samples_in_it() {
        let report = assess(&healthy(), Budget::default(), 0);
        let rendered = render(&report);
        assert!(rendered.contains("every check passed"));
        assert!(
            rendered.lines().count() < 12,
            "a green report is a handful of lines, not a sample dump:\n{rendered}"
        );
    }
}
