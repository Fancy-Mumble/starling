//! What the virtual clients do, and for how long.
//!
//! A scenario is a TOML file rather than a function, so adding one is a config
//! change and a nightly can run a different shape from a per-PR smoke test
//! without a second driver to keep in step. The defaults here are the shape of
//! a small community server; `scenarios/*.toml` overrides what a particular run
//! wants to stress.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::assess::Budget;

/// One run's worth of load.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scenario {
    /// A name for the report, so two artifacts are distinguishable.
    pub name: String,
    /// Virtual clients at steady state.
    pub population: u64,
    /// How long the whole run lasts, seconds.
    pub duration_s: u64,
    /// How long clients take to all be connected, seconds.
    ///
    /// Arrivals are spread over this rather than all at once: a thundering herd
    /// measures admission control, which is a different test, and it makes the
    /// warm-up window unrepresentative of the steady one.
    pub warmup_s: u64,
    /// How long to wait after the last client leaves before the settled sample.
    ///
    /// Long enough for every timeout, sweep and idle-eviction in the server to
    /// have fired at least once. A quiesce assertion taken before the reaper
    /// runs measures the reaper's period, not a leak.
    pub quiesce_s: u64,
    /// Seconds between samples.
    pub sample_every_s: u64,
    /// Channels to create, which clients then move between.
    pub channels: u64,
    /// Seconds between one client's channel joins, on average.
    pub join_every_s: u64,
    /// Seconds between one client's chat messages, on average.
    pub chat_every_s: u64,
    /// Fraction of chat messages that are near the maximum size, 0-100.
    pub large_chat_percent: u64,
    /// Fraction of clients speaking at any moment, 0-100.
    pub speaking_percent: u64,
    /// Fraction of clients that reconnect during the run, 0-100.
    pub reconnect_percent: u64,
    /// How many load-and-quiesce cycles to run.
    ///
    /// Two, so the run carries the one leak check with no tuned constant in it:
    /// the second idle sample against the first. One cycle can only compare an
    /// idle server against a *cold* one, which means allowing for whatever the
    /// server pays once on first use, which means a constant somebody will
    /// widen the next time it fails.
    ///
    /// `duration_s` covers a single cycle; a two-cycle run takes about twice
    /// as long, which is the price of the assertion.
    pub cycles: u64,
    /// What the run is allowed to do. Overridable per scenario, because a
    /// deliberately hostile run has a different budget from a quiet one.
    pub budget: Budget,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            name: "default".to_owned(),
            population: 20,
            duration_s: 120,
            warmup_s: 20,
            quiesce_s: 20,
            sample_every_s: 10,
            channels: 8,
            join_every_s: 20,
            chat_every_s: 15,
            large_chat_percent: 3,
            speaking_percent: 15,
            reconnect_percent: 5,
            cycles: 2,
            budget: Budget::default(),
        }
    }
}

impl Scenario {
    /// Parse one, reporting the key that was wrong rather than a line number.
    ///
    /// # Errors
    ///
    /// The parse failure, verbatim. `deny_unknown_fields` means a renamed key
    /// is an error at load rather than a silently ignored setting -- a soak
    /// that quietly ran the default population is a soak that proved nothing.
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|error| error.to_string())
    }

    /// How long the loaded, asserted-on part of the run lasts.
    #[must_use]
    pub fn steady(&self) -> Duration {
        Duration::from_secs(
            self.duration_s
                .saturating_sub(self.warmup_s)
                .saturating_sub(self.quiesce_s),
        )
    }

    /// Reject a scenario whose phases do not fit inside its duration.
    ///
    /// # Errors
    ///
    /// Says which phase does not fit. Without this a `duration_s` shorter than
    /// `warmup_s + quiesce_s` produces a run with an empty steady window, which
    /// asserts nothing and reports green.
    pub fn check(&self) -> Result<(), String> {
        if self.steady().is_zero() {
            return Err(format!(
                "{}: duration_s {} leaves no steady window after warmup_s {} \
                 and quiesce_s {}; the run would assert nothing",
                self.name, self.duration_s, self.warmup_s, self.quiesce_s,
            ));
        }
        if self.sample_every_s == 0 {
            return Err(format!("{}: sample_every_s must not be zero", self.name));
        }
        let steady_samples = self.steady().as_secs() / self.sample_every_s;
        if steady_samples < 3 {
            return Err(format!(
                "{}: the steady window holds {steady_samples} sample(s) at \
                 sample_every_s {}; a slope needs at least three",
                self.name, self.sample_every_s,
            ));
        }
        if self.population == 0 {
            return Err(format!("{}: population must not be zero", self.name));
        }
        if self.cycles == 0 {
            return Err(format!("{}: cycles must not be zero", self.name));
        }
        Ok(())
    }
}

/// A small explicit generator, so a seed means the same thing next year.
///
/// Not `rand`. The whole value of printing the seed at start-up is that a
/// failure reproduces, and `rand` makes no promise that a version bump leaves
/// the stream unchanged -- a dependency update would silently retire every
/// recorded reproduction. Sixteen lines of xorshift is the price of that
/// promise.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seed it. Zero is remapped, since xorshift has a fixed point there.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// The next value in the stream.
    pub const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value below `bound`, or zero when `bound` is zero.
    pub const fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next() % bound
    }

    /// Whether a `percent`-likely event happens this time.
    pub const fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    /// An exponential-ish delay averaging `mean`, so arrivals are Poisson
    /// rather than a metronome.
    ///
    /// A metronome is the one arrival pattern a server never sees, and it hides
    /// exactly the contention a soak is looking for: every client doing the
    /// same thing at the same instant either always fits or never does.
    pub fn delay(&mut self, mean: Duration) -> Duration {
        let millis = mean.as_millis().min(u128::from(u64::MAX)) as u64;
        if millis == 0 {
            return Duration::ZERO;
        }
        // Inverse-transform sampling, in integer arithmetic: -mean * ln(u).
        let u = (self.below(1_000_000) + 1) as f64 / 1_000_001.0;
        let scaled = -(u.ln()) * millis as f64;
        Duration::from_millis(scaled.min(millis as f64 * 8.0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_scenario_is_runnable() {
        Scenario::default()
            .check()
            .expect("the default must be valid");
    }

    #[test]
    fn a_scenario_with_no_steady_window_is_refused_rather_than_reported_green() {
        let scenario = Scenario {
            duration_s: 30,
            warmup_s: 20,
            quiesce_s: 20,
            ..Scenario::default()
        };
        let error = scenario.check().expect_err("this asserts nothing");
        assert!(error.contains("no steady window"), "{error}");
    }

    #[test]
    fn a_steady_window_too_short_to_fit_a_trend_is_refused() {
        let scenario = Scenario {
            duration_s: 60,
            warmup_s: 20,
            quiesce_s: 20,
            sample_every_s: 10,
            ..Scenario::default()
        };
        let error = scenario.check().expect_err("two samples are not a trend");
        assert!(error.contains("at least three"), "{error}");
    }

    #[test]
    fn a_renamed_key_is_an_error_rather_than_a_silently_ignored_setting() {
        let error = Scenario::parse("populaton = 500").expect_err("a typo must not load");
        assert!(error.contains("populaton"), "{error}");
    }

    #[test]
    fn a_scenario_round_trips_through_toml() {
        let scenario = Scenario {
            name: "nightly".to_owned(),
            population: 100,
            duration_s: 2700,
            ..Scenario::default()
        };
        let text = toml::to_string(&scenario).expect("serialises");
        assert_eq!(Scenario::parse(&text).expect("parses"), scenario);
    }

    #[test]
    fn the_same_seed_produces_the_same_run() {
        // The whole point of printing the seed. If this ever fails, every
        // recorded reproduction in a bug report has quietly expired.
        let draw = |seed| {
            let mut rng = Rng::new(seed);
            (0..8).map(|_| rng.below(1000)).collect::<Vec<_>>()
        };
        assert_eq!(draw(42), draw(42));
        assert_ne!(draw(42), draw(43));
    }

    #[test]
    fn a_zero_seed_is_not_a_fixed_point() {
        let mut rng = Rng::new(0);
        let first = rng.next();
        assert_ne!(first, 0);
        assert_ne!(rng.next(), first);
    }

    #[test]
    fn poisson_delays_average_out_near_the_mean_and_are_not_all_equal() {
        let mut rng = Rng::new(7);
        let mean = Duration::from_millis(100);
        let draws: Vec<u128> = (0..2000).map(|_| rng.delay(mean).as_millis()).collect();
        let average = draws.iter().sum::<u128>() / draws.len() as u128;
        assert!((50..=160).contains(&average), "average {average}ms");
        assert!(
            draws
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 50,
            "a metronome is the one arrival pattern a server never sees"
        );
    }
}
