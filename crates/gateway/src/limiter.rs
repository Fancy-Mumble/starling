//! A bucket per route, per client — and a refusal that is never silent.
//!
//! murmur runs one shared leaky bucket per user: 1 msg/s sustained, burst 5,
//! **silent drop**. Starting a screen share legitimately emits several
//! signalling messages back to back, and that ate the loopback viewer's SDP
//! offer in most runs — the client logged success, the server logged nothing.
//!
//! So: buckets are per route, and a throttled message produces a [`Verdict`]
//! the caller must act on. Fancy clients are told they were throttled; legacy
//! clients keep the silence they expect, because a message type they have never
//! seen is worse than the silence they were built against.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use starling_runtime::config::LimitConfig;
use starling_runtime::ratelimit::{Rate, TokenBucket};

/// The bucket every route falls back to, and the one murmur's `messagelimit`
/// is about.
pub const CONTROL: &str = "control";

/// What to do with a frame that has just arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forward it.
    Allow,
    /// Refuse it, and tell the client how long to wait.
    Throttle {
        /// Milliseconds until a token is available.
        retry_after_ms: u32,
    },
}

/// The control-bucket numbers an operator can change while the server runs.
///
/// `message_limit` and `message_burst` were in `server-config`, read back by
/// `operator-api`, and applied nowhere — the gateway sized its buckets from the
/// deployment TOML, so murmur's runtime-tunable rate limit was not tunable at
/// runtime (`docs/GAP-ANALYSIS.md` §5).
///
/// Shared by every connection and read on the frame path, so it is two atomics
/// rather than a lock: a mutex here would put every client's frames behind one
/// another for a value that changes about once a month.
///
/// Absent — `rate` of zero — means "the operator has said nothing", and the
/// TOML stands. That distinction has to exist: a deployment that tuned its
/// `control` bucket must not have it silently reset to murmur's 1/s by a
/// `server-config` that merely came up with its defaults.
#[derive(Debug, Default)]
pub struct MessageLimit {
    /// Tokens per second, as `f64` bits. Zero means unset.
    rate: AtomicU64,
    burst: AtomicU32,
}

impl MessageLimit {
    /// Publish a change. `rate` of zero clears it.
    pub fn set(&self, rate: f64, burst: u32) {
        self.rate.store(rate.to_bits(), Ordering::Relaxed);
        self.burst.store(burst, Ordering::Relaxed);
    }

    /// What the operator has set, if anything.
    #[must_use]
    pub fn get(&self) -> Option<LimitConfig> {
        let rate = f64::from_bits(self.rate.load(Ordering::Relaxed));
        (rate > 0.0).then(|| LimitConfig {
            rate: Rate::per_second(rate),
            burst: self.burst.load(Ordering::Relaxed),
        })
    }
}

/// Every bucket one connection owns.
///
/// Per connection rather than per account on purpose: the limit protects the
/// server from a socket, and an unauthenticated peer has no account to charge.
#[derive(Debug)]
pub struct Limiter {
    buckets: HashMap<String, TokenBucket>,
    config: BTreeMap<String, LimitConfig>,
    /// The live `control` numbers, shared with every other connection.
    live: Arc<MessageLimit>,
    /// What was last applied from `live`, so an unchanged setting is not
    /// re-applied on every frame.
    applied: Option<LimitConfig>,
}

impl Limiter {
    /// A limiter with the configured buckets, all full.
    #[must_use]
    pub fn new(config: &BTreeMap<String, LimitConfig>, now_ms: u64) -> Self {
        Self::live(config, now_ms, Arc::new(MessageLimit::default()))
    }

    /// The same, following `live` for the control bucket.
    #[must_use]
    pub fn live(
        config: &BTreeMap<String, LimitConfig>,
        now_ms: u64,
        live: Arc<MessageLimit>,
    ) -> Self {
        let buckets = config
            .iter()
            .map(|(name, limit)| {
                (
                    name.clone(),
                    TokenBucket::new(limit.rate, limit.burst, now_ms),
                )
            })
            .collect();
        Self {
            buckets,
            config: config.clone(),
            live,
            applied: None,
        }
    }

    /// Charge one frame to `bucket`.
    ///
    /// An unknown bucket name is allowed rather than refused: a route naming a
    /// bucket the operator did not define is a configuration mistake, and
    /// silently rate-limiting everything to zero would be a far worse failure
    /// than not limiting it at all. It is logged once by the caller.
    pub fn check(&mut self, bucket: &str, now_ms: u64) -> Verdict {
        if bucket == CONTROL {
            self.follow_live();
        }
        let Some(tokens) = self.buckets.get_mut(bucket) else {
            return Verdict::Allow;
        };
        match tokens.take(now_ms) {
            Ok(()) => Verdict::Allow,
            Err(throttled) => Verdict::Throttle {
                retry_after_ms: throttled.retry_after.as_millis().min(u128::from(u32::MAX)) as u32,
            },
        }
    }

    /// Apply the operator's `messagelimit` to this connection's control bucket.
    ///
    /// Checked per frame rather than per connection, which is what makes the
    /// setting *live*: a client that connected an hour ago is throttled by the
    /// number in force now, not by the one in force when it dialled.
    fn follow_live(&mut self) {
        let Some(limit) = self.live.get() else {
            return;
        };
        if self.applied == Some(limit) {
            return;
        }
        if let Some(bucket) = self.buckets.get_mut(CONTROL) {
            bucket.retune(limit.rate, limit.burst);
        } else {
            let _ = self.buckets.insert(
                CONTROL.to_owned(),
                TokenBucket::new(limit.rate, limit.burst, 0),
            );
        }
        let _ = self.config.insert(CONTROL.to_owned(), limit);
        self.applied = Some(limit);
    }

    /// Which buckets exist, for diagnostics.
    #[must_use]
    pub fn buckets(&self) -> Vec<&str> {
        self.config.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_runtime::ratelimit::Rate;

    fn config() -> BTreeMap<String, LimitConfig> {
        BTreeMap::from([
            (
                "control".to_owned(),
                LimitConfig {
                    rate: Rate::per_second(1.0),
                    burst: 5,
                },
            ),
            (
                "signalling".to_owned(),
                LimitConfig {
                    rate: Rate::per_second(10.0),
                    burst: 20,
                },
            ),
        ])
    }

    #[test]
    fn one_route_running_dry_does_not_stop_another() {
        // The entire reason the buckets are per route: a screen-share burst
        // must not spend the budget chat needs.
        let mut limiter = Limiter::new(&config(), 0);
        for _ in 0..5 {
            assert_eq!(limiter.check("control", 0), Verdict::Allow);
        }
        assert!(matches!(
            limiter.check("control", 0),
            Verdict::Throttle { .. }
        ));
        assert_eq!(limiter.check("signalling", 0), Verdict::Allow);
    }

    #[test]
    fn a_throttle_says_how_long_to_wait_rather_than_dropping_in_silence() {
        let mut limiter = Limiter::new(&config(), 0);
        for _ in 0..5 {
            let _ = limiter.check("control", 0);
        }
        let Verdict::Throttle { retry_after_ms } = limiter.check("control", 0) else {
            panic!("the sixth frame must be throttled");
        };
        assert!(retry_after_ms > 0 && retry_after_ms <= 1000);
    }

    #[test]
    fn a_route_naming_an_undefined_bucket_is_allowed_rather_than_starved() {
        // Refusing would turn a typo in the TOML into a service that silently
        // never receives anything.
        let mut limiter = Limiter::new(&config(), 0);
        assert_eq!(limiter.check("whiteboard", 0), Verdict::Allow);
    }

    #[test]
    fn the_operators_message_limit_reaches_a_connection_that_is_already_open() {
        // §5's `message_limit`/`message_burst`: read back by `operator-api` and
        // applied nowhere, because the buckets came from the deployment TOML.
        // Raising it must reach a client that never reconnects — which is what
        // murmur's `setLiveConf` does and what a per-connection bucket built at
        // connect time cannot.
        let live = Arc::new(MessageLimit::default());
        let mut limiter = Limiter::live(&config(), 0, Arc::clone(&live));

        // The TOML's burst of 5, and then throttled.
        for _ in 0..5 {
            assert_eq!(limiter.check(CONTROL, 0), Verdict::Allow);
        }
        assert!(matches!(
            limiter.check(CONTROL, 0),
            Verdict::Throttle { .. }
        ));

        // A tenth of a second later it is still throttled at the TOML's 1/s,
        // which is what makes the next assertion about the setting and not
        // about the passage of time.
        assert!(matches!(
            limiter.check(CONTROL, 100),
            Verdict::Throttle { .. }
        ));

        // The operator raises it. No reconnect, no new limiter.
        live.set(50.0, 50);
        assert_eq!(
            limiter.check(CONTROL, 200),
            Verdict::Allow,
            "the new rate must refill this connection's bucket"
        );
    }

    #[test]
    fn lowering_the_message_limit_takes_effect_in_the_same_direction() {
        // The direction an operator actually reaches for it: something is
        // flooding, and the limit has to bite now rather than at its next
        // reconnect.
        let live = Arc::new(MessageLimit::default());
        let mut limiter = Limiter::live(&config(), 0, Arc::clone(&live));
        live.set(1.0, 1);
        assert_eq!(limiter.check(CONTROL, 0), Verdict::Allow);
        assert!(
            matches!(limiter.check(CONTROL, 0), Verdict::Throttle { .. }),
            "a burst of 1 must refuse the second frame"
        );
    }

    #[test]
    fn an_unset_message_limit_leaves_the_deployments_own_numbers_alone() {
        // A `server-config` that comes up with its defaults must not silently
        // reset a `control` bucket the deployment deliberately tuned.
        let live = Arc::new(MessageLimit::default());
        let mut limiter = Limiter::live(&config(), 0, live);
        for _ in 0..5 {
            assert_eq!(limiter.check(CONTROL, 0), Verdict::Allow);
        }
        assert!(matches!(
            limiter.check(CONTROL, 0),
            Verdict::Throttle { .. }
        ));
    }

    #[test]
    fn the_live_limit_does_not_touch_the_other_buckets() {
        // `messagelimit` is murmur's control-message limit. Applying it to the
        // audio bucket would throttle a call off the air.
        let live = Arc::new(MessageLimit::default());
        let mut limiter = Limiter::live(&config(), 0, Arc::clone(&live));
        live.set(1.0, 1);
        let _ = limiter.check(CONTROL, 0);
        for _ in 0..20 {
            assert_eq!(limiter.check("signalling", 0), Verdict::Allow);
        }
    }
}
