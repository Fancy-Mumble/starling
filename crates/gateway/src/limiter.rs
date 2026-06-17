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

use starling_runtime::config::LimitConfig;
use starling_runtime::ratelimit::TokenBucket;

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

/// Every bucket one connection owns.
///
/// Per connection rather than per account on purpose: the limit protects the
/// server from a socket, and an unauthenticated peer has no account to charge.
#[derive(Debug)]
pub struct Limiter {
    buckets: HashMap<String, TokenBucket>,
    config: BTreeMap<String, LimitConfig>,
}

impl Limiter {
    /// A limiter with the configured buckets, all full.
    #[must_use]
    pub fn new(config: &BTreeMap<String, LimitConfig>, now_ms: u64) -> Self {
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
        }
    }

    /// Charge one frame to `bucket`.
    ///
    /// An unknown bucket name is allowed rather than refused: a route naming a
    /// bucket the operator did not define is a configuration mistake, and
    /// silently rate-limiting everything to zero would be a far worse failure
    /// than not limiting it at all. It is logged once by the caller.
    pub fn check(&mut self, bucket: &str, now_ms: u64) -> Verdict {
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
}
