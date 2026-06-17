//! The token bucket, and the rate an operator writes for it.
//!
//! murmur runs **one** shared bucket per user — 1 msg/s sustained, burst 5,
//! and a **silent drop** when it trips (`RATELIMIT` in `Messages.cpp`).
//! Starting a screen share legitimately emits several signalling messages back
//! to back, and that silently ate the loopback viewer's SDP offer in most runs:
//! the client logged success and the server logged nothing.
//!
//! Two things follow, and both are structural rather than a policy someone
//! remembers:
//!
//! * buckets are **per route**, so a burst of signalling cannot exhaust the
//!   budget chat needs (the gateway owns the routes; this type owns the maths)
//! * a refusal is **returned**, never swallowed — the caller decides whether to
//!   tell a Fancy client or keep the silence a legacy client expects

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A sustained rate, written `"10/s"` or `"600/m"`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    per_second: f64,
}

impl Rate {
    /// A rate of `count` per second.
    #[must_use]
    pub const fn per_second(count: f64) -> Self {
        Self { per_second: count }
    }

    /// Tokens accrued per second.
    #[must_use]
    pub const fn as_per_second(self) -> f64 {
        self.per_second
    }
}

impl FromStr for Rate {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (count, unit) = text
            .split_once('/')
            .ok_or_else(|| format!("{text:?} is not a rate: write 10/s or 600/m"))?;
        let count: f64 = count
            .trim()
            .parse()
            .map_err(|_| format!("{text:?} does not start with a number"))?;
        let divisor = match unit.trim() {
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            other => return Err(format!("unknown rate unit {other:?}: use s, m or h")),
        };
        Ok(Self {
            per_second: count / divisor,
        })
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/s", self.per_second)
    }
}

impl<'de> Deserialize<'de> for Rate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

impl Serialize for Rate {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// A leaky bucket that refills at [`Rate`] and holds `burst` tokens.
///
/// Time is supplied by the caller rather than read from the clock, so the
/// behaviour is testable without sleeping and a caller that already has a
/// timestamp does not take a second one.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: Rate,
    burst: f64,
    tokens: f64,
    last_ms: u64,
}

/// Why a message was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttled {
    /// How long until one token is available again.
    pub retry_after: Duration,
}

impl TokenBucket {
    /// A full bucket.
    #[must_use]
    pub fn new(rate: Rate, burst: u32, now_ms: u64) -> Self {
        Self {
            rate,
            burst: f64::from(burst),
            tokens: f64::from(burst),
            last_ms: now_ms,
        }
    }

    /// Spend one token, or say how long to wait.
    ///
    /// # Errors
    ///
    /// [`Throttled`] when the bucket is empty, carrying the wait — that value
    /// is what a Fancy client is told, and what makes the refusal actionable
    /// rather than a mystery.
    pub fn take(&mut self, now_ms: u64) -> Result<(), Throttled> {
        self.refill(now_ms);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }
        let deficit = 1.0 - self.tokens;
        let seconds = if self.rate.per_second > 0.0 {
            deficit / self.rate.per_second
        } else {
            // A rate of zero means "never", and a retry hint of forever is more
            // honest than one that invites a retry storm.
            f64::from(u16::MAX)
        };
        Err(Throttled {
            retry_after: Duration::from_secs_f64(seconds),
        })
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        if elapsed == 0 {
            return;
        }
        self.last_ms = now_ms;
        let gained = (elapsed as f64 / 1000.0) * self.rate.per_second;
        self.tokens = (self.tokens + gained).min(self.burst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_admitted_up_to_the_bucket_size() {
        let mut bucket = TokenBucket::new(Rate::per_second(1.0), 5, 0);
        for _ in 0..5 {
            assert!(bucket.take(0).is_ok());
        }
        assert!(bucket.take(0).is_err(), "the sixth must be refused");
    }

    #[test]
    fn a_refusal_says_how_long_to_wait_rather_than_dropping_in_silence() {
        // This is the whole difference from murmur's bucket: the caller gets a
        // value it can hand to the client.
        let mut bucket = TokenBucket::new(Rate::per_second(2.0), 1, 0);
        assert!(bucket.take(0).is_ok());
        let throttled = bucket.take(0).expect_err("bucket is empty");
        assert!(throttled.retry_after <= Duration::from_millis(500));
        assert!(throttled.retry_after > Duration::ZERO);
    }

    #[test]
    fn tokens_accrue_at_the_configured_rate() {
        let mut bucket = TokenBucket::new(Rate::per_second(1.0), 1, 0);
        assert!(bucket.take(0).is_ok());
        assert!(bucket.take(500).is_err(), "half a token is not a token");
        assert!(bucket.take(1000).is_ok());
    }

    #[test]
    fn the_bucket_never_fills_past_its_burst() {
        // Otherwise an idle client accrues an unbounded allowance and the burst
        // limit means nothing after a quiet minute.
        let mut bucket = TokenBucket::new(Rate::per_second(10.0), 3, 0);
        for _ in 0..3 {
            assert!(bucket.take(60_000).is_ok());
        }
        assert!(bucket.take(60_000).is_err());
    }

    #[test]
    fn rates_parse_the_way_an_operator_writes_them() {
        assert_eq!("10/s".parse::<Rate>().map(Rate::as_per_second), Ok(10.0));
        assert_eq!("600/m".parse::<Rate>().map(Rate::as_per_second), Ok(10.0));
        assert!("10".parse::<Rate>().is_err());
    }
}
