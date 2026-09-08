//! What one person may spend of the browser.
//!
//! Every other rung of the ladder is an HTTP request, bounded by the fetch
//! limits and paid for in sockets. The browser is not: a render is a whole
//! engine, a tab, a few hundred megabytes and seconds of CPU, against a page a
//! stranger chose. The frame that asked for it was already rate-limited by the
//! gateway, and that is the wrong unit - one frame can cost a browser render or
//! nothing at all, depending on a host's bot wall.
//!
//! So the expensive rung has its own bucket, and there are two of them:
//!
//! * **per session**, so one person pasting forty links from a defended site
//!   cannot hold the browser for everybody else
//! * **server-wide**, so twenty people each inside their own limit cannot do
//!   the same thing between them
//!
//! Both are charged or neither is, and both are probed on copies before either
//! is committed: a token spent on a render the other bucket then refuses is a
//! token taken from somebody who would have got a preview for it.
//!
//! The shape is `gifs`'s [`Quota`](../../gifs/src/quota.rs) without the cache
//! and the coalescer - there is nothing to cache here, because the *page* is
//! what a render produces and two people pasting the same link seconds apart is
//! rare enough not to build for.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use starling_runtime::ratelimit::{Rate, Throttled, TokenBucket};

/// A rate and the burst it allows.
#[derive(Debug, Clone, Copy)]
pub struct Limit {
    /// What accrues, sustained.
    pub rate: Rate,
    /// How much may be spent at once, after an idle spell.
    pub burst: u32,
}

impl Limit {
    /// One render every `seconds`, allowing `burst` at once.
    #[must_use]
    pub fn every(seconds: f64, burst: u32) -> Self {
        Self {
            rate: Rate::per_second(1.0 / seconds),
            burst,
        }
    }
}

/// Why a render was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This session is asking for browsers faster than its own limit.
    Session(Duration),
    /// The server as a whole is at its limit. Distinguished because it is the
    /// operator's problem rather than this person's: they can do nothing about
    /// it, and it belongs in a log.
    Server(Duration),
}

impl Refusal {
    /// How long until asking again could work.
    #[must_use]
    pub const fn retry_after(self) -> Duration {
        match self {
            Self::Session(wait) | Self::Server(wait) => wait,
        }
    }

    /// What the client is told, which is a wait and not a policy.
    #[must_use]
    pub fn reason(self) -> String {
        let seconds = self.retry_after().as_secs().max(1);
        match self {
            Self::Session(_) => format!("that link needs a browser; try again in {seconds}s"),
            Self::Server(_) => {
                format!("the server is rendering too many links; try again in {seconds}s")
            }
        }
    }
}

/// The buckets, behind one lock.
#[derive(Debug)]
pub struct Quota {
    inner: Mutex<Inner>,
    per_session: Limit,
    /// How long a session's bucket is kept after its last render.
    ///
    /// Kept for a while rather than dropped on disconnect: a bucket dropped the
    /// moment a session ends hands a full burst to whoever reconnects, which
    /// turns the limit into an instruction to reconnect.
    idle_after: Duration,
}

#[derive(Debug)]
struct Inner {
    sessions: HashMap<u32, Session>,
    server: TokenBucket,
}

#[derive(Debug)]
struct Session {
    bucket: TokenBucket,
    last_ms: u64,
}

impl Quota {
    /// A quota with full buckets.
    #[must_use]
    pub fn new(per_session: Limit, server: Limit, now_ms: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                sessions: HashMap::new(),
                server: TokenBucket::new(server.rate, server.burst, now_ms),
            }),
            per_session,
            idle_after: Duration::from_secs(600),
        }
    }

    /// Charge one render, or say how long to wait.
    ///
    /// # Errors
    ///
    /// [`Refusal`], carrying the wait, so the person is told when rather than
    /// just no.
    pub fn admit(&self, session: u32, now_ms: u64) -> Result<(), Refusal> {
        let per_session = self.per_session;
        let idle_after = millis(self.idle_after);
        let mut inner = self.lock();

        inner
            .sessions
            .retain(|_, held| now_ms.saturating_sub(held.last_ms) < idle_after);

        let entry = inner.sessions.entry(session).or_insert_with(|| Session {
            bucket: TokenBucket::new(per_session.rate, per_session.burst, now_ms),
            last_ms: now_ms,
        });
        let mut session_probe = entry.bucket.clone();
        session_probe
            .take(now_ms)
            .map_err(|Throttled { retry_after }| Refusal::Session(retry_after))?;

        let mut server_probe = inner.server.clone();
        server_probe
            .take(now_ms)
            .map_err(|Throttled { retry_after }| Refusal::Server(retry_after))?;

        // Committed only now, when both have said yes.
        if let Some(entry) = inner.sessions.get_mut(&session) {
            entry.bucket = session_probe;
            entry.last_ms = now_ms;
        }
        inner.server = server_probe;
        Ok(())
    }

    /// How many sessions hold a bucket. For the gauge an operator reads.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.lock().sessions.len()
    }

    /// The buckets, never poisoned into a panic: the worst a recovered guard
    /// costs is one render's worth of confused accounting, and the alternative
    /// is the feature dying for the life of the process.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A duration in milliseconds, saturating.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generous() -> Limit {
        Limit {
            rate: Rate::per_second(100.0),
            burst: 100,
        }
    }

    #[test]
    fn one_session_cannot_hold_the_browser_by_itself() {
        // The case this exists for: somebody pastes a channel full of links to
        // a site that only renders. Their own bucket empties; everybody else's
        // is untouched.
        let quota = Quota::new(Limit::every(30.0, 3), generous(), 0);
        for _ in 0..3 {
            assert!(quota.admit(7, 0).is_ok());
        }
        match quota.admit(7, 0) {
            Err(Refusal::Session(wait)) => assert!(wait > Duration::ZERO),
            other => panic!("the fourth must be refused with a wait: {other:?}"),
        }
        assert!(
            quota.admit(8, 0).is_ok(),
            "somebody else's previews are not affected"
        );
    }

    #[test]
    fn a_crowd_inside_their_own_limits_is_still_bounded() {
        let quota = Quota::new(Limit::every(1.0, 5), Limit::every(10.0, 4), 0);
        for session in 0..4 {
            assert!(quota.admit(session, 0).is_ok());
        }
        match quota.admit(99, 0) {
            Err(Refusal::Server(wait)) => assert!(wait > Duration::ZERO),
            other => panic!("the server-wide bucket must bite: {other:?}"),
        }
    }

    #[test]
    fn a_token_is_not_spent_on_a_render_the_other_bucket_refuses() {
        // Both are probed before either is committed. Without this, a session
        // that trips the server-wide limit still pays a token of its own, and
        // that token bought nobody a preview.
        let quota = Quota::new(Limit::every(60.0, 2), Limit::every(60.0, 1), 0);
        assert!(quota.admit(1, 0).is_ok());
        assert!(matches!(quota.admit(2, 0), Err(Refusal::Server(_))));
        // Session 2 was refused by the *server* bucket, so its own is intact:
        // once the server bucket refills, its first render still works.
        assert!(quota.admit(2, 60_000).is_ok());
    }

    #[test]
    fn tokens_come_back_at_the_rate_the_operator_set() {
        let quota = Quota::new(Limit::every(30.0, 1), generous(), 0);
        assert!(quota.admit(4, 0).is_ok());
        assert!(
            quota.admit(4, 15_000).is_err(),
            "half a token is not a token"
        );
        assert!(quota.admit(4, 30_000).is_ok());
    }

    #[test]
    fn a_reconnect_does_not_hand_out_a_fresh_burst() {
        // The bucket outlives the session for exactly this reason.
        let quota = Quota::new(Limit::every(600.0, 1), generous(), 0);
        assert!(quota.admit(11, 0).is_ok());
        assert!(
            quota.admit(11, 1_000).is_err(),
            "the same session, one second later"
        );
        assert_eq!(quota.tracked(), 1);
    }

    #[test]
    fn a_refusal_says_when_rather_than_only_no() {
        let quota = Quota::new(Limit::every(30.0, 1), generous(), 0);
        assert!(quota.admit(2, 0).is_ok());
        let refusal = quota.admit(2, 0).expect_err("the bucket is empty");
        assert!(refusal.reason().contains("try again in"));
    }
}
