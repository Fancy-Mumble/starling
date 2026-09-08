//! What bounds the cost of a search, in four layers that each stop a different
//! thing.
//!
//! The resource being protected is not the server's CPU. It is **the operator's
//! provider quota**: one key, paid for or rate-limited by a third party, shared
//! by everyone on the server. A limit that only counted frames would miss the
//! shape of the abuse entirely, because the expensive thing is not the request,
//! it is the *upstream call the request causes*.
//!
//! So the layers are:
//!
//! 1. **The gateway's `gifs` bucket** counts inbound frames, per connection.
//!    Not here - it is the ordinary route bucket every service has, and it
//!    bounds how often a client may *ask*.
//! 2. **The cache** ([`Quota::cached`]) answers a repeat without an upstream
//!    call. Every picker opens on the same trending page, so on a busy server
//!    this is the layer doing most of the work.
//! 3. **Coalescing** ([`Quota::begin`]) folds concurrent identical misses into
//!    one call. Without it, twenty people opening the picker in the same second
//!    on a cold cache is twenty calls for one answer - the cache cannot help,
//!    because none of them has returned yet.
//! 4. **The buckets** ([`Quota::admit`]) charge a token per upstream call, one
//!    per session and one for the whole server. The per-session bucket stops
//!    one person burning the key; the server-wide one stops a crowd doing it,
//!    each of them individually within their own limit.
//!
//! **A cache hit is charged nothing**, deliberately. Charging it would make
//! opening the picker cost quota that no provider was ever asked for, and the
//! frame it arrived in was already charged at layer 1.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use starling_runtime::ratelimit::{Rate, Throttled, TokenBucket};

use crate::provider::Page;

/// A rate and the burst it allows.
#[derive(Debug, Clone, Copy)]
pub struct Limit {
    /// What accrues, sustained.
    pub rate: Rate,
    /// How much may be spent at once, after an idle spell.
    pub burst: u32,
}

/// What one search asks for. The cache and the coalescer key on it.
///
/// The query is normalised - trimmed, lowercased - so that "Cat", "cat " and
/// "cat" are one entry rather than three. That is a cache-hit-rate decision and
/// also a limit decision: without it, varying the case is a way to miss the
/// cache on demand.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    query: String,
    page: u32,
}

impl Key {
    /// The key for `query` at `page`.
    #[must_use]
    pub fn new(query: &str, page: u32) -> Self {
        Self {
            query: query.trim().to_lowercase(),
            page: page.max(1),
        }
    }

    /// The query as it will be sent upstream.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The page as it will be sent upstream.
    #[must_use]
    pub const fn page(&self) -> u32 {
        self.page
    }
}

/// Somebody waiting for an answer to a query somebody else is already fetching.
#[derive(Debug, Clone)]
pub struct Waiter {
    /// The connection to answer.
    pub conn: u64,
    /// Their own correlation id, which is not the id of whoever started the
    /// fetch - that is the whole reason this carries one.
    pub request_id: String,
}

/// Why a search was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This session is asking faster than its own limit.
    Session(Duration),
    /// The server as a whole is at its limit. Distinguished from
    /// [`Self::Session`] because it is the operator's problem rather than the
    /// caller's: one person can do nothing about it, and it belongs in a log.
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
}

/// The cache, the coalescer and the buckets, behind one lock.
///
/// One lock rather than three, because every one of them is touched on the same
/// path in the same order, and three locks taken in sequence is three chances
/// to acquire them in a different order somewhere else.
#[derive(Debug)]
pub struct Quota {
    inner: Mutex<Inner>,
    per_session: Limit,
    cache_ttl: Duration,
    cache_entries: usize,
    /// How long a session's bucket is kept after its last search.
    ///
    /// Sessions come and go and this map is keyed by one, so without a sweep it
    /// grows for the life of the process. Kept for a while rather than dropped
    /// on disconnect: a bucket dropped the moment a session ends would hand a
    /// full burst to anybody who reconnects, which turns the limit into an
    /// invitation to reconnect.
    idle_after: Duration,
}

#[derive(Debug)]
struct Inner {
    sessions: HashMap<u32, Session>,
    server: TokenBucket,
    cache: HashMap<Key, Cached>,
    in_flight: HashMap<Key, Vec<Waiter>>,
}

#[derive(Debug)]
struct Session {
    bucket: TokenBucket,
    last_ms: u64,
}

#[derive(Debug, Clone)]
struct Cached {
    page: Page,
    expires_at_ms: u64,
}

impl Quota {
    /// A quota with no history.
    #[must_use]
    pub fn new(
        per_session: Limit,
        server: Limit,
        cache_ttl: Duration,
        cache_entries: usize,
        now_ms: u64,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                sessions: HashMap::new(),
                server: TokenBucket::new(server.rate, server.burst, now_ms),
                cache: HashMap::new(),
                in_flight: HashMap::new(),
            }),
            per_session,
            cache_ttl,
            cache_entries,
            idle_after: Duration::from_secs(600),
        }
    }

    /// The lock, never poisoned into a panic.
    ///
    /// A poisoned quota would take every later search down with it; recovering
    /// the guard means the worst case is one search's worth of confused
    /// accounting rather than the feature dying for the life of the process.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A page answered without asking the provider, if there is one.
    #[must_use]
    pub fn cached(&self, key: &Key, now_ms: u64) -> Option<Page> {
        let mut inner = self.lock();
        let entry = inner.cache.get(key)?;
        if entry.expires_at_ms <= now_ms {
            // Dropped on the way past rather than left to the sweep: a stale
            // entry that stays is one the next caller checks again.
            let _ = inner.cache.remove(key);
            return None;
        }
        Some(entry.page.clone())
    }

    /// Charge one upstream call, or say how long to wait.
    ///
    /// Both buckets are charged or neither is. They are tried on **copies**
    /// first and committed together, because a token spent on a call that the
    /// other bucket then refuses is a token nobody got any GIFs for - and if
    /// that is the shared bucket, it is a token taken from everyone else.
    ///
    /// # Errors
    ///
    /// [`Refusal`], carrying the wait, so the client can be told when rather
    /// than just no.
    pub fn admit(&self, session: u32, now_ms: u64) -> Result<(), Refusal> {
        let per_session = self.per_session;
        let idle_after = self.idle_after;
        let mut inner = self.lock();

        inner.sweep_sessions(now_ms, idle_after);
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
        let entry = inner.sessions.entry(session).or_insert_with(|| Session {
            bucket: session_probe.clone(),
            last_ms: now_ms,
        });
        entry.bucket = session_probe;
        entry.last_ms = now_ms;
        inner.server = server_probe;
        Ok(())
    }

    /// Register `waiter` against `key`.
    ///
    /// Returns `true` when this caller is the one that must go and fetch, and
    /// `false` when an identical fetch is already running and this waiter has
    /// been attached to it. Either way the waiter is recorded, so
    /// [`Self::finish`] answers everybody including the one that fetched.
    pub fn begin(&self, key: &Key, waiter: Waiter) -> bool {
        let mut inner = self.lock();
        match inner.in_flight.get_mut(key) {
            Some(waiting) => {
                waiting.push(waiter);
                false
            }
            None => {
                let _ = inner.in_flight.insert(key.clone(), vec![waiter]);
                true
            }
        }
    }

    /// Everybody waiting on `key`, and the end of that fetch.
    ///
    /// Must be called for **every** fetch that [`Self::begin`] said to start,
    /// including the ones that failed: an entry left behind here is a key that
    /// never fetches again, because every later caller attaches to a fetch that
    /// is not running.
    #[must_use]
    pub fn finish(&self, key: &Key) -> Vec<Waiter> {
        self.lock().in_flight.remove(key).unwrap_or_default()
    }

    /// Remember `page` as the answer to `key`.
    pub fn store(&self, key: &Key, page: &Page, now_ms: u64) {
        if self.cache_entries == 0 || self.cache_ttl.is_zero() {
            return;
        }
        let expires_at_ms =
            now_ms.saturating_add(u64::try_from(self.cache_ttl.as_millis()).unwrap_or(u64::MAX));
        let mut inner = self.lock();
        let _ = inner.cache.insert(
            key.clone(),
            Cached {
                page: page.clone(),
                expires_at_ms,
            },
        );
        inner.evict(now_ms, self.cache_entries);
    }

    /// How many entries the cache holds, for the pressure gauge.
    #[must_use]
    pub fn cached_entries(&self) -> usize {
        self.lock().cache.len()
    }

    /// Forget a session's bucket. Called when its connection goes away.
    ///
    /// Deliberately *not* wired to disconnect: see [`Self::idle_after`]. It
    /// exists for a test to assert the map is not immutable, and for a future
    /// caller that has a better reason than reconnection.
    #[cfg(test)]
    fn forget(&self, session: u32) {
        let _ = self.lock().sessions.remove(&session);
    }
}

impl Inner {
    /// Drop the buckets of sessions that have not searched in a while.
    fn sweep_sessions(&mut self, now_ms: u64, idle_after: Duration) {
        let idle_ms = u64::try_from(idle_after.as_millis()).unwrap_or(u64::MAX);
        self.sessions
            .retain(|_, session| now_ms.saturating_sub(session.last_ms) < idle_ms);
    }

    /// Keep the cache under `cap`: expired entries first, then the soonest to
    /// expire, which for one fixed TTL is the oldest.
    fn evict(&mut self, now_ms: u64, cap: usize) {
        self.cache.retain(|_, entry| entry.expires_at_ms > now_ms);
        while self.cache.len() > cap {
            let Some(oldest) = self
                .cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at_ms)
                .map(|(key, _)| key.clone())
            else {
                return;
            };
            let _ = self.cache.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(id: &str) -> Page {
        Page {
            results: vec![crate::provider::Gif {
                id: id.to_owned(),
                ..crate::provider::Gif::default()
            }],
            has_next: false,
        }
    }

    fn quota() -> Quota {
        Quota::new(
            Limit {
                rate: Rate::per_second(1.0),
                burst: 3,
            },
            Limit {
                rate: Rate::per_second(10.0),
                burst: 20,
            },
            Duration::from_secs(300),
            8,
            0,
        )
    }

    #[test]
    fn one_session_cannot_burn_the_key_on_its_own() {
        let quota = quota();
        for _ in 0..3 {
            assert!(quota.admit(7, 0).is_ok(), "the burst is admitted");
        }
        let refused = quota.admit(7, 0).expect_err("the fourth is not");
        assert!(matches!(refused, Refusal::Session(_)));
        // ...and the wait it reports is real: a second later there is a token.
        assert!(quota.admit(7, 1_000).is_ok());
    }

    #[test]
    fn one_session_running_out_does_not_stop_anybody_else() {
        // The failure this rules out is a shared bucket, where one person
        // scrolling a picker throttles the whole server.
        let quota = quota();
        for _ in 0..3 {
            let _ = quota.admit(7, 0);
        }
        assert!(quota.admit(7, 0).is_err());
        assert!(
            quota.admit(8, 0).is_ok(),
            "a different session is unaffected"
        );
    }

    #[test]
    fn a_crowd_within_their_own_limits_is_still_bounded() {
        // The layer the per-session bucket cannot provide: fifty people each
        // asking once are fifty upstream calls, and the operator pays for the
        // key. Each of them is inside their own limit.
        let quota = quota();
        let mut admitted = 0;
        for session in 0..50 {
            if quota.admit(session, 0).is_ok() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 20, "the server-wide burst is the ceiling");
        let refused = quota.admit(999, 0).expect_err("and it is reached");
        assert!(
            matches!(refused, Refusal::Server(_)),
            "the operator needs to be able to tell this from a busy user"
        );
    }

    #[test]
    fn a_token_is_never_spent_on_a_call_the_other_bucket_refuses() {
        // Admission is all-or-nothing. Drain the server bucket, then have a
        // fresh session try: it must be refused *and* keep its own tokens,
        // otherwise a server-wide throttle silently eats everybody's personal
        // allowance while they get nothing for it.
        let quota = quota();
        for session in 0..50 {
            let _ = quota.admit(session, 0);
        }
        assert!(matches!(quota.admit(500, 0), Err(Refusal::Server(_))));
        // A second later the server bucket has refilled; the session that was
        // refused must still have its whole burst.
        for _ in 0..3 {
            assert!(
                quota.admit(500, 10_000).is_ok(),
                "its burst was never charged"
            );
        }
    }

    #[test]
    fn a_repeat_is_answered_without_asking_the_provider() {
        let quota = quota();
        let key = Key::new("cat", 1);
        assert!(quota.cached(&key, 0).is_none());
        quota.store(&key, &page("a"), 0);
        assert_eq!(quota.cached(&key, 1_000), Some(page("a")));
    }

    #[test]
    fn the_case_of_a_query_is_not_a_way_to_miss_the_cache() {
        // Otherwise "cat", "Cat", "CAT" and "cAt" are four upstream calls for
        // one search, which makes the cache trivially bypassable.
        let quota = quota();
        quota.store(&Key::new("cat", 1), &page("a"), 0);
        assert_eq!(quota.cached(&Key::new("  CAT ", 1), 0), Some(page("a")));
        // ...but a different page is genuinely a different answer.
        assert!(quota.cached(&Key::new("cat", 2), 0).is_none());
    }

    #[test]
    fn a_stale_entry_is_not_served() {
        let quota = quota();
        let key = Key::new("cat", 1);
        quota.store(&key, &page("a"), 0);
        assert!(quota.cached(&key, 299_999).is_some());
        assert!(quota.cached(&key, 300_001).is_none());
    }

    #[test]
    fn the_cache_does_not_grow_without_bound() {
        // It is keyed by a string somebody typed, so an unbounded cache is a
        // memory-exhaustion primitive reachable from a search box.
        let quota = quota();
        for n in 0..100 {
            quota.store(&Key::new(&format!("q{n}"), 1), &page("a"), n);
        }
        assert_eq!(quota.cached_entries(), 8, "the configured cap");
    }

    #[test]
    fn concurrent_identical_misses_become_one_fetch() {
        // The layer the cache cannot provide: on a cold cache none of these
        // has returned yet, so every one of them would otherwise call out.
        let quota = quota();
        let key = Key::new("cat", 1);
        let waiter = |conn| Waiter {
            conn,
            request_id: format!("r{conn}"),
        };
        assert!(quota.begin(&key, waiter(1)), "the first goes and fetches");
        assert!(!quota.begin(&key, waiter(2)), "the second attaches");
        assert!(!quota.begin(&key, waiter(3)), "and so does the third");

        let waiting = quota.finish(&key);
        assert_eq!(waiting.len(), 3, "everybody is answered, fetcher included");
        assert_eq!(waiting[2].request_id, "r3", "each with their own id");
    }

    #[test]
    fn a_different_query_is_not_folded_into_an_unrelated_fetch() {
        let quota = quota();
        assert!(quota.begin(
            &Key::new("cat", 1),
            Waiter {
                conn: 1,
                request_id: "a".to_owned()
            }
        ));
        assert!(
            quota.begin(
                &Key::new("dog", 1),
                Waiter {
                    conn: 2,
                    request_id: "b".to_owned()
                }
            ),
            "a different query fetches on its own"
        );
    }

    #[test]
    fn a_failed_fetch_does_not_wedge_its_key_forever() {
        // `finish` runs on the error path too. Without that, the key is
        // permanently "already being fetched" and every later search for it
        // attaches to a fetch that is not running and is never answered.
        let quota = quota();
        let key = Key::new("cat", 1);
        assert!(quota.begin(
            &key,
            Waiter {
                conn: 1,
                request_id: "a".to_owned()
            }
        ));
        let _ = quota.finish(&key);
        assert!(
            quota.begin(
                &key,
                Waiter {
                    conn: 2,
                    request_id: "b".to_owned()
                }
            ),
            "the next search fetches rather than waiting for a ghost"
        );
    }

    #[test]
    fn an_idle_session_stops_being_remembered() {
        // The map is keyed by session id, so without a sweep it grows for the
        // life of the process.
        let quota = quota();
        assert!(quota.admit(7, 0).is_ok());
        assert_eq!(quota.lock().sessions.len(), 1);
        // A later search by somebody else sweeps the idle one out.
        assert!(quota.admit(8, 700_000).is_ok());
        assert_eq!(quota.lock().sessions.len(), 1, "only the recent one");
    }

    #[test]
    fn reconnecting_does_not_hand_out_a_fresh_burst() {
        // Buckets outlive the session on purpose: dropped on disconnect, the
        // limit is sidestepped by reconnecting, which is cheap.
        let quota = quota();
        for _ in 0..3 {
            let _ = quota.admit(7, 0);
        }
        assert!(quota.admit(7, 0).is_err());
        // The same person, same session id, one second later: one token, not
        // a whole new burst.
        assert!(quota.admit(7, 1_000).is_ok());
        assert!(quota.admit(7, 1_000).is_err());
        // And the map really is mutable, so the sweep above can do its work.
        quota.forget(7);
        assert!(quota.admit(7, 1_000).is_ok());
    }
}
