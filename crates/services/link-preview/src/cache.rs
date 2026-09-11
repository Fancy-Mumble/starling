//! The answer for a URL, kept so the next person to ask is not a second walk.
//!
//! [`quota`](crate::quota) says this service has nothing to cache, because "the
//! *page* is what a render produces and two people pasting the same link
//! seconds apart is rare enough not to build for". That is true of a *paste*
//! and false of everything else a client does with a link, which is where the
//! cost actually was:
//!
//! * **Rejoining a channel.** History comes back, every message in the viewport
//!   asks for its links again, and none of those links changed while the person
//!   was away. A channel with fifty links is fifty walks per join, per member.
//! * **The same link twice.** A client asks per *message*, so a link posted ten
//!   times is ten walks of the same ladder to the same host.
//! * **A crowd arriving together.** Twenty people reconnecting after a restart
//!   ask for the same history's links inside the same second, and a cache
//!   cannot help any of them, because none of the fetches has returned yet.
//!
//! So this is the other half of `gifs`'s [`Quota`](../../gifs/src/quota.rs) -
//! the cache and the coalescer - against the same three layers of cost the
//! ladder charges: sockets on every rung, and on the top rung a whole browser.
//!
//! # What is stored, and for how long
//!
//! The finished [`Preview`], not the page it was parsed from: the oEmbed ask,
//! the picture fetch, the icon fetch, the classification and the shrink are all
//! downstream of the fetch and all deterministic for one URL, so caching the
//! page would re-pay for them on every hit.
//!
//! Failures are stored too, and separately, on a much shorter clock. A host
//! that is down is down for everybody, and twenty clients retrying it on every
//! render is the thing that turns one outage into a load problem. Short,
//! because the whole point of the entry is that it should stop being believed
//! quickly - a negative cached as long as a card would mean one bad minute
//! costs a link its preview for the rest of the day.
//!
//! Refusals from the guard are *not* stored: [`vet`](crate::vet) rejects them
//! without a fetch, so there is no cost to save, and an entry would only be a
//! way for the deny list to go stale.
//!
//! # The key is the URL as asked
//!
//! Not the URL the walk ended on. A shortener and its target are two different
//! questions with the same answer, and the one a client will ask again is the
//! one it asked the first time.
//!
//! Normalisation is deliberately timid - the scheme and host lowercased, the
//! fragment dropped - because those are the only two rewrites that cannot
//! change which document is meant. Anything cleverer (sorting query parameters,
//! stripping tracking ones) risks a *wrong hit*, which is a card for a page
//! nobody linked, and the cost of a miss is only a fetch we were doing anyway.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use starling_proto_fancy::fancy::feature::{Preview, PreviewError, link_preview_envelope};

/// What one URL's answer is filed under.
///
/// A newtype rather than a bare `String` so the normalisation cannot be
/// forgotten at one call site and applied at another, which is the way a cache
/// quietly stops hitting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key(String);

impl Key {
    /// The key for `url`.
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self(normalise(url))
    }

    /// The normalised URL, for a log line that has to name it.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.0
    }
}

/// Lowercase the scheme and host, drop the fragment, leave everything else
/// byte-for-byte.
///
/// The path is **not** touched: hosts are case-insensitive and paths are not,
/// and a server that serves `/A` and `/a` as two documents is unusual but not
/// wrong. See the module note on why this stops here.
fn normalise(url: &str) -> String {
    /// What separates a scheme from the authority that follows it.
    const SEPARATOR: &str = "://";

    // The fragment never reaches the origin, so two URLs differing only after
    // `#` are one request. Split first, so a `#` inside a query is kept: a
    // fragment is everything after the *first* one.
    let without_fragment = url.split_once('#').map_or(url, |(head, _)| head);
    let trimmed = without_fragment.trim();
    let Some((scheme, after_scheme)) = trimmed.split_once(SEPARATOR) else {
        // Not a URL this service would have fetched anyway - `vet` will refuse
        // it. Filed as given so a malformed string still coalesces with itself.
        return trimmed.to_owned();
    };
    // The authority runs to the first `/` or `?`. Both have to be looked for:
    // `https://example.com?a=B` has a query and no path, and lowercasing to the
    // end of the string there would rewrite the query - which *is*
    // case-sensitive, and is often an identifier.
    let authority_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
    // `find` returns a char boundary, so this cannot split a codepoint.
    let (authority, tail) = after_scheme.split_at(authority_end);
    let mut out = String::with_capacity(trimmed.len());
    out.push_str(&scheme.to_lowercase());
    out.push_str(SEPARATOR);
    out.push_str(&authority.to_lowercase());
    out.push_str(tail);
    out
}

/// Somebody waiting for an answer to a URL somebody else is already walking.
#[derive(Debug, Clone)]
pub struct Waiter {
    /// The connection to answer.
    pub conn: u64,
    /// Their own correlation id, which is not the id of whoever started the
    /// walk - that is the whole reason this carries one.
    pub request_id: String,
    /// Their own spelling of the URL, which is not the key and not necessarily
    /// what anybody else waiting on it wrote. A failure is reported back as
    /// `"{url}: {reason}"` and the client matches that against what it sent, so
    /// the normalised key would be a string it does not recognise.
    pub url: String,
}

/// A finished answer, with the asker's name taken off it.
///
/// `request_id` belongs to one request and this outlives all of them, so it is
/// blanked on the way in and stamped back on the way out by [`Self::stamp`].
/// Storing it as it arrived is how a cache starts answering one client with
/// another client's correlation id.
#[derive(Debug, Clone)]
pub enum Answer {
    /// A card.
    Card(Box<Preview>),
    /// A walk that reached nothing, as the bare reason - the `"{url}: "` prefix
    /// the client is sent is put back by [`Self::stamp`], because the URL it
    /// names is the caller's spelling rather than the normalised key.
    Failed(String),
}

impl Answer {
    /// The card for `preview`, with the request id stripped.
    #[must_use]
    pub fn card(mut preview: Preview) -> Self {
        preview.request_id = String::new();
        Self::Card(Box::new(preview))
    }

    /// This answer addressed to one request.
    #[must_use]
    pub fn stamp(&self, request_id: &str, url: &str) -> link_preview_envelope::Body {
        match self {
            Self::Card(preview) => {
                let mut preview = (**preview).clone();
                preview.request_id = request_id.to_owned();
                link_preview_envelope::Body::Preview(preview)
            }
            Self::Failed(reason) => link_preview_envelope::Body::Error(PreviewError {
                request_id: request_id.to_owned(),
                reason: format!("{url}: {reason}"),
            }),
        }
    }

    /// Roughly what this costs to keep, for the byte budget.
    ///
    /// Dominated by the two pictures - a thumbnail and an icon - which is why
    /// an entry budget alone would not bound anything: ten thousand text-only
    /// cards and ten thousand cards carrying a 64 KiB thumbnail are the same
    /// number of entries and three orders of magnitude apart in memory.
    fn weight(&self) -> usize {
        match self {
            Self::Card(preview) => {
                preview.image.len()
                    + preview.icon.len()
                    + preview.title.len()
                    + preview.description.len()
                    + preview.url.len()
                    + preview.site.len()
            }
            Self::Failed(reason) => reason.len(),
        }
    }
}

/// The cache and the coalescer, behind one lock.
///
/// One lock rather than two, for the reason `gifs` gives: both are touched on
/// the same path in the same order, and two locks taken in sequence is two
/// chances to acquire them in a different order somewhere else.
#[derive(Debug)]
pub struct Cache {
    inner: Mutex<Inner>,
    /// How long a card is believed.
    ttl: Duration,
    /// How long a failure is believed. Much shorter; see the module note.
    negative_ttl: Duration,
    /// The most entries kept, whatever they weigh.
    entries: usize,
    /// The most bytes kept, however few entries that is.
    budget: usize,
}

#[derive(Debug, Default)]
struct Inner {
    cache: HashMap<Key, Cached>,
    in_flight: HashMap<Key, Vec<Waiter>>,
    /// The sum of every entry's weight, kept rather than recomputed: eviction
    /// runs on every store, and summing the map each time would make a store
    /// cost the size of the cache.
    held: usize,
}

#[derive(Debug, Clone)]
struct Cached {
    answer: Answer,
    expires_at_ms: u64,
    weight: usize,
}

impl Cache {
    /// A cache with nothing in it.
    ///
    /// `entries` or `budget` of zero, or a zero `ttl`, switches it off: every
    /// lookup misses and every store is dropped. Coalescing still works, and
    /// deliberately - it costs no memory and it is what stops a crowd arriving
    /// together from becoming a crowd of fetches.
    #[must_use]
    pub fn new(ttl: Duration, negative_ttl: Duration, entries: usize, budget: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            ttl,
            negative_ttl,
            entries,
            budget,
        }
    }

    /// The lock, never poisoned into a panic.
    ///
    /// A poisoned cache would take every later preview down with it; recovering
    /// the guard means the worst case is one entry's worth of confused
    /// accounting rather than the feature dying for the life of the process.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The answer for `key`, if one is held and still believed.
    #[must_use]
    pub fn get(&self, key: &Key, now_ms: u64) -> Option<Answer> {
        let mut inner = self.lock();
        let entry = inner.cache.get(key)?;
        if entry.expires_at_ms <= now_ms {
            // Dropped on the way past rather than left to the sweep: a stale
            // entry that stays is one the next caller checks again.
            if let Some(gone) = inner.cache.remove(key) {
                inner.held = inner.held.saturating_sub(gone.weight);
            }
            return None;
        }
        Some(entry.answer.clone())
    }

    /// Register `waiter` against `key`.
    ///
    /// Returns `true` when this caller is the one that must go and walk, and
    /// `false` when an identical walk is already running and this waiter has
    /// been attached to it. Either way the waiter is recorded, so
    /// [`Self::finish`] answers everybody including the one that walked.
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

    /// Everybody waiting on `key`, and the end of that walk.
    ///
    /// Must be called for **every** walk that [`Self::begin`] said to start,
    /// including the ones that failed: an entry left behind here is a URL that
    /// never fetches again, because every later caller attaches to a walk that
    /// is not running.
    #[must_use]
    pub fn finish(&self, key: &Key) -> Vec<Waiter> {
        self.lock().in_flight.remove(key).unwrap_or_default()
    }

    /// Remember `answer` as what `key` resolves to.
    pub fn store(&self, key: &Key, answer: &Answer, now_ms: u64) {
        let ttl = match *answer {
            Answer::Card(_) => self.ttl,
            Answer::Failed(_) => self.negative_ttl,
        };
        if self.entries == 0 || self.budget == 0 || ttl.is_zero() {
            return;
        }
        let weight = answer.weight();
        // An entry that alone exceeds the whole budget is not stored: keeping
        // it would evict everything else to hold one card.
        if weight > self.budget {
            return;
        }
        let expires_at_ms =
            now_ms.saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
        let mut inner = self.lock();
        if let Some(replaced) = inner.cache.insert(
            key.clone(),
            Cached {
                answer: answer.clone(),
                expires_at_ms,
                weight,
            },
        ) {
            inner.held = inner.held.saturating_sub(replaced.weight);
        }
        inner.held = inner.held.saturating_add(weight);
        inner.evict(now_ms, self.entries, self.budget);
    }

    /// How many entries are held, for the pressure gauge.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().cache.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many bytes are held, for the pressure gauge.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.lock().held
    }
}

impl Inner {
    /// Keep the cache inside both caps: expired entries first, then the soonest
    /// to expire, which for one fixed TTL is the oldest.
    fn evict(&mut self, now_ms: u64, entries: usize, budget: usize) {
        self.cache.retain(|_, entry| {
            let live = entry.expires_at_ms > now_ms;
            if !live {
                self.held = self.held.saturating_sub(entry.weight);
            }
            live
        });
        while self.cache.len() > entries || self.held > budget {
            let Some(oldest) = self
                .cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at_ms)
                .map(|(key, _)| key.clone())
            else {
                return;
            };
            if let Some(gone) = self.cache.remove(&oldest) {
                self.held = self.held.saturating_sub(gone.weight);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(title: &str) -> Preview {
        Preview {
            request_id: "whoever-asked-first".to_owned(),
            url: "https://example.com/a".to_owned(),
            title: title.to_owned(),
            ..Preview::default()
        }
    }

    fn cache() -> Cache {
        Cache::new(
            Duration::from_secs(3600),
            Duration::from_secs(60),
            8,
            1024 * 1024,
        )
    }

    #[test]
    fn a_stored_card_answers_the_next_asker() {
        let cache = cache();
        let key = Key::new("https://example.com/a");
        cache.store(&key, &Answer::card(preview("A page")), 0);
        let hit = cache.get(&key, 1_000).expect("the card is still believed");
        let link_preview_envelope::Body::Preview(card) = hit.stamp("mine", "https://example.com/a")
        else {
            panic!("a card stamps as a card");
        };
        assert_eq!(card.title, "A page");
        // The whole reason `Answer` blanks it: without this the second asker is
        // answered with the first asker's correlation id and drops the card.
        assert_eq!(card.request_id, "mine");
    }

    #[test]
    fn a_card_is_forgotten_when_its_ttl_runs_out() {
        let cache = cache();
        let key = Key::new("https://example.com/a");
        cache.store(&key, &Answer::card(preview("A page")), 0);
        assert!(cache.get(&key, 3_600_000).is_none(), "expired at the tick");
        assert!(cache.is_empty(), "and dropped on the way past");
    }

    #[test]
    fn a_failure_is_believed_for_much_less_time_than_a_card() {
        // The point of the separate clock: one bad minute must not cost a link
        // its preview for the rest of the day.
        let cache = cache();
        let key = Key::new("https://example.com/down");
        cache.store(
            &key,
            &Answer::Failed("the host did not answer".to_owned()),
            0,
        );
        assert!(cache.get(&key, 59_000).is_some(), "believed for a moment");
        assert!(cache.get(&key, 61_000).is_none(), "and then not");
    }

    #[test]
    fn a_failure_names_the_url_the_caller_spelled() {
        let cache = cache();
        let key = Key::new("https://EXAMPLE.com/down");
        cache.store(
            &key,
            &Answer::Failed("the host did not answer".to_owned()),
            0,
        );
        let hit = cache.get(&key, 0).expect("held");
        let link_preview_envelope::Body::Error(error) =
            hit.stamp("mine", "https://EXAMPLE.com/down")
        else {
            panic!("a failure stamps as an error");
        };
        // Not the normalised key: the client matches this against what it sent.
        assert_eq!(
            error.reason,
            "https://EXAMPLE.com/down: the host did not answer"
        );
    }

    #[test]
    fn the_second_asker_attaches_rather_than_walking_again() {
        let cache = cache();
        let key = Key::new("https://example.com/a");
        let first = Waiter {
            conn: 1,
            request_id: "one".to_owned(),
            url: "https://example.com/a".to_owned(),
        };
        let second = Waiter {
            conn: 2,
            request_id: "two".to_owned(),
            url: "https://example.com/a".to_owned(),
        };
        assert!(cache.begin(&key, first), "the first caller walks");
        assert!(!cache.begin(&key, second), "the second attaches to it");
        let waiting = cache.finish(&key);
        assert_eq!(waiting.len(), 2, "and both are answered");
        assert_eq!(waiting[0].request_id, "one");
        assert_eq!(waiting[1].request_id, "two");
    }

    #[test]
    fn finishing_releases_the_url_for_a_later_walk() {
        // The failure this rules out: an in-flight entry left behind is a URL
        // that never fetches again, because every later caller waits on a walk
        // that is not running.
        let cache = cache();
        let key = Key::new("https://example.com/a");
        assert!(cache.begin(
            &key,
            Waiter {
                conn: 1,
                request_id: "one".to_owned(),
                url: "https://example.com/a".to_owned(),
            }
        ));
        let _ = cache.finish(&key);
        assert!(
            cache.begin(
                &key,
                Waiter {
                    conn: 2,
                    request_id: "two".to_owned(),
                    url: "https://example.com/a".to_owned(),
                }
            ),
            "the next caller walks rather than waiting forever"
        );
    }

    #[test]
    fn the_same_link_spelled_two_ways_is_one_entry() {
        let cache = cache();
        cache.store(
            &Key::new("https://Example.COM/a"),
            &Answer::card(preview("A page")),
            0,
        );
        assert!(
            cache
                .get(&Key::new("https://example.com/a#section"), 0)
                .is_some(),
            "the host's case and the fragment are not part of the question"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn the_path_is_left_alone() {
        // The other half of the timid rule: a host that serves `/A` and `/a` as
        // two documents is unusual, not wrong, and a wrong hit is a card for a
        // page nobody linked.
        let cache = cache();
        cache.store(
            &Key::new("https://example.com/A"),
            &Answer::card(preview("Upper")),
            0,
        );
        assert!(cache.get(&Key::new("https://example.com/a"), 0).is_none());
    }

    #[test]
    fn a_query_string_is_part_of_the_question() {
        let cache = cache();
        cache.store(
            &Key::new("https://example.com/watch?v=one"),
            &Answer::card(preview("One")),
            0,
        );
        assert!(
            cache
                .get(&Key::new("https://example.com/watch?v=two"), 0)
                .is_none(),
            "two videos are not one card"
        );
    }

    #[test]
    fn the_entry_cap_holds() {
        let cache = Cache::new(
            Duration::from_secs(3600),
            Duration::from_secs(60),
            2,
            1024 * 1024,
        );
        for (at, url) in ["a", "b", "c"].iter().enumerate() {
            cache.store(
                &Key::new(&format!("https://example.com/{url}")),
                &Answer::card(preview(url)),
                at as u64,
            );
        }
        assert_eq!(cache.len(), 2, "the oldest is evicted");
        assert!(
            cache.get(&Key::new("https://example.com/a"), 0).is_none(),
            "and it is the oldest that went"
        );
    }

    #[test]
    fn the_byte_budget_holds_where_the_entry_cap_would_not() {
        // Ten thousand text cards and ten thousand cards carrying a thumbnail
        // are the same number of entries and nowhere near the same memory.
        let cache = Cache::new(Duration::from_secs(3600), Duration::from_secs(60), 100, 200);
        let heavy = |name: &str| {
            let mut card = preview(name);
            card.image = vec![0u8; 90];
            Answer::card(card)
        };
        for (at, url) in ["a", "b", "c"].iter().enumerate() {
            cache.store(
                &Key::new(&format!("https://example.com/{url}")),
                &heavy(url),
                at as u64,
            );
        }
        assert!(cache.len() < 3, "the budget evicted before the entry cap");
        assert!(cache.held_bytes() <= 200);
    }

    #[test]
    fn an_entry_larger_than_the_whole_budget_is_not_stored() {
        // Storing it would evict everything else to hold one card.
        let cache = Cache::new(Duration::from_secs(3600), Duration::from_secs(60), 100, 64);
        let mut card = preview("huge");
        card.image = vec![0u8; 4096];
        cache.store(
            &Key::new("https://example.com/huge"),
            &Answer::card(card),
            0,
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn replacing_an_entry_does_not_double_count_its_bytes() {
        let cache = cache();
        let key = Key::new("https://example.com/a");
        let heavy = || {
            let mut card = preview("A page");
            card.image = vec![0u8; 500];
            Answer::card(card)
        };
        cache.store(&key, &heavy(), 0);
        let once = cache.held_bytes();
        cache.store(&key, &heavy(), 1);
        assert_eq!(cache.held_bytes(), once, "a re-store is not an addition");
    }

    #[test]
    fn a_switched_off_cache_still_coalesces() {
        // Coalescing costs no memory, and it is what stops a crowd arriving
        // together from becoming a crowd of fetches.
        let cache = Cache::new(Duration::ZERO, Duration::ZERO, 0, 0);
        let key = Key::new("https://example.com/a");
        cache.store(&key, &Answer::card(preview("A page")), 0);
        assert!(cache.get(&key, 0).is_none(), "nothing is kept");
        assert!(cache.begin(
            &key,
            Waiter {
                conn: 1,
                request_id: "one".to_owned(),
                url: "https://example.com/a".to_owned(),
            }
        ));
        assert!(
            !cache.begin(
                &key,
                Waiter {
                    conn: 2,
                    request_id: "two".to_owned(),
                    url: "https://example.com/a".to_owned(),
                }
            ),
            "but the second asker still attaches"
        );
    }
}
