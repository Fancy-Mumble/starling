//! Ask honestly first, escalate only when that fails, and remember which was
//! needed.
//!
//! There is no one way to fetch a page any more. What a site returns depends on
//! what the fetch claims to be and what its handshake looks like, and the four
//! answers are different enough that the choice cannot be made once and written
//! into a constant:
//!
//! | rung | what it is | measured, 2026-09-08 |
//! |---|---|---|
//! | [`Rung::Honest`] | our own name | most of the web, `YouTube` and tagesschau included |
//! | [`Rung::Crawler`] | Discord's crawler | the only rung Reddit gives a card to |
//! | [`Rung::Browser`] | a browser's user-agent | for sites that check the string but not the handshake |
//! | [`Rung::Headless`] | an actual browser | the only rung idealo (Akamai) gives anything to |
//!
//! Reddit is the case that shapes the whole design: an honest fetch gets an
//! eight-kilobyte script shell whose title is "Reddit", with no description and
//! no image; `Discordbot` gets the full card; and a *browser* user-agent gets
//! the shell again. So the ladder is not "cheap to expensive" alone, and a rung
//! cannot be judged by whether the fetch succeeded - the shell is a 200. It is
//! judged by whether the card is worth showing, which is [`Card::informative`].
//!
//! # Why we start honest
//!
//! The old default announced itself as Discord's crawler on every request,
//! which is a lie told to every site on the web to make a few of them answer.
//! Telling it first, and only where being honest demonstrably does not work, is
//! a smaller lie for the same previews - and the memory below means each site
//! is asked honestly again later, in case it stopped needing the lie.
//!
//! # The memory
//!
//! Walking four rungs on every paste of the same host is three wasted requests
//! per link. [`Memory`] records which rung produced a card for a host and
//! starts there next time.
//!
//! It **expires**, and that is the point rather than an implementation detail.
//! A site's defences change, and a memory that only ever learned to escalate
//! would keep a host on the browser for the life of the process after one bad
//! afternoon. So a learned rung is trusted for a while and then re-probed from
//! the cheapest rung, which is the only way a host can ever come back down.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::parse::Card;

/// A browser's user-agent, for the rung that is a lie about the client but not
/// yet a whole browser.
///
/// Some sites read the string and nothing else; those are answered by this. The
/// ones that fingerprint the TLS handshake are not, and no string reaches them
/// - that is what [`Rung::Headless`] is for.
pub const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

/// What this server calls itself when it is not pretending to be anything.
///
/// The first rung, and the one an operator can replace: a server that would
/// rather be identifiable by name and contact address than by version says so
/// with `preview_user_agent`.
pub const HONEST_USER_AGENT: &str = "Mozilla/5.0 (compatible; StarlingBot/0.2; \
     +https://github.com/fancy-mumble/starling)";

/// One way of asking for a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rung {
    /// Our own name.
    Honest,
    /// Discord's crawler, which several large sites publish metadata to and
    /// nobody else.
    Crawler,
    /// A browser's user-agent, on an HTTP client that is not a browser.
    Browser,
    /// A real browser, in the `render` service.
    Headless,
}

impl Rung {
    /// Every rung, cheapest and most honest first.
    pub const ALL: &'static [Self] = &[Self::Honest, Self::Crawler, Self::Browser, Self::Headless];

    /// The name an operator writes in `preview_ladder`.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Honest => "honest",
            Self::Crawler => "crawler",
            Self::Browser => "browser",
            Self::Headless => "headless",
        }
    }

    /// The rung an operator named, if it is one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().to_ascii_lowercase();
        Self::ALL.iter().copied().find(|rung| rung.key() == text)
    }

    /// What this rung calls itself, or `None` for the rung that is not a fetch.
    #[must_use]
    pub fn user_agent<'a>(self, honest: &'a str) -> Option<&'a str>
    where
        'static: 'a,
    {
        match self {
            Self::Honest => Some(honest),
            Self::Crawler => Some(starling_outbound::DEFAULT_USER_AGENT),
            Self::Browser => Some(BROWSER_USER_AGENT),
            Self::Headless => None,
        }
    }
}

/// The rungs this server will climb, in order.
#[derive(Debug, Clone)]
pub struct Ladder {
    rungs: Vec<Rung>,
}

impl Default for Ladder {
    /// Every rung a fetch can do, and not the browser.
    ///
    /// The browser is off until an operator asks for it: it is a second
    /// container, a few hundred megabytes and a renderer running a stranger's
    /// script, none of which should arrive because somebody upgraded.
    fn default() -> Self {
        Self {
            rungs: vec![Rung::Honest, Rung::Crawler, Rung::Browser],
        }
    }
}

impl Ladder {
    /// Read an operator's list, keeping their order and dropping what they did
    /// not name.
    ///
    /// An empty or unreadable setting is [`Self::default`]: a typo in one entry
    /// must not switch previews off, and a server with no ladder at all would
    /// fetch nothing while looking configured.
    #[must_use]
    pub fn parse(spec: &str) -> Self {
        let mut rungs: Vec<Rung> = Vec::new();
        for name in spec.split(',') {
            if name.trim().is_empty() {
                continue;
            }
            match Rung::parse(name) {
                // Kept in the operator's order, and each rung once: a list that
                // repeats a rung would fetch the same way twice.
                Some(rung) if !rungs.contains(&rung) => rungs.push(rung),
                Some(_) => {}
                None => tracing::warn!(rung = name, "preview_ladder names no such rung"),
            }
        }
        if rungs.is_empty() {
            return Self::default();
        }
        Self { rungs }
    }

    /// The rungs to try, beginning at `start` or at the cheapest if that rung
    /// is not on this ladder.
    pub fn from(&self, start: Rung) -> impl Iterator<Item = Rung> + '_ {
        let at = self
            .rungs
            .iter()
            .position(|rung| *rung == start)
            .unwrap_or(0);
        self.rungs.iter().copied().skip(at)
    }

    /// Whether the operator asked for the browser at all.
    #[must_use]
    pub fn has_headless(&self) -> bool {
        self.rungs.contains(&Rung::Headless)
    }

    /// The cheapest rung on this ladder.
    #[must_use]
    pub fn cheapest(&self) -> Rung {
        self.rungs.first().copied().unwrap_or(Rung::Honest)
    }

    /// What this ladder is, for a log line an operator can act on.
    #[must_use]
    pub fn describe(&self) -> String {
        self.rungs
            .iter()
            .map(|rung| rung.key())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// What a host needed last time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Learned {
    /// The rung that produced a card, or `None` for a host where none did.
    rung: Option<Rung>,
    /// When that was learned. What the cooldowns are measured from.
    since_ms: u64,
    /// When it was last used, which is what eviction sorts on.
    used_ms: u64,
}

/// How long each kind of memory is trusted.
#[derive(Debug, Clone, Copy)]
pub struct Cooldowns {
    /// How long a learned rung is used before the cheapest rungs are tried
    /// again.
    ///
    /// The knob that lets a site come back down. Long enough that a busy
    /// channel is not re-probing all day, short enough that a site which
    /// dropped its bot wall is noticed the same day.
    pub revalidate: Duration,
    /// How long a host where nothing worked is left alone.
    ///
    /// Short, because "nothing worked" is often "the site was down for a
    /// minute", and a preview nobody gets is cheap to retry. It exists so that
    /// a channel full of one dead host does not walk the whole ladder, browser
    /// included, once per message.
    pub hopeless: Duration,
}

impl Default for Cooldowns {
    fn default() -> Self {
        Self {
            revalidate: Duration::from_secs(6 * 60 * 60),
            hopeless: Duration::from_secs(15 * 60),
        }
    }
}

/// Which rung each host needed, until it is time to ask again.
#[derive(Debug)]
pub struct Memory {
    hosts: Mutex<HashMap<String, Learned>>,
    cooldowns: Cooldowns,
    capacity: usize,
}

/// How to fetch a host this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Begin here and climb from here.
    Walk(Rung),
    /// One attempt at this rung, and no climbing.
    ///
    /// Nothing worked on this host recently, so walking the whole ladder again,
    /// with a browser at the end of it, would spend the expensive rungs on a
    /// host that has just refused every one of them. One cheap fetch is what a
    /// preview cost before any of this existed, and a site that has come back
    /// answers it.
    Once(Rung),
}

impl Memory {
    /// A memory with nothing in it.
    #[must_use]
    pub fn new(cooldowns: Cooldowns, capacity: usize) -> Self {
        Self {
            hosts: Mutex::new(HashMap::new()),
            cooldowns,
            capacity: capacity.max(1),
        }
    }

    /// Where to begin for `host`.
    #[must_use]
    pub fn plan(&self, host: &str, cheapest: Rung, now_ms: u64) -> Plan {
        let mut hosts = self.lock();
        let Some(learned) = hosts.get_mut(host) else {
            return Plan::Walk(cheapest);
        };
        let age = now_ms.saturating_sub(learned.since_ms);
        learned.used_ms = now_ms;
        match learned.rung {
            // Trusted while it is fresh, and then deliberately forgotten as a
            // starting point: the walk begins at the bottom again so a host
            // that no longer needs the expensive rung stops paying for it.
            Some(rung) if age < millis(self.cooldowns.revalidate) => Plan::Walk(rung),
            Some(_) => Plan::Walk(cheapest),
            None if age < millis(self.cooldowns.hopeless) => Plan::Once(cheapest),
            None => Plan::Walk(cheapest),
        }
    }

    /// Record that `rung` produced a card for `host`.
    pub fn learned(&self, host: &str, rung: Rung, now_ms: u64) {
        self.remember(
            host,
            Learned {
                rung: Some(rung),
                since_ms: now_ms,
                used_ms: now_ms,
            },
        );
    }

    /// Record that no rung produced one.
    pub fn exhausted(&self, host: &str, now_ms: u64) {
        self.remember(
            host,
            Learned {
                rung: None,
                since_ms: now_ms,
                used_ms: now_ms,
            },
        );
    }

    /// How many hosts are remembered. For the gauge an operator reads.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing has been learned yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn remember(&self, host: &str, learned: Learned) {
        let mut hosts = self.lock();
        if hosts.len() >= self.capacity && !hosts.contains_key(host) {
            // The least recently used host goes. Bounded because the key is
            // chosen by whoever pastes a link: without a cap this map is a
            // memory leak a stranger controls.
            let oldest = hosts
                .iter()
                .min_by_key(|(_, entry)| entry.used_ms)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                let _ = hosts.remove(&oldest);
            }
        }
        let _ = hosts.insert(host.to_owned(), learned);
    }

    /// The map, never poisoned into a panic: a lost memory costs one extra
    /// fetch, and taking the service down over it would cost every preview.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Learned>> {
        self.hosts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A duration in milliseconds, saturating: a cooldown longer than 500 million
/// years is the same as forever.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl Card {
    /// Whether this card is worth showing, and therefore whether the rung that
    /// produced it worked.
    ///
    /// A title alone is not enough, and Reddit is why: an honest fetch of a
    /// Reddit thread returns a 200 with a script shell whose whole head is
    /// `<title>Reddit</title>`, no description and no image. Treating that as
    /// success would pin every Reddit link to a card that says "Reddit", and
    /// the rung above it - the one that returns the real card - would never be
    /// tried.
    #[must_use]
    pub fn informative(&self) -> bool {
        !self.title.is_empty() && (!self.description.is_empty() || !self.image.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(title: &str, description: &str, image: &str) -> Card {
        Card {
            title: title.to_owned(),
            description: description.to_owned(),
            image: image.to_owned(),
            ..Card::default()
        }
    }

    #[test]
    fn reddits_script_shell_is_not_a_card() {
        // Measured: an honest fetch of a Reddit thread is 8470 bytes titled
        // "Reddit" with nothing else in the head. If this reads as success the
        // ladder stops one rung too early on every Reddit link there is.
        assert!(!card("Reddit", "", "").informative());
        assert!(
            card(
                "From the ChatGPT community on Reddit: PSA...",
                "511 votes",
                ""
            )
            .informative(),
            "the crawler rung's answer is a card"
        );
        // A picture and a title is a card too: plenty of pages describe
        // themselves with an image and no summary.
        assert!(card("A page", "", "https://example.org/card.png").informative());
        assert!(!card("", "", "https://example.org/card.png").informative());
    }

    #[test]
    fn the_ladder_keeps_the_order_an_operator_wrote() {
        let ladder = Ladder::parse("crawler, honest");
        assert_eq!(
            ladder.from(Rung::Crawler).collect::<Vec<_>>(),
            vec![Rung::Crawler, Rung::Honest]
        );
        assert_eq!(ladder.cheapest(), Rung::Crawler);
    }

    #[test]
    fn a_typo_does_not_switch_previews_off() {
        // One misspelled rung must not empty the ladder: the failure would be
        // a server that previews nothing and looks configured.
        assert_eq!(Ladder::parse("honest,brwoser").describe(), "honest");
        assert_eq!(Ladder::parse("").describe(), Ladder::default().describe());
        assert_eq!(
            Ladder::parse(",,,").describe(),
            Ladder::default().describe()
        );
    }

    #[test]
    fn the_browser_is_off_unless_it_is_asked_for() {
        assert!(!Ladder::default().has_headless());
        assert!(Ladder::parse("honest,headless").has_headless());
    }

    #[test]
    fn a_walk_starts_at_the_rung_that_worked_last_time() {
        let memory = Memory::new(Cooldowns::default(), 16);
        assert_eq!(
            memory.plan("idealo.de", Rung::Honest, 0),
            Plan::Walk(Rung::Honest),
            "a host nobody has fetched starts at the bottom"
        );
        memory.learned("idealo.de", Rung::Headless, 1_000);
        assert_eq!(
            memory.plan("idealo.de", Rung::Honest, 2_000),
            Plan::Walk(Rung::Headless),
            "and then at the rung that worked, without three wasted fetches"
        );
    }

    #[test]
    fn a_learned_rung_expires_so_a_host_can_come_back_down() {
        // The whole reason the memory has a clock. A site that drops its bot
        // wall must be able to go back to being fetched honestly, and nothing
        // else in this design would ever try a cheaper rung again.
        let cooldowns = Cooldowns {
            revalidate: Duration::from_secs(60),
            ..Cooldowns::default()
        };
        let memory = Memory::new(cooldowns, 16);
        memory.learned("example.org", Rung::Browser, 0);
        assert_eq!(
            memory.plan("example.org", Rung::Honest, 59_000),
            Plan::Walk(Rung::Browser)
        );
        assert_eq!(
            memory.plan("example.org", Rung::Honest, 61_000),
            Plan::Walk(Rung::Honest),
            "past the cooldown the cheapest rung is tried again"
        );
    }

    #[test]
    fn a_host_where_nothing_worked_is_left_alone_for_a_while() {
        let cooldowns = Cooldowns {
            hopeless: Duration::from_secs(60),
            ..Cooldowns::default()
        };
        let memory = Memory::new(cooldowns, 16);
        memory.exhausted("blocked.example", 0);
        assert_eq!(
            memory.plan("blocked.example", Rung::Honest, 30_000),
            Plan::Once(Rung::Honest),
            "one cheap fetch, which is what a preview cost before the ladder"
        );
        assert_eq!(
            memory.plan("blocked.example", Rung::Honest, 61_000),
            Plan::Walk(Rung::Honest),
            "a site that was down for a minute must not be written off for good"
        );
    }

    #[test]
    fn the_memory_is_bounded_by_something_other_than_what_gets_pasted() {
        let memory = Memory::new(Cooldowns::default(), 4);
        for host in 0..10_u64 {
            memory.learned(&format!("host{host}.example"), Rung::Honest, host);
        }
        assert_eq!(memory.len(), 4, "the key is a stranger's to choose");
        // The most recent survive; the first ones learned are the ones evicted.
        assert_eq!(
            memory.plan("host9.example", Rung::Crawler, 10),
            Plan::Walk(Rung::Honest)
        );
    }
}
