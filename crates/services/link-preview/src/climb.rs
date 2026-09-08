//! Walking the ladder: one URL, up to four ways of asking, and what is learned
//! from it.
//!
//! [`ladder`](crate::ladder) says what the rungs are and remembers which one a
//! host needed. This is the part that actually climbs: it starts where the
//! memory says to start, stops the moment a rung produces a card worth showing,
//! and charges the browser to the person who asked for it.
//!
//! # Stopping early is the whole point
//!
//! Every rung above the first costs a request to somebody else's server, and
//! the last one costs a browser. A walk that ran to the top every time would
//! turn one pasted link into four fetches and a render, so:
//!
//! * a card that is [informative](crate::parse::Card::informative) ends the
//!   walk, and the rung that produced it is remembered for that host
//! * a card that is not - Reddit's script shell, a bot wall with a title -
//!   is kept as a fallback and the walk continues
//! * a host where nothing worked is remembered too, so the next paste of it
//!   costs one cheap fetch rather than the whole ladder again

use std::sync::Arc;
use std::time::Duration;

use starling_outbound::{FetchError, Fetcher, Page};
use starling_proto_fancy::render::FetchRequest;
use starling_proto_fancy::render::render_client::RenderClient;
use starling_runtime::channel::Resolver;
use starling_runtime::ids::now_ms;

use crate::ladder::{Ladder, Memory, Plan, Rung};
use crate::parse;
use crate::quota::Quota;

/// Where the `render` service is, and how long it may take.
#[derive(Debug, Clone)]
pub struct Renderer {
    /// How this deployment reaches its services, which is also how it reaches
    /// the browser: in `--all-in-one` the call never leaves the process, and
    /// split out it is a gRPC hop. Neither side knows which.
    pub resolver: Resolver,
    /// What one render may cost. The render service has its own ceiling and
    /// applies the lower of the two.
    pub budget: Duration,
}

/// Everything one walk needs, cloned out of the service.
///
/// Cloned rather than borrowed because a walk outlives the frame handler that
/// started it: a preview takes as long as a stranger's server takes, and
/// holding the connection's handler for that would stop the client's other
/// frames.
#[derive(Debug, Clone)]
pub struct Climb {
    /// The fetcher every rung shares. Cloning it and changing the user-agent
    /// keeps one set of limits and **one semaphore**: four rungs with four
    /// fetchers would be four times the concurrency the operator allowed.
    pub fetcher: Fetcher,
    /// The rungs, in the operator's order.
    pub ladder: Ladder,
    /// What each host needed last time.
    pub memory: Arc<Memory>,
    /// What one person may spend of the browser.
    pub quota: Arc<Quota>,
    /// What this server calls itself on the honest rung.
    pub honest: Arc<str>,
    /// The browser, if this deployment has one.
    pub renderer: Option<Renderer>,
}

/// How a walk ended.
#[derive(Debug)]
pub enum Reached {
    /// A page, and the rung that got it.
    Page {
        /// What was fetched or rendered.
        page: Page,
        /// Which rung produced it, so the caller can fetch the picture the
        /// same way the page was fetched.
        rung: Rung,
    },
    /// The host says this is not a page at all, which usually means it is a
    /// picture. Escalating a picture through a browser would be spending a
    /// renderer to be told the same thing, so the walk stops here and the
    /// caller fetches it as media.
    NotAPage,
    /// Nothing worked, with the last thing that went wrong.
    Nothing(String),
}

impl Climb {
    /// The fetcher a rung asks with.
    ///
    /// Also what the *picture* is fetched with afterwards: an `og:image` on a
    /// host that answers a browser and not a crawler is the same wall the page
    /// had, and fetching the card's picture as somebody else than the card
    /// would be asking two different questions.
    #[must_use]
    pub fn fetcher_for(&self, rung: Rung) -> Fetcher {
        let agent = rung
            .user_agent(&self.honest)
            .unwrap_or(crate::ladder::BROWSER_USER_AGENT);
        self.fetcher.clone().announcing(agent)
    }

    /// Climb until something works, or until the rungs run out.
    pub async fn walk(&self, url: &str, session: u32) -> Reached {
        let host = crate::host_of(url);
        let plan = self.memory.plan(&host, self.ladder.cheapest(), now_ms());
        let (rungs, climbing): (Vec<Rung>, bool) = match plan {
            Plan::Walk(from) => (self.ladder.from(from).collect(), true),
            // One cheap attempt and no escalation. What a preview cost before
            // any of this existed, which is the right amount to spend on a host
            // that refused every rung a few minutes ago.
            Plan::Once(rung) => (vec![rung], false),
        };

        let mut fallback: Option<(Page, Rung)> = None;
        let mut last = String::new();
        for rung in rungs {
            match self.attempt(rung, url, session).await {
                Ok(page) => {
                    if parse::card(&page.html).informative() {
                        // The end of the walk, and the only thing worth
                        // remembering: this rung produced a card.
                        self.memory.learned(&host, rung, now_ms());
                        tracing::debug!(%url, rung = rung.key(), "link preview: this rung worked");
                        return Reached::Page { page, rung };
                    }
                    // A 200 with nothing in it. Kept in case every rung above
                    // is worse, but not learned: learning it would stop the
                    // ladder one rung below the card.
                    tracing::debug!(%url, rung = rung.key(), "link preview: a page with no card");
                    if fallback.is_none() {
                        fallback = Some((page, rung));
                    }
                }
                // The host has said what it is serving, and it is not a page.
                Err(Refused::NotAPage) => return Reached::NotAPage,
                Err(Refused::Because(reason)) => last = reason,
                // The person asking has run out of browser. Not the host's
                // fault and not remembered as one: the next paste, a minute
                // later, may well render.
                Err(Refused::OutOfBudget(reason)) => {
                    last = reason;
                    break;
                }
            }
        }

        if let Some((page, rung)) = fallback {
            return Reached::Page { page, rung };
        }
        if climbing {
            // Every rung this server has, and none of them worked. Remembered
            // so the next link to this host costs one fetch instead of the
            // whole ladder with a browser on the end of it.
            self.memory.exhausted(&host, now_ms());
        }
        Reached::Nothing(last)
    }

    /// One rung.
    async fn attempt(&self, rung: Rung, url: &str, session: u32) -> Result<Page, Refused> {
        match rung {
            Rung::Headless => self.render(url, session).await,
            fetching => self
                .fetcher_for(fetching)
                .fetch(url)
                .await
                .map_err(|error| match error {
                    FetchError::NotHtml => Refused::NotAPage,
                    other => Refused::Because(other.reason().to_owned()),
                }),
        }
    }

    /// The browser rung: charge it, dial it, and take the DOM it produced.
    async fn render(&self, url: &str, session: u32) -> Result<Page, Refused> {
        let Some(renderer) = self.renderer.as_ref() else {
            return Err(Refused::Because("that link needs a browser".to_owned()));
        };
        // Charged **before** the call, and to the session rather than the
        // connection: the cost being bounded is a browser tab, and the person
        // who asked for it is the one who should run out of them.
        if let Err(refusal) = self.quota.admit(session, now_ms()) {
            tracing::debug!(%url, session, "link preview: out of browser budget");
            return Err(Refused::OutOfBudget(refusal.reason()));
        }

        let channel = renderer.resolver.channel("render").map_err(|error| {
            // An operator asked for the browser rung and there is no browser
            // service to dial. Worth saying plainly: every other rung still
            // works, so the symptom without this line is "some links never
            // preview" with nothing in the log.
            tracing::warn!(%error, "link preview: the render service cannot be reached");
            Refused::Because("that link needs a browser".to_owned())
        })?;
        let budget = u32::try_from(renderer.budget.as_millis()).unwrap_or(u32::MAX);
        let reply = RenderClient::new(channel)
            .fetch(FetchRequest {
                url: url.to_owned(),
                timeout_ms: budget,
            })
            .await
            .map_err(|status| {
                tracing::debug!(%url, %status, "link preview: the render service refused");
                Refused::Because("that link could not be rendered".to_owned())
            })?
            .into_inner();

        if !reply.error.is_empty() {
            return Err(Refused::Because(reply.error));
        }
        // A rendered block page is still a block page. Without this the walk
        // would end on a 403 whose title is the site's name, learn that the
        // browser "works" for that host, and spend one on every link to it.
        if reply.status != 0 && !(200..400).contains(&reply.status) {
            return Err(Refused::Because(format!(
                "that link did not load ({})",
                reply.status
            )));
        }
        Ok(Page {
            url: if reply.final_url.is_empty() {
                url.to_owned()
            } else {
                reply.final_url
            },
            html: reply.html,
        })
    }
}

/// Why one rung did not produce a page.
#[derive(Debug)]
enum Refused {
    /// The host served something that is not a page. Ends the walk: no rung
    /// above this one turns a JPEG into an article.
    NotAPage,
    /// This rung did not work, and the next one may.
    Because(String),
    /// The browser was not refused by the host but by this server, on behalf
    /// of everybody else. Ends the walk without blaming the host.
    OutOfBudget(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ladder::Cooldowns;

    fn climb(ladder: &str) -> Climb {
        Climb {
            fetcher: Fetcher::new(starling_outbound::Limits::default()),
            ladder: Ladder::parse(ladder),
            memory: Arc::new(Memory::new(Cooldowns::default(), 64)),
            quota: Arc::new(Quota::new(
                crate::quota::Limit::every(30.0, 3),
                crate::quota::Limit::every(5.0, 10),
                0,
            )),
            honest: Arc::from(crate::ladder::HONEST_USER_AGENT),
            renderer: None,
        }
    }

    #[test]
    fn each_rung_asks_as_itself() {
        // The user-agent is the rung. A walk that sent the same string four
        // times would be four identical requests and three wasted ones.
        let climb = climb("honest,crawler,browser,headless");
        let agents: Vec<String> = [Rung::Honest, Rung::Crawler, Rung::Browser]
            .into_iter()
            .map(|rung| {
                rung.user_agent(&climb.honest)
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        assert!(agents[0].contains("StarlingBot"));
        assert!(agents[1].contains("Discordbot"));
        assert!(agents[2].contains("Chrome"));
        assert_eq!(
            agents.len(),
            agents
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "two rungs asking the same way is one rung"
        );
    }

    #[test]
    fn the_picture_is_fetched_as_whoever_fetched_the_page() {
        // An og:image behind the same wall as the page: fetching it as
        // somebody else asks a different question and gets a different answer.
        let climb = climb("honest,headless");
        // The headless rung has no user-agent of its own - it is a browser -
        // so its pictures are fetched as a browser rather than as nothing.
        assert!(Rung::Headless.user_agent(&climb.honest).is_none());
        let _ = climb.fetcher_for(Rung::Headless);
    }

    #[tokio::test]
    async fn the_browser_rung_without_a_render_service_is_a_refusal_and_not_a_panic() {
        let climb = climb("headless");
        let reached = climb.walk("https://example.org/", 1).await;
        match reached {
            Reached::Nothing(reason) => assert!(reason.contains("browser")),
            other => panic!("a missing render service must refuse cleanly: {other:?}"),
        }
    }
}
