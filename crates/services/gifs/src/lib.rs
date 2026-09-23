//! `gifs`: animated-media search, keyed by the operator rather than by each
//! user.
//!
//! # Why the key moved here
//!
//! The client used to hold a provider API key of its own, typed into Advanced
//! settings. That is a feature that works for whoever went and registered for a
//! key and does not exist for everybody else, which on a chat server is almost
//! everybody. One key, held once by the operator, is the whole point.
//!
//! It also takes the *query* off the client. A search box in a chat client is a
//! stream of things people typed, and it now reaches the provider from one
//! address with no per-person session attached rather than from each member's
//! own machine.
//!
//! Discord made the same move and stopped halfway: its client calls Discord's
//! `/gifs/*` rather than the provider's, but its picker still loads every
//! thumbnail straight from the provider's CDN, which hands that CDN each
//! viewer's address and a `referer` naming the channel they are in. `proxy` is
//! the other half, off by default because it costs the deployment bandwidth.
//!
//! # What stops this being expensive
//!
//! The provider key is a metered resource shared by everyone on the server, so
//! the limits are about **upstream calls**, not about frames. `quota` has the
//! argument in full; the short version is a cache, coalescing of concurrent
//! identical misses, a per-session bucket and a server-wide one, on top of the
//! gateway's ordinary per-connection frame bucket.

pub mod provider;
pub mod proxy;
pub mod quota;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message as _;
use starling_outbound::{Fetcher, Limits};
use starling_proto_fancy::fancy::media::{
    Gif, GifPage, GifQuery, GifRefused, GifSupport, GifsEnvelope, gif_refused, gifs_envelope,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::metrics::Counter;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::ratelimit::Rate;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

use provider::{Provider, ProviderError};
use quota::{Key, Limit, Quota, Waiter};

/// How the media proxy is configured, when it is on at all.
#[derive(Debug)]
struct ProxyConfig {
    secret: Vec<u8>,
    /// What a signed URL points at, which is not necessarily what `listen`
    /// binds - the same distinction the files service draws.
    public_url: String,
    /// The domains a signed URL may name.
    domains: Vec<String>,
    /// How long a signed `preview_url` stays good.
    ttl: Duration,
    /// How long a signed `url` stays good. See [`ProxyStamp::send_ttl`].
    send_ttl: Duration,
    /// Where the listener binds, absent when the operator configured none.
    listen: Option<String>,
}

/// One cached picture.
#[derive(Debug, Clone)]
pub struct CachedBytes {
    /// What the CDN called it, passed through so the client decodes it as the
    /// provider serves it rather than as we guess.
    pub mime: String,
    /// The picture, whole.
    pub bytes: Vec<u8>,
}

/// The service.
#[derive(Debug)]
pub struct GifsService {
    fanout: Fanout,
    logger: Logger,
    fetcher: Fetcher,
    /// `None` when no key is configured, which is the ordinary state of a
    /// server that has not opted in. Every search is then refused
    /// `UNAVAILABLE`, which is the one refusal a client may fall back to its
    /// own key on.
    provider: Option<Provider>,
    quota: Arc<Quota>,
    proxy: Option<ProxyConfig>,
    /// Proxied pictures, bounded by total bytes.
    pictures: Mutex<PictureCache>,
    /// The longest query that will be sent upstream.
    max_query: usize,
    /// The highest page that will be asked for.
    ///
    /// Not politeness: paging is the cheapest way to miss the cache on demand,
    /// since every page number is a different key. A ceiling makes the number
    /// of distinct keys one query can produce finite.
    max_page: u32,
    counters: Counters,
}

/// Everything lost or spent, counted.
#[derive(Debug, Clone)]
struct Counters {
    searches: Counter,
    cache_hits: Counter,
    coalesced: Counter,
    upstream: Counter,
    upstream_failed: Counter,
    throttled_session: Counter,
    throttled_server: Counter,
    refused_unavailable: Counter,
    refused_malformed: Counter,
}

/// Proxied picture bytes, capped by total size.
#[derive(Debug, Default)]
struct PictureCache {
    entries: HashMap<String, CachedBytes>,
    bytes: usize,
    cap: usize,
}

impl ClientService for GifsService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        if inbound.type_id != ServiceKind::Gifs.outer_type() {
            return Actions::new();
        }
        let Ok(envelope) = GifsEnvelope::decode(inbound.payload.as_slice()) else {
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable GifsEnvelope"
            );
            return Actions::new();
        };
        let query = match envelope.body {
            Some(gifs_envelope::Body::Query(query)) => query,
            Some(gifs_envelope::Body::SupportQuery(asked)) => {
                // Answered here and now, from configuration alone: no bucket
                // is charged and the provider is not asked, because nothing
                // about the answer depends on either. It is asked on every
                // connect, and charging it would spend a token of everybody's
                // budget per login on a question the config file answers.
                return vec![framed(
                    inbound.conn,
                    gifs_envelope::Body::Support(self.support(&asked.request_id)),
                )];
            }
            _ => {
                // A `GifPage`, `GifRefused` or `GifSupport` from a client is
                // either confused or newer than this server; there is nothing
                // here that answers one.
                return Actions::new();
            }
        };
        self.counters.searches.inc();

        let mut actions = Actions::new();
        if let Err(refused) = self.search(&inbound, &query) {
            actions.push(refusal_action(inbound.conn, refused));
        }
        actions
    }
}

impl GifsService {
    /// Start answering one query, or say why not.
    ///
    /// The fetch itself happens off this handler: the provider takes as long as
    /// it takes, and awaiting it here would hold this connection's frame
    /// handler while a third party decides - the same reason `link-preview`
    /// spawns.
    fn search(&self, inbound: &Inbound, query: &GifQuery) -> Result<(), GifRefused> {
        let Some(provider) = self.provider.clone() else {
            self.counters.refused_unavailable.inc();
            return Err(self.unavailable(&query.request_id));
        };
        let text = query.query.trim();
        if text.chars().count() > self.max_query {
            self.counters.refused_malformed.inc();
            return Err(GifRefused {
                request_id: query.request_id.clone(),
                reason: format!("a search is at most {} characters", self.max_query),
                retry_after_ms: 0,
                kind: gif_refused::Reason::Malformed as i32,
            });
        }
        if query.page > self.max_page {
            self.counters.refused_malformed.inc();
            return Err(GifRefused {
                request_id: query.request_id.clone(),
                reason: "that is further than this server pages".to_owned(),
                retry_after_ms: 0,
                kind: gif_refused::Reason::Malformed as i32,
            });
        }

        let now = now_ms();
        let key = Key::new(text, query.page);

        // Layer 2: a repeat costs nothing, and is deliberately not charged to
        // any bucket - the frame it arrived in was already charged by the
        // gateway, and charging quota for a call nobody made would make simply
        // opening the picker expensive.
        if let Some(page) = self.quota.cached(&key, now) {
            self.counters.cache_hits.inc();
            self.answer(inbound.conn, &query.request_id, &key, &page);
            return Ok(());
        }

        let waiter = Waiter {
            conn: inbound.conn,
            request_id: query.request_id.clone(),
        };
        // Layer 3. `begin` records the waiter either way; `false` means an
        // identical fetch is already running and will answer this caller too.
        if !self.quota.begin(&key, waiter) {
            self.counters.coalesced.inc();
            return Ok(());
        }

        // Layer 4, and only now: an admission spent on a call that coalescing
        // would have made unnecessary is a token wasted.
        if let Err(refusal) = self.quota.admit(inbound.session, now) {
            // This caller registered as a waiter above and is about to be
            // refused instead, so the key has to be released - otherwise it is
            // permanently "being fetched" and every later search for it waits
            // for a fetch that never started.
            let waiting = self.quota.finish(&key);
            match refusal {
                quota::Refusal::Session(_) => self.counters.throttled_session.inc(),
                quota::Refusal::Server(_) => {
                    self.counters.throttled_server.inc();
                    // The operator's problem rather than this user's: nobody
                    // on the server can search, and no single client's log
                    // would ever show why.
                    self.logger.log(
                        LogEvent::warning(
                            Category::Server,
                            "gif search throttled: the server-wide provider budget is spent",
                        )
                        .with("session", inbound.session),
                    );
                }
            }
            let retry_after_ms =
                u32::try_from(refusal.retry_after().as_millis()).unwrap_or(u32::MAX);
            // Everybody who attached behind this caller is refused with it;
            // they are waiting on a fetch that is not going to happen.
            for waiter in &waiting {
                self.fanout.push(refusal_action(
                    waiter.conn,
                    GifRefused {
                        request_id: waiter.request_id.clone(),
                        reason: "too many searches at once; try again in a moment".to_owned(),
                        retry_after_ms,
                        kind: gif_refused::Reason::Throttled as i32,
                    },
                ));
            }
            return Ok(());
        }

        self.spawn_fetch(provider, key);
        Ok(())
    }

    /// Fetch one page in the background and answer everybody waiting on it.
    fn spawn_fetch(&self, provider: Provider, key: Key) {
        let fetcher = self.fetcher.clone();
        let fanout = self.fanout.clone();
        let logger = self.logger.clone();
        let counters = self.counters.clone();
        let quota_answer = self.answer_parts();
        drop(tokio::spawn(async move {
            counters.upstream.inc();
            let outcome = provider.page(&fetcher, key.query(), key.page()).await;
            // Taken unconditionally, success or failure: an entry left in the
            // in-flight map is a key that never fetches again.
            let waiting = quota_answer.quota.finish(&key);
            match outcome {
                Ok(page) => {
                    quota_answer.quota.store(&key, &page, now_ms());
                    for waiter in &waiting {
                        fanout.push(quota_answer.page_action(
                            waiter.conn,
                            &waiter.request_id,
                            &key,
                            &page,
                        ));
                    }
                }
                Err(error) => {
                    counters.upstream_failed.inc();
                    // The detail an operator needs - a dead key, a provider
                    // outage and a timeout are three different things to do
                    // something about - and that a client is not given, because
                    // it can act on none of them.
                    tracing::warn!(
                        what = %provider.describe(key.query(), key.page()),
                        detail = %error.detail(),
                        "a gif search failed upstream"
                    );
                    logger.log(
                        LogEvent::warning(Category::Server, "gif search failed upstream")
                            .with("what", provider.describe(key.query(), key.page()))
                            .with("detail", error.detail()),
                    );
                    let reason = match error {
                        ProviderError::Fetch(_) => "the GIF provider could not be reached",
                        ProviderError::Unreadable => "the GIF provider sent something unreadable",
                    };
                    for waiter in &waiting {
                        fanout.push(refusal_action(
                            waiter.conn,
                            GifRefused {
                                request_id: waiter.request_id.clone(),
                                reason: reason.to_owned(),
                                retry_after_ms: 0,
                                kind: gif_refused::Reason::Upstream as i32,
                            },
                        ));
                    }
                }
            }
        }));
    }

    /// Send one page to one connection.
    fn answer(&self, conn: u64, request_id: &str, key: &Key, page: &provider::Page) {
        self.fanout
            .push(self.answer_parts().page_action(conn, request_id, key, page));
    }

    /// The pieces `spawn_fetch` needs after `self` is gone.
    fn answer_parts(&self) -> AnswerParts {
        AnswerParts {
            quota: Arc::clone(&self.quota),
            provider_name: self.provider_name().to_owned(),
            proxy: self.proxy.as_ref().map(|proxy| ProxyStamp {
                secret: proxy.secret.clone(),
                public_url: proxy.public_url.clone(),
                preview_ttl: proxy.ttl,
                send_ttl: proxy.send_ttl,
            }),
        }
    }

    /// Which provider answers searches, or `""` when none does.
    fn provider_name(&self) -> &'static str {
        self.provider
            .as_ref()
            .map_or("", |provider| provider.kind().as_str())
    }

    /// What this server does for a client, before it has searched for
    /// anything.
    ///
    /// `available` is exactly the condition `search` refuses `UNAVAILABLE` on,
    /// so the up-front answer and the refusal cannot disagree. `media_base`
    /// comes from [`proxy::media_base`], the same function every proxied URL
    /// is built with.
    fn support(&self, request_id: &str) -> GifSupport {
        GifSupport {
            request_id: request_id.to_owned(),
            available: self.provider.is_some(),
            media_base: self
                .proxy
                .as_ref()
                .map(|proxy| proxy::media_base(&proxy.public_url))
                .unwrap_or_default(),
            provider: self.provider_name().to_owned(),
        }
    }

    /// What a server with no key configured says.
    fn unavailable(&self, request_id: &str) -> GifRefused {
        GifRefused {
            request_id: request_id.to_owned(),
            // Written for the person reading it in a picker, and deliberately
            // naming who can fix it: nobody on this server can, so a message
            // saying "try again" would be a lie.
            reason: "this server has no GIF provider configured".to_owned(),
            retry_after_ms: 0,
            kind: gif_refused::Reason::Unavailable as i32,
        }
    }

    /// The signing key, when the proxy is on.
    #[must_use]
    pub fn proxy_secret(&self) -> Option<&[u8]> {
        self.proxy.as_ref().map(|proxy| proxy.secret.as_slice())
    }

    /// The domains a proxied URL may name.
    #[must_use]
    pub fn proxy_domains(&self) -> &[String] {
        self.proxy
            .as_ref()
            .map_or(&[] as &[String], |proxy| proxy.domains.as_slice())
    }

    /// The outbound client, for the proxy route.
    #[must_use]
    pub const fn fetcher(&self) -> &Fetcher {
        &self.fetcher
    }

    /// A proxied picture already fetched, if it is still held.
    #[must_use]
    pub fn cached_bytes(&self, url: &str) -> Option<CachedBytes> {
        self.pictures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .get(url)
            .cloned()
    }

    /// Remember a proxied picture, dropping older ones to stay under the cap.
    pub fn store_bytes(&self, url: &str, mime: &str, bytes: &[u8]) {
        let mut cache = self
            .pictures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.cap == 0 || bytes.len() > cache.cap {
            return;
        }
        let _ = cache.entries.insert(
            url.to_owned(),
            CachedBytes {
                mime: mime.to_owned(),
                bytes: bytes.to_vec(),
            },
        );
        cache.bytes = cache.bytes.saturating_add(bytes.len());
        while cache.bytes > cache.cap {
            // Arbitrary rather than least-recently-used, and that is a
            // deliberate trade: an LRU needs a touch on every read, and what
            // this cache is for is a burst of viewers opening the same page
            // within seconds of each other. Anything still in it is recent.
            let Some((url, entry)) = cache
                .entries
                .iter()
                .next()
                .map(|(url, entry)| (url.clone(), entry.bytes.len()))
            else {
                break;
            };
            let _ = cache.entries.remove(&url);
            cache.bytes = cache.bytes.saturating_sub(entry);
        }
    }
}

/// A `GifRefused`, framed and addressed.
fn refusal_action(conn: u64, refused: GifRefused) -> starling_proto_fancy::control::ServerAction {
    framed(conn, gifs_envelope::Body::Refused(refused))
}

/// Any answer, framed and addressed to one connection.
fn framed(conn: u64, body: gifs_envelope::Body) -> starling_proto_fancy::control::ServerAction {
    to_conn(
        conn,
        ServiceKind::Gifs.outer_type(),
        GifsEnvelope { body: Some(body) }.encode_to_vec(),
    )
}

/// Enough of the service to answer, without holding it across an await.
#[derive(Debug)]
struct AnswerParts {
    quota: Arc<Quota>,
    provider_name: String,
    proxy: Option<ProxyStamp>,
}

/// What turns a provider URL into one pointing at this server.
#[derive(Debug, Clone)]
struct ProxyStamp {
    secret: Vec<u8>,
    public_url: String,
    /// How long a picker thumbnail's grant is good for. Short, because a
    /// thumbnail is only ever drawn by the picker that asked for it, and a
    /// picker opened again after it lapses searches again and is re-signed.
    preview_ttl: Duration,
    /// How long the full-size grant is good for: years rather than an hour.
    ///
    /// `url` is the rendition a client *sends*, and once sent it lives in chat
    /// history and is read back for as long as that history is. A grant that
    /// lapsed after an hour would turn every GIF in the backlog into a broken
    /// image by the next morning, with no picker left to re-sign it. The length
    /// costs nothing worth guarding: the signature covers one provider URL and
    /// the host allow-list still applies, so a grant that outlives everyone
    /// buys its holder that one GIF and nothing else.
    send_ttl: Duration,
}

impl AnswerParts {
    /// One page, framed for one waiter.
    fn page_action(
        &self,
        conn: u64,
        request_id: &str,
        key: &Key,
        page: &provider::Page,
    ) -> starling_proto_fancy::control::ServerAction {
        let results = page
            .results
            .iter()
            .map(|gif| Gif {
                id: gif.id.clone(),
                title: gif.title.clone(),
                // Rewritten here rather than at parse time, so the cache holds
                // the provider's own URLs: a signed URL carries an expiry, and
                // caching one would serve grants that expire before the page
                // does. Stamped here, every answer - from the cache or fresh -
                // counts its expiry from the moment it is sent.
                url: self.stamp(&gif.url, |proxy| proxy.send_ttl),
                preview_url: self.stamp(&gif.preview_url, |proxy| proxy.preview_ttl),
                width: gif.width,
                height: gif.height,
                preview_width: gif.preview_width,
                preview_height: gif.preview_height,
                mime: gif.mime.clone(),
            })
            .collect();
        to_conn(
            conn,
            ServiceKind::Gifs.outer_type(),
            GifsEnvelope {
                body: Some(gifs_envelope::Body::Page(GifPage {
                    request_id: request_id.to_owned(),
                    results,
                    page: key.page(),
                    has_next: page.has_next,
                    provider: self.provider_name.clone(),
                })),
            }
            .encode_to_vec(),
        )
    }

    /// `url` as the client should be given it, signed for as long as `ttl`
    /// picks when the proxy is on.
    fn stamp(&self, url: &str, ttl: impl Fn(&ProxyStamp) -> Duration) -> String {
        self.proxy.as_ref().map_or_else(
            || url.to_owned(),
            |proxy| proxy::proxied(&proxy.public_url, &proxy.secret, url, ttl(proxy)),
        )
    }
}

impl Serve for GifsService {
    const NAME: &'static str = "gifs";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let service = ctx.service();
        let counter = |name: &str| ctx.metrics.counter(name);
        Ok(Arc::new(Self {
            fanout: Fanout::default(),
            fetcher: Fetcher::new(fetch_limits(&service)),
            provider: configured_provider(&service)?,
            quota: Arc::new(configured_quota(&service)),
            proxy: configured_proxy(&service, &ctx.config.runtime.data_dir)?,
            pictures: Mutex::new(PictureCache {
                cap: service
                    .option::<usize>("gif_media_cache_bytes")
                    .unwrap_or(64 * 1024 * 1024),
                ..PictureCache::default()
            }),
            max_query: service.option::<usize>("gif_max_query").unwrap_or(100),
            max_page: service.option::<u32>("gif_max_page").unwrap_or(20),
            counters: Counters {
                searches: counter("gifs.searches"),
                cache_hits: counter("gifs.cache_hits"),
                coalesced: counter("gifs.coalesced"),
                upstream: counter("gifs.upstream_calls"),
                upstream_failed: counter("gifs.upstream_failed"),
                throttled_session: counter("gifs.throttled_session"),
                throttled_server: counter("gifs.throttled_server"),
                refused_unavailable: counter("gifs.refused_unavailable"),
                refused_malformed: counter("gifs.refused_malformed"),
            },
            logger: ctx.logger,
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let Some(listen) = self.proxy.as_ref().and_then(|proxy| proxy.listen.clone()) else {
            // Either the proxy is off, or it is on with only a `public_url` -
            // which is a deployment where something in front terminates and
            // forwards. Nothing to bind either way.
            ctx.shutdown.wait().await;
            return Ok(());
        };
        let listener = tokio::net::TcpListener::bind(&listen)
            .await
            .map_err(|error| {
                ServiceError::service(format!(
                    "the gif media listener could not bind {listen}: {error}"
                ))
            })?;
        tracing::info!(%listen, "gifs media proxy listening");
        let router = proxy::router(Arc::clone(&self));
        let shutdown = ctx.shutdown.clone();
        let served = axum::serve(listener, router)
            .with_graceful_shutdown(async move { shutdown.wait().await });
        if let Err(error) = served.await {
            tracing::error!(%error, "the gif media listener stopped");
        }
        Ok(())
    }
}

/// What one outbound fetch may cost.
fn fetch_limits(service: &starling_runtime::config::ServiceConfig) -> Limits {
    let default = Limits::default();
    Limits {
        timeout: service
            .option::<u64>("gif_timeout_ms")
            .map_or(Duration::from_secs(8), Duration::from_millis),
        concurrency: service
            .option::<usize>("gif_concurrency")
            .unwrap_or(8)
            // Zero would mean "never fetch anything", silently. An operator who
            // wants that has `enabled = false`.
            .max(1),
        json_bytes: service
            .option::<usize>("gif_max_bytes")
            .unwrap_or(default.json_bytes),
        // Only reached with the media proxy on, where it bounds one thumbnail.
        image_bytes: service
            .option::<usize>("gif_media_max_bytes")
            .unwrap_or(8 * 1024 * 1024),
        ..default
    }
}

/// The provider, or `None` when no key is configured.
///
/// # Errors
///
/// [`ServiceError`] for a provider name this build does not know. Refused at
/// startup, where an operator will see it: a typo that silently fell back to
/// the default would be a server pointing at something nobody chose.
fn configured_provider(
    service: &starling_runtime::config::ServiceConfig,
) -> Result<Option<Provider>, ServiceError> {
    let named = service.option::<String>("gif_provider").unwrap_or_default();
    let name = provider::Name::parse(&named).ok_or_else(|| {
        ServiceError::service(format!(
            "gif_provider = {named:?} is not a provider this build knows; \
             the supported one is \"klipy\""
        ))
    })?;
    let key = service
        .option::<String>("gif_api_key")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if key.is_empty() {
        // Said once, at startup, rather than on every search: a server with the
        // service enabled and no key is a supported state - it is the default,
        // and a Fancy client falls back to a key of its own - but an operator
        // who *meant* to configure one needs to find out here.
        tracing::info!(
            "gifs is running without a provider key; searches will be refused as \
             unavailable until `gif_api_key` is set"
        );
        return Ok(None);
    }
    Ok(Some(Provider::new(
        name,
        key,
        service.option::<u32>("gif_per_page").unwrap_or(24),
    )))
}

/// The cache and the two budgets. See `quota` for what each one stops.
fn configured_quota(service: &starling_runtime::config::ServiceConfig) -> Quota {
    Quota::new(
        Limit {
            rate: service
                .option::<Rate>("gif_session_rate")
                .unwrap_or_else(|| Rate::per_second(1.0)),
            burst: service.option::<u32>("gif_session_burst").unwrap_or(5),
        },
        Limit {
            rate: service
                .option::<Rate>("gif_server_rate")
                .unwrap_or_else(|| Rate::per_second(10.0)),
            burst: service.option::<u32>("gif_server_burst").unwrap_or(30),
        },
        service
            .option::<u64>("gif_cache_ttl_ms")
            .map_or(Duration::from_secs(300), Duration::from_millis),
        service.option::<usize>("gif_cache_entries").unwrap_or(512),
        now_ms(),
    )
}

/// The media proxy, when the operator has switched it on.
///
/// # Errors
///
/// [`ServiceError`] when it is on and there is nowhere for a proxied URL to
/// point, or when the signing key can neither be read nor written. Both fail at
/// startup rather than producing URLs that never work.
fn configured_proxy(
    service: &starling_runtime::config::ServiceConfig,
    data_dir: &std::path::Path,
) -> Result<Option<ProxyConfig>, ServiceError> {
    if !service.option::<bool>("gif_proxy_media").unwrap_or(false) {
        return Ok(None);
    }
    let public_url = service
        .public_url
        .clone()
        .or_else(|| {
            service
                .listen
                .clone()
                .map(|listen| format!("http://{listen}"))
        })
        .ok_or_else(|| {
            ServiceError::service(
                "gif_proxy_media is on but the gifs service has neither `public_url` \
                 nor `listen`, so a proxied URL would point nowhere",
            )
        })?;
    Ok(Some(ProxyConfig {
        secret: proxy::secret(data_dir)?,
        public_url,
        domains: service
            .option::<String>("gif_proxy_domains")
            .unwrap_or_else(|| "klipy.com,klipy.co".to_owned())
            .split(',')
            .map(|domain| domain.trim().to_owned())
            .filter(|domain| !domain.is_empty())
            .collect(),
        ttl: service
            .option::<u64>("gif_proxy_ttl_ms")
            .map_or(Duration::from_secs(3600), Duration::from_millis),
        // Ten years: longer than any history anybody keeps, and nowhere near
        // making `now + ttl` overflow.
        send_ttl: service.option::<u64>("gif_proxy_send_ttl_ms").map_or(
            Duration::from_millis(315_360_000_000),
            Duration::from_millis,
        ),
        listen: service.listen.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::control::server_action;

    /// A service with the limits a test wants and no proxy. Crate-visible, as
    /// are `proxying` and `generous`, so `proxy`'s tests build theirs the same
    /// way.
    pub(crate) fn service(
        provider: Option<Provider>,
        session: Limit,
        server: Limit,
    ) -> GifsService {
        let metrics = starling_runtime::metrics::Metrics::new();
        let counter = |name: &str| metrics.counter(name);
        GifsService {
            fanout: Fanout::default(),
            logger: Logger::null(),
            fetcher: Fetcher::new(Limits::default()),
            provider,
            quota: Arc::new(Quota::new(
                session,
                server,
                Duration::from_secs(300),
                64,
                now_ms(),
            )),
            proxy: None,
            pictures: Mutex::new(PictureCache::default()),
            max_query: 100,
            max_page: 20,
            counters: Counters {
                searches: counter("searches"),
                cache_hits: counter("cache_hits"),
                coalesced: counter("coalesced"),
                upstream: counter("upstream"),
                upstream_failed: counter("upstream_failed"),
                throttled_session: counter("throttled_session"),
                throttled_server: counter("throttled_server"),
                refused_unavailable: counter("refused_unavailable"),
                refused_malformed: counter("refused_malformed"),
            },
        }
    }

    fn query(text: &str, page: u32) -> Inbound {
        Inbound {
            conn: 1,
            session: 7,
            type_id: ServiceKind::Gifs.outer_type(),
            payload: GifsEnvelope {
                body: Some(gifs_envelope::Body::Query(GifQuery {
                    request_id: "r1".to_owned(),
                    query: text.to_owned(),
                    page,
                })),
            }
            .encode_to_vec(),
            gateway: "g".to_owned(),
            scope: 1,
        }
    }

    /// What one action says, decoded.
    fn body_of(
        action: &starling_proto_fancy::control::ServerAction,
    ) -> Option<gifs_envelope::Body> {
        let server_action::Action::Send(send) = action.action.as_ref()? else {
            return None;
        };
        GifsEnvelope::decode(send.payload.as_slice()).ok()?.body
    }

    /// The refusal in an action, or `None` when it is not one.
    fn refusal_in(actions: &Actions) -> Option<GifRefused> {
        match body_of(actions.first()?)? {
            gifs_envelope::Body::Refused(refused) => Some(refused),
            _ => None,
        }
    }

    /// The support answer in an action, or `None` when it is not one.
    fn support_in(actions: &Actions) -> Option<GifSupport> {
        match body_of(actions.first()?)? {
            gifs_envelope::Body::Support(support) => Some(support),
            _ => None,
        }
    }

    fn support_query() -> Inbound {
        let mut inbound = query("", 1);
        inbound.payload = GifsEnvelope {
            body: Some(gifs_envelope::Body::SupportQuery(
                starling_proto_fancy::fancy::media::GifSupportQuery {
                    request_id: "s1".to_owned(),
                },
            )),
        }
        .encode_to_vec();
        inbound
    }

    fn klipy() -> Option<Provider> {
        Some(Provider::new(provider::Name::Klipy, "k".to_owned(), 24))
    }

    /// `service` with the media proxy switched on.
    pub(crate) fn proxying(mut service: GifsService) -> GifsService {
        service.proxy = Some(ProxyConfig {
            secret: b"secret".to_vec(),
            // A trailing slash, as an operator will sometimes write it.
            public_url: "https://chat.example.org/".to_owned(),
            domains: vec!["klipy.com".to_owned()],
            ttl: Duration::from_secs(3600),
            send_ttl: Duration::from_millis(315_360_000_000),
            listen: None,
        });
        service
    }

    /// A page as the provider might send it.
    fn provider_page() -> provider::Page {
        provider::Page {
            results: (0..3)
                .map(|n| provider::Gif {
                    id: n.to_string(),
                    url: format!("https://static.klipy.com/full/{n}.webp?x=1&y=2"),
                    preview_url: format!("https://static.klipy.com/tiny/{n}.webp"),
                    ..provider::Gif::default()
                })
                .collect(),
            has_next: true,
        }
    }

    /// The page in an action, or `None` when it is not one.
    fn page_in(action: &starling_proto_fancy::control::ServerAction) -> Option<GifPage> {
        match body_of(action)? {
            gifs_envelope::Body::Page(page) => Some(page),
            _ => None,
        }
    }

    pub(crate) fn generous() -> Limit {
        Limit {
            rate: Rate::per_second(100.0),
            burst: 100,
        }
    }

    #[tokio::test]
    async fn a_server_with_no_key_says_so_rather_than_saying_nothing() {
        // The refusal a client falls back on. Dropped silently instead, the
        // picker spins until its timeout on every single server that has not
        // configured a key - which is every server by default.
        let service = service(None, generous(), generous());
        let refused = refusal_in(&service.frame(query("cat", 1)).await).expect("a refusal");
        assert_eq!(refused.request_id, "r1");
        assert_eq!(refused.kind, gif_refused::Reason::Unavailable as i32);
    }

    #[tokio::test]
    async fn an_absurd_query_is_refused_before_the_provider_is_asked() {
        let service = service(
            Some(Provider::new(provider::Name::Klipy, "k".to_owned(), 24)),
            generous(),
            generous(),
        );
        let refused =
            refusal_in(&service.frame(query(&"a".repeat(101), 1)).await).expect("a refusal");
        assert_eq!(refused.kind, gif_refused::Reason::Malformed as i32);
        // Malformed, not throttled: nothing was charged, because nothing was
        // going to be sent upstream.
        assert_eq!(refused.retry_after_ms, 0);

        // Paging past the ceiling is the same answer, and for a reason worth
        // keeping distinct: every page number is its own cache key, so
        // unbounded paging is a way to miss the cache on demand.
        let refused = refusal_in(&service.frame(query("cat", 999)).await).expect("a refusal");
        assert_eq!(refused.kind, gif_refused::Reason::Malformed as i32);
    }

    #[tokio::test]
    async fn a_page_a_client_never_asked_about_is_not_answered() {
        // A frame for another service, and an envelope this build cannot read:
        // both must produce nothing rather than a refusal addressed at a
        // request id that does not exist.
        let service = service(None, generous(), generous());
        let mut wrong = query("cat", 1);
        wrong.type_id = ServiceKind::Text.outer_type();
        assert!(service.frame(wrong).await.is_empty());

        let mut garbage = query("cat", 1);
        garbage.payload = vec![0xff, 0xff, 0xff];
        assert!(service.frame(garbage).await.is_empty());
    }

    #[tokio::test]
    async fn a_throttled_search_releases_the_key_it_was_holding() {
        // The bug this exists to stop: a caller registers as a waiter, is then
        // refused by the bucket, and the in-flight entry is left behind - after
        // which every later search for that query attaches to a fetch that was
        // never started and is never answered. The key would be permanently
        // dead, and only that one query.
        let service = service(
            Some(Provider::new(provider::Name::Klipy, "k".to_owned(), 24)),
            Limit {
                rate: Rate::per_second(0.0),
                burst: 0,
            },
            generous(),
        );
        // Refused, and the refusal goes out through the fanout rather than as
        // a returned action, because the caller may have waiters behind it.
        assert!(service.frame(query("cat", 1)).await.is_empty());

        // The key is free again: a second caller is the one that would fetch.
        assert!(service.quota.begin(
            &Key::new("cat", 1),
            Waiter {
                conn: 2,
                request_id: "r2".to_owned(),
            }
        ));
    }

    #[tokio::test]
    async fn a_cached_page_is_answered_without_charging_anything() {
        // A picker opening on trending must not spend quota that no provider
        // was ever asked for.
        let service = service(
            Some(Provider::new(provider::Name::Klipy, "k".to_owned(), 24)),
            Limit {
                rate: Rate::per_second(0.0),
                burst: 0,
            },
            generous(),
        );
        service.quota.store(
            &Key::new("", 1),
            &provider::Page {
                results: vec![provider::Gif {
                    id: "1".to_owned(),
                    url: "https://cdn/one.webp".to_owned(),
                    ..provider::Gif::default()
                }],
                has_next: false,
            },
            now_ms(),
        );
        // The session bucket is empty, so an uncached search would be refused.
        // This one is answered anyway, which is the whole point.
        let actions = service.frame(query("", 1)).await;
        assert!(actions.is_empty(), "the answer goes out through the fanout");
        assert_eq!(service.counters.cache_hits.get(), 1);
        assert_eq!(
            service.counters.throttled_session.get(),
            0,
            "a cache hit must not be charged"
        );
    }

    #[tokio::test]
    async fn support_says_whether_a_search_would_be_served() {
        // The up-front form of the UNAVAILABLE refusal, and it must agree with
        // it: a client told "available" that is then refused on its first
        // search has been lied to once per connect.
        let keyless = service(None, generous(), generous());
        let support = support_in(&keyless.frame(support_query()).await).expect("an answer");
        assert_eq!(support.request_id, "s1");
        assert!(!support.available);
        assert_eq!(support.provider, "");
        assert_eq!(
            support.media_base, "",
            "no proxy, so the pictures come from the provider's own CDN"
        );

        let keyed = service(klipy(), generous(), generous());
        let support = support_in(&keyed.frame(support_query()).await).expect("an answer");
        assert!(support.available);
        assert_eq!(support.provider, "klipy");
        assert_eq!(support.media_base, "");
    }

    #[tokio::test]
    async fn the_media_base_is_what_every_proxied_url_starts_with() {
        // The client refuses to load a URL that does not start with this, so
        // the answer and the URLs drifting apart would make every GIF on the
        // server look unproxied.
        let service = proxying(service(klipy(), generous(), generous()));
        let support = support_in(&service.frame(support_query()).await).expect("an answer");
        assert_eq!(support.media_base, "https://chat.example.org/gif?");

        let action =
            service
                .answer_parts()
                .page_action(1, "r1", &Key::new("cat", 1), &provider_page());
        let page = page_in(&action).expect("a page");
        assert_eq!(page.results.len(), 3);
        for gif in &page.results {
            assert!(gif.url.starts_with(&support.media_base), "{}", gif.url);
            assert!(
                gif.preview_url.starts_with(&support.media_base),
                "{}",
                gif.preview_url
            );
        }
    }

    /// The expiry a proxied URL was signed with.
    fn expiry_of(url: &str) -> u64 {
        url.split(['?', '&'])
            .find_map(|pair| pair.strip_prefix("expires="))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("no expiry in {url}"))
    }

    #[test]
    fn a_sent_gif_outlives_the_picker_it_was_chosen_in() {
        // `url` goes into chat and is read back for as long as the history
        // is; `preview_url` is only ever drawn by the picker that asked. An
        // hour on the first is a backlog of broken images by morning.
        let service = proxying(service(klipy(), generous(), generous()));
        let before = now_ms();
        let action =
            service
                .answer_parts()
                .page_action(1, "r1", &Key::new("cat", 1), &provider_page());
        let after = now_ms();
        let page = page_in(&action).expect("a page");

        let hour = 3_600_000;
        let decade = 315_360_000_000;
        for gif in &page.results {
            // Counted from when the page was *sent*, not from when the
            // provider answered: the cache holds the provider's own URLs and
            // every answer signs afresh, so a page served from a cache nearly
            // as old as `gif_cache_ttl_ms` still hands out a whole grant.
            let sent = expiry_of(&gif.url);
            assert!(
                (before + decade..=after + decade).contains(&sent),
                "{}",
                gif.url
            );
            let preview = expiry_of(&gif.preview_url);
            assert!(
                (before + hour..=after + hour).contains(&preview),
                "{}",
                gif.preview_url
            );
        }
    }

    #[tokio::test]
    async fn asking_what_the_server_supports_costs_nothing() {
        // Asked on every connect. Charged, a server with a busy lobby would
        // spend its members' search budget on logins; sent upstream, it would
        // tell the provider every time somebody connects.
        let service = service(
            klipy(),
            Limit {
                rate: Rate::per_second(0.0),
                burst: 1,
            },
            Limit {
                rate: Rate::per_second(0.0),
                burst: 1,
            },
        );
        for _ in 0..5 {
            let actions = service.frame(support_query()).await;
            assert!(support_in(&actions).expect("an answer").available);
        }
        assert_eq!(service.counters.searches.get(), 0);
        assert_eq!(service.counters.upstream.get(), 0);
        assert_eq!(service.quota.cached_entries(), 0);
        // The one token each bucket holds is still there.
        assert!(service.quota.admit(7, now_ms()).is_ok());
    }
}
