//! `link-preview`: previews fetched by the server, never by the client.
//!
//! A preview fetched by the viewer turns every chat link into a way to probe
//! that viewer's network and learn their address. Fetching here moves both to
//! the server, which is the point, and makes the SSRF guard the server's
//! problem, where it can actually be enforced.
//!
//! The guard is a deny list of destinations no legitimate preview target ever
//! lives on: loopback, link-local, and the private ranges that hold a cloud
//! metadata service. It lives in `starling-outbound`, one tier below: the
//! `gifs` service needs the same guard for the same reason, services may not
//! link each other, and a second copy of that deny list is a second list to
//! keep in step with this one.

pub mod classify;
pub mod climb;
pub mod ladder;
pub mod parse;
pub mod quota;
pub mod structured;
pub mod thumbnail;

use std::sync::Arc;
use std::time::Duration;

// Re-exported rather than renamed at every call site: these were this crate's
// surface before the guard moved, and they still describe what a preview does.
pub use starling_outbound::{
    DEFAULT_USER_AGENT, FetchError, Fetcher, Limits, Page, Refusal, fetch, vet,
};

use prost::Message as _;
use starling_proto_fancy::fancy::feature::{
    LinkPreviewEnvelope, Preview, PreviewError, PreviewRequest, link_preview_envelope, preview,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::ratelimit::Rate;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

use crate::climb::{Climb, Reached, Renderer};
use crate::ladder::{Cooldowns, Ladder, Memory};
use crate::quota::{Limit, Quota};

/// The service.
#[derive(Debug)]
pub struct LinkPreviewService {
    fanout: Fanout,
    logger: Logger,
    /// How a page is asked for, which rungs are allowed, what each host needed
    /// last time and what a person may spend of the browser. Cloned into every
    /// walk; see [`climb`].
    climb: Climb,
}

impl ClientService for LinkPreviewService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::LinkPreview.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = LinkPreviewEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable LinkPreviewEnvelope"
            );
            return Actions::new();
        };
        let Some(link_preview_envelope::Body::Request(request)) = envelope.body else {
            return Actions::new();
        };

        // One answer per URL, and the caps are per request: a message with
        // forty links is forty fetches, and a client that sends one is not
        // doing anything a client is not allowed to do.
        let mut actions = Actions::new();
        for url in &request.urls {
            match vet(url) {
                Err(refusal) => {
                    actions.push(self.refuse(&inbound, &request.request_id, url, refusal));
                }
                Ok(()) => {
                    // The fetch happens off this handler and the answer arrives
                    // through the fanout. A preview is a request to a host
                    // somebody else chose: it takes as long as that host takes,
                    // and awaiting it here would hold this connection's frame
                    // handler for seconds while a stranger's server decides.
                    self.spawn_fetch(
                        inbound.conn,
                        inbound.session,
                        PreviewRequest {
                            request_id: request.request_id.clone(),
                            urls: vec![url.clone()],
                        },
                    );
                }
            }
        }
        actions
    }
}

impl LinkPreviewService {
    /// Tell the client why a URL will not be fetched, and the operator when it
    /// is the kind of refusal worth knowing about.
    fn refuse(
        &self,
        inbound: &Inbound,
        request_id: &str,
        url: &str,
        refusal: Refusal,
    ) -> starling_proto_fancy::control::ServerAction {
        // A client asking the server to fetch a loopback or metadata address is
        // an SSRF attempt, whether or not it knows it. The guard already
        // refuses; this is what makes it visible, and it records the session so
        // a repeat offender is attributable.
        if matches!(refusal, Refusal::PrivateAddress) {
            tracing::warn!(
                session = inbound.session,
                url = %url,
                "link preview refused: the target is inside the deployment"
            );
            self.logger.log(
                LogEvent::warning(Category::Security, "link preview refused: private address")
                    .with("session", inbound.session)
                    .with("url", url.to_owned()),
            );
        } else {
            tracing::debug!(
                session = inbound.session,
                reason = refusal.reason(),
                "link preview refused"
            );
        }
        to_conn(
            inbound.conn,
            ServiceKind::LinkPreview.outer_type(),
            LinkPreviewEnvelope {
                body: Some(link_preview_envelope::Body::Error(PreviewError {
                    request_id: request_id.to_owned(),
                    // Named, so a client with several links in one message can
                    // say which of them it could not preview.
                    reason: format!("{url}: {}", refusal.reason()),
                })),
            }
            .encode_to_vec(),
        )
    }
}

impl LinkPreviewService {
    /// Climb the ladder in the background and push the answer when it arrives.
    ///
    /// Off this handler, because a preview is a request to a host somebody else
    /// chose: it takes as long as that host takes, and awaiting it here would
    /// hold this connection's frame handler for seconds while a stranger's
    /// server decides - now several times over, since a walk may ask more than
    /// once.
    fn spawn_fetch(&self, conn: u64, session: u32, request: PreviewRequest) {
        let climb = self.climb.clone();
        let fanout = self.fanout.clone();
        let logger = self.logger.clone();
        let outer = ServiceKind::LinkPreview.outer_type();
        drop(tokio::spawn(async move {
            let url = request.urls.first().cloned().unwrap_or_default();
            let body = match climb.walk(&url, session).await {
                Reached::Page { page, rung } => {
                    // The picture is fetched as whoever fetched the page: an
                    // `og:image` behind the same wall answers the same client.
                    let fetcher = climb.fetcher_for(rung);
                    link_preview_envelope::Body::Preview(
                        of_page(&fetcher, request.request_id, page).await,
                    )
                }
                // Not a page, which for a link somebody pasted usually means
                // it is a picture: the host said so in its `content-type`,
                // and that is a better answer than any page ever gives. It is
                // fetched again as one - `fetch_image` accepts nothing else,
                // so a type that only *looked* like an image still fails -
                // and the picture becomes its own card.
                Reached::NotAPage => {
                    let fetcher = climb.fetcher_for(climb.ladder.cheapest());
                    match of_media(&fetcher, &request.request_id, &url).await {
                        Some(preview) => link_preview_envelope::Body::Preview(preview),
                        None => link_preview_envelope::Body::Error(PreviewError {
                            request_id: request.request_id,
                            reason: format!("{url}: {}", FetchError::NotHtml.reason()),
                        }),
                    }
                }
                Reached::Nothing(reason) => {
                    // The operator's line, which the client is not given: a
                    // name that resolves inside the deployment is a fact about
                    // this network, and a stranger mapping it one URL at a time
                    // must not have it. The walk has already logged which rungs
                    // were tried at debug level.
                    if reason.contains(FetchError::ResolvesInside.reason()) {
                        logger.log(
                            LogEvent::warning(
                                Category::Security,
                                "link preview refused: the name resolves inside the deployment",
                            )
                            .with("url", url.clone()),
                        );
                    }
                    tracing::debug!(url = %url, reason, "link preview failed");
                    link_preview_envelope::Body::Error(PreviewError {
                        request_id: request.request_id,
                        reason: format!("{url}: {reason}"),
                    })
                }
            };
            fanout.push(to_conn(
                conn,
                outer,
                LinkPreviewEnvelope { body: Some(body) }.encode_to_vec(),
            ));
        }));
    }
}

/// The card for a page that was read.
///
/// Everything a client draws comes from here, and what makes the several
/// drawings possible is that the *kind* is decided on this side: the page's
/// own declarations are in front of us, and they are not in front of a client
/// holding a title and a thumbnail. See [`classify`].
///
/// Public for `tests/card.rs`, which is where the composition of the two
/// fetches is exercised, as [`picture_for`] is and for the same reason.
pub async fn of_page(fetcher: &Fetcher, request_id: String, page: Page) -> Preview {
    let card = parse::card(&page.html);
    let kind = classify::Kind::of(&page.url, &card);
    // A second fetch, of a second host, before the answer goes out: the card
    // is worth more with the picture on it, and the picture is only safe to
    // show because the server is the one that went and got it.
    let picture = picture_for(fetcher, &page.url, &card).await;
    // And the site's own mark, which is the one thing on a card that says
    // where a link goes before a word of it is read. Fetched here for the
    // reason the picture is: a favicon loaded by every viewer is a request
    // per reader to a host that then knows who is in the channel.
    let icon = icon_for(fetcher, &page.url, &card).await;
    // A page that never named itself is labelled with its host, which is what
    // a reader wanted from that line anyway: where this link goes.
    let site = if card.site.is_empty() {
        host_of(&page.url)
    } else {
        card.site
    };
    Preview {
        request_id,
        // Where it *ended up*: a preview of a shortened link that shows the
        // shortener has told the reader nothing.
        url: page.url,
        title: card.title,
        description: card.description,
        site,
        // Left empty, and this is the honest state rather than an oversight:
        // `image_key` names a full-resolution object in the files service, and
        // nothing here stores one yet. The thumbnail below is what clients
        // render, and it travels as bytes precisely so no viewer has to
        // contact the origin to see it.
        image_key: String::new(),
        kind: kind.wire() as i32,
        author: card.author,
        duration_seconds: card.duration,
        // The price only where the page named one, whatever the kind: a
        // `PRODUCT` with an empty price block would have a client drawing a
        // currency symbol next to nothing.
        price: card.price.is_named().then_some(preview::Price {
            amount: card.price.amount,
            currency: card.price.currency,
            was: card.price.was,
            availability: card.price.availability,
        }),
        facts: card
            .facts
            .into_iter()
            .map(|fact| preview::Fact {
                key: fact.key,
                label: fact.label,
                value: fact.value,
            })
            .collect(),
        published_at: card.published,
        content_rating: card.rating,
        icon: icon
            .as_ref()
            .map(|mark| mark.bytes.clone())
            .unwrap_or_default(),
        icon_mime: icon
            .as_ref()
            .map(|mark| mark.mime.to_owned())
            .unwrap_or_default(),
        ..with_picture(picture.as_ref())
    }
}

/// The card for a URL that turned out to *be* a picture.
///
/// A link straight to an image had no preview at all before this: the fetch
/// asks for a page, the host answers `image/png`, and a card that would have
/// been the picture itself became "that link is not a page". The content type
/// is the strongest classification there is - the host said what it was
/// serving - so the picture is fetched as one and becomes its own card.
///
/// `None` where the second fetch fails too, and then the caller reports the
/// original refusal rather than this one: what the reader needs to know is
/// that the link did not preview, not that it did not preview twice.
///
/// Public for `tests/card.rs`; see [`of_page`].
pub async fn of_media(fetcher: &Fetcher, request_id: &str, url: &str) -> Option<Preview> {
    let limits = fetcher.limits();
    let image = fetcher.fetch_image(url).await.ok()?;
    let picture = thumbnail::shrink(&image.bytes, limits.image_edge, limits.image_pixels)?;
    Some(Preview {
        request_id: request_id.to_owned(),
        // The file's own name, which is all the title there is: a picture
        // carries no `<title>`, and an empty one leaves a client printing the
        // URL it already has.
        title: file_name_of(&image.url),
        site: host_of(&image.url),
        url: image.url,
        kind: classify::Kind::Image.wire() as i32,
        ..with_picture(Some(&picture))
    })
}

/// The longest side of a site icon that travels.
///
/// A favicon is drawn at 13 points beside the source's name, so this is what
/// that needs on a dense screen and nothing more: the 512-pixel PNG a site
/// publishes for a phone's home screen is 40 kilobytes that no reader will
/// ever see the detail of, paid once per viewer.
const ICON_EDGE: u32 = 48;

/// Fetch and shrink the site icon `card` declared, if it declared one.
///
/// `None` for every way it does not happen, exactly as [`picture_for`]: the
/// card is drawn with a monogram instead, which is what a page that declares
/// no icon gets anyway. It may never cost the preview.
async fn icon_for(
    fetcher: &Fetcher,
    page_url: &str,
    card: &parse::Card,
) -> Option<thumbnail::Thumbnail> {
    if card.icon.is_empty() || fetcher.limits().image_bytes == 0 {
        return None;
    }
    let url = fetch::join(page_url, &card.icon);
    if !fetcher.private_is_allowed()
        && let Err(refusal) = vet(&url)
    {
        tracing::debug!(%url, reason = refusal.reason(), "site icon refused");
        return None;
    }
    match fetcher.fetch_image(&url).await {
        Ok(image) => thumbnail::shrink(&image.bytes, ICON_EDGE, fetcher.limits().image_pixels),
        Err(error) => {
            tracing::debug!(%url, ?error, "site icon could not be fetched");
            None
        }
    }
}

/// The picture's half of a [`Preview`], or the empty state of those fields.
///
/// Its own function because both cards fill them the same way and there are
/// six of them: two constructors that each spell out six fields is two places
/// for the thumbnail and the original to be confused for each other.
fn with_picture(picture: Option<&thumbnail::Thumbnail>) -> Preview {
    Preview {
        image: picture.map(|thumb| thumb.bytes.clone()).unwrap_or_default(),
        image_mime: picture
            .map(|thumb| thumb.mime.to_owned())
            .unwrap_or_default(),
        image_width: picture.map_or(0, |thumb| thumb.width),
        image_height: picture.map_or(0, |thumb| thumb.height),
        source_width: picture.map_or(0, |thumb| thumb.source_width),
        source_height: picture.map_or(0, |thumb| thumb.source_height),
        ..Preview::default()
    }
}

/// The last path segment of `url`, without its extension, as a title.
///
/// `/art/summer-beach_2026.png` becomes "summer-beach 2026": a file name is
/// what somebody called the picture, and the separators that make it a legal
/// name are not part of what they called it.
fn file_name_of(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let name = path.rsplit('/').next().unwrap_or_default();
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    let spaced = stem.replace(['_', '+', '%'], " ");
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The bare host of `url`, as a label for a page that named no site.
///
/// `www.` goes, because "www.rust-lang.org" is not what anybody calls it, and
/// the point of the line is recognition.
fn host_of(url: &str) -> String {
    let rest = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default();
    let host = rest
        .split('@')
        .next_back()
        .unwrap_or(rest)
        .split(':')
        .next()
        .unwrap_or(rest);
    host.strip_prefix("www.").unwrap_or(host).to_owned()
}

/// Fetch and shrink the picture `card` points at, if it points at one.
///
/// Public for `tests/card.rs`, which is the only place the *composition* of
/// the two fetches can be exercised; nothing outside this crate calls it.
///
/// `None` covers every way this does not happen - the page named no image, the
/// URL is one the guard refuses, the host would not answer, the file is past
/// the cap, the bytes are not a picture the decoder knows. All of them are the
/// same outcome for a reader: a card with words and no picture, which is the
/// preview they would have had anyway. None of them may cost the *preview*,
/// which is why this cannot return an error the caller might propagate.
pub async fn picture_for(
    fetcher: &Fetcher,
    page_url: &str,
    card: &parse::Card,
) -> Option<thumbnail::Thumbnail> {
    if card.image.is_empty() {
        return None;
    }
    let limits = fetcher.limits();
    if limits.image_bytes == 0 {
        return None;
    }
    // What the page *says* it is, before a byte is fetched: a page describing
    // a 30000x30000 image has already told us the decode would be refused, and
    // a request saved is a request a stranger did not get the server to make.
    let claimed = u64::from(card.image_width) * u64::from(card.image_height);
    if claimed > u64::from(limits.image_pixels) {
        tracing::debug!(
            url = %card.image,
            width = card.image_width,
            height = card.image_height,
            "preview image skipped: the page describes it as too large"
        );
        return None;
    }

    // Resolved against the page it was found on, because `og:image` is a
    // relative path as often as not, and then vetted in its own right: the
    // image is a *different* host from the page, and an SSRF guard that
    // checked only the page would be a guard around the front door of a house
    // with two.
    let url = fetch::join(page_url, &card.image);
    // Belt and braces, and the braces are the ones that hold: `fetch_image`
    // vets every hop of its own accord, so this is the early-out that saves a
    // socket rather than the check the guard depends on.
    if !fetcher.private_is_allowed()
        && let Err(refusal) = vet(&url)
    {
        tracing::debug!(%url, reason = refusal.reason(), "preview image refused");
        return None;
    }
    match fetcher.fetch_image(&url).await {
        Ok(image) => thumbnail::shrink(&image.bytes, limits.image_edge, limits.image_pixels),
        Err(error) => {
            tracing::debug!(%url, ?error, "preview image could not be fetched");
            None
        }
    }
}

impl Serve for LinkPreviewService {
    const NAME: &'static str = "link-preview";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        // Every limit is an operator's to raise, and every default is chosen to
        // be the one a server can leave alone. They bound work a *stranger*
        // asks for against a host the stranger picked, so the defaults are
        // deliberately mean.
        let service = ctx.service();
        let default = Limits::default();
        let limits = Limits {
            timeout: service
                .option::<u64>("preview_timeout_ms")
                .map_or(default.timeout, Duration::from_millis),
            bytes: service
                .option::<usize>("preview_max_bytes")
                .unwrap_or(default.bytes),
            redirects: service
                .option::<u8>("preview_redirects")
                .unwrap_or(default.redirects),
            concurrency: service
                .option::<usize>("preview_concurrency")
                .unwrap_or(default.concurrency)
                // Zero would mean "never fetch anything", silently, and an
                // operator who wants that switches the service off.
                .max(1),
            image_bytes: service
                .option::<usize>("preview_image_max_bytes")
                .unwrap_or(default.image_bytes),
            image_edge: service
                .option::<u32>("preview_image_edge")
                .unwrap_or(default.image_edge)
                // A zero-pixel thumbnail is not a smaller picture, it is a
                // decode that produces nothing. An operator switching images
                // off has `preview_image_max_bytes` for that.
                .max(16),
            image_pixels: service
                .option::<u32>("preview_image_max_pixels")
                .unwrap_or(default.image_pixels),
            // Not a preview knob and deliberately not offered as one: this
            // service never asks for JSON, so the cap bounds nothing an
            // operator here could tune. `gifs` owns that setting.
            json_bytes: default.json_bytes,
        };
        // What this server calls itself on the first rung. An operator who
        // would rather be identifiable by name and contact address than by
        // version says so here; the other rungs are not theirs to name, because
        // each is a specific lie that a specific set of sites answers to. See
        // `ladder`.
        let honest = service
            .option::<String>("preview_user_agent")
            .filter(|agent| !agent.trim().is_empty())
            .unwrap_or_else(|| ladder::HONEST_USER_AGENT.to_owned());
        // Which rungs this server will climb, in order. The browser is not on
        // the default ladder: it is a second container and a renderer running a
        // stranger's script, and neither should arrive because somebody
        // upgraded. See `preview_ladder` in `examples/reference.toml`.
        let ladder = Ladder::parse(
            &service
                .option::<String>("preview_ladder")
                .unwrap_or_default(),
        );
        let cooldowns = Cooldowns {
            revalidate: service
                .option::<u64>("preview_method_ttl_ms")
                .map_or(Cooldowns::default().revalidate, Duration::from_millis),
            hopeless: service
                .option::<u64>("preview_method_retry_ms")
                .map_or(Cooldowns::default().hopeless, Duration::from_millis),
        };
        // Both buckets are the browser's alone: every other rung is an HTTP
        // request the fetch limits already bound, and charging those to a
        // person would be charging them for the cheap thing.
        let quota = Quota::new(
            Limit {
                rate: service
                    .option::<Rate>("preview_browser_session_rate")
                    .unwrap_or_else(|| Rate::per_second(3.0 / 60.0)),
                burst: service
                    .option::<u32>("preview_browser_session_burst")
                    .unwrap_or(3),
            },
            Limit {
                rate: service
                    .option::<Rate>("preview_browser_server_rate")
                    .unwrap_or_else(|| Rate::per_second(30.0 / 60.0)),
                burst: service
                    .option::<u32>("preview_browser_server_burst")
                    .unwrap_or(10),
            },
            starling_runtime::ids::now_ms(),
        );
        // Dialled only if the operator put the browser on the ladder. A
        // renderer nobody asked for is a service dialled for nothing.
        let renderer = ladder.has_headless().then(|| Renderer {
            resolver: ctx.resolver.clone(),
            budget: service
                .option::<u64>("preview_browser_timeout_ms")
                .map_or(Duration::from_secs(20), Duration::from_millis),
        });
        tracing::info!(
            ladder = ladder.describe(),
            browser = renderer.is_some(),
            "link preview ladder"
        );
        Ok(Arc::new(Self {
            fanout: Fanout::default(),
            logger: ctx.logger,
            climb: Climb {
                fetcher: Fetcher::new(limits),
                ladder,
                memory: Arc::new(Memory::new(
                    cooldowns,
                    service
                        .option::<usize>("preview_method_hosts")
                        .unwrap_or(4096),
                )),
                quota: Arc::new(quota),
                honest: Arc::from(honest.trim()),
                renderer,
            },
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_that_names_no_site_is_labelled_with_its_host() {
        assert_eq!(host_of("https://www.rust-lang.org/learn"), "rust-lang.org");
        assert_eq!(
            host_of("https://de.wikipedia.org/wiki/Jean-Baptiste_Auriol"),
            "de.wikipedia.org"
        );
        // The port and any credentials belong to the connection, not to the
        // label a reader is shown.
        assert_eq!(host_of("http://user:pw@example.org:8080/a"), "example.org");
    }

    #[test]
    fn the_guard_still_refuses_what_it_always_did() {
        // The deny list itself is tested where it now lives. This asserts the
        // *wiring*: this service reaches that guard, so moving the crate under
        // it cannot quietly leave previews unguarded.
        assert_eq!(
            vet("http://169.254.169.254/latest/meta-data/"),
            Err(Refusal::PrivateAddress)
        );
        assert!(vet("https://example.org/article").is_ok());
    }
}
