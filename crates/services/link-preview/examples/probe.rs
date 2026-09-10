//! Preview one URL from the command line, and log what the crawler made of it.
//!
//! `cargo run -p starling-link-preview --example probe -- https://example.org/`
//!
//! The card a link gets is decided from what a *stranger's* server answers,
//! which is the one input no test can hold still: a page serves different
//! metadata to different crawlers, moves it behind a consent wall, or buries
//! it past the byte cap. When a preview comes out wrong, the first question is
//! always "what did the server actually receive", and answering it by reading
//! the code is guesswork. This asks.
//!
//! Deliberately an example rather than a test: it talks to the internet, so it
//! is run by a person looking into something, never by CI.
//!
//! # Why it logs rather than prints
//!
//! Because the thing being diagnosed logs. A probe that printed its own findings
//! to stdout while the code under it wrote `tracing` events to stderr gave two
//! accounts of one fetch, interleaved by luck, and the interesting half was
//! usually the one the probe did not write - the fetcher's own line about which
//! rung was refused, at which URL, with which reason. Sharing the subscriber
//! means one ordered account, with `RUST_LOG` deciding how much of it appears:
//!
//! ```text
//! RUST_LOG=debug cargo run -p starling-link-preview --example probe -- <url>
//! ```

use starling_link_preview::{Fetcher, Limits, classify, of_page, parse};
use tracing::info;

// Linked by the library, not by this: an example is its own crate.
use image as _;
use prost as _;
use serde_json as _;
use starling_imaging as _;
use starling_outbound as _;
use starling_runtime as _;
use tonic as _;

#[tokio::main]
async fn main() {
    // The library's own events go to the same place as this probe's, in the
    // order they happened. `info` by default so a run says something without
    // an environment variable, and `RUST_LOG=debug` for the fetcher's own
    // account of which rung answered what.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let Some(url) = std::env::args().nth(1) else {
        tracing::error!("usage: probe <url>");
        return;
    };
    // The user agent an operator would get by default, because which crawler
    // we claim to be is exactly the sort of thing that changes the answer.
    let fetcher = Fetcher::new(Limits::default()).announcing("");
    let page = match fetcher.fetch(&url).await {
        Ok(page) => page,
        Err(error) => {
            tracing::error!(?error, %url, "the fetch failed");
            return;
        }
    };
    info!(
        ended_at = %page.url,
        bytes = page.html.len(),
        head_ends = ?page.html.to_ascii_lowercase().find("</head"),
        "fetched"
    );
    for marker in [
        "og:title",
        "og:image",
        "og:type",
        "json+oembed",
        "<title",
        "itemprop=\"duration\"",
    ] {
        info!(marker, at = ?page.html.find(marker), "marker");
    }

    let card = parse::card(&page.html);
    info!(?card, "the card the page's own tags describe");
    // Before the oEmbed endpoint has been asked, and with no rendered body:
    // what the page's own tags alone are worth, and which of them weighed
    // most - which is the question when a card comes out the wrong shape.
    let verdict = classify::classify(&page.url, &card, None);
    info!(kind = ?verdict.kind, why = %verdict.why, "kind, from the tags alone");

    let preview = of_page(&fetcher, "probe".to_owned(), page, false).await;
    info!(
        kind = ?starling_proto_fancy::fancy::feature::preview::Kind::try_from(preview.kind),
        title = %preview.title,
        site = %preview.site,
        author = %preview.author,
        duration = preview.duration_seconds,
        published = %preview.published_at,
        rating = %preview.content_rating,
        "the preview a client would draw"
    );
    info!(
        bytes = preview.image.len(),
        thumbnail = format!("{}x{}", preview.image_width, preview.image_height),
        source = format!("{}x{}", preview.source_width, preview.source_height),
        icon_bytes = preview.icon.len(),
        "the picture on it"
    );
    for fact in &preview.facts {
        info!(key = %fact.key, label = %fact.label, value = %fact.value, "fact");
    }
}
