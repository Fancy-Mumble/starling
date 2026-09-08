//! Preview one URL from the command line, and print what the crawler made of it.
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

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line probe whose whole output is what it printed"
)]

use starling_link_preview::{Fetcher, Limits, classify, of_page, parse};

// Linked by the library, not by this: an example is its own crate.
use image as _;
use prost as _;
use serde_json as _;
use starling_outbound as _;
use starling_proto_fancy as _;
use starling_runtime as _;
use tonic as _;
use tracing as _;

#[tokio::main]
async fn main() {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: probe <url>");
        return;
    };
    // The user agent an operator would get by default, because which crawler
    // we claim to be is exactly the sort of thing that changes the answer.
    let fetcher = Fetcher::new(Limits::default()).announcing("");
    let page = match fetcher.fetch(&url).await {
        Ok(page) => page,
        Err(error) => {
            eprintln!("fetch failed: {error:?}");
            return;
        }
    };
    println!("-- fetch ---------------------------------------------------");
    println!("ended at   {}", page.url);
    println!("bytes read {}", page.html.len());
    println!(
        "head ends  {:?}",
        page.html.to_ascii_lowercase().find("</head")
    );
    for marker in [
        "og:title",
        "og:image",
        "og:type",
        "json+oembed",
        "<title",
        "itemprop=\"duration\"",
    ] {
        println!("  {marker:22} at {:?}", page.html.find(marker));
    }

    let card = parse::card(&page.html);
    println!("-- card ----------------------------------------------------");
    println!("{card:#?}");
    println!(
        "kind (before oembed) {:?}",
        classify::Kind::of(&page.url, &card)
    );

    let preview = of_page(&fetcher, "probe".to_owned(), page).await;
    println!("-- preview -------------------------------------------------");
    println!("kind      {}", preview.kind);
    println!("title     {}", preview.title);
    println!("site      {}", preview.site);
    println!("author    {}", preview.author);
    println!("duration  {}", preview.duration_seconds);
    println!("published {}", preview.published_at);
    println!("rating    {}", preview.content_rating);
    println!(
        "image     {} bytes, {}x{} from {}x{}",
        preview.image.len(),
        preview.image_width,
        preview.image_height,
        preview.source_width,
        preview.source_height
    );
    println!("icon      {} bytes", preview.icon.len());
    for fact in &preview.facts {
        println!("fact      {} = {} ({})", fact.label, fact.value, fact.key);
    }
}
