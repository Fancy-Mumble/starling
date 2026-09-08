//! Composing a card: the page fetch, the picture fetch, and the shrink.
//!
//! The two fetches on their own are `starling-outbound`'s to test, and it does.
//! What is only testable here is the *composition* - reading `og:image` off the
//! page, resolving it against the URL the page ended up at, and deciding
//! whether to go and get it at all. That is where a card silently fetches the
//! wrong thing when it is wrong.
//!
//! An integration test rather than a `mod tests`, because the loopback fetcher
//! it needs comes from a `[dev-dependencies]` feature and that is exactly the
//! edge a dev-dependency is allowed to be.

// An integration test is its own crate, so it is neither `#[cfg(test)]` to
// clippy nor a user of everything the library it exercises depends on.
#![expect(
    clippy::expect_used,
    reason = "AUDIT: a test, and a fixture that cannot be built is a failure to               report rather than one to paper over"
)]

// Linked because this is a test *of* the library, used because none of them is
// what the composition under test is made of.
use prost as _;
use serde_json as _;
use starling_runtime as _;
use tonic as _;
use tracing as _;
use tracing_subscriber as _;

use starling_link_preview::{Fetcher, Limits, of_media, of_page, parse, picture_for};
use starling_outbound::testing::{asset, html, serving, status};
use starling_proto_fancy::fancy::feature::preview;

/// A real JPEG, `size` square, because the point of these tests is the bytes
/// surviving the trip intact.
fn jpeg(size: u32) -> Vec<u8> {
    sized_jpeg(size, size)
}

/// The same, at a size that is not square: what a card says a picture measures
/// is only testable where the two numbers differ.
fn sized_jpeg(width: u32, height: u32) -> Vec<u8> {
    let picture =
        image::DynamicImage::ImageRgb8(image::ImageBuffer::from_fn(width, height, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 200])
        }));
    let mut out = std::io::Cursor::new(Vec::new());
    picture
        .write_to(&mut out, image::ImageFormat::Jpeg)
        .expect("encodes");
    out.into_inner()
}

#[tokio::test]
async fn a_page_that_points_at_a_picture_ends_up_with_one_on_its_card() {
    // The whole server half in one test: fetch the page, read its `og:image`,
    // resolve it against the page it was found on, fetch that, and shrink it.
    // The image is served from a *path* the page does not live at, because the
    // relative resolution is the step that silently fetches the wrong thing
    // when it is wrong.
    let base = serving(|path| {
        if path == "/media/card.jpg" {
            asset("image/jpeg", jpeg(900))
        } else {
            html(
                r#"<head>
                     <meta property="og:title" content="A Page">
                     <meta property="og:image" content="/media/card.jpg">
                   </head>"#,
            )
        }
    })
    .await;

    let fetcher = Fetcher::against_loopback(Limits::default());
    let page = fetcher.fetch(&base).await.expect("fetched");
    let card = parse::card(&page.html);
    let thumb = picture_for(&fetcher, &page.url, &card)
        .await
        .expect("a picture");

    assert!(thumb.width <= 640 && thumb.height <= 640, "{thumb:?}");
    assert_eq!(thumb.mime, "image/jpeg");
}

#[tokio::test]
async fn a_page_whose_picture_is_missing_still_previews() {
    // A dead `og:image` is ordinary - CDNs expire, paths move - and it must
    // cost the picture and nothing else.
    let base = serving(|path| {
        if path == "/gone.jpg" {
            status(404)
        } else {
            html(r#"<head><meta property="og:image" content="/gone.jpg"></head>"#)
        }
    })
    .await;

    let fetcher = Fetcher::against_loopback(Limits::default());
    let page = fetcher.fetch(&base).await.expect("fetched");
    let card = parse::card(&page.html);
    assert!(picture_for(&fetcher, &page.url, &card).await.is_none());
}

#[tokio::test]
async fn a_page_that_calls_its_picture_enormous_is_taken_at_its_word() {
    // No request is made at all: the page has already said the decode would be
    // refused, and the cheapest fetch is the one that does not happen. Served
    // bytes that *would* have worked, so a failure here means the hint was
    // ignored rather than that the picture was bad.
    let base = serving(|path| {
        if path == "/huge.jpg" {
            asset("image/jpeg", jpeg(64))
        } else {
            html(
                r#"<head>
                     <meta property="og:image" content="/huge.jpg">
                     <meta property="og:image:width" content="30000">
                     <meta property="og:image:height" content="30000">
                   </head>"#,
            )
        }
    })
    .await;

    let fetcher = Fetcher::against_loopback(Limits::default());
    let page = fetcher.fetch(&base).await.expect("fetched");
    let card = parse::card(&page.html);
    assert_eq!(card.image_width, 30000);
    assert!(picture_for(&fetcher, &page.url, &card).await.is_none());
}

#[tokio::test]
async fn a_card_says_what_the_page_said_it_was() {
    // The classification and the facets travel together with the picture, and
    // this is the only place the whole composition runs: a page that declares
    // a video, a playing time and a byline has to arrive as a card that says
    // so, or every client draws the generic one.
    let base = serving(|path| {
        if path == "/thumb.jpg" {
            asset("image/jpeg", sized_jpeg(850, 478))
        } else {
            html(
                r#"<head>
                     <meta property="og:type" content="video.other">
                     <meta property="og:title" content="UK Hardcore 1 Hour Mix #4">
                     <meta property="og:site_name" content="YouTube">
                     <meta property="og:image" content="/thumb.jpg">
                     <meta name="author" content="UberCrow">
                     <meta itemprop="duration" content="PT1H0M14S">
                   </head>"#,
            )
        }
    })
    .await;

    let fetcher = Fetcher::against_loopback(Limits::default());
    let page = fetcher.fetch(&base).await.expect("fetched");
    let preview = of_page(&fetcher, "r1".to_owned(), page, false).await;

    assert_eq!(preview.kind, preview::Kind::Video as i32);
    assert_eq!(preview.site, "YouTube");
    assert_eq!(preview.author, "UberCrow");
    assert_eq!(preview.duration_seconds, 3614);
    // What travels is the thumbnail, and what the thumbnail *was* travels
    // beside it: both are needed to lay the card out, and after the shrink
    // the second is no longer visible in the bytes.
    assert_eq!((preview.source_width, preview.source_height), (850, 478));
    assert!(preview.image_width <= 640 && preview.image_width > 0);
}

#[tokio::test]
async fn a_link_straight_to_a_picture_is_a_card_of_that_picture() {
    // Before this, the fetch asked for a page, the host answered `image/png`,
    // and a link that is *already* the thing worth showing previewed as "that
    // link is not a page". The content type is the strongest statement about
    // a link there is: the host made it about what it is actually serving.
    let base = serving(|path| {
        if path.ends_with(".png") {
            asset("image/png", sized_jpeg(360, 253))
        } else {
            status(404)
        }
    })
    .await;

    let fetcher = Fetcher::against_loopback(Limits::default());
    let url = format!("{base}/art/summer_beach.png");
    assert!(fetcher.fetch(&url).await.is_err(), "not a page");

    let preview = of_media(&fetcher, "r2", &url).await.expect("a card");
    assert_eq!(preview.kind, preview::Kind::Image as i32);
    // The file's own name is the only title there is, and it is what somebody
    // called the picture.
    assert_eq!(preview.title, "summer beach");
    assert!(!preview.image.is_empty());
    assert_eq!((preview.source_width, preview.source_height), (360, 253));
    // Small enough that the shrink left it alone: a client is told the true
    // size so it can decline to blow a 360-wide picture up to a banner.
    assert_eq!((preview.image_width, preview.image_height), (360, 253));
}

#[tokio::test]
async fn a_link_that_is_neither_a_page_nor_a_picture_is_still_refused() {
    // The fallback may not turn "this is a zip file" into a card: the second
    // fetch asks for an image and accepts nothing else.
    let base = serving(|_| asset("application/zip", vec![0; 32])).await;
    let fetcher = Fetcher::against_loopback(Limits::default());
    assert!(of_media(&fetcher, "r3", &base).await.is_none());
}

#[tokio::test]
async fn a_page_that_withholds_its_metadata_is_asked_for_it_properly() {
    // What YouTube actually serves a crawler: a `<title>` of "- YouTube", no
    // picture, no byline - and a full answer at the oEmbed endpoint it
    // advertises two lines further down the same head. Before this, that
    // previewed as a card with a dash on it.
    let base = serving(|path| {
        if path.starts_with("/oembed") {
            asset(
                "application/json",
                br#"{"type":"video","title":"UK Hardcore 1 Hour Mix #4",
                     "author_name":"UberCrow","provider_name":"YouTube",
                     "thumbnail_url":"/thumb.jpg","thumbnail_width":480,
                     "thumbnail_height":360}"#
                    .to_vec(),
            )
        } else if path == "/thumb.jpg" {
            asset("image/jpeg", sized_jpeg(480, 360))
        } else {
            html(
                r#"<head>
                     <title>- YouTube</title>
                     <link rel="alternate" type="application/json+oembed" href="/oembed?url=x">
                   </head>"#,
            )
        }
    })
    .await;

    let fetcher = Fetcher::against_loopback(Limits::default());
    let page = fetcher.fetch(&base).await.expect("fetched");
    let preview = of_page(&fetcher, "r4".to_owned(), page, false).await;

    // The endpoint's answer to "what is this" outranks the page's own tags,
    // and everything the tags left empty comes from it.
    assert_eq!(preview.kind, preview::Kind::Video as i32);
    assert_eq!(preview.title, "UK Hardcore 1 Hour Mix #4");
    assert_eq!(preview.author, "UberCrow");
    assert_eq!(preview.site, "YouTube");
    // Including the picture, which is the whole difference between a card and
    // a card worth looking at.
    assert!(!preview.image.is_empty());
    assert_eq!((preview.source_width, preview.source_height), (480, 360));
}

#[tokio::test]
async fn a_page_that_named_its_own_picture_keeps_it() {
    // Gap-filling, not overriding: the tags are what a publisher wrote *for*
    // a card like this one, so a title and a picture already there stay.
    let base = serving(|path| {
        if path.starts_with("/oembed") {
            asset(
                "application/json",
                br#"{"type":"photo","title":"From The Endpoint",
                     "thumbnail_url":"/endpoint.jpg"}"#
                    .to_vec(),
            )
        } else {
            asset("image/jpeg", sized_jpeg(600, 400))
        }
    })
    .await;
    let base_for_page = base.clone();
    let served = serving(move |path| {
        if path == "/page" {
            html(&format!(
                r#"<head>
                     <meta property="og:title" content="From The Tags">
                     <meta property="og:image" content="{base_for_page}/own.jpg">
                     <link rel="alternate" type="application/json+oembed" href="{base_for_page}/oembed">
                   </head>"#
            ))
        } else {
            status(404)
        }
    })
    .await;

    let fetcher = Fetcher::against_loopback(Limits::default());
    let page = fetcher
        .fetch(&format!("{served}/page"))
        .await
        .expect("fetched");
    let preview = of_page(&fetcher, "r5".to_owned(), page, false).await;

    assert_eq!(preview.title, "From The Tags");
    // The kind still comes from the endpoint, because the tags have no answer
    // to that question at all.
    assert_eq!(preview.kind, preview::Kind::Image as i32);
}
