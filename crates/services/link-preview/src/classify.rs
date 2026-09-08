//! Deciding what a link actually points at.
//!
//! # Why the server decides and not the client
//!
//! A card for a video, a shop listing, a piece of artwork and a forum thread
//! are four different drawings, and none of them can be told apart from a
//! title, a description and a picture - which is all a client is given. The
//! evidence is on the server: the page's own declarations, the endpoint it
//! publishes for embedders, the content type the host served, and - when the
//! page had to be rendered to yield anything at all - what the finished
//! document is made of. Deciding here means one table of rules instead of one
//! per client, and it means a client never has to keep a list of hosts it
//! recognises, which is the design that stops working the day somebody links a
//! site nobody thought of.
//!
//! # It reads what the page says, not what the host is called
//!
//! There is deliberately no list of domains in this file. A rule that says
//! "reddit.com is a forum" knows about Reddit and nothing about the thousand
//! Discourse and Lemmy instances that are also forums, and it answers wrongly
//! the moment somebody links a Reddit *profile*. Every rule below reads a
//! declaration the page made about itself, or something the document plainly
//! is.
//!
//! # Decisive answers, then weighed evidence
//!
//! Three things settle the question outright: whether the page named a price,
//! what it told an embedder, and what type it gave itself in `schema.org`.
//! Each is a deliberate statement about the content, written by somebody who
//! wanted it read. (A fourth lives outside this function: what the host served
//! - see [`of_content_type`] - and it beats all of them.)
//!
//! Everything else is *evidence*, because pages contradict themselves
//! constantly: `og:type` of "website" on a video, an art host that calls its
//! pieces articles, a news story with a reply count. So the rest is scored
//! rather than ordered - each signal adds weight to a kind, the heaviest wins,
//! and a page that says nothing recognisable stays a [`Kind::Page`], which is
//! a card too. Ordering rules by hand is what produces "fix one kind, break
//! another"; a weight is a thing you can argue about in one place.

use starling_proto_fancy::fancy::feature::preview;

use crate::parse::Card;

/// What a link points at.
///
/// Mirrors `Preview.Kind` on the wire; the conversion is [`Kind::wire`]. Kept
/// as a Rust enum here rather than using the generated one directly so the
/// rules read as rules, and so a change to either shape has to be made
/// deliberately in both.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Nothing in particular: an ordinary page, which is most of them.
    #[default]
    Page,
    /// A piece somebody published: a news story, a post, a wiki entry.
    Article,
    /// Something to watch.
    Video,
    /// The link *is* a picture, rather than a page that has one on it.
    Image,
    /// Something to listen to.
    Audio,
    /// Something for sale. The card carries a price.
    Product,
    /// A thread somebody replied to.
    Forum,
    /// A person or an account.
    Profile,
}

/// Every kind that can be scored, in the order a tie is broken.
///
/// More specific first: a page that is equally a video and an article is a
/// video, because "article" is what a CMS calls everything it publishes.
const RANKED: [Kind; 7] = [
    Kind::Video,
    Kind::Audio,
    Kind::Image,
    Kind::Product,
    Kind::Forum,
    Kind::Profile,
    Kind::Article,
];

/// What the classifier decided, and the one thing that decided it.
///
/// The reason is for the operator's log and for `examples/probe.rs`: when a
/// card comes out wrong, the only useful question is which signal won, and
/// re-deriving that by reading the page again is how an afternoon goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// What it is.
    pub kind: Kind,
    /// The signal that weighed most towards it.
    pub why: &'static str,
}

impl Kind {
    /// What this is on the wire.
    #[must_use]
    pub const fn wire(self) -> preview::Kind {
        match self {
            Self::Page => preview::Kind::Page,
            Self::Article => preview::Kind::Article,
            Self::Video => preview::Kind::Video,
            Self::Image => preview::Kind::Image,
            Self::Audio => preview::Kind::Audio,
            Self::Product => preview::Kind::Product,
            Self::Forum => preview::Kind::Forum,
            Self::Profile => preview::Kind::Profile,
        }
    }

    /// What the page at `url` is, given what it said about itself.
    ///
    /// The short form, for callers with no rendered document; see [`classify`].
    #[must_use]
    pub fn of(url: &str, card: &Card) -> Self {
        classify(url, card, None).kind
    }
}

/// Decide, and say what decided it.
///
/// `rendered` is the finished document, and is `Some` only when the page had
/// to be put through a browser to yield anything - see `climb`. It is the one
/// input here that is not a declaration: a page that says nothing about itself
/// may still visibly *be* a video, and by the time a renderer has been spent
/// on it, reading what came back is free.
#[must_use]
pub fn classify(url: &str, card: &Card, rendered: Option<&str>) -> Verdict {
    if let Some(settled) = declared(card) {
        return settled;
    }
    let mut scores = Scores::default();
    weigh_tags(card, &mut scores);
    weigh_url(url, &mut scores);
    if let Some(html) = rendered {
        weigh_document(html, &mut scores);
    }
    scores.verdict()
}

/// The three statements that settle it outright.
fn declared(card: &Card) -> Option<Verdict> {
    // A price is the least ambiguous thing a page can say, and it is said in a
    // tag that exists for no other purpose.
    if card.price.is_named() {
        return Some(Verdict {
            kind: Kind::Product,
            why: "a named price",
        });
    }
    // What the page told an *embedder*. `og:type` is what a share button
    // should say, filled in by a CMS that calls every page an article; this is
    // filled in by the code that would embed the thing.
    match card.oembed_type.as_str() {
        "video" => {
            return Some(Verdict {
                kind: Kind::Video,
                why: "its oEmbed endpoint says video",
            });
        }
        "photo" => {
            return Some(Verdict {
                kind: Kind::Image,
                why: "its oEmbed endpoint says photo",
            });
        }
        _ => {}
    }
    // The type it gave itself for a search engine, which is the most precise
    // vocabulary any of these pages speaks.
    schema_kind(&card.schema_type).map(|kind| Verdict {
        kind,
        why: "the schema.org type it gave itself",
    })
}

/// A `schema.org` type as a kind, where it names one.
fn schema_kind(named: &str) -> Option<Kind> {
    match named {
        "videoobject" | "movie" | "tvepisode" | "musicvideoobject" => Some(Kind::Video),
        "imageobject" | "photograph" | "painting" | "visualartwork" => Some(Kind::Image),
        "audioobject" | "musicrecording" | "podcastepisode" => Some(Kind::Audio),
        "product" | "productgroup" | "offer" => Some(Kind::Product),
        "discussionforumposting" | "socialmediaposting" | "question" | "answer" => {
            Some(Kind::Forum)
        }
        "person" | "profilepage" => Some(Kind::Profile),
        "newsarticle" | "article" | "blogposting" | "report" | "techarticle"
        | "liveblogposting" => Some(Kind::Article),
        _ => None,
    }
}

/// Weights, and the reason attached to each.
#[derive(Debug, Default)]
struct Scores {
    entries: Vec<(Kind, i32, &'static str)>,
}

impl Scores {
    fn add(&mut self, kind: Kind, weight: i32, why: &'static str) {
        self.entries.push((kind, weight, why));
    }

    /// The heaviest kind, and the single signal that contributed most to it.
    fn verdict(&self) -> Verdict {
        let mut best = Verdict {
            kind: Kind::Page,
            why: "nothing the page said",
        };
        let mut best_total = 0;
        for kind in RANKED {
            let mine = || self.entries.iter().filter(|(scored, ..)| *scored == kind);
            let total: i32 = mine().map(|(_, weight, _)| weight).sum();
            if total > best_total {
                let why = mine()
                    .max_by_key(|(_, weight, _)| *weight)
                    .map_or("several small signals", |(_, _, why)| *why);
                best = Verdict { kind, why };
                best_total = total;
            }
        }
        best
    }
}

/// What the page's own tags are worth.
fn weigh_tags(card: &Card, scores: &mut Scores) {
    let page_type = card.page_type.as_str();
    if page_type.starts_with("product") {
        scores.add(Kind::Product, 4, "og:type says product");
    }
    if page_type.starts_with("video") {
        scores.add(Kind::Video, 4, "og:type says video");
    }
    if page_type.starts_with("music") || page_type.starts_with("audio") {
        scores.add(Kind::Audio, 4, "og:type says music");
    }
    if page_type.starts_with("profile") {
        scores.add(Kind::Profile, 4, "og:type says profile");
    }
    if page_type.starts_with("article") || page_type.starts_with("book") {
        // Lower than the rest on purpose: "article" is what a CMS calls
        // everything it publishes, including an artwork and a listing.
        scores.add(Kind::Article, 2, "og:type says article");
    }
    // Something to play, named. A page that carries a player has something to
    // play whatever it calls itself, and "website" is what a great many of
    // them call themselves.
    if !card.video.is_empty() {
        scores.add(Kind::Video, 4, "it names a video to play");
    }
    if !card.audio.is_empty() {
        scores.add(Kind::Audio, 4, "it names audio to play");
    }
    if card.twitter_card == "player" {
        scores.add(Kind::Video, 3, "its Twitter card is a player");
    }
    // A playing time says there is *something* with a duration, and not which
    // of the two it is - so it is worth a little to both and settles neither.
    if card.duration > 0 {
        scores.add(Kind::Video, 1, "it states a playing time");
        scores.add(Kind::Audio, 1, "it states a playing time");
    }
    if is_thread(card) {
        scores.add(Kind::Forum, 5, "it counts replies to itself");
    }
    if card.product_tags {
        // Weaker than a price, because a listing that is sold out states no
        // price and is still a listing.
        scores.add(Kind::Product, 3, "it uses the product vocabulary");
    }
    if card.profile_tags {
        scores.add(Kind::Profile, 3, "it uses the profile vocabulary");
    }
    if card.article_tags {
        scores.add(Kind::Article, 2, "it uses the article vocabulary");
    }
    // "rich" is an embeddable widget, which art hosts, music services and
    // social sites all answer. It settles nothing alone; with a picture of the
    // work beside it, it is a page whose content is media.
    if card.oembed_type == "rich" && !card.image.is_empty() {
        scores.add(Kind::Image, 3, "it offers a rich embed of a picture");
    }
}

/// What the URL itself claims.
///
/// The one place a *name* is read rather than a declaration, and it is barely
/// one: `/art/piece.png` is a claim the URL makes about what is at the other
/// end, in the same way a `content-type` header is.
fn weigh_url(url: &str, scores: &mut Scores) {
    let Some(extension) = extension_of(url) else {
        return;
    };
    match extension.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "bmp" | "apng" | "jxl" => {
            scores.add(Kind::Image, 5, "the URL names a picture file");
        }
        "mp4" | "webm" | "mkv" | "mov" | "m4v" | "avi" => {
            scores.add(Kind::Video, 5, "the URL names a video file");
        }
        "mp3" | "flac" | "ogg" | "oga" | "wav" | "m4a" | "opus" => {
            scores.add(Kind::Audio, 5, "the URL names an audio file");
        }
        _ => {}
    }
}

/// The extension of the last path segment, lowercased.
fn extension_of(url: &str) -> Option<String> {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    path.rsplit_once('.')
        .map(|(_, extension)| extension.to_owned())
}

/// Whether the page is one post in a discussion rather than a publication.
///
/// Two independent signals, either of which is enough on its own only when
/// paired with something that says "this is a document with a body":
///
/// * the page counts replies at itself - `twitter:label1` of "Reply count" is
///   what every Discourse instance in the world publishes, and what a news
///   site's article does not;
/// * it was generated by forum software *and* declares itself an article,
///   which a thread does and a forum's index page does not.
fn is_thread(card: &Card) -> bool {
    let counts_replies = card
        .facts
        .iter()
        .any(|fact| matches!(fact.key.as_str(), "comments" | "score"));
    let forum_software = [
        "discourse",
        "xenforo",
        "phpbb",
        "vbulletin",
        "flarum",
        "nodebb",
        "mybb",
        "smf",
        "lemmy",
    ]
    .iter()
    .any(|engine| card.generator.contains(engine));
    let article_shaped =
        card.page_type.starts_with("article") || card.page_type.starts_with("website");
    article_shaped && (counts_replies || forum_software)
}

/// How much of a rendered document is read before this gives up.
///
/// The renderer caps what it returns already; this is a second bound so the
/// scan costs the same whatever that cap is set to. A page that has not shown
/// what it is in a quarter of a megabyte of markup is a page that is mostly
/// script.
const SCAN: usize = 256 * 1024;

/// What the finished document plainly is.
///
/// Only reached when the page came back from a browser, which happens for the
/// sites that serve a crawler nothing at all - and those are exactly the sites
/// whose metadata cannot be trusted to answer any of this. What a document is
/// made of is harder to get wrong than what it says: a `<video>` is a video.
fn weigh_document(html: &str, scores: &mut Scores) {
    let html = html.get(..SCAN.min(html.len())).unwrap_or(html);
    let lower = html.to_ascii_lowercase();
    let count = |needle: &str| lower.matches(needle).count();

    if count("<video") > 0 {
        scores.add(Kind::Video, 5, "the rendered page has a video element");
    }
    if count("<audio") > 0 {
        scores.add(Kind::Audio, 5, "the rendered page has an audio element");
    }
    // A player somebody embedded. `/embed/` is the convention every video host
    // follows, and it is a shape rather than a host name.
    if lower.contains("<iframe") && (lower.contains("/embed/") || lower.contains("player")) {
        scores.add(Kind::Video, 3, "the rendered page embeds a player");
    }
    // A discussion is repetition: one comment is a quote, thirty is a thread.
    let comments = count("comment") + count("\"reply") + count("replies");
    if comments >= 8 {
        scores.add(Kind::Forum, 4, "the rendered page is mostly comments");
    }
    // Something to buy has controls for buying it.
    let buying = count("add to cart")
        + count("add to basket")
        + count("in den warenkorb")
        + count("itemprop=\"price\"")
        + count("add-to-cart");
    if buying > 0 {
        scores.add(Kind::Product, 4, "the rendered page has a way to buy it");
    }

    // What is left when the markup goes: a document with a body of prose is an
    // article, and a page with a picture and almost no words is a picture.
    let words = text_length(html);
    let pictures = count("<img");
    if words > 2500 {
        scores.add(Kind::Article, 4, "the rendered page is a body of prose");
    } else if words > 900 {
        scores.add(Kind::Article, 2, "the rendered page is mostly prose");
    }
    if words < 400 && (1..=4).contains(&pictures) {
        scores.add(
            Kind::Image,
            3,
            "the rendered page is a picture and little else",
        );
    }
}

/// How many characters of text a document has, ignoring its script and style.
///
/// A scan rather than a parse, for the reason `parse` is one: this runs over a
/// document a stranger chose. It over-counts a little - the contents of a
/// `<template>` count as text - and that is fine, because the number is only
/// ever compared against a threshold.
fn text_length(html: &str) -> usize {
    let lower = html.to_ascii_lowercase();
    let mut length = 0usize;
    let mut depth_of_code = 0usize;
    let mut inside_tag = false;
    for (index, byte) in html.bytes().enumerate() {
        let rest = lower.get(index..).unwrap_or_default();
        if byte == b'<' {
            inside_tag = true;
            if rest.starts_with("<script") || rest.starts_with("<style") {
                depth_of_code += 1;
            } else if rest.starts_with("</script") || rest.starts_with("</style") {
                depth_of_code = depth_of_code.saturating_sub(1);
            }
        } else if byte == b'>' {
            inside_tag = false;
        } else if !inside_tag && depth_of_code == 0 && !byte.is_ascii_whitespace() {
            length += 1;
        }
    }
    length
}

/// What the `content-type` a host actually served says the link is.
///
/// The strongest evidence there is, and the only kind that does not depend on
/// a publisher having filled a vocabulary in: a host that answers `image/png`
/// has settled the question. `None` for anything that is a document - a page
/// is classified by reading it, which is what everything else here does.
#[must_use]
pub fn of_content_type(mime: &str) -> Option<Kind> {
    let mime = mime.trim().to_ascii_lowercase();
    let mime = mime.split(';').next().unwrap_or(&mime);
    if mime.starts_with("image/") {
        return Some(Kind::Image);
    }
    if mime.starts_with("video/") {
        return Some(Kind::Video);
    }
    if mime.starts_with("audio/") {
        return Some(Kind::Audio);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{Fact, Price};

    fn card(page_type: &str) -> Card {
        Card {
            page_type: page_type.to_owned(),
            ..Card::default()
        }
    }

    #[test]
    fn a_page_that_says_nothing_is_an_ordinary_page() {
        assert_eq!(
            Kind::of("https://example.org/", &Card::default()),
            Kind::Page
        );
    }

    #[test]
    fn the_opengraph_vocabulary_is_read_by_its_prefix() {
        // `og:type` is a namespace, not a word: "video.other",
        // "video.episode" and "music.song" are all defined values, and a rule
        // matching them exactly would classify half the web as an ordinary
        // page.
        assert_eq!(
            Kind::of("https://e.org/v", &card("video.other")),
            Kind::Video
        );
        assert_eq!(
            Kind::of("https://e.org/s", &card("music.song")),
            Kind::Audio
        );
        assert_eq!(Kind::of("https://e.org/a", &card("article")), Kind::Article);
        assert_eq!(Kind::of("https://e.org/u", &card("profile")), Kind::Profile);
    }

    #[test]
    fn a_price_settles_it_whatever_else_the_page_claims() {
        let listing = Card {
            page_type: "article".to_owned(),
            price: Price {
                amount: "89.99".to_owned(),
                ..Price::default()
            },
            ..Card::default()
        };
        let verdict = classify("https://shop.example/x", &listing, None);
        assert_eq!(verdict.kind, Kind::Product);
        assert_eq!(verdict.why, "a named price");
    }

    #[test]
    fn the_type_a_page_gave_itself_for_a_search_engine_outranks_its_share_tag() {
        // The disagreement this exists for: a CMS that calls every page an
        // article, and a `schema.org` block that names the thing precisely.
        let clip = Card {
            page_type: "article".to_owned(),
            schema_type: "videoobject".to_owned(),
            ..Card::default()
        };
        assert_eq!(classify("https://e.org/v", &clip, None).kind, Kind::Video);

        let art = Card {
            page_type: "article".to_owned(),
            schema_type: "photograph".to_owned(),
            ..Card::default()
        };
        assert_eq!(classify("https://e.org/p", &art, None).kind, Kind::Image);
    }

    #[test]
    fn a_page_that_names_a_player_is_media_whatever_it_calls_itself() {
        // "website" is what a great many video pages say in `og:type`.
        let clip = Card {
            page_type: "website".to_owned(),
            video: "https://cdn.example/clip.mp4".to_owned(),
            ..Card::default()
        };
        assert_eq!(Kind::of("https://e.org/clip", &clip), Kind::Video);

        let song = Card {
            page_type: "website".to_owned(),
            audio: "https://cdn.example/song.mp3".to_owned(),
            ..Card::default()
        };
        assert_eq!(Kind::of("https://e.org/song", &song), Kind::Audio);
    }

    #[test]
    fn a_playing_time_alone_settles_nothing() {
        // It says there is something with a duration, not which of the two it
        // is, so it must not be able to outvote anything.
        let stated = Card {
            page_type: "article".to_owned(),
            duration: 212,
            ..Card::default()
        };
        assert_eq!(
            Kind::of("https://e.org/x", &stated),
            Kind::Article,
            "a stated article with a duration is still an article"
        );
    }

    #[test]
    fn a_listing_with_nothing_in_stock_is_still_a_listing() {
        let sold_out = Card {
            page_type: "website".to_owned(),
            product_tags: true,
            ..Card::default()
        };
        assert_eq!(Kind::of("https://shop.example/x", &sold_out), Kind::Product);
    }

    #[test]
    fn an_article_people_replied_to_is_a_thread() {
        let thread = Card {
            page_type: "article".to_owned(),
            facts: vec![Fact {
                key: "comments".to_owned(),
                label: "Reply count".to_owned(),
                value: "206".to_owned(),
            }],
            ..Card::default()
        };
        // Both are in evidence - it is an article that counts replies - and
        // the reply count is the heavier, which is the point of weighing them
        // rather than ordering them.
        assert_eq!(Kind::of("https://forum.example/t/1", &thread), Kind::Forum);
    }

    #[test]
    fn forum_software_names_itself_and_that_is_enough() {
        let thread = Card {
            page_type: "article".to_owned(),
            generator: "discourse 3.2.0".to_owned(),
            ..Card::default()
        };
        assert_eq!(Kind::of("https://forum.example/t/1", &thread), Kind::Forum);
        // The index page of the same forum is not a thread: it is not an
        // article, and nothing on it has been replied to.
        let index = Card {
            generator: "discourse 3.2.0".to_owned(),
            ..Card::default()
        };
        assert_eq!(Kind::of("https://forum.example/", &index), Kind::Page);
    }

    #[test]
    fn a_url_that_names_a_file_is_that_file() {
        let bare = Card::default();
        assert_eq!(
            Kind::of("https://cdn.example/a/art.PNG", &bare),
            Kind::Image
        );
        assert_eq!(Kind::of("https://cdn.example/clip.mp4", &bare), Kind::Video);
        assert_eq!(
            Kind::of("https://cdn.example/song.flac", &bare),
            Kind::Audio
        );
        // A page *about* a picture is not the picture: the name in the query
        // belongs to a parameter, and the path is a gallery.
        assert_eq!(
            Kind::of("https://example.org/gallery?file=art.png", &bare),
            Kind::Page
        );
    }

    #[test]
    fn what_the_host_served_is_read_before_anything_the_page_claims() {
        assert_eq!(of_content_type("image/png"), Some(Kind::Image));
        assert_eq!(
            of_content_type("audio/mpeg; charset=binary"),
            Some(Kind::Audio)
        );
        assert_eq!(of_content_type("video/mp4"), Some(Kind::Video));
        // A document is classified by reading it, not by its type.
        assert_eq!(of_content_type("text/html"), None);
    }

    #[test]
    fn a_rendered_document_is_read_for_what_it_plainly_is() {
        // The case this exists for: a page that serves a crawler nothing at
        // all, which is why it was rendered - so its metadata cannot be the
        // thing that decides.
        let bare = Card::default();
        let player = r#"<html><body><div><video src="/x.mp4"></video></div></body></html>"#;
        let verdict = classify("https://e.org/watch", &bare, Some(player));
        assert_eq!(verdict.kind, Kind::Video);
        assert_eq!(verdict.why, "the rendered page has a video element");

        let shop = r#"<html><body><h1>A Thing</h1><button>Add to cart</button></body></html>"#;
        assert_eq!(
            classify("https://e.org/item", &bare, Some(shop)).kind,
            Kind::Product
        );
    }

    #[test]
    fn a_rendered_document_full_of_replies_is_a_thread() {
        let mut thread = String::from("<html><body>");
        for index in 0..12 {
            thread.push_str(&format!("<div class=\"comment\">reply {index}</div>"));
        }
        thread.push_str("</body></html>");
        assert_eq!(
            classify("https://e.org/t/1", &Card::default(), Some(&thread)).kind,
            Kind::Forum
        );
    }

    #[test]
    fn a_rendered_body_of_prose_is_an_article_and_a_bare_picture_is_not() {
        let prose = format!(
            "<html><body><article>{}</article></body></html>",
            "word ".repeat(700)
        );
        assert_eq!(
            classify("https://e.org/story", &Card::default(), Some(&prose)).kind,
            Kind::Article
        );

        let picture = r#"<html><body><figure><img src="/a.jpg"><figcaption>x</figcaption></figure></body></html>"#;
        assert_eq!(
            classify("https://e.org/p", &Card::default(), Some(picture)).kind,
            Kind::Image
        );
    }

    #[test]
    fn the_script_a_page_ships_is_not_prose() {
        // Every rendered page carries hundreds of kilobytes of it, and
        // counting that as text would make every one of them an article.
        let scripted = format!(
            "<html><head><script>{}</script></head><body><p>short</p></body></html>",
            "var x = 1; ".repeat(500)
        );
        assert_eq!(
            classify("https://e.org/app", &Card::default(), Some(&scripted)).kind,
            Kind::Page
        );
    }
}
