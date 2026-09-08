//! Deciding what a link actually points at.
//!
//! # Why the server decides and not the client
//!
//! A card for a video, a shop listing, a piece of artwork and a forum thread
//! are four different drawings, and none of them can be told apart from a
//! title, a description and a picture - which is all a client is given. The
//! evidence is on the server: the page's own `og:type`, the Twitter card it
//! declares, the content type the host actually served, whether it named a
//! price, whether it counts replies. Deciding here means one table of rules
//! instead of one per client, and it means a client never has to keep a list
//! of hosts it recognises - which is the design that stops working the day
//! somebody links a site nobody thought of.
//!
//! # It reads what the page says, not what the host is called
//!
//! There is deliberately no list of domains in this file. A rule that says
//! "reddit.com is a forum" is a rule that knows about Reddit and nothing about
//! the thousand Discourse and Lemmy instances that are also forums, and it
//! answers wrongly the moment somebody links a Reddit *profile*. Every rule
//! below reads a declaration the page made about itself: the vocabularies
//! (`OpenGraph`, Twitter cards, `<meta name="generator">`) exist precisely so
//! a crawler does not have to guess, and a page that declares nothing gets
//! [`Kind::Page`], which is a card too.
//!
//! The one exception is the file extension in [`Kind::of`], and it is not
//! really one: `/art/piece.png` is a claim the URL itself makes about what is
//! at the other end, in the same way a `content-type` header is.

use starling_proto_fancy::fancy::feature::preview;

use crate::parse::Card;

/// What a link points at.
///
/// Mirrors `Preview.Kind` on the wire; the conversion is [`Kind::wire`]. Kept
/// as a Rust enum here rather than using the generated one directly so the
/// rules read as rules, and so a change to either shape has to be made
/// deliberately in both.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
    /// The order of the rules is the whole of the design, because pages
    /// declare several things at once and the declarations disagree. A shop
    /// listing is `og:type=product` *and* an article by its Twitter card; a
    /// Discourse thread is `og:type=article` with a reply count under it;
    /// `YouTube` is `og:type=video.other` and also a `player` card. So the more
    /// specific evidence is read first, and the general vocabulary last.
    #[must_use]
    pub fn of(url: &str, card: &Card) -> Self {
        let page_type = card.page_type.as_str();
        // A price is the least ambiguous thing a page can say, and it is
        // said in a tag that exists for no other purpose. Anything with one
        // is a listing, whatever else it claims to be.
        if card.price.is_named() || page_type.starts_with("product") {
            return Self::Product;
        }
        // Playing time and a player card are both statements that there is
        // something to play, and `og:type` is where a page says which of the
        // two it is - `music.song` and `video.movie` are both "media with a
        // duration" until you read it.
        if page_type.starts_with("music") || page_type.starts_with("audio") {
            return Self::Audio;
        }
        if page_type.starts_with("video") || card.twitter_card == "player" {
            return Self::Video;
        }
        if page_type.starts_with("profile") {
            return Self::Profile;
        }
        // A thread is an article that people replied to. Both halves matter:
        // the reply count alone is on some news sites too, and forum software
        // alone is on the front page of every forum, which is not a thread.
        if is_thread(card) {
            return Self::Forum;
        }
        if page_type.starts_with("article") || page_type.starts_with("book") {
            return Self::Article;
        }
        if page_type.starts_with("image")
            || page_type.starts_with("photo")
            || page_type.starts_with("artwork")
            || is_image_url(url)
        {
            return Self::Image;
        }
        Self::Page
    }
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

/// Whether the URL's own path claims to be a picture.
///
/// The query string is dropped first: `/image.png?width=800` is a picture, and
/// `/gallery?file=a.png` is a page about one. Everything after the last `/`
/// and its final `.` is the claim.
fn is_image_url(url: &str) -> bool {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let Some((_, extension)) = path.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "bmp" | "apng" | "jxl"
    )
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
        // The case this exists for: a shop's listing page is `og:type=article`
        // on a surprising number of sites, and the price is the thing that is
        // never there by accident.
        let listing = Card {
            page_type: "article".to_owned(),
            price: Price {
                amount: "89.99".to_owned(),
                currency: "EUR".to_owned(),
                ..Price::default()
            },
            ..Card::default()
        };
        assert_eq!(Kind::of("https://shop.example/x", &listing), Kind::Product);
    }

    #[test]
    fn a_player_card_is_a_video_where_the_page_named_no_type() {
        let embedded = Card {
            twitter_card: "player".to_owned(),
            ..Card::default()
        };
        assert_eq!(Kind::of("https://e.org/clip", &embedded), Kind::Video);
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
    fn a_url_that_names_a_picture_is_one() {
        let bare = Card::default();
        assert_eq!(
            Kind::of("https://cdn.example/a/art.PNG", &bare),
            Kind::Image
        );
        assert_eq!(
            Kind::of("https://cdn.example/art.jpg?w=800", &bare),
            Kind::Image
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
}
