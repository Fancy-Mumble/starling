//! What a page publishes about itself in `JSON-LD`.
//!
//! # Why this exists beside the meta tags
//!
//! `OpenGraph` was designed to make a link look right when it is shared, so it
//! carries a title, a picture and a sentence and stops. The things a reader
//! actually asks about a link - who made this, when, how many people liked it,
//! is it rated for everyone - are not in that vocabulary, and the pages that
//! publish them publish them here: `schema.org` in a
//! `<script type="application/ld+json">`, which is the same block a search
//! engine reads. An art site names the `creator`, a shop the
//! `aggregateRating`, a video its `uploadDate` and its view count.
//!
//! # What this is not
//!
//! It is not a `schema.org` implementation. It walks the document looking for
//! a handful of well-known keys wherever they appear - inside `@graph`, inside
//! an array, nested under an `ItemPage` - and takes the first plausible value
//! for each. A page whose structure it does not recognise yields nothing,
//! which is the same outcome as a page that published none of this.
//!
//! # Bounded, because a stranger wrote it
//!
//! Only blocks inside `<head>` are read - the fetch stops at `</head>`, so
//! nothing further down is even downloaded - and the walk has a depth limit.
//! `serde_json` does the parsing: a hand-rolled reader over a document a
//! stranger chose is exactly the sort of thing this crate's HTML scanner
//! exists to avoid.

use serde_json::Value;

/// The absent value, for [`field`] to hand back.
///
/// A `static` rather than `Value::Null` inline, because a reference into a
/// document that does not have the key has to point at something that
/// outlives the call.
static NOTHING: Value = Value::Null;

/// One key of `value`, or nothing where it has no such key.
///
/// `serde_json`'s own `value["key"]` does exactly this and cannot panic on an
/// object - but it *is* an `Index`, and indexing is denied in this workspace
/// because the reader cannot tell which indexes are the safe kind. This is
/// the safe kind, spelled so.
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&NOTHING)
}

/// How deep the walk goes before it stops looking.
///
/// `@graph` nests two or three levels on the pages that use it, and a
/// document that buries its author deeper than this is a document that has
/// stopped describing itself and started describing its layout.
const MAX_DEPTH: u8 = 6;

/// The `schema.org` types worth reading, and what each one means about a page.
///
/// Deliberately a short list of *content* types. `WebSite`, `WebPage`,
/// `Organization` and `BreadcrumbList` are on almost every page that publishes
/// any of this and describe the site rather than the thing, so reading them
/// would classify the whole web as "a page".
const CONTENT_TYPES: &[&str] = &[
    "videoobject",
    "movie",
    "tvepisode",
    "musicvideoobject",
    "imageobject",
    "photograph",
    "painting",
    "visualartwork",
    "audioobject",
    "musicrecording",
    "podcastepisode",
    "newsarticle",
    "article",
    "blogposting",
    "report",
    "techarticle",
    "liveblogposting",
    "discussionforumposting",
    "socialmediaposting",
    "question",
    "answer",
    "product",
    "productgroup",
    "offer",
    "person",
    "profilepage",
];

/// Keys whose value describes something *else* - the author, the picture, the
/// publisher - rather than the thing the page is about.
///
/// The walk does not descend into them when it is looking for a type: an
/// article's `image` is an `ImageObject`, and reading that as the page's own
/// type turns every illustrated news story into a photograph.
const SUB_ENTITY_KEYS: &[&str] = &[
    "image",
    "thumbnail",
    "author",
    "creator",
    "publisher",
    "logo",
    "breadcrumb",
    "potentialaction",
    "aggregaterating",
    "interactionstatistic",
    "provider",
    "sponsor",
    "video",
];

/// What a page's structured data said, where it said anything.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Structured {
    /// The `@type` of the thing the page is about, lowercased.
    ///
    /// The shallowest one that names actual content; see `CONTENT_TYPES`.
    pub kind: String,
    /// `author` or `creator`, as a name.
    pub author: String,
    /// `datePublished`, `uploadDate` or `dateCreated`, as written.
    pub published: String,
    /// `contentRating`, lowercased.
    pub rating: String,
    /// `aggregateRating`, rendered as the page's own scale: "4.6/5".
    pub stars: String,
    /// How many ratings that average is of, as written.
    pub rating_count: String,
    /// `duration`, in seconds, from the ISO-8601 the vocabulary asks for.
    pub duration: String,
    /// How many people watched it, from `interactionStatistic`.
    pub views: String,
    /// How many liked it, from the same list.
    pub likes: String,
    /// How many replied, from the same list.
    pub comments: String,
}

impl Structured {
    /// Whether the page said anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Read every `application/ld+json` block in `head`.
///
/// Later blocks fill only what earlier ones left empty, which is the same
/// first-value-wins rule the meta tags follow: a page that repeats itself has
/// already said what it meant the first time.
#[must_use]
pub fn read(head: &str) -> Structured {
    let mut found = Structured::default();
    for block in blocks(head) {
        let Ok(value) = serde_json::from_str::<Value>(block) else {
            // A malformed block is a page that published nothing, not a
            // preview that fails: this is decoration on a card.
            continue;
        };
        walk(&value, 0, &mut found);
    }
    found
}

/// The text of each `<script type="application/ld+json">` in `html`.
fn blocks(html: &str) -> Vec<&str> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(start) = lower.get(at..).and_then(|rest| rest.find("<script")) {
        let start = at + start;
        let Some(open_end) = lower.get(start..).and_then(|rest| rest.find('>')) else {
            break;
        };
        let open_end = start + open_end + 1;
        let opener = lower.get(start..open_end).unwrap_or_default();
        // The type has to say so. A `<script>` with no type is JavaScript, and
        // handing that to a JSON parser is a waste of the parser's time.
        let is_ld = opener.contains("application/ld+json");
        let end = lower
            .get(open_end..)
            .and_then(|rest| rest.find("</script"))
            .map_or(lower.len(), |e| open_end + e);
        if is_ld && let Some(text) = html.get(open_end..end) {
            out.push(text);
        }
        at = end.max(open_end);
    }
    out
}

/// Walk `value`, filling anything `found` is still missing.
fn walk(value: &Value, depth: u8, found: &mut Structured) {
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::Array(items) => {
            for item in items {
                walk(item, depth + 1, found);
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                take(key, field, found);
            }
            // And down, because the keys above are as often on a node nested
            // under `@graph` or `mainEntity` as on the document's root - but
            // never into a key that describes something else, or an article's
            // picture would answer for the article.
            for (key, field) in fields {
                let sub = SUB_ENTITY_KEYS.contains(&key.to_ascii_lowercase().as_str());
                if !sub && (field.is_object() || field.is_array()) {
                    walk(field, depth + 1, found);
                }
            }
        }
        _ => {}
    }
}

/// Read one key, if it is one of the handful this knows.
fn take(key: &str, value: &Value, found: &mut Structured) {
    let set = |slot: &mut String, value: String| {
        if slot.is_empty() && !value.is_empty() {
            *slot = value;
        }
    };
    match key.to_ascii_lowercase().as_str() {
        // A name, an object with a name, or a list of either: all three are
        // in the wild for the same field.
        "author" | "creator" => set(&mut found.author, name_of(value)),
        "datepublished" | "uploaddate" | "datecreated" => {
            set(&mut found.published, text_of(value));
        }
        "contentrating" => set(&mut found.rating, text_of(value).to_ascii_lowercase()),
        "duration" => set(&mut found.duration, text_of(value)),
        "aggregaterating" => {
            let average = text_of(field(value, "ratingValue"));
            if !average.is_empty() {
                // On the page's own scale, because a "4.6" with no scale is a
                // number nobody can read: out of five, or out of ten?
                let best = text_of(field(value, "bestRating"));
                let best = if best.is_empty() {
                    "5".to_owned()
                } else {
                    best
                };
                set(&mut found.stars, format!("{average}/{best}"));
            }
            let count = text_of(field(value, "ratingCount"));
            let count = if count.is_empty() {
                text_of(field(value, "reviewCount"))
            } else {
                count
            };
            set(&mut found.rating_count, count);
        }
        "interactionstatistic" => interactions(value, found),
        // What the page says it *is*, which is the most precise thing it ever
        // says: `og:type` has five useful values and this vocabulary has a
        // hundred, and a list written for a search engine is filled in with
        // more care than the tag a share button reads.
        "@type" => {
            let named = match value {
                Value::String(text) => text.to_ascii_lowercase(),
                // A node may claim several types; the first recognised one is
                // as good an answer as any.
                Value::Array(items) => items
                    .iter()
                    .map(|item| text_of(item).to_ascii_lowercase())
                    .find(|text| CONTENT_TYPES.contains(&text.as_str()))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            if CONTENT_TYPES.contains(&named.as_str()) {
                set(&mut found.kind, named);
            }
        }
        _ => {}
    }
}

/// Read `interactionStatistic`, which is a list of counted actions.
fn interactions(value: &Value, found: &mut Structured) {
    let items = match value {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };
    for item in items {
        let kind = text_of(field(&item, "interactionType")).to_ascii_lowercase();
        let kind = if kind.is_empty() {
            name_of(field(&item, "interactionType")).to_ascii_lowercase()
        } else {
            kind
        };
        let count = text_of(field(&item, "userInteractionCount"));
        if count.is_empty() {
            continue;
        }
        // The type is a schema.org URL - "https://schema.org/WatchAction" -
        // so it is matched by its tail rather than compared whole: the same
        // action is written with and without the scheme, and with either
        // host.
        let slot = if kind.ends_with("watchaction") || kind.ends_with("viewaction") {
            &mut found.views
        } else if kind.ends_with("likeaction") {
            &mut found.likes
        } else if kind.ends_with("commentaction") {
            &mut found.comments
        } else {
            continue;
        };
        if slot.is_empty() {
            *slot = count;
        }
    }
}

/// A person's name - or a node's type - out of whatever shape the field took.
fn name_of(value: &Value) -> String {
    match value {
        Value::String(name) => name.trim().to_owned(),
        // `@type` after `name`, because the same helper reads both a person
        // ("who wrote this") and an action ("what was counted"), and the
        // vocabulary names those two things in different keys.
        Value::Object(_) => {
            let name = text_of(field(value, "name"));
            if name.is_empty() {
                text_of(field(value, "@type"))
            } else {
                name
            }
        }
        Value::Array(items) => items
            .iter()
            .map(name_of)
            .find(|name| !name.is_empty())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// A field as text, whether the page wrote it as a string or a number.
fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_owned(),
        Value::Number(number) => number.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_type_read_is_the_page_s_own_and_not_its_picture_s() {
        // The trap this exists for: every illustrated article carries an
        // `ImageObject` under `image`, and a walk that read types wherever it
        // found them would call every news story a photograph.
        let found = read(
            r#"<head><script type="application/ld+json">
                 {"@type":"NewsArticle","headline":"A Story",
                  "image":{"@type":"ImageObject","url":"https://cdn/x.jpg"},
                  "author":{"@type":"Person","name":"A Reporter"}}
               </script></head>"#,
        );
        assert_eq!(found.kind, "newsarticle");
        assert_eq!(found.author, "A Reporter");
    }

    #[test]
    fn the_sites_own_furniture_is_not_a_type() {
        // `WebSite`, `Organization` and `BreadcrumbList` are on every page
        // that publishes any of this, and describe the site rather than the
        // thing on it.
        let found = read(
            r#"<head><script type="application/ld+json">
                 {"@context":"https://schema.org","@graph":[
                    {"@type":"WebSite","name":"Example"},
                    {"@type":"BreadcrumbList"},
                    {"@type":"VideoObject","name":"A Clip"}]}
               </script></head>"#,
        );
        assert_eq!(found.kind, "videoobject");
    }

    #[test]
    fn a_page_with_no_structured_data_says_nothing() {
        assert!(read("<head><title>x</title></head>").is_empty());
        // And a block that is not JSON is a page that published nothing,
        // rather than a preview that fails.
        assert!(
            read(r#"<head><script type="application/ld+json">{oh no</script></head>"#).is_empty()
        );
    }

    #[test]
    fn the_creator_is_read_from_all_three_shapes_pages_write() {
        let plain =
            read(r#"<head><script type="application/ld+json">{"creator":"ame"}</script></head>"#);
        assert_eq!(plain.author, "ame");
        let object = read(
            r#"<head><script type="application/ld+json">{"author":{"name":"ame"}}</script></head>"#,
        );
        assert_eq!(object.author, "ame");
        let list = read(
            r#"<head><script type="application/ld+json">{"author":[{"name":"ame"},{"name":"two"}]}</script></head>"#,
        );
        assert_eq!(list.author, "ame");
    }

    #[test]
    fn a_rating_arrives_on_the_scale_the_page_rated_it_against() {
        let found = read(
            r#"<head><script type="application/ld+json">
                 {"aggregateRating":{"ratingValue":"4.6","bestRating":"5","ratingCount":128}}
               </script></head>"#,
        );
        // "4.6" on its own is a number nobody can read: out of five, or ten?
        assert_eq!(found.stars, "4.6/5");
        assert_eq!(found.rating_count, "128");
    }

    #[test]
    fn a_scale_the_page_left_out_is_the_one_everybody_means() {
        let found = read(
            r#"<head><script type="application/ld+json">
                 {"aggregateRating":{"ratingValue":4.6,"reviewCount":9}}
               </script></head>"#,
        );
        assert_eq!(found.stars, "4.6/5");
        // `reviewCount` where there is no `ratingCount`: the same fact under
        // the name half the web uses for it.
        assert_eq!(found.rating_count, "9");
    }

    #[test]
    fn counted_actions_are_read_by_the_action_they_count() {
        let found = read(
            r#"<head><script type="application/ld+json">
                 {"@type":"VideoObject","uploadDate":"2017-05-01T00:00:00Z",
                  "contentRating":"Safe","duration":"PT1H0M14S",
                  "interactionStatistic":[
                    {"interactionType":"https://schema.org/WatchAction","userInteractionCount":412000},
                    {"interactionType":{"@type":"LikeAction"},"userInteractionCount":9100}]}
               </script></head>"#,
        );
        assert_eq!(found.views, "412000");
        // The type as an object rather than a URL, which is the other way the
        // vocabulary is written.
        assert_eq!(found.likes, "9100");
        assert_eq!(found.published, "2017-05-01T00:00:00Z");
        assert_eq!(found.rating, "safe");
        assert_eq!(found.duration, "PT1H0M14S");
    }

    #[test]
    fn a_node_nested_under_a_graph_is_still_read() {
        // The shape every CMS that publishes structured data emits: nothing
        // is on the root object, and a walk that only read the top level
        // would find none of it.
        let found = read(
            r#"<head><script type="application/ld+json">
                 {"@context":"https://schema.org","@graph":[
                    {"@type":"WebSite","name":"Example"},
                    {"@type":"Article","author":{"@type":"Person","name":"A Reporter"},
                     "datePublished":"2026-09-01"}]}
               </script></head>"#,
        );
        assert_eq!(found.author, "A Reporter");
        assert_eq!(found.published, "2026-09-01");
    }

    #[test]
    fn a_script_that_is_not_structured_data_is_not_parsed_as_any() {
        // Every page has scripts. Only the ones that say what they are get
        // handed to a JSON parser.
        let found = read(r#"<head><script>var author = {"name":"nope"};</script></head>"#);
        assert!(found.is_empty());
    }
}
