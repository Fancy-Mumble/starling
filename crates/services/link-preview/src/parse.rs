//! Pulling a title, a description and a site name out of a page.
//!
//! # Why this is not an HTML parser
//!
//! It reads `<meta>` and `<title>` and stops at `</head>`. A conforming parser
//! would build a document we would then throw away, on input chosen by a
//! stranger, every parser bug in it becomes reachable from a chat message.
//! The job is four strings out of the head of a document, and the smaller thing
//! that does only that has less to get wrong.
//!
//! It follows that this is *lenient*: unknown tags, broken nesting and
//! attributes it does not recognise are skipped rather than refused. There is
//! no such thing as a malformed page here, only a page that yields nothing.
//!
//! # What it prefers
//!
//! `OpenGraph` first, because it is what a page author wrote *for* this, then
//! Twitter's equivalents, then the ordinary `<title>` and
//! `<meta name="description">`. A page that offers none of them gets a preview
//! with its host as the title, which is still better than a bare URL.

/// What a page says about itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Card {
    /// What the page calls itself.
    pub title: String,
    /// Its own one-line summary.
    pub description: String,
    /// The publication, where it names one.
    pub site: String,
    /// The `og:image` URL, as the page gave it.
    ///
    /// **Not** what goes on the wire: sending it would have every viewer load
    /// the origin's picture, which is precisely the network probe that having
    /// the server fetch previews exists to prevent. It is where the *server's*
    /// image fetch starts, and only the bytes it brings back travel.
    ///
    /// Relative as often as not (`/static/card.png`), so a caller resolves it
    /// against the page's own URL before it means anything.
    pub image: String,
    /// What the page says the image measures, or `0` where it did not say.
    ///
    /// A hint, and used as one: the bytes that travel are downscaled and carry
    /// their own size. This is what lets a fetch decline a picture the page
    /// itself describes as enormous without spending a request to find out.
    pub image_width: u32,
    /// The height the page claims, paired with [`Card::image_width`].
    pub image_height: u32,
}

/// Read `html` for what it says about itself.
#[must_use]
pub fn card(html: &str) -> Card {
    let head = head_of(html);
    let mut card = Card::default();

    // First value wins for each field, so a page that repeats a tag does not
    // have its own preferred answer overwritten by an afterthought further
    // down.
    let take = |slot: &mut String, value: String| {
        if slot.is_empty() && !value.is_empty() {
            *slot = value;
        }
    };
    // Same rule for the dimensions, and unparseable means absent: a page that
    // writes `og:image:width` as "large" has said nothing about the size, which
    // is exactly the state a `0` already means.
    let take_number = |slot: &mut u32, value: &str| {
        if *slot == 0 {
            *slot = value.trim().parse().unwrap_or(0);
        }
    };

    for tag in tags(head, "meta") {
        let key = attribute(tag, "property")
            .or_else(|| attribute(tag, "name"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let Some(content) = attribute(tag, "content") else {
            continue;
        };
        let content = decode(&content);
        match key.as_str() {
            "og:title" | "twitter:title" => take(&mut card.title, content),
            "og:description" | "twitter:description" | "description" => {
                take(&mut card.description, content);
            }
            // `twitter:site` is deliberately not here: by Twitter's own
            // definition it is an @handle for an account, not the name of a
            // publication, so reading it as one labelled cards "@rustlang" and
            // "@github". A page that names no site gets its host, which the
            // caller fills in because it is the only one that knows the URL.
            "og:site_name" => take(&mut card.site, content),
            // `og:image:secure_url` before `og:image`, and both before
            // Twitter's: a page that offers https for the same picture is
            // offering the one a fetch can actually use.
            "og:image:secure_url"
            | "og:image"
            | "og:image:url"
            | "twitter:image"
            | "twitter:image:src" => take(&mut card.image, content),
            "og:image:width" | "twitter:image:width" => {
                take_number(&mut card.image_width, &content);
            }
            "og:image:height" | "twitter:image:height" => {
                take_number(&mut card.image_height, &content);
            }
            _ => {}
        }
    }

    if card.title.is_empty()
        && let Some(title) = between(head, "<title", "</title")
    {
        // `<title` and not `<title>`: the tag may carry attributes, and a page
        // that writes `<title lang="en">` would otherwise have no title at all.
        let text = title.split_once('>').map_or(title, |(_, rest)| rest);
        card.title = decode(text.trim());
    }
    card
}

/// The document head, or the whole input if it has no head.
///
/// Bounded scanning: a page's metadata is at the top, and reading past
/// `</head>` is reading the entire body for tags that are not there.
fn head_of(html: &str) -> &str {
    let lower = html.to_ascii_lowercase();
    lower
        .find("</head")
        .map_or(html, |end| html.get(..end).unwrap_or(html))
}

/// Every `<name ...>` tag in `html`, as raw text.
fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let lower = html.to_ascii_lowercase();
    let opener = format!("<{name}");
    let mut out = Vec::new();
    let mut at = 0;
    // Every slice is a `get`. The input is a page a stranger chose, so a byte
    // index that lands inside a multi-byte character is a panic reachable from
    // a chat message, and `at` walks the string, so it is exactly the index
    // most likely to land in the middle of one.
    while let Some(start) = lower.get(at..).and_then(|rest| rest.find(&opener)) {
        let start = at + start;
        // The character after the name has to be a delimiter, or `<metadata>`
        // would be read as a `<meta>` tag with strange attributes.
        let after = lower.as_bytes().get(start + opener.len()).copied();
        let end = lower
            .get(start..)
            .and_then(|rest| rest.find('>'))
            .map_or(lower.len(), |e| start + e);
        if matches!(after, Some(b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>')) {
            out.push(html.get(start..end).unwrap_or_default());
        }
        at = end.max(start + 1);
    }
    out
}

/// The value of `name` in a tag, quoted or bare.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut at = 0;
    while let Some(found) = lower.get(at..).and_then(|rest| rest.find(name)) {
        let start = at + found;
        at = start + name.len();
        // Preceded by whitespace, or `name` would match inside `og:sitename`
        // and `property` inside `data-property`.
        let before = start.checked_sub(1).and_then(|i| lower.as_bytes().get(i));
        if !matches!(before, Some(b' ' | b'\t' | b'\n' | b'\r' | b'<')) {
            continue;
        }
        let rest = lower.get(at..)?.trim_start();
        if !rest.starts_with('=') {
            continue;
        }
        let value_at = tag.len() - rest.len() + 1;
        let value = tag.get(value_at..)?.trim_start();
        return Some(match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value
                .get(1..)?
                .split(quote)
                .next()
                .unwrap_or_default()
                .to_owned(),
            _ => value
                .split([' ', '\t', '\n', '\r', '>'])
                .next()
                .unwrap_or_default()
                .to_owned(),
        });
    }
    None
}

/// The text between two markers, case-insensitively.
fn between<'a>(html: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find(open)? + open.len();
    let end = lower.get(start..)?.find(close)? + start;
    html.get(start..end)
}

/// Decode the handful of entities that actually appear in titles.
///
/// Not a full entity table: `&amp;` and the numeric forms are what a title
/// carries, and the rest render as themselves, which is a better failure than
/// dropping the text.
fn decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(rest.get(..start).unwrap_or_default());
        let after = rest.get(start..).unwrap_or_default();
        let Some(end) = after.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = after.get(1..).unwrap_or_default();
            continue;
        };
        let entity = after.get(1..end).unwrap_or_default();
        let decoded = match entity.to_ascii_lowercase().as_str() {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            _ => entity
                .strip_prefix('#')
                .and_then(|number| match number.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => number.parse().ok(),
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(character) => out.push(character),
            // Unrecognised, so it goes back verbatim: an entity nobody decodes
            // renders as itself, which is a better outcome than dropping the
            // text around it.
            None => out.push_str(after.get(..=end).unwrap_or_default()),
        }
        rest = after.get(end + 1..).unwrap_or_default();
    }
    out.push_str(rest);
    // Collapsed, because HTML treats a newline in a title as a space and a
    // client rendering one gets a preview card with a hole in it.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opengraph_wins_and_the_title_tag_is_the_fallback() {
        let card = card(
            r#"<html><head>
                 <title>Fallback</title>
                 <meta property="og:title" content="The Real Title">
                 <meta property="og:site_name" content="Example">
               </head><body>ignored</body></html>"#,
        );
        assert_eq!(card.title, "The Real Title");
        assert_eq!(card.site, "Example");
    }

    #[test]
    fn a_page_with_only_a_title_tag_still_previews() {
        let card = card("<html><head><title lang=\"en\">Just This</title></head>");
        assert_eq!(card.title, "Just This");
    }

    #[test]
    fn entities_are_decoded_and_whitespace_collapsed() {
        let card = card(
            "<head><title>Fish &amp; Chips\n   &#128512; a review &#x1F600; part&nbsp;2</title></head>",
        );
        // U+1F600, decimal and hex, because an emoji is the widest a single
        // `char` gets: four UTF-8 bytes, and above the BMP, so it is also a
        // surrogate pair anywhere the text passes through UTF-16. A decoder
        // holding a codepoint in a `u16`, or truncating to one byte, passes on
        // a Latin-1 entity and fails here.
        //
        // Written as `\u{...}` rather than as the character, so the assertion is
        // byte-for-byte what the entity decodes to while the file stays ASCII.
        assert_eq!(
            card.title,
            "Fish & Chips \u{1F600} a review \u{1F600} part 2"
        );
    }

    #[test]
    fn the_widest_codepoint_and_the_longest_entity_that_can_name_it_both_survive() {
        // Two limits that meet. `char::from_u32` accepts up to U+10FFFF, and
        // `decode` only treats `&...;` as an entity when the `;` is within ten
        // bytes of the `&` - which the *longest* way to write that codepoint,
        // seven decimal digits, just fits with one byte to spare. Tightening
        // that window would silently stop decoding the top of the range,
        // leaving the entity rendered as its own source text.
        let widest = card("<head><title>&#1114111; and &#x10FFFF;</title></head>");
        assert_eq!(widest.title, "\u{10FFFF} and \u{10FFFF}");

        // A grapheme built from two codepoints, eight bytes in all: each entity
        // decodes on its own and they are concatenated untouched, so the pair
        // is still one cluster to anything that renders it. The whitespace
        // collapse runs over the decoded string, and must not find a seam here.
        let flag = card("<head><title>a &#x1F1E9;&#x1F1EA; b</title></head>");
        assert_eq!(flag.title, "a \u{1F1E9}\u{1F1EA} b");
    }

    #[test]
    fn single_quoted_and_bare_attributes_are_read() {
        let card = card("<head><meta property='og:title' content='Quoted'></head>");
        assert_eq!(card.title, "Quoted");
    }

    #[test]
    fn a_tag_whose_name_merely_starts_the_same_is_not_a_meta_tag() {
        // `<metadata>` is not `<meta>`. Reading it as one is how a parser picks
        // up content from a tag that was never about the document.
        let card = card(r#"<head><metadata content="Not This"></metadata></head>"#);
        assert!(card.title.is_empty());
    }

    #[test]
    fn an_attribute_that_merely_ends_the_same_is_not_that_attribute() {
        let card = card(r#"<head><meta data-content="No" property="og:title"></head>"#);
        // `data-content` must not answer for `content`, so there is nothing to
        // take and the title stays empty rather than becoming "No".
        assert!(card.title.is_empty());
    }

    #[test]
    fn the_body_is_not_scanned() {
        // Bounded on purpose: metadata is in the head, and a `<meta>` in the
        // body is either a mistake or somebody's idea of a joke.
        let card = card(
            "<head><title>Head</title></head><body><meta property=\"og:title\" content=\"Body\"></body>",
        );
        assert_eq!(card.title, "Head");
    }

    #[test]
    fn the_first_value_wins() {
        let card = card(
            r#"<head>
                 <meta property="og:title" content="First">
                 <meta property="og:title" content="Second">
               </head>"#,
        );
        assert_eq!(card.title, "First");
    }

    #[test]
    fn the_picture_and_the_size_it_claims_are_both_read() {
        let card = card(
            r#"<head>
                 <meta property="og:image" content="https://cdn.example/card.png">
                 <meta property="og:image:width" content="1200">
                 <meta property="og:image:height" content="630">
               </head>"#,
        );
        assert_eq!(card.image, "https://cdn.example/card.png");
        assert_eq!((card.image_width, card.image_height), (1200, 630));
    }

    #[test]
    fn a_size_that_is_not_a_number_is_the_same_as_no_size() {
        // The dimensions are a hint used to decline enormous pictures early. A
        // page that writes "large" has said nothing, and nothing is `0`, not a
        // refusal and not a panic.
        let card = card(
            r#"<head>
                 <meta property="og:image" content="/c.png">
                 <meta property="og:image:width" content="large">
               </head>"#,
        );
        assert_eq!(card.image_width, 0);
        assert_eq!(card.image, "/c.png");
    }

    #[test]
    fn twitter_names_the_picture_when_opengraph_does_not() {
        let card = card(r#"<head><meta name="twitter:image" content="/t.png"></head>"#);
        assert_eq!(card.image, "/t.png");
    }

    #[test]
    fn a_page_with_nothing_to_say_yields_an_empty_card() {
        assert_eq!(card("<html><body>hello</body></html>"), Card::default());
    }

    #[test]
    fn a_truncated_page_still_yields_what_it_had() {
        // The byte cap cuts pages mid-document, so this is the ordinary case
        // for anything large, not an edge one.
        let card = card("<html><head><meta property=\"og:title\" content=\"Cut Off\"><meta prop");
        assert_eq!(card.title, "Cut Off");
    }
}
