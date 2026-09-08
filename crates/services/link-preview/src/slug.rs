//! What the URL itself says, for the links nothing else will answer for.
//!
//! Every other rung asks somebody's server. This one asks the link, and it is
//! the only rung that cannot fail for a reason outside this process: no
//! request, no bot wall, no rate limit, nothing to be refused by.
//!
//! It exists because the alternative is a bare URL. A page behind a bot wall
//! that answers no client at all still arrives carrying most of its own title:
//!
//! ```text
//! /deals/abholung-dhl-paketshop-retro-games-ltd-the-c64-maxi-...-2836700
//! /dreame-Saugroboter-Wischfunktion-24-000-Saugkraft/dp/B0GSRVQB6D/
//! ```
//!
//! Those are not as good as the page's own title and they are not meant to be.
//! They are the difference between a card that says where a link goes and what
//! it is roughly about, and forty characters of hyphenated URL wrapped across
//! four lines - which is what a reader gets today when every rung is refused.
//!
//! # What it will not do
//!
//! Guess. A slug that is an identifier (a UUID, an Amazon ASIN, a bare number)
//! carries no words, and a "title" made of one is worse than none, so the
//! segment is skipped and the one before it tried instead. A URL whose path
//! yields nothing readable produces **no card at all** rather than a card
//! asserting something the URL never said.

/// The most characters a derived title may run to.
///
/// Slugs repeat the whole first sentence of an article, and a card is a few
/// lines. Cut on a word boundary rather than mid-word: a title ending in
/// "verbind" reads as corruption, one ending in "verbindung" as a title.
const MAX_TITLE: usize = 90;

/// Path segments that name a route rather than the thing at the end of it.
///
/// `/dp/` is Amazon's product route, `/p/` and `/item/` are most shops',
/// `/watch` and `/view` are what a player calls itself. None of them is what a
/// reader wants read out to them.
const ROUTE_WORDS: &[&str] = &[
    "dp", "gp", "p", "item", "items", "product", "products", "view", "watch", "index", "home",
    "page", "post", "posts", "article", "articles", "story", "en", "de", "www",
];

/// A title from the URL, or nothing if the URL says nothing.
#[must_use]
pub fn title_of(url: &str) -> String {
    let path = path_of(url);
    // Walked from the end, because the last *readable* segment is the thing
    // being linked to: "/dreame-Saugroboter-.../dp/B0GSRVQB6D" is a product
    // whose name is two segments from the end.
    for segment in path.rsplit('/') {
        let words = readable(segment);
        if !words.is_empty() {
            return capped(&words);
        }
    }
    String::new()
}

/// The path of `url`, without scheme, host, query or fragment.
fn path_of(url: &str) -> &str {
    let rest = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    rest.split_once('/').map_or("", |(_, path)| path)
}

/// The words in one path segment, or nothing if it holds none.
fn readable(segment: &str) -> String {
    let segment = decode(segment.trim_matches('/'));
    let segment = strip_extension(&segment);
    if segment.is_empty() || ROUTE_WORDS.contains(&segment.to_ascii_lowercase().as_str()) {
        return String::new();
    }
    let words: Vec<&str> = segment
        .split(['-', '_', '+', '.', ','])
        .map(str::trim)
        .filter(|word| !word.is_empty())
        // A run of digits inside a slug is a date or a size and reads fine in
        // place; one *alone* at either end is the site's own id for the thing,
        // and reading an id aloud is not a title.
        .collect();
    let words = trim_identifiers(&words);
    // Two words is the threshold, and it is what stops an id becoming a title:
    // "B0GSRVQB6D" is one word, "1w8lev2" is one word, and a real slug that
    // says anything says it in several.
    if words.iter().filter(|word| has_letters(word)).count() < 2 {
        return String::new();
    }
    words.join(" ")
}

/// The words with leading and trailing identifiers removed.
///
/// idealo puts its id first (`5972779_-860-evo-...`) and mydealz puts it last
/// (`...-via-hdmi-2836700`). Both are the site's own key for the row, and
/// neither is part of what the page is called.
fn trim_identifiers<'a>(words: &[&'a str]) -> Vec<&'a str> {
    let mut words = words;
    while let Some((first, rest)) = words.split_first() {
        if is_identifier(first, Position::Leading) {
            words = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = words.split_last() {
        if is_identifier(last, Position::Trailing) {
            words = rest;
        } else {
            break;
        }
    }
    words.to_vec()
}

/// Which end of the slug a word sits at.
///
/// It decides how a bare number is read, and the asymmetry is measured rather
/// than tidy. A number at the *end* of a slug is the site's row id or a page
/// number almost every time: `...-verbindung-via-hdmi-2836700`,
/// `...-wahl-ergebnis-analyse-100`. A *short* number at the front is usually
/// part of the name, because that is where model numbers live:
/// `860-evo-1tb-2-5-samsung` is a Samsung 860 Evo, and dropping the 860 names
/// the wrong drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Position {
    Leading,
    Trailing,
}

/// Whether a word is the site's key for something rather than a word.
///
/// Digits alone - subject to [`Position`] - or the shouted alphanumeric run a
/// catalogue uses: `B0GSRVQB6D`, `1w8lev2`. A short mixed word is left alone,
/// because "c64", "4k" and "usb" are words people would want read to them.
fn is_identifier(word: &str, position: Position) -> bool {
    if word.is_empty() {
        return true;
    }
    if word.chars().all(|c| c.is_ascii_digit()) {
        // Five digits is past every model number and year, and short of no
        // catalogue id that matters.
        return position == Position::Trailing || word.len() >= 5;
    }
    let mixed = word.chars().any(|c| c.is_ascii_digit()) && word.chars().any(char::is_alphabetic);
    mixed && word.len() >= 8
}

/// Whether a word carries any letter at all.
fn has_letters(word: &str) -> bool {
    word.chars().any(char::is_alphabetic)
}

/// A segment without its file extension.
fn strip_extension(segment: &str) -> String {
    for suffix in [".html", ".htm", ".php", ".aspx", ".asp", ".jsp", ".shtml"] {
        if let Some(stem) = segment
            .to_ascii_lowercase()
            .strip_suffix(suffix)
            .map(str::len)
        {
            return segment.get(..stem).unwrap_or(segment).to_owned();
        }
    }
    segment.to_owned()
}

/// Percent-decoding, for the slugs that carry non-ASCII words.
///
/// Bytes that are not valid UTF-8 once decoded are left as they were written:
/// a title with a stray `%` in it is a worse outcome than one that never
/// decoded, but a title full of replacement characters is worse than both.
fn decode(text: &str) -> String {
    if !text.contains('%') {
        return text.to_owned();
    }
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes.get(at).copied().unwrap_or(b'%');
        if byte == b'%' && at + 2 < bytes.len() {
            let hex = text.get(at + 1..at + 3).unwrap_or_default();
            if let Ok(decoded) = u8::from_str_radix(hex, 16) {
                out.push(decoded);
                at += 3;
                continue;
            }
        }
        out.push(byte);
        at += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// The title, capped on a word boundary and with its first letter raised.
fn capped(words: &str) -> String {
    let mut title = String::with_capacity(words.len().min(MAX_TITLE));
    for word in words.split(' ') {
        if title.len() + word.len() + 1 > MAX_TITLE {
            break;
        }
        if !title.is_empty() {
            title.push(' ');
        }
        title.push_str(word);
    }
    if title.is_empty() {
        // One word longer than the whole cap: cut it rather than return
        // nothing, on a character boundary because the input is a stranger's.
        title = words.chars().take(MAX_TITLE).collect();
    }
    let mut chars = title.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_that_started_this_carries_its_own_title() {
        // Measured: every rung including a real browser is refused for this
        // host from some addresses, and this is what is left.
        assert_eq!(
            title_of(
                "https://www.mydealz.de/deals/abholung-dhl-paketshop-retro-games-ltd-the-c64-maxi-commodore-c64-nachbau-64-vorinstallierte-classic-retrospiele-verbindung-via-hdmi-2836700"
            ),
            "Abholung dhl paketshop retro games ltd the c64 maxi commodore c64 nachbau 64"
        );
    }

    #[test]
    fn a_route_segment_is_stepped_over_to_reach_the_name() {
        // Amazon: the last segment is the ASIN and the one before it is
        // `/dp/`, so the name is two steps back.
        assert_eq!(
            title_of(
                "https://www.amazon.de/dreame-Saugroboter-Wischfunktion-24-000-Saugkraft/dp/B0GSRVQB6D/?_encoding=UTF8"
            ),
            "Dreame Saugroboter Wischfunktion 24 000 Saugkraft"
        );
    }

    #[test]
    fn an_identifier_at_either_end_is_not_part_of_the_name() {
        // idealo puts its key first, mydealz puts it last.
        assert_eq!(
            title_of(
                "https://www.idealo.de/preisvergleich/OffersOfProduct/5972779_-860-evo-1tb-2-5-samsung.html"
            ),
            "860 evo 1tb 2 5 samsung"
        );
    }

    #[test]
    fn a_url_that_says_nothing_produces_nothing() {
        // The rule that keeps this honest: no words, no card, rather than a
        // card asserting something the URL never said.
        assert_eq!(title_of("https://example.org/"), "");
        assert_eq!(title_of("https://example.org"), "");
        assert_eq!(title_of("https://example.org/a1b2c3d4e5f6"), "");
        assert_eq!(title_of("https://example.org/12345"), "");
        assert_eq!(title_of("https://example.org/dp/"), "");
        // One word is an identifier as often as a title, and the cases where
        // it is not are not worth the ones where it is.
        assert_eq!(title_of("https://example.org/downloads"), "");
    }

    #[test]
    fn a_percent_encoded_slug_is_read_as_the_words_it_encodes() {
        assert_eq!(
            title_of("https://de.wikipedia.org/wiki/Gebr%C3%BCder_Grimm_Denkmal"),
            "Gebrüder Grimm Denkmal"
        );
    }

    #[test]
    fn a_very_long_slug_is_cut_between_words() {
        // A title ending mid-word reads as corruption rather than as a title.
        let title = title_of(
            "https://example.org/one-two-three-four-five-six-seven-eight-nine-ten-eleven-twelve-thirteen-fourteen-fifteen",
        );
        assert!(title.len() <= MAX_TITLE, "{title:?}");
        assert!(!title.ends_with('-'));
        assert!(
            title.split(' ').next_back().is_some_and(|last| [
                "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
                "eleven", "twelve", "thirteen", "fourteen", "fifteen"
            ]
            .contains(&last)),
            "cut mid-word: {title:?}"
        );
    }

    #[test]
    fn a_date_path_keeps_the_headline_and_not_the_date() {
        assert_eq!(
            title_of("https://www.tagesschau.de/inland/2026/09/wahl-ergebnis-analyse-100.html"),
            "Wahl ergebnis analyse"
        );
    }
}
