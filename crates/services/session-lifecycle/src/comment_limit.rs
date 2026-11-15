//! How long a user's own comment may be.
//!
//! murmur holds a comment to the rule a chat message is held to,
//! `Server::isTextAllowed` (`vendor/server/src/murmur/Server.cpp:2708`): under
//! `text_message_length` it is fine; over `image_message_length` it is not,
//! whatever it is made of; between the two only what a reader sees is
//! counted, embedded pictures left out.
//!
//! A Fancy client's profile rides in front of the comment as an HTML comment,
//! `<!--FANCY:{json}-->`, with a banner and thumbnails in it. It is no more
//! read than a picture is, so it is left out of the count the same way, and
//! the whole comment is still bounded by `image_message_length`.

use starling_runtime::over_limit;

/// Whether `comment` may be stored, given the two settings.
pub(crate) fn fits(comment: &str, text_limit: u32, image_limit: u32) -> bool {
    let whole = comment.chars().count();
    if over_limit(whole, image_limit) {
        return false;
    }
    !over_limit(whole, text_limit) || !over_limit(visible_chars(comment), text_limit)
}

/// How many characters of `html` a reader sees: what is outside tags and
/// outside `<!-- -->` comments.
///
/// Comments are skipped whole first, because the JSON inside a profile mark
/// may itself hold a `>`, which would end an ordinary tag early and count the
/// rest of the JSON as text.
fn visible_chars(html: &str) -> usize {
    let mut count = 0;
    let mut rest = html;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after
                .find("-->")
                .map_or("", |end| after.get(end + 3..).unwrap_or(""));
        } else if let Some(after) = rest.strip_prefix('<') {
            rest = after
                .find('>')
                .map_or("", |end| after.get(end + 1..).unwrap_or(""));
        } else {
            let text_end = rest.find('<').unwrap_or(rest.len());
            count += rest.get(..text_end).unwrap_or("").chars().count();
            rest = rest.get(text_end..).unwrap_or("");
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: u32 = 5_000;
    const IMAGE: u32 = 131_072;

    #[test]
    fn a_short_comment_fits_as_it_always_did() {
        assert!(fits("hello", TEXT, IMAGE));
        assert!(
            fits(&"w".repeat(5_000), TEXT, IMAGE),
            "exactly at the limit"
        );
    }

    #[test]
    fn a_profile_mark_is_not_counted_against_the_text_limit() {
        let comment = format!(
            "<!--FANCY:{{\"thumbs\":\"{}\",\"a\":\"x>y\"}}-->hi",
            "A".repeat(9_000)
        );
        assert_eq!(
            visible_chars(&comment),
            2,
            "the `>` inside the JSON ends nothing"
        );
        assert!(fits(&comment, TEXT, IMAGE));
    }

    #[test]
    fn the_words_themselves_are_still_held_to_the_text_limit() {
        assert!(!fits(&"w".repeat(5_001), TEXT, IMAGE));
        let marked = format!("<!--FANCY:{{}}--><b>{}</b>", "w".repeat(5_001));
        assert!(!fits(&marked, TEXT, IMAGE), "markup around too many words");
    }

    #[test]
    fn the_whole_comment_is_held_to_the_image_limit() {
        let comment = format!("<!--FANCY:{{\"x\":\"{}\"}}-->hi", "A".repeat(140_000));
        assert!(!fits(&comment, TEXT, IMAGE));
    }

    #[test]
    fn an_embedded_picture_is_left_out_as_murmur_leaves_it() {
        let picture = format!(
            "<img src=\"data:image/png;base64,{}\"/>caption",
            "A".repeat(20_000)
        );
        assert!(fits(&picture, TEXT, IMAGE));
    }

    #[test]
    fn a_limit_of_zero_is_no_limit() {
        assert!(fits(&"w".repeat(200_000), 0, 0));
    }
}
