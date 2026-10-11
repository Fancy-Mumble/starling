//! What a message may contain, and how long it may be.
//!
//! murmur's `Server::isTextAllowed` (`Server.cpp:2708`), transcribed. Both
//! settings were in `server-config` and read by nothing: an operator could turn
//! HTML off and clients kept posting markup, or set a length and clients kept
//! posting novels (`docs/GAP-ANALYSIS.md` §5).
//!
//! # Why HTML off means *rewrite* rather than refuse
//!
//! It is the difference between a chat window that shows plain text and one
//! that shows nothing. murmur strips the markup and delivers the words, so a
//! client that sends `<b>hi</b>` to a server with HTML off is heard saying
//! `hi`. Refusing would punish the user for their client's default formatting.
//!
//! # Why the length check comes *after* the strip
//!
//! The limit is on the message, not on its markup. Measuring before would let
//! `text_message_length` be exhausted by tags the recipient never sees, which
//! is how a 5000-character limit ends up refusing a two-line message pasted
//! with formatting.
//!
//! # Why Fancy markers survive the strip
//!
//! A Fancy client says what a message *is* in HTML comments: `<!-- FANCY_FILE:
//! ... -->` for an attachment, others for a voice note, a reply, a watch
//! invitation. Stripped with the rest of the markup, a voice note or a picture
//! sent without a caption became an empty body and vanished, and one with a
//! caption reached other Fancy clients as the caption alone. They are not
//! formatting, a stock client draws a comment as nothing, so they are kept.
//!
//! The one fenced region, `<!-- FANCY_LEGACY -->...<!-- /FANCY_LEGACY -->`, is
//! the part written *for* stock clients, and its contents are stripped like any
//! other text: with HTML off, that audience gets the words of the fallback
//! ("(edited)" before an edit, a file's name) and none of its markup.

use starling_runtime::over_limit;

/// What the server decided about one message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Deliver it unchanged.
    Deliver,
    /// Deliver this instead, the markup was stripped.
    Rewritten(String),
    /// Refuse it: too long, and no rewrite would shorten it.
    TooLong,
}

/// Whether `text` may be delivered, given the two settings.
///
/// `image_message_length` bounds the whole body when HTML is allowed, because
/// that is where a data-URI image lives: without it a single `<img src=...>` is
/// an unbounded upload wearing a chat message.
#[must_use]
pub fn check(text: &str, allow_html: bool, text_limit: u32, image_limit: u32) -> Verdict {
    if !allow_html {
        let (stripped, visible) = strip_keeping_markers(text);
        // The markers are not words anybody reads, so they do not spend the
        // limit; a file marker alone is a few hundred characters of JSON.
        if over_limit(visible, text_limit) {
            return Verdict::TooLong;
        }
        return if stripped == text {
            Verdict::Deliver
        } else {
            Verdict::Rewritten(stripped)
        };
    }

    let length = text.chars().count();
    if text_limit == 0 && image_limit == 0 {
        return Verdict::Deliver;
    }
    // Over the image ceiling is fatal whatever it is made of: this is the
    // bound on the *bytes*, and nothing can be stripped to get under it.
    if over_limit(length, image_limit) {
        return Verdict::TooLong;
    }
    if !over_limit(length, text_limit) {
        return Verdict::Deliver;
    }
    // Over the text limit but under the image one. murmur's rule: if it is not
    // markup at all it is simply too long, and if it is, the text limit is
    // measured with image payloads discounted, the picture was already
    // bounded above.
    if !text.contains('<') {
        return Verdict::TooLong;
    }
    if over_limit(strip_html(text).chars().count(), text_limit) {
        return Verdict::TooLong;
    }
    Verdict::Deliver
}

/// The visible text of `html`, with `<br>` and `</p>` as line breaks.
///
/// Deliberately not an HTML parser. It is the same shape as murmur's
/// `HTMLFilter::filter`: take what is between the tags, treat two of them as
/// newlines, collapse whitespace, and escape any `<` or `>` that survives so
/// the result cannot be markup again. A message body is untrusted input on its
/// way to every other client's renderer, and the safe operation on untrusted
/// markup is to stop it being markup.
#[must_use]
pub fn strip_html(html: &str) -> String {
    if !html.contains('<') {
        return simplify(html);
    }

    let mut out = String::with_capacity(html.len());
    let mut tag = String::new();
    let mut in_tag = false;
    for character in html.chars() {
        match character {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                if breaks_line(&tag) {
                    out.push('\n');
                }
            }
            _ if in_tag => tag.push(character),
            _ => out.push(character),
        }
    }
    // An unterminated tag is discarded rather than emitted: `<b` at the end of
    // a message is a truncated tag, and printing it would put a `<` back into
    // text that is supposed to have none.
    escape(&simplify(&out))
}

/// Stands in for a kept marker while the rest of the body is stripped.
///
/// Private-use characters, which no renderer draws and the stripper treats as
/// ordinary text, so whitespace around a marker is collapsed exactly as it
/// would be around a word and the marker itself is never touched.
const SLOT_OPEN: char = '\u{E000}';
/// Closes the index a [`SLOT_OPEN`] opened.
const SLOT_CLOSE: char = '\u{E001}';

/// Opens an HTML comment.
const COMMENT_OPEN: &str = "<!--";
/// Closes one.
const COMMENT_CLOSE: &str = "-->";

/// The inside of the Fancy marker comment `after_open` continues, and what
/// follows it, if what follows a `<!--` is one.
///
/// `<!-- FANCY_... -->` or `<!-- /FANCY_... -->`, ending at the first `-->`.
/// One carrying a `<` or `>` inside is not a marker this keeps: the guarantee
/// of the strip is that nothing in its output can be markup again, and a
/// comment is only inert while nothing in it can close it early or open a tag.
fn fancy_marker(after_open: &str) -> Option<(&str, &str)> {
    let (inside, after) = after_open.split_once(COMMENT_CLOSE)?;
    let content = inside.trim();
    let name = content.strip_prefix('/').unwrap_or(content);
    (name.starts_with("FANCY_") && !content.contains(['<', '>'])).then_some((inside, after))
}

/// [`strip_html`], keeping every Fancy marker comment where it stood.
///
/// Returns the stripped body and how many characters of it are visible text,
/// which is what the length limit is measured against.
#[must_use]
pub fn strip_keeping_markers(html: &str) -> (String, usize) {
    // A body that already holds the stand-in characters could name a marker
    // slot of its own choosing, so they go first. Nothing legitimate is lost:
    // they are private-use code points no client draws.
    let clean: String = html
        .chars()
        .filter(|c| *c != SLOT_OPEN && *c != SLOT_CLOSE)
        .collect();
    if !clean.contains(COMMENT_OPEN) {
        let stripped = strip_html(&clean);
        let visible = stripped.chars().count();
        return (stripped, visible);
    }

    let mut markers: Vec<String> = Vec::new();
    let mut masked = String::with_capacity(clean.len());
    let mut rest = clean.as_str();
    while let Some((before, after_open)) = rest.split_once(COMMENT_OPEN) {
        masked.push_str(before);
        if let Some((inside, after)) = fancy_marker(after_open) {
            masked.push(SLOT_OPEN);
            masked.push_str(&markers.len().to_string());
            masked.push(SLOT_CLOSE);
            markers.push(format!("{COMMENT_OPEN}{inside}{COMMENT_CLOSE}"));
            rest = after;
        } else {
            // Not ours: left for the stripper, which drops it as a tag.
            masked.push_str(COMMENT_OPEN);
            rest = after_open;
        }
    }
    masked.push_str(rest);

    let stripped = strip_html(&masked);
    let mut out = String::with_capacity(stripped.len());
    let mut visible = 0_usize;
    let mut chars = stripped.chars();
    while let Some(character) = chars.next() {
        if character != SLOT_OPEN {
            out.push(character);
            visible += 1;
            continue;
        }
        let index: String = chars.by_ref().take_while(|c| *c != SLOT_CLOSE).collect();
        if let Some(marker) = index.parse::<usize>().ok().and_then(|i| markers.get(i)) {
            out.push_str(marker);
        }
    }
    (out, visible)
}

/// Whether a tag ends a line, as murmur's filter has it: `br` and `p`.
///
/// murmur emits the break on the *end* element, which is why `<p>one</p>` is
/// one newline and not two. `br` is void, a client may write it `<br>`,
/// `<br/>` or `<br />` and mean the same thing, so it breaks however it is
/// spelled, while `p` breaks only when it closes.
fn breaks_line(tag: &str) -> bool {
    let closing = tag.starts_with('/');
    let name = tag
        .trim_start_matches('/')
        .split([' ', '/', '\t'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    name == "br" || (closing && name == "p")
}

/// Collapse runs of whitespace and trim, as `QString::simplified` does.
///
/// Line breaks written by the stripper survive, because they are the one piece
/// of structure the markup carried that the reader still needs.
fn simplify(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for character in text.chars() {
        if character == '\n' {
            while out.ends_with(' ') {
                let _ = out.pop();
            }
            out.push('\n');
            pending_space = false;
        } else if character.is_whitespace() {
            pending_space = !out.is_empty();
        } else {
            if pending_space && !out.ends_with('\n') {
                out.push(' ');
            }
            pending_space = false;
            out.push(character);
        }
    }
    out.trim().to_owned()
}

/// Turn any surviving angle bracket into an entity.
fn escape(text: &str) -> String {
    text.replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_off_strips_the_markup_and_keeps_the_words() {
        // The behaviour the setting is *for*, and the reason it rewrites
        // rather than refusing: the user said "hi", and they should be heard.
        assert_eq!(
            check("<b>hi</b>", false, 0, 0),
            Verdict::Rewritten("hi".to_owned())
        );
    }

    #[test]
    fn html_on_leaves_the_markup_alone() {
        // Same message, same server, the other setting: this is the assertion
        // that the value decides the outcome rather than round-tripping.
        assert_eq!(check("<b>hi</b>", true, 0, 0), Verdict::Deliver);
    }

    #[test]
    fn plain_text_is_never_rewritten() {
        // A rewrite that changes nothing would still be re-encoded and
        // re-broadcast, and every client would see an edit that did not happen.
        assert_eq!(check("hello there", false, 0, 0), Verdict::Deliver);
    }

    #[test]
    fn a_message_over_the_length_limit_is_refused() {
        assert_eq!(check(&"x".repeat(11), true, 10, 0), Verdict::TooLong);
        assert_eq!(check(&"x".repeat(10), true, 10, 0), Verdict::Deliver);
    }

    #[test]
    fn lowering_the_length_limit_refuses_what_it_had_delivered() {
        // §5: the setting has to change the answer for one identical message.
        let message = "x".repeat(50);
        assert_eq!(check(&message, true, 100, 0), Verdict::Deliver);
        assert_eq!(check(&message, true, 20, 0), Verdict::TooLong);
    }

    #[test]
    fn a_length_limit_of_zero_is_unlimited() {
        assert_eq!(check(&"x".repeat(100_000), true, 0, 0), Verdict::Deliver);
    }

    #[test]
    fn the_limit_is_measured_after_the_markup_is_removed() {
        // Otherwise a two-word message pasted with formatting exhausts a limit
        // meant for the words the recipient reads.
        let message = "<span style=\"font-weight:600\">hi</span>";
        assert!(message.len() > 5);
        assert_eq!(
            check(message, false, 5, 0),
            Verdict::Rewritten("hi".to_owned())
        );
    }

    #[test]
    fn an_image_is_bounded_by_the_image_limit_and_not_the_text_one() {
        // murmur's asymmetry: a long body made of markup is judged by its
        // visible text, but the whole thing still has a ceiling, otherwise a
        // data-URI image is an unbounded upload wearing a chat message.
        let image = format!("<img src=\"data:{}\" />ok", "A".repeat(200));
        assert_eq!(check(&image, true, 10, 1_000), Verdict::Deliver);
        assert_eq!(check(&image, true, 10, 100), Verdict::TooLong);
    }

    #[test]
    fn a_long_message_with_no_markup_is_refused_rather_than_measured_twice() {
        let long = "x".repeat(500);
        assert_eq!(check(&long, true, 10, 1_000), Verdict::TooLong);
    }

    #[test]
    fn breaks_and_paragraphs_become_newlines() {
        assert_eq!(strip_html("one<br />two"), "one\ntwo");
        assert_eq!(strip_html("<p>one</p><p>two</p>"), "one\ntwo");
    }

    #[test]
    fn a_stripped_message_cannot_be_markup_again() {
        // The property that matters for a body on its way to every other
        // client's renderer: whatever comes out must not be re-parseable as a
        // tag by whoever displays it.
        let stripped = strip_html("<b>a &lt; b</b> <notatag");
        assert!(!stripped.contains('<'), "left markup in: {stripped}");
    }

    #[test]
    fn an_unterminated_tag_is_dropped_rather_than_printed() {
        assert_eq!(strip_html("hello <b"), "hello");
    }

    #[test]
    fn a_marker_only_body_survives_html_off() {
        // A voice note or a captionless picture is nothing but its marker.
        // Stripped, it was an empty body, and the server dropped it.
        let voice = "<!-- FANCY_VOICE:{\"id\":\"abc\"} -->";
        assert_eq!(check(voice, false, 0, 0), Verdict::Deliver);
    }

    #[test]
    fn a_caption_keeps_its_marker_and_loses_its_markup() {
        let body = "<b>look</b> <!-- FANCY_FILE:{\"id\":\"f1\"} -->";
        assert_eq!(
            check(body, false, 0, 0),
            Verdict::Rewritten("look <!-- FANCY_FILE:{\"id\":\"f1\"} -->".to_owned())
        );
    }

    #[test]
    fn the_legacy_fence_is_kept_and_its_contents_are_stripped() {
        // The fallback is written for stock clients; with HTML off they get its
        // words, and the fence still tells a Fancy client to cut them out.
        let body = "<!-- FANCY_LEGACY --><i>(edited)</i> <!-- /FANCY_LEGACY -->fixed";
        assert_eq!(
            check(body, false, 0, 0),
            Verdict::Rewritten(
                "<!-- FANCY_LEGACY -->(edited) <!-- /FANCY_LEGACY -->fixed".to_owned()
            )
        );
    }

    #[test]
    fn an_ordinary_comment_is_still_stripped() {
        assert_eq!(
            check("hi <!-- not ours -->", false, 0, 0),
            Verdict::Rewritten("hi".to_owned())
        );
    }

    #[test]
    fn a_marker_that_could_close_early_is_not_kept() {
        // The output of the strip must never be markup again; a "marker" that
        // carries a tag is treated as the markup it is.
        let (out, _) = strip_keeping_markers("<!-- FANCY_X <script> -->hi");
        assert!(!out.contains("<script"), "kept markup in: {out}");
        assert!(
            !out.contains("FANCY_X <"),
            "kept a hostile marker in: {out}"
        );
    }

    #[test]
    fn a_body_cannot_forge_a_marker_slot() {
        let forged = format!("{SLOT_OPEN}0{SLOT_CLOSE}<!-- FANCY_A -->");
        let (out, _) = strip_keeping_markers(&forged);
        assert_eq!(out, "0<!-- FANCY_A -->");
    }

    #[test]
    fn markers_do_not_spend_the_length_limit() {
        let body = format!("hi<!-- FANCY_FILE:{} -->", "x".repeat(500));
        assert!(matches!(check(&body, false, 10, 0), Verdict::Deliver));
    }

    #[test]
    fn whitespace_is_collapsed_the_way_the_filter_it_replaces_does() {
        assert_eq!(strip_html("  a   b  "), "a b");
    }
}
