//! Asking a page's own embed endpoint what it is.
//!
//! # Why a second request is worth making
//!
//! A page's `<meta>` tags are what it wants a *sharing card* to look like, and
//! two kinds of site fill them badly. Some withhold them from anything that
//! does not look like a browser - `YouTube`'s server-rendered head carries a
//! `<title>` of "- `YouTube`" and no picture at all, which previews as a card
//! with a dash on it. Others describe the sharing card rather than the work:
//! an art host's `og:image` is a 1200x630 composite it drew for Twitter.
//!
//! oEmbed is the endpoint those same sites publish for the case where somebody
//! wants to *embed* the thing, and it answers the questions a preview actually
//! asks: what is this (`video`, `photo`, `rich`, `link`), what is it called,
//! who made it, and where is its thumbnail. `YouTube` answers it happily.
//!
//! # Discovery, and the one case where it cannot happen
//!
//! Normally the endpoint is not guessed: the page advertises it in
//! `<link rel="alternate" type="application/json+oembed">`, which is the
//! discovery mechanism the specification defines, and a page that advertises
//! none is not asked. The URL is vetted and fetched exactly like the picture
//! is - it is a stranger's host, named by a stranger's page.
//!
//! That requires the page. The case this module also has to answer is the one
//! where the page cannot be had at all: a host that refuses every rung of the
//! ladder, a real browser included. Discovery is impossible there and the
//! answer may still be sitting behind a published endpoint, so `KNOWN` is a
//! short table of providers whose endpoint is a documented constant.
//!
//! It is a table of **measured** entries, not a copy of a registry: every one
//! was asked for a real URL on 2026-09-08 and answered with a title. The
//! public registry lists 378 providers and most of them are services nobody
//! pastes into a chat; a table nobody can check is a table that rots. Twitter
//! is the reason to check rather than copy - `publish.twitter.com/oembed`
//! answers `301` now and is not in the list below.

use serde_json::Value;

use starling_outbound::{Fetcher, fetch, vet};

/// What an oEmbed endpoint said.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OEmbed {
    /// `type`: "video", "photo", "rich" or "link", lowercased.
    pub kind: String,
    /// What the endpoint calls the work.
    pub title: String,
    /// Who made it.
    pub author: String,
    /// What the endpoint calls its own site.
    pub provider: String,
    /// A picture of the work, as an absolute URL.
    pub thumbnail: String,
    /// What it says that picture measures across, or `0`.
    pub width: u32,
    /// And down, paired with [`OEmbed::width`].
    pub height: u32,
}

/// Providers whose oEmbed endpoint is published and answers.
///
/// `(host suffix, endpoint)`. The suffix matches the host or any subdomain of
/// it, so `youtu.be` and `m.youtube.com` are covered without a rule each.
///
/// The endpoint is asked with the pasted URL as the `url` parameter, which is
/// the specification's own shape, so the request goes to **the provider whose
/// link was pasted** - no third party learns anything it would not have
/// learned from the fetch this replaces.
const KNOWN: &[(&str, &str)] = &[
    (
        "youtube.com",
        "https://www.youtube.com/oembed?format=json&url=",
    ),
    (
        "youtu.be",
        "https://www.youtube.com/oembed?format=json&url=",
    ),
    ("vimeo.com", "https://vimeo.com/api/oembed.json?url="),
    (
        "soundcloud.com",
        "https://soundcloud.com/oembed?format=json&url=",
    ),
    ("spotify.com", "https://open.spotify.com/oembed?url="),
    (
        "flickr.com",
        "https://www.flickr.com/services/oembed/?format=json&url=",
    ),
    (
        "dailymotion.com",
        "https://www.dailymotion.com/services/oembed?url=",
    ),
    ("reddit.com", "https://www.reddit.com/oembed?url="),
    ("tiktok.com", "https://www.tiktok.com/oembed?url="),
    ("bsky.app", "https://embed.bsky.app/oembed?format=json&url="),
];

/// The endpoint to ask about `url`, if this is a provider with a known one.
///
/// Used only when the page itself could not be read; a page that was fetched
/// advertises its own endpoint and that one is preferred, because it is the
/// site's current answer rather than this table's.
#[must_use]
pub fn known_endpoint(url: &str) -> Option<String> {
    let host = host_of(url)?.to_ascii_lowercase();
    KNOWN.iter().find_map(|(suffix, endpoint)| {
        (host == *suffix || host.ends_with(&format!(".{suffix}")))
            .then(|| format!("{endpoint}{}", encoded(url)))
    })
}

/// The host of a URL, lowercased by the caller.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map(|(_, rest)| rest)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.split('@').next_back().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then_some(host)
}

/// `url` as a query-parameter value.
///
/// Percent-encoded here rather than by a dependency: the reserved set is
/// short, and what must not survive is the character that would end the
/// parameter and start another one.
fn encoded(url: &str) -> String {
    let mut out = String::with_capacity(url.len() + 16);
    for byte in url.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Fetch and read the endpoint `page` advertised, if it advertised one.
///
/// `None` for every way this does not happen - no endpoint, a URL the guard
/// refuses, a host that will not answer, an answer that is not JSON. All of
/// them leave the card exactly as the page's own tags made it, which is the
/// card there would have been anyway.
pub async fn ask(fetcher: &Fetcher, page_url: &str, endpoint: &str) -> Option<OEmbed> {
    if endpoint.is_empty() {
        return None;
    }
    let url = fetch::join(page_url, endpoint);
    // Vetted in its own right: an oEmbed endpoint is as often a different host
    // from the page as an `og:image` is, and a guard that checked only the
    // page would be a guard around one door of two.
    if !fetcher.private_is_allowed()
        && let Err(refusal) = vet(&url)
    {
        tracing::debug!(%url, reason = refusal.reason(), "oembed refused");
        return None;
    }
    let answer = match fetcher.fetch_json(&url).await {
        Ok(answer) => answer,
        Err(error) => {
            tracing::debug!(%url, ?error, "oembed could not be fetched");
            return None;
        }
    };
    let value: Value = serde_json::from_slice(&answer.bytes).ok()?;
    let read = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let size = |key: &str| {
        value
            .get(key)
            .and_then(|field| {
                field
                    .as_u64()
                    .or_else(|| field.as_str().and_then(|text| text.parse().ok()))
            })
            .and_then(|number| u32::try_from(number).ok())
            .unwrap_or(0)
    };
    Some(OEmbed {
        kind: read("type").to_ascii_lowercase(),
        title: read("title"),
        author: read("author_name"),
        provider: read("provider_name"),
        thumbnail: read("thumbnail_url"),
        width: size("thumbnail_width"),
        height: size("thumbnail_height"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of the answer, without the fetch: the parsing is what this
    /// module gets wrong, and the fetch is `starling-outbound`'s to test.
    fn read(json: &str) -> OEmbed {
        let value: Value = serde_json::from_str(json).expect("valid fixture");
        let read = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        OEmbed {
            kind: read("type").to_ascii_lowercase(),
            title: read("title"),
            author: read("author_name"),
            provider: read("provider_name"),
            thumbnail: read("thumbnail_url"),
            width: 0,
            height: 0,
        }
    }

    #[test]
    fn a_known_provider_is_asked_at_its_own_endpoint() {
        // The request goes to the provider whose link was pasted, so nothing
        // is disclosed that the fetch this replaces would not have disclosed.
        let asked = known_endpoint("https://www.youtube.com/watch?v=B5EwrXHvE5o&t=1s")
            .expect("YouTube is a known provider");
        assert!(asked.starts_with("https://www.youtube.com/oembed?format=json&url="));
        // The whole URL survives as one parameter: an unencoded `&` would end
        // it and turn `t=1s` into a parameter of the *endpoint*.
        assert!(
            asked.ends_with("https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DB5EwrXHvE5o%26t%3D1s")
        );
    }

    #[test]
    fn a_subdomain_and_a_short_link_reach_the_same_provider() {
        assert!(known_endpoint("https://m.youtube.com/watch?v=x").is_some());
        assert!(known_endpoint("https://youtu.be/x").is_some());
        assert!(known_endpoint("https://open.spotify.com/track/x").is_some());
    }

    #[test]
    fn a_host_that_merely_ends_in_a_providers_name_is_not_that_provider() {
        // `notyoutube.com` is not a subdomain of `youtube.com`, and matching
        // on a bare suffix would send a stranger's URL to YouTube's endpoint.
        assert_eq!(known_endpoint("https://notyoutube.com/watch?v=x"), None);
        assert_eq!(known_endpoint("https://youtube.com.evil.example/x"), None);
        assert_eq!(known_endpoint("https://example.org/watch"), None);
    }

    #[test]
    fn a_video_endpoint_answers_what_the_page_withheld() {
        // Transcribed from the real answer: the same video whose HTML head
        // carries a `<title>` of "- YouTube" and no picture.
        let found = read(
            r#"{"title":"Happy Hardcore / UK Hardcore 1 Hour Mix #4 - Lift Me Up",
                "author_name":"Ubercrow","type":"video","provider_name":"YouTube",
                "thumbnail_url":"https://i.ytimg.com/vi/B5EwrXHvE5o/hqdefault.jpg"}"#,
        );
        assert_eq!(found.kind, "video");
        assert_eq!(found.author, "Ubercrow");
        assert!(found.title.starts_with("Happy Hardcore"));
        assert!(found.thumbnail.ends_with("hqdefault.jpg"));
    }

    #[test]
    fn an_art_endpoint_names_the_artist_the_page_did_not() {
        let found = read(
            r#"{"version":"1.0","type":"rich","title":"秤アツコ","author_name":"213号",
                "provider_name":"pixiv",
                "thumbnail_url":"https://embed.pixiv.net/decorate.php?illust_id=1"}"#,
        );
        assert_eq!(found.kind, "rich");
        assert_eq!(found.author, "213号");
        assert_eq!(found.title, "秤アツコ");
    }
}
