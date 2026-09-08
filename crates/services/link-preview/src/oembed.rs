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
//! # It is not a list of hosts
//!
//! The endpoint is not guessed: the page advertises it in
//! `<link rel="alternate" type="application/json+oembed">`, which is the
//! discovery mechanism the specification defines, and a page that advertises
//! none is not asked. The URL is vetted and fetched exactly like the picture
//! is - it is a stranger's host, named by a stranger's page.

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
