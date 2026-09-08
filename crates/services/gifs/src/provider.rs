//! The media provider, and reading what it sends back.
//!
//! One provider is implemented, Klipy, because one is what the operator can get
//! a key for: Google decommissions the Tenor API on 2026-06-30 and stopped
//! issuing keys in January, and Discord moved its own picker to Klipy for the
//! same reason. The shape here is nonetheless a *trait-free seam* rather than
//! Klipy spelled through the service - [`Provider::endpoint`] and
//! `parse_page` are the whole of what is provider-specific, and a second one
//! is those two functions rather than a refactor.
//!
//! # Why the key never leaves this process
//!
//! Klipy takes its key as a **path segment**, so the URL is itself a secret.
//! Nothing here logs a built URL, and [`Provider::describe`] exists so that the
//! things that do want to say what was fetched have something safe to say.

use starling_outbound::{FetchError, Fetcher};

/// The provider an operator configured.
#[derive(Debug, Clone)]
pub struct Provider {
    /// Which one. Only `klipy` today; an unknown name is refused at startup
    /// rather than at the first search.
    name: Name,
    /// The operator's key. Empty is not represented: a `Provider` only exists
    /// once there is a key to build a URL with, so "no key configured" is
    /// `Option<Provider>` at the call site and cannot be forgotten here.
    key: String,
    /// How many results one page asks for.
    per_page: u32,
}

/// The providers this build can talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Name {
    /// <https://klipy.com>, which is what Discord's picker now uses too.
    Klipy,
}

impl Name {
    /// The name as it is written in the configuration and reported to clients.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Klipy => "klipy",
        }
    }

    /// Parse an operator's `gif_provider`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            // An unset key means the default rather than an error: an operator
            // who sets `gif_api_key` and nothing else gets a working service.
            "" | "klipy" => Some(Self::Klipy),
            _ => None,
        }
    }
}

impl Provider {
    /// A provider with a key to search it with.
    #[must_use]
    pub fn new(name: Name, key: String, per_page: u32) -> Self {
        Self {
            name,
            key,
            // Zero would ask the provider for nothing and hand back an empty
            // picker, which reads as a broken feature rather than a
            // misconfigured one.
            per_page: per_page.clamp(1, 50),
        }
    }

    /// Which provider this is.
    #[must_use]
    pub const fn kind(&self) -> Name {
        self.name
    }

    /// What a log may say about a fetch.
    ///
    /// Never the URL: the key is in it.
    #[must_use]
    pub fn describe(&self, query: &str, page: u32) -> String {
        if query.is_empty() {
            format!("{} trending page {page}", self.name.as_str())
        } else {
            format!("{} search page {page}", self.name.as_str())
        }
    }

    /// The URL for one page of results. **Carries the API key.**
    #[must_use]
    pub fn endpoint(&self, query: &str, page: u32) -> String {
        match self.name {
            Name::Klipy => {
                let action = if query.is_empty() {
                    "trending"
                } else {
                    "search"
                };
                let mut url = format!(
                    "https://api.klipy.com/api/v1/{}/gifs/{action}?per_page={}&page={}",
                    encode(&self.key),
                    self.per_page,
                    page.max(1)
                );
                if !query.is_empty() {
                    url.push_str("&q=");
                    url.push_str(&encode(query));
                }
                url
            }
        }
    }

    /// Fetch and read one page.
    ///
    /// # Errors
    ///
    /// [`ProviderError`], which the service turns into a `GifRefused`. A
    /// provider that answers something unreadable and a provider that does not
    /// answer are the same outcome for a client and are deliberately not
    /// distinguished to it; the operator's log has both.
    pub async fn page(
        &self,
        fetcher: &Fetcher,
        query: &str,
        page: u32,
    ) -> Result<Page, ProviderError> {
        let body = fetcher
            .fetch_json(&self.endpoint(query, page))
            .await
            .map_err(ProviderError::Fetch)?;
        match self.name {
            Name::Klipy => parse_page(&body.bytes).ok_or(ProviderError::Unreadable),
        }
    }
}

/// One page of results.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// What was found, in the provider's order.
    pub results: Vec<Gif>,
    /// Whether asking for the next page would return anything.
    pub has_next: bool,
}

/// One result, in the shape the envelope carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gif {
    /// The provider's own handle, passed back out unchanged.
    pub id: String,
    /// A label for the tile. `"GIF"` when the provider named none, because a
    /// grid still needs alt text.
    pub title: String,
    /// Full size, the one that gets sent into a channel.
    pub url: String,
    /// Grid size, the one a picker draws a hundred of.
    pub preview_url: String,
    /// The size of `url`, or zero when the provider did not say.
    pub width: u32,
    /// The size of `url`, or zero when the provider did not say.
    pub height: u32,
    /// The size of `preview_url`, or zero when the provider did not say.
    pub preview_width: u32,
    /// The size of `preview_url`, or zero when the provider did not say.
    pub preview_height: u32,
    /// What `url` is: `image/webp`, `image/gif`, `video/mp4`.
    pub mime: String,
}

/// Why a page did not come back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The request itself failed: unreachable, timed out, refused, too large.
    Fetch(FetchError),
    /// It answered, with something this cannot read. A provider that changed
    /// its shape, or an error page served as JSON.
    Unreadable,
}

impl ProviderError {
    /// What an operator's log says.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Fetch(error) => format!("{error:?}"),
            Self::Unreadable => "the answer was not a page of results".to_owned(),
        }
    }
}

/// Percent-encode everything that is not unreserved.
///
/// Written out rather than pulled in, because the only two things that reach it
/// are a key an operator pasted and a query somebody typed, and both go into a
/// URL - a query holding `&per_page=1000` must not become a second parameter,
/// and a key holding a `/` must not become a second path segment.
fn encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Read Klipy's answer.
///
/// Returns `None` for anything that is not recognisably a page, rather than an
/// empty page: "the provider sent something we cannot read" and "there are no
/// cat GIFs" are different, and a client shown the second when the first
/// happened will keep asking.
///
/// Individual *entries* are the opposite: one entry with no usable file is
/// skipped and the rest of the page is kept, because a page that renders 23 of
/// 24 results is worth more than an error.
fn parse_page(bytes: &[u8]) -> Option<Page> {
    let root: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    // Klipy wraps the page in an outer `data`, so the array is `data.data`.
    let page = root.get("data")?;
    let items = page.get("data")?.as_array()?;
    let results = items.iter().filter_map(parse_gif).collect();
    Some(Page {
        results,
        // Absent means "no more": a picker that keeps asking for pages that do
        // not exist is the failure mode of guessing `true` here.
        has_next: page
            .get("has_next")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

/// One entry, or `None` when it carries no file anything could render.
fn parse_gif(item: &serde_json::Value) -> Option<Gif> {
    let file = item.get("file")?;
    // Largest first for the thing that gets sent, smallest first for the thing
    // that gets drawn in a grid a hundred at a time. The fallbacks matter:
    // Klipy omits sizes per item rather than serving every size for everything.
    let full = ["hd", "md", "sm"]
        .iter()
        .find_map(|size| variant(file, size))?;
    let preview = ["sm", "xs"]
        .iter()
        .find_map(|size| variant(file, size))
        .unwrap_or_else(|| full.clone());

    Some(Gif {
        // Numeric in Klipy's shape and a string here: an id is an opaque handle
        // that goes back out unchanged, and every provider spells it
        // differently. `as_str` first so a provider that already sends a string
        // is not turned into `"\"abc\""`.
        id: item
            .get("id")
            .map(|id| {
                id.as_str()
                    .map_or_else(|| id.to_string(), ToOwned::to_owned)
            })
            .unwrap_or_default(),
        // Titles are routinely absent and a grid tile still needs an alt text.
        title: item
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("GIF")
            .to_owned(),
        url: full.url,
        width: full.width,
        height: full.height,
        preview_url: preview.url,
        preview_width: preview.width,
        preview_height: preview.height,
        mime: full.mime,
    })
}

/// One rendition of one result.
#[derive(Debug, Clone)]
struct Variant {
    url: String,
    width: u32,
    height: u32,
    mime: String,
}

/// The `webp` (or `gif`) rendition at `size`, if there is a usable one.
///
/// WebP first because it is a fraction of the bytes for the same picture and
/// every client that can draw this can decode it; `gif` is the fallback for an
/// entry that has no WebP rather than a preference.
fn variant(file: &serde_json::Value, size: &str) -> Option<Variant> {
    let at = file.get(size)?;
    let (format, mime) = ["webp", "gif", "mp4"]
        .iter()
        .find_map(|format| at.get(*format).map(|value| (value, *format)))?;
    let url = format.get("url")?.as_str()?;
    if url.is_empty() {
        return None;
    }
    Some(Variant {
        url: url.to_owned(),
        width: dimension(format, "width"),
        height: dimension(format, "height"),
        mime: match mime {
            "webp" => "image/webp",
            "mp4" => "video/mp4",
            _ => "image/gif",
        }
        .to_owned(),
    })
}

/// A dimension, or zero when the provider did not say.
///
/// Zero rather than a guess: a client that is told a size lays the grid out
/// before the picture arrives, and a wrong size makes the grid jump once it
/// does. Zero says "unknown", which a client can handle.
fn dimension(value: &serde_json::Value, key: &str) -> u32 {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn klipy() -> Provider {
        Provider::new(Name::Klipy, "k3y".to_owned(), 24)
    }

    #[test]
    fn an_empty_query_asks_for_trending_and_a_query_asks_for_search() {
        // The distinction a picker depends on: it opens on trending, before
        // anybody has typed anything.
        assert!(klipy().endpoint("", 1).contains("/gifs/trending"));
        assert!(klipy().endpoint("cat", 1).contains("/gifs/search"));
    }

    #[test]
    fn a_query_cannot_smuggle_a_second_parameter() {
        // `&per_page=1000` in the search box would otherwise be a way to make
        // the server ask the provider for a far larger page than the operator
        // configured - a rate limit sidestepped through the search box.
        let url = klipy().endpoint("cats&per_page=1000", 1);
        assert!(url.contains("q=cats%26per_page%3D1000"), "{url}");
        assert_eq!(url.matches("per_page=").count(), 1, "{url}");
    }

    #[test]
    fn a_key_cannot_smuggle_a_second_path_segment() {
        // The key is a *path* segment in this provider's URL, so a stray slash
        // in a pasted key would silently change which endpoint is called.
        let url = Provider::new(Name::Klipy, "ab/../../admin".to_owned(), 24).endpoint("", 1);
        assert!(url.contains("/api/v1/ab%2F..%2F..%2Fadmin/gifs/"), "{url}");
    }

    #[test]
    fn what_a_log_may_say_never_carries_the_key() {
        // The URL is a secret in this provider's shape, so the description
        // that goes near a log must not be built from it.
        let described = klipy().describe("cat", 2);
        assert!(!described.contains("k3y"), "{described}");
        assert!(described.contains("klipy"), "{described}");
    }

    #[test]
    fn the_page_size_is_clamped_rather_than_taken_literally() {
        // A misconfigured `gif_per_page = 100000` is an operator asking the
        // provider for a page nobody can render, on the server's quota.
        let url = Provider::new(Name::Klipy, "k".to_owned(), 100_000).endpoint("", 1);
        assert!(url.contains("per_page=50"), "{url}");
        let url = Provider::new(Name::Klipy, "k".to_owned(), 0).endpoint("", 1);
        assert!(url.contains("per_page=1"), "{url}");
    }

    #[test]
    fn a_page_of_results_reads_the_sizes_a_picker_needs() {
        let body = br#"{"data":{"has_next":true,"data":[
            {"id":42,"title":"A Cat","file":{
              "hd":{"webp":{"url":"https://cdn/hd.webp","width":800,"height":600}},
              "sm":{"webp":{"url":"https://cdn/sm.webp","width":200,"height":150}}
            }}
        ]}}"#;
        let page = parse_page(body).expect("a page");
        assert!(page.has_next);
        let [gif] = page.results.as_slice() else {
            panic!("one result, got {:?}", page.results)
        };
        assert_eq!(gif.id, "42");
        assert_eq!(gif.title, "A Cat");
        assert_eq!(gif.url, "https://cdn/hd.webp");
        assert_eq!(gif.preview_url, "https://cdn/sm.webp");
        assert_eq!((gif.width, gif.height), (800, 600));
        assert_eq!((gif.preview_width, gif.preview_height), (200, 150));
        assert_eq!(gif.mime, "image/webp");
    }

    #[test]
    fn an_entry_with_only_one_size_uses_it_for_both() {
        // Common, and it must not cost the whole entry: a picker with no
        // preview URL draws nothing at all for that tile.
        let body = br#"{"data":{"data":[
            {"id":"x","file":{"md":{"webp":{"url":"https://cdn/md.webp"}}}}
        ]}}"#;
        let page = parse_page(body).expect("a page");
        let gif = page.results.first().expect("a result");
        assert_eq!(gif.url, "https://cdn/md.webp");
        assert_eq!(gif.preview_url, "https://cdn/md.webp");
        // Absent dimensions are zero, which means "unknown" rather than a
        // guess a layout would jump on.
        assert_eq!((gif.width, gif.height), (0, 0));
    }

    #[test]
    fn an_unusable_entry_is_skipped_and_the_rest_of_the_page_survives() {
        // One malformed result must not empty a picker.
        let body = br#"{"data":{"data":[
            {"id":1},
            {"id":2,"file":{"hd":{"webp":{"url":""}}}},
            {"id":3,"file":{"hd":{"webp":{"url":"https://cdn/ok.webp"}}}}
        ]}}"#;
        let page = parse_page(body).expect("a page");
        assert_eq!(page.results.len(), 1);
        assert_eq!(page.results[0].id, "3");
    }

    #[test]
    fn something_that_is_not_a_page_is_not_an_empty_page() {
        // The distinction the caller branches on: an empty page is an answer a
        // client should show, and an unreadable one is a failure it should be
        // told about. Reading the second as the first leaves a picker
        // cheerfully reporting "no results" for a broken API key.
        assert!(parse_page(b"not json").is_none());
        assert!(parse_page(br#"{"error":"invalid api key"}"#).is_none());
        // ...and a genuinely empty page still parses.
        let empty = parse_page(br#"{"data":{"data":[],"has_next":false}}"#).expect("a page");
        assert!(empty.results.is_empty());
    }

    #[test]
    fn a_missing_has_next_does_not_invite_an_endless_scroll() {
        let page = parse_page(br#"{"data":{"data":[]}}"#).expect("a page");
        assert!(!page.has_next);
    }

    #[test]
    fn an_unknown_provider_is_refused_and_a_blank_one_is_the_default() {
        assert_eq!(Name::parse("klipy"), Some(Name::Klipy));
        assert_eq!(Name::parse("  KLIPY "), Some(Name::Klipy));
        // Unset is the default, so a key and nothing else is a working config.
        assert_eq!(Name::parse(""), Some(Name::Klipy));
        // Named and unknown is a typo, and a typo that silently fell back to
        // the default would be an operator pointing at the wrong provider.
        assert_eq!(Name::parse("tenor"), None);
    }
}
