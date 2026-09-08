//! The optional half: serving the pictures as well as finding them.
//!
//! Off by default (`gif_proxy_media`). With it off, a `GifPage` carries the
//! provider's own CDN URLs and every viewer's client loads thumbnails straight
//! from that CDN - which is what Discord's picker does, and it hands the CDN
//! each viewer's address and a `referer` naming the channel they are in. With
//! it on, those URLs point here instead and the provider sees one address, the
//! server's.
//!
//! It is a switch rather than a default because it is a real cost: a picker
//! draws two dozen thumbnails per page and scrolls, so the deployment carries
//! bytes it otherwise would not. An operator who would rather pay that than
//! leak their members' addresses says so in one key.
//!
//! # Why this is not an open proxy
//!
//! A URL naming a host to fetch, served by a public endpoint, *is* an open
//! proxy unless something stops it. Three things do, and they are independent:
//!
//! 1. **The signature.** The URL carries an HMAC over `(url, expiry)` that only
//!    this process can mint, so the only fetchable URLs are ones this server
//!    itself put in a `GifPage`.
//! 2. **The host allow-list.** Even a correctly signed URL is only fetched if
//!    its host belongs to the configured provider. A signing key that leaked
//!    still buys nothing but GIFs.
//! 3. **The SSRF guard**, from `starling-outbound`, exactly as the search path
//!    uses it: no private address, on the URL and again on the resolved
//!    address, on every redirect hop.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use starling_runtime::ids::now_ms;
use starling_runtime::serve::ServiceError;
use subtle::ConstantTimeEq as _;

use crate::GifsService;

/// What a proxied URL carries.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct Grant {
    /// The upstream URL, as it came from the provider.
    u: String,
    /// When this stops working, in milliseconds since the epoch.
    expires: u64,
    /// The signature over both of the above.
    sig: String,
}

/// The one route.
pub(crate) fn router(service: Arc<GifsService>) -> Router {
    Router::new().route("/gif", get(fetch)).with_state(service)
}

/// Sign a proxied URL.
///
/// The expiry is inside the signature so that editing it invalidates the URL;
/// without that, a grant would be good forever and the TTL would be a comment.
#[must_use]
pub fn sign(secret: &[u8], url: &str, expires_at_ms: u64) -> String {
    let Ok(mut mac) = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(url.as_bytes());
    mac.update(b"\0");
    mac.update(&expires_at_ms.to_be_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether a grant is one we minted and has not expired.
///
/// Constant-time, because a comparison that leaks its progress through timing
/// is one an attacker can walk a byte at a time.
#[must_use]
pub fn verify(secret: &[u8], url: &str, expires_at_ms: u64, signature: &str, now: u64) -> bool {
    if now > expires_at_ms {
        return false;
    }
    let expected = sign(secret, url, expires_at_ms);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

/// The signing key, generated on first boot and reused after.
///
/// Stable across restarts, like the files service's: regenerating it would
/// invalidate every URL in every open picker at once.
///
/// # Errors
///
/// [`ServiceError`] when the key can neither be read nor written, which is a
/// misconfigured data directory and should stop the service at startup rather
/// than produce URLs that never verify.
pub fn secret(data_dir: &std::path::Path) -> Result<Vec<u8>, ServiceError> {
    let path = data_dir.join("gifs-signing.key");
    if let Ok(existing) = std::fs::read(&path)
        && existing.len() >= 32
    {
        return Ok(existing);
    }
    let mut key = vec![0_u8; 32];
    {
        use rand::Rng as _;
        rand::rng().fill_bytes(&mut key);
    }
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(&path, &key)?;
    Ok(key)
}

/// Percent-encode for a query parameter.
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

/// The URL a client should be given for `upstream`.
#[must_use]
pub fn proxied(public_url: &str, secret: &[u8], upstream: &str, ttl: Duration) -> String {
    let expires = now_ms().saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
    let sig = sign(secret, upstream, expires);
    format!(
        "{}/gif?u={}&expires={expires}&sig={sig}",
        public_url.trim_end_matches('/'),
        encode(upstream)
    )
}

/// Whether `url`'s host belongs to the provider we are configured for.
///
/// Suffix matching on a **dot-prefixed** domain, so `evilklipy.com` does not
/// match `klipy.com`; the naive `ends_with("klipy.com")` is that bug.
#[must_use]
pub fn host_is_allowed(url: &str, domains: &[String]) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    // Credentials cannot be used to disguise the host, the same bypass `vet`
    // guards against.
    let authority = authority.split('@').next_back().unwrap_or(authority);
    let host = authority.split(':').next().unwrap_or(authority);
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    domains.iter().any(|domain| {
        let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
        !domain.is_empty() && (host == domain || host.ends_with(&format!(".{domain}")))
    })
}

/// Serve one proxied picture.
async fn fetch(State(service): State<Arc<GifsService>>, Query(grant): Query<Grant>) -> Response {
    let Some(secret) = service.proxy_secret() else {
        // The switch is off, so nothing was ever signed with anything.
        return StatusCode::NOT_FOUND.into_response();
    };
    if !verify(secret, &grant.u, grant.expires, &grant.sig, now_ms()) {
        // One status for "forged" and "expired" together: telling them apart
        // tells somebody probing this endpoint which half of the grant to work
        // on. A client that gets it re-opens the picker, which re-signs.
        return StatusCode::FORBIDDEN.into_response();
    }
    if !host_is_allowed(&grant.u, service.proxy_domains()) {
        // Belt and braces: a signature this process minted should already only
        // ever cover a provider URL. This is what holds if the signing key
        // leaks, and it is the difference between that being a GIF cache and
        // that being an open proxy into the deployment's network.
        tracing::warn!(url = %grant.u, "a signed gif URL pointed off the provider");
        return StatusCode::FORBIDDEN.into_response();
    }

    if let Some(hit) = service.cached_bytes(&grant.u) {
        return picture(hit.mime, hit.bytes, grant.expires);
    }
    match service.fetcher().fetch_image(&grant.u).await {
        Ok(image) => {
            service.store_bytes(&grant.u, &image.mime, &image.bytes);
            picture(image.mime, image.bytes, grant.expires)
        }
        Err(error) => {
            tracing::debug!(url = %grant.u, ?error, "a proxied gif could not be fetched");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// The response a fetched picture becomes.
///
/// Cached by the client for as long as the grant is good for and no longer: a
/// URL that has expired must not keep being served out of a browser cache,
/// because then the expiry is not an expiry.
fn picture(mime: String, bytes: Vec<u8>, expires_at_ms: u64) -> Response {
    let remaining = expires_at_ms.saturating_sub(now_ms()) / 1000;
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                if mime.is_empty() {
                    "application/octet-stream".to_owned()
                } else {
                    mime
                },
            ),
            (
                header::CACHE_CONTROL,
                format!("private, max-age={remaining}"),
            ),
        ],
        Body::from(bytes),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_this_server_did_not_sign_is_not_fetched() {
        // The whole open-proxy question in one assertion.
        let secret = b"secret";
        let signature = sign(secret, "https://cdn.klipy.com/a.webp", 10_000);
        assert!(verify(
            secret,
            "https://cdn.klipy.com/a.webp",
            10_000,
            &signature,
            5_000
        ));
        assert!(
            !verify(
                secret,
                "http://169.254.169.254/latest/meta-data/",
                10_000,
                &signature,
                5_000
            ),
            "a signature for one URL must not cover another"
        );
    }

    #[test]
    fn editing_the_expiry_invalidates_the_grant() {
        let secret = b"secret";
        let signature = sign(secret, "https://cdn.klipy.com/a.webp", 10_000);
        assert!(!verify(
            secret,
            "https://cdn.klipy.com/a.webp",
            99_000,
            &signature,
            5_000
        ));
    }

    #[test]
    fn an_expired_grant_is_refused_even_though_it_verifies() {
        let secret = b"secret";
        let signature = sign(secret, "https://cdn.klipy.com/a.webp", 10_000);
        assert!(!verify(
            secret,
            "https://cdn.klipy.com/a.webp",
            10_000,
            &signature,
            20_001
        ));
    }

    #[test]
    fn a_lookalike_domain_is_not_the_provider() {
        // `ends_with("klipy.com")` is the bug this rules out: it is true of
        // `evilklipy.com`, which anybody can register.
        let allowed = vec!["klipy.com".to_owned()];
        assert!(host_is_allowed("https://cdn.klipy.com/a.webp", &allowed));
        assert!(host_is_allowed("https://klipy.com/a.webp", &allowed));
        assert!(!host_is_allowed("https://evilklipy.com/a.webp", &allowed));
        assert!(!host_is_allowed("https://klipy.com.evil.net/a", &allowed));
    }

    #[test]
    fn credentials_do_not_disguise_the_host_here_either() {
        let allowed = vec!["klipy.com".to_owned()];
        assert!(!host_is_allowed(
            "https://cdn.klipy.com@169.254.169.254/a",
            &allowed
        ));
    }

    #[test]
    fn a_trailing_dot_is_the_same_host() {
        // `cdn.klipy.com.` is the fully qualified form and resolves to the same
        // machine, so a check that treats it as a different host is one more
        // way past the allow-list.
        assert!(host_is_allowed(
            "https://cdn.klipy.com./a.webp",
            &["klipy.com".to_owned()]
        ));
    }

    #[test]
    fn a_scheme_we_do_not_speak_is_not_allowed() {
        let allowed = vec!["klipy.com".to_owned()];
        assert!(!host_is_allowed("file:///etc/passwd", &allowed));
        assert!(!host_is_allowed("//cdn.klipy.com/a.webp", &allowed));
    }

    #[test]
    fn a_proxied_url_carries_the_upstream_one_intact() {
        let secret = b"secret";
        let upstream = "https://cdn.klipy.com/a.webp?x=1&y=2";
        let url = proxied(
            "https://chat.example.org/m",
            secret,
            upstream,
            Duration::from_secs(60),
        );
        assert!(
            url.starts_with("https://chat.example.org/m/gif?u="),
            "{url}"
        );
        // The upstream query must not become part of ours: `&y=2` arriving as
        // a second parameter is how a proxy fetches something else entirely.
        assert!(url.contains("%3Fx%3D1%26y%3D2"), "{url}");
        assert_eq!(url.matches("expires=").count(), 1, "{url}");
    }
}
