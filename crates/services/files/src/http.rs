//! The data plane: the listener the signed URLs actually point at.
//!
//! The control plane hands out a short-lived signed URL over the Mumble
//! connection ([`crate::FilesService`]); this is the other half, where the
//! bytes move. Two routes, and they are deliberately the only two: a client
//! presents a grant and either writes the object it names or reads it.
//!
//! # Why the grant is the whole authorisation
//!
//! There is no session cookie, no bearer token and no per-request permission
//! lookup here. A request carries a signature over `(method, key, expiry)`,
//! and that signature was minted by the control plane *after* it asked
//! `permissions` on behalf of a session that had already authenticated. So the
//! check that matters happened before the URL existed, and this half only has
//! to prove the URL was not forged or edited.
//!
//! That is what makes the listener safe to put behind a CDN or a reverse proxy
//! that knows nothing about Mumble sessions.
//!
//! # Why a download answers `Range`
//!
//! A video is watched, not downloaded and then watched. A player asks for the
//! first few hundred kilobytes, reads the header, and then asks for whatever
//! the viewer seeks to -- so a listener that can only hand over whole objects
//! forces a client to spend the entire file before it can show a single frame,
//! and makes seeking impossible afterwards. Answering ranges is what turns a
//! shared clip into something a client can simply play.
//!
//! # Why an upload is checked against its grant
//!
//! A `PUT` grant names one key and one size ceiling. Without re-checking, a
//! client could ask to upload a 10 KiB avatar, be granted a URL, and then
//! stream a gigabyte through it -- the control plane's limit would be advice.
//! So the body is counted as it is written and abandoned the moment it passes
//! what was granted.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt as _;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::FilesService;

/// The query a signed URL carries.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct Grant {
    expires: u64,
    sig: String,
}

/// The routes, and the service they are served from.
///
/// Two families. `/{key}` is the signed one every session uses. `/s/{key}` is
/// the share link: no signature, no session, only whatever the object's own
/// visibility says. They cannot collide, because a key always begins with a
/// channel id and a channel id is digits.
pub(crate) fn router(service: Arc<FilesService>) -> Router {
    Router::new()
        .route("/s/{*key}", get(share).post(authorise))
        .route("/{*key}", get(download).put(upload))
        .with_state(service)
}

/// Where an object's bytes live.
///
/// Keys contain `/`, which is what makes them nest, so the path is built by
/// joining the components rather than by string concatenation -- and every
/// component is checked, because a key containing `..` would otherwise walk
/// out of the data directory.
pub(crate) fn object_path(root: &Path, key: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for part in key.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
            return None;
        }
        path.push(part);
    }
    Some(path)
}

/// The span of an object a request asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Span {
    /// The whole object: no `Range`, or one in units this listener does not
    /// speak. Ignoring such a header is what the spec asks for, and answering
    /// with everything is always a correct answer to a range request.
    Whole,
    /// A byte span, inclusive at both ends and already clamped to the object.
    Part { start: u64, end: u64 },
    /// A `Range` that names nothing inside the object.
    Unsatisfiable,
}

/// Work out which bytes of an object of `size` a `Range` header asked for.
///
/// Only single spans are answered. A multi-range request is legal and would
/// need a `multipart/byteranges` body to answer properly; no player sends one
/// for media, so it collapses to "the whole object" rather than to an error.
pub(crate) fn parse_range(header: Option<&str>, size: u64) -> Span {
    let Some(header) = header else {
        return Span::Whole;
    };
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return Span::Whole;
    };
    if spec.contains(',') {
        return Span::Whole;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return Span::Whole;
    };
    // An empty object has no byte to name, so every range over it misses.
    if size == 0 {
        return Span::Unsatisfiable;
    }
    let last_byte = size - 1;

    // `-N`: the final N bytes, however many of them there turn out to be.
    if first.is_empty() {
        let Ok(suffix) = last.parse::<u64>() else {
            return Span::Whole;
        };
        if suffix == 0 {
            return Span::Unsatisfiable;
        }
        return Span::Part {
            start: size.saturating_sub(suffix),
            end: last_byte,
        };
    }

    let Ok(start) = first.parse::<u64>() else {
        return Span::Whole;
    };
    // `N-` is what a player sends first: everything from here on.
    let end = if last.is_empty() {
        last_byte
    } else {
        let Ok(end) = last.parse::<u64>() else {
            return Span::Whole;
        };
        end.min(last_byte)
    };
    if start > end || start > last_byte {
        return Span::Unsatisfiable;
    }
    Span::Part { start, end }
}

/// Read one object, or the part of it that was asked for, if the grant says so.
async fn download(
    State(service): State<Arc<FilesService>>,
    UrlPath(key): UrlPath<String>,
    Query(grant): Query<Grant>,
    headers: HeaderMap,
) -> Response {
    if !service.verify_grant("GET", &key, grant.expires, &grant.sig) {
        return refuse(
            StatusCode::FORBIDDEN,
            "this link is not valid or has expired",
        );
    }
    // No name: the client that signed for this download already knows what it
    // asked for, and is saving it under a name of its own.
    let answer = serve_object(&service, &key, None, &headers).await;
    if answer.status().is_success() {
        service.note_read(&key).await;
    }
    answer
}

/// Hand over an object's bytes, or the span of them that was asked for.
///
/// Says nothing about who may have them: both callers have already settled
/// that, one with a signature and the other with the object's own visibility.
async fn serve_object(
    service: &Arc<FilesService>,
    key: &str,
    filename: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let Some(path) = object_path(service.objects_dir(), key) else {
        return refuse(StatusCode::BAD_REQUEST, "that is not a key");
    };
    // An expiry is a promise to everyone, not only to whoever followed a share
    // link: a member of the channel holding a signed URL must not still be able
    // to read a file the uploader gave a week to.
    if service
        .share_record(key)
        .await
        .is_some_and(|record| record.expired())
    {
        return refuse(StatusCode::NOT_FOUND, "no such object");
    }
    let Ok(mut file) = tokio::fs::File::open(&path).await else {
        return refuse(StatusCode::NOT_FOUND, "no such object");
    };
    let Ok(metadata) = file.metadata().await else {
        return refuse(StatusCode::NOT_FOUND, "no such object");
    };
    let size = metadata.len();

    let requested = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let span = parse_range(requested, size);
    // Answered with the object's length rather than silently truncated: a
    // player that asked for the tail of a file it thinks is longer would
    // otherwise seek into nothing forever.
    if span == Span::Unsatisfiable {
        return (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [
                (header::CONTENT_RANGE, format!("bytes */{size}")),
                (header::ACCEPT_RANGES, "bytes".to_owned()),
            ],
        )
            .into_response();
    }
    let (start, end) = match span {
        Span::Part { start, end } => (start, end),
        // `size == 0` lands here with nothing to send, which is what a zero
        // length body is.
        Span::Whole | Span::Unsatisfiable => (0, size.saturating_sub(1)),
    };
    let length = if size == 0 { 0 } else { end - start + 1 };

    if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not read the file");
    }

    let content_type = service
        .content_type_of(key)
        .await
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let stream = span_stream(file, length);

    let mut out = object_headers(&content_type);
    if let Some(filename) = filename {
        name_the_download(&mut out, filename, &content_type);
    }
    // Said on every answer, not only on a partial one: a player asks whether
    // seeking is possible by reading this off the first response it gets.
    if let Ok(value) = "bytes".parse() {
        drop(out.insert(header::ACCEPT_RANGES, value));
    }
    if let Ok(value) = length.to_string().parse() {
        drop(out.insert(header::CONTENT_LENGTH, value));
    }

    let partial = matches!(span, Span::Part { .. });
    if partial {
        if let Ok(value) = format!("bytes {start}-{end}/{size}").parse() {
            drop(out.insert(header::CONTENT_RANGE, value));
        }
        return (StatusCode::PARTIAL_CONTENT, out, Body::from_stream(stream)).into_response();
    }
    (out, Body::from_stream(stream)).into_response()
}

/// The headers every object answer carries, whatever route served it.
///
/// The bytes are attacker-supplied and, on a share link, reached without any
/// login at all - so the browser is told not to guess at their type, not to
/// frame them, and not to run anything they contain in this origin. A public
/// file server that renders somebody's uploaded HTML is a cross-site scripting
/// hole with a progress bar.
fn object_headers(content_type: &str) -> HeaderMap {
    let mut out = HeaderMap::new();
    if let Ok(value) = content_type.parse() {
        drop(out.insert(header::CONTENT_TYPE, value));
    }
    if let Ok(value) = "nosniff".parse() {
        drop(out.insert(header::X_CONTENT_TYPE_OPTIONS, value));
    }
    if let Ok(value) = "DENY".parse() {
        drop(out.insert(header::X_FRAME_OPTIONS, value));
    }
    if let Ok(value) = "no-referrer".parse() {
        drop(out.insert(header::REFERRER_POLICY, value));
    }
    if let Ok(value) = "default-src 'none'; img-src 'self'; media-src 'self'; \
         object-src 'none'; script-src 'none'; style-src 'none'; base-uri 'none'; \
         frame-ancestors 'none'; sandbox;"
        .parse()
    {
        drop(out.insert(header::CONTENT_SECURITY_POLICY, value));
    }
    out
}

/// What a share link may carry beyond the key.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ShareQuery {
    /// Proof that a password was presented, for a password share.
    #[serde(default)]
    ticket: Option<String>,
}

/// `GET /s/{key}` -- the link.
///
/// # Why this route has no signature
///
/// The signed routes exist so that permission checked once, on the control
/// connection, can be spent later over plain HTTP. A share link is the case
/// where there is no session to check anything against: the point of it is
/// that a person with no account can open it. So what stands in for the
/// signature is the object's own visibility, which the uploader set and the
/// row records.
///
/// A session-only object is answered as if it did not exist. Saying "this is
/// private" would make the route a way to learn which keys are real, and a key
/// is guessable in the sense that a leaked one from a chat log is a key.
async fn share(
    State(service): State<Arc<FilesService>>,
    UrlPath(key): UrlPath<String>,
    Query(query): Query<ShareQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(record) = service.share_record(&key).await else {
        return refuse(StatusCode::NOT_FOUND, "no such object");
    };
    // Expired is answered as absent, like a session share: a link whose time is
    // up is a link that no longer names anything, and the person holding it
    // does not need to be told which of the two it was.
    if !record.public || record.expired() {
        return refuse(StatusCode::NOT_FOUND, "no such object");
    }
    if record.password_hash.is_none() {
        // A public share is just the object, and it goes out through the same
        // path a signed download takes -- ranges, headers and all.
        let answer = serve_object(&service, &key, Some(&record.filename), &headers).await;
        let served = answer.status().is_success();
        if served {
            service.note_read(&key).await;
        }
        burn_if_spent(&service, &key, served, headers.contains_key(header::RANGE)).await;
        return answer;
    }

    let Some(ticket) = query.ticket.as_deref() else {
        // A browser gets somewhere to type the password; anything else gets an
        // answer it can act on.
        if wants_html(&headers) {
            return password_page();
        }
        return refuse(
            StatusCode::UNAUTHORIZED,
            "this file needs a password: POST it to this URL for a ticket",
        );
    };
    let (redeemed, enc_key) = service.tickets().redeem(ticket, &key);
    if redeemed != crate::tickets::Redeemed::Ok {
        return refuse(StatusCode::FORBIDDEN, "that ticket is not valid any more");
    }
    let (Some(key_bytes), Some(nonce)) = (enc_key, record.enc_nonce.as_deref()) else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not open the file");
    };
    let answer = serve_sealed(
        &service,
        &key,
        &record.content_type,
        &record.filename,
        &key_bytes,
        nonce,
    );
    let served = answer.status().is_success();
    if served {
        service.note_read(&key).await;
    }
    burn_if_spent(&service, &key, served, headers.contains_key(header::RANGE)).await;
    answer
}

/// Destroy the object this answer just handed over, where the operator asked.
///
/// Only a whole-object answer counts. A `Range` request is a player reading a
/// header before it reads anything else, and treating that as "downloaded"
/// would delete the file between the first request and the second - which is
/// how one-shot links and media playback stop being compatible.
///
/// The row goes before the body finishes streaming, which is deliberate: the
/// bytes are already open on the reader's side, and a second request arriving
/// mid-transfer must not find the object still there.
async fn burn_if_spent(service: &Arc<FilesService>, key: &str, served: bool, ranged: bool) {
    if !service.burns_on_read() || !served || ranged {
        return;
    }
    service.forget_object(key).await;
}

/// `POST /s/{key}` -- trade the password for a single-use ticket.
///
/// The password travels in a header on a request with no body, never on the
/// query string: a URL is written down by every proxy, history and referrer on
/// the way, and this is the one secret that must not be.
async fn authorise(
    State(service): State<Arc<FilesService>>,
    UrlPath(key): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(record) = service.share_record(&key).await else {
        return refuse(StatusCode::NOT_FOUND, "no such object");
    };
    if !record.public || record.expired() {
        // Answered as absent, exactly as the `GET` is: a session share must
        // not be discoverable through the route that authorises share links,
        // and neither must one whose time is up.
        return refuse(StatusCode::NOT_FOUND, "no such object");
    }
    let Some(hash) = record.password_hash.as_deref() else {
        // Public, and already reachable by anyone holding the link. Saying so
        // gives away nothing the `GET` does not, and is better than minting a
        // ticket that would mean nothing.
        return refuse(StatusCode::BAD_REQUEST, "this file needs no password");
    };
    let Some(password) = bearer(&headers) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "send the password as a bearer token",
        );
    };
    // Checked before the hash, not after: Argon2id is the only thing standing
    // between a guesser and the file, and it is measured in milliseconds
    // against an attacker measured in cores.
    if !service.attempts().allowed(&key) {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "too many wrong passwords; try again later",
        );
    }
    if !crate::crypto::verify_password(&password, hash) {
        service.attempts().failed(&key);
        return refuse(StatusCode::FORBIDDEN, "wrong password");
    }
    service.attempts().cleared(&key);
    let Some(salt) = record.enc_salt.as_deref() else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not open the file");
    };
    let Ok(derived) = crate::crypto::derive_key(&password, salt) else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not open the file");
    };
    let Some(ticket) = service.tickets().issue(&key, Some(derived)) else {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not issue a ticket",
        );
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        format!(
            "{{\"ticket\":{ticket:?},\"ttl_seconds\":{}}}",
            crate::tickets::TICKET_TTL.as_secs()
        ),
    )
        .into_response()
}

/// Hand over a sealed object, opening it as it goes.
///
/// No ranges: the STREAM construction is sequential, and answering byte 900 000
/// would mean opening everything before it anyway. So a password share says
/// `Accept-Ranges: none` and is played or saved whole.
///
/// The opening happens on a blocking thread and reaches the response through a
/// channel, because Poly1305 over a large object is real work and an async
/// worker is not where it belongs.
fn serve_sealed(
    service: &Arc<FilesService>,
    key: &str,
    content_type: &str,
    filename: &str,
    enc_key: &[u8; 32],
    nonce: &[u8],
) -> Response {
    let Some(path) = object_path(service.objects_dir(), key) else {
        return refuse(StatusCode::BAD_REQUEST, "that is not a key");
    };
    let Ok(nonce) = <[u8; crate::crypto::ENC_NONCE_PREFIX_BYTES]>::try_from(nonce) else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not open the file");
    };
    let enc_key = *enc_key;

    // One chunk in flight: the reader is the network, and buffering more of a
    // decrypted file in memory than the client is taking is how a slow reader
    // becomes a memory problem.
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
    drop(tokio::task::spawn_blocking(move || {
        let opened = crate::crypto::open(&path, &enc_key, &nonce, |chunk| {
            sender
                .blocking_send(Ok(bytes::Bytes::from(chunk)))
                .map_err(|_| crate::crypto::CryptoError::Io)
        });
        if opened.is_err() {
            // The body has already begun by the time this can be known, so the
            // only way left to say "do not trust these bytes" is to break the
            // stream rather than end it.
            drop(sender.blocking_send(Err(std::io::Error::other("the file could not be opened"))));
        }
    }));

    let mut out = object_headers(content_type);
    if let Ok(value) = "none".parse() {
        drop(out.insert(header::ACCEPT_RANGES, value));
    }
    name_the_download(&mut out, filename, content_type);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    (out, Body::from_stream(stream)).into_response()
}

/// Somewhere to type the password, for a share opened in a browser.
///
/// Written out here rather than built from a frontend project, the way the
/// epoch-0 plugin did it: this is one form and one `fetch`, and a Node
/// toolchain in the server's build to produce it would cost more than the page
/// is. It does the same two steps a caller would do by hand -- POST the
/// password for a ticket, then follow the link with the ticket on it.
///
/// The script is inline, so the page carries a CSP that allows exactly itself
/// and nothing else: no network beyond this origin, no images, no frames.
fn password_page() -> Response {
    const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Password required</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
         background: #f6f7f9; color: #15181d; }
  @media (prefers-color-scheme: dark) { body { background: #14161a; color: #e7e9ee; } }
  form { width: min(360px, calc(100vw - 48px)); display: grid; gap: 12px;
         padding: 28px; border-radius: 14px; background: #fff;
         box-shadow: 0 1px 2px rgba(0,0,0,.06), 0 8px 24px rgba(0,0,0,.08); }
  @media (prefers-color-scheme: dark) { form { background: #1c1f26; box-shadow: none;
         border: 1px solid #2a2f38; } }
  h1 { margin: 0; font-size: 17px; font-weight: 600; }
  p { margin: 0; font-size: 13px; opacity: .7; }
  input, button { font: inherit; border-radius: 9px; padding: 10px 12px; }
  input { border: 1px solid #c9ced8; background: #fff; color: inherit; }
  @media (prefers-color-scheme: dark) { input { background: #14161a; border-color: #333a45; } }
  button { border: 0; background: #3b6fd4; color: #fff; font-weight: 600; cursor: pointer; }
  button[disabled] { opacity: .6; cursor: default; }
  .error { color: #c0392b; font-size: 13px; min-height: 1.5em; }
  @media (prefers-color-scheme: dark) { .error { color: #ff8a7a; } }
</style>
</head>
<body>
<form id="f">
  <h1>This file is password protected</h1>
  <p>Enter the password the sender gave you.</p>
  <input id="p" type="password" autocomplete="off" autofocus aria-label="Password">
  <button id="b" type="submit">Open</button>
  <div class="error" id="e" role="alert"></div>
</form>
<script>
(function () {
  var form = document.getElementById("f");
  var field = document.getElementById("p");
  var button = document.getElementById("b");
  var error = document.getElementById("e");
  // The address of the object is the address of this page, minus anything a
  // previous attempt left on the query string.
  var url = location.origin + location.pathname;
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    error.textContent = "";
    button.disabled = true;
    fetch(url, { method: "POST", headers: { Authorization: "Bearer " + field.value } })
      .then(function (response) {
        if (!response.ok) throw new Error(response.status === 403 ? "Wrong password." : "That did not work.");
        return response.json();
      })
      .then(function (body) {
        // Replaced rather than pushed, so Back does not land on a spent ticket.
        location.replace(url + "?ticket=" + encodeURIComponent(body.ticket));
      })
      .catch(function (failure) {
        error.textContent = failure.message || "That did not work.";
        button.disabled = false;
        field.select();
      });
  });
})();
</script>
</body>
</html>
"#;
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; \
                 script-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none';",
            ),
        ],
        PAGE,
    )
        .into_response()
}

/// Say what a share link should save as.
///
/// Only on the share routes: a signed download is being fetched by a client
/// that already knows the name it asked for, while a link is opened by a
/// browser that would otherwise name the file after the last path segment.
///
/// `inline` only for [`INLINE_TYPES`], and `attachment` for everything else -
/// a shared photo opens in the browser, a shared `.html` downloads.
/// The types a browser may render in place rather than save.
///
/// An allow-list, and a short one, transcribed from the epoch-0 plugin. What
/// is *not* on it is the point: `image/svg+xml` carries script, `text/html`
/// obviously does, and `text/plain` is sniffed into either by browsers that
/// have historically ignored being told not to. Everything absent is served as
/// a download, which is inert whatever it contains.
///
/// Rendering somebody's upload in an origin that serves other people's uploads
/// is what the CSP beside this exists to contain; the allow-list is the second
/// of the two, so a gap in either is not on its own a way in.
const INLINE_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/webm",
    "video/mp4",
    "video/webm",
    "video/ogg",
    "application/pdf",
];

/// Whether a browser may render this type in place.
fn renders_inline(content_type: &str) -> bool {
    let primary = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    INLINE_TYPES.contains(&primary.as_str())
}

fn name_the_download(headers: &mut HeaderMap, filename: &str, content_type: &str) {
    // ASCII only in the quoted form, with the real name repeated as RFC 5987
    // so anything not spellable there still arrives correctly named. A quote
    // or a backslash in the quoted form would end it early, so both go.
    let ascii: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let encoded: String = filename
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    let mode = if renders_inline(content_type) {
        "inline"
    } else {
        "attachment"
    };
    if let Ok(value) = format!("{mode}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}").parse() {
        drop(headers.insert(header::CONTENT_DISPOSITION, value));
    }
}

/// The password from an `Authorization: Bearer` header.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Whether this request came from something that would rather read a page.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// The bytes of one span, from a handle already positioned at its start.
///
/// Streamed in chunks rather than read whole: an object may be hundreds of
/// megabytes, and holding one in memory per concurrent download is how a file
/// server becomes the reason a server runs out of it. The remaining count is
/// carried along because the object continues past the span -- a read that
/// only stopped at the end of the file would answer every range with the
/// whole tail.
fn span_stream(
    file: tokio::fs::File,
    length: u64,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    futures_util::stream::try_unfold((file, length), |(mut file, left)| async move {
        if left == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        let want = usize::try_from(left.min(64 * 1024)).unwrap_or(64 * 1024);
        let mut chunk = vec![0_u8; want];
        let read = file.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        chunk.truncate(read);
        Ok(Some((
            bytes::Bytes::from(chunk),
            (file, left - read as u64),
        )))
    })
}

/// Write one object, if the grant says so.
async fn upload(
    State(service): State<Arc<FilesService>>,
    UrlPath(key): UrlPath<String>,
    Query(grant): Query<Grant>,
    body: Body,
) -> Response {
    if !service.verify_grant("PUT", &key, grant.expires, &grant.sig) {
        return refuse(
            StatusCode::FORBIDDEN,
            "this link is not valid or has expired",
        );
    }
    // The grant is what says this upload was allowed, how big it may be and
    // who it belongs to. Without a pending record the URL is either already
    // spent or was minted by a server that has since restarted.
    let Some(pending) = service.take_pending(&key) else {
        return refuse(StatusCode::CONFLICT, "this upload slot is no longer open");
    };
    let Some(path) = object_path(service.objects_dir(), &key) else {
        return refuse(StatusCode::BAD_REQUEST, "that is not a key");
    };
    if let Some(parent) = path.parent()
        && tokio::fs::create_dir_all(parent).await.is_err()
    {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not store the file",
        );
    }

    // Written beside the final name and renamed at the end, so a failed or
    // over-long upload never leaves a half file that a download would serve.
    let temporary = path.with_extension("part");
    let Ok(mut file) = tokio::fs::File::create(&temporary).await else {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not store the file",
        );
    };

    let written = match drain_body(body, &mut file, &pending, &temporary).await {
        Ok(written) => written,
        Err(response) => return response,
    };
    if file.flush().await.is_err() || tokio::fs::rename(&temporary, &path).await.is_err() {
        return abandon(
            &temporary,
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not store the file",
        )
        .await;
    }

    match service
        .record_object(&key, &pending, written, now_ms())
        .await
    {
        Ok(()) => {
            // The bytes are down and the row is written, so a name may now
            // point at them. Never before: a name bound at grant time would
            // resolve to an upload that failed.
            if let Some(bind) = &pending.bind {
                service.bind_finished_upload(1, &key, bind).await;
            }
        }
        Err(error) => {
            service.logger.log(
                LogEvent::error(Category::Admin, "an uploaded object could not be recorded")
                    .with("key", key.clone())
                    .with("error", error.to_string()),
            );
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not record the file",
            );
        }
    }

    // Derived after the row is written, never before: the upload has already
    // succeeded at this point, and a picture the decoder cannot read must not
    // turn a stored file into a failed one.
    let thumb_key = derive_thumbnail(&service, &key, &pending, written, &path).await;

    // Everyone in the channel learns the file exists, which is what makes it a
    // shared file rather than one only the uploader can reach. The preview
    // travels with the announcement so a transcript can render it without
    // asking a second question.
    service.announce_share(&key, &pending, written, thumb_key);
    StatusCode::CREATED.into_response()
}

/// Shrink an uploaded picture and record the result as a sibling object.
///
/// Silent when there is nothing to do — a sealed upload the server cannot
/// read, something that is not a picture, or a decoder that did not recognise
/// it. Best effort by construction: the caller has already answered CREATED in
/// every case but this one, and a missing preview is a worse picture rather
/// than a lost file.
async fn derive_thumbnail(
    service: &Arc<FilesService>,
    key: &str,
    pending: &crate::Pending,
    written: u64,
    source: &Path,
) -> String {
    if !crate::thumb::wanted(&pending.content_type, pending.seal.is_some(), written) {
        return String::new();
    }
    let thumb_key = crate::thumb::thumb_key(key);
    let Some(destination) = object_path(service.objects_dir(), &thumb_key) else {
        return String::new();
    };
    let Some((size, mime)) = crate::thumb::derive(source, &destination).await else {
        tracing::debug!(key, "no thumbnail could be derived for an uploaded picture");
        return String::new();
    };
    if let Err(error) = service
        .record_thumbnail(&thumb_key, key, pending, size, mime, now_ms())
        .await
    {
        // The file is on disk but no row points at it, so nothing will serve
        // it and nothing will sweep it. Worth a line rather than a silence.
        tracing::warn!(%error, key = thumb_key, "a derived thumbnail could not be recorded");
        drop(tokio::fs::remove_file(&destination).await);
        return String::new();
    }
    thumb_key
}

/// Write the body out, sealing it first when the share has a password.
///
/// Answers with the count of *plain* bytes, which is what the grant's ceiling
/// was about and what the row records: ciphertext is longer than its plaintext
/// by one tag per chunk, and a size the reader could not reconcile with the
/// file they downloaded would be worse than no size at all.
///
/// A sealed object is built here rather than encrypted afterwards so the
/// plaintext never lands in the object directory at all, not even for the
/// moment between writing and re-reading it.
async fn drain_body(
    body: Body,
    file: &mut tokio::fs::File,
    pending: &crate::Pending,
    temporary: &Path,
) -> Result<u64, Response> {
    let mut sealer = pending
        .seal
        .as_ref()
        .map(|seal| crate::crypto::Sealer::new(&seal.key, &seal.nonce));
    let mut written: u64 = 0;
    let mut stream = body.into_data_stream();

    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return Err(abandon(
                temporary,
                StatusCode::BAD_REQUEST,
                "the upload stopped early",
            )
            .await);
        };
        written += chunk.len() as u64;
        if written > pending.size {
            // The ceiling is enforced here and not only at grant time: the
            // control plane's limit would otherwise be a suggestion.
            return Err(abandon(
                temporary,
                StatusCode::PAYLOAD_TOO_LARGE,
                "more bytes than this upload was granted",
            )
            .await);
        }
        let outgoing = match sealer.as_mut() {
            Some(sealer) => match sealer.update(&chunk) {
                Ok(sealed) => bytes::Bytes::from(sealed),
                Err(_) => return Err(store_failed(temporary).await),
            },
            None => chunk,
        };
        if !outgoing.is_empty() && file.write_all(&outgoing).await.is_err() {
            return Err(store_failed(temporary).await);
        }
    }

    if let Some(sealer) = sealer.take() {
        let Ok(tail) = sealer.finish() else {
            return Err(store_failed(temporary).await);
        };
        if file.write_all(&tail).await.is_err() {
            return Err(store_failed(temporary).await);
        }
    }
    Ok(written)
}

/// The one answer every way of failing to write the object gives.
async fn store_failed(temporary: &Path) -> Response {
    abandon(
        temporary,
        StatusCode::INTERNAL_SERVER_ERROR,
        "could not store the file",
    )
    .await
}

/// Give up on an upload, taking the partial file with it.
async fn abandon(temporary: &Path, status: StatusCode, reason: &'static str) -> Response {
    drop(tokio::fs::remove_file(temporary).await);
    refuse(status, reason)
}

/// One shape for every refusal, so a client never has to parse prose.
fn refuse(status: StatusCode, reason: &'static str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        format!("{{\"error\":{reason:?}}}"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_cannot_walk_out_of_the_object_directory() {
        // The key reaches this from the URL, so `..` in it is the difference
        // between serving an upload and serving the signing key beside it.
        let root = Path::new("/data/files");
        assert!(object_path(root, "../files-signing.key").is_none());
        assert!(object_path(root, "1/../../etc/passwd").is_none());
        assert!(object_path(root, "1//name").is_none());
        assert!(object_path(root, r"1\..\name").is_none());
    }

    #[test]
    fn an_ordinary_nested_key_becomes_a_path_under_the_root() {
        let root = Path::new("/data/files");
        let path = object_path(root, "7/01890a/photo.png").expect("a nested key is a path");
        assert!(path.starts_with(root));
        assert!(path.ends_with("photo.png"));
    }

    #[test]
    fn a_request_without_a_range_asks_for_the_whole_object() {
        assert_eq!(parse_range(None, 1_000), Span::Whole);
    }

    #[test]
    fn an_open_ended_range_runs_to_the_last_byte() {
        // What a media element sends first, before it knows how long the file
        // is: everything from here on, which the listener answers as a partial
        // response so the player learns the length from `Content-Range`.
        assert_eq!(
            parse_range(Some("bytes=0-"), 1_000),
            Span::Part { start: 0, end: 999 }
        );
        assert_eq!(
            parse_range(Some("bytes=500-"), 1_000),
            Span::Part {
                start: 500,
                end: 999
            }
        );
    }

    #[test]
    fn a_closed_range_is_clamped_to_the_object() {
        assert_eq!(
            parse_range(Some("bytes=0-99"), 1_000),
            Span::Part { start: 0, end: 99 }
        );
        // Asking past the end is not an error - it is an ask for what is
        // there, which is how a player requests the tail of a file whose
        // length it is still guessing at.
        assert_eq!(
            parse_range(Some("bytes=900-5000"), 1_000),
            Span::Part {
                start: 900,
                end: 999
            }
        );
    }

    #[test]
    fn a_suffix_range_counts_back_from_the_end() {
        // How a player finds an MP4 whose index sits at the end of the file.
        assert_eq!(
            parse_range(Some("bytes=-100"), 1_000),
            Span::Part {
                start: 900,
                end: 999
            }
        );
        // More than there is: the whole object, not an error.
        assert_eq!(
            parse_range(Some("bytes=-5000"), 1_000),
            Span::Part { start: 0, end: 999 }
        );
        assert_eq!(parse_range(Some("bytes=-0"), 1_000), Span::Unsatisfiable);
    }

    #[test]
    fn a_range_that_starts_past_the_end_is_unsatisfiable() {
        // The 416 this becomes carries the real length, which is what stops a
        // player seeking into nothing over and over.
        assert_eq!(parse_range(Some("bytes=1000-"), 1_000), Span::Unsatisfiable);
        assert_eq!(
            parse_range(Some("bytes=2000-3000"), 1_000),
            Span::Unsatisfiable
        );
        assert_eq!(parse_range(Some("bytes=5-2"), 1_000), Span::Unsatisfiable);
    }

    #[test]
    fn an_empty_object_satisfies_no_range_at_all() {
        assert_eq!(parse_range(Some("bytes=0-"), 0), Span::Unsatisfiable);
        assert_eq!(parse_range(None, 0), Span::Whole);
    }

    #[tokio::test]
    async fn a_span_stops_where_it_was_asked_to_and_not_at_the_end_of_the_file() {
        // The whole point of the remaining-byte count: the handle is seeked to
        // the start of the span, and reading until EOF from there would answer
        // every range with the entire tail of the object.
        use futures_util::TryStreamExt as _;

        let dir = std::env::temp_dir().join(format!("starling-span-{}", now_ms()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("object.bin");
        let object: Vec<u8> = (0..200_000_u32).map(|byte| (byte % 251) as u8).collect();
        std::fs::write(&path, &object).expect("an object to read back");

        let mut file = tokio::fs::File::open(&path).await.expect("open");
        let _at: u64 = file
            .seek(std::io::SeekFrom::Start(1_000))
            .await
            .expect("seek");
        let chunks: Vec<bytes::Bytes> = span_stream(file, 300)
            .try_collect()
            .await
            .expect("the span reads");
        let read: Vec<u8> = chunks.concat();

        assert_eq!(
            read.len(),
            300,
            "exactly the span, not the rest of the file"
        );
        assert_eq!(read.as_slice(), &object[1_000..1_300]);

        // A span longer than one chunk still ends on its own boundary.
        let mut file = tokio::fs::File::open(&path).await.expect("open");
        let _at: u64 = file.seek(std::io::SeekFrom::Start(10)).await.expect("seek");
        let chunks: Vec<bytes::Bytes> = span_stream(file, 100_000)
            .try_collect()
            .await
            .expect("the span reads");
        let read: Vec<u8> = chunks.concat();
        assert_eq!(read.len(), 100_000);
        assert_eq!(read.as_slice(), &object[10..100_010]);

        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_range_this_listener_does_not_answer_becomes_the_whole_object() {
        // Everything here is legal to answer with a 200 and the full body, so
        // none of it is a refusal.
        assert_eq!(parse_range(Some("items=0-10"), 1_000), Span::Whole);
        assert_eq!(parse_range(Some("bytes=0-10,20-30"), 1_000), Span::Whole);
        assert_eq!(parse_range(Some("bytes=abc-def"), 1_000), Span::Whole);
        assert_eq!(parse_range(Some("bytes="), 1_000), Span::Whole);
    }
}
