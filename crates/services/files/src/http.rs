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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::FilesService;

/// The query a signed URL carries.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct Grant {
    expires: u64,
    sig: String,
}

/// The two routes, and the service they are served from.
pub(crate) fn router(service: Arc<FilesService>) -> Router {
    Router::new()
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

/// Read one object, if the grant says so.
async fn download(
    State(service): State<Arc<FilesService>>,
    UrlPath(key): UrlPath<String>,
    Query(grant): Query<Grant>,
) -> Response {
    if !service.verify_grant("GET", &key, grant.expires, &grant.sig) {
        return refuse(
            StatusCode::FORBIDDEN,
            "this link is not valid or has expired",
        );
    }
    let Some(path) = object_path(service.objects_dir(), &key) else {
        return refuse(StatusCode::BAD_REQUEST, "that is not a key");
    };
    let Ok(file) = tokio::fs::File::open(&path).await else {
        return refuse(StatusCode::NOT_FOUND, "no such object");
    };

    let content_type = service
        .content_type_of(&key)
        .await
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    // Streamed in chunks rather than read whole: an object may be hundreds of
    // megabytes, and holding one in memory per concurrent download is how a
    // file server becomes the reason a server runs out of it.
    let stream = futures_util::stream::try_unfold(file, |mut file| async move {
        let mut chunk = vec![0_u8; 64 * 1024];
        let read = file.read(&mut chunk).await?;
        if read == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        chunk.truncate(read);
        Ok(Some((bytes::Bytes::from(chunk), file)))
    });

    let mut headers = HeaderMap::new();
    if let Ok(value) = content_type.parse() {
        drop(headers.insert(header::CONTENT_TYPE, value));
    }
    // The bytes are attacker-supplied, so the browser is told not to guess at
    // their type and not to run them in this origin.
    if let Ok(nosniff) = "nosniff".parse() {
        drop(headers.insert(header::X_CONTENT_TYPE_OPTIONS, nosniff));
    }
    (headers, Body::from_stream(stream)).into_response()
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

    let mut written: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return abandon(
                &temporary,
                StatusCode::BAD_REQUEST,
                "the upload stopped early",
            )
            .await;
        };
        written += chunk.len() as u64;
        if written > pending.size {
            // The ceiling is enforced here and not only at grant time: the
            // control plane's limit would otherwise be a suggestion.
            return abandon(
                &temporary,
                StatusCode::PAYLOAD_TOO_LARGE,
                "more bytes than this upload was granted",
            )
            .await;
        }
        if file.write_all(&chunk).await.is_err() {
            return abandon(
                &temporary,
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not store the file",
            )
            .await;
        }
    }
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
        Ok(()) => {}
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

    // Everyone in the channel learns the file exists, which is what makes it a
    // shared file rather than one only the uploader can reach.
    service.announce_share(&key, &pending, written);
    StatusCode::CREATED.into_response()
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
}
