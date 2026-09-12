//! What `audit` keeps of a profile change: a shrunk avatar or a compressed
//! comment, small enough that a history of them is affordable.

use sha2::{Digest as _, Sha256};

/// An avatar change.
pub(crate) const AVATAR: &str = "avatar";
/// A comment change.
pub(crate) const COMMENT: &str = "comment";

/// The longest side of a kept avatar. Clients draw avatars at 64px or less, so
/// this stays sharp at double density.
pub(crate) const AVATAR_EDGE: u32 = 128;

/// The decode gate: an avatar whose header describes more pixels is not kept.
const AVATAR_MAX_PIXELS: u32 = 16_000_000;

/// The largest stored copy, the 64 KiB a MySQL `BLOB` holds
/// (`docs/STORAGE.md` D3). A copy that does not fit is not kept; the entry
/// still records the change.
pub(crate) const MAX_STORED: usize = 64 * 1024;

/// The most a stored comment may inflate to, whatever the row says.
const MAX_COMMENT: usize = 1024 * 1024;

/// zstd level for comments. They are a few kilobytes, so the slow end costs
/// well under a millisecond.
const COMMENT_LEVEL: i32 = 19;

/// One copy, ready to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Packed {
    /// What `body` decodes to.
    pub mime: String,
    /// `zstd` or `identity`.
    pub encoding: &'static str,
    /// The stored bytes.
    pub body: Vec<u8>,
    /// SHA-256 of what the user sent, to recognise an unchanged re-send.
    pub content_hash: Vec<u8>,
}

impl Packed {
    /// SHA-256 of the stored bytes, as hex.
    #[must_use]
    pub(crate) fn digest(&self) -> String {
        hex(&Sha256::digest(&self.body))
    }
}

/// Shrink or compress `body`, or `None` when there is nothing worth keeping.
#[must_use]
pub(crate) fn pack(kind: &str, body: &[u8]) -> Option<Packed> {
    if body.is_empty() {
        return None;
    }
    let content_hash = Sha256::digest(body).to_vec();
    let packed = match kind {
        AVATAR => {
            // A noisy picture with alpha stays PNG and can miss the cap at
            // 128px; half the edge is a quarter of the pixels.
            let thumb = starling_imaging::shrink(body, AVATAR_EDGE, AVATAR_MAX_PIXELS)
                .filter(|thumb| thumb.bytes.len() <= MAX_STORED)
                .or_else(|| starling_imaging::shrink(body, AVATAR_EDGE / 2, AVATAR_MAX_PIXELS))?;
            Packed {
                mime: thumb.mime.to_owned(),
                encoding: "identity",
                body: thumb.bytes,
                content_hash,
            }
        }
        COMMENT => {
            let compressed = zstd::bulk::compress(body, COMMENT_LEVEL).ok()?;
            let (encoding, body) = if compressed.len() < body.len() {
                ("zstd", compressed)
            } else {
                ("identity", body.to_vec())
            };
            Packed {
                mime: "text/html".to_owned(),
                encoding,
                body,
                content_hash,
            }
        }
        _ => return None,
    };
    (packed.body.len() <= MAX_STORED).then_some(packed)
}

/// The stored bytes back as the user's content, or `None` if they do not decode.
#[must_use]
pub(crate) fn unpack(encoding: &str, body: Vec<u8>) -> Option<Vec<u8>> {
    match encoding {
        "identity" => Some(body),
        "zstd" => zstd::bulk::decompress(&body, MAX_COMMENT).ok(),
        _ => None,
    }
}

/// `detail` with the digest of its kept copy, which the chain then covers.
#[must_use]
pub(crate) fn with_digest(detail: &str, digest: &str) -> String {
    if detail.is_empty() {
        marker(digest)
    } else {
        format!("{detail} · {}", marker(digest))
    }
}

/// Whether `detail` chains the copy whose stored bytes are `body`.
#[must_use]
pub(crate) fn matches(detail: &str, body: &[u8]) -> bool {
    detail.ends_with(&marker(&hex(&Sha256::digest(body))))
}

fn marker(digest: &str) -> String {
    format!("snapshot sha256:{digest}")
}

/// Lowercase hex.
#[must_use]
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
    use std::io::Cursor;

    fn jpeg(size: u32) -> Vec<u8> {
        let image = DynamicImage::ImageRgb8(ImageBuffer::from_fn(size, size, |x, y| {
            Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        }));
        let mut out = Cursor::new(Vec::new());
        image
            .write_to(&mut out, ImageFormat::Jpeg)
            .expect("encodes");
        out.into_inner()
    }

    #[test]
    fn an_avatar_is_kept_at_most_128_pixels_a_side() {
        let original = jpeg(1024);
        let packed = pack(AVATAR, &original).expect("kept");
        let kept = image::load_from_memory(&packed.body).expect("decodes");
        assert!(kept.width() <= AVATAR_EDGE && kept.height() <= AVATAR_EDGE);
        assert!(packed.body.len() < original.len());
        assert_eq!(packed.mime, "image/jpeg");
    }

    #[test]
    fn a_comment_round_trips_through_compression() {
        let comment = "<p>hello there</p>".repeat(200);
        let packed = pack(COMMENT, comment.as_bytes()).expect("kept");
        assert_eq!(packed.encoding, "zstd");
        assert!(packed.body.len() < comment.len() / 10);
        assert_eq!(
            unpack(packed.encoding, packed.body).expect("inflates"),
            comment.as_bytes()
        );
    }

    #[test]
    fn a_comment_too_short_to_compress_is_kept_as_it_is() {
        let packed = pack(COMMENT, b"hi").expect("kept");
        assert_eq!(packed.encoding, "identity");
        assert_eq!(packed.body, b"hi");
    }

    #[test]
    fn nothing_and_not_a_picture_are_not_kept() {
        assert!(pack(COMMENT, b"").is_none());
        assert!(pack(AVATAR, b"<html>not a picture").is_none());
        assert!(pack("banner", b"whatever").is_none());
    }

    #[test]
    fn the_digest_in_the_detail_names_the_stored_bytes() {
        let packed = pack(COMMENT, b"a comment").expect("kept");
        let detail = with_digest("alice", &packed.digest());
        assert!(matches(&detail, &packed.body));
        assert!(!matches(&detail, b"something else"));
        assert!(detail.starts_with("alice · "));
    }
}
