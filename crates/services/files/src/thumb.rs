//! Deriving a small preview of an uploaded picture.
//!
//! A chat transcript shows a picture inline, and without a thumbnail that
//! means every viewer downloads the original — a photo straight off a phone,
//! several megabytes, to fill a box a few hundred pixels wide. The thumbnail
//! is what makes the transcript affordable to *look at*; the original is
//! fetched when somebody opens the lightbox and not before.
//!
//! # Only where the server can already read the bytes
//!
//! A password-sealed object is stored as ciphertext under a key derived from
//! the uploader's password, which this server does not have. There is nothing
//! to shrink, and there must not be: deriving a thumbnail would mean holding
//! the plaintext, which is the one thing that mode promises not to do. Those
//! uploads get no server thumbnail and rely on the one the sender inlined.
//!
//! For every other object the server already has the plaintext — it wrote the
//! file — so a thumbnail beside it discloses nothing new.

use std::path::Path;

/// The long edge of a derived thumbnail, in pixels.
///
/// Sized for a chat bubble rather than a viewer. Anything larger is paid by
/// every reader of the channel and seen by none of them.
const EDGE: u32 = 320;

/// The most pixels a picture may *claim* before it is refused undecoded.
///
/// The decode gate, not a file-size limit: an image is a compressed
/// description of a pixel buffer, and a small upload may describe an enormous
/// one. 8000x8000 is well past any camera and far short of a buffer that
/// hurts.
const MAX_PIXELS: u32 = 64_000_000;

/// The largest original this will read into memory to shrink.
///
/// Beyond it the thumbnail is skipped rather than the upload refused: a large
/// file is a perfectly good upload, it simply does not get a preview derived
/// on this path. 64 MiB is comfortably above a phone photograph.
const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

/// The key a thumbnail is stored under, given its original's.
///
/// A sibling key rather than a column, so the thumbnail is an ordinary object:
/// it downloads through the same signed URL, expires with the same sweep, and
/// needs no new route. `Grant` and `Share` only have to *name* it.
#[must_use]
pub(crate) fn thumb_key(key: &str) -> String {
    format!("{key}.thumb")
}

/// Whether a thumbnail should be derived for an object of this type.
#[must_use]
pub(crate) fn wanted(content_type: &str, sealed: bool, size: u64) -> bool {
    !sealed
        && size <= MAX_SOURCE_BYTES
        && content_type
            .split(';')
            .next()
            .is_some_and(|primary| is_image_type(primary.trim()))
}

/// Read `source`, shrink it, and write the result beside it.
///
/// Returns the size and content type of what it wrote, or `None` when there is
/// no thumbnail to be had — an unreadable file, a format the decoder does not
/// know, or a picture already smaller than the box. A failure here is never an
/// upload failure: the bytes are down and the row is written, and a missing
/// preview is a worse picture rather than a lost file.
pub(crate) async fn derive(source: &Path, destination: &Path) -> Option<(u64, &'static str)> {
    let bytes = tokio::fs::read(source).await.ok()?;
    // The decode and re-encode is CPU work on a runtime that is otherwise
    // carrying conversations, so it does not run on the reactor.
    let shrunk =
        tokio::task::spawn_blocking(move || starling_imaging::shrink(&bytes, EDGE, MAX_PIXELS))
            .await
            .ok()??;
    let size = shrunk.bytes.len() as u64;
    tokio::fs::write(destination, &shrunk.bytes).await.ok()?;
    Some((size, shrunk.mime))
}

/// Whether a media type names a picture, whatever case the header used.
///
/// Compared as bytes rather than by slicing the string: a `content-type`
/// arrives from a client, and slicing one by a byte index lands inside a
/// character the moment somebody sends a non-ASCII header.
fn is_image_type(primary: &str) -> bool {
    primary
        .as_bytes()
        .get(.."image/".len())
        .is_some_and(|head| head.eq_ignore_ascii_case(b"image/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thumbnail_sits_beside_the_picture_it_shrank() {
        assert_eq!(thumb_key("7/01890a/photo.png"), "7/01890a/photo.png.thumb");
    }

    #[test]
    fn a_picture_the_server_can_read_gets_one() {
        assert!(wanted("image/png", false, 1024));
        assert!(wanted("image/jpeg; charset=binary", false, 1024));
        assert!(
            wanted("IMAGE/PNG", false, 1024),
            "the header's case is not ours to insist on"
        );
    }

    #[test]
    fn a_sealed_picture_does_not() {
        // The whole point of the password mode: this server does not hold the
        // plaintext, and deriving a preview would mean it did.
        assert!(!wanted("image/png", true, 1024));
    }

    #[test]
    fn something_that_is_not_a_picture_does_not() {
        assert!(!wanted("application/pdf", false, 1024));
        assert!(!wanted("video/mp4", false, 1024));
        assert!(!wanted("text/plain", false, 1024));
    }

    #[test]
    fn an_original_too_large_to_read_is_skipped_rather_than_refused() {
        // A large upload is a perfectly good upload; it just gets no preview
        // derived on this path.
        assert!(!wanted("image/png", false, MAX_SOURCE_BYTES + 1));
        assert!(wanted("image/png", false, MAX_SOURCE_BYTES));
    }

    #[test]
    fn a_header_with_a_non_ascii_byte_does_not_panic() {
        // The type comes off the wire, so it is whatever a client sent. The
        // byte-wise compare is what keeps a multi-byte character from being
        // sliced through the middle.
        assert!(!wanted("imäge/png", false, 1024));
        assert!(!wanted("é", false, 1024));
        assert!(!wanted("", false, 1024));
    }
}
