//! Turning the picture a page points at into the small one that travels.
//!
//! # Why the server shrinks it at all
//!
//! The bytes go to every client that asks about the message, so the size of a
//! preview image is paid once per viewer, on a control connection that is also
//! carrying the conversation. An `og:image` is a social card sized for a
//! full-width unfurl - a megabyte and 1200 pixels wide is ordinary - and none
//! of that is visible in a card the width of a chat bubble. Shrinking here is
//! what makes carrying the image at all affordable, and carrying it is what
//! keeps the viewer's address away from the origin.
//!
//! # Decoding is the dangerous part
//!
//! This is the one place in the service that runs a decoder over bytes a
//! stranger chose, so the size is checked *before* the decode rather than
//! after: an image is a compressed description of a pixel buffer, and a small
//! file may describe an enormous one. `image` reads the header on its own, so
//! the dimensions are known while the pixels are still a promise.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader};

/// The picture that goes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thumbnail {
    /// The re-encoded picture.
    pub bytes: Vec<u8>,
    /// What `bytes` are, ready for a `data:` URL.
    pub mime: &'static str,
    /// The size of `bytes`, not of what was fetched.
    pub width: u32,
    /// The height of `bytes`, paired with [`Thumbnail::width`].
    pub height: u32,
    /// The size of what was fetched, before the shrink.
    ///
    /// Read off the decoder rather than taken from the page's own
    /// `og:image:width`, because the page is a stranger and the decoder is
    /// the thing that actually looked. It is carried because the difference
    /// between a 360x253 thumbnail and a 3000x2000 photograph is invisible
    /// once both are inside the same box, and a client laying the card out
    /// wants it: one may not be enlarged, the other may be cropped to a band.
    pub source_width: u32,
    /// The height of what was fetched, paired with
    /// [`Thumbnail::source_width`].
    pub source_height: u32,
}

/// JPEG quality for the re-encode.
///
/// A preview card is a few hundred pixels wide, where the difference between
/// this and quality 95 is invisible and the difference in size is not.
const QUALITY: u8 = 80;

/// Shrink `bytes` to fit a box `edge` on a side.
///
/// `max_pixels` is the decode gate: an image whose *header* describes more
/// pixels than that is refused without being decoded, so a hundred-kilobyte
/// file claiming 40000x40000 costs a header read rather than six gigabytes of
/// pixel buffer.
///
/// `None` for anything that is not a picture this understands, which is the
/// same outcome as a page with no image at all: a card without one.
#[must_use]
pub fn shrink(bytes: &[u8], edge: u32, max_pixels: u32) -> Option<Thumbnail> {
    // The format is guessed from the bytes, never from the `content-type` the
    // far end claimed: the decoder is what runs on this, so it is the bytes
    // that have to be believed.
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let format = reader.format()?;
    let (width, height) = reader.into_dimensions().ok()?;
    if u64::from(width) * u64::from(height) > u64::from(max_pixels) {
        tracing::debug!(width, height, "preview image refused: too many pixels");
        return None;
    }

    // A second ceiling, inside the decoder. The dimension gate above trusts the
    // header, and a header is written by the same stranger as the pixels: a
    // malformed or hostile file can describe one size and decode into another.
    // `Limits` is enforced by the decoder itself as it allocates, so it holds
    // even when the header lied.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(max_pixels);
    limits.max_image_height = Some(max_pixels);
    limits.max_alloc = Some(u64::from(max_pixels) * 4);
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits);
    let decoded = reader.decode().ok()?;
    // Only ever down. A 60x60 favicon blown up to the box would be a blurry
    // version of a picture that was already the right size.
    let shrunk = if width > edge || height > edge {
        decoded.thumbnail(edge, edge)
    } else {
        decoded
    };
    encode(&shrunk).map(|thumbnail| Thumbnail {
        source_width: width,
        source_height: height,
        ..thumbnail
    })
}

/// Re-encode, keeping transparency where there is any.
///
/// JPEG cannot express an alpha channel, and flattening one silently puts a
/// black box behind every logo with a transparent corner - which is most of
/// them. So a picture with alpha keeps it, as PNG, and everything else (which
/// is to say every photograph) takes the format that makes photographs small.
fn encode(image: &DynamicImage) -> Option<Thumbnail> {
    let (format, mime) = if image.color().has_alpha() {
        (ImageFormat::Png, "image/png")
    } else {
        (ImageFormat::Jpeg, "image/jpeg")
    };
    let mut out = Cursor::new(Vec::new());
    match format {
        ImageFormat::Jpeg => image
            .to_rgb8()
            .write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(
                &mut out, QUALITY,
            ))
            .ok()?,
        _ => image.write_to(&mut out, format).ok()?,
    }
    Some(Thumbnail {
        bytes: out.into_inner(),
        mime,
        width: image.width(),
        height: image.height(),
        // Filled in by the caller, which is the only one that saw the
        // original: by here the picture has already been shrunk.
        source_width: 0,
        source_height: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, Rgba};

    /// A JPEG of `size` square, as bytes a fetch might have returned.
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
    fn a_large_picture_comes_back_inside_the_box_and_much_smaller() {
        let original = jpeg(1200);
        let thumb = shrink(&original, 640, 40_000_000).expect("shrinks");
        assert!(thumb.width <= 640 && thumb.height <= 640, "{thumb:?}");
        assert!(
            thumb.bytes.len() < original.len(),
            "a thumbnail that is not smaller is not worth making"
        );
        assert_eq!(thumb.mime, "image/jpeg");
    }

    #[test]
    fn a_picture_already_smaller_than_the_box_is_not_stretched_to_fill_it() {
        let thumb = shrink(&jpeg(64), 640, 40_000_000).expect("shrinks");
        assert_eq!((thumb.width, thumb.height), (64, 64));
    }

    #[test]
    fn transparency_survives_rather_than_turning_black() {
        // The failure this rules out is a logo on a transparent ground, which
        // is what a large share of `og:image` values are: encoded as JPEG it
        // comes back on a black box, and the card looks broken rather than
        // plain.
        let image = DynamicImage::ImageRgba8(ImageBuffer::from_fn(120, 120, |x, _| {
            Rgba([255, 0, 0, if x < 60 { 0 } else { 255 }])
        }));
        let mut source = Cursor::new(Vec::new());
        image
            .write_to(&mut source, ImageFormat::Png)
            .expect("encodes");

        let thumb = shrink(source.get_ref(), 640, 40_000_000).expect("shrinks");
        assert_eq!(thumb.mime, "image/png");
        let back = image::load_from_memory(&thumb.bytes).expect("decodes");
        assert_eq!(
            back.to_rgba8().get_pixel(10, 10)[3],
            0,
            "alpha was flattened"
        );
    }

    #[test]
    fn a_picture_that_describes_more_pixels_than_allowed_is_never_decoded() {
        // The decompression bomb: the file is small, the buffer it asks for is
        // not, and the check has to happen on the header rather than after.
        let bomb = jpeg(2000);
        assert!(shrink(&bomb, 640, 1_000_000).is_none());
        // The same bytes are fine when the allowance covers them, so this is a
        // limit and not a mistaken rejection.
        assert!(shrink(&bomb, 640, 40_000_000).is_some());
    }

    #[test]
    fn bytes_that_are_not_a_picture_yield_nothing_rather_than_an_error() {
        assert!(shrink(b"<html><head><title>not a picture</title>", 640, 40_000_000).is_none());
        assert!(shrink(&[], 640, 40_000_000).is_none());
    }
}
