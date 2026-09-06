//! Fuzz the preview image decoder.
//!
//! The `image` crate's jpeg, png, gif and webp decoders, on bytes fetched from
//! a URL a *user* chose. Third-party code, remotely triggerable, and the one
//! place in the tree that decodes a picture at all.
//!
//! The counting allocator matters more here than anywhere: a small file
//! describing an enormous bitmap is the classic attack, and it ends the process
//! without panicking.
//!
//! ```text
//! cargo +nightly fuzz run thumbnail
//! ```

#![no_main]

#[path = "alloc.rs"]
mod alloc;

use libfuzzer_sys::fuzz_target;

#[global_allocator]
static ALLOC: alloc::Counting = alloc::Counting;

fuzz_target!(|data: &[u8]| {
    // The same limits the service uses, so a crash here is a crash there.
    let thumbnail = starling_link_preview::thumbnail::shrink(data, 320, 4096 * 4096);
    if let Some(thumbnail) = thumbnail {
        assert!(
            thumbnail.width <= 320 && thumbnail.height <= 320,
            "a thumbnail came back larger than the box it was asked for: \
             {}x{}",
            thumbnail.width,
            thumbnail.height
        );
    }
});
