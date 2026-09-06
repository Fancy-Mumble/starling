//! Fuzz the zstd batch decompressor, asserting a bound rather than no-panic.
//!
//! A decompressor that does not panic can still end a server: a small input
//! describing an enormous output is a bomb, and the process dies with no panic
//! anywhere. The `LimitedWriter` in `compress.rs` is what stops that, and this
//! asserts the limit holds rather than that the call returns.
//!
//! The counting allocator in `alloc.rs` is the other half: it aborts if one
//! iteration holds too much, which catches the bomb even where the output bound
//! is respected but the intermediate buffers are not.
//!
//! ```text
//! cargo +nightly fuzz run unbatch
//! ```

#![no_main]

#[path = "alloc.rs"]
mod alloc;

use libfuzzer_sys::fuzz_target;

#[global_allocator]
static ALLOC: alloc::Counting = alloc::Counting;

fuzz_target!(|data: &[u8]| {
    let limit = 1024 * 1024;
    if let Ok(out) = starling_gateway::compress::unbatch(data, limit) {
        assert!(
            out.len() <= limit,
            "unbatch returned {} bytes against a limit of {limit}",
            out.len()
        );
    }
});
