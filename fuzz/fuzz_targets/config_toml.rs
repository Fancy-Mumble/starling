//! Fuzz the configuration parser.
//!
//! Operator-controlled rather than peer-controlled, and still process-fatal: a
//! configuration that panics on load is a server that will not start, and the
//! person who would fix it is the one who cannot start it.
//!
//! The counting allocator is what makes this catch more than a panic. An
//! eagerly-sized pool -- `max_users * 2` collected at boot -- is not a panic, it
//! is a multi-gigabyte allocation from a mistyped number, and this target finds
//! that class mechanically rather than by someone thinking of it.
//!
//! ```text
//! cargo +nightly fuzz run config_toml
//! ```

#![no_main]

#[path = "alloc.rs"]
mod alloc;

use libfuzzer_sys::fuzz_target;

#[global_allocator]
static ALLOC: alloc::Counting = alloc::Counting;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(config) = toml::from_str::<starling_runtime::config::Config>(text) else {
        return;
    };
    // Parsing is half of it. `validate` is what an operator runs as
    // `check-config`, and it is the half that walks what was parsed.
    let _ = config.validate();
});
