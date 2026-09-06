//! Fuzz the hand-rolled varint reader.
//!
//! `crates/services/voice/src/varint.rs` is a parser written here rather than
//! taken from a crate, and it reads both its offsets and its lengths from the
//! wire. `take(len)` with an attacker-chosen length is the shape that panics,
//! and every audio packet on a UDP port anyone can send to goes through it.
//!
//! ```text
//! cargo +nightly fuzz run voice_varint
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use starling_voice::varint::Reader;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);

    // Driven the way the packet parser drives it: keep reading until it says
    // there is nothing left. A reader that returned `Ok` without consuming
    // would spin here, which is as fatal as a panic and less obvious.
    for _ in 0..1024 {
        let before = reader.remaining();
        match reader.varint() {
            Ok(_) => assert!(
                reader.remaining() < before,
                "a successful read must consume input"
            ),
            Err(_) => break,
        }
    }

    // The other entry points, on the same bytes: each must refuse rather than
    // read past the end.
    let mut reader = Reader::new(data);
    let _ = reader.u8();
    let _ = reader.f32();
    let _ = reader.count();
    let _ = reader.take(data.len().wrapping_add(1));
    let _ = reader.take_rest();
});
