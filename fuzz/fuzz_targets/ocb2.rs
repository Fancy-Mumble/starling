//! Fuzz the voice cipher, and assert it does not accept a forgery.
//!
//! Two properties, because "does not panic" is the weaker half. OCB2 is the
//! cipher every UDP voice packet is sealed with, and a forgery accepted here is
//! an attacker speaking as somebody else.
//!
//! ```text
//! cargo +nightly fuzz run ocb2
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use starling_crypto::VoiceCipher as _;
use starling_crypto::ocb2::{Block, Ocb2};

/// A cipher with fixed key and nonces.
///
/// The property is about the cipher, not about key handling, and a key from the
/// fuzzer would only make a failure harder to reproduce.
fn fresh() -> Ocb2 {
    Ocb2::new([0x42_u8; 16], Block([0_u8; 16]), Block([0_u8; 16]))
}

fuzz_target!(|data: &[u8]| {
    let mut cipher = fresh();

    // 1. Arbitrary bytes must be rejected, not decoded, and never panic.
    let _ = cipher.open(data, &[]);

    // 2. A packet this cipher sealed must open, and its own tag must not
    //    authenticate a modified version of it.
    let mut sender = fresh();
    let Ok(sealed) = sender.seal(data, &[]) else {
        return;
    };
    let mut receiver = fresh();
    if receiver.open(&sealed, &[]).is_err() {
        // Not a bug, and worth stating because it is surprising: seal-then-open
        // is **not** a total round trip. OCB2 refuses a plaintext whose final
        // block matches the offset in all but its last byte, which is the
        // shape eprint 2019/311 §9 constructs, and it refuses it whoever
        // produced it -- including this cipher a moment ago.
        //
        // A fuzzer finds this in seconds because the key here is fixed, so the
        // offset is deterministic and coverage feedback can search for a
        // matching block. A real peer cannot: it does not know the key, and
        // hitting the shape by chance is about 2^-120.
        //
        // So the assertion is on the *reason*, not on the outcome.
        assert_eq!(
            receiver.suspected_forgeries(),
            1,
            "a packet this cipher sealed was refused for some reason other \
             than the 2019 forgery shape"
        );
        return;
    }

    // Flip one bit anywhere and it must stop authenticating.
    if let Some(index) = data.first().map(|b| usize::from(*b) % sealed.len().max(1)) {
        let mut forged = sealed.clone();
        if let Some(byte) = forged.get_mut(index) {
            *byte ^= 0x01;
            let mut receiver = fresh();
            assert!(
                receiver.open(&forged, &[]).is_err(),
                "a modified packet authenticated: byte {index} flipped"
            );
        }
    }
});
