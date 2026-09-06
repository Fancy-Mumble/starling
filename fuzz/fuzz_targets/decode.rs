//! Fuzz the TCP frame decoder.
//!
//! `codec::decode` is the very first code an unauthenticated peer reaches, so
//! its contract is absolute: for *any* byte sequence it returns
//! `Ok(Some(msg))`, `Ok(None)` or `Err(_)`, and never panics, never aborts on
//! an allocation it was told to make, and never loops forever.
//!
//! Run locally:
//!
//! ```text
//! cargo +nightly fuzz run decode
//! ```

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use starling_proto::codec;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);

    // Drive the decoder the way the read loop does: keep pulling frames until
    // it asks for more input or rejects the stream. This exercises the
    // multi-frame path, not just a single decode.
    loop {
        let before = buf.len();
        match codec::decode(&mut buf) {
            Ok(Some(msg)) => {
                // Round-tripping a decoded message must not panic either: the
                // server re-encodes what it relays.
                let _ = codec::encode(&msg);

                // A successful decode must consume input. If it did not, the
                // read loop above would spin forever on the same bytes.
                assert!(
                    buf.len() < before,
                    "decode returned a message without consuming input"
                );
            }
            Ok(None) | Err(_) => break,
        }
    }
});
