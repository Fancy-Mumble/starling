//! Fuzz the Fancy envelope decoders.
//!
//! One hop past the frame decoder: every Fancy service reads its own envelope
//! out of a frame the gateway routed by type id, and a client sends these the
//! moment it has authenticated.
//!
//! ```text
//! cargo +nightly fuzz run fancy_envelope
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message as _;

fuzz_target!(|data: &[u8]| {
    use starling_proto_fancy::fancy;

    // Every envelope a client can put on the wire, on the same bytes. A decoder
    // that accepts something another rejects is not itself a bug; one that
    // panics on either is.
    if let Ok(envelope) = fancy::social::SocialEnvelope::decode(data) {
        let _ = envelope.encode_to_vec();
    }
    if let Ok(envelope) = fancy::pchat::PchatEnvelope::decode(data) {
        let _ = envelope.encode_to_vec();
    }
    if let Ok(envelope) = fancy::screenshare::ScreenshareEnvelope::decode(data) {
        let _ = envelope.encode_to_vec();
    }
});
