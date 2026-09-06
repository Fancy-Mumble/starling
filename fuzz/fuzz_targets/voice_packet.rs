//! Fuzz the audio packet parser, in both wire formats.
//!
//! One hop from an unauthenticated UDP datagram: the SFU aside, this is what
//! the voice port hands raw bytes to. Both `UdpFormat`s are exercised, because
//! a server accepts either and the legacy one is the older code.
//!
//! ```text
//! cargo +nightly fuzz run voice_packet
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use starling_voice::packet::{AudioCodec, Datagram, LegacyCodec, ProtobufCodec};

/// Both codecs, because a server accepts either and the legacy one is older.
fn codecs() -> [Box<dyn AudioCodec>; 2] {
    [Box::new(LegacyCodec), Box::new(ProtobufCodec)]
}

fuzz_target!(|data: &[u8]| {
    for codec in codecs() {
        let Ok(datagram) = codec.decode(data) else {
            continue;
        };
        // Re-encoding what was decoded must not panic either: the router
        // re-emits every packet it relays, so this runs per listener per frame
        // and is reached by anything that decodes at all.
        match datagram {
            Datagram::Audio(packet) => {
                let _ = codec.encode_audio(&packet);
            }
            Datagram::Ping(_) => {}
        }
    }
});
