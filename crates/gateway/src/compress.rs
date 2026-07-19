//! Compressing the control stream for peers that asked for it.
//!
//! # Why a frame type rather than the stream
//!
//! The obvious alternative is to compress the TCP stream itself once the
//! handshake is done. It is rejected because both ends must then switch at
//! *exactly* the same byte: one frame written before the switch and read after
//! it desynchronises the connection permanently, and the symptom is garbage at
//! a layer that has no idea compression exists.
//!
//! A frame type has none of that. Each batch is self-describing, the boundary
//! is the framing that already exists, and a batch that fails to decompress
//! costs one batch rather than the connection. It is also inspectable: a
//! capture shows type 1900 and a length, not an opaque byte river.
//!
//! # What it is not
//!
//! **Not a service.** [`COMPRESSED_BATCH`] is a property of the connection, not
//! a destination on it, what comes out of a batch is ordinary frames that
//! route exactly as they did before. That is why it is numbered far from the
//! service block rather than taking the next free slot there.
//!
//! # Who sees one
//!
//! Only a peer that announced `zstd` in its `Hello`. A stock Mumble client
//! never announces anything, so it never receives a type it cannot parse, the
//! same rule the resume sequence follows, and the reason both are safe to add
//! to a protocol whose whole point is that murmur's clients keep working.

use bytes::{BufMut, Bytes, BytesMut};
use starling_proto_fancy::types::COMPRESSED_BATCH;

use crate::connection::Outbound;

/// Below this, a batch is sent uncompressed.
///
/// zstd on forty bytes of `UserState` spends CPU to produce something no
/// smaller, and often slightly larger. The interesting payloads, a reconnect
/// flood, a page of chat history, are far above it.
const WORTH_COMPRESSING: usize = 256;

/// The compression level.
///
/// 1, not the default 3. This runs on the socket write path, where the budget
/// is a 10 ms audio frame; level 1 gets most of the ratio on protobuf for a
/// fraction of the time, and the alternative to compressing quickly is not
/// compressing better, it is stalling the writer.
const LEVEL: i32 = 1;

/// Join `frames` into one compressed batch, or `None` if it is not worth it.
///
/// The frames go in whole, `type ‖ len ‖ payload` each, exactly as they would
/// have been written, so the receiver decompresses and then reads frames with
/// the parser it already has. Nothing needs to know what is inside them, which
/// is what keeps this out of the routing layer entirely.
#[must_use]
pub fn batch(frames: &[Outbound]) -> Option<Outbound> {
    if frames.len() < 2 {
        // One frame is not a batch, and wrapping it would add a header and a
        // compression pass to save nothing.
        return None;
    }
    let total: usize = frames.iter().map(Outbound::len).sum();
    if total < WORTH_COMPRESSING {
        return None;
    }

    let mut joined = BytesMut::with_capacity(total);
    for frame in frames {
        joined.put_slice(&frame.prefix);
        joined.put_slice(&frame.payload);
    }

    let compressed = zstd::stream::encode_all(joined.as_ref(), LEVEL).ok()?;
    // A batch that did not shrink is sent as it was. Compression that makes a
    // payload larger is a cost with no benefit, and protobuf that is mostly
    // random bytes (sealed pchat ciphertext, an avatar) does exactly that.
    if compressed.len() >= total {
        return None;
    }

    let payload = Bytes::from(compressed);
    Some(Outbound {
        prefix: starling_proto::codec::header(COMPRESSED_BATCH, payload.len(), None),
        payload,
    })
}

/// The inverse, for a peer receiving one.
///
/// Bounded: `limit` caps what one batch may expand to, because the number in a
/// compressed header is chosen by whoever sent it and a small batch can claim
/// to be enormous. That is the same rule the frame decoder follows on the
/// declared length, for the same reason.
///
/// # Errors
///
/// When the payload is not valid zstd, or expands past `limit`.
pub fn unbatch(payload: &[u8], limit: usize) -> Result<Bytes, &'static str> {
    let mut out = Vec::new();
    zstd::stream::copy_decode(payload, &mut LimitedWriter::new(&mut out, limit))
        .map_err(|_| "undecodable or oversized compressed batch")?;
    Ok(Bytes::from(out))
}

/// A sink that refuses to grow past a bound.
struct LimitedWriter<'a> {
    out: &'a mut Vec<u8>,
    limit: usize,
}

impl<'a> LimitedWriter<'a> {
    const fn new(out: &'a mut Vec<u8>, limit: usize) -> Self {
        Self { out, limit }
    }
}

impl std::io::Write for LimitedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.out.len() + buf.len() > self.limit {
            // Refused mid-stream rather than after the fact: the point of the
            // bound is to never hold the oversized thing at all.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "compressed batch expands past its bound",
            ));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` frames that compress well, because protobuf control traffic does:
    /// the same field tags and the same channel ids over and over.
    fn repetitive(n: usize) -> Vec<Outbound> {
        (0..n)
            .map(|i| {
                let payload = Bytes::from(vec![b'a' + (i % 4) as u8; 64]);
                Outbound {
                    prefix: starling_proto::codec::header(9, payload.len(), None),
                    payload,
                }
            })
            .collect()
    }

    #[test]
    fn a_batch_round_trips_to_exactly_the_frames_that_went_in() {
        let frames = repetitive(8);
        let expected: Vec<u8> = frames
            .iter()
            .flat_map(|f| [f.prefix.as_ref(), f.payload.as_ref()].concat())
            .collect();

        let batched = batch(&frames).expect("worth compressing");
        assert!(batched.payload.len() < expected.len(), "it did shrink");

        let out = unbatch(&batched.payload, 1 << 20).expect("decodes");
        assert_eq!(
            out.as_ref(),
            expected.as_slice(),
            "what comes out must be the frames that went in, byte for byte, a \
             receiver parses them with the decoder it already has"
        );
    }

    #[test]
    fn the_batch_announces_its_own_length() {
        // The header is read by a peer that has not decompressed anything yet,
        // so it must describe the *compressed* payload.
        let batched = batch(&repetitive(8)).expect("worth compressing");
        let declared = u32::from_be_bytes([
            batched.prefix[2],
            batched.prefix[3],
            batched.prefix[4],
            batched.prefix[5],
        ]);
        assert_eq!(declared as usize, batched.payload.len());
        assert_eq!(
            u16::from_be_bytes([batched.prefix[0], batched.prefix[1]]),
            COMPRESSED_BATCH
        );
        assert_eq!(
            batched.prefix.len(),
            starling_proto::codec::HEADER_SIZE,
            "no sequence on a batch"
        );
    }

    #[test]
    fn nothing_small_or_singular_is_batched() {
        // Compressing one small frame spends CPU to produce something no
        // smaller, and often larger.
        assert!(batch(&[]).is_none());
        assert!(batch(&repetitive(1)).is_none(), "one frame is not a batch");

        let two_tiny = vec![
            Outbound {
                prefix: Bytes::from_static(b"aaaaaa"),
                payload: Bytes::from_static(b"x"),
            },
            Outbound {
                prefix: Bytes::from_static(b"bbbbbb"),
                payload: Bytes::from_static(b"y"),
            },
        ];
        assert!(batch(&two_tiny).is_none(), "below the threshold");
    }

    #[test]
    fn incompressible_frames_are_left_alone() {
        // Sealed pchat ciphertext and avatars are effectively random, and zstd
        // makes random data slightly *larger*. Sending the batch anyway would
        // cost bandwidth to save none.
        // xorshift64, because the obvious `i * prime + j` generator produces a
        // pattern zstd finds immediately, which made this test assert the
        // opposite of what it meant to.
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        let random: Vec<Outbound> = (0..8u32)
            .map(|_| {
                let payload: Bytes = (0..256).map(|_| next()).collect::<Vec<u8>>().into();
                Outbound {
                    prefix: starling_proto::codec::header(9, payload.len(), None),
                    payload,
                }
            })
            .collect();
        assert!(batch(&random).is_none(), "no shrink, no batch");
    }

    #[test]
    fn a_batch_cannot_expand_past_its_bound() {
        // The expanded size is chosen by whoever sent the batch, so a small
        // payload can claim to be enormous. Refused rather than allocated.
        let frames = repetitive(64);
        let batched = batch(&frames).expect("worth compressing");
        assert!(unbatch(&batched.payload, 64).is_err(), "bound is enforced");
        assert!(unbatch(b"not zstd at all", 1 << 20).is_err());
    }
}
