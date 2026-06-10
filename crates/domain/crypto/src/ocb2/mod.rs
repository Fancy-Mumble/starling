//! OCB2-AES128, the cipher every stock Mumble client speaks.
//!
//! The other implementation of [`VoiceCipher`], and the one
//! that is not a choice: a 1.4 or 1.5 client offers this and nothing else, so
//! backwards compatibility means having it. `XChaCha20-Poly1305` is what a
//! client gets when it announces Fancy 0.4.0 or later.
//!
//! # What is worse about it
//!
//! Three bytes of tag, against sixteen. That is one forgery accepted per 2^24
//! attempts, and an attacker who can send 50 packets a second gets there in
//! about four days. Mumble's answer is that a forged *audio* frame is a burst of
//! noise, not a compromise — there is no parser behind it to attack, because the
//! Opus payload is passed through untouched.
//!
//! It also needed a mitigation for a 2019 break of OCB2 itself, which is carried
//! here in this module's `core` submodule, because the wire format cannot be
//! changed without breaking the clients this exists to serve.
//!
//! # Layout
//!
//! ```text
//! nonce low byte   1 byte
//! tag              3 bytes, truncated from 16
//! ciphertext       as long as the plaintext
//! ```

mod block;
mod core;
mod iv;

pub use block::{Block, BLOCK_LEN};
pub use core::TAG_LEN;
pub use iv::{Arrival, NonceError};

use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use crate::session::VoiceError;
use crate::stream::VoiceCipher;
use crate::voice::Rejected;
use block::BlockCipher;
use iv::{RecvNonce, SendNonce};

/// Bytes a packet grows by: one of nonce and three of tag.
pub const OVERHEAD: usize = 1 + TAG_LEN;

/// One peer's OCB2 state, both directions.
///
/// murmur calls this `CryptState`, and it is per-connection: the key and both
/// nonces are exchanged in `CryptSetup` at handshake and never reused.
pub struct Ocb2 {
    cipher: BlockCipher,
    key: [u8; BLOCK_LEN],
    send: SendNonce,
    recv: RecvNonce,
    /// Packets refused for having the shape of an eprint 2019/311 §9 forgery.
    ///
    /// Counted rather than logged per packet: an attacker who can trigger a log
    /// line per datagram has a denial of service.
    suspected_forgeries: u64,
}

impl Ocb2 {
    /// A state from a key and the two nonces `CryptSetup` carried.
    #[must_use]
    pub fn new(key: [u8; BLOCK_LEN], client_nonce: Block, server_nonce: Block) -> Self {
        Self {
            cipher: BlockCipher::new(&key),
            key,
            // The server sends under its own nonce and expects the client's.
            send: SendNonce::new(server_nonce),
            recv: RecvNonce::new(client_nonce),
            suspected_forgeries: 0,
        }
    }

    /// The key, for putting in `CryptSetup`.
    ///
    /// Returned by value and not stored anywhere else; the caller is expected to
    /// put it straight on the wire inside TLS and drop it.
    #[must_use]
    pub const fn key(&self) -> [u8; BLOCK_LEN] {
        self.key
    }

    /// The nonce this server sends under, for `CryptSetup`.
    #[must_use]
    pub const fn server_nonce(&self) -> Block {
        self.send.get()
    }

    /// The nonce this server expects from the client, for a resynchronisation.
    #[must_use]
    pub const fn client_nonce(&self) -> Block {
        self.recv.get()
    }

    /// Adopt a client's claimed nonce after it asked to resynchronise.
    ///
    /// The client sends this when it has decided the server is too far out of
    /// step to recover. Trusting it is safe only because the tag still has to
    /// verify afterwards — the nonce is a hint about where to look, not a
    /// credential.
    pub fn resync_to(&mut self, client_nonce: Block) {
        self.recv = RecvNonce::new(client_nonce);
    }

    /// How many packets were refused as suspected forgeries.
    #[must_use]
    pub const fn suspected_forgeries(&self) -> u64 {
        self.suspected_forgeries
    }
}

impl VoiceCipher for Ocb2 {
    fn name(&self) -> &'static str {
        "OCB2-AES128"
    }

    fn overhead(&self) -> usize {
        OVERHEAD
    }

    fn seal(&mut self, frame: &[u8], _aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        // OCB2 as Mumble uses it has no associated data: the header is one byte
        // of nonce and three of tag, both already covered. The parameter exists
        // because the other cipher does authenticate a header, and the trait
        // serves both.
        let nonce = self.send.advance();
        let (ciphertext, tag) = core::encrypt(&self.cipher, nonce, frame);

        let mut packet = Vec::with_capacity(OVERHEAD + ciphertext.len());
        packet.push(nonce.0[0]);
        packet.extend_from_slice(&tag.0[..TAG_LEN]);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    fn open(&mut self, packet: &[u8], _aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        let (header, ciphertext) = packet
            .split_at_checked(OVERHEAD)
            .ok_or(VoiceError::Truncated { len: packet.len() })?;

        // Only eight bits of counter reach the wire, so the sequence in the
        // error is the byte, not a reconstructed 64-bit number. Reporting the
        // byte is honest; inventing the high bits would put a guess in a log.
        let candidate = self.recv.place(header[0]).map_err(|error| match error {
            NonceError::Replay => Rejected::Replay {
                sequence: u64::from(header[0]),
            },
            NonceError::OutOfRange => Rejected::TooOld {
                sequence: u64::from(header[0]),
            },
        })?;

        let opened = core::decrypt(&self.cipher, candidate.nonce, ciphertext);

        // Constant time: a timing signal here leaks how much of a forged tag was
        // right, which turns 2^24 guesses into three lots of 2^8.
        if opened.tag.0[..TAG_LEN].ct_eq(&header[1..]).unwrap_u8() != 1 {
            return Err(VoiceError::NotAuthentic);
        }

        // Authentic *and* shaped like the 2019 attack. Both can be true: that is
        // exactly what the paper constructs, so the tag alone is not enough.
        if opened.forgery_suspected {
            self.suspected_forgeries = self.suspected_forgeries.saturating_add(1);
            return Err(VoiceError::NotAuthentic);
        }

        self.recv.accept(&candidate);
        Ok(opened.plain)
    }
}

impl std::fmt::Debug for Ocb2 {
    /// Prints no key or nonce material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ocb2")
            .field("suspected_forgeries", &self.suspected_forgeries)
            .finish_non_exhaustive()
    }
}

impl Drop for Ocb2 {
    /// Clears the key copy kept for `CryptSetup`.
    ///
    /// `BlockCipher`'s expanded round keys are `aes`'s to clear; this is the
    /// plain copy this type chose to keep, so it is this type's to erase.
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::assert_voice_cipher_contract;

    const KEY: [u8; BLOCK_LEN] = [0x42; BLOCK_LEN];

    /// A sender and a receiver keyed as `CryptSetup` would key them.
    ///
    /// Note the crossover: what the server sends under, the client expects. Get
    /// this backwards and every packet fails its tag.
    fn pair() -> (Ocb2, Ocb2) {
        let client_nonce = Block::from_padded(&[0xA0, 0x01]);
        let server_nonce = Block::from_padded(&[0xB0, 0x02]);
        (
            Ocb2::new(KEY, client_nonce, server_nonce),
            Ocb2::new(KEY, server_nonce, client_nonce),
        )
    }

    #[test]
    fn it_meets_the_voice_cipher_contract() {
        // The same function `VoiceSession` passes. Two ciphers behind one trait
        // are only interchangeable if one test holds both to the same rules.
        let (mut sender, mut receiver) = pair();
        assert_voice_cipher_contract(&mut sender, &mut receiver);
    }

    #[test]
    fn the_overhead_is_four_bytes() {
        // Not sixteen. The whole reason the tag is weak, and the number the UDP
        // path uses to size its buffers.
        let (mut sender, _) = pair();
        assert_eq!(sender.overhead(), 4);
        assert_eq!(sender.seal(b"payload", b"").expect("sealed").len(), 7 + 4);
    }

    #[test]
    fn a_frame_survives_the_trip() {
        let (mut sender, mut receiver) = pair();
        let frame = b"a frame of opus data";
        let packet = sender.seal(frame, b"").expect("sealed");
        assert_eq!(receiver.open(&packet, b"").expect("opened"), frame);
    }

    #[test]
    fn every_frame_length_survives() {
        // Opus frames vary; the block-multiple lengths are where an off-by-one
        // in the final-block handling hides.
        let (mut sender, mut receiver) = pair();
        for len in 0..64 {
            let frame: Vec<u8> = (0..len).map(|i| u8::try_from(i + 1).unwrap_or(1)).collect();
            let packet = sender.seal(&frame, b"").expect("sealed");
            assert_eq!(
                receiver.open(&packet, b"").expect("opened"),
                frame,
                "len {len}"
            );
        }
    }

    #[test]
    fn a_reordered_packet_still_opens() {
        // UDP reorders. Refusing a late packet the jitter buffer still wants
        // would make Starling sound worse than murmur on the same network.
        let (mut sender, mut receiver) = pair();
        let first = sender.seal(b"one", b"").expect("sealed");
        let second = sender.seal(b"two", b"").expect("sealed");

        assert_eq!(receiver.open(&second, b"").expect("opened"), b"two");
        assert_eq!(
            receiver
                .open(&first, b"")
                .expect("the late packet was refused"),
            b"one"
        );
    }

    #[test]
    fn a_gap_does_not_break_the_stream() {
        let (mut sender, mut receiver) = pair();
        let first = sender.seal(b"one", b"").expect("sealed");
        for _ in 0..20 {
            let _ = sender.seal(b"lost", b"").expect("sealed");
        }
        let later = sender.seal(b"later", b"").expect("sealed");

        assert_eq!(receiver.open(&first, b"").expect("opened"), b"one");
        assert_eq!(receiver.open(&later, b"").expect("opened"), b"later");
    }

    #[test]
    fn a_replay_is_refused() {
        let (mut sender, mut receiver) = pair();
        let packet = sender.seal(b"once", b"").expect("sealed");
        assert!(receiver.open(&packet, b"").is_ok());
        assert!(
            matches!(
                receiver.open(&packet, b""),
                Err(VoiceError::Rejected(Rejected::Replay { .. }))
            ),
            "an immediate replay must be reported as one"
        );
    }

    #[test]
    fn a_forged_tag_is_refused_and_does_not_advance_the_counter() {
        // The attack: guess a tag, and even when it fails, drag the peer's
        // counter forward so the real packets look like replays.
        let (mut sender, mut receiver) = pair();
        let good = sender.seal(b"genuine", b"").expect("sealed");

        let mut forged = good.clone();
        forged[1] ^= 0xFF;
        assert_eq!(receiver.open(&forged, b""), Err(VoiceError::NotAuthentic));

        assert_eq!(
            receiver.open(&good, b"").expect("the real packet was lost"),
            b"genuine"
        );
    }

    #[test]
    fn a_short_packet_is_refused() {
        let (_, mut receiver) = pair();
        for len in 0..OVERHEAD {
            assert_eq!(
                receiver.open(&vec![0; len], b""),
                Err(VoiceError::Truncated { len })
            );
        }
    }

    #[test]
    fn a_thousand_packets_stay_in_step_across_the_wrap() {
        // Four wraps of the wire byte. If the high bytes diverge, the tag stops
        // matching and the call goes silent — the failure that only shows up
        // after four seconds of talking.
        let (mut sender, mut receiver) = pair();
        for i in 0..1000_u32 {
            let frame = i.to_be_bytes();
            let packet = sender.seal(&frame, b"").expect("sealed");
            assert_eq!(
                receiver.open(&packet, b"").expect("opened"),
                frame,
                "packet {i}"
            );
        }
    }

    #[test]
    fn silence_is_carried_without_being_flagged() {
        // Digital silence produces the 2019 attack's block shape in bulk. If the
        // mitigation refused instead of flipping, a muted microphone would
        // disconnect the user.
        let (mut sender, mut receiver) = pair();
        for len in 0..48 {
            let packet = sender.seal(&vec![0; len], b"").expect("sealed");
            let opened = receiver.open(&packet, b"").expect("silence was refused");
            assert_eq!(opened.len(), len);
        }
        assert_eq!(receiver.suspected_forgeries(), 0);
    }

    #[test]
    fn the_key_survives_for_crypt_setup() {
        let (sender, _) = pair();
        assert_eq!(sender.key(), KEY);
    }

    #[test]
    fn resynchronising_accepts_a_stream_that_had_walked_away() {
        // What `CryptSetup` with a client nonce means: the client says where it
        // is, and the server believes it far enough to try the tag.
        let (mut sender, mut receiver) = pair();
        for _ in 0..500 {
            let _ = sender.seal(b"unheard", b"").expect("sealed");
        }
        let packet = sender.seal(b"after the gap", b"").expect("sealed");

        assert!(
            receiver.open(&packet, b"").is_err(),
            "the gap was too large"
        );

        receiver.resync_to(sender.server_nonce());
        // Resyncing to the *last sent* nonce means the next packet is in order.
        let next = sender.seal(b"resynced", b"").expect("sealed");
        assert_eq!(receiver.open(&next, b"").expect("opened"), b"resynced");
    }

    #[test]
    fn it_prints_no_key_material() {
        let (sender, _) = pair();
        let printed = format!("{sender:?}");
        assert!(!printed.contains("66"), "{printed}");
        assert!(!printed.contains("42"), "{printed}");
    }
}
