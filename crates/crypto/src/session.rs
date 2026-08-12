//! Encrypting one peer's voice stream.
//!
//! Implements the construction specified in [`crate::voice`]: a per-session
//! subkey derived once, then plain ChaCha20-Poly1305 per packet with the counter
//! as nonce.
//!
//! # Equivalent to XChaCha20-Poly1305, on purpose
//!
//! XChaCha20-Poly1305 is defined as `HChaCha20` to derive a subkey from the first
//! 16 nonce bytes, then ChaCha20-Poly1305 on the remaining 8. This does exactly
//! that, with the first 16 bytes fixed per session, so a peer holding the same
//! key can encrypt with an off-the-shelf `XChaCha20Poly1305` and a 24-byte nonce
//! of `salt ‖ counter` and interoperate byte for byte. The client already has
//! that implementation, and
//! `sealing_matches_offtheshelf_xchacha` in this module's tests proves the two
//! agree rather than asserting it.
//!
//! Splitting it this way is what moves `HChaCha20` off the per-packet path
//! without inventing a construction that needs its own analysis.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::voice::{
    CounterExhausted, Direction, PacketCounter, Rejected, Sequence, SequenceWindow,
    WIRE_COUNTER_BYTES,
};

/// Length of the master secret exchanged in `CryptSetup`.
pub const MASTER_KEY_LEN: usize = 32;

/// Length of the per-session salt exchanged in `CryptSetup`.
///
/// Sixteen because that is what `HChaCha20` consumes; it is the first half of
/// what would otherwise be a 24-byte `XChaCha` nonce.
pub const SALT_LEN: usize = 16;

/// The Poly1305 tag, untruncated.
pub const TAG_LEN: usize = 16;

/// Smallest packet that could be valid: counter plus tag, with no payload.
pub const MIN_PACKET_LEN: usize = WIRE_COUNTER_BYTES + TAG_LEN;

/// Why a voice packet could not be sealed or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VoiceError {
    /// The counter space is used up; the session must be rekeyed.
    #[error(transparent)]
    Exhausted(#[from] CounterExhausted),

    /// The packet was a replay or too old to verify.
    #[error(transparent)]
    Rejected(#[from] Rejected),

    /// Too short to contain a counter and a tag.
    #[error("voice packet is {len} bytes; at least {MIN_PACKET_LEN} are needed")]
    Truncated {
        /// What arrived.
        len: usize,
    },

    /// Authentication failed: wrong key, wrong direction, or tampering.
    ///
    /// Deliberately one variant. Distinguishing the causes would tell an attacker
    /// which of their guesses was closer.
    #[error("voice packet failed authentication")]
    NotAuthentic,
}

/// One direction of one peer's encrypted voice stream.
///
/// Holds the derived subkey, the send counter and the receive window together,
/// because they are one thing: using a counter with the wrong key, or a window
/// against the wrong stream, is how nonce reuse gets reintroduced after the
/// arithmetic is already correct.
pub struct VoiceSession {
    cipher: ChaCha20Poly1305,
    counter: PacketCounter,
    window: SequenceWindow,
    direction: Direction,
    /// Receive-side counters, murmur's `uiGood`/`uiLate`/`uiLost`.
    stats: crate::stream::CryptStats,
}

impl std::fmt::Debug for VoiceSession {
    /// Hand-written so key material cannot reach a log through a derive.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceSession")
            .field("direction", &self.direction)
            .field("highest_received", &self.window.highest())
            .finish_non_exhaustive()
    }
}

impl VoiceSession {
    /// Derive a session from the master secret and salt exchanged in
    /// `CryptSetup`.
    ///
    /// Two derivations, both once per session:
    ///
    /// 1. HKDF-SHA256 separates the two directions, so client-to-server and
    ///    server-to-client never share a keystream;
    /// 2. `HChaCha20` folds in the salt, producing the subkey every packet uses.
    #[must_use]
    pub fn derive(
        master: &[u8; MASTER_KEY_LEN],
        salt: &[u8; SALT_LEN],
        direction: Direction,
    ) -> Self {
        let mut directional = [0_u8; MASTER_KEY_LEN];
        let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
        // Infallible for a 32-byte output; HKDF only fails past 255 hash lengths.
        hkdf.expand(direction.label(), &mut directional)
            .unwrap_or_else(|_| unreachable!("32 bytes is within HKDF's output limit"));

        // `R20` and not `R12`/`R8`: it is the 20-round ChaCha the AEAD below
        // uses, and it is the same round count the previous `U10` asked for,
        // that spelled ten *double* rounds, which `Rounds::COUNT` still records
        // as 10 for `R20`. Naming the variant after the rounds rather than the
        // doublings is the whole of the change; picking a neighbour here would
        // weaken the cipher without failing anything.
        // `(&...).into()` rather than the deprecated `Key::from_slice`: both
        // arrays are fixed at 32 bytes by their types, so the conversion
        // cannot fail and needs no unwrap to say so.
        let subkey = chacha20::hchacha::<chacha20::R20>((&directional).into(), salt.into());
        directional.zeroize();

        let cipher = ChaCha20Poly1305::new(&subkey);

        Self {
            cipher,
            counter: PacketCounter::new(),
            window: SequenceWindow::new(),
            direction,
            stats: crate::stream::CryptStats::default(),
        }
    }

    /// The receive-side counters accumulated so far.
    #[must_use]
    pub const fn stats(&self) -> crate::stream::CryptStats {
        self.stats
    }

    /// Which way this session encrypts.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Encrypt one audio frame.
    ///
    /// Returns `counter ‖ ciphertext ‖ tag`, with only the low two counter bytes
    /// on the wire.
    ///
    /// # Errors
    ///
    /// [`VoiceError::Exhausted`] once the counter space is used up. There is no
    /// correct way to continue; the session must be rekeyed.
    pub fn seal(&mut self, frame: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        let sequence = self.counter.issue()?;
        let ciphertext = self
            .cipher
            .encrypt(&Self::nonce(sequence), Payload { msg: frame, aad })
            .map_err(|_| VoiceError::NotAuthentic)?;

        let mut packet = Vec::with_capacity(WIRE_COUNTER_BYTES + ciphertext.len());
        packet.extend_from_slice(&sequence.truncated().to_be_bytes());
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    /// Decrypt one received packet.
    ///
    /// # Errors
    ///
    /// [`VoiceError::Truncated`] if it is too short, [`VoiceError::Rejected`] if
    /// it is a replay or too old, [`VoiceError::NotAuthentic`] if the tag does
    /// not verify.
    ///
    /// The replay window is advanced **before** the tag is checked, and rolled
    /// back if authentication fails, see the note in the body for why.
    pub fn open(&mut self, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        if packet.len() < MIN_PACKET_LEN {
            return Err(VoiceError::Truncated { len: packet.len() });
        }
        // The length check above is the real bound, a packet also needs a tag,
        // not just a counter, but reading the counter through
        // `split_first_chunk` keeps that read correct on its own terms rather
        // than resting on a check five lines away.
        let Some((header, body)) = packet.split_first_chunk::<WIRE_COUNTER_BYTES>() else {
            return Err(VoiceError::Truncated { len: packet.len() });
        };
        let truncated = u16::from_be_bytes(*header);

        // Reconstruct without recording: an unauthenticated packet must not be
        // able to move the window, or an attacker could jump it forward with a
        // forged counter and make every real packet look too old.
        let candidate = self.window.clone().accept(truncated)?;

        let frame = self
            .cipher
            .decrypt(&Self::nonce(candidate), Payload { msg: body, aad })
            .map_err(|_| VoiceError::NotAuthentic)?;

        // Authentic: now it may advance the real window. This second call cannot
        // fail, because the clone above already accepted the same value.
        let first = !self.window.started();
        let previous = self.window.highest();
        let _ = self.window.accept(truncated)?;

        // The window has no per-packet arrival report the way OCB2's IV does,
        // but the same facts are derivable from where the counter sat: above
        // the previous highest with a gap means the gap was lost, below it
        // means this packet arrived late. The first packet of the stream is
        // neither, whatever counter it starts at.
        let sequence = candidate.value();
        if first {
            self.stats.record(false, 0);
        } else if sequence > previous {
            let lost = u32::try_from(sequence - previous - 1).unwrap_or(u32::MAX);
            self.stats.record(false, lost);
        } else {
            self.stats.record(true, 0);
        }
        Ok(frame)
    }

    /// The 12-byte ChaCha20-Poly1305 nonce for a counter.
    ///
    /// Four zero bytes then the counter, which is exactly what `XChaCha20` feeds
    /// its inner `ChaCha20` after `HChaCha20` has consumed the first 16.
    fn nonce(sequence: Sequence) -> Nonce {
        let mut bytes = [0_u8; 12];
        bytes[4..].copy_from_slice(&sequence.nonce_tail());
        Nonce::from(bytes)
    }
}

impl crate::stream::VoiceCipher for VoiceSession {
    fn name(&self) -> &'static str {
        "XChaCha20-Poly1305"
    }

    fn overhead(&self) -> usize {
        WIRE_COUNTER_BYTES + TAG_LEN
    }

    fn seal(&mut self, frame: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        Self::seal(self, frame, aad)
    }

    fn open(&mut self, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        Self::open(self, packet, aad)
    }

    /// Nothing: this is one direction of the cipher
    /// [`XChaCha20Voice`](crate::XChaCha20Voice) pairs, and it resynchronises the
    /// same way that type does, by being re-keyed. The salt is already inside
    /// the derived subkey and the counter's high bits are reconstructed from the
    /// wire, so there is no nonce to exchange.
    fn send_nonce(&self) -> Option<Vec<u8>> {
        None
    }

    /// Refused, for the same reason.
    fn adopt_recv_nonce(&mut self, _nonce: &[u8]) -> bool {
        false
    }

    fn stats(&self) -> crate::stream::CryptStats {
        Self::stats(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; MASTER_KEY_LEN] = [0x42; MASTER_KEY_LEN];
    const SALT: [u8; SALT_LEN] = [0x17; SALT_LEN];
    const AAD: &[u8] = b"session=7";

    /// The two ends of one direction: what the server sends, the client opens.
    fn pair(direction: Direction) -> (VoiceSession, VoiceSession) {
        (
            VoiceSession::derive(&MASTER, &SALT, direction),
            VoiceSession::derive(&MASTER, &SALT, direction),
        )
    }

    #[test]
    fn it_satisfies_the_voice_cipher_contract() {
        // The same function OCB2 will have to pass.
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        crate::stream::assert_voice_cipher_contract(&mut sender, &mut receiver);
    }

    #[test]
    fn a_frame_round_trips() {
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        let frame = b"opus frame bytes";
        let packet = sender.seal(frame, AAD).expect("sealed");
        assert_eq!(receiver.open(&packet, AAD).expect("opened"), frame);
    }

    #[test]
    fn the_wire_overhead_is_exactly_eighteen_bytes() {
        let (mut sender, _) = pair(Direction::Outbound);
        let frame = vec![0_u8; 80];
        let packet = sender.seal(&frame, AAD).expect("sealed");
        assert_eq!(
            packet.len() - frame.len(),
            18,
            "2 counter bytes plus a full 16-byte tag"
        );
    }

    #[test]
    fn many_frames_round_trip_in_order() {
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        for n in 0..5_000_u32 {
            let frame = n.to_be_bytes();
            let packet = sender.seal(&frame, AAD).expect("sealed");
            assert_eq!(receiver.open(&packet, AAD).expect("opened"), frame);
        }
    }

    #[test]
    fn a_tampered_payload_fails_authentication() {
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        let mut packet = sender.seal(b"hello", AAD).expect("sealed");
        let last = packet.len() - 1;
        packet[last] ^= 0x01;
        assert_eq!(receiver.open(&packet, AAD), Err(VoiceError::NotAuthentic));
    }

    #[test]
    fn a_tampered_counter_fails_authentication() {
        // The counter is the nonce, so changing it changes the keystream.
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        let mut packet = sender.seal(b"hello", AAD).expect("sealed");
        packet[1] ^= 0x01;
        assert_eq!(receiver.open(&packet, AAD), Err(VoiceError::NotAuthentic));
    }

    #[test]
    fn different_aad_fails_authentication() {
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        let packet = sender.seal(b"hello", AAD).expect("sealed");
        assert_eq!(
            receiver.open(&packet, b"session=8"),
            Err(VoiceError::NotAuthentic)
        );
    }

    #[test]
    fn the_other_direction_cannot_open_it() {
        // HKDF separates the directions, so a reflected packet is not authentic.
        let mut sender = VoiceSession::derive(&MASTER, &SALT, Direction::Outbound);
        let mut wrong = VoiceSession::derive(&MASTER, &SALT, Direction::Inbound);
        let packet = sender.seal(b"hello", AAD).expect("sealed");
        assert_eq!(wrong.open(&packet, AAD), Err(VoiceError::NotAuthentic));
    }

    #[test]
    fn a_different_salt_cannot_open_it() {
        let mut sender = VoiceSession::derive(&MASTER, &SALT, Direction::Outbound);
        let mut wrong = VoiceSession::derive(&MASTER, &[0x18; SALT_LEN], Direction::Outbound);
        let packet = sender.seal(b"hello", AAD).expect("sealed");
        assert_eq!(wrong.open(&packet, AAD), Err(VoiceError::NotAuthentic));
    }

    #[test]
    fn a_replayed_packet_is_rejected() {
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        let packet = sender.seal(b"hello", AAD).expect("sealed");
        assert!(receiver.open(&packet, AAD).is_ok());
        assert!(matches!(
            receiver.open(&packet, AAD),
            Err(VoiceError::Rejected(Rejected::Replay { .. }))
        ));
    }

    #[test]
    fn a_forged_packet_does_not_move_the_replay_window() {
        // The reason `open` checks the tag before advancing. Without it, one
        // forged packet with a high counter would silence the stream: every real
        // packet after it would look too old.
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        let real = sender.seal(b"first", AAD).expect("sealed");
        assert!(receiver.open(&real, AAD).is_ok());

        let mut forged = sender.seal(b"unused", AAD).expect("sealed");
        forged[0] = 0xFF; // claim a counter far in the future
        forged[1] = 0xFF;
        assert!(receiver.open(&forged, AAD).is_err());

        // The next genuine packet still opens.
        let next = sender.seal(b"second", AAD).expect("sealed");
        assert_eq!(receiver.open(&next, AAD).expect("opened"), b"second");
    }

    #[test]
    fn out_of_order_delivery_still_opens() {
        // UDP reorders; both must open, each exactly once.
        let (mut sender, mut receiver) = pair(Direction::Outbound);
        let first = sender.seal(b"first", AAD).expect("sealed");
        let second = sender.seal(b"second", AAD).expect("sealed");

        assert_eq!(receiver.open(&second, AAD).expect("opened"), b"second");
        assert_eq!(receiver.open(&first, AAD).expect("opened"), b"first");
        assert!(receiver.open(&first, AAD).is_err(), "only once");
    }

    #[test]
    fn a_short_packet_is_reported_rather_than_panicking() {
        let (_, mut receiver) = pair(Direction::Outbound);
        for len in 0..MIN_PACKET_LEN {
            assert_eq!(
                receiver.open(&vec![0; len], AAD),
                Err(VoiceError::Truncated { len }),
                "a {len}-byte packet must be refused, not indexed into"
            );
        }
    }

    #[test]
    fn sealing_matches_offtheshelf_xchacha() {
        // The interoperability claim, proven rather than asserted: the client can
        // use a stock `XChaCha20Poly1305` with a 24-byte nonce of `salt ‖ counter`
        // and read exactly what this produces.
        use chacha20poly1305::XChaCha20Poly1305;

        let mut session = VoiceSession::derive(&MASTER, &SALT, Direction::Outbound);
        let frame = b"opus frame bytes";
        let packet = session.seal(frame, AAD).expect("sealed");

        // Rebuild the directional key the same way `derive` does.
        let mut directional = [0_u8; MASTER_KEY_LEN];
        Hkdf::<Sha256>::new(Some(&SALT), &MASTER)
            .expand(Direction::Outbound.label(), &mut directional)
            .expect("32 bytes");

        // Counter 0 was the first sealed, so the full XChaCha nonce is salt ‖ 0.
        let mut nonce = [0_u8; 24];
        nonce[..SALT_LEN].copy_from_slice(&SALT);

        let opened = XChaCha20Poly1305::new((&directional).into())
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &packet[WIRE_COUNTER_BYTES..],
                    aad: AAD,
                },
            )
            .expect("stock XChaCha must open what we sealed");
        assert_eq!(opened, frame);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let session = VoiceSession::derive(&MASTER, &SALT, Direction::Outbound);
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("42"), "master bytes reached Debug");
        assert!(!rendered.contains("17"), "salt bytes reached Debug");
        assert!(rendered.contains("Outbound"));
    }
}
