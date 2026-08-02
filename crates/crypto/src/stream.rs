//! The seam every voice cipher plugs into.
//!
//! Two implementations are expected: [`VoiceSession`](crate::VoiceSession) for
//! XChaCha20-Poly1305, and an OCB2-AES128 one for stock Mumble clients that is
//! not written yet. The trait exists ahead of the second so that porting OCB2 is
//! filling in a shape rather than deciding one.
//!
//! # The contract is executable
//!
//! `assert_voice_cipher_contract` (in this module, test-only) is the
//! specification. An implementation that
//! passes it round-trips, detects tampering, rejects replays and refuses short
//! packets — the properties that make a voice cipher a voice cipher rather than
//! an obfuscator. OCB2 has to pass exactly the same function, which is the
//! cheapest way to keep two ciphers honest about the same rules.
//!
//! Note what the contract does **not** assert: OCB2 truncates its tag to three
//! bytes and so has different overhead, and Mumble's variant needs the
//! counter-cryptanalysis mitigation from eprint 2019/311 §9 that has no analogue
//! here. Those are per-implementation tests, not shared ones.

use crate::session::VoiceError;

/// One direction of an encrypted voice stream.
///
/// `&mut self` on both halves is deliberate: a cipher that could seal through a
/// shared reference would let two callers draw the same counter, which is nonce
/// reuse. The type system says no.
pub trait VoiceCipher: std::fmt::Debug + Send {
    /// A short name for logs and the admin API.
    fn name(&self) -> &'static str;

    /// Bytes added to a frame: counter or nonce, plus the tag.
    ///
    /// Reported rather than assumed, because the two ciphers differ — 18 bytes
    /// for `XChaCha` here against OCB2's 7 — and the UDP path needs it to size
    /// buffers without knowing which cipher it holds.
    fn overhead(&self) -> usize;

    /// Encrypt one audio frame.
    ///
    /// # Errors
    ///
    /// [`VoiceError`] if the counter space is exhausted or the cipher fails.
    fn seal(&mut self, frame: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError>;

    /// Decrypt one received packet.
    ///
    /// # Errors
    ///
    /// [`VoiceError`] if the packet is short, a replay, or not authentic.
    fn open(&mut self, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError>;

    /// The nonce this half seals under, for answering a peer's resync request.
    ///
    /// `None` means *this cipher cannot be resynchronised by swapping a nonce*,
    /// and it is a real answer rather than a hole: `XChaCha20-Poly1305` folds its
    /// salt into a derived subkey and reconstructs the counter's high bits from
    /// the wire, so no value it could hand over would mean anything to the peer.
    /// A peer on such a cipher is recovered by being re-keyed instead.
    ///
    /// Deliberately not a defaulted method. A cipher added later must *decide*
    /// which of the two it is, and a default would let it inherit the wrong
    /// answer silently — which is a peer that asks to resynchronise and is told
    /// something it cannot use.
    fn send_nonce(&self) -> Option<Vec<u8>>;

    /// Adopt the nonce a peer says it is sending under, and report whether it was
    /// taken.
    ///
    /// `false` for a cipher that cannot resynchronise this way, and for a nonce
    /// of the wrong width — which is the implementation's own judgement to make,
    /// because only it knows what width it expects. A refusal is not an error:
    /// the caller's fallback is to re-key, which recovers the peer either way.
    ///
    /// Trusting the value is safe **only** because every packet still has to
    /// authenticate afterwards. The nonce is a hint about where to look, not a
    /// credential, and a wrong one costs the peer nothing but another resync.
    fn adopt_recv_nonce(&mut self, nonce: &[u8]) -> bool;
}

/// The properties every [`VoiceCipher`] must have.
///
/// Takes two freshly derived sessions for the same key and direction — a sender
/// and a receiver — because half the contract is about what the receiver refuses.
///
/// # Panics
///
/// If the implementation violates the contract, which is the point.
#[cfg(test)]
pub(crate) fn assert_voice_cipher_contract(
    sender: &mut dyn VoiceCipher,
    receiver: &mut dyn VoiceCipher,
) {
    const AAD: &[u8] = b"contract";
    let name = sender.name();

    // 1. A sealed frame opens to exactly what went in.
    let frame = b"a frame of audio";
    let packet = sender.seal(frame, AAD).expect("sealing must succeed");
    assert_eq!(
        receiver.open(&packet, AAD).expect("opening must succeed"),
        frame,
        "{name}: a sealed frame must round-trip"
    );

    // 2. Overhead is reported honestly, so the UDP path can size a buffer.
    assert_eq!(
        packet.len() - frame.len(),
        sender.overhead(),
        "{name}: reported overhead does not match what sealing produced"
    );

    // 3. Ciphertext is not the plaintext. Catches a stub that forgot to encrypt.
    assert!(
        !packet.windows(frame.len()).any(|w| w == frame),
        "{name}: the plaintext appears verbatim in the packet"
    );

    // 4. Tampering anywhere in the packet is detected.
    for byte in 0..packet.len() {
        let mut tampered = packet.clone();
        tampered[byte] ^= 0x01;
        assert!(
            receiver.open(&tampered, AAD).is_err(),
            "{name}: a flipped bit at offset {byte} was accepted"
        );
    }

    // 5. A replay of an already-opened packet is refused.
    assert!(
        receiver.open(&packet, AAD).is_err(),
        "{name}: a replayed packet was accepted"
    );

    // 6. Short input is refused rather than indexed into.
    for len in 0..sender.overhead() {
        assert!(
            receiver.open(&vec![0; len], AAD).is_err(),
            "{name}: a {len}-byte packet was accepted"
        );
    }

    // 7. Sealing twice never produces the same packet, even for identical input.
    // This is the counter doing its job; equal packets would mean a repeated
    // nonce.
    let first = sender.seal(frame, AAD).expect("sealed");
    let second = sender.seal(frame, AAD).expect("sealed");
    assert_ne!(
        first, second,
        "{name}: identical frames sealed identically, so the nonce repeated"
    );

    // 8. The two halves of the resync answer agree with each other.
    //
    // Last, because it mutates the receiver. A cipher that offers a nonce must
    // accept one of that width back, and one that offers nothing must accept
    // nothing — the mixed answers are the ones that strand a peer: offering a
    // nonce the peer cannot give back, or refusing to say what to send while
    // accepting what arrives.
    match sender.send_nonce() {
        Some(nonce) => {
            assert!(
                !nonce.is_empty(),
                "{name}: offered an empty nonce, which no peer can use"
            );
            assert!(
                receiver.adopt_recv_nonce(&nonce),
                "{name}: offers a {}-byte nonce and will not adopt one",
                nonce.len()
            );
        }
        None => assert!(
            !receiver.adopt_recv_nonce(&[0; 16]),
            "{name}: cannot say what it sends under, yet adopts what it is handed"
        ),
    }
}
