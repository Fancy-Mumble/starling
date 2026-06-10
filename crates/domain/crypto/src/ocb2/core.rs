//! OCB2 itself: offset codebook mode over AES-128.
//!
//! A direct port of murmur's `ocb_encrypt` / `ocb_decrypt`, including the
//! counter-cryptanalysis mitigation. Byte-for-byte compatibility is the whole
//! requirement — a stock Mumble client will not negotiate anything else, so
//! "nearly OCB2" is the same as no voice at all.
//!
//! # The 2019 attack, and why the mitigation changes the audio
//!
//! Inoue and Minematsu showed (eprint 2019/311 §9) that OCB2 is forgeable when
//! an attacker can get a specific block encrypted: one that is all zeros except
//! its final byte. Mumble's fix is to detect that block and flip one bit of it
//! before encrypting.
//!
//! That is a real change to the plaintext — the receiver decrypts to something
//! one bit different from what was sent. Upstream accepts it because the block
//! only arises from digital silence, where a single flipped bit in one sample is
//! inaudible. The alternative upstream tried first, refusing to send the packet,
//! turned out to fire constantly: silence produces these blocks in bulk.
//!
//! The decrypting side detects the same shape and refuses, which is what makes
//! the pair a mitigation rather than an obfuscation.

use super::block::{Block, BlockCipher, BLOCK_LEN};

/// The three-byte authentication tag, truncated from a full block.
///
/// Mumble sends three bytes, not sixteen. That is 24 bits of authentication —
/// weak by any modern standard, and one of the reasons `XChaCha20-Poly1305`
/// exists as the upgrade path. It is not negotiable for a stock client.
pub const TAG_LEN: usize = 3;

/// Encrypt `plain` under `nonce`, returning the ciphertext and its tag.
///
/// Ciphertext is exactly as long as plaintext; OCB2 is length-preserving, and
/// the tag is returned separately for the caller to truncate and frame.
#[must_use]
pub(super) fn encrypt(cipher: &BlockCipher, nonce: Block, plain: &[u8]) -> (Vec<u8>, Block) {
    let mut offset = cipher.encrypt(nonce);
    let mut checksum = Block::ZERO;
    let mut out = Vec::with_capacity(plain.len());

    // Strictly greater: the loop stops with one block still in hand, because
    // the final block always goes through the partial path even when it is
    // full. That path is what folds the length into the tag.
    let mut at = 0;
    while plain.len() - at > BLOCK_LEN {
        let mut block = Block::from_padded(&plain[at..at + BLOCK_LEN]);

        // The mitigation, and only where the attack can reach: the block that
        // will be second-to-last, meaning one block or less follows it.
        if plain.len() - at - BLOCK_LEN <= BLOCK_LEN && block.is_zero_but_last() {
            block = block.flip_low_bit();
        }

        offset = offset.times2();
        let masked = cipher.encrypt(block.xor(offset));
        out.extend_from_slice(&offset.xor(masked).0);
        checksum = checksum.xor(block);
        at += BLOCK_LEN;
    }

    // Whatever the loop left: the trailing partial block, or the final full one.
    let tail = &plain[at..];
    offset = offset.times2();
    let pad = cipher.encrypt(Block::length_encoding(tail.len()).xor(offset));

    // The checksum absorbs the tail padded with the *pad's* own tail, not with
    // zeros. Getting this wrong produces a tag that only ever matches itself.
    let mut padded = pad;
    padded.0[..tail.len()].copy_from_slice(tail);
    checksum = checksum.xor(padded);
    out.extend_from_slice(pad.xor(padded).prefix(tail.len()));

    (out, cipher.encrypt(offset.times3().xor(checksum)))
}

/// Decrypt `encrypted` under `nonce`.
///
/// Returns the plaintext, the tag it authenticates under, and whether the
/// counter-cryptanalysis check passed. The caller compares the tag; separating
/// the two lets the caller decide the comparison is constant-time, which is not
/// a decision this function should make for it.
#[must_use]
pub(super) fn decrypt(cipher: &BlockCipher, nonce: Block, encrypted: &[u8]) -> Decrypted {
    let mut offset = cipher.encrypt(nonce);
    let mut checksum = Block::ZERO;
    let mut out = Vec::with_capacity(encrypted.len());

    // Mirrors the encrypting loop's bound, or the two would disagree about
    // which block is the final one and nothing would authenticate.
    let mut at = 0;
    while encrypted.len() - at > BLOCK_LEN {
        offset = offset.times2();
        let unmasked =
            cipher.decrypt(Block::from_padded(&encrypted[at..at + BLOCK_LEN]).xor(offset));
        let plain = offset.xor(unmasked);
        out.extend_from_slice(&plain.0);
        checksum = checksum.xor(plain);
        at += BLOCK_LEN;
    }

    let tail = &encrypted[at..];
    offset = offset.times2();
    let pad = cipher.encrypt(Block::length_encoding(tail.len()).xor(offset));

    let recovered = Block::from_padded(tail).xor(pad);
    checksum = checksum.xor(recovered);
    out.extend_from_slice(recovered.prefix(tail.len()));

    Decrypted {
        // The attack signature: the recovered final block equals the offset in
        // every byte but the last. Checked on `recovered` rather than on the
        // emitted plaintext because a short tail would have hidden the evidence.
        forgery_suspected: recovered.matches_but_last(offset),
        tag: cipher.encrypt(offset.times3().xor(checksum)),
        plain: out,
    }
}

/// What [`decrypt`] recovered, before anyone has decided to believe it.
///
/// The plaintext is handed back alongside the check rather than behind it so the
/// caller does exactly one thing with a failure: drop all of it. A `Result`
/// would tempt a caller into using the plaintext from the error path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Decrypted {
    /// The recovered bytes. **Unauthenticated** until `tag` has been compared.
    pub plain: Vec<u8>,

    /// The tag the recovered plaintext produces.
    pub tag: Block,

    /// Whether this packet has the shape of an eprint 2019/311 §9 forgery.
    pub forgery_suspected: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; BLOCK_LEN] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    fn cipher() -> BlockCipher {
        BlockCipher::new(&KEY)
    }

    fn nonce() -> Block {
        Block::from_padded(&[0x01, 0x02, 0x03])
    }

    #[test]
    fn every_length_round_trips() {
        // Zero through four blocks, which covers empty, partial, exactly one
        // block, and the block-multiple case that has no trailing bytes. The
        // block-multiple case is the one an off-by-one in the loop breaks.
        let cipher = cipher();
        for len in 0..=(BLOCK_LEN * 4) {
            let plain: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect();
            let (encrypted, tag) = encrypt(&cipher, nonce(), &plain);

            assert_eq!(
                encrypted.len(),
                plain.len(),
                "len {len}: OCB2 must preserve length"
            );

            let recovered = decrypt(&cipher, nonce(), &encrypted);
            assert_eq!(recovered.plain, plain, "len {len}: plaintext changed");
            assert_eq!(recovered.tag, tag, "len {len}: tag does not match");
        }
    }

    #[test]
    fn a_flipped_ciphertext_bit_changes_the_tag() {
        let cipher = cipher();
        let plain = vec![0x11; 40];
        let (encrypted, _) = encrypt(&cipher, nonce(), &plain);
        let honest = decrypt(&cipher, nonce(), &encrypted).tag;

        for byte in 0..encrypted.len() {
            let mut tampered = encrypted.clone();
            tampered[byte] ^= 0x80;
            assert_ne!(
                decrypt(&cipher, nonce(), &tampered).tag,
                honest,
                "a flipped bit at offset {byte} produced the same tag"
            );
        }
    }

    #[test]
    fn a_different_nonce_gives_a_different_tag() {
        // The nonce is what makes two identical frames encrypt differently. If
        // it did not reach the tag, replay detection would be the only defence.
        let cipher = cipher();
        let plain = vec![0x22; 30];
        let (_, first) = encrypt(&cipher, nonce(), &plain);
        let (_, second) = encrypt(&cipher, Block::from_padded(&[0x09]), &plain);
        assert_ne!(first, second);
    }

    #[test]
    fn a_different_nonce_gives_different_ciphertext() {
        let cipher = cipher();
        let plain = vec![0x22; 30];
        let (first, _) = encrypt(&cipher, nonce(), &plain);
        let (second, _) = encrypt(&cipher, Block::from_padded(&[0x09]), &plain);
        assert_ne!(first, second);
    }

    #[test]
    fn the_plaintext_does_not_appear_in_the_ciphertext() {
        let cipher = cipher();
        let plain = b"the quick brown fox jumps over the lazy dog".to_vec();
        let (encrypted, _) = encrypt(&cipher, nonce(), &plain);
        assert!(!encrypted
            .windows(8)
            .any(|w| plain.windows(8).any(|p| w == p)));
    }

    #[test]
    fn a_length_changing_truncation_changes_the_tag() {
        // The length is folded into the final pad, so a truncated packet must
        // not authenticate. Without that, an attacker could cut a frame short.
        let cipher = cipher();
        let (encrypted, tag) = encrypt(&cipher, nonce(), &[0x33; 48]);
        assert_ne!(decrypt(&cipher, nonce(), &encrypted[..47]).tag, tag);
        assert_ne!(decrypt(&cipher, nonce(), &encrypted[..32]).tag, tag);
    }

    #[test]
    fn the_attack_block_is_mitigated_on_the_way_out() {
        // Digital silence: a second-to-last block that is all zeros but its last
        // byte. The bit flip means the receiver gets something one bit
        // different, which is the trade upstream deliberately makes.
        let cipher = cipher();
        let mut plain = vec![0; BLOCK_LEN * 2];
        plain[BLOCK_LEN - 1] = 0x40;

        let (encrypted, tag) = encrypt(&cipher, nonce(), &plain);
        let recovered = decrypt(&cipher, nonce(), &encrypted);

        assert_eq!(recovered.tag, tag, "the mitigated packet must authenticate");
        assert_eq!(
            recovered.plain[0], 1,
            "the mitigation bit is not visible in the recovered plaintext"
        );
        assert_eq!(
            recovered.plain[1..],
            plain[1..],
            "the mitigation changed more than one bit"
        );
    }

    #[test]
    fn an_ordinary_packet_is_not_mitigated() {
        // The flip must be rare: applying it to real audio would be audible.
        let cipher = cipher();
        let plain: Vec<u8> = (0..64).map(|i| u8::try_from(i + 1).unwrap_or(1)).collect();
        let (encrypted, _) = encrypt(&cipher, nonce(), &plain);
        assert_eq!(decrypt(&cipher, nonce(), &encrypted).plain, plain);
    }

    #[test]
    fn an_ordinary_packet_raises_no_forgery_suspicion() {
        // A false positive here would drop legitimate audio.
        let cipher = cipher();
        for len in 0..=64 {
            let plain: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 97 + 1).unwrap_or(1))
                .collect();
            let (encrypted, _) = encrypt(&cipher, nonce(), &plain);
            assert!(
                !decrypt(&cipher, nonce(), &encrypted).forgery_suspected,
                "len {len}: honest packet flagged as a forgery"
            );
        }
    }

    #[test]
    fn silence_raises_no_forgery_suspicion_either() {
        // The case that made upstream switch from refusing to flipping: silent
        // audio must still go through.
        let cipher = cipher();
        for len in 0..=64 {
            let (encrypted, _) = encrypt(&cipher, nonce(), &vec![0; len]);
            assert!(
                !decrypt(&cipher, nonce(), &encrypted).forgery_suspected,
                "len {len}: silence flagged as a forgery"
            );
        }
    }

    #[test]
    fn a_crafted_final_block_is_flagged() {
        // Construct the attack shape directly: a ciphertext whose final block
        // decrypts to the offset. The tag check would very likely catch it too,
        // but the paper's point is that it can be made not to.
        let cipher = cipher();
        let offset = cipher.encrypt(nonce()).times2();
        let pad = cipher.encrypt(Block::length_encoding(BLOCK_LEN).xor(offset));
        let crafted = offset.xor(pad);

        assert!(decrypt(&cipher, nonce(), &crafted.0).forgery_suspected);
    }

    #[test]
    fn an_empty_message_still_authenticates() {
        let cipher = cipher();
        let (encrypted, tag) = encrypt(&cipher, nonce(), &[]);
        assert!(encrypted.is_empty());
        assert_eq!(decrypt(&cipher, nonce(), &[]).tag, tag);
    }
}
