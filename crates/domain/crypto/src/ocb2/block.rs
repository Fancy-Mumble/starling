//! The 128-bit block, and the field arithmetic OCB2 does to it.
//!
//! OCB2 treats a block as an element of GF(2^128) and multiplies the running
//! offset by 2 or 3 between blocks. Both are a shift and a conditional XOR, but
//! only over the *big-endian* reading of the block, which is why this is a type
//! with two named operations rather than sixteen bytes and a loop at each use.
//!
//! murmur writes the same arithmetic as a macro over native-endian `quint64`
//! pairs wrapped in `SWAP64`, which is this with the endianness handled by hand.

use aes::cipher::{BlockDecrypt as _, BlockEncrypt as _, KeyInit as _};
use aes::Aes128;

/// AES's block size, and OCB2's.
pub const BLOCK_LEN: usize = 16;

/// The reduction polynomial for GF(2^128), low byte of x^128 + x^7 + x^2 + x + 1.
const REDUCTION: u8 = 0x87;

/// One 128-bit block.
///
/// A newtype rather than a bare `[u8; 16]` so that a checksum, an offset and a
/// tag cannot be passed to each other's parameters — they are all sixteen bytes
/// and the compiler would not object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Block(pub [u8; BLOCK_LEN]);

impl Block {
    /// The all-zero block, where every checksum starts.
    pub const ZERO: Self = Self([0; BLOCK_LEN]);

    /// A block from the first [`BLOCK_LEN`] bytes of `bytes`, zero-padded.
    ///
    /// Short input is padded rather than refused because OCB2's final block is
    /// deliberately partial: the length is folded into the tag separately, so a
    /// short block is not ambiguous.
    #[must_use]
    pub fn from_padded(bytes: &[u8]) -> Self {
        let mut block = [0; BLOCK_LEN];
        let take = bytes.len().min(BLOCK_LEN);
        block[..take].copy_from_slice(&bytes[..take]);
        Self(block)
    }

    /// This block XOR `other`.
    #[must_use]
    pub fn xor(self, other: Self) -> Self {
        let mut out = self.0;
        for (byte, source) in out.iter_mut().zip(other.0) {
            *byte ^= source;
        }
        Self(out)
    }

    /// Multiply by two in GF(2^128) — murmur's `S2`.
    ///
    /// A left shift of the whole block as a big-endian integer, then a XOR of
    /// the reduction polynomial when a one was shifted out of the top.
    #[must_use]
    pub fn times2(self) -> Self {
        let carry = self.0[0] >> 7;
        let mut out = [0; BLOCK_LEN];
        for (shifted, pair) in out.iter_mut().zip(self.0.windows(2)) {
            *shifted = (pair[0] << 1) | (pair[1] >> 7);
        }
        out[BLOCK_LEN - 1] = (self.0[BLOCK_LEN - 1] << 1) ^ (carry * REDUCTION);
        Self(out)
    }

    /// Multiply by three — murmur's `S3`, which is `x ^ times2(x)`.
    #[must_use]
    pub fn times3(self) -> Self {
        self.xor(self.times2())
    }

    /// Whether every byte but the last matches `other`'s.
    ///
    /// The exact shape of the counter-cryptanalysis check from eprint 2019/311
    /// §9: only the last byte of the length-encoding block varies, so a match on
    /// the first fifteen is the signature of the attack.
    #[must_use]
    pub fn matches_but_last(self, other: Self) -> bool {
        self.0[..BLOCK_LEN - 1] == other.0[..BLOCK_LEN - 1]
    }

    /// Whether every byte but the last is zero.
    ///
    /// The other half of the same check, applied to plaintext during encryption.
    #[must_use]
    pub fn is_zero_but_last(self) -> bool {
        self.0[..BLOCK_LEN - 1].iter().all(|byte| *byte == 0)
    }

    /// Flip the lowest bit of the first byte.
    ///
    /// The mitigation itself. Upstream applies it to the offset-masked block and
    /// to the checksum together, which is exactly equivalent to flipping the bit
    /// in the plaintext — and it does change the audio, by one bit in one sample
    /// of what was digital silence.
    #[must_use]
    pub fn flip_low_bit(self) -> Self {
        let mut out = self.0;
        out[0] ^= 1;
        Self(out)
    }

    /// A block encoding `len` bytes as a bit count, for the final-block pad.
    ///
    /// The length lives in the last eight bytes big-endian. A partial block is
    /// at most sixteen bytes, so in practice only the final byte is nonzero —
    /// which is what makes [`Self::matches_but_last`] the right check.
    #[must_use]
    pub fn length_encoding(len: usize) -> Self {
        let mut block = [0; BLOCK_LEN];
        let bits = u64::try_from(len).unwrap_or(0).wrapping_mul(8);
        block[BLOCK_LEN - 8..].copy_from_slice(&bits.to_be_bytes());
        Self(block)
    }

    /// The first `len` bytes.
    #[must_use]
    pub fn prefix(&self, len: usize) -> &[u8] {
        &self.0[..len.min(BLOCK_LEN)]
    }
}

/// AES-128 in the raw single-block mode OCB2 needs.
///
/// Not a mode of operation — OCB2 *is* the mode, and it calls the bare block
/// cipher. Wrapping it in a type keeps `aes`'s trait imports out of the OCB2
/// logic, which is otherwise the only thing in that file that is not arithmetic.
#[derive(Clone)]
pub(super) struct BlockCipher(Aes128);

impl BlockCipher {
    /// A cipher under `key`.
    #[must_use]
    pub(super) fn new(key: &[u8; BLOCK_LEN]) -> Self {
        Self(Aes128::new(key.into()))
    }

    /// Encrypt one block.
    #[must_use]
    pub(super) fn encrypt(&self, block: Block) -> Block {
        let mut buffer = block.0.into();
        self.0.encrypt_block(&mut buffer);
        Block(buffer.into())
    }

    /// Decrypt one block.
    #[must_use]
    pub(super) fn decrypt(&self, block: Block) -> Block {
        let mut buffer = block.0.into();
        self.0.decrypt_block(&mut buffer);
        Block(buffer.into())
    }
}

impl std::fmt::Debug for BlockCipher {
    /// Prints no key material.
    ///
    /// `aes`'s own `Debug` is already opaque, but relying on that would make
    /// this type's safety depend on a dependency's formatting choice.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlockCipher(aes128)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubling_shifts_left() {
        let block = Block::from_padded(&[0x01]);
        assert_eq!(block.times2().0[0], 0x02);
    }

    #[test]
    fn doubling_carries_between_bytes() {
        // The bit leaving byte 1 must arrive in byte 0, or the offsets diverge
        // from murmur's after the first block and nothing decrypts.
        let mut bytes = [0; BLOCK_LEN];
        bytes[1] = 0x80;
        assert_eq!(Block(bytes).times2().0[0], 0x01);
    }

    #[test]
    fn doubling_reduces_when_the_top_bit_is_set() {
        // The defining property: shifting a one out of the top must fold the
        // reduction polynomial back in.
        let mut bytes = [0; BLOCK_LEN];
        bytes[0] = 0x80;
        assert_eq!(Block(bytes).times2().0[BLOCK_LEN - 1], REDUCTION);
        assert_eq!(Block(bytes).times2().0[0], 0);
    }

    #[test]
    fn doubling_without_a_carry_leaves_the_low_byte_alone() {
        let block = Block::from_padded(&[0x40]);
        assert_eq!(block.times2().0[BLOCK_LEN - 1], 0);
    }

    #[test]
    fn tripling_is_doubling_xor_the_original() {
        for seed in [0x01_u8, 0x80, 0xFF] {
            let block = Block([seed; BLOCK_LEN]);
            assert_eq!(block.times3(), block.xor(block.times2()));
        }
    }

    #[test]
    fn xor_is_its_own_inverse() {
        let a = Block([0xA5; BLOCK_LEN]);
        let b = Block([0x3C; BLOCK_LEN]);
        assert_eq!(a.xor(b).xor(b), a);
    }

    #[test]
    fn the_length_encoding_is_bits_not_bytes() {
        // Encoding bytes instead would be a silent interop break: every packet
        // would authenticate against itself and none against a real client.
        assert_eq!(Block::length_encoding(1).0[BLOCK_LEN - 1], 8);
        assert_eq!(Block::length_encoding(16).0[BLOCK_LEN - 1], 128);
        assert_eq!(Block::length_encoding(0), Block::ZERO);
    }

    #[test]
    fn the_length_encoding_touches_only_the_last_byte() {
        // Which is what makes `matches_but_last` the correct attack check.
        for len in 0..=BLOCK_LEN {
            assert!(Block::length_encoding(len).is_zero_but_last(), "len {len}");
        }
    }

    #[test]
    fn a_short_slice_is_padded_not_truncated() {
        let block = Block::from_padded(&[1, 2, 3]);
        assert_eq!(block.0[..3], [1, 2, 3]);
        assert!(block.0[3..].iter().all(|b| *b == 0));
    }

    #[test]
    fn an_oversized_slice_is_truncated_not_a_panic() {
        assert_eq!(Block::from_padded(&[7; 64]).0, [7; BLOCK_LEN]);
    }

    #[test]
    fn flipping_the_low_bit_is_its_own_inverse() {
        let block = Block([0x5A; BLOCK_LEN]);
        assert_eq!(block.flip_low_bit().flip_low_bit(), block);
        assert_ne!(block.flip_low_bit(), block);
    }

    #[test]
    fn matching_but_the_last_byte_ignores_only_the_last() {
        let a = Block([0; BLOCK_LEN]);
        let mut b = [0; BLOCK_LEN];
        b[BLOCK_LEN - 1] = 0xFF;
        assert!(a.matches_but_last(Block(b)));
        b[0] = 1;
        assert!(!a.matches_but_last(Block(b)));
    }

    #[test]
    fn aes_matches_the_fips_197_test_vector() {
        // The published AES-128 vector. If this fails the port is wrong at the
        // primitive, and every OCB2 test above it would be testing nothing.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plain = Block([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let cipher = BlockCipher::new(&key);
        assert_eq!(cipher.encrypt(plain).0, expected);
        assert_eq!(cipher.decrypt(Block(expected)), plain);
    }

    #[test]
    fn the_cipher_prints_no_key_material() {
        let cipher = BlockCipher::new(&[0xAB; BLOCK_LEN]);
        assert!(!format!("{cipher:?}").contains("171"));
        assert!(!format!("{cipher:?}").contains("ab"));
    }
}
