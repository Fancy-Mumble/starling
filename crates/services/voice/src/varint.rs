//! Mumble's variable-length integers.
//!
//! Not protobuf's LEB128. Mumble's own encoding, from `PacketDataStream.h`, is
//! big-endian and prefix-coded: the leading bits of the first byte say how many
//! bytes follow, so a decoder knows the length before reading the payload.
//!
//! | Leading bits | Total bytes | Value bits |
//! |---|---|---|
//! | `0xxxxxxx` | 1 | 7 |
//! | `10xxxxxx` | 2 | 14 |
//! | `110xxxxx` | 3 | 21 |
//! | `1110xxxx` | 4 | 28 |
//! | `111100__` | 5 | 32 |
//! | `111101__` | 9 | 64 |
//! | `111110__` | 1 + inner | negative recursion |
//! | `111111xx` | 1 | small negative, `~x` |
//!
//! Only the legacy audio format uses this; everything from Mumble 1.5 on is
//! protobuf. It lives here rather than in `starling-proto` because that crate is
//! the protobuf codegen, and this is emphatically not protobuf.
//!
//! # The negative forms are decoded, not just tolerated
//!
//! Every field Mumble encodes this way is logically unsigned, so a negative
//! varint is either a bug or an attack. Decoding them anyway costs four lines
//! and means a hostile peer cannot desynchronise the reader: skipping a byte it
//! did not understand would make every subsequent field in the packet garbage.

/// A varint could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VarintError {
    /// The buffer ended inside the integer.
    #[error("varint needs {needed} bytes but only {available} remain")]
    Truncated {
        /// Bytes the encoding requires.
        needed: usize,
        /// Bytes actually left.
        available: usize,
    },
}

/// Reads Mumble varints and raw fields from a packet, tracking position.
///
/// A cursor rather than free functions returning `(value, consumed)`: every
/// caller was going to keep an offset and advance it by hand, and an offset the
/// caller maintains is an offset the caller can get wrong.
#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// Read from the start of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes are left unread.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// Whether every byte has been read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take `n` bytes.
    ///
    /// # Errors
    ///
    /// [`VarintError::Truncated`] if fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], VarintError> {
        let available = self.remaining();
        if available < n {
            return Err(VarintError::Truncated {
                needed: n,
                available,
            });
        }
        let slice = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(slice)
    }

    /// Take everything that remains.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let slice = &self.bytes[self.at..];
        self.at = self.bytes.len();
        slice
    }

    /// Read one byte.
    ///
    /// # Errors
    ///
    /// [`VarintError::Truncated`] at the end of the buffer.
    pub fn u8(&mut self) -> Result<u8, VarintError> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `f32`.
    ///
    /// Little-endian because murmur writes floats through a union of `float` and
    /// four bytes, which is host order on every platform it supports.
    ///
    /// # Errors
    ///
    /// [`VarintError::Truncated`] if fewer than four bytes remain.
    pub fn f32(&mut self) -> Result<f32, VarintError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().unwrap_or([0; 4]);
        Ok(f32::from_le_bytes(bytes))
    }

    /// Read one varint.
    ///
    /// # Errors
    ///
    /// [`VarintError::Truncated`] if the encoding runs past the end.
    pub fn varint(&mut self) -> Result<i64, VarintError> {
        let lead = self.u8()?;

        // Ordered by how the prefixes nest: each test assumes the previous ones
        // already failed, which is what makes `0x80`/`0xC0`/`0xE0` unambiguous.
        if lead & 0x80 == 0 {
            return Ok(i64::from(lead & 0x7F));
        }
        if lead & 0xC0 == 0x80 {
            return self.big_endian(1, i64::from(lead & 0x3F));
        }
        if lead & 0xE0 == 0xC0 {
            return self.big_endian(2, i64::from(lead & 0x1F));
        }
        if lead & 0xF0 == 0xE0 {
            return self.big_endian(3, i64::from(lead & 0x0F));
        }
        match lead & 0xFC {
            0xF0 => self.big_endian(4, 0),
            0xF4 => self.big_endian(8, 0),
            // Negative: the next varint is the magnitude.
            0xF8 => Ok(!self.varint()?),
            // Small negative packed into the low two bits.
            _ => Ok(!i64::from(lead & 0x03)),
        }
    }

    /// Read a varint as a count, refusing negatives.
    ///
    /// Lengths and session ids are unsigned on the wire; a negative one is
    /// hostile input, and casting it would produce an enormous length.
    ///
    /// # Errors
    ///
    /// [`VarintError::Truncated`] if the encoding runs past the end. A negative
    /// value yields `Ok(0)`, which every caller treats as an empty field.
    pub fn count(&mut self) -> Result<u64, VarintError> {
        Ok(u64::try_from(self.varint()?).unwrap_or(0))
    }

    /// Fold `n` further big-endian bytes into `acc`.
    fn big_endian(&mut self, n: usize, acc: i64) -> Result<i64, VarintError> {
        self.take(n)?
            .iter()
            .try_fold(acc, |value, byte| Ok(value << 8 | i64::from(*byte)))
    }
}

/// Appends Mumble varints and raw fields to a buffer.
#[derive(Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A buffer that will not reallocate below `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Append raw bytes.
    pub fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Append one byte.
    pub fn u8(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    /// Append a little-endian `f32`.
    pub fn f32(&mut self, value: f32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a varint, using the shortest encoding that fits.
    ///
    /// Only non-negative values occur in the audio format, so the negative forms
    /// are decoded but never produced. `u64` rather than `i64` in the signature
    /// says that in the type instead of a comment.
    pub fn varint(&mut self, value: u64) {
        match value {
            v if v < 0x80 => self.u8(u8::try_from(v).unwrap_or(0)),
            v if v < 0x4000 => {
                self.u8(u8::try_from(v >> 8).unwrap_or(0) | 0x80);
                self.u8(u8::try_from(v & 0xFF).unwrap_or(0));
            }
            v if v < 0x0020_0000 => {
                self.u8(u8::try_from(v >> 16).unwrap_or(0) | 0xC0);
                self.big_endian(v, 2);
            }
            v if v < 0x1000_0000 => {
                self.u8(u8::try_from(v >> 24).unwrap_or(0) | 0xE0);
                self.big_endian(v, 3);
            }
            v if u32::try_from(v).is_ok() => {
                self.u8(0xF0);
                self.big_endian(v, 4);
            }
            v => {
                self.u8(0xF4);
                self.big_endian(v, 8);
            }
        }
    }

    /// Append the low `n` bytes of `value`, most significant first.
    fn big_endian(&mut self, value: u64, n: u32) {
        for shift in (0..n).rev() {
            self.u8(u8::try_from(value >> (shift * 8) & 0xFF).unwrap_or(0));
        }
    }

    /// The encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode then decode, asserting the value survives and the length is as
    /// expected. The length matters: a longer encoding than necessary is still
    /// decodable, so only checking the value would let padding slip through.
    #[track_caller]
    fn round_trip(value: u64, expected_len: usize) {
        let mut writer = Writer::new();
        writer.varint(value);
        let encoded = writer.finish();
        assert_eq!(
            encoded.len(),
            expected_len,
            "encoding {value} as {encoded:?}"
        );

        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.varint(), Ok(i64::try_from(value).expect("in range")));
        assert!(
            reader.is_empty(),
            "decoder left {} bytes",
            reader.remaining()
        );
    }

    #[test]
    fn each_width_boundary_round_trips() {
        // The values either side of every prefix change: an off-by-one in the
        // width selection shows up here and almost nowhere else.
        for (value, len) in [
            (0, 1),
            (0x7F, 1),
            (0x80, 2),
            (0x3FFF, 2),
            (0x4000, 3),
            (0x001F_FFFF, 3),
            (0x0020_0000, 4),
            (0x0FFF_FFFF, 4),
            (0x1000_0000, 5),
            (0xFFFF_FFFF, 5),
            (0x1_0000_0000, 9),
        ] {
            round_trip(value, len);
        }
    }

    #[test]
    fn a_truncated_varint_is_an_error_not_a_panic() {
        // Every prefix promising more bytes than exist. Indexing instead of
        // checking here would be a remote panic on an open UDP port.
        for lead in [0x80, 0xC0, 0xE0, 0xF0, 0xF4, 0xF8] {
            assert!(
                Reader::new(&[lead]).varint().is_err(),
                "lead byte {lead:#04x} was accepted with no payload"
            );
        }
    }

    #[test]
    fn an_empty_buffer_is_an_error() {
        assert!(Reader::new(&[]).varint().is_err());
    }

    #[test]
    fn the_negative_forms_decode() {
        // Never produced, but a hostile peer can send them, and skipping a byte
        // would desynchronise every field after it.
        assert_eq!(Reader::new(&[0xFC]).varint(), Ok(-1));
        assert_eq!(Reader::new(&[0xFD]).varint(), Ok(-2));
        assert_eq!(Reader::new(&[0xF8, 0x05]).varint(), Ok(-6));
    }

    #[test]
    fn a_negative_count_is_zero_not_a_huge_length() {
        // The bug this prevents: `-1` cast to `u64` is 18 exabytes, and the
        // caller allocates it.
        assert_eq!(Reader::new(&[0xFC]).count(), Ok(0));
    }

    #[test]
    fn floats_survive_a_round_trip() {
        let mut writer = Writer::new();
        for value in [0.0, 1.5, -273.15, f32::MAX] {
            writer.f32(value);
        }
        let encoded = writer.finish();
        let mut reader = Reader::new(&encoded);
        for value in [0.0, 1.5, -273.15, f32::MAX] {
            assert_eq!(reader.f32(), Ok(value));
        }
    }

    #[test]
    fn taking_more_than_remains_reports_both_numbers() {
        let mut reader = Reader::new(&[1, 2, 3]);
        assert_eq!(
            reader.take(4),
            Err(VarintError::Truncated {
                needed: 4,
                available: 3
            })
        );
    }

    #[test]
    fn a_failed_take_does_not_consume() {
        // Otherwise one short read would silently skip the rest of the packet.
        let mut reader = Reader::new(&[1, 2, 3]);
        assert!(reader.take(9).is_err());
        assert_eq!(reader.remaining(), 3);
    }
}
