//! Wire-level errors.

/// Errors produced while encoding or decoding Mumble wire data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A frame declared a payload larger than [`crate::codec::MAX_PAYLOAD_SIZE`].
    ///
    /// This is checked *before* any allocation, so a hostile peer cannot make
    /// the server reserve memory on its say-so.
    #[error("frame payload too large: {0} bytes")]
    PayloadTooLarge(u32),

    /// The payload was not valid protobuf for its declared message type.
    #[error("malformed payload for message type {type_id}: {source}")]
    Decode {
        /// The 16-bit message type id from the frame header.
        type_id: u16,
        /// The underlying `prost` decode failure.
        #[source]
        source: prost::DecodeError,
    },
}

/// Convenience alias for wire results.
pub type Result<T> = std::result::Result<T, Error>;
