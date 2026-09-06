//! Passwords, and the encryption a password buys.
//!
//! A password-protected share is not a file with a gate in front of it. The
//! bytes are sealed with a key derived from the uploader's password, so the
//! server stores ciphertext and nothing else: an operator reading the object
//! directory, a stolen backup, or a subpoena served on the host gets bytes
//! nobody can open. The password is never stored - only an Argon2id hash of
//! it, to tell a right guess from a wrong one - so a forgotten password makes
//! the file permanently unreadable. That is the trade, and it is the point.
//!
//! The cipher is XChaCha20-Poly1305 in the audited STREAM construction
//! ([`EncryptorBE32`]/[`DecryptorBE32`]): plaintext is cut into [`CHUNK_SIZE`]
//! pieces, each sealed under a per-chunk nonce built from a random per-file
//! prefix and a big-endian counter, and the final piece is tagged distinctly
//! so a truncated or reordered file fails to open rather than opening short.
//! Memory stays bounded to a couple of chunks however large the upload is.
//!
//! The shape is deliberately the one the epoch-0 file-server plugin arrived
//! at, down to the chunk size and the nonce prefix width: the two servers hold
//! the same kind of object, and a reader who has understood one has understood
//! the other.

use aead_stream::{DecryptorBE32, EncryptorBE32};
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _, Salt, SaltString};
use argon2::{Argon2, PasswordHash};
use chacha20poly1305::XChaCha20Poly1305;
use rand::TryRng as _;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

/// Bytes of Argon2id salt kept per object, for the key derivation.
pub(crate) const ENC_SALT_BYTES: usize = 32;

/// Bytes of STREAM nonce prefix kept per object.
///
/// XChaCha20-Poly1305 takes a 24-byte nonce and the BE32 STREAM construction
/// spends the last 5 on its counter and last-block marker, so 19 are ours.
pub(crate) const ENC_NONCE_PREFIX_BYTES: usize = 19;

/// Plaintext bytes per sealed chunk.
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

/// Poly1305 tag appended to every sealed chunk.
pub(crate) const TAG_BYTES: usize = 16;

/// What went wrong, said coarsely on purpose.
///
/// A caller must not be able to tell "wrong password" from "corrupt file" by
/// the error it gets back: both are a chunk that would not open, and naming
/// which is an oracle.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CryptoError {
    /// Argon2id could not produce a key.
    #[error("key derivation failed")]
    KeyDerivation,
    /// Reading or writing the object failed.
    #[error("crypto i/o error")]
    Io,
    /// A chunk would not seal.
    #[error("encryption failed")]
    Encrypt,
    /// A chunk would not open: wrong key, or tampered-with bytes.
    #[error("decryption failed")]
    Decrypt,
}

/// Fill `bytes` from the system RNG.
fn random(bytes: &mut [u8]) -> Result<(), CryptoError> {
    SysRng
        .try_fill_bytes(bytes)
        .map_err(|_| CryptoError::KeyDerivation)
}

/// A fresh key-derivation salt.
pub(crate) fn generate_salt() -> Result<[u8; ENC_SALT_BYTES], CryptoError> {
    let mut salt = [0u8; ENC_SALT_BYTES];
    random(&mut salt)?;
    Ok(salt)
}

/// A fresh STREAM nonce prefix.
pub(crate) fn generate_nonce_prefix() -> Result<[u8; ENC_NONCE_PREFIX_BYTES], CryptoError> {
    let mut prefix = [0u8; ENC_NONCE_PREFIX_BYTES];
    random(&mut prefix)?;
    Ok(prefix)
}

/// Hash a password for storage, as a PHC string.
pub(crate) fn hash_password(password: &str) -> Result<String, CryptoError> {
    let mut salt_bytes = [0u8; Salt::RECOMMENDED_LENGTH];
    random(&mut salt_bytes)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| CryptoError::KeyDerivation)?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| CryptoError::KeyDerivation)
}

/// Whether `password` is the one `stored` was made from.
///
/// The comparison is the hash crate's, which is constant-time.
pub(crate) fn verify_password(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Derive an object's encryption key from its password and salt.
///
/// Separate from [`hash_password`]: the stored hash exists to check a guess,
/// and reusing it as the key would mean the thing kept in the database were
/// also the thing that opens the file.
pub(crate) fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Seals a stream of bytes as they arrive, a chunk at a time.
///
/// Incremental rather than the plugin's file-to-file pass, because an upload
/// is already a stream here and staging the plaintext on disk first would put
/// the very bytes this exists to protect in the object directory - briefly,
/// but written down all the same.
///
/// One full chunk is always held back, because the last chunk has to be sealed
/// with `encrypt_last` and nothing knows a chunk was the last one until the
/// bytes after it fail to arrive.
pub(crate) struct Sealer {
    encryptor: Option<EncryptorBE32<XChaCha20Poly1305>>,
    /// Plaintext taken in but not yet cut into a whole chunk.
    pending: Vec<u8>,
    /// The whole chunk held back, if there is one.
    held: Option<Vec<u8>>,
}

impl Sealer {
    pub(crate) fn new(key: &[u8; 32], nonce_prefix: &[u8; ENC_NONCE_PREFIX_BYTES]) -> Self {
        Self {
            encryptor: Some(EncryptorBE32::new(key.into(), nonce_prefix.into())),
            pending: Vec::with_capacity(CHUNK_SIZE),
            held: None,
        }
    }

    /// Take `input`, and hand back whatever ciphertext that completed.
    pub(crate) fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.pending.extend_from_slice(input);
        let mut out = Vec::new();
        while self.pending.len() >= CHUNK_SIZE {
            let rest = self.pending.split_off(CHUNK_SIZE);
            let chunk = std::mem::replace(&mut self.pending, rest);
            if let Some(previous) = self.held.replace(chunk) {
                let sealed = self
                    .encryptor
                    .as_mut()
                    .ok_or(CryptoError::Encrypt)?
                    .encrypt_next(previous.as_slice())
                    .map_err(|_| CryptoError::Encrypt)?;
                out.extend_from_slice(&sealed);
            }
        }
        Ok(out)
    }

    /// Seal what is left. The sealer is spent afterwards.
    pub(crate) fn finish(mut self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        let mut encryptor = self.encryptor.take().ok_or(CryptoError::Encrypt)?;
        // A held chunk with a partial tail behind it was not the last one
        // after all, so it goes out the ordinary way first.
        if let Some(held) = self.held.take() {
            if self.pending.is_empty() {
                self.pending = held;
            } else {
                let sealed = encryptor
                    .encrypt_next(held.as_slice())
                    .map_err(|_| CryptoError::Encrypt)?;
                out.extend_from_slice(&sealed);
            }
        }
        // Always one sealed chunk, even for an object with no bytes in it, so
        // that opening an empty file is a read rather than a special case.
        let last = encryptor
            .encrypt_last(self.pending.as_slice())
            .map_err(|_| CryptoError::Encrypt)?;
        out.extend_from_slice(&last);
        Ok(out)
    }
}

/// Open a sealed object, handing each plaintext chunk to `on_chunk` in order.
///
/// Blocking, and meant to be run as such: Argon2 has already happened by the
/// time this is called, but a gigabyte of Poly1305 is still not something to
/// do on an async worker.
pub(crate) fn open(
    path: &std::path::Path,
    key: &[u8; 32],
    nonce_prefix: &[u8; ENC_NONCE_PREFIX_BYTES],
    mut on_chunk: impl FnMut(Vec<u8>) -> Result<(), CryptoError>,
) -> Result<(), CryptoError> {
    use std::io::{BufReader, Read};

    /// Read until `cap` bytes or end of file, so a short read means the end.
    fn read_up_to(reader: &mut impl Read, cap: usize) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; cap];
        let mut filled = 0;
        while filled < cap {
            let read = reader
                .read(buffer.get_mut(filled..).unwrap_or_default())
                .map_err(|_| CryptoError::Io)?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        buffer.truncate(filled);
        Ok(buffer)
    }

    let mut decryptor = Some(DecryptorBE32::<XChaCha20Poly1305>::new(
        key.into(),
        nonce_prefix.into(),
    ));
    let mut reader = BufReader::new(std::fs::File::open(path).map_err(|_| CryptoError::Io)?);
    let sealed_chunk = CHUNK_SIZE + TAG_BYTES;

    // Same one-chunk lookahead as sealing, for the same reason: the last chunk
    // opens differently, and only the read after it says which one it was.
    let mut current = read_up_to(&mut reader, sealed_chunk)?;
    if current.is_empty() {
        return Err(CryptoError::Decrypt);
    }
    loop {
        let next = read_up_to(&mut reader, sealed_chunk)?;
        if next.is_empty() {
            let opened = decryptor
                .take()
                .ok_or(CryptoError::Decrypt)?
                .decrypt_last(current.as_slice())
                .map_err(|_| CryptoError::Decrypt)?;
            on_chunk(opened)?;
            return Ok(());
        }
        let opened = decryptor
            .as_mut()
            .ok_or(CryptoError::Decrypt)?
            .decrypt_next(current.as_slice())
            .map_err(|_| CryptoError::Decrypt)?;
        on_chunk(opened)?;
        current = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seal `plaintext` in pieces of `feed` bytes, the way a body arrives.
    fn seal(plaintext: &[u8], feed: usize) -> (Vec<u8>, [u8; 32], [u8; ENC_NONCE_PREFIX_BYTES]) {
        let key = [7u8; 32];
        let prefix = [9u8; ENC_NONCE_PREFIX_BYTES];
        let mut sealer = Sealer::new(&key, &prefix);
        let mut out = Vec::new();
        for piece in plaintext.chunks(feed.max(1)) {
            out.extend_from_slice(&sealer.update(piece).expect("seal a piece"));
        }
        out.extend_from_slice(&sealer.finish().expect("seal the tail"));
        (out, key, prefix)
    }

    fn open_all(sealed: &[u8], key: &[u8; 32], prefix: &[u8; ENC_NONCE_PREFIX_BYTES]) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("files-crypto-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("object");
        std::fs::write(&path, sealed).expect("write the sealed object");
        let mut plain = Vec::new();
        let result = open(&path, key, prefix, |chunk| {
            plain.extend_from_slice(&chunk);
            Ok(())
        });
        drop(std::fs::remove_dir_all(&dir));
        result.expect("open the object");
        plain
    }

    #[test]
    fn a_sealed_object_opens_to_what_went_in() {
        // Sizes that bracket the chunk boundary in both directions, because
        // the held-back chunk is what makes the boundary cases differ: an
        // exact multiple takes the `(Some, true)` arm and one byte more takes
        // `(Some, false)`.
        for size in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            CHUNK_SIZE * 2,
        ] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (sealed, key, prefix) = seal(&plaintext, 7777);
            assert_eq!(open_all(&sealed, &key, &prefix), plaintext, "size {size}");
        }
    }

    #[test]
    fn how_the_bytes_arrive_does_not_change_the_object() {
        // The body is fed in whatever pieces the network hands over, and the
        // chunking has to be the sealer's rather than the socket's.
        let plaintext: Vec<u8> = (0..CHUNK_SIZE * 2 + 13).map(|i| (i % 251) as u8).collect();
        let (one, ..) = seal(&plaintext, plaintext.len());
        let (many, ..) = seal(&plaintext, 1024);
        assert_eq!(one, many);
    }

    #[test]
    fn a_truncated_object_does_not_open_short() {
        // The property the last-chunk marker exists for: cutting the file must
        // fail, not hand back a prefix of the plaintext.
        let plaintext: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
        let (sealed, key, prefix) = seal(&plaintext, 4096);
        let dir = std::env::temp_dir().join(format!("files-crypto-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("object");
        std::fs::write(&path, &sealed[..sealed.len() - (CHUNK_SIZE + TAG_BYTES)])
            .expect("write a truncated object");
        let opened = open(&path, &key, &prefix, |_| Ok(()));
        drop(std::fs::remove_dir_all(&dir));
        assert!(opened.is_err(), "a truncated object must not open");
    }

    #[test]
    fn the_wrong_password_does_not_open_the_object() {
        let salt = generate_salt().expect("a salt");
        let right = derive_key("correct horse", &salt).expect("derive");
        let wrong = derive_key("battery staple", &salt).expect("derive");
        let prefix = generate_nonce_prefix().expect("a prefix");
        let mut sealer = Sealer::new(&right, &prefix);
        let mut sealed = sealer.update(b"the contents").expect("seal");
        sealed.extend_from_slice(&sealer.finish().expect("finish"));

        let dir = std::env::temp_dir().join(format!("files-crypto-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("object");
        std::fs::write(&path, &sealed).expect("write");
        let opened = open(&path, &wrong, &prefix, |_| Ok(()));
        drop(std::fs::remove_dir_all(&dir));
        assert!(opened.is_err(), "the wrong key must not open the object");
    }

    #[test]
    fn a_stored_hash_recognises_its_own_password_and_no_other() {
        let stored = hash_password("hunter2").expect("hash");
        assert!(verify_password("hunter2", &stored));
        assert!(!verify_password("hunter3", &stored));
        assert!(!verify_password("hunter2", "not a phc string"));
    }
}
