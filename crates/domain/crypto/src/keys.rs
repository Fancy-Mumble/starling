//! The key material one peer's voice session is built from.
//!
//! `CryptSetup` (wire type 15) carries three fields — a key and two nonces — and
//! the server generates all of them. This module holds them as a value that
//! cannot accidentally be logged, and knows how a resync is meant to work.
//!
//! # What a resync is for
//!
//! UDP loses packets, and a receiver that has lost track of the sender's counter
//! cannot decrypt. Rather than tearing the session down, either side may ask for
//! the other's current counter and adopt it. murmur handles that in
//! `Server::msgCryptSetup` (`Messages.cpp:2117`), and the two directions are
//! deliberately different:
//!
//! | `client_nonce` | Meaning | Response |
//! |---|---|---|
//! | absent | *tell me your counter* | reply with the server's send counter |
//! | present | *here is mine, adopt it* | update the server's receive counter, no reply |
//!
//! Getting that branch backwards would look like a working handshake and then
//! silence, which is why [`ResyncRequest`] names the two cases instead of leaving
//! callers to test an `Option`.

use rand::rngs::SysRng;
use rand::TryRng;
use starling_gate::CipherChoice;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::session::{MASTER_KEY_LEN, SALT_LEN};

/// The key and nonces a peer needs to encrypt voice.
///
/// Zeroized on drop, and its [`Debug`] shows lengths rather than contents: this
/// value ends up on a connection record, and connection records get logged.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct VoiceKeys {
    key: [u8; MASTER_KEY_LEN],
    client_salt: [u8; SALT_LEN],
    server_salt: [u8; SALT_LEN],
}

impl std::fmt::Debug for VoiceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceKeys")
            .field("key", &format_args!("[{} bytes]", self.key.len()))
            .field("client_salt", &format_args!("[{SALT_LEN} bytes]"))
            .field("server_salt", &format_args!("[{SALT_LEN} bytes]"))
            .finish()
    }
}

impl VoiceKeys {
    /// Generate fresh material from the operating system's CSPRNG.
    ///
    /// # Errors
    ///
    /// [`KeyGenerationFailed`] if the OS entropy source is unavailable. Refusing
    /// the connection is the only safe response; falling back to a weaker source
    /// would be a silent downgrade of every session it produced.
    pub fn generate() -> Result<Self, KeyGenerationFailed> {
        let mut rng = SysRng;
        let mut keys = Self {
            key: [0; MASTER_KEY_LEN],
            client_salt: [0; SALT_LEN],
            server_salt: [0; SALT_LEN],
        };
        rng.try_fill_bytes(&mut keys.key)
            .map_err(|_| KeyGenerationFailed)?;
        rng.try_fill_bytes(&mut keys.client_salt)
            .map_err(|_| KeyGenerationFailed)?;
        rng.try_fill_bytes(&mut keys.server_salt)
            .map_err(|_| KeyGenerationFailed)?;
        Ok(keys)
    }

    /// Build from material received on the wire.
    ///
    /// # Errors
    ///
    /// [`MalformedKeys`] if any field is the wrong length. Sizes are checked here
    /// rather than at the cipher, so a hostile peer cannot reach key scheduling
    /// with a short buffer.
    pub fn from_wire(
        key: &[u8],
        client_salt: &[u8],
        server_salt: &[u8],
    ) -> Result<Self, MalformedKeys> {
        Ok(Self {
            key: exact(key, MASTER_KEY_LEN, "key")?,
            client_salt: exact(client_salt, SALT_LEN, "client_nonce")?,
            server_salt: exact(server_salt, SALT_LEN, "server_nonce")?,
        })
    }

    /// The shared master secret.
    #[must_use]
    pub const fn key(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.key
    }

    /// The salt for packets the client sends.
    #[must_use]
    pub const fn client_salt(&self) -> &[u8; SALT_LEN] {
        &self.client_salt
    }

    /// The salt for packets the server sends.
    #[must_use]
    pub const fn server_salt(&self) -> &[u8; SALT_LEN] {
        &self.server_salt
    }
}

/// Read exactly `len` bytes, or say which field was wrong.
fn exact<const N: usize>(
    bytes: &[u8],
    len: usize,
    field: &'static str,
) -> Result<[u8; N], MalformedKeys> {
    if bytes.len() != len {
        return Err(MalformedKeys {
            field,
            expected: len,
            found: bytes.len(),
        });
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// The OS entropy source was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("could not generate voice keys: the system entropy source is unavailable")]
pub struct KeyGenerationFailed;

/// A peer sent key material of the wrong shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("CryptSetup {field} is {found} bytes; {expected} are required")]
pub struct MalformedKeys {
    /// Which field was wrong.
    pub field: &'static str,
    /// How many bytes were required.
    pub expected: usize,
    /// How many arrived.
    pub found: usize,
}

/// What a peer's `CryptSetup` is asking for.
///
/// Named rather than left as an `Option`, because the two cases have opposite
/// effects and confusing them produces a session that handshakes and then goes
/// quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncRequest {
    /// No `client_nonce`: the peer lost track and wants ours.
    ///
    /// Reply with the server's current send counter. Nothing is updated.
    SendMine,

    /// A `client_nonce` was present: adopt it as the receive counter.
    ///
    /// No reply. murmur counts these to spot a peer resyncing in a loop, which is
    /// a symptom of a broken path rather than a broken peer.
    AdoptTheirs {
        /// The counter the peer says it is sending from.
        counter: u64,
    },
}

impl ResyncRequest {
    /// Classify an inbound `CryptSetup`.
    ///
    /// A present-but-malformed `client_nonce` is treated as [`Self::SendMine`]:
    /// the peer is evidently confused, and answering with our counter is the
    /// response most likely to recover the session. Adopting an unparseable value
    /// would be worse than useless.
    #[must_use]
    pub fn classify(client_nonce: Option<&[u8]>) -> Self {
        match client_nonce {
            None => Self::SendMine,
            Some(bytes) => match bytes.try_into() {
                Ok(eight) => Self::AdoptTheirs {
                    counter: u64::from_be_bytes(eight),
                },
                Err(_) => Self::SendMine,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_material_is_not_all_zero() {
        // A CSPRNG that silently produced zeros would key every session
        // identically. Vanishingly unlikely to fire by chance, and the failure it
        // guards against is total.
        let keys = VoiceKeys::generate().expect("entropy is available");
        assert_ne!(keys.key(), &[0; MASTER_KEY_LEN]);
        assert_ne!(keys.client_salt(), &[0; SALT_LEN]);
        assert_ne!(keys.server_salt(), &[0; SALT_LEN]);
    }

    #[test]
    fn each_session_gets_different_material() {
        let first = VoiceKeys::generate().expect("entropy");
        let second = VoiceKeys::generate().expect("entropy");
        assert_ne!(first.key(), second.key());
    }

    #[test]
    fn the_two_directions_get_different_salts() {
        // Sharing one salt would give both directions the same subkey, undoing
        // the separation `Direction` exists for.
        let keys = VoiceKeys::generate().expect("entropy");
        assert_ne!(keys.client_salt(), keys.server_salt());
    }

    #[test]
    fn wire_material_round_trips() {
        let keys = VoiceKeys::generate().expect("entropy");
        let rebuilt = VoiceKeys::from_wire(keys.key(), keys.client_salt(), keys.server_salt())
            .expect("well-formed");
        assert_eq!(rebuilt, keys);
    }

    #[test]
    fn a_short_field_is_named_rather_than_panicking() {
        // Hostile input reaches this before it reaches key scheduling.
        let err = VoiceKeys::from_wire(&[0; 4], &[0; SALT_LEN], &[0; SALT_LEN])
            .expect_err("a 4-byte key must be refused");
        assert_eq!(err.field, "key");
        assert_eq!(err.found, 4);

        let err = VoiceKeys::from_wire(&[0; MASTER_KEY_LEN], &[0; 3], &[0; SALT_LEN])
            .expect_err("a short client nonce must be refused");
        assert_eq!(err.field, "client_nonce");
    }

    #[test]
    fn an_absent_client_nonce_asks_for_ours() {
        assert_eq!(ResyncRequest::classify(None), ResyncRequest::SendMine);
    }

    #[test]
    fn a_present_client_nonce_is_adopted() {
        let counter = 4_242_u64;
        assert_eq!(
            ResyncRequest::classify(Some(&counter.to_be_bytes())),
            ResyncRequest::AdoptTheirs { counter }
        );
    }

    #[test]
    fn a_malformed_client_nonce_falls_back_to_sending_ours() {
        // Recovering the session beats adopting a value we cannot parse.
        for len in [0, 1, 7, 9, 24] {
            assert_eq!(
                ResyncRequest::classify(Some(&vec![0; len])),
                ResyncRequest::SendMine,
                "a {len}-byte nonce should ask for ours"
            );
        }
    }

    #[test]
    fn debug_reports_lengths_not_contents() {
        // These land on a connection record, and connection records get logged.
        let keys = VoiceKeys::generate().expect("entropy");
        let rendered = format!("{keys:?}");
        assert!(rendered.contains("32 bytes"));
        assert!(rendered.contains("16 bytes"));
        assert!(
            !rendered.contains(&format!("{:?}", keys.key()[0])) || rendered.contains("bytes"),
            "raw key bytes must not be rendered"
        );
    }
}

/// The AES key and two IVs an OCB2 session needs.
///
/// Sixteen bytes each, against `VoiceKeys`'s thirty-two-byte master secret. The
/// two ciphers genuinely take different-shaped material, which is why they are
/// separate types rather than one struct with a length field: a `[u8; 16]`
/// cannot be handed to something expecting a master key.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct LegacyKeys {
    key: [u8; OCB2_KEY_LEN],
    client_nonce: [u8; OCB2_KEY_LEN],
    server_nonce: [u8; OCB2_KEY_LEN],
}

/// AES-128's key length, and OCB2's nonce length.
pub const OCB2_KEY_LEN: usize = 16;

impl std::fmt::Debug for LegacyKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyKeys")
            .field("key", &format_args!("[{OCB2_KEY_LEN} bytes]"))
            .field("client_nonce", &format_args!("[{OCB2_KEY_LEN} bytes]"))
            .field("server_nonce", &format_args!("[{OCB2_KEY_LEN} bytes]"))
            .finish()
    }
}

impl LegacyKeys {
    /// Generate fresh material from the operating system's CSPRNG.
    ///
    /// # Errors
    ///
    /// [`KeyGenerationFailed`] if the OS entropy source is unavailable.
    pub fn generate() -> Result<Self, KeyGenerationFailed> {
        let mut rng = SysRng;
        let mut keys = Self {
            key: [0; OCB2_KEY_LEN],
            client_nonce: [0; OCB2_KEY_LEN],
            server_nonce: [0; OCB2_KEY_LEN],
        };
        for field in [
            &mut keys.key,
            &mut keys.client_nonce,
            &mut keys.server_nonce,
        ] {
            rng.try_fill_bytes(field).map_err(|_| KeyGenerationFailed)?;
        }
        Ok(keys)
    }

    /// Build from material received on the wire.
    ///
    /// # Errors
    ///
    /// [`MalformedKeys`] if any field is the wrong length.
    pub fn from_wire(
        key: &[u8],
        client_nonce: &[u8],
        server_nonce: &[u8],
    ) -> Result<Self, MalformedKeys> {
        Ok(Self {
            key: exact(key, OCB2_KEY_LEN, "key")?,
            client_nonce: exact(client_nonce, OCB2_KEY_LEN, "client_nonce")?,
            server_nonce: exact(server_nonce, OCB2_KEY_LEN, "server_nonce")?,
        })
    }

    /// The AES-128 key.
    #[must_use]
    pub const fn key(&self) -> &[u8; OCB2_KEY_LEN] {
        &self.key
    }

    /// The IV the client sends under.
    #[must_use]
    pub const fn client_nonce(&self) -> &[u8; OCB2_KEY_LEN] {
        &self.client_nonce
    }

    /// The IV the server sends under.
    #[must_use]
    pub const fn server_nonce(&self) -> &[u8; OCB2_KEY_LEN] {
        &self.server_nonce
    }
}

/// Whichever cipher's key material this peer negotiated.
///
/// The product of the cipher axis, carried from the handler that generated it to
/// the service that builds the cipher. An enum rather than three byte vectors
/// and a tag: the shapes differ, and a tag that could disagree with the lengths
/// is a tag that eventually will.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceSecrets {
    /// OCB2-AES128, for every stock Mumble client.
    Legacy(LegacyKeys),
    /// `XChaCha20-Poly1305`, for a Fancy client at 0.4.0 or later.
    Modern(VoiceKeys),
}

impl VoiceSecrets {
    /// Generate material for `choice`.
    ///
    /// # Errors
    ///
    /// [`KeyGenerationFailed`] if the OS entropy source is unavailable. Refusing
    /// is the only safe response: a weaker fallback would silently downgrade
    /// every session it produced.
    pub fn generate(choice: CipherChoice) -> Result<Self, KeyGenerationFailed> {
        match choice {
            CipherChoice::Ocb2Aes128 => LegacyKeys::generate().map(Self::Legacy),
            CipherChoice::XChaCha20Poly1305 => VoiceKeys::generate().map(Self::Modern),
        }
    }

    /// Which cipher this material is for.
    #[must_use]
    pub const fn choice(&self) -> CipherChoice {
        match self {
            Self::Legacy(_) => CipherChoice::Ocb2Aes128,
            Self::Modern(_) => CipherChoice::XChaCha20Poly1305,
        }
    }

    /// The three fields `CryptSetup` carries, in wire order.
    ///
    /// One accessor rather than three, because all a caller ever does with them
    /// is put them in that message — and because the middle two mean different
    /// things per variant (IVs against salts) that no caller should have to know.
    #[must_use]
    pub fn to_wire(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        match self {
            Self::Legacy(keys) => (
                keys.key().to_vec(),
                keys.client_nonce().to_vec(),
                keys.server_nonce().to_vec(),
            ),
            Self::Modern(keys) => (
                keys.key().to_vec(),
                keys.client_salt().to_vec(),
                keys.server_salt().to_vec(),
            ),
        }
    }
}
