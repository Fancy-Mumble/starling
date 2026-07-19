//! Voice cipher specifications.
//!
//! These describe *what* a cipher is on the wire: its identifier, key and nonce
//! sizes, and whether it is still considered sound. The encryption itself lives
//! in [`super::ocb2`] and [`super::modern`]. Keeping the parameters separate
//! from the implementations is what lets the negotiation in [`super::policy`]
//! be tested without standing up either cipher.

/// How much confidence a cipher deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CipherStanding {
    /// Known weaknesses; offered only for backwards compatibility.
    Legacy,
    /// No known practical attacks; the preferred choice.
    Modern,
}

/// A UDP voice cipher, as a specification.
///
/// # Contract
///
/// [`Self::wire_id`] is **wire-visible and permanent**: it is how the two sides
/// agree on which cipher is in use, so a value may never be reused for a
/// different algorithm. `0` is reserved for OCB2, because that is what every
/// existing Mumble client uses without negotiating anything.
pub trait VoiceCipherSpec: std::fmt::Debug + Send + Sync {
    /// Human-readable name, for logs and the admin API.
    fn name(&self) -> &'static str;

    /// The negotiated identifier carried on the wire.
    fn wire_id(&self) -> u8;

    /// Symmetric key length in bytes.
    fn key_len(&self) -> usize;

    /// Nonce length in bytes.
    fn nonce_len(&self) -> usize;

    /// Authentication tag length in bytes.
    fn tag_len(&self) -> usize;

    /// How much confidence this cipher deserves.
    fn standing(&self) -> CipherStanding;
}

/// OCB2-AES128, what stock Mumble uses.
///
/// Retained **only** for backwards compatibility. OCB2 has a practical forgery
/// attack (Inoue–Iwata–Minematsu–Poettering, CRYPTO 2019); Mumble's fixed-length
/// framing limits the practical exposure, but it is not a cipher anyone would
/// choose today. Every client that can do better is given
/// [`XChaCha20Poly1305Spec`] instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ocb2Aes128Spec;

impl VoiceCipherSpec for Ocb2Aes128Spec {
    fn name(&self) -> &'static str {
        "OCB2-AES128"
    }
    fn wire_id(&self) -> u8 {
        // Reserved: stock clients assume this cipher without negotiating.
        0
    }
    fn key_len(&self) -> usize {
        16
    }
    fn nonce_len(&self) -> usize {
        16
    }
    fn tag_len(&self) -> usize {
        // Mumble truncates the OCB2 tag to 3 bytes in the UDP header.
        3
    }
    fn standing(&self) -> CipherStanding {
        CipherStanding::Legacy
    }
}

/// `XChaCha20-Poly1305` with HKDF-SHA256, the modern choice.
///
/// Matches the client's `fancy_v1` suite exactly (`XChaChaEncryptor`, suite
/// version `0x01`, 32-byte key, 24-byte nonce, 16-byte tag), so voice and
/// persistent chat share one cipher and one implementation to review. Chosen over
/// AES-GCM because it is constant-time in software on every target, the client
/// runs on phones and on hardware without AES-NI.
///
/// The 24-byte nonce is what makes it `XChaCha` rather than `ChaCha`: it is large
/// enough to be chosen at random per message without a birthday-bound concern,
/// which is why the chat stack transmits it inline.
///
/// # The nonce must not be transmitted on the voice path
///
/// Chat sends `[version:1][nonce:24][ciphertext+tag:16+]`, 41 bytes of overhead,
/// which is fine for a chat message and unacceptable for a 20 ms voice frame,
/// where an Opus payload at 32 kbit/s is roughly 80 bytes. Transmitting the nonce
/// would add about 30% to every packet.
///
/// So the voice path must **derive** the nonce from the packet sequence number it
/// already carries, the way OCB2 does with its truncated 4-byte nonce, and send
/// only the tag. Same cipher, same key schedule, different nonce discipline. That
/// derivation is not written yet; it is the first thing the UDP path needs, and
/// getting it wrong means nonce reuse, which is catastrophic for any AEAD.
#[derive(Debug, Clone, Copy, Default)]
pub struct XChaCha20Poly1305Spec;

impl VoiceCipherSpec for XChaCha20Poly1305Spec {
    fn name(&self) -> &'static str {
        "XChaCha20-Poly1305 + HKDF-SHA256"
    }
    fn wire_id(&self) -> u8 {
        // Matches the client's `ENCRYPTION_VERSION`, so one number identifies the
        // suite on both the chat and voice paths.
        1
    }
    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        24
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn standing(&self) -> CipherStanding {
        CipherStanding::Modern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Box<dyn VoiceCipherSpec>> {
        vec![Box::new(Ocb2Aes128Spec), Box::new(XChaCha20Poly1305Spec)]
    }

    /// The contract every cipher specification must satisfy.
    fn assert_spec_contract(spec: &dyn VoiceCipherSpec) {
        assert!(!spec.name().is_empty());
        assert!(spec.key_len() >= 16, "{}: key is too short", spec.name());
        assert!(spec.nonce_len() > 0, "{}: nonce is empty", spec.name());
        assert!(spec.tag_len() > 0, "{}: tag is empty", spec.name());
    }

    #[test]
    fn every_cipher_satisfies_the_specification_contract() {
        for spec in all() {
            assert_spec_contract(spec.as_ref());
        }
    }

    #[test]
    fn wire_ids_are_unique() {
        // A collision would make the two sides silently disagree about which
        // cipher is in use, which fails as garbled audio rather than an error.
        let mut ids: Vec<_> = all().iter().map(|s| s.wire_id()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "two ciphers share a wire id");
    }

    #[test]
    fn ocb2_keeps_wire_id_zero() {
        // Stock clients assume this cipher without negotiating, so 0 can never
        // be reassigned.
        assert_eq!(Ocb2Aes128Spec.wire_id(), 0);
    }

    #[test]
    fn ocb2_matches_the_parameters_stock_mumble_uses() {
        let spec = Ocb2Aes128Spec;
        assert_eq!(spec.key_len(), 16, "AES-128");
        assert_eq!(spec.nonce_len(), 16, "AES block-sized IV");
        assert_eq!(spec.tag_len(), 3, "Mumble truncates the OCB2 tag");
    }

    #[test]
    fn xchacha20_poly1305_matches_the_clients_suite() {
        // These are the client's `fancy_v1` constants: `KEY_LEN`, its 24-byte
        // `NONCE_LEN`, and the Poly1305 tag. Pinned here because the two sides
        // must agree exactly, and a mismatch would show up as an authentication
        // failure on the first voice packet rather than as a build error.
        let spec = XChaCha20Poly1305Spec;
        assert_eq!(spec.key_len(), 32, "client KEY_LEN");
        assert_eq!(spec.nonce_len(), 24, "24 bytes is what makes it XChaCha");
        assert_eq!(spec.tag_len(), 16, "Poly1305");
    }

    #[test]
    fn the_modern_wire_id_matches_the_clients_encryption_version() {
        // The client's `ENCRYPTION_VERSION` is `0x01`, and it prefixes every
        // chat ciphertext with it. Sharing the number means one value identifies
        // the suite on both paths.
        assert_eq!(XChaCha20Poly1305Spec.wire_id(), 0x01);
    }

    #[test]
    fn the_nonce_is_too_large_to_transmit_per_voice_packet() {
        // Not a property of the cipher but of how it must be *used*: chat sends
        // the nonce inline, and doing that per 20 ms frame would add version +
        // nonce + tag to an ~80-byte Opus payload. The UDP path must derive the
        // nonce from the sequence number instead. Asserted so the number is on
        // record before the voice path is written.
        let spec = XChaCha20Poly1305Spec;
        let inline_overhead = 1 + spec.nonce_len() + spec.tag_len();
        assert_eq!(inline_overhead, 41);
        assert!(
            inline_overhead > 32,
            "inline nonce framing is not affordable per frame; derive it instead"
        );
    }

    #[test]
    fn the_legacy_cipher_is_marked_as_such() {
        assert_eq!(Ocb2Aes128Spec.standing(), CipherStanding::Legacy);
        assert_eq!(XChaCha20Poly1305Spec.standing(), CipherStanding::Modern);
        assert!(
            CipherStanding::Modern > CipherStanding::Legacy,
            "standing must order so 'prefer the best available' is a max()"
        );
    }

    #[test]
    fn the_modern_cipher_has_a_full_strength_tag() {
        // The truncated OCB2 tag is part of why it is legacy; the replacement
        // must not inherit that.
        assert!(XChaCha20Poly1305Spec.tag_len() >= 16);
    }
}
