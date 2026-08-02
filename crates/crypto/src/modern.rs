//! `XChaCha20-Poly1305` as a two-directional voice cipher.
//!
//! [`VoiceSession`] encrypts one direction. A peer needs two — one to seal what
//! it sends and one to open what it receives — and they must not be the same
//! session, because a single session sealing and opening would use one keystream
//! for both halves of a two-party conversation.
//!
//! This is the pairing, and it is also where the [`VoiceCipher`] seam is
//! implemented, so [`Ocb2`](crate::Ocb2) and this are interchangeable behind
//! one trait object.
//!
//! # The two roles are mirror images
//!
//! | | seals with | opens with |
//! |---|---|---|
//! | server | `s2c` label, server salt | `c2s` label, client salt |
//! | client | `c2s` label, client salt | `s2c` label, server salt |
//!
//! Getting either row backwards produces a handshake that looks perfect and a
//! session in which no packet ever authenticates. There is a test for exactly
//! that, because it is the mistake this file exists to make impossible.
//!
//! # What it costs against OCB2
//!
//! | | OCB2-AES128 | this |
//! |---|---|---|
//! | tag | 3 bytes | 16 bytes |
//! | forgery odds per attempt | 2^-24 | 2^-128 |
//! | wire overhead | 4 bytes | 18 bytes |
//! | replay window | 256 entries, guessed high bits | 64-bit bitmap over a reconstructed counter |
//!
//! Fourteen extra bytes per packet, against a tag an attacker can currently
//! brute-force in about four days at 50 packets a second. Every stock Mumble
//! client is stuck with OCB2 forever; a Fancy client announcing 0.4.0 or later
//! is not.

use crate::keys::VoiceKeys;
use crate::session::{VoiceError, VoiceSession};
use crate::stream::VoiceCipher;
use crate::voice::Direction;

/// Bytes a packet grows by: the wire counter plus the tag.
pub const OVERHEAD: usize = crate::voice::WIRE_COUNTER_BYTES + crate::session::TAG_LEN;

/// One peer's `XChaCha20-Poly1305` state, both directions.
///
/// The modern counterpart to `Ocb2`, and constructed the same way: from the key
/// material `CryptSetup` carried, once, at authentication.
pub struct XChaCha20Voice {
    sending: VoiceSession,
    receiving: VoiceSession,
}

impl XChaCha20Voice {
    /// The server's half of a session.
    ///
    /// Named for the role rather than taking a `Direction`, because a
    /// `Direction` parameter is exactly the thing a caller gets backwards: two
    /// sessions are derived here and neither of them takes the caller's word for
    /// which is which.
    #[must_use]
    pub fn for_server(keys: &VoiceKeys) -> Self {
        Self {
            sending: VoiceSession::derive(keys.key(), keys.server_salt(), Direction::Outbound),
            receiving: VoiceSession::derive(keys.key(), keys.client_salt(), Direction::Inbound),
        }
    }

    /// The client's half of the same session.
    ///
    /// The exact mirror of [`Self::for_server`]. Both live here so the two can
    /// be read against each other; separating them across crates is how they
    /// drift.
    #[must_use]
    pub fn for_client(keys: &VoiceKeys) -> Self {
        Self {
            sending: VoiceSession::derive(keys.key(), keys.client_salt(), Direction::Inbound),
            receiving: VoiceSession::derive(keys.key(), keys.server_salt(), Direction::Outbound),
        }
    }
}

impl VoiceCipher for XChaCha20Voice {
    fn name(&self) -> &'static str {
        "XChaCha20-Poly1305"
    }

    fn overhead(&self) -> usize {
        OVERHEAD
    }

    fn seal(&mut self, frame: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        self.sending.seal(frame, aad)
    }

    fn open(&mut self, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, VoiceError> {
        self.receiving.open(packet, aad)
    }

    /// Nothing, and that is the honest answer rather than an omission.
    ///
    /// murmur's resynchronisation swaps an IV, which works because OCB2's nonce
    /// *is* its counter. Here the salt is folded into the subkey by `HChaCha20`
    /// at derivation and never travels again, and the counter's high bits are
    /// reconstructed by the receiver from the two bytes on the wire — so there is
    /// no value this half could hand over that the peer could install.
    ///
    /// Saying so is what lets the caller pick the recovery that does work: a peer
    /// on this cipher is re-keyed. Returning some plausible-looking bytes instead
    /// would be answered, accepted, and inert.
    fn send_nonce(&self) -> Option<Vec<u8>> {
        None
    }

    /// Refused, for the same reason.
    ///
    /// The counter reconstruction is already self-healing across the wire wrap,
    /// so there is nothing a peer's claim could repair — and installing one would
    /// mean rebuilding both sessions from key material this type no longer holds.
    fn adopt_recv_nonce(&mut self, _nonce: &[u8]) -> bool {
        false
    }
}

impl std::fmt::Debug for XChaCha20Voice {
    /// Prints no key material; both halves are already opaque.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChaCha20Voice")
            .field("sending", &self.sending)
            .field("receiving", &self.receiving)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::assert_voice_cipher_contract;

    fn keys() -> VoiceKeys {
        VoiceKeys::from_wire(&[0x11; 32], &[0x22; 16], &[0x33; 16]).expect("well-formed")
    }

    /// The two ends of one connection.
    fn pair() -> (XChaCha20Voice, XChaCha20Voice) {
        (
            XChaCha20Voice::for_server(&keys()),
            XChaCha20Voice::for_client(&keys()),
        )
    }

    #[test]
    fn it_meets_the_voice_cipher_contract() {
        // The same function `Ocb2` passes. Two ciphers behind one trait are
        // only interchangeable if one test holds both to the same rules.
        let (mut server, mut client) = pair();
        assert_voice_cipher_contract(&mut server, &mut client);
    }

    #[test]
    fn the_server_can_be_heard_by_the_client() {
        let (mut server, mut client) = pair();
        let packet = server.seal(b"server speaking", b"").expect("sealed");
        assert_eq!(
            client
                .open(&packet, b"")
                .expect("the client could not open it"),
            b"server speaking"
        );
    }

    #[test]
    fn the_client_can_be_heard_by_the_server() {
        // The other direction, which uses an entirely different subkey. A test
        // for one direction alone passes even when the roles are swapped.
        let (mut server, mut client) = pair();
        let packet = client.seal(b"client speaking", b"").expect("sealed");
        assert_eq!(
            server
                .open(&packet, b"")
                .expect("the server could not open it"),
            b"client speaking"
        );
    }

    #[test]
    fn a_peer_cannot_open_its_own_packets() {
        // The property that makes the two directions worth separating: even
        // holding the master key, the sending keystream cannot read itself. A
        // single shared session would fail this and nothing else would notice.
        let (mut server, _) = pair();
        let packet = server.seal(b"outbound", b"").expect("sealed");
        assert!(
            server.open(&packet, b"").is_err(),
            "a peer opened its own outbound packet, so both directions share a key"
        );
    }

    #[test]
    fn swapping_the_roles_breaks_everything() {
        // The mistake this file exists to prevent, asserted directly: two peers
        // that both think they are the server cannot talk.
        let (mut one, mut two) = (
            XChaCha20Voice::for_server(&keys()),
            XChaCha20Voice::for_server(&keys()),
        );
        let packet = one.seal(b"mismatched", b"").expect("sealed");
        assert!(
            two.open(&packet, b"").is_err(),
            "two servers understood each other, so the direction label does nothing"
        );
    }

    #[test]
    fn a_different_master_key_cannot_listen_in() {
        let (mut server, _) = pair();
        let mut eavesdropper = XChaCha20Voice::for_client(
            &VoiceKeys::from_wire(&[0x99; 32], &[0x22; 16], &[0x33; 16]).expect("well-formed"),
        );
        let packet = server.seal(b"private", b"").expect("sealed");
        assert!(eavesdropper.open(&packet, b"").is_err());
    }

    #[test]
    fn a_different_salt_cannot_listen_in() {
        // The salt is folded in by `HChaCha20`, so it separates sessions as
        // firmly as the key does. Two connections on one server share neither.
        let (mut server, _) = pair();
        let mut other = XChaCha20Voice::for_client(
            &VoiceKeys::from_wire(&[0x11; 32], &[0x44; 16], &[0x55; 16]).expect("well-formed"),
        );
        let packet = server.seal(b"private", b"").expect("sealed");
        assert!(other.open(&packet, b"").is_err());
    }

    #[test]
    fn the_overhead_is_eighteen_bytes() {
        // Fourteen more than OCB2, for a tag that is 2^104 times harder to
        // forge. The UDP path uses this number to size its buffers.
        let (mut server, _) = pair();
        assert_eq!(server.overhead(), 18);
        assert_eq!(server.seal(b"payload", b"").expect("sealed").len(), 7 + 18);
    }

    #[test]
    fn every_frame_length_survives() {
        let (mut server, mut client) = pair();
        for len in 0..128 {
            let frame: Vec<u8> = (0..len).map(|i| u8::try_from(i + 1).unwrap_or(1)).collect();
            let packet = server.seal(&frame, b"").expect("sealed");
            assert_eq!(
                client.open(&packet, b"").expect("opened"),
                frame,
                "len {len}"
            );
        }
    }

    #[test]
    fn a_long_run_stays_in_step_across_the_wire_counter_wrap() {
        // Only two counter bytes reach the wire, so the receiver reconstructs
        // the high bits. Past 65 536 packets — about 22 minutes of talking —
        // a broken reconstruction goes silent, and nothing before that would
        // have shown it.
        let (mut server, mut client) = pair();
        for i in 0..70_000_u32 {
            let packet = server.seal(&i.to_be_bytes(), b"").expect("sealed");
            assert_eq!(
                client.open(&packet, b"").expect("opened"),
                i.to_be_bytes(),
                "packet {i}"
            );
        }
    }

    /// The interoperability anchor, shared with the client.
    ///
    /// The client's `mumble-protocol` implements this same wire format in a
    /// separate repository, so the two can drift. This is the mitigation: the
    /// same constants and the same expected ciphertext are pinned on both sides,
    /// and a change to either that would break the other fails a test rather
    /// than a call.
    ///
    /// Counter 0, `c2s`, master `0x11`x32, client salt `0x22`x16, frame
    /// `b"opus frame bytes"`, no associated data.
    const KNOWN_VECTOR: &str =
        "0000e67fe8959303117e9c1b5efcc120278f6013774c9545d68cbcd545bfaff3793a";

    #[test]
    fn the_known_vector_still_holds() {
        // Deliberately built as the *client*: this is the c2s direction, and
        // asserting on the server's own sending direction would pin the wrong
        // key and pass while interoperability was broken.
        let mut client = XChaCha20Voice::for_client(&keys());
        let packet = client.seal(b"opus frame bytes", &[]).expect("sealed");

        let hex: String = packet.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, KNOWN_VECTOR,
            "the wire bytes changed; the Fancy client will not understand this build"
        );
    }

    /// The same anchor for the other direction.
    ///
    /// Counter 0, `s2c`, master `0x11`x32, server salt `0x33`x16, frame
    /// `b"server to client"`. The client pins this one as something it must be
    /// able to *open*, which is the half a sending-only vector cannot check.
    const S2C_VECTOR: &str = "0000fc76c7db29e4b5854fc9a6801d1531d84dafd1d79a1c8f8b999fcc399d680b52";

    #[test]
    fn the_s2c_vector_still_holds() {
        let mut server = XChaCha20Voice::for_server(&keys());
        let packet = server.seal(b"server to client", &[]).expect("sealed");

        let hex: String = packet.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, S2C_VECTOR,
            "the wire bytes changed; the Fancy client will not understand this build"
        );
    }

    #[test]
    fn it_prints_no_key_material() {
        let (server, _) = pair();
        let printed = format!("{server:?}");
        assert!(!printed.contains("17"), "{printed}");
        assert!(!printed.contains("11"), "{printed}");
    }
}
