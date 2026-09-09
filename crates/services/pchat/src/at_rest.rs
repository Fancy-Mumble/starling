//! Sealing a server-managed channel's messages on disk.
//!
//! Every other mode this service stores is end-to-end: the bytes arrive sealed,
//! and the column holds ciphertext because the client put ciphertext in it.
//! `SERVER_MANAGED` is the one where they do not. Its members have been told
//! this server keeps their history and can read it, which is what buys them a
//! late joiner who can read the archive and a client that needs no key ladder
//! at all. Storing that as plaintext would still be worse than it has to be, so
//! it is sealed here under a key the server holds.
//!
//! # What this does and does not buy
//!
//! It defends the database at rest and nothing else. A stolen backup, a disk
//! that leaves the building, an operator reading the object directory: those
//! get bytes nobody can open. A running server reads everything, and so does
//! anyone who takes [`DataKey`] along with the database. Said plainly because
//! the alternative is a reader assuming "encrypted" means what it means two
//! modes up the enum.
//!
//! # The row is bound to its place
//!
//! `AAD = server_id ‖ channel_id ‖ id ‖ client_id`. A sealed row moved to
//! another channel, another tenant, or another id fails to open rather than
//! opening into the wrong conversation. That is the same discipline the
//! end-to-end modes already apply on the client, where the sender's AAD is
//! `channel ‖ message_id ‖ sent_at_ms` — and it is the reason the id columns
//! must never be rewritten under a stored row.

use chacha20poly1305::aead::{Aead, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use starling_runtime::data_key::DataKey;

/// Bytes of XChaCha20-Poly1305 nonce.
const NONCE_BYTES: usize = 24;

/// What a sealed column looks like: `key_id ‖ nonce ‖ ciphertext‖tag`.
///
/// The key id leads so that a row can be routed to the right key before
/// anything else is read, which is what makes a rotation possible later
/// without a migration over the whole table.
const HEADER_BYTES: usize = 1 + NONCE_BYTES;

/// Everything needed to name where a row lives.
///
/// Passed as a struct rather than four arguments because they are all integers
/// and byte strings, and getting two of them the wrong way round would produce
/// rows that seal and never open.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Placement<'a> {
    pub(crate) scope: u32,
    pub(crate) channel: u32,
    /// This server's storage id, 16 bytes of `UUIDv7`.
    pub(crate) id: &'a [u8],
    /// The id the sender minted, which is what the wire calls the message.
    pub(crate) client_id: &'a str,
}

impl Placement<'_> {
    /// The additional data a row is bound to.
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(8 + self.id.len() + self.client_id.len());
        aad.extend_from_slice(&self.scope.to_be_bytes());
        aad.extend_from_slice(&self.channel.to_be_bytes());
        aad.extend_from_slice(self.id);
        aad.extend_from_slice(self.client_id.as_bytes());
        aad
    }
}

/// Seal `plaintext` for storage, or `None` if it will not seal.
///
/// A refusal is a refusal to store, never a fallback to plaintext: the one
/// thing this must not do is quietly write the message in clear because the
/// cipher had a bad day.
pub(crate) fn seal(key: &DataKey, at: Placement<'_>, plaintext: &[u8]) -> Option<Vec<u8>> {
    use rand::TryRng as _;

    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes()).ok()?;
    let mut nonce = [0_u8; NONCE_BYTES];
    rand::rngs::SysRng.try_fill_bytes(&mut nonce).ok()?;

    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &at.aad(),
            },
        )
        .ok()?;

    let mut out = Vec::with_capacity(HEADER_BYTES + sealed.len());
    out.push(key.id());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Some(out)
}

/// Open a sealed column, or `None` if it will not open.
///
/// `None` covers a wrong key, a truncated column, a row moved between channels
/// and a row whose ids were rewritten. Deliberately one answer for all of them:
/// distinguishing them for the caller would be an oracle, and the caller's
/// response is the same either way, which is to leave the message out of the
/// page rather than serve something it cannot vouch for.
pub(crate) fn open(key: &DataKey, at: Placement<'_>, stored: &[u8]) -> Option<Vec<u8>> {
    let (&stored_key_id, rest) = stored.split_first()?;
    if stored_key_id != key.id() {
        return None;
    }
    if rest.len() < NONCE_BYTES {
        return None;
    }
    let (nonce, sealed) = rest.split_at(NONCE_BYTES);

    XChaCha20Poly1305::new_from_slice(key.bytes())
        .ok()?
        .decrypt(
            &XNonce::try_from(nonce).ok()?,
            Payload {
                msg: sealed,
                aad: &at.aad(),
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_runtime::data_key::CURRENT_KEY_ID;

    fn key(byte: u8) -> DataKey {
        DataKey::from_bytes([byte; 32], CURRENT_KEY_ID)
    }

    fn placement<'a>(channel: u32, id: &'a [u8], client_id: &'a str) -> Placement<'a> {
        Placement {
            scope: 1,
            channel,
            id,
            client_id,
        }
    }

    #[test]
    fn a_sealed_message_comes_back_the_way_it_went_in() {
        let key = key(7);
        let at = placement(4, b"0123456789abcdef", "m-1");
        let sealed = seal(&key, at, b"what was said").expect("it seals");
        assert_eq!(
            open(&key, at, &sealed).as_deref(),
            Some(&b"what was said"[..])
        );
    }

    #[test]
    fn the_stored_bytes_are_not_the_message() {
        // The whole claim of the mode, asserted rather than assumed.
        let key = key(7);
        let at = placement(4, b"0123456789abcdef", "m-1");
        let sealed = seal(&key, at, b"what was said").expect("it seals");
        assert!(
            !sealed.windows(4).any(|window| window == b"what"),
            "a backup must not hold the plaintext"
        );
    }

    #[test]
    fn two_seals_of_one_message_differ() {
        // A fixed nonce would let anyone reading the table see which messages
        // are the same message, across every channel on the server.
        let key = key(7);
        let at = placement(4, b"0123456789abcdef", "m-1");
        let first = seal(&key, at, b"yes").expect("it seals");
        let second = seal(&key, at, b"yes").expect("it seals");
        assert_ne!(first, second);
    }

    #[test]
    fn another_key_does_not_open_it() {
        let at = placement(4, b"0123456789abcdef", "m-1");
        let sealed = seal(&key(7), at, b"what was said").expect("it seals");
        assert_eq!(open(&key(8), at, &sealed), None);
    }

    #[test]
    fn a_row_moved_to_another_channel_does_not_open() {
        // What the AAD is for: a sealed row lifted into a channel its author
        // never wrote in must fail rather than open into that conversation.
        let key = key(7);
        let sealed = seal(
            &key,
            placement(4, b"0123456789abcdef", "m-1"),
            b"what was said",
        )
        .expect("it seals");
        assert_eq!(
            open(&key, placement(9, b"0123456789abcdef", "m-1"), &sealed),
            None
        );
    }

    #[test]
    fn a_row_whose_ids_were_rewritten_does_not_open() {
        // The id columns are load-bearing, which is why nothing rewrites them
        // under a stored row.
        let key = key(7);
        let sealed = seal(
            &key,
            placement(4, b"0123456789abcdef", "m-1"),
            b"what was said",
        )
        .expect("it seals");
        assert_eq!(
            open(&key, placement(4, b"fedcba9876543210", "m-1"), &sealed),
            None,
            "a different storage id"
        );
        assert_eq!(
            open(&key, placement(4, b"0123456789abcdef", "m-2"), &sealed),
            None,
            "a different sender id"
        );
    }

    #[test]
    fn another_tenants_row_does_not_open() {
        let key = key(7);
        let at = placement(4, b"0123456789abcdef", "m-1");
        let sealed = seal(&key, at, b"what was said").expect("it seals");
        let elsewhere = Placement { scope: 2, ..at };
        assert_eq!(open(&key, elsewhere, &sealed), None);
    }

    #[test]
    fn a_truncated_column_does_not_panic() {
        let key = key(7);
        let at = placement(4, b"0123456789abcdef", "m-1");
        let sealed = seal(&key, at, b"what was said").expect("it seals");
        for cut in 0..sealed.len() {
            assert_eq!(open(&key, at, &sealed[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn the_key_generation_leads_the_column() {
        // Layout matters beyond this module: a rotation reads the generation
        // off the front of the column to pick a key, before anything else.
        let key = key(7);
        let at = placement(4, b"0123456789abcdef", "m-1");
        let sealed = seal(&key, at, b"x").expect("it seals");
        assert_eq!(sealed.first(), Some(&CURRENT_KEY_ID));
        assert!(sealed.len() > HEADER_BYTES, "a header and a body");
    }

    #[test]
    fn a_row_sealed_by_another_generation_is_left_alone() {
        // Not opened with today's key on the assumption the byte is noise: the
        // point of the generation is that a row it does not name is somebody
        // else's to open.
        let key = key(7);
        let at = placement(4, b"0123456789abcdef", "m-1");
        let mut sealed = seal(&key, at, b"x").expect("it seals");
        sealed[0] = CURRENT_KEY_ID.wrapping_add(1);
        assert_eq!(open(&key, at, &sealed), None);
    }
}
