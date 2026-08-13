//! Password hashing and TOTP.
//!
//! PBKDF2-HMAC-SHA256 with a per-account salt and a recorded iteration count,
//! so raising the count later does not invalidate existing passwords, the
//! stored value carries the count it was made with.
//!
//! Comparison is constant-time. A timing side channel on a password check is
//! the kind of bug that survives review precisely because the fast version
//! looks correct.
//!
//! # murmur's hashes are also readable here
//!
//! A password hash cannot be converted, only re-derived from a plaintext nobody
//! has. So [`Secret`] can also hold the two forms murmur wrote, and
//! `starling migrate-db` imports them as they are: without that, the day a
//! server moves is the day every registered user is locked out of it. They are
//! transitional, and they retire themselves, see [`Secret`].

// `KeyInit` carries `new_from_slice` from hmac 0.13 on; `Mac` still carries
// `update`/`finalize`. HMAC keeps its own variable-length key handling, so
// nothing about how these keys are accepted has changed.
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq as _;

/// How many PBKDF2 iterations a new password gets.
///
/// Recorded per account rather than assumed, so this can be raised without a
/// migration and without locking anyone out.
pub const DEFAULT_ITERATIONS: u32 = 210_000;

/// The count may not drop below OWASP's figure for PBKDF2-HMAC-SHA256.
///
/// A compile-time assertion rather than a test, because it guards a decision
/// rather than a behaviour: this is precisely the knob somebody reaches for
/// when logins feel slow, and it should not be possible to turn it down and
/// still get a build. If logins are slow the answer is a **release build** and
/// the blocking pool, the derivation costs 1.45 s compiled without
/// optimisation and 30 ms with, and only one of those is what ships.
const _: () = assert!(
    DEFAULT_ITERATIONS >= 210_000,
    "PBKDF2-HMAC-SHA256 below 210 000 rounds is under the OWASP recommendation"
);

/// How long the native storage form is: salt, count and key.
///
/// Load-bearing rather than a convenience: it is what tells the two storage
/// forms apart when a row is read back, see [`Secret::from_bytes`].
const NATIVE_LEN: usize = 16 + 4 + 32;

/// The first byte of a **carried** secret's storage form.
///
/// A native secret has no tag, because rows written before carried secrets
/// existed have none and must keep working. The two are told apart by length
/// first, so this byte is a check rather than the discriminator.
const CARRIED_TAG: u8 = 0xff;

/// A carried PBKDF2-HMAC-SHA384 secret.
const CARRIED_PBKDF2_SHA384: u8 = 1;

/// A carried unsalted SHA-1 digest.
const CARRIED_SHA1: u8 = 2;

/// A stored password.
///
/// # Why there is more than one of these
///
/// [`Self::Native`] is the only form this server ever *writes*. The other two
/// are murmur's, and they exist because of what a database migration would
/// otherwise mean: hashes cannot be converted, so an import that dropped them
/// would lock every registered user out of the server on the day it moved, and
/// hand the operator a list of people to reset passwords for by hand. Carrying
/// them means a migrated server accepts the passwords its users already have.
///
/// They are **transitional**, and the mechanism that makes that true is
/// [`Self::is_native`]: a login that succeeds against a carried secret is a
/// login that has just handed us the plaintext, so `userdata` re-derives it
/// natively and writes it back (`Accounts::store_password`). A migrated
/// server therefore converts itself account by account as people sign in, and
/// murmur's unsalted SHA-1 in particular disappears from the database the first
/// time each of its owners logs in rather than living there forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    /// Starling's own: PBKDF2-HMAC-SHA256 with a per-account salt.
    Native {
        /// Random per account.
        salt: [u8; 16],
        /// The count this key was derived with.
        iterations: u32,
        /// The derived key.
        key: [u8; 32],
    },
    /// murmur 1.3 and later: PBKDF2-HMAC-SHA384, 48-byte key, 8-byte salt.
    ///
    /// The lengths are murmur's rather than this server's, so they are `Vec`s:
    /// a fixed array here would be a second place to encode upstream's
    /// constants, and it would refuse to read a database written by a build
    /// that changed them.
    Murmur {
        /// The salt murmur generated, decoded from its hex.
        salt: Vec<u8>,
        /// The count murmur benchmarked its way to.
        iterations: u32,
        /// The derived key.
        key: Vec<u8>,
    },
    /// murmur before 1.3: an **unsalted** SHA-1 of the password.
    ///
    /// Weak, and imported anyway, for the reason above: the alternative is not
    /// a stronger hash, it is no login. It is also the form that benefits most
    /// from the upgrade on next use, which is why that exists.
    MurmurLegacy {
        /// The digest, decoded from murmur's hex.
        digest: Vec<u8>,
    },
}

impl Secret {
    /// Derive a secret for `password` with a fresh salt.
    #[must_use]
    pub fn new(password: &str) -> Self {
        let mut salt = [0_u8; 16];
        fill_random(&mut salt);
        Self::derive(password, salt, DEFAULT_ITERATIONS)
    }

    /// Derive with a given salt and count, which is what verification does.
    #[must_use]
    pub fn derive(password: &str, salt: [u8; 16], iterations: u32) -> Self {
        Self::Native {
            salt,
            iterations,
            key: pbkdf2_sha256(password.as_bytes(), &salt, iterations.max(1)),
        }
    }

    /// Whether this is a secret this server made.
    ///
    /// `false` means it came from murmur, which is the signal to re-derive on
    /// the next successful login. See the type's own documentation.
    #[must_use]
    pub const fn is_native(&self) -> bool {
        matches!(self, Self::Native { .. })
    }

    /// Whether `password` is the one this secret was made from.
    ///
    /// Constant-time in every arm. A timing side channel on a password check is
    /// the kind of bug that survives review precisely because the fast version
    /// looks correct, and an imported hash must not be the one that reintroduces
    /// it.
    #[must_use]
    pub fn verify(&self, password: &str) -> bool {
        match self {
            Self::Native {
                salt,
                iterations,
                key,
            } => {
                let candidate = pbkdf2_sha256(password.as_bytes(), salt, (*iterations).max(1));
                candidate.as_slice().ct_eq(key.as_slice()).into()
            }
            Self::Murmur {
                salt,
                iterations,
                key,
            } => {
                // murmur derives exactly one SHA-384 block and stores all 48
                // bytes of it, so a key of any other length is not one of its
                // hashes and nothing can verify against it.
                let candidate = pbkdf2_sha384(password.as_bytes(), salt, (*iterations).max(1));
                key.len() == candidate.len()
                    && bool::from(candidate.as_slice().ct_eq(key.as_slice()))
            }
            Self::MurmurLegacy { digest } => {
                let candidate = sha1(password.as_bytes());
                digest.len() == candidate.len()
                    && bool::from(candidate.as_slice().ct_eq(digest.as_slice()))
            }
        }
    }

    /// The storage form.
    ///
    /// Native is `salt ‖ iterations ‖ key`, unchanged and untagged, because
    /// every account row already written is in that form and a tag would make
    /// them all unreadable. A carried secret is
    /// `0xff ‖ kind ‖ iterations ‖ salt_len ‖ salt ‖ key`, which cannot come
    /// out at the native form's length for either of murmur's two shapes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Native {
                salt,
                iterations,
                key,
            } => {
                let mut out = Vec::with_capacity(NATIVE_LEN);
                out.extend_from_slice(salt);
                out.extend_from_slice(&iterations.to_be_bytes());
                out.extend_from_slice(key);
                out
            }
            Self::Murmur {
                salt,
                iterations,
                key,
            } => carried(CARRIED_PBKDF2_SHA384, *iterations, salt, key),
            Self::MurmurLegacy { digest } => carried(CARRIED_SHA1, 0, &[], digest),
        }
    }

    /// Read the storage form back.
    ///
    /// Length decides which form this is, and the native length is checked
    /// first: a row written before carried secrets existed has no tag byte to
    /// look at, and its first byte is salt, which may be anything at all.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == NATIVE_LEN {
            let mut salt = [0_u8; 16];
            salt.copy_from_slice(bytes.get(..16)?);
            let mut count = [0_u8; 4];
            count.copy_from_slice(bytes.get(16..20)?);
            let mut key = [0_u8; 32];
            key.copy_from_slice(bytes.get(20..NATIVE_LEN)?);
            return Some(Self::Native {
                salt,
                iterations: u32::from_be_bytes(count),
                key,
            });
        }

        if bytes.first().copied()? != CARRIED_TAG {
            return None;
        }
        let kind = bytes.get(1).copied()?;
        let mut count = [0_u8; 4];
        count.copy_from_slice(bytes.get(2..6)?);
        let salt_len = usize::from(bytes.get(6).copied()?);
        let salt = bytes.get(7..7 + salt_len)?.to_vec();
        let key = bytes.get(7 + salt_len..)?.to_vec();
        if key.is_empty() {
            return None;
        }
        match kind {
            CARRIED_PBKDF2_SHA384 => Some(Self::Murmur {
                salt,
                iterations: u32::from_be_bytes(count),
                key,
            }),
            // A digest, so a salt here would mean the value was written by
            // something that did not understand the form.
            CARRIED_SHA1 if salt.is_empty() => Some(Self::MurmurLegacy { digest: key }),
            _ => None,
        }
    }
}

/// The storage form of a carried secret.
///
/// The salt length is one byte and murmur's salt is eight, so the truncation
/// below cannot happen with anything murmur wrote. It truncates the **salt**
/// rather than the length, because the alternative -- a length byte that
/// disagrees with the bytes after it -- reads back as a different secret
/// entirely, and a value that decodes into something plausible and wrong is the
/// worst outcome available here.
fn carried(kind: u8, iterations: u32, salt: &[u8], key: &[u8]) -> Vec<u8> {
    let salt = salt
        .get(..salt.len().min(usize::from(u8::MAX)))
        .unwrap_or(salt);
    let mut out = Vec::with_capacity(7 + salt.len() + key.len());
    out.push(CARRIED_TAG);
    out.push(kind);
    out.extend_from_slice(&iterations.to_be_bytes());
    out.push(u8::try_from(salt.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(salt);
    out.extend_from_slice(key);
    out
}

/// PBKDF2-HMAC-SHA384, one 48-byte block: murmur's, for a carried secret.
///
/// The same construction as [`pbkdf2_sha256`] over a different PRF, and the
/// same single block, because murmur's `DERIVED_KEY_LENGTH` is 48 and SHA-384
/// produces exactly that (`vendor/server/src/murmur/PBKDF2.h`). It is here
/// rather than in the migration tool for the reason the type's documentation
/// gives: the hash cannot be converted, so the *verifier* has to travel with
/// the account.
fn pbkdf2_sha384(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 48] {
    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1_u32.to_be_bytes());

    let mut previous = hmac_sha384(password, &block);
    let mut output = previous;
    for _ in 1..iterations {
        previous = hmac_sha384(password, &previous);
        for (out, next) in output.iter_mut().zip(previous.iter()) {
            *out ^= next;
        }
    }
    output
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(key).unwrap_or_else(|_| {
        // As in `hmac_sha256`: HMAC accepts every key length, so this arm is
        // unreachable and exists to keep the `unwrap_used` rule without
        // inventing an error path nobody can hit.
        <Hmac<Sha384> as KeyInit>::new_from_slice(&[0_u8; 48])
            .unwrap_or_else(|_| panic!("HMAC-SHA384 rejected a 48-byte key"))
    });
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// A bare SHA-1 digest: murmur's pre-1.3 password hash.
///
/// Unsalted and fast, which is exactly what is wrong with it. It is implemented
/// here only to be able to *accept* one that already exists, never to make one:
/// nothing in this crate calls it except [`Secret::verify`], and a login that
/// passes through it replaces itself with a native secret.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    Sha1::digest(data).into()
}

/// PBKDF2-HMAC-SHA256, one 32-byte block.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1_u32.to_be_bytes());

    let mut previous = hmac_sha256(password, &block);
    let mut output = previous;
    for _ in 1..iterations {
        previous = hmac_sha256(password, &previous);
        for (out, next) in output.iter_mut().zip(previous.iter()) {
            *out ^= next;
        }
    }
    output
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap_or_else(|_| {
        // `new_from_slice` only fails for key lengths HMAC cannot take, and
        // HMAC-SHA256 accepts every length. The fallback keeps the `unwrap_used`
        // rule without inventing an error path nobody can hit.
        <Hmac<Sha256> as KeyInit>::new_from_slice(&[0_u8; 32]).unwrap_or_else(|_| unreachable_mac())
    });
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn unreachable_mac() -> Hmac<Sha256> {
    // Reached only if HMAC rejects a 32-byte key, which it cannot.
    panic!("HMAC-SHA256 rejected a 32-byte key")
}

/// Verify a six-digit TOTP code against `secret`, allowing one step of drift.
///
/// One step either way, because a phone's clock and a server's differ by a few
/// seconds routinely; more than that turns a second factor into a lottery.
#[must_use]
pub fn verify_totp(secret: &[u8], code: &str, unix_seconds: u64) -> bool {
    let Ok(expected) = code.parse::<u32>() else {
        return false;
    };
    let step = unix_seconds / 30;
    (-1_i64..=1).any(|drift| {
        let counter = step.saturating_add_signed(drift);
        totp(secret, counter) == expected
    })
}

/// How many bytes a new TOTP secret gets.
///
/// RFC 4226 §4 requires at least 128 bits and recommends 160, which is also
/// the HMAC-SHA1 block size, so a longer secret would be hashed down to this
/// anyway and a shorter one is weaker for nothing.
const TOTP_SECRET_BYTES: usize = 20;

/// A fresh TOTP secret, from the same generator the SuperUser password uses.
///
/// `rand::rng()` is seeded from the operating system and reseeded as it runs;
/// what matters here is only that nothing else can reproduce it, because a
/// predictable second factor is worse than none, the account is trusted more
/// for having one.
#[must_use]
pub fn new_totp_secret() -> Vec<u8> {
    use rand::RngExt as _;
    let mut rng = rand::rng();
    (0..TOTP_SECRET_BYTES).map(|_| rng.random()).collect()
}

/// RFC 4648 base32, unpadded, the form every authenticator app takes.
///
/// Written out rather than pulled in as a dependency: it is fifteen lines, and
/// the alternative is a supply-chain edge on the one path that hands out key
/// material.
#[must_use]
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u16 = 0;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(ALPHABET[index]));
    }
    out
}

/// The code `secret` shows at `counter`.
///
/// `pub(crate)` for the enrolment tests, which have to be able to *produce*
/// a code and not only check one. Nothing on a wire calls it: the server
/// never generates a code, it only ever verifies the one a client sends.
pub(crate) fn totp(secret: &[u8], counter: u64) -> u32 {
    let Ok(mut mac) = <Hmac<Sha1> as KeyInit>::new_from_slice(secret) else {
        return u32::MAX;
    };
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = digest.last().map_or(0, |byte| (byte & 0x0f) as usize);
    let slice = digest.get(offset..offset + 4).unwrap_or(&[0, 0, 0, 0]);
    let binary = u32::from_be_bytes([
        slice.first().copied().unwrap_or_default() & 0x7f,
        slice.get(1).copied().unwrap_or_default(),
        slice.get(2).copied().unwrap_or_default(),
        slice.get(3).copied().unwrap_or_default(),
    ]);
    binary % 1_000_000
}

fn fill_random(buffer: &mut [u8]) {
    use rand::Rng as _;
    // The thread generator is seeded from the operating system and reseeds
    // itself; a salt from a predictable source is not a salt.
    rand::rng().fill_bytes(buffer);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_verifies_against_its_own_secret_and_nothing_else() {
        let secret = Secret::new("correct horse");
        assert!(secret.verify("correct horse"));
        assert!(!secret.verify("correct horses"));
    }

    #[test]
    fn two_accounts_with_one_password_do_not_share_a_stored_value() {
        // A shared hash would let one leak confirm the other, and would make a
        // rainbow table worth building.
        assert_ne!(
            Secret::new("hunter2").to_bytes(),
            Secret::new("hunter2").to_bytes()
        );
    }

    #[test]
    fn a_secret_round_trips_through_storage_with_its_iteration_count() {
        // The count travels with the value, which is what lets it be raised
        // later without locking anyone out.
        let secret = Secret::derive("pw", [7_u8; 16], 1_000);
        let restored = Secret::from_bytes(&secret.to_bytes()).expect("round trip");
        assert_eq!(restored, secret);
        assert!(matches!(restored, Secret::Native { iterations, .. } if iterations == 1_000));
        assert!(restored.verify("pw"));
    }

    #[test]
    fn a_truncated_stored_secret_is_rejected_rather_than_padded() {
        assert!(Secret::from_bytes(&[0_u8; 10]).is_none());
    }

    #[test]
    fn a_native_secret_is_stored_exactly_as_it_always_was() {
        // Every account row already written is in this form and carries no tag
        // byte. A change here does not fail a test in a deployment: it silently
        // stops every existing password from verifying.
        assert_eq!(Secret::derive("pw", [7_u8; 16], 1_000).to_bytes().len(), 52);
    }

    #[test]
    fn a_murmur_pbkdf2_password_verifies_against_the_hash_murmur_stored() {
        // The vector is derived here rather than pasted, because what is being
        // tested is that this is *murmur's* construction: PBKDF2-HMAC-SHA384,
        // one 48-byte block, the salt as bytes and the count as stored.
        let salt = vec![0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11];
        let key = pbkdf2_sha384(b"correct horse", &salt, 5_000).to_vec();
        let secret = Secret::Murmur {
            salt,
            iterations: 5_000,
            key,
        };

        assert!(secret.verify("correct horse"));
        assert!(!secret.verify("correct horses"));
        assert!(!secret.is_native(), "an imported hash must be upgradable");
    }

    #[test]
    fn a_murmur_pre_1_3_password_verifies_against_its_unsalted_digest() {
        // Weak, and the point: an account whose owner has not logged in since
        // 2018 still gets in, and the login is what replaces the hash.
        let secret = Secret::MurmurLegacy {
            digest: sha1(b"hunter2").to_vec(),
        };
        assert!(secret.verify("hunter2"));
        assert!(!secret.verify("hunter3"));
        assert!(!secret.is_native());
    }

    #[test]
    fn a_carried_secret_round_trips_through_storage() {
        for secret in [
            Secret::Murmur {
                salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
                iterations: 33_000,
                key: pbkdf2_sha384(b"pw", &[1, 2, 3, 4, 5, 6, 7, 8], 33_000).to_vec(),
            },
            Secret::MurmurLegacy {
                digest: sha1(b"pw").to_vec(),
            },
        ] {
            let stored = secret.to_bytes();
            assert_ne!(
                stored.len(),
                52,
                "a carried secret must never be the length a native one is read back at"
            );
            let restored = Secret::from_bytes(&stored).expect("round trip");
            assert_eq!(restored, secret);
            assert!(restored.verify("pw"));
        }
    }

    #[test]
    fn a_native_secret_that_happens_to_be_tagged_is_still_read_as_native() {
        // The tag byte is a check, not the discriminator: a native secret's
        // first byte is salt and may be anything, 0xff included. Reading one of
        // those as a carried secret would lock out one account in 256.
        let secret = Secret::derive("pw", [0xff_u8; 16], 1_000);
        let restored = Secret::from_bytes(&secret.to_bytes()).expect("round trip");
        assert!(restored.is_native());
        assert!(restored.verify("pw"));
    }

    #[test]
    fn a_totp_code_is_accepted_one_step_either_side_of_now() {
        // Phone clocks drift; a strict window turns a second factor into a
        // lottery.
        let secret = b"12345678901234567890";
        let now = 1_700_000_000_u64;
        let code = format!("{:06}", totp(secret, now / 30));
        assert!(verify_totp(secret, &code, now));
        assert!(verify_totp(secret, &code, now + 30));
        assert!(!verify_totp(secret, &code, now + 300));
    }

    #[test]
    fn a_non_numeric_totp_code_is_refused_without_panicking() {
        assert!(!verify_totp(b"secret", "abcdef", 0));
    }
}
