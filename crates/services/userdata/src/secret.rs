//! Password hashing and TOTP.
//!
//! PBKDF2-HMAC-SHA256 with a per-account salt and a recorded iteration count,
//! so raising the count later does not invalidate existing passwords — the
//! stored value carries the count it was made with.
//!
//! Comparison is constant-time. A timing side channel on a password check is
//! the kind of bug that survives review precisely because the fast version
//! looks correct.

// `KeyInit` carries `new_from_slice` from hmac 0.13 on; `Mac` still carries
// `update`/`finalize`. HMAC keeps its own variable-length key handling, so
// nothing about how these keys are accepted has changed.
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;
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
/// the blocking pool — the derivation costs 1.45 s compiled without
/// optimisation and 30 ms with, and only one of those is what ships.
const _: () = assert!(
    DEFAULT_ITERATIONS >= 210_000,
    "PBKDF2-HMAC-SHA256 below 210 000 rounds is under the OWASP recommendation"
);

/// A stored password: salt, iterations and the derived key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// Random per account.
    pub salt: [u8; 16],
    /// The count this key was derived with.
    pub iterations: u32,
    /// The derived key.
    pub key: [u8; 32],
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
        Self {
            salt,
            iterations,
            key: pbkdf2_sha256(password.as_bytes(), &salt, iterations.max(1)),
        }
    }

    /// Whether `password` is the one this secret was made from.
    #[must_use]
    pub fn verify(&self, password: &str) -> bool {
        let candidate = Self::derive(password, self.salt, self.iterations);
        candidate.key.ct_eq(&self.key).into()
    }

    /// The storage form: `salt ‖ iterations ‖ key`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(52);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.iterations.to_be_bytes());
        out.extend_from_slice(&self.key);
        out
    }

    /// Read the storage form back.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 52 {
            return None;
        }
        let mut salt = [0_u8; 16];
        salt.copy_from_slice(bytes.get(..16)?);
        let mut count = [0_u8; 4];
        count.copy_from_slice(bytes.get(16..20)?);
        let mut key = [0_u8; 32];
        key.copy_from_slice(bytes.get(20..52)?);
        Some(Self {
            salt,
            iterations: u32::from_be_bytes(count),
            key,
        })
    }
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

fn totp(secret: &[u8], counter: u64) -> u32 {
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
        assert_ne!(Secret::new("hunter2").key, Secret::new("hunter2").key);
    }

    #[test]
    fn a_secret_round_trips_through_storage_with_its_iteration_count() {
        // The count travels with the value, which is what lets it be raised
        // later without locking anyone out.
        let secret = Secret::derive("pw", [7_u8; 16], 1_000);
        let restored = Secret::from_bytes(&secret.to_bytes()).expect("round trip");
        assert_eq!(restored, secret);
        assert_eq!(restored.iterations, 1_000);
        assert!(restored.verify("pw"));
    }

    #[test]
    fn a_truncated_stored_secret_is_rejected_rather_than_padded() {
        assert!(Secret::from_bytes(&[0_u8; 10]).is_none());
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
