//! Signing a URL, and the key that signs it.
//!
//! The signature covers the method, the key and the expiry, so a `GET` grant
//! cannot be replayed as a `PUT`, a grant for one object cannot be pointed at
//! another, and an expired grant cannot be revived by editing the timestamp.
//!
//! Comparison is constant-time: a signature check that leaks its progress
//! through timing is a signature check an attacker can walk.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use starling_runtime::serve::ServiceError;
use subtle::ConstantTimeEq as _;

/// A URL signature, hex-encoded.
pub type Signature = String;

/// Sign a grant.
#[must_use]
pub fn sign(secret: &[u8], method: &str, key: &str, expires_at_ms: u64) -> Signature {
    let Ok(mut mac) = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(method.as_bytes());
    mac.update(b"\0");
    mac.update(key.as_bytes());
    mac.update(b"\0");
    mac.update(&expires_at_ms.to_be_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether a grant is valid and unexpired.
#[must_use]
pub fn verify(
    secret: &[u8],
    method: &str,
    key: &str,
    expires_at_ms: u64,
    signature: &str,
    now_ms: u64,
) -> bool {
    if now_ms > expires_at_ms {
        return false;
    }
    let expected = sign(secret, method, key, expires_at_ms);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

/// The signing key, generated on first boot and reused after.
///
/// Stable across restarts on purpose: regenerating it would invalidate every
/// outstanding grant, which looks to a user like every download breaking at
/// once.
pub fn secret(data_dir: &std::path::Path) -> Result<Vec<u8>, ServiceError> {
    let path = data_dir.join("files-signing.key");
    if let Ok(existing) = std::fs::read(&path)
        && existing.len() >= 32
    {
        return Ok(existing);
    }
    let mut key = vec![0_u8; 32];
    {
        use rand::Rng as _;
        rand::rng().fill_bytes(&mut key);
    }
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(&path, &key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_get_grant_cannot_be_replayed_as_a_put() {
        // The method is in the signature precisely so a read capability is not
        // silently a write one.
        let secret = b"secret";
        let signature = sign(secret, "GET", "1/file", 10_000);
        assert!(verify(secret, "GET", "1/file", 10_000, &signature, 5_000));
        assert!(!verify(secret, "PUT", "1/file", 10_000, &signature, 5_000));
    }

    #[test]
    fn a_grant_for_one_object_cannot_be_pointed_at_another() {
        let secret = b"secret";
        let signature = sign(secret, "GET", "1/mine", 10_000);
        assert!(!verify(secret, "GET", "1/yours", 10_000, &signature, 5_000));
    }

    #[test]
    fn an_expired_grant_is_refused_even_with_a_valid_signature() {
        let secret = b"secret";
        let signature = sign(secret, "GET", "1/file", 10_000);
        assert!(!verify(secret, "GET", "1/file", 10_000, &signature, 20_000));
    }

    #[test]
    fn editing_the_expiry_invalidates_the_signature() {
        let secret = b"secret";
        let signature = sign(secret, "GET", "1/file", 10_000);
        assert!(!verify(secret, "GET", "1/file", 99_000, &signature, 5_000));
    }
}
