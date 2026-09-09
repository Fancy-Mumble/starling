//! A long-lived symmetric key the server holds, for data it must be able to
//! read back.
//!
//! Almost nothing here needs one. Voice keys are per session, file objects are
//! sealed under the uploader's password, and persistent chat is end-to-end by
//! construction — in every one of those the server's inability to read is the
//! feature. This exists for the one case where it is not: a channel whose
//! members have been told the server keeps their history, so that a member who
//! joins later can read what was said before they arrived.
//!
//! At-rest encryption there buys what it buys and no more. An operator reading
//! the database directory, a stolen backup, or a disk that leaves the building
//! gets bytes nobody can open. A running server, or anyone who takes the key
//! file with the database, reads everything. That is the honest description,
//! and it is why the mode is named for who holds the key.
//!
//! # The key is the data
//!
//! Lose it and the rows are gone; there is no recovery path and there is not
//! meant to be. It is generated on first boot and never rotated underneath a
//! running deployment, for the same reason
//! [`files::sign::secret`](https://docs.rs/starling-files) is stable across
//! restarts: regenerating invalidates everything at once, and the failure
//! looks like data loss rather than a configuration mistake.
//!
//! An operator with a secret manager should pass the key in by environment
//! variable instead, and back it up with the database rather than beside it.

use std::path::Path;

use base64::Engine as _;
use zeroize::Zeroize as _;

use crate::serve::ServiceError;

/// Bytes in a data key.
pub const KEY_BYTES: usize = 32;

/// A key generation, so one can be replaced without a flag day.
///
/// Stored beside every sealed row rather than assumed, because a rotation that
/// cannot say which key sealed which row is not a rotation, it is an outage
/// with extra steps. Nothing rotates yet; the byte is here so that when
/// something does, the rows written today can still be opened.
pub type KeyId = u8;

/// The generation new rows are sealed under.
pub const CURRENT_KEY_ID: KeyId = 1;

/// A key held in memory, wiped when it is dropped.
///
/// Not `Clone` and not `Debug`-printable: the whole point is that it does not
/// end up in a log line or a copy nobody is tracking.
pub struct DataKey {
    bytes: [u8; KEY_BYTES],
    id: KeyId,
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Named, never shown. A key that prints itself gets printed.
        f.debug_struct("DataKey")
            .field("id", &self.id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        // Through `zeroize` rather than a plain loop: the property that matters
        // is that the optimiser may not elide the wipe as a dead store, and
        // that is exactly what the crate exists to guarantee. Doing it by hand
        // would also mean `unsafe`, which this workspace denies.
        self.bytes.zeroize();
    }
}

impl DataKey {
    /// The key material.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }

    /// Which generation this is.
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    /// A key built from bytes a caller already has, for tests and for an
    /// operator's environment variable.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_BYTES], id: KeyId) -> Self {
        Self { bytes, id }
    }

    /// Load `<data_dir>/<name>.key`, generating it on first boot.
    ///
    /// `env` names an environment variable holding a base64 key, which wins
    /// when it is set: a deployment with a secret manager should not be made
    /// to write the key to the container's disk to satisfy this function.
    ///
    /// A file that exists but is the wrong length is an **error**, not a
    /// reason to generate a new one. Overwriting it would silently discard
    /// every row it sealed, and a truncated key file is far more likely to be
    /// a broken mount than a corrupt secret.
    pub fn load(data_dir: &Path, name: &str, env: &str) -> Result<Self, ServiceError> {
        if let Ok(encoded) = std::env::var(env) {
            let bytes = decode_base64(encoded.trim()).ok_or_else(|| {
                ServiceError::Service(format!("{env} is not base64 for {KEY_BYTES} bytes"))
            })?;
            let bytes: [u8; KEY_BYTES] = bytes.try_into().map_err(|_| {
                ServiceError::Service(format!("{env} must decode to exactly {KEY_BYTES} bytes"))
            })?;
            tracing::info!(name, "using a data key from the environment");
            return Ok(Self::from_bytes(bytes, CURRENT_KEY_ID));
        }

        let path = data_dir.join(format!("{name}.key"));
        match std::fs::read(&path) {
            Ok(existing) => {
                let bytes: [u8; KEY_BYTES] = existing.as_slice().try_into().map_err(|_| {
                    ServiceError::Service(format!(
                        "{} holds {} bytes, not {KEY_BYTES}; refusing to replace it, \
                         because generating a new one would discard everything it sealed",
                        path.display(),
                        existing.len()
                    ))
                })?;
                Ok(Self::from_bytes(bytes, CURRENT_KEY_ID))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                std::fs::create_dir_all(data_dir)?;
                write_private(&path, &key.bytes)?;
                tracing::info!(
                    path = %path.display(),
                    "generated a data key; back this up with the database, it \
                     cannot be recovered and the rows it seals cannot be read \
                     without it"
                );
                Ok(key)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// A fresh key from the system generator.
    ///
    /// An error rather than a fallback if the platform cannot produce
    /// randomness: a server that carried on regardless would seal an archive
    /// under a predictable key, and failing to boot is the better outcome.
    fn generate() -> Result<Self, ServiceError> {
        use rand::TryRng as _;

        let mut bytes = [0_u8; KEY_BYTES];
        rand::rngs::SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| {
                ServiceError::Service(format!("no system randomness for a data key: {error}"))
            })?;
        Ok(Self::from_bytes(bytes, CURRENT_KEY_ID))
    }
}

/// Write `bytes` to `path`, readable by this user alone.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

/// Windows inherits the directory's ACL, which for a service data directory is
/// the account the service runs as.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Decode standard base64, padded or not, or `None`.
///
/// Both paddings accepted because an operator pasting a secret out of a vault
/// gets whichever that vault emits, and failing on the padding would look like
/// a wrong key.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that removes itself.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("starling-data-key-{name}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temporary directory");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_key_survives_a_restart() {
        // The property everything else rests on: a server that generated a new
        // key on every boot would lose the archive on every deploy.
        let dir = TempDir::new("restart");
        let first = DataKey::load(&dir.0, "test", "STARLING_TEST_KEY_UNSET_A").expect("first boot");
        let second =
            DataKey::load(&dir.0, "test", "STARLING_TEST_KEY_UNSET_A").expect("second boot");
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn two_servers_do_not_share_a_key_by_accident() {
        let one = TempDir::new("one");
        let two = TempDir::new("two");
        let first = DataKey::load(&one.0, "test", "STARLING_TEST_KEY_UNSET_B").expect("a key");
        let second = DataKey::load(&two.0, "test", "STARLING_TEST_KEY_UNSET_B").expect("a key");
        assert_ne!(first.bytes(), second.bytes(), "generated, not derived");
    }

    #[test]
    fn a_truncated_key_file_is_an_error_and_not_a_fresh_key() {
        // Overwriting it would silently discard every row it sealed, and a
        // short key file is far more likely to be a broken mount than a
        // corrupt secret.
        let dir = TempDir::new("truncated");
        std::fs::write(dir.0.join("test.key"), b"too short").expect("a stub key");
        let result = DataKey::load(&dir.0, "test", "STARLING_TEST_KEY_UNSET_C");
        assert!(result.is_err());
    }

    #[test]
    fn a_key_does_not_print_itself() {
        // A key that prints itself gets printed, into a log that outlives it.
        let key = DataKey::from_bytes([7; KEY_BYTES], CURRENT_KEY_ID);
        let shown = format!("{key:?}");
        assert!(shown.contains("redacted"));
        assert!(!shown.contains('7'), "no key material in the rendering");
    }

    #[test]
    fn base64_round_trips_the_shapes_an_operator_will_paste() {
        assert_eq!(decode_base64("AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(decode_base64("////"), Some(vec![255, 255, 255]));
        // Both paddings, because a vault emits whichever it emits.
        assert_eq!(decode_base64("QQ=="), Some(vec![b'A']));
        assert_eq!(decode_base64("QQ"), Some(vec![b'A']));
        assert_eq!(decode_base64("not base64!"), None);
    }
}
