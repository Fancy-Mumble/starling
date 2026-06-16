//! Obtaining the server's TLS identity (Strategy).
//!
//! Mumble servers are conventionally self-signed: clients identify a server by
//! its certificate fingerprint (trust-on-first-use), not by a CA chain, and the
//! e2e fixture connects with validation disabled. So generating one on first
//! boot is the normal path, not a fallback — which is why both are
//! [`CertificateSource`] implementations rather than a success path and an
//! error path.

use std::path::{Path, PathBuf};

/// The server's TLS certificate and private key.
///
/// Not `Clone`: `PrivateKeyDer` deliberately is not, so key material is not
/// duplicated around the process by accident.
#[derive(Debug)]
pub struct TlsIdentity {
    /// Certificate chain, leaf first.
    pub certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// Private key for the leaf certificate.
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

/// Attach the path an I/O error happened at, so `?` can carry it.
///
/// Six call sites wrote the `TlsError::Io { path, source }` struct literal by
/// hand. `#[from]` cannot replace it — a bare `io::Error` says "No such file or
/// directory" without saying *which* file, which is the only detail an operator
/// needs — so the context stays and the ceremony goes.
pub trait PathContext<T> {
    /// Convert into [`TlsError::Io`], recording `path`.
    ///
    /// # Errors
    ///
    /// Propagates the receiver's error, wrapped.
    fn at(self, path: &Path) -> Result<T, TlsError>;
}

impl<T> PathContext<T> for Result<T, std::io::Error> {
    fn at(self, path: &Path) -> Result<T, TlsError> {
        self.map_err(|source| TlsError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[path = "identity_generated.rs"]
mod generated;
#[path = "identity_pem.rs"]
mod pem_file;

pub use generated::SelfSigned;
pub use pem_file::PemFiles;


use tracing::info;

/// Failures while obtaining a TLS identity.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A certificate or key file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The PEM did not contain what was expected.
    #[error("{path}: {reason}")]
    Pem {
        /// The file involved.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },
    /// A self-signed certificate could not be generated.
    #[error("failed to generate a self-signed certificate: {0}")]
    Generate(#[from] rcgen::Error),
}

/// Produces the certificate and key the listener presents.
///
/// # Contract
///
/// [`Self::available`] reports whether this source can produce an identity
/// *without side effects*, so the caller can choose between sources before any
/// of them writes to disk. A source that returns `true` and then fails from
/// [`Self::load`] is reporting a real error (unreadable file, bad PEM), not an
/// absence.
pub trait CertificateSource {
    /// A short name for logs.
    fn name(&self) -> &'static str;

    /// Whether this source can supply an identity right now.
    fn available(&self) -> bool;

    /// Produce the identity, performing any side effects (such as writing a
    /// freshly generated certificate to disk).
    fn load(&self) -> Result<TlsIdentity, TlsError>;
}

/// Load `cert`/`key`, generating a self-signed pair if neither exists.
///
/// Generation is all-or-nothing: a half-present pair is an error rather than a
/// silent regeneration, because overwriting a live server's key would change its
/// fingerprint and make every client warn about an identity change.
pub fn load_or_generate(cert: &Path, key: &Path) -> Result<TlsIdentity, TlsError> {
    let files = PemFiles::new(cert, key);
    if files.available() {
        return files.load();
    }
    if let Some(missing) = files.half_present() {
        return Err(TlsError::Pem {
            path: missing,
            reason: "half of the certificate pair is missing; refusing to regenerate \
                     (that would change the server's fingerprint)"
                .to_owned(),
        });
    }

    let generator = SelfSigned::new(cert, key);
    info!(
        source = generator.name(),
        cert = %cert.display(),
        "no certificate found; generating a self-signed one"
    );
    generator.load()
}

#[cfg(test)]
/// Shared test-only helpers for identity loading tests.
pub mod testing {
    use std::path::PathBuf;

    /// A throwaway directory that cleans itself up.
    #[derive(Debug)]
    pub struct TempDir(PathBuf);

    impl TempDir {
        /// Creates a fresh, empty directory tagged with `tag` for uniqueness.
        pub fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "starling-tls-test-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        /// Joins `name` onto this directory's path.
        pub fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TempDir;
    use super::*;

    #[test]
    fn a_missing_pair_is_generated_and_written_to_disk() {
        let dir = TempDir::new("generate");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));

        let identity = load_or_generate(&cert, &key).expect("generation should succeed");
        assert_eq!(identity.certs.len(), 1);
        assert!(
            cert.exists() && key.exists(),
            "both files must be persisted"
        );
    }

    #[test]
    fn a_generated_certificate_is_reloaded_rather_than_regenerated() {
        // The fingerprint must be stable across restarts, or every client warns
        // about an identity change on every reboot.
        let dir = TempDir::new("stable");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));

        let first = load_or_generate(&cert, &key).expect("first boot");
        let second = load_or_generate(&cert, &key).expect("second boot");
        assert_eq!(first.certs, second.certs, "certificate changed on restart");
    }

    #[test]
    fn a_half_present_pair_is_refused_rather_than_regenerated() {
        let dir = TempDir::new("half");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let _ = load_or_generate(&cert, &key).expect("generate the pair");
        std::fs::remove_file(&key).expect("remove the key");

        let err = load_or_generate(&cert, &key)
            .expect_err("a missing key must not silently regenerate the pair");
        assert!(matches!(err, TlsError::Pem { .. }));
        assert!(cert.exists(), "the surviving certificate must be untouched");
    }

    #[test]
    fn a_certificate_file_without_a_pem_block_is_rejected() {
        let dir = TempDir::new("garbage");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let _ = load_or_generate(&cert, &key).expect("generate the pair");
        std::fs::write(&cert, "not a certificate").expect("overwrite cert");

        assert!(matches!(
            load_or_generate(&cert, &key),
            Err(TlsError::Pem { .. })
        ));
    }
}
