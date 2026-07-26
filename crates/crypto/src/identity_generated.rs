//! Generate a self-signed identity and persist it.

use crate::identity::TlsIdentity;
use std::path::{Path, PathBuf};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::warn;

use crate::identity::{CertificateSource, PathContext, TlsError};

/// A freshly generated self-signed certificate, written to disk.
///
/// Persisting it is the point: the fingerprint must be stable across restarts,
/// or every client warns about an identity change on every reboot.
#[derive(Debug)]
pub struct SelfSigned {
    cert: PathBuf,
    key: PathBuf,
}

impl SelfSigned {
    /// Generate into these paths.
    pub fn new(cert: &Path, key: &Path) -> Self {
        Self {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
        }
    }

    fn write(&self, path: &Path, contents: &str) -> Result<(), TlsError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).at(parent)?;
        }
        std::fs::write(path, contents).at(path)
    }
}

impl CertificateSource for SelfSigned {
    fn name(&self) -> &'static str {
        "self-signed"
    }

    fn available(&self) -> bool {
        // Always: generation needs nothing but a writable directory, and a
        // directory that turns out not to be writable is a real error from
        // `load`, not an absence.
        true
    }

    fn load(&self) -> Result<TlsIdentity, TlsError> {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;

        self.write(&self.cert, &generated.cert.pem())?;
        self.write(&self.key, &generated.key_pair.serialize_pem())?;

        warn!(
            cert = %self.cert.display(),
            "generated a self-signed certificate; clients will see an untrusted identity"
        );

        Ok(TlsIdentity {
            certs: vec![CertificateDer::from(generated.cert)],
            // `serialize_der` emits PKCS#8, which is what rustls wants.
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PemFiles;
    use crate::identity::testing::TempDir;

    #[test]
    fn generation_writes_both_files() {
        let dir = TempDir::new("gen-writes");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));

        let identity = SelfSigned::new(&cert, &key).load().expect("generate");
        assert_eq!(identity.certs.len(), 1);
        assert!(cert.exists() && key.exists());
    }

    #[test]
    fn the_written_pair_is_loadable_by_the_file_source() {
        // Generation and loading must agree, or the second boot fails.
        let dir = TempDir::new("gen-loadable");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));

        let generated = SelfSigned::new(&cert, &key).load().expect("generate");
        let loaded = PemFiles::new(&cert, &key).load().expect("load");
        assert_eq!(generated.certs, loaded.certs);
    }

    #[test]
    fn a_missing_parent_directory_is_created() {
        let dir = TempDir::new("gen-mkdir");
        let nested = dir.join("deeply/nested");
        let (cert, key) = (nested.join("cert.pem"), nested.join("key.pem"));

        let _ = SelfSigned::new(&cert, &key).load().expect("generate");
        assert!(cert.exists());
    }

    #[test]
    fn two_generations_produce_different_certificates() {
        // Which is exactly why `load_or_generate` must not regenerate over an
        // existing pair.
        let dir = TempDir::new("gen-differs");
        let first = SelfSigned::new(&dir.join("a.pem"), &dir.join("a.key"))
            .load()
            .expect("generate");
        let second = SelfSigned::new(&dir.join("b.pem"), &dir.join("b.key"))
            .load()
            .expect("generate");
        assert_ne!(first.certs, second.certs);
    }
}
