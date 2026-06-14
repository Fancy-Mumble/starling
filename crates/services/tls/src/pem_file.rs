//! Load an identity from PEM files on disk.

use crate::TlsIdentity;
use std::path::{Path, PathBuf};

use tracing::info;

use crate::{CertificateSource, PathContext, TlsError};

/// A certificate/key pair read from two PEM files.
#[derive(Debug)]
pub struct PemFiles {
    cert: PathBuf,
    key: PathBuf,
}

impl PemFiles {
    /// Point at a certificate and key path.
    pub fn new(cert: &Path, key: &Path) -> Self {
        Self {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
        }
    }

    /// The path that is missing when exactly one of the pair exists.
    ///
    /// Distinguishing "half present" from "absent" is what stops a lost key
    /// from silently regenerating the server's identity.
    pub fn half_present(&self) -> Option<PathBuf> {
        match (self.cert.exists(), self.key.exists()) {
            (true, false) => Some(self.key.clone()),
            (false, true) => Some(self.cert.clone()),
            _ => None,
        }
    }
}

impl CertificateSource for PemFiles {
    fn name(&self) -> &'static str {
        "pem-files"
    }

    fn available(&self) -> bool {
        self.cert.exists() && self.key.exists()
    }

    fn load(&self) -> Result<TlsIdentity, TlsError> {
        let cert_pem = std::fs::read(&self.cert).at(&self.cert)?;
        let key_pem = std::fs::read(&self.key).at(&self.key)?;

        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .at(&self.cert)?;
        if certs.is_empty() {
            return Err(TlsError::Pem {
                path: self.cert.clone(),
                reason: "no CERTIFICATE block found".to_owned(),
            });
        }

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .at(&self.key)?
            .ok_or_else(|| TlsError::Pem {
                path: self.key.clone(),
                reason: "no PRIVATE KEY block found".to_owned(),
            })?;

        info!(cert = %self.cert.display(), chain_len = certs.len(), "loaded certificate");
        Ok(TlsIdentity { certs, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SelfSigned;
    use crate::testing::TempDir;

    fn generated(dir: &TempDir) -> (PathBuf, PathBuf) {
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let _ = SelfSigned::new(&cert, &key)
            .load()
            .expect("generation should succeed");
        (cert, key)
    }

    #[test]
    fn an_absent_pair_is_reported_as_unavailable_not_half_present() {
        let dir = TempDir::new("absent");
        let files = PemFiles::new(&dir.join("cert.pem"), &dir.join("key.pem"));
        assert!(!files.available());
        assert_eq!(files.half_present(), None);
    }

    #[test]
    fn a_complete_pair_is_available() {
        let dir = TempDir::new("complete");
        let (cert, key) = generated(&dir);
        let files = PemFiles::new(&cert, &key);
        assert!(files.available());
        assert_eq!(files.half_present(), None);
    }

    #[test]
    fn a_missing_key_is_reported_as_half_present() {
        let dir = TempDir::new("no-key");
        let (cert, key) = generated(&dir);
        std::fs::remove_file(&key).expect("remove key");

        let files = PemFiles::new(&cert, &key);
        assert!(!files.available());
        assert_eq!(files.half_present(), Some(key));
    }

    #[test]
    fn a_missing_certificate_is_reported_as_half_present() {
        let dir = TempDir::new("no-cert");
        let (cert, key) = generated(&dir);
        std::fs::remove_file(&cert).expect("remove cert");

        let files = PemFiles::new(&cert, &key);
        assert!(files.half_present().is_some());
    }

    #[test]
    fn a_written_pair_loads_back_identically() {
        let dir = TempDir::new("roundtrip");
        let (cert, key) = generated(&dir);
        let identity = PemFiles::new(&cert, &key).load().expect("load");
        assert_eq!(identity.certs.len(), 1);
    }

    #[test]
    fn a_certificate_without_a_pem_block_is_rejected() {
        let dir = TempDir::new("bad-cert");
        let (cert, key) = generated(&dir);
        std::fs::write(&cert, "not a certificate").expect("overwrite");
        assert!(matches!(
            PemFiles::new(&cert, &key).load(),
            Err(TlsError::Pem { .. })
        ));
    }

    #[test]
    fn a_key_without_a_pem_block_is_rejected() {
        let dir = TempDir::new("bad-key");
        let (cert, key) = generated(&dir);
        std::fs::write(&key, "not a key").expect("overwrite");
        assert!(matches!(
            PemFiles::new(&cert, &key).load(),
            Err(TlsError::Pem { .. })
        ));
    }
}
