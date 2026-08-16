//! The certificate the gateway presents, replaceable while it is listening.
//!
//! The acceptor used to be built once, before the accept loop, holding the
//! certificate by value. Every renewal was therefore a restart of the process
//! holding every client's connection -- and renewals are not rare: cert-manager
//! and Let's Encrypt rotate on a schedule nobody schedules around, and a
//! deployment that misses one starts refusing clients.
//!
//! So rustls is given a [`ResolvesServerCert`] rather than a fixed pair, and the
//! resolver reads an `ArcSwap`-shaped cell that a follower updates. The next
//! handshake presents the new chain; handshakes already completed are untouched,
//! which is right -- TLS is negotiated once per connection and there is nothing
//! to retrofit.
//!
//! # The fingerprint is the server's identity
//!
//! Mumble clients identify a server by the SHA-1 of its certificate, and a
//! client that has seen this server before will notice the change. Renewing
//! **with the same key** keeps the fingerprint, which is what cert-manager does
//! by default and what makes this transparent. Rotating to a *new key* is a
//! client-visible event whatever the server does, and no amount of hot-reloading
//! changes that; it is logged at notice for exactly that reason.
//!
//! The `directory` service announces the same fingerprint to the public server
//! list by reading the same file, so it follows without coordination here.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use starling_runtime::config::Config;
use starling_runtime::log::{Category, LogEvent, Logger};

/// The certificate and key paths a configuration names.
///
/// Resolved rather than read straight out of `[gateway.tls]` because both keys
/// are optional and default into the data directory, and the follower has to
/// compare *resolved* paths to know whether anything moved.
#[must_use]
pub fn paths(config: &Config) -> (PathBuf, PathBuf) {
    let data_dir = &config.runtime.data_dir;
    (
        config
            .gateway
            .tls
            .cert
            .clone()
            .unwrap_or_else(|| data_dir.join("cert.pem")),
        config
            .gateway
            .tls
            .key
            .clone()
            .unwrap_or_else(|| data_dir.join("key.pem")),
    )
}

/// Hands rustls the certificate in force at the moment of each handshake.
#[derive(Debug)]
pub struct CertResolver {
    current: Mutex<Arc<CertifiedKey>>,
}

impl CertResolver {
    /// A resolver presenting `initial`.
    #[must_use]
    pub fn new(initial: Arc<CertifiedKey>) -> Self {
        Self {
            current: Mutex::new(initial),
        }
    }

    /// Present `next` from the next handshake onwards.
    pub fn replace(&self, next: Arc<CertifiedKey>) {
        match self.current.lock() {
            Ok(mut held) => *held = next,
            // A poisoned lock must not stop the server presenting a
            // certificate; the previous one is still valid until it expires.
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }

    /// The certificate in force.
    #[must_use]
    pub fn current(&self) -> Arc<CertifiedKey> {
        match self.current.lock() {
            Ok(held) => Arc::clone(&held),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // No SNI branching: Mumble has one identity per server, and choosing by
        // requested name would be a second notion of identity alongside the
        // fingerprint clients actually pin.
        Some(self.current())
    }
}

/// Build a [`CertifiedKey`] from the pair at `cert`/`key`.
///
/// Generates a self-signed pair when neither file exists, and refuses when
/// exactly one does -- the same rule the boot path follows, because
/// regenerating over half a pair would change the server's fingerprint.
///
/// # Errors
///
/// Whatever `starling_crypto` reports, plus a signing-key error when the file
/// holds a key this build cannot use.
pub fn load(cert: &std::path::Path, key: &std::path::Path) -> Result<Arc<CertifiedKey>, String> {
    let identity = starling_crypto::identity::load_or_generate(cert, key)
        .map_err(|error| error.to_string())?;
    let provider = rustls::crypto::CryptoProvider::get_default().map_or_else(
        || Arc::new(rustls::crypto::ring::default_provider()),
        Arc::clone,
    );
    let signing = provider
        .key_provider
        .load_private_key(identity.key)
        .map_err(|error| format!("{}: {error}", key.display()))?;
    Ok(Arc::new(CertifiedKey::new(identity.certs, signing)))
}

/// The SHA-1 fingerprint a Mumble client identifies this server by.
///
/// SHA-1 because that is what the protocol specifies and what every client
/// compares against; it is an identifier here, not a security claim.
#[must_use]
pub fn fingerprint(certified: &CertifiedKey) -> String {
    use sha1::Digest as _;
    let Some(leaf) = certified.cert.first() else {
        return String::new();
    };
    let digest = sha1::Sha1::digest(leaf.as_ref());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Keep `resolver` following `[gateway.tls]` in `cell`.
///
/// Reloading is deliberately **not** limited to a changed path: cert-manager
/// renews in place, so the common case is the same two filenames holding a new
/// certificate. Every reload therefore re-reads the pair, and a load that
/// produces the same fingerprint is silently kept rather than announced.
pub fn follow(
    cell: &starling_runtime::live::ConfigCell,
    resolver: Arc<CertResolver>,
    logger: Logger,
) {
    let mut configs = cell.subscribe();
    drop(tokio::spawn(async move {
        while configs.changed().await.is_ok() {
            let (cert, key) = {
                let config = configs.borrow_and_update();
                paths(&config)
            };
            let before = fingerprint(&resolver.current());
            match load(&cert, &key) {
                Ok(certified) => {
                    let after = fingerprint(&certified);
                    if after == before {
                        continue;
                    }
                    resolver.replace(certified);
                    // Notice, not info: a changed fingerprint is what a
                    // returning client is warned about, so an operator needs to
                    // be able to find the moment it happened.
                    logger.log(
                        LogEvent::notice(Category::Security, "server certificate replaced")
                            .with("path", cert.display().to_string())
                            .with("fingerprint", after),
                    );
                }
                Err(error) => {
                    // The certificate in force stays in force: a reload that
                    // could not read the new pair must not leave the gateway
                    // unable to complete a handshake.
                    logger.log(
                        LogEvent::warning(Category::Security, "server certificate unchanged")
                            .with("path", cert.display().to_string())
                            .with("error", error),
                    );
                }
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("starling-certs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    fn provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn a_generated_pair_loads_and_has_a_fingerprint() {
        provider();
        let dir = scratch("generated");
        let certified = load(&dir.join("cert.pem"), &dir.join("key.pem")).expect("generated");
        let fingerprint = fingerprint(&certified);
        assert_eq!(fingerprint.len(), 40, "SHA-1 is 20 bytes as hex");
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn replacing_the_certificate_changes_what_the_next_handshake_is_offered() {
        provider();
        let first = scratch("replace-first");
        let second = scratch("replace-second");
        let one = load(&first.join("cert.pem"), &first.join("key.pem")).expect("generated");
        let two = load(&second.join("cert.pem"), &second.join("key.pem")).expect("generated");
        assert_ne!(
            fingerprint(&one),
            fingerprint(&two),
            "two self-signed pairs must differ, or this test proves nothing"
        );

        let resolver = CertResolver::new(Arc::clone(&one));
        assert_eq!(fingerprint(&resolver.current()), fingerprint(&one));
        resolver.replace(Arc::clone(&two));
        assert_eq!(fingerprint(&resolver.current()), fingerprint(&two));
    }

    #[test]
    fn renewing_in_place_is_picked_up_from_the_same_paths() {
        // cert-manager's actual behaviour: the filenames do not change, the
        // bytes do. A follower keyed on the path would never notice.
        provider();
        let dir = scratch("renew-in-place");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let before = fingerprint(&load(&cert, &key).expect("generated"));

        std::fs::remove_file(&cert).expect("removable");
        std::fs::remove_file(&key).expect("removable");
        let after = fingerprint(&load(&cert, &key).expect("regenerated"));

        assert_ne!(before, after, "the same paths now hold a different pair");
    }

    #[test]
    fn half_a_pair_is_refused_rather_than_regenerated() {
        // Regenerating over half a pair would change the server's fingerprint,
        // which to every client that has connected before looks exactly like a
        // man in the middle.
        provider();
        let dir = scratch("half-pair");
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        let _ = load(&cert, &key).expect("generated");
        std::fs::remove_file(&key).expect("removable");

        let error = load(&cert, &key).expect_err("half a pair must be refused");
        assert!(error.contains("half"), "{error}");
    }

    #[test]
    fn the_paths_default_into_the_data_directory() {
        let mut config = Config::with_defaults(std::path::Path::new("/run/starling"));
        config.runtime.data_dir = PathBuf::from("/var/lib/starling");
        let (cert, key) = paths(&config);
        assert_eq!(cert, PathBuf::from("/var/lib/starling/cert.pem"));
        assert_eq!(key, PathBuf::from("/var/lib/starling/key.pem"));
    }
}
