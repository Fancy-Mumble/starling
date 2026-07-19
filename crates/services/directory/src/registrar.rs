//! Getting the document to the list, and the seam that keeps that testable.
//!
//! The transport is a [`Registrar`] rather than an inlined HTTP call, for the
//! usual reason a port exists: everything interesting about registration, the
//! preconditions, the payload, the cadence, can then be tested without a
//! network, and the one part that cannot be is small enough to read in full.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use starling_crypto::identity::TlsIdentity;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Where the trust store lives on a Debian-family image.
///
/// Overridable through this service's `options` table, because the path differs
/// per distribution and a hard-coded one turns "not listed" into a mystery on
/// anything else.
pub const DEFAULT_TRUST_STORE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Why a registration could not be submitted.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The trust store could not be read, so the list could not be verified.
    ///
    /// Fatal rather than skipped: continuing without verification would send the
    /// registry password to whoever answered.
    #[error("reading the trust store at {path}: {reason}")]
    TrustStore {
        /// Where it was looked for.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// rustls refused the identity or the roots.
    #[error("tls configuration: {0}")]
    Tls(#[from] rustls::Error),
    /// The endpoint was not a URL this can post to.
    #[error("{0}")]
    Endpoint(String),
    /// The network failed.
    #[error("connecting to the public list: {0}")]
    Io(#[from] std::io::Error),
    /// HTTP failed.
    #[error("posting to the public list: {0}")]
    Http(#[from] hyper::Error),
    /// The request could not be built.
    #[error("building the request: {0}")]
    Request(#[from] hyper::http::Error),
    /// The list answered, and said no.
    #[error("the public list refused the registration: {status} {body}")]
    Refused {
        /// The status it answered with.
        status: StatusCode,
        /// What it said, which is the only explanation there is.
        body: String,
    },
}

/// Somewhere a registration document can be submitted.
///
/// Static dispatch: the one caller takes `&impl Registrar`, so there is no
/// reason to box a future per announcement. `+ Send` because the announcement
/// runs in a spawned task.
pub trait Registrar: std::fmt::Debug + Send + Sync {
    /// Submit one document.
    ///
    /// # Errors
    ///
    /// [`RegisterError`] when it could not be delivered, or was refused.
    fn submit(&self, body: String) -> impl Future<Output = Result<(), RegisterError>> + Send;
}

/// The real thing: an HTTPS POST authenticated by the server's own certificate.
///
/// The client certificate *is* the authentication. The list ties an entry to the
/// fingerprint that presents it, which is the same fingerprint clients pin, so
/// nobody can update somebody else's listing without their private key.
#[derive(Debug)]
pub struct PublicList {
    endpoint: String,
    tls: Arc<ClientConfig>,
}

impl PublicList {
    /// Build a client that authenticates as `identity`.
    ///
    /// Consumes the identity because `PrivateKeyDer` is deliberately not
    /// `Clone`; take the digest before calling this.
    ///
    /// # Errors
    ///
    /// [`RegisterError`] when the trust store is unreadable or rustls refuses
    /// the identity.
    pub fn new(
        endpoint: &str,
        identity: TlsIdentity,
        trust_store: &Path,
    ) -> Result<Self, RegisterError> {
        // rustls 0.23 installs no crypto backend on its own. Ignored if another
        // component in this process got there first, the workspace enables
        // exactly one provider, so a second install is the same one.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut roots = rustls::RootCertStore::empty();
        let pem = std::fs::read(trust_store).map_err(|error| RegisterError::TrustStore {
            path: trust_store.to_path_buf(),
            reason: error.to_string(),
        })?;
        let mut reader = std::io::BufReader::new(pem.as_slice());
        for certificate in rustls_pemfile::certs(&mut reader) {
            let certificate = certificate.map_err(|error| RegisterError::TrustStore {
                path: trust_store.to_path_buf(),
                reason: error.to_string(),
            })?;
            // A single unparseable entry in a system bundle is not a reason to
            // refuse every root in it.
            let _ = roots.add(certificate);
        }
        if roots.is_empty() {
            return Err(RegisterError::TrustStore {
                path: trust_store.to_path_buf(),
                reason: "no certificates in the bundle".to_owned(),
            });
        }

        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(identity.certs, identity.key)?;

        Ok(Self {
            endpoint: endpoint.to_owned(),
            tls: Arc::new(tls),
        })
    }

    /// The `host` and path inside an `https://` endpoint.
    fn split(endpoint: &str) -> Result<(&str, &str), RegisterError> {
        let rest = endpoint
            .strip_prefix("https://")
            .ok_or_else(|| RegisterError::Endpoint(format!("{endpoint:?} is not https")))?;
        Ok(match rest.find('/') {
            // Split at the slash rather than taking `split_once`'s second half,
            // so the path keeps the leading slash a request line needs.
            Some(cut) => rest.split_at(cut),
            None => (rest, "/"),
        })
    }
}

impl Registrar for PublicList {
    async fn submit(&self, body: String) -> Result<(), RegisterError> {
        let (host, path) = Self::split(&self.endpoint)?;
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| RegisterError::Endpoint(format!("{host:?} is not a server name")))?;

        let stream = TcpStream::connect((host, 443)).await?;
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, stream)
            .await?;

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        // The connection has to be driven for the request to make progress, and
        // it ends on its own when the response is done.
        drop(tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "the public list closed the connection");
            }
        }));

        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", host)
            .header("content-type", "text/xml")
            .header(
                "user-agent",
                concat!("Starling/", env!("CARGO_PKG_VERSION")),
            )
            .body(Full::new(Bytes::from(body)))?;

        let response = sender.send_request(request).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        let body = String::from_utf8_lossy(&body).trim().to_owned();

        if !status.is_success() {
            return Err(RegisterError::Refused { status, body });
        }
        // murmur logs whatever the list says and does not parse it; there is no
        // documented success schema to parse.
        tracing::info!(%status, response = %body, "registered with the public server list");
        Ok(())
    }
}

#[cfg(test)]
// Not private: [`Recording`] is the substitute the service's own tests submit
// through, which is the whole reason [`Registrar`] is a trait.
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A registrar that records instead of posting.
    #[derive(Debug, Default)]
    pub(crate) struct Recording {
        submitted: Mutex<Vec<String>>,
    }

    impl Recording {
        pub(crate) fn documents(&self) -> Vec<String> {
            self.submitted
                .lock()
                .map(|submitted| submitted.clone())
                .unwrap_or_default()
        }
    }

    impl Registrar for Recording {
        async fn submit(&self, body: String) -> Result<(), RegisterError> {
            if let Ok(mut submitted) = self.submitted.lock() {
                submitted.push(body);
            }
            Ok(())
        }
    }

    #[test]
    fn an_endpoint_splits_into_a_host_to_dial_and_a_path_to_post() {
        assert_eq!(
            PublicList::split("https://publist-registration.mumble.info/v1/register").ok(),
            Some(("publist-registration.mumble.info", "/v1/register"))
        );
        assert_eq!(
            PublicList::split("https://example.org").ok(),
            Some(("example.org", "/"))
        );
    }

    #[test]
    fn a_plain_http_endpoint_is_refused() {
        // The document carries the registry password. Posting it in the clear
        // because a URL said so is not a configuration this offers.
        assert!(PublicList::split("http://example.org/v1/register").is_err());
    }

    #[test]
    fn a_missing_trust_store_is_an_error_and_not_a_silent_downgrade() {
        // Proceeding without roots would send the registry password to whoever
        // answered on port 443, so this must fail loudly at construction rather
        // than quietly at the first POST.
        let dir = std::env::temp_dir().join(format!("starling-directory-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp directory");
        let identity = starling_crypto::identity::load_or_generate(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
        )
        .expect("a generated identity");

        let error = PublicList::new(
            crate::listing::PUBLIC_LIST,
            identity,
            Path::new("/nonexistent/ca-bundle.crt"),
        )
        .expect_err("a missing trust store must not be shrugged off");

        assert!(matches!(error, RegisterError::TrustStore { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
