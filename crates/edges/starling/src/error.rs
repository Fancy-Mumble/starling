//! What can go wrong before the server is serving.
//!
//! Every variant wraps the typed error it came from. The previous version of
//! this binary returned `Result<(), String>` and called `.map_err(|e|
//! e.to_string())` at five call sites, which threw away `ConfigError`'s path,
//! `TlsError`'s cause and `ListenError`'s kind — all of which are already proper
//! `thiserror` enums — and left the caller nothing to match on.

use starling_cli::{CommandError, ConfigError};
use starling_net::ListenError;
use starling_tls::TlsError;

/// A failure between process start and the listener accepting.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StartupError {
    /// The command line could not be parsed. Carries the usage text.
    #[error("{0}")]
    Usage(String),

    /// `rustls` refused to install its process-wide crypto provider.
    ///
    /// Only possible if something already installed one, which in a binary this
    /// size means a double call.
    #[error("failed to install the rustls crypto provider")]
    CryptoProvider,

    /// A subcommand failed.
    #[error(transparent)]
    Command(#[from] CommandError),

    /// The configuration file could not be read or did not match the schema.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The certificate or key could not be loaded or generated.
    #[error(transparent)]
    Tls(#[from] TlsError),

    /// The listener could not bind, or failed while serving.
    #[error(transparent)]
    Listen(#[from] ListenError),

    /// The configured database could not be opened.
    ///
    /// Fatal on purpose: a server that starts without the database it was told
    /// to use accepts registrations and silently drops them, which is worse than
    /// not starting. Not configuring one at all is a different thing and is not
    /// an error.
    ///
    /// Not `#[from]`: the URL has to be redacted on the way in, and a blanket
    /// conversion would let a call site skip that.
    #[error("could not open the database at {url}: {source}")]
    Database {
        /// The URL, with any password removed.
        url: String,
        /// What the store said.
        #[source]
        source: starling_api::StoreError,
    },
}
