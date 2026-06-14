//! `starling-cli` — the command-line surface.
//!
//! What an operator may type or write, and the [`Settings`] it resolves to. One
//! responsibility: turning intent expressed outside the process into values
//! inside it.
//!
//! # Commands register themselves
//!
//! A subcommand is a [`Command`] announced with
//! [`register_command!`](crate::register_command), collected by `inventory` the
//! same way features are. `migrate-config` lives in `starling-migrate`, not here
//! — this crate does not know which commands exist, only how to find them.
//!
//! That is why the murmur `.ini` reader is not here either: reading murmur's
//! format is murmur compatibility, and it belongs with the command that exists
//! for it.

/// Re-exported so [`register_command!`](crate::register_command) resolves
/// without a command crate depending on `inventory` itself.
pub use inventory;

pub mod args;
pub mod command;
pub mod formats;
pub mod native;
pub mod overrides;

pub use args::{Command as Invocation, ServeArgs, USAGE};
pub use command::{registered, Command, CommandError};
pub use formats::ConfigFormat;
pub use native::NativeConfig;
pub use overrides::CliOverrides;

use starling_log::LogConfig;
use std::path::{Path, PathBuf};

use starling_config::ServerConfig;

/// Where the TLS identity lives.
///
/// Kept out of [`ServerConfig`] because the server crate has no business
/// knowing about the filesystem — it is handed an already-loaded identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    /// Certificate chain PEM.
    pub certificate: PathBuf,
    /// Private key PEM.
    pub key: PathBuf,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            certificate: PathBuf::from("starling-data/cert.pem"),
            key: PathBuf::from("starling-data/key.pem"),
        }
    }
}

/// Everything the binary needs to start.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Settings handed to the server core.
    pub server: ServerConfig,
    /// Where to find the TLS identity.
    pub tls: TlsSettings,
    /// Where log records go.
    pub logging: LogConfig,
}

/// A layer of configuration that can adjust the settings resolved so far.
///
/// # Contract
///
/// [`Self::apply`] must only change the settings this source actually
/// specifies, leaving the rest untouched — that is what makes the layers
/// compose. A source with nothing to say returns `settings` unchanged rather
/// than returning defaults, which would silently discard earlier layers.
pub trait ConfigSource: std::fmt::Debug {
    /// A short name for logs, so a surprising value can be traced to its layer.
    fn name(&self) -> &'static str;

    /// Apply this layer's settings on top of `settings`.
    fn apply(&self, settings: Settings) -> Settings;
}

/// Fold every source over the defaults, in order. Later sources win.
pub fn resolve(sources: &[&dyn ConfigSource]) -> Settings {
    sources.iter().fold(Settings::default(), |settings, src| {
        tracing::debug!(source = src.name(), "applying configuration layer");
        src.apply(settings)
    })
}

/// Errors while reading a config file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// No registered format claimed the file.
    ///
    /// Only reachable if the TOML fallback is not linked, which means the binary
    /// was built without `starling-cli`'s own registration — worth a clear error
    /// rather than a silent default.
    #[error("{path}: no configuration format recognised this file (known: {known})")]
    Unknown {
        /// The file involved.
        path: PathBuf,
        /// Formats that were available.
        known: String,
    },
    /// The file could not be read.
    #[error("{path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file was not valid TOML, or did not match the schema.
    #[error("{path}: {source}")]
    Toml {
        /// The file involved.
        path: PathBuf,
        /// What the parser objected to.
        #[source]
        source: toml::de::Error,
    },
}

/// A config file, parsed by whichever registered format claimed it.
///
/// The enum this replaced had a variant per format, so this crate had to know
/// that murmur `.ini` exists — and therefore depend on the crate that reads it.
/// Formats now register themselves ([`ConfigFormat`]), so adding one touches no
/// file here.
#[derive(Debug)]
pub struct ConfigFile {
    format: &'static str,
    source: Box<dyn ConfigSource>,
}

impl ConfigFile {
    /// Read a config file, letting the registered formats choose.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Io`] if the file cannot be read, [`ConfigError::Unknown`]
    /// if no format claims it, or the format's own parse error.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        for format in formats::registered() {
            if !format.claims(path) {
                continue;
            }
            let source = format.parse(path, &contents)?;
            return Ok(Self {
                format: format.name(),
                source,
            });
        }
        Err(ConfigError::Unknown {
            path: path.to_path_buf(),
            known: formats::registered()
                .iter()
                .map(|f| f.name())
                .collect::<Vec<_>>()
                .join(", "),
        })
    }
}

impl ConfigSource for ConfigFile {
    fn name(&self) -> &'static str {
        self.format
    }

    fn apply(&self, settings: Settings) -> Settings {
        self.source.apply(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that sets exactly one field, to prove layering order.
    #[derive(Debug)]
    struct SetsPort(u16);

    impl ConfigSource for SetsPort {
        fn name(&self) -> &'static str {
            "sets-port"
        }
        fn apply(&self, settings: Settings) -> Settings {
            Settings {
                server: ServerConfig {
                    port: self.0,
                    ..settings.server
                },
                ..settings
            }
        }
    }

    /// A source that specifies nothing.
    #[derive(Debug)]
    struct Silent;

    impl ConfigSource for Silent {
        fn name(&self) -> &'static str {
            "silent"
        }
        fn apply(&self, settings: Settings) -> Settings {
            settings
        }
    }

    #[test]
    fn no_sources_yields_the_defaults() {
        assert_eq!(resolve(&[]).server.port, ServerConfig::default().port);
    }

    #[test]
    fn later_sources_win() {
        assert_eq!(
            resolve(&[&SetsPort(1111), &SetsPort(2222)]).server.port,
            2222
        );
    }

    #[test]
    fn a_silent_source_preserves_earlier_layers() {
        // The contract that makes layering safe: a source with nothing to say
        // must not reset what came before it.
        assert_eq!(resolve(&[&SetsPort(1111), &Silent]).server.port, 1111);
    }

    #[test]
    fn a_source_only_changes_what_it_specifies() {
        let settings = resolve(&[&SetsPort(1111)]);
        let defaults = ServerConfig::default();
        assert_eq!(settings.server.port, 1111);
        assert_eq!(settings.server.limits.max_users, defaults.limits.max_users);
        assert_eq!(settings.tls, TlsSettings::default());
    }
}
