//! Command-line overrides — the last configuration layer.

use std::path::PathBuf;

use starling_config::ServerConfig;

use crate::{ConfigSource, Settings, TlsSettings};

/// Settings given on the command line.
///
/// `None` means "not specified", so an absent flag leaves the config file's
/// value alone rather than resetting it to a default.
#[derive(Debug, Default, Clone)]
pub struct CliOverrides {
    /// `--port`
    pub port: Option<u16>,
    /// `--cert`
    pub certificate: Option<PathBuf>,
    /// `--key`
    pub key: Option<PathBuf>,
}

impl ConfigSource for CliOverrides {
    fn name(&self) -> &'static str {
        "cli"
    }

    fn apply(&self, settings: Settings) -> Settings {
        Settings {
            server: ServerConfig {
                port: self.port.unwrap_or(settings.server.port),
                ..settings.server
            },
            tls: TlsSettings {
                certificate: self.certificate.clone().unwrap_or(settings.tls.certificate),
                key: self.key.clone().unwrap_or(settings.tls.key),
            },
            // Nothing on the command line configures logging yet.
            logging: settings.logging,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_config::Limits;

    fn base() -> Settings {
        Settings {
            server: ServerConfig {
                port: 9999,
                register_name: "Kept".into(),
                limits: Limits {
                    max_users: 42,
                    ..Default::default()
                },
                ..Default::default()
            },
            tls: TlsSettings {
                certificate: PathBuf::from("from-config/cert.pem"),
                key: PathBuf::from("from-config/key.pem"),
            },
            ..Default::default()
        }
    }

    #[test]
    fn an_absent_override_leaves_the_earlier_value_alone() {
        let applied = CliOverrides::default().apply(base());
        assert_eq!(applied.server.port, 9999);
        assert_eq!(applied.tls, base().tls);
    }

    #[test]
    fn a_present_port_override_wins() {
        let cli = CliOverrides {
            port: Some(1234),
            ..Default::default()
        };
        assert_eq!(cli.apply(base()).server.port, 1234);
    }

    #[test]
    fn tls_paths_can_be_overridden_independently() {
        let cli = CliOverrides {
            certificate: Some(PathBuf::from("cli/cert.pem")),
            ..Default::default()
        };
        let applied = cli.apply(base());
        assert_eq!(applied.tls.certificate, PathBuf::from("cli/cert.pem"));
        assert_eq!(
            applied.tls.key,
            PathBuf::from("from-config/key.pem"),
            "an unspecified key must not be reset"
        );
    }

    #[test]
    fn overrides_do_not_disturb_other_settings() {
        let cli = CliOverrides {
            port: Some(1234),
            ..Default::default()
        };
        let applied = cli.apply(base());
        assert_eq!(applied.server.register_name, "Kept");
        assert_eq!(applied.server.limits.max_users, 42);
    }
}
