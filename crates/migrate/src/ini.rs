//! murmur `.ini` parsing.
//!
//! Deliberately compatible with `fixtures/mumble-server.ini`, quirks included:
//!
//! * keys are matched **case-sensitively**, because murmur's are (`registerName`
//!   vs `registername` genuinely differ on Linux, and the e2e fixture depends on
//!   the camelCase spelling);
//! * `;` and `#` both start a comment;
//! * values may be double-quoted, which is stripped;
//! * `[section]` headers are accepted and ignored, as murmur does.
//!
//! Keys Starling does not act on yet are **reported**, never silently dropped: a
//! config that used to mean something must not quietly mean less here.

use std::collections::BTreeMap;
use std::path::Path;

use starling_runtime::config::{Config, VirtualServer};
use tracing::warn;

/// Why an `.ini` could not be migrated.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// The file could not be read.
    #[error("{path}: {source}")]
    Io {
        /// The file involved.
        path: std::path::PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The migrated [`Config`] could not be rendered as TOML.
    ///
    /// Never expected in practice: every field [`Ini::migrate`] fills in is a
    /// plain string or number, none of which TOML refuses to serialise.
    #[error("rendering the migrated config: {0}")]
    Render(#[from] toml::ser::Error),
}

/// A parsed `.ini` file.
#[derive(Debug, Default)]
pub struct Ini {
    entries: BTreeMap<String, String>,
}

impl Ini {
    /// Read and parse a murmur-style `.ini` from disk.
    ///
    /// # Errors
    ///
    /// [`MigrateError::Io`] if `path` cannot be read.
    pub fn read(path: &Path) -> Result<Self, MigrateError> {
        let contents = std::fs::read_to_string(path).map_err(|source| MigrateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self::parse(&contents))
    }

    /// Parse the contents of a murmur-style `.ini`.
    #[must_use]
    pub fn parse(contents: &str) -> Self {
        let mut entries = BTreeMap::new();
        for raw in contents.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() || line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let _ = entries.insert(key.trim().to_owned(), unquote(value.trim()).to_owned());
        }
        Self { entries }
    }

    /// A raw value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    fn string(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or(default).to_owned()
    }

    fn number<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        match self.get(key) {
            None => default,
            Some(raw) => raw.parse().unwrap_or_else(|_| {
                warn!(key, value = raw, "not a number; using the default");
                default
            }),
        }
    }

    /// murmur's database settings, as a sqlx connection URL.
    ///
    /// murmur spreads this across six keys and a Qt driver name; sqlx wants one
    /// string. There is no deployment-config field to put this in yet, each
    /// service owns its own schema and connects independently
    /// (`docs/STORAGE.md`), so this is exposed for a future per-service
    /// migration path rather than wired into [`Self::migrate`].
    ///
    /// An empty `database` with no driver means murmur's own default, which is a
    /// SQLite file called `murmur.sqlite` beside the binary. That is reproduced
    /// rather than guessed at, because "no database configured" and "the default
    /// database" are different situations with the same empty value.
    #[must_use]
    pub fn database_url(&self) -> String {
        let driver = self.string("dbDriver", "QSQLITE");
        let name = self.string("database", "");
        let host = self.string("dbHost", "localhost");
        let user = self.string("dbUsername", "");
        let password = self.string("dbPassword", "");

        // Qt's driver names, which are what a murmur `.ini` actually contains.
        let scheme = match driver.to_ascii_uppercase().as_str() {
            "QMYSQL" => "mysql",
            "QPSQL" => "postgres",
            // Including `QSQLITE` and anything unrecognised: murmur falls back
            // to SQLite too, and a URL that names a file is recoverable in a way
            // that a URL naming the wrong server is not.
            _ => "sqlite",
        };

        if scheme == "sqlite" {
            let path = if name.is_empty() {
                "murmur.sqlite"
            } else {
                &name
            };
            return format!("sqlite://{path}");
        }

        let port = self.number::<u16>("dbPort", if scheme == "mysql" { 3306 } else { 5432 });
        let credentials = match (user.is_empty(), password.is_empty()) {
            (true, _) => String::new(),
            (false, true) => format!("{user}@"),
            (false, false) => format!("{user}:{password}@"),
        };
        format!("{scheme}://{credentials}{host}:{port}/{name}")
    }

    /// Report configured behaviour with no home in the deployment config.
    ///
    /// Grouped by the phase that implements it, so an operator reading the log
    /// can tell "not yet" from "not ever". Most of these are **operational**
    /// settings that will belong to the `server-config` service once it has a
    /// schema, not to [`Config`], murmur kept both in one `Config` table,
    /// Starling splits them (`docs/ARCHITECTURE.md` §4).
    fn warn_about_unimplemented(&self) {
        for (key, phase) in UNIMPLEMENTED {
            if self.get(key).is_some() {
                warn!(key, phase, "configured but not implemented yet; ignoring");
            }
        }
        for key in self.entries.keys() {
            if key.starts_with("plugin.") {
                warn!(key, phase = "3", "plugin configuration ignored; ignoring");
            }
        }
    }

    /// The equivalent [`Config`].
    ///
    /// Only the deployment-layer subset survives the translation: the listen
    /// address and the virtual server's id, name and port. Everything else the
    /// `.ini` configures is operational (`docs/ARCHITECTURE.md` §4) and is
    /// reported by [`Self::warn_about_unimplemented`] instead, since it has no
    /// field to land in yet.
    #[must_use]
    pub fn to_config(&self) -> Config {
        self.warn_about_unimplemented();

        let host = self.string("host", "0.0.0.0");
        let port = self.number("port", VirtualServer::default().port);

        let mut config = Config {
            virtual_servers: vec![VirtualServer {
                id: 1,
                name: self.string("registerName", &VirtualServer::default().name),
                port,
            }],
            ..Config::default()
        };
        config.gateway.listen_tcp = format!("{host}:{port}");
        config
    }

    /// [`Self::to_config`], rendered as TOML text ready to write to
    /// `starling.toml`.
    ///
    /// # Errors
    ///
    /// [`MigrateError::Render`] if the migrated config could not be
    /// serialised, not expected in practice, see that variant's docs.
    pub fn migrate(&self) -> Result<String, MigrateError> {
        Ok(toml::to_string_pretty(&self.to_config())?)
    }
}

/// Keys murmur honours that have no deployment-config home yet, and the phase
/// that will give them one. See `PORTING-PLAN.md` §4.
const UNIMPLEMENTED: &[(&str, &str)] = &[
    ("database", "2"),
    ("certrequired", "2"),
    ("autobanAttempts", "2"),
    ("autobanTimeframe", "2"),
    ("autobanTime", "2"),
    ("opusthreshold", "1"),
    ("messagelimit", "1"),
    ("messageburst", "1"),
    ("users", "2"),
    ("bandwidth", "1"),
    ("welcometext", "2"),
    ("allowhtml", "2"),
    ("serverpassword", "2"),
    ("textmessagelength", "2"),
    ("imagemessagelength", "2"),
    ("allowrecording", "2"),
    ("ice", "6 (replaced by gRPC - see PORTING-PLAN.md §6)"),
    ("webrtcsfuenabled", "6"),
    ("webrtcsfuport", "6"),
    ("webrtcsfupublicip", "6"),
    ("pchatenabled", "4"),
    ("pchatrequireregistration", "4"),
];

fn strip_comment(line: &str) -> &str {
    line.split_once([';', '#']).map_or(line, |(live, _)| live)
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_keys_and_values_parse() {
        let ini = Ini::parse("port=64738\nusers = 42\n");
        assert_eq!(ini.get("port"), Some("64738"));
        assert_eq!(ini.get("users"), Some("42"), "whitespace must be trimmed");
    }

    #[test]
    fn both_comment_characters_are_honoured() {
        let ini = Ini::parse("; a comment\n# another\nport=1234 ; trailing\n");
        assert_eq!(ini.get("port"), Some("1234"));
    }

    #[test]
    fn section_headers_are_ignored_rather_than_parsed_as_keys() {
        let ini = Ini::parse("[server]\nport=1234\n");
        assert_eq!(ini.get("port"), Some("1234"));
        assert_eq!(ini.get("[server]"), None);
    }

    #[test]
    fn quoted_values_are_unquoted() {
        // The fixture writes `ice="tcp -h 0.0.0.0 -p 6502"`.
        let ini = Ini::parse(r#"ice="tcp -h 0.0.0.0 -p 6502""#);
        assert_eq!(ini.get("ice"), Some("tcp -h 0.0.0.0 -p 6502"));
    }

    #[test]
    fn keys_are_case_sensitive_like_murmur() {
        // This is the `registerName` quirk the e2e fixture depends on.
        let ini = Ini::parse("registerName=Fancy Mumble e2e\n");
        assert_eq!(ini.get("registerName"), Some("Fancy Mumble e2e"));
        assert_eq!(ini.get("registername"), None);
    }

    #[test]
    fn values_may_contain_equals_signs() {
        let ini = Ini::parse("welcometext=a=b=c\n");
        assert_eq!(ini.get("welcometext"), Some("a=b=c"));
    }

    #[test]
    fn an_empty_value_is_preserved_as_empty() {
        let ini = Ini::parse("serverpassword=\n");
        assert_eq!(ini.get("serverpassword"), Some(""));
    }

    #[test]
    fn the_e2e_fixture_resolves_to_the_expected_config() {
        let ini = Ini::parse(
            r#"
; Fancy Mumble e2e test server config.
database=/data/mumble-server.sqlite
port=64738
host=0.0.0.0
users=100
bandwidth=320000
certrequired=false
serverpassword=
textmessagelength=131072
imagemessagelength=10485760
allowhtml=true
welcometext=<b>Fancy Mumble e2e test server</b>
registerName=Fancy Mumble e2e
"#,
        );
        let config = ini.to_config();

        assert_eq!(config.gateway.listen_tcp, "0.0.0.0:64738");
        assert_eq!(config.virtual_servers.len(), 1);
        assert_eq!(config.virtual_servers[0].name, "Fancy Mumble e2e");
        assert_eq!(config.virtual_servers[0].port, 64738);
    }

    #[test]
    fn sqlite_is_the_default_and_names_murmurs_own_file() {
        // "No database configured" and "murmur's default database" are the same
        // empty value in a `.ini`, and they mean the same thing, the file
        // beside the binary. Guessing "no database" would silently discard every
        // registered account on migration.
        let ini = Ini::parse("");
        assert_eq!(ini.database_url(), "sqlite://murmur.sqlite");
    }

    #[test]
    fn a_sqlite_path_is_carried_across() {
        let ini = Ini::parse("database=/var/lib/mumble/server.sqlite");
        assert_eq!(ini.database_url(), "sqlite:///var/lib/mumble/server.sqlite");
    }

    #[test]
    fn qt_driver_names_map_to_sqlx_schemes() {
        // A `.ini` contains Qt's names, not sqlx's.
        for (driver, expected) in [("QMYSQL", "mysql"), ("QPSQL", "postgres")] {
            let ini = Ini::parse(&format!(
                "dbDriver={driver}\ndatabase=mumble\ndbUsername=murmur\ndbPassword=secret\ndbHost=db.local"
            ));
            let url = ini.database_url();
            assert!(url.starts_with(&format!("{expected}://")), "{url}");
            assert!(url.contains("murmur:secret@db.local"), "{url}");
            assert!(url.ends_with("/mumble"), "{url}");
        }
    }

    #[test]
    fn each_server_gets_its_conventional_port_when_unset() {
        assert!(
            Ini::parse("dbDriver=QMYSQL\ndatabase=m\ndbUsername=u")
                .database_url()
                .contains(":3306/")
        );
        assert!(
            Ini::parse("dbDriver=QPSQL\ndatabase=m\ndbUsername=u")
                .database_url()
                .contains(":5432/")
        );
    }

    #[test]
    fn an_unrecognised_driver_falls_back_to_sqlite() {
        // As murmur does. A URL naming a file is recoverable; one naming the
        // wrong server is not.
        let ini = Ini::parse("dbDriver=QODBC\ndatabase=x.db");
        assert_eq!(ini.database_url(), "sqlite://x.db");
    }

    #[test]
    fn a_password_free_account_produces_no_stray_colon() {
        // `user:@host` is a different credential from `user@host` to some
        // drivers, and an empty password is not the same as none.
        let url = Ini::parse("dbDriver=QPSQL\ndatabase=m\ndbUsername=murmur").database_url();
        assert!(url.contains("murmur@"), "{url}");
        assert!(!url.contains("murmur:@"), "{url}");
    }

    #[test]
    fn an_unparseable_number_falls_back_to_the_default() {
        // Better than refusing to boot on one malformed key, and the warning
        // says which one.
        let config = Ini::parse("port=not-a-number").to_config();
        assert_eq!(
            config.virtual_servers[0].port,
            VirtualServer::default().port
        );
    }

    #[test]
    fn a_missing_file_yields_pure_defaults() {
        let config = Ini::parse("").to_config();
        let defaults = VirtualServer::default();
        assert_eq!(config.virtual_servers[0].port, defaults.port);
        assert_eq!(config.virtual_servers[0].name, defaults.name);
    }

    #[test]
    fn lines_without_an_equals_sign_are_skipped_not_fatal() {
        let ini = Ini::parse("garbage line\nport=1234\n");
        assert_eq!(ini.get("port"), Some("1234"));
    }

    #[test]
    fn migrated_config_renders_as_toml() {
        let toml = Ini::parse("port=64738\nregisterName=Fancy Mumble e2e\n")
            .migrate()
            .expect("a fresh Config always serialises");
        assert!(toml.contains("64738"));
        assert!(toml.contains("Fancy Mumble e2e"));
    }
}
