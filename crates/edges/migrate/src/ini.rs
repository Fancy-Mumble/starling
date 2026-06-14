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

use starling_config::{Limits, ServerConfig};
use tracing::warn;

use starling_cli::{ConfigSource, Settings};

/// A parsed `.ini` file.
#[derive(Debug, Default)]
pub struct Ini {
    entries: BTreeMap<String, String>,
}

impl Ini {
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

    /// murmur accepts `true`/`false` and `1`/`0`.
    fn boolean(&self, key: &str, default: bool) -> bool {
        match self.get(key) {
            None => default,
            Some(raw) => match raw.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => true,
                "false" | "0" | "no" => false,
                other => {
                    warn!(key, value = other, "not a boolean; using the default");
                    default
                }
            },
        }
    }

    /// Report configured behaviour Starling does not yet provide.
    ///
    /// Grouped by the phase that implements it, so an operator reading the log
    /// can tell "not yet" from "not ever".
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
}

/// Keys murmur honours that Starling does not act on yet, and the phase that
/// will implement each. See `PORTING-PLAN.md` §4.
const UNIMPLEMENTED: &[(&str, &str)] = &[
    ("database", "2"),
    ("certrequired", "2"),
    ("autobanAttempts", "2"),
    ("autobanTimeframe", "2"),
    ("autobanTime", "2"),
    ("opusthreshold", "1"),
    ("messagelimit", "1"),
    ("messageburst", "1"),
    ("ice", "6 (replaced by gRPC - see PORTING-PLAN.md §6)"),
    ("webrtcsfuenabled", "6"),
    ("webrtcsfuport", "6"),
    ("webrtcsfupublicip", "6"),
    ("pchatenabled", "4"),
    ("pchatrequireregistration", "4"),
];

impl ConfigSource for Ini {
    fn name(&self) -> &'static str {
        "murmur.ini (legacy)"
    }

    /// Each key falls back to what the previous layer resolved, so a `.ini` that
    /// omits a setting does not reset it (see [`ConfigSource`]'s contract).
    fn apply(&self, settings: Settings) -> Settings {
        self.warn_about_unimplemented();
        let base = settings.server;
        Settings {
            server: ServerConfig {
                host: self.string("host", &base.host),
                port: self.number("port", base.port),
                register_name: self.string("registerName", &base.register_name),
                server_password: self.string("serverpassword", &base.server_password),
                limits: Limits {
                    max_users: self.number("users", base.limits.max_users),
                    max_bandwidth: self.number("bandwidth", base.limits.max_bandwidth),
                    welcome_text: self.string("welcometext", &base.limits.welcome_text),
                    allow_html: self.boolean("allowhtml", base.limits.allow_html),
                    max_text_message_length: self
                        .number("textmessagelength", base.limits.max_text_message_length),
                    max_image_message_length: self
                        .number("imagemessagelength", base.limits.max_image_message_length),
                    allow_recording: self.boolean("allowrecording", base.limits.allow_recording),
                },
            },
            // The .ini has no TLS paths; murmur takes them from `sslCert`/`sslKey`,
            // which Phase 2 maps once certificate handling exists.
            ..settings
        }
    }
}

fn strip_comment(line: &str) -> &str {
    let cut = line.find([';', '#']).unwrap_or(line.len());
    &line[..cut]
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
        // `serverpassword=` means "no password", not "unset".
        let ini = Ini::parse("serverpassword=\n");
        assert_eq!(ini.get("serverpassword"), Some(""));
        assert!(!ini.apply(Settings::default()).server.requires_password());
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
        let config = ini.apply(Settings::default()).server;

        assert_eq!(config.port, 64738);
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.limits.max_users, 100);
        assert_eq!(config.limits.max_bandwidth, 320_000);
        assert_eq!(config.register_name, "Fancy Mumble e2e");
        assert_eq!(
            config.limits.welcome_text,
            "<b>Fancy Mumble e2e test server</b>"
        );
        assert_eq!(config.limits.max_text_message_length, 131_072);
        assert_eq!(config.limits.max_image_message_length, 10_485_760);
        assert!(config.limits.allow_html);
        assert!(!config.requires_password());
    }

    #[test]
    fn booleans_accept_murmurs_spellings() {
        assert!(
            Ini::parse("allowhtml=true")
                .apply(Settings::default())
                .server
                .limits
                .allow_html
        );
        assert!(
            Ini::parse("allowhtml=1")
                .apply(Settings::default())
                .server
                .limits
                .allow_html
        );
        assert!(
            !Ini::parse("allowhtml=false")
                .apply(Settings::default())
                .server
                .limits
                .allow_html
        );
        assert!(
            !Ini::parse("allowhtml=0")
                .apply(Settings::default())
                .server
                .limits
                .allow_html
        );
    }

    #[test]
    fn an_unparseable_number_falls_back_to_the_default() {
        // Better than refusing to boot on one malformed key, and the warning
        // says which one.
        let config = Ini::parse("port=not-a-number")
            .apply(Settings::default())
            .server;
        assert_eq!(config.port, ServerConfig::default().port);
    }

    #[test]
    fn a_missing_file_yields_pure_defaults() {
        let config = Ini::parse("").apply(Settings::default()).server;
        let defaults = ServerConfig::default();
        assert_eq!(config.port, defaults.port);
        assert_eq!(config.register_name, defaults.register_name);
    }

    #[test]
    fn lines_without_an_equals_sign_are_skipped_not_fatal() {
        let ini = Ini::parse("garbage line\nport=1234\n");
        assert_eq!(ini.get("port"), Some("1234"));
    }
}
