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

use starling_runtime::config::{Config, Instance, ServerSettings};
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
    /// `MigrateError::Io` if `path` cannot be read.
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

    /// The same reader, over key/value pairs that did not come from a file.
    ///
    /// murmur's `config` **table** holds the settings an operator changed while
    /// the server was running, under the same key names the `.ini` uses, and it
    /// overrides the file key for key. A database migration therefore reads its
    /// settings through this rather than through a second table of key names,
    /// which would be a second thing to keep in step with [`Self::to_settings`]
    /// and would fall behind it the first time a setting was added.
    ///
    /// Values arrive as murmur stored them, so they are **not** unquoted: the
    /// quoting `parse` strips is a property of the file format, and a value in
    /// the table that begins and ends with a quote contains those quotes.
    #[must_use]
    pub fn from_pairs<K, V>(pairs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            entries: pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
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
        self.warn_about_push();
    }

    /// Hand back the `[services.push]` block a migrated push setup needs.
    ///
    /// Told rather than written, and this is the one place the migration is
    /// deliberately manual: a service block in the output would override the
    /// built-in defaults *whole*, wire types and tier included, so a
    /// `[services.push]` composed from two `.ini` lines would quietly
    /// unregister push from the gateway. The operator gets the block to paste
    /// and keeps the defaults underneath it.
    fn warn_about_push(&self) {
        let Some(block) = self.push_block() else {
            return;
        };
        if self.get("pushmodulepath").is_some() {
            // There is no module: Starling links FCM into the push service, so
            // the path names a shared library nothing will ever load.
            warn!(
                key = "pushmodulepath",
                "push is built in and loads no module; ignoring"
            );
        }
        // murmur's master switch has no equivalent: a push service with no
        // credentials configured delivers nothing, which is the same state.
        let enabled = self
            .get("pushenabled")
            .is_some_and(|value| self.flag("pushenabled", value));
        warn!(
            %block,
            enabled,
            "push settings do not migrate on their own; add this block"
        );
    }

    /// The `[services.push]` block this `.ini`'s push keys spell out, if it
    /// states any.
    #[must_use]
    pub fn push_block(&self) -> Option<String> {
        let stated = PUSH_OPTIONS
            .iter()
            .filter_map(|(key, option)| {
                self.get(key).map(|value| format!("{option} = \"{value}\""))
            })
            .collect::<Vec<_>>();
        if stated.is_empty() {
            return None;
        }
        Some(format!(
            "[services.push]\noptions = {{ {} }}",
            stated.join(", ")
        ))
    }

    /// The equivalent [`Config`].
    ///
    /// Two layers land in two places, as they do everywhere else: the listen
    /// address and the server instance's id, name and port are deployment, and
    /// the limits, the welcome text and the public listing are operational and
    /// go under `[instances.settings]`, which is where a deployment file
    /// states the values a server starts with.
    ///
    /// Only keys the `.ini` actually contains are written, so a migrated file
    /// says what the operator said and nothing more. What has no home at all is
    /// reported by `Self::warn_about_unimplemented`.
    #[must_use]
    pub fn to_config(&self) -> Config {
        self.warn_about_unimplemented();

        let host = self.string("host", "0.0.0.0");
        let port = self.number("port", Instance::default().port);

        let mut config = Config {
            instances: vec![Instance {
                id: 1,
                name: self.string("registerName", &Instance::default().name),
                port,
                settings: self.to_settings(),
            }],
            ..Config::default()
        };
        config.gateway.listen_tcp = format!("{host}:{port}");
        config
    }

    /// The operational settings the `.ini` states, and only those.
    ///
    /// murmur's spellings are its own -- lowercase for the limits, camelCase
    /// for the `register*` family -- and the parser is case-sensitive on
    /// purpose, so both are written out rather than derived.
    #[must_use]
    pub fn to_settings(&self) -> ServerSettings {
        let mut settings = ServerSettings::default();

        macro_rules! text {
            ($($ini:literal => $field:ident),* $(,)?) => {
                $(settings.$field = self.get($ini).map(ToOwned::to_owned);)*
            };
        }
        macro_rules! count {
            ($($ini:literal => $field:ident),* $(,)?) => {
                $(settings.$field = self.get($ini).map(|_| self.number($ini, 0));)*
            };
        }
        macro_rules! flag {
            ($($ini:literal => $field:ident),* $(,)?) => {
                $(settings.$field = self.get($ini).map(|value| self.flag($ini, value)));*
            };
        }

        text! {
            "welcometext" => welcome_text,
            "serverpassword" => password,
            "registerName" => registry_name,
            "registerPassword" => registry_password,
            "registerUrl" => registry_url,
            "registerHostname" => registry_hostname,
            "registerLocation" => registry_location,
        }
        count! {
            "users" => max_users,
            "bandwidth" => max_bandwidth,
            "textmessagelength" => text_message_length,
            "imagemessagelength" => image_message_length,
            "channelnestinglimit" => channel_nesting_limit,
            "channelcountlimit" => channel_count_limit,
            "listenersperchannel" => listeners_per_channel,
            "listenersperuser" => listeners_per_user,
            "usersperchannel" => users_per_channel,
            "defaultchannel" => default_channel,
            "rememberchannelduration" => remember_channel_duration,
            "logdays" => log_days,
            "messagelimit" => message_limit,
            "messageburst" => message_burst,
        }
        flag! {
            "allowhtml" => allow_html,
            "allowrecording" => allow_recording,
            "allowping" => allow_ping,
            "certrequired" => cert_required,
            "obfuscate" => obfuscate_ips,
            "broadcastlistenervolumeadjustments" => broadcast_listener_volume_adjustments,
            "rememberchannel" => remember_channel,
        }
        // The two name patterns, carried across verbatim. murmur's `.ini` has
        // them double-escaped for its own parser (`\\w`), and `unquote` has
        // already undone the quoting, so what lands here is the pattern
        // upstream compiles rather than the pattern as typed.
        text! {
            "channelname" => channel_name_regex,
            "username" => user_name_regex,
        }
        settings
    }

    /// murmur writes booleans as `true`/`false` and as `1`/`0`, both.
    fn flag(&self, key: &str, value: &str) -> bool {
        match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => true,
            "false" | "0" | "no" | "" => false,
            other => {
                warn!(key, value = other, "not a boolean; reading it as false");
                false
            }
        }
    }

    /// [`Self::to_config`], rendered as TOML text ready to write to
    /// `starling.toml`.
    ///
    /// # Errors
    ///
    /// `MigrateError::Render` if the migrated config could not be
    /// serialised, not expected in practice, see that variant's docs.
    pub fn migrate(&self) -> Result<String, MigrateError> {
        Ok(toml::to_string_pretty(&self.to_config())?)
    }
}

/// Keys murmur honours that have no config home yet, and the phase that will
/// give them one. See `docs/PORTING-PLAN.md` §4.
///
/// The operational settings that used to be listed here -- `users`,
/// `bandwidth`, `welcometext`, `messagelimit` and the rest -- now migrate into
/// `[instances.settings]`, so they are gone from this list rather than
/// reported at every migration.
const UNIMPLEMENTED: &[(&str, &str)] = &[
    ("database", "2"),
    ("autobanAttempts", "2"),
    ("autobanTimeframe", "2"),
    ("autobanTime", "2"),
    ("opusthreshold", "1"),
    ("ice", "6 (replaced by gRPC - see docs/PORTING-PLAN.md §6)"),
    ("webrtcsfuenabled", "6"),
    ("webrtcsfuport", "6"),
    ("webrtcsfupublicip", "6"),
    ("pchatenabled", "4"),
    ("pchatrequireregistration", "4"),
];

/// murmur's push keys, and the `options` key each becomes.
///
/// The provider is the same one (`starling-push`'s `fcm` module is murmur's
/// `libmumble_push_fcm` ported), so the values carry across unchanged; only the
/// spellings differ. See `starling.example.toml`.
const PUSH_OPTIONS: &[(&str, &str)] = &[
    ("pushcredentialspath", "fcm_credentials"),
    ("pushprojectid", "fcm_project"),
    ("pushtopicprefix", "fcm_topic_prefix"),
    ("pushnotifytextmessage", "notify_text_message"),
    ("pushnotifyreaction", "notify_reaction"),
    ("pushnotifyuserjoin", "notify_user_join"),
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
        assert_eq!(config.instances.len(), 1);
        assert_eq!(config.instances[0].name, "Fancy Mumble e2e");
        assert_eq!(config.instances[0].port, 64738);

        // The operational half, which used to be warned about and dropped: an
        // operator migrating a tuned server got a file that quietly restored
        // every limit to murmur's default.
        let settings = &config.instances[0].settings;
        assert_eq!(settings.max_users, Some(100));
        assert_eq!(settings.max_bandwidth, Some(320_000));
        assert_eq!(settings.text_message_length, Some(131_072));
        assert_eq!(settings.allow_html, Some(true));
        assert_eq!(settings.cert_required, Some(false));
        assert_eq!(
            settings.welcome_text.as_deref(),
            Some("<b>Fancy Mumble e2e test server</b>")
        );
        assert_eq!(
            settings.password.as_deref(),
            Some(""),
            "an empty password is a stated one: it means the server is open"
        );
    }

    #[test]
    fn a_setting_the_ini_never_mentions_is_left_unstated() {
        // Writing every key would turn a migration into a decision about
        // settings the operator never made, and freeze them at whatever
        // murmur's default was on the day they migrated.
        let settings = Ini::parse("port=64738\n").to_settings();
        assert_eq!(settings.max_users, None);
        assert_eq!(settings.allow_html, None);
        assert!(settings.is_empty());
    }

    #[test]
    fn murmurs_two_spellings_of_a_boolean_both_migrate() {
        // `.ini` files in the wild carry both, and reading `1` as false would
        // silently switch a setting off on migration.
        assert_eq!(
            Ini::parse("allowhtml=1\n").to_settings().allow_html,
            Some(true)
        );
        assert_eq!(
            Ini::parse("allowhtml=false\n").to_settings().allow_html,
            Some(false)
        );
    }

    #[test]
    fn the_public_listing_migrates_as_a_whole() {
        // Half of it is a server that stops being listed; murmur refuses to
        // register without the name, the URL and the password together.
        let settings = Ini::parse(
            "registerName=Frog Pond\nregisterPassword=secret\n\
             registerUrl=https://frogpond.example\nregisterHostname=frogpond.example\n\
             registerLocation=DE\n",
        )
        .to_settings();

        assert_eq!(settings.registry_name.as_deref(), Some("Frog Pond"));
        assert_eq!(settings.registry_password.as_deref(), Some("secret"));
        assert_eq!(
            settings.registry_url.as_deref(),
            Some("https://frogpond.example")
        );
        assert_eq!(
            settings.registry_hostname.as_deref(),
            Some("frogpond.example")
        );
        assert_eq!(settings.registry_location.as_deref(), Some("DE"));
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
        assert_eq!(config.instances[0].port, Instance::default().port);
    }

    #[test]
    fn push_settings_come_back_as_a_block_to_paste_and_not_as_silence() {
        // The values carry across unchanged -- Starling's provider is murmur's
        // FCM module ported -- so all an operator needs is the spellings.
        let ini = Ini::parse(
            "pushenabled=true\npushcredentialspath=/etc/mumble/fcm.json\n\
             pushprojectid=frogpond\npushnotifyreaction=true\n",
        );
        let block = ini.push_block().expect("push keys produce a block");
        assert!(block.starts_with("[services.push]"), "{block}");
        assert!(
            block.contains(r#"fcm_credentials = "/etc/mumble/fcm.json""#),
            "{block}"
        );
        assert!(block.contains(r#"fcm_project = "frogpond""#), "{block}");
        assert!(block.contains(r#"notify_reaction = "true""#), "{block}");
    }

    #[test]
    fn an_ini_that_never_mentions_push_gets_no_block() {
        // Most do not, and a migration that hands back configuration nobody
        // asked for is one an operator stops reading.
        assert_eq!(Ini::parse("port=64738").push_block(), None);
    }

    #[test]
    fn a_migrated_file_never_writes_a_service_block_of_its_own() {
        // It would override the built-in defaults whole -- tier and wire types
        // included -- and a push service with `types = []` is one the gateway
        // routes nothing to, silently.
        let toml = Ini::parse("pushenabled=true\npushprojectid=frogpond\n")
            .migrate()
            .expect("it renders");
        assert!(!toml.contains("[services.push]"), "{toml}");
    }

    #[test]
    fn a_missing_file_yields_pure_defaults() {
        let config = Ini::parse("").to_config();
        let defaults = Instance::default();
        assert_eq!(config.instances[0].port, defaults.port);
        assert_eq!(config.instances[0].name, defaults.name);
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
