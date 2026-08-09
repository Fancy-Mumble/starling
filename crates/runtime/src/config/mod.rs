//! Deployment configuration: read once at startup and injected at construction.
//!
//! The restart-anyway layer -- endpoints, ports, TLS paths, storage URLs, tiers
//! and routes -- plus, per server instance, the *starting values* for the
//! settings `server-config` owns at run time (see [`ServerSettings`]).
//!
//! A file is an **overlay on the built-in defaults**, not a replacement for
//! them: it names what it changes and stays silent about the rest, so a working
//! configuration is six lines rather than three hundred. It may be split across
//! files with `include`. Both live in [`merge`].
//!
//! Unknown keys are **rejected**, so a typo fails loudly.

mod env;
mod gateway;
mod merge;
mod operator;
mod scalars;
mod server;
mod service;

pub use env::{apply_environment, env_key};
pub use gateway::{GatewayConfig, LimitConfig, ResumeConfig, TlsConfig};
pub use operator::{AuthMode, JwtAuth, MtlsAuth, OidcAuth, OperatorAuth, StaticToken, TokenAuth};
pub use scalars::{ByteSize, HumanDuration};
pub use server::ServerSettings;
pub use service::{OperatorAudit, ServiceConfig, StorageConfig, WebTransport};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use starling_proto_fancy::ServiceKind;

use crate::log::LogConfig;
use crate::tier::Tier;

/// Everything a process needs to know before it starts.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Other files to read first, as a base for this one.
    ///
    /// A path is resolved against the directory of the file naming it, and a
    /// directory means every `*.toml` directly inside it, in name order. The
    /// file naming them is applied last, so it wins.
    pub include: Vec<PathBuf>,
    /// Process-level choices.
    pub runtime: RuntimeConfig,
    /// The control-plane front door.
    pub gateway: GatewayConfig,
    /// Where traces, metrics and logs go.
    pub telemetry: TelemetryConfig,
    /// The operator event log: who connected, what was refused.
    ///
    /// Separate from [`telemetry`](Self::telemetry): `RUST_LOG` is a developer's
    /// dial, while this is the record an operator keeps, with its own level,
    /// categories and destinations.
    pub logging: LogConfig,
    /// Every service, by name.
    pub services: BTreeMap<String, ServiceConfig>,
    /// Server instances, in murmur's sense. Metadata runs one actor per entry.
    pub instances: Vec<Instance>,
}

/// Process-level choices.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeConfig {
    /// Every service in one process, over in-memory transports.
    ///
    /// Same binary and config file, with `endpoint` values ignored; the
    /// single-VPS mode.
    pub all_in_one: bool,
    /// Where generated certificates and default databases live.
    pub data_dir: PathBuf,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            all_in_one: false,
            data_dir: PathBuf::from("starling-data"),
        }
    }
}

/// Observability.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    /// OTLP collector, if one is running.
    pub otlp_endpoint: Option<String>,
    /// Where the metrics endpoint binds.
    pub metrics: Option<String>,
    /// `json` for a log collector, `text` for a terminal.
    pub log_format: LogFormat,
}

/// How diagnostics are formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

/// One server instance.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Instance {
    /// Its id. Every stored row and every actor is keyed by this.
    pub id: u32,
    /// Its name, which is also the name of its root channel.
    pub name: String,
    /// Its control port. murmur's convention is `base_port + server_id`.
    pub port: u16,
    /// Starting values for the settings `server-config` owns at run time.
    ///
    /// Here rather than only in the admin API because the first thing anybody
    /// configures is how many people may join and whether there is a password,
    /// and neither was expressible in a file at all.
    pub settings: ServerSettings,
}

impl Default for Instance {
    fn default() -> Self {
        Self {
            id: 1,
            name: "Starling".to_owned(),
            port: 64738,
            settings: ServerSettings::default(),
        }
    }
}

/// Why a configuration could not be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("{path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML, or carries a key Starling does not know.
    #[error("{path}: {source}")]
    Parse {
        /// The file involved.
        path: PathBuf,
        /// What was wrong.
        #[source]
        source: toml::de::Error,
    },
    /// An `include` could not be followed.
    #[error("{path}: {reason}")]
    Include {
        /// The file whose `include` is at fault.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },
    /// The built-in defaults could not be rendered to merge a file over.
    ///
    /// Not reachable from any file: it means the shipped defaults do not
    /// serialise, which is a bug in Starling rather than in a configuration.
    #[error("the built-in defaults could not be prepared: {0}")]
    Defaults(String),
    /// An environment override did not fit the key it was overriding.
    #[error("{key}: {reason}")]
    Environment {
        /// The environment variable.
        key: String,
        /// What was wrong.
        reason: String,
    },
    /// Two services claim the same wire type, so routing would be ambiguous.
    #[error("wire type {type_id} is claimed by both {first} and {second}")]
    DuplicateType {
        /// The contested type.
        type_id: u16,
        /// One claimant.
        first: String,
        /// The other.
        second: String,
    },
}

impl Config {
    /// Read `path` and everything it includes, over the defaults, then apply
    /// environment overrides.
    ///
    /// The file is an **overlay**: what it does not mention keeps the built-in
    /// value, so it needs to carry only what this deployment changes. What it
    /// does mention replaces wholesale rather than merging item-wise, arrays
    /// included -- `[[instances]]` means *these* instances.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] if a file cannot be read, carries an unknown key, has an
    /// `include` that cannot be followed, or describes a routing table two
    /// services would both answer for.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let operator = merge::document(path)?;

        // The defaults are built *around* the operator's `data_dir`, because
        // that is where the local endpoints live: reading it afterwards would
        // give a file that moves the data directory a set of sockets still
        // under the old one.
        let data_dir = operator
            .get("runtime")
            .and_then(|runtime| runtime.get("data_dir"))
            .and_then(toml::Value::as_str)
            .map_or_else(|| RuntimeConfig::default().data_dir, PathBuf::from);

        let mut merged = toml::Table::try_from(Self::with_defaults(&data_dir.join("run")))
            .map_err(|error| ConfigError::Defaults(error.to_string()))?;
        merge::overlay(&mut merged, operator.clone());

        // Every file has already been checked on its own, so a failure here is
        // about the *combination* -- a fragment that sets `port` to a string
        // another fragment made a table. Reported against the file the operator
        // named, which is the one whose include tree produced it.
        let mut config: Self = merged.try_into().map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.adopt_single_server_port(&operator);
        apply_environment(&mut config, &std::env::vars().collect::<Vec<_>>())?;
        config.validate()?;
        Ok(config)
    }

    /// The built-in defaults, with every service on a local endpoint.
    ///
    /// What a first boot with no file gets, and what `--all-in-one` starts from.
    /// The local mechanism -- Unix socket, or named pipe on Windows -- is
    /// [`crate::transport::local_endpoint`], so a first boot needs no per-service
    /// port allocation.
    #[must_use]
    pub fn with_defaults(run_dir: &Path) -> Self {
        let mut config = Self {
            instances: vec![Instance::default()],
            ..Self::default()
        };
        for kind in ServiceKind::all() {
            let mut service = ServiceConfig::new(
                &crate::transport::local_endpoint(run_dir, kind.name()),
                default_tier(*kind),
                &default_types(*kind),
            );
            service.limits = default_limit_name(*kind).map(str::to_owned);
            if matches!(kind, ServiceKind::Voice) {
                service.udp_listen = Some("0.0.0.0:64738".to_owned());
            }
            let _ = config.services.insert(kind.name().to_owned(), service);
        }
        // Not a `ServiceKind`: it owns no wire type and the gateway never
        // routes to it directly (`docs/ARCHITECTURE.md` §4). It still needs a
        // real endpoint, because every other service subscribes to it over
        // gRPC, the same self-discovery gap that a bare `ServiceKind` loop
        // cannot fill.
        let _ = config.services.insert(
            "session-view".to_owned(),
            ServiceConfig::new(
                &crate::transport::local_endpoint(run_dir, "session-view"),
                Tier::Essential,
                &[],
            ),
        );
        // Also not a `ServiceKind`, and for the opposite reason to session-view:
        // it needs no endpoint at all. Nothing dials the announcer, it dials the
        // public server list, so this entry exists only so that an operator can
        // switch it off or point it at a different trust store.
        let _ = config.services.insert(
            "directory".to_owned(),
            ServiceConfig {
                tier: Tier::Optional,
                ..ServiceConfig::default()
            },
        );
        // Not a `ServiceKind` either (no client talks to it) but unlike the
        // announcer it *is* dialled, by `operator-api` reading the aggregate,
        // so it needs a real endpoint. Optional: a server with no health
        // collector is a server nobody can see the state of, which is a poorer
        // deployment and not a broken one.
        let _ = config.services.insert(
            "health".to_owned(),
            ServiceConfig::new(
                &crate::transport::local_endpoint(run_dir, "health"),
                Tier::Optional,
                &[],
            ),
        );
        // The gateway. It owns no wire type -- it routes them -- and nothing
        // dials it for work, but it still serves a gRPC surface so the `health`
        // collector can ask how it is; without an endpoint it fails at startup
        // with "gateway has no endpoint in the configuration", which is what a
        // bare `starling --all-in-one` did. Both shipped files carried a block
        // by hand to work around exactly this.
        //
        // `core`, the default. A tier says what the gateway does while a
        // service is unhealthy, so the gateway's own is one it would only ever
        // consult about itself.
        let _ = config.services.insert(
            "gateway".to_owned(),
            ServiceConfig::new(
                &crate::transport::local_endpoint(run_dir, "gateway"),
                Tier::Core,
                &[],
            ),
        );
        config
    }

    /// Let one server instance's `port` be the port it actually listens on.
    ///
    /// It was not: the gateway binds `[gateway] listen_tcp` and voice binds its
    /// own `udp_listen`, so `port` reached nothing but the public listing, and
    /// moving a server off 64738 meant finding three keys, two of which are in
    /// blocks an operator has no other reason to open. murmur has one `port=`,
    /// and so does this now.
    ///
    /// Only for a lone server instance, because that is the only case with an
    /// unambiguous answer: several of them share one gateway listener, and
    /// picking one of their ports for it would be arbitrary. Those deployments
    /// say `listen_tcp` themselves -- and a file that says it keeps it, here as
    /// everywhere else.
    fn adopt_single_server_port(&mut self, operator: &toml::Table) {
        let [server] = self.instances.as_slice() else {
            return;
        };
        let port = server.port;
        let stated = |table: &str, key: &str| {
            operator
                .get(table)
                .and_then(|table| table.get(key))
                .is_some()
        };

        if !stated("gateway", "listen_tcp") {
            self.gateway.listen_tcp = with_port(&self.gateway.listen_tcp, port);
        }
        // Audio skips the gateway, so voice has a socket of its own. A client
        // sends UDP to the host and port it made its TCP connection to, so the
        // two moving together is not tidiness: they are the same port to a
        // client, on the two protocols it uses.
        let voice_stated = operator
            .get("services")
            .and_then(|services| services.get("voice"))
            .and_then(|voice| voice.get("udp_listen"))
            .is_some();
        if !voice_stated
            && let Some(voice) = self.services.get_mut("voice")
            && let Some(udp) = &voice.udp_listen
        {
            voice.udp_listen = Some(with_port(udp, port));
        }
    }

    /// The service that owns `type_id`, if one is configured and enabled.
    #[must_use]
    pub fn route(&self, type_id: u16) -> Option<(&str, &ServiceConfig)> {
        self.services
            .iter()
            .find(|(_, service)| service.enabled && service.types.contains(&type_id))
            .map(|(name, service)| (name.as_str(), service))
    }

    /// Refuse a routing table with two answers for one question.
    ///
    /// # Errors
    ///
    /// [`ConfigError::DuplicateType`] naming both claimants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen: BTreeMap<u16, &str> = BTreeMap::new();
        for (name, service) in &self.services {
            if !service.enabled {
                continue;
            }
            for type_id in &service.types {
                if let Some(first) = seen.insert(*type_id, name) {
                    return Err(ConfigError::DuplicateType {
                        type_id: *type_id,
                        first: first.to_owned(),
                        second: name.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// `address` with its port replaced, keeping whatever it binds to.
///
/// Split at the **last** colon so an IPv6 literal keeps its address; an address
/// with no port at all is left alone rather than guessed at.
fn with_port(address: &str, port: u16) -> String {
    address
        .rsplit_once(':')
        .map_or_else(|| address.to_owned(), |(host, _)| format!("{host}:{port}"))
}

/// The tier each service ships with.
fn default_tier(kind: ServiceKind) -> Tier {
    match kind {
        ServiceKind::SessionLifecycle
        | ServiceKind::Permissions
        | ServiceKind::Metadata
        | ServiceKind::Userdata
        | ServiceKind::ServerConfig => Tier::Essential,
        ServiceKind::Voice | ServiceKind::Text | ServiceKind::Pchat | ServiceKind::Moderation => {
            Tier::Core
        }
        _ => Tier::Optional,
    }
}

/// The upstream types a service answers for, plus its own envelope.
///
/// Upstream numbers are flat and frozen, so they are listed here once.
fn default_types(kind: ServiceKind) -> Vec<u16> {
    let upstream: &[u16] = match kind {
        // UserState (9) and UserStats (22) are connection state, and both were
        // routed to userdata, which has no arm for either and returned
        // nothing. A frame with no handler is dropped silently, because an
        // unroutable frame is normally harmless, so both simply did nothing:
        // right-click → Information never opened a window, and self-mute and
        // self-deafen never took effect. The handlers for both live here, on
        // the service that owns a connection's existence.
        ServiceKind::SessionLifecycle => &[0, 2, 3, 4, 5, 9, 15, 21, 22],
        ServiceKind::Permissions => &[12, 13, 20],
        ServiceKind::Metadata => &[6, 7],
        // 18 is `UserList`, the registered-account list, which is genuinely
        // userdata's; it is simply not implemented yet, unlike the two above,
        // which were implemented and merely unreachable.
        ServiceKind::Userdata => &[14, 18, 23],
        ServiceKind::Voice => &[1, 19],
        ServiceKind::Text => &[11],
        // UserRemove (8) is a kick or a ban, which is moderation's, not userdata's.
        ServiceKind::Moderation => &[8, 10],
        ServiceKind::ServerConfig => &[24, 25],
        ServiceKind::Plugins => &[26],
        ServiceKind::ContextActions => &[16, 17],
        _ => &[],
    };
    let mut types = upstream.to_vec();
    types.push(kind.outer_type());
    types
}

/// Which bucket a service's inbound traffic is charged to.
fn default_limit_name(kind: ServiceKind) -> Option<&'static str> {
    match kind {
        ServiceKind::Screenshare => Some("signalling"),
        ServiceKind::Plugins => Some("plugin"),
        // Tunnelled audio is fifty frames a second, so the control bucket,
        // murmur's 1/s, throttles a talking client off the air within one
        // second of speech. Upstream does not charge it at all: `UDPTunnel` is
        // handled and returned from at the top of `Server::message`
        // (`Server.cpp:1905`), before the message-rate check further down.
        ServiceKind::Voice => Some("audio"),
        // The ACL editor emits one query per channel when it opens the tree,
        // and chat is a person typing. Both are *interactive bursts* by a human
        // rather than a flood, and both were being silently decimated by the
        // shared 1/s bucket, the same failure that moved screen-share
        // signalling and tunnelled audio off it.
        ServiceKind::Permissions => Some("acl"),
        ServiceKind::Text => Some("chat"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `text` to a scratch file and load it the way `--config` does.
    fn loaded(name: &str, text: &str) -> Config {
        let dir = std::env::temp_dir().join(format!("starling-config-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("starling.toml");
        std::fs::write(&path, text).expect("a scratch file");
        Config::load(&path).expect("the file loads")
    }

    #[test]
    fn a_media_plane_in_a_delta_file_reaches_both_of_its_readers() {
        // The shape the e2e harness writes. Screenshare starts its SFU from
        // this entry and session-lifecycle advertises it; a merge that dropped
        // or moved the field would break one of them silently.
        let config = loaded(
            "media-plane",
            "[services.screenshare]\npublic_url = \"127.0.0.1:39999\"\noptions = { media_port = \"39999\" }\n",
        );
        let service = config.services.get("screenshare").expect("the entry");
        assert!(service.enabled);
        assert_eq!(service.media_ip(), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(service.option::<u16>("media_port"), Some(39_999));
    }

    #[test]
    fn a_file_that_mentions_one_setting_keeps_every_other_default() {
        // The whole point of the overlay. This file used to be a server with an
        // empty service map: no routes, no buckets, and every service dead at
        // startup for want of an endpoint.
        let config = loaded("overlay", "[gateway]\nlisten_tcp = \"0.0.0.0:1234\"\n");

        assert_eq!(config.gateway.listen_tcp, "0.0.0.0:1234");
        assert_eq!(
            config.route(11).map(|(name, _)| name),
            Some("text"),
            "the routing table is not something a file has to restate"
        );
        assert!(config.gateway.limits.contains_key("chat"));
        assert!(
            config.services.get("voice").is_some_and(|v| v.enabled),
            "a service the file never mentions still runs"
        );
    }

    #[test]
    fn the_file_still_turns_a_service_off_when_it_says_so() {
        // Omission no longer means "off", so saying it has to keep working, or
        // the overlay would have removed an operator's only way to say it.
        let config = loaded("disable", "[services.pchat]\nenabled = false\n");
        assert!(config.route(1006).is_none());
        assert!(config.services.get("text").is_some_and(|t| t.enabled));
    }

    #[test]
    fn listing_server_instances_replaces_the_built_in_one_rather_than_adding_to_it() {
        // An array that merged item-wise would give an operator who listed two
        // servers a third one they never asked for, named "Starling".
        let config = loaded(
            "servers",
            "[[instances]]\nid = 1\nname = \"Main\"\nport = 64738\n\n\
             [[instances]]\nid = 2\nname = \"Staging\"\nport = 64739\n",
        );
        assert_eq!(config.instances.len(), 2);
        assert_eq!(config.instances[0].name, "Main");
    }

    #[test]
    fn moving_the_data_directory_moves_the_endpoints_that_live_under_it() {
        // The ordering trap: defaults built before `data_dir` was read would
        // leave every local socket under the old directory, and the operator
        // would find sockets in a directory they had just moved away from.
        let config = loaded("data-dir", "[runtime]\ndata_dir = \"/var/lib/starling\"\n");
        let endpoint = config
            .services
            .get("text")
            .and_then(|text| text.endpoint.clone())
            .expect("text has a local endpoint");
        assert!(
            endpoint.contains("/var/lib/starling"),
            "{endpoint} is not under the configured data directory"
        );
    }

    #[test]
    fn the_operational_settings_a_file_names_reach_the_server_instance() {
        // "How do I let twenty friends in and put a password on it?" had no
        // answer that looked like configuration before this.
        let config = loaded(
            "settings",
            "[[instances]]\nid = 1\nname = \"Frog Pond\"\nport = 64738\n\n\
             [instances.settings]\nmax_users = 20\npassword = \"hunter2\"\n",
        );
        let server = &config.instances[0];
        assert_eq!(server.name, "Frog Pond");
        assert_eq!(server.settings.max_users, Some(20));
        assert_eq!(
            server.settings.welcome_text, None,
            "unmentioned stays unset"
        );
    }

    #[test]
    fn one_servers_port_is_the_port_it_listens_on() {
        // It used to reach nothing but the public listing, so a server moved to
        // 64740 in the obvious place went on answering on 64738, and the two
        // keys that would have moved it are in blocks an operator otherwise
        // never opens.
        let config = loaded(
            "port",
            "[[instances]]\nid = 1\nname = \"Frog Pond\"\nport = 64740\n",
        );
        assert_eq!(config.gateway.listen_tcp, "0.0.0.0:64740");
        assert_eq!(
            config
                .services
                .get("voice")
                .and_then(|v| v.udp_listen.clone()),
            Some("0.0.0.0:64740".to_owned()),
            "a client sends UDP to the port it made TCP to"
        );
    }

    #[test]
    fn a_stated_listener_is_never_moved_underneath_the_operator() {
        // Binding to loopback, or to a port the gateway alone should move to,
        // is a deliberate thing to write and must survive the convenience above.
        let config = loaded(
            "port-explicit",
            "[[instances]]\nid = 1\nname = \"Frog Pond\"\nport = 64740\n\n\
             [gateway]\nlisten_tcp = \"127.0.0.1:9000\"\n",
        );
        assert_eq!(config.gateway.listen_tcp, "127.0.0.1:9000");
    }

    #[test]
    fn several_server_instances_leave_the_gateway_listener_alone() {
        // They share one listener, so picking one of their ports for it would
        // be arbitrary; those deployments say `listen_tcp` themselves.
        let config = loaded(
            "port-many",
            "[[instances]]\nid = 1\nname = \"Main\"\nport = 64738\n\n\
             [[instances]]\nid = 2\nname = \"Staging\"\nport = 64739\n",
        );
        assert_eq!(config.gateway.listen_tcp, "0.0.0.0:64738");
    }

    #[test]
    fn the_defaults_can_actually_start_a_server() {
        // `starling --all-in-one` with no file at all died on "gateway has no
        // endpoint in the configuration": the gateway is not a `ServiceKind`,
        // so the loop that fills this map skipped it, and both shipped files
        // carried a block by hand to paper over it. With a file being an
        // overlay on these defaults, that hole would have been inherited by
        // every configuration anybody wrote.
        let config = Config::with_defaults(Path::new("/run/starling"));
        for name in ["gateway", "health", "session-view"] {
            assert!(
                config
                    .services
                    .get(name)
                    .is_some_and(|service| service.endpoint.is_some()),
                "{name} must have an endpoint to bind"
            );
        }
    }

    #[test]
    fn a_typo_is_still_refused_after_the_merge() {
        // `deny_unknown_fields` is the reason a stale file fails at startup
        // rather than silently leaving a limit at its default, and merging over
        // the defaults must not be a way to smuggle one past it.
        let dir = std::env::temp_dir().join("starling-config-typo");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("starling.toml");
        std::fs::write(&path, "[gateway]\nlisten_tcpp = \"0.0.0.0:1\"\n").expect("a scratch file");

        let err = Config::load(&path).expect_err("an unknown key must be refused");
        assert!(matches!(err, ConfigError::Parse { .. }), "got {err}");
    }

    #[test]
    fn the_types_a_client_uses_go_to_the_service_that_implements_them() {
        // Routing a type to a service with no arm for it is invisible: the
        // frame is accepted, dropped, and never answered, so the feature just
        // does nothing. It happened to `UserState` and `UserStats`, which sat
        // on userdata while their handlers sat unreachable on
        // session-lifecycle, self-mute did nothing and right-click →
        // Information opened no window.
        let config = Config::with_defaults(Path::new("/run/starling"));
        for (type_id, expected, what) in [
            (9_u16, "session-lifecycle", "UserState / self-mute"),
            (22, "session-lifecycle", "UserStats / Information"),
            (21, "session-lifecycle", "CodecVersion"),
            (11, "text", "TextMessage"),
            (7, "metadata", "ChannelState"),
            (8, "moderation", "UserRemove / kick"),
            (14, "userdata", "QueryUsers"),
            (23, "userdata", "RequestBlob"),
        ] {
            assert_eq!(
                config.route(type_id).map(|(name, _)| name),
                Some(expected),
                "type {type_id} ({what}) must be routed to {expected}"
            );
        }
    }

    #[test]
    fn every_service_gets_a_route_and_a_tier_by_default() {
        let config = Config::with_defaults(Path::new("/run/starling"));
        for kind in ServiceKind::all() {
            let service = config
                .services
                .get(kind.name())
                .unwrap_or_else(|| panic!("{} is unconfigured", kind.name()));
            assert!(service.types.contains(&kind.outer_type()));
        }
        assert_eq!(
            config.services.get("session-lifecycle").map(|s| s.tier),
            Some(Tier::Essential)
        );
    }

    #[test]
    fn the_defaults_route_every_upstream_type_exactly_once() {
        // Two services claiming one type is unroutable, and the gateway cannot
        // notice at run time because it never parses a payload.
        Config::with_defaults(Path::new("/run/starling"))
            .validate()
            .expect("the shipped defaults must be a valid routing table");
    }

    #[test]
    fn every_bucket_a_service_names_actually_exists() {
        // A service naming a bucket the operator did not define is allowed
        // through unlimited by `Limiter::check`, deliberately, because
        // starving a route over a typo is the worse failure. That makes the
        // typo *invisible*, so it is caught here instead: the defaults must
        // name only buckets the defaults define.
        let config = Config::with_defaults(Path::new("/run/starling"));
        for (name, service) in &config.services {
            let Some(bucket) = &service.limits else {
                continue;
            };
            assert!(
                config.gateway.limits.contains_key(bucket),
                "{name} is charged to {bucket:?}, which no bucket defines"
            );
        }
    }

    #[test]
    fn the_interactive_routes_do_not_share_murmurs_one_per_second_bucket() {
        // Measured in an e2e run: 120 `ACL` frames and a `TextMessage` dropped,
        // the latter failing a fan-out test by losing exactly the sixth message
        // of eight. Both are human-driven bursts rather than floods.
        let config = Config::with_defaults(Path::new("/run/starling"));
        for service in ["permissions", "text"] {
            let bucket = config
                .services
                .get(service)
                .and_then(|s| s.limits.clone())
                .unwrap_or_else(|| "control".to_owned());
            assert_ne!(bucket, "control", "{service} is still on murmur's 1/s");
        }
    }

    #[test]
    fn a_contested_type_is_refused_with_both_claimants_named() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        if let Some(text) = config.services.get_mut("text") {
            // pchat already owns 1006; claiming it twice is what must be caught.
            text.types.push(1006);
        }
        let err = config.validate().expect_err("1006 belongs to pchat");
        assert!(matches!(
            err,
            ConfigError::DuplicateType { type_id: 1006, .. }
        ));
    }

    #[test]
    fn a_disabled_service_stops_answering_for_its_types() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        assert!(config.route(1006).is_some());
        if let Some(pchat) = config.services.get_mut("pchat") {
            pchat.enabled = false;
        }
        assert!(config.route(1006).is_none());
    }

    #[test]
    fn voice_owns_its_own_udp_socket_by_default() {
        // Audio bypassing the gateway is the whole realtime plane; a default
        // that left this unset would quietly route audio through the gateway.
        let config = Config::with_defaults(Path::new("/run/starling"));
        assert_eq!(
            config
                .services
                .get("voice")
                .and_then(|v| v.udp_listen.clone()),
            Some("0.0.0.0:64738".to_owned())
        );
    }
}
