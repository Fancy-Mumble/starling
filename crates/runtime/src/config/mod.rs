//! Deployment configuration: read once at startup and injected at construction.
//!
//! The restart-anyway layer -- endpoints, ports, TLS paths, storage URLs, tiers
//! and routes. Anything an operator expects to change live belongs to the
//! `server-config` service instead.
//!
//! Unknown keys are **rejected**, so a typo fails loudly.

mod env;
mod gateway;
mod operator;
mod scalars;
mod service;

pub use env::{apply_environment, env_key};
pub use gateway::{GatewayConfig, LimitConfig, ResumeConfig, TlsConfig};
pub use operator::{AuthMode, JwtAuth, MtlsAuth, OidcAuth, OperatorAuth, StaticToken, TokenAuth};
pub use scalars::{ByteSize, HumanDuration};
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
    /// Virtual servers, in murmur's sense. Metadata runs one actor per entry.
    pub virtual_servers: Vec<VirtualServer>,
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

/// One virtual server.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct VirtualServer {
    /// Its id. Every stored row and every actor is keyed by this.
    pub id: u32,
    /// Its name, which is also the name of its root channel.
    pub name: String,
    /// Its control port. murmur's convention is `base_port + server_id`.
    pub port: u16,
}

impl Default for VirtualServer {
    fn default() -> Self {
        Self {
            id: 1,
            name: "Starling".to_owned(),
            port: 64738,
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
    /// Read `path`, then apply environment overrides.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] if the file cannot be read, carries an unknown key, or
    /// describes a routing table two services would both answer for.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
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
            virtual_servers: vec![VirtualServer::default()],
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
        config
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
