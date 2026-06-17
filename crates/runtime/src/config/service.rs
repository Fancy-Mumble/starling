//! One service's deployment configuration.
//!
//! Every service block takes the same keys, and `types` is the outer message
//! type from `docs/PROTOCOL-COMPATIBILITY.md` §3 — one number per service,
//! because the service's own message types live in its nested envelope and the
//! gateway never looks inside. Adding a service is three lines of TOML and no
//! gateway release.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::operator::OperatorAuth;
use crate::config::scalars::{ByteSize, HumanDuration};
use crate::tier::Tier;

/// Where a service listens, what it owns, and what it stores.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServiceConfig {
    /// A service the operator has chosen not to run.
    ///
    /// The gateway treats an absent service exactly as it treats an unhealthy
    /// one, by tier — so switching this off is a supported deployment, not a
    /// broken one.
    pub enabled: bool,

    /// `http://host:port` or `unix:/run/starling/name.sock`.
    ///
    /// Ignored in all-in-one mode, where calls never leave the process.
    pub endpoint: Option<String>,

    /// What the gateway does while this service is down.
    pub tier: Tier,

    /// The wire types the gateway routes here.
    pub types: Vec<u16>,

    /// Which rate-limit bucket inbound frames for this service are charged to.
    ///
    /// Absent means the default control bucket, which is murmur's 1/s. Screen
    /// sharing must not be on that one — see `ratelimit`.
    pub limits: Option<String>,

    /// The address this service's own gRPC server binds.
    pub bind: Option<String>,

    /// Voice's own UDP socket. Audio skips the gateway entirely.
    pub udp_listen: Option<String>,

    /// An extra HTTP listener, for the services that have one.
    pub listen: Option<String>,

    /// What signed URLs point at, which is not necessarily what `listen` binds.
    pub public_url: Option<String>,

    /// How long a signed URL stays valid.
    pub url_ttl: Option<HumanDuration>,

    /// Largest upload accepted.
    pub max_upload: Option<ByteSize>,

    /// This service's own database. No service reads another's tables.
    pub storage: Option<StorageConfig>,

    /// Authentication for the admin plane. Only `operator-api` reads it.
    pub auth: Option<OperatorAuth>,

    /// Where `operator-api` writes its own audit record.
    pub audit: Option<OperatorAudit>,

    /// Settings a service adds without a runtime release.
    pub options: BTreeMap<String, String>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: None,
            tier: Tier::Core,
            types: Vec::new(),
            limits: None,
            bind: None,
            udp_listen: None,
            listen: None,
            public_url: None,
            url_ttl: None,
            max_upload: None,
            storage: None,
            auth: None,
            audit: None,
            options: BTreeMap::new(),
        }
    }
}

impl ServiceConfig {
    /// A service running at `endpoint`, in `tier`, owning `types`.
    #[must_use]
    pub fn new(endpoint: &str, tier: Tier, types: &[u16]) -> Self {
        Self {
            endpoint: Some(endpoint.to_owned()),
            tier,
            types: types.to_vec(),
            ..Self::default()
        }
    }

    /// An `options` entry, parsed.
    pub fn option<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.options.get(key).and_then(|v| v.parse().ok())
    }
}

/// A service's own database.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    /// `sqlite://…`, `postgres://…` or `mysql://…`.
    pub url: String,
    /// Pool size. In-memory SQLite is capped to one automatically, because five
    /// connections to `:memory:` are five different databases.
    pub max_connections: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: 8,
        }
    }
}

/// The admin plane's own audit file.
///
/// `operator-api` writes this itself rather than calling the audit service:
/// audit is optional, and the highest-privilege plane must not depend on a
/// service the operator may not be running.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct OperatorAudit {
    /// Where the record goes.
    pub path: PathBuf,
    /// A request that cannot be recorded is refused.
    pub fail_closed: bool,
}

impl Default for OperatorAudit {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/log/starling/operator-audit.log"),
            fail_closed: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_key_in_a_service_block_is_an_error_not_a_shrug() {
        // A typo that silently leaves a limit at its default is the failure
        // mode this rejects.
        let err = toml::from_str::<ServiceConfig>("tier = \"core\"\ntyps = [1005]\n");
        assert!(err.is_err(), "unknown key must be refused");
    }

    #[test]
    fn a_service_block_needs_only_the_three_documented_lines() {
        let cfg: ServiceConfig = toml::from_str(
            "endpoint = \"http://whiteboard:50051\"\ntier = \"optional\"\ntypes = [1018]\n",
        )
        .expect("three lines is a whole service");
        assert_eq!(cfg.tier, Tier::Optional);
        assert_eq!(cfg.types, vec![1018]);
        assert!(cfg.enabled);
    }
}
