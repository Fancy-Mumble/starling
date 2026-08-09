//! One service's deployment configuration.
//!
//! Every service block takes the same keys. `types` is the outer message type,
//! one set per service; a service's own types live in its nested envelope.

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
    /// The gateway treats it by tier, exactly as it treats an unhealthy one, so
    /// switching it off is a supported deployment, not a broken one.
    pub enabled: bool,

    /// `http://host:port` or `unix:/run/starling/name.sock`.
    ///
    /// Where other services **dial** this one and, unless [`Self::bind`] says
    /// otherwise, the address it **serves** on -- one string for both directions.
    ///
    /// Not ignored under `--all-in-one`: a service binds this string in every
    /// mode, so the shipped local endpoints mean all-in-one serves over real
    /// sockets. Use `inproc:name` for calls that never leave the process; a
    /// co-located pair short-circuits to in-process once the callee registers,
    /// even over a configured socket.
    pub endpoint: Option<String>,

    /// What the gateway does while this service is down.
    pub tier: Tier,

    /// The wire types the gateway routes here.
    pub types: Vec<u16>,

    /// Which rate-limit bucket inbound frames for this service are charged to.
    ///
    /// Absent means the default control bucket (1/s); screen sharing must not be
    /// on that one.
    pub limits: Option<String>,

    /// The address this service's own gRPC server binds, when it differs from
    /// the one others dial it at.
    ///
    /// Absent (the normal case) means [`Self::endpoint`]: one address per
    /// service. Set it when the dialled name is not bindable -- on Kubernetes
    /// `endpoint` names a Service whose virtual `ClusterIP` belongs to no
    /// interface, so a pod cannot bind it; `bind = "http://0.0.0.0:50051"`
    /// separates the two without moving the name others dial.
    ///
    /// Both parse the same way, so a `unix:` endpoint with an `http://` bind is
    /// two visible boundaries, never a silent transport change.
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

    /// The live channel over WebTransport. Only `operator-api` reads it.
    pub webtransport: Option<WebTransport>,

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
            webtransport: None,
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

    /// The literal IP in `public_url`, when it names one.
    ///
    /// The media-plane precondition: an SDP answer carries an address, not a
    /// name, so a `public_url` whose host is a hostname cannot start an SFU.
    /// Screenshare starts its SFU on this and the handshake advertises the SFU
    /// on this; two parsers would let the advertisement and the media plane
    /// disagree.
    #[must_use]
    pub fn media_ip(&self) -> Option<std::net::IpAddr> {
        let (host, _) = self.public_url.as_deref()?.rsplit_once(':')?;
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()
    }
}

/// A service's own database.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    /// `sqlite://...`, `postgres://...` or `mysql://...`.
    pub url: String,
    /// Pool size. In-memory SQLite is capped to one automatically (five
    /// connections to `:memory:` are five different databases).
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
/// service that may not be running.
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

/// The live channel's WebTransport half.
///
/// Off unless configured: WebTransport is HTTP/3 over QUIC, which a reverse
/// proxy generally cannot forward. Behind one, reach the same channel over the
/// WebSocket at `/v1/events` and never bind this port.
///
/// `listen` is UDP, a different socket from the API's TCP `listen`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebTransport {
    /// Off unless the deployment can terminate QUIC.
    pub enabled: bool,
    /// The UDP address to bind, e.g. `0.0.0.0:8443`.
    pub listen: String,
    /// The certificate chain, PEM.
    ///
    /// Needed even when a proxy terminates TLS elsewhere -- this is the listener
    /// it does not terminate. Absent, a self-signed pair is generated on first
    /// boot, which a browser refuses, so deploy a real one.
    pub cert: Option<PathBuf>,
    /// The private key, PEM.
    pub key: Option<PathBuf>,
}

impl Default for WebTransport {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:8443".to_owned(),
            cert: None,
            key: None,
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
    fn webtransport_is_off_and_needs_no_keys_at_all() {
        // A service block that never mentions it must not bind a UDP port.
        // WebTransport cannot be proxied, so switching it on is a deployment
        // decision and never a default.
        let cfg: ServiceConfig =
            toml::from_str("tier = \"optional\"\ntypes = []\n").expect("a block without it");
        assert!(cfg.webtransport.is_none());

        let cfg: ServiceConfig =
            toml::from_str("tier = \"optional\"\ntypes = []\n\n[webtransport]\n")
                .expect("an empty block");
        assert!(!cfg.webtransport.expect("present").enabled);
    }

    #[test]
    fn webtransport_takes_its_own_udp_address_and_certificate() {
        let cfg: ServiceConfig = toml::from_str(
            "tier = \"optional\"\ntypes = []\n\n[webtransport]\n\
             enabled = true\nlisten = \"0.0.0.0:8443\"\n\
             cert = \"/etc/starling/wt/cert.pem\"\nkey = \"/etc/starling/wt/key.pem\"\n",
        )
        .expect("a configured block");

        let wt = cfg.webtransport.expect("present");
        assert!(wt.enabled);
        // UDP, and deliberately not the API's TCP `listen`: they are different
        // sockets and sharing the number would only look like they were not.
        assert_eq!(wt.listen, "0.0.0.0:8443");
        assert!(wt.cert.is_some() && wt.key.is_some());
    }

    #[test]
    fn media_ip_is_the_literal_ip_and_never_a_name() {
        let with = |url: &str| ServiceConfig {
            public_url: Some(url.to_owned()),
            ..ServiceConfig::default()
        };
        assert_eq!(
            with("203.0.113.9:7000").media_ip(),
            Some("203.0.113.9".parse().unwrap())
        );
        assert_eq!(
            with("[2001:db8::1]:7000").media_ip(),
            Some("2001:db8::1".parse().unwrap())
        );
        // A name is a valid public_url (files signs URLs with one) but not a
        // valid SDP candidate, so it must not read as a media plane.
        assert_eq!(with("sfu.example.org:7000").media_ip(), None);
        assert_eq!(ServiceConfig::default().media_ip(), None);
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
