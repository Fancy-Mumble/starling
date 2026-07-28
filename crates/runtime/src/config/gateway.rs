//! The gateway's own deployment configuration.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::scalars::HumanDuration;
use crate::ratelimit::Rate;

/// Where the control plane listens and how much it will hold for a client.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct GatewayConfig {
    /// The control plane. TLS terminates here.
    pub listen_tcp: String,

    /// Per client. Full means **disconnect that client**: dropping a control
    /// message desyncs it permanently and silently, and queueing without a
    /// bound is a memory `DoS` (`docs/ARCHITECTURE.md` §5).
    pub control_queue: usize,

    /// Per client, for tunnelled audio. Full means drop the oldest and count
    /// it — a late audio frame is worthless.
    pub audio_queue: usize,

    /// Per gRPC call, unless a route overrides it.
    pub default_deadline: HumanDuration,

    /// How many consecutive failures trip a service's breaker, and for how
    /// long. Deadlines alone fail slowly: a saturated service makes every
    /// caller wait the full deadline and *then* fail.
    pub breaker_failures: u32,

    /// How long a tripped breaker sheds before probing again.
    pub breaker_cooldown: HumanDuration,

    /// The identity presented to clients.
    pub tls: TlsConfig,

    /// Buckets, by name. A route names one; absent means `control`.
    pub limits: BTreeMap<String, LimitConfig>,

    /// The replay ring that makes RESUME possible.
    pub resume: ResumeConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_tcp: "0.0.0.0:64738".to_owned(),
            control_queue: 4096,
            audio_queue: 128,
            default_deadline: HumanDuration::secs(5),
            breaker_failures: 5,
            breaker_cooldown: HumanDuration::secs(10),
            tls: TlsConfig::default(),
            limits: default_limits(),
            resume: ResumeConfig::default(),
        }
    }
}

/// murmur's single bucket, plus the routes that must not share it.
fn default_limits() -> BTreeMap<String, LimitConfig> {
    BTreeMap::from([
        (
            "control".to_owned(),
            LimitConfig {
                rate: Rate::per_second(1.0),
                burst: 5,
            },
        ),
        // Tunnelled audio, which is the fallback path for every client whose
        // UDP is blocked. Opus frames are 10 ms to 60 ms; a client sending the
        // usual 10 ms frames emits a hundred a second, and the burst covers the
        // jitter of a client that batches rather than paces them.
        //
        // Deliberately generous, because the cost of being wrong is asymmetric:
        // too high wastes some bandwidth from one client, while too low cuts a
        // person off mid-sentence with no error anywhere. Upstream does not
        // rate-limit this path at all (`Server.cpp:1905`), so a bucket is
        // already stricter than murmur.
        (
            "audio".to_owned(),
            LimitConfig {
                rate: Rate::per_second(200.0),
                burst: 400,
            },
        ),
        (
            "signalling".to_owned(),
            LimitConfig {
                rate: Rate::per_second(10.0),
                burst: 20,
            },
        ),
        (
            "plugin".to_owned(),
            LimitConfig {
                rate: Rate::per_second(4.0),
                burst: 15,
            },
        ),
    ])
}

/// One named bucket.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    /// Sustained rate.
    pub rate: Rate,
    /// How much may arrive at once.
    pub burst: u32,
}

/// Certificate and key.
///
/// Omit both and a self-signed pair is generated on first boot, as murmur does:
/// Mumble clients identify a server by certificate fingerprint, so the pair
/// must then be stable across restarts.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Certificate chain, PEM, leaf first.
    pub cert: Option<PathBuf>,
    /// Private key, PEM.
    pub key: Option<PathBuf>,
}

/// The sequence number and its replay ring.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResumeConfig {
    /// Whether Fancy clients may resume at all.
    pub enabled: bool,
    /// Frames kept per session. The ring bounds the memory a resuming client
    /// can cost; a longer gap than this forces a full re-sync, and the client
    /// is told so rather than left with a hole.
    pub ring: usize,
    /// How long a disconnected session may still resume.
    pub ttl: HumanDuration,
}

impl Default for ResumeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ring: 256,
            ttl: HumanDuration::secs(120),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_control_bucket_matches_murmur() {
        // Legacy clients are tuned against 1 msg/s burst 5; changing it would
        // change behaviour they were built around.
        let limits = GatewayConfig::default().limits;
        let control = limits.get("control").copied().expect("control bucket");
        assert!(
            (control.rate.as_per_second() - 1.0).abs() < f64::EPSILON,
            "the default control bucket is murmur's 1 msg/s"
        );
        assert_eq!(control.burst, 5);
    }

    #[test]
    fn audio_is_not_charged_to_the_control_bucket() {
        // The bug this exists for: tunnelled audio was routed to `control`,
        // which is murmur's 1 message per second. A client talking over TCP —
        // everyone behind a UDP-blocking firewall — was throttled off the air
        // after its first five frames, and the only symptom was silence.
        let limits = GatewayConfig::default().limits;
        let audio = limits.get("audio").copied().expect("audio bucket");
        assert!(
            audio.rate.as_per_second() >= 100.0,
            "a client sending 10 ms Opus frames emits a hundred a second"
        );
        assert!(audio.burst >= 100);
    }

    #[test]
    fn signalling_is_not_charged_to_the_control_bucket() {
        // A screen-share start emits several messages back to back; on murmur's
        // single bucket that silently ate the SDP offer.
        let limits = GatewayConfig::default().limits;
        let signalling = limits
            .get("signalling")
            .copied()
            .expect("signalling bucket");
        assert!(signalling.rate.as_per_second() > 1.0);
        assert!(signalling.burst > 5);
    }
}
