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

    /// Per client; full means **disconnect that client**. Dropping a control
    /// message desyncs it silently, and unbounded queueing is a memory `DoS`.
    pub control_queue: usize,

    /// Per client, the bytes the control lane may hold before that client is
    /// disconnected. Bounds memory where `control_queue` only bounds the frame
    /// count. The login channel flood is what pushes against it: a server whose
    /// channel descriptions sum past this admits a client to a truncated tree.
    /// Raise it for a server with heavy channel artwork.
    pub control_bytes: usize,

    /// Per client, for tunnelled audio. Full means drop the oldest and count
    /// it, a late audio frame is worthless.
    pub audio_queue: usize,

    /// How long the gateway waits on one call to a service before counting it
    /// as a failure.
    ///
    /// The call it bounds is `attach`, which is the only one the gateway makes:
    /// the dial, the handshake and the response headers. Not the attachment
    /// that follows, which is a stream and is meant to be long-lived.
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

    /// How long a peer has to finish its TLS handshake.
    ///
    /// Everything before this point is unauthenticated. Without a deadline a
    /// peer that completes TCP and then trickles one byte holds a task, a file
    /// descriptor and a rustls buffer for as long as it likes: the idle reaper
    /// only sees connections registered *after* the handshake returns.
    pub handshake_timeout: HumanDuration,

    /// How many TLS handshakes may be in flight at once, server-wide.
    ///
    /// Reached means the next connection is closed immediately rather than
    /// queued. Well above what a genuine login storm needs, because a
    /// reconnect after a restart is every client at once.
    pub max_pending_handshakes: usize,

    /// How many of those one address may hold.
    ///
    /// What stops a single peer filling `max_pending_handshakes` and locking
    /// everybody else out. Several, not one: a household or an office behind
    /// one NAT address is normal.
    pub max_pending_per_address: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_tcp: "0.0.0.0:64738".to_owned(),
            control_queue: 4096,
            // 4 MiB: dozens of avatars plus far more ordinary control traffic
            // than a healthy client is ever behind on. A thousand clients each
            // at the ceiling is 4 GiB, a figure an operator can reason about.
            control_bytes: 4 * 1024 * 1024,
            audio_queue: 128,
            default_deadline: HumanDuration::secs(5),
            breaker_failures: 5,
            breaker_cooldown: HumanDuration::secs(10),
            tls: TlsConfig::default(),
            limits: default_limits(),
            resume: ResumeConfig::default(),
            // Ten seconds: a TLS 1.3 handshake over a bad mobile link is well
            // under one second, and murmur's own client gives up long before
            // this. Slow enough to never cut off a real client, short enough
            // that a held slot is measured in seconds.
            handshake_timeout: HumanDuration::secs(10),
            // 1 024 concurrent handshakes is far more than a full server's
            // reconnect storm, and bounds what an unauthenticated peer can
            // make the process hold.
            max_pending_handshakes: 1024,
            // Concurrency is rate times duration, which is what makes this
            // number defensible rather than a guess: a handshake takes single
            // -digit milliseconds, so 64 in flight from one address is
            // thousands of logins a second from it. A whole office reconnecting
            // through one NAT address after a restart never reaches that --
            // they arrive over seconds, not all within one handshake -- while a
            // peer holding slots open to the deadline is stopped at 64 rather
            // than at the server-wide ceiling.
            max_pending_per_address: 64,
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
        // The ACL editor, and the reason this bucket exists: opening the
        // channel tree issues one `ACL`(13) query **per channel**, so a server
        // with thirty channels emits thirty queries in a second or two. On the
        // shared control bucket the first five arrive and the rest are dropped
        // in silence, an administrator sees a tree that renders empty
        // permissions for most of it and no error anywhere.
        //
        // Measured, not guessed: a single e2e run dropped 120 `ACL` frames.
        (
            "acl".to_owned(),
            LimitConfig {
                rate: Rate::per_second(20.0),
                burst: 60,
            },
        ),
        // Bulk transfer's control plane, and the reason this bucket exists:
        // playing a shared video asks for a download URL per span it fetches.
        // A signed URL is reused while it lasts, but the first request for one
        // is not the only one - a second file, a save, a URL that has aged out
        // mid-playback - and on the shared control bucket those arrive at a
        // player as a stream that stops partway through with "Error". Nothing
        // in the client can retry it into existence: a throttled frame is
        // dropped, so the grant it asked for simply never comes.
        (
            "files".to_owned(),
            LimitConfig {
                rate: Rate::per_second(10.0),
                burst: 30,
            },
        ),
        // Chat. A person typing several short messages in a row legitimately
        // emits them faster than one a second, and the burst is shared with
        // every other control message their client is sending, so a client
        // that is also announcing a channel change or a mute can exhaust it
        // between two sentences and lose one.
        //
        // Losing a message somebody typed is the worst failure in this table:
        // it is silent, it is attributed to nothing, and the sender believes
        // they were heard.
        (
            "chat".to_owned(),
            LimitConfig {
                rate: Rate::per_second(5.0),
                burst: 20,
            },
        ),
    ])
}

/// One named bucket.
///
/// `PartialEq` so a live `messagelimit` change can be compared with what is
/// applied, and an unchanged bucket skipped rather than re-tuned per frame.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    /// Sustained rate.
    pub rate: Rate,
    /// How much may arrive at once.
    pub burst: u32,
}

/// Certificate and key.
///
/// Omit both and a self-signed pair is generated on first boot. Mumble clients
/// identify a server by certificate fingerprint, so the pair must then be
/// stable across restarts.
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
        // which is murmur's 1 message per second. A client talking over TCP,
        // everyone behind a UDP-blocking firewall, was throttled off the air
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
    fn an_acl_editor_is_not_charged_to_the_control_bucket() {
        // Found in an e2e run, where 120 `ACL`(13) frames were dropped: the
        // editor issues one query per channel when it opens the tree, so the
        // shared 1/s bucket admits five and silently discards the rest. The
        // administrator sees a tree with most of its permissions blank and
        // nothing anywhere says why.
        let limits = GatewayConfig::default().limits;
        let acl = limits.get("acl").copied().expect("acl bucket");
        assert!(
            acl.burst >= 30,
            "a server with thirty channels opens thirty queries at once"
        );
        assert!(acl.rate.as_per_second() > 1.0);
    }

    #[test]
    fn bulk_transfer_gets_more_than_one_message_a_second() {
        // A player fetching a video asks for a signed URL more than once a
        // second when one ages out or a second file is opened, and a dropped
        // ask is a stream that stops with no error the client can explain.
        let limits = GatewayConfig::default().limits;
        let files = limits.get("files").copied().expect("files bucket");
        assert!(files.rate.as_per_second() > 1.0);
        assert!(files.burst >= 20);
    }

    #[test]
    fn chat_is_not_charged_to_the_control_bucket() {
        // The failure this exists for is the worst kind in this table: a
        // message somebody typed is dropped in silence, attributed to nothing,
        // and the sender believes they were heard. A person sending several
        // short messages in a row exceeds one a second easily, and shares the
        // burst with every other control frame their client emits.
        let limits = GatewayConfig::default().limits;
        let chat = limits.get("chat").copied().expect("chat bucket");
        assert!(chat.rate.as_per_second() >= 5.0);
        assert!(chat.burst >= 10);
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
