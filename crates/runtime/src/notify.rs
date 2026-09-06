//! Telling systemd what this process is doing.
//!
//! The service unit is `Type=notify` with a `WatchdogSec`, which means systemd
//! waits for `READY=1` before it considers the unit started and restarts the
//! process if `WATCHDOG=1` stops arriving.
//!
//! # Why the watchdog is gated on liveness
//!
//! A plain periodic ping proves only that the runtime is still scheduling
//! timers, which a wedged server also does: every background task can be dead
//! while the accept loop still answers and the timer still fires. Pinging only
//! while [`Health::is_live`] holds is what makes systemd restart a server whose
//! work has stopped but whose socket has not.
//!
//! # Why this is not a dependency
//!
//! The protocol is a newline-separated `KEY=value` datagram to the path in
//! `$NOTIFY_SOCKET`. That is this file. A crate for it would be another
//! third-party graph for `cargo-deny` to vet, in the process that terminates
//! TLS for strangers.

#[cfg(target_os = "linux")]
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use crate::health::Health;

/// Send one notification to systemd, if it is listening.
///
/// A no-op when `$NOTIFY_SOCKET` is unset, which is every case except running
/// under a `Type=notify` unit: the same binary run from a terminal, from
/// Docker, or under a supervisor that does not speak this protocol.
#[cfg(target_os = "linux")]
pub fn notify(state: &str) -> bool {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return false;
    };
    let path = std::path::PathBuf::from(path);
    // An abstract socket, which systemd uses by default, is written with a
    // leading NUL. `UnixDatagram` cannot address one through a path, so this
    // handles the filesystem form and reports the other rather than pretending.
    if path.as_os_str().as_encoded_bytes().first() == Some(&b'@') {
        tracing::debug!("NOTIFY_SOCKET is abstract; readiness will not be reported");
        return false;
    }
    let Ok(socket) = UnixDatagram::unbound() else {
        return false;
    };
    socket.send_to(state.as_bytes(), &path).is_ok()
}

/// Non-Linux: there is no systemd to tell.
#[cfg(not(target_os = "linux"))]
pub fn notify(state: &str) -> bool {
    let _ = state;
    false
}

/// Tell systemd the server is up and can answer.
///
/// Sent after warm-up rather than at start-up, so `systemctl start` returns
/// when the server can serve rather than when the process exists. Without it a
/// `Type=notify` unit waits for its whole timeout and then reports a failure
/// for a server that is running perfectly.
pub fn ready() {
    let _ = notify("READY=1\n");
}

/// Tell systemd the server is going down on purpose.
pub fn stopping() {
    let _ = notify("STOPPING=1\n");
}

/// Ping the watchdog for as long as this process is live.
///
/// Returns when `shutdown` drains. **Stops pinging** when [`Health::is_live`]
/// goes false, which is what makes systemd restart the process: the alternative,
/// pinging on a timer, proves only that the timer works.
///
/// `interval` should be well under the unit's `WatchdogSec`, because a missed
/// ping is a restart and a busy machine must not cause one. Half is the
/// convention and what systemd's own documentation suggests.
pub async fn watchdog(health: Health, shutdown: crate::shutdown::Shutdown, interval: Duration) {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return;
    }
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = shutdown.wait() => {
                stopping();
                return;
            }
            _ = tick.tick() => {
                if health.is_live() {
                    let _ = notify("WATCHDOG=1\n");
                } else {
                    // Deliberately silent to systemd, loud in the log: the
                    // restart that follows should not be a mystery.
                    tracing::error!(
                        stale = ?health.stale(),
                        "not pinging the watchdog: this process is no longer live"
                    );
                }
            }
        }
    }
}

/// How often to ping, given the unit's `WatchdogSec`.
///
/// systemd exports it as `WATCHDOG_USEC`.
#[must_use]
pub fn interval_from_env() -> Option<Duration> {
    interval_from(std::env::var("WATCHDOG_USEC").ok().as_deref())
}

/// The same, from a value rather than from the environment.
///
/// Split out so the arithmetic is testable: the workspace denies `unsafe`, and
/// setting an environment variable is `unsafe` in this edition, so a test that
/// went through the environment could not be written at all.
#[must_use]
pub fn interval_from(raw: Option<&str>) -> Option<Duration> {
    let micros: u64 = raw?.parse().ok()?;
    // Halved, so one late tick on a loaded machine is not a restart. A missed
    // ping is not a warning to systemd; it is a kill.
    (micros > 0).then(|| Duration::from_micros(micros / 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ping_interval_is_half_the_watchdog_deadline() {
        // A missed ping is not a warning to systemd, it is a kill, so pinging
        // at the deadline would restart a healthy server on a busy machine.
        assert_eq!(
            interval_from(Some("60000000")),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn no_deadline_asks_for_no_pings() {
        // Unset, zero, or unparseable all mean the unit has no watchdog, and
        // pinging one that does not exist is not an error to report.
        assert_eq!(interval_from(None), None);
        assert_eq!(interval_from(Some("0")), None);
        assert_eq!(interval_from(Some("not a number")), None);
    }
}
