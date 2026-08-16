//! The per-client queue bounds, as the operator has them *now*.
//!
//! `[gateway] control_bytes`, `audio_queue` and `control_queue` size what one
//! client may have outstanding before the policy in `connection`'s header
//! applies: disconnect on a full control lane, drop the oldest audio frame.
//!
//! They used to be read from the boot configuration at accept time, which made
//! them exactly the wrong shape for the incident they exist for. A server
//! disconnecting clients for control overflow -- a channel tree with more
//! artwork than 4 MiB, the case `runtime.max_tree_message` was raised for --
//! could only be widened by restarting the process holding every client. So
//! they live here instead, in atomics shared by every connection, and a
//! reloaded file moves them under the connections already open.
//!
//! # Two of the three reach a live connection, and one cannot
//!
//! `control_bytes` and `audio_queue` are **read on every enqueue**, so raising
//! either takes effect on the next frame for every client, connected or not.
//!
//! `control_queue` is the capacity of a `tokio::sync::mpsc`, fixed when the
//! channel is created and not resizable afterwards. A client already accepted
//! keeps the depth it was accepted with. That is why it is classified
//! `NextConnection` rather than `Live`: the distinction is the difference
//! between an operator waiting for a change that is coming and one waiting for
//! a change that can never arrive.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use starling_runtime::config::GatewayConfig;

/// The queue bounds every connection reads.
///
/// Cheap to clone behind the `Arc` every connection holds; every clone sees
/// the same numbers, which is the point.
#[derive(Debug)]
pub struct Limits {
    control_bytes: AtomicUsize,
    audio_queue: AtomicUsize,
    control_queue: AtomicUsize,
}

impl Limits {
    /// The bounds `config` states.
    #[must_use]
    pub fn from_config(config: &GatewayConfig) -> Self {
        Self {
            // `max(1)` here rather than at each read: a queue of zero accepts
            // nothing, so a file saying `0` would disconnect every client on
            // its first frame, and the read path is not where that should be
            // discovered.
            control_bytes: AtomicUsize::new(config.control_bytes.max(1)),
            audio_queue: AtomicUsize::new(config.audio_queue.max(1)),
            control_queue: AtomicUsize::new(config.control_queue.max(1)),
        }
    }

    /// Adopt `config`, and say which bounds actually moved.
    ///
    /// The names are for the log line an operator reads: "the file changed" is
    /// not the same statement as "this gateway is now running on it".
    pub fn adopt(&self, config: &GatewayConfig) -> Vec<&'static str> {
        let mut moved = Vec::new();
        for (name, cell, wanted) in [
            (
                "control_bytes",
                &self.control_bytes,
                config.control_bytes.max(1),
            ),
            ("audio_queue", &self.audio_queue, config.audio_queue.max(1)),
            (
                "control_queue",
                &self.control_queue,
                config.control_queue.max(1),
            ),
        ] {
            if cell.swap(wanted, Ordering::Relaxed) != wanted {
                moved.push(name);
            }
        }
        moved
    }

    /// Bytes one client may have queued on the control lane.
    #[must_use]
    pub fn control_bytes(&self) -> usize {
        self.control_bytes.load(Ordering::Relaxed)
    }

    /// Audio frames one client may have buffered.
    #[must_use]
    pub fn audio_queue(&self) -> usize {
        self.audio_queue.load(Ordering::Relaxed)
    }

    /// Control frames one client's lane is created with.
    #[must_use]
    pub fn control_queue(&self) -> usize {
        self.control_queue.load(Ordering::Relaxed)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::from_config(&GatewayConfig::default())
    }
}

/// Keep `limits` following `cell`, for as long as the process lives.
///
/// Spawns a task; the handle is dropped, because the process exiting is what
/// stops it.
pub fn follow(cell: &starling_runtime::live::ConfigCell, limits: Arc<Limits>) {
    let mut configs = cell.subscribe();
    drop(tokio::spawn(async move {
        while configs.changed().await.is_ok() {
            let moved = {
                let config = configs.borrow_and_update();
                limits.adopt(&config.gateway)
            };
            if !moved.is_empty() {
                tracing::info!(
                    limits = moved.join(", "),
                    control_bytes = limits.control_bytes(),
                    audio_queue = limits.audio_queue(),
                    control_queue = limits.control_queue(),
                    "gateway queue bounds changed"
                );
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(control_bytes: usize, audio_queue: usize, control_queue: usize) -> GatewayConfig {
        GatewayConfig {
            control_bytes,
            audio_queue,
            control_queue,
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn the_bounds_start_at_what_the_file_says() {
        let limits = Limits::from_config(&config(1024, 8, 16));
        assert_eq!(limits.control_bytes(), 1024);
        assert_eq!(limits.audio_queue(), 8);
        assert_eq!(limits.control_queue(), 16);
    }

    #[test]
    fn adopting_reports_only_what_moved() {
        let limits = Limits::from_config(&config(1024, 8, 16));
        assert_eq!(limits.adopt(&config(2048, 8, 16)), vec!["control_bytes"]);
        assert_eq!(limits.control_bytes(), 2048);
        assert!(
            limits.adopt(&config(2048, 8, 16)).is_empty(),
            "an unchanged file must produce no log line"
        );
    }

    #[test]
    fn a_zero_bound_is_raised_to_one_rather_than_stopping_the_server() {
        // A control lane of zero accepts no frame at all, so every client would
        // be disconnected on its first. Clamped here, once, rather than at each
        // of the two read sites.
        let limits = Limits::from_config(&config(0, 0, 0));
        assert_eq!(limits.control_bytes(), 1);
        assert_eq!(limits.audio_queue(), 1);
        assert_eq!(limits.control_queue(), 1);
    }
}
