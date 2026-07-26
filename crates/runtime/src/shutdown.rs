//! `SIGTERM` → graceful drain.
//!
//! Non-negotiable, because Kubernetes sends `SIGTERM`, waits
//! `terminationGracePeriodSeconds`, and then sends `SIGKILL` regardless. A
//! process that ignores the first signal does not avoid the second; it only
//! loses the chance to finish what it was holding.
//!
//! Draining a gateway is the interesting case: it holds client sockets, and
//! dropping ten thousand at once produces ten thousand simultaneous reconnects
//! and full floods. So the drain is staggered and clients are given jittered
//! reconnect hints — required whether or not the resume store exists, because
//! legacy clients can never resume.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// A shared "stop accepting, finish what you have" signal.
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    draining: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Shutdown {
    /// A signal nobody has raised yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the drain has started.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Start the drain and wake everything waiting.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Resolve when the drain starts.
    ///
    /// Returns immediately if it already has, so a task spawned late cannot
    /// wait forever for a signal that has been and gone.
    pub async fn wait(&self) {
        if self.is_draining() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_draining() {
            return;
        }
        notified.await;
    }

    /// Raise the drain on `SIGTERM` or `SIGINT`.
    ///
    /// Spawns a task; the handle is deliberately dropped, because the process
    /// exiting is what stops it.
    pub fn install_signal_handler(&self) {
        let signal = self.clone();
        drop(tokio::spawn(async move {
            let interrupt = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal as unix_signal};
                match unix_signal(SignalKind::terminate()) {
                    Ok(mut term) => {
                        tokio::select! {
                            _ = interrupt => {}
                            _ = term.recv() => {}
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "no SIGTERM handler; falling back to SIGINT only");
                        let _ = interrupt.await;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = interrupt.await;
            }
            tracing::info!("shutdown signal received; draining");
            signal.drain();
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waiting_after_the_drain_has_started_returns_immediately() {
        // A task spawned during the drain must not block forever on a signal
        // that has already fired — that is how a pod hangs until SIGKILL.
        let shutdown = Shutdown::new();
        shutdown.drain();
        tokio::time::timeout(std::time::Duration::from_millis(100), shutdown.wait())
            .await
            .expect("wait must return once draining");
    }

    #[tokio::test]
    async fn every_waiter_is_woken_by_one_drain() {
        let shutdown = Shutdown::new();
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let shutdown = shutdown.clone();
                tokio::spawn(async move { shutdown.wait().await })
            })
            .collect();

        tokio::task::yield_now().await;
        shutdown.drain();

        for waiter in waiters {
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .expect("no waiter may be left behind")
                .expect("task must not panic");
        }
    }
}
