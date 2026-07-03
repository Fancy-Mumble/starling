//! `/healthz` and `/readyz`, and the reason they are two endpoints.
//!
//! **Liveness** answers "is this process worth keeping". **Readiness** answers
//! "may traffic arrive now", and the gap between them is the failure mode with
//! no log line: a restarted voice service is alive immediately, but until it
//! has re-subscribed to `session-view` and refetched membership it routes audio
//! into nowhere and says nothing about it (`docs/ARCHITECTURE.md` §8, R11).
//!
//! So readiness gates on **cache warm-up**, not on the process being up, and a
//! service declares its own warm-up conditions.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// What a service must finish before it is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Not there yet. Traffic must not be routed here.
    Warming,
    /// Warm.
    Ready,
    /// Degraded, but not a reason to be taken out of rotation.
    ///
    /// The gateway's session store is the reason this exists: its absence is a
    /// lost optimisation whose failure is deferred and amplifying, and neither
    /// "unready" nor silence is honest about it (§5).
    Warning,
}

/// The health of one process, as its dependencies report it.
#[derive(Debug, Clone, Default)]
pub struct Health {
    gates: Arc<Mutex<BTreeMap<String, Readiness>>>,
}

impl Health {
    /// A process with no gates, which is therefore ready.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a gate that starts cold.
    ///
    /// Declaring is separate from satisfying so a service cannot be ready
    /// *before* it has said what it is waiting for — the race that makes a
    /// cold cache look warm for one scrape interval.
    pub fn gate(&self, name: &str) {
        self.set(name, Readiness::Warming);
    }

    /// Update a gate.
    pub fn set(&self, name: &str, state: Readiness) {
        if let Ok(mut gates) = self.gates.lock() {
            let _ = gates.insert(name.to_owned(), state);
        }
    }

    /// Mark a gate warm.
    pub fn ready(&self, name: &str) {
        self.set(name, Readiness::Ready);
    }

    /// Whether every gate is warm.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.gates.lock().is_ok_and(|gates| {
            gates
                .values()
                .all(|state| !matches!(state, Readiness::Warming))
        })
    }

    /// The gates that are not warm yet, for the readiness body.
    ///
    /// A readiness probe that says only "no" costs an operator a debugging
    /// session; one that names the gate costs a `curl`.
    #[must_use]
    pub fn pending(&self) -> Vec<String> {
        self.gates
            .lock()
            .map(|gates| {
                gates
                    .iter()
                    .filter(|(_, state)| matches!(state, Readiness::Warming))
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The gates that are degraded but not blocking.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        self.gates
            .lock()
            .map(|gates| {
                gates
                    .iter()
                    .filter(|(_, state)| matches!(state, Readiness::Warning))
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every gate and its state, for the health surface.
    ///
    /// [`Self::pending`] and [`Self::warnings`] each answer one question and
    /// throw the rest away, which is right for `/readyz`'s prose and wrong for
    /// a dashboard: it wants the whole picture, including the gates that are
    /// *fine*, or it cannot tell "warm" from "never declared anything".
    ///
    /// Sorted, because it is a `BTreeMap`: a dashboard that reorders its rows
    /// on every poll is a dashboard nobody can read.
    #[must_use]
    pub fn gates(&self) -> Vec<(String, Readiness)> {
        self.gates
            .lock()
            .map(|gates| {
                gates
                    .iter()
                    .map(|(name, state)| (name.clone(), *state))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The readiness body: the status, then the gates that explain it.
    #[must_use]
    pub fn report(&self) -> String {
        let pending = self.pending();
        let warnings = self.warnings();
        let mut body = if pending.is_empty() {
            String::from("ready\n")
        } else {
            String::from("warming\n")
        };
        for gate in pending {
            body.push_str(&format!("warming: {gate}\n"));
        }
        for gate in warnings {
            body.push_str(&format!("warning: {gate}\n"));
        }
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_gate_holds_readiness_until_it_is_warm() {
        // The whole point: alive is not ready, and a cold cache must not take
        // traffic.
        let health = Health::new();
        health.gate("session-view subscription");
        assert!(!health.is_ready());
        health.ready("session-view subscription");
        assert!(health.is_ready());
    }

    #[test]
    fn readiness_names_what_it_is_waiting_for() {
        let health = Health::new();
        health.gate("membership cache");
        assert!(health.report().contains("membership cache"));
    }

    #[test]
    fn a_warning_is_reported_without_making_the_process_unready() {
        // The session store: reported, never a reason to leave rotation.
        let health = Health::new();
        health.set("session store", Readiness::Warning);
        assert!(health.is_ready());
        assert_eq!(health.warnings(), vec!["session store".to_owned()]);
        assert!(health.report().contains("warning: session store"));
    }
}
