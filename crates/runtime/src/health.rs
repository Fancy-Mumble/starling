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
use std::time::{Duration, Instant};

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

/// One background task's proof that it is still running.
///
/// Readiness gates only ever move forward: `Warming` is written once at build
/// time and nothing puts a gate back. That is right for warm-up and useless for
/// detection, because a service whose background task died keeps reporting
/// `Ready` and serving a frozen cache, and the Kubernetes `tcpSocket` probe a
/// process with every task dead still passes.
///
/// A heartbeat is the other direction: it goes stale on its own unless
/// something keeps it fresh, so *not being told* is the signal.
#[derive(Debug, Clone, Copy)]
struct Heartbeat {
    /// When it was last beaten.
    at: Instant,
    /// How old it may get before this process is not live.
    max_age: Duration,
}

/// The health of one process, as its dependencies report it.
#[derive(Debug, Clone, Default)]
pub struct Health {
    gates: Arc<Mutex<BTreeMap<String, Readiness>>>,
    /// What must keep proving it is running. See [`Heartbeat`].
    beats: Arc<Mutex<BTreeMap<String, Heartbeat>>>,
}

impl Health {
    /// A process with no gates, which is therefore ready.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a heartbeat that must be beaten at least every `max_age`.
    ///
    /// Registered before the task starts and beaten by it, so a task that never
    /// starts fails liveness exactly as one that stopped does. `max_age` should
    /// be a comfortable multiple of the task's own period: this is for a task
    /// that has *died*, and making it also a latency alarm would produce a
    /// restart every time the machine was busy.
    pub fn heartbeat(&self, name: &str, max_age: Duration) {
        if let Ok(mut beats) = self.beats.lock() {
            let _ = beats.insert(
                name.to_owned(),
                Heartbeat {
                    at: Instant::now(),
                    max_age,
                },
            );
        }
    }

    /// Say that `name` is still running.
    ///
    /// Cheap enough for a hot loop: one lock and one `Instant::now`. A task
    /// with nothing to do must still beat -- the gateway beats on its accept
    /// loop's timer arm as well as on an accept -- or an idle server reports
    /// itself dead.
    pub fn beat(&self, name: &str) {
        if let Ok(mut beats) = self.beats.lock()
            && let Some(beat) = beats.get_mut(name)
        {
            beat.at = Instant::now();
        }
    }

    /// Stop expecting `name` to beat.
    ///
    /// For a task that ended because it was asked to. Without this, draining
    /// would make every service report itself dead on the way out.
    pub fn forget_heartbeat(&self, name: &str) {
        if let Ok(mut beats) = self.beats.lock() {
            let _ = beats.remove(name);
        }
    }

    /// Whether every heartbeat is fresh.
    ///
    /// **This, and not [`Self::is_ready`], is what a liveness probe asks.** A
    /// process that fails this has tasks that are gone and will not come back
    /// on their own, so restarting it is the correct response; a process that
    /// merely fails readiness is warming up and restarting it makes that worse.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.stale().is_empty()
    }

    /// The heartbeats that have gone stale, and how late each is.
    ///
    /// Named, because "not live" is not something an operator can act on and
    /// "voice's sweep has not beaten in 4 minutes" is.
    #[must_use]
    pub fn stale(&self) -> Vec<(String, Duration)> {
        let now = Instant::now();
        self.beats
            .lock()
            .map(|beats| {
                beats
                    .iter()
                    .filter_map(|(name, beat)| {
                        let age = now.saturating_duration_since(beat.at);
                        (age > beat.max_age).then(|| (name.clone(), age))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Declare a gate that starts cold.
    ///
    /// Declaring is separate from satisfying so a service cannot be ready
    /// *before* it has said what it is waiting for, the race that makes a
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

    /// The wedge this exists to catch: gates green, tasks gone.
    #[test]
    fn a_process_whose_task_died_is_not_live_though_it_is_ready() {
        let health = Health::new();
        health.gate("cache");
        health.ready("cache");
        health.heartbeat("sweep", Duration::from_millis(30));

        assert!(health.is_ready());
        assert!(health.is_live(), "a heartbeat just registered is fresh");

        // Nothing beats it: the task is gone.
        std::thread::sleep(Duration::from_millis(60));

        assert!(
            health.is_ready(),
            "readiness only moves forward, which is exactly the problem"
        );
        assert!(!health.is_live(), "liveness must notice");
        let stale = health.stale();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, "sweep", "and must name what stopped");
    }

    #[test]
    fn a_task_that_keeps_beating_stays_live() {
        let health = Health::new();
        health.heartbeat("sweep", Duration::from_millis(50));
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(20));
            health.beat("sweep");
            assert!(health.is_live());
        }
    }

    #[test]
    fn a_heartbeat_that_was_asked_to_stop_does_not_fail_liveness() {
        // Otherwise every service reports itself dead while draining.
        let health = Health::new();
        health.heartbeat("sweep", Duration::from_millis(20));
        health.forget_heartbeat("sweep");
        std::thread::sleep(Duration::from_millis(40));
        assert!(health.is_live());
    }

    #[test]
    fn a_process_with_no_heartbeats_is_live() {
        // A service that declares none is not making a claim; it must not be
        // restarted for failing to make one.
        assert!(Health::new().is_live());
    }

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
