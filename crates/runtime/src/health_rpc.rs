//! Every service's readiness, over gRPC, without the service writing any of it.
//!
//! [`Health`](crate::health::Health) has always existed per service, and until
//! this module the only way to read it was `/readyz` on the process holding it.
//! That is enough for a Kubernetes probe and useless for anything else:
//!
//! * in `--all-in-one` twenty services share one process and each holds its own
//!   `Health`, so nineteen of them had no endpoint at all;
//! * `/readyz` is a liveness contract for an orchestrator, not a read model,
//!   it answers about *one* process and returns prose;
//! * nothing could ask a service how it was without being that service.
//!
//! So the runtime adds this to every service's routes in
//! [`serve`](crate::serve), the same way it adds config, discovery and metrics.
//! A service opts into nothing and cannot forget to implement it, which is the
//! only way a health surface stays honest, the service most worth asking about
//! is the one nobody remembered to instrument.

use starling_proto_fancy::health::health_server::{Health as HealthRpc, HealthServer};
use starling_proto_fancy::health::{CheckRequest, Gate, Load, ServiceHealth, State};
use tonic::{Request, Response, Status};

use crate::health::{Health, Readiness};
use crate::pressure::Pressure;

/// One service answering for itself.
#[derive(Debug, Clone)]
pub struct HealthReporter {
    name: String,
    health: Health,
    /// How full this service's queues are.
    ///
    /// Answered on the same call as readiness, because they are two halves of
    /// one question and asking them separately guarantees they disagree: a
    /// service polled for readiness at one instant and for load at another
    /// produces a dashboard where a row is green and its queue is overflowing,
    /// with no way to tell whether that is a race or the truth.
    pressure: Pressure,
}

impl HealthReporter {
    /// A reporter for `name`, reading `health` and `pressure`.
    #[must_use]
    pub fn new(name: impl Into<String>, health: Health, pressure: Pressure) -> Self {
        Self {
            name: name.into(),
            health,
            pressure,
        }
    }

    /// The server to add to a service's routes.
    #[must_use]
    pub fn into_server(self) -> HealthServer<Self> {
        HealthServer::new(self)
    }

    /// This service's health, as the collector will read it.
    #[must_use]
    pub fn snapshot(&self) -> ServiceHealth {
        let gates: Vec<Gate> = self
            .health
            .gates()
            .into_iter()
            .map(|(name, state)| Gate {
                name,
                state: i32::from(map_state(state)),
            })
            .collect();

        ServiceHealth {
            service: self.name.clone(),
            state: i32::from(worst(&gates)),
            gates,
            load: self
                .pressure
                .sample()
                .into_iter()
                .map(|load| Load {
                    name: load.name,
                    used: load.used,
                    peak: load.peak,
                    capacity: load.capacity,
                    rejected: load.rejected,
                })
                .collect(),
            // The service cannot time its own round trip; the collector fills
            // this in. Left zero rather than invented.
            latency_us: 0,
            error: String::new(),
        }
    }
}

/// The worst state among `gates`, which is the one a dashboard colours by.
///
/// Ordered by how much it should worry somebody, not by the enum's numbering:
/// a service with one warming gate and nine ready ones is warming, and saying
/// "ready" because most of it is would be the reassuring answer rather than the
/// true one.
fn worst(gates: &[Gate]) -> State {
    let mut worst = State::Ready;
    for gate in gates {
        let state = State::try_from(gate.state).unwrap_or(State::Unspecified);
        worst = match (worst, state) {
            (_, State::Unreachable) | (State::Unreachable, _) => State::Unreachable,
            (_, State::Warming) | (State::Warming, _) => State::Warming,
            (_, State::Warning) | (State::Warning, _) => State::Warning,
            _ => worst,
        };
    }
    worst
}

const fn map_state(state: Readiness) -> State {
    match state {
        Readiness::Ready => State::Ready,
        Readiness::Warming => State::Warming,
        Readiness::Warning => State::Warning,
    }
}

#[tonic::async_trait]
impl HealthRpc for HealthReporter {
    async fn check(
        &self,
        _request: Request<CheckRequest>,
    ) -> Result<Response<ServiceHealth>, Status> {
        Ok(Response::new(self.snapshot()))
    }
}

/// Add the health surface to a service's own routes.
///
/// A free function so [`serve`](crate::serve) can apply it uniformly without
/// every service's `routes()` remembering to.
#[must_use]
pub fn with_health(
    routes: tonic::service::Routes,
    name: &str,
    health: &Health,
    pressure: &Pressure,
) -> tonic::service::Routes {
    let reporter = HealthReporter::new(name, health.clone(), pressure.clone());
    routes.add_service(reporter.into_server())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_with_no_gates_is_ready() {
        // A service that caches nothing has nothing to warm, and must not be
        // reported as warming forever because it declared no gates.
        let reporter = HealthReporter::new("text", Health::new(), Pressure::new());
        let snapshot = reporter.snapshot();
        assert_eq!(snapshot.service, "text");
        assert_eq!(snapshot.state, i32::from(State::Ready));
        assert!(snapshot.gates.is_empty());
    }

    #[test]
    fn one_warming_gate_makes_the_whole_service_warming() {
        // The rule that matters for a dashboard: a service is as good as its
        // worst gate. Voice with a warm socket and a cold session-view
        // subscription routes audio into nowhere, and reporting it green
        // because most of it is up is exactly the failure the gates exist for.
        let health = Health::new();
        health.gate("udp socket");
        health.gate("session view");
        health.ready("udp socket");

        let snapshot = HealthReporter::new("voice", health, Pressure::new()).snapshot();
        assert_eq!(snapshot.state, i32::from(State::Warming));
        assert_eq!(snapshot.gates.len(), 2);
        let cold = snapshot
            .gates
            .iter()
            .find(|gate| gate.name == "session view")
            .expect("the gate is named");
        assert_eq!(cold.state, i32::from(State::Warming));
    }

    #[test]
    fn a_warning_is_reported_without_making_the_service_unready() {
        // The gateway's resume store: its absence is a lost optimisation, and
        // neither "unready" nor silence is honest about it.
        let health = Health::new();
        health.gate("listener");
        health.ready("listener");
        health.set("session store", Readiness::Warning);

        let snapshot = HealthReporter::new("gateway", health, Pressure::new()).snapshot();
        assert_eq!(snapshot.state, i32::from(State::Warning));
    }

    #[test]
    fn warming_outranks_warning() {
        // A service that is both degraded and not yet warm is warming: the
        // stronger statement is the one traffic must be kept away by.
        let health = Health::new();
        health.gate("cache");
        health.set("optional thing", Readiness::Warning);

        let snapshot = HealthReporter::new("svc", health, Pressure::new()).snapshot();
        assert_eq!(snapshot.state, i32::from(State::Warming));
    }
}
