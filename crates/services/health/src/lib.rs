//! `health` — the one place that knows how the whole server is.
//!
//! Every service reports its own readiness (`starling-runtime`'s
//! `health_rpc`), and every service reporting it separately is not an answer:
//! an operator asking "is the server all right" would have to know the list,
//! reach twenty endpoints and merge the results, and in `--all-in-one` those
//! endpoints do not exist at all because twenty services share one process.
//!
//! This service asks all of them on a timer and keeps the answer.
//!
//! # Why polled, and not pushed
//!
//! A service that has stopped pushing looks exactly like a service with
//! nothing to say, and the difference is the entire question. Polling makes
//! silence into evidence: a service that does not answer is `UNREACHABLE`, and
//! that is a state the service could never have reported about itself.
//!
//! # Why it holds a snapshot rather than answering on demand
//!
//! A dashboard refreshing every second must not turn into twenty gRPC calls
//! per viewer per second, and a health surface that falls over when several
//! people are watching is worse than none. The poll runs once for everybody at
//! a fixed interval, and every reader gets the last snapshot with the time it
//! was taken — so a stale picture is visibly stale rather than quietly wrong.
//!
//! # Why it is not on the client plane
//!
//! It has no wire type and no `ServiceKind`. No client talks to it: readiness
//! is an operator's question, and the answer names internal services and their
//! caches. `operator-api` serves it over HTTP for a dashboard
//! (`docs/ARCHITECTURE.md` §3, the admin plane).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use starling_proto_fancy::health::health_client::HealthClient;
use starling_proto_fancy::health::health_overview_server::{HealthOverview, HealthOverviewServer};
use starling_proto_fancy::health::{
    CheckRequest, HistoryReply, Overview, OverviewRequest, Sample, ServiceHealth, State,
};
use starling_runtime::config::ServiceConfig;
use starling_runtime::ids::now_ms;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tonic::{Request, Response, Status};

/// How often every service is asked.
///
/// Five seconds is far below the patience of somebody watching a dashboard and
/// far above the cost of twenty in-process calls. It is also the reason this
/// does not need a cache invalidation story: the snapshot is never more than
/// one interval old and says exactly how old it is.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long one service has to answer before it is called unreachable.
///
/// Short on purpose. A service that takes longer than this to say how it is
/// cannot serve traffic either, so waiting longer would only make the whole
/// sweep as slow as its worst member — and a dashboard that hangs is a
/// dashboard that gets closed.
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// How many past sweeps are kept.
///
/// An hour at [`POLL_INTERVAL`], which is the window somebody actually asks
/// about — "did it wobble while I was at lunch". Bounded in samples rather
/// than time because each is a fixed handful of integers: 720 of them is a few
/// tens of kilobytes, and a health service that leaks is a poor joke.
const HISTORY: usize = 720;

/// The service.
#[derive(Debug)]
pub struct HealthService {
    /// The last completed sweep. Read by every viewer, written by the poller.
    latest: Mutex<Overview>,
    /// The recent past, oldest first, for plotting.
    ///
    /// Separate from `latest` because they are read at different rates and
    /// answer different questions: a viewer wants the detail of *now* and the
    /// shape of the last hour, and coupling them would mean either keeping
    /// every gate of every sweep or having no history at all.
    history: Mutex<VecDeque<Sample>>,
}

impl HealthService {
    /// The last sweep, or an empty one before the first has finished.
    #[must_use]
    pub fn latest(&self) -> Overview {
        self.latest
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
    }

    /// The recent past, oldest first.
    #[must_use]
    pub fn history(&self) -> Vec<Sample> {
        self.history
            .lock()
            .map(|held| held.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Fold one sweep into the shape a plot needs.
    fn sample(overview: &Overview) -> Sample {
        Tally::of(overview).into_sample(overview)
    }

    /// Ask every enabled service how it is, once.
    async fn sweep(&self, ctx: &ServiceContext) -> Overview {
        let mut services = Vec::new();
        let mut disabled = Vec::new();

        for (name, configured) in &ctx.config.services {
            match Plan::for_service(name, configured, Self::NAME) {
                Plan::Ask => services.push(check(ctx, name).await),
                Plan::Disabled => disabled.push(name.clone()),
                Plan::NothingToAsk => {}
            }
        }

        services.sort_by(|a, b| a.service.cmp(&b.service));
        Overview {
            state: i32::from(worst(&services)),
            services,
            observed_at_ms: now_ms(),
            disabled,
        }
    }
}

/// Microseconds since `started`, saturating.
///
/// Microseconds and not milliseconds because in `--all-in-one` a check is an
/// in-process call: every honest measurement truncates to `0ms`, and a latency
/// column of zeroes is indistinguishable from one that was never wired up.
fn micros_since(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// One sweep, folded down to the numbers a plot needs.
///
/// A struct rather than the tuple of accumulators this started as: it was
/// already `(u32, u32, u32, u32)` plus a slowest-so-far pair, and adding
/// pressure to that would have made `counts.3` mean something no reader could
/// guess. Named fields also let the two "worst so far" rules be written where
/// they apply instead of inline in a loop body.
#[derive(Debug, Default)]
struct Tally {
    ready: u32,
    warming: u32,
    warning: u32,
    unreachable: u32,
    /// Slowest service this sweep, and how slow.
    slowest: (String, u64),
    /// Fullest gauge this sweep: percent, and `service/gauge` naming it.
    busiest: (u32, String),
    /// Refusals across every gauge in the server.
    rejected: u64,
}

impl Tally {
    fn of(overview: &Overview) -> Self {
        let mut tally = Self::default();
        for service in &overview.services {
            tally.count(service);
        }
        tally
    }

    fn count(&mut self, service: &ServiceHealth) {
        match State::try_from(service.state) {
            Ok(State::Ready) => self.ready += 1,
            Ok(State::Warming) => self.warming += 1,
            Ok(State::Warning) => self.warning += 1,
            Ok(State::Unreachable) => self.unreachable += 1,
            _ => {}
        }
        // The slowest, never the mean: nineteen services answering in 40µs and
        // one timing out averages to "fine", which is the one answer that is
        // certainly wrong.
        if service.latency_us > self.slowest.1 {
            self.slowest = (service.service.clone(), service.latency_us);
        }
        for load in &service.load {
            self.rejected += load.rejected;
            // Only a gauge that declares a capacity can have a percentage. An
            // unbounded one contributes its refusals and nothing else, because
            // a fraction of an unknown bound is not a fraction.
            if load.capacity == 0 {
                continue;
            }
            let percent = u32::try_from(load.peak.saturating_mul(100) / load.capacity)
                .unwrap_or(u32::MAX)
                .min(100);
            if percent > self.busiest.0 {
                self.busiest = (percent, format!("{}/{}", service.service, load.name));
            }
        }
    }

    fn into_sample(self, overview: &Overview) -> Sample {
        Sample {
            observed_at_ms: overview.observed_at_ms,
            state: overview.state,
            ready: self.ready,
            warming: self.warming,
            warning: self.warning,
            unreachable: self.unreachable,
            worst_latency_us: self.slowest.1,
            slowest: self.slowest.0,
            busiest_percent: self.busiest.0,
            busiest: self.busiest.1,
            rejected: self.rejected,
        }
    }
}

/// What a sweep does with one configured service.
///
/// Separated from the sweep itself because it is the whole of the judgement and
/// none of the I/O: deciding it needs a name and a `ServiceConfig`, while
/// running it needs a live server and twenty spawned services. Getting this
/// wrong is also not visibly wrong — it shows up as a dashboard that is red for
/// a server that is fine — so it is the part worth pinning with tests.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Dial it and ask how it is.
    Ask,
    /// Not running. Reported, not omitted: "switched off" is the answer to
    /// most "why is this feature missing" questions.
    Disabled,
    /// Running, but with no question this collector can put to it.
    NothingToAsk,
}

impl Plan {
    fn for_service(name: &str, configured: &ServiceConfig, collector: &str) -> Self {
        if !configured.enabled {
            return Self::Disabled;
        }
        // Asking itself would deadlock the sweep behind its own server for no
        // information: this service's readiness is that the sweep runs.
        if name == collector {
            return Self::NothingToAsk;
        }
        // No endpoint means no gRPC surface, so there is nothing here to dial —
        // `operator-api` speaks REST on `listen`, and the announcer only calls
        // out. Reporting those as unreachable was false in the worst way
        // available: the overview's `state` is the worst state present, so one
        // service that was never dialable turned the whole dashboard red on a
        // server where all twenty real services were ready.
        //
        // Omitted rather than given a state of its own, because the honest
        // answer is "not a question this collector can put". For `operator-api`
        // the answer is self-evident anyway: it served the page the overview is
        // being read on.
        if configured.endpoint.is_none() {
            return Self::NothingToAsk;
        }
        Self::Ask
    }
}

/// Ask one service, and turn every failure into a state rather than an error.
///
/// A collector that propagates errors has nothing to show for the service that
/// is actually broken, which is the one the viewer came to look at.
async fn check(ctx: &ServiceContext, name: &str) -> ServiceHealth {
    let started = std::time::Instant::now();

    let unreachable = |error: String| ServiceHealth {
        service: name.to_owned(),
        state: i32::from(State::Unreachable),
        gates: Vec::new(),
        load: Vec::new(),
        latency_us: micros_since(started),
        error,
    };

    let Ok(channel) = ctx.resolver.channel(name) else {
        return unreachable("no route to this service".to_owned());
    };

    let mut client = HealthClient::new(channel);
    let call = client.check(Request::new(CheckRequest {}));
    match tokio::time::timeout(CHECK_TIMEOUT, call).await {
        Ok(Ok(answer)) => ServiceHealth {
            latency_us: micros_since(started),
            ..answer.into_inner()
        },
        Ok(Err(status)) => unreachable(status.message().to_owned()),
        // Distinguished from a refusal, because they mean opposite things: a
        // service that answers "no" is working, and one that never answers is
        // the outage.
        Err(_) => unreachable(format!("no answer within {CHECK_TIMEOUT:?}")),
    }
}

/// The worst state across a sweep.
///
/// The number a dashboard shows before anybody expands anything, so it has to
/// be the pessimistic one: a server with nineteen ready services and one
/// unreachable is not "mostly fine".
fn worst(services: &[ServiceHealth]) -> State {
    let mut worst = State::Ready;
    for service in services {
        let state = State::try_from(service.state).unwrap_or(State::Unspecified);
        worst = match (worst, state) {
            (_, State::Unreachable) | (State::Unreachable, _) => State::Unreachable,
            (_, State::Warming) | (State::Warming, _) => State::Warming,
            (_, State::Warning) | (State::Warning, _) => State::Warning,
            _ => worst,
        };
    }
    worst
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct HealthOverviewRpc(Arc<HealthService>);

#[tonic::async_trait]
impl HealthOverview for HealthOverviewRpc {
    async fn get(&self, _request: Request<OverviewRequest>) -> Result<Response<Overview>, Status> {
        Ok(Response::new(self.0.latest()))
    }

    async fn history(
        &self,
        _request: Request<OverviewRequest>,
    ) -> Result<Response<HistoryReply>, Status> {
        Ok(Response::new(HistoryReply {
            samples: self.0.history(),
            interval_ms: u32::try_from(POLL_INTERVAL.as_millis()).unwrap_or(u32::MAX),
        }))
    }
}

impl Serve for HealthService {
    const NAME: &'static str = "health";

    async fn build(_ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        Ok(Arc::new(Self {
            latest: Mutex::new(Overview::default()),
            history: Mutex::new(VecDeque::with_capacity(HISTORY)),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        tonic::service::Routes::default()
            .add_service(HealthOverviewServer::new(HealthOverviewRpc(self)))
    }

    /// Sweep until shutdown.
    ///
    /// The first sweep runs immediately rather than after an interval: a
    /// dashboard opened just after a restart should show the server warming,
    /// which is the most interesting moment there is, not an empty panel.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => return Ok(()),
                _ = ticker.tick() => {}
            }

            let overview = self.sweep(&ctx).await;
            let unreachable = overview
                .services
                .iter()
                .filter(|s| s.state == i32::from(State::Unreachable))
                .map(|s| s.service.clone())
                .collect::<Vec<_>>();
            if !unreachable.is_empty() {
                // On the operator's own record: a service the collector cannot
                // reach is the event somebody is paged for, and `tracing`
                // alone is a developer's dial that may be turned off.
                ctx.logger.log(
                    starling_runtime::log::LogEvent::warning(
                        starling_runtime::log::Category::Server,
                        "services are unreachable",
                    )
                    .with("services", unreachable.join(", ")),
                );
            }
            if let Ok(mut held) = self.history.lock() {
                held.push_back(Self::sample(&overview));
                while held.len() > HISTORY {
                    let _ = held.pop_front();
                }
            }
            if let Ok(mut held) = self.latest.lock() {
                *held = overview;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::health::Gate;

    fn service(name: &str, state: State) -> ServiceHealth {
        ServiceHealth {
            service: name.to_owned(),
            state: i32::from(state),
            gates: Vec::new(),
            load: Vec::new(),
            latency_us: 1,
            error: String::new(),
        }
    }

    fn configured(endpoint: Option<&str>, enabled: bool) -> ServiceConfig {
        ServiceConfig {
            enabled,
            endpoint: endpoint.map(ToOwned::to_owned),
            ..ServiceConfig::default()
        }
    }

    #[test]
    fn a_service_with_no_grpc_surface_is_not_called_unreachable() {
        // `operator-api` serves REST on `listen` and has no endpoint to dial.
        // Asking it and calling the failure an outage made the overview's
        // headline `unreachable` on a server whose every real service was
        // ready — a dashboard that is red when nothing is wrong is worse than
        // one that omits a row, because it is the boy who cried wolf.
        assert_eq!(
            Plan::for_service("operator-api", &configured(None, true), "health"),
            Plan::NothingToAsk
        );
    }

    #[test]
    fn a_service_with_an_endpoint_is_asked() {
        assert_eq!(
            Plan::for_service("voice", &configured(Some("inproc:voice"), true), "health"),
            Plan::Ask
        );
    }

    #[test]
    fn the_collector_does_not_ask_itself() {
        // It would block on its own server, and the answer is already implied
        // by the sweep having run at all.
        assert_eq!(
            Plan::for_service("health", &configured(Some("inproc:health"), true), "health"),
            Plan::NothingToAsk
        );
    }

    #[test]
    fn a_switched_off_service_is_reported_rather_than_dialled() {
        // Distinct from `NothingToAsk`: this one shows up in the overview's
        // `disabled` list, because "somebody turned it off" is an answer and
        // silence is not.
        assert_eq!(
            Plan::for_service("directory", &configured(None, false), "health"),
            Plan::Disabled
        );
        assert_eq!(
            Plan::for_service("voice", &configured(Some("inproc:voice"), false), "health"),
            Plan::Disabled
        );
    }

    #[test]
    fn one_unreachable_service_makes_the_whole_server_unreachable() {
        // The headline number is pessimistic on purpose. A server with
        // nineteen ready services and one that cannot be reached is not
        // "mostly fine", and a dashboard that says so trains people to ignore
        // it.
        let sweep = vec![
            service("text", State::Ready),
            service("voice", State::Unreachable),
            service("metadata", State::Ready),
        ];
        assert_eq!(worst(&sweep), State::Unreachable);
    }

    #[test]
    fn warming_outranks_warning_and_both_outrank_ready() {
        assert_eq!(
            worst(&[service("a", State::Ready), service("b", State::Warning)]),
            State::Warning
        );
        assert_eq!(
            worst(&[service("a", State::Warning), service("b", State::Warming)]),
            State::Warming
        );
        assert_eq!(
            worst(&[service("a", State::Ready), service("b", State::Ready)]),
            State::Ready
        );
    }

    #[test]
    fn an_empty_server_is_ready_rather_than_unspecified() {
        // Before the first sweep there is nothing to be wrong. Reporting
        // `UNSPECIFIED` would paint the dashboard a colour that means nothing.
        assert_eq!(worst(&[]), State::Ready);
    }

    #[test]
    fn a_snapshot_before_the_first_sweep_is_empty_rather_than_wrong() {
        // The window between the process starting and the first sweep
        // finishing. An empty overview with `observed_at_ms = 0` is visibly
        // "nothing measured yet"; inventing `READY` would be a green dashboard
        // for a server nobody has looked at.
        let service = HealthService {
            latest: Mutex::new(Overview::default()),
            history: Mutex::new(VecDeque::new()),
        };
        let latest = service.latest();
        assert!(latest.services.is_empty());
        assert_eq!(latest.observed_at_ms, 0);
    }

    #[test]
    fn a_sample_records_the_slowest_service_not_the_average() {
        // What a latency plot has to show. An average over twenty services
        // hides the one that is timing out, which is the only one worth
        // plotting — and it names it, so a spike can be attributed rather
        // than guessed at.
        let overview = Overview {
            state: i32::from(State::Ready),
            services: vec![
                ServiceHealth {
                    latency_us: 2,
                    ..service("text", State::Ready)
                },
                ServiceHealth {
                    latency_us: 91,
                    ..service("userdata", State::Ready)
                },
                ServiceHealth {
                    latency_us: 3,
                    ..service("voice", State::Ready)
                },
            ],
            observed_at_ms: 1_000,
            disabled: Vec::new(),
        };

        let sample = HealthService::sample(&overview);
        assert_eq!(sample.worst_latency_us, 91);
        assert_eq!(sample.slowest, "userdata");
        assert_eq!(sample.ready, 3);
        assert_eq!(sample.unreachable, 0);
    }

    #[test]
    fn a_sample_counts_each_state_so_a_plot_can_stack_them() {
        let overview = Overview {
            state: i32::from(State::Unreachable),
            services: vec![
                service("a", State::Ready),
                service("b", State::Warming),
                service("c", State::Warning),
                service("d", State::Unreachable),
                service("e", State::Ready),
            ],
            observed_at_ms: 5,
            disabled: Vec::new(),
        };

        let sample = HealthService::sample(&overview);
        assert_eq!(
            (
                sample.ready,
                sample.warming,
                sample.warning,
                sample.unreachable
            ),
            (2, 1, 1, 1)
        );
        assert_eq!(sample.state, i32::from(State::Unreachable));
    }

    #[test]
    fn a_services_gates_survive_the_aggregation() {
        // The detail a dashboard expands into. Rolling every service up to one
        // colour and throwing the gates away would answer "something is wrong"
        // without ever saying what.
        let health = ServiceHealth {
            service: "voice".to_owned(),
            state: i32::from(State::Warming),
            gates: vec![Gate {
                name: "session view".to_owned(),
                state: i32::from(State::Warming),
            }],
            load: Vec::new(),
            latency_us: 3,
            error: String::new(),
        };
        assert_eq!(health.gates.len(), 1);
        assert_eq!(health.gates[0].name, "session view");
    }
}
