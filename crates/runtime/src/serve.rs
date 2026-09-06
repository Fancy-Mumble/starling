//! The one-line binary every service is.
//!
//! ```ignore
//! fn main() -> Result<(), ServiceError> { starling_runtime::serve::<TextService>() }
//! ```
//!
//! Everything a service would otherwise repeat, config, discovery, health,
//! drain, telemetry, storage, the transport, is here, once. What a service
//! writes is [`Serve::build`], its gRPC routes, and optionally a background
//! task.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use tonic::service::Routes;

use crate::channel::Resolver;
use crate::config::{Config, ConfigError, ServiceConfig};
use crate::health::Health;
use crate::inproc::Broker;
use crate::listen::{ListenError, serve_routes};
use crate::live::ConfigCell;
use crate::log::{Category, LogEvent, Logger, Severity};
use crate::metrics::Metrics;
use crate::pressure::Pressure;
use crate::shutdown::Shutdown;
use crate::storage::{Store, StoreError};
use crate::telemetry;

/// Everything a service is handed at construction.
#[derive(Debug, Clone)]
pub struct ServiceContext {
    /// This service's configuration key, which is also its log name.
    pub name: String,
    /// The whole deployment configuration, **as it was at construction**.
    ///
    /// Right for everything that needs a restart anyway, which is almost all of
    /// it: a service reading its own endpoint or storage URL wants the value it
    /// was built with, not a moving target.
    ///
    /// A key classified [`Reload::Live`](crate::config::Reload::Live) is the
    /// exception and **must** be read through [`Self::live`] instead, because
    /// this snapshot does not follow the file. The classification table says
    /// which is which, and nothing is live until something follows it.
    pub config: Arc<Config>,
    /// The configuration as it reads *now*, and a way to follow it.
    ///
    /// The same value as [`Self::config`] until somebody reloads the file.
    pub live: ConfigCell,
    /// How to reach other services, without learning which transport.
    pub resolver: Resolver,
    /// Readiness gates. A service that caches declares them here.
    pub health: Health,
    /// Counters. Everything lost is counted.
    pub metrics: Metrics,
    /// Queue occupancy. Everything bounded says how full it is.
    ///
    /// The companion to `metrics` and not a duplicate of it: a counter says
    /// how many requests were refused, this says how close the next one is to
    /// being refused. The runtime fills in one gauge for every service by
    /// itself (`inflight`), so a service that registers nothing still reports
    /// its concurrency.
    pub pressure: Pressure,
    /// The operator event log.
    ///
    /// Every service holds the same one: the writer is process-wide, and a
    /// clone is only a channel handle. Use it for what an operator would want
    /// to read months later (a login, a refusal, a ban) and `tracing` for
    /// what a developer wants while reproducing a bug.
    pub logger: Logger,
    /// Drain.
    pub shutdown: Shutdown,
    /// The in-process switchboard, used only under `--all-in-one`.
    pub broker: Broker,
}

impl ServiceContext {
    /// This service's own block from the configuration.
    #[must_use]
    pub fn service(&self) -> ServiceConfig {
        self.config
            .services
            .get(&self.name)
            .cloned()
            .unwrap_or_default()
    }

    /// Follow `cell` rather than the fixed configuration built at construction.
    ///
    /// A composition root that knows which file it was started from calls this;
    /// [`context`] cannot, because it is handed a `Config` and not the path it
    /// came from.
    #[must_use]
    pub fn following(mut self, cell: ConfigCell) -> Self {
        // The resolver too: `runtime.max_tree_message` and
        // `gateway.control_bytes` are deployment-wide sizes it hands out, and
        // every reader of the channel tree asks it for them.
        self.resolver = self.resolver.clone().following(cell.clone());
        self.live = cell;
        self
    }

    /// Share one process-wide [`Health`] rather than this context's own.
    ///
    /// Under `--all-in-one` every service is in one process, so "should this be
    /// restarted" has one answer for all of them: a dead sweep in `voice` is
    /// this process's problem however healthy `pchat` is. Per-service health is
    /// still right when each runs on its own, which is why this is a choice the
    /// composition makes rather than a default.
    #[must_use]
    pub fn sharing_health(mut self, health: Health) -> Self {
        self.health = health;
        self
    }

    /// The server instances this deployment runs.
    #[must_use]
    pub fn instances(&self) -> Vec<u32> {
        if self.config.instances.is_empty() {
            return vec![1];
        }
        self.config.instances.iter().map(|v| v.id).collect()
    }

    /// Open this service's own database.
    ///
    /// Each service owns its own schema and no service reads another's tables,
    /// so this is deliberately per-service rather than a shared pool. With no
    /// `[services.<name>.storage]` block, a file under the data directory is
    /// used, a service that persists nothing simply never calls this.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the database cannot be opened or migrated.
    pub async fn storage(&self) -> Result<Store, StoreError> {
        let service = self.service();
        let (url, max_connections) = match service.storage {
            Some(storage) if !storage.url.is_empty() => (storage.url, storage.max_connections),
            _ => (
                self.default_storage_url(),
                crate::storage::DEFAULT_MAX_CONNECTIONS,
            ),
        };
        Store::open(&url, max_connections).await
    }

    fn default_storage_url(&self) -> String {
        let dir: &Path = &self.config.runtime.data_dir;
        let _ = std::fs::create_dir_all(dir);
        sqlite_url(dir, &self.name)
    }
}

/// The URL for `service`'s own database file under `dir`.
///
/// `sqlite:` and not `sqlite://`. Those two slashes introduce a URL *authority*,
/// so everything up to the next separator is parsed as a host, which for
/// `C:\srv\starling` means the drive letter becomes the host and the database is
/// looked for at the filesystem root, reported as nothing more than "unable to
/// open database file". Unix hides the mistake completely, because a data
/// directory there starts with `/` and leaves the authority empty.
///
/// With no authority the whole remainder is the filename, which is also what
/// lets the spaces and brackets a real data directory contains survive without
/// percent-encoding a path by hand.
fn sqlite_url(dir: &Path, service: &str) -> String {
    format!(
        "sqlite:{}?mode=rwc",
        dir.join(format!("{service}.db")).display()
    )
}

/// What a service implements to be servable.
///
/// The async methods are written as `-> impl Future<..> + Send` rather than as
/// `async fn`. The trait is `Sized`, so nothing here needs boxing, but `run`
/// below is spawned over a generic `S: Serve` and a plain `async fn` in a trait
/// gives no way to require its future is `Send`, return-type notation is still
/// unstable. Implementations may, and do, write `async fn` regardless.
pub trait Serve: Send + Sync + Sized + 'static {
    /// The configuration key and log name.
    const NAME: &'static str;

    /// Whether anything calls this unit.
    ///
    /// The gateway is the one that says `false`: nothing calls it, it calls
    /// everything, and giving it an endpoint nobody dials would be a socket
    /// with no purpose and one more thing to misconfigure.
    const SERVES_GRPC: bool = true;

    /// Construct, but do not start serving.
    ///
    /// Anything that can fail an operator's configuration belongs here, so a
    /// misconfigured service fails at startup rather than on the first request.
    fn build(ctx: ServiceContext) -> impl Future<Output = Result<Arc<Self>, ServiceError>> + Send;

    /// The gRPC surface. A service may register several servers.
    fn routes(self: Arc<Self>) -> Routes;

    /// Background work: sockets this service owns, sweeps, subscriptions.
    ///
    /// Returning is a shutdown, not an error. The default does nothing.
    fn run(
        self: Arc<Self>,
        ctx: ServiceContext,
    ) -> impl Future<Output = Result<(), ServiceError>> + Send {
        let _ = ctx;
        async { Ok(()) }
    }
}

/// Why a service could not start or keep running.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The configuration was unusable.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The transport failed.
    #[error(transparent)]
    Listen(#[from] ListenError),
    /// Another service could not be reached.
    #[error(transparent)]
    Channel(#[from] crate::channel::ChannelError),
    /// Storage failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Something specific to one service.
    #[error("{0}")]
    Service(String),
    /// An I/O failure at startup.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ServiceError {
    /// A service-specific failure.
    #[must_use]
    pub fn service(message: impl Into<String>) -> Self {
        Self::Service(message.into())
    }
}

/// Build a context for `name` from `config`.
///
/// `logger` is a parameter rather than something defaulted here because a
/// service that logs nowhere looks exactly like a service where nothing is
/// happening. A caller with no log to give says so with [`Logger::null`].
#[must_use]
pub fn context(
    name: &str,
    config: Arc<Config>,
    broker: Broker,
    shutdown: Shutdown,
    logger: Logger,
) -> ServiceContext {
    ServiceContext {
        name: name.to_owned(),
        resolver: Resolver::new(Arc::clone(&config), broker.clone()),
        // Fixed: a caller with a file behind it replaces this with
        // [`ServiceContext::following`], and one without never reloads.
        live: ConfigCell::fixed(Arc::clone(&config)),
        health: Health::new(),
        metrics: Metrics::new(),
        pressure: Pressure::new(),
        logger,
        shutdown,
        broker,
        config,
    }
}

/// Build, start and serve one service until it drains.
///
/// # Errors
///
/// [`ServiceError`] if construction or serving fails. A background task
/// returning `Err` is logged and ends that task; it does not take the process
/// down, because a service whose sweep failed is still worth answering
/// queries. A background task that *panicked* is reported as this service
/// failing, because a release build would already have aborted on it.
pub async fn run<S: Serve>(ctx: ServiceContext) -> Result<(), ServiceError> {
    let service = match S::build(ctx.clone()).await {
        Ok(service) => service,
        Err(error) => {
            // A service that cannot be built is the operator's problem, not the
            // developer's: it means the configuration it was handed is wrong.
            ctx.logger.log(
                LogEvent::error(Category::Server, "service failed to start")
                    .with("service", ctx.name.clone())
                    .with("error", error.to_string()),
            );
            return Err(error);
        }
    };
    ctx.logger
        .log(LogEvent::info(Category::Server, "service started").with("service", ctx.name.clone()));

    // Supervised, not merely spawned. A `run` that returned `Err` used to end
    // there: the task was gone for the life of the process, everything
    // depending on it failed, and the only trace was one log line at start-up.
    // Now it is restarted with backoff, and a service that cannot stay up stops
    // claiming to be live, which is what makes systemd or Kubernetes act.
    ctx.health
        .heartbeat(BACKGROUND_HEARTBEAT, background_max_age::<S>());
    let mut background = {
        let service = Arc::clone(&service);
        let ctx = ctx.clone();
        tokio::spawn(async move { supervise(service, ctx).await })
    };

    if !S::SERVES_GRPC {
        // Nothing to serve: the unit *is* its background task, so its exit is
        // the exit of the whole thing rather than something to abort.
        return match background.await {
            Ok(result) => result,
            Err(error) => Err(ServiceError::service(format!(
                "{} stopped: {error}",
                ctx.name
            ))),
        };
    }

    let transport = ctx.resolver.listener(&ctx.name)?;
    let result = serve_routes(
        &ctx.name,
        transport.as_ref(),
        &ctx.broker,
        // Every service answers for its own readiness and load, wired in here
        // rather than by each service's `routes()`, a health surface a
        // service can forget to implement is one the least-instrumented
        // service lacks, which is the service most worth asking about.
        // One call site for the whole tree: every service's counters and
        // gauges reach the collector from here, so a service cannot forget to
        // export them and the least-instrumented service is not the one most
        // worth asking about.
        crate::health_rpc::with_health(
            service.routes(),
            &ctx.name,
            &ctx.health,
            &ctx.pressure,
            &ctx.metrics,
        ),
        // Counts requests this service has not finished. Same argument as
        // above and the same place to make it: measured for everyone, opted
        // into by no one.
        &ctx.pressure,
        ctx.shutdown.clone(),
    )
    .await;

    // The background task is given its moment before it is cut off, because it
    // is the half that lets go: by convention every `run` waits for the drain
    // and then aborts the subscriptions this service holds *on other services*,
    // and those are exactly the streams the other services are waiting to see
    // closed before their own drain can finish. Aborting the instant this
    // socket falls quiet took that code away from whichever service happened to
    // drain first -- the gateway, usually, since nothing holds a stream into it
    // -- and left every service it had attached to waiting for a stream nobody
    // was coming back for.
    //
    // Bounded, and only while draining: a `run` that ended by itself has
    // already returned, and one that is still working through an ordinary
    // request has no reason to be waited on at all.
    //
    // The join result is inspected rather than discarded. A panicking task is
    // not the same event as one that returned `Err`: in a release build
    // `panic = "abort"` takes the whole process down at the panic, so there is
    // no "the sweep failed but queries are still worth answering" to preserve.
    // Under `cargo test` the same panic unwinds into a `JoinError` here, and
    // dropping it was what let a service die mid-suite and surface only as
    // some later test timing out on a client this service should have
    // answered. Reported as this service failing, which is what the abort
    // would have made it.
    let mut panicked = None;
    if ctx.shutdown.is_draining()
        && let Ok(Err(joined)) = tokio::time::timeout(LETTING_GO, &mut background).await
        && joined.is_panic()
    {
        panicked = Some(panic_message(joined));
    }
    background.abort();
    if let Some(message) = panicked {
        ctx.logger.log(
            LogEvent::new(
                Severity::Critical,
                Category::Server,
                "background task panicked",
            )
            .with("service", ctx.name.clone())
            .with("panic", message.clone()),
        );
        return Err(ServiceError::service(format!(
            "{}'s background task panicked: {message}",
            ctx.name
        )));
    }
    ctx.logger
        .log(LogEvent::info(Category::Server, "service stopped").with("service", ctx.name.clone()));
    result.map_err(ServiceError::from)
}

/// The message a panicking task carried.
///
/// A payload is `Box<dyn Any>`; the two shapes `panic!` produces are a
/// `&'static str` for a literal and a `String` for a format.
fn panic_message(error: tokio::task::JoinError) -> String {
    let payload = error.into_panic();
    payload
        .downcast_ref::<&'static str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a payload that is not a string".to_owned())
}

/// The heartbeat a supervised background task keeps fresh.
///
/// One name, not one per service, because a process holds one service's
/// background task and the liveness answer is about the process.
const BACKGROUND_HEARTBEAT: &str = "background";

/// How long a background task may go without beating before this process is
/// not live.
///
/// A service whose `run` is a sweep on a five-minute timer is not late at four
/// minutes, so this is deliberately generous: it exists to catch a task that is
/// *gone*, and a tighter bound would restart a healthy server on a busy
/// machine. The supervisor beats it on every restart as well as through the
/// task, so a service restarting in a loop stays live until it exceeds
/// `MAX_RESTARTS`, where a *count* rather than a clock is the right signal.
fn background_max_age<S: Serve>() -> std::time::Duration {
    let _ = std::marker::PhantomData::<S>;
    std::time::Duration::from_secs(600)
}

/// How many times a background task is restarted before the process gives up.
///
/// Not unlimited: a task that fails immediately every time would otherwise spin
/// forever, reporting itself live, doing nothing. After this the heartbeat is
/// left to go stale, `/livez` fails, and the supervisor above this process --
/// systemd or Kubernetes -- restarts the whole thing, which is the one thing
/// that can clear state this process cannot.
const MAX_RESTARTS: u32 = 5;

/// The delay before the first restart. Doubles, to a ceiling.
const RESTART_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

/// The longest the supervisor waits between restarts.
const RESTART_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// Run a service's background task, restarting it if it fails.
///
/// Returns when the task returns `Ok`, when the process is draining, or when
/// the task has failed [`MAX_RESTARTS`] times. A panic is not caught here: with
/// `panic = "abort"` there is nothing to catch in a release build, and under
/// test the join in `run` above reports it.
async fn supervise<S: Serve>(service: Arc<S>, ctx: ServiceContext) -> Result<(), ServiceError> {
    let mut backoff = RESTART_BACKOFF;
    for attempt in 0..=MAX_RESTARTS {
        ctx.health.beat(BACKGROUND_HEARTBEAT);
        let result = Arc::clone(&service).run(ctx.clone()).await;

        let Err(error) = result else {
            // Returned on purpose, which for every service here means the
            // drain. Nothing left to keep alive.
            ctx.health.forget_heartbeat(BACKGROUND_HEARTBEAT);
            return Ok(());
        };

        // A drain that surfaced as an error is still a drain.
        if ctx.shutdown.is_draining() {
            ctx.health.forget_heartbeat(BACKGROUND_HEARTBEAT);
            return Ok(());
        }

        ctx.logger.log(
            LogEvent::error(Category::Server, "background task stopped")
                .with("service", ctx.name.clone())
                .with("error", error.to_string())
                .with("attempt", u64::from(attempt)),
        );

        if attempt == MAX_RESTARTS {
            // Left to go stale deliberately: this process cannot fix itself,
            // and the next thing that can is whatever restarts processes.
            ctx.logger.log(
                LogEvent::new(
                    Severity::Critical,
                    Category::Server,
                    "background task will not stay up; this process is no longer live",
                )
                .with("service", ctx.name.clone())
                .with("restarts", u64::from(MAX_RESTARTS)),
            );
            return Err(error);
        }

        tokio::select! {
            () = ctx.shutdown.wait() => {
                ctx.health.forget_heartbeat(BACKGROUND_HEARTBEAT);
                return Ok(());
            }
            () = tokio::time::sleep(backoff) => {}
        }
        // Counted here, not above: this is the point at which a restart
        // actually happens, so the counter means restarts rather than
        // failures. The two differ by one on the give-up path, which is
        // exactly the case an alert on this rate is about.
        ctx.metrics.counter("starling_service_restarts").inc();
        backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
    }
    Ok(())
}

/// How long a drained service's background task has to let go of what it holds.
///
/// Long enough for the aborts and the last flush a `run` does on its way out,
/// which are immediate, and short enough that a `run` written without a drain
/// in mind costs a moment rather than the whole grace period.
const LETTING_GO: std::time::Duration = std::time::Duration::from_secs(1);

/// The whole binary for one service: runtime, config, telemetry, serve.
///
/// # Errors
///
/// [`ServiceError`] if the configuration cannot be read or the service cannot
/// be served.
pub fn serve<S: Serve>() -> Result<(), ServiceError> {
    let (config, source) = load_config()?;
    telemetry::install(&config.telemetry);
    let log = crate::log::LogRuntime::start_from(&config.logging);
    let logger = log.logger().clone();
    let handles = log.handles();

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let shutdown = Shutdown::new();
        shutdown.install_signal_handler();

        let config = Arc::new(config);
        let cell = match source {
            Some(path) => ConfigCell::watching(Arc::clone(&config), path),
            // No file, so nothing to re-read. The cell still exists, so a
            // service written against it needs no second code path.
            None => ConfigCell::fixed(Arc::clone(&config)),
        };
        cell.install_signal_handler(&logger);
        crate::live::follow_logging(&cell, handles, logger.clone());

        let ctx = context(S::NAME, config, Broker::new(), shutdown, logger).following(cell);
        run::<S>(ctx).await
    });

    // After the runtime is done, so records written on the way out are not lost
    // to a writer that stopped first.
    log.finish();
    result
}

/// Start one service inside a process that is already running others.
///
/// This is what `--all-in-one` uses; the returned handle is joined by the
/// caller so a failure in any service is reported rather than swallowed.
pub fn spawn<S: Serve>(ctx: ServiceContext) -> tokio::task::JoinHandle<Result<(), ServiceError>> {
    tokio::spawn(async move {
        let name = ctx.name.clone();
        let logger = ctx.logger.clone();
        let result = run::<S>(ctx).await;
        if let Err(error) = &result {
            // Distinct from the "service stopped" `run` records on the way out:
            // that one is a service draining normally, this is one that failed.
            // Same words, opposite meanings, which is why they need different
            // severities rather than one shared line.
            logger.log(
                LogEvent::error(Category::Server, "service failed")
                    .with("service", name)
                    .with("error", error.to_string()),
            );
        }
        result
    })
}

/// `--config <path>`, or the built-in defaults.
///
/// Returns the path alongside the configuration, because reloading needs to
/// know where it came from and argv is the only place that says so.
fn load_config() -> Result<(Config, Option<std::path::PathBuf>), ConfigError> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config"
            && let Some(path) = args.next()
        {
            let path = std::path::PathBuf::from(path);
            return Ok((Config::load(&path)?, Some(path)));
        }
    }
    let mut config = Config::with_defaults(Path::new("/run/starling"));
    crate::config::apply_environment(&mut config, &std::env::vars().collect::<Vec<_>>())?;
    Ok((config, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A service whose background task fails a fixed number of times.
    struct Flaky {
        /// Failures remaining before `run` starts succeeding.
        failures: std::sync::atomic::AtomicU32,
        /// How many times `run` has been entered.
        runs: Arc<std::sync::atomic::AtomicU32>,
    }

    impl Serve for Flaky {
        const NAME: &'static str = "flaky";

        async fn build(_ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
            Ok(Arc::new(Self {
                failures: std::sync::atomic::AtomicU32::new(0),
                runs: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            }))
        }

        fn routes(self: Arc<Self>) -> Routes {
            Routes::default()
        }

        async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
            let _ = self.runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let left = self.failures.load(std::sync::atomic::Ordering::Relaxed);
            if left > 0 {
                self.failures
                    .store(left - 1, std::sync::atomic::Ordering::Relaxed);
                return Err(ServiceError::service("the sweep fell over"));
            }
            ctx.shutdown.wait().await;
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_background_task_that_fails_is_restarted_rather_than_lost() {
        // It used to end there: gone for the life of the process, with one log
        // line at start-up and everything depending on it failing since.
        let ctx = ctx("flaky");
        let runs = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let service = Arc::new(Flaky {
            failures: std::sync::atomic::AtomicU32::new(2),
            runs: Arc::clone(&runs),
        });

        ctx.health
            .heartbeat(BACKGROUND_HEARTBEAT, std::time::Duration::from_secs(600));
        let supervised = tokio::spawn({
            let ctx = ctx.clone();
            async move { supervise(service, ctx).await }
        });

        // Two failures, two backoffs, then it stays up.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(
            runs.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "two failures must be followed by a third attempt that stays up"
        );
        assert_eq!(
            ctx.metrics.counter("starling_service_restarts").get(),
            2,
            "each restart must be counted, so an operator can alert on the rate"
        );
        assert!(ctx.health.is_live(), "a service that recovered is live");

        ctx.shutdown.drain();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), supervised).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_task_that_will_not_stay_up_stops_claiming_to_be_live() {
        // The point of the ceiling: a task failing instantly forever would
        // otherwise spin, reporting itself healthy, doing nothing. Failing
        // liveness is what gets the process restarted by something that can
        // clear state it cannot.
        let ctx = ctx("hopeless");
        let service = Arc::new(Flaky {
            failures: std::sync::atomic::AtomicU32::new(u32::MAX),
            runs: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        });

        // A zero max-age, so "still registered" is observable the instant the
        // supervisor returns. `Health` measures with `std::time::Instant`,
        // which a paused tokio clock does not move, and the staleness rule
        // itself is tested in `crate::health`.
        ctx.health
            .heartbeat(BACKGROUND_HEARTBEAT, std::time::Duration::ZERO);
        let result = supervise(service, ctx.clone()).await;

        assert!(result.is_err(), "the supervisor must give up and say so");
        assert_eq!(
            ctx.metrics.counter("starling_service_restarts").get(),
            u64::from(MAX_RESTARTS),
            "one count per restart actually made, not per failure seen"
        );
        // Left to go stale, not forgotten: forgetting it would make a process
        // that gave up look healthy, which is the whole failure being closed.
        assert!(
            !ctx.health.is_live(),
            "a process that cannot keep its own task up must not pass liveness"
        );
        assert_eq!(
            ctx.health.stale().first().map(|(name, _)| name.as_str()),
            Some(BACKGROUND_HEARTBEAT),
            "and must name what stopped"
        );
    }

    #[tokio::test]
    async fn draining_is_not_a_failure() {
        // Otherwise every service reports itself dead on the way out, and a
        // clean shutdown looks like a crash in every dashboard.
        let ctx = ctx("draining");
        let service = Arc::new(Flaky {
            failures: std::sync::atomic::AtomicU32::new(0),
            runs: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        });
        ctx.health
            .heartbeat(BACKGROUND_HEARTBEAT, std::time::Duration::from_millis(1));

        ctx.shutdown.drain();
        assert!(supervise(service, ctx.clone()).await.is_ok());
        assert_eq!(ctx.metrics.counter("starling_service_restarts").get(), 0);
        assert!(
            ctx.health.is_live(),
            "the heartbeat must be forgotten, not left to go stale"
        );
    }

    fn ctx(name: &str) -> ServiceContext {
        let config = Config::with_defaults(Path::new("/run/starling"));
        context(
            name,
            Arc::new(config),
            Broker::new(),
            Shutdown::new(),
            Logger::null(),
        )
    }

    #[test]
    fn a_service_reads_its_own_block_and_not_another() {
        let voice = ctx("voice").service();
        assert!(voice.udp_listen.is_some(), "voice owns a UDP socket");
        assert!(ctx("text").service().udp_listen.is_none());
    }

    #[test]
    fn a_deployment_with_no_server_instances_still_has_one() {
        // Everything is keyed by server instance; an empty list would mean a
        // server that stores nothing anywhere.
        assert_eq!(ctx("metadata").instances(), vec![1]);
    }

    #[test]
    fn the_default_database_is_per_service_not_shared() {
        // No service reads another's tables, and one file would invite it.
        assert_ne!(
            sqlite_url(Path::new("/var/lib/starling"), "pchat"),
            sqlite_url(Path::new("/var/lib/starling"), "audit")
        );
        assert!(
            sqlite_url(Path::new("/var/lib/starling"), "pchat").contains("pchat"),
            "a service's database has to be findable by its name"
        );
    }

    #[test]
    fn a_data_directory_is_never_parsed_as_a_url_authority() {
        // `sqlite://C:\srv\...` reads the drive letter as the host and then opens
        // nothing. Unix cannot reproduce it, a data directory there starts with
        // `/`, which leaves the authority empty, so this assertion is the only
        // thing standing between the shipped default and a Windows server whose
        // every persisting service dies at startup.
        for dir in [
            r"C:\srv\starling data",
            "/var/lib/starling",
            "starling-data",
        ] {
            let url = sqlite_url(Path::new(dir), "text");
            assert!(
                !url.starts_with("sqlite://"),
                "{url} puts {dir} in the authority"
            );
            assert!(url.starts_with("sqlite:"), "{url} lost its scheme");
            assert!(url.contains(dir), "{url} lost the directory it was given");
        }
    }
}
