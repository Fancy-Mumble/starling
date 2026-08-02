//! The one-line binary every service is.
//!
//! ```ignore
//! fn main() -> Result<(), ServiceError> { starling_runtime::serve::<TextService>() }
//! ```
//!
//! Everything a service would otherwise repeat — config, discovery, health,
//! drain, telemetry, storage, the transport — is here, once. What a service
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
use crate::log::{Category, LogEvent, Logger};
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
    /// The whole deployment configuration, read once at startup.
    pub config: Arc<Config>,
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
    /// to read months later — a login, a refusal, a ban — and `tracing` for
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

    /// The virtual servers this deployment runs.
    #[must_use]
    pub fn virtual_servers(&self) -> Vec<u32> {
        if self.config.virtual_servers.is_empty() {
            return vec![1];
        }
        self.config.virtual_servers.iter().map(|v| v.id).collect()
    }

    /// Open this service's own database.
    ///
    /// Each service owns its own schema and no service reads another's tables,
    /// so this is deliberately per-service rather than a shared pool. With no
    /// `[services.<name>.storage]` block, a file under the data directory is
    /// used — a service that persists nothing simply never calls this.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the database cannot be opened or migrated.
    pub async fn storage(&self) -> Result<Store, StoreError> {
        let service = self.service();
        let (url, max_connections) = match service.storage {
            Some(storage) if !storage.url.is_empty() => (storage.url, storage.max_connections),
            _ => (self.default_storage_url(), 8),
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
/// so everything up to the next separator is parsed as a host — which for
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
/// gives no way to require its future is `Send` — return-type notation is still
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
/// failing is logged and ends that task; it does not take the process down,
/// because a service whose sweep failed is still worth answering queries.
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

    let background = {
        let service = Arc::clone(&service);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let result = service.run(ctx.clone()).await;
            if let Err(error) = &result {
                ctx.logger.log(
                    LogEvent::error(Category::Server, "background task stopped")
                        .with("service", ctx.name.clone())
                        .with("error", error.to_string()),
                );
            }
            result
        })
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

    let transport = ctx.resolver.transport(&ctx.name)?;
    let result = serve_routes(
        &ctx.name,
        transport.as_ref(),
        &ctx.broker,
        // Every service answers for its own readiness and load, wired in here
        // rather than by each service's `routes()` — a health surface a
        // service can forget to implement is one the least-instrumented
        // service lacks, which is the service most worth asking about.
        crate::health_rpc::with_health(service.routes(), &ctx.name, &ctx.health, &ctx.pressure),
        // Counts requests this service has not finished. Same argument as
        // above and the same place to make it: measured for everyone, opted
        // into by no one.
        &ctx.pressure,
        ctx.shutdown.clone(),
    )
    .await;

    background.abort();
    ctx.logger
        .log(LogEvent::info(Category::Server, "service stopped").with("service", ctx.name.clone()));
    result.map_err(ServiceError::from)
}

/// The whole binary for one service: runtime, config, telemetry, serve.
///
/// # Errors
///
/// [`ServiceError`] if the configuration cannot be read or the service cannot
/// be served.
pub fn serve<S: Serve>() -> Result<(), ServiceError> {
    let config = load_config()?;
    telemetry::install(&config.telemetry);
    let log = crate::log::LogRuntime::start_from(&config.logging);
    let logger = log.logger().clone();

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let shutdown = Shutdown::new();
        shutdown.install_signal_handler();
        let ctx = context(S::NAME, Arc::new(config), Broker::new(), shutdown, logger);
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
            // Same words, opposite meanings — which is why they need different
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
fn load_config() -> Result<Config, ConfigError> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config"
            && let Some(path) = args.next()
        {
            return Config::load(Path::new(&path));
        }
    }
    let mut config = Config::with_defaults(Path::new("/run/starling"));
    crate::config::apply_environment(&mut config, &std::env::vars().collect::<Vec<_>>())?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
    fn a_deployment_with_no_virtual_servers_still_has_one() {
        // Everything is keyed by virtual server; an empty list would mean a
        // server that stores nothing anywhere.
        assert_eq!(ctx("metadata").virtual_servers(), vec![1]);
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
        // `sqlite://C:\srv\…` reads the drive letter as the host and then opens
        // nothing. Unix cannot reproduce it — a data directory there starts with
        // `/`, which leaves the authority empty — so this assertion is the only
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
