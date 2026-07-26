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

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tonic::service::Routes;

use crate::channel::Resolver;
use crate::config::{Config, ConfigError, ServiceConfig};
use crate::health::Health;
use crate::inproc::Broker;
use crate::listen::{ListenError, serve_routes};
use crate::metrics::Metrics;
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
        let dir: PathBuf = self.config.runtime.data_dir.clone();
        let _ = std::fs::create_dir_all(&dir);
        format!("sqlite://{}/{}.db?mode=rwc", dir.display(), self.name)
    }
}

/// What a service implements to be servable.
#[async_trait]
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
    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError>;

    /// The gRPC surface. A service may register several servers.
    fn routes(self: Arc<Self>) -> Routes;

    /// Background work: sockets this service owns, sweeps, subscriptions.
    ///
    /// Returning is a shutdown, not an error. The default does nothing.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let _ = ctx;
        Ok(())
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
#[must_use]
pub fn context(name: &str, config: Arc<Config>, broker: Broker, shutdown: Shutdown) -> ServiceContext {
    ServiceContext {
        name: name.to_owned(),
        resolver: Resolver::new(Arc::clone(&config), broker.clone()),
        health: Health::new(),
        metrics: Metrics::new(),
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
    let service = S::build(ctx.clone()).await?;

    let background = {
        let service = Arc::clone(&service);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let result = service.run(ctx.clone()).await;
            if let Err(error) = &result {
                tracing::error!(service = %ctx.name, %error, "background task stopped");
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

    let endpoint = ctx.resolver.endpoint(&ctx.name)?;
    let result = serve_routes(
        &ctx.name,
        &endpoint,
        &ctx.broker,
        service.routes(),
        ctx.shutdown.clone(),
    )
    .await;

    background.abort();
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
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let shutdown = Shutdown::new();
        shutdown.install_signal_handler();
        let ctx = context(S::NAME, Arc::new(config), Broker::new(), shutdown);
        run::<S>(ctx).await
    })
}

/// Start one service inside a process that is already running others.
///
/// This is what `--all-in-one` uses; the returned handle is joined by the
/// caller so a failure in any service is reported rather than swallowed.
pub fn spawn<S: Serve>(ctx: ServiceContext) -> tokio::task::JoinHandle<Result<(), ServiceError>> {
    tokio::spawn(async move {
        let name = ctx.name.clone();
        let result = run::<S>(ctx).await;
        if let Err(error) = &result {
            tracing::error!(service = %name, %error, "service stopped");
        }
        result
    })
}

/// `--config <path>`, or the built-in defaults.
fn load_config() -> Result<Config, ConfigError> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config"
            && let Some(path) = args.next() {
                return Config::load(std::path::Path::new(&path));
            }
    }
    let mut config = Config::with_defaults(std::path::Path::new("/run/starling"));
    crate::config::apply_environment(&mut config, &std::env::vars().collect::<Vec<_>>())?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn ctx(name: &str) -> ServiceContext {
        let config = Config::with_defaults(Path::new("/run/starling"));
        context(name, Arc::new(config), Broker::new(), Shutdown::new())
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
        assert_ne!(ctx("pchat").default_storage_url(), ctx("audit").default_storage_url());
        assert!(ctx("pchat").default_storage_url().contains("pchat"));
    }
}
