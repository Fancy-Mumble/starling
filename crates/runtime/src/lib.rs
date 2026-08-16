//! `starling-runtime`: the one common standalone crate.
//!
//! Every service is a library crate plus a one-line binary:
//!
//! ```ignore
//! fn main() -> anyhow::Result<()> { starling_runtime::serve::<TextService>() }
//! ```
//!
//! What it provides, once, is what every service needs and what Kubernetes
//! requires (`docs/ARCHITECTURE.md` §7):
//!
//! * TOML config with environment override, so a `ConfigMap` works untemplated
//! * a tonic bootstrap over TCP or a Unix socket
//! * `/healthz` and `/readyz`, **distinct**, readiness fails while caches warm
//! * `SIGTERM` → graceful drain, because Kubernetes kills you 30 s later anyway
//! * tracing with a request id threaded through every hop, and a metrics endpoint
//! * endpoint discovery, which Kubernetes DNS fills in for free
//! * `--all-in-one`: every service in one process over in-memory transports,
//!   which is the same code exercising the same boundaries
//!
//! # What separate processes cost, and where that cost is paid
//!
//! The in-process design got health, tracing, restart semantics and version
//! skew for free (§8). Each of those is a module here, so a service author pays
//! for none of them again.

pub mod breaker;
pub mod channel;
pub mod config;
pub mod health;
pub mod health_rpc;
pub mod ids;
pub mod inflight;
pub mod inproc;
pub mod listen;
pub mod live;
pub mod log;
pub mod metrics;
pub mod names;
pub mod permit;
pub mod plane;
pub mod pressure;
pub mod ratelimit;
pub mod roster;
pub mod serve;
pub mod settings;
pub mod shutdown;
pub mod storage;
pub mod telemetry;
pub mod tier;
pub mod trail;
pub mod transport;

pub use breaker::{Breaker, BreakerState};
pub use channel::{ChannelError, Resolver};
pub use config::{Config, ConfigError, ServiceConfig};
pub use health::{Health, Readiness};
pub use ids::{Uuid7, now_ms};
pub use inproc::Broker;
pub use live::{ConfigCell, Outcome as ReloadOutcome, ReloadError};
pub use metrics::{Counter, Metrics};
pub use names::{NameRule, is_channel_name, is_user_name};
pub use permit::{Permit, permission_denied, refused};
pub use plane::{Actions, ClientService, Fanout, Inbound, Plane};
pub use ratelimit::{Rate, Throttled, TokenBucket};
pub use serve::{Serve, ServiceContext, ServiceError, context, run, serve, spawn};
pub use settings::{Settings, over_limit};
pub use shutdown::Shutdown;
pub use storage::{Store, StoreError};
pub use tier::Tier;
pub use trail::{Record, Trail};
pub use transport::{MalformedEndpoint, Transport};

/// The server's release version, `Cargo.toml`'s `[workspace.package] version`.
///
/// This crate inherits the workspace version (the binary and the internal
/// libraries do; the services and proto crates pin their own), so it is the one
/// place a service can read the *server's* version rather than its own crate's.
/// `session-lifecycle`'s handshake used to build its `Version.release` from its
/// own `CARGO_PKG_VERSION`, so every client was told "Starling 0.2.0" -- that
/// service's pinned number -- regardless of the release actually running.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
