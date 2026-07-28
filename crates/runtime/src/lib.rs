//! `starling-runtime` — the one common standalone crate.
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
//! * `/healthz` and `/readyz`, **distinct** — readiness fails while caches warm
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
pub mod ids;
pub mod inproc;
pub mod listen;
pub mod log;
pub mod metrics;
pub mod permit;
pub mod plane;
pub mod ratelimit;
pub mod serve;
pub mod shutdown;
pub mod storage;
pub mod telemetry;
pub mod tier;
pub mod transport;

pub use breaker::{Breaker, BreakerState};
pub use channel::{ChannelError, Resolver};
pub use config::{Config, ConfigError, ServiceConfig};
pub use health::{Health, Readiness};
pub use ids::{Uuid7, now_ms};
pub use inproc::Broker;
pub use metrics::{Counter, Metrics};
pub use permit::{Permit, permission_denied};
pub use plane::{Actions, ClientService, Fanout, Inbound, Plane};
pub use ratelimit::{Rate, Throttled, TokenBucket};
pub use serve::{Serve, ServiceContext, ServiceError, context, run, serve, spawn};
pub use shutdown::Shutdown;
pub use storage::{Store, StoreError};
pub use tier::Tier;
pub use transport::{MalformedEndpoint, Transport};
