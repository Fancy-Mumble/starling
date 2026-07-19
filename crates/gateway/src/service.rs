//! The gateway as something the runtime can start.
//!
//! It is not a gRPC service (it is the process that *calls* them) but it
//! wants the same config loading, health endpoints, drain and telemetry every
//! service gets. So it implements [`Serve`] with an empty route set and does
//! its work in [`Serve::run`].

use std::sync::Arc;

use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tonic::service::Routes;

use crate::listener::Gateway;

/// The gateway, as a startable unit.
#[derive(Debug)]
pub struct GatewayService {
    gateway: Arc<Gateway>,
}

impl Serve for GatewayService {
    const NAME: &'static str = "gateway";

    /// Something does call the gateway over gRPC now: the `health` collector.
    ///
    /// This was `false`, on the argument that an endpoint nobody dials is one
    /// more thing to misconfigure. That argument held until there was a
    /// collector, and its consequence was that the gateway, the process every
    /// client connects to, holding every control queue and every audio buffer
    /// in the server, was the one component absent from the health dashboard.
    /// Its `listener` and `session store` gates existed and had no reader.
    ///
    /// The runtime's `with_health` adds the health surface to the empty route
    /// set below, so this costs a `[services.gateway]` entry with an endpoint
    /// and no gateway code at all.
    const SERVES_GRPC: bool = true;

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("listener");
        let gateway = Gateway::new(
            Arc::clone(&ctx.config),
            ctx.metrics.clone(),
            &ctx.pressure,
            ctx.health.clone(),
            ctx.logger.clone(),
        )
        .map_err(|error| ServiceError::service(error.to_string()))?;
        Ok(Arc::new(Self {
            gateway: Arc::new(gateway),
        }))
    }

    /// No gRPC surface: nothing calls the gateway, the gateway calls everything.
    fn routes(self: Arc<Self>) -> Routes {
        Routes::default()
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        Arc::clone(&self.gateway)
            .run(ctx.resolver.clone(), ctx.shutdown.clone())
            .await
            .map_err(|error| ServiceError::service(error.to_string()))
    }
}

impl GatewayService {
    /// The gateway underneath, for the admin surface.
    #[must_use]
    pub fn gateway(&self) -> &Arc<Gateway> {
        &self.gateway
    }
}
