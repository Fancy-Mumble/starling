//! Serving a service's gRPC routes over whichever transport it was given.
//!
//! One function, every transport, and the service never learns which, the
//! same asymmetry [`crate::channel`] provides on the calling side. Which
//! transport it is lives behind [`Transport::bind`]; what is left here is the
//! part that is identical for all of them, including that every one stops
//! accepting on drain and finishes what it is holding, because Kubernetes
//! sends `SIGTERM` and then `SIGKILL` thirty seconds later whatever the
//! process thinks about it.

use tonic::service::Routes;
use tonic::transport::Server;

use crate::inflight::InFlightLayer;
use crate::inproc::Broker;
use crate::pressure::Pressure;
use crate::shutdown::Shutdown;
use crate::transport::Transport;

/// Why a service could not be served.
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    /// The socket could not be bound.
    #[error("binding {what}: {source}")]
    Bind {
        /// What was being bound.
        what: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The endpoint could not be turned into an address to bind.
    #[error("{0}")]
    Address(String),
    /// The server stopped with an error.
    #[error(transparent)]
    Serve(#[from] tonic::transport::Error),
    /// The in-process registry refused.
    #[error(transparent)]
    Broker(#[from] crate::inproc::BrokerError),
}

/// Serve `routes` over `transport` until `shutdown` drains.
///
/// # Errors
///
/// [`ListenError`] if the transport cannot be bound, or if serving fails.
pub async fn serve_routes(
    name: &str,
    transport: &dyn Transport,
    broker: &Broker,
    routes: Routes,
    pressure: &Pressure,
    shutdown: Shutdown,
) -> Result<(), ListenError> {
    let signal = {
        let shutdown = shutdown.clone();
        async move { shutdown.wait().await }
    };
    tracing::info!(service = name, endpoint = %transport.describe(), "serving");

    let incoming = transport.bind(broker).await?;
    Server::builder()
        // Wraps every RPC this service serves, including the health surface
        // itself. That is intentional: the collector's own call is a request
        // like any other, and a gauge that excluded it would under-report a
        // service by exactly the traffic the dashboard generates.
        .layer(InFlightLayer::new(pressure))
        .add_routes(routes)
        .serve_with_incoming_shutdown(incoming, signal)
        .await?;

    tracing::info!(service = name, "drained");
    Ok(())
}
