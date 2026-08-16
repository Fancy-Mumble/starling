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

/// How long a drained service waits for what it is still holding.
///
/// tonic's graceful shutdown stops accepting and then waits for every open
/// connection to close, which is right for the requests in flight and wrong for
/// a subscription: a `watch` or an `attach` stream ends when its *client*
/// decides to end it, and the clients here are the peer services draining
/// alongside this one. Whoever waits last waits forever, and the process leaves
/// on `SIGKILL` with no records of why.
///
/// So the wait is bounded. This is long enough for any request-reply exchange
/// -- they are milliseconds, in-process ones are microseconds -- and short
/// enough to be well inside the grace period an init system allows before it
/// stops asking.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

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
    let serving = Server::builder()
        // Wraps every RPC this service serves, including the health surface
        // itself. That is intentional: the collector's own call is a request
        // like any other, and a gauge that excluded it would under-report a
        // service by exactly the traffic the dashboard generates.
        .layer(InFlightLayer::new(pressure))
        .add_routes(routes)
        .serve_with_incoming_shutdown(incoming, signal);
    tokio::pin!(serving);

    tokio::select! {
        result = &mut serving => result?,
        () = shutdown.wait() => match tokio::time::timeout(DRAIN_GRACE, &mut serving).await {
            Ok(result) => result?,
            // Named, and at warning: a service that has to be cut off is
            // holding a stream somebody forgot to end on drain, and the name
            // is the whole of the answer to which one.
            Err(_) => tracing::warn!(
                service = name,
                grace = ?DRAIN_GRACE,
                "still holding connections after the drain; stopping anyway"
            ),
        },
    }

    tracing::info!(service = name, "drained");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use starling_proto_fancy::control::client_plane_client::ClientPlaneClient;
    use starling_proto_fancy::control::{ClientEvent, GatewayHello, client_event};
    use tokio::sync::mpsc;

    use super::{DRAIN_GRACE, serve_routes};
    use crate::inproc::Broker;
    use crate::plane::{Actions, ClientService, Fanout, Inbound, Plane};
    use crate::pressure::Pressure;
    use crate::shutdown::Shutdown;
    use crate::transport;

    /// A service with a client plane and nothing to say on it.
    struct Silent;

    impl ClientService for Silent {
        async fn frame(&self, _inbound: Inbound) -> Actions {
            Actions::new()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_drain_is_not_held_open_by_a_stream_whose_other_end_is_also_draining() {
        // The shutdown hang, in one test. A gateway's attachment is a stream
        // that ends when the gateway ends it, and on `SIGTERM` the gateway is
        // draining at the same moment this service is: whoever waits for the
        // other waits forever. Graceful means "finish the requests in flight",
        // not "wait for a subscription nobody is going to close".
        let broker = Broker::new();
        let shutdown = Shutdown::new();
        let transport = transport::in_process("silent");
        let routes = tonic::service::Routes::default()
            .add_service(Plane::new(Arc::new(Silent), Fanout::default(), "silent").into_server());

        let serving = tokio::spawn({
            let broker = broker.clone();
            let shutdown = shutdown.clone();
            let transport = Arc::clone(&transport);
            async move {
                serve_routes(
                    "silent",
                    transport.as_ref(),
                    &broker,
                    routes,
                    &Pressure::new(),
                    shutdown,
                )
                .await
            }
        });

        while !broker.has("silent") {
            tokio::task::yield_now().await;
        }
        let channel = transport.connect("silent", &broker).expect("dial");
        let (events, stream) = mpsc::channel::<ClientEvent>(4);
        events
            .send(ClientEvent {
                event: Some(client_event::Event::Hello(GatewayHello {
                    gateway_id: "gw-test".to_owned(),
                    instance: 1,
                })),
            })
            .await
            .expect("the attachment must be accepted");
        let attached = ClientPlaneClient::new(channel)
            .attach(tokio_stream::wrappers::ReceiverStream::new(stream))
            .await
            .expect("attach");

        shutdown.drain();

        // Held for the whole wait, exactly as a gateway that never let go
        // would hold it: dropping either half here would end the stream and
        // test the case that already worked.
        let stopped = tokio::time::timeout(DRAIN_GRACE * 2, serving).await;
        drop(attached);
        drop(events);

        stopped
            .expect("a drained service must stop even while a stream is open")
            .expect("the serving task must not panic")
            .expect("serving must end without an error");
    }
}
