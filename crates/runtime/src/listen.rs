//! Serving a service's gRPC routes over whichever transport it was given.
//!
//! One function, every transport, and the service never learns which, the
//! same asymmetry [`crate::channel`] provides on the calling side. Which
//! transport it is lives behind [`Transport::bind`]; what is left here is the
//! part that is identical for all of them, including that every one stops
//! accepting on drain and finishes what it is holding, because Kubernetes
//! sends `SIGTERM` and then `SIGKILL` thirty seconds later whatever the
//! process thinks about it.

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::task::JoinSet;
use tokio_stream::StreamExt as _;
use tonic::service::Routes;
use tower::Layer as _;

use crate::inflight::{InFlight, InFlightLayer};
use crate::inproc::Broker;
use crate::pressure::Pressure;
use crate::shutdown::Shutdown;
use crate::transport::{BoxedIo, LocalStream, Transport};

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
/// Graceful shutdown stops accepting and then waits for every open connection
/// to close, which is right for the requests in flight and wrong for a
/// subscription: a `watch` or an `attach` stream ends when its *client* decides
/// to end it, and the clients here are the peer services draining alongside
/// this one. Whoever waits last waits forever, and the process leaves on
/// `SIGKILL` with no records of why.
///
/// So the wait is bounded. This is long enough for any request-reply exchange
/// -- they are milliseconds, in-process ones are microseconds -- and short
/// enough to be well inside the grace period an init system allows before it
/// stops asking.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// The service every connection is served with: [`InFlight`] over the routes.
type Served = InFlight<Routes>;

/// Serve `routes` over `transport` until `shutdown` drains.
///
/// # A hand-rolled accept loop, and why
///
/// This was `tonic::transport::Server::serve_with_incoming_shutdown`, which is
/// four lines instead of forty and wrong in one way that matters: it serves
/// each connection from a bare `tokio::spawn` and drops the handle
/// (`tonic-0.14/src/transport/server/mod.rs:925`). Nothing can then stop those
/// tasks. Its graceful shutdown asks them to finish and waits, and the outer
/// timeout below only ever abandoned *the wait* -- the connections carried on,
/// holding the `Routes`, and so an `Arc` to the service, for the life of the
/// process.
///
/// That is invisible while the whole process drains together, which is the only
/// thing that ever happened here. It stops being invisible the moment one
/// service is restarted on its own: the replacement `voice` could not bind its
/// UDP port, because the instance that had drained was still holding it through
/// a gateway connection that had no reason to close. Defect 23 in
/// `docs/RELIABILITY.md`.
///
/// So the connections are ours. A [`JoinSet`] is the whole of the difference:
/// each one still shuts down gracefully when the drain starts, and if they are
/// not all finished by the three-second `DRAIN_GRACE` they are aborted rather
/// than merely stopped being waited for.
///
/// # Errors
///
/// [`ListenError`] if the transport cannot be bound.
pub async fn serve_routes(
    name: &str,
    transport: &dyn Transport,
    broker: &Broker,
    routes: Routes,
    pressure: &Pressure,
    shutdown: Shutdown,
) -> Result<(), ListenError> {
    tracing::info!(service = name, endpoint = %transport.describe(), "serving");
    let mut incoming = transport.bind(broker).await?;

    // Wraps every RPC this service serves, including the health surface
    // itself. That is intentional: the collector's own call is a request
    // like any other, and a gauge that excluded it would under-report a
    // service by exactly the traffic the dashboard generates.
    //
    // `prepare` is axum's own advice for a router about to be served; it was
    // what `Server` did on the way in.
    let service = InFlightLayer::new(pressure).layer(routes.prepare());

    // HTTP/2 only, which is what `Server` did unless asked for otherwise
    // (`accept_http1` defaults to false). Every caller of a service is a tonic
    // client, so accepting HTTP/1 here would only widen the surface.
    let builder = auto::Builder::new(TokioExecutor::new()).http2_only();

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.wait() => break,
            accepted = incoming.next() => match accepted {
                Some(Ok(io)) => {
                    let _ = connections.spawn(connection(
                        io,
                        service.clone(),
                        builder.clone(),
                        shutdown.clone(),
                    ));
                }
                // One connection that could not be accepted is not this
                // service's problem to report; the peer will see it.
                Some(Err(error)) => {
                    tracing::trace!(service = name, %error, "accepting a connection");
                }
                None => break,
            },
            // Reaped as they finish. Without this the set is every connection
            // the service has ever served, and a long-lived one would look
            // exactly like the leak this function exists to have fixed.
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                reap(name, joined);
            }
        }
    }

    // Every connection is already shutting down gracefully by now: each one
    // watches the same drain this loop does, so the GOAWAY went out when it was
    // raised rather than when we got here.
    let finished = async {
        while let Some(joined) = connections.join_next().await {
            reap(name, joined);
        }
    };
    if tokio::time::timeout(DRAIN_GRACE, finished).await.is_err() {
        // Named, and at warning: a service that has to be cut off is holding a
        // stream somebody forgot to end on drain, and the name is the whole of
        // the answer to which one.
        tracing::warn!(
            service = name,
            grace = ?DRAIN_GRACE,
            held = connections.len(),
            "still holding connections after the drain; closing them"
        );
        connections.shutdown().await;
    }

    tracing::info!(service = name, "drained");
    Ok(())
}

/// Report a connection task that panicked, and say nothing about one that did not.
///
/// Owning the tasks means owning their `JoinError`s, and the whole of Stage 0 is
/// that a swallowed one is how a fault becomes an unrelated timeout somewhere
/// else. In a release build `panic = "abort"` means this line never prints,
/// because the process is already gone; under test it names the connection that
/// took a service down.
fn reap(name: &str, joined: Result<(), tokio::task::JoinError>) {
    if let Err(error) = joined
        && error.is_panic()
    {
        tracing::error!(service = name, %error, "a connection task panicked");
    }
}

/// Serve one connection, gracefully on drain, until it ends.
///
/// The graceful half is the same as tonic's: on the drain a GOAWAY goes out and
/// whatever is in flight is allowed to finish. The difference is that this runs
/// in a task the caller holds, so a stream that never ends can be cut off
/// instead of outliving the service.
async fn connection(
    io: LocalStream<BoxedIo>,
    service: Served,
    builder: auto::Builder<TokioExecutor>,
    shutdown: Shutdown,
) {
    let served = builder.serve_connection(TokioIo::new(io), TowerToHyperService::new(service));
    tokio::pin!(served);

    let outcome = tokio::select! {
        result = &mut served => result,
        () = shutdown.wait() => {
            served.as_mut().graceful_shutdown();
            served.await
        }
    };
    if let Err(error) = outcome {
        // Debug, not warning. A peer that goes away mid-request is ordinary,
        // and this is the line that would otherwise fire once per client on
        // every shutdown.
        tracing::debug!(error = %*error, "serving a connection");
    }
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_drained_service_is_let_go_of_and_not_merely_stopped_waiting_for() {
        // Defect 23. Stopping and being released are different things, and for
        // six months only the first was tested: `serve_with_incoming_shutdown`
        // returned on the drain while the connection tasks it had spawned and
        // detached carried on holding the `Routes`, and so this `Arc`. Nothing
        // noticed until a service was restarted rather than shut down, and the
        // replacement `voice` could not bind the UDP port the released-looking
        // instance was still listening on.
        //
        // The stream is deliberately left open, as a peer service that is not
        // draining would leave it. That is the case where the connection has to
        // be closed rather than waited for.
        let broker = Broker::new();
        let shutdown = Shutdown::new();
        let transport = transport::in_process("held");
        let service = Arc::new(Silent);
        let watch = Arc::downgrade(&service);
        let routes = tonic::service::Routes::default()
            .add_service(Plane::new(service, Fanout::default(), "held").into_server());

        let serving = tokio::spawn({
            let broker = broker.clone();
            let shutdown = shutdown.clone();
            let transport = Arc::clone(&transport);
            async move {
                serve_routes(
                    "held",
                    transport.as_ref(),
                    &broker,
                    routes,
                    &Pressure::new(),
                    shutdown,
                )
                .await
            }
        });

        while !broker.has("held") {
            tokio::task::yield_now().await;
        }
        let channel = transport.connect("held", &broker).expect("dial");
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
        let _attached = ClientPlaneClient::new(channel)
            .attach(tokio_stream::wrappers::ReceiverStream::new(stream))
            .await
            .expect("attach");

        shutdown.drain();
        tokio::time::timeout(DRAIN_GRACE * 2, serving)
            .await
            .expect("a drained service must stop")
            .expect("the serving task must not panic")
            .expect("serving must end without an error");

        // The abort is observed by the connection task, which then has to be
        // scheduled to drop what it holds. Bounded rather than instant, but a
        // second is a thousand times longer than it takes.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        while watch.strong_count() > 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the service is still held after its socket drained: \
                 {} reference(s) outlived it",
                watch.strong_count()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
