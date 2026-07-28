//! The client plane, implemented once for every service that has one.
//!
//! Nineteen services speak the same contract to the gateway
//! (`proto/control.proto`): a bidirectional stream of client events in and
//! server actions out. Writing that stream plumbing nineteen times would be
//! nineteen chances to get backpressure, fan-out or drain subtly different.
//!
//! So a service implements [`ClientService`] — three async methods over
//! *decoded* events — and [`Plane`] turns that into the gRPC surface. A service
//! that wants to push without being asked (a fan-out, a broadcast) sends into
//! its [`Fanout`], which every attached gateway is subscribed to.
//!
//! # Why a broadcast rather than a per-gateway queue
//!
//! Several gateway pods attach to one service, and a client lives on exactly
//! one of them. A frame addressed at a session the pod does not hold is
//! dropped there. Broadcasting is therefore correct and cheap: the alternative
//! is the service tracking which pod holds which session, which is the routing
//! table the gateway already owns.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use starling_proto_fancy::control::client_plane_server::{ClientPlane, ClientPlaneServer};
use starling_proto_fancy::control::{
    ClientEvent, Opened, ServerAction, client_event, server_action,
};
use tokio::sync::broadcast;
use tokio_stream::{Stream, StreamExt as _};
use tonic::{Request, Response, Status, Streaming};

/// One decoded frame from a client.
#[derive(Debug, Clone)]
pub struct Inbound {
    /// Which connection it arrived on.
    pub conn: u64,
    /// The session, or 0 before the handshake completes.
    pub session: u32,
    /// The wire type from the frame header.
    pub type_id: u16,
    /// The payload, verbatim.
    pub payload: Vec<u8>,
    /// Which gateway holds the connection.
    pub gateway: String,
    /// Which virtual server it belongs to.
    pub scope: u32,
}

/// What a service wants done with a client.
pub type Actions = Vec<ServerAction>;

/// Build a `Send` action addressed at sessions.
#[must_use]
pub fn to_sessions(sessions: Vec<u32>, type_id: u16, payload: Vec<u8>) -> ServerAction {
    ServerAction {
        action: Some(server_action::Action::Send(
            starling_proto_fancy::control::Send {
                conns: Vec::new(),
                sessions,
                r#type: u32::from(type_id),
                payload,
                audio: false,
                except: Vec::new(),
            },
        )),
    }
}

/// Build a `Send` action addressed at one connection, for the handshake.
#[must_use]
pub fn to_conn(conn: u64, type_id: u16, payload: Vec<u8>) -> ServerAction {
    ServerAction {
        action: Some(server_action::Action::Send(
            starling_proto_fancy::control::Send {
                conns: vec![conn],
                sessions: Vec::new(),
                r#type: u32::from(type_id),
                payload,
                audio: false,
                except: Vec::new(),
            },
        )),
    }
}

/// Build a `Send` action for everyone except the speaker.
#[must_use]
pub fn broadcast_except(except: u32, type_id: u16, payload: Vec<u8>) -> ServerAction {
    ServerAction {
        action: Some(server_action::Action::Send(
            starling_proto_fancy::control::Send {
                conns: Vec::new(),
                sessions: Vec::new(),
                r#type: u32::from(type_id),
                payload,
                audio: false,
                except: vec![except],
            },
        )),
    }
}

/// Build a `Disconnect` action.
#[must_use]
pub fn disconnect(conn: u64, reason: &str) -> ServerAction {
    ServerAction {
        action: Some(server_action::Action::Disconnect(
            starling_proto_fancy::control::Disconnect {
                conn,
                reason: reason.to_owned(),
            },
        )),
    }
}

/// A service's push channel toward every attached gateway.
#[derive(Debug, Clone)]
pub struct Fanout {
    tx: broadcast::Sender<ServerAction>,
}

impl Fanout {
    /// A channel holding `capacity` actions before the slowest gateway loses
    /// the oldest.
    ///
    /// Bounded on purpose: an unbounded inbox turns one slow consumer into an
    /// OOM, which is the specific failure Discord hit with Erlang mailboxes
    /// under fan-out (`docs/ARCHITECTURE.md` §5).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Push an action to every attached gateway.
    ///
    /// A push with no gateway attached is dropped, not an error: a service that
    /// starts before the gateway is normal, not broken.
    pub fn push(&self, action: ServerAction) {
        let _ = self.tx.send(action);
    }

    /// Push several.
    pub fn push_all(&self, actions: Actions) {
        for action in actions {
            self.push(action);
        }
    }

    /// Receive everything pushed from now on.
    ///
    /// Public because a service that pushes from somewhere other than a
    /// [`ClientService`] method — voice's packet path is the one that does —
    /// has no returned `Actions` for a test to inspect, and asserting on what
    /// reached the gateway is the only way to test it end to end.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ServerAction> {
        self.tx.subscribe()
    }
}

impl Default for Fanout {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// What a service implements to be reachable by a client.
///
/// Written as `-> impl Future<..> + Send` for the reason given on
/// [`Serve`](crate::serve::Serve): these run inside a spawned task over a
/// generic `S: ClientService`, and a plain `async fn` in a trait cannot promise
/// its future is `Send`. Implementations still write `async fn`.
pub trait ClientService: Send + Sync + 'static {
    /// A new connection was accepted. Nothing is known about it yet beyond its
    /// address and certificate.
    fn opened(&self, _opened: &Opened, _gateway: &str) -> impl Future<Output = Actions> + Send {
        async { Actions::new() }
    }

    /// A frame arrived for one of this service's types.
    fn frame(&self, inbound: Inbound) -> impl Future<Output = Actions> + Send;

    /// A connection went away.
    fn closed(&self, _conn: u64, _reason: &str) -> impl Future<Output = Actions> + Send {
        async { Actions::new() }
    }
}

/// The gRPC adapter: [`ClientService`] in, `ClientPlane` out.
#[derive(Debug)]
pub struct Plane<S> {
    service: Arc<S>,
    fanout: Fanout,
    name: &'static str,
}

impl<S: ClientService> Plane<S> {
    /// Wrap `service`, pushing through `fanout`.
    ///
    /// `name` is what this service is called in the log. It is passed in rather
    /// than derived because [`ClientService`] deliberately knows nothing about
    /// deployment — but a frame log that cannot say *which* of nineteen
    /// services handled the frame is not worth writing.
    #[must_use]
    pub fn new(service: Arc<S>, fanout: Fanout, name: &'static str) -> Self {
        Self {
            service,
            fanout,
            name,
        }
    }

    /// The gRPC server to register in a service's routes.
    #[must_use]
    pub fn into_server(self) -> ClientPlaneServer<Self> {
        ClientPlaneServer::new(self)
    }
}

type ActionStream = Pin<Box<dyn Stream<Item = Result<ServerAction, Status>> + Send>>;

#[tonic::async_trait]
impl<S: ClientService> ClientPlane for Plane<S> {
    type AttachStream = ActionStream;

    async fn attach(
        &self,
        request: Request<Streaming<ClientEvent>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        let service = Arc::clone(&self.service);
        let pushes = self.fanout.subscribe();
        let name = self.name;
        let mut inbound = request.into_inner();

        tracing::info!(service = name, "gateway attached");

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ServerAction, Status>>(256);

        // Two producers into one stream: replies to this gateway's frames, and
        // pushes addressed to whatever sessions it happens to hold.
        let replies = tx.clone();
        drop(tokio::spawn(async move {
            let mut gateway = String::new();
            let mut scope = 0_u32;
            while let Some(event) = inbound.next().await {
                let Ok(event) = event else { break };
                let actions = handle(&service, event, &mut gateway, &mut scope, name).await;
                for action in actions {
                    if replies.send(Ok(action)).await.is_err() {
                        return;
                    }
                }
            }
            // Losing the attachment is how a service stops receiving anything
            // at all, and it is silent from the client's side: frames simply
            // stop being answered.
            tracing::info!(service = name, %gateway, "gateway detached");
        }));

        drop(tokio::spawn(async move {
            let mut pushes = pushes;
            let mut lagged = 0_u64;
            loop {
                match pushes.recv().await {
                    Ok(action) => {
                        if tx.send(Ok(action)).await.is_err() {
                            return;
                        }
                    }
                    // Lagged: this gateway fell behind and lost pushes. It is
                    // counted by the caller's metrics and the stream continues,
                    // because dropping the attachment would cost every session
                    // on that pod rather than the frames it already missed.
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        // Warned rather than left to the metric alone: this is
                        // the shape of "some users did not see a message" and
                        // it is otherwise indistinguishable from a bug.
                        lagged += missed;
                        tracing::warn!(
                            service = name,
                            missed,
                            total = lagged,
                            "gateway fell behind; pushes were lost"
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }));

        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

/// One event from a gateway, dispatched to the service and logged.
///
/// Every client frame for every service passes through here, which makes it the
/// one place per-service traffic can be made visible without nineteen services
/// each remembering to do it. It is `debug`/`trace` rather than `info` on
/// purpose: this is per-frame and would drown an operator, so the audience is a
/// developer who has turned `RUST_LOG` up while reproducing something.
async fn handle<S: ClientService>(
    service: &Arc<S>,
    event: ClientEvent,
    gateway: &mut String,
    scope: &mut u32,
    name: &'static str,
) -> Actions {
    match event.event {
        Some(client_event::Event::Hello(hello)) => {
            tracing::debug!(
                service = name,
                gateway = %hello.gateway_id,
                scope = hello.virtual_server,
                "hello"
            );
            *gateway = hello.gateway_id;
            *scope = hello.virtual_server;
            Actions::new()
        }
        Some(client_event::Event::Opened(opened)) => {
            tracing::debug!(
                service = name,
                conn = opened.conn,
                peer = %opened.peer_addr,
                "connection opened"
            );
            let actions = service.opened(&opened, gateway).await;
            trace_actions(name, opened.conn, 0, &actions);
            actions
        }
        Some(client_event::Event::Frame(frame)) => {
            let (conn, session, type_id, len) = (
                frame.conn,
                frame.session,
                frame.r#type as u16,
                frame.payload.len(),
            );
            tracing::trace!(service = name, conn, session, type_id, len, "frame");
            let actions = service
                .frame(Inbound {
                    conn,
                    session,
                    type_id,
                    payload: frame.payload,
                    gateway: gateway.clone(),
                    scope: *scope,
                })
                .await;
            trace_actions(name, conn, session, &actions);
            actions
        }
        Some(client_event::Event::Closed(closed)) => {
            tracing::debug!(
                service = name,
                conn = closed.conn,
                reason = %closed.reason,
                "connection closed"
            );
            let actions = service.closed(closed.conn, &closed.reason).await;
            trace_actions(name, closed.conn, 0, &actions);
            actions
        }
        None => {
            // An event with nothing in it means the two sides disagree about
            // the protobuf, which is a deployment skew rather than bad input.
            tracing::warn!(service = name, "empty client event");
            Actions::new()
        }
    }
}

/// Record what a service decided to do, when the developer asked for detail.
///
/// The reply is the half that is missing when a client "did not get" something:
/// the inbound frame is visible on the wire, the decision is not.
fn trace_actions(name: &'static str, conn: u64, session: u32, actions: &[ServerAction]) {
    if actions.is_empty() || !tracing::enabled!(tracing::Level::TRACE) {
        return;
    }
    for action in actions {
        match &action.action {
            Some(server_action::Action::Send(send)) => tracing::trace!(
                service = name,
                conn,
                session,
                type_id = send.r#type,
                len = send.payload.len(),
                sessions = send.sessions.len(),
                conns = send.conns.len(),
                audio = send.audio,
                "reply"
            ),
            Some(server_action::Action::Disconnect(disconnect)) => tracing::debug!(
                service = name,
                conn = disconnect.conn,
                reason = %disconnect.reason,
                "service asked for a disconnect"
            ),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fan_out_addressed_at_sessions_carries_no_connection_ids() {
        // Sessions are the service's vocabulary; connection ids are the
        // gateway's, and a service that used them would be guessing which pod
        // holds what.
        let action = to_sessions(vec![7, 9], 11, vec![1, 2, 3]);
        let Some(server_action::Action::Send(send)) = action.action else {
            panic!("expected a Send");
        };
        assert_eq!(send.sessions, vec![7, 9]);
        assert!(send.conns.is_empty());
        assert_eq!(send.r#type, 11);
    }

    #[test]
    fn a_handshake_reply_is_addressed_at_the_connection_because_there_is_no_session_yet() {
        let action = to_conn(4, 0, vec![]);
        let Some(server_action::Action::Send(send)) = action.action else {
            panic!("expected a Send");
        };
        assert_eq!(send.conns, vec![4]);
        assert!(send.sessions.is_empty());
    }

    #[test]
    fn a_push_with_nobody_attached_is_dropped_rather_than_failing() {
        // A service starting before any gateway is normal.
        Fanout::new(4).push(disconnect(1, "test"));
    }
}
