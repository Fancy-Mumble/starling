//! The gateway's side of the client plane: one attachment per service.
//!
//! Each attachment is a long-lived bidirectional gRPC stream. Frames go out
//! verbatim; actions come back and are applied to the connection registry. The
//! payload is never re-encoded — it is already protobuf, and the gateway has no
//! stubs to decode it with anyway.
//!
//! Reconnection is automatic and quiet: a service pod being replaced is a
//! rolling deploy, not an incident. What is *not* quiet is the breaker — after
//! a threshold of consecutive failures the route sheds at the door rather than
//! making every client wait a full deadline to be told the same thing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto_fancy::control::client_plane_client::ClientPlaneClient;
use starling_proto_fancy::control::{
    ClientEvent, Closed, GatewayHello, Opened, ServerAction, client_event, server_action,
};
use starling_runtime::breaker::Breaker;
use starling_runtime::channel::Resolver;
use starling_runtime::ids::now_ms;
use starling_runtime::metrics::Metrics;
use starling_runtime::tier::Tier;
use tokio::sync::mpsc;

use crate::connection::{Lane, Registry};
use crate::resume::ResumeStore;

/// One service's attachment.
#[derive(Debug, Clone)]
pub struct ServiceLink {
    /// The service's name.
    pub name: String,
    /// Its tier, which decides what happens while it is unhealthy.
    pub tier: Tier,
    events: mpsc::Sender<ClientEvent>,
    breaker: Breaker,
}

impl ServiceLink {
    /// Whether this service is currently taking traffic.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.breaker.allows(now_ms())
    }

    /// Forward one client event.
    ///
    /// A full attachment queue counts as a failure: it means the service is not
    /// draining, and the breaker exists to notice exactly that.
    pub fn forward(&self, event: ClientEvent) -> bool {
        match self.events.try_send(event) {
            Ok(()) => true,
            Err(_) => {
                self.breaker.failed(now_ms());
                false
            }
        }
    }
}

/// Every service the routing table names.
#[derive(Debug, Clone, Default)]
pub struct Attachments {
    links: Arc<Mutex<HashMap<String, ServiceLink>>>,
}

impl Attachments {
    /// Nothing attached yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The link for `service`, if it has been attached.
    #[must_use]
    pub fn get(&self, service: &str) -> Option<ServiceLink> {
        self.links.lock().ok().and_then(|links| links.get(service).cloned())
    }

    /// Announce a new connection to every service, so a service that cares
    /// about pre-authentication state (moderation's ban check, session's
    /// handshake) sees it.
    pub fn broadcast_opened(&self, opened: &Opened) {
        self.broadcast(&ClientEvent {
            event: Some(client_event::Event::Opened(opened.clone())),
        });
    }

    /// Announce a closed connection to every service.
    pub fn broadcast_closed(&self, conn: u64, reason: &str) {
        self.broadcast(&ClientEvent {
            event: Some(client_event::Event::Closed(Closed {
                conn,
                reason: reason.to_owned(),
            })),
        });
    }

    fn broadcast(&self, event: &ClientEvent) {
        let links: Vec<ServiceLink> = self
            .links
            .lock()
            .map(|links| links.values().cloned().collect())
            .unwrap_or_default();
        for link in links {
            let _ = link.forward(event.clone());
        }
    }

    /// Attach to `service` and keep the stream alive until shutdown.
    ///
    /// Spawns two tasks: one dialling and re-dialling, one applying the actions
    /// that come back.
    pub fn spawn(&self, service: &str, tier: Tier, ctx: &AttachContext) {
        let (tx, rx) = mpsc::channel::<ClientEvent>(1024);
        let breaker = Breaker::new(ctx.breaker_failures, ctx.breaker_cooldown_ms);
        let link = ServiceLink {
            name: service.to_owned(),
            tier,
            events: tx,
            breaker: breaker.clone(),
        };
        if let Ok(mut links) = self.links.lock() {
            let _ = links.insert(service.to_owned(), link);
        }

        let service = service.to_owned();
        let ctx = ctx.clone();
        drop(tokio::spawn(async move {
            run_attachment(service, rx, breaker, ctx).await;
        }));
    }
}

/// What an attachment needs from the gateway.
#[derive(Debug, Clone)]
pub struct AttachContext {
    /// This gateway's identity, so a service can address the pod holding a
    /// session.
    pub gateway_id: String,
    /// Which virtual server this gateway fronts.
    pub virtual_server: u32,
    /// How to reach services.
    pub resolver: Resolver,
    /// Who is connected.
    pub registry: Registry,
    /// Where outbound frames are stamped.
    pub resume: ResumeStore,
    /// Counters.
    pub metrics: Metrics,
    /// Consecutive failures before the breaker trips.
    pub breaker_failures: u32,
    /// How long a tripped breaker sheds.
    pub breaker_cooldown_ms: u64,
}

async fn run_attachment(
    service: String,
    mut events: mpsc::Receiver<ClientEvent>,
    breaker: Breaker,
    ctx: AttachContext,
) {
    loop {
        let channel = match ctx.resolver.channel(&service).await {
            Ok(channel) => channel,
            Err(error) => {
                tracing::warn!(service = %service, %error, "cannot resolve service; retrying");
                breaker.failed(now_ms());
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        let (relay, stream) = mpsc::channel::<ClientEvent>(1024);
        let hello = ClientEvent {
            event: Some(client_event::Event::Hello(GatewayHello {
                gateway_id: ctx.gateway_id.clone(),
                virtual_server: ctx.virtual_server,
            })),
        };
        if relay.send(hello).await.is_err() {
            continue;
        }

        let mut client = ClientPlaneClient::new(channel);
        let outbound = tokio_stream::wrappers::ReceiverStream::new(stream);
        let response = match client.attach(outbound).await {
            Ok(response) => response,
            Err(status) => {
                tracing::warn!(service = %service, %status, "attach failed; retrying");
                breaker.failed(now_ms());
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        breaker.succeeded();
        tracing::info!(service = %service, "attached");

        let mut actions = response.into_inner();
        loop {
            tokio::select! {
                event = events.recv() => {
                    let Some(event) = event else { return };
                    if relay.send(event).await.is_err() {
                        break;
                    }
                }
                action = actions.message() => {
                    match action {
                        Ok(Some(action)) => apply(&action, &ctx),
                        Ok(None) => break,
                        Err(status) => {
                            tracing::warn!(service = %service, %status, "attachment ended");
                            breaker.failed(now_ms());
                            break;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Apply one action from a service to the clients this gateway holds.
fn apply(action: &ServerAction, ctx: &AttachContext) {
    match &action.action {
        Some(server_action::Action::Send(send)) => deliver(send, ctx),
        Some(server_action::Action::Disconnect(disconnect)) => {
            if let Some(handle) = ctx.registry.by_conn(disconnect.conn) {
                tracing::debug!(conn = handle.conn, reason = %disconnect.reason, "service asked for a disconnect");
                ctx.registry.remove(handle.conn);
                ctx.metrics.counter("starling_gateway_service_disconnects").inc();
            }
        }
        Some(server_action::Action::SessionUp(up)) => {
            ctx.registry.bind_session(up.session, up.conn);
            if let Some(handle) = ctx.registry.by_conn(up.conn) {
                handle.set_fancy(up.fancy_version);
            }
        }
        Some(server_action::Action::SessionDown(down)) => {
            ctx.registry.remove(down.conn);
        }
        Some(server_action::Action::Throttle(_)) | None => {}
    }
}

/// Write one `Send` to every addressed client this gateway holds.
fn deliver(send: &starling_proto_fancy::control::Send, ctx: &AttachContext) {
    let type_id = send.r#type as u16;
    let lane = if send.audio { Lane::Audio } else { Lane::Control };

    let targets = if !send.conns.is_empty() {
        send.conns
            .iter()
            .filter_map(|conn| ctx.registry.by_conn(*conn))
            .collect()
    } else if !send.sessions.is_empty() {
        send.sessions
            .iter()
            .filter_map(|session| ctx.registry.by_session(*session))
            .collect()
    } else {
        ctx.registry.authenticated()
    };

    // Encode once, clone the handle per recipient. This is murmur's
    // `QByteArray &cache` parameter, made structural.
    let frame = starling_proto::codec::frame(type_id, &send.payload);

    for handle in targets {
        if send.except.contains(&handle.session()) {
            continue;
        }
        let _ = ctx.resume.stamp(&handle.token, type_id, &send.payload);
        if handle.send(lane, frame.clone()).is_err() {
            // Control overflow: bounded and honest. Reconnect re-syncs from
            // scratch, and the client is told by the socket closing rather than
            // by a silent hole in its world.
            ctx.metrics
                .counter("starling_gateway_control_overflow_disconnects")
                .inc();
            ctx.registry.remove(handle.conn);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unattached_service_is_absent_rather_than_a_panic() {
        // Services start in any order; a gateway that came up first must not
        // fall over on the first frame.
        assert!(Attachments::new().get("text").is_none());
    }
}
