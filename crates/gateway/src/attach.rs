//! The gateway's side of the client plane: one attachment per service.
//!
//! Each attachment is a long-lived bidirectional gRPC stream. Frames go out
//! verbatim; actions come back and are applied to the connection registry. The
//! payload is never re-encoded; it is already protobuf, and the gateway has no
//! stubs to decode it with anyway.
//!
//! Reconnection is automatic and quiet: a service pod being replaced is a
//! rolling deploy, not an incident. What is *not* quiet is the breaker, after
//! a threshold of consecutive failures the route sheds at the door rather than
//! making every client wait a full deadline to be told the same thing.

use std::collections::{BTreeMap, HashMap};
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

use crate::connection::Outbound;
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
    /// Stops the dial-and-redial task when this service leaves the table.
    task: Arc<tokio::task::AbortHandle>,
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

/// What one pass of [`Attachments::reconcile`] changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Services newly in the routing table, now attached.
    pub attached: Vec<String>,
    /// Services no longer in it, now detached.
    pub detached: Vec<String>,
    /// Services whose tier changed.
    pub retiered: Vec<String>,
}

impl Reconciled {
    /// Whether the table's service set and tiers were already correct.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attached.is_empty() && self.detached.is_empty() && self.retiered.is_empty()
    }
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
        self.links
            .lock()
            .ok()
            .and_then(|links| links.get(service).cloned())
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

    /// Adopt changed breaker numbers on every attached service.
    ///
    /// The breakers themselves are long-lived and shared with their
    /// attachments, so this retunes rather than replaces: a service that is
    /// currently failing keeps the count that says so.
    pub fn retune_breakers(&self, failures: u32, cooldown_ms: u64) {
        let Ok(links) = self.links.lock() else {
            return;
        };
        // Sorted by name: the order does not affect the outcome, but an
        // unordered iteration makes a log or a trace of a retune differ run to
        // run for no reason.
        let mut names: Vec<_> = links.keys().cloned().collect();
        names.sort_unstable();
        for name in names {
            if let Some(link) = links.get(&name) {
                link.breaker.retune(failures, cooldown_ms);
            }
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
            // Replaced immediately below, once the task exists. A link is only
            // reachable through `self.links`, which is written under the same
            // lock, so nothing can observe this placeholder.
            task: Arc::new(tokio::spawn(std::future::ready(())).abort_handle()),
        };
        if let Ok(mut links) = self.links.lock() {
            let _ = links.insert(service.to_owned(), link);
        }

        let name = service.to_owned();
        let ctx = ctx.clone();
        let task = tokio::spawn(async move {
            run_attachment(name, rx, breaker, ctx).await;
        });
        // The abort handle is what makes a service removable from the routing
        // table at run time: `run_attachment` is an infinite dial-and-redial
        // loop, so nothing else ever ends it.
        if let Ok(mut links) = self.links.lock()
            && let Some(link) = links.get_mut(service)
        {
            link.task = Arc::new(task.abort_handle());
        }
    }

    /// Attach, detach and re-tier so the attachments match `wanted`.
    ///
    /// `wanted` is the service set the routing table now names, with each
    /// service's tier. Called after a reload, so that adding a service to
    /// `[services]` is the three lines the documentation promises and not also
    /// a gateway restart.
    ///
    /// A service that is merely *unhealthy* is untouched: this reconciles the
    /// table against the file, and a breaker doing its job is not a reason to
    /// tear down an attachment and lose the failure count that says so.
    pub fn reconcile(&self, wanted: &BTreeMap<String, Tier>, ctx: &AttachContext) -> Reconciled {
        let mut changed = Reconciled::default();

        let (existing, retier): (Vec<String>, Vec<(String, Tier)>) = {
            let Ok(links) = self.links.lock() else {
                return changed;
            };
            (
                links.keys().cloned().collect(),
                links
                    .iter()
                    .filter_map(|(name, link)| {
                        wanted
                            .get(name)
                            .filter(|tier| **tier != link.tier)
                            .map(|tier| (name.clone(), *tier))
                    })
                    .collect(),
            )
        };

        for name in wanted.keys() {
            if !existing.contains(name) {
                self.spawn(name, wanted[name], ctx);
                changed.attached.push(name.clone());
            }
        }

        for name in &existing {
            if !wanted.contains_key(name) {
                self.detach(name);
                changed.detached.push(name.clone());
            }
        }

        // A tier decides what the gateway does while a service is down, so
        // changing it needs no reconnection -- only the recorded value.
        if let Ok(mut links) = self.links.lock() {
            for (name, tier) in retier {
                if let Some(link) = links.get_mut(&name) {
                    link.tier = tier;
                    changed.retiered.push(name);
                }
            }
        }

        changed.attached.sort_unstable();
        changed.detached.sort_unstable();
        changed.retiered.sort_unstable();
        changed
    }

    /// Stop attaching to `service` and forget it.
    fn detach(&self, service: &str) {
        let Ok(mut links) = self.links.lock() else {
            return;
        };
        if let Some(link) = links.remove(service) {
            // Aborting rather than letting it drain: the loop is infinite and
            // its only other exit is the event channel closing, which happens
            // when this link is dropped -- a race the abort settles at once.
            link.task.abort();
        }
    }

    /// Detach from everything, on the way out. Returns how many were attached.
    ///
    /// An attachment is an open `attach` stream, and a service's graceful
    /// shutdown waits for exactly those streams to end before it stops serving.
    /// Nothing else ends them: the dial-and-redial loop is infinite by design,
    /// and dropping the gateway drops an `AbortHandle`, which is not an abort.
    /// So the drain has to say so. Without it every routed service waits for a
    /// stream held open by a gateway that has already stopped, and the process
    /// leaves on `SIGKILL` rather than on the signal it was sent.
    pub fn detach_all(&self) -> usize {
        let Ok(mut links) = self.links.lock() else {
            return 0;
        };
        // By name, as `retune_breakers` is: the order changes nothing, and an
        // unordered one makes a log of the drain differ run to run.
        let mut names: Vec<String> = links.keys().cloned().collect();
        names.sort_unstable();
        let detached = names.len();
        for name in names {
            if let Some(link) = links.remove(&name) {
                link.task.abort();
            }
        }
        detached
    }
}

/// What an attachment needs from the gateway.
#[derive(Debug, Clone)]
pub struct AttachContext {
    /// This gateway's identity, so a service can address the pod holding a
    /// session.
    pub gateway_id: String,
    /// Which server instance this gateway fronts.
    pub instance: u32,
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
    /// How long one call may take before it counts as a failure.
    ///
    /// `gateway.default_deadline`. It bounds *opening* the attachment, not the
    /// attachment: see [`run_attachment`].
    pub default_deadline: std::time::Duration,
}

/// Dial `service`, then pump it until the stream ends, forever.
///
/// `gateway.default_deadline` bounds the dial and nothing else. The call it
/// applies to is `attach` itself: a tonic `Channel` connects lazily, so the TCP
/// connect, the TLS handshake and the response headers all happen inside that
/// await, and a service that accepts the connection and then answers nothing
/// leaves it hanging with no timer under it. That is the failure this bounds:
/// the loop below never retries, the breaker never counts a failure, and the
/// route is dead while every gate says it is fine.
///
/// It deliberately does not become a `grpc-timeout` on the request. The
/// attachment is a long-lived bidirectional stream, and a per-call deadline on
/// the wire would cancel it five seconds in, every five seconds, on a service
/// that is working perfectly.
async fn run_attachment(
    service: String,
    mut events: mpsc::Receiver<ClientEvent>,
    breaker: Breaker,
    ctx: AttachContext,
) {
    loop {
        let channel = match ctx.resolver.channel(&service) {
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
                instance: ctx.instance,
            })),
        };
        if relay.send(hello).await.is_err() {
            continue;
        }

        // Raised off tonic's 4 MiB default, which is the same ceiling the
        // per-connection control lane already enforces: a single `ServerAction`
        // carrying one channel's artwork can exceed it, and the default caps the
        // *decode* here rather than the send, so the whole attachment dies with
        // "decoded message length too large" and every client on this gateway
        // loses the service. `session-lifecycle` raises the same limit for its
        // `get_tree` read (`handshake.rs`); this is the matching hop.
        let mut client = ClientPlaneClient::new(channel)
            .max_decoding_message_size(ctx.resolver.max_tree_message());
        let outbound = tokio_stream::wrappers::ReceiverStream::new(stream);
        let response =
            match tokio::time::timeout(ctx.default_deadline, client.attach(outbound)).await {
                Ok(Ok(response)) => response,
                Ok(Err(status)) => {
                    tracing::warn!(service = %service, %status, "attach failed; retrying");
                    breaker.failed(now_ms());
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                // Distinguished from a refusal in the log because they mean
                // opposite things: a service that answers with a status is running
                // and said no, and one that never answers is the outage.
                Err(_) => {
                    tracing::warn!(
                        service = %service,
                        deadline = ?ctx.default_deadline,
                        "attach did not answer within the deadline; retrying"
                    );
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
                tracing::info!(
                    conn = handle.conn,
                    session = handle.session(),
                    reason = %disconnect.reason,
                    "service asked for a disconnect"
                );
                // Close the socket rather than only forgetting the entry. This
                // used to be a bare `registry.remove`, which left the client
                // connected and still sending, and, because `finish` never
                // ran, never told any service the session had ended, so a
                // kicked or banned user went on being rendered by everyone
                // else. The close makes the read loop break, and the ordinary
                // disconnect path does the removal and the broadcast.
                handle.close();
                ctx.metrics
                    .counter("starling_gateway_service_disconnects")
                    .inc();
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
        Some(server_action::Action::Sequence(sequence)) => {
            if let Some(handle) = ctx.registry.by_conn(sequence.conn) {
                handle.set_sequenced(sequence.enabled);
                handle.set_compresses(sequence.compress);
            }
        }
        Some(server_action::Action::Replay(replay)) => replay_to(replay, ctx),
        Some(server_action::Action::Throttle(_)) | None => {}
    }
}

/// Re-send what one connection missed.
///
/// The frames go out through the same queue as anything else, so the ordinary
/// backpressure applies: a client that asks to resume and then stops reading is
/// disconnected for control overflow exactly as it would be otherwise. They are
/// **not** re-stamped, a replayed frame keeps the sequence it was written
/// under, which is what lets a client that disconnects again mid-replay resume
/// from the right place rather than from a number that has since moved.
fn replay_to(replay: &starling_proto_fancy::control::Replay, ctx: &AttachContext) {
    let Some(handle) = ctx.registry.by_conn(replay.conn) else {
        return;
    };
    let frames = match ctx.resume.resume(&handle.token, replay.from_seq) {
        crate::resume::ResumeOutcome::Replay(frames) => frames,
        // Nothing is sent, and nothing needs to be said. The client learns of
        // the gap from the sequence numbers themselves: the next frame it
        // receives carries a number well past the one it asked from, and a jump
        // means re-sync. That covers every cause of a gap rather than just this
        // one, and it keeps the gateway from having to encode a service's
        // message to explain itself, which is the coupling §1 exists to avoid.
        outcome => {
            tracing::debug!(
                conn = replay.conn,
                from = replay.from_seq,
                ?outcome,
                "cannot replay; the client will see the gap and re-sync"
            );
            return;
        }
    };
    tracing::debug!(
        conn = replay.conn,
        from = replay.from_seq,
        frames = frames.len(),
        "replaying"
    );
    for frame in frames {
        let prefix =
            starling_proto::codec::header(frame.type_id, frame.payload.len(), Some(frame.seq));
        let queued = handle.send(
            Lane::Control,
            Outbound {
                prefix,
                payload: frame.payload,
            },
        );
        if queued.is_err() {
            // Same overflow, on the resume path: close and say so rather than
            // silently unregister and leave the client hanging.
            ctx.metrics
                .counter("starling_gateway_control_overflow_disconnects")
                .inc();
            tracing::warn!(
                conn = handle.conn,
                session = handle.session(),
                "control lane overflowed during replay; disconnecting the client"
            );
            handle.close();
            ctx.registry.remove(handle.conn);
            return;
        }
    }
}

/// Write one `Send` to every addressed client this gateway holds.
fn deliver(send: &starling_proto_fancy::control::Send, ctx: &AttachContext) {
    let type_id = send.r#type as u16;
    let lane = if send.audio {
        Lane::Audio
    } else {
        Lane::Control
    };

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

    // Encoded once and shared by every recipient. This is murmur's
    // `QByteArray &cache` parameter, made structural, and it is why the
    // header is built separately below rather than concatenated here: the
    // sequence number in it differs per connection, and joining them would
    // copy the payload once per client to carry eight bytes of difference.
    let payload = bytes::Bytes::copy_from_slice(&send.payload);
    // The one header every peer that is *not* sequenced shares.
    let plain = starling_proto::codec::header(type_id, payload.len(), None);

    for handle in targets {
        if send.except.contains(&handle.session()) {
            continue;
        }
        // Stamped for everybody, because the ring is what a resume replays
        // from and a peer may negotiate resume after frames have already gone
        // out. Only a peer that asked is *told* its number.
        let seq = ctx.resume.stamp(&handle.token, type_id, &payload);
        let prefix = if handle.sequenced() {
            starling_proto::codec::header(type_id, payload.len(), Some(seq))
        } else {
            plain.clone()
        };
        let frame = Outbound {
            prefix,
            payload: payload.clone(),
        };
        if handle.send(lane, frame).is_err() {
            // Control overflow: bounded and honest. This used to remove the
            // registry entry and stop, which never closed the socket — the
            // client sat half-connected with a truncated handshake (an empty
            // channel tree, no `ServerSync`, no users) until it gave up on its
            // own tens of seconds later, and nothing was logged, only a counter.
            // Close the socket so the client learns at once, and warn so an
            // operator can see it: the send outgrew this client's byte budget.
            ctx.metrics
                .counter("starling_gateway_control_overflow_disconnects")
                .inc();
            tracing::warn!(
                conn = handle.conn,
                session = handle.session(),
                "control lane overflowed mid-send; disconnecting the client \
                 (its outbound queue exceeded the byte budget)"
            );
            handle.close();
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

    fn ctx() -> AttachContext {
        let config = Arc::new(starling_runtime::config::Config::with_defaults(
            std::path::Path::new("/run/starling"),
        ));
        AttachContext {
            gateway_id: "gw-test".to_owned(),
            instance: 1,
            resolver: Resolver::new(config, starling_runtime::inproc::Broker::new()),
            registry: Registry::new(),
            resume: ResumeStore::new(16),
            metrics: Metrics::new(),
            breaker_failures: 5,
            breaker_cooldown_ms: 10_000,
            default_deadline: std::time::Duration::from_secs(5),
        }
    }

    fn wanted(services: &[(&str, Tier)]) -> BTreeMap<String, Tier> {
        services
            .iter()
            .map(|(name, tier)| ((*name).to_owned(), *tier))
            .collect()
    }

    #[tokio::test]
    async fn a_service_added_to_the_table_is_attached_without_a_restart() {
        // "Three lines, no gateway release" (`docs/CONFIGURATION.md`), and now
        // no gateway restart either.
        let attachments = Attachments::new();
        let ctx = ctx();

        let first = attachments.reconcile(&wanted(&[("text", Tier::Core)]), &ctx);
        assert_eq!(first.attached, vec!["text".to_owned()]);
        assert!(attachments.get("text").is_some());

        let second = attachments.reconcile(
            &wanted(&[("text", Tier::Core), ("pchat", Tier::Core)]),
            &ctx,
        );
        assert_eq!(second.attached, vec!["pchat".to_owned()]);
        assert!(second.detached.is_empty(), "text must not be disturbed");
        assert!(attachments.get("pchat").is_some());
    }

    #[tokio::test]
    async fn a_service_removed_from_the_table_is_detached() {
        let attachments = Attachments::new();
        let ctx = ctx();
        let _ = attachments.reconcile(
            &wanted(&[("text", Tier::Core), ("pchat", Tier::Core)]),
            &ctx,
        );

        let changed = attachments.reconcile(&wanted(&[("text", Tier::Core)]), &ctx);
        assert_eq!(changed.detached, vec!["pchat".to_owned()]);
        assert!(attachments.get("pchat").is_none());
        assert!(attachments.get("text").is_some(), "text must survive");
    }

    #[tokio::test]
    async fn a_drain_detaches_from_everything() {
        // Each of these is a stream held open on a service that is draining
        // too, and a service finishes draining only once the streams into it
        // have ended. A gateway that stopped without letting go held every one
        // of them past the signal, and the process left on SIGKILL.
        let attachments = Attachments::new();
        let ctx = ctx();
        let _ = attachments.reconcile(
            &wanted(&[("text", Tier::Core), ("pchat", Tier::Core)]),
            &ctx,
        );

        assert_eq!(attachments.detach_all(), 2);
        assert!(attachments.get("text").is_none());
        assert!(attachments.get("pchat").is_none());
        assert_eq!(attachments.detach_all(), 0, "a second drain finds nothing");
    }

    #[tokio::test]
    async fn an_unchanged_table_reattaches_nothing() {
        // Re-attaching on every reload would drop each service's stream and
        // cost every one of them a reconnect for a file that did not move.
        let attachments = Attachments::new();
        let ctx = ctx();
        let table = wanted(&[("text", Tier::Core), ("voice", Tier::Core)]);
        let _ = attachments.reconcile(&table, &ctx);

        let changed = attachments.reconcile(&table, &ctx);
        assert!(changed.is_empty(), "{changed:?}");
    }

    #[tokio::test]
    async fn a_changed_tier_is_recorded_without_reconnecting() {
        // A tier says what the gateway does while a service is down; changing
        // it is a decision about shedding, not a reason to drop the stream.
        let attachments = Attachments::new();
        let ctx = ctx();
        let _ = attachments.reconcile(&wanted(&[("text", Tier::Core)]), &ctx);

        let changed = attachments.reconcile(&wanted(&[("text", Tier::Essential)]), &ctx);
        assert_eq!(changed.retiered, vec!["text".to_owned()]);
        assert!(changed.attached.is_empty() && changed.detached.is_empty());
        assert_eq!(
            attachments.get("text").expect("still attached").tier,
            Tier::Essential
        );
    }

    #[tokio::test]
    async fn an_unhealthy_service_is_left_alone_by_a_reload() {
        // Reconciling is about the file, not about health: tearing down an
        // attachment whose breaker has tripped would lose the failure count
        // that is the only record the service is in trouble.
        let attachments = Attachments::new();
        let ctx = ctx();
        let table = wanted(&[("text", Tier::Core)]);
        let _ = attachments.reconcile(&table, &ctx);

        let link = attachments.get("text").expect("attached");
        for _ in 0..10 {
            link.breaker.failed(now_ms());
        }
        assert!(!link.healthy(), "the breaker must be open for this test");

        let changed = attachments.reconcile(&table, &ctx);
        assert!(changed.is_empty(), "{changed:?}");
        assert!(
            !attachments.get("text").expect("still attached").healthy(),
            "the failure count must survive the reload"
        );
    }

    #[tokio::test]
    async fn a_service_that_accepts_and_never_answers_hits_the_deadline() {
        // The failure this covers is the quiet one: the dial parks forever, so
        // the redial loop never comes round, the breaker counts nothing, and
        // the route is dead while every gate on the gateway says it is fine.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("a bound address");
        // Accepted and then ignored: no HTTP/2 settings, no headers, ever. The
        // sockets are held rather than dropped, because closing one would give
        // tonic an error to report and this test is about silence.
        drop(tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        }));

        let mut config =
            starling_runtime::config::Config::with_defaults(std::path::Path::new("/run/starling"));
        config
            .services
            .get_mut("text")
            .expect("text is a configured service")
            .endpoint = Some(format!("http://{address}"));

        let mut ctx = ctx();
        ctx.resolver = Resolver::new(Arc::new(config), starling_runtime::inproc::Broker::new());
        ctx.default_deadline = std::time::Duration::from_millis(200);
        // One failure is enough, and the cooldown outlasts the test: this is
        // asserting that a failure was counted at all.
        ctx.breaker_failures = 1;
        ctx.breaker_cooldown_ms = 60_000;

        let attachments = Attachments::new();
        let _ = attachments.reconcile(&wanted(&[("text", Tier::Core)]), &ctx);
        let link = attachments.get("text").expect("attached");

        // Generously more than the deadline, and still far less than the
        // forever this used to take.
        for _ in 0..100 {
            if !link.healthy() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the dial never gave up: no deadline is being applied");
    }
}
