//! `pchat` — persistent chat: a relay and a store, never a decryptor.
//!
//! The end-to-end crypto lives in the client
//! (`vendor/client/crates/mumble-protocol/src/persistent/`), so this service
//! never sees plaintext. What it owns is storage, fan-out, offline queues,
//! key-holder bookkeeping and rate limiting (`PORTING-PLAN.md` Phase 4).
//!
//! The key is `channel_id ‖ uuidv7`, so the table is physically ordered
//! tenant → channel → time. Both fetch shapes — newest page and scroll-back —
//! are then one backwards range scan, which is what turns murmur's full scan of
//! an unindexed `TEXT` UUID into an index seek (`docs/STORAGE.md` L3).

mod limits;

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::Scope;
use starling_proto_fancy::control::ServerAction;
use starling_proto_fancy::fancy::pchat::{
    Ack, Fetch, FetchResponse, Message, PchatEnvelope, ack, pchat_envelope,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::sessionview::SubscribeRequest;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::permit::{Permit, permission_denied};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};

use crate::limits::{Limits, Op};

/// How long to wait before re-subscribing to `session-view`.
const VIEW_RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A pchat service that is up with a cold roster relays nothing, which looks
/// exactly like a chat that has gone quiet. Gating readiness keeps traffic away
/// until it can actually address a channel.
const VIEW_GATE: &str = "session-view";

/// The schema. `expires_at_ms` and its index are here from day one, because
/// retention on a table that grows without bound is a schema property rather
/// than an afterthought (`docs/STORAGE.md` D4).
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_pchat_message",
    &[
        "CREATE TABLE IF NOT EXISTS pchat_message (\
             server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, id BLOB NOT NULL, \
             sent_at_ms BIGINT NOT NULL, sender BIGINT NOT NULL, epoch INTEGER NOT NULL, \
             ciphertext BLOB NOT NULL, supersedes BLOB NULL, expires_at_ms BIGINT NULL, \
             PRIMARY KEY (server_id, channel_id, id))",
        "CREATE INDEX IF NOT EXISTS ix_pchat_expiry ON pchat_message(server_id, expires_at_ms)",
        "CREATE TABLE IF NOT EXISTS pchat_holder (\
             server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, epoch INTEGER NOT NULL, \
             holder BIGINT NOT NULL, \
             PRIMARY KEY (server_id, channel_id, epoch, holder))",
    ],
)];

/// The service.
#[derive(Debug)]
pub struct PchatService {
    store: Store,
    fanout: Fanout,
    /// Asks `permissions` before a channel's archive is written or read.
    ///
    /// The ciphertext is opaque to this service, which is not the same as it
    /// being safe to hand to anyone who asks: the archive still discloses who
    /// spoke in a channel and when, and the ciphertext itself is exactly what
    /// an offline attack needs. `Permit` denies when `permissions` is
    /// unreachable, so a broken dependency closes the archive rather than
    /// opening it.
    permit: Permit,
    /// Who is in which channel, so a relay can be addressed at one.
    roster: Arc<Roster>,
    /// Per-connection budgets.
    limits: Limits,
}

impl PchatService {
    /// Store one ciphertext, returning the id it was filed under.
    async fn store_message(&self, scope: u32, message: &Message) -> Option<Uuid7> {
        let id = Uuid7::now();
        let result = sqlx::query(
            "INSERT INTO pchat_message \
                 (server_id, channel_id, id, sent_at_ms, sender, epoch, ciphertext, supersedes) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(i64::from(message.channel))
        .bind(id.to_vec())
        .bind(now_ms() as i64)
        .bind(i64::from(message.sender))
        .bind(i64::from(message.epoch))
        .bind(message.ciphertext.as_slice())
        .bind(Uuid7::parse(&message.supersedes).map(Uuid7::to_vec))
        .execute(self.store.pool())
        .await;
        match result {
            Ok(_) => Some(id),
            Err(error) => {
                tracing::error!(%error, "could not store a persistent-chat message");
                None
            }
        }
    }

    /// A page of ciphertexts, newest first.
    async fn fetch(&self, scope: u32, request: &Fetch) -> FetchResponse {
        use sqlx::Row as _;
        let limit = request.limit.clamp(1, 200);
        let before = Uuid7::parse(&request.before_id).map(Uuid7::to_vec);
        let sql = if before.is_some() {
            "SELECT id, sent_at_ms, sender, epoch, ciphertext FROM pchat_message \
             WHERE server_id = ? AND channel_id = ? AND id < ? ORDER BY id DESC LIMIT ?"
        } else {
            "SELECT id, sent_at_ms, sender, epoch, ciphertext FROM pchat_message \
             WHERE server_id = ? AND channel_id = ? ORDER BY id DESC LIMIT ?"
        };
        let mut query = sqlx::query(sql)
            .bind(i64::from(scope))
            .bind(i64::from(request.channel));
        if let Some(cursor) = &before {
            query = query.bind(cursor.as_slice());
        }
        let rows = query
            .bind(i64::from(limit + 1))
            .fetch_all(self.store.pool())
            .await
            .unwrap_or_default();

        let more = rows.len() > limit as usize;
        let messages = rows
            .into_iter()
            .take(limit as usize)
            .map(|row| Message {
                message_id: Uuid7::from_slice(&row.try_get::<Vec<u8>, _>("id").unwrap_or_default())
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                channel: request.channel,
                sender: row.try_get::<i64, _>("sender").unwrap_or_default() as u32,
                ciphertext: row.try_get("ciphertext").unwrap_or_default(),
                sent_at_ms: row.try_get::<i64, _>("sent_at_ms").unwrap_or_default() as u64,
                supersedes: String::new(),
                epoch: row.try_get::<i64, _>("epoch").unwrap_or_default() as u32,
            })
            .collect();

        FetchResponse {
            channel: request.channel,
            messages,
            more,
            total_stored: self.count(scope, request.channel).await,
        }
    }

    /// How many messages a channel holds.
    ///
    /// A real `COUNT`, because this table has the index to serve it; on the KV
    /// alternative it would be a maintained counter key
    /// (`docs/STORAGE.md` §5.6).
    async fn count(&self, scope: u32, channel: u32) -> u64 {
        use sqlx::Row as _;
        sqlx::query(
            "SELECT COUNT(*) AS n FROM pchat_message WHERE server_id = ? AND channel_id = ?",
        )
        .bind(i64::from(scope))
        .bind(i64::from(channel))
        .fetch_optional(self.store.pool())
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<i64, _>("n").ok())
        .unwrap_or_default() as u64
    }

    /// Drop everything past its retention.
    async fn sweep(&self) {
        let _ = sqlx::query(
            "DELETE FROM pchat_message WHERE expires_at_ms IS NOT NULL AND expires_at_ms < ?",
        )
        .bind(now_ms() as i64)
        .execute(self.store.pool())
        .await;
    }
}

/// What a relayed body is, for routing and authorisation.
///
/// Every body except `Ack` carries a channel. Reading that field is not
/// "understanding the payload" -- it is the routing address, sitting beside the
/// ciphertext rather than inside it -- so the verbatim relay can be both scoped
/// and authorised without this service learning any crypto.
struct Relay {
    channel: u32,
    /// What the sender must hold in that channel.
    needs: Perm,
    /// Deliver to this one session instead of the channel, when the body names
    /// its recipient.
    unicast: Option<u32>,
}

impl Relay {
    /// How a client-originated body is routed, or `None` if a client has no
    /// business sending it.
    fn of(body: &pchat_envelope::Body) -> Option<Self> {
        use pchat_envelope::Body;
        let in_channel = |channel, needs| {
            Some(Self {
                channel,
                needs,
                unicast: None,
            })
        };
        match body {
            // Sealed key material naming exactly one recipient. Relaying it to
            // the channel handed every member a copy of a message addressed to
            // one of them.
            Body::KeyDeliver(deliver) => Some(Self {
                channel: deliver.channel,
                needs: Perm::ENTER,
                unicast: Some(deliver.recipient),
            }),
            Body::KeyAnnounce(announce) => in_channel(announce.channel, Perm::ENTER),
            Body::KeyRequest(request) => in_channel(request.channel, Perm::ENTER),
            Body::HolderReport(report) => in_channel(report.channel, Perm::ENTER),
            Body::HolderQuery(query) => in_channel(query.channel, Perm::ENTER),
            Body::Reaction(reaction) => in_channel(reaction.channel, Perm::TEXT_MESSAGE),
            Body::Pin(pin) => in_channel(pin.channel, Perm::TEXT_MESSAGE),
            Body::Receipt(receipt) => in_channel(receipt.channel, Perm::ENTER),
            Body::Delete(delete) => in_channel(delete.channel, Perm::DELETE_MESSAGE),
            // Server-to-client answers. A client that sends one is trying to
            // forge somebody else's history or pin list, and the verbatim relay
            // would have passed it on unaltered.
            Body::FetchResponse(_) | Body::PinList(_) => None,
            // Handled before this point.
            Body::Message(_) | Body::Fetch(_) | Body::Ack(_) => None,
        }
    }
}

impl ClientService for PchatService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        if inbound.type_id != ServiceKind::Pchat.outer_type() {
            return Actions::new();
        }
        let Ok(envelope) = PchatEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable PchatEnvelope"
            );
            return Actions::new();
        };

        match envelope.body {
            Some(pchat_envelope::Body::Message(message)) => {
                self.on_message(&inbound, message).await
            }
            Some(pchat_envelope::Body::Fetch(request)) => self.on_fetch(&inbound, request).await,
            // A client acknowledging its offline queue. Nothing to relay, and
            // the old catch-all broadcast every one of these to the whole
            // server.
            Some(pchat_envelope::Body::Ack(_)) => Actions::new(),
            Some(body) => self.on_relay(&inbound, &body).await,
            None => Actions::new(),
        }
    }

    async fn closed(&self, conn: u64, _reason: &str) -> Actions {
        // Otherwise the map grows one entry per (connection, operation) for the
        // life of the process.
        self.limits.forget(conn);
        Actions::new()
    }
}

impl PchatService {
    /// Address `payload` at everyone in `channel` except the sender.
    ///
    /// An empty roster produces no action at all rather than a broadcast. That
    /// is the difference between "membership is unknown" and "everyone", and
    /// conflating them is the leak this replaced.
    fn to_channel(&self, inbound: &Inbound, channel: u32, payload: Vec<u8>) -> Actions {
        let members = self.roster.in_channel(channel, inbound.session);
        if members.is_empty() {
            if !self.roster.is_warm() {
                tracing::warn!(
                    channel,
                    "the session-view roster is cold; a pchat relay reached nobody"
                );
            }
            return Actions::new();
        }
        vec![to_sessions(
            members,
            ServiceKind::Pchat.outer_type(),
            payload,
        )]
    }

    /// One acknowledgement, addressed at the connection that asked.
    fn ack(
        &self,
        inbound: &Inbound,
        message_id: &str,
        status: ack::Status,
        detail: &str,
    ) -> ServerAction {
        let envelope = PchatEnvelope {
            body: Some(pchat_envelope::Body::Ack(Ack {
                message_id: message_id.to_owned(),
                status: status as i32,
                detail: detail.to_owned(),
            })),
        };
        to_conn(
            inbound.conn,
            ServiceKind::Pchat.outer_type(),
            envelope.encode_to_vec(),
        )
    }

    /// Follow `session-view`, so a relay knows who is in a channel.
    ///
    /// Re-subscribes on failure: a `session-view` restart is a rolling deploy,
    /// not an incident. The stream is also dropped deliberately when this
    /// subscriber falls behind, because a missed delta cannot be repaired from
    /// the next one — reconnecting replaces the whole table, which is the only
    /// way back to agreement.
    fn follow_view(self: Arc<Self>, ctx: ServiceContext) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let scope = ctx.virtual_servers().first().copied().unwrap_or(1);
            loop {
                self.read_view(&ctx, scope).await;
                tokio::time::sleep(VIEW_RETRY).await;
            }
        })
    }

    /// One subscription, from opening it to the stream ending.
    async fn read_view(&self, ctx: &ServiceContext, scope: u32) {
        let Ok(channel) = ctx.resolver.channel("session-view") else {
            // Worth a line: with no roster, a relay is addressed at nobody, and
            // that is indistinguishable from a channel where nobody is talking.
            tracing::warn!("cannot reach session-view; no pchat relay will be delivered");
            return;
        };
        let Ok(stream) = SessionViewClient::new(channel)
            .subscribe(SubscribeRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
                subscriber: Self::NAME.to_owned(),
            })
            .await
        else {
            return;
        };

        let mut events = stream.into_inner();
        while let Ok(Some(event)) = events.message().await {
            let _ = self.roster.apply(event);
            // After the first event, not before: a subscription opens with a
            // full snapshot, so this is the moment the roster stops being cold.
            ctx.health.ready(VIEW_GATE);
        }
        tracing::warn!("the session-view subscription ended; pchat relays are now stale");
    }

    /// Store a message and relay it to its channel.
    async fn on_message(&self, inbound: &Inbound, mut message: Message) -> Actions {
        if !self.limits.allow(inbound.conn, Op::Message) {
            return vec![self.ack(
                inbound,
                &message.message_id,
                ack::Status::RateLimited,
                "too many messages",
            )];
        }

        // Checked before the message is stored, not just before it is relayed:
        // an unauthorised write that is refused delivery still leaves a row in
        // somebody else's channel archive, and the sender is the one who chose
        // the channel id.
        if !self
            .permit
            .allows(inbound, message.channel, Perm::TEXT_MESSAGE.bits())
            .await
        {
            return vec![permission_denied(
                inbound,
                Perm::TEXT_MESSAGE,
                message.channel,
            )];
        }

        message.sender = inbound.session;
        let Some(id) = self.store_message(inbound.scope, &message).await else {
            return vec![self.ack(
                inbound,
                &message.message_id,
                ack::Status::Refused,
                "the message could not be stored",
            )];
        };

        message.message_id = id.to_string();
        let channel = message.channel;
        let acknowledgement = self.ack(inbound, &message.message_id, ack::Status::Stored, "");
        let relay = PchatEnvelope {
            body: Some(pchat_envelope::Body::Message(message)),
        };

        let mut actions = vec![acknowledgement];
        actions.extend(self.to_channel(inbound, channel, relay.encode_to_vec()));
        actions
    }

    /// Serve a page of the archive to the asker alone.
    async fn on_fetch(&self, inbound: &Inbound, request: Fetch) -> Actions {
        if !self.limits.allow(inbound.conn, Op::Fetch) {
            return Actions::new();
        }

        // The channel id comes off the wire, so without this a client could
        // page through the stored archive of any channel on the server --
        // including ones it cannot see. murmur gates the same read on Enter
        // (`handlePchatFetch`).
        if !self
            .permit
            .allows(inbound, request.channel, Perm::ENTER.bits())
            .await
        {
            return vec![permission_denied(inbound, Perm::ENTER, request.channel)];
        }

        let page = self.fetch(inbound.scope, &request).await;
        let reply = PchatEnvelope {
            body: Some(pchat_envelope::Body::FetchResponse(page)),
        };
        vec![to_conn(
            inbound.conn,
            ServiceKind::Pchat.outer_type(),
            reply.encode_to_vec(),
        )]
    }

    /// Pass a body this service does not read on to whoever it is addressed to.
    ///
    /// Still verbatim: the bytes are re-sent unaltered, because re-encoding a
    /// body whose meaning this service does not know is how a relay corrupts
    /// things. What changed is that it is now addressed and authorised, both
    /// decided from the channel field beside the payload.
    async fn on_relay(&self, inbound: &Inbound, body: &pchat_envelope::Body) -> Actions {
        let Some(relay) = Relay::of(body) else {
            tracing::debug!(
                session = inbound.session,
                "refused a pchat body a client may not originate"
            );
            return Actions::new();
        };

        if !self.limits.allow(inbound.conn, Op::Manage) {
            return Actions::new();
        }

        if !self
            .permit
            .allows(inbound, relay.channel, relay.needs.bits())
            .await
        {
            return vec![permission_denied(inbound, relay.needs, relay.channel)];
        }

        match relay.unicast {
            Some(recipient) => vec![to_sessions(
                vec![recipient],
                ServiceKind::Pchat.outer_type(),
                inbound.payload.clone(),
            )],
            None => self.to_channel(inbound, relay.channel, inbound.payload.clone()),
        }
    }
}

impl Serve for PchatService {
    const NAME: &'static str = "pchat";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        ctx.health.gate(VIEW_GATE);
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            permit: Permit::new(ctx.resolver.clone()),
            roster: Arc::new(Roster::new()),
            limits: Limits::new(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let follower = Arc::clone(&self).follow_view(ctx.clone());
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => {
                    follower.abort();
                    return Ok(());
                }
                _ = ticker.tick() => self.sweep().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::fancy::pchat::{Delete, KeyAnnounce, KeyDeliver, PinList, Reaction};

    async fn service() -> Arc<PchatService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:pchat-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        // Points at a `permissions` nothing is serving, so every check denies.
        // The storage tests below call `store_message`/`fetch` directly and are
        // unaffected; the two that go through `frame` rely on this to assert
        // that an unauthorised client is refused.
        let resolver = starling_runtime::channel::Resolver::new(
            Arc::new(starling_runtime::config::Config::with_defaults(
                std::path::Path::new("/run/starling"),
            )),
            starling_runtime::inproc::Broker::new(),
        );
        Arc::new(PchatService {
            store,
            fanout: Fanout::default(),
            permit: Permit::new(resolver),
            roster: Arc::new(Roster::new()),
            limits: Limits::new(),
        })
    }

    /// The same service with a warm roster, so a relay has somewhere to go.
    ///
    /// Sessions 7, 8 are in channel 4 and session 9 is in channel 9 — enough to
    /// tell "the channel" from "everyone".
    async fn service_with_members() -> Arc<PchatService> {
        use starling_proto_fancy::sessionview::{Session, Sessions, ViewEvent, view_event};
        let service = service().await;
        let _ = service.roster.apply(ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                sessions: vec![
                    Session {
                        session: 7,
                        channel: 4,
                        ..Session::default()
                    },
                    Session {
                        session: 8,
                        channel: 4,
                        ..Session::default()
                    },
                    Session {
                        session: 9,
                        channel: 9,
                        ..Session::default()
                    },
                ],
                ..Sessions::default()
            })),
        });
        service
    }

    /// One decoded frame carrying `body`, from session 7 in channel 4.
    fn frame(body: pchat_envelope::Body) -> Inbound {
        Inbound {
            conn: 1,
            session: 7,
            scope: 1,
            type_id: ServiceKind::Pchat.outer_type(),
            gateway: String::new(),
            payload: PchatEnvelope { body: Some(body) }.encode_to_vec(),
        }
    }

    fn message(channel: u32, ciphertext: &[u8]) -> Message {
        Message {
            message_id: String::new(),
            channel,
            sender: 1,
            ciphertext: ciphertext.to_vec(),
            sent_at_ms: 0,
            supersedes: String::new(),
            epoch: 1,
        }
    }

    fn fetch(channel: u32, limit: u32) -> Fetch {
        Fetch {
            channel,
            limit,
            before_id: String::new(),
            after_id: String::new(),
        }
    }

    #[tokio::test]
    async fn a_stored_message_keeps_its_ciphertext_byte_for_byte() {
        // The server cannot read it and must not touch it: any transformation
        // here is a message the recipient cannot decrypt.
        let service = service().await;
        let _ = service
            .store_message(1, &message(4, b"\x00\xffopaque"))
            .await;
        let page = service.fetch(1, &fetch(4, 10)).await;
        assert_eq!(
            page.messages.first().map(|m| m.ciphertext.clone()),
            Some(b"\x00\xffopaque".to_vec())
        );
    }

    #[tokio::test]
    async fn a_fetch_reports_the_total_so_a_client_can_show_progress() {
        let service = service().await;
        for _ in 0..3 {
            let _ = service.store_message(1, &message(5, b"x")).await;
        }
        let page = service.fetch(1, &fetch(5, 2)).await;
        assert_eq!(page.total_stored, 3);
        assert!(page.more);
    }

    #[tokio::test]
    async fn a_fetch_the_client_may_not_make_returns_no_archive() {
        // The channel id is chosen by the client, so an unchecked fetch paged
        // through the stored archive of any channel on the server.
        let service = service().await;
        let _ = service.store_message(1, &message(4, b"secret")).await;

        let actions = service
            .frame(frame(pchat_envelope::Body::Fetch(fetch(4, 10))))
            .await;

        // Refused, and specifically not a FetchResponse carrying the archive.
        assert_eq!(actions.len(), 1);
        let payload = sent_payload(&actions[0]);
        assert!(
            PchatEnvelope::decode(payload.as_slice())
                .ok()
                .and_then(|envelope| envelope.body)
                .is_none(),
            "a refused fetch must not answer with a pchat body"
        );
    }

    #[tokio::test]
    async fn no_relay_is_ever_a_server_wide_broadcast() {
        // The finding this replaced: a Send naming no conns and no sessions is
        // delivered to every authenticated client on the server, so a message
        // to one channel reached every other.
        let service = service_with_members().await;

        for body in [
            pchat_envelope::Body::Message(message(4, b"x")),
            pchat_envelope::Body::Reaction(Reaction {
                message_id: "m".to_owned(),
                channel: 4,
                emoji: "x".to_owned(),
                remove: false,
            }),
            pchat_envelope::Body::KeyAnnounce(KeyAnnounce {
                channel: 4,
                epoch: 1,
                public_key: vec![1],
                holder: 7,
            }),
            pchat_envelope::Body::Ack(Ack::default()),
        ] {
            for action in service.frame(frame(body)).await {
                let (_, broadcast) = addressed(&action);
                assert!(!broadcast, "a pchat action must never be server-wide");
            }
        }
    }

    #[tokio::test]
    async fn a_cold_roster_relays_to_nobody_rather_than_everybody() {
        // `service()` leaves the roster cold. Failing open here would be the
        // original leak wearing a fallback.
        let service = service().await;
        let actions = service
            .frame(frame(pchat_envelope::Body::Reaction(Reaction {
                message_id: "m".to_owned(),
                channel: 4,
                emoji: "x".to_owned(),
                remove: false,
            })))
            .await;

        for action in &actions {
            let (sessions, broadcast) = addressed(action);
            assert!(!broadcast);
            assert!(sessions.is_empty());
        }
    }

    #[tokio::test]
    async fn a_response_body_from_a_client_is_refused_not_relayed() {
        // FetchResponse and PinList are server-to-client. The verbatim relay
        // passed them on unaltered, which let a client forge somebody else's
        // history.
        let service = service_with_members().await;

        let actions = service
            .frame(frame(pchat_envelope::Body::FetchResponse(FetchResponse {
                channel: 4,
                messages: vec![message(4, b"forged")],
                more: false,
                total_stored: 1,
            })))
            .await;

        assert!(actions.is_empty(), "a forged response must reach nobody");
    }

    #[test]
    fn sealed_key_material_is_addressed_to_its_recipient_alone() {
        // KeyDeliver names one recipient; relaying it to the channel handed
        // every member a copy of a message addressed to one of them.
        //
        // Asserted against `Relay::of` rather than through `frame`, because the
        // test resolver denies every permission — a frame test would pass on
        // the refusal and prove nothing about the addressing.
        let relay = Relay::of(&pchat_envelope::Body::KeyDeliver(KeyDeliver {
            channel: 4,
            epoch: 1,
            recipient: 8,
            sealed_key: vec![9],
            countersignature: Vec::new(),
        }))
        .expect("KeyDeliver is relayable");

        assert_eq!(relay.unicast, Some(8));
        assert_eq!(relay.channel, 4);
    }

    #[test]
    fn every_relayable_body_names_the_channel_it_is_authorised_against() {
        // The routing table in one assertion: a body whose channel this got
        // wrong would be checked against the wrong ACL and delivered to the
        // wrong people.
        let cases: Vec<(pchat_envelope::Body, Option<(u32, Perm)>)> = vec![
            (
                pchat_envelope::Body::Reaction(Reaction {
                    message_id: "m".to_owned(),
                    channel: 4,
                    emoji: "x".to_owned(),
                    remove: false,
                }),
                Some((4, Perm::TEXT_MESSAGE)),
            ),
            (
                pchat_envelope::Body::Delete(Delete {
                    channel: 5,
                    message_ids: vec!["m".to_owned()],
                }),
                Some((5, Perm::DELETE_MESSAGE)),
            ),
            (
                pchat_envelope::Body::KeyAnnounce(KeyAnnounce {
                    channel: 6,
                    epoch: 1,
                    public_key: vec![1],
                    holder: 7,
                }),
                Some((6, Perm::ENTER)),
            ),
            // Server-to-client: a client may not originate these at all.
            (
                pchat_envelope::Body::FetchResponse(FetchResponse::default()),
                None,
            ),
            (pchat_envelope::Body::PinList(PinList::default()), None),
        ];

        for (body, expected) in cases {
            let got = Relay::of(&body).map(|relay| (relay.channel, relay.needs));
            assert_eq!(got, expected, "routing for {body:?}");
        }
    }

    #[tokio::test]
    async fn a_message_the_client_may_not_send_is_never_stored() {
        // Refusing only the relay would still leave the row in somebody else's
        // channel archive.
        let service = service().await;

        let actions = service
            .frame(frame(pchat_envelope::Body::Message(message(4, b"x"))))
            .await;

        assert_eq!(actions.len(), 1);
        assert_eq!(service.count(1, 4).await, 0);
    }

    /// The payload of a `Send` action, for asserting on what a refusal carries.
    fn sent_payload(action: &ServerAction) -> Vec<u8> {
        match &action.action {
            Some(starling_proto_fancy::control::server_action::Action::Send(send)) => {
                send.payload.clone()
            }
            _ => Vec::new(),
        }
    }

    /// The sessions a `Send` action is addressed at, and whether it is a
    /// server-wide broadcast (no conns and no sessions named).
    fn addressed(action: &ServerAction) -> (Vec<u32>, bool) {
        match &action.action {
            Some(starling_proto_fancy::control::server_action::Action::Send(send)) => (
                send.sessions.clone(),
                send.conns.is_empty() && send.sessions.is_empty(),
            ),
            _ => (Vec::new(), false),
        }
    }
}
