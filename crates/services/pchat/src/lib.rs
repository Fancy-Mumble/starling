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

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::fancy::pchat::{
    Ack, Fetch, FetchResponse, Message, PchatEnvelope, ack, pchat_envelope,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, broadcast_except, to_conn,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};

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

impl ClientService for PchatService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Pchat.outer_type();
        if inbound.type_id != outer {
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
            Some(pchat_envelope::Body::Message(mut message)) => {
                message.sender = inbound.session;
                let Some(id) = self.store_message(inbound.scope, &message).await else {
                    let refusal = PchatEnvelope {
                        body: Some(pchat_envelope::Body::Ack(Ack {
                            message_id: message.message_id.clone(),
                            status: ack::Status::Refused as i32,
                            detail: "the message could not be stored".to_owned(),
                        })),
                    };
                    return vec![to_conn(inbound.conn, outer, refusal.encode_to_vec())];
                };

                message.message_id = id.to_string();
                let acknowledgement = PchatEnvelope {
                    body: Some(pchat_envelope::Body::Ack(Ack {
                        message_id: message.message_id.clone(),
                        status: ack::Status::Stored as i32,
                        detail: String::new(),
                    })),
                };
                let relay = PchatEnvelope {
                    body: Some(pchat_envelope::Body::Message(message)),
                };
                vec![
                    to_conn(inbound.conn, outer, acknowledgement.encode_to_vec()),
                    broadcast_except(inbound.session, outer, relay.encode_to_vec()),
                ]
            }
            Some(pchat_envelope::Body::Fetch(request)) => {
                let page = self.fetch(inbound.scope, &request).await;
                let reply = PchatEnvelope {
                    body: Some(pchat_envelope::Body::FetchResponse(page)),
                };
                vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
            }
            // Key distribution, pins, reactions and receipts are relayed
            // verbatim: reading any of them would mean understanding a payload
            // this service deliberately cannot decrypt.
            Some(_) => vec![broadcast_except(
                inbound.session,
                outer,
                inbound.payload.clone(),
            )],
            None => Actions::new(),
        }
    }
}

impl Serve for PchatService {
    const NAME: &'static str = "pchat";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => return Ok(()),
                _ = ticker.tick() => self.sweep().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        Arc::new(PchatService {
            store,
            fanout: Fanout::default(),
        })
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
}
