//! `text` — chat that is not end-to-end encrypted, and its history.
//!
//! Rows are keyed by **`UUIDv7`**: time-sortable and coordination-free, so
//! "newest 50 in this channel" is a backwards range scan off the end of an
//! index rather than a sort, and an insert appends instead of scattering the
//! way `UUIDv4` does (`docs/STORAGE.md` L3).
//!
//! Fan-out names the speaker as an *exclusion* rather than filtering here:
//! only the gateway knows which sessions it holds.

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::feature::{TextEnvelope, text_envelope};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::text::text_server::{Text, TextServer};
use starling_proto_fancy::text::{HistoryPage, HistoryRequest, PurgeRequest, StoredMessage};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::permit::{Permit, permission_denied};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, broadcast_except, to_conn,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tonic::{Request, Response, Status};

/// Upstream `TextMessage`.
const TEXT_MESSAGE: u16 = 11;

/// The schema.
///
/// The primary key is `(server_id, channel_id, id)`, so the table is physically
/// ordered tenant → channel → time and both query shapes — newest page and
/// scroll-back — are one range scan.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_text_message",
    &[
        "CREATE TABLE IF NOT EXISTS text_message (\
             server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, id BLOB NOT NULL, \
             sender_account BIGINT NOT NULL, sender_name VARCHAR(190) NOT NULL, \
             body TEXT NOT NULL, sent_at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, channel_id, id))",
        "CREATE INDEX IF NOT EXISTS ix_text_sent ON text_message(server_id, sent_at_ms)",
    ],
)];

/// The service.
#[derive(Debug)]
pub struct TextService {
    store: Store,
    fanout: Fanout,
    logger: Logger,
    /// Asks `permissions` before a message reaches anyone.
    permit: Permit,
}

impl TextService {
    /// Store one message and return the id it was given.
    async fn record(&self, scope: u32, message: &StoredMessage) -> Uuid7 {
        let id = Uuid7::now();
        let result = sqlx::query(
            "INSERT INTO text_message \
                 (server_id, channel_id, id, sender_account, sender_name, body, sent_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(i64::from(message.channel))
        .bind(id.to_vec())
        .bind(message.sender_account as i64)
        .bind(&message.sender_name)
        .bind(&message.body)
        .bind(message.sent_at_ms as i64)
        .execute(self.store.pool())
        .await;
        if let Err(error) = result {
            // History is not the message: a storage failure must not swallow a
            // message that has already been delivered.
            tracing::error!(%error, "could not store a chat message");
        }
        id
    }

    /// A page, newest first, optionally before a cursor.
    async fn history(&self, scope: u32, channel: u32, limit: u32, before: &[u8]) -> HistoryPage {
        use sqlx::Row as _;
        let limit = limit.clamp(1, 200);
        let sql = if before.is_empty() {
            "SELECT id, sender_account, sender_name, body, sent_at_ms FROM text_message \
             WHERE server_id = ? AND channel_id = ? ORDER BY id DESC LIMIT ?"
        } else {
            "SELECT id, sender_account, sender_name, body, sent_at_ms FROM text_message \
             WHERE server_id = ? AND channel_id = ? AND id < ? ORDER BY id DESC LIMIT ?"
        };
        let mut query = sqlx::query(sql)
            .bind(i64::from(scope))
            .bind(i64::from(channel));
        if !before.is_empty() {
            query = query.bind(before);
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
            .map(|row| StoredMessage {
                id: row.try_get("id").unwrap_or_default(),
                channel,
                sender_account: row.try_get::<i64, _>("sender_account").unwrap_or_default() as u64,
                sender_name: row.try_get("sender_name").unwrap_or_default(),
                body: row.try_get("body").unwrap_or_default(),
                sent_at_ms: row.try_get::<i64, _>("sent_at_ms").unwrap_or_default() as u64,
            })
            .collect();
        HistoryPage { messages, more }
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct TextRpc(Arc<TextService>);

#[tonic::async_trait]
impl Text for TextRpc {
    async fn history(
        &self,
        request: Request<HistoryRequest>,
    ) -> Result<Response<HistoryPage>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.virtual_server);
        Ok(Response::new(
            self.0
                .history(scope, req.channel, req.limit, &req.before)
                .await,
        ))
    }

    async fn purge(&self, request: Request<PurgeRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.virtual_server);
        let _ = sqlx::query(
            "DELETE FROM text_message WHERE server_id = ? AND channel_id = ? AND sent_at_ms < ?",
        )
        .bind(i64::from(scope))
        .bind(i64::from(req.channel))
        .bind(req.older_than_ms as i64)
        .execute(self.0.store.pool())
        .await;
        Ok(Response::new(Ack {}))
    }
}

impl ClientService for TextService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            TEXT_MESSAGE => self.on_text_message(&inbound).await,
            id if id == ServiceKind::Text.outer_type() => self.on_envelope(&inbound).await,
            _ => Actions::new(),
        }
    }
}

impl TextService {
    async fn on_text_message(&self, inbound: &Inbound) -> Actions {
        let Ok(message) =
            starling_proto::proto::tcp::TextMessage::decode(inbound.payload.as_slice())
        else {
            tracing::debug!(conn = inbound.conn, "undecodable TextMessage");
            return Actions::new();
        };
        if message.message.is_empty() {
            return Actions::new();
        }

        // Checked before the message is stored or delivered, and against every
        // channel it is addressed to: a message naming five channels the sender
        // may not write to must not reach the one they may. murmur refuses the
        // whole message rather than delivering it partially, and a partial
        // delivery is the worse answer — the sender is told nothing and some
        // recipients saw it.
        for channel in message
            .channel_id
            .iter()
            .chain(message.tree_id.iter())
            .copied()
        {
            if !self
                .permit
                .allows(inbound, channel, Perm::TEXT_MESSAGE.bits())
                .await
            {
                return vec![permission_denied(inbound, Perm::TEXT_MESSAGE, channel)];
            }
        }

        // The body is deliberately absent: this log is kept for as long as the
        // retention policy says and read by whoever operates the server, which
        // is not consent to archive everybody's conversations. Length and
        // destination are enough to answer "was it delivered".
        tracing::debug!(
            session = inbound.session,
            channels = message.channel_id.len(),
            trees = message.tree_id.len(),
            sessions = message.session.len(),
            len = message.message.len(),
            "text message"
        );
        self.logger.log(
            LogEvent::info(Category::Message, "text message")
                .with("session", inbound.session)
                .with("channel", message.channel_id.first().copied().unwrap_or(0))
                .with("recipients", message.session.len())
                .with("length", message.message.len()),
        );

        let mut stored = StoredMessage {
            id: Vec::new(),
            channel: message.channel_id.first().copied().unwrap_or_default(),
            sender_account: 0,
            sender_name: String::new(),
            body: message.message.clone(),
            sent_at_ms: now_ms(),
        };
        stored.id = self.record(inbound.scope, &stored).await.to_vec();

        let echo = starling_proto::proto::tcp::TextMessage {
            actor: Some(inbound.session),
            ..message
        };
        vec![broadcast_except(
            inbound.session,
            TEXT_MESSAGE,
            echo.encode_to_vec(),
        )]
    }

    async fn on_envelope(&self, inbound: &Inbound) -> Actions {
        let Ok(envelope) = TextEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        let Some(text_envelope::Body::History(request)) = envelope.body else {
            return Actions::new();
        };
        let before = Uuid7::parse(&request.before_id)
            .map(Uuid7::to_vec)
            .unwrap_or_default();
        let page = self
            .history(inbound.scope, request.channel, request.limit, &before)
            .await;
        let reply = TextEnvelope {
            body: Some(text_envelope::Body::Page(
                starling_proto_fancy::fancy::feature::HistoryPage {
                    channel: request.channel,
                    more: page.more,
                    messages: page
                        .messages
                        .into_iter()
                        .map(
                            |message| starling_proto_fancy::fancy::feature::StoredMessage {
                                message_id: Uuid7::from_slice(&message.id)
                                    .map(|id| id.to_string())
                                    .unwrap_or_default(),
                                channel: message.channel,
                                sender: 0,
                                sender_name: message.sender_name,
                                body: message.body,
                                sent_at_ms: message.sent_at_ms,
                                edited: false,
                            },
                        )
                        .collect(),
                },
            )),
        };
        vec![to_conn(
            inbound.conn,
            ServiceKind::Text.outer_type(),
            reply.encode_to_vec(),
        )]
    }
}

impl Serve for TextService {
    const NAME: &'static str = "text";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            permit: Permit::new(ctx.resolver.clone()),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(TextServer::new(TextRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn service() -> Arc<TextService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:text-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        Arc::new(TextService {
            store,
            fanout: Fanout::default(),
            logger: Logger::null(),
            // Points at a `permissions` nothing is serving, so every check
            // denies. These tests exercise storage and history, not delivery;
            // a test that wanted delivery would have to stand one up, which is
            // the right amount of friction for skipping an authorisation.
            permit: Permit::new(starling_runtime::channel::Resolver::new(
                Arc::new(starling_runtime::config::Config::with_defaults(
                    std::path::Path::new("/run/starling"),
                )),
                starling_runtime::inproc::Broker::new(),
            )),
        })
    }

    fn message(channel: u32, body: &str) -> StoredMessage {
        StoredMessage {
            id: Vec::new(),
            channel,
            sender_account: 0,
            sender_name: "someone".to_owned(),
            body: body.to_owned(),
            sent_at_ms: now_ms(),
        }
    }

    #[tokio::test]
    async fn history_comes_back_newest_first() {
        // A chat window renders bottom-up; any other order is a second sort
        // somewhere else.
        let service = service().await;
        for body in ["first", "second", "third"] {
            let _ = service.record(1, &message(9, body)).await;
        }
        let page = service.history(1, 9, 10, &[]).await;
        assert_eq!(
            page.messages.first().map(|m| m.body.as_str()),
            Some("third")
        );
    }

    #[tokio::test]
    async fn scrolling_back_from_a_cursor_returns_only_older_messages() {
        // This is the query murmur serves with a full table scan
        // (`docs/STORAGE.md` L3); here it is a range scan on the primary key.
        let service = service().await;
        for body in ["a", "b", "c", "d"] {
            let _ = service.record(1, &message(8, body)).await;
        }
        let newest = service.history(1, 8, 2, &[]).await;
        let cursor = newest
            .messages
            .last()
            .map(|m| m.id.clone())
            .unwrap_or_default();
        let older = service.history(1, 8, 10, &cursor).await;
        assert!(older.messages.iter().all(|m| m.id < cursor));
    }

    #[tokio::test]
    async fn a_page_says_whether_there_is_more_rather_than_making_the_client_guess() {
        let service = service().await;
        for body in ["a", "b", "c"] {
            let _ = service.record(1, &message(7, body)).await;
        }
        assert!(service.history(1, 7, 2, &[]).await.more);
        assert!(!service.history(1, 7, 10, &[]).await.more);
    }
}
