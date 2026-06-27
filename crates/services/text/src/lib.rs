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
use starling_proto_fancy::common::{Ack, Scope};
use starling_proto_fancy::fancy::feature::{TextEnvelope, text_envelope};
use starling_proto_fancy::metadata::TreeRequest;
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::sessionview::SubscribeRequest;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::text::text_server::{Text, TextServer};
use starling_proto_fancy::text::{
    AnnounceRequest, AnnounceResult, HistoryPage, HistoryRequest, MessageEvent, PurgeRequest,
    StoredMessage, WatchRequest,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::log::{Category, LogEvent, Logger, describe_actor};
use starling_runtime::permit::{Permit, permission_denied};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, broadcast_except, to_conn, to_sessions,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

/// Upstream `TextMessage`.
const TEXT_MESSAGE: u16 = 11;

/// How many delivered messages a `Watch` subscriber may fall behind by.
///
/// Bounded because an unbounded queue turns one stalled watcher into an OOM.
/// A subscriber that exceeds it is told it lagged rather than being
/// disconnected, so a slow consumer loses events and knows it did.
const EVENT_BACKLOG: usize = 1024;

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
    /// How `Announce` reaches `session-view` and `metadata` to turn a channel
    /// into the sessions sitting in it. A client's own message never needs
    /// this — the gateway holds the sessions and fan-out is an exclusion —
    /// but a server-originated message has no session to broadcast from.
    resolver: starling_runtime::channel::Resolver,
    /// Delivered messages, for `Watch` subscribers.
    ///
    /// Bounded and lossy on purpose, like [`Fanout`]: a watcher that stops
    /// reading must cost the oldest events it has not read, never memory
    /// without limit and never the delivery of the message itself. A chat
    /// observer falling behind is not a reason to stop serving chat.
    events: broadcast::Sender<MessageEvent>,
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

    /// Every channel in `roots`, plus their descendants when `tree`.
    ///
    /// Walks the tree by parent rather than asking for a subtree, because
    /// `metadata` publishes a flat list and the parent edge is the only shape
    /// the descent needs.
    async fn expand_channels(&self, scope: u32, roots: &[u32], tree: bool) -> Vec<u32> {
        let mut wanted: Vec<u32> = roots.to_vec();
        if !tree {
            return wanted;
        }
        let Ok(channel) = self.resolver.channel("metadata") else {
            // The roots themselves still resolve; a missing `metadata` costs
            // the subchannels, not the message.
            tracing::warn!("metadata is unreachable; announcing to the named channels only");
            return wanted;
        };
        let Ok(reply) = MetadataClient::new(channel)
            .get_tree(TreeRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
            })
            .await
        else {
            tracing::warn!(
                "could not read the channel tree; announcing to the named channels only"
            );
            return wanted;
        };

        // Repeated passes rather than recursion: the tree is small, and a
        // parent cycle in bad data would make a recursive descent hang.
        let channels = reply.into_inner().channels;
        loop {
            let before = wanted.len();
            for c in &channels {
                if let Some(parent) = c.parent
                    && wanted.contains(&parent)
                    && !wanted.contains(&c.id)
                {
                    wanted.push(c.id);
                }
            }
            if wanted.len() == before {
                break;
            }
        }
        wanted
    }

    /// The sessions an announcement should actually be written to.
    ///
    /// Named sessions are taken as given; channels are resolved through
    /// `session-view`, which is the one place that knows who is where.
    async fn recipients(&self, scope: u32, request: &AnnounceRequest) -> Vec<u32> {
        let mut sessions = request.sessions.clone();
        if request.channels.is_empty() {
            return sessions;
        }

        let wanted = self
            .expand_channels(scope, &request.channels, request.tree)
            .await;
        let Ok(channel) = self.resolver.channel("session-view") else {
            tracing::warn!("session-view is unreachable; a channel announcement has no recipients");
            return sessions;
        };
        let Ok(reply) = SessionViewClient::new(channel)
            .list(SubscribeRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
                subscriber: "text".to_owned(),
            })
            .await
        else {
            tracing::warn!("could not list sessions; a channel announcement has no recipients");
            return sessions;
        };

        for session in reply.into_inner().sessions {
            if wanted.contains(&session.channel) && !sessions.contains(&session.session) {
                sessions.push(session.session);
            }
        }
        sessions
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

    /// Every message as it is delivered.
    ///
    /// A late subscriber sees what happens from now on and nothing before it:
    /// this is a notification channel, not a replay. What was said already is
    /// `History`, which is the query built for it.
    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<MessageEvent, Status>>;

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = request.into_inner();
        let subscriber = req.subscriber;
        let mut events = self.0.events.subscribe();
        let (tx, rx) = tokio::sync::mpsc::channel(EVENT_BACKLOG);

        drop(tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        // The receiver has gone: the subscriber disconnected,
                        // and this task is the only thing still holding on.
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        // Reported rather than hidden. A watcher that silently
                        // skips messages is worse than one that knows it did,
                        // because only the second can go and read History.
                        tracing::warn!(subscriber, missed, "a text watcher fell behind");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }));

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// A message from the server, with no client behind it.
    ///
    /// **No permission check, deliberately.** `Permit` exists to stop a client
    /// asserting an identity it does not have; the caller here is the operator
    /// plane, which has already authenticated and been scoped by
    /// `operator-api` and whose action is already in the audit log. Asking
    /// `permissions` would mean asking on behalf of a session that does not
    /// exist, and the only honest answer to that is a denial.
    async fn announce(
        &self,
        request: Request<AnnounceRequest>,
    ) -> Result<Response<AnnounceResult>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);

        if req.body.is_empty() {
            return Err(Status::invalid_argument("an announcement needs a body"));
        }
        // Addressed at nobody is a mistake, not a broadcast. Treating it as one
        // would turn a dropped session id into a message to the whole server.
        if req.sessions.is_empty() && req.channels.is_empty() {
            return Err(Status::invalid_argument(
                "an announcement needs at least one session or channel",
            ));
        }

        let sessions = self.0.recipients(scope, &req).await;
        if sessions.is_empty() {
            // Not an error: everyone addressed is simply offline. The caller
            // gets `applied = false` and a reason rather than a fault, because
            // "nobody was there" is a normal outcome for a notice.
            return Ok(Response::new(AnnounceResult {
                applied: false,
                refused: "no addressed session is connected".to_owned(),
            }));
        }

        let message = starling_proto::proto::tcp::TextMessage {
            // No actor: the message is from the server itself. A client renders
            // an actorless TextMessage as a server notice, which is what murmur
            // sends for a server-originated message.
            actor: None,
            session: req.sessions.clone(),
            channel_id: req.channels.clone(),
            tree_id: if req.tree {
                req.channels.clone()
            } else {
                Vec::new()
            },
            message: req.body.clone(),
            ..starling_proto::proto::tcp::TextMessage::default()
        };

        self.0.logger.log(
            LogEvent::info(Category::Message, "announcement")
                .with("actor", describe_actor(req.actor.as_ref()))
                .with("recipients", sessions.len())
                .with("length", req.body.len()),
        );

        // Watchers see server-originated messages too, flagged as such, so a
        // watcher can tell a message the server sent from one a user did —
        // including one it caused itself.
        let _ = self.0.events.send(MessageEvent {
            sender_session: 0,
            sender_account: 0,
            sender_name: String::new(),
            sender_registered: false,
            channels: req.channels.clone(),
            sessions: sessions.clone(),
            tree: if req.tree {
                req.channels.clone()
            } else {
                Vec::new()
            },
            body: req.body.clone(),
            sent_at_ms: now_ms(),
            from_client: false,
        });

        self.0
            .fanout
            .push(to_sessions(sessions, TEXT_MESSAGE, message.encode_to_vec()));

        // History is per channel, so a message addressed only at sessions has
        // nowhere to be stored even when `store` is set.
        if req.store {
            for channel in &req.channels {
                let stored = StoredMessage {
                    id: Vec::new(),
                    channel: *channel,
                    sender_account: 0,
                    sender_name: String::new(),
                    body: req.body.clone(),
                    sent_at_ms: now_ms(),
                };
                let _ = self.0.record(scope, &stored).await;
            }
        }

        Ok(Response::new(AnnounceResult {
            applied: true,
            refused: String::new(),
        }))
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

        // Published after the message is stored and before it is returned for
        // delivery. A watcher is an observer, so this is never allowed to
        // decide whether the message goes out — `send` failing means only that
        // nobody is watching.
        let _ = self.events.send(MessageEvent {
            sender_session: inbound.session,
            sender_account: stored.sender_account,
            sender_name: stored.sender_name.clone(),
            // `on_text_message` does not resolve the sender's account, so this
            // says what is actually known rather than implying account 0 is
            // the SuperUser.
            sender_registered: false,
            channels: message.channel_id.clone(),
            sessions: message.session.clone(),
            tree: message.tree_id.clone(),
            body: stored.body.clone(),
            sent_at_ms: stored.sent_at_ms,
            from_client: true,
        });

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
            resolver: ctx.resolver,
            events: broadcast::channel(EVENT_BACKLOG).0,
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
        // Points at a `permissions` nothing is serving, so every check denies.
        // These tests exercise storage and history, not delivery; a test that
        // wanted delivery would have to stand one up, which is the right amount
        // of friction for skipping an authorisation.
        let resolver = starling_runtime::channel::Resolver::new(
            Arc::new(starling_runtime::config::Config::with_defaults(
                std::path::Path::new("/run/starling"),
            )),
            starling_runtime::inproc::Broker::new(),
        );
        Arc::new(TextService {
            store,
            fanout: Fanout::default(),
            logger: Logger::null(),
            permit: Permit::new(resolver.clone()),
            resolver,
            events: broadcast::channel(EVENT_BACKLOG).0,
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
