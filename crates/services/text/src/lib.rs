//! `text`: chat that is not end-to-end encrypted, and its history.
//!
//! Rows are keyed by **`UUIDv7`**: time-sortable and coordination-free, so
//! "newest 50 in this channel" is a backwards range scan off the end of an
//! index rather than a sort, and an insert appends instead of scattering the
//! way `UUIDv4` does (`docs/STORAGE.md` L3).
//!
//! Fan-out **addresses** its recipients. It used to name the speaker as an
//! exclusion and leave the rest to the gateway, on the reasoning that only the
//! gateway knows which sessions it holds, but a `Send` naming no sessions goes
//! to every authenticated client on the server, so excluding the speaker left
//! everyone else *on the server* rather than everyone else in the channel.
//! Membership comes from `session-view` through a [`Roster`], and a cold roster
//! addresses nobody rather than falling back to a broadcast.

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::{Ack, Scope};
use starling_proto_fancy::fancy::feature::{
    ScheduleAck, ScheduleCancel, ScheduleList, ScheduleQuery, ScheduleStatus, Scheduled,
    TextEnvelope, text_envelope,
};
use starling_proto_fancy::fancy::wire::PageInfo;
use starling_proto_fancy::metadata::TreeRequest;
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::push::push_client::PushClient;
use starling_proto_fancy::push::{LiveQuery, Notification};
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
use starling_runtime::permit::{Permit, permission_denied, refused};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::settings::Settings;
use starling_runtime::storage::{Migration, Store};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

pub mod filter;
pub mod scheduled;

/// Upstream `TextMessage`.
const TEXT_MESSAGE: u16 = 11;

/// The longest the delivery timer sleeps before it looks again.
///
/// A day, as murmur's does (`Server.cpp:2443`): a delivery a month out should
/// cost a handful of wakeups, and a timer that is never re-armed is one that
/// cannot notice a clock jump or a row another pod wrote.
const MAX_DELIVERY_SLEEP_MS: u64 = 24 * 60 * 60 * 1000;

/// The shortest it sleeps, so a row it cannot claim cannot spin it.
const MIN_DELIVERY_SLEEP_MS: u64 = 250;

/// How long the timer waits before looking again when the roster is cold and
/// something is already due.
const COLD_ROSTER_RETRY_MS: u64 = 1_000;

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A text service that is up with a cold roster delivers nothing, which looks
/// exactly like a server where nobody is talking. Gating readiness keeps
/// traffic away until it can actually address a channel.
const VIEW_GATE: &str = "session-view";

/// How long a message may wait for `push` to name its live subscribers.
///
/// This one is on the delivery path rather than behind a spawn, so it is the
/// only place an optional service can slow chat down. Short enough that a
/// `push` in trouble costs a few extra recipients and not a visible delay.
const LIVE_SUBSCRIBER_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/// How much of a message a push notification carries.
///
/// murmur's `.left(200)`. A preview and not the message: the point is to say
/// enough that somebody decides whether to open the app, and a notification
/// that reproduces a whole paste on a lock screen is the wrong side of that.
const PREVIEW_CHARS: usize = 200;

/// How many delivered messages a `Watch` subscriber may fall behind by.
///
/// Bounded because an unbounded queue turns one stalled watcher into an OOM.
/// A subscriber that exceeds it is told it lagged rather than being
/// disconnected, so a slow consumer loses events and knows it did.
const EVENT_BACKLOG: usize = 1024;

/// The schema.
///
/// The primary key is `(server_id, channel_id, id)`, so the table is physically
/// ordered tenant → channel → time and both query shapes, newest page and
/// scroll-back, are one range scan.
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
    /// into the sessions sitting in it, and how a client's message expands a
    /// `tree_id` into the channels under it.
    ///
    /// This used to say a client's own message never needed any of it, because
    /// "the gateway holds the sessions and fan-out is an exclusion". That was
    /// the mistake: excluding the sender from a `Send` that names nobody leaves
    /// *everyone else on the server*, not everyone else in the channel.
    resolver: starling_runtime::channel::Resolver,
    /// Who is in which channel, so a message can be addressed at one.
    roster: Arc<Roster>,
    /// The two settings that bound a message: how long it may be and whether
    /// it may carry markup.
    ///
    /// Live rather than read at boot, because murmur's are: `setLiveConf`
    /// applies a changed `textmessagelength` to the next message anybody sends.
    settings: Settings,
    /// Delivered messages, for `Watch` subscribers.
    ///
    /// Bounded and lossy on purpose, like [`Fanout`]: a watcher that stops
    /// reading must cost the oldest events it has not read, never memory
    /// without limit and never the delivery of the message itself. A chat
    /// observer falling behind is not a reason to stop serving chat.
    events: broadcast::Sender<MessageEvent>,
    /// Whether `push` is a service this deployment runs.
    ///
    /// Read once at start-up so that an operator who switched push off does not
    /// pay a dial, and a log line, on every message anybody sends.
    live_push: bool,
    /// Wakes the delivery timer when what is due next has changed.
    ///
    /// Without it a message scheduled for two minutes from now would wait
    /// behind whatever the timer was already sleeping on, which is up to a
    /// day.
    schedules: tokio::sync::Notify,
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
        let limit = starling_proto_fancy::page::page_size(limit, 50, 200);
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
            .max_decoding_message_size(self.resolver.max_tree_message())
            .get_tree(TreeRequest {
                scope: Some(Scope { instance: scope }),
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
                scope: Some(Scope { instance: scope }),
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
        let scope = req.scope.map_or(1, |s| s.instance);
        Ok(Response::new(
            self.0
                .history(scope, req.channel, req.limit, &req.before)
                .await,
        ))
    }

    async fn purge(&self, request: Request<PurgeRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.instance);
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
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);

        if req.body.is_empty() {
            return Err(Status::invalid_argument("an announcement needs a body"));
        }
        // A mistake, not a broadcast: treating it as one would turn a dropped
        // session id into a message to the whole server.
        let addressed_at_nobody = req.sessions.is_empty() && req.channels.is_empty();
        if addressed_at_nobody {
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
        // watcher can tell a message the server sent from one a user did,
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
    /// Apply `text_message_length` and `allow_html` to a body in place.
    ///
    /// `Err` carries the refusal to send. Split out of
    /// [`Self::on_text_message`] because it is the whole of what the two
    /// settings do, and reads there as one decision rather than three.
    fn bound_body(
        &self,
        inbound: &Inbound,
        message: &mut starling_proto::proto::tcp::TextMessage,
    ) -> Result<(), Actions> {
        let config = self.settings.get(inbound.scope);
        match filter::check(
            &message.message,
            config.allow_html,
            config.text_message_length,
            config.image_message_length,
        ) {
            filter::Verdict::Deliver => Ok(()),
            filter::Verdict::Rewritten(text) => {
                tracing::debug!(
                    session = inbound.session,
                    before = message.message.len(),
                    after = text.len(),
                    "html stripped from a text message"
                );
                message.message = text;
                Ok(())
            }
            // murmur's `TextTooLong`, and it is sent rather than dropped: a
            // message that vanishes with no reply is indistinguishable from a
            // server that stopped delivering chat.
            filter::Verdict::TooLong => {
                self.logger.log(
                    LogEvent::notice(Category::Message, "text message refused")
                        .with("session", inbound.session)
                        .with("length", message.message.len())
                        .with("limit", config.text_message_length)
                        .with("reason", "over the text message length"),
                );
                Err(vec![refused(
                    inbound,
                    starling_proto::proto::tcp::permission_denied::DenyType::TextTooLong,
                    message.channel_id.first().copied().unwrap_or_default(),
                    "that message is too long",
                )])
            }
        }
    }

    async fn on_text_message(&self, inbound: &Inbound) -> Actions {
        let Ok(mut message) =
            starling_proto::proto::tcp::TextMessage::decode(inbound.payload.as_slice())
        else {
            tracing::debug!(conn = inbound.conn, "undecodable TextMessage");
            return Actions::new();
        };
        if message.message.is_empty() {
            return Actions::new();
        }

        // Before the permission check, as murmur has it (`Messages.cpp:2322`):
        // a body that is too long is refused whatever the sender may do, and
        // checking permission first would put a round trip in front of a
        // refusal that needs none.
        if let Err(denial) = self.bound_body(inbound, &mut message) {
            return denial;
        }
        // A body that was only markup is now empty, and an empty message is
        // not delivered, murmur returns here too rather than broadcasting a
        // blank line to a channel.
        if message.message.is_empty() {
            return Actions::new();
        }

        // Checked before the message is stored or delivered, and against every
        // channel it is addressed to: a message naming five channels the sender
        // may not write to must not reach the one they may. murmur refuses the
        // whole message rather than delivering it partially, and a partial
        // delivery is the worse answer, the sender is told nothing and some
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
        // decide whether the message goes out, `send` failing means only that
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

        let recipients = self.recipients_of(inbound, &message).await;

        // Before the empty-recipients return below, because a message into a
        // channel nobody is sitting in is exactly the one push exists for.
        self.notify_absent(inbound, &message).await;

        let echo = starling_proto::proto::tcp::TextMessage {
            actor: Some(inbound.session),
            ..message
        };

        if recipients.is_empty() {
            // Nobody to tell. Deliberately not a broadcast: an empty answer
            // means either the channel is empty or membership is unknown, and
            // neither of those is "send it to the whole server".
            if !self.roster.is_warm() {
                tracing::warn!("the session-view roster is cold; a text message reached nobody");
            }
            return Actions::new();
        }
        vec![to_sessions(recipients, TEXT_MESSAGE, echo.encode_to_vec())]
    }

    /// Tell `push` about a message, for the people who are not here to read it.
    ///
    /// murmur's `Server::dispatchPushNotifications`, and the two halves have
    /// swapped places: upstream walks its own registration table from inside
    /// the chat path, here the chat service says what happened and the push
    /// service decides whose phone that reaches. It is the only division that
    /// works, since who is *connected* is knowledge this service has and who
    /// registered a device is knowledge it does not.
    ///
    /// The push calls are spawned and never awaited. A notification is
    /// best-effort by definition, and a chat message must not wait on an OAuth
    /// exchange with Google to reach the people who are already looking at the
    /// channel.
    async fn notify_absent(
        &self,
        inbound: &Inbound,
        message: &starling_proto::proto::tcp::TextMessage,
    ) {
        // Only channels. A message addressed at sessions is addressed at people
        // who are connected by definition, and there is nobody absent to tell.
        let mut channels = message.channel_id.clone();
        if !message.tree_id.is_empty() {
            for channel in self
                .expand_channels(inbound.scope, &message.tree_id, true)
                .await
            {
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
            }
        }
        if channels.is_empty() {
            return;
        }
        let Ok(transport) = self.resolver.channel("push") else {
            tracing::debug!("push is unreachable; nobody offline hears about this message");
            return;
        };

        let scope = inbound.scope;
        let title = self.roster.name_of(inbound.session).unwrap_or_default();
        let body = preview(&message.message);
        // Everyone with a session, which includes the sender: they are all
        // looking at the message already. A cold roster skips nobody, so the
        // failure is a phone that buzzes about something on screen rather than
        // one that stays silent about something it should have shown.
        let skip_accounts = self.roster.connected_accounts();

        drop(tokio::spawn(async move {
            let mut client = PushClient::new(transport);
            // One per channel: a mute preference and a `SubscribePush` grant
            // are both per channel, so a message to three of them is three
            // different questions about the same words.
            for channel in channels {
                let answer = client
                    .notify(Notification {
                        scope: Some(Scope { instance: scope }),
                        // Deliberately nobody: this service knows who is
                        // connected, `push` knows who registered a device.
                        accounts: Vec::new(),
                        title: title.clone(),
                        body: body.clone(),
                        data: std::collections::HashMap::new(),
                        skip_accounts: skip_accounts.clone(),
                        channel,
                    })
                    .await;
                match answer {
                    Ok(result) => {
                        let result = result.into_inner();
                        tracing::debug!(
                            channel,
                            delivered = result.delivered,
                            skipped = result.skipped,
                            failed = result.failed,
                            "notified the absent about a message"
                        );
                    }
                    // Debug, not warn: push is optional and a server without it
                    // is a supported deployment, not a broken one.
                    Err(status) => tracing::debug!(
                        channel,
                        %status,
                        "could not tell push about a message"
                    ),
                }
            }
        }));
    }

    /// Who a client's message is actually for.
    ///
    /// The union of the sessions it names outright, the members of every
    /// channel it names, and the members of every channel under a `tree_id`,
    /// minus the sender, who already has it.
    async fn recipients_of(
        &self,
        inbound: &Inbound,
        message: &starling_proto::proto::tcp::TextMessage,
    ) -> Vec<u32> {
        let mut targets: Vec<u32> = Vec::new();
        let mut add = |session: u32| {
            if session != inbound.session && !targets.contains(&session) {
                targets.push(session);
            }
        };

        // A direct message names its recipients, so they need no lookup.
        for session in message.session.iter().copied() {
            add(session);
        }
        for channel in message.channel_id.iter().copied() {
            for session in self.roster.in_channel(channel, inbound.session) {
                add(session);
            }
        }
        // Only pay for the tree walk when a tree was actually addressed.
        let mut channels = message.channel_id.clone();
        if !message.tree_id.is_empty() {
            for channel in self
                .expand_channels(inbound.scope, &message.tree_id, true)
                .await
            {
                if !channels.contains(&channel) {
                    channels.push(channel);
                }
                for session in self.roster.in_channel(channel, inbound.session) {
                    add(session);
                }
            }
        }

        // Everyone who asked to hear this room without sitting in it.
        for session in self.live_subscribers(inbound, &channels).await {
            add(session);
        }
        targets
    }

    /// The connected sessions that asked `push` for live delivery here.
    ///
    /// The fork keeps these in the server object and walks them inline
    /// (`Messages.cpp:2497`); across a service boundary it is one question
    /// asked of the service that holds the subscriptions, which also holds the
    /// permission and mute decisions that go with them.
    ///
    /// Bounded hard, and answered with nobody on any failure. Live delivery is
    /// an extra: a `push` that is down, slow or absent must cost the people it
    /// would have reached, never the message itself.
    async fn live_subscribers(&self, inbound: &Inbound, channels: &[u32]) -> Vec<u32> {
        if channels.is_empty() || !self.live_push {
            return Vec::new();
        }
        let Ok(transport) = self.resolver.channel("push") else {
            return Vec::new();
        };
        let mut client = PushClient::new(transport);
        let query = client.live_subscribers(LiveQuery {
            scope: Some(Scope {
                instance: inbound.scope,
            }),
            channels: channels.to_vec(),
            exclude_session: inbound.session,
        });
        match tokio::time::timeout(LIVE_SUBSCRIBER_BUDGET, query).await {
            Ok(Ok(list)) => list.into_inner().sessions,
            Ok(Err(status)) => {
                tracing::debug!(%status, "push could not name its live subscribers");
                Vec::new()
            }
            Err(_) => {
                // Warned about, unlike the error above: a `push` that answers
                // too slowly delays every message on the server by this budget,
                // and that is worth an operator seeing.
                tracing::warn!(
                    budget_ms = LIVE_SUBSCRIBER_BUDGET.as_millis(),
                    "push did not name its live subscribers in time"
                );
                Vec::new()
            }
        }
    }

    async fn on_envelope(&self, inbound: &Inbound) -> Actions {
        let Ok(envelope) = TextEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        match envelope.body {
            Some(text_envelope::Body::History(request)) => self.on_history(inbound, request).await,
            Some(text_envelope::Body::Schedule(request)) => {
                self.on_schedule(inbound, request).await
            }
            Some(text_envelope::Body::Query(query)) => {
                self.on_schedule_query(inbound, &query).await
            }
            Some(text_envelope::Body::Cancel(cancel)) => {
                self.on_schedule_cancel(inbound, &cancel).await
            }
            // Server-to-client bodies and an empty envelope. Answering a
            // client's own copy of a page or an ack would be echoing its claim
            // about state only the server holds.
            Some(
                text_envelope::Body::Page(_)
                | text_envelope::Body::Edit(_)
                | text_envelope::Body::Delete(_)
                | text_envelope::Body::List(_)
                | text_envelope::Body::Ack(_),
            )
            | None => Actions::new(),
        }
    }

    async fn on_history(
        &self,
        inbound: &Inbound,
        request: starling_proto_fancy::fancy::feature::HistoryRequest,
    ) -> Actions {
        let cursor = request.page.unwrap_or_default();
        let before = Uuid7::parse(&cursor.before_id)
            .map(Uuid7::to_vec)
            .unwrap_or_default();
        let limit = cursor.page_size(50, 200);
        let page = self
            .history(inbound.scope, request.channel, limit, &before)
            .await;
        let messages: Vec<_> = page
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
            .collect();
        // `history` already trimmed to `limit`, so the cursor comes from the
        // page it returned rather than from an unconsumed extra row.
        let page_info = if page.more {
            PageInfo::more_before(
                messages
                    .last()
                    .map(|message| message.message_id.clone())
                    .unwrap_or_default(),
            )
        } else {
            PageInfo::complete()
        };
        let reply = TextEnvelope {
            body: Some(text_envelope::Body::Page(
                starling_proto_fancy::fancy::feature::HistoryPage {
                    channel: request.channel,
                    page: Some(page_info),
                    messages,
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

/// Scheduled messages: the client half.
///
/// The store, the schema and the reasoning about what is kept are in
/// [`scheduled`]; this is the part that answers a client.
impl TextService {
    /// One `ScheduleAck`, addressed at the connection that asked.
    fn ack(inbound: &Inbound, id: &str, status: ScheduleStatus, reason: &str) -> Actions {
        let envelope = TextEnvelope {
            body: Some(text_envelope::Body::Ack(ScheduleAck {
                schedule_id: id.to_owned(),
                status: status as i32,
                reason: reason.to_owned(),
            })),
        };
        vec![to_conn(
            inbound.conn,
            ServiceKind::Text.outer_type(),
            envelope.encode_to_vec(),
        )]
    }

    /// A refusal, which is an ack with a reason a client can show.
    ///
    /// murmur answers most of these with `PermissionDenied` and the rest by
    /// dropping the frame. Neither reaches a compose panel, and a scheduling
    /// dialog that silently does nothing is the worst of the three.
    fn refuse(inbound: &Inbound, reason: &str) -> Actions {
        tracing::debug!(session = inbound.session, reason, "schedule refused");
        Self::ack(inbound, "", ScheduleStatus::ScheduleRefused, reason)
    }

    /// Accept a message for later delivery, or say why not.
    async fn on_schedule(&self, inbound: &Inbound, request: Scheduled) -> Actions {
        // The owner has to outlive the connection, so a peer with no
        // certificate has nothing this can be keyed on. murmur refuses for the
        // same reason (`Messages.cpp:5330`).
        let Some(cert) = self.roster.cert_of(inbound.session) else {
            return Self::refuse(inbound, "scheduling a message needs a client certificate");
        };

        let mut channels = request.channels.clone();
        let mut trees = request.trees.clone();
        channels.sort_unstable();
        channels.dedup();
        trees.sort_unstable();
        trees.dedup();
        if channels.is_empty() && trees.is_empty() {
            return Self::refuse(inbound, "a scheduled message needs a target channel");
        }
        if channels.len() + trees.len() > scheduled::MAX_TARGETS {
            return Self::refuse(inbound, "too many target channels");
        }

        // The same body rules a message sent now would meet, applied now
        // rather than at the due time: a refusal is only useful while somebody
        // is still looking at the compose box.
        let config = self.settings.get(inbound.scope);
        let body = match filter::check(
            &request.body,
            config.allow_html,
            config.text_message_length,
            config.image_message_length,
        ) {
            filter::Verdict::Deliver => request.body.clone(),
            filter::Verdict::Rewritten(text) => text,
            filter::Verdict::TooLong => {
                return Self::refuse(inbound, "that message is too long");
            }
        };
        if body.is_empty() {
            return Self::refuse(inbound, "a scheduled message needs a body");
        }

        let now = now_ms();
        if request.deliver_at_ms <= now {
            return Self::refuse(inbound, "the delivery time must be in the future");
        }
        if request.deliver_at_ms - now > scheduled::MAX_LEAD_MS {
            return Self::refuse(inbound, "the delivery time is too far away");
        }

        if scheduled::pending_count(&self.store, inbound.scope, &cert).await
            >= scheduled::MAX_PENDING_PER_CREATOR
        {
            return Self::refuse(inbound, "you already have too many scheduled messages");
        }

        // Checked here and not again at the due time, which is a deliberate
        // difference from a message sent now. The permission plane answers
        // about a *session*, and the creator of a message due tomorrow may
        // well not have one then; asking on behalf of a session that no longer
        // exists can only be denied, which would make every overnight schedule
        // fail. Rights lost between the two are therefore not caught, and a
        // channel that has to be certain gates entry rather than posting.
        for channel in channels.iter().chain(trees.iter()).copied() {
            if !self
                .permit
                .allows(inbound, channel, Perm::TEXT_MESSAGE.bits())
                .await
            {
                return Self::refuse(inbound, "you may not post in that channel");
            }
        }

        let row = scheduled::Row {
            // The server's, never the peer's: an id a client picks is an id it
            // can collide with somebody else's row.
            id: Uuid7::now(),
            channels,
            trees,
            body,
            deliver_at_ms: request.deliver_at_ms,
            creator_cert: cert,
            creator_name: self.roster.name_of(inbound.session).unwrap_or_default(),
            created_at_ms: now,
            status: ScheduleStatus::SchedulePending as i32,
        };
        if let Err(error) = scheduled::store(&self.store, inbound.scope, &row).await {
            tracing::error!(%error, "could not store a scheduled message");
            return Self::refuse(inbound, "the server could not store that message");
        }

        self.logger.log(
            LogEvent::info(Category::Message, "message scheduled")
                .with("session", inbound.session)
                .with("schedule", row.id.to_string())
                .with("deliver_at_ms", row.deliver_at_ms)
                .with("length", row.body.len()),
        );
        // The timer is asleep until whatever was next; this one may be sooner.
        self.schedules.notify_one();

        Self::ack(
            inbound,
            &row.id.to_string(),
            ScheduleStatus::SchedulePending,
            "",
        )
    }

    /// The caller's own scheduled messages.
    ///
    /// Only ever the caller's: a list keyed on anything but the asking
    /// certificate would hand one user everybody else's drafts.
    async fn on_schedule_query(&self, inbound: &Inbound, query: &ScheduleQuery) -> Actions {
        let rows = match self.roster.cert_of(inbound.session) {
            Some(cert) => {
                scheduled::list(&self.store, inbound.scope, &cert, query.include_finished).await
            }
            // Not a refusal: a peer with no certificate cannot have scheduled
            // anything, so the honest answer is an empty list.
            None => Vec::new(),
        };
        let envelope = TextEnvelope {
            body: Some(text_envelope::Body::List(ScheduleList {
                messages: rows.iter().map(scheduled::Row::to_canon).collect(),
            })),
        };
        vec![to_conn(
            inbound.conn,
            ServiceKind::Text.outer_type(),
            envelope.encode_to_vec(),
        )]
    }

    /// Cancel a pending message, if the caller is the one who scheduled it.
    async fn on_schedule_cancel(&self, inbound: &Inbound, cancel: &ScheduleCancel) -> Actions {
        let Some(id) = Uuid7::parse(&cancel.schedule_id) else {
            return Self::refuse(inbound, "no such scheduled message");
        };
        let cert = self.roster.cert_of(inbound.session).unwrap_or_default();
        let owned = scheduled::get(&self.store, inbound.scope, id)
            .await
            .is_some_and(|row| !cert.is_empty() && row.creator_cert == cert);
        // One answer for "not yours" and "not there": telling them apart would
        // let anyone probe for other people's schedule ids.
        if !owned {
            return Self::refuse(inbound, "no such scheduled message");
        }
        if !scheduled::finish(
            &self.store,
            inbound.scope,
            id,
            ScheduleStatus::ScheduleCancelled,
        )
        .await
        {
            return Self::refuse(inbound, "that message is no longer pending");
        }

        self.logger.log(
            LogEvent::info(Category::Message, "scheduled message cancelled")
                .with("session", inbound.session)
                .with("schedule", id.to_string()),
        );
        // What was next may have just gone away.
        self.schedules.notify_one();
        Self::ack(
            inbound,
            &cancel.schedule_id,
            ScheduleStatus::ScheduleCancelled,
            "",
        )
    }

    /// Deliver everything due in `scope`, and answer when the next one is.
    ///
    /// Returns `None` when nothing is pending, which is the timer's cue to
    /// sleep until something wakes it.
    async fn deliver_due(&self, scope: u32) -> Option<u64> {
        // A cold roster addresses nobody, and a message delivered to nobody is
        // marked delivered and gone, so a due message waits for membership.
        //
        // It asks for a wake-up shortly rather than reporting the real due
        // time, which is in the past and would spin, or nothing, which would
        // sleep for a day over a message that is due now. Nothing is said
        // unless something is actually waiting: a cold roster with an empty
        // table is a service that has just started.
        if !self.roster.is_warm() {
            let next = scheduled::next_due(&self.store, scope).await?;
            if next > now_ms() {
                return Some(next);
            }
            tracing::warn!("the session-view roster is cold; a due message is waiting on it");
            return Some(now_ms() + COLD_ROSTER_RETRY_MS);
        }
        for row in scheduled::due(&self.store, scope, now_ms()).await {
            // Claimed before it is sent, not after. The claim is the same
            // conditional update a cancel uses, so exactly one of the two can
            // win and a message can never be posted to a channel twice. The
            // cost is the other direction: a crash between the claim and the
            // send loses that message rather than repeating it, which is the
            // side to fail on for something that is already public.
            if !scheduled::finish(
                &self.store,
                scope,
                row.id,
                ScheduleStatus::ScheduleDelivered,
            )
            .await
            {
                continue;
            }
            self.deliver(scope, &row).await;
        }
        scheduled::next_due(&self.store, scope).await
    }

    /// Post one stored message to the channels it named.
    async fn deliver(&self, scope: u32, row: &scheduled::Row) {
        let mut wanted = row.channels.clone();
        if !row.trees.is_empty() {
            for channel in self.expand_channels(scope, &row.trees, true).await {
                if !wanted.contains(&channel) {
                    wanted.push(channel);
                }
            }
        }

        let mut recipients: Vec<u32> = Vec::new();
        for channel in &wanted {
            for session in self.roster.in_channel(*channel, 0) {
                if !recipients.contains(&session) {
                    recipients.push(session);
                }
            }
        }

        // Attributed to the creator only while the same certificate is still
        // connected. Otherwise it goes out with no actor, which every client
        // renders as a message from the server, exactly as murmur does
        // (`Server.cpp:2477`).
        let actor = self.roster.session_with_cert(&row.creator_cert);
        let sent_at = now_ms();
        let message = starling_proto::proto::tcp::TextMessage {
            actor,
            session: Vec::new(),
            channel_id: row.channels.clone(),
            tree_id: row.trees.clone(),
            message: row.body.clone(),
            message_id: Some(Uuid7::now().to_string()),
            timestamp: Some(sent_at),
            ..starling_proto::proto::tcp::TextMessage::default()
        };

        self.logger.log(
            LogEvent::info(Category::Message, "scheduled message delivered")
                .with("schedule", row.id.to_string())
                .with("recipients", recipients.len())
                .with("length", row.body.len()),
        );

        // Stored whether or not anybody was there to read it: history is what
        // makes a message delivered into an empty channel worth scheduling.
        for channel in &row.channels {
            let stored = StoredMessage {
                id: Vec::new(),
                channel: *channel,
                sender_account: 0,
                sender_name: row.creator_name.clone(),
                body: row.body.clone(),
                sent_at_ms: sent_at,
            };
            let _ = self.record(scope, &stored).await;
        }

        let _ = self.events.send(MessageEvent {
            sender_session: actor.unwrap_or_default(),
            sender_account: 0,
            sender_name: row.creator_name.clone(),
            sender_registered: false,
            channels: row.channels.clone(),
            sessions: recipients.clone(),
            tree: row.trees.clone(),
            body: row.body.clone(),
            sent_at_ms: sent_at,
            // The server sent it. A watcher that could not tell this from a
            // message typed just now would attribute it to a session that may
            // be doing something else entirely.
            from_client: false,
        });

        if recipients.is_empty() {
            return;
        }
        self.fanout.push(to_sessions(
            recipients,
            TEXT_MESSAGE,
            message.encode_to_vec(),
        ));
    }

    /// Deliver due messages until shutdown, sleeping until the next one.
    ///
    /// Woken early by [`Self::schedules`] when a schedule or a cancel changes
    /// what "next" means; otherwise it sleeps, capped at a day so a delivery a
    /// month out costs a handful of wakeups rather than one long timer nothing
    /// can adjust. murmur's reaper does the same (`Server.cpp:2443`).
    async fn deliver_loop(self: Arc<Self>, scopes: Vec<u32>) {
        loop {
            let mut next: Option<u64> = None;
            for scope in &scopes {
                if let Some(due) = self.deliver_due(*scope).await {
                    next = Some(next.map_or(due, |held: u64| held.min(due)));
                }
            }
            let wait = next
                .map_or(MAX_DELIVERY_SLEEP_MS, |due| {
                    due.saturating_sub(now_ms()).min(MAX_DELIVERY_SLEEP_MS)
                })
                // A floor, so a row that is due but could not be claimed (a
                // cancel won the race) cannot spin this loop.
                .max(MIN_DELIVERY_SLEEP_MS);

            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_millis(wait)) => {}
                () = self.schedules.notified() => {}
            }
        }
    }
}

/// The line a notification shows under the sender's name.
///
/// Markup comes off first: the body is delivered to clients as it was sent,
/// tags and all, and a phone shows a notification as plain text, so a message
/// typed in a formatting client would arrive on a lock screen as `<b>hi</b>`.
/// Then 200 characters of what is left, counted in characters and not bytes,
/// so the cut never lands inside one.
fn preview(body: &str) -> String {
    filter::strip_html(body)
        .chars()
        .take(PREVIEW_CHARS)
        .collect()
}

impl Serve for TextService {
    const NAME: &'static str = "text";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        store.migrate(scheduled::SCHEMA).await?;
        let settings = Settings::new(ctx.resolver.clone()).logging_to(ctx.logger.clone());
        ctx.health.gate(VIEW_GATE);
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            permit: Permit::new(ctx.resolver.clone()),
            settings,
            resolver: ctx.resolver,
            roster: Arc::new(Roster::new()),
            events: broadcast::channel(EVENT_BACKLOG).0,
            schedules: tokio::sync::Notify::new(),
            live_push: ctx
                .config
                .services
                .get("push")
                .is_none_or(|push| push.enabled),
        }))
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let follower = Arc::clone(&self.roster).follow(ctx.clone(), Self::NAME, VIEW_GATE);
        // Started here rather than in `build`, so a service that is only
        // constructed (a test, a config check) never posts anything.
        let deliveries = tokio::spawn(Arc::clone(&self).deliver_loop(ctx.instances()));
        // Here rather than in `build` for the same reason, and because a
        // subscription started there had nowhere to be stopped: it is a stream
        // on `server-config`, which cannot finish its own drain while this
        // service holds one open.
        let watchers = self.settings.watch(&ctx.instances());
        ctx.shutdown.wait().await;
        follower.abort();
        deliveries.abort();
        for watcher in watchers {
            watcher.abort();
        }
        Ok(())
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
        service_with(starling_runtime::settings::defaults(1)).await
    }

    /// The same service, with the operator's settings pinned to `config`.
    ///
    /// Pinned rather than fetched: the point of a §5 test is that the *value*
    /// decides the outcome, so the value has to be the only thing that varies.
    async fn service_with(
        config: starling_proto_fancy::serverconfig::Snapshot,
    ) -> Arc<TextService> {
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
        store
            .migrate(scheduled::SCHEMA)
            .await
            .expect("the scheduled-message schema");
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
            settings: Settings::fixed(resolver.clone(), config),
            resolver,
            roster: Arc::new(Roster::new()),
            events: broadcast::channel(EVENT_BACKLOG).0,
            schedules: tokio::sync::Notify::new(),
            // On, so the path a message takes in production is the path these
            // tests take; `push` is unreachable here, which is the case the
            // budget and the empty answer exist for.
            live_push: true,
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

    /// One `TextMessage` frame, as the gateway would deliver it.
    fn frame(body: &str) -> Inbound {
        use prost::Message as _;
        Inbound {
            conn: 1,
            session: 7,
            scope: 1,
            type_id: TEXT_MESSAGE,
            gateway: String::new(),
            payload: starling_proto::proto::tcp::TextMessage {
                channel_id: vec![0],
                message: body.to_owned(),
                ..starling_proto::proto::tcp::TextMessage::default()
            }
            .encode_to_vec(),
        }
    }

    /// A message addressed at `channels` and `sessions`, from session 7.
    fn addressed_to(
        channels: Vec<u32>,
        sessions: Vec<u32>,
    ) -> starling_proto::proto::tcp::TextMessage {
        starling_proto::proto::tcp::TextMessage {
            channel_id: channels,
            session: sessions,
            message: "hello".to_owned(),
            ..starling_proto::proto::tcp::TextMessage::default()
        }
    }

    /// Sessions 7 and 8 in channel 4, session 9 in channel 9.
    fn warm(service: &TextService) {
        use starling_proto_fancy::sessionview::{Session, Sessions, ViewEvent, view_event};
        let member = |session, channel| Session {
            session,
            channel,
            ..Session::default()
        };
        let _ = service.roster.apply(ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                sessions: vec![member(7, 4), member(8, 4), member(9, 9)],
                ..Sessions::default()
            })),
        });
    }

    #[tokio::test]
    async fn a_message_reaches_its_channel_and_not_the_whole_server() {
        // The finding: fan-out named the speaker as an exclusion on a Send that
        // named nobody, so a message to channel 4 reached session 9 in channel
        // 9 as well -- and everybody else on the server.
        let service = service().await;
        warm(&service);

        let recipients = service
            .recipients_of(&frame("hello"), &addressed_to(vec![4], Vec::new()))
            .await;

        assert_eq!(recipients, vec![8], "only the other member of channel 4");
    }

    #[tokio::test]
    async fn a_cold_roster_sends_a_message_to_nobody_rather_than_everybody() {
        // Failing open here would be the leak wearing a fallback.
        let service = service().await;

        let recipients = service
            .recipients_of(&frame("hello"), &addressed_to(vec![4], Vec::new()))
            .await;

        assert!(recipients.is_empty());
        assert!(!service.roster.is_warm());
    }

    #[tokio::test]
    async fn a_direct_message_reaches_the_sessions_it_names() {
        // A session named outright needs no membership lookup, and must still
        // arrive when it is sitting in a different channel.
        let service = service().await;
        warm(&service);

        let recipients = service
            .recipients_of(&frame("hello"), &addressed_to(Vec::new(), vec![9]))
            .await;

        assert_eq!(recipients, vec![9]);
    }

    #[tokio::test]
    async fn the_sender_is_never_told_its_own_message_twice() {
        // Session 7 is both the sender and a member of channel 4, and names
        // itself directly as well.
        let service = service().await;
        warm(&service);

        let recipients = service
            .recipients_of(&frame("hello"), &addressed_to(vec![4], vec![7, 8]))
            .await;

        assert_eq!(recipients, vec![8]);
    }

    /// The `DenyType` of a `PermissionDenied` action, if that is what it is.
    fn deny_type(actions: &Actions) -> Option<i32> {
        use prost::Message as _;
        use starling_proto_fancy::control::server_action::Action;
        let Some(Action::Send(send)) = actions.first().and_then(|action| action.action.as_ref())
        else {
            return None;
        };
        starling_proto::proto::tcp::PermissionDenied::decode(send.payload.as_slice())
            .ok()
            .and_then(|denied| denied.r#type)
    }

    #[tokio::test]
    async fn the_text_message_length_decides_whether_a_message_is_delivered() {
        // §5's first entry. The limit was applied to comments and to nothing
        // else, so an operator who set it watched clients keep posting past it.
        //
        // The same body, twice, with only the setting different, asserting it
        // round-trips through the API would reproduce the bug being fixed.
        use starling_proto::proto::tcp::permission_denied::DenyType;
        let body = "x".repeat(64);

        let strict = service_with(starling_proto_fancy::serverconfig::Snapshot {
            text_message_length: 10,
            ..starling_runtime::settings::defaults(1)
        })
        .await;
        let refusal = strict.on_text_message(&frame(&body)).await;
        assert_eq!(
            deny_type(&refusal),
            Some(DenyType::TextTooLong as i32),
            "the client must be told which limit it met, not left in silence"
        );

        // With a limit that admits it, the message reaches the permission
        // check instead, which denies here, because these tests point at a
        // `permissions` nothing is serving. A different refusal is the proof
        // the length check is no longer the one refusing.
        let lenient = service_with(starling_proto_fancy::serverconfig::Snapshot {
            text_message_length: 1_000,
            ..starling_runtime::settings::defaults(1)
        })
        .await;
        assert_eq!(
            deny_type(&lenient.on_text_message(&frame(&body)).await),
            Some(DenyType::Permission as i32),
            "a message under the limit must get past the length check"
        );
    }

    #[tokio::test]
    async fn a_length_check_happens_before_the_permission_round_trip() {
        // murmur's order (`Messages.cpp:2322`), and it is what makes the test
        // above possible: a body that is too long is refused whatever the
        // sender may do, with no round trip in front of the refusal.
        use starling_proto::proto::tcp::permission_denied::DenyType;
        let service = service_with(starling_proto_fancy::serverconfig::Snapshot {
            text_message_length: 1,
            ..starling_runtime::settings::defaults(1)
        })
        .await;
        assert_eq!(
            deny_type(&service.on_text_message(&frame("far too long")).await),
            Some(DenyType::TextTooLong as i32)
        );
    }

    // -- Scheduled messages -------------------------------------------------

    /// The certificate session 7 presented in [`warm_with_certs`].
    const ALICE: &[u8] = b"alice-cert";
    /// Session 8's.
    const BOB: &[u8] = b"bob-cert";

    /// As [`warm`], but with certificates and names, which scheduling needs.
    fn warm_with_certs(service: &TextService) {
        use starling_proto_fancy::sessionview::{Session, Sessions, ViewEvent, view_event};
        let member = |session, channel, cert: &[u8], name: &str| Session {
            session,
            channel,
            cert_hash: cert.to_vec(),
            name: name.to_owned(),
            ..Session::default()
        };
        let _ = service.roster.apply(ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                sessions: vec![
                    member(7, 4, ALICE, "alice"),
                    member(8, 4, BOB, "bob"),
                    member(9, 9, b"carol-cert", "carol"),
                ],
                ..Sessions::default()
            })),
        });
    }

    /// One `TextEnvelope` frame carrying `body`, from session 7.
    fn envelope(body: text_envelope::Body) -> Inbound {
        Inbound {
            conn: 1,
            session: 7,
            scope: 1,
            type_id: ServiceKind::Text.outer_type(),
            gateway: String::new(),
            payload: TextEnvelope { body: Some(body) }.encode_to_vec(),
        }
    }

    /// The `ScheduleAck` in `actions`.
    fn ack_of(actions: &Actions) -> ScheduleAck {
        use starling_proto_fancy::control::server_action;
        let Some(server_action::Action::Send(send)) =
            actions.first().and_then(|a| a.action.as_ref())
        else {
            panic!("expected a Send");
        };
        let Some(text_envelope::Body::Ack(ack)) = TextEnvelope::decode(send.payload.as_slice())
            .expect("a text envelope")
            .body
        else {
            panic!("expected an ack");
        };
        ack
    }

    /// A pending row due at `deliver_at_ms`, owned by `cert`.
    fn pending(cert: &[u8], deliver_at_ms: u64) -> scheduled::Row {
        scheduled::Row {
            id: Uuid7::now(),
            channels: vec![4],
            trees: Vec::new(),
            body: "later".to_owned(),
            deliver_at_ms,
            creator_cert: cert.to_vec(),
            creator_name: "alice".to_owned(),
            created_at_ms: now_ms(),
            status: ScheduleStatus::SchedulePending as i32,
        }
    }

    #[tokio::test]
    async fn scheduling_without_a_certificate_is_refused_rather_than_stored() {
        // The owner has to outlive the connection, and a session id does not.
        // murmur refuses for the same reason (`Messages.cpp:5330`).
        let service = service().await;
        warm(&service); // no certificates in this roster
        let actions = service
            .frame(envelope(text_envelope::Body::Schedule(Scheduled {
                channels: vec![4],
                body: "later".to_owned(),
                deliver_at_ms: now_ms() + 60_000,
                ..Scheduled::default()
            })))
            .await;
        assert_eq!(
            ack_of(&actions).status,
            ScheduleStatus::ScheduleRefused as i32
        );
    }

    #[tokio::test]
    async fn a_delivery_time_in_the_past_is_refused_with_a_reason() {
        // The client validates this too, and a server that trusted it would be
        // trusting a clock it does not own.
        let service = service().await;
        warm_with_certs(&service);
        let actions = service
            .frame(envelope(text_envelope::Body::Schedule(Scheduled {
                channels: vec![4],
                body: "later".to_owned(),
                deliver_at_ms: now_ms() - 1,
                ..Scheduled::default()
            })))
            .await;
        let ack = ack_of(&actions);
        assert_eq!(ack.status, ScheduleStatus::ScheduleRefused as i32);
        assert!(
            ack.reason.contains("future"),
            "a refusal a panel can show, not an empty ack: {}",
            ack.reason
        );
    }

    #[tokio::test]
    async fn a_list_shows_the_asking_certificate_its_own_messages_and_no_others() {
        // Anything else hands one user everybody else's drafts.
        let service = service().await;
        warm_with_certs(&service);
        for cert in [ALICE, BOB] {
            scheduled::store(&service.store, 1, &pending(cert, now_ms() + 60_000))
                .await
                .expect("stored");
        }

        let actions = service
            .frame(envelope(text_envelope::Body::Query(ScheduleQuery {
                include_finished: false,
            })))
            .await;
        use starling_proto_fancy::control::server_action;
        let Some(server_action::Action::Send(send)) =
            actions.first().and_then(|a| a.action.as_ref())
        else {
            panic!("expected a Send");
        };
        let Some(text_envelope::Body::List(list)) = TextEnvelope::decode(send.payload.as_slice())
            .expect("a text envelope")
            .body
        else {
            panic!("expected a list");
        };
        assert_eq!(list.messages.len(), 1);
        assert_eq!(list.messages[0].creator_cert, ALICE);
    }

    #[tokio::test]
    async fn only_the_certificate_that_scheduled_a_message_may_cancel_it() {
        // And "not yours" answers the same as "not there", so the id space
        // cannot be probed.
        let service = service().await;
        warm_with_certs(&service);
        let row = pending(BOB, now_ms() + 60_000);
        scheduled::store(&service.store, 1, &row)
            .await
            .expect("stored");

        let actions = service
            .frame(envelope(text_envelope::Body::Cancel(ScheduleCancel {
                schedule_id: row.id.to_string(),
            })))
            .await;
        assert_eq!(
            ack_of(&actions).status,
            ScheduleStatus::ScheduleRefused as i32
        );
        assert_eq!(
            scheduled::get(&service.store, 1, row.id)
                .await
                .map(|held| held.status),
            Some(ScheduleStatus::SchedulePending as i32),
            "somebody else's message stays pending"
        );
    }

    #[tokio::test]
    async fn a_due_message_is_delivered_once_and_only_once() {
        // The claim is a conditional update, so a second pass over the same
        // row finds nothing to claim. Without it, two timer ticks (or two
        // pods) would each post the same message to the channel.
        let service = service().await;
        warm_with_certs(&service);
        let row = pending(ALICE, now_ms() - 1);
        scheduled::store(&service.store, 1, &row)
            .await
            .expect("stored");

        let mut delivered = service.fanout.subscribe();
        let _ = service.deliver_due(1).await;
        let _ = service.deliver_due(1).await;

        assert!(delivered.try_recv().is_ok(), "the first pass posts it");
        assert!(
            delivered.try_recv().is_err(),
            "the second pass must find nothing to claim"
        );
        assert_eq!(
            scheduled::get(&service.store, 1, row.id)
                .await
                .map(|held| held.status),
            Some(ScheduleStatus::ScheduleDelivered as i32)
        );
    }

    #[tokio::test]
    async fn a_cancelled_message_is_never_delivered() {
        let service = service().await;
        warm_with_certs(&service);
        let row = pending(ALICE, now_ms() - 1);
        scheduled::store(&service.store, 1, &row)
            .await
            .expect("stored");
        assert!(
            scheduled::finish(&service.store, 1, row.id, ScheduleStatus::ScheduleCancelled).await
        );

        let mut delivered = service.fanout.subscribe();
        let _ = service.deliver_due(1).await;
        assert!(delivered.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_cold_roster_holds_a_due_message_rather_than_delivering_it_to_nobody() {
        // Delivering into an unknown roster would mark it delivered and lose
        // it, which is the one outcome a scheduled message cannot survive.
        let service = service().await;
        let row = pending(ALICE, now_ms() - 1);
        scheduled::store(&service.store, 1, &row)
            .await
            .expect("stored");

        // It asks to be woken again rather than sleeping over it, and the row
        // is still pending.
        let next = service.deliver_due(1).await.expect("a retry, not a day");
        assert!(next <= now_ms() + COLD_ROSTER_RETRY_MS);
        assert_eq!(
            scheduled::get(&service.store, 1, row.id)
                .await
                .map(|held| held.status),
            Some(ScheduleStatus::SchedulePending as i32),
            "still pending, to be delivered once membership is known"
        );
    }

    #[tokio::test]
    async fn a_delivery_is_attributed_to_its_creator_only_while_they_are_connected() {
        // murmur sends it with no actor otherwise, which every client renders
        // as a message from the server (`Server.cpp:2477`).
        let service = service().await;
        warm_with_certs(&service);
        let mut delivered = service.fanout.subscribe();

        scheduled::store(&service.store, 1, &pending(ALICE, now_ms() - 1))
            .await
            .expect("stored");
        let _ = service.deliver_due(1).await;
        assert_eq!(
            actor_of(&delivered.try_recv().expect("a delivery")),
            Some(7)
        );

        // The same message from somebody who has since disconnected.
        service.roster.remove(7);
        scheduled::store(&service.store, 1, &pending(ALICE, now_ms() - 1))
            .await
            .expect("stored");
        let _ = service.deliver_due(1).await;
        assert_eq!(actor_of(&delivered.try_recv().expect("a delivery")), None);
    }

    #[test]
    fn a_notification_preview_is_the_words_and_not_the_markup() {
        // The body reaches clients as it was sent, tags included; a lock screen
        // renders none of them, so `<b>hi</b>` would arrive verbatim.
        assert_eq!(preview("<b>hi</b> there"), "hi there");
    }

    #[test]
    fn a_long_message_is_cut_by_characters_and_never_inside_one() {
        // murmur's 200, and counted the way a `String` can actually be cut: a
        // byte-wise truncation lands mid-character on the first non-ASCII
        // message and panics.
        let long = "é".repeat(PREVIEW_CHARS + 50);
        let preview = preview(&long);
        assert_eq!(preview.chars().count(), PREVIEW_CHARS);
        assert!(preview.starts_with('é'));
    }

    #[tokio::test]
    async fn a_message_nobody_is_there_for_still_goes_to_push() {
        // The case push exists for. `push` is unreachable in these tests, so
        // what is asserted is that the attempt is made and that failing to
        // reach an optional service never touches delivery.
        let service = service().await;
        let message = starling_proto::proto::tcp::TextMessage {
            channel_id: vec![7],
            message: "anybody there?".to_owned(),
            ..starling_proto::proto::tcp::TextMessage::default()
        };
        let inbound = Inbound {
            scope: 1,
            conn: 1,
            session: 7,
            type_id: TEXT_MESSAGE,
            gateway: String::new(),
            payload: message.encode_to_vec(),
        };
        service.notify_absent(&inbound, &message).await;
    }

    /// The actor on the `TextMessage` a delivery pushed.
    fn actor_of(action: &starling_proto_fancy::control::ServerAction) -> Option<u32> {
        use starling_proto_fancy::control::server_action;
        let Some(server_action::Action::Send(send)) = action.action.as_ref() else {
            panic!("expected a Send");
        };
        starling_proto::proto::tcp::TextMessage::decode(send.payload.as_slice())
            .expect("a text message")
            .actor
    }
}
