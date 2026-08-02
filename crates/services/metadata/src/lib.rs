//! `metadata` — the channel tree and who is in it.
//!
//! One actor per virtual server, sharded by server id: the guild-process
//! pattern, and simultaneously the answer to running several virtual servers
//! (`docs/ARCHITECTURE.md` §6). Because it is the single writer of channel
//! state, the order it applies mutations is a **total order**, and the
//! gateway's single-writer socket carries that order through to the wire — so
//! a client can never see a `UserState` naming a channel before the
//! `ChannelState` that created it.
//!
//! The database is not a read path. The tree is loaded once at boot and kept in
//! memory; writes leave behind it (`docs/STORAGE.md` L7, D1).

pub mod channel;
pub mod ids;
pub mod serialize;
pub mod tree_actor;

pub use channel::{Channel, ChannelStore, ChannelTree};
pub use ids::{ChannelId, ROOT_CHANNEL};
pub use serialize::{ChannelEdit, channel_state, to_proto};
pub use tree_actor::{ListenRefusal, Listened, Removal, TreeLimits, Trees, Unlistened};

use std::sync::Arc;

use crate::tree_actor::FLAG_HIDDEN;
use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::metadata::metadata_server::{Metadata, MetadataServer};
use starling_proto_fancy::metadata::{
    ChannelResult, CreateRequest, EnterRequest, EnterResult, LeaveRequest, LinkRequest,
    ListenRequest, ListenResult, RemoveRequest, RestoreListenersRequest, Tree, TreeEvent,
    TreeRequest, UpdateRequest, listen_refusal,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::permit::{Permit, permission_denied, refused};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_sessions};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::settings::Settings;
use starling_runtime::storage::{Migration, Store};
use starling_runtime::trail::{self, Record, Trail};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

/// The schema. Typed columns, one row per channel, and the index the parent
/// lookup actually uses (`docs/STORAGE.md` L1, L2).
const SCHEMA: &[Migration<'static>] = &[
    Migration::new(
        "0001_channel",
        &[
            "CREATE TABLE IF NOT EXISTS channel (\
             server_id BIGINT NOT NULL, id BIGINT NOT NULL, parent_id BIGINT NULL, \
             name VARCHAR(190) NOT NULL, description TEXT NOT NULL, \
             position INTEGER NOT NULL, max_users INTEGER NOT NULL, flags INTEGER NOT NULL, \
             expiry_mode INTEGER NOT NULL, expiry_duration_s INTEGER NOT NULL, \
             created_at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, id))",
            "CREATE INDEX IF NOT EXISTS ix_channel_parent ON channel(server_id, parent_id)",
            "CREATE TABLE IF NOT EXISTS channel_link (\
             server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, linked_id BIGINT NOT NULL, \
             PRIMARY KEY (server_id, channel_id, linked_id))",
        ],
    ),
    // murmur's `channel_listeners`, and the two odd-looking columns are the
    // whole design:
    //
    // * keyed by **account**, not by session, because a session is one visit and
    //   the point of the table is that the listener outlives it;
    // * `enabled` rather than deleting the row, because the volume has to
    //   survive un-listening — a user who turns a room off and back on gets the
    //   level they chose, not a silent reset to full.
    //
    // One statement, and deliberately: the only query against this table is
    // "every listener of one account on one server", and the primary key is a
    // left prefix of exactly that — so a separate index on
    // `(server_id, account_id)` would be a second copy of one the table already
    // has, paid for on every write forever. It also costs a `fsync` at boot,
    // which is not free either: every service migrates its own SQLite file at
    // once, and one more DDL statement in that scrum measured **1.4 seconds**
    // of added start-up before this was cut back to a single statement.
    Migration::new(
        "0002_channel_listener",
        &["CREATE TABLE IF NOT EXISTS channel_listener (\
             server_id BIGINT NOT NULL, account_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, \
             volume_adjustment REAL NOT NULL, enabled INTEGER NOT NULL, \
             PRIMARY KEY (server_id, account_id, channel_id))"],
    ),
];

/// How many tree events a subscriber may fall behind.
const EVENT_BUFFER: usize = 256;

/// The service.
#[derive(Debug)]
pub struct MetadataService {
    trees: Trees,
    events: broadcast::Sender<TreeEvent>,
    fanout: Fanout,
    logger: Logger,
    /// Asks `permissions` before every mutation a client asks for.
    ///
    /// Not an `Option`. A service that could be built without one would have a
    /// state in which every check is skipped, and nothing at the call site
    /// would look different.
    permit: Permit,
    /// How to reach `session-view`, to learn who is connected.
    ///
    /// Needed because announcing a *hidden* channel is addressed rather than
    /// broadcast: the recipient list has to be built before it can be filtered.
    resolver: Resolver,
    /// The operator-facing record of channel edits.
    ///
    /// Separate from `logger`: that is the server's own diagnostic log, this is
    /// what an operator queries and whose chain they verify. The same action
    /// belongs in both, and neither is derivable from the other.
    trail: Trail,
    /// The ceilings an operator sets on the tree.
    ///
    /// Live rather than read at boot: murmur's `setLiveConf` applies a changed
    /// `channelnestinglimit` to the next channel anybody creates, not to the
    /// next server anybody restarts.
    settings: Settings,
    /// Where channel listeners are kept between visits.
    ///
    /// `None` when the deployment has no storage configured, which is a running
    /// server with listeners that last exactly one session — the same degradation
    /// a guest gets, rather than a refusal.
    store: Option<Store>,
}

/// Which listener limit refused a request, for the log.
const fn describe_refusal(refusal: ListenRefusal) -> &'static str {
    match refusal {
        ListenRefusal::ChannelFull => "listeners_per_channel",
        ListenRefusal::UserFull => "listeners_per_user",
    }
}

/// The same refusal on the wire, for the caller to turn into a client reply.
const fn refusal_limit(refusal: ListenRefusal) -> listen_refusal::Limit {
    match refusal {
        ListenRefusal::ChannelFull => listen_refusal::Limit::ChannelFull,
        ListenRefusal::UserFull => listen_refusal::Limit::UserFull,
    }
}

/// Tell every client that a removed channel took some listeners with it.
///
/// One `UserState` per affected session, as murmur sends
/// (`Server.cpp:2202`), rather than one message listing everybody: the field is
/// `listening_channel_remove` on a *user*, so there is nowhere in the message
/// to put a second one.
fn unlisten_broadcast(unlistened: &[Unlistened]) -> Actions {
    unlistened
        .iter()
        .map(|entry| {
            let payload = starling_proto::proto::tcp::UserState {
                session: Some(entry.session),
                listening_channel_remove: entry.channels.clone(),
                ..starling_proto::proto::tcp::UserState::default()
            }
            .encode_to_vec();
            to_sessions(Vec::new(), USER_STATE, payload)
        })
        .collect()
}

/// The client on `session`, as an audit actor.
///
/// A free function because the only alternative is spelling the nested `Who`
/// out at every call site, and a two-level enum literal repeated is a two-level
/// enum literal eventually built wrong.
fn session_actor(session: u32) -> starling_proto_fancy::common::Actor {
    starling_proto_fancy::common::Actor {
        who: Some(starling_proto_fancy::common::actor::Who::Session(session)),
    }
}

impl MetadataService {
    /// The trees, for the operator surface and tests.
    #[must_use]
    pub fn trees(&self) -> &Trees {
        &self.trees
    }

    /// The ceilings in force for `scope` right now.
    ///
    /// Only the client path asks for these. The gRPC surface passes
    /// [`TreeLimits::UNLIMITED`], because an operator building a tree through
    /// `operator-api` is the person who set the limit and refusing them their
    /// own ceiling turns a deliberate action into a mystery — which is where
    /// murmur draws the same line: `canNest` and the count check are in
    /// `msgChannelState`, the *client* handler.
    fn limits(&self, scope: u32) -> TreeLimits {
        TreeLimits::from(&self.settings.get(scope))
    }

    /// Push a `ChannelState` to every client, so the tree they render is the
    /// tree that exists.
    fn announce(&self, event: TreeEvent) {
        if let Some(starling_proto_fancy::metadata::tree_event::Event::Upsert(channel)) =
            &event.event
        {
            let payload = channel_state(channel).encode_to_vec();
            self.fanout
                .push(to_sessions(Vec::new(), CHANNEL_STATE, payload));
        }
        let _ = self.events.send(event);
    }
}

/// Upstream `ChannelState`.
const CHANNEL_STATE: u16 = 7;
/// Upstream `ChannelRemove`.
const CHANNEL_REMOVE: u16 = 6;
/// Upstream `UserState`, used to relocate an occupant of a reaped channel.
const USER_STATE: u16 = 9;

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct MetadataRpc(Arc<MetadataService>);

#[tonic::async_trait]
impl Metadata for MetadataRpc {
    async fn get_tree(&self, request: Request<TreeRequest>) -> Result<Response<Tree>, Status> {
        let scope = scope_of(request.into_inner().scope);
        Ok(Response::new(self.0.trees.snapshot(scope)))
    }

    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<TreeEvent, Status>>;

    async fn watch(
        &self,
        request: Request<TreeRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let scope = scope_of(request.into_inner().scope);
        let (tx, rx) = tokio::sync::mpsc::channel(EVENT_BUFFER);
        let _ = tx
            .send(Ok(TreeEvent {
                event: Some(starling_proto_fancy::metadata::tree_event::Event::Snapshot(
                    self.0.trees.snapshot(scope),
                )),
            }))
            .await;

        let mut events = self.0.events.subscribe();
        drop(tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if tx.send(Ok(event)).await.is_err() {
                    return;
                }
            }
        }));
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn create(
        &self,
        request: Request<CreateRequest>,
    ) -> Result<Response<ChannelResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let result = self
            .0
            .trees
            .create(scope, req.channel, req.temporary, TreeLimits::UNLIMITED);
        if let Some(channel) = &result.channel {
            self.0.announce(TreeEvent {
                event: Some(starling_proto_fancy::metadata::tree_event::Event::Upsert(
                    channel.clone(),
                )),
            });
        }
        Ok(Response::new(result))
    }

    async fn update(
        &self,
        request: Request<UpdateRequest>,
    ) -> Result<Response<ChannelResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let result = self.0.trees.update(
            scope,
            req.channel,
            req.values,
            &req.fields,
            TreeLimits::UNLIMITED,
        );
        if let Some(channel) = &result.channel {
            self.0.announce(TreeEvent {
                event: Some(starling_proto_fancy::metadata::tree_event::Event::Upsert(
                    channel.clone(),
                )),
            });
        }
        Ok(Response::new(result))
    }

    async fn remove(
        &self,
        request: Request<RemoveRequest>,
    ) -> Result<Response<ChannelResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let removal = self.0.trees.remove(scope, req.channel);
        if removal.result.applied {
            // Ahead of the `ChannelRemove`, as murmur orders it
            // (`Server.cpp:2193` before `:2210`), and the order is the point: a
            // `listening_channel_remove` naming a channel the client has already
            // deleted from its tree is one it cannot match to anything.
            for action in unlisten_broadcast(&removal.unlistened) {
                self.0.fanout.push(action);
            }
            let payload = starling_proto::proto::tcp::ChannelRemove {
                channel_id: req.channel,
            }
            .encode_to_vec();
            self.0
                .fanout
                .push(to_sessions(Vec::new(), CHANNEL_REMOVE, payload));
            let _ = self.0.events.send(TreeEvent {
                event: Some(starling_proto_fancy::metadata::tree_event::Event::Removed(
                    req.channel,
                )),
            });
        }
        Ok(Response::new(removal.result))
    }

    async fn link(&self, request: Request<LinkRequest>) -> Result<Response<ChannelResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let result = self
            .0
            .trees
            .link(scope, req.channel, &req.link, &req.unlink);
        if result.applied {
            // Both ends, because the edge was written into both: a client told
            // only about the channel the operator named would render a link
            // that the other channel does not agree it has.
            self.0
                .announce_links(scope, req.channel, &req.link, &req.unlink)
                .await;
        }
        Ok(Response::new(result))
    }

    async fn enter(&self, request: Request<EnterRequest>) -> Result<Response<EnterResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let result = self.0.trees.enter(scope, req.session, req.channel);

        // Who is where is the second question an operator asks after who is
        // connected, and a refusal here is what a user experiences as "I click
        // the channel and nothing happens".
        if result.applied {
            self.0.logger.log(
                LogEvent::info(Category::Channel, "user entered a channel")
                    .with("session", req.session)
                    .with("channel", req.channel)
                    .with("previous", result.previous.unwrap_or(0))
                    .with("scope", scope),
            );
        } else {
            self.0.logger.log(
                LogEvent::notice(Category::Channel, "channel entry refused")
                    .with("session", req.session)
                    .with("channel", req.channel)
                    .with("reason", result.refused.clone()),
            );
        }

        // A temporary channel that emptied is gone, and a client rendering it
        // has no other way to find out.
        if let Some(collected) = result.collected {
            self.0.logger.log(
                LogEvent::info(Category::Channel, "temporary channel collected")
                    .with("channel", collected)
                    .with("scope", scope),
            );
        }
        Ok(Response::new(result))
    }

    async fn leave(&self, request: Request<LeaveRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        tracing::debug!(session = req.session, scope, "user left its channel");
        self.0.trees.leave(scope, req.session);
        Ok(Response::new(Ack {}))
    }

    async fn listen(
        &self,
        request: Request<ListenRequest>,
    ) -> Result<Response<ListenResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        // The operator's caps apply here, unlike the ceilings on the tree: a
        // listener is a *user's* resource, and `operator-api` registering one
        // on somebody's behalf must not be a way around the limit set on how
        // many that user may hold.
        let outcome = self.0.trees.listen(
            scope,
            req.session,
            &req.listen,
            &req.unlisten,
            &req.volume,
            self.0.limits(scope),
        );
        for (channel, refusal) in &outcome.refused {
            self.0.logger.log(
                LogEvent::notice(Category::Channel, "listener refused")
                    .with("session", req.session)
                    .with("channel", *channel)
                    .with("reason", describe_refusal(*refusal))
                    .with("scope", scope),
            );
        }
        // Who is listening to what is an operator-visible fact about a room —
        // "was anyone able to hear that channel" is exactly the question asked
        // after the fact, and it cannot be answered from a log that only records
        // the refusals.
        for channel in &outcome.added {
            self.0.logger.log(
                LogEvent::info(Category::Channel, "user is listening to a channel")
                    .with("session", req.session)
                    .with("channel", *channel)
                    .with("scope", scope),
            );
        }
        for channel in &outcome.removed {
            self.0.logger.log(
                LogEvent::info(Category::Channel, "user stopped listening to a channel")
                    .with("session", req.session)
                    .with("channel", *channel)
                    .with("scope", scope),
            );
        }

        // Only for a registered account. A guest's listeners live and die with
        // the session, because there is no identity for a later visit to match.
        if let Some(account) = req.account {
            self.0.persist_listeners(scope, account, &outcome).await;
        }

        Ok(Response::new(ListenResult {
            added: outcome.added,
            removed: outcome.removed,
            refused: outcome
                .refused
                .into_iter()
                .map(
                    |(channel, refusal)| starling_proto_fancy::metadata::ListenRefusal {
                        channel,
                        limit: refusal_limit(refusal).into(),
                    },
                )
                .collect(),
            volume: outcome.volume,
        }))
    }

    async fn restore_listeners(
        &self,
        request: Request<RestoreListenersRequest>,
    ) -> Result<Response<ListenResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let stored = self.0.stored_listeners(scope, req.account).await;
        if stored.is_empty() {
            return Ok(Response::new(ListenResult::default()));
        }
        let outcome = self.0.trees.restore(scope, req.session, &stored);
        self.0.logger.log(
            LogEvent::info(Category::Channel, "channel listeners restored")
                .with("session", req.session)
                .with("count", outcome.added.len() as u64)
                .with("scope", scope),
        );
        Ok(Response::new(ListenResult {
            added: outcome.added,
            removed: Vec::new(),
            refused: Vec::new(),
            volume: outcome.volume,
        }))
    }
}

impl ClientService for MetadataService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            CHANNEL_STATE => self.on_channel_state(&inbound).await,
            CHANNEL_REMOVE => self.on_channel_remove(&inbound).await,
            _ => Actions::new(),
        }
    }
}

impl MetadataService {
    /// Write one account's listener changes to disk.
    ///
    /// Three rules, all murmur's, and each one is a bug if dropped:
    ///
    /// * **only for an account.** A guest has no identity for a later visit to
    ///   be matched against, so there is nothing to key a row on
    ///   (`Server.cpp:3224`).
    /// * **not for temporary channels.** The channel is gone when its last
    ///   member leaves, and the id is reused — a restored row would subscribe
    ///   the user to whatever room got the number next.
    /// * **disabled, not deleted.** Un-listening keeps the row so the volume
    ///   survives it, which is what makes toggling a channel off and on again
    ///   return the level the user chose.
    ///
    /// Write-behind, unlike an ACL: losing the tail here costs a listener that
    /// has to be re-enabled, not a revocation that silently un-revokes.
    async fn persist_listeners(&self, scope: u32, account: u64, outcome: &Listened) {
        let Some(store) = &self.store else {
            return;
        };
        let touched: Vec<u32> = outcome
            .added
            .iter()
            .chain(&outcome.removed)
            .chain(outcome.volume.keys())
            .copied()
            .collect();
        let transient = self.trees.transient(scope, &touched);

        for channel in &outcome.added {
            if transient.contains(channel) {
                continue;
            }
            // `ON CONFLICT ... DO UPDATE SET enabled` and nothing else: the row
            // may already exist from a previous visit, carrying the gain the
            // user chose then, and re-listening must not reset it.
            let result = sqlx::query(
                "INSERT INTO channel_listener \
                     (server_id, account_id, channel_id, volume_adjustment, enabled) \
                 VALUES (?, ?, ?, 1.0, 1) \
                 ON CONFLICT (server_id, account_id, channel_id) DO UPDATE SET enabled = 1",
            )
            .bind(i64::from(scope))
            .bind(account as i64)
            .bind(i64::from(*channel))
            .execute(store.pool())
            .await;
            self.report_listener_write(result.err(), scope, *channel);
        }

        for channel in &outcome.removed {
            if transient.contains(channel) {
                continue;
            }
            let result =
                sqlx::query("UPDATE channel_listener SET enabled = 0 WHERE server_id = ? AND account_id = ? AND channel_id = ?")
                    .bind(i64::from(scope))
                    .bind(account as i64)
                    .bind(i64::from(*channel))
                    .execute(store.pool())
                    .await;
            self.report_listener_write(result.err(), scope, *channel);
        }

        // Sorted into a list first: the source is a `HashMap`, and a write order
        // that depends on a hash seed is one that cannot be reproduced when a
        // deadlock or a constraint failure has to be explained.
        let mut gains: Vec<(u32, f32)> = outcome
            .volume
            .iter()
            .map(|(channel, gain)| (*channel, *gain))
            .collect();
        gains.sort_by_key(|(channel, _)| *channel);

        for (channel, gain) in &gains {
            if transient.contains(channel) {
                continue;
            }
            // Upserted rather than updated: murmur stores a gain for a listener
            // that does not exist yet (`Server.cpp:3242` consults the database
            // when the manager has never heard of it), so the row may have to be
            // created here — disabled, because setting a volume is not asking to
            // listen.
            let result = sqlx::query(
                "INSERT INTO channel_listener \
                     (server_id, account_id, channel_id, volume_adjustment, enabled) \
                 VALUES (?, ?, ?, ?, 0) \
                 ON CONFLICT (server_id, account_id, channel_id) \
                 DO UPDATE SET volume_adjustment = excluded.volume_adjustment",
            )
            .bind(i64::from(scope))
            .bind(account as i64)
            .bind(i64::from(*channel))
            .bind(f64::from(*gain))
            .execute(store.pool())
            .await;
            self.report_listener_write(result.err(), scope, *channel);
        }
    }

    /// Say so when a listener write fails, on the operator's own record.
    ///
    /// The change has already taken effect in memory, so the difference is
    /// invisible until a restart quietly undoes it — which is exactly the class
    /// of fault nobody connects to its cause.
    fn report_listener_write(&self, error: Option<sqlx::Error>, scope: u32, channel: u32) {
        let Some(error) = error else {
            return;
        };
        tracing::error!(%error, channel, "could not persist a channel listener");
        self.logger.log(
            LogEvent::error(Category::Channel, "channel listener was not persisted")
                .with("channel", channel)
                .with("scope", scope)
                .with("error", error.to_string()),
        );
    }

    /// One account's stored listeners: the enabled ones, with their gains.
    async fn stored_listeners(&self, scope: u32, account: u64) -> Vec<(u32, f32)> {
        use sqlx::Row as _;
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let rows = sqlx::query(
            "SELECT channel_id, volume_adjustment FROM channel_listener \
             WHERE server_id = ? AND account_id = ? AND enabled = 1",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .fetch_all(store.pool())
        .await;
        match rows {
            Ok(rows) => rows
                .into_iter()
                .map(|row| {
                    let channel: i64 = row.try_get("channel_id").unwrap_or_default();
                    let gain: f64 = row.try_get("volume_adjustment").unwrap_or(1.0);
                    (channel as u32, gain as f32)
                })
                .collect(),
            Err(error) => {
                // Returning nothing is the failure that is merely disappointing:
                // the user reconnects without their listeners and can set them
                // again. Refusing the handshake over it would not be.
                tracing::error!(%error, account, "could not read stored channel listeners");
                Vec::new()
            }
        }
    }

    /// Whether the client on `inbound` holds `needed` in `channel`.
    ///
    /// A thin wrapper so the call sites read in [`Perm`] rather than in raw
    /// bits. [`Permit::allows`] denies on any failure, including `permissions`
    /// being unreachable, so there is no error case for a caller to get wrong.
    async fn allows(&self, inbound: &Inbound, channel: u32, needed: Perm) -> bool {
        self.permit.allows(inbound, channel, needed.bits()).await
    }

    /// Turn a freshly created channel into a private room for named invitees.
    ///
    /// murmur's rule (`Messages.cpp:1827`): deny `see|enter|traverse` to `@all`
    /// and grant the same three to each invited **registered** user. The
    /// creator keeps access through their own `Write`, which implies both.
    ///
    /// `apply_subs` is false on every entry, as upstream has it: the invitation
    /// is to this room, and a sub-channel created inside it later is a separate
    /// decision rather than something silently pre-shared with everyone on this
    /// list.
    ///
    /// Creation only. Re-running it on an update would silently rewrite an ACL
    /// an operator had since edited by hand.
    ///
    /// A failure is logged rather than swallowed, because the channel exists
    /// either way: without the deny it is a *public* room that was asked to be
    /// private, which is the one outcome nobody wants to discover later.
    async fn invite(&self, scope: u32, channel: u32, invitees: &[u32]) {
        use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
        use starling_proto_fancy::permissions::{AclEntry, AclSet, SetAclRequest};

        let gated = Perm::SEE_CHANNEL
            .union(Perm::ENTER)
            .union(Perm::TRAVERSE)
            .bits();

        let mut acls = vec![AclEntry {
            apply_here: true,
            apply_subs: false,
            group: Some("all".to_owned()),
            deny: gated,
            ..AclEntry::default()
        }];
        acls.extend(invitees.iter().map(|id| AclEntry {
            apply_here: true,
            apply_subs: false,
            account: Some(u64::from(*id)),
            grant: gated,
            ..AclEntry::default()
        }));

        let Ok(transport) = self.resolver.channel("permissions") else {
            tracing::error!(channel, "permissions unreachable; room is NOT private");
            return;
        };
        let result = PermissionsClient::new(transport)
            .set_acl(SetAclRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
                actor: None,
                acls: Some(AclSet {
                    channel,
                    inherit: true,
                    acls,
                    groups: Vec::new(),
                }),
            })
            .await;

        match result {
            Ok(_) => self.logger.log(
                LogEvent::notice(Category::Channel, "private room created")
                    .with("channel", channel)
                    .with("invitees", invitees.len())
                    .with("scope", scope),
            ),
            Err(status) => {
                tracing::error!(channel, %status, "could not write the invitee ACL");
                self.logger.log(
                    LogEvent::error(Category::Channel, "invitee acl not written")
                        .with("channel", channel)
                        .with("error", status.message().to_owned())
                        .with("private", false),
                );
            }
        }
    }

    /// One reap pass across every virtual server.
    fn sweep_all(&self, scopes: &[u32]) {
        for scope in scopes {
            self.sweep(*scope);
        }
    }

    /// One reap pass, and everything the clients must be told about it.
    ///
    /// Order matters: the **move is announced before the removal**. A client
    /// told its channel is gone while it still believes it is inside would be
    /// rendering itself in a room the server has forgotten, and there is no
    /// way for it to leave a channel that no longer exists. Telling it where it
    /// now is first leaves no such window.
    fn sweep(&self, scope: u32) {
        let reaped = self
            .trees
            .reap_expired(scope, starling_runtime::ids::now_ms());
        if reaped.channels.is_empty() {
            return;
        }

        for moved in &reaped.moved {
            let state = starling_proto::proto::tcp::UserState {
                session: Some(moved.session),
                channel_id: Some(moved.to),
                ..starling_proto::proto::tcp::UserState::default()
            };
            self.fanout
                .push(to_sessions(Vec::new(), USER_STATE, state.encode_to_vec()));
        }

        for channel in &reaped.channels {
            self.logger.log(
                LogEvent::info(Category::Channel, "channel expired")
                    .with("channel", *channel)
                    .with("scope", scope),
            );
            let payload = starling_proto::proto::tcp::ChannelRemove {
                channel_id: *channel,
            }
            .encode_to_vec();
            self.fanout
                .push(to_sessions(Vec::new(), CHANNEL_REMOVE, payload));
            let _ = self.events.send(TreeEvent {
                event: Some(starling_proto_fancy::metadata::tree_event::Event::Removed(
                    *channel,
                )),
            });
        }
    }

    /// How to announce a channel: to everyone, or only to those who may see it.
    ///
    /// murmur gates the same broadcast per recipient with `canSee`
    /// (`Server.cpp:2100`, `sendProtoToChannelObserversExcept`), and notes that
    /// for a non-hidden channel `canSee` is always true — so the ordinary case
    /// is an ordinary broadcast. That shape is kept here: an empty session list
    /// means "everyone", and only a hidden channel pays for the filtering.
    ///
    /// Without this, creating a hidden channel announced it to every connected
    /// client. The login flood already filtered them, so the room was invisible
    /// to anyone who connected *afterwards* and visible to everyone who was
    /// already online — the kind of split that looks like a caching bug.
    ///
    /// A session that cannot be checked is left out. The cost of excluding
    /// someone wrongly is a channel they must reconnect to see; the cost of
    /// including someone wrongly is disclosing a private room.
    async fn announce_to(&self, scope: u32, channel: u32, hidden: bool) -> Vec<u32> {
        use starling_proto_fancy::sessionview::SubscribeRequest;
        use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;

        if !hidden {
            return Vec::new();
        }

        let Ok(transport) = self.resolver.channel("session-view") else {
            tracing::warn!(channel, "session-view is unreachable; announcing to nobody");
            return vec![u32::MAX];
        };
        let sessions = SessionViewClient::new(transport)
            .list(SubscribeRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
                subscriber: "metadata".to_owned(),
            })
            .await;
        let Ok(sessions) = sessions else {
            tracing::warn!(channel, "cannot list sessions; announcing to nobody");
            return vec![u32::MAX];
        };

        let mut allowed = Vec::new();
        for session in sessions.into_inner().sessions {
            if self
                .permit
                .allows_session(scope, session.session, channel, Perm::SEE_CHANNEL.bits())
                .await
            {
                allowed.push(session.session);
            }
        }
        // Never an empty list: that is the wire's "everyone", which would
        // announce the hidden channel to precisely the clients it must not
        // reach. A sentinel session nobody holds addresses it to no one.
        if allowed.is_empty() {
            allowed.push(u32::MAX);
        }
        allowed
    }

    /// An inbound `ChannelState`: create when it names no channel, otherwise
    /// update. murmur reads the same message both ways.
    async fn on_channel_state(&self, inbound: &Inbound) -> Actions {
        let Ok(state) =
            starling_proto::proto::tcp::ChannelState::decode(inbound.payload.as_slice())
        else {
            tracing::debug!(conn = inbound.conn, "undecodable ChannelState");
            return Actions::new();
        };
        let creating = state.channel_id.is_none();

        // `temporary` is deprecated upstream but frozen, not removed: some
        // clients still set it, and this proto is never changed
        // (`docs/ARCHITECTURE.md` §7).
        // `expect` rather than `allow`, matching `serialize.rs`: it deletes
        // itself if the field is ever un-deprecated.
        #[expect(
            deprecated,
            reason = "frozen upstream field, still sent by some clients"
        )]
        let temporary = state.temporary.unwrap_or(false);

        // Checked before anything is written, and against the channel the
        // permission is *about*: creating is authorised on the parent, because
        // the new channel does not exist to hold an ACL yet, while editing is
        // authorised on the channel being edited.
        let (channel_asked_about, needed) = if creating {
            let parent = state.parent.unwrap_or(ROOT_CHANNEL.0);
            let make = if temporary {
                Perm::MAKE_TEMP_CHANNEL
            } else {
                Perm::MAKE_CHANNEL
            };
            (parent, make)
        } else {
            (state.channel_id.unwrap_or(ROOT_CHANNEL.0), Perm::WRITE)
        };
        if !self.allows(inbound, channel_asked_about, needed).await {
            return vec![permission_denied(inbound, needed, channel_asked_about)];
        }

        let edit = to_proto(&state, state.channel_id.unwrap_or_default());
        // Links are their own permission and their own message, so they are
        // settled before the field write: murmur checks `LinkChannel` on both
        // ends and refuses the *whole* `ChannelState` if either is denied
        // (`Messages.cpp:2053`), rather than renaming the channel and silently
        // dropping the link the same message asked for.
        if edit.touches_links() {
            if let Some(id) = state.channel_id {
                if let Err(denial) = self.authorise_links(inbound, id, &edit).await {
                    return vec![denial];
                }
            } else {
                // A creation cannot carry links: the channel has no id yet, so
                // there is nothing for the far end to be linked to.
                tracing::debug!(conn = inbound.conn, "ignoring links on a channel creation");
            }
        }

        let limits = self.limits(inbound.scope);
        let result = match state.channel_id {
            Some(id) => self.trees.update(
                inbound.scope,
                id,
                Some(edit.channel.clone()),
                &edit.fields,
                limits,
            ),
            None => self
                .trees
                .create(inbound.scope, Some(edit.channel.clone()), temporary, limits),
        };
        // Named against the channel the limit is *about*: the parent a channel
        // would have been created under, or the channel a move would have
        // re-parented — which is the one the client has on screen.
        if !result.applied
            && let Some(denial) = self.limit_denial(inbound, &result, channel_asked_about)
        {
            return vec![denial];
        }
        let mut actions = match state.channel_id {
            Some(id) if edit.touches_links() => self.apply_links(inbound, id, &edit).await,
            _ => Actions::new(),
        };
        let Some(channel) = result.channel else {
            // Refused for a reason that is not a limit — a duplicate name, a
            // parent that has gone — or a no-op. The client is told nothing
            // either way, so this is the only record that it was attempted.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                creating,
                reason = %result.refused,
                "channel change had no effect"
            );
            return actions;
        };
        actions.extend(
            self.announce_edit(inbound, &state, &channel, creating)
                .await,
        );
        actions
    }

    /// Record a created or edited channel, and tell whoever may see it.
    ///
    /// Split from [`Self::on_channel_state`] because it is what happens *after*
    /// the decision: everything above it can refuse, and nothing here can.
    async fn announce_edit(
        &self,
        inbound: &Inbound,
        state: &starling_proto::proto::tcp::ChannelState,
        channel: &starling_proto_fancy::metadata::Channel,
        creating: bool,
    ) -> Actions {
        let what = if creating {
            "channel created"
        } else {
            "channel updated"
        };
        self.logger.log(
            LogEvent::info(Category::Channel, what)
                .with("channel", channel.id)
                .with("name", channel.name.clone())
                .with("session", inbound.session)
                .with("scope", inbound.scope),
        );
        self.trail.record(
            inbound.scope,
            Record::new(
                trail::category::CHANNEL,
                if creating { "created" } else { "updated" },
            )
            .actor(session_actor(inbound.session), String::new())
            .target_channel(channel.id)
            .detail(channel.name.clone()),
        );
        if creating && !state.invitee_user_ids.is_empty() {
            self.invite(inbound.scope, channel.id, &state.invitee_user_ids)
                .await;
        }
        let recipients = self
            .announce_to(inbound.scope, channel.id, channel.flags & FLAG_HIDDEN != 0)
            .await;
        vec![to_sessions(
            recipients,
            CHANNEL_STATE,
            channel_state(channel).encode_to_vec(),
        )]
    }

    /// Whether the client may make every link change this edit asks for.
    ///
    /// murmur's rule (`Messages.cpp:2053`): `LinkChannel` on the channel being
    /// edited, **and** on each channel being linked *to*. Unlinking needs it
    /// only on the near side — taking an edge away cannot expose anything, and
    /// requiring the far end's permission would mean an operator who linked two
    /// rooms and then lost access to one could never separate them again.
    async fn authorise_links(
        &self,
        inbound: &Inbound,
        channel: u32,
        edit: &ChannelEdit,
    ) -> Result<(), starling_proto_fancy::control::ServerAction> {
        if !self.allows(inbound, channel, Perm::LINK_CHANNEL).await {
            return Err(permission_denied(inbound, Perm::LINK_CHANNEL, channel));
        }
        for target in &edit.links_add {
            if !self.allows(inbound, *target, Perm::LINK_CHANNEL).await {
                return Err(permission_denied(inbound, Perm::LINK_CHANNEL, *target));
            }
        }
        Ok(())
    }

    /// Write the link change a `ChannelState` asked for, and announce it.
    ///
    /// Split out of [`Self::on_channel_state`] because it is a second edit with
    /// a second permission and a second message: the field write above it can
    /// succeed while this is refused, and vice versa.
    async fn apply_links(&self, inbound: &Inbound, channel: u32, edit: &ChannelEdit) -> Actions {
        let linked = self
            .trees
            .link(inbound.scope, channel, &edit.links_add, &edit.links_remove);
        if !linked.applied {
            tracing::debug!(
                conn = inbound.conn,
                channel,
                reason = %linked.refused,
                "link change had no effect"
            );
            return Actions::new();
        }
        self.record_links(inbound, channel, edit);
        self.link_actions(inbound.scope, channel, &edit.links_add, &edit.links_remove)
            .await
    }

    /// The `ChannelState` frames a link change produces.
    async fn link_actions(
        &self,
        scope: u32,
        channel: u32,
        added: &[u32],
        removed: &[u32],
    ) -> Actions {
        let mut actions = Actions::new();
        actions.push(to_sessions(
            self.announce_to(scope, channel, self.is_hidden(scope, channel))
                .await,
            CHANNEL_STATE,
            serialize::link_state(channel, added, removed).encode_to_vec(),
        ));
        // The far ends, each as their own frame. A client keys a `ChannelState`
        // by `channel_id`, so one message can only ever describe one channel —
        // and the far end's link set changed too.
        for target in added.iter().chain(removed.iter()) {
            let near = [channel];
            let (add, remove) = if added.contains(target) {
                (&near[..], &[][..])
            } else {
                (&[][..], &near[..])
            };
            actions.push(to_sessions(
                self.announce_to(scope, *target, self.is_hidden(scope, *target))
                    .await,
                CHANNEL_STATE,
                serialize::link_state(*target, add, remove).encode_to_vec(),
            ));
        }
        actions
    }

    /// Whether `channel` is hidden, for deciding who hears about it.
    fn is_hidden(&self, scope: u32, channel: u32) -> bool {
        self.trees
            .snapshot(scope)
            .channels
            .iter()
            .find(|other| other.id == channel)
            .is_some_and(|other| other.flags & FLAG_HIDDEN != 0)
    }

    /// Record a link change in both the diagnostic log and the operator trail.
    ///
    /// Linking two channels joins two rooms' audio, which is the kind of change
    /// somebody asks about weeks later — and `LinkChannel` is a permission an
    /// operator grants deliberately, so its use belongs on the record.
    fn record_links(&self, inbound: &Inbound, channel: u32, edit: &ChannelEdit) {
        self.logger.log(
            LogEvent::notice(Category::Channel, "channel links changed")
                .with("channel", channel)
                .with("session", inbound.session)
                .with("linked", edit.links_add.len())
                .with("unlinked", edit.links_remove.len())
                .with("scope", inbound.scope),
        );
        self.trail.record(
            inbound.scope,
            Record::new(trail::category::CHANNEL, "linked")
                .actor(session_actor(inbound.session), String::new())
                .target_channel(channel)
                .detail(format!("+{:?} -{:?}", edit.links_add, edit.links_remove)),
        );
    }

    /// The refusal to send when a limit stopped a channel edit.
    ///
    /// murmur answers each of these with its own `DenyType`, and the difference
    /// is what the user sees: "the channel nesting limit has been reached" is a
    /// thing an operator can change, while the `Permission` type every other
    /// refusal here carries would render as a permission they do not lack.
    ///
    /// `None` for a refusal that is not a limit — a duplicate name, a parent
    /// that has gone — which keeps this from turning every no-op into a
    /// message murmur does not send.
    fn limit_denial(
        &self,
        inbound: &Inbound,
        result: &ChannelResult,
        channel: u32,
    ) -> Option<starling_proto_fancy::control::ServerAction> {
        use starling_proto::proto::tcp::permission_denied::DenyType;

        let kind = match result.refused.as_str() {
            reason if reason == tree_actor::NESTING_REFUSED => DenyType::NestingLimit,
            reason if reason == tree_actor::COUNT_REFUSED => DenyType::ChannelCountLimit,
            _ => return None,
        };
        self.logger.log(
            LogEvent::notice(Category::Channel, "channel edit refused by a limit")
                .with("session", inbound.session)
                .with("reason", result.refused.clone())
                .with("scope", inbound.scope),
        );
        Some(refused(inbound, kind, channel, &result.refused))
    }

    /// Tell clients about a link change made over gRPC.
    async fn announce_links(&self, scope: u32, channel: u32, added: &[u32], removed: &[u32]) {
        for action in self.link_actions(scope, channel, added, removed).await {
            self.fanout.push(action);
        }
    }

    async fn on_channel_remove(&self, inbound: &Inbound) -> Actions {
        let Ok(remove) =
            starling_proto::proto::tcp::ChannelRemove::decode(inbound.payload.as_slice())
        else {
            tracing::debug!(conn = inbound.conn, "undecodable ChannelRemove");
            return Actions::new();
        };
        // Removing a channel is editing it, so it takes the same permission
        // murmur asks for: `Write` on the channel itself.
        if !self.allows(inbound, remove.channel_id, Perm::WRITE).await {
            return vec![permission_denied(inbound, Perm::WRITE, remove.channel_id)];
        }
        let removal = self.trees.remove(inbound.scope, remove.channel_id);
        if !removal.result.applied {
            tracing::debug!(
                session = inbound.session,
                channel = remove.channel_id,
                "channel removal had no effect"
            );
            return Actions::new();
        }
        self.logger.log(
            LogEvent::notice(Category::Channel, "channel removed")
                .with("channel", remove.channel_id)
                .with("session", inbound.session)
                .with("scope", inbound.scope),
        );
        self.trail.record(
            inbound.scope,
            Record::new(trail::category::CHANNEL, "removed")
                .actor(session_actor(inbound.session), String::new())
                .target_channel(remove.channel_id),
        );
        // The cancellations first, then the removal — the client has to be able
        // to match `listening_channel_remove` to a channel it still has.
        let mut actions = unlisten_broadcast(&removal.unlistened);
        actions.push(to_sessions(
            Vec::new(),
            CHANNEL_REMOVE,
            remove.encode_to_vec(),
        ));
        actions
    }
}

impl Serve for MetadataService {
    const NAME: &'static str = "metadata";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("tree loaded");
        let trees = Trees::new(&ctx.virtual_servers(), &root_name(&ctx));
        let mut store = None;
        if let Ok(opened) = ctx.storage().await {
            opened.migrate(SCHEMA).await?;
            trees.load(&opened).await;
            store = Some(opened);
        }
        ctx.health.ready("tree loaded");

        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Ok(Arc::new(Self {
            trees,
            events,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            trail: Trail::new(ctx.resolver.clone()),
            permit: Permit::new(ctx.resolver.clone()),
            settings: Settings::new(ctx.resolver.clone()).logging_to(ctx.logger.clone()),
            resolver: ctx.resolver.clone(),
            store,
        }))
    }

    /// Reap expired channels until shutdown.
    ///
    /// A timer rather than a per-channel alarm: expiry is a coarse deadline, a
    /// scan of the tree is cheap next to the round trips it would take to
    /// schedule one, and a missed alarm would leave a channel alive forever
    /// while a missed tick only delays it by one interval.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        /// Short enough that "8 seconds" reads as 8 seconds to a person
        /// watching, since expiry is user-visible.
        const TICK: std::time::Duration = std::time::Duration::from_secs(1);

        let scopes = ctx.virtual_servers();
        // Subscribed rather than fetched per edit: the ceilings are read on
        // every channel a client creates, and a gRPC round trip on that path
        // would put `server-config` in the way of the channel tree.
        let watchers = self.settings.watch(&scopes);
        let sweeper = tokio::spawn({
            let service = Arc::clone(&self);
            let scopes = scopes.clone();
            async move {
                loop {
                    tokio::time::sleep(TICK).await;
                    service.sweep_all(&scopes);
                }
            }
        });
        ctx.shutdown.wait().await;
        sweeper.abort();
        for watcher in watchers {
            watcher.abort();
        }
        Ok(())
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(MetadataServer::new(MetadataRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

/// The root channel's name is the server's name, as it is in murmur.
fn root_name(ctx: &ServiceContext) -> String {
    ctx.config
        .virtual_servers
        .first()
        .map_or_else(|| "Starling".to_owned(), |server| server.name.clone())
}

/// The scope a request names, defaulting to the first virtual server.
#[must_use]
pub fn scope_of(scope: Option<starling_proto_fancy::common::Scope>) -> u32 {
    scope.map_or(1, |scope| scope.virtual_server)
}

/// The outer type this service owns, for the routing table.
#[must_use]
pub const fn outer_type() -> u16 {
    ServiceKind::Metadata.outer_type()
}
