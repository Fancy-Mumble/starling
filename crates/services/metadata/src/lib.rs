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
pub use serialize::{channel_state, to_proto};
pub use tree_actor::Trees;

use std::sync::Arc;

use crate::tree_actor::FLAG_HIDDEN;
use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::metadata::metadata_server::{Metadata, MetadataServer};
use starling_proto_fancy::metadata::{
    ChannelResult, CreateRequest, EnterRequest, EnterResult, LeaveRequest, LinkRequest,
    ListenRequest, RemoveRequest, Tree, TreeEvent, TreeRequest, UpdateRequest,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::permit::{Permit, permission_denied};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_sessions};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::Migration;
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

/// The schema. Typed columns, one row per channel, and the index the parent
/// lookup actually uses (`docs/STORAGE.md` L1, L2).
const SCHEMA: &[Migration<'static>] = &[Migration::new(
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
)];

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
}

impl MetadataService {
    /// The trees, for the operator surface and tests.
    #[must_use]
    pub fn trees(&self) -> &Trees {
        &self.trees
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
        let result = self.0.trees.create(scope, req.channel, req.temporary);
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
        let result = self
            .0
            .trees
            .update(scope, req.channel, req.values, &req.fields);
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
        let result = self.0.trees.remove(scope, req.channel);
        if result.applied {
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
        Ok(Response::new(result))
    }

    async fn link(&self, request: Request<LinkRequest>) -> Result<Response<ChannelResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        Ok(Response::new(self.0.trees.link(
            scope,
            req.channel,
            &req.link,
            &req.unlink,
        )))
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

    async fn listen(&self, request: Request<ListenRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        self.0
            .trees
            .listen(scope, req.session, &req.listen, &req.unlisten);
        Ok(Response::new(Ack {}))
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

        let result = match state.channel_id {
            Some(id) => {
                let (channel, fields) = to_proto(&state, id);
                self.trees.update(inbound.scope, id, Some(channel), &fields)
            }
            None => {
                let (channel, _) = to_proto(&state, 0);
                self.trees.create(inbound.scope, Some(channel), temporary)
            }
        };
        match result.channel {
            Some(channel) => {
                self.logger.log(
                    LogEvent::info(
                        Category::Channel,
                        if creating {
                            "channel created"
                        } else {
                            "channel updated"
                        },
                    )
                    .with("channel", channel.id)
                    .with("name", channel.name.clone())
                    .with("session", inbound.session)
                    .with("scope", inbound.scope),
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
                    channel_state(&channel).encode_to_vec(),
                )]
            }
            None => {
                // Refused or a no-op, and the client is told nothing either
                // way — so this is the only record that it was attempted.
                tracing::debug!(
                    conn = inbound.conn,
                    session = inbound.session,
                    creating,
                    "channel change had no effect"
                );
                Actions::new()
            }
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
        if !self.trees.remove(inbound.scope, remove.channel_id).applied {
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
        vec![to_sessions(
            Vec::new(),
            CHANNEL_REMOVE,
            remove.encode_to_vec(),
        )]
    }
}

impl Serve for MetadataService {
    const NAME: &'static str = "metadata";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("tree loaded");
        let trees = Trees::new(&ctx.virtual_servers(), &root_name(&ctx));
        if let Ok(store) = ctx.storage().await {
            store.migrate(SCHEMA).await?;
            trees.load(&store).await;
        }
        ctx.health.ready("tree loaded");

        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Ok(Arc::new(Self {
            trees,
            events,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            permit: Permit::new(ctx.resolver.clone()),
            resolver: ctx.resolver.clone(),
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
        let sweeper = tokio::spawn({
            let service = Arc::clone(&self);
            async move {
                loop {
                    tokio::time::sleep(TICK).await;
                    service.sweep_all(&scopes);
                }
            }
        });
        ctx.shutdown.wait().await;
        sweeper.abort();
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
