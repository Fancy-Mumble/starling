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

use async_trait::async_trait;
use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::metadata::metadata_server::{Metadata, MetadataServer};
use starling_proto_fancy::metadata::{
    ChannelResult, CreateRequest, EnterRequest, EnterResult, LeaveRequest, LinkRequest,
    ListenRequest, RemoveRequest, Tree, TreeEvent, TreeRequest, UpdateRequest,
};
use starling_proto_fancy::types::ServiceKind;
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
        Ok(Response::new(self.0.trees.enter(
            scope,
            req.session,
            req.channel,
        )))
    }

    async fn leave(&self, request: Request<LeaveRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
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

#[async_trait]
impl ClientService for MetadataService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            CHANNEL_STATE => self.on_channel_state(&inbound),
            CHANNEL_REMOVE => self.on_channel_remove(&inbound),
            _ => Actions::new(),
        }
    }
}

impl MetadataService {
    /// An inbound `ChannelState`: create when it names no channel, otherwise
    /// update. murmur reads the same message both ways.
    fn on_channel_state(&self, inbound: &Inbound) -> Actions {
        let Ok(state) =
            starling_proto::proto::tcp::ChannelState::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        let result = match state.channel_id {
            Some(id) => {
                let (channel, fields) = to_proto(&state, id);
                self.trees.update(inbound.scope, id, Some(channel), &fields)
            }
            None => {
                let (channel, _) = to_proto(&state, 0);
                // `temporary` is deprecated upstream but frozen, not removed:
                // some clients still set it, and this proto is never changed
                // (`docs/ARCHITECTURE.md` §7).
                #[allow(
                    deprecated,
                    reason = "frozen upstream field, still sent by some clients"
                )]
                let temporary = state.temporary.unwrap_or(false);
                self.trees.create(inbound.scope, Some(channel), temporary)
            }
        };
        match result.channel {
            Some(channel) => vec![to_sessions(
                Vec::new(),
                CHANNEL_STATE,
                channel_state(&channel).encode_to_vec(),
            )],
            None => Actions::new(),
        }
    }

    fn on_channel_remove(&self, inbound: &Inbound) -> Actions {
        let Ok(remove) =
            starling_proto::proto::tcp::ChannelRemove::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        if !self.trees.remove(inbound.scope, remove.channel_id).applied {
            return Actions::new();
        }
        vec![to_sessions(
            Vec::new(),
            CHANNEL_REMOVE,
            remove.encode_to_vec(),
        )]
    }
}

#[async_trait]
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
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
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
