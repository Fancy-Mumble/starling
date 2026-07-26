//! `userdata` — registered accounts, profiles, settings and blobs.
//!
//! **Account settings are userdata, not settings**: they are per-user profile
//! data and belong with the profile, while `server-config` owns what an
//! operator changes for everyone (`docs/ARCHITECTURE.md` §4).
//!
//! Authentication is the one read that cannot be deferred (`docs/STORAGE.md`
//! D1), so accounts are cached in memory at boot and maintained write-through.
//! Everything else is write-behind like the rest of the control plane.
//!
//! Blobs are content-addressed with a refcount (L4): identical avatars are
//! stored once, and `RequestBlob` becomes a primary-key lookup.

pub mod ids;

pub mod accounts;
pub mod secret;

pub use accounts::Accounts;
pub use ids::UserId;
pub use secret::{Secret, verify_totp};

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use starling_proto_fancy::common::{Ack, Scope};
use starling_proto_fancy::types::ServiceKind;
use starling_proto_fancy::userdata::user_data_server::{UserData, UserDataServer};
use starling_proto_fancy::userdata::{
    Account, AccountPage, AuthRequest, AuthResult, Blob, BlobRef, BlobRequest, DeleteRequest,
    ListRequest, LookupRequest, RegisterRequest, UpdateRequest, auth_result, lookup_request,
};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tonic::{Request, Response, Status};

/// Upstream `QueryUsers`.
const QUERY_USERS: u16 = 14;
/// Upstream `RequestBlob`.
const REQUEST_BLOB: u16 = 23;

/// The service.
#[derive(Debug)]
pub struct UserdataService {
    accounts: Accounts,
    fanout: Fanout,
}

impl UserdataService {
    /// The accounts, for the operator surface and tests.
    #[must_use]
    pub fn accounts(&self) -> &Accounts {
        &self.accounts
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct UserdataRpc(Arc<UserdataService>);

#[tonic::async_trait]
impl UserData for UserdataRpc {
    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResult>, Status> {
        let req = request.into_inner();
        Ok(Response::new(
            self.0
                .accounts
                .authenticate(scope_of(req.scope), &req)
                .await,
        ))
    }

    async fn lookup(&self, request: Request<LookupRequest>) -> Result<Response<Account>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let found = match req.by {
            Some(lookup_request::By::Id(id)) => self.0.accounts.by_id(scope, id).await,
            Some(lookup_request::By::Name(name)) => self.0.accounts.by_name(scope, &name).await,
            Some(lookup_request::By::CertHash(hash)) => self.0.accounts.by_cert(scope, &hash).await,
            None => None,
        };
        found
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such account"))
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<AccountPage>, Status> {
        let req = request.into_inner();
        Ok(Response::new(
            self.0
                .accounts
                .list(
                    scope_of(req.scope),
                    &req.name_prefix,
                    req.limit,
                    req.after_id,
                )
                .await,
        ))
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<Account>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let Some(account) = req.account else {
            return Err(Status::invalid_argument("no account was described"));
        };
        self.0
            .accounts
            .register(scope, account, &req.password)
            .await
            .map(Response::new)
            .map_err(Status::already_exists)
    }

    async fn update(&self, request: Request<UpdateRequest>) -> Result<Response<Account>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        self.0
            .accounts
            .update(scope, req)
            .await
            .map(Response::new)
            .map_err(Status::permission_denied)
    }

    async fn delete(&self, request: Request<DeleteRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        self.0.accounts.delete(scope_of(req.scope), req.id).await;
        Ok(Response::new(Ack {}))
    }

    async fn get_blob(&self, request: Request<BlobRequest>) -> Result<Response<Blob>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        self.0
            .accounts
            .blob(scope, &req.hash)
            .await
            .map(|bytes| {
                Response::new(Blob {
                    scope: Some(Scope {
                        virtual_server: scope,
                    }),
                    hash: req.hash.clone(),
                    bytes,
                })
            })
            .ok_or_else(|| Status::not_found("no such blob"))
    }

    async fn put_blob(&self, request: Request<Blob>) -> Result<Response<BlobRef>, Status> {
        let blob = request.into_inner();
        let scope = scope_of(blob.scope);
        let reference = self.0.accounts.put_blob(scope, &blob.bytes).await;
        Ok(Response::new(reference))
    }
}

#[async_trait]
impl ClientService for UserdataService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            QUERY_USERS => self.on_query_users(&inbound).await,
            REQUEST_BLOB => self.on_request_blob(&inbound).await,
            _ => Actions::new(),
        }
    }
}

impl UserdataService {
    /// `QueryUsers`: names to ids and back, in one round trip.
    async fn on_query_users(&self, inbound: &Inbound) -> Actions {
        let Ok(query) = starling_proto::proto::tcp::QueryUsers::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        let mut ids = Vec::new();
        let mut names = Vec::new();
        for id in &query.ids {
            if let Some(account) = self.accounts.by_id(inbound.scope, u64::from(*id)).await {
                ids.push(*id);
                names.push(account.name);
            }
        }
        for name in &query.names {
            if let Some(account) = self.accounts.by_name(inbound.scope, name).await {
                ids.push(account.id as u32);
                names.push(account.name);
            }
        }
        let reply = starling_proto::proto::tcp::QueryUsers { ids, names };
        vec![to_conn(inbound.conn, QUERY_USERS, reply.encode_to_vec())]
    }

    /// `RequestBlob`: a primary-key lookup, because storage is content-addressed
    /// even though murmur's is not.
    async fn on_request_blob(&self, inbound: &Inbound) -> Actions {
        let Ok(request) =
            starling_proto::proto::tcp::RequestBlob::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        let mut states = Vec::new();
        for session in &request.session_texture {
            if let Some(account) = self
                .accounts
                .by_id(inbound.scope, u64::from(*session))
                .await
            {
                let texture = self
                    .accounts
                    .blob(inbound.scope, &account.texture_hash)
                    .await;
                states.push(starling_proto::proto::tcp::UserState {
                    session: Some(*session),
                    texture,
                    ..starling_proto::proto::tcp::UserState::default()
                });
            }
        }
        states
            .into_iter()
            .map(|state| to_conn(inbound.conn, 9, state.encode_to_vec()))
            .collect()
    }
}

#[async_trait]
impl Serve for UserdataService {
    const NAME: &'static str = "userdata";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("accounts loaded");
        let accounts = Accounts::open(ctx.storage().await?).await?;
        ctx.health.ready("accounts loaded");
        Ok(Arc::new(Self {
            accounts,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
        tonic::service::Routes::default()
            .add_service(UserDataServer::new(UserdataRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

/// The scope a request names, defaulting to the first virtual server.
#[must_use]
pub fn scope_of(scope: Option<Scope>) -> u32 {
    scope.map_or(1, |scope| scope.virtual_server)
}

/// The outer type this service owns.
#[must_use]
pub const fn outer_type() -> u16 {
    ServiceKind::Userdata.outer_type()
}

/// Whether an authentication outcome lets the client in.
#[must_use]
pub fn admits(outcome: auth_result::Outcome) -> bool {
    matches!(outcome, auth_result::Outcome::Ok)
}
