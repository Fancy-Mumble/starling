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

use prost::Message as _;
use starling_proto_fancy::common::{Ack, Scope};
use starling_proto_fancy::identity;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::types::ServiceKind;
use starling_proto_fancy::userdata::user_data_server::{UserData, UserDataServer};
use starling_proto_fancy::userdata::{
    Account, AccountPage, AuthRequest, AuthResult, Blob, BlobRef, BlobRequest, DeleteRequest,
    ListRequest, LookupRequest, RegisterRequest, UpdateRequest, auth_result, lookup_request,
};
use starling_runtime::channel::Resolver;
use starling_runtime::log::{Category, LogEvent, Logger};
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
    logger: Logger,
    /// To reach `session-view`, which is the only place that knows which
    /// account a session belongs to — see [`UserdataService::sessions`].
    resolver: Resolver,
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
        let result = self.0.accounts.authenticate(scope_of(req.scope), &req);

        // The refusal reason is decided here and only the enum reaches
        // session-lifecycle, so this is the one place that can say which
        // credential was wrong without the password going anywhere near a log.
        tracing::debug!(
            name = %req.name,
            outcome = result.outcome,
            strong_cert = req.strong_cert,
            "authentication decided"
        );
        Ok(Response::new(result))
    }

    async fn lookup(&self, request: Request<LookupRequest>) -> Result<Response<Account>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let found = match req.by {
            Some(lookup_request::By::Id(id)) => self.0.accounts.by_id(scope, id),
            Some(lookup_request::By::Name(name)) => self.0.accounts.by_name(scope, &name),
            Some(lookup_request::By::CertHash(hash)) => self.0.accounts.by_cert(scope, &hash),
            None => None,
        };
        found
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such account"))
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<AccountPage>, Status> {
        let req = request.into_inner();
        Ok(Response::new(self.0.accounts.list(
            scope_of(req.scope),
            &req.name_prefix,
            req.limit,
            req.after_id,
        )))
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
        let name = account.name.clone();
        match self
            .0
            .accounts
            .register(scope, account, &req.password)
            .await
        {
            Ok(account) => {
                self.0.logger.log(
                    LogEvent::notice(Category::Admin, "account registered")
                        .with("account", account.id)
                        .with("name", name)
                        .with("scope", scope),
                );
                Ok(Response::new(account))
            }
            Err(refused) => {
                tracing::info!(%name, %refused, "account registration refused");
                Err(Status::already_exists(refused))
            }
        }
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

impl ClientService for UserdataService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            QUERY_USERS => self.on_query_users(&inbound),
            REQUEST_BLOB => self.on_request_blob(&inbound).await,
            _ => Actions::new(),
        }
    }
}

impl UserdataService {
    /// `QueryUsers`: names to ids and back, in one round trip.
    fn on_query_users(&self, inbound: &Inbound) -> Actions {
        let Ok(query) = starling_proto::proto::tcp::QueryUsers::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        let mut ids = Vec::new();
        let mut names = Vec::new();
        for id in &query.ids {
            if let Some(account) = self.accounts.by_id(inbound.scope, u64::from(*id)) {
                ids.push(*id);
                names.push(account.name);
            }
        }
        for name in &query.names {
            if let Some(account) = self.accounts.by_name(inbound.scope, name) {
                ids.push(account.id as u32);
                names.push(account.name);
            }
        }
        let reply = starling_proto::proto::tcp::QueryUsers { ids, names };
        vec![to_conn(inbound.conn, QUERY_USERS, reply.encode_to_vec())]
    }

    /// `RequestBlob`: a primary-key lookup, because storage is content-addressed
    /// even though murmur's is not.
    ///
    /// The request names **sessions**, and blobs hang off **accounts**. This
    /// used to pass the session id straight to `by_id` as though the two were
    /// the same number. They are not related at all — sessions are handed out
    /// per connection and reused after a disconnect — so the answer was
    /// whichever account happened to share the integer: usually none, and
    /// occasionally somebody else's avatar.
    async fn on_request_blob(&self, inbound: &Inbound) -> Actions {
        let Ok(request) =
            starling_proto::proto::tcp::RequestBlob::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };

        let sessions = self.sessions(inbound.scope).await;
        let account_of = |session: u32| {
            sessions
                .iter()
                .find(|other| other.session == session)
                .and_then(|other| identity::account(other.registered, other.account))
        };

        let mut states = Vec::new();
        for session in &request.session_texture {
            let Some(id) = account_of(*session) else {
                // A guest, or a session that left between asking and answering.
                // Neither is an error: murmur answers what it can and says
                // nothing about the rest.
                continue;
            };
            if let Some(account) = self.accounts.by_id(inbound.scope, id) {
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
        for session in &request.session_comment {
            let Some(id) = account_of(*session) else {
                continue;
            };
            if let Some(account) = self.accounts.by_id(inbound.scope, id) {
                let comment = self
                    .accounts
                    .blob(inbound.scope, &account.comment_hash)
                    .await
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                states.push(starling_proto::proto::tcp::UserState {
                    session: Some(*session),
                    comment,
                    ..starling_proto::proto::tcp::UserState::default()
                });
            }
        }
        states
            .into_iter()
            .map(|state| to_conn(inbound.conn, 9, state.encode_to_vec()))
            .collect()
    }

    /// Every live session on a virtual server, from `session-view`.
    ///
    /// Fetched per request rather than subscribed to: `RequestBlob` arrives
    /// once per avatar a client has never seen, which is rare and bursty, and a
    /// maintained mirror of the whole session table would be a second copy of
    /// state this service does not otherwise need.
    async fn sessions(&self, scope: u32) -> Vec<starling_proto_fancy::sessionview::Session> {
        let Ok(channel) = self.resolver.channel("session-view") else {
            return Vec::new();
        };
        SessionViewClient::new(channel)
            .list(starling_proto_fancy::sessionview::SubscribeRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
                subscriber: "userdata".to_owned(),
            })
            .await
            .map(|sessions| sessions.into_inner().sessions)
            .unwrap_or_default()
    }
}

impl Serve for UserdataService {
    const NAME: &'static str = "userdata";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("accounts loaded");
        let accounts = Accounts::open(ctx.storage().await?).await?;

        // Every virtual server gets an administrator on its first boot, because
        // a server with no way in is a server that has to be rebuilt. The
        // password is generated and announced exactly once, at creation — a
        // restart never repeats it, so this is safe to run unconditionally.
        for scope in ctx.virtual_servers() {
            if let Some(password) = accounts.ensure_superuser(scope).await {
                announce_superuser(&ctx, scope, &password);
            }
        }

        ctx.health.ready("accounts loaded");
        Ok(Arc::new(Self {
            accounts,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            resolver: ctx.resolver.clone(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(UserDataServer::new(UserdataRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

/// Print a freshly generated SuperUser password where an operator will see it.
///
/// The **only** place Starling writes a password in the clear, and it is
/// deliberate: this credential exists nowhere else, so a line nobody sees is an
/// administrator account nobody can use. murmur makes the same trade.
///
/// Sent to both records for the same reason. `tracing` is what is on the console
/// of whoever just ran the server, and the operator log is what survives to be
/// read afterwards — an operator who scrolled past it needs the second one, and
/// one who is following `docker compose up` needs the first.
///
/// It is announced once, at creation. Re-announcing on every boot would leave a
/// live administrator password in every log aggregator the deployment has.
fn announce_superuser(ctx: &ServiceContext, scope: u32, password: &str) {
    // The operator log only, and deliberately not `tracing` as well. This is
    // the one line in the system that prints a live administrator password, so
    // printing it twice doubles the number of places it can be scraped from —
    // and the two went to the same console anyway. The operator log is the
    // right home: it is what an operator is reading at first boot, and it is
    // the stream a deployment can point at a file with restricted permissions.
    ctx.logger.log(
        LogEvent::notice(
            Category::Server,
            "superuser account created; this password is shown once and cannot be recovered",
        )
        .with("virtual_server", scope)
        .with("user", identity::SUPERUSER_NAME.to_owned())
        .with("password", password.to_owned()),
    );
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
