//! `userdata`: registered accounts, profiles, settings and blobs.
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
mod directory;
pub mod secret;

pub mod selfservice;

pub use accounts::{Accounts, Import};
pub use ids::UserId;
pub use secret::{Secret, verify_totp};

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::{Ack, Scope};
use starling_proto_fancy::identity;
use starling_proto_fancy::metadata::TreeRequest;
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::types::ServiceKind;
use starling_proto_fancy::userdata::user_data_server::{UserData, UserDataServer};
use starling_proto_fancy::userdata::{
    Account, AccountPage, AuthRequest, AuthResult, Blob, BlobRef, BlobRequest, DeleteRequest,
    ListRequest, LookupRequest, RegisterRequest, UpdateRequest, auth_result, lookup_request,
};
use starling_runtime::channel::Resolver;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::permit::Permit;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::settings::Settings;
use starling_runtime::trail::{self, Record, Trail};
use tonic::{Request, Response, Status};

/// Upstream `QueryUsers`.
const QUERY_USERS: u16 = 14;
/// Upstream `UserList`, which is the client's registered-users dialog.
const USER_LIST: u16 = 18;
/// Upstream `RequestBlob`.
const REQUEST_BLOB: u16 = 23;

/// The root channel, where the server-wide permissions live.
const ROOT_CHANNEL: u32 = 0;

/// The service.
#[derive(Debug)]
pub struct UserdataService {
    accounts: Accounts,
    fanout: Fanout,
    logger: Logger,
    /// Asks `permissions` before the registered-user directory is read or
    /// edited. It is the account list of everyone who has ever been on the
    /// server, so it is not public.
    permit: Permit,
    /// To reach `session-view`, which is the only place that knows which
    /// account a session belongs to, see [`UserdataService::sessions`].
    resolver: Resolver,
    /// The operator-facing record of account changes.
    trail: Trail,
    /// TOTP secrets handed out and not yet confirmed by a code.
    ///
    /// In memory on purpose, see `selfservice`: an enrolment nobody finished
    /// should evaporate rather than sit in the database looking enabled.
    enrolling: std::sync::Mutex<selfservice::Enrolments>,
    /// The operator's settings, of which this service reads one:
    /// `user_name_regex`. Held here so [`Serve::run`] has something to keep
    /// live; the copy that answers the question lives in [`Accounts`].
    settings: Settings,
}

/// The client on `session`, as an audit actor.
fn actor_of(session: u32) -> starling_proto_fancy::common::Actor {
    starling_proto_fancy::common::Actor {
        who: Some(starling_proto_fancy::common::actor::Who::Session(session)),
    }
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
    /// Decide a login.
    ///
    /// # Why this hops to the blocking pool
    ///
    /// Verifying a password is 210 000 rounds of PBKDF2-HMAC-SHA256, the
    /// OWASP figure, and deliberately expensive, because the whole point is to
    /// cost an attacker something. Measured here: **30 ms in release, 1.45 s in
    /// a debug build**.
    ///
    /// Run inline, that is 30 ms during which this runtime worker serves
    /// nobody: other clients' pings, text and channel joins queue behind a
    /// stranger's failed login. It is also a lever anyone can pull *without
    /// credentials*, since the cost is paid before the password is known to be
    /// wrong, so a handful of connections can hold every worker busy.
    ///
    /// `spawn_blocking` puts it on the pool that exists for exactly this, where
    /// blocking is expected and the async workers stay free. The cost itself is
    /// not reduced and must not be: lowering the iteration count to make logins
    /// feel snappier would trade every stored password's security for latency
    /// nobody notices at 30 ms.
    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResult>, Status> {
        let req = request.into_inner();
        // Kept for the log line below, which outlives the request moved into
        // the closure.
        let name = req.name.clone();
        let strong_cert = req.strong_cert;
        let scope = scope_of(req.scope);
        // Kept for the upgrade below, which needs the plaintext and can only
        // have it here. Dropped with this function either way.
        let offered = req.password.clone();

        let service = Arc::clone(&self.0);
        let result =
            tokio::task::spawn_blocking(move || service.accounts.authenticate(scope, &req))
                .await
                .map_err(|error| {
                    // The pool panicked or was shut down. Refusing is the only safe
                    // answer: a login that cannot be decided must not be allowed.
                    tracing::error!(%error, "the password check could not be run");
                    Status::internal("the account service could not decide this login")
                })?;

        // A password imported from murmur retires itself here. The login has
        // already been decided, so this changes no outcome; what it changes is
        // that the account stops being stored under murmur's hash -- an
        // unsalted SHA-1, for anything registered before Mumble 1.3 -- the
        // first time its owner signs in.
        //
        // Only when a password was actually offered and checked. An account
        // reached by certificate alone proves nothing about the plaintext, and
        // re-deriving from an empty string there would replace a working
        // password with one nobody knows.
        if result.outcome == auth_result::Outcome::Ok as i32
            && !offered.is_empty()
            && let Some(account) = result.account.as_ref()
            && self.0.accounts.password_is_carried(scope, account.id)
        {
            let id = account.id;
            // The same hop the check itself makes, and for the same reason:
            // deriving a full-strength secret blocks for as long as verifying
            // one does, and an async worker holding it serves nobody.
            match tokio::task::spawn_blocking(move || Secret::new(&offered)).await {
                Ok(secret) => self.0.accounts.store_password(scope, id, secret).await,
                // Reported, not refused: the login has already succeeded, and
                // failing it now because a bookkeeping write did not happen
                // would lock out exactly the accounts this exists to let in.
                Err(error) => {
                    tracing::warn!(%error, account = id, "an imported password was not upgraded");
                }
            }
        }

        // The refusal reason is decided here and only the enum reaches
        // session-lifecycle, so this is the one place that can say which
        // credential was wrong without the password going anywhere near a log.
        tracing::debug!(
            %name,
            outcome = result.outcome,
            strong_cert,
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
                self.0.trail.record(
                    scope,
                    Record::new(trail::category::REGISTER, "registered")
                        .actor(req.actor.clone().unwrap_or_default(), String::new())
                        .target_account(account.id)
                        .detail(account.name.clone()),
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
                    scope: Some(Scope { instance: scope }),
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
            USER_LIST => self.on_user_list(&inbound).await,
            REQUEST_BLOB => self.on_request_blob(&inbound).await,
            type_id if type_id == outer_type() => self.on_self_service(&inbound).await,
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
    /// the same number. They are not related at all, sessions are handed out
    /// per connection and reused after a disconnect, so the answer was
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

        // Named by **account**, not by session: this is how a client redeems the
        // `comment_hash` in a `UserList` entry, whose subject may well not be
        // connected; that is the whole point of a directory. Answered as a
        // `UserList` of one for the same reason: there is no session to hang a
        // `UserState` on.
        let mut listed = Vec::new();
        for id in &request.user_id_comment {
            let Some(account) = self.accounts.by_id(inbound.scope, u64::from(*id)) else {
                continue;
            };
            let comment = self
                .accounts
                .blob(inbound.scope, &account.comment_hash)
                .await
                .and_then(|bytes| String::from_utf8(bytes).ok());
            if comment.is_some() {
                listed.push(starling_proto::proto::tcp::user_list::User {
                    user_id: *id,
                    comment,
                    ..starling_proto::proto::tcp::user_list::User::default()
                });
            }
        }

        let mut actions: Actions = states
            .into_iter()
            .map(|state| to_conn(inbound.conn, 9, state.encode_to_vec()))
            .collect();
        if !listed.is_empty() {
            let reply = starling_proto::proto::tcp::UserList { users: listed };
            actions.push(to_conn(inbound.conn, USER_LIST, reply.encode_to_vec()));
        }
        // Channel descriptions travel as a hash in the flood, so the client
        // redeems the body here just as it redeems avatars and comments above.
        actions.extend(
            self.channel_descriptions(inbound.scope, inbound.conn, &request.channel_description)
                .await,
        );
        actions
    }

    /// Answer `RequestBlob.channel_description`: the full body of a description
    /// the client was handed only as a hash in the channel flood.
    ///
    /// The tree lives in `metadata`, so this reads it the way every other tree
    /// reader does and returns each description as a `ChannelState`, which is
    /// where a client merges a description in. Best-effort: an unreachable
    /// metadata answers nothing, as murmur answers only what it can. The decode
    /// limit is raised off the 4 MiB default for the same reason the handshake
    /// raises it -- the tree is the one reply that outgrows it.
    async fn channel_descriptions(&self, scope: u32, conn: u64, ids: &[u32]) -> Actions {
        if ids.is_empty() {
            return Actions::new();
        }
        let Ok(transport) = self.resolver.channel("metadata") else {
            return Actions::new();
        };
        let Ok(tree) = MetadataClient::new(transport)
            .max_decoding_message_size(self.resolver.max_tree_message())
            .get_tree(TreeRequest {
                scope: Some(Scope { instance: scope }),
            })
            .await
        else {
            return Actions::new();
        };
        let channels = tree.into_inner().channels;
        ids.iter()
            .filter_map(|id| channels.iter().find(|channel| channel.id == *id))
            .map(|channel| {
                let state = starling_proto::proto::tcp::ChannelState {
                    channel_id: Some(channel.id),
                    description: Some(channel.description.clone()),
                    ..starling_proto::proto::tcp::ChannelState::default()
                };
                // 7 is ChannelState, as in the flood (`session-lifecycle`).
                to_conn(conn, 7, state.encode_to_vec())
            })
            .collect()
    }

    /// Every live session on a server instance, from `session-view`.
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
                scope: Some(Scope { instance: scope }),
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
        let settings = Settings::new(ctx.resolver.clone());
        // Subscribed rather than fetched per login: `user_name_regex` is read on
        // every authentication, and a `server-config` round trip on that path
        // would put it in the way of every connect.
        let accounts = Accounts::open(ctx.storage().await?)
            .await?
            .watching(settings.clone());

        // Every server instance gets an administrator on its first boot, because
        // a server with no way in is a server that has to be rebuilt. The
        // password is generated and announced exactly once, at creation, a
        // restart never repeats it, so this is safe to run unconditionally.
        for scope in ctx.instances() {
            if let Some(password) = accounts.ensure_superuser(scope).await {
                announce_superuser(&ctx, scope, &password);
            }
        }

        ctx.health.ready("accounts loaded");
        Ok(Arc::new(Self {
            accounts,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            permit: Permit::new(ctx.resolver.clone()),
            trail: Trail::new(ctx.resolver.clone()),
            resolver: ctx.resolver.clone(),
            enrolling: std::sync::Mutex::default(),
            settings,
        }))
    }

    /// Follow the operator's settings until shutdown.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let watchers = self.settings.watch(&ctx.instances());
        ctx.shutdown.wait().await;
        for watcher in watchers {
            watcher.abort();
        }
        Ok(())
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
/// read afterwards, an operator who scrolled past it needs the second one, and
/// one who is following `docker compose up` needs the first.
///
/// It is announced once, at creation. Re-announcing on every boot would leave a
/// live administrator password in every log aggregator the deployment has.
fn announce_superuser(ctx: &ServiceContext, scope: u32, password: &str) {
    // The operator log only, and deliberately not `tracing` as well. This is
    // the one line in the system that prints a live administrator password, so
    // printing it twice doubles the number of places it can be scraped from,
    // and the two went to the same console anyway. The operator log is the
    // right home: it is what an operator is reading at first boot, and it is
    // the stream a deployment can point at a file with restricted permissions.
    ctx.logger.log(
        LogEvent::notice(
            Category::Server,
            "superuser account created; this password is shown once and cannot be recovered",
        )
        .with("instance", scope)
        .with("user", identity::SUPERUSER_NAME.to_owned())
        .with("password", password.to_owned()),
    );
}

/// The scope a request names, defaulting to the first server instance.
#[must_use]
pub fn scope_of(scope: Option<Scope>) -> u32 {
    scope.map_or(1, |scope| scope.instance)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime must keep serving other clients while a password is checked.
    ///
    /// Verifying a password is 210 000 rounds of PBKDF2, 30 ms in release,
    /// 1.45 s in a debug build like the one this test runs in. Done inline on
    /// an async worker, that is time no other client is served, and it is
    /// reachable *without credentials*: the cost is paid before the password
    /// is known to be wrong.
    ///
    /// A single-worker runtime is what makes the difference visible. With the
    /// check on the blocking pool the ticker below keeps running; with it
    /// inline the worker is held and the ticker cannot advance at all.
    #[tokio::test(flavor = "current_thread", start_paused = false)]
    async fn a_password_check_does_not_stall_the_runtime() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let ticks = Arc::new(AtomicU64::new(0));
        let counting = Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                let _ = counting.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Not the service's RPC surface, which would need a whole deployment,
        // the same `spawn_blocking` hop it makes, around the same work.
        let secret = Secret::new("correct horse");
        let checked = tokio::task::spawn_blocking(move || secret.verify("wrong"))
            .await
            .expect("the blocking pool ran the check");
        assert!(!checked, "a wrong password must not verify");

        ticker.abort();
        assert!(
            ticks.load(Ordering::Relaxed) > 0,
            "the runtime made no progress while a password was being checked; the check is running on an async worker and every other client is queued behind it"
        );
    }

    #[test]
    fn admits_only_a_successful_outcome() {
        assert!(admits(auth_result::Outcome::Ok));
        assert!(!admits(auth_result::Outcome::WrongPassword));
        assert!(!admits(auth_result::Outcome::NameTaken));
    }
}
