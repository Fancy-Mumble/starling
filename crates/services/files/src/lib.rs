//! `files`: bulk transfer, off the control stream.
//!
//! Mumble has no file transfer; `RequestBlob` (23) moves avatars and comments
//! over the control connection, where anything large head-of-line blocks every
//! control message behind it, and the control-overflow-disconnects rule would
//! then kill clients mid-upload (`docs/ARCHITECTURE.md` §3).
//!
//! So this service gets its own HTTP listener. The gateway hands out a
//! **short-lived signed URL** over the control channel, and bytes move over
//! HTTP: shared files, avatars, comments, plugin binaries, link-preview
//! thumbnails, audit exports. Being HTTP, it can sit behind an `Ingress` and get
//! TLS termination and a CDN for free.

mod crypto;
pub mod http;
pub mod sign;
mod tickets;

pub use sign::{Signature, sign, verify};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::files::{
    FilesEnvelope, Grant, Listing, Refused, Share, UploadRequest, Visibility, files_envelope,
};
use starling_proto_fancy::fancy::wire::{Refusal, refusal};
use starling_proto_fancy::files::files_server::{Files, FilesServer};
use starling_proto_fancy::files::{ObjectInfo, SignRequest, SignedUrl, StatRequest, sign_request};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::config::ByteSize;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

/// A client's filename, reduced to something that can be a path component.
///
/// The name survives into the object key, so `../` in it would otherwise be a
/// directory traversal minted by the server itself. The data plane checks the
/// key again; this is the first of the two, not the only one.
fn safe_name(filename: &str) -> String {
    let cleaned: String = filename
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Runs of dots collapse to one: `-..-etc-passwd` is a legal single path
    // component and so not a traversal, but a name carrying `..` at all is a
    // thing every future reader has to re-derive the safety of.
    let mut collapsed = String::with_capacity(cleaned.len());
    for c in cleaned.chars() {
        if c == '.' && collapsed.ends_with('.') {
            continue;
        }
        collapsed.push(c);
    }
    let trimmed = collapsed.trim_matches(['.', '-']).to_owned();
    if trimmed.is_empty() {
        "file".to_owned()
    } else {
        trimmed
    }
}

/// The service whose roster tells this one who is in a channel.
const VIEW_GATE: &str = "session-view";

/// How long an object is kept when the operator has not said.
///
/// Zero: a shared file stays until somebody removes it. Deleting a colleague's
/// attachment a week later because a default said so is worse than a disk that
/// needs attention.
const DEFAULT_RETAIN_MS: u64 = 0;

/// The schema: one row per stored object.
const SCHEMA: &[Migration<'static>] = &[
    Migration::new(
        "0001_object",
        &[
            "CREATE TABLE IF NOT EXISTS object (\
             server_id BIGINT NOT NULL, k VARCHAR(190) NOT NULL, \
             channel_id BIGINT NOT NULL, owner BIGINT NOT NULL, \
             filename VARCHAR(190) NOT NULL, content_type VARCHAR(190) NOT NULL, \
             size BIGINT NOT NULL, sha256 BLOB NULL, created_at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, k))",
            "CREATE INDEX IF NOT EXISTS ix_object_channel ON object(server_id, channel_id, k)",
        ],
    ),
    Migration::new(
        // Listing a channel's files orders by age and shows who may reach them,
        // neither of which the original row could answer.
        "0002_object_sharing",
        &[
            "ALTER TABLE object ADD COLUMN public BIGINT NOT NULL DEFAULT 0",
            "CREATE INDEX IF NOT EXISTS ix_object_age ON object(server_id, created_at_ms)",
        ],
    ),
    Migration::new(
        // A share behind a password. `public` stayed the coarse "reachable by
        // link" it always was, and these three say what reaching it costs:
        // the hash a guess is checked against, and the salt and nonce the
        // bytes were sealed under. All three are null together or set
        // together - a row with a hash and no salt would be a file nothing
        // could open, and one with a salt and no hash a file anything could.
        "0003_object_password",
        &[
            "ALTER TABLE object ADD COLUMN password_hash VARCHAR(255) NULL",
            "ALTER TABLE object ADD COLUMN enc_salt BLOB NULL",
            "ALTER TABLE object ADD COLUMN enc_nonce BLOB NULL",
        ],
    ),
    Migration::new(
        // A share the uploader put a clock on. Null means it outlives every
        // clock but the operator's own `retain_seconds`, which is the answer
        // every object gave before this column existed.
        "0004_object_expiry",
        &[
            "ALTER TABLE object ADD COLUMN expires_at_ms BIGINT NULL",
            "CREATE INDEX IF NOT EXISTS ix_object_expiry ON object(server_id, expires_at_ms)",
        ],
    ),
];

/// The service.
#[derive(Debug)]
pub struct FilesService {
    store: Store,
    secret: Vec<u8>,
    /// What signed URLs point at, as the operator has it now.
    ///
    /// Live, and the most valuable of the three: a `public_url` that is wrong
    /// -- the wrong scheme behind a new TLS terminator, a hostname that moved,
    /// a port that a proxy no longer forwards -- hands every client a URL that
    /// does not resolve, and every one of those is discovered *after* the
    /// deployment, from users who cannot download anything. Minted per grant,
    /// so correcting it fixes the next URL rather than the next restart.
    public_url: RwLock<Arc<str>>,
    /// How long a signed URL stays valid.
    ttl_ms: AtomicU64,
    /// The largest upload that will be signed for.
    max_upload: AtomicU64,
    fanout: Fanout,
    pub(crate) logger: Logger,
    /// Where the bytes live, under the runtime data directory.
    objects_dir: PathBuf,
    /// Grants minted but not yet spent, keyed by object key.
    pending: RwLock<HashMap<String, Pending>>,
    /// Tickets minted for password shares and not yet redeemed.
    tickets: tickets::Tickets,
    /// Who is in which channel, so a finished upload can be announced to them.
    roster: Arc<Roster>,
    /// How long an object is kept. `0` keeps it for good.
    retain_ms: AtomicU64,
}

impl FilesService {
    /// Mint a signed URL.
    ///
    /// Short-lived and signed rather than a capability that never expires: a
    /// URL that leaks into a log or a chat history should stop working.
    fn grant(&self, method: &str, key: &str) -> SignedUrl {
        let expires = now_ms() + self.ttl_ms.load(Ordering::Relaxed);
        let signature = sign(&self.secret, method, key, expires);
        SignedUrl {
            url: format!(
                "{}/{key}?expires={expires}&sig={signature}",
                self.public_url().trim_end_matches('/')
            ),
            expires_at_ms: expires,
            method: method.to_owned(),
        }
    }

    /// What signed URLs currently point at.
    fn public_url(&self) -> Arc<str> {
        match self.public_url.read() {
            Ok(url) => Arc::clone(&url),
            // Serving a URL is worth more than a panic here, and the poisoned
            // value is still the last one an operator set.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// The largest upload that will be signed for.
    fn max_upload(&self) -> u64 {
        self.max_upload.load(Ordering::Relaxed)
    }

    /// The three keys this service reads from `[services.files]`, resolved.
    fn settings(service: &starling_runtime::config::ServiceConfig) -> (Arc<str>, u64, u64) {
        (
            service
                .public_url
                .clone()
                .unwrap_or_else(|| "http://localhost:8080".to_owned())
                .into(),
            service
                .url_ttl
                .map_or(900_000, |ttl| ttl.get().as_millis() as u64),
            service.max_upload.map_or(512 * 1024 * 1024, ByteSize::get),
        )
    }

    /// Adopt `[services.files]` as the file now states it.
    fn adopt(&self, service: &starling_runtime::config::ServiceConfig) {
        let (public_url, ttl_ms, max_upload) = Self::settings(service);
        if *self.public_url() != *public_url {
            match self.public_url.write() {
                Ok(mut held) => *held = Arc::clone(&public_url),
                Err(poisoned) => *poisoned.into_inner() = Arc::clone(&public_url),
            }
            tracing::info!(public_url = %public_url, "signed URLs now point here");
        }
        self.ttl_ms.store(ttl_ms, Ordering::Relaxed);
        self.max_upload.store(max_upload, Ordering::Relaxed);
        if let Some(retain) = service
            .options
            .get("retain_seconds")
            .and_then(|v| v.parse::<u64>().ok())
        {
            self.retain_ms
                .store(retain.saturating_mul(1_000), Ordering::Relaxed);
        }
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct FilesRpc(Arc<FilesService>);

#[tonic::async_trait]
impl Files for FilesRpc {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignedUrl>, Status> {
        let req = request.into_inner();
        let op = sign_request::Op::try_from(req.op).unwrap_or(sign_request::Op::Get);
        if matches!(op, sign_request::Op::Put) && req.max_bytes > self.0.max_upload() {
            // The client is told, but the operator is the one who can raise the
            // limit, and cannot if the refusal never reaches them.
            self.0.logger.log(
                LogEvent::notice(Category::Permission, "upload refused: over the size limit")
                    .with("key", req.key.clone())
                    .with("requested", req.max_bytes)
                    .with("limit", self.0.max_upload()),
            );
            return Err(Status::invalid_argument(format!(
                "an upload may be at most {} bytes",
                self.0.max_upload()
            )));
        }
        let method = if matches!(op, sign_request::Op::Put) {
            "PUT"
        } else {
            "GET"
        };
        tracing::debug!(key = %req.key, method, "signed url granted");
        Ok(Response::new(self.0.grant(method, &req.key)))
    }

    async fn stat(&self, request: Request<StatRequest>) -> Result<Response<ObjectInfo>, Status> {
        use sqlx::Row as _;
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        let row = sqlx::query(
            "SELECT size, content_type, created_at_ms, sha256 FROM object \
             WHERE server_id = ? AND k = ?",
        )
        .bind(i64::from(scope))
        .bind(&req.key)
        .fetch_optional(self.0.store.pool())
        .await
        .map_err(|error| Status::internal(error.to_string()))?;

        Ok(Response::new(match row {
            Some(row) => ObjectInfo {
                exists: true,
                size: row.try_get::<i64, _>("size").unwrap_or_default() as u64,
                content_type: row.try_get("content_type").unwrap_or_default(),
                created_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default() as u64,
                sha256: row.try_get("sha256").unwrap_or_default(),
            },
            None => ObjectInfo::default(),
        }))
    }

    async fn delete(&self, request: Request<StatRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        let result = sqlx::query("DELETE FROM object WHERE server_id = ? AND k = ?")
            .bind(i64::from(scope))
            .bind(&req.key)
            .execute(self.0.store.pool())
            .await;
        match result {
            Ok(done) if done.rows_affected() > 0 => {
                self.0.logger.log(
                    LogEvent::notice(Category::Admin, "object deleted")
                        .with("key", req.key.clone())
                        .with("scope", scope),
                );
            }
            Ok(_) => tracing::debug!(key = %req.key, "delete for an object that does not exist"),
            Err(error) => {
                // Acknowledged either way, so without this the caller believes
                // a file is gone that is still there.
                tracing::error!(key = %req.key, %error, "could not delete an object");
                self.0.logger.log(
                    LogEvent::error(Category::Admin, "object could not be deleted")
                        .with("key", req.key.clone())
                        .with("error", error.to_string()),
                );
            }
        }
        Ok(Response::new(Ack {}))
    }
}

impl ClientService for FilesService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Files.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = FilesEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };

        let reply = match envelope.body {
            Some(files_envelope::Body::Upload(upload)) => {
                if upload.size > self.max_upload() {
                    FilesEnvelope {
                        body: Some(files_envelope::Body::Refused(Refused {
                            request_id: upload.request_id,
                            refusal: Some(Refusal {
                                kind: refusal::Kind::Limit as i32,
                                detail: format!("the limit is {} bytes", self.max_upload()),
                                retry_after_ms: 0,
                            }),
                        })),
                    }
                } else {
                    match self.prepare_upload(&upload, inbound.session) {
                        Ok(envelope) => envelope,
                        Err(detail) => FilesEnvelope {
                            body: Some(files_envelope::Body::Refused(Refused {
                                request_id: upload.request_id,
                                refusal: Some(Refusal {
                                    kind: refusal::Kind::Invalid as i32,
                                    detail,
                                    retry_after_ms: 0,
                                }),
                            })),
                        },
                    }
                }
            }
            Some(files_envelope::Body::Download(download)) => {
                let url = self.grant("GET", &download.key);
                // The share link, for a client that wants something to copy
                // rather than something to fetch with. Read from the row, so a
                // session-only object still answers with nothing here.
                let record = self.share_record(&download.key).await;
                let share_url = match &record {
                    Some(record) if record.public => self.share_url(&download.key),
                    _ => String::new(),
                };
                FilesEnvelope {
                    body: Some(files_envelope::Body::Grant(Grant {
                        request_id: download.request_id,
                        url: url.url,
                        method: url.method,
                        expires_at_ms: url.expires_at_ms,
                        key: download.key,
                        share_url,
                        share_expires_at_ms: record
                            .and_then(|record| record.expires_at_ms)
                            .unwrap_or_default(),
                    })),
                }
            }
            Some(files_envelope::Body::List(request)) => FilesEnvelope {
                body: Some(files_envelope::Body::Listing(Listing {
                    channel: request.channel,
                    files: self.listing(request.channel, request.limit).await,
                })),
            },
            _ => return Actions::new(),
        };
        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
    }
}

impl Serve for FilesService {
    const NAME: &'static str = "files";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        let service = ctx.service();
        let (public_url, ttl_ms, max_upload) = Self::settings(&service);
        Ok(Arc::new(Self {
            store,
            secret: sign::secret(&ctx.config.runtime.data_dir)?,
            public_url: RwLock::new(public_url),
            ttl_ms: AtomicU64::new(ttl_ms),
            max_upload: AtomicU64::new(max_upload),
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            objects_dir: ctx.config.runtime.data_dir.join("files"),
            pending: RwLock::new(HashMap::new()),
            tickets: tickets::Tickets::default(),
            roster: Arc::new(Roster::new()),
            // `retain_seconds` in `[services.files].options`: a plain number,
            // because this is the one knob and a duration grammar would be a
            // dependency for a single field.
            retain_ms: AtomicU64::new(
                service
                    .options
                    .get("retain_seconds")
                    .and_then(|value| value.parse::<u64>().ok())
                    .map_or(DEFAULT_RETAIN_MS, |seconds| seconds.saturating_mul(1_000)),
            ),
        }))
    }

    /// Follow `[services.files]`, so a corrected `public_url` reaches the next
    /// URL minted rather than the next restart.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        // Who is in which channel, so a finished upload can be announced to
        // the people it was shared with.
        let follower = Arc::clone(&self.roster).follow(ctx.clone(), Self::NAME, VIEW_GATE);
        let collector = tokio::spawn(Arc::clone(&self).collect_loop(ctx.shutdown.clone()));
        let listener = self.spawn_data_plane(&ctx).await;

        let mut configs = ctx.live.subscribe();
        loop {
            tokio::select! {
                () = ctx.shutdown.wait() => break,
                changed = configs.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let config = Arc::clone(&configs.borrow_and_update());
                    if let Some(service) = config.services.get(&ctx.name) {
                        self.adopt(service);
                    }
                }
            }
        }
        follower.abort();
        collector.abort();
        if let Some(listener) = listener {
            listener.abort();
        }
        Ok(())
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(FilesServer::new(FilesRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

impl FilesService {
    /// Bind the listener the signed URLs point at.
    ///
    /// Absent `listen`, the service still signs URLs and still answers the
    /// control plane -- it just is not the thing serving them, which is the
    /// shape a deployment behind separate object storage would take. Logged
    /// either way, because "downloads 404" is otherwise a mystery.
    async fn spawn_data_plane(
        self: &Arc<Self>,
        ctx: &ServiceContext,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let listen = ctx.service().listen?;
        if let Err(error) = tokio::fs::create_dir_all(self.objects_dir()).await {
            tracing::error!(%error, "the object directory could not be created");
            return None;
        }
        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::error!(%listen, %error, "the file listener could not bind");
                self.logger.log(
                    LogEvent::error(Category::Admin, "the file listener could not bind")
                        .with("listen", listen.clone())
                        .with("error", error.to_string()),
                );
                return None;
            }
        };
        tracing::info!(%listen, public_url = %self.public_url(), "files listening");

        let router = http::router(Arc::clone(self));
        let shutdown = ctx.shutdown.clone();
        Some(tokio::spawn(async move {
            let served = axum::serve(listener, router)
                .with_graceful_shutdown(async move { shutdown.wait().await })
                .await;
            if let Err(error) = served {
                tracing::error!(%error, "the file listener stopped");
            }
        }))
    }

    /// Sweep expired objects for as long as the service runs.
    async fn collect_loop(self: Arc<Self>, shutdown: starling_runtime::shutdown::Shutdown) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                () = shutdown.wait() => return,
                _ = tick.tick() => {
                    // Unconditional now: even with no blanket retention there
                    // are objects to collect, because a share can carry a
                    // lifetime of its own.
                    let _collected = self
                        .collect_expired(self.retain_ms.load(Ordering::Relaxed))
                        .await;
                }
            }
        }
    }
}

/// An upload that has been granted but has not arrived.
///
/// The grant proves the client may write *something*; this is what says what.
/// Held server-side rather than encoded into the URL because the filename and
/// the owner are not the client's to restate at `PUT` time -- a client that
/// could would be able to attribute its upload to somebody else.
#[derive(Debug, Clone)]
pub(crate) struct Pending {
    pub(crate) channel: u32,
    pub(crate) owner: u32,
    pub(crate) filename: String,
    pub(crate) content_type: String,
    /// The ceiling this grant was signed for, in bytes.
    pub(crate) size: u64,
    pub(crate) public: bool,
    /// When the *grant* stops being spendable. Not the share's own clock.
    pub(crate) expires_at_ms: u64,
    /// When the finished share stops answering, or `None` for never.
    pub(crate) share_expires_at_ms: Option<u64>,
    /// What a password guess is checked against, for a password share.
    pub(crate) password_hash: Option<String>,
    /// The salt and nonce prefix the bytes are sealed under.
    ///
    /// Alongside the key rather than instead of it: the key is spent sealing
    /// this one upload and then gone, while these two have to outlive it in
    /// the row so a later reader can derive the key again from the password.
    pub(crate) seal: Option<Seal>,
}

/// What is needed to seal one object, and what has to be kept to open it.
#[derive(Clone)]
pub(crate) struct Seal {
    pub(crate) salt: [u8; crypto::ENC_SALT_BYTES],
    pub(crate) nonce: [u8; crypto::ENC_NONCE_PREFIX_BYTES],
    /// Derived once, when the upload was granted.
    ///
    /// Here rather than derived again at `PUT` time because Argon2id is meant
    /// to be slow, and the data plane is where the bytes are already waiting.
    pub(crate) key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Seal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key: `Pending` is `Debug`, and a tracing call that printed
        // one would put the only secret protecting the object in a log.
        formatter.write_str("Seal")
    }
}

impl Pending {
    /// How this upload asked to be shared.
    fn visibility(&self) -> Visibility {
        visibility_of(self.public, self.password_hash.is_some())
    }
}

/// The two stored facts, read back as the one thing they say.
///
/// A password always implies a link - a password on a share nobody can reach
/// protects nothing - so the hash is checked first and `public` only decides
/// between the remaining two.
fn visibility_of(public: bool, locked: bool) -> Visibility {
    match (public, locked) {
        (_, true) => Visibility::Password,
        (true, false) => Visibility::Public,
        (false, false) => Visibility::Session,
    }
}

/// One stored object, as the share routes need to know it.
#[derive(Debug, Clone)]
pub(crate) struct ShareRecord {
    pub(crate) filename: String,
    pub(crate) content_type: String,
    /// Reachable by link at all. A session-only object is not.
    pub(crate) public: bool,
    /// Set when the link also costs a password.
    pub(crate) password_hash: Option<String>,
    pub(crate) enc_salt: Option<Vec<u8>>,
    pub(crate) enc_nonce: Option<Vec<u8>>,
    /// When this share stops answering, or `None` for never.
    pub(crate) expires_at_ms: Option<u64>,
}

impl ShareRecord {
    /// Whether this share's time is up.
    ///
    /// Asked on every read rather than left to the sweeper: the sweeper runs on
    /// a timer, and "expires in seven days" that keeps working until the next
    /// sweep is a promise the server did not keep.
    pub(crate) fn expired(&self) -> bool {
        self.expires_at_ms.is_some_and(|at| at <= now_ms())
    }
}

impl FilesService {
    /// Where objects are written, under the runtime's data directory.
    pub(crate) fn objects_dir(&self) -> &std::path::Path {
        &self.objects_dir
    }

    /// Whether a request's signature is one this server minted and still honours.
    pub(crate) fn verify_grant(
        &self,
        method: &str,
        key: &str,
        expires: u64,
        signature: &str,
    ) -> bool {
        verify(&self.secret, method, key, expires, signature, now_ms())
    }

    /// Remember what a `PUT` grant was for, so the data plane can attribute it.
    fn remember_pending(&self, key: &str, pending: Pending) {
        let mut held = match self.pending.write() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Grants that were never used would otherwise accumulate for the life
        // of the process, one entry per abandoned upload.
        let now = now_ms();
        held.retain(|_, value| value.expires_at_ms > now);
        drop(held.insert(key.to_owned(), pending));
    }

    /// Claim a pending upload. A grant is good for one object, once.
    pub(crate) fn take_pending(&self, key: &str) -> Option<Pending> {
        let mut held = match self.pending.write() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        let pending = held.remove(key)?;
        (pending.expires_at_ms > now_ms()).then_some(pending)
    }

    /// Turn one upload request into the grant that answers it.
    ///
    /// `Err` is the sentence to refuse with. Only one thing is refused here -
    /// a password share with no password - and it is refused rather than
    /// quietly downgraded to a public one, because the difference between
    /// those two is the whole of what the uploader asked for.
    fn prepare_upload(
        &self,
        upload: &UploadRequest,
        session: u32,
    ) -> Result<FilesEnvelope, String> {
        let visibility = Visibility::try_from(upload.visibility).unwrap_or(Visibility::Session);
        let password = upload.password.trim();
        if visibility == Visibility::Password && password.is_empty() {
            return Err("a password share needs a password".to_owned());
        }

        // Sealed before the bytes exist, so the data plane has only cheap work
        // to do once they start arriving: Argon2id twice here, nothing there.
        let (password_hash, seal) = if visibility == Visibility::Password {
            let salt = crypto::generate_salt().map_err(|_| "could not prepare the share")?;
            let nonce =
                crypto::generate_nonce_prefix().map_err(|_| "could not prepare the share")?;
            let key =
                crypto::derive_key(password, &salt).map_err(|_| "could not prepare the share")?;
            let hash =
                crypto::hash_password(password).map_err(|_| "could not prepare the share")?;
            (Some(hash), Some(Seal { salt, nonce, key }))
        } else {
            (None, None)
        };

        // Keyed by a fresh id, not by filename: two people sharing
        // `screenshot.png` in one channel must not be the same object, and the
        // second must not overwrite the first.
        let key = format!(
            "{}/{}/{}",
            upload.channel,
            uuid::Uuid::now_v7().simple(),
            safe_name(&upload.filename)
        );
        let url = self.grant("PUT", &key);
        let public = visibility != Visibility::Session;
        // Counted from the ask rather than from the arrival: an upload that
        // takes an hour was still shared when the person shared it, and a
        // seven-day link that becomes a six-day one because the file was large
        // is a link that expires for a reason nobody can see.
        let share_expires_at_ms = (upload.ttl_seconds > 0)
            .then(|| now_ms().saturating_add(upload.ttl_seconds.saturating_mul(1_000)));
        self.remember_pending(
            &key,
            Pending {
                channel: upload.channel,
                owner: session,
                filename: upload.filename.clone(),
                content_type: upload.content_type.clone(),
                size: upload.size,
                public,
                expires_at_ms: url.expires_at_ms,
                share_expires_at_ms,
                password_hash,
                seal,
            },
        );
        Ok(FilesEnvelope {
            body: Some(files_envelope::Body::Grant(Grant {
                request_id: upload.request_id.clone(),
                url: url.url,
                method: url.method,
                expires_at_ms: url.expires_at_ms,
                share_url: self.share_url_if(public, &key),
                share_expires_at_ms: share_expires_at_ms.unwrap_or_default(),
                key,
            })),
        })
    }

    /// Where an object answers to anyone holding the link.
    ///
    /// A different path from the signed one, and deliberately not a variant of
    /// it: `/s/` is served without a signature, so the two must never be
    /// reachable at the same address by accident. No key can collide with the
    /// prefix, because every key begins with a channel id and channel ids are
    /// digits.
    fn share_url(&self, key: &str) -> String {
        format!("{}/s/{key}", self.public_url().trim_end_matches('/'))
    }

    /// The link for a share that has one, or empty for a session share.
    fn share_url_if(&self, public: bool, key: &str) -> String {
        if public {
            self.share_url(key)
        } else {
            String::new()
        }
    }

    /// One object, as the unsigned share routes need it.
    pub(crate) async fn share_record(&self, key: &str) -> Option<ShareRecord> {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT filename, content_type, public, password_hash, enc_salt, enc_nonce, \
             expires_at_ms FROM object WHERE server_id = ? AND k = ?",
        )
        .bind(1_i64)
        .bind(key)
        .fetch_optional(self.store.pool())
        .await
        .ok()??;
        Some(ShareRecord {
            filename: row.try_get("filename").unwrap_or_default(),
            content_type: row.try_get("content_type").unwrap_or_default(),
            public: row.try_get::<i64, _>("public").unwrap_or_default() != 0,
            password_hash: row.try_get("password_hash").ok().flatten(),
            enc_salt: row.try_get("enc_salt").ok().flatten(),
            enc_nonce: row.try_get("enc_nonce").ok().flatten(),
            expires_at_ms: row
                .try_get::<Option<i64>, _>("expires_at_ms")
                .ok()
                .flatten()
                .map(|at| at as u64),
        })
    }

    /// The tickets minted for this server's password shares.
    pub(crate) fn tickets(&self) -> &tickets::Tickets {
        &self.tickets
    }

    /// The stored content type, for a download's `Content-Type`.
    pub(crate) async fn content_type_of(&self, key: &str) -> Option<String> {
        use sqlx::Row as _;
        let row = sqlx::query("SELECT content_type FROM object WHERE k = ?")
            .bind(key)
            .fetch_optional(self.store.pool())
            .await
            .ok()??;
        row.try_get("content_type").ok()
    }

    /// Record an object that has finished uploading.
    pub(crate) async fn record_object(
        &self,
        key: &str,
        pending: &Pending,
        size: u64,
        now: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO object \
             (server_id, k, channel_id, owner, filename, content_type, size, sha256, created_at_ms, \
             public, password_hash, enc_salt, enc_nonce, expires_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)",
        )
        .bind(1_i64)
        .bind(key)
        .bind(i64::from(pending.channel))
        .bind(i64::from(pending.owner))
        .bind(&pending.filename)
        .bind(&pending.content_type)
        .bind(size as i64)
        .bind(now as i64)
        .bind(i64::from(pending.public))
        .bind(pending.password_hash.clone())
        .bind(pending.seal.as_ref().map(|seal| seal.salt.to_vec()))
        .bind(pending.seal.as_ref().map(|seal| seal.nonce.to_vec()))
        .bind(pending.share_expires_at_ms.map(|at| at as i64))
        .execute(self.store.pool())
        .await
        .map(drop)
    }

    /// Tell the channel a file has arrived.
    ///
    /// This is what makes an upload *shared*. Without it the uploader holds a
    /// URL nobody else has heard of, which is a private file with extra steps.
    pub(crate) fn announce_share(&self, key: &str, pending: &Pending, size: u64) {
        let share = FilesEnvelope {
            body: Some(files_envelope::Body::Share(Share {
                key: key.to_owned(),
                channel: pending.channel,
                owner: pending.owner,
                filename: pending.filename.clone(),
                size,
                shared_at_ms: now_ms(),
                public: pending.public,
                visibility: pending.visibility() as i32,
                share_url: self.share_url_if(pending.public, key),
                expires_at_ms: pending.share_expires_at_ms.unwrap_or_default(),
            })),
        };
        // The uploader included: it learns the final key and size from the same
        // message everyone else does, rather than from a reply only it gets.
        let sessions = self.roster.in_channel(pending.channel, 0);
        if sessions.is_empty() {
            return;
        }
        self.fanout.push_all(vec![to_sessions(
            sessions,
            ServiceKind::Files.outer_type(),
            share.encode_to_vec(),
        )]);
    }

    /// The files shared in a channel, newest first.
    pub(crate) async fn listing(&self, channel: u32, limit: u32) -> Vec<Share> {
        use sqlx::Row as _;
        // Bounded whatever the client asks: an unbounded listing is a way to
        // make the server read its whole table on request.
        let limit = limit.clamp(1, 200);
        let rows = sqlx::query(
            "SELECT k, owner, filename, size, created_at_ms, public, password_hash, \
             expires_at_ms FROM object WHERE server_id = ? AND channel_id = ? \
             AND (expires_at_ms IS NULL OR expires_at_ms > ?) \
             ORDER BY created_at_ms DESC LIMIT ?",
        )
        .bind(1_i64)
        .bind(i64::from(channel))
        .bind(now_ms() as i64)
        .bind(i64::from(limit))
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default();

        rows.iter()
            .map(|row| {
                let key: String = row.try_get("k").unwrap_or_default();
                let public = row.try_get::<i64, _>("public").unwrap_or_default() != 0;
                let locked = row
                    .try_get::<Option<String>, _>("password_hash")
                    .ok()
                    .flatten()
                    .is_some();
                Share {
                    channel,
                    owner: row.try_get::<i64, _>("owner").unwrap_or_default() as u32,
                    filename: row.try_get("filename").unwrap_or_default(),
                    size: row.try_get::<i64, _>("size").unwrap_or_default() as u64,
                    shared_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default() as u64,
                    public,
                    visibility: visibility_of(public, locked) as i32,
                    share_url: self.share_url_if(public, &key),
                    expires_at_ms: row
                        .try_get::<Option<i64>, _>("expires_at_ms")
                        .ok()
                        .flatten()
                        .unwrap_or_default() as u64,
                    key,
                }
            })
            .collect()
    }

    /// Delete objects whose time is up, rows and bytes together.
    ///
    /// Bytes after rows: a row without its file serves a 404, which is a bad
    /// download. A file without its row is invisible and never freed, which is
    /// a disk that fills for reasons nobody can see.
    pub(crate) async fn collect_expired(&self, older_than_ms: u64) -> u64 {
        use sqlx::Row as _;
        // Two clocks, either of which can be the one that ends an object: the
        // operator's blanket retention, and the lifetime the uploader chose.
        // A share past its own expiry goes even where the operator keeps files
        // for good, which is the whole of what choosing one buys.
        let cutoff = (older_than_ms > 0).then(|| now_ms().saturating_sub(older_than_ms));
        let rows = sqlx::query(
            "SELECT k FROM object WHERE server_id = ? \
             AND ((? > 0 AND created_at_ms < ?) \
                  OR (expires_at_ms IS NOT NULL AND expires_at_ms <= ?))",
        )
        .bind(1_i64)
        .bind(cutoff.unwrap_or_default() as i64)
        .bind(cutoff.unwrap_or_default() as i64)
        .bind(now_ms() as i64)
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default();

        let mut collected = 0;
        for row in &rows {
            let key: String = row.try_get("k").unwrap_or_default();
            if key.is_empty() {
                continue;
            }
            let deleted = sqlx::query("DELETE FROM object WHERE server_id = ? AND k = ?")
                .bind(1_i64)
                .bind(&key)
                .execute(self.store.pool())
                .await;
            if deleted.is_ok()
                && let Some(path) = http::object_path(self.objects_dir(), &key)
            {
                drop(tokio::fs::remove_file(path).await);
                collected += 1;
            }
        }
        if collected > 0 {
            tracing::info!(collected, "expired objects collected");
        }
        collected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::fancy::files::UploadRequest;

    async fn service() -> Arc<FilesService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:files-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        Arc::new(FilesService {
            store,
            secret: b"test-secret".to_vec(),
            public_url: RwLock::new("https://files.example.org".into()),
            ttl_ms: AtomicU64::new(900_000),
            max_upload: AtomicU64::new(1024),
            fanout: Fanout::default(),
            logger: Logger::null(),
            objects_dir: std::env::temp_dir().join("starling-files-test"),
            pending: RwLock::new(HashMap::new()),
            tickets: tickets::Tickets::default(),
            roster: Arc::new(Roster::new()),
            retain_ms: AtomicU64::new(0),
        })
    }

    /// A `[services.files]` block with the three reloadable keys set.
    fn block(
        public_url: &str,
        ttl: &str,
        max_upload: &str,
    ) -> starling_runtime::config::ServiceConfig {
        toml::from_str(&format!(
            "public_url = {public_url:?}\nurl_ttl = {ttl:?}\nmax_upload = {max_upload:?}\n"
        ))
        .expect("a [services.files] block")
    }

    #[tokio::test]
    async fn a_corrected_public_url_reaches_the_next_signed_url() {
        // The failure this exists for: a `public_url` naming the wrong scheme
        // or a host that moved hands every client a URL that does not resolve,
        // and it is always discovered from users who cannot download anything.
        let service = service().await;
        assert!(
            service
                .grant("GET", "k")
                .url
                .starts_with("https://files.example.org/"),
            "{}",
            service.grant("GET", "k").url
        );

        service.adopt(&block("https://cdn.example.net", "15m", "512MiB"));

        let granted = service.grant("GET", "k");
        assert!(
            granted.url.starts_with("https://cdn.example.net/k?"),
            "the next URL must point at the corrected host, got {}",
            granted.url
        );
    }

    #[tokio::test]
    async fn a_reloaded_ttl_and_upload_ceiling_take_effect_at_once() {
        let service = service().await;
        assert_eq!(service.max_upload(), 1024);

        service.adopt(&block("https://files.example.org", "1s", "2KiB"));

        assert_eq!(service.max_upload(), 2048);
        let granted = service.grant("GET", "k");
        assert!(
            granted.expires_at_ms <= now_ms() + 1_000,
            "a shortened TTL must apply to the next grant"
        );
    }

    #[tokio::test]
    async fn a_block_that_states_nothing_returns_the_documented_defaults() {
        // Removing a line has to mean the layer below it, here the shipped
        // default, or the file could never express "never mind".
        let service = service().await;
        service.adopt(&starling_runtime::config::ServiceConfig::default());
        assert_eq!(service.max_upload(), 512 * 1024 * 1024);
        assert!(
            service
                .grant("GET", "k")
                .url
                .starts_with("http://localhost:8080/"),
            "{}",
            service.grant("GET", "k").url
        );
    }

    #[tokio::test]
    async fn an_upload_over_the_limit_is_refused_with_the_limit_in_the_message() {
        // "Refused" without a number is a support ticket.
        let service = service().await;
        let envelope = FilesEnvelope {
            body: Some(files_envelope::Body::Upload(UploadRequest {
                request_id: "r1".to_owned(),
                channel: 1,
                filename: "big.bin".to_owned(),
                content_type: "application/octet-stream".to_owned(),
                size: 4096,
                ..UploadRequest::default()
            })),
        };
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: ServiceKind::Files.outer_type(),
                payload: envelope.encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;
        assert_eq!(actions.len(), 1);
    }

    /// One request through the router, answered by the real handler.
    async fn fetch(
        service: &Arc<FilesService>,
        key: &str,
        range: Option<&str>,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        let expires = now_ms() + 60_000;
        let signature = sign(&service.secret, "GET", key, expires);
        let mut builder = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/{key}?expires={expires}&sig={signature}"));
        if let Some(range) = range {
            builder = builder.header("range", range);
        }
        let request = builder.body(axum::body::Body::empty()).expect("a request");

        let response = http::router(Arc::clone(service))
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }

    /// An object on disk, under a key this service will serve.
    fn put_object(service: &Arc<FilesService>, key: &str, bytes: &[u8]) {
        let path = http::object_path(service.objects_dir(), key).expect("a path");
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the object directory");
        std::fs::write(&path, bytes).expect("the object");
    }

    /// One request through the router, with whatever a share link carries.
    async fn call(
        service: &Arc<FilesService>,
        method: &str,
        uri: &str,
        auth: Option<&str>,
        accept: Option<&str>,
        body: Vec<u8>,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(auth) = auth {
            builder = builder.header("authorization", format!("Bearer {auth}"));
        }
        if let Some(accept) = accept {
            builder = builder.header("accept", accept);
        }
        let request = builder
            .body(axum::body::Body::from(body))
            .expect("a request");
        let response = http::router(Arc::clone(service))
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }

    /// Ask for an upload the way a client does, and read the grant back.
    async fn grant_for(service: &Arc<FilesService>, request: UploadRequest) -> Grant {
        match ask(service, request).await.body {
            Some(files_envelope::Body::Grant(grant)) => grant,
            other => panic!("expected a grant, got {other:?}"),
        }
    }

    /// One upload request, as a client would send it.
    fn upload_as(visibility: Visibility, password: &str, size: u64) -> UploadRequest {
        UploadRequest {
            request_id: "r1".to_owned(),
            channel: 4,
            filename: "secret plan.txt".to_owned(),
            content_type: "text/plain".to_owned(),
            size,
            visibility: visibility as i32,
            password: password.to_owned(),
            ..UploadRequest::default()
        }
    }

    /// The same, with a lifetime on it.
    fn upload_lasting(visibility: Visibility, ttl_seconds: u64, size: u64) -> UploadRequest {
        UploadRequest {
            ttl_seconds,
            ..upload_as(visibility, "", size)
        }
    }

    /// Put `bytes` through the granted URL, the way the client streams them.
    async fn put_through(service: &Arc<FilesService>, grant: &Grant, bytes: &[u8]) -> u16 {
        let uri = grant
            .url
            .strip_prefix("https://files.example.org")
            .expect("the granted URL points at this service");
        call(service, "PUT", uri, None, None, bytes.to_vec())
            .await
            .0
    }

    #[tokio::test]
    async fn a_public_share_is_reachable_with_no_signature_at_all() {
        // The whole point of the option: somebody with no account, no client
        // and no session opens the link and gets the file.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Public, "", 11)).await;
        assert!(
            grant.share_url.starts_with("https://files.example.org/s/"),
            "a public share is granted a link to hand out: {}",
            grant.share_url
        );
        assert_eq!(put_through(&service, &grant, b"hello there").await, 201);

        let (status, headers, body) = call(
            &service,
            "GET",
            &format!("/s/{}", grant.key),
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, b"hello there");
        assert!(
            headers
                .get("content-disposition")
                .is_some_and(|value| value.contains("secret plan.txt")),
            "a link opened in a browser saves under the name it was shared as"
        );
    }

    #[tokio::test]
    async fn a_session_share_is_not_reachable_by_link() {
        // The default has to stay what it was: a file shared into a channel is
        // for the channel, and the share route must not quietly widen it.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Session, "", 5)).await;
        assert_eq!(grant.share_url, "", "a session share has no link");
        assert_eq!(put_through(&service, &grant, b"inner").await, 201);

        let (status, ..) = call(
            &service,
            "GET",
            &format!("/s/{}", grant.key),
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(
            status, 404,
            "and it is answered as absent, not as forbidden: telling the \
             difference would make the route a way to test whether a key is real"
        );
    }

    #[tokio::test]
    async fn a_password_share_opens_only_for_the_password() {
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Password, "hunter2", 12)).await;
        assert_eq!(put_through(&service, &grant, b"the contents").await, 201);
        let path = format!("/s/{}", grant.key);

        // The bytes on disk are not the bytes that went in.
        let stored =
            std::fs::read(http::object_path(service.objects_dir(), &grant.key).expect("a path"))
                .expect("the stored object");
        assert_ne!(
            stored, b"the contents",
            "a password share is sealed at rest"
        );

        // No ticket, no file.
        let (status, ..) = call(&service, "GET", &path, None, None, Vec::new()).await;
        assert_eq!(status, 401);

        // The wrong password buys nothing.
        let (status, ..) = call(&service, "POST", &path, Some("hunter3"), None, Vec::new()).await;
        assert_eq!(status, 403);

        // The right one buys a ticket, and the ticket opens it.
        let (status, _, body) =
            call(&service, "POST", &path, Some("hunter2"), None, Vec::new()).await;
        assert_eq!(status, 200);
        let ticket = String::from_utf8(body)
            .expect("json")
            .split('"')
            .nth(3)
            .expect("a ticket in the json")
            .to_owned();
        let (status, _, body) = call(
            &service,
            "GET",
            &format!("{path}?ticket={ticket}"),
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, b"the contents");

        // And the ticket is spent: a link that kept working would be a link
        // that no longer needs the password.
        let (status, ..) = call(
            &service,
            "GET",
            &format!("{path}?ticket={ticket}"),
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn a_password_share_opened_in_a_browser_gets_somewhere_to_type_it() {
        // A JSON 401 in a browser window is a dead end for the person the link
        // was sent to, who has the password and nowhere to put it.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Password, "hunter2", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        let (status, headers, body) = call(
            &service,
            "GET",
            &format!("/s/{}", grant.key),
            None,
            Some("text/html,application/xhtml+xml"),
            Vec::new(),
        )
        .await;
        assert_eq!(status, 401);
        assert!(
            headers
                .get("content-type")
                .is_some_and(|value| value.starts_with("text/html")),
            "a browser gets a page"
        );
        assert!(String::from_utf8_lossy(&body).contains("password"));
    }

    #[tokio::test]
    async fn a_password_share_with_no_password_is_refused_rather_than_widened() {
        // The one way this could go quietly wrong: treating a missing password
        // as "public" would publish a file the uploader meant to lock.
        let service = service().await;
        let envelope = ask(&service, upload_as(Visibility::Password, "  ", 5)).await;
        assert!(
            matches!(envelope.body, Some(files_envelope::Body::Refused(_))),
            "expected a refusal, got {:?}",
            envelope.body
        );
    }

    #[tokio::test]
    async fn a_listing_says_how_each_file_may_be_reached() {
        // What the composer reads to draw the badge on an existing card.
        let service = service().await;
        for (visibility, password) in [
            (Visibility::Session, ""),
            (Visibility::Public, ""),
            (Visibility::Password, "hunter2"),
        ] {
            let grant = grant_for(&service, upload_as(visibility, password, 2)).await;
            assert_eq!(put_through(&service, &grant, b"hi").await, 201);
        }
        let listed = service.listing(4, 50).await;
        let mut seen: Vec<i32> = listed.iter().map(|share| share.visibility).collect();
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![
                Visibility::Session as i32,
                Visibility::Public as i32,
                Visibility::Password as i32,
            ],
            "each of the three comes back as what it was uploaded as"
        );
        for share in &listed {
            let linked = share.visibility != Visibility::Session as i32;
            assert_eq!(
                !share.share_url.is_empty(),
                linked,
                "a link is listed for exactly the shares that have one"
            );
        }
    }

    #[tokio::test]
    async fn a_share_with_a_lifetime_says_when_it_ends_and_stops_when_it_does() {
        let service = service().await;
        let grant = grant_for(&service, upload_lasting(Visibility::Public, 3_600, 2)).await;
        assert!(
            grant.share_expires_at_ms > now_ms(),
            "the server states the moment, so every reader agrees on it"
        );
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        let path = format!("/s/{}", grant.key);
        let (status, ..) = call(&service, "GET", &path, None, None, Vec::new()).await;
        assert_eq!(status, 200, "still inside its lifetime");

        // Wound forward by hand rather than by waiting an hour: what is being
        // tested is that the stored moment is honoured, not the clock.
        let _wound = sqlx::query("UPDATE object SET expires_at_ms = ? WHERE k = ?")
            .bind((now_ms() - 1) as i64)
            .bind(&grant.key)
            .execute(service.store.pool())
            .await
            .expect("wind the clock forward");

        let (status, ..) = call(&service, "GET", &path, None, None, Vec::new()).await;
        assert_eq!(
            status, 404,
            "expired on the read, not only on the next sweep: a link that keeps \
             working until a timer fires is a promise the server did not keep"
        );
        assert!(
            service.listing(4, 50).await.is_empty(),
            "and it is gone from the listing too"
        );
    }

    #[tokio::test]
    async fn a_share_without_a_lifetime_never_expires() {
        // The default has to stay "forever": a file that vanished because the
        // uploader did not pick a lifetime would be a file lost to a default.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert_eq!(grant.share_expires_at_ms, 0);
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        let collected = service.collect_expired(0).await;
        assert_eq!(collected, 0, "the sweeper leaves it alone");
        let (status, ..) = call(
            &service,
            "GET",
            &format!("/s/{}", grant.key),
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn the_sweeper_collects_a_share_whose_own_time_is_up() {
        // Even with no blanket retention: `retain_seconds` is the operator's
        // clock, and a per-share lifetime has to hold without one.
        let service = service().await;
        let grant = grant_for(&service, upload_lasting(Visibility::Public, 3_600, 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);
        let _wound = sqlx::query("UPDATE object SET expires_at_ms = ? WHERE k = ?")
            .bind((now_ms() - 1) as i64)
            .bind(&grant.key)
            .execute(service.store.pool())
            .await
            .expect("wind the clock forward");

        assert_eq!(
            service.collect_expired(0).await,
            1,
            "the row and the bytes go"
        );
        assert!(
            http::object_path(service.objects_dir(), &grant.key).is_some_and(|path| !path.exists()),
            "the bytes are gone from disk, not only from the table"
        );
    }

    #[tokio::test]
    async fn a_download_hands_back_only_the_range_it_was_asked_for() {
        // Without this a video is unplayable: a player asks for a header and a
        // seek point, and a listener that can only answer with whole objects
        // makes it spend the entire file to show one frame.
        let service = service().await;
        let object: Vec<u8> = (0..50_000_u32).map(|byte| (byte % 251) as u8).collect();
        put_object(&service, "9/ranged/clip.mp4", &object);

        let (status, headers, body) =
            fetch(&service, "9/ranged/clip.mp4", Some("bytes=1000-1999")).await;

        assert_eq!(status, 206, "a partial answer to a partial ask");
        assert_eq!(
            headers.get("content-range").map(String::as_str),
            Some("bytes 1000-1999/50000"),
            "the real length is how a player learns how long the file is"
        );
        assert_eq!(
            headers.get("content-length").map(String::as_str),
            Some("1000")
        );
        assert_eq!(body.as_slice(), &object[1000..2000]);
    }

    #[tokio::test]
    async fn a_download_says_it_answers_ranges_even_when_none_was_asked_for() {
        // Read off the first response: a player decides whether seeking is
        // possible before it asks for a second byte.
        let service = service().await;
        put_object(&service, "9/plain/note.txt", b"hello");

        let (status, headers, body) = fetch(&service, "9/plain/note.txt", None).await;

        assert_eq!(status, 200);
        assert_eq!(
            headers.get("accept-ranges").map(String::as_str),
            Some("bytes")
        );
        assert_eq!(headers.get("content-length").map(String::as_str), Some("5"));
        assert_eq!(body.as_slice(), b"hello");
    }

    #[tokio::test]
    async fn an_open_ended_range_is_answered_from_where_it_starts_to_the_end() {
        // `bytes=N-` is what a seek turns into.
        let service = service().await;
        put_object(&service, "9/seek/clip.mp4", &vec![7_u8; 4_096]);

        let (status, headers, body) = fetch(&service, "9/seek/clip.mp4", Some("bytes=4000-")).await;

        assert_eq!(status, 206);
        assert_eq!(
            headers.get("content-range").map(String::as_str),
            Some("bytes 4000-4095/4096")
        );
        assert_eq!(body.len(), 96);
    }

    #[tokio::test]
    async fn a_range_past_the_end_is_refused_with_the_length() {
        // The length in the 416 is what stops a player asking again forever.
        let service = service().await;
        put_object(&service, "9/short/clip.mp4", b"tiny");

        let (status, headers, _) = fetch(&service, "9/short/clip.mp4", Some("bytes=900-999")).await;

        assert_eq!(status, 416);
        assert_eq!(
            headers.get("content-range").map(String::as_str),
            Some("bytes */4")
        );
    }

    #[tokio::test]
    async fn a_range_without_a_valid_grant_is_still_refused() {
        // Ranging is not a way around the signature.
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        let service = service().await;
        put_object(&service, "9/guarded/clip.mp4", b"secret");

        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/9/guarded/clip.mp4?expires=99999999999999&sig=deadbeef")
            .header("range", "bytes=0-3")
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = http::router(Arc::clone(&service))
            .oneshot(request)
            .await
            .expect("the router answers");

        assert_eq!(response.status().as_u16(), 403);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes();
        assert!(!body.starts_with(b"secr"), "no bytes leak past the check");
    }

    #[tokio::test]
    async fn a_granted_url_expires() {
        let service = service().await;
        let url = service.grant("GET", "1/file.txt");
        assert!(url.expires_at_ms > now_ms());
        assert!(url.url.contains("sig="));
    }

    /// Ask for an upload the way a client does, and read back what it is told.
    async fn ask(service: &Arc<FilesService>, upload: UploadRequest) -> FilesEnvelope {
        let envelope = FilesEnvelope {
            body: Some(files_envelope::Body::Upload(upload)),
        };
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 7,
                type_id: ServiceKind::Files.outer_type(),
                payload: envelope.encode_to_vec(),
                gateway: String::new(),
                scope: 1,
            })
            .await;
        let action = actions.into_iter().next().expect("a reply");
        let Some(starling_proto_fancy::control::server_action::Action::Send(sent)) = action.action
        else {
            panic!("a reply is a send");
        };
        FilesEnvelope::decode(sent.payload.as_slice()).expect("a files envelope")
    }

    fn upload_of(filename: &str, size: u64) -> UploadRequest {
        UploadRequest {
            request_id: "r1".to_owned(),
            channel: 3,
            filename: filename.to_owned(),
            content_type: "image/png".to_owned(),
            size,
            ..UploadRequest::default()
        }
    }

    #[tokio::test]
    async fn two_uploads_of_one_filename_are_two_objects() {
        // The failure this exists for: keying by `channel/filename` made the
        // second person to share `screenshot.png` overwrite the first.
        let service = service().await;
        let first = ask(&service, upload_of("screenshot.png", 10)).await;
        let second = ask(&service, upload_of("screenshot.png", 10)).await;

        let (Some(files_envelope::Body::Grant(first)), Some(files_envelope::Body::Grant(second))) =
            (first.body, second.body)
        else {
            panic!("both uploads are granted");
        };
        assert_ne!(first.key, second.key, "one name must not be one object");
        assert!(
            first.key.starts_with("3/"),
            "keyed under its channel: {}",
            first.key
        );
        assert!(
            first.key.ends_with("screenshot.png"),
            "the name survives: {}",
            first.key
        );
    }

    #[tokio::test]
    async fn a_filename_cannot_carry_a_path_out_of_the_channel() {
        // The name reaches the key, and the key reaches the filesystem.
        let service = service().await;
        let granted = ask(&service, upload_of("../../etc/passwd", 10)).await;
        let Some(files_envelope::Body::Grant(granted)) = granted.body else {
            panic!("granted");
        };
        assert!(
            !granted.key.contains(".."),
            "no traversal in {}",
            granted.key
        );
        assert_eq!(
            granted.key.split('/').count(),
            3,
            "channel/id/name: {}",
            granted.key
        );
    }

    #[tokio::test]
    async fn an_upload_over_the_ceiling_is_refused_with_the_limit() {
        // Refused rather than granted-then-truncated: the client can say why.
        let service = service().await;
        let refused = ask(&service, upload_of("big.bin", 4096)).await;
        let Some(files_envelope::Body::Refused(refused)) = refused.body else {
            panic!("over the ceiling is a refusal");
        };
        assert_eq!(
            refused.request_id, "r1",
            "correlated to the request it refuses"
        );
        let refusal = refused.refusal.expect("a reason");
        assert_eq!(refusal.kind, refusal::Kind::Limit as i32);
        assert!(
            refusal.detail.contains("1024"),
            "says the limit: {}",
            refusal.detail
        );
    }

    #[tokio::test]
    async fn a_grant_is_good_for_one_upload_only() {
        // Replay protection: the signature stays valid until it expires, so
        // without spending the pending record a client could write the same
        // key repeatedly, each time re-announcing it to the channel.
        let service = service().await;
        let granted = ask(&service, upload_of("once.bin", 10)).await;
        let Some(files_envelope::Body::Grant(granted)) = granted.body else {
            panic!("granted");
        };
        assert!(
            service.take_pending(&granted.key).is_some(),
            "the first PUT is expected"
        );
        assert!(
            service.take_pending(&granted.key).is_none(),
            "the second is not"
        );
    }

    #[tokio::test]
    async fn an_upload_is_attributed_to_the_session_that_asked() {
        // Attribution is server-side because the client does not restate it at
        // PUT time -- one that could would be able to sign a file as somebody
        // else.
        let service = service().await;
        let granted = ask(&service, upload_of("mine.png", 10)).await;
        let Some(files_envelope::Body::Grant(granted)) = granted.body else {
            panic!("granted");
        };
        let pending = service.take_pending(&granted.key).expect("pending");
        assert_eq!(pending.owner, 7, "the asking session owns it");
        assert_eq!(pending.channel, 3);
        assert_eq!(
            pending.filename, "mine.png",
            "the original name, not the sanitised one"
        );
    }

    #[tokio::test]
    async fn a_recorded_object_is_listed_for_its_channel() {
        let service = service().await;
        let pending = Pending {
            channel: 3,
            owner: 7,
            filename: "notes.pdf".to_owned(),
            content_type: "application/pdf".to_owned(),
            size: 100,
            public: false,
            expires_at_ms: now_ms() + 60_000,
            share_expires_at_ms: None,
            password_hash: None,
            seal: None,
        };
        service
            .record_object("3/abc/notes.pdf", &pending, 84, now_ms())
            .await
            .expect("recorded");

        let listed = service.listing(3, 50).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].filename, "notes.pdf");
        assert_eq!(
            listed[0].size, 84,
            "the size that arrived, not the size claimed"
        );
        assert!(
            service.listing(4, 50).await.is_empty(),
            "another channel sees nothing"
        );
    }

    #[tokio::test]
    async fn expired_objects_are_collected_and_current_ones_are_not() {
        let service = service().await;
        let pending = Pending {
            channel: 3,
            owner: 7,
            filename: "old.bin".to_owned(),
            content_type: "application/octet-stream".to_owned(),
            size: 10,
            public: false,
            expires_at_ms: now_ms() + 60_000,
            share_expires_at_ms: None,
            password_hash: None,
            seal: None,
        };
        // One well past the horizon, one just made.
        service
            .record_object("3/old/old.bin", &pending, 10, now_ms() - 100_000)
            .await
            .expect("recorded");
        service
            .record_object("3/new/new.bin", &pending, 10, now_ms())
            .await
            .expect("recorded");

        assert_eq!(
            service.collect_expired(50_000).await,
            1,
            "only the old one goes"
        );
        let left = service.listing(3, 50).await;
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].key, "3/new/new.bin");
    }

    #[tokio::test]
    async fn retention_of_zero_collects_nothing() {
        // The default. Deleting a colleague's attachment because a default
        // said so is worse than a disk that needs attention.
        let service = service().await;
        let pending = Pending {
            channel: 3,
            owner: 7,
            filename: "keep.bin".to_owned(),
            content_type: "application/octet-stream".to_owned(),
            size: 10,
            public: false,
            expires_at_ms: now_ms() + 60_000,
            share_expires_at_ms: None,
            password_hash: None,
            seal: None,
        };
        service
            .record_object("3/keep/keep.bin", &pending, 10, 0)
            .await
            .expect("recorded");
        assert_eq!(service.collect_expired(0).await, 0);
        assert_eq!(service.listing(3, 50).await.len(), 1);
    }

    #[tokio::test]
    async fn a_listing_is_bounded_however_much_is_asked_for() {
        // An unbounded listing is a way to make the server read its whole
        // table on request.
        let service = service().await;
        assert!(service.listing(3, u32::MAX).await.len() <= 200);
    }
}
