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

pub mod http;
pub mod sign;

pub use sign::{Signature, sign, verify};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::files::{
    FilesEnvelope, Grant, Listing, Refused, Share, files_envelope,
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
                    // Keyed by a fresh id, not by filename: two people sharing
                    // `screenshot.png` in one channel must not be the same
                    // object, and the second must not overwrite the first.
                    let key = format!(
                        "{}/{}/{}",
                        upload.channel,
                        uuid::Uuid::now_v7().simple(),
                        safe_name(&upload.filename)
                    );
                    let url = self.grant("PUT", &key);
                    self.remember_pending(
                        &key,
                        Pending {
                            channel: upload.channel,
                            owner: inbound.session,
                            filename: upload.filename.clone(),
                            content_type: upload.content_type.clone(),
                            size: upload.size,
                            // Epoch 1 has one axis: reachable by link, or only
                            // by the people the share is announced to.
                            public: false,
                            expires_at_ms: url.expires_at_ms,
                        },
                    );
                    FilesEnvelope {
                        body: Some(files_envelope::Body::Grant(Grant {
                            request_id: upload.request_id,
                            url: url.url,
                            method: url.method,
                            expires_at_ms: url.expires_at_ms,
                            key,
                        })),
                    }
                }
            }
            Some(files_envelope::Body::Download(download)) => {
                let url = self.grant("GET", &download.key);
                FilesEnvelope {
                    body: Some(files_envelope::Body::Grant(Grant {
                        request_id: download.request_id,
                        url: url.url,
                        method: url.method,
                        expires_at_ms: url.expires_at_ms,
                        key: download.key,
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
                    let retain = self.retain_ms.load(Ordering::Relaxed);
                    if retain > 0 {
                        let _collected = self.collect_expired(retain).await;
                    }
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
    pub(crate) expires_at_ms: u64,
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
             (server_id, k, channel_id, owner, filename, content_type, size, sha256, created_at_ms, public) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
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
            "SELECT k, owner, filename, size, created_at_ms, public FROM object \
             WHERE server_id = ? AND channel_id = ? ORDER BY created_at_ms DESC LIMIT ?",
        )
        .bind(1_i64)
        .bind(i64::from(channel))
        .bind(i64::from(limit))
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default();

        rows.iter()
            .map(|row| Share {
                key: row.try_get("k").unwrap_or_default(),
                channel,
                owner: row.try_get::<i64, _>("owner").unwrap_or_default() as u32,
                filename: row.try_get("filename").unwrap_or_default(),
                size: row.try_get::<i64, _>("size").unwrap_or_default() as u64,
                shared_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default() as u64,
                public: row.try_get::<i64, _>("public").unwrap_or_default() != 0,
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
        if older_than_ms == 0 {
            return 0;
        }
        let cutoff = now_ms().saturating_sub(older_than_ms);
        let rows = sqlx::query("SELECT k FROM object WHERE server_id = ? AND created_at_ms < ?")
            .bind(1_i64)
            .bind(cutoff as i64)
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
                sha256: Vec::new(),
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
            sha256: Vec::new(),
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
