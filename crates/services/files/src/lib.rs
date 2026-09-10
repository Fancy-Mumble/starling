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

mod attempts;
mod crypto;
pub mod http;
mod names;
mod namespace;
pub mod sign;
mod thumb;
mod tickets;

pub use sign::{Signature, sign, verify};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::files::{
    Audience, Emote, EmoteForget, EmoteUpload, Emotes, FilesEnvelope, ForgetRequest, Grant,
    Listing, ManageListing, ManageRequest, ManagedFile, Refused, Share, Storage, UploadRequest,
    Visibility, files_envelope,
};
use starling_proto_fancy::fancy::wire::{Refusal, refusal};
use starling_proto_fancy::files::files_server::{Files, FilesServer};
use starling_proto_fancy::files::{
    ListNamesRequest, NameListing, NameRequest, NameRevision, NameRevisions, NamedObject,
    ObjectInfo, PutNameRequest, Reservation, ReserveRequest, RevisionsRequest, SignRequest,
    SignedUrl, StatRequest, sign_request,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::config::ByteSize;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::permit::Permit;
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

/// Whether `shortcode` is something a client can type between colons.
///
/// Letters, digits, `_` and `-`, and at least one of them. Stricter than
/// `safe_name`, which exists to make a filename a path component and would
/// happily turn `:-)` into `file`.
fn is_shortcode(shortcode: &str) -> bool {
    !shortcode.is_empty()
        && shortcode
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// An emote's alias and description as one string for the name's `meta`.
///
/// A unit separator between the two, which neither an emoji nor a sentence
/// contains, and no JSON: this is two strings, not a document.
fn pack_emote_meta(facts: &EmoteFacts) -> String {
    format!("{}\u{1f}{}", facts.alias_emoji, facts.description)
}

/// The inverse, tolerant of a name that says nothing.
fn unpack_emote_meta(meta: Option<&str>) -> (String, String) {
    meta.and_then(|packed| packed.split_once('\u{1f}'))
        .map_or_else(
            || (String::new(), String::new()),
            |(alias, description)| (alias.to_owned(), description.to_owned()),
        )
}

/// One stored revision, as the wire carries it.
fn revision_of(revision: names::Revision) -> NameRevision {
    NameRevision {
        found: true,
        rev: revision.rev,
        key: revision.key,
        created_at_ms: revision.created_at_ms,
    }
}

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

/// One `[services.files].options` entry read as a count of seconds, in ms.
fn seconds(service: &starling_runtime::config::ServiceConfig, key: &str) -> Option<u64> {
    service
        .options
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.saturating_mul(1_000))
}

/// One `[services.files].options` entry read as a switch, off unless said.
fn flag(service: &starling_runtime::config::ServiceConfig, key: &str) -> bool {
    service
        .options
        .get(key)
        .is_some_and(|value| matches!(value.trim(), "true" | "yes" | "1"))
}

/// The channel a server-wide permission is asked at.
///
/// Mumble expresses "administers this server" as holding a permission on the
/// root, so that is where the operator questions go.
const ROOT_CHANNEL: u32 = 0;

/// What reading a channel's files costs.
///
/// `Enter`, and not `SeeChannel`. `SeeChannel` is not in the default set, and
/// the rest of this server only consults it for channels flagged hidden
/// (`metadata::visible_to`) - so requiring it here would make an unconfigured
/// server hide every file from everybody, which is stricter than the channel
/// the file is in. `Enter` is the permission that says a session belongs in
/// this channel, and a channel that denies it to somebody is a channel whose
/// files are not theirs either.
///
/// A hidden channel's files are covered only as far as its own `Enter` covers
/// it. Tightening that means teaching this service about channel flags, which
/// is `metadata`'s to know rather than this one's.
const READ_CHANNEL: Perm = Perm::ENTER;

/// Which channel an object key belongs to, for a key a client may name.
///
/// The key is minted here as `{channel}/{id}/{name}`, so its first component
/// is the channel the file was shared in. Read back rather than looked up
/// because the permission check has to happen before the row is touched.
///
/// `None` for a key in one of the lettered namespaces (`u/`, `s/`, `p/`),
/// which a client frame may not name at all: those are reached through the
/// account's own surfaces or through the host, and answering one here would
/// check it against the root channel - a permission every session holds.
fn client_channel_of(key: &str) -> Option<u32> {
    match namespace::namespace_of(key) {
        namespace::Namespace::Channel(channel) => Some(channel),
        _ => None,
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
    Migration::new(
        // Who shared it, in terms that outlive the sharing. `owner` is a
        // session id: per connection, recycled, and meaningless the moment the
        // uploader reconnects - so a listing could say a file belonged to
        // whoever happens to hold that number now. These three are the person.
        "0005_object_uploader",
        &[
            "ALTER TABLE object ADD COLUMN uploader_account BIGINT NULL",
            "ALTER TABLE object ADD COLUMN uploader_name VARCHAR(190) NULL",
            "ALTER TABLE object ADD COLUMN uploader_cert BLOB NULL",
        ],
    ),
    Migration::new(
        // When it was last read. The operator's view shows it, and it is the
        // one column here that answers "is this file still being used".
        "0006_object_read",
        &["ALTER TABLE object ADD COLUMN downloaded_at_ms BIGINT NULL"],
    ),
    Migration::new(
        // Whether a derived preview sits beside this object.
        //
        // On the original's row rather than inferred from the thumbnail's,
        // so a listing answers "is there a preview" for free. The alternative
        // was a second query per page, or a `LIKE` scan over every key in the
        // channel, to learn something one bit already says.
        //
        // Not backfilled: objects uploaded before this have no preview, which
        // is exactly what `0` means.
        "0007_object_thumb",
        &["ALTER TABLE object ADD COLUMN has_thumb INTEGER NOT NULL DEFAULT 0"],
    ),
];

/// The preview key a listing row should report, or empty when there is none.
///
/// Read off `has_thumb` rather than guessed from the content type: a picture
/// whose format the decoder did not recognise has no preview, and naming one
/// that does not exist shows the reader a broken image.
fn thumb_key_of(row: &sqlx::any::AnyRow, key: &str) -> String {
    use sqlx::Row as _;

    if row.try_get::<i64, _>("has_thumb").unwrap_or_default() == 0 {
        return String::new();
    }
    thumb::thumb_key(key)
}

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
    /// Names over objects: what a document or an emote is reached by, and the
    /// revisions each has accumulated. See `names`.
    names: names::Names,
    /// Grants minted but not yet spent, keyed by object key.
    pending: RwLock<HashMap<String, Pending>>,
    /// Tickets minted for password shares and not yet redeemed.
    tickets: tickets::Tickets,
    /// Wrong password guesses, so a share link cannot simply be brute-forced.
    attempts: attempts::Attempts,
    /// Who is in which channel, so a finished upload can be announced to them.
    roster: Arc<Roster>,
    /// Asks `permissions` whether the session in front of us may do this.
    ///
    /// Every route into this service goes through it. A file server that
    /// skipped the ACL would make every channel's contents readable by anyone
    /// who can connect, whatever the channel's own permissions say - and a
    /// share link would be publishable by a guest.
    permit: Permit,
    /// How long an object is kept. `0` keeps it for good.
    retain_ms: AtomicU64,
    /// The longest lifetime an uploader may ask for. `0` is no ceiling.
    max_ttl_ms: AtomicU64,
    /// Bytes this server will hold across every object. `0` is no ceiling.
    max_total_storage: AtomicU64,
    /// Whether an object is destroyed by the first download that succeeds.
    delete_on_download: AtomicBool,
    /// Whether a session's uploads go when the session does.
    delete_on_disconnect: AtomicBool,
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
        if let Some(retain) = seconds(service, "retain_seconds") {
            self.retain_ms.store(retain, Ordering::Relaxed);
        }
        if let Some(ceiling) = seconds(service, "max_ttl_seconds") {
            self.max_ttl_ms.store(ceiling, Ordering::Relaxed);
        }
        if let Some(cap) = service
            .options
            .get("max_total_storage")
            .and_then(|value| value.parse::<ByteSize>().ok())
        {
            self.max_total_storage.store(cap.get(), Ordering::Relaxed);
        }
        self.delete_on_download
            .store(flag(service, "delete_on_download"), Ordering::Relaxed);
        self.delete_on_disconnect
            .store(flag(service, "delete_on_disconnect"), Ordering::Relaxed);
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

    async fn reserve(
        &self,
        request: Request<ReserveRequest>,
    ) -> Result<Response<Reservation>, Status> {
        let req = request.into_inner();
        // A lettered namespace only. A channel upload is permission-checked on
        // the client envelope; a reservation is not checked at all, because
        // its callers are other services and the namespace they hand over is
        // what says who may reach the object. One that named a channel would
        // be a channel share nobody was asked about.
        if matches!(
            namespace::namespace_of(&format!("{}/x", req.ns.trim_end_matches('/'))),
            namespace::Namespace::Channel(_)
        ) {
            return Err(Status::invalid_argument(
                "a reservation names an account, server or plugin namespace, not a channel",
            ));
        }
        if req.size > self.0.max_upload() {
            return Err(Status::invalid_argument(format!(
                "an upload may be at most {} bytes",
                self.0.max_upload()
            )));
        }
        if !self.0.has_room_for(req.size).await {
            return Err(Status::resource_exhausted(
                "this server has no room for more files",
            ));
        }

        // The same shape a channel upload mints, for the same reason: a fresh
        // id rather than the filename, so storing one name twice is two
        // objects and the second cannot overwrite the first.
        let key = format!(
            "{}/{}/{}",
            req.ns.trim_end_matches('/'),
            uuid::Uuid::now_v7().simple(),
            safe_name(&req.filename)
        );
        let url = self.0.grant("PUT", &key);
        self.0.remember_pending(
            &key,
            Pending {
                // Not a channel object. Zero is the root, and the namespace in
                // the key is what actually decides who may reach this - a
                // client frame cannot name it at all.
                channel: 0,
                owner: 0,
                filename: safe_name(&req.filename),
                content_type: req.content_type,
                size: req.size,
                public: req.public,
                expires_at_ms: url.expires_at_ms,
                share_expires_at_ms: None,
                uploader: Uploader::default(),
                password_hash: None,
                seal: None,
                bind: None,
            },
        );
        tracing::debug!(ns = %req.ns, key = %key, "reserved an upload slot");
        Ok(Response::new(Reservation {
            key,
            url: url.url,
            method: url.method,
            expires_at_ms: url.expires_at_ms,
        }))
    }

    async fn put_name(
        &self,
        request: Request<PutNameRequest>,
    ) -> Result<Response<NameRevision>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        let rev = self
            .0
            .names
            .put(scope, &req.ns, &req.name, &req.key, None)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;

        // Trimming after the write, not before: the new revision has to exist
        // before anything decides which older ones are surplus, or a `keep` of
        // one would drop the revision that was about to become the latest.
        if req.keep > 0 {
            for orphan in self.0.names.trim(scope, &req.ns, &req.name, req.keep).await {
                self.0.forget_object(&orphan).await;
            }
        }
        tracing::debug!(ns = %req.ns, name = %req.name, rev, "name stored");
        Ok(Response::new(NameRevision {
            found: true,
            rev,
            key: req.key,
            created_at_ms: now_ms(),
        }))
    }

    async fn latest_name(
        &self,
        request: Request<NameRequest>,
    ) -> Result<Response<NameRevision>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        Ok(Response::new(
            self.0
                .names
                .latest(scope, &req.ns, &req.name)
                .await
                .map_or_else(NameRevision::default, revision_of),
        ))
    }

    async fn list_revisions(
        &self,
        request: Request<RevisionsRequest>,
    ) -> Result<Response<NameRevisions>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        let revisions = self
            .0
            .names
            .revisions(scope, &req.ns, &req.name, req.limit)
            .await;
        Ok(Response::new(NameRevisions {
            revisions: revisions.into_iter().map(revision_of).collect(),
        }))
    }

    async fn list_names(
        &self,
        request: Request<ListNamesRequest>,
    ) -> Result<Response<NameListing>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        Ok(Response::new(NameListing {
            names: self
                .0
                .names
                .list(scope, &req.ns)
                .await
                .into_iter()
                .map(|(name, latest)| NamedObject {
                    name,
                    latest: Some(revision_of(latest)),
                })
                .collect(),
        }))
    }

    async fn forget_name(&self, request: Request<NameRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        // The bytes go with the last name that held them: an object nothing
        // points at is unreachable, and leaving it is a disk that only grows.
        for orphan in self.0.names.forget(scope, &req.ns, &req.name).await {
            self.0.forget_object(&orphan).await;
        }
        Ok(Response::new(Ack {}))
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
                self.answer_upload(&inbound, upload).await
            }
            Some(files_envelope::Body::Download(download)) => {
                self.answer_download(&inbound, download).await
            }
            Some(files_envelope::Body::List(request)) => self.answer_list(&inbound, request).await,
            Some(files_envelope::Body::Manage(request)) => {
                self.answer_manage(&inbound, request).await
            }
            Some(files_envelope::Body::Forget(request)) => {
                self.answer_forget(&inbound, request).await
            }
            Some(files_envelope::Body::EmoteUpload(upload)) => {
                self.answer_emote_upload(&inbound, upload).await
            }
            Some(files_envelope::Body::EmoteForget(request)) => {
                self.answer_emote_forget(&inbound, request).await
            }
            Some(files_envelope::Body::EmoteQuery(query)) => {
                self.emote_listing(inbound.scope, &query.request_id).await
            }
            _ => return Actions::new(),
        };
        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
    }
}

impl FilesService {
    /// Answer an upload request, if the session may make one.
    ///
    /// Two bits, as the epoch-0 plugin had them: one to share at all, and a
    /// second to make the share reachable by link. They are separate because
    /// they are separate decisions - a server can want its members exchanging
    /// files without any of them able to publish one to the open internet.
    async fn answer_upload(&self, inbound: &Inbound, upload: UploadRequest) -> FilesEnvelope {
        let visibility = Visibility::try_from(upload.visibility).unwrap_or(Visibility::Session);
        let needed = if visibility == Visibility::Session {
            Perm::SHARE_FILES
        } else {
            Perm::SHARE_FILES.union(Perm::SHARE_FILES_PUBLIC)
        };
        if !self.allows(inbound, upload.channel, needed).await {
            self.logger.log(
                LogEvent::notice(Category::Permission, "upload refused: not allowed")
                    .with("channel", upload.channel)
                    .with("session", inbound.session),
            );
            return refused(
                &upload.request_id,
                refusal::Kind::Permission,
                if visibility == Visibility::Session {
                    "you may not share files here"
                } else {
                    "you may not share files by link here"
                },
            );
        }
        if upload.size > self.max_upload() {
            return refused(
                &upload.request_id,
                refusal::Kind::Limit,
                &format!("the limit is {} bytes", self.max_upload()),
            );
        }
        if !self.has_room_for(upload.size).await {
            self.logger.log(
                LogEvent::notice(Category::Admin, "upload refused: the server is full")
                    .with("size", upload.size)
                    .with("cap", self.max_total_storage.load(Ordering::Relaxed)),
            );
            return refused(
                &upload.request_id,
                refusal::Kind::Limit,
                "this server has no room for more files",
            );
        }
        match self.prepare_upload(&upload, inbound.session) {
            Ok(envelope) => envelope,
            Err(detail) => refused(&upload.request_id, refusal::Kind::Invalid, &detail),
        }
    }

    /// Answer a download request, if the session may read that channel.
    ///
    /// A key is not an authorisation. Keys travel in messages and in listings,
    /// so one reaching a session that may not see the channel it belongs to is
    /// ordinary rather than exceptional - and without this check, holding it
    /// would be enough.
    async fn answer_download(
        &self,
        inbound: &Inbound,
        download: starling_proto_fancy::fancy::files::DownloadRequest,
    ) -> FilesEnvelope {
        let Some(channel) = client_channel_of(&download.key) else {
            // A key in a namespace no client frame speaks for. Invalid rather
            // than a refusal, and worded like a key that names nothing:
            // whether an account or a plugin holds an object is not something
            // to confirm to whoever went looking.
            return refused(&download.request_id, refusal::Kind::Invalid, "no such file");
        };
        if !self.allows(inbound, channel, READ_CHANNEL).await {
            return refused(
                &download.request_id,
                refusal::Kind::Permission,
                "you may not read files from that channel",
            );
        }
        let url = self.grant("GET", &download.key);
        // The share link, for a client that wants something to copy rather
        // than something to fetch with. Read from the row, so a session-only
        // object still answers with nothing here.
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

    /// Answer a listing, empty for a channel the session cannot see.
    ///
    /// Empty rather than a refusal: this is also how a client discovers the
    /// service exists at all, and a channel the asker cannot see should look
    /// like a channel with no files rather than like one it is being kept out
    /// of.
    async fn answer_list(
        &self,
        inbound: &Inbound,
        request: starling_proto_fancy::fancy::files::ListRequest,
    ) -> FilesEnvelope {
        let allowed = self.allows(inbound, request.channel, READ_CHANNEL).await;
        FilesEnvelope {
            body: Some(files_envelope::Body::Listing(Listing {
                channel: request.channel,
                files: if allowed {
                    self.listing(request.channel, request.limit).await
                } else {
                    Vec::new()
                },
            })),
        }
    }
}

impl FilesService {
    /// Answer "my shared files", or an operator's view of every file.
    ///
    /// Two audiences from one query, differing in the `WHERE` and in whether
    /// the storage header is filled: a user's own files say nothing about the
    /// server's disk, and an operator asking about the disk is not asking
    /// about their own uploads.
    async fn answer_manage(&self, inbound: &Inbound, request: ManageRequest) -> FilesEnvelope {
        let audience = Audience::try_from(request.audience).unwrap_or(Audience::Mine);
        if audience == Audience::Everyone && !self.administers(inbound).await {
            return refused(
                &request.request_id,
                refusal::Kind::Permission,
                "you do not administer this server",
            );
        }
        let limit = i64::from(request.limit.clamp(1, 500));
        let files = match audience {
            Audience::Everyone => self.managed_files(None, limit).await,
            // Matched on the account where there is one, so a reconnect still
            // finds the same files; a guest has only their session id, which
            // is why their list empties when they come back as somebody else.
            Audience::Mine => {
                self.managed_files(Some(self.identity_of(inbound.session)), limit)
                    .await
            }
        };
        FilesEnvelope {
            body: Some(files_envelope::Body::Managed(ManageListing {
                request_id: request.request_id,
                files,
                storage: match audience {
                    Audience::Everyone => Some(self.storage_stats().await),
                    Audience::Mine => None,
                },
            })),
        }
    }

    /// Remove one stored file, if it is the caller's or they may remove others'.
    async fn answer_forget(&self, inbound: &Inbound, request: ForgetRequest) -> FilesEnvelope {
        if client_channel_of(&request.key).is_none() {
            // Not the caller's to remove, and not theirs to learn about. Said
            // the same way a key that names nothing is said.
            return refused(&request.request_id, refusal::Kind::Invalid, "no such file");
        }
        let Some(owner) = self.owner_of(&request.key).await else {
            // Absent rather than refused: a key that names nothing is not a
            // permission question, and answering it as one would say which
            // keys exist.
            return refused(&request.request_id, refusal::Kind::Invalid, "no such file");
        };
        let mine = owner.matches(&self.identity_of(inbound.session));
        if !mine
            && !self
                .allows(inbound, ROOT_CHANNEL, Perm::RESET_USER_CONTENT)
                .await
        {
            return refused(
                &request.request_id,
                refusal::Kind::Permission,
                "that file is not yours to remove",
            );
        }
        self.forget_object(&request.key).await;
        self.logger.log(
            LogEvent::notice(Category::Admin, "a shared file was removed")
                .with("key", request.key.clone())
                .with("session", inbound.session)
                .with("own", mine),
        );
        FilesEnvelope {
            body: Some(files_envelope::Body::Managed(ManageListing {
                request_id: request.request_id,
                files: Vec::new(),
                storage: None,
            })),
        }
    }

    /// Grant an upload slot for one emote, if the session may manage them.
    ///
    /// The image lands in `s/emotes/` and the shortcode becomes its name, so
    /// replacing an emote keeps the shortcode and swaps what it points at.
    /// Only one revision is kept: the previous image is unreachable the moment
    /// the name moves, and an emoji has no history worth a disk.
    async fn answer_emote_upload(&self, inbound: &Inbound, upload: EmoteUpload) -> FilesEnvelope {
        if !self
            .allows(inbound, ROOT_CHANNEL, Perm::MANAGE_EMOTES)
            .await
        {
            return refused(
                &upload.request_id,
                refusal::Kind::Permission,
                "you may not manage this server's emotes",
            );
        }
        // Validated rather than sanitised: `safe_name` answers `"file"` for a
        // name it reduced to nothing, and an emote called `:file:` because
        // somebody typed `:-)` is a surprise, not a fix.
        if !is_shortcode(&upload.shortcode) {
            return refused(
                &upload.request_id,
                refusal::Kind::Invalid,
                "a shortcode is letters, digits, `_` and `-`, and at least one of them",
            );
        }
        let shortcode = upload.shortcode.clone();
        if upload.size > self.max_upload() {
            return refused(
                &upload.request_id,
                refusal::Kind::Limit,
                &format!("the limit is {} bytes", self.max_upload()),
            );
        }
        if !self.has_room_for(upload.size).await {
            return refused(
                &upload.request_id,
                refusal::Kind::Limit,
                "this server has no room for more files",
            );
        }

        let key = format!(
            "srv/emotes/{}/{}",
            uuid::Uuid::now_v7().simple(),
            safe_name(&upload.filename)
        );
        let url = self.grant("PUT", &key);
        self.remember_pending(
            &key,
            Pending {
                channel: ROOT_CHANNEL,
                owner: inbound.session,
                filename: safe_name(&upload.filename),
                content_type: upload.content_type,
                size: upload.size,
                // An `<img>` cannot sign a request, so an emote nobody can
                // fetch without a signature is an emote nobody can see.
                public: true,
                expires_at_ms: url.expires_at_ms,
                share_expires_at_ms: None,
                uploader: Uploader {
                    account: self.roster.account_of(inbound.session),
                    name: self.roster.name_of(inbound.session),
                    cert: self.roster.cert_of(inbound.session),
                },
                password_hash: None,
                seal: None,
                bind: Some(Bind {
                    ns: "srv/emotes".to_owned(),
                    name: shortcode,
                    keep: 1,
                    emote: Some(EmoteFacts {
                        alias_emoji: upload.alias_emoji,
                        description: upload.description,
                    }),
                }),
            },
        );
        FilesEnvelope {
            body: Some(files_envelope::Body::Grant(Grant {
                request_id: upload.request_id,
                url: url.url,
                method: url.method,
                expires_at_ms: url.expires_at_ms,
                key,
                share_url: String::new(),
                share_expires_at_ms: 0,
            })),
        }
    }

    /// Remove one emote, image and all.
    async fn answer_emote_forget(&self, inbound: &Inbound, request: EmoteForget) -> FilesEnvelope {
        if !self
            .allows(inbound, ROOT_CHANNEL, Perm::MANAGE_EMOTES)
            .await
        {
            return refused(
                &request.request_id,
                refusal::Kind::Permission,
                "you may not manage this server's emotes",
            );
        }
        let shortcode = safe_name(&request.shortcode);
        for orphan in self
            .names
            .forget(inbound.scope, "srv/emotes", &shortcode)
            .await
        {
            self.forget_object(&orphan).await;
        }
        self.logger.log(
            LogEvent::notice(Category::Admin, "an emote was removed")
                .with("shortcode", shortcode)
                .with("session", inbound.session),
        );
        // Everyone, not only the asker: the point of pushing the set is that
        // a deleted emote stops rendering for people who never asked.
        self.broadcast_emotes(inbound.scope).await;
        self.emote_listing(inbound.scope, &request.request_id).await
    }

    /// Every emote this server has, as the clients see them.
    async fn emote_listing(&self, scope: u32, request_id: &str) -> FilesEnvelope {
        let mut emotes = Vec::new();
        for (shortcode, latest) in self.names.list(scope, "srv/emotes").await {
            let (alias_emoji, description) = unpack_emote_meta(latest.meta.as_deref());
            emotes.push(Emote {
                shortcode,
                url: self.share_url(&latest.key),
                alias_emoji,
                description,
                created_at_ms: latest.created_at_ms,
            });
        }
        FilesEnvelope {
            body: Some(files_envelope::Body::Emotes(Emotes {
                request_id: request_id.to_owned(),
                emotes,
            })),
        }
    }

    /// Bind the name a finished upload asked for, and tell everyone if the set
    /// of emotes changed.
    pub(crate) async fn bind_finished_upload(&self, scope: u32, key: &str, bind: &Bind) {
        let meta = bind.emote.as_ref().map(pack_emote_meta);
        if let Err(error) = self
            .names
            .put(scope, &bind.ns, &bind.name, key, meta.as_deref())
            .await
        {
            tracing::warn!(%error, key, "could not name a finished upload");
            return;
        }
        if bind.keep > 0 {
            for orphan in self
                .names
                .trim(scope, &bind.ns, &bind.name, bind.keep)
                .await
            {
                self.forget_object(&orphan).await;
            }
        }
        if bind.emote.is_some() {
            self.broadcast_emotes(scope).await;
        }
    }

    /// Send the emote set to everyone connected.
    ///
    /// Pushed rather than polled: a client that never asks still has to stop
    /// showing an emote somebody deleted.
    async fn broadcast_emotes(&self, scope: u32) {
        let envelope = self.emote_listing(scope, "").await;
        let sessions = self.roster.sessions();
        if sessions.is_empty() {
            return;
        }
        self.fanout.push(to_sessions(
            sessions,
            ServiceKind::Files.outer_type(),
            envelope.encode_to_vec(),
        ));
    }

    /// Whether this session administers the server.
    async fn administers(&self, inbound: &Inbound) -> bool {
        self.allows(inbound, ROOT_CHANNEL, Perm::WRITE).await
    }

    /// Who a session is, in the terms an object row records.
    fn identity_of(&self, session: u32) -> Uploader {
        Uploader {
            account: self.roster.account_of(session),
            name: self.roster.name_of(session),
            cert: self.roster.cert_of(session),
        }
    }

    /// Who uploaded `key`, or `None` if there is no such object.
    async fn owner_of(&self, key: &str) -> Option<Uploader> {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT uploader_account, uploader_name, uploader_cert, owner FROM object \
             WHERE server_id = ? AND k = ?",
        )
        .bind(1_i64)
        .bind(key)
        .fetch_optional(self.store.pool())
        .await
        .ok()??;
        Some(Uploader {
            account: row
                .try_get::<Option<i64>, _>("uploader_account")
                .ok()
                .flatten()
                .map(|account| account as u64),
            name: row.try_get("uploader_name").ok().flatten(),
            cert: row.try_get("uploader_cert").ok().flatten(),
        })
    }

    /// The stored files, for everyone or for one person.
    async fn managed_files(&self, mine: Option<Uploader>, limit: i64) -> Vec<ManagedFile> {
        use sqlx::Row as _;
        let rows =
            match &mine {
                Some(who) => {
                    // An account is the person; a certificate is the keypair they
                    // hold. Either identifies the same uploader across reconnects,
                    // and a guest with neither has no files to find.
                    sqlx::query(
                    "SELECT k, channel_id, filename, content_type, size, created_at_ms, public, \
                     password_hash, expires_at_ms, downloaded_at_ms, uploader_account, \
                     uploader_name, uploader_cert, has_thumb FROM object WHERE server_id = ? \
                     AND ((? IS NOT NULL AND uploader_account = ?) \
                          OR (? IS NOT NULL AND uploader_cert = ?)) \
                     AND k NOT LIKE 'u/%' AND k NOT LIKE 'srv/%' AND k NOT LIKE 'p/%' \
                     AND k NOT LIKE '%.thumb' \
                     ORDER BY created_at_ms DESC LIMIT ?",
                )
                .bind(1_i64)
                .bind(who.account.map(|account| account as i64))
                .bind(who.account.map(|account| account as i64))
                .bind(who.cert.clone())
                .bind(who.cert.clone())
                .bind(limit)
                .fetch_all(self.store.pool())
                .await
                }
                None => sqlx::query(
                    "SELECT k, channel_id, filename, content_type, size, created_at_ms, public, \
                     password_hash, expires_at_ms, downloaded_at_ms, uploader_account, \
                     uploader_name, uploader_cert, has_thumb FROM object WHERE server_id = ? \
                     AND k NOT LIKE '%.thumb' \
                     ORDER BY created_at_ms DESC LIMIT ?",
                )
                .bind(1_i64)
                .bind(limit)
                .fetch_all(self.store.pool())
                .await,
            }
            .unwrap_or_default();

        let online = self.roster.sessions();
        rows.iter()
            .map(|row| {
                let key: String = row.try_get("k").unwrap_or_default();
                let public = row.try_get::<i64, _>("public").unwrap_or_default() != 0;
                let locked = row
                    .try_get::<Option<String>, _>("password_hash")
                    .ok()
                    .flatten()
                    .is_some();
                let account = row
                    .try_get::<Option<i64>, _>("uploader_account")
                    .ok()
                    .flatten()
                    .map(|account| account as u64);
                let cert: Option<Vec<u8>> = row.try_get("uploader_cert").ok().flatten();
                ManagedFile {
                    thumb_key: thumb_key_of(row, &key),
                    channel: row.try_get::<i64, _>("channel_id").unwrap_or_default() as u32,
                    filename: row.try_get("filename").unwrap_or_default(),
                    content_type: row.try_get("content_type").unwrap_or_default(),
                    size: row.try_get::<i64, _>("size").unwrap_or_default() as u64,
                    visibility: visibility_of(public, locked) as i32,
                    shared_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default() as u64,
                    expires_at_ms: row
                        .try_get::<Option<i64>, _>("expires_at_ms")
                        .ok()
                        .flatten()
                        .unwrap_or_default() as u64,
                    downloaded_at_ms: row
                        .try_get::<Option<i64>, _>("downloaded_at_ms")
                        .ok()
                        .flatten()
                        .unwrap_or_default() as u64,
                    share_url: self.share_url_if(public, &key),
                    uploader_online: online.iter().any(|&session| {
                        (account.is_some() && self.roster.account_of(session) == account)
                            || (cert.is_some() && self.roster.cert_of(session) == cert)
                    }),
                    uploader_account: account.unwrap_or_default(),
                    uploader_name: row
                        .try_get("uploader_name")
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                    uploader_cert: cert.unwrap_or_default(),
                    key,
                }
            })
            .collect()
    }

    /// What this server is holding, and what it is allowed to hold.
    async fn storage_stats(&self) -> Storage {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT COALESCE(SUM(size), 0) AS used, COUNT(*) AS files FROM object \
             WHERE server_id = ?",
        )
        .bind(1_i64)
        .fetch_one(self.store.pool())
        .await;
        let (used, files) = row.map_or((0, 0), |row| {
            (
                row.try_get::<i64, _>("used").unwrap_or_default() as u64,
                row.try_get::<i64, _>("files").unwrap_or_default() as u64,
            )
        });
        Storage {
            used_bytes: used,
            max_total_bytes: self.max_total_storage.load(Ordering::Relaxed),
            max_upload_bytes: self.max_upload(),
            file_count: files,
        }
    }

    /// Note that an object was read, for the operator's view.
    pub(crate) async fn note_read(&self, key: &str) {
        let _noted =
            sqlx::query("UPDATE object SET downloaded_at_ms = ? WHERE server_id = ? AND k = ?")
                .bind(now_ms() as i64)
                .bind(1_i64)
                .bind(key)
                .execute(self.store.pool())
                .await;
    }
}

impl Uploader {
    /// Whether these two describe the same person.
    ///
    /// An account first, because it survives a new certificate; the
    /// fingerprint second, because a guest has no account but may still hold a
    /// keypair. Two uploaders with neither are never the same person - that
    /// would make every anonymous upload everyone's.
    fn matches(&self, other: &Self) -> bool {
        match (self.account, other.account) {
            (Some(mine), Some(theirs)) => mine == theirs,
            _ => match (self.cert.as_ref(), other.cert.as_ref()) {
                (Some(mine), Some(theirs)) => mine == theirs,
                _ => false,
            },
        }
    }
}

/// One refusal, correlated to the request that earned it.
fn refused(request_id: &str, kind: refusal::Kind, detail: &str) -> FilesEnvelope {
    FilesEnvelope {
        body: Some(files_envelope::Body::Refused(Refused {
            request_id: request_id.to_owned(),
            refusal: Some(Refusal {
                kind: kind as i32,
                detail: detail.to_owned(),
                retry_after_ms: 0,
            }),
        })),
    }
}

impl Serve for FilesService {
    const NAME: &'static str = "files";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        // The same database, a second schema chain: one connection pool for
        // the service, and two sets of migrations recorded by name.
        let names = names::Names::open(store.clone()).await?;
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
            names,
            pending: RwLock::new(HashMap::new()),
            tickets: tickets::Tickets::default(),
            attempts: attempts::Attempts::default(),
            roster: Arc::new(Roster::new()),
            permit: Permit::new(ctx.resolver.clone()),
            // `retain_seconds` in `[services.files].options`: a plain number,
            // because this is the one knob and a duration grammar would be a
            // dependency for a single field.
            max_ttl_ms: AtomicU64::new(seconds(&service, "max_ttl_seconds").unwrap_or_default()),
            max_total_storage: AtomicU64::new(
                service
                    .options
                    .get("max_total_storage")
                    .and_then(|value| value.parse::<ByteSize>().ok())
                    .map_or(0, ByteSize::get),
            ),
            delete_on_download: AtomicBool::new(flag(&service, "delete_on_download")),
            delete_on_disconnect: AtomicBool::new(flag(&service, "delete_on_disconnect")),
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
        let departures = tokio::spawn(
            Arc::clone(&self).forget_departed(self.roster.departures(), ctx.shutdown.clone()),
        );
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
        departures.abort();
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

    /// Drop each departing session's shares, for as long as the service runs.
    ///
    /// Subscribed even when the operator has not asked for it, so turning the
    /// switch on takes effect at the next disconnect rather than the next
    /// restart; `forget_session` is what reads the switch.
    async fn forget_departed(
        self: Arc<Self>,
        mut departures: tokio::sync::broadcast::Receiver<u32>,
        shutdown: starling_runtime::shutdown::Shutdown,
    ) {
        loop {
            tokio::select! {
                () = shutdown.wait() => return,
                gone = departures.recv() => match gone {
                    Ok(session) => self.forget_session(session).await,
                    // Lagged: some departures were missed, and the sessions
                    // they named are unknowable now. The sweeper is what
                    // eventually collects those, so this keeps listening
                    // rather than giving up on the ones still to come.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
            }
        }
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
    /// Who shared it, in terms that outlive their connection.
    pub(crate) uploader: Uploader,
    /// What a password guess is checked against, for a password share.
    pub(crate) password_hash: Option<String>,
    /// The salt and nonce prefix the bytes are sealed under.
    ///
    /// Alongside the key rather than instead of it: the key is spent sealing
    /// this one upload and then gone, while these two have to outlive it in
    /// the row so a later reader can derive the key again from the password.
    pub(crate) seal: Option<Seal>,
    /// A name to point at this object once the bytes have actually arrived.
    ///
    /// Bound on completion rather than at grant time, because a name written
    /// first would - if the upload then failed - resolve to bytes that never
    /// came, and the emote would render as a broken image for everybody. The
    /// other order leaves an unreferenced object, which the collector takes.
    pub(crate) bind: Option<Bind>,
}

/// What to name a finished upload, and how much history to keep.
#[derive(Debug, Clone)]
pub(crate) struct Bind {
    /// The namespace, without a trailing separator.
    pub(crate) ns: String,
    /// The name inside it.
    pub(crate) name: String,
    /// Revisions to keep; `1` for an emote, whose history is waste.
    pub(crate) keep: u64,
    /// What to say about it once it is stored, for the broadcast.
    pub(crate) emote: Option<EmoteFacts>,
}

/// The parts of an emote that are not the image.
#[derive(Debug, Clone)]
pub(crate) struct EmoteFacts {
    pub(crate) alias_emoji: String,
    pub(crate) description: String,
}

/// Who shared a file, as something still true after they disconnect.
///
/// Read at grant time, from the roster, because that is while the session is
/// still there to be resolved. All three can be absent: a guest has no
/// account, and a client that presented no certificate has no fingerprint.
#[derive(Debug, Clone, Default)]
pub(crate) struct Uploader {
    pub(crate) account: Option<u64>,
    pub(crate) name: Option<String>,
    pub(crate) cert: Option<Vec<u8>>,
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

    /// Whether the client on `inbound` holds `needed` in `channel`.
    ///
    /// [`Permit::allows`] denies on any failure, `permissions` being
    /// unreachable included, so there is no error case here for a caller to
    /// get wrong: a service that cannot check is a service that says no.
    async fn allows(&self, inbound: &Inbound, channel: u32, needed: Perm) -> bool {
        self.permit.allows(inbound, channel, needed.bits()).await
    }

    /// Whether this server has room for `incoming` more bytes.
    ///
    /// Checked at grant time, before anything moves: a client told after the
    /// transfer that the disk was full has spent the whole upload finding out.
    /// The count is of what is *stored*, so grants in flight are not reserved -
    /// two large uploads racing can pass the cap between them, and the data
    /// plane's own per-object ceiling is what bounds the overshoot.
    async fn has_room_for(&self, incoming: u64) -> bool {
        use sqlx::Row as _;
        let cap = self.max_total_storage.load(Ordering::Relaxed);
        if cap == 0 {
            return true;
        }
        let held: i64 = sqlx::query("SELECT COALESCE(SUM(size), 0) AS total FROM object")
            .fetch_one(self.store.pool())
            .await
            .ok()
            .and_then(|row| row.try_get("total").ok())
            .unwrap_or_default();
        (held as u64).saturating_add(incoming) <= cap
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
        // Clamped rather than refused: an uploader asking for longer than the
        // operator allows gets the longest they can have, which is what they
        // wanted the most of. A ceiling also means "forever" is no longer an
        // option, so an upload that asked for nothing takes the ceiling too.
        let ceiling = self.max_ttl_ms.load(Ordering::Relaxed);
        let asked = upload.ttl_seconds.saturating_mul(1_000);
        let lifetime = match (ceiling, asked) {
            (0, 0) => 0,
            (0, asked) => asked,
            (ceiling, 0) => ceiling,
            (ceiling, asked) => asked.min(ceiling),
        };
        let share_expires_at_ms = (lifetime > 0).then(|| now_ms().saturating_add(lifetime));
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
                uploader: Uploader {
                    account: self.roster.account_of(session),
                    name: self.roster.name_of(session),
                    cert: self.roster.cert_of(session),
                },
                password_hash,
                seal,
                // A channel upload names nothing: its key is how it is
                // reached, and the listing is what finds it.
                bind: None,
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

    /// The wrong-guess counter that keeps a share link from being brute-forced.
    pub(crate) fn attempts(&self) -> &attempts::Attempts {
        &self.attempts
    }

    /// Whether an object is destroyed by the download that just succeeded.
    pub(crate) fn burns_on_read(&self) -> bool {
        self.delete_on_download.load(Ordering::Relaxed)
    }

    /// Destroy one object, row and bytes together.
    ///
    /// Bytes after the row, as the sweeper does it: a row without its file is
    /// a 404 on a link that still looks live, and a file without its row is
    /// disk nobody can account for.
    pub(crate) async fn forget_object(&self, key: &str) {
        let deleted = sqlx::query("DELETE FROM object WHERE server_id = ? AND k = ?")
            .bind(1_i64)
            .bind(key)
            .execute(self.store.pool())
            .await;
        if deleted.is_ok()
            && let Some(path) = http::object_path(self.objects_dir(), key)
        {
            drop(tokio::fs::remove_file(path).await);
        }
    }

    /// Drop everything a session shared, because the session is gone.
    ///
    /// Only where the operator asked for it. The owner is the session id, so
    /// this is exactly the set that id can still be matched against - once the
    /// id is reused by somebody else it would mean a different person, which
    /// is why it happens on the disconnect rather than later.
    async fn forget_session(&self, session: u32) {
        use sqlx::Row as _;
        if !self.delete_on_disconnect.load(Ordering::Relaxed) {
            return;
        }
        let rows = sqlx::query("SELECT k FROM object WHERE server_id = ? AND owner = ?")
            .bind(1_i64)
            .bind(i64::from(session))
            .fetch_all(self.store.pool())
            .await
            .unwrap_or_default();
        for row in &rows {
            let key: String = row.try_get("k").unwrap_or_default();
            if !key.is_empty() {
                self.forget_object(&key).await;
            }
        }
        if !rows.is_empty() {
            tracing::debug!(
                session,
                count = rows.len(),
                "a session's shares went with it"
            );
        }
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
             public, password_hash, enc_salt, enc_nonce, expires_at_ms, \
             uploader_account, uploader_name, uploader_cert) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind(pending.uploader.account.map(|account| account as i64))
        .bind(pending.uploader.name.clone())
        .bind(pending.uploader.cert.clone())
        .execute(self.store.pool())
        .await
        .map(drop)
    }

    /// Record a thumbnail derived from an object that has just been stored.
    ///
    /// An ordinary row, so the thumbnail downloads through the same signed
    /// URL, expires with the same sweep and needs no route of its own. It
    /// inherits the original's channel, owner and visibility, because a
    /// preview of a file is exactly as private as the file: giving it a
    /// laxer visibility would publish a readable version of a restricted
    /// picture.
    ///
    /// Never sealed, and it cannot be: a sealed original is one this server
    /// could not read, and [`crate::thumb::wanted`] refuses those before any
    /// of this.
    pub(crate) async fn record_thumbnail(
        &self,
        key: &str,
        original_key: &str,
        original: &Pending,
        size: u64,
        content_type: &str,
        now: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO object              (server_id, k, channel_id, owner, filename, content_type, size, sha256, created_at_ms,              public, password_hash, enc_salt, enc_nonce, expires_at_ms,              uploader_account, uploader_name, uploader_cert)              VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?)",
        )
        .bind(1_i64)
        .bind(key)
        .bind(i64::from(original.channel))
        .bind(i64::from(original.owner))
        .bind(format!("{}.thumb", original.filename))
        .bind(content_type)
        .bind(size as i64)
        .bind(now as i64)
        .bind(i64::from(original.public))
        .bind(original.share_expires_at_ms.map(|at| at as i64))
        .bind(original.uploader.account.map(|account| account as i64))
        .bind(original.uploader.name.clone())
        .bind(original.uploader.cert.clone())
        .execute(self.store.pool())
        .await
        .map(drop)?;

        // The bit the listings read. Written after the row, so a failure
        // leaves an unreferenced thumbnail rather than a promise of one that
        // is not there -- the first wastes a little disk, the second shows the
        // reader a broken picture.
        sqlx::query("UPDATE object SET has_thumb = 1 WHERE server_id = ? AND k = ?")
            .bind(1_i64)
            .bind(original_key)
            .execute(self.store.pool())
            .await
            .map(drop)
    }

    /// Tell the channel a file has arrived.
    ///
    /// This is what makes an upload *shared*. Without it the uploader holds a
    /// URL nobody else has heard of, which is a private file with extra steps.
    pub(crate) fn announce_share(
        &self,
        key: &str,
        pending: &Pending,
        size: u64,
        thumb_key: String,
    ) {
        let share = FilesEnvelope {
            body: Some(files_envelope::Body::Share(Share {
                key: key.to_owned(),
                thumb_key,
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
            // `k LIKE '{channel}/%'` as well as `channel_id`: an emote or a
            // plugin's document carries channel 0, and without the key check
            // every one of them listed as a file shared in the root.
            "SELECT k, owner, filename, size, created_at_ms, public, password_hash, \
             expires_at_ms, has_thumb FROM object WHERE server_id = ? AND channel_id = ? \
             AND k LIKE ? \
             AND k NOT LIKE '%.thumb' \
             AND (expires_at_ms IS NULL OR expires_at_ms > ?) \
             ORDER BY created_at_ms DESC LIMIT ?",
        )
        .bind(1_i64)
        .bind(i64::from(channel))
        .bind(format!("{channel}/%"))
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
                    thumb_key: thumb_key_of(row, &key),
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

    /// A `permissions` that answers whatever the test told it to.
    ///
    /// A real one, served in-process, rather than a permit that waves
    /// everything through: the gate is the thing under test in half these
    /// cases, and a stub that could not say no would let a missing check pass.
    #[derive(Clone)]
    struct Gate(Arc<std::sync::atomic::AtomicU32>);

    #[tonic::async_trait]
    impl starling_proto_fancy::permissions::permissions_server::Permissions for Gate {
        async fn check_session(
            &self,
            request: Request<starling_proto_fancy::permissions::SessionCheckRequest>,
        ) -> Result<Response<starling_proto_fancy::common::Decision>, Status> {
            let asked = request.into_inner().permission;
            let held = self.0.load(Ordering::Relaxed);
            Ok(Response::new(starling_proto_fancy::common::Decision {
                // Every bit asked for must be held, which is what `Permit`
                // promises its callers.
                allowed: asked & held == asked,
                ..Default::default()
            }))
        }
        async fn effective(
            &self,
            _: Request<starling_proto_fancy::permissions::EffectiveRequest>,
        ) -> Result<Response<starling_proto_fancy::permissions::EffectiveResponse>, Status>
        {
            Err(Status::unimplemented("not used by files"))
        }
        async fn check(
            &self,
            _: Request<starling_proto_fancy::permissions::CheckRequest>,
        ) -> Result<Response<starling_proto_fancy::common::Decision>, Status> {
            Err(Status::unimplemented("files uses check_session"))
        }
        async fn get_acl(
            &self,
            _: Request<starling_proto_fancy::permissions::AclRequest>,
        ) -> Result<Response<starling_proto_fancy::permissions::AclSet>, Status> {
            Err(Status::unimplemented("not used by files"))
        }
        async fn set_acl(
            &self,
            _: Request<starling_proto_fancy::permissions::SetAclRequest>,
        ) -> Result<Response<starling_proto_fancy::permissions::AclResult>, Status> {
            Err(Status::unimplemented("not used by files"))
        }
        async fn add_temporary_group(
            &self,
            _: Request<starling_proto_fancy::permissions::TemporaryGroupRequest>,
        ) -> Result<Response<starling_proto_fancy::permissions::AclResult>, Status> {
            Err(Status::unimplemented("not used by files"))
        }
        async fn remove_temporary_group(
            &self,
            _: Request<starling_proto_fancy::permissions::TemporaryGroupRequest>,
        ) -> Result<Response<starling_proto_fancy::permissions::AclResult>, Status> {
            Err(Status::unimplemented("not used by files"))
        }
        type WatchInvalidationsStream = std::pin::Pin<
            Box<
                dyn futures_util::Stream<
                        Item = Result<starling_proto_fancy::permissions::Invalidation, Status>,
                    > + Send,
            >,
        >;
        async fn watch_invalidations(
            &self,
            _: Request<starling_proto_fancy::common::Scope>,
        ) -> Result<Response<Self::WatchInvalidationsStream>, Status> {
            Err(Status::unimplemented("not used by files"))
        }
    }

    /// Everything this service ever asks for, as an operator would hold it.
    ///
    /// The tests that care about a gate take a bit away with
    /// `service_holding`; this is the "allowed to do all of it" baseline.
    fn everything() -> Perm {
        Perm::SHARE_FILES
            .union(Perm::SHARE_FILES_PUBLIC)
            .union(Perm::WRITE)
            .union(Perm::RESET_USER_CONTENT)
            .union(READ_CHANNEL)
    }

    /// A resolver reaching a stub `permissions` that grants exactly `held`.
    ///
    /// Built per service rather than once for the suite: every `#[tokio::test]`
    /// gets its own runtime, and a server spawned on the first one dies with
    /// it - after which every later test sees `permissions` as unreachable and
    /// is denied, which looks exactly like the gate working.
    async fn gate_granting(held: Perm) -> starling_runtime::channel::Resolver {
        use starling_proto_fancy::permissions::permissions_server::PermissionsServer;
        use starling_runtime::transport::{InProcess, Transport as _};

        let broker = starling_runtime::inproc::Broker::new();
        let incoming = InProcess::new("permissions")
            .bind(&broker)
            .await
            .expect("bind the stub");
        let bits = Arc::new(std::sync::atomic::AtomicU32::new(held.bits()));
        drop(tokio::spawn(async move {
            let _served = tonic::transport::Server::builder()
                .add_service(PermissionsServer::new(Gate(bits)))
                .serve_with_incoming(incoming)
                .await;
        }));
        let mut config =
            starling_runtime::config::Config::with_defaults(std::path::Path::new("/run/starling"));
        config.runtime.all_in_one = true;
        starling_runtime::channel::Resolver::new(Arc::new(config), broker)
    }

    /// A service whose sessions hold everything.
    async fn service() -> Arc<FilesService> {
        service_holding(everything()).await
    }

    /// A service whose sessions hold exactly `held`, and nothing else.
    async fn service_holding(held: Perm) -> Arc<FilesService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:files-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        let names = names::Names::open(store.clone())
            .await
            .expect("the name schema");
        Arc::new(FilesService {
            store,
            secret: b"test-secret".to_vec(),
            public_url: RwLock::new("https://files.example.org".into()),
            ttl_ms: AtomicU64::new(900_000),
            max_upload: AtomicU64::new(1024),
            fanout: Fanout::default(),
            logger: Logger::null(),
            objects_dir: std::env::temp_dir().join("starling-files-test"),
            names,
            pending: RwLock::new(HashMap::new()),
            tickets: tickets::Tickets::default(),
            attempts: attempts::Attempts::default(),
            roster: Arc::new(Roster::new()),
            permit: Permit::new(gate_granting(held).await),
            retain_ms: AtomicU64::new(0),
            max_ttl_ms: AtomicU64::new(0),
            max_total_storage: AtomicU64::new(0),
            delete_on_download: AtomicBool::new(false),
            delete_on_disconnect: AtomicBool::new(false),
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

    /// One share-route request carrying a `Range`.
    async fn ranged(
        service: &Arc<FilesService>,
        path: &str,
        range: &str,
    ) -> (u16, HashMap<String, String>, Vec<u8>) {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        let request = axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .header("range", range)
            .body(axum::body::Body::empty())
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
    async fn a_session_without_share_files_cannot_upload_at_all() {
        let service = service_holding(READ_CHANNEL).await;
        let envelope = ask(&service, upload_as(Visibility::Session, "", 2)).await;
        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Permission as i32
        );
    }

    #[tokio::test]
    async fn share_files_alone_does_not_buy_a_public_link() {
        // The two bits are separate for exactly this: a server can want its
        // members exchanging files without any of them able to publish one to
        // the open internet.
        let service = service_holding(Perm::SHARE_FILES.union(READ_CHANNEL)).await;

        let allowed = ask(&service, upload_as(Visibility::Session, "", 2)).await;
        assert!(
            matches!(allowed.body, Some(files_envelope::Body::Grant(_))),
            "a session share is what SHARE_FILES is for"
        );

        for visibility in [Visibility::Public, Visibility::Password] {
            let refused = ask(&service, upload_as(visibility, "hunter2", 2)).await;
            assert!(
                matches!(refused.body, Some(files_envelope::Body::Refused(_))),
                "{visibility:?} needs SHARE_FILES_PUBLIC, got {:?}",
                refused.body
            );
        }
    }

    #[tokio::test]
    async fn a_key_is_not_an_authorisation_to_download_it() {
        // Keys travel in messages and in listings, so one reaching a session
        // that cannot see the channel is ordinary rather than exceptional.
        // Without the check, holding it would be enough.
        let service = service_holding(Perm::SHARE_FILES).await;
        let envelope = ask_body(
            &service,
            files_envelope::Body::Download(starling_proto_fancy::fancy::files::DownloadRequest {
                request_id: "d1".to_owned(),
                key: "4/018f/secret.txt".to_owned(),
            }),
        )
        .await;
        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Permission as i32
        );
    }

    #[tokio::test]
    async fn a_channel_you_cannot_see_lists_as_empty_rather_than_as_forbidden() {
        // Empty rather than refused because this is also how a client finds
        // out the service exists: a channel the asker cannot see should look
        // like one with no files, not like one it is being kept out of.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Session, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);
        assert_eq!(service.listing(4, 50).await.len(), 1, "it is really there");

        let blind = service_holding(Perm::SHARE_FILES).await;
        let envelope = ask_body(
            &blind,
            files_envelope::Body::List(starling_proto_fancy::fancy::files::ListRequest {
                channel: 4,
                limit: 50,
                before_key: String::new(),
            }),
        )
        .await;
        let Some(files_envelope::Body::Listing(listing)) = envelope.body else {
            panic!("expected a listing, got {:?}", envelope.body);
        };
        assert!(listing.files.is_empty());
    }

    #[tokio::test]
    async fn a_share_link_stops_taking_guesses_after_enough_wrong_ones() {
        // A share link is a public address with a secret behind it, which makes
        // it the one thing here that can simply be guessed at.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Password, "hunter2", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);
        let path = format!("/s/{}", grant.key);

        for _ in 0..attempts::MAX_FAILURES {
            let (status, ..) = call(&service, "POST", &path, Some("wrong"), None, Vec::new()).await;
            assert_eq!(status, 403);
        }
        let (status, ..) = call(&service, "POST", &path, Some("wrong"), None, Vec::new()).await;
        assert_eq!(status, 429, "the guessing stops");
        let (status, ..) = call(&service, "POST", &path, Some("hunter2"), None, Vec::new()).await;
        assert_eq!(
            status, 429,
            "and the right password waits with the rest: answering it now would \
             say which of the two the guesser had just found"
        );
    }

    /// One management request, from the session `ask` uses.
    async fn manage(service: &Arc<FilesService>, audience: Audience) -> FilesEnvelope {
        ask_body(
            service,
            files_envelope::Body::Manage(ManageRequest {
                request_id: "m1".to_owned(),
                audience: audience as i32,
                limit: 100,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn an_operator_sees_every_file_and_what_the_disk_is_doing() {
        let service = service().await;
        service
            .max_total_storage
            .store(1_000_000, Ordering::Relaxed);
        for _ in 0..3 {
            let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
            assert_eq!(put_through(&service, &grant, b"hi").await, 201);
        }

        let Some(files_envelope::Body::Managed(listing)) =
            manage(&service, Audience::Everyone).await.body
        else {
            panic!("expected a listing");
        };
        assert_eq!(listing.files.len(), 3);
        let storage = listing
            .storage
            .expect("an operator's view says what is held");
        assert_eq!(storage.file_count, 3);
        assert_eq!(storage.used_bytes, 6);
        assert_eq!(storage.max_total_bytes, 1_000_000);
        assert!(storage.max_upload_bytes > 0);
        assert!(
            listing.files.iter().all(|file| !file.filename.is_empty()),
            "each row carries what a dashboard renders"
        );
    }

    #[tokio::test]
    async fn a_file_remembers_when_it_was_last_read() {
        // The one column that answers "is anybody still using this", which is
        // what an operator clearing space needs.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        let before = &manage(&service, Audience::Everyone).await;
        let Some(files_envelope::Body::Managed(listing)) = &before.body else {
            panic!("expected a listing");
        };
        assert_eq!(listing.files[0].downloaded_at_ms, 0, "never read yet");

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

        let Some(files_envelope::Body::Managed(listing)) =
            manage(&service, Audience::Everyone).await.body
        else {
            panic!("expected a listing");
        };
        assert!(listing.files[0].downloaded_at_ms > 0, "and now it has been");
    }

    #[tokio::test]
    async fn a_user_without_write_on_the_root_gets_no_operator_view() {
        let service = service_holding(Perm::SHARE_FILES.union(READ_CHANNEL)).await;
        let envelope = manage(&service, Audience::Everyone).await;
        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Permission as i32
        );
    }

    #[tokio::test]
    async fn my_files_are_the_ones_i_uploaded_and_no_others() {
        // The roster has nobody in these tests, so an upload records no
        // account and no certificate - which is the guest case, and the one
        // where "mine" must come back empty rather than come back as
        // everyone's.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        let Some(files_envelope::Body::Managed(listing)) =
            manage(&service, Audience::Mine).await.body
        else {
            panic!("expected a listing");
        };
        assert!(
            listing.files.is_empty(),
            "an upload with no identity on it belongs to nobody, not to everybody"
        );
        assert!(
            listing.storage.is_none(),
            "a user's own files say nothing about the server's disk"
        );
    }

    #[tokio::test]
    async fn removing_a_file_takes_its_row_and_its_bytes() {
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        let envelope = ask_body(
            &service,
            files_envelope::Body::Forget(ForgetRequest {
                request_id: "f1".to_owned(),
                key: grant.key.clone(),
            }),
        )
        .await;
        assert!(
            matches!(envelope.body, Some(files_envelope::Body::Managed(_))),
            "expected an acknowledgement, got {:?}",
            envelope.body
        );
        assert!(service.listing(4, 50).await.is_empty());
        assert!(
            http::object_path(service.objects_dir(), &grant.key).is_some_and(|path| !path.exists()),
            "the bytes went too"
        );
    }

    #[tokio::test]
    async fn removing_somebody_elses_file_needs_the_permission_for_it() {
        // The uploads here carry no identity, so none of them are the caller's
        // - which makes this exactly the "somebody else's" path.
        let service = service_holding(Perm::SHARE_FILES.union(READ_CHANNEL)).await;
        let grant = grant_for(&service, upload_as(Visibility::Session, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        let envelope = ask_body(
            &service,
            files_envelope::Body::Forget(ForgetRequest {
                request_id: "f1".to_owned(),
                key: grant.key.clone(),
            }),
        )
        .await;
        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Permission as i32
        );
        assert_eq!(
            service.listing(4, 50).await.len(),
            1,
            "and it is still there"
        );
    }

    #[tokio::test]
    async fn removing_a_file_that_does_not_exist_says_so_without_asking_permission() {
        let service = service_holding(Perm::SHARE_FILES).await;
        let envelope = ask_body(
            &service,
            files_envelope::Body::Forget(ForgetRequest {
                request_id: "f1".to_owned(),
                key: "4/nothing/here.txt".to_owned(),
            }),
        )
        .await;
        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Invalid as i32,
            "a key that names nothing is not a permission question"
        );
    }

    #[tokio::test]
    async fn a_photo_opens_in_the_browser_and_a_page_does_not() {
        // The epoch-0 allow-list. What is absent from it is the point: an
        // uploaded `.html` rendered in this origin is cross-site scripting
        // with a progress bar.
        let service = service().await;
        for (name, mime, expected) in [
            ("holiday.png", "image/png", "inline"),
            ("notes.html", "text/html", "attachment"),
            ("drawing.svg", "image/svg+xml", "attachment"),
        ] {
            let grant = grant_for(
                &service,
                UploadRequest {
                    filename: name.to_owned(),
                    content_type: mime.to_owned(),
                    ..upload_as(Visibility::Public, "", 2)
                },
            )
            .await;
            assert_eq!(put_through(&service, &grant, b"hi").await, 201);
            let (_, headers, _) = call(
                &service,
                "GET",
                &format!("/s/{}", grant.key),
                None,
                None,
                Vec::new(),
            )
            .await;
            let disposition = headers
                .get("content-disposition")
                .expect("a share link names its download");
            assert!(
                disposition.starts_with(expected),
                "{name} ({mime}) should be {expected}, got {disposition}"
            );
        }
    }

    #[tokio::test]
    async fn a_lifetime_longer_than_the_operator_allows_is_clamped_not_refused() {
        // Clamped because the uploader wanted the most they could have, and a
        // refusal here would make the option unusable rather than bounded.
        let service = service().await;
        service.max_ttl_ms.store(3_600_000, Ordering::Relaxed);

        let grant = grant_for(&service, upload_lasting(Visibility::Public, 604_800, 2)).await;
        let asked_for = now_ms() + 604_800_000;
        assert!(
            grant.share_expires_at_ms < asked_for,
            "a week was asked for and the ceiling is an hour"
        );
        assert!(grant.share_expires_at_ms > now_ms());
    }

    #[tokio::test]
    async fn a_ceiling_also_ends_shares_that_asked_for_nothing() {
        // Otherwise the ceiling is advice: an uploader who picks "never" would
        // simply opt out of the operator's limit.
        let service = service().await;
        service.max_ttl_ms.store(3_600_000, Ordering::Relaxed);

        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert!(
            grant.share_expires_at_ms > now_ms(),
            "forever is not on offer where a ceiling is set"
        );
    }

    #[tokio::test]
    async fn an_upload_past_the_total_cap_is_refused_before_a_byte_moves() {
        let service = service().await;
        service.max_upload.store(8_192, Ordering::Relaxed);
        service.max_total_storage.store(4_096, Ordering::Relaxed);

        let first = grant_for(&service, upload_as(Visibility::Session, "", 4_000)).await;
        assert_eq!(put_through(&service, &first, &vec![0u8; 4_000]).await, 201);

        let envelope = ask(&service, upload_as(Visibility::Session, "", 4_000)).await;
        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Limit as i32,
            "refused at grant time: a client told after the transfer has already \
             spent the whole upload finding out"
        );
    }

    #[tokio::test]
    async fn a_one_shot_share_is_gone_after_it_is_read() {
        let service = service().await;
        service.delete_on_download.store(true, Ordering::Relaxed);

        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);
        let path = format!("/s/{}", grant.key);

        let (status, _, body) = call(&service, "GET", &path, None, None, Vec::new()).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"hi", "the reader still gets the file");

        let (status, ..) = call(&service, "GET", &path, None, None, Vec::new()).await;
        assert_eq!(status, 404, "and nobody gets it twice");
    }

    #[tokio::test]
    async fn a_range_request_does_not_spend_a_one_shot_share() {
        // A player asks for a header before it asks for anything else. Counting
        // that as the download would delete the file between a video's first
        // request and its second.
        let service = service().await;
        service.delete_on_download.store(true, Ordering::Relaxed);

        let grant = grant_for(&service, upload_as(Visibility::Public, "", 10)).await;
        assert_eq!(put_through(&service, &grant, b"0123456789").await, 201);
        let path = format!("/s/{}", grant.key);

        let (status, ..) = ranged(&service, &path, "bytes=0-3").await;
        assert_eq!(status, 206);
        let (status, ..) = ranged(&service, &path, "bytes=4-9").await;
        assert_eq!(status, 206, "still there for the rest of the file");
    }

    #[tokio::test]
    async fn a_session_share_goes_when_the_session_does_if_the_operator_asked() {
        let service = service().await;
        service.delete_on_disconnect.store(true, Ordering::Relaxed);

        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);
        assert_eq!(service.listing(4, 50).await.len(), 1);

        // `ask` sends as session 7, which is the owner recorded on the row.
        service.forget_session(7).await;
        assert!(
            service.listing(4, 50).await.is_empty(),
            "the row went with the session"
        );
        assert!(
            http::object_path(service.objects_dir(), &grant.key).is_some_and(|path| !path.exists()),
            "and so did the bytes"
        );
    }

    #[tokio::test]
    async fn shares_outlive_a_disconnect_unless_the_operator_said_otherwise() {
        // The default, and the one that must not change by accident: a channel
        // losing every attachment because somebody closed their client is a
        // worse server than one that keeps files around.
        let service = service().await;
        let grant = grant_for(&service, upload_as(Visibility::Public, "", 2)).await;
        assert_eq!(put_through(&service, &grant, b"hi").await, 201);

        service.forget_session(7).await;
        assert_eq!(service.listing(4, 50).await.len(), 1);
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

    /// One frame in, one frame out, for a body that is not an upload.
    async fn ask_body(service: &Arc<FilesService>, body: files_envelope::Body) -> FilesEnvelope {
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: ServiceKind::Files.outer_type(),
                payload: FilesEnvelope { body: Some(body) }.encode_to_vec(),
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
            uploader: Uploader::default(),
            password_hash: None,
            seal: None,
            bind: None,
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
            uploader: Uploader::default(),
            password_hash: None,
            seal: None,
            bind: None,
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
            uploader: Uploader::default(),
            password_hash: None,
            seal: None,
            bind: None,
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

    #[tokio::test]
    async fn a_client_cannot_reach_a_plugins_objects_by_naming_one() {
        // Without the namespace check, `p/…` parses as no channel number at
        // all, falls back to channel zero, and is then checked against a
        // permission on the root that every session holds - so a client that
        // guessed a live document's key could read it.
        let service = service_holding(Perm::ENTER | Perm::SHARE_FILES).await;
        let envelope = ask_body(
            &service,
            files_envelope::Body::Download(starling_proto_fancy::fancy::files::DownloadRequest {
                request_id: "d1".to_owned(),
                key: "p/fancy-live-doc/018f/notes.md".to_owned(),
            }),
        )
        .await;

        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Invalid as i32,
            "and told as an unknown key rather than a forbidden one, which              would confirm the object exists"
        );
    }

    #[tokio::test]
    async fn a_client_cannot_reach_another_accounts_objects() {
        let service = service_holding(Perm::ENTER | Perm::SHARE_FILES).await;
        let envelope = ask_body(
            &service,
            files_envelope::Body::Download(starling_proto_fancy::fancy::files::DownloadRequest {
                request_id: "d1".to_owned(),
                key: "u/42/library.json".to_owned(),
            }),
        )
        .await;

        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Invalid as i32
        );
    }

    #[tokio::test]
    async fn a_client_cannot_remove_an_object_outside_the_channel_namespace() {
        // The operator permission for removing other people's files is held
        // here, so only the namespace check stands between it and a plugin's
        // documents.
        let service = service_holding(Perm::WRITE | Perm::RESET_USER_CONTENT).await;
        let envelope = ask_body(
            &service,
            files_envelope::Body::Forget(ForgetRequest {
                request_id: "f1".to_owned(),
                key: "p/fancy-live-doc/018f/notes.md".to_owned(),
            }),
        )
        .await;

        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Invalid as i32
        );
    }

    /// The whole plugin object path, as live-doc will walk it: reserve a slot,
    /// move the bytes, point a name at the key, read the name back.
    #[tokio::test]
    async fn a_plugin_stores_a_document_and_reads_it_back_by_name() {
        let service = service().await;
        let rpc = FilesRpc(Arc::clone(&service));

        let reservation = rpc
            .reserve(Request::new(ReserveRequest {
                scope: None,
                ns: "p/fancy-live-doc".to_owned(),
                filename: "notes.md".to_owned(),
                content_type: "text/markdown".to_owned(),
                size: 64,
                public: false,
            }))
            .await
            .expect("a reservation")
            .into_inner();
        assert!(
            reservation.key.starts_with("p/fancy-live-doc/"),
            "the slot is minted inside the namespace that asked: {}",
            reservation.key
        );

        let uri = reservation
            .url
            .strip_prefix("https://files.example.org")
            .expect("the granted URL points at this service");
        let (status, _, _) = call(&service, "PUT", uri, None, None, b"# notes".to_vec()).await;
        assert_eq!(
            status, 201,
            "the reservation is what the data plane accepts"
        );

        let put = rpc
            .put_name(Request::new(PutNameRequest {
                scope: None,
                ns: "p/fancy-live-doc".to_owned(),
                name: "notes".to_owned(),
                key: reservation.key.clone(),
                keep: 0,
            }))
            .await
            .expect("a revision")
            .into_inner();
        assert_eq!(put.rev, 1);

        let latest = rpc
            .latest_name(Request::new(NameRequest {
                scope: None,
                ns: "p/fancy-live-doc".to_owned(),
                name: "notes".to_owned(),
            }))
            .await
            .expect("a name")
            .into_inner();
        assert!(latest.found);
        assert_eq!(latest.key, reservation.key);

        // And the bytes are actually there, under the key the name gave.
        let signed = rpc
            .sign(Request::new(SignRequest {
                scope: None,
                actor: None,
                op: sign_request::Op::Get as i32,
                key: latest.key.clone(),
                content_type: String::new(),
                max_bytes: 0,
            }))
            .await
            .expect("a signed url")
            .into_inner();
        let uri = signed
            .url
            .strip_prefix("https://files.example.org")
            .expect("the granted URL points at this service");
        let (status, _, body) = call(&service, "GET", uri, None, None, Vec::new()).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"# notes");
    }

    #[tokio::test]
    async fn an_upload_with_no_reservation_is_refused_even_with_a_valid_signature() {
        // `Sign` alone does not open a slot, which is what stops a grant that
        // was already spent - or minted before a restart - from being replayed.
        let service = service().await;
        let rpc = FilesRpc(Arc::clone(&service));
        let signed = rpc
            .sign(Request::new(SignRequest {
                scope: None,
                actor: None,
                op: sign_request::Op::Put as i32,
                key: "p/fancy-live-doc/018f/notes.md".to_owned(),
                content_type: String::new(),
                max_bytes: 8,
            }))
            .await
            .expect("a signed url")
            .into_inner();

        let uri = signed
            .url
            .strip_prefix("https://files.example.org")
            .expect("the granted URL points at this service");
        let (status, _, _) = call(&service, "PUT", uri, None, None, b"nope".to_vec()).await;

        assert_eq!(status, 409, "no pending record, so no upload");
    }

    #[tokio::test]
    async fn keeping_one_revision_drops_the_bytes_the_old_one_held() {
        // What an emote wants: the history is not the point, and the old
        // object is waste that nothing can reach.
        let service = service().await;
        let rpc = FilesRpc(Arc::clone(&service));

        let mut keys = Vec::new();
        for _ in 0..2 {
            let reservation = rpc
                .reserve(Request::new(ReserveRequest {
                    scope: None,
                    ns: "srv/emotes".to_owned(),
                    filename: "blobfish.png".to_owned(),
                    content_type: "image/png".to_owned(),
                    size: 8,
                    public: true,
                }))
                .await
                .expect("a reservation")
                .into_inner();
            let uri = reservation
                .url
                .strip_prefix("https://files.example.org")
                .expect("the granted URL points at this service");
            let _ = call(&service, "PUT", uri, None, None, b"png".to_vec()).await;
            let _ = rpc
                .put_name(Request::new(PutNameRequest {
                    scope: None,
                    ns: "srv/emotes".to_owned(),
                    name: "blobfish".to_owned(),
                    key: reservation.key.clone(),
                    keep: 1,
                }))
                .await
                .expect("a revision");
            keys.push(reservation.key);
        }

        let stat = rpc
            .stat(Request::new(StatRequest {
                scope: None,
                actor: None,
                key: keys[0].clone(),
            }))
            .await
            .expect("a stat")
            .into_inner();
        assert!(
            !stat.exists,
            "the superseded object is gone, not left on the disk for ever"
        );

        let latest = rpc
            .latest_name(Request::new(NameRequest {
                scope: None,
                ns: "srv/emotes".to_owned(),
                name: "blobfish".to_owned(),
            }))
            .await
            .expect("a name")
            .into_inner();
        assert_eq!(latest.key, keys[1], "and the name answers with the new one");
    }

    /// Upload one emote the whole way: ask, `PUT`, and read the listing back.
    async fn upload_emote(
        service: &Arc<FilesService>,
        shortcode: &str,
        bytes: &[u8],
    ) -> FilesEnvelope {
        let envelope = ask_body(
            service,
            files_envelope::Body::EmoteUpload(EmoteUpload {
                request_id: "e1".to_owned(),
                shortcode: shortcode.to_owned(),
                filename: format!("{shortcode}.png"),
                content_type: "image/png".to_owned(),
                size: bytes.len() as u64,
                alias_emoji: "🐟".to_owned(),
                description: "a fish".to_owned(),
            }),
        )
        .await;
        let Some(files_envelope::Body::Grant(grant)) = envelope.body else {
            return envelope;
        };
        let uri = grant
            .url
            .strip_prefix("https://files.example.org")
            .expect("the granted URL points at this service");
        let (status, _, _) = call(service, "PUT", uri, None, None, bytes.to_vec()).await;
        assert_eq!(status, 201, "the emote's bytes are stored");
        ask_body(
            service,
            files_envelope::Body::EmoteQuery(starling_proto_fancy::fancy::files::EmoteQuery {
                request_id: "q1".to_owned(),
            }),
        )
        .await
    }

    #[tokio::test]
    async fn an_emote_is_listed_with_a_link_that_needs_no_signature() {
        // An `<img>` cannot sign a request, so an emote only works if its URL
        // is fetchable as it stands.
        let service = service_holding(Perm::MANAGE_EMOTES | Perm::ENTER).await;

        let envelope = upload_emote(&service, "blobfish", b"png-bytes").await;

        let Some(files_envelope::Body::Emotes(emotes)) = envelope.body else {
            panic!("expected a listing, got {:?}", envelope.body);
        };
        assert_eq!(emotes.emotes.len(), 1);
        let emote = &emotes.emotes[0];
        assert_eq!(emote.shortcode, "blobfish");
        assert_eq!(
            emote.alias_emoji, "🐟",
            "what to show where the image cannot be"
        );
        assert_eq!(emote.description, "a fish");

        let uri = emote
            .url
            .strip_prefix("https://files.example.org")
            .expect("a link on this server");
        let (status, _, body) = call(&service, "GET", uri, None, None, Vec::new()).await;
        assert_eq!(status, 200, "and it opens with no signature at all");
        assert_eq!(body, b"png-bytes");
    }

    #[tokio::test]
    async fn a_session_without_the_permission_cannot_add_an_emote() {
        let service = service_holding(Perm::ENTER | Perm::SHARE_FILES).await;

        let envelope = ask_body(
            &service,
            files_envelope::Body::EmoteUpload(EmoteUpload {
                request_id: "e1".to_owned(),
                shortcode: "blobfish".to_owned(),
                filename: "blobfish.png".to_owned(),
                content_type: "image/png".to_owned(),
                size: 9,
                alias_emoji: String::new(),
                description: String::new(),
            }),
        )
        .await;

        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Permission as i32
        );
    }

    #[tokio::test]
    async fn replacing_an_emote_keeps_its_shortcode_and_drops_the_old_image() {
        let service = service_holding(Perm::MANAGE_EMOTES | Perm::ENTER).await;
        let first = upload_emote(&service, "blobfish", b"old-bytes").await;
        let Some(files_envelope::Body::Emotes(listing)) = first.body else {
            panic!("expected a listing");
        };
        let old_url = listing.emotes[0].url.clone();

        let second = upload_emote(&service, "blobfish", b"new-bytes").await;

        let Some(files_envelope::Body::Emotes(listing)) = second.body else {
            panic!("expected a listing");
        };
        assert_eq!(listing.emotes.len(), 1, "one shortcode, not two");
        assert_ne!(listing.emotes[0].url, old_url, "pointing at the new image");

        let uri = old_url
            .strip_prefix("https://files.example.org")
            .expect("a link on this server");
        let (status, _, _) = call(&service, "GET", uri, None, None, Vec::new()).await;
        assert_eq!(
            status, 404,
            "the superseded image is gone: nothing can reach it, so keeping it is only disk"
        );
    }

    #[tokio::test]
    async fn removing_an_emote_takes_it_out_of_the_listing() {
        let service = service_holding(Perm::MANAGE_EMOTES | Perm::ENTER).await;
        let _ = upload_emote(&service, "blobfish", b"png-bytes").await;

        let envelope = ask_body(
            &service,
            files_envelope::Body::EmoteForget(EmoteForget {
                request_id: "f1".to_owned(),
                shortcode: "blobfish".to_owned(),
            }),
        )
        .await;

        let Some(files_envelope::Body::Emotes(emotes)) = envelope.body else {
            panic!("expected a listing, got {:?}", envelope.body);
        };
        assert!(emotes.emotes.is_empty());
    }

    #[tokio::test]
    async fn a_session_without_the_permission_cannot_remove_an_emote() {
        let service = service_holding(Perm::ENTER).await;

        let envelope = ask_body(
            &service,
            files_envelope::Body::EmoteForget(EmoteForget {
                request_id: "f1".to_owned(),
                shortcode: "blobfish".to_owned(),
            }),
        )
        .await;

        let Some(files_envelope::Body::Refused(refused)) = envelope.body else {
            panic!("expected a refusal, got {:?}", envelope.body);
        };
        assert_eq!(
            refused.refusal.expect("a refusal").kind,
            refusal::Kind::Permission as i32
        );
    }

    #[tokio::test]
    async fn an_emote_does_not_appear_as_a_file_shared_in_the_root_channel() {
        // Every reserved object carries channel 0, so before the key check a
        // channel-0 listing showed every emote and every plugin document as a
        // shared file.
        let service = service_holding(Perm::MANAGE_EMOTES | Perm::ENTER).await;
        let _ = upload_emote(&service, "blobfish", b"png-bytes").await;

        let listed = service.listing(0, 50).await;

        assert!(
            listed.is_empty(),
            "the emote is not a file anyone shared: {listed:?}"
        );
    }

    #[tokio::test]
    async fn an_emote_is_not_among_its_uploaders_shared_files() {
        let service = service_holding(Perm::MANAGE_EMOTES | Perm::ENTER).await;
        let _ = upload_emote(&service, "blobfish", b"png-bytes").await;

        let envelope = manage(&service, Audience::Mine).await;

        let Some(files_envelope::Body::Managed(listing)) = envelope.body else {
            panic!("expected a managed listing");
        };
        assert!(listing.files.is_empty(), "{:?}", listing.files);
    }

    #[tokio::test]
    async fn replacing_an_emotes_image_keeps_its_description() {
        let service = service_holding(Perm::MANAGE_EMOTES | Perm::ENTER).await;
        let _ = upload_emote(&service, "blobfish", b"old").await;

        let envelope = upload_emote(&service, "blobfish", b"new").await;

        let Some(files_envelope::Body::Emotes(listing)) = envelope.body else {
            panic!("expected a listing");
        };
        assert_eq!(listing.emotes[0].description, "a fish");
        assert_eq!(listing.emotes[0].alias_emoji, "🐟");
    }

    #[test]
    fn a_shortcode_is_letters_digits_and_two_punctuation_marks() {
        assert!(is_shortcode("blobfish"));
        assert!(is_shortcode("blob_fish-2"));
        assert!(!is_shortcode(""), "nothing is not a name");
        assert!(
            !is_shortcode(":-)"),
            "which safe_name would have called `file`"
        );
        assert!(
            !is_shortcode("blob fish"),
            "a space cannot sit between colons"
        );
    }

    #[tokio::test]
    async fn a_reservation_cannot_name_a_channel() {
        // The reservation path is not permission-checked - its callers are
        // services - so the namespace is the only thing keeping it from
        // minting a channel share behind the client envelope's back.
        let service = service().await;
        let rpc = FilesRpc(Arc::clone(&service));

        let refused = rpc
            .reserve(Request::new(ReserveRequest {
                scope: None,
                ns: "3".to_owned(),
                filename: "x.bin".to_owned(),
                content_type: "application/octet-stream".to_owned(),
                size: 1,
                public: false,
            }))
            .await;

        assert!(refused.is_err());
    }
}
