//! `files` — bulk transfer, off the control stream.
//!
//! Mumble has no file transfer; `RequestBlob` (23) moves avatars and comments
//! over the control connection, where anything large head-of-line blocks every
//! control message behind it — and the control-overflow-disconnects rule would
//! then kill clients mid-upload (`docs/ARCHITECTURE.md` §3).
//!
//! So this service gets its own HTTP listener. The gateway hands out a
//! **short-lived signed URL** over the control channel, and bytes move over
//! HTTP: shared files, avatars, comments, plugin binaries, link-preview
//! thumbnails, audit exports. Being HTTP, it can sit behind an `Ingress` and get
//! TLS termination and a CDN for free.

pub mod sign;

pub use sign::{Signature, sign, verify};

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::files::{FilesEnvelope, Grant, Refused, files_envelope};
use starling_proto_fancy::files::files_server::{Files, FilesServer};
use starling_proto_fancy::files::{ObjectInfo, SignRequest, SignedUrl, StatRequest, sign_request};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::config::ByteSize;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tonic::{Request, Response, Status};

/// The schema: one row per stored object.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
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
)];

/// The service.
#[derive(Debug)]
pub struct FilesService {
    store: Store,
    secret: Vec<u8>,
    public_url: String,
    ttl_ms: u64,
    max_upload: u64,
    fanout: Fanout,
    logger: Logger,
}

impl FilesService {
    /// Mint a signed URL.
    ///
    /// Short-lived and signed rather than a capability that never expires: a
    /// URL that leaks into a log or a chat history should stop working.
    fn grant(&self, method: &str, key: &str) -> SignedUrl {
        let expires = now_ms() + self.ttl_ms;
        let signature = sign(&self.secret, method, key, expires);
        SignedUrl {
            url: format!(
                "{}/{key}?expires={expires}&sig={signature}",
                self.public_url.trim_end_matches('/')
            ),
            expires_at_ms: expires,
            method: method.to_owned(),
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
        if matches!(op, sign_request::Op::Put) && req.max_bytes > self.0.max_upload {
            // The client is told, but the operator is the one who can raise the
            // limit — and cannot if the refusal never reaches them.
            self.0.logger.log(
                LogEvent::notice(Category::Permission, "upload refused: over the size limit")
                    .with("key", req.key.clone())
                    .with("requested", req.max_bytes)
                    .with("limit", self.0.max_upload),
            );
            return Err(Status::invalid_argument(format!(
                "an upload may be at most {} bytes",
                self.0.max_upload
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
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
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
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
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
                if upload.size > self.max_upload {
                    FilesEnvelope {
                        body: Some(files_envelope::Body::Refused(Refused {
                            request_id: upload.request_id,
                            reason: format!("the limit is {} bytes", self.max_upload),
                        })),
                    }
                } else {
                    let key = format!("{}/{}", upload.channel, upload.filename);
                    let url = self.grant("PUT", &key);
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
        Ok(Arc::new(Self {
            store,
            secret: sign::secret(&ctx.config.runtime.data_dir)?,
            public_url: service
                .public_url
                .clone()
                .unwrap_or_else(|| "http://localhost:8080".to_owned()),
            ttl_ms: service
                .url_ttl
                .map_or(900_000, |ttl| ttl.get().as_millis() as u64),
            max_upload: service.max_upload.map_or(512 * 1024 * 1024, ByteSize::get),
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(FilesServer::new(FilesRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            public_url: "https://files.example.org".to_owned(),
            ttl_ms: 900_000,
            max_upload: 1024,
            fanout: Fanout::default(),
            logger: Logger::null(),
        })
    }

    #[tokio::test]
    async fn an_upload_over_the_limit_is_refused_with_the_limit_in_the_message() {
        // "Refused" without a number is a support ticket.
        let service = service().await;
        let envelope = FilesEnvelope {
            body: Some(files_envelope::Body::Upload(
                starling_proto_fancy::fancy::files::UploadRequest {
                    request_id: "r1".to_owned(),
                    channel: 1,
                    filename: "big.bin".to_owned(),
                    content_type: "application/octet-stream".to_owned(),
                    size: 4096,
                    sha256: Vec::new(),
                },
            )),
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
}
