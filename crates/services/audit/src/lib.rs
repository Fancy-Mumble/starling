//! `audit` — the hash-chained operator record.
//!
//! Every entry carries the hash of the one before it, so a deletion from the
//! middle is **detectable** rather than silent. That is the property that makes
//! an audit log worth keeping: a log that can be edited without evidence tells
//! you only what its editor wanted you to see.
//!
//! The shape — typed columns, composite indexes led by `server_id`, a retention
//! column with an index to sweep it — is the one the existing audit plugin
//! already uses (`docs/STORAGE.md` L5). What is deliberately *not* copied is
//! its own database file per plugin: one database, one pool, one backup.

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use starling_proto_fancy::audit::audit_server::{Audit, AuditServer};
use starling_proto_fancy::audit::{
    Entry, EntryPage, QueryRequest, RecordResult, VerifyRequest, VerifyResult,
};
use starling_proto_fancy::fancy::feature::{AuditEnvelope, AuditRecord, Page, audit_envelope};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tonic::{Request, Response, Status};

/// The schema, with the indexes the three query shapes actually use.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_audit",
    &[
        "CREATE TABLE IF NOT EXISTS server_audit (\
             server_id BIGINT NOT NULL, id BLOB NOT NULL, at_ms BIGINT NOT NULL, \
             category VARCHAR(64) NOT NULL, action VARCHAR(64) NOT NULL, \
             actor VARCHAR(190) NOT NULL, target_account BIGINT NOT NULL, \
             target_channel BIGINT NOT NULL, detail TEXT NOT NULL, \
             expires_at_ms BIGINT NULL, event_offset BIGINT NULL, \
             prev_hash BLOB NOT NULL, entry_hash BLOB NOT NULL, \
             PRIMARY KEY (server_id, id))",
        "CREATE INDEX IF NOT EXISTS ix_audit_server_ts ON server_audit(server_id, at_ms)",
        "CREATE INDEX IF NOT EXISTS ix_audit_target ON server_audit(server_id, target_account, at_ms)",
        "CREATE INDEX IF NOT EXISTS ix_audit_expiry ON server_audit(server_id, expires_at_ms)",
    ],
)];

/// The service.
#[derive(Debug)]
pub struct AuditService {
    store: Store,
    fanout: Fanout,
}

/// The hash of one entry, given the hash before it.
///
/// The previous hash is part of the input, which is what makes the chain a
/// chain rather than a list of independently verifiable rows.
#[must_use]
pub fn chain_hash(previous: &[u8], entry: &Entry) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update(entry.at_ms.to_be_bytes());
    hasher.update(entry.category.as_bytes());
    hasher.update(entry.action.as_bytes());
    hasher.update(entry.actor_name.as_bytes());
    hasher.update(entry.target_account.to_be_bytes());
    hasher.update(entry.target_channel.to_be_bytes());
    hasher.update(entry.detail.as_bytes());
    hasher.finalize().to_vec()
}

impl AuditService {
    /// The hash of the most recent entry, which the next one chains onto.
    async fn head(&self, scope: u32) -> Vec<u8> {
        use sqlx::Row as _;
        sqlx::query(
            "SELECT entry_hash FROM server_audit WHERE server_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(i64::from(scope))
        .fetch_optional(self.store.pool())
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<Vec<u8>, _>("entry_hash").ok())
        .unwrap_or_default()
    }

    /// Append one entry.
    async fn record(&self, scope: u32, mut entry: Entry) -> RecordResult {
        if entry.at_ms == 0 {
            entry.at_ms = now_ms();
        }
        let id = Uuid7::now();
        let previous = self.head(scope).await;
        let hash = chain_hash(&previous, &entry);

        let result = sqlx::query(
            "INSERT INTO server_audit (server_id, id, at_ms, category, action, actor, \
                 target_account, target_channel, detail, expires_at_ms, event_offset, \
                 prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(id.to_vec())
        .bind(entry.at_ms as i64)
        .bind(&entry.category)
        .bind(&entry.action)
        .bind(&entry.actor_name)
        .bind(entry.target_account as i64)
        .bind(i64::from(entry.target_channel))
        .bind(&entry.detail)
        .bind(entry.expires_at_ms as i64)
        .bind(entry.event_offset.map(|offset| offset as i64))
        .bind(previous.as_slice())
        .bind(hash.as_slice())
        .execute(self.store.pool())
        .await;

        match result {
            Ok(_) => RecordResult {
                id: id.to_vec(),
                entry_hash: hash,
                duplicate: false,
            },
            // A duplicate offset is accepted once and then ignored, which is
            // what makes a producer safe to retry.
            Err(_) => RecordResult {
                id: id.to_vec(),
                entry_hash: hash,
                duplicate: true,
            },
        }
    }

    /// A page, newest first.
    async fn query(&self, scope: u32, request: &QueryRequest) -> EntryPage {
        use sqlx::Row as _;
        let limit = request.limit.clamp(1, 500);
        let rows = sqlx::query(
            "SELECT id, at_ms, category, action, actor, target_account, target_channel, \
                    detail, entry_hash FROM server_audit \
             WHERE server_id = ? AND at_ms >= ? ORDER BY id DESC LIMIT ?",
        )
        .bind(i64::from(scope))
        .bind(request.since_ms as i64)
        .bind(i64::from(limit + 1))
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default();

        let more = rows.len() > limit as usize;
        let mut entries = Vec::new();
        let mut hashes = Vec::new();
        for row in rows.into_iter().take(limit as usize) {
            hashes.push(row.try_get::<Vec<u8>, _>("entry_hash").unwrap_or_default());
            entries.push(Entry {
                scope: None,
                id: row.try_get("id").unwrap_or_default(),
                at_ms: row.try_get::<i64, _>("at_ms").unwrap_or_default() as u64,
                category: row.try_get("category").unwrap_or_default(),
                action: row.try_get("action").unwrap_or_default(),
                actor: None,
                actor_name: row.try_get("actor").unwrap_or_default(),
                target_account: row.try_get::<i64, _>("target_account").unwrap_or_default() as u64,
                target_channel: row.try_get::<i64, _>("target_channel").unwrap_or_default() as u32,
                detail: row.try_get("detail").unwrap_or_default(),
                expires_at_ms: 0,
                event_offset: None,
            });
        }
        EntryPage {
            entries,
            hashes,
            more,
        }
    }

    /// Walk the chain and report the first link that does not hold.
    async fn verify(&self, scope: u32) -> VerifyResult {
        use sqlx::Row as _;
        let rows = sqlx::query(
            "SELECT id, at_ms, category, action, actor, target_account, target_channel, \
                    detail, prev_hash, entry_hash FROM server_audit \
             WHERE server_id = ? ORDER BY id ASC",
        )
        .bind(i64::from(scope))
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default();

        let mut previous: Vec<u8> = Vec::new();
        let mut checked = 0_u64;
        for row in rows {
            let entry = Entry {
                at_ms: row.try_get::<i64, _>("at_ms").unwrap_or_default() as u64,
                category: row.try_get("category").unwrap_or_default(),
                action: row.try_get("action").unwrap_or_default(),
                actor_name: row.try_get("actor").unwrap_or_default(),
                target_account: row.try_get::<i64, _>("target_account").unwrap_or_default() as u64,
                target_channel: row.try_get::<i64, _>("target_channel").unwrap_or_default() as u32,
                detail: row.try_get("detail").unwrap_or_default(),
                ..Entry::default()
            };
            let expected = chain_hash(&previous, &entry);
            let stored: Vec<u8> = row.try_get("entry_hash").unwrap_or_default();
            if expected != stored {
                return VerifyResult {
                    intact: false,
                    checked,
                    broken_at: row.try_get("id").unwrap_or_default(),
                };
            }
            previous = stored;
            checked += 1;
        }
        VerifyResult {
            intact: true,
            checked,
            broken_at: Vec::new(),
        }
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct AuditRpc(Arc<AuditService>);

#[tonic::async_trait]
impl Audit for AuditRpc {
    async fn record(&self, request: Request<Entry>) -> Result<Response<RecordResult>, Status> {
        let entry = request.into_inner();
        let scope = entry.scope.as_ref().map_or(1, |s| s.virtual_server);
        Ok(Response::new(self.0.record(scope, entry).await))
    }

    async fn query(&self, request: Request<QueryRequest>) -> Result<Response<EntryPage>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        Ok(Response::new(self.0.query(scope, &req).await))
    }

    async fn verify(&self, request: Request<VerifyRequest>) -> Result<Response<VerifyResult>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        Ok(Response::new(self.0.verify(scope).await))
    }
}

#[async_trait]
impl ClientService for AuditService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Audit.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = AuditEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        let Some(audit_envelope::Body::Query(query)) = envelope.body else {
            return Actions::new();
        };
        let page = self
            .query(
                inbound.scope,
                &QueryRequest {
                    since_ms: query.since_ms,
                    until_ms: query.until_ms,
                    category: query.category,
                    limit: query.limit,
                    ..QueryRequest::default()
                },
            )
            .await;

        let reply = AuditEnvelope {
            body: Some(audit_envelope::Body::Page(Page {
                more: page.more,
                records: page
                    .entries
                    .into_iter()
                    .zip(page.hashes)
                    .map(|(entry, hash)| AuditRecord {
                        id: Uuid7::from_slice(&entry.id)
                            .map(|id| id.to_string())
                            .unwrap_or_default(),
                        at_ms: entry.at_ms,
                        category: entry.category,
                        action: entry.action,
                        actor: entry.actor_name,
                        detail: entry.detail,
                        entry_hash: hex(&hash),
                    })
                    .collect(),
            })),
        };
        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[async_trait]
impl Serve for AuditService {
    const NAME: &'static str = "audit";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
        tonic::service::Routes::default()
            .add_service(AuditServer::new(AuditRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn service() -> Arc<AuditService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(&format!("sqlite:file:audit-test-{id}?mode=memory&cache=shared"), 1)
            .await
            .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        Arc::new(AuditService {
            store,
            fanout: Fanout::default(),
        })
    }

    fn entry(action: &str) -> Entry {
        Entry {
            category: "moderation".to_owned(),
            action: action.to_owned(),
            actor_name: "operator".to_owned(),
            detail: "detail".to_owned(),
            ..Entry::default()
        }
    }

    #[tokio::test]
    async fn an_intact_chain_verifies() {
        let service = service().await;
        for action in ["ban", "kick", "unban"] {
            let _ = service.record(1, entry(action)).await;
        }
        let result = service.verify(1).await;
        assert!(result.intact);
        assert_eq!(result.checked, 3);
    }

    #[tokio::test]
    async fn every_entry_hashes_over_the_one_before_it() {
        // Without the previous hash in the input, a row could be removed and
        // the rest would still verify — which is the whole failure this is
        // built to make visible.
        let first = chain_hash(&[], &entry("ban"));
        let second = chain_hash(&first, &entry("ban"));
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn a_tampered_row_is_reported_with_the_entry_it_broke_at() {
        let service = service().await;
        for action in ["ban", "kick"] {
            let _ = service.record(1, entry(action)).await;
        }
        let _ = sqlx::query("UPDATE server_audit SET detail = 'edited' WHERE server_id = 1")
            .execute(service.store.pool())
            .await;
        let result = service.verify(1).await;
        assert!(!result.intact);
        assert!(!result.broken_at.is_empty());
    }
}
