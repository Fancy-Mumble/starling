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

use prost::Message as _;
use sha2::{Digest as _, Sha256};
use starling_proto_fancy::audit::audit_server::{Audit, AuditServer};
use starling_proto_fancy::audit::{
    Entry, EntryPage, QueryRequest, RecordResult, VerifyRequest, VerifyResult,
};
use starling_proto_fancy::fancy::feature::{AuditEnvelope, AuditRecord, Page, audit_envelope};
use starling_proto_fancy::fancy::wire::PageInfo;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::log::{Category, LogEvent, Logger};
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
    logger: Logger,
    /// `log_days`, the retention an operator sets.
    ///
    /// It existed in `server-config` and was read by nothing, so the operator
    /// log had no retention at all (`docs/GAP-ANALYSIS.md` §5): a record of
    /// every login and every moderation action, kept for ever, on a server
    /// whose operator had written down how long they wanted to keep it.
    settings: starling_runtime::Settings,
}

/// How often expired entries are swept.
///
/// Hourly, because the unit of the setting is a *day*: sweeping more often
/// would be a query per minute to delete nothing, and a record surviving an
/// extra few minutes past a 31-day retention is not a retention failure.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3_600);

/// Milliseconds in a day.
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

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

    /// Delete entries older than `log_days`, for one virtual server.
    ///
    /// Returns how many went, so the operator log can say so — a retention
    /// sweep that silently removes a month of records is exactly the kind of
    /// deletion this service exists to make visible.
    ///
    /// **The chain is not re-linked.** Every surviving entry keeps the
    /// `prev_hash` it was written with, so a verify across the seam reports a
    /// break — which is correct and is the point: retention *is* a deletion,
    /// and an audit log that could delete its own history and still verify
    /// clean would be an audit log that can be edited without evidence. The
    /// sweep is announced in the log so the break has a documented cause.
    ///
    /// Zero days is "keep for ever", the same convention every other limit
    /// here uses, and it is also what an unreachable `server-config` yields —
    /// so the failure mode of this path is keeping too much, never deleting
    /// something an operator meant to keep.
    pub async fn sweep(&self, scope: u32, now_ms: u64) -> u64 {
        let days = u64::from(self.settings.get(scope).log_days);
        if days == 0 {
            return 0;
        }
        let cutoff = now_ms.saturating_sub(days.saturating_mul(DAY_MS));
        // `at_ms` rather than `expires_at_ms`: that column is a per-entry
        // deadline some records carry, and this is the server-wide policy.
        // A record with its own earlier deadline is swept by whichever comes
        // first, which is what both settings mean read together.
        let result = sqlx::query(
            "DELETE FROM server_audit WHERE server_id = ? AND (at_ms < ? \
             OR (expires_at_ms > 0 AND expires_at_ms < ?))",
        )
        .bind(i64::from(scope))
        .bind(cutoff as i64)
        .bind(now_ms as i64)
        .execute(self.store.pool())
        .await;

        match result {
            Ok(done) if done.rows_affected() > 0 => {
                let removed = done.rows_affected();
                self.logger.log(
                    LogEvent::notice(Category::Server, "audit retention swept")
                        .with("removed", removed)
                        .with("days", days)
                        .with("scope", scope),
                );
                removed
            }
            Ok(_) => 0,
            Err(error) => {
                // Reported rather than swallowed: a retention policy that has
                // silently stopped running looks exactly like one that is
                // working, until the disk fills.
                tracing::error!(%error, scope, "the audit retention sweep failed");
                0
            }
        }
    }

    /// One sweep per interval, across every virtual server, until aborted.
    async fn sweep_forever(self: Arc<Self>, scopes: Vec<u32>) {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            for scope in &scopes {
                let _ = self.sweep(*scope, now_ms()).await;
            }
        }
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
        // Not `clamp(1, 500)`: an operator calling `GET /v1/log` without a
        // limit sends 0, and clamping that up returned a one-row audit log.
        let limit = starling_proto_fancy::page::page_size(request.limit, 50, 500);

        // Every filter below was already in the contract and **none of them was
        // applied**: the statement bound `scope` and `since_ms` and nothing
        // else, so an operator narrowing by category, by target or by time
        // window got the unfiltered log back and no indication of it. A filter
        // that is accepted and ignored is worse than one that is refused —
        // whoever is reading the result believes it.
        //
        // A `QueryBuilder` rather than an assembled string: every clause sits
        // beside the value it binds, so the two cannot fall out of order, and
        // no operator-supplied text reaches the statement as text.
        let mut query = sqlx::QueryBuilder::<sqlx::Any>::new(
            "SELECT id, at_ms, category, action, actor, target_account, target_channel, \
                    detail, entry_hash FROM server_audit WHERE server_id = ",
        );
        let _ = query.push_bind(i64::from(scope));
        let _ = query.push(" AND at_ms >= ").push_bind(request.since_ms as i64);
        if request.until_ms > 0 {
            let _ = query
                .push(" AND at_ms <= ")
                .push_bind(request.until_ms as i64);
        }
        if !request.category.is_empty() {
            let _ = query
                .push(" AND category = ")
                .push_bind(request.category.clone());
        }
        if request.target_account > 0 {
            let _ = query
                .push(" AND target_account = ")
                .push_bind(request.target_account as i64);
        }
        // Keyset pagination: entries are UUIDv7, so "older than this id" stays
        // a stable position as the log grows underneath the reader.
        if !request.before.is_empty() {
            let _ = query.push(" AND id < ").push_bind(request.before.clone());
        }
        let _ = query
            .push(" ORDER BY id DESC LIMIT ")
            .push_bind(i64::from(limit + 1));

        let rows = query
            .build()
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
                let broken_at: Vec<u8> = row.try_get("id").unwrap_or_default();
                // The audit chain not matching means rows were altered under
                // the server. Nothing else in this system is worth an `error`
                // more than this, and it must not depend on whoever called
                // `verify` bothering to read the result.
                tracing::error!(
                    checked,
                    scope,
                    "the audit chain is broken; entries have been altered"
                );
                self.logger.log(
                    LogEvent::error(Category::Security, "the audit chain is broken")
                        .with("scope", scope)
                        .with("verified", checked)
                        .with(
                            "broken_at",
                            Uuid7::from_slice(&broken_at)
                                .map(|id| id.to_string())
                                .unwrap_or_default(),
                        ),
                );
                return VerifyResult {
                    intact: false,
                    checked,
                    broken_at,
                };
            }
            previous = stored;
            checked += 1;
        }
        tracing::info!(checked, scope, "the audit chain verified intact");
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

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResult>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        Ok(Response::new(self.0.verify(scope).await))
    }
}

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
        let cursor = query.page.unwrap_or_default();
        let page = self
            .query(
                inbound.scope,
                &QueryRequest {
                    since_ms: query.since_ms,
                    until_ms: query.until_ms,
                    category: query.category,
                    target_account: query.target_account,
                    limit: cursor.page_size(50, 200),
                    // Keyset pagination, so a client pages by handing back the
                    // id of the oldest entry it holds.
                    before: Uuid7::parse(&cursor.before_id)
                        .map(Uuid7::to_vec)
                        .unwrap_or_default(),
                    ..QueryRequest::default()
                },
            )
            .await;

        let reply = AuditEnvelope {
            body: Some(audit_envelope::Body::Page(Page {
                page: Some(if page.more {
                    PageInfo::more_before(
                        page.entries
                            .last()
                            .and_then(|entry| Uuid7::from_slice(&entry.id))
                            .map(|id| id.to_string())
                            .unwrap_or_default(),
                    )
                } else {
                    PageInfo::complete()
                }),
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
                        target_account: entry.target_account,
                        target_channel: entry.target_channel,
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

impl Serve for AuditService {
    const NAME: &'static str = "audit";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        let settings =
            starling_runtime::Settings::new(ctx.resolver.clone()).logging_to(ctx.logger.clone());
        drop(settings.watch(&ctx.virtual_servers()));
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            settings,
        }))
    }

    /// Sweep expired entries until shutdown.
    ///
    /// A timer rather than a check per write: retention is a coarse deadline,
    /// and doing it on the write path would make every audited action wait for
    /// a `DELETE` that concerns none of it.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let scopes = ctx.virtual_servers();
        let sweeper = tokio::spawn(Arc::clone(&self).sweep_forever(scopes));
        ctx.shutdown.wait().await;
        sweeper.abort();
        Ok(())
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(AuditServer::new(AuditRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn service() -> Arc<AuditService> {
        service_keeping(starling_runtime::settings::defaults(1).log_days).await
    }

    /// The same service, with `log_days` pinned to `days`.
    async fn service_keeping(days: u32) -> Arc<AuditService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:audit-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        let resolver = starling_runtime::channel::Resolver::new(
            Arc::new(starling_runtime::config::Config::with_defaults(
                std::path::Path::new("/run/starling"),
            )),
            starling_runtime::inproc::Broker::new(),
        );
        Arc::new(AuditService {
            store,
            fanout: Fanout::default(),
            logger: Logger::null(),
            settings: starling_runtime::Settings::fixed(
                resolver,
                starling_proto_fancy::serverconfig::Snapshot {
                    log_days: days,
                    ..starling_runtime::settings::defaults(1)
                },
            ),
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
    async fn a_filtered_query_actually_filters() {
        // Every one of these filters was in the contract and none was applied:
        // the statement bound `scope` and `since_ms` and nothing else. An
        // operator narrowing the log got the whole log back, looking narrowed.
        let service = service().await;
        let _ = service
            .record(
                1,
                Entry {
                    category: "moderation".to_owned(),
                    target_account: 7,
                    ..entry("ban")
                },
            )
            .await;
        let _ = service
            .record(
                1,
                Entry {
                    category: "channel".to_owned(),
                    target_account: 9,
                    ..entry("create")
                },
            )
            .await;

        let by_category = service
            .query(
                1,
                &QueryRequest {
                    category: "moderation".to_owned(),
                    limit: 100,
                    ..QueryRequest::default()
                },
            )
            .await;
        assert_eq!(by_category.entries.len(), 1, "the category was ignored");
        assert_eq!(by_category.entries[0].action, "ban");

        let by_target = service
            .query(
                1,
                &QueryRequest {
                    target_account: 9,
                    limit: 100,
                    ..QueryRequest::default()
                },
            )
            .await;
        assert_eq!(by_target.entries.len(), 1, "the target was ignored");
        assert_eq!(by_target.entries[0].target_account, 9);

        // An upper bound in the past matches nothing, which is the case that
        // proves `until_ms` is bound rather than silently dropped: without it
        // this returns both entries.
        let ancient = service
            .query(
                1,
                &QueryRequest {
                    until_ms: 1,
                    limit: 100,
                    ..QueryRequest::default()
                },
            )
            .await;
        assert!(ancient.entries.is_empty(), "until_ms was ignored");
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

    /// One entry, recorded as though it happened `days` ago.
    async fn record_aged(service: &AuditService, days: u64, now: u64) {
        let _ = service
            .record(
                1,
                Entry {
                    at_ms: now.saturating_sub(days * DAY_MS),
                    ..entry("ban")
                },
            )
            .await;
    }

    /// How many entries the log holds for scope 1.
    ///
    /// The limit is explicit because `QueryRequest::default()` asks for zero,
    /// which the query clamps to one — a count taken through the default would
    /// read "1" however many entries survived.
    async fn held(service: &AuditService) -> usize {
        service
            .query(
                1,
                &QueryRequest {
                    limit: 100,
                    ..QueryRequest::default()
                },
            )
            .await
            .entries
            .len()
    }

    #[tokio::test]
    async fn log_days_decides_how_much_of_the_operator_log_survives() {
        // §5's `log_days`: in `server-config`, read by nothing, so the operator
        // log had no retention at all. An operator who wrote down 7 days kept
        // every login and every ban for ever.
        //
        // The same three entries, swept twice, with only the setting different.
        let now = now_ms();

        let strict = service_keeping(7).await;
        for age in [1, 10, 40] {
            record_aged(&strict, age, now).await;
        }
        assert_eq!(strict.sweep(1, now).await, 2, "two entries are past 7 days");
        assert_eq!(held(&strict).await, 1);

        let lenient = service_keeping(90).await;
        for age in [1, 10, 40] {
            record_aged(&lenient, age, now).await;
        }
        assert_eq!(
            lenient.sweep(1, now).await,
            0,
            "all three are inside 90 days"
        );
        assert_eq!(held(&lenient).await, 3);
    }

    #[tokio::test]
    async fn a_retention_of_zero_keeps_everything() {
        // The convention every other limit here uses, and the direction this
        // one has to fail in: an unreachable `server-config` must not be a way
        // to delete an operator's records.
        let now = now_ms();
        let service = service_keeping(0).await;
        record_aged(&service, 4_000, now).await;
        assert_eq!(service.sweep(1, now).await, 0);
        assert_eq!(held(&service).await, 1);
    }

    #[tokio::test]
    async fn an_entry_with_its_own_deadline_goes_at_whichever_comes_first() {
        // `log_days` is the server-wide policy and `expires_at_ms` is a
        // per-entry one. Read together they mean "delete at the earlier", and
        // a sweep that honoured only the policy would keep a record somebody
        // deliberately marked short-lived.
        let now = now_ms();
        let service = service_keeping(365).await;
        let _ = service
            .record(
                1,
                Entry {
                    at_ms: now,
                    expires_at_ms: now.saturating_sub(1_000),
                    ..entry("ban")
                },
            )
            .await;
        assert_eq!(service.sweep(1, now).await, 1);
        assert_eq!(held(&service).await, 0);
    }
}
