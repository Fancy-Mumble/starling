//! Per-service storage: a pool, a dialect, a migration chain, and a key/value
//! table.
//!
//! **Each service owns its own schema. No service reads another's tables.** A
//! shared database *service* would keep the schema coupling and add a hop — the
//! anti-pattern this architecture exists to avoid — so what is shared is this
//! code, not the data (`docs/ARCHITECTURE.md` §4).
//!
//! Two rules from `docs/STORAGE.md` are enforced by the shape of this module
//! rather than by review:
//!
//! * **typed columns, and every table carries the index its query shape needs**
//!   (L1, L2). A migration is SQL written next to the query it serves.
//! * **the database is never on a permission-check path** (L7, D1). Control
//!   plane state is held in memory and written behind; what lives here is the
//!   durable record, not the read path.

pub mod backend;
pub mod dialect;
mod kv;
mod migrations;

pub use backend::Backend;
pub use dialect::{Dialect, SqlDialect};
pub use kv::{KvOp, KvStore};
pub use migrations::Migration;

/// Why a store could not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database could not be reached, or the URL was not understood.
    #[error("{0}")]
    Backend(String),
    /// A statement failed.
    #[error("{0}")]
    Query(String),
    /// The data on disk does not match what the schema promises.
    #[error("{0}")]
    Corrupt(String),
    /// A uniqueness or foreign-key constraint refused the write.
    ///
    /// Distinct from [`Self::Query`] because it is the caller's answer, not a
    /// failure: registering a name that is taken is a refusal to report, not an
    /// error to log.
    #[error("{0}")]
    Conflict(String),
}

/// One service's database.
#[derive(Debug, Clone)]
pub struct Store {
    backend: Backend,
}

impl Store {
    /// Open `url` and apply nothing yet.
    ///
    /// Migrations are applied by the owning service, because the schema belongs
    /// to it — this type deliberately does not know what tables exist.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] if the database cannot be opened.
    pub async fn open(url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let _ = max_connections;
        Ok(Self {
            backend: Backend::connect(url).await?,
        })
    }

    /// The pool, for a service's own queries.
    #[must_use]
    pub const fn pool(&self) -> &sqlx::AnyPool {
        self.backend.pool()
    }

    /// The dialect, for the handful of things the backends disagree about.
    #[must_use]
    pub const fn dialect(&self) -> Dialect {
        self.backend.dialect()
    }

    /// Apply `migrations` in order, skipping any already recorded.
    ///
    /// Migrations are additive and recorded by name, so a restarted service
    /// re-applies nothing and a rolled-back binary still reads its data.
    ///
    /// # Errors
    ///
    /// [`StoreError::Query`] if a statement fails, naming the migration.
    pub async fn migrate(&self, migrations: &[Migration<'_>]) -> Result<(), StoreError> {
        migrations::apply(self, migrations).await
    }

    /// A namespaced key/value view of this database.
    ///
    /// This is what a plugin gets instead of SQL: the host never learns a
    /// plugin's schema, and a plugin cannot name or reach another's data
    /// (`docs/STORAGE.md` §5).
    #[must_use]
    pub fn kv(&self) -> KvStore {
        KvStore::new(self.clone())
    }

    /// Run a statement with no parameters, for schema work.
    ///
    /// # Errors
    ///
    /// [`StoreError::Query`] with the statement's first line for context.
    pub async fn execute(&self, sql: &str) -> Result<(), StoreError> {
        // `AssertSqlSafe` because sqlx 0.9 will only take a `&'static str`
        // otherwise, and this is schema work: every caller passes a `Migration`
        // constant compiled into the binary. No value from a client reaches
        // here — a migration is not somewhere user data is interpolated — which
        // is exactly the audit the assertion is asking for.
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(|error| {
                let first = sql.lines().next().unwrap_or_default();
                StoreError::Query(format!("{first}: {error}"))
            })
    }
}

#[cfg(test)]
pub(crate) async fn memory_store() -> Store {
    // A shared-cache in-memory database: a private one would be a different,
    // empty database per pooled connection. Named uniquely per call, because
    // `cache=shared` makes same-named databases visible to every connection
    // that names them — sharing one name across tests would let them race on
    // the same tables.
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    Store::open(
        &format!("sqlite:file:starling-test-{id}?mode=memory&cache=shared"),
        1,
    )
    .await
    .expect("an in-memory database must open")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unknown_scheme_is_named_rather_than_defaulted() {
        // Defaulting to SQLite for a typo'd Postgres URL would start the server
        // against an empty local file and look exactly like data loss.
        let err = Store::open("postgrse://localhost/starling", 1)
            .await
            .expect_err("a typo must not open something else");
        assert!(matches!(err, StoreError::Backend(_)));
    }
}
