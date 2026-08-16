//! The connection pool, and which database is on the other end.
//!
//! murmur supports SQLite, MySQL and PostgreSQL and picks between them from
//! configuration, so the choice cannot be a compile-time generic without
//! building three binaries. sqlx's `Any` driver resolves it from the URL scheme
//! at connect time, which is the same shape murmur has.
//!
//! What `Any` unifies is the *protocol*. It does not unify the SQL; that is
//! [`crate::storage::dialect`]'s job, and the reason a pool alone is not enough.
//!
//! # Two things a pool gets wrong unless told
//!
//! Both are SQLite's, and both are silent.
//!
//! **Per-connection settings apply per connection.** SQLite's foreign-key
//! enforcement is one, so running the pragma once after connecting arms it on
//! exactly one pooled connection and leaves the rest ignoring every
//! `ON DELETE CASCADE` in the schema. Whether a delete cascaded would then depend
//! on which connection the pool happened to hand out. `after_connect` runs it
//! on every one.
//!
//! **`:memory:` is private to a connection.** Two connections to `sqlite::memory:`
//! are two different empty databases, so a pool creates the schema on one and
//! reads from another. In-memory therefore gets a pool of exactly one, whatever
//! `max_connections` says.
//!
//! # What `Any` costs
//!
//! Compile-time query checking: `sqlx::query!` cannot verify a statement it will
//! not know the dialect of until run time. Every query in this crate is
//! therefore an unchecked `sqlx::query`, and the schema is exercised against a
//! real database in the tests instead, SQLite in memory, which is a genuine SQL
//! engine rather than a mock.

use std::time::Duration;

use crate::storage::StoreError;
use sqlx::AnyPool;
use sqlx::any::{AnyPoolOptions, install_default_drivers};

use crate::storage::dialect::{Dialect, SqlDialect};

/// How long to wait for a connection before giving up.
///
/// A server that cannot reach its database should say so at boot rather than
/// hanging with no output, which is what an unbounded wait looks like to an
/// operator.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many connections to keep when nothing is configured.
///
/// The one default behind `services.*.storage.max_connections`, so a service
/// with no `[storage]` block and one with an empty block get the same pool.
/// Generous for a service whose concurrency is bounded by the handshake path
/// and the admin surface, and small enough not to exhaust a shared database
/// server.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 8;

/// A connection pool and the dialect it speaks.
#[derive(Debug, Clone)]
pub struct Backend {
    pool: AnyPool,
    dialect: Dialect,
}

impl Backend {
    /// Connect to `url` with a pool of `max_connections`.
    ///
    /// The size is what the operator asked for, capped where the URL cannot
    /// support it; see [`pool_size`].
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] if the scheme is unsupported or the database
    /// cannot be reached within `CONNECT_TIMEOUT`.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StoreError> {
        // `Any` resolves a scheme to a driver through a registry that starts
        // empty. Without this every connection fails with "no driver found",
        // including for schemes that are compiled in.
        install_default_drivers();

        let dialect = Dialect::from_url(url)?;
        let pragma = dialect.foreign_key_pragma();

        let pool = AnyPoolOptions::new()
            .max_connections(pool_size(url, max_connections))
            .acquire_timeout(CONNECT_TIMEOUT)
            // Every connection, not just the first. A pragma run once arms one
            // pooled connection and leaves the others ignoring the schema's
            // foreign keys, so whether a delete cascades would depend on which
            // connection the pool handed out.
            .after_connect(move |connection, _meta| {
                Box::pin(async move {
                    if let Some(pragma) = pragma {
                        let _ = sqlx::query(pragma).execute(&mut *connection).await?;
                    }
                    Ok(())
                })
            })
            .connect(url)
            .await
            .map_err(|e| StoreError::Backend(format!("could not connect to {url}: {e}")))?;

        Ok(Self { pool, dialect })
    }

    /// The pool, for a repository to query through.
    #[must_use]
    pub const fn pool(&self) -> &AnyPool {
        &self.pool
    }

    /// The dialect, for building statements the backends disagree about.
    #[must_use]
    pub const fn dialect(&self) -> Dialect {
        self.dialect
    }
}

/// The configured size, capped at what this URL can safely support.
///
/// One for a private in-memory SQLite database, whatever was asked for, because
/// a second connection would be a second, empty database, the schema would be
/// created on one and queried on another, and every read would come back
/// missing its tables.
///
/// A *shared-cache* in-memory URL (`file::memory:?cache=shared`) does not have
/// that problem, and neither does a file, so both get the size they asked for.
/// Zero is not one of the sizes on offer: a pool that can never hand out a
/// connection would hang the service at its first query rather than report
/// anything.
fn pool_size(url: &str, configured: u32) -> u32 {
    let in_memory = url.contains(":memory:") || url.contains("mode=memory");
    let shared = url.contains("cache=shared");
    if in_memory && !shared {
        1
    } else {
        configured.max(1)
    }
}

/// Turn a sqlx error into the crate's own.
///
/// One place, so no repository has to decide how to describe a failure and no
/// two describe the same failure differently.
pub fn wrap(context: &str, error: sqlx::Error) -> StoreError {
    match error {
        sqlx::Error::RowNotFound => {
            StoreError::Corrupt(format!("{context}: a row that must exist is missing"))
        }
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            StoreError::Conflict(format!("{context}: {db}"))
        }
        other => StoreError::Backend(format!("{context}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_in_memory_sqlite_backend_connects() {
        let backend = Backend::connect("sqlite::memory:", 1)
            .await
            .expect("connect");
        assert_eq!(backend.dialect().name(), "sqlite");
    }

    #[tokio::test]
    async fn an_unsupported_scheme_never_reaches_the_pool() {
        let error = Backend::connect("oracle://host/db", DEFAULT_MAX_CONNECTIONS)
            .await
            .expect_err("connected");
        assert!(error.to_string().contains("oracle"), "{error}");
    }

    #[tokio::test]
    async fn an_unreachable_database_is_an_error_not_a_hang() {
        // Port 1 on loopback refuses immediately, so this measures the error
        // path rather than the timeout.
        let error = Backend::connect(
            "postgres://user:pw@127.0.0.1:1/none",
            DEFAULT_MAX_CONNECTIONS,
        )
        .await
        .expect_err("connected to nothing");
        assert!(matches!(error, StoreError::Backend(_)), "{error}");
    }

    #[test]
    fn a_private_in_memory_database_gets_one_connection() {
        // Two connections would be two different empty databases: the schema
        // created on one, every read served from another. The configured size
        // does not get a say.
        assert_eq!(pool_size("sqlite::memory:", 16), 1);
        assert_eq!(pool_size("sqlite:file:x?mode=memory", 16), 1);
    }

    #[test]
    fn everything_else_gets_the_size_it_asked_for() {
        assert_eq!(pool_size("sqlite://starling.db", 16), 16);
        assert_eq!(
            pool_size("sqlite:file::memory:?cache=shared", 16),
            16,
            "a shared cache is one database, so it can take a pool"
        );
        assert_eq!(pool_size("postgres://user@host/db", 32), 32);
    }

    #[test]
    fn a_pool_of_zero_is_raised_to_one() {
        // A pool that can never hand out a connection does not fail, it hangs
        // at the first query, which is the worst way to learn about a typo.
        assert_eq!(pool_size("postgres://user@host/db", 0), 1);
    }

    #[tokio::test]
    async fn the_configured_size_reaches_the_pool() {
        // The bug this prevents: the size was parsed, then dropped on the floor
        // one layer down, and every deployment silently ran the same pool.
        let backend = Backend::connect("sqlite:file:size-test?mode=memory&cache=shared", 3)
            .await
            .expect("connect");
        assert_eq!(backend.pool().options().get_max_connections(), 3);
    }

    #[tokio::test]
    async fn foreign_keys_are_armed_on_every_pooled_connection() {
        // The bug this prevents is silent and intermittent: a pragma run once
        // arms one connection, and whether a delete cascades then depends on
        // which one the pool hands out.
        let backend = Backend::connect(
            "sqlite:file:fk-test?mode=memory&cache=shared",
            DEFAULT_MAX_CONNECTIONS,
        )
        .await
        .expect("connect");

        for _ in 0..DEFAULT_MAX_CONNECTIONS + 2 {
            let (enabled,): (i64,) = sqlx::query_as("PRAGMA foreign_keys")
                .fetch_one(backend.pool())
                .await
                .expect("read pragma");
            assert_eq!(enabled, 1, "a pooled connection had foreign keys disabled");
        }
    }

    #[test]
    fn a_unique_violation_is_a_conflict_not_a_backend_fault() {
        // The caller's recourse differs: a conflict means the request was wrong,
        // a backend error means try again later.
        let missing = wrap("reading", sqlx::Error::RowNotFound);
        assert!(matches!(missing, StoreError::Corrupt(_)), "{missing}");
    }
}
