//! `starling-store` — persistence.
//!
//! Implements `starling-api`'s repository traits over sqlx, against SQLite,
//! MySQL or PostgreSQL, chosen from a connection URL at run time. Nothing above
//! this crate names sqlx and nothing below it knows persistence exists.
//!
//! # The pieces
//!
//! | | |
//! |---|---|
//! | [`backend`] | the connection pool |
//! | [`dialect`] | what the three backends' SQL disagrees about, one impl each |
//! | [`schema`] | the tables, their constraints, and the migration that creates them |
//! | [`SqlStore`] | the facade — one repository per aggregate |
//! | [`StoreService`] | the bus participant: a reactor loop on `Lane::Io` |
//!
//! # Getting one
//!
//! ```no_run
//! # async fn example() -> Result<(), starling_api::StoreError> {
//! use starling_store::SqlStore;
//!
//! let store = SqlStore::open("sqlite://starling.db", 1).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The second argument is the virtual server id. Every table carries one, and a
//! store is scoped to a single value of it — so multiple virtual servers (P2)
//! means several stores rather than a parameter on every call that one call site
//! could forget.

mod backend;
pub mod dialect;
mod repo;
mod round_trip;
pub mod schema;
mod service;

pub use backend::Backend;
pub use service::StoreService;
pub use dialect::{Dialect, SqlDialect};

use starling_api::{
    AclRepository, BanRepository, ChannelRepository, ConfigRepository, LogRepository, Store,
    StoreError,
};

use repo::{Acls, Bans, Channels, Config, Log, Users};

/// A [`Store`] backed by SQL.
///
/// Holds one repository per aggregate, each sharing the same pool. They are
/// built once at open rather than per call because a repository is a pool handle
/// and a dialect — nothing worth reconstructing, and constructing it per call
/// would put an allocation on every read.
#[derive(Debug)]
pub struct SqlStore {
    backend: Backend,
    channels: Channels,
    users: Users,
    acls: Acls,
    bans: Bans,
    config: Config,
    log: Log,
}

impl SqlStore {
    /// Connect, create the schema if it is absent, and check its version.
    ///
    /// `server_id` scopes every query this store makes. It is not validated
    /// against a list of known servers: creating a virtual server *is* writing
    /// rows with a new id, so requiring it to exist first would be circular.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the URL names an unsupported backend, the database
    /// cannot be reached, the schema cannot be created, or the database was
    /// written by a newer Starling.
    pub async fn open(url: &str, server_id: i64) -> Result<Self, StoreError> {
        let backend = Backend::connect(url).await?;
        schema::migrate(&backend).await?;
        Ok(Self::with_backend(backend, server_id))
    }

    /// Build the repositories over an already-migrated backend.
    ///
    /// Separate from [`Self::open`] so a test can hand in an in-memory database
    /// it set up itself, and so `starling-migrate` can reuse the same
    /// repositories against a connection it already holds.
    #[must_use]
    pub fn with_backend(backend: Backend, server_id: i64) -> Self {
        Self {
            channels: Channels::new(backend.clone(), server_id),
            users: Users::new(backend.clone(), server_id),
            acls: Acls::new(backend.clone(), server_id),
            bans: Bans::new(backend.clone(), server_id),
            config: Config::new(backend.clone(), server_id),
            log: Log::new(backend.clone(), server_id),
            backend,
        }
    }

    /// The pool, for a migration tool that needs to go outside the repositories.
    #[must_use]
    pub const fn backend(&self) -> &Backend {
        &self.backend
    }
}

impl Store for SqlStore {
    fn backend(&self) -> &'static str {
        self.backend.dialect().name()
    }

    fn channels(&self) -> &dyn ChannelRepository {
        &self.channels
    }

    fn users(&self) -> &dyn starling_api::UserRepository {
        &self.users
    }

    fn acls(&self) -> &dyn AclRepository {
        &self.acls
    }

    fn bans(&self) -> &dyn BanRepository {
        &self.bans
    }

    fn config(&self) -> &dyn ConfigRepository {
        &self.config
    }

    fn log(&self) -> &dyn LogRepository {
        &self.log
    }
}

/// A store that persists nothing (Null Object).
///
/// What a server configured without a database gets: every write succeeds and
/// every read comes back empty, so the control paths work and nothing survives a
/// restart. That is a legitimate way to run — murmur's in-memory mode is the
/// same — and it keeps `Option<Box<dyn Store>>` out of every consumer.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStore;

impl Store for NoStore {
    fn backend(&self) -> &'static str {
        "none"
    }

    fn channels(&self) -> &dyn ChannelRepository {
        &repo::Nothing
    }

    fn users(&self) -> &dyn starling_api::UserRepository {
        &repo::Nothing
    }

    fn acls(&self) -> &dyn AclRepository {
        &repo::Nothing
    }

    fn bans(&self) -> &dyn BanRepository {
        &repo::Nothing
    }

    fn config(&self) -> &dyn ConfigRepository {
        &repo::Nothing
    }

    fn log(&self) -> &dyn LogRepository {
        &repo::Nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_in_memory_store_opens_and_names_its_backend() {
        let store = SqlStore::open("sqlite::memory:", 1).await.expect("open");
        assert_eq!(Store::backend(&store), "sqlite");
    }

    #[tokio::test]
    async fn opening_an_unsupported_backend_is_an_error() {
        assert!(SqlStore::open("oracle://host/db", 1).await.is_err());
    }

    #[tokio::test]
    async fn the_null_store_reads_empty_and_writes_nowhere() {
        // A legitimate configuration, not a failure mode: every control path
        // works and nothing survives a restart.
        let store = NoStore;
        assert_eq!(Store::backend(&store), "none");
        assert!(store.channels().all().await.expect("read").is_empty());
        assert!(store.users().all().await.expect("read").is_empty());
        assert!(store.bans().all().await.expect("read").is_empty());
        assert!(store.config().all().await.expect("read").is_empty());

        store
            .config()
            .set("key", "value")
            .await
            .expect("a write to nowhere must succeed");
        assert_eq!(store.config().get("key").await.expect("read"), None);
    }
}
