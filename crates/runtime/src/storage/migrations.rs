//! The migration chain: additive only, recorded by name.
//!
//! **Additive only** is a rollback rule, not a style: a service that drops a
//! column cannot be rolled back to the binary that reads it, and rollback is
//! the only thing that makes replacing a live server safe (`PORTING-PLAN.md`
//! §3).
//!
//! Recording by *name* rather than by number means two services can grow their
//! own schemas independently, which they must, because each owns its own.

use crate::storage::{Store, StoreError};

/// One step of a schema.
#[derive(Debug, Clone, Copy)]
pub struct Migration<'a> {
    /// A stable name, recorded once applied. Renaming one re-runs it.
    pub name: &'a str,
    /// The statements, in order. Split rather than one blob because several
    /// backends refuse more than one statement per prepare.
    pub statements: &'a [&'a str],
}

impl<'a> Migration<'a> {
    /// A migration called `name`.
    #[must_use]
    pub const fn new(name: &'a str, statements: &'a [&'a str]) -> Self {
        Self { name, statements }
    }
}

/// Apply every migration that has not been recorded yet.
pub(crate) async fn apply(store: &Store, migrations: &[Migration<'_>]) -> Result<(), StoreError> {
    store
        .execute(
            "CREATE TABLE IF NOT EXISTS starling_migration (\
                 name VARCHAR(190) PRIMARY KEY, applied_at_ms BIGINT NOT NULL)",
        )
        .await?;

    let applied = applied_names(store).await?;
    for migration in migrations {
        if applied.iter().any(|name| name == migration.name) {
            continue;
        }
        for statement in migration.statements {
            store.execute(statement).await.map_err(|error| {
                StoreError::Query(format!("migration {}: {error}", migration.name))
            })?;
        }
        record(store, migration.name).await?;
        tracing::info!(migration = migration.name, "schema applied");
    }
    Ok(())
}

async fn applied_names(store: &Store) -> Result<Vec<String>, StoreError> {
    use sqlx::Row as _;
    let rows = sqlx::query("SELECT name FROM starling_migration")
        .fetch_all(store.pool())
        .await
        .map_err(|error| StoreError::Query(format!("reading applied migrations: {error}")))?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.try_get::<String, _>("name").ok())
        .collect())
}

async fn record(store: &Store, name: &str) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO starling_migration (name, applied_at_ms) VALUES (?, ?)")
        .bind(name)
        .bind(crate::ids::now_ms() as i64)
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(|error| StoreError::Query(format!("recording migration {name}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory_store;

    const SCHEMA: &[Migration<'static>] = &[Migration::new(
        "0001_example",
        &["CREATE TABLE example (id BIGINT PRIMARY KEY, name VARCHAR(64) NOT NULL)"],
    )];

    #[tokio::test]
    async fn applying_twice_does_not_re_run_a_migration() {
        // Re-running a CREATE TABLE would fail, so a service that restarts
        // would never come back up.
        let store = memory_store().await;
        store.migrate(SCHEMA).await.expect("first apply");
        store
            .migrate(SCHEMA)
            .await
            .expect("second apply is a no-op");

        let applied = applied_names(&store).await.expect("read back");
        assert_eq!(applied, vec!["0001_example".to_owned()]);
    }

    #[tokio::test]
    async fn a_failing_statement_names_the_migration_it_came_from() {
        let store = memory_store().await;
        let broken: &[Migration<'static>] = &[Migration::new("0001_broken", &["NOT SQL AT ALL"])];
        let err = store.migrate(broken).await.expect_err("garbage must fail");
        assert!(err.to_string().contains("0001_broken"));
    }
}
