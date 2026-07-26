//! The persisted operator-facing server log.

use async_trait::async_trait;
use sqlx::Row;
use starling_api::{LogRepository, StoreError};

use crate::backend::{Backend, wrap};
use crate::repo::{Scoped, cell};

/// Log persistence for one virtual server.
#[derive(Debug)]
pub(crate) struct Log(Scoped);

impl Log {
    /// Bind to a backend and a virtual server.
    #[must_use]
    pub(crate) fn new(backend: Backend, server_id: i64) -> Self {
        Self(Scoped::new(backend, server_id))
    }
}

#[async_trait]
impl LogRepository for Log {
    async fn append(&self, at: i64, message: &str) -> Result<(), StoreError> {
        let sql = self
            .0
            .sql("INSERT INTO server_log (server_id, logged_at, message) VALUES ({1}, {2}, {3})");
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(at)
            .bind(message)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("appending to the server log", e))?;
        Ok(())
    }

    async fn recent(&self, limit: u32) -> Result<Vec<(i64, String)>, StoreError> {
        // `log_id` breaks ties: several entries can share a second, and without
        // it their order is whatever the backend returns — so paging through the
        // log could show one entry twice and skip another.
        let sql = self.0.sql(
            "SELECT logged_at, message FROM server_log
             WHERE server_id = {1} ORDER BY logged_at DESC, log_id DESC LIMIT {2}",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(limit))
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading the server log", e))?;

        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("logged_at").map_err(|e| cell(&e))?,
                    row.try_get("message").map_err(|e| cell(&e))?,
                ))
            })
            .collect()
    }

    async fn prune(&self, before: i64) -> Result<u64, StoreError> {
        let sql = self
            .0
            .sql("DELETE FROM server_log WHERE server_id = {1} AND logged_at < {2}");
        let result = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(before)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("pruning the server log", e))?;
        Ok(result.rows_affected())
    }
}
