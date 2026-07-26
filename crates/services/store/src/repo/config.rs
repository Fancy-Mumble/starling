//! Per-server configuration held in the database.

use async_trait::async_trait;
use sqlx::Row;
use starling_api::{ConfigRepository, StoreError};

use crate::backend::{Backend, wrap};
use crate::repo::{Scoped, cell};

/// Configuration persistence for one virtual server.
#[derive(Debug)]
pub(crate) struct Config(Scoped);

impl Config {
    /// Bind to a backend and a virtual server.
    #[must_use]
    pub(crate) fn new(backend: Backend, server_id: i64) -> Self {
        Self(Scoped::new(backend, server_id))
    }
}

#[async_trait]
impl ConfigRepository for Config {
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let sql = self
            .0
            .sql("SELECT value FROM config WHERE server_id = {1} AND \"key\" = {2}");
        let row = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(key)
            .fetch_optional(self.0.pool())
            .await
            .map_err(|e| wrap("reading a setting", e))?;

        row.map(|row| row.try_get("value").map_err(|e| cell(&e)))
            .transpose()
    }

    async fn all(&self) -> Result<Vec<(String, String)>, StoreError> {
        let sql = self
            .0
            .sql("SELECT \"key\", value FROM config WHERE server_id = {1} ORDER BY \"key\"");
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading settings", e))?;

        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("key").map_err(|e| cell(&e))?,
                    row.try_get("value").map_err(|e| cell(&e))?,
                ))
            })
            .collect()
    }

    async fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let sql = self.0.upsert(
            "INSERT INTO config (server_id, \"key\", value) VALUES ({1}, {2}, {3})",
            &["server_id", "key"],
            &["value"],
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(key)
            .bind(value)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("setting a value", e))?;
        Ok(())
    }

    async fn clear(&self, key: &str) -> Result<(), StoreError> {
        let sql = self
            .0
            .sql("DELETE FROM config WHERE server_id = {1} AND \"key\" = {2}");
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(key)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("clearing a setting", e))?;
        Ok(())
    }
}
