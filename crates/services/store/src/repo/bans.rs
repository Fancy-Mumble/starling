//! Bans.

use async_trait::async_trait;
use sqlx::Row;
use starling_api::{BanRepository, StoreError, StoredBan};

use crate::backend::{Backend, wrap};
use crate::repo::{Scoped, cell};

/// Ban persistence for one virtual server.
#[derive(Debug)]
pub(crate) struct Bans(Scoped);

impl Bans {
    /// Bind to a backend and a virtual server.
    #[must_use]
    pub(crate) fn new(backend: Backend, server_id: i64) -> Self {
        Self(Scoped::new(backend, server_id))
    }
}

#[async_trait]
impl BanRepository for Bans {
    async fn all(&self) -> Result<Vec<StoredBan>, StoreError> {
        let sql = self.0.sql(
            "SELECT address, prefix_length, name, cert_hash, reason, start_at, expires_at
             FROM bans WHERE server_id = {1} ORDER BY ban_id",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading bans", e))?;

        rows.iter()
            .map(|row| {
                Ok(StoredBan {
                    address: row.try_get("address").map_err(|e| cell(&e))?,
                    prefix_length: i32::try_from(
                        row.try_get::<i64, _>("prefix_length")
                            .map_err(|e| cell(&e))?,
                    )
                    .unwrap_or(0),
                    name: row.try_get("name").map_err(|e| cell(&e))?,
                    cert_hash: row.try_get("cert_hash").map_err(|e| cell(&e))?,
                    reason: row.try_get("reason").map_err(|e| cell(&e))?,
                    start: row.try_get("start_at").map_err(|e| cell(&e))?,
                    // NULL is a permanent ban, not a missing value.
                    expires_at: row.try_get("expires_at").map_err(|e| cell(&e))?,
                })
            })
            .collect()
    }

    async fn replace_all(&self, bans: &[StoredBan]) -> Result<(), StoreError> {
        // In one transaction: a half-applied ban list is not a partial answer,
        // it is a list that lets in people the operator just banned.
        let mut tx = self
            .0
            .pool()
            .begin()
            .await
            .map_err(|e| wrap("beginning a ban replacement", e))?;

        let _ = sqlx::query(&self.0.sql("DELETE FROM bans WHERE server_id = {1}"))
            .bind(self.0.server_id())
            .execute(&mut *tx)
            .await
            .map_err(|e| wrap("clearing bans", e))?;

        let insert = self.0.sql(
            "INSERT INTO bans
                (server_id, address, prefix_length, name, cert_hash, reason, start_at, expires_at)
             VALUES ({1}, {2}, {3}, {4}, {5}, {6}, {7}, {8})",
        );
        for ban in bans {
            let _ = sqlx::query(&insert)
                .bind(self.0.server_id())
                .bind(&ban.address)
                .bind(i64::from(ban.prefix_length))
                .bind(ban.name.as_deref())
                .bind(ban.cert_hash.as_deref())
                .bind(ban.reason.as_deref())
                .bind(ban.start)
                .bind(ban.expires_at)
                .execute(&mut *tx)
                .await
                .map_err(|e| wrap("inserting a ban", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| wrap("committing a ban replacement", e))
    }

    async fn prune_expired(&self, now: i64) -> Result<u64, StoreError> {
        // `IS NOT NULL` first: a permanent ban has no expiry and must survive
        // every prune. Comparing against NULL yields NULL rather than false,
        // which is not a distinction to leave to a reader of the query.
        let sql = self.0.sql(
            "DELETE FROM bans
             WHERE server_id = {1} AND expires_at IS NOT NULL AND expires_at <= {2}",
        );
        let result = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(now)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("pruning expired bans", e))?;
        Ok(result.rows_affected())
    }
}
