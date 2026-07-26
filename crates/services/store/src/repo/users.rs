//! Registered accounts and their properties.

use async_trait::async_trait;
use sqlx::Row;
use starling_api::{StoreError, StoredUser, UserRepository};
use starling_model::{ChannelId, UserId};

use crate::backend::{Backend, wrap};
use crate::repo::{Scoped, cell, u32_from};

/// Every column of an account, in one place.
///
/// Written once because it appears in four queries, and four copies of a column
/// list is four chances for one to fall behind a schema change.
const COLUMNS: &str = "user_id, name, password_hash, salt, kdf_iterations, cert_hash,
                       last_channel_id, last_active, last_disconnect";

/// Account persistence for one virtual server.
#[derive(Debug)]
pub(crate) struct Users(Scoped);

impl Users {
    /// Bind to a backend and a virtual server.
    #[must_use]
    pub(crate) fn new(backend: Backend, server_id: i64) -> Self {
        Self(Scoped::new(backend, server_id))
    }

    /// Read one account out of a row.
    fn user(row: &sqlx::any::AnyRow) -> Result<StoredUser, StoreError> {
        Ok(StoredUser {
            id: UserId(u32_from(
                row.try_get::<i64, _>("user_id").map_err(|e| cell(&e))?,
            )?),
            name: row.try_get("name").map_err(|e| cell(&e))?,
            password_hash: row.try_get("password_hash").map_err(|e| cell(&e))?,
            salt: row.try_get("salt").map_err(|e| cell(&e))?,
            kdf_iterations: row.try_get("kdf_iterations").map_err(|e| cell(&e))?,
            cert_hash: row.try_get("cert_hash").map_err(|e| cell(&e))?,
            last_channel: row
                .try_get::<Option<i64>, _>("last_channel_id")
                .map_err(|e| cell(&e))?
                .map(|id| u32_from(id).map(ChannelId))
                .transpose()?,
            last_active: row.try_get("last_active").map_err(|e| cell(&e))?,
            last_disconnect: row.try_get("last_disconnect").map_err(|e| cell(&e))?,
        })
    }

    /// Fetch at most one account matching `predicate`.
    async fn one(&self, predicate: &str, bind: &str) -> Result<Option<StoredUser>, StoreError> {
        let sql = self.0.sql(&format!(
            "SELECT {COLUMNS} FROM users WHERE server_id = {{1}} AND {predicate}"
        ));
        let row = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(bind)
            .fetch_optional(self.0.pool())
            .await
            .map_err(|e| wrap("reading an account", e))?;
        row.as_ref().map(Users::user).transpose()
    }
}

#[async_trait]
impl UserRepository for Users {
    async fn all(&self) -> Result<Vec<StoredUser>, StoreError> {
        let sql = self.0.sql(&format!(
            "SELECT {COLUMNS} FROM users WHERE server_id = {{1}}"
        ));
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading accounts", e))?;
        rows.iter().map(Users::user).collect()
    }

    async fn by_name(&self, name: &str) -> Result<Option<StoredUser>, StoreError> {
        // `=` rather than a case-insensitive comparison: murmur treats `Alice`
        // and `alice` as different registrations, and matching more loosely
        // would let one account authenticate as another.
        self.one("name = {2}", name).await
    }

    async fn by_id(&self, id: UserId) -> Result<Option<StoredUser>, StoreError> {
        let sql = self.0.sql(&format!(
            "SELECT {COLUMNS} FROM users WHERE server_id = {{1}} AND user_id = {{2}}"
        ));
        let row = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(id.0))
            .fetch_optional(self.0.pool())
            .await
            .map_err(|e| wrap("reading an account", e))?;
        row.as_ref().map(Users::user).transpose()
    }

    async fn by_cert_hash(&self, hash: &str) -> Result<Option<StoredUser>, StoreError> {
        self.one("cert_hash = {2}", hash).await
    }

    async fn save(&self, user: &StoredUser) -> Result<(), StoreError> {
        let sql = self.0.upsert(
            "INSERT INTO users
                (server_id, user_id, name, password_hash, salt, kdf_iterations, cert_hash,
                 last_channel_id, last_active, last_disconnect)
             VALUES ({1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10})",
            &["server_id", "user_id"],
            &[
                "name",
                "password_hash",
                "salt",
                "kdf_iterations",
                "cert_hash",
                "last_channel_id",
                "last_active",
                "last_disconnect",
            ],
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(user.id.0))
            .bind(&user.name)
            .bind(user.password_hash.as_deref())
            .bind(user.salt.as_deref())
            .bind(user.kdf_iterations)
            .bind(user.cert_hash.as_deref())
            .bind(user.last_channel.map(|c| i64::from(c.0)))
            .bind(user.last_active)
            .bind(user.last_disconnect)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("saving an account", e))?;
        Ok(())
    }

    async fn remove(&self, id: UserId) -> Result<(), StoreError> {
        // Properties, memberships and listener rows go with it by cascade.
        let sql = self
            .0
            .sql("DELETE FROM users WHERE server_id = {1} AND user_id = {2}");
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(id.0))
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("removing an account", e))?;
        Ok(())
    }

    async fn next_id(&self) -> Result<UserId, StoreError> {
        // `MAX + 1` rather than a sequence, because ids must be reusable after a
        // deletion the way murmur's are, and because SuperUser is fixed at 0 and
        // must not be handed out again.
        let sql = self
            .0
            .sql("SELECT COALESCE(MAX(user_id), 0) AS highest FROM users WHERE server_id = {1}");
        let row = sqlx::query(&sql)
            .bind(self.0.server_id())
            .fetch_one(self.0.pool())
            .await
            .map_err(|e| wrap("allocating an account id", e))?;

        let highest = row.try_get::<i64, _>("highest").map_err(|e| cell(&e))?;
        u32_from(highest + 1).map(UserId)
    }

    async fn properties(&self, id: UserId) -> Result<Vec<(String, String)>, StoreError> {
        let sql = self.0.sql(
            "SELECT \"key\", value FROM user_properties WHERE server_id = {1} AND user_id = {2}",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(id.0))
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading account properties", e))?;

        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("key").map_err(|e| cell(&e))?,
                    row.try_get("value").map_err(|e| cell(&e))?,
                ))
            })
            .collect()
    }

    async fn set_property(&self, id: UserId, key: &str, value: &str) -> Result<(), StoreError> {
        let sql = self.0.upsert(
            "INSERT INTO user_properties (server_id, user_id, \"key\", value)
             VALUES ({1}, {2}, {3}, {4})",
            &["server_id", "user_id", "key"],
            &["value"],
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(id.0))
            .bind(key)
            .bind(value)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("setting an account property", e))?;
        Ok(())
    }
}
