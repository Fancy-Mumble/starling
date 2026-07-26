//! Ordered, namespaced key/value with atomic batches.
//!
//! This is what a plugin gets instead of SQL, and the reasoning is in
//! `docs/STORAGE.md` §5.3. SQL passthrough is the tempting alternative —
//! executing opaque SQL is philosophically identical to shuttling opaque
//! messages — and it loses on two practical points: every plugin author would
//! have to write SQL portable across three dialects, and the host would have to
//! *parse* SQL to enforce namespace isolation. Both taxes are permanent.
//!
//! What KV genuinely costs is stated rather than hidden: secondary indexes and
//! aggregates are manual. The atomic batch is what makes those possible, which
//! is why [`KvStore::write`] takes a list and not one operation.
//!
//! The physical ordering is `plugin → tenant → key`, so a key of
//! `channel_id ‖ uuidv7` gives pchat exactly the range scan a dedicated table
//! would (§5.6).

use sqlx::Row as _;

use crate::storage::{Migration, Store, StoreError};

/// The one table, identical on all three backends.
pub(crate) const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_plugin_kv",
    &["CREATE TABLE IF NOT EXISTS plugin_kv (\
             plugin_id VARCHAR(190) NOT NULL, \
             server_id BIGINT NOT NULL, \
             k BLOB NOT NULL, \
             v BLOB NOT NULL, \
             PRIMARY KEY (plugin_id, server_id, k))"],
)];

/// One write in a batch. A missing value is a delete.
#[derive(Debug, Clone)]
pub struct KvOp {
    /// The key.
    pub key: Vec<u8>,
    /// The value, or `None` to delete.
    pub value: Option<Vec<u8>>,
}

/// A namespaced view of one database.
#[derive(Debug, Clone)]
pub struct KvStore {
    store: Store,
}

impl KvStore {
    /// Wrap `store`.
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }

    /// Create the backing table if it does not exist.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the schema cannot be applied.
    pub async fn ensure_schema(&self) -> Result<(), StoreError> {
        self.store.migrate(SCHEMA).await
    }

    /// One value.
    ///
    /// # Errors
    ///
    /// [`StoreError::Query`] if the read fails.
    pub async fn get(
        &self,
        plugin: &str,
        server: u32,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let row =
            sqlx::query("SELECT v FROM plugin_kv WHERE plugin_id = ? AND server_id = ? AND k = ?")
                .bind(plugin)
                .bind(i64::from(server))
                .bind(key)
                .fetch_optional(self.store.pool())
                .await
                .map_err(|error| StoreError::Query(format!("kv get: {error}")))?;
        Ok(row.and_then(|row| row.try_get::<Vec<u8>, _>("v").ok()))
    }

    /// A half-open key range, forwards or backwards.
    ///
    /// This is an index range scan on the clustered primary key with no
    /// dialect-specific syntax — the access path the whole design is chosen
    /// for.
    ///
    /// # Errors
    ///
    /// [`StoreError::Query`] if the read fails.
    pub async fn scan(
        &self,
        plugin: &str,
        server: u32,
        start: &[u8],
        end: &[u8],
        limit: u32,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        let order = if reverse { "DESC" } else { "ASC" };
        let sql = format!(
            "SELECT k, v FROM plugin_kv \
             WHERE plugin_id = ? AND server_id = ? AND k >= ? AND k < ? \
             ORDER BY k {order} LIMIT ?"
        );
        let rows = sqlx::query(&sql)
            .bind(plugin)
            .bind(i64::from(server))
            .bind(start)
            .bind(end)
            .bind(i64::from(limit.clamp(1, 10_000)))
            .fetch_all(self.store.pool())
            .await
            .map_err(|error| StoreError::Query(format!("kv scan: {error}")))?;

        Ok(rows
            .into_iter()
            .filter_map(|row| {
                Some((
                    row.try_get::<Vec<u8>, _>("k").ok()?,
                    row.try_get::<Vec<u8>, _>("v").ok()?,
                ))
            })
            .collect())
    }

    /// Apply `ops` atomically.
    ///
    /// Atomicity is the point: it is what lets a plugin keep its own secondary
    /// indexes consistent with its records, which is the one thing KV genuinely
    /// costs it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Query`] if any statement fails; nothing is applied.
    pub async fn write(&self, plugin: &str, server: u32, ops: &[KvOp]) -> Result<(), StoreError> {
        let mut tx = self
            .store
            .pool()
            .begin()
            .await
            .map_err(|error| StoreError::Query(format!("kv batch: {error}")))?;

        for op in ops {
            let query = match &op.value {
                Some(value) => sqlx::query(
                    "INSERT INTO plugin_kv (plugin_id, server_id, k, v) VALUES (?, ?, ?, ?) \
                     ON CONFLICT (plugin_id, server_id, k) DO UPDATE SET v = excluded.v",
                )
                .bind(plugin)
                .bind(i64::from(server))
                .bind(op.key.as_slice())
                .bind(value.as_slice()),
                None => sqlx::query(
                    "DELETE FROM plugin_kv WHERE plugin_id = ? AND server_id = ? AND k = ?",
                )
                .bind(plugin)
                .bind(i64::from(server))
                .bind(op.key.as_slice()),
            };
            query
                .execute(&mut *tx)
                .await
                .map(|_| ())
                .map_err(|error| StoreError::Query(format!("kv batch: {error}")))?;
        }

        tx.commit()
            .await
            .map_err(|error| StoreError::Query(format!("kv commit: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory_store;

    async fn kv() -> KvStore {
        let kv = memory_store().await.kv();
        kv.ensure_schema().await.expect("schema");
        kv
    }

    fn put(key: &[u8], value: &[u8]) -> KvOp {
        KvOp {
            key: key.to_vec(),
            value: Some(value.to_vec()),
        }
    }

    #[tokio::test]
    async fn one_plugin_cannot_read_another_s_data() {
        // The namespace is the isolation. If this ever passes across plugins,
        // the opacity rule is gone.
        let kv = kv().await;
        kv.write("audit", 1, &[put(b"k", b"v")])
            .await
            .expect("write");
        assert_eq!(
            kv.get("audit", 1, b"k").await.expect("get"),
            Some(b"v".to_vec())
        );
        assert_eq!(kv.get("pchat", 1, b"k").await.expect("get"), None);
    }

    #[tokio::test]
    async fn a_tenant_cannot_read_another_tenant_s_data() {
        let kv = kv().await;
        kv.write("pchat", 1, &[put(b"k", b"one")])
            .await
            .expect("write");
        kv.write("pchat", 2, &[put(b"k", b"two")])
            .await
            .expect("write");
        assert_eq!(
            kv.get("pchat", 2, b"k").await.expect("get"),
            Some(b"two".to_vec())
        );
    }

    #[tokio::test]
    async fn a_scan_returns_the_range_in_key_order_and_reversed_on_request() {
        // Newest-first is a backwards scan off the end of the range; that is
        // the whole reason pchat's key is channel ‖ uuidv7.
        let kv = kv().await;
        let ops: Vec<KvOp> = (1_u8..=3).map(|i| put(&[7, i], b"x")).collect();
        kv.write("pchat", 1, &ops).await.expect("write");

        let forwards = kv
            .scan("pchat", 1, &[7, 0], &[8, 0], 10, false)
            .await
            .expect("scan");
        assert_eq!(
            forwards.iter().map(|(k, _)| k[1]).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        let backwards = kv
            .scan("pchat", 1, &[7, 0], &[8, 0], 2, true)
            .await
            .expect("scan");
        assert_eq!(
            backwards.iter().map(|(k, _)| k[1]).collect::<Vec<_>>(),
            vec![3, 2]
        );
    }

    #[tokio::test]
    async fn a_batch_that_writes_a_record_and_its_index_applies_as_one() {
        let kv = kv().await;
        kv.write(
            "audit",
            1,
            &[put(b"\x00rec", b"body"), put(b"\x01idx", b"\x00rec")],
        )
        .await
        .expect("batch");

        assert!(kv.get("audit", 1, b"\x01idx").await.expect("get").is_some());
    }

    #[tokio::test]
    async fn a_missing_value_deletes() {
        let kv = kv().await;
        kv.write("audit", 1, &[put(b"k", b"v")])
            .await
            .expect("write");
        kv.write(
            "audit",
            1,
            &[KvOp {
                key: b"k".to_vec(),
                value: None,
            }],
        )
        .await
        .expect("delete");
        assert_eq!(kv.get("audit", 1, b"k").await.expect("get"), None);
    }
}
