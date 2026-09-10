//! The per-account record store: one opaque value under one name.
//!
//! What a client keeps on the server about itself and nobody else - a document
//! library, a citation list, a calendar. `docs/STORAGE-UNIFICATION.md` D4: the
//! *record* half of the two primitives, where `files` is the *object* half.
//!
//! Three things separate this from the settings map beside it:
//!
//! * **One key at a time.** `Settings` is answered whole, so a library living
//!   in it would ride every preference toggle. These are read and written by
//!   name.
//! * **Bytes, not strings.** The callers store JSON today and are welcome to
//!   store anything tomorrow; the server never looks inside.
//! * **Actually persisted.** `account_setting` has existed since the first
//!   migration and nothing has ever written a row to it, so account settings
//!   do not survive a restart. A store whose whole purpose is outliving the
//!   connection cannot be built the same way, so every write here is a row.
//!
//! Not cached. Authentication is the one read that cannot wait
//! (`docs/STORAGE.md` D1) and this is not it: a record is read when a client
//! asks for one, on the service's own task, off every hot path.

use starling_runtime::ids::now_ms;
use starling_runtime::storage::{Migration, Store, StoreError};

/// The largest record this server will store.
///
/// 64 KiB because that is what a `TEXT`/`BLOB` column holds on MySQL, and the
/// portable-SQL rule (`docs/STORAGE.md` D3) rules out the `MEDIUMBLOB` that
/// would lift it. The file-server plugin this replaces allowed 1 MiB, so the
/// ceiling is lower - but its own callers are a document index, a source list
/// and a calendar, none of which approach either number, and a refusal that
/// names the limit is better than a column that truncates silently.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// The longest key. `VARCHAR(190)` in the schema, and the same everywhere in
/// this tree: 190 is what a utf8mb4 index allows on MySQL.
pub const MAX_KEY_LEN: usize = 190;

/// The schema. Additive, and independent of `account`'s own chain.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_account_record",
    &["CREATE TABLE IF NOT EXISTS account_record (\
             server_id BIGINT NOT NULL, account_id BIGINT NOT NULL, \
             k VARCHAR(190) NOT NULL, v BLOB NOT NULL, \
             updated_at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, account_id, k))"],
)];

/// One stored record.
#[derive(Debug, Clone)]
pub struct Stored {
    /// The bytes, as they were written.
    pub value: Vec<u8>,
    /// When they were last written.
    pub updated_at_ms: u64,
}

/// Why a record operation could not be carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The key was empty or longer than [`MAX_KEY_LEN`].
    BadKey,
    /// The value was larger than [`MAX_RECORD_BYTES`].
    TooLarge,
    /// The database refused it. The caller logs; the client is told the
    /// operation did not happen rather than what the disk is doing.
    Storage,
}

/// The store.
#[derive(Debug, Clone)]
pub struct Records {
    store: Store,
}

impl Records {
    /// Open the record store, applying its schema.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the schema cannot be applied.
    pub async fn open(store: Store) -> Result<Self, StoreError> {
        store.migrate(SCHEMA).await?;
        Ok(Self { store })
    }

    /// One record, or `None` when there is not one.
    pub async fn get(&self, scope: u32, account: u64, key: &str) -> Option<Stored> {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT v, updated_at_ms FROM account_record \
             WHERE server_id = ? AND account_id = ? AND k = ?",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .bind(key)
        .fetch_optional(self.store.pool())
        .await
        .inspect_err(|error| tracing::warn!(%error, "could not read a record"))
        .ok()
        .flatten()?;
        Some(Stored {
            value: row.try_get::<Vec<u8>, _>("v").ok()?,
            updated_at_ms: row
                .try_get::<i64, _>("updated_at_ms")
                .unwrap_or_default()
                .max(0) as u64,
        })
    }

    /// Every key under `prefix`, in order. An empty prefix lists all of them.
    ///
    /// A range scan on the primary key rather than a `LIKE`: the key is the
    /// third column of `(server_id, account_id, k)`, so a prefix is a
    /// contiguous run and the index walks exactly it.
    pub async fn list(&self, scope: u32, account: u64, prefix: &str) -> Vec<String> {
        use sqlx::Row as _;
        // The successor of the prefix, so `>= prefix AND < end` is the run.
        // A prefix whose last byte is 0xFF has no successor expressible this
        // way, so those fall back to listing from the prefix onwards and
        // filtering, which is correct and rare enough not to optimise.
        let end = successor(prefix);
        let rows = match end {
            Some(ref end) => {
                sqlx::query(
                    "SELECT k FROM account_record \
                     WHERE server_id = ? AND account_id = ? AND k >= ? AND k < ? ORDER BY k",
                )
                .bind(i64::from(scope))
                .bind(account as i64)
                .bind(prefix)
                .bind(end)
                .fetch_all(self.store.pool())
                .await
            }
            None => {
                sqlx::query(
                    "SELECT k FROM account_record \
                     WHERE server_id = ? AND account_id = ? AND k >= ? ORDER BY k",
                )
                .bind(i64::from(scope))
                .bind(account as i64)
                .bind(prefix)
                .fetch_all(self.store.pool())
                .await
            }
        };
        match rows {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|row| row.try_get::<String, _>("k").ok())
                .filter(|key| key.starts_with(prefix))
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "could not list records");
                Vec::new()
            }
        }
    }

    /// Store one record, replacing whatever was under the key.
    ///
    /// Returns when it was written, so the answer carries the same timestamp a
    /// later read would.
    ///
    /// # Errors
    ///
    /// [`Denied`] when the key or the value is outside what this store takes,
    /// checked before the database is touched.
    pub async fn put(
        &self,
        scope: u32,
        account: u64,
        key: &str,
        value: &[u8],
    ) -> Result<u64, Denied> {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(Denied::BadKey);
        }
        if value.len() > MAX_RECORD_BYTES {
            return Err(Denied::TooLarge);
        }
        let now = now_ms();
        let _ = sqlx::query(
            "INSERT INTO account_record (server_id, account_id, k, v, updated_at_ms) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, account_id, k) DO UPDATE SET \
                 v = excluded.v, updated_at_ms = excluded.updated_at_ms",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .bind(key)
        .bind(value)
        .bind(now as i64)
        .execute(self.store.pool())
        .await
        .map_err(|error| {
            tracing::warn!(%error, "could not store a record");
            Denied::Storage
        })?;
        Ok(now)
    }

    /// Remove one record. Removing one that is not there is not an error.
    pub async fn remove(&self, scope: u32, account: u64, key: &str) {
        let _ = sqlx::query(
            "DELETE FROM account_record WHERE server_id = ? AND account_id = ? AND k = ?",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .bind(key)
        .execute(self.store.pool())
        .await
        .inspect_err(|error| tracing::warn!(%error, "could not remove a record"));
    }

    /// Every account that has stored anything, in order.
    ///
    /// For a verification pass that has to walk the store without a list of
    /// accounts to walk it with. Not a per-user read, so not part of what a
    /// client can ask for.
    pub async fn accounts(&self, scope: u32) -> Vec<u64> {
        use sqlx::Row as _;
        sqlx::query(
            "SELECT DISTINCT account_id FROM account_record WHERE server_id = ? \
             ORDER BY account_id",
        )
        .bind(i64::from(scope))
        .fetch_all(self.store.pool())
        .await
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.try_get::<i64, _>("account_id").ok())
                .map(|account| account.max(0) as u64)
                .collect()
        })
        .unwrap_or_default()
    }

    /// Drop everything one account stored.
    ///
    /// For UNREGISTER: the account is going, and its records are its own. A
    /// library left behind would be handed to whoever is assigned the id next.
    pub async fn forget_account(&self, scope: u32, account: u64) {
        let _ = sqlx::query("DELETE FROM account_record WHERE server_id = ? AND account_id = ?")
            .bind(i64::from(scope))
            .bind(account as i64)
            .execute(self.store.pool())
            .await
            .inspect_err(|error| tracing::warn!(%error, "could not forget the records"));
    }
}

/// The least string greater than every string starting with `prefix`.
///
/// `None` when there is not one, which is a prefix of nothing but `0xFF`
/// bytes. Operates on bytes and rebuilds a `String` because the increment can
/// land mid-character; the result is only ever compared, never shown.
fn successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.pop() {
        if last < 0xFF {
            bytes.push(last + 1);
            return String::from_utf8(bytes).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn records() -> Records {
        let store = Store::open("sqlite::memory:", 1).await.expect("a database");
        Records::open(store).await.expect("the schema")
    }

    #[tokio::test]
    async fn a_record_reads_back_as_it_was_written() {
        let records = records().await;
        let _ = records
            .put(1, 7, "livedoc/sidebar", b"{}")
            .await
            .expect("stored");

        let stored = records
            .get(1, 7, "livedoc/sidebar")
            .await
            .expect("a record");
        assert_eq!(stored.value, b"{}");
        assert!(stored.updated_at_ms > 0);
    }

    #[tokio::test]
    async fn a_record_that_was_never_written_is_absent_rather_than_empty() {
        let records = records().await;
        assert!(records.get(1, 7, "nothing").await.is_none());
    }

    #[tokio::test]
    async fn a_second_put_replaces_the_first() {
        let records = records().await;
        let _ = records.put(1, 7, "k", b"one").await.expect("stored");
        let _ = records.put(1, 7, "k", b"two").await.expect("stored");

        assert_eq!(
            records.get(1, 7, "k").await.expect("a record").value,
            b"two"
        );
    }

    #[tokio::test]
    async fn one_account_cannot_see_anothers() {
        let records = records().await;
        let _ = records.put(1, 7, "k", b"mine").await.expect("stored");

        assert!(records.get(1, 8, "k").await.is_none());
        assert!(records.list(1, 8, "").await.is_empty());
    }

    #[tokio::test]
    async fn one_instance_cannot_see_anothers() {
        let records = records().await;
        let _ = records.put(1, 7, "k", b"mine").await.expect("stored");

        assert!(records.get(2, 7, "k").await.is_none());
    }

    #[tokio::test]
    async fn listing_by_prefix_returns_that_run_in_order() {
        let records = records().await;
        for key in ["livedoc/sidebar", "livedoc/sources", "calendar", "lively"] {
            let _ = records.put(1, 7, key, b"x").await.expect("stored");
        }

        assert_eq!(
            records.list(1, 7, "livedoc/").await,
            vec!["livedoc/sidebar".to_owned(), "livedoc/sources".to_owned()],
            "the prefix run, and not the key that merely shares its first letters"
        );
        assert_eq!(
            records.list(1, 7, "").await.len(),
            4,
            "an empty prefix is everything"
        );
    }

    #[tokio::test]
    async fn a_value_past_the_ceiling_is_refused_with_nothing_written() {
        let records = records().await;
        let huge = vec![b'x'; MAX_RECORD_BYTES + 1];

        assert_eq!(records.put(1, 7, "k", &huge).await, Err(Denied::TooLarge));
        assert!(
            records.get(1, 7, "k").await.is_none(),
            "a refused write must not leave a truncated record behind"
        );
    }

    #[tokio::test]
    async fn a_value_at_the_ceiling_is_stored() {
        let records = records().await;
        let big = vec![b'x'; MAX_RECORD_BYTES];

        let _ = records.put(1, 7, "k", &big).await.expect("stored");
        assert_eq!(
            records.get(1, 7, "k").await.expect("a record").value.len(),
            MAX_RECORD_BYTES
        );
    }

    #[tokio::test]
    async fn an_empty_key_is_refused() {
        let records = records().await;
        assert_eq!(records.put(1, 7, "", b"x").await, Err(Denied::BadKey));
    }

    #[tokio::test]
    async fn a_key_past_the_column_is_refused_rather_than_truncated() {
        let records = records().await;
        let long = "k".repeat(MAX_KEY_LEN + 1);
        assert_eq!(records.put(1, 7, &long, b"x").await, Err(Denied::BadKey));
    }

    #[tokio::test]
    async fn an_empty_value_is_stored_and_is_not_a_deletion() {
        let records = records().await;
        let _ = records.put(1, 7, "k", b"").await.expect("stored");

        let stored = records.get(1, 7, "k").await.expect("a record");
        assert!(stored.value.is_empty(), "found, and empty");
    }

    #[tokio::test]
    async fn removing_takes_the_record_and_nothing_else() {
        let records = records().await;
        let _ = records.put(1, 7, "a", b"x").await.expect("stored");
        let _ = records.put(1, 7, "b", b"x").await.expect("stored");

        records.remove(1, 7, "a").await;

        assert!(records.get(1, 7, "a").await.is_none());
        assert!(records.get(1, 7, "b").await.is_some());
    }

    #[tokio::test]
    async fn removing_what_is_not_there_is_not_an_error() {
        let records = records().await;
        records.remove(1, 7, "absent").await;
    }

    #[tokio::test]
    async fn forgetting_an_account_takes_every_record_it_had() {
        let records = records().await;
        let _ = records.put(1, 7, "a", b"x").await.expect("stored");
        let _ = records.put(1, 7, "b", b"x").await.expect("stored");
        let _ = records.put(1, 8, "a", b"theirs").await.expect("stored");

        records.forget_account(1, 7).await;

        assert!(records.list(1, 7, "").await.is_empty());
        assert!(
            records.get(1, 8, "a").await.is_some(),
            "another account's records are not this one's to drop"
        );
    }

    #[tokio::test]
    async fn a_record_survives_reopening_the_store() {
        let dir = std::env::temp_dir().join(format!("starling-records-{}", now_ms()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let url = format!("sqlite:{}?mode=rwc", dir.join("r.sqlite").display());

        let first = Records::open(Store::open(&url, 1).await.expect("a database"))
            .await
            .expect("the schema");
        let _ = first.put(1, 7, "k", b"durable").await.expect("stored");
        drop(first);

        let second = Records::open(Store::open(&url, 1).await.expect("a database"))
            .await
            .expect("the schema");
        assert_eq!(
            second.get(1, 7, "k").await.expect("a record").value,
            b"durable",
            "the point of the store is outliving the connection that wrote it"
        );

        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
