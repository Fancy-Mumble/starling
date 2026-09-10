//! Names over objects, and the revisions a name accumulates.
//!
//! An object key is minted by the server and never reused; a *name* is chosen
//! by whoever stores it and points at the object that currently answers for
//! it. `docs/STORAGE-UNIFICATION.md` D3.
//!
//! That is the whole of what a document store needs beyond bytes: live-doc's
//! `documents` + `document_revisions` pair is this table, and an emote is a
//! name with one revision kept.
//!
//! Revisions are free because they are the primary key's last column: putting
//! a name inserts at the next number, reading the latest is a backwards range
//! scan from the end of that name's run, and listing the history is the run
//! itself. The same shape `docs/STORAGE.md` L3 turned pchat's fetch into.

use starling_runtime::ids::now_ms;
use starling_runtime::storage::{Migration, Store, StoreError};

/// The schema. Its own chain, additive beside `object`'s.
pub(crate) const SCHEMA: &[Migration<'static>] = &[
    Migration::new(
        "0001_name",
        &[
            "CREATE TABLE IF NOT EXISTS name (\
             server_id BIGINT NOT NULL, ns VARCHAR(190) NOT NULL, \
             n VARCHAR(190) NOT NULL, rev BIGINT NOT NULL, \
             k VARCHAR(190) NOT NULL, created_at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, ns, n, rev))",
            // Finding every name that points at one object, which is what deleting
            // an object has to do before its rows are left dangling.
            "CREATE INDEX IF NOT EXISTS ix_name_key ON name(server_id, k)",
        ],
    ),
    Migration::new(
        // What a name says about itself beyond which object it points at: an
        // emote's alias and description. On the revision rather than the object,
        // because they belong to the shortcode and must survive the picture being
        // replaced. `TEXT`, and nullable, because most names say nothing.
        "0002_name_meta",
        &["ALTER TABLE name ADD COLUMN meta TEXT NULL"],
    ),
];

/// One revision of a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Revision {
    /// Which revision, from 1.
    pub(crate) rev: u64,
    /// The object it points at.
    pub(crate) key: String,
    /// When it was made.
    pub(crate) created_at_ms: u64,
    /// What the name says about itself, if anything. Opaque here.
    pub(crate) meta: Option<String>,
}

/// Names over objects, in one namespace at a time.
#[derive(Debug, Clone)]
pub(crate) struct Names {
    store: Store,
}

impl Names {
    /// Wrap `store`, applying the schema.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the schema cannot be applied.
    pub(crate) async fn open(store: Store) -> Result<Self, StoreError> {
        store.migrate(SCHEMA).await?;
        Ok(Self { store })
    }

    /// Point `name` at `key`, as a new revision.
    ///
    /// Returns the revision number written. Racing writers both read the same
    /// latest and would pick the same next number; the primary key refuses the
    /// second, which is the right outcome - a lost update is better than two
    /// revisions claiming to be the same one - and the caller sees the error.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the row cannot be written.
    pub(crate) async fn put(
        &self,
        scope: u32,
        ns: &str,
        name: &str,
        key: &str,
        meta: Option<&str>,
    ) -> Result<u64, StoreError> {
        let next = self.latest(scope, ns, name).await.map_or(1, |r| r.rev + 1);
        let now = now_ms();
        let _ = sqlx::query(
            "INSERT INTO name (server_id, ns, n, rev, k, created_at_ms, meta) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(ns)
        .bind(name)
        .bind(next as i64)
        .bind(key)
        .bind(now as i64)
        .bind(meta)
        .execute(self.store.pool())
        .await
        .map_err(|error| StoreError::Query(error.to_string()))?;
        Ok(next)
    }

    /// The revision a name currently answers with, or `None` for a name that
    /// has never been written.
    pub(crate) async fn latest(&self, scope: u32, ns: &str, name: &str) -> Option<Revision> {
        let row = sqlx::query(
            "SELECT rev, k, created_at_ms, meta FROM name \
             WHERE server_id = ? AND ns = ? AND n = ? ORDER BY rev DESC LIMIT 1",
        )
        .bind(i64::from(scope))
        .bind(ns)
        .bind(name)
        .fetch_optional(self.store.pool())
        .await
        .inspect_err(|error| tracing::warn!(%error, "could not read a name"))
        .ok()
        .flatten()?;
        Some(revision(&row))
    }

    /// A name's revisions, newest first.
    pub(crate) async fn revisions(
        &self,
        scope: u32,
        ns: &str,
        name: &str,
        limit: u32,
    ) -> Vec<Revision> {
        let rows = sqlx::query(
            "SELECT rev, k, created_at_ms, meta FROM name \
             WHERE server_id = ? AND ns = ? AND n = ? ORDER BY rev DESC LIMIT ?",
        )
        .bind(i64::from(scope))
        .bind(ns)
        .bind(name)
        .bind(i64::from(limit.max(1)))
        .fetch_all(self.store.pool())
        .await;
        match rows {
            Ok(rows) => rows.iter().map(revision).collect(),
            Err(error) => {
                tracing::warn!(%error, "could not list revisions");
                Vec::new()
            }
        }
    }

    /// Every name in a namespace, in order, with the revision each currently
    /// answers with.
    pub(crate) async fn list(&self, scope: u32, ns: &str) -> Vec<(String, Revision)> {
        use sqlx::Row as _;
        let rows = sqlx::query(
            "SELECT n, rev, k, created_at_ms, meta FROM name \
             WHERE server_id = ? AND ns = ? ORDER BY n, rev",
        )
        .bind(i64::from(scope))
        .bind(ns)
        .fetch_all(self.store.pool())
        .await;
        let Ok(rows) = rows.inspect_err(|error| tracing::warn!(%error, "could not list names"))
        else {
            return Vec::new();
        };
        // Ordered by name then revision, so the last row seen for each name is
        // its latest. Folded here rather than asked for with a correlated
        // subquery, which is where the three backends stop agreeing.
        let mut out: Vec<(String, Revision)> = Vec::new();
        for row in &rows {
            let Ok(name) = row.try_get::<String, _>("n") else {
                continue;
            };
            let rev = revision(row);
            match out.last_mut() {
                Some((last, current)) if *last == name => *current = rev,
                _ => out.push((name, rev)),
            }
        }
        out
    }

    /// Drop revisions of `name` beyond the newest `keep`, and say which object
    /// keys are no longer pointed at by anything.
    ///
    /// The caller deletes those objects. Split that way because this table
    /// knows what a name points at and the object store knows how to remove
    /// bytes, and neither should learn the other's job.
    ///
    /// `keep` of zero is treated as one: a name with no revisions is a name
    /// that resolves to nothing, which is a deletion and not a trim.
    pub(crate) async fn trim(&self, scope: u32, ns: &str, name: &str, keep: u64) -> Vec<String> {
        use sqlx::Row as _;
        let keep = keep.max(1);
        let rows = sqlx::query(
            "SELECT rev, k FROM name WHERE server_id = ? AND ns = ? AND n = ? ORDER BY rev DESC",
        )
        .bind(i64::from(scope))
        .bind(ns)
        .bind(name)
        .fetch_all(self.store.pool())
        .await;
        let Ok(rows) = rows.inspect_err(|error| tracing::warn!(%error, "could not trim a name"))
        else {
            return Vec::new();
        };

        let mut orphaned = Vec::new();
        for row in rows.iter().skip(keep as usize) {
            let (Ok(rev), Ok(key)) = (row.try_get::<i64, _>("rev"), row.try_get::<String, _>("k"))
            else {
                continue;
            };
            let _ = sqlx::query(
                "DELETE FROM name WHERE server_id = ? AND ns = ? AND n = ? AND rev = ?",
            )
            .bind(i64::from(scope))
            .bind(ns)
            .bind(name)
            .bind(rev)
            .execute(self.store.pool())
            .await
            .inspect_err(|error| tracing::warn!(%error, "could not drop a revision"));
            if self.pointed_at(scope, &key).await == 0 {
                orphaned.push(key);
            }
        }
        orphaned
    }

    /// Forget a name entirely, and say which objects that orphaned.
    pub(crate) async fn forget(&self, scope: u32, ns: &str, name: &str) -> Vec<String> {
        use sqlx::Row as _;
        let rows = sqlx::query("SELECT k FROM name WHERE server_id = ? AND ns = ? AND n = ?")
            .bind(i64::from(scope))
            .bind(ns)
            .bind(name)
            .fetch_all(self.store.pool())
            .await;
        let keys: Vec<String> = match rows {
            Ok(rows) => rows
                .iter()
                .filter_map(|row| row.try_get::<String, _>("k").ok())
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "could not read a name before forgetting it");
                return Vec::new();
            }
        };

        let _ = sqlx::query("DELETE FROM name WHERE server_id = ? AND ns = ? AND n = ?")
            .bind(i64::from(scope))
            .bind(ns)
            .bind(name)
            .execute(self.store.pool())
            .await
            .inspect_err(|error| tracing::warn!(%error, "could not forget a name"));

        let mut orphaned = Vec::new();
        for key in keys {
            if self.pointed_at(scope, &key).await == 0 {
                orphaned.push(key);
            }
        }
        orphaned
    }

    /// How many names still point at one object.
    ///
    /// Two revisions of one name can share a key, and so can two names, so an
    /// object is only orphaned when nothing at all refers to it.
    async fn pointed_at(&self, scope: u32, key: &str) -> i64 {
        use sqlx::Row as _;
        sqlx::query("SELECT COUNT(*) AS n FROM name WHERE server_id = ? AND k = ?")
            .bind(i64::from(scope))
            .bind(key)
            .fetch_one(self.store.pool())
            .await
            .ok()
            .and_then(|row| row.try_get::<i64, _>("n").ok())
            .unwrap_or(1)
    }
}

/// One row as a revision.
fn revision(row: &sqlx::any::AnyRow) -> Revision {
    use sqlx::Row as _;
    Revision {
        rev: row.try_get::<i64, _>("rev").unwrap_or_default().max(0) as u64,
        key: row.try_get::<String, _>("k").unwrap_or_default(),
        created_at_ms: row
            .try_get::<i64, _>("created_at_ms")
            .unwrap_or_default()
            .max(0) as u64,
        meta: row.try_get::<Option<String>, _>("meta").ok().flatten(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn names() -> Names {
        let store = Store::open("sqlite::memory:", 1).await.expect("a database");
        Names::open(store).await.expect("the schema")
    }

    #[tokio::test]
    async fn a_name_answers_with_what_it_was_last_pointed_at() {
        let names = names().await;
        assert_eq!(
            names
                .put(1, "p/doc", "notes", "k1", None)
                .await
                .expect("put"),
            1
        );
        assert_eq!(
            names
                .put(1, "p/doc", "notes", "k2", None)
                .await
                .expect("put"),
            2
        );

        let latest = names.latest(1, "p/doc", "notes").await.expect("a revision");
        assert_eq!(latest.rev, 2);
        assert_eq!(latest.key, "k2");
    }

    #[tokio::test]
    async fn a_name_that_was_never_written_answers_with_nothing() {
        let names = names().await;
        assert!(names.latest(1, "p/doc", "absent").await.is_none());
    }

    #[tokio::test]
    async fn revisions_come_back_newest_first() {
        let names = names().await;
        for key in ["k1", "k2", "k3"] {
            let _ = names
                .put(1, "p/doc", "notes", key, None)
                .await
                .expect("put");
        }

        let history = names.revisions(1, "p/doc", "notes", 10).await;
        assert_eq!(
            history.iter().map(|r| r.rev).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "a history is read backwards from now, which is the order it is shown in"
        );
    }

    #[tokio::test]
    async fn namespaces_do_not_see_each_others_names() {
        let names = names().await;
        let _ = names
            .put(1, "p/one", "notes", "k1", None)
            .await
            .expect("put");

        assert!(names.latest(1, "p/two", "notes").await.is_none());
        assert!(names.list(1, "p/two").await.is_empty());
    }

    #[tokio::test]
    async fn instances_do_not_see_each_others_names() {
        let names = names().await;
        let _ = names
            .put(1, "p/one", "notes", "k1", None)
            .await
            .expect("put");

        assert!(names.latest(2, "p/one", "notes").await.is_none());
    }

    #[tokio::test]
    async fn a_listing_gives_each_name_once_at_its_latest() {
        let names = names().await;
        let _ = names
            .put(1, "s/emotes", "blobfish", "k1", None)
            .await
            .expect("put");
        let _ = names
            .put(1, "s/emotes", "blobfish", "k2", None)
            .await
            .expect("put");
        let _ = names
            .put(1, "s/emotes", "party", "k3", None)
            .await
            .expect("put");

        let listed = names.list(1, "s/emotes").await;
        assert_eq!(
            listed.len(),
            2,
            "a name appears once however many revisions it has"
        );
        assert_eq!(listed[0].0, "blobfish");
        assert_eq!(
            listed[0].1.key, "k2",
            "and at the revision it currently answers with"
        );
        assert_eq!(listed[1].0, "party");
    }

    #[tokio::test]
    async fn trimming_keeps_the_newest_and_orphans_the_rest() {
        let names = names().await;
        for key in ["k1", "k2", "k3"] {
            let _ = names
                .put(1, "s/emotes", "blobfish", key, None)
                .await
                .expect("put");
        }

        let orphaned = names.trim(1, "s/emotes", "blobfish", 1).await;

        assert_eq!(orphaned, vec!["k2".to_owned(), "k1".to_owned()]);
        assert_eq!(
            names.revisions(1, "s/emotes", "blobfish", 10).await.len(),
            1,
            "an emote keeps one revision: the history is not what it is for"
        );
    }

    #[tokio::test]
    async fn trimming_does_not_orphan_an_object_another_revision_still_points_at() {
        let names = names().await;
        // The same bytes stored twice - an edit that undid itself, say.
        for key in ["shared", "k2", "shared"] {
            let _ = names
                .put(1, "p/doc", "notes", key, None)
                .await
                .expect("put");
        }

        let orphaned = names.trim(1, "p/doc", "notes", 1).await;

        assert!(
            !orphaned.contains(&"shared".to_owned()),
            "revision 3 still points at it, and deleting the bytes would empty the live document"
        );
    }

    #[tokio::test]
    async fn forgetting_a_name_orphans_every_object_it_alone_held() {
        let names = names().await;
        let _ = names
            .put(1, "p/doc", "notes", "k1", None)
            .await
            .expect("put");
        let _ = names
            .put(1, "p/doc", "notes", "k2", None)
            .await
            .expect("put");
        let _ = names
            .put(1, "p/doc", "other", "k3", None)
            .await
            .expect("put");

        let orphaned = names.forget(1, "p/doc", "notes").await;

        assert_eq!(orphaned.len(), 2);
        assert!(names.latest(1, "p/doc", "notes").await.is_none());
        assert!(
            names.latest(1, "p/doc", "other").await.is_some(),
            "another name's objects are not this one's to orphan"
        );
    }

    #[tokio::test]
    async fn keeping_zero_revisions_keeps_one() {
        // A name with no revisions resolves to nothing, which is a deletion
        // and not a trim - and `forget` is the way to ask for that.
        let names = names().await;
        let _ = names
            .put(1, "p/doc", "notes", "k1", None)
            .await
            .expect("put");

        let _ = names.trim(1, "p/doc", "notes", 0).await;

        assert!(names.latest(1, "p/doc", "notes").await.is_some());
    }

    #[tokio::test]
    async fn a_names_meta_travels_with_the_revision_that_carries_it() {
        let names = names().await;
        let _ = names
            .put(1, "srv/emotes", "blobfish", "k1", Some("a fish"))
            .await
            .expect("put");

        let latest = names
            .latest(1, "srv/emotes", "blobfish")
            .await
            .expect("a revision");
        assert_eq!(latest.meta.as_deref(), Some("a fish"));

        let listed = names.list(1, "srv/emotes").await;
        assert_eq!(
            listed[0].1.meta.as_deref(),
            Some("a fish"),
            "and the listing carries it too"
        );
    }
}
