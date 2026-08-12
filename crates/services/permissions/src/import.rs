//! Writing ACL sets that came from somewhere else.
//!
//! Here rather than in `starling-migrate` for the reason
//! `docs/STORAGE.md` §1 gives: the `channel_acl` table belongs to this service,
//! and the encoding of the blob in it -- a prost-encoded [`AclSet`], not a row
//! per entry -- is a decision this crate made and may change. A migration tool
//! writing that blob itself would be a copy of that decision living somewhere
//! that has no way to know when it stops being true.
//!
//! # One row per channel, and why the order in it matters
//!
//! An ACL set is stored whole, because the evaluator reads it whole and the
//! **order within it is load-bearing**: deny beats allow at the same level.
//! So the import writes the entries in murmur's `priority` order, which is the
//! order murmur evaluates them in, and does not sort, deduplicate or normalise
//! them on the way.

use prost::Message as _;
use starling_proto_fancy::permissions::AclSet;
use starling_runtime::storage::{Store, StoreError};

/// Write one ACL set per channel into `store` under server instance `scope`.
///
/// Upserts, so an interrupted migration can be run again. A channel that is
/// already in the table is **replaced**, not merged: two half-sets for one
/// channel is not a policy anyone wrote, and the entry order that makes deny
/// beat allow could not survive being interleaved.
///
/// Returns how many sets were written, for `--verify`.
///
/// # Errors
///
/// [`StoreError`] if the schema cannot be applied. A set that will not go in is
/// logged and skipped rather than abandoning the rest: leaving a server with
/// *some* of its ACL entries is bad, and leaving it with the first three is
/// worse.
pub async fn import(store: &Store, scope: u32, sets: &[AclSet]) -> Result<usize, StoreError> {
    store.migrate(crate::SCHEMA).await?;

    let mut written = 0;
    for set in sets {
        let result = sqlx::query(
            "INSERT INTO channel_acl (server_id, channel_id, acls) VALUES (?, ?, ?) \
             ON CONFLICT (server_id, channel_id) DO UPDATE SET acls = excluded.acls",
        )
        .bind(i64::from(scope))
        .bind(i64::from(set.channel))
        .bind(set.encode_to_vec())
        .execute(store.pool())
        .await;
        match result {
            Ok(_) => written += 1,
            Err(error) => {
                tracing::error!(%error, channel = set.channel, "an ACL set could not be imported");
            }
        }
    }
    Ok(written)
}

/// How many channels in `scope` have a stored ACL set.
///
/// # Errors
///
/// [`StoreError::Query`] if the table cannot be read.
pub async fn count(store: &Store, scope: u32) -> Result<usize, StoreError> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT COUNT(*) AS n FROM channel_acl WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_one(store.pool())
        .await
        .map_err(|error| StoreError::Query(format!("counting channel_acl: {error}")))?;
    Ok(row.try_get::<i64, _>("n").unwrap_or_default().max(0) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::Acls;
    use crate::perm::Perm;
    use starling_proto_fancy::permissions::{AclEntry, Group, Subject};

    async fn store() -> Store {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        Store::open(
            &format!("sqlite:file:permissions-import-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("an in-memory database")
    }

    /// The root's set: everybody may enter and speak, and one group may kick.
    fn root_set() -> AclSet {
        AclSet {
            channel: 0,
            inherit: true,
            acls: vec![
                AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("all".to_owned()),
                    grant: Perm::ENTER.union(Perm::SPEAK).bits(),
                    ..AclEntry::default()
                },
                AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("admin".to_owned()),
                    grant: Perm::KICK.bits(),
                    ..AclEntry::default()
                },
            ],
            groups: vec![Group {
                name: "admin".to_owned(),
                inherit: true,
                inheritable: true,
                add: vec![7],
                ..Group::default()
            }],
        }
    }

    #[tokio::test]
    async fn an_imported_set_evaluates_to_the_permissions_it_states() {
        // Reading the row back is not the check that matters; evaluating it is.
        // A set written in a shape the evaluator does not understand is a server
        // where every ACL entry is silently inert, which is exactly the failure
        // `docs/GAP-ANALYSIS.md` G3 records.
        let store = store().await;
        assert_eq!(import(&store, 1, &[root_set()]).await.expect("import"), 1);

        let acls = Acls::new();
        let _ = acls.load(&store).await;
        let member = Subject {
            account: 7,
            registered: true,
            ..Subject::default()
        };
        let granted = Perm::from_bits_truncate(crate::evaluate::evaluate(&acls, 1, &member, 0));
        assert!(
            granted.contains(Perm::KICK),
            "the group grant did not apply"
        );

        let stranger = Subject::default();
        let granted = Perm::from_bits_truncate(crate::evaluate::evaluate(&acls, 1, &stranger, 0));
        assert!(!granted.contains(Perm::KICK), "a stranger was let in");
        assert!(granted.contains(Perm::ENTER));
    }

    #[tokio::test]
    async fn entry_order_survives_the_round_trip() {
        // Deny beats allow *at the same level*, so the order inside a set is
        // policy. A round trip that sorted or deduplicated would change what
        // the server enforces without changing anything an operator can see.
        let store = store().await;
        let ordered = AclSet {
            channel: 3,
            inherit: false,
            acls: vec![
                AclEntry {
                    apply_here: true,
                    group: Some("all".to_owned()),
                    grant: Perm::SPEAK.bits(),
                    ..AclEntry::default()
                },
                AclEntry {
                    apply_here: true,
                    group: Some("all".to_owned()),
                    deny: Perm::SPEAK.bits(),
                    ..AclEntry::default()
                },
            ],
            groups: Vec::new(),
        };
        let _ = import(&store, 1, std::slice::from_ref(&ordered))
            .await
            .expect("import");

        let acls = Acls::new();
        let _ = acls.load(&store).await;
        assert_eq!(acls.get(1, 3).acls, ordered.acls);
    }

    #[tokio::test]
    async fn importing_twice_replaces_a_set_rather_than_doubling_it() {
        let store = store().await;
        let _ = import(&store, 1, &[root_set()]).await.expect("first");
        let _ = import(&store, 1, &[root_set()]).await.expect("second");
        assert_eq!(count(&store, 1).await.expect("count"), 1);

        let acls = Acls::new();
        let _ = acls.load(&store).await;
        assert_eq!(acls.get(1, 0).acls.len(), 2, "the set was concatenated");
    }
}
