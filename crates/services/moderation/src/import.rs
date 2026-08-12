//! Writing a ban list that came from somewhere else.
//!
//! Here rather than in `starling-migrate` because the `ban` table belongs to
//! this service (`docs/STORAGE.md` §1), and one column of it in particular is a
//! decision this crate made: `address` holds the **v6-mapped sixteen bytes**,
//! because that is what [`crate::covers`] walks when a peer connects. murmur
//! stores a text address in its newer schema and raw bytes in its older one, and
//! neither is what a prefix comparison here reads.
//!
//! An expired ban is imported like any other. It costs one row, it is what the
//! operator's list said, and the alternative is a migration that quietly edits
//! moderation history.

use starling_proto_fancy::moderation::Ban;
use starling_runtime::storage::{Store, StoreError};

/// Write `bans` into `store` under server instance `scope`.
///
/// Upserts by id, so an interrupted migration can be run again. murmur has no
/// ban id -- its primary key is the address, the prefix and the certificate
/// hash -- so the caller assigns one and must assign the *same* one on a second
/// pass, or a re-run doubles the list. `starling migrate-db` derives it from the
/// ban's own contents for exactly that reason.
///
/// Returns how many were written, for `--verify`.
///
/// # Errors
///
/// [`StoreError`] if the schema cannot be applied. A ban that will not go in is
/// logged and skipped: a ban list with one hole is worth having, and stopping
/// half way leaves the rest of the list unenforced.
pub async fn import(store: &Store, scope: u32, bans: &[Ban]) -> Result<usize, StoreError> {
    store.migrate(crate::SCHEMA).await?;

    let mut written = 0;
    for ban in bans {
        let result = sqlx::query(
            "INSERT INTO ban (server_id, id, address, prefix_len, name, cert_hash, reason, \
                 start_ms, duration_s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, id) DO UPDATE SET \
                 address = excluded.address, prefix_len = excluded.prefix_len, \
                 name = excluded.name, cert_hash = excluded.cert_hash, \
                 reason = excluded.reason, start_ms = excluded.start_ms, \
                 duration_s = excluded.duration_s",
        )
        .bind(i64::from(scope))
        .bind(ban.id as i64)
        .bind(ban.address.as_slice())
        .bind(i64::from(ban.prefix_len))
        .bind(&ban.name)
        .bind(ban.cert_hash.as_slice())
        .bind(&ban.reason)
        .bind(ban.start_ms as i64)
        .bind(i64::from(ban.duration_s))
        .execute(store.pool())
        .await;
        match result {
            Ok(_) => written += 1,
            Err(error) => {
                tracing::error!(%error, name = %ban.name, "a ban could not be imported");
            }
        }
    }
    Ok(written)
}

/// How many bans `scope` holds, expired ones included.
///
/// # Errors
///
/// [`StoreError::Query`] if the table cannot be read.
pub async fn count(store: &Store, scope: u32) -> Result<usize, StoreError> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT COUNT(*) AS n FROM ban WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_one(store.pool())
        .await
        .map_err(|error| StoreError::Query(format!("counting bans: {error}")))?;
    Ok(row.try_get::<i64, _>("n").unwrap_or_default().max(0) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> Store {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        Store::open(
            &format!("sqlite:file:moderation-import-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("an in-memory database")
    }

    /// A `/128` ban on one address, as a migration would build it.
    fn ban() -> Ban {
        Ban {
            id: 42,
            address: std::net::Ipv4Addr::new(192, 0, 2, 7)
                .to_ipv6_mapped()
                .octets()
                .to_vec(),
            prefix_len: 128,
            name: "mallory".to_owned(),
            cert_hash: vec![0xab, 0xcd],
            reason: "spam".to_owned(),
            start_ms: 1_700_000_000_000,
            duration_s: 0,
        }
    }

    #[tokio::test]
    async fn an_imported_ban_still_covers_the_address_it_named() {
        // Storing the address in a form the check does not read is a ban list
        // that exists and stops nobody, which no test of the row would catch.
        let store = store().await;
        assert_eq!(import(&store, 1, &[ban()]).await.expect("import"), 1);

        let banned = std::net::Ipv4Addr::new(192, 0, 2, 7)
            .to_ipv6_mapped()
            .octets();
        assert!(crate::covers(&ban(), &banned));

        let somebody_else = std::net::Ipv4Addr::new(192, 0, 2, 8)
            .to_ipv6_mapped()
            .octets();
        assert!(!crate::covers(&ban(), &somebody_else));
    }

    #[tokio::test]
    async fn importing_twice_leaves_one_ban_rather_than_two() {
        // murmur has no ban id, so the caller derives one. If it derived a
        // different one per run, a re-run would double every operator's list.
        let store = store().await;
        let _ = import(&store, 1, &[ban()]).await.expect("first");
        let _ = import(&store, 1, &[ban()]).await.expect("second");
        assert_eq!(count(&store, 1).await.expect("count"), 1);
    }

    #[tokio::test]
    async fn an_expired_ban_is_carried_across_rather_than_edited_out() {
        // It is what the operator's list said. Dropping it would be a migration
        // quietly rewriting moderation history.
        let store = store().await;
        let expired = Ban {
            id: 7,
            duration_s: 60,
            start_ms: 1,
            ..ban()
        };
        assert!(crate::expired(&expired, 1_700_000_000_000));
        let _ = import(&store, 1, &[expired]).await.expect("import");
        assert_eq!(count(&store, 1).await.expect("count"), 1);
    }
}
