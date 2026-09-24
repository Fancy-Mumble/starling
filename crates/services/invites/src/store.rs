//! The two tables, and every question asked of them.
//!
//! `invite` is one row per link. `invite_use` is one row per person a link has
//! admitted, which is what makes a use countable *once*: somebody who comes
//! back with the same link - a reconnect, a second evening - is recognised and
//! let in without spending another use, and an invite that has admitted as
//! many people as it may still re-admits every one of them.

use starling_runtime::storage::{Migration, Store, StoreError};

/// The schema.
pub(crate) const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_invites",
    &[
        "CREATE TABLE IF NOT EXISTS invite (\
             server_id BIGINT NOT NULL, code VARCHAR(32) NOT NULL, \
             channel_id BIGINT NOT NULL, created_ms BIGINT NOT NULL, \
             expires_ms BIGINT NOT NULL, max_uses BIGINT NOT NULL, uses BIGINT NOT NULL, \
             creator VARCHAR(128) NOT NULL, creator_key VARCHAR(96) NOT NULL, \
             creator_account BIGINT, \
             PRIMARY KEY (server_id, code))",
        "CREATE INDEX IF NOT EXISTS ix_invite_expiry ON invite(server_id, expires_ms)",
        "CREATE INDEX IF NOT EXISTS ix_invite_creator ON invite(server_id, creator_key)",
        "CREATE TABLE IF NOT EXISTS invite_use (\
             server_id BIGINT NOT NULL, code VARCHAR(32) NOT NULL, who VARCHAR(96) NOT NULL, \
             at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, code, who))",
    ],
)];

/// One invite, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub code: String,
    pub channel: u32,
    pub created_ms: u64,
    /// Zero: never.
    pub expires_ms: u64,
    /// Zero: unlimited.
    pub max_uses: u32,
    pub uses: u32,
    pub creator: String,
    /// Who made it, in the form [`crate::identity_key`] writes. What "mine"
    /// and the per-creator ceiling are decided on; `creator` is only a label.
    pub creator_key: String,
    pub creator_account: Option<u64>,
}

impl Row {
    /// Whether it has lapsed at `now`.
    pub(crate) const fn expired(&self, now: u64) -> bool {
        self.expires_ms != 0 && self.expires_ms <= now
    }
}

/// What redeeming a code came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Redeemed {
    /// Let in, and where to.
    Admitted { channel: u32 },
    /// Not let in, and why, for the log.
    Refused(&'static str),
}

/// Map a query failure into the store's error.
fn query(error: &sqlx::Error) -> StoreError {
    StoreError::Query(error.to_string())
}

/// Read a column that is a `u32` on the way in and a `BIGINT` on disk.
fn narrow(value: i64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Widen for the database, which has no unsigned types.
fn wide(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn row_of(row: &sqlx::any::AnyRow) -> Result<Row, sqlx::Error> {
    use sqlx::Row as _;
    let account: Option<i64> = row.try_get("creator_account")?;
    Ok(Row {
        code: row.try_get("code")?,
        channel: narrow(row.try_get("channel_id")?),
        created_ms: u64::try_from(row.try_get::<i64, _>("created_ms")?).unwrap_or(0),
        expires_ms: u64::try_from(row.try_get::<i64, _>("expires_ms")?).unwrap_or(0),
        max_uses: narrow(row.try_get("max_uses")?),
        uses: narrow(row.try_get("uses")?),
        creator: row.try_get("creator")?,
        creator_key: row.try_get("creator_key")?,
        creator_account: account.and_then(|account| u64::try_from(account).ok()),
    })
}

/// Store a new invite.
pub(crate) async fn insert(store: &Store, scope: u32, row: &Row) -> Result<(), StoreError> {
    let _ = sqlx::query(
        "INSERT INTO invite (server_id, code, channel_id, created_ms, expires_ms, max_uses, \
             uses, creator, creator_key, creator_account) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(i64::from(scope))
    .bind(&row.code)
    .bind(i64::from(row.channel))
    .bind(wide(row.created_ms))
    .bind(wide(row.expires_ms))
    .bind(i64::from(row.max_uses))
    .bind(i64::from(row.uses))
    .bind(&row.creator)
    .bind(&row.creator_key)
    .bind(row.creator_account.map(wide))
    .execute(store.pool())
    .await
    .map_err(|error| query(&error))?;
    Ok(())
}

/// Every invite that has not lapsed, newest first, optionally only one
/// creator's.
pub(crate) async fn live(
    store: &Store,
    scope: u32,
    creator_key: Option<&str>,
    now: u64,
) -> Result<Vec<Row>, StoreError> {
    // Bounded: an admin screen is the only reader, and a server with more live
    // invites than this has a problem the list would not help with.
    let rows = match creator_key {
        Some(key) => {
            sqlx::query(
                "SELECT * FROM invite WHERE server_id = ? \
                     AND (expires_ms = 0 OR expires_ms > ?) AND creator_key = ? \
                 ORDER BY created_ms DESC LIMIT 500",
            )
            .bind(i64::from(scope))
            .bind(wide(now))
            .bind(key.to_owned())
            .fetch_all(store.pool())
            .await
        }
        None => {
            sqlx::query(
                "SELECT * FROM invite WHERE server_id = ? \
                     AND (expires_ms = 0 OR expires_ms > ?) \
                 ORDER BY created_ms DESC LIMIT 500",
            )
            .bind(i64::from(scope))
            .bind(wide(now))
            .fetch_all(store.pool())
            .await
        }
    }
    .map_err(|error| query(&error))?;
    rows.iter()
        .map(row_of)
        .collect::<Result<_, _>>()
        .map_err(|error| query(&error))
}

/// How many live invites one creator holds.
pub(crate) async fn live_count(
    store: &Store,
    scope: u32,
    creator_key: &str,
    now: u64,
) -> Result<u32, StoreError> {
    use sqlx::Row as _;
    let row = sqlx::query(
        "SELECT COUNT(*) AS held FROM invite WHERE server_id = ? AND creator_key = ? \
             AND (expires_ms = 0 OR expires_ms > ?)",
    )
    .bind(i64::from(scope))
    .bind(creator_key)
    .bind(wide(now))
    .fetch_one(store.pool())
    .await
    .map_err(|error| query(&error))?;
    Ok(narrow(row.try_get("held").map_err(|error| query(&error))?))
}

/// One invite by code, lapsed or not.
pub(crate) async fn find(store: &Store, scope: u32, code: &str) -> Result<Option<Row>, StoreError> {
    let row = sqlx::query("SELECT * FROM invite WHERE server_id = ? AND code = ?")
        .bind(i64::from(scope))
        .bind(code)
        .fetch_optional(store.pool())
        .await
        .map_err(|error| query(&error))?;
    row.as_ref()
        .map(row_of)
        .transpose()
        .map_err(|error| query(&error))
}

/// Delete one invite and everything it remembers, answering whether it
/// existed. `creator_key` narrows it to one creator's.
pub(crate) async fn remove(
    store: &Store,
    scope: u32,
    code: &str,
    creator_key: Option<&str>,
) -> Result<bool, StoreError> {
    let removed = match creator_key {
        Some(key) => {
            sqlx::query("DELETE FROM invite WHERE server_id = ? AND code = ? AND creator_key = ?")
                .bind(i64::from(scope))
                .bind(code)
                .bind(key)
                .execute(store.pool())
                .await
        }
        None => {
            sqlx::query("DELETE FROM invite WHERE server_id = ? AND code = ?")
                .bind(i64::from(scope))
                .bind(code)
                .execute(store.pool())
                .await
        }
    }
    .map_err(|error| query(&error))?
    .rows_affected();
    if removed > 0 {
        let _ = sqlx::query("DELETE FROM invite_use WHERE server_id = ? AND code = ?")
            .bind(i64::from(scope))
            .bind(code)
            .execute(store.pool())
            .await
            .map_err(|error| query(&error))?;
    }
    Ok(removed > 0)
}

/// Whether `code` lets `who` in at `now`, spending a use when it is their
/// first time.
///
/// The use is spent by a conditional `UPDATE` rather than a read-then-write,
/// so two strangers racing for an invite's last use cannot both get it: the
/// database lets exactly one of the two updates match.
pub(crate) async fn redeem(
    store: &Store,
    scope: u32,
    code: &str,
    who: &str,
    now: u64,
) -> Result<Redeemed, StoreError> {
    let Some(invite) = find(store, scope, code).await? else {
        return Ok(Redeemed::Refused("no such invite"));
    };
    if invite.expired(now) {
        return Ok(Redeemed::Refused("the invite has expired"));
    }
    let admitted = Redeemed::Admitted {
        channel: invite.channel,
    };

    let returning = sqlx::query(
        "SELECT 1 AS seen FROM invite_use WHERE server_id = ? AND code = ? AND who = ?",
    )
    .bind(i64::from(scope))
    .bind(code)
    .bind(who)
    .fetch_optional(store.pool())
    .await
    .map_err(|error| query(&error))?
    .is_some();
    if returning {
        return Ok(admitted);
    }

    let spent = sqlx::query(
        "UPDATE invite SET uses = uses + 1 WHERE server_id = ? AND code = ? \
             AND (max_uses = 0 OR uses < max_uses)",
    )
    .bind(i64::from(scope))
    .bind(code)
    .execute(store.pool())
    .await
    .map_err(|error| query(&error))?
    .rows_affected();
    if spent == 0 {
        return Ok(Redeemed::Refused("the invite has been used up"));
    }
    let _ = sqlx::query(
        "INSERT INTO invite_use (server_id, code, who, at_ms) VALUES (?, ?, ?, ?) \
         ON CONFLICT (server_id, code, who) DO NOTHING",
    )
    .bind(i64::from(scope))
    .bind(code)
    .bind(who)
    .bind(wide(now))
    .execute(store.pool())
    .await
    .map_err(|error| query(&error))?;
    Ok(admitted)
}

/// Delete every invite that lapsed before `now`, and what they remembered.
pub(crate) async fn sweep(store: &Store, scope: u32, now: u64) -> Result<u64, StoreError> {
    let _ = sqlx::query(
        "DELETE FROM invite_use WHERE server_id = ? AND code IN (\
             SELECT code FROM invite WHERE server_id = ? AND expires_ms <> 0 AND expires_ms <= ?)",
    )
    .bind(i64::from(scope))
    .bind(i64::from(scope))
    .bind(wide(now))
    .execute(store.pool())
    .await
    .map_err(|error| query(&error))?;
    let removed = sqlx::query(
        "DELETE FROM invite WHERE server_id = ? AND expires_ms <> 0 AND expires_ms <= ?",
    )
    .bind(i64::from(scope))
    .bind(wide(now))
    .execute(store.pool())
    .await
    .map_err(|error| query(&error))?
    .rows_affected();
    Ok(removed)
}
