//! Messages the server holds and posts later.
//!
//! A scheduled message is a text message with a due time, so it lives here
//! rather than in its own service: at the due time it *is* an ordinary
//! `TextMessage`, under the same length limit, the same markup filter and the
//! same history. murmur reached the same conclusion at wire ids 161-165
//! (`Messages.cpp:5322` for the handlers, `Server.cpp:2427` for the timer);
//! this is that design against the canon and `sqlx`.
//!
//! # What is stored and what is not
//!
//! The row is the durable half: body, due time, owner, status. Who it will
//! reach is not stored, because membership at delivery time is the only
//! membership that matters and it is read from the roster then. What *is*
//! stored is the address it was written to, one row per channel or tree, in a
//! child table rather than as a packed id list: murmur packs them into a
//! space-separated `TEXT` column, and `docs/STORAGE.md` is a list of the
//! reasons not to.
//!
//! # Ownership is a certificate, never a session
//!
//! Session ids are per connection and recycled. A message scheduled for
//! tomorrow outlives today's connection by definition, so "only the creator
//! may cancel it" can only be keyed on the certificate, which is what murmur
//! does too (`creatorHash`).

use starling_proto_fancy::fancy::feature::{ScheduleStatus, Scheduled};
use starling_runtime::ids::Uuid7;
use starling_runtime::storage::{Migration, Store};

/// The schema.
///
/// Indexed for the two questions the timer asks on every wakeup, *what is due*
/// and *what is next*, and for the one a client asks, *what have I got
/// pending*. Both are covered by leading with `(server_id, status)`.
pub(crate) const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0002_scheduled_message",
    &[
        "CREATE TABLE IF NOT EXISTS scheduled_message (\
             server_id BIGINT NOT NULL, id BLOB NOT NULL, \
             body TEXT NOT NULL, deliver_at_ms BIGINT NOT NULL, \
             creator_cert BLOB NOT NULL, creator_name VARCHAR(190) NOT NULL, \
             created_at_ms BIGINT NOT NULL, status INTEGER NOT NULL, \
             PRIMARY KEY (server_id, id))",
        "CREATE INDEX IF NOT EXISTS ix_scheduled_due \
             ON scheduled_message(server_id, status, deliver_at_ms)",
        "CREATE TABLE IF NOT EXISTS scheduled_message_target (\
             server_id BIGINT NOT NULL, id BLOB NOT NULL, \
             channel_id BIGINT NOT NULL, is_tree INTEGER NOT NULL, \
             PRIMARY KEY (server_id, id, channel_id, is_tree))",
    ],
)];

/// Most channels and trees one scheduled message may address.
///
/// A message to every channel on a server is a broadcast, and a broadcast is
/// an operator action (`Announce`) rather than something a client schedules.
pub const MAX_TARGETS: usize = 32;

/// Most messages one creator may have pending at once.
///
/// Storage a client fills is storage a client can fill without limit.
pub const MAX_PENDING_PER_CREATOR: i64 = 64;

/// The longest a message may be scheduled ahead, in milliseconds.
///
/// A year. Not a protocol rule: a due date beyond it is far likelier to be a
/// client that sent seconds where the canon says milliseconds than a genuine
/// intention, and the row would otherwise sit in the table forever.
pub const MAX_LEAD_MS: u64 = 365 * 24 * 60 * 60 * 1000;

/// One stored message, with the address it was written to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The identifier, whose wire form is this `UUIDv7` as text.
    pub id: Uuid7,
    /// The channels it is addressed to.
    pub channels: Vec<u32>,
    /// The channels whose whole subtree it is addressed to.
    pub trees: Vec<u32>,
    /// The message, already filtered and length-checked at schedule time.
    pub body: String,
    /// When it is due, in Unix epoch milliseconds.
    pub deliver_at_ms: u64,
    /// The owner's leaf certificate: who may cancel it, and who it is from.
    pub creator_cert: Vec<u8>,
    /// The owner's display name when they scheduled it, for the list.
    pub creator_name: String,
    /// When it was scheduled, in Unix epoch milliseconds.
    pub created_at_ms: u64,
    /// A [`ScheduleStatus`], as its wire number.
    pub status: i32,
}

impl Row {
    /// The row as the canon reports it.
    ///
    /// `creator` is 0: the session that scheduled it is not the session that
    /// will receive this list, and a stale id would read as somebody else.
    #[must_use]
    pub fn to_canon(&self) -> Scheduled {
        Scheduled {
            schedule_id: self.id.to_string(),
            channels: self.channels.clone(),
            trees: self.trees.clone(),
            body: self.body.clone(),
            deliver_at_ms: self.deliver_at_ms,
            creator: 0,
            creator_cert: self.creator_cert.clone(),
            creator_name: self.creator_name.clone(),
            created_at_ms: self.created_at_ms,
            status: self.status,
        }
    }
}

/// Store one scheduled message and its targets.
///
/// The targets go in after the row, and a failure to write them leaves a
/// message addressed at nobody rather than one addressed at everybody, which
/// is the direction to fail in.
pub(crate) async fn store(store: &Store, scope: u32, row: &Row) -> Result<(), sqlx::Error> {
    let _ = sqlx::query(
        "INSERT INTO scheduled_message \
             (server_id, id, body, deliver_at_ms, creator_cert, creator_name, \
              created_at_ms, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(i64::from(scope))
    .bind(row.id.to_vec())
    .bind(&row.body)
    .bind(row.deliver_at_ms as i64)
    .bind(&row.creator_cert)
    .bind(&row.creator_name)
    .bind(row.created_at_ms as i64)
    .bind(row.status)
    .execute(store.pool())
    .await?;

    for (channel, is_tree) in row
        .channels
        .iter()
        .map(|channel| (*channel, 0_i32))
        .chain(row.trees.iter().map(|channel| (*channel, 1_i32)))
    {
        let _ = sqlx::query(
            "INSERT INTO scheduled_message_target \
                 (server_id, id, channel_id, is_tree) VALUES (?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(row.id.to_vec())
        .bind(i64::from(channel))
        .bind(is_tree)
        .execute(store.pool())
        .await?;
    }
    Ok(())
}

/// Read one message back, targets included.
pub(crate) async fn get(store: &Store, scope: u32, id: Uuid7) -> Option<Row> {
    let rows = read(
        store,
        scope,
        "SELECT id, body, deliver_at_ms, creator_cert, creator_name, created_at_ms, status \
         FROM scheduled_message WHERE server_id = ? AND id = ?",
        Bind::Bytes(id.to_vec()),
    )
    .await;
    rows.into_iter().next()
}

/// Everything `cert` has scheduled, newest due first.
pub(crate) async fn list(
    store: &Store,
    scope: u32,
    cert: &[u8],
    include_finished: bool,
) -> Vec<Row> {
    let sql = if include_finished {
        "SELECT id, body, deliver_at_ms, creator_cert, creator_name, created_at_ms, status \
         FROM scheduled_message WHERE server_id = ? AND creator_cert = ? \
         ORDER BY deliver_at_ms ASC"
    } else {
        "SELECT id, body, deliver_at_ms, creator_cert, creator_name, created_at_ms, status \
         FROM scheduled_message WHERE server_id = ? AND creator_cert = ? AND status = 0 \
         ORDER BY deliver_at_ms ASC"
    };
    read(store, scope, sql, Bind::Bytes(cert.to_vec())).await
}

/// How many pending messages `cert` is holding.
pub(crate) async fn pending_count(store: &Store, scope: u32, cert: &[u8]) -> i64 {
    use sqlx::Row as _;
    sqlx::query(
        "SELECT COUNT(*) AS pending FROM scheduled_message \
         WHERE server_id = ? AND creator_cert = ? AND status = 0",
    )
    .bind(i64::from(scope))
    .bind(cert.to_vec())
    .fetch_one(store.pool())
    .await
    .ok()
    .and_then(|row| row.try_get::<i64, _>("pending").ok())
    .unwrap_or_default()
}

/// Everything pending and due at `now_ms`.
pub(crate) async fn due(store: &Store, scope: u32, now_ms: u64) -> Vec<Row> {
    read(
        store,
        scope,
        "SELECT id, body, deliver_at_ms, creator_cert, creator_name, created_at_ms, status \
         FROM scheduled_message WHERE server_id = ? AND status = 0 AND deliver_at_ms <= ? \
         ORDER BY deliver_at_ms ASC",
        Bind::Time(now_ms),
    )
    .await
}

/// When the next pending message is due, if there is one.
pub(crate) async fn next_due(store: &Store, scope: u32) -> Option<u64> {
    use sqlx::Row as _;
    sqlx::query(
        "SELECT MIN(deliver_at_ms) AS next FROM scheduled_message \
         WHERE server_id = ? AND status = 0",
    )
    .bind(i64::from(scope))
    .fetch_optional(store.pool())
    .await
    .ok()
    .flatten()
    .and_then(|row| row.try_get::<Option<i64>, _>("next").ok().flatten())
    .map(|next| next.max(0) as u64)
}

/// Move a message to `status`, only from pending.
///
/// The `status = 0` clause is what makes this safe to race: a cancel arriving
/// while the timer is delivering the same row updates nothing and the caller
/// sees `false`, rather than the two of them each believing they won.
pub(crate) async fn finish(store: &Store, scope: u32, id: Uuid7, status: ScheduleStatus) -> bool {
    sqlx::query(
        "UPDATE scheduled_message SET status = ? \
         WHERE server_id = ? AND id = ? AND status = 0",
    )
    .bind(status as i32)
    .bind(i64::from(scope))
    .bind(id.to_vec())
    .execute(store.pool())
    .await
    .map(|result| result.rows_affected() > 0)
    .unwrap_or_default()
}

/// The one parameter a read below binds after the scope.
///
/// An enum rather than a generic or a closure over `sqlx::query::Query`: the
/// query type carries a lifetime *and* an argument buffer, so threading one
/// through a callback costs more signature than the two shapes are worth.
enum Bind {
    /// A due time.
    Time(u64),
    /// A schedule id or a certificate.
    Bytes(Vec<u8>),
}

/// Run a `SELECT` over `scheduled_message` and attach each row's targets.
///
/// `sql` is `&'static str` because every caller passes a literal; nothing from
/// a client is ever interpolated into a statement here.
async fn read(store: &Store, scope: u32, sql: &'static str, bind: Bind) -> Vec<Row> {
    use sqlx::Row as _;
    let query = sqlx::query(sql).bind(i64::from(scope));
    let query = match bind {
        Bind::Time(at) => query.bind(at as i64),
        Bind::Bytes(bytes) => query.bind(bytes),
    };
    let rows = query.fetch_all(store.pool()).await.unwrap_or_default();

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(id) = row
            .try_get::<Vec<u8>, _>("id")
            .ok()
            .and_then(|bytes| Uuid7::from_slice(&bytes))
        else {
            // A row whose key is not a UUID is a row nothing can address, so
            // it is skipped rather than delivered under a made-up id.
            tracing::warn!("a scheduled message has an unreadable id");
            continue;
        };
        let (channels, trees) = targets(store, scope, id).await;
        out.push(Row {
            id,
            channels,
            trees,
            body: row.try_get("body").unwrap_or_default(),
            deliver_at_ms: row.try_get::<i64, _>("deliver_at_ms").unwrap_or_default() as u64,
            creator_cert: row.try_get("creator_cert").unwrap_or_default(),
            creator_name: row.try_get("creator_name").unwrap_or_default(),
            created_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default() as u64,
            status: row.try_get("status").unwrap_or_default(),
        });
    }
    out
}

/// The channels and trees one message is addressed to.
async fn targets(store: &Store, scope: u32, id: Uuid7) -> (Vec<u32>, Vec<u32>) {
    use sqlx::Row as _;
    let rows = sqlx::query(
        "SELECT channel_id, is_tree FROM scheduled_message_target \
         WHERE server_id = ? AND id = ? ORDER BY channel_id ASC",
    )
    .bind(i64::from(scope))
    .bind(id.to_vec())
    .fetch_all(store.pool())
    .await
    .unwrap_or_default();

    let mut channels = Vec::new();
    let mut trees = Vec::new();
    for row in rows {
        let channel = row.try_get::<i64, _>("channel_id").unwrap_or_default() as u32;
        if row.try_get::<i32, _>("is_tree").unwrap_or_default() == 0 {
            channels.push(channel);
        } else {
            trees.push(channel);
        }
    }
    (channels, trees)
}
