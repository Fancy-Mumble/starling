//! Pins kept with a channel's stored messages.
//!
//! A pin is a property of the stored message (`PROTOCOL-COMPATIBILITY.md` §3),
//! so it is kept beside it, and only where messages are kept: one per stored
//! row, keyed by the row, so a deleted message takes its pin with it. Who
//! pinned and when are what this server knew when the pin arrived, the
//! connection's certificate and name and its own clock, never what a client
//! said.

use starling_proto_fancy::fancy::pchat::Pin;
use starling_runtime::storage::{Migration, Store};

/// The table. Its own migration, beside the message table's, so neither has
/// to know the other's numbering.
pub(crate) const SCHEMA: Migration<'static> = Migration::new(
    "0008_pchat_pin",
    &["CREATE TABLE IF NOT EXISTS pchat_pin (\
         server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, row_id BLOB NOT NULL, \
         message_id TEXT NOT NULL, pinner_cert BLOB NULL, pinner_name TEXT NOT NULL, \
         pinned_at_ms BIGINT NOT NULL, \
         PRIMARY KEY (server_id, channel_id, row_id))"],
);

/// The pins of every channel that keeps its messages.
#[derive(Debug, Clone)]
pub(crate) struct Pins {
    store: Store,
}

impl Pins {
    /// The pins in `store`, whose schema has been migrated.
    pub(crate) fn new(store: Store) -> Self {
        Self { store }
    }

    /// Keep `pin` on the stored row `row`, replacing any pin it had.
    ///
    /// Delete and insert in one transaction rather than an upsert, whose
    /// syntax is not the same on the three backends (`docs/STORAGE.md` D3).
    pub(crate) async fn keep(&self, scope: u32, row: &[u8], pin: &Pin) -> Result<(), sqlx::Error> {
        let mut tx = self.store.pool().begin().await?;
        let _ = sqlx::query(
            "DELETE FROM pchat_pin WHERE server_id = ? AND channel_id = ? AND row_id = ?",
        )
        .bind(i64::from(scope))
        .bind(i64::from(pin.channel))
        .bind(row)
        .execute(&mut *tx)
        .await?;
        let _ = sqlx::query(
            "INSERT INTO pchat_pin (server_id, channel_id, row_id, message_id, pinner_cert, \
                 pinner_name, pinned_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(i64::from(pin.channel))
        .bind(row)
        .bind(pin.message_id.as_str())
        .bind((!pin.pinner_cert.is_empty()).then(|| pin.pinner_cert.clone()))
        .bind(pin.pinner_name.as_str())
        .bind(pin.pinned_at_ms as i64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }

    /// Drop the pin on the stored row `row`, if it has one.
    pub(crate) async fn drop_pin(
        &self,
        scope: u32,
        channel: u32,
        row: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM pchat_pin WHERE server_id = ? AND channel_id = ? AND row_id = ?")
            .bind(i64::from(scope))
            .bind(i64::from(channel))
            .bind(row)
            .execute(self.store.pool())
            .await
            .map(|_| ())
    }

    /// Every pin in `channel` whose message is still stored, oldest first.
    ///
    /// Joined to the messages rather than trusted: a message the retention
    /// sweep removed takes its pin with it here, before the sweep below has
    /// caught up with the pin's row.
    pub(crate) async fn list(&self, scope: u32, channel: u32) -> Vec<Pin> {
        use sqlx::Row as _;
        let rows = sqlx::query(
            "SELECT p.message_id, p.pinner_cert, p.pinner_name, p.pinned_at_ms \
             FROM pchat_pin p \
             WHERE p.server_id = ? AND p.channel_id = ? AND EXISTS (\
                 SELECT 1 FROM pchat_message m WHERE m.server_id = p.server_id \
                 AND m.channel_id = p.channel_id AND m.id = p.row_id) \
             ORDER BY p.pinned_at_ms ASC",
        )
        .bind(i64::from(scope))
        .bind(i64::from(channel))
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default();
        rows.iter()
            .map(|row| Pin {
                message_id: row.try_get("message_id").unwrap_or_default(),
                channel,
                unpin: false,
                pinner: 0,
                pinner_cert: row
                    .try_get::<Option<Vec<u8>>, _>("pinner_cert")
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
                pinner_name: row.try_get("pinner_name").unwrap_or_default(),
                pinned_at_ms: row.try_get::<i64, _>("pinned_at_ms").unwrap_or_default() as u64,
            })
            .collect()
    }

    /// Forget the pins whose message is gone, by any route.
    pub(crate) async fn sweep(&self) {
        let _ = sqlx::query(
            "DELETE FROM pchat_pin WHERE NOT EXISTS (\
                 SELECT 1 FROM pchat_message m WHERE m.server_id = pchat_pin.server_id \
                 AND m.channel_id = pchat_pin.channel_id AND m.id = pchat_pin.row_id)",
        )
        .execute(self.store.pool())
        .await;
    }
}

/// Whether a channel running `mode` keeps its messages, and so its pins.
///
/// Every persistent mode but `signal_v1`, which keeps no history by design;
/// `None` (not yet known) and 0 (a plain channel) keep nothing.
pub(crate) fn keeps(mode: Option<u32>) -> bool {
    use starling_proto_fancy::fancy::pchat::Protocol;
    mode.is_some_and(|mode| mode != 0 && mode != Protocol::SignalV1 as u32)
}
