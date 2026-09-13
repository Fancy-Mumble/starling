//! Writing the live tree down, so a restart comes back to the tree it left.
//!
//! The tree is the only copy anything reads (`docs/STORAGE.md` L7), and until
//! this existed it was the only copy there was: a channel a client created,
//! renamed, linked or set a `pchat_protocol` on lived in memory and was gone on
//! the next start, taking the channel's persistent-chat history with it.
//! [`Trees`](crate::Trees) journals what each mutation touched; this applies the
//! journal, write-behind (D1).

use starling_proto_fancy::metadata::Channel;
use starling_runtime::storage::Store;

/// One write the tree owes the store.
#[derive(Debug, Clone, PartialEq)]
pub enum Persist {
    /// The channel as it now is, links included.
    Upsert {
        /// The server instance.
        scope: u32,
        /// The whole record.
        channel: Channel,
    },
    /// A channel that is gone, or is temporary and so is never stored.
    Remove {
        /// The server instance.
        scope: u32,
        /// The channel.
        channel: u32,
    },
    /// The id the next channel will be given.
    ///
    /// Stored rather than derived from the surviving rows because ids are never
    /// reused (`ChannelStore` invariant 4): once the highest channel is deleted,
    /// max + 1 hands its id, and the ACL and history still keyed by it, to the
    /// next room anybody creates.
    NextId {
        /// The server instance.
        scope: u32,
        /// The next id.
        next_id: u32,
    },
}

/// Apply one journal entry, in one transaction.
///
/// # Errors
///
/// The database error, with nothing applied.
pub async fn apply(store: &Store, op: &Persist) -> Result<(), sqlx::Error> {
    let mut tx = store.pool().begin().await?;
    match op {
        Persist::Upsert { scope, channel } => {
            upsert_channel(&mut *tx, *scope, channel).await?;
            // Replaced as a set, because that is what `links` is: a link the
            // tree dropped has to leave the table too, not only the ones added.
            let _ = sqlx::query("DELETE FROM channel_link WHERE server_id = ? AND channel_id = ?")
                .bind(i64::from(*scope))
                .bind(i64::from(channel.id))
                .execute(&mut *tx)
                .await?;
            for linked in &channel.links {
                let _ = sqlx::query(
                    "INSERT INTO channel_link (server_id, channel_id, linked_id) VALUES (?, ?, ?) \
                     ON CONFLICT (server_id, channel_id, linked_id) DO NOTHING",
                )
                .bind(i64::from(*scope))
                .bind(i64::from(channel.id))
                .bind(i64::from(*linked))
                .execute(&mut *tx)
                .await?;
            }
        }
        Persist::Remove { scope, channel } => {
            // Listener and remembered-channel rows go with it, as murmur deletes
            // them (`Server.cpp:2194`): a row naming a channel that no longer
            // exists is never restored, only carried forever.
            for statement in [
                "DELETE FROM channel WHERE server_id = ? AND id = ?",
                "DELETE FROM channel_link WHERE server_id = ? AND channel_id = ?",
                "DELETE FROM channel_link WHERE server_id = ? AND linked_id = ?",
                "DELETE FROM channel_listener WHERE server_id = ? AND channel_id = ?",
                "DELETE FROM last_channel WHERE server_id = ? AND channel_id = ?",
            ] {
                let _ = sqlx::query(statement)
                    .bind(i64::from(*scope))
                    .bind(i64::from(*channel))
                    .execute(&mut *tx)
                    .await?;
            }
        }
        Persist::NextId { scope, next_id } => {
            let _ = sqlx::query(
                "INSERT INTO channel_sequence (server_id, next_id) VALUES (?, ?) \
                 ON CONFLICT (server_id) DO UPDATE SET next_id = excluded.next_id",
            )
            .bind(i64::from(*scope))
            .bind(i64::from(*next_id))
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await
}

/// Write one channel row, every stored column of it.
///
/// The one definition of that row: the import and the live journal both call
/// it, so a column added here is written by both, and a column added to
/// neither fails the round-trip test in `tree_actor`.
pub(crate) async fn upsert_channel<'c, E>(
    executor: E,
    scope: u32,
    channel: &Channel,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'c, Database = sqlx::Any>,
{
    let _ = sqlx::query(
        "INSERT INTO channel (server_id, id, parent_id, name, description, position, \
             max_users, flags, expiry_mode, expiry_duration_s, created_at_ms, pchat_protocol) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (server_id, id) DO UPDATE SET \
             parent_id = excluded.parent_id, name = excluded.name, \
             description = excluded.description, position = excluded.position, \
             max_users = excluded.max_users, flags = excluded.flags, \
             expiry_mode = excluded.expiry_mode, \
             expiry_duration_s = excluded.expiry_duration_s, \
             created_at_ms = excluded.created_at_ms, \
             pchat_protocol = excluded.pchat_protocol",
    )
    .bind(i64::from(scope))
    .bind(i64::from(channel.id))
    .bind(channel.parent.map(i64::from))
    .bind(channel.name.clone())
    .bind(channel.description.clone())
    .bind(i64::from(channel.position))
    .bind(i64::from(channel.max_users))
    .bind(i64::from(channel.flags))
    .bind(i64::from(channel.expiry_mode))
    .bind(i64::from(channel.expiry_duration_s))
    .bind(channel.created_at_ms as i64)
    .bind(i64::from(channel.pchat_protocol))
    .execute(executor)
    .await?;
    Ok(())
}
