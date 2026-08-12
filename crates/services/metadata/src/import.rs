//! Writing a channel tree that came from somewhere else.
//!
//! Here rather than in `starling-migrate` because of the rule the whole storage
//! design rests on: **each service owns its own schema, and no service reads or
//! writes another's tables** (`docs/STORAGE.md` §1). A migration tool that
//! issued its own `INSERT INTO channel` would be a second definition of this
//! table, in a crate that has no reason to know it exists, and the first
//! migration to be added here would leave it writing rows the service can no
//! longer read.
//!
//! So the tool reads murmur and this writes the tree. What crosses the boundary
//! is [`Tree`], made of the types this service already speaks.
//!
//! # What it does not do
//!
//! Fix anything up. The ids are murmur's, the parents are murmur's, and a
//! channel whose parent is missing stays that way rather than being reparented
//! to the root: an import that quietly repaired its input would make the
//! `--verify` pass meaningless, because the two sides would differ by design.
//! The caller checks the tree it read and reports what it found.

use starling_proto_fancy::metadata::Channel;
use starling_runtime::storage::{Store, StoreError};

/// What a migration hands the tree.
///
/// Everything keyed by **account**, not session: a listener and a remembered
/// channel both outlive the visit that created them, which is the whole reason
/// they are stored at all.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    /// The channels, in any order. Parents need not come first.
    pub channels: Vec<Channel>,
    /// Linked pairs, as `(channel, linked)`.
    pub links: Vec<(u32, u32)>,
    /// Stored listeners.
    pub listeners: Vec<Listener>,
    /// Where each account was when it last disconnected.
    pub last_channels: Vec<LastChannel>,
}

/// One account listening to one channel it is not in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Listener {
    /// The account.
    pub account: u64,
    /// The channel.
    pub channel: u32,
    /// The gain, `1.0` for no adjustment.
    pub volume: f32,
    /// Whether the listener is on. A disabled row keeps the volume, which is
    /// what makes turning a room back on restore the level that was chosen.
    pub enabled: bool,
}

/// Where one account was when it last disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastChannel {
    /// The account.
    pub account: u64,
    /// The channel it was in.
    pub channel: u32,
    /// When it left, in milliseconds. `remember_channel_duration` is measured
    /// from here, so a migration that had nothing better to say should say the
    /// time of the migration rather than zero, which reads as "long ago" and
    /// expires the memory immediately.
    pub left_at_ms: u64,
}

/// How much of a [`Tree`] was written.
///
/// Counted rather than assumed: `--verify` compares these against what was read
/// out of murmur, and a migration nobody can check is a migration nobody can
/// trust (`docs/STORAGE.md` §4, requirement 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Written {
    /// Channels written.
    pub channels: usize,
    /// Link rows written. Both directions of a link are separate rows.
    pub links: usize,
    /// Listener rows written.
    pub listeners: usize,
    /// Remembered channels written.
    pub last_channels: usize,
}

/// Write `tree` into `store` under server instance `scope`.
///
/// Upserts every row, so an interrupted migration can simply be run again
/// (`docs/STORAGE.md` §4, requirement 3). Nothing is deleted: a target that
/// already holds channels ends up holding both sets, which is the direction that
/// loses no data and is visible in the count the caller prints.
///
/// # Errors
///
/// [`StoreError`] if the schema cannot be applied. A row that will not go in is
/// **not** an error: it is skipped, logged, and absent from [`Written`], so one
/// unreadable channel does not abandon the other four hundred half way through.
pub async fn import(store: &Store, scope: u32, tree: &Tree) -> Result<Written, StoreError> {
    store.migrate(crate::SCHEMA).await?;

    let mut written = Written::default();
    for channel in &tree.channels {
        let result = sqlx::query(
            "INSERT INTO channel (server_id, id, parent_id, name, description, position, \
                 max_users, flags, expiry_mode, expiry_duration_s, created_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, id) DO UPDATE SET \
                 parent_id = excluded.parent_id, name = excluded.name, \
                 description = excluded.description, position = excluded.position, \
                 max_users = excluded.max_users, flags = excluded.flags, \
                 expiry_mode = excluded.expiry_mode, \
                 expiry_duration_s = excluded.expiry_duration_s, \
                 created_at_ms = excluded.created_at_ms",
        )
        .bind(i64::from(scope))
        .bind(i64::from(channel.id))
        .bind(channel.parent.map(i64::from))
        .bind(&channel.name)
        .bind(&channel.description)
        .bind(i64::from(channel.position))
        .bind(i64::from(channel.max_users))
        .bind(i64::from(channel.flags))
        .bind(i64::from(channel.expiry_mode))
        .bind(i64::from(channel.expiry_duration_s))
        .bind(channel.created_at_ms as i64)
        .execute(store.pool())
        .await;
        match result {
            Ok(_) => written.channels += 1,
            Err(error) => {
                tracing::error!(%error, channel = channel.id, "a channel could not be imported");
            }
        }
    }

    for (channel, linked) in &tree.links {
        let result = sqlx::query(
            "INSERT INTO channel_link (server_id, channel_id, linked_id) VALUES (?, ?, ?) \
             ON CONFLICT (server_id, channel_id, linked_id) DO NOTHING",
        )
        .bind(i64::from(scope))
        .bind(i64::from(*channel))
        .bind(i64::from(*linked))
        .execute(store.pool())
        .await;
        match result {
            Ok(_) => written.links += 1,
            Err(error) => tracing::error!(%error, channel, linked, "a link could not be imported"),
        }
    }

    for listener in &tree.listeners {
        let result = sqlx::query(
            "INSERT INTO channel_listener \
                 (server_id, account_id, channel_id, volume_adjustment, enabled) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, account_id, channel_id) DO UPDATE SET \
                 volume_adjustment = excluded.volume_adjustment, enabled = excluded.enabled",
        )
        .bind(i64::from(scope))
        .bind(listener.account as i64)
        .bind(i64::from(listener.channel))
        .bind(f64::from(listener.volume))
        .bind(i64::from(listener.enabled))
        .execute(store.pool())
        .await;
        match result {
            Ok(_) => written.listeners += 1,
            Err(error) => tracing::error!(
                %error,
                account = listener.account,
                channel = listener.channel,
                "a channel listener could not be imported"
            ),
        }
    }

    for last in &tree.last_channels {
        let result = sqlx::query(
            "INSERT INTO last_channel (server_id, account_id, channel_id, left_at_ms) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (server_id, account_id) DO UPDATE SET \
                 channel_id = excluded.channel_id, left_at_ms = excluded.left_at_ms",
        )
        .bind(i64::from(scope))
        .bind(last.account as i64)
        .bind(i64::from(last.channel))
        .bind(last.left_at_ms as i64)
        .execute(store.pool())
        .await;
        match result {
            Ok(_) => written.last_channels += 1,
            Err(error) => tracing::error!(
                %error,
                account = last.account,
                "a remembered channel could not be imported"
            ),
        }
    }

    Ok(written)
}

/// How many channels and links `scope` holds, for `--verify`.
///
/// Read back through a fresh query rather than reported from the write, because
/// what the caller wants to know is what is *in the database*, and a count
/// returned by the code that did the writing cannot answer that.
///
/// # Errors
///
/// [`StoreError::Query`] if the tables cannot be read.
pub async fn count(store: &Store, scope: u32) -> Result<(usize, usize), StoreError> {
    let channels = count_rows(store, "channel", scope).await?;
    let links = count_rows(store, "channel_link", scope).await?;
    Ok((channels, links))
}

async fn count_rows(store: &Store, table: &str, scope: u32) -> Result<usize, StoreError> {
    use sqlx::Row as _;
    // `AssertSqlSafe` because the only interpolation is a table name from the
    // two literals above; nothing from outside this crate reaches it.
    let sql = format!("SELECT COUNT(*) AS n FROM {table} WHERE server_id = ?");
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(i64::from(scope))
        .fetch_one(store.pool())
        .await
        .map_err(|error| StoreError::Query(format!("counting {table}: {error}")))?;
    Ok(row.try_get::<i64, _>("n").unwrap_or_default().max(0) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_actor::Trees;

    async fn store() -> Store {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        Store::open(
            &format!("sqlite:file:metadata-import-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("an in-memory database")
    }

    fn channel(id: u32, parent: Option<u32>, name: &str) -> Channel {
        Channel {
            id,
            parent,
            name: name.to_owned(),
            ..Channel::default()
        }
    }

    #[tokio::test]
    async fn an_imported_tree_is_the_tree_the_server_boots() {
        // The check that matters: `Trees::load` is what a real start runs, so
        // an import that wrote rows this cannot read would look like a success
        // and produce an empty server.
        let store = store().await;
        let tree = Tree {
            channels: vec![
                channel(0, None, "Root"),
                Channel {
                    description: "a room".to_owned(),
                    position: 3,
                    max_users: 10,
                    ..channel(1, Some(0), "Lobby")
                },
            ],
            links: vec![(0, 1), (1, 0)],
            ..Tree::default()
        };
        let written = import(&store, 1, &tree).await.expect("import");
        assert_eq!(written.channels, 2);
        assert_eq!(written.links, 2);

        let trees = Trees::new(&[1], "Root");
        trees.load(&store).await;
        assert!(
            trees.exists(1, 1),
            "the imported channel is not in the tree"
        );
    }

    #[tokio::test]
    async fn importing_twice_leaves_one_of_each_row() {
        // An interrupted migration has to be runnable again
        // (`docs/STORAGE.md` §4, requirement 3).
        let store = store().await;
        let tree = Tree {
            channels: vec![channel(0, None, "Root"), channel(1, Some(0), "Lobby")],
            links: vec![(0, 1)],
            listeners: vec![Listener {
                account: 7,
                channel: 1,
                volume: 0.5,
                enabled: true,
            }],
            last_channels: vec![LastChannel {
                account: 7,
                channel: 1,
                left_at_ms: 1_700_000_000_000,
            }],
        };
        let _ = import(&store, 1, &tree).await.expect("first");
        let _ = import(&store, 1, &tree).await.expect("second");

        assert_eq!(count(&store, 1).await.expect("count"), (2, 1));
    }

    #[tokio::test]
    async fn two_server_instances_do_not_share_a_tree() {
        // murmur is multi-tenant in the same way Starling is, and an import that
        // lost the distinction would merge two servers into one.
        let store = store().await;
        let tree = Tree {
            channels: vec![channel(0, None, "Root"), channel(1, Some(0), "Lobby")],
            ..Tree::default()
        };
        let _ = import(&store, 1, &tree).await.expect("one");
        let _ = import(&store, 2, &tree).await.expect("two");
        assert_eq!(count(&store, 1).await.expect("count").0, 2);
        assert_eq!(count(&store, 2).await.expect("count").0, 2);
    }
}
