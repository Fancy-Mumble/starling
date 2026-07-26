//! Channels, their links and their listeners.

use async_trait::async_trait;
use sqlx::Row;
use starling_api::{ChannelRepository, StoreError, StoredChannel, StoredListener};
use starling_model::{ChannelId, UserId};

use crate::backend::{Backend, wrap};
use crate::repo::{Scoped, bool_from, cell, u32_from};

/// Channel persistence for one virtual server.
#[derive(Debug)]
pub(crate) struct Channels(Scoped);

impl Channels {
    /// Bind to a backend and a virtual server.
    #[must_use]
    pub(crate) fn new(backend: Backend, server_id: i64) -> Self {
        Self(Scoped::new(backend, server_id))
    }

    /// Order a link pair canonically.
    ///
    /// The schema's `CHECK (low_id < high_id)` makes this mandatory rather than
    /// tidy: a reversed pair is refused outright, which is the point — it is
    /// what stops one link being stored twice and `unlink` removing only half.
    const fn ordered(one: ChannelId, other: ChannelId) -> (i64, i64) {
        if one.0 <= other.0 {
            (one.0 as i64, other.0 as i64)
        } else {
            (other.0 as i64, one.0 as i64)
        }
    }
}

#[async_trait]
impl ChannelRepository for Channels {
    async fn all(&self) -> Result<Vec<StoredChannel>, StoreError> {
        let sql = self.0.sql(
            "SELECT channel_id, parent_id, name, inherit_acl, description, position, max_users
             FROM channels WHERE server_id = {1}",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading channels", e))?;

        rows.iter()
            .map(|row| {
                Ok(StoredChannel {
                    id: ChannelId(u32_from(
                        row.try_get::<i64, _>("channel_id").map_err(|e| cell(&e))?,
                    )?),
                    // A NULL parent is the root, not an error.
                    parent: row
                        .try_get::<Option<i64>, _>("parent_id")
                        .map_err(|e| cell(&e))?
                        .map(|id| u32_from(id).map(ChannelId))
                        .transpose()?,
                    name: row.try_get("name").map_err(|e| cell(&e))?,
                    inherit_acl: bool_from(
                        row.try_get::<i64, _>("inherit_acl").map_err(|e| cell(&e))?,
                    ),
                    description: row.try_get("description").map_err(|e| cell(&e))?,
                    position: i32::try_from(
                        row.try_get::<i64, _>("position").map_err(|e| cell(&e))?,
                    )
                    .unwrap_or(0),
                    max_users: i32::try_from(
                        row.try_get::<i64, _>("max_users").map_err(|e| cell(&e))?,
                    )
                    .unwrap_or(0),
                })
            })
            .collect()
    }

    async fn save(&self, channel: &StoredChannel) -> Result<(), StoreError> {
        let sql = self.0.upsert(
            "INSERT INTO channels
                (server_id, channel_id, parent_id, name, inherit_acl, description, position, max_users)
             VALUES ({1}, {2}, {3}, {4}, {5}, {6}, {7}, {8})",
            &["server_id", "channel_id"],
            &[
                "parent_id",
                "name",
                "inherit_acl",
                "description",
                "position",
                "max_users",
            ],
        );

        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(channel.id.0))
            .bind(channel.parent.map(|p| i64::from(p.0)))
            .bind(&channel.name)
            .bind(i64::from(channel.inherit_acl))
            .bind(&channel.description)
            .bind(i64::from(channel.position))
            .bind(i64::from(channel.max_users))
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("saving a channel", e))?;
        Ok(())
    }

    async fn remove(&self, id: ChannelId) -> Result<(), StoreError> {
        // One statement. The ACLs, groups, links, listeners and any child
        // channels go with it through `ON DELETE CASCADE` — murmur writes each
        // of those out by hand at every call site that removes a channel.
        let sql = self
            .0
            .sql("DELETE FROM channels WHERE server_id = {1} AND channel_id = {2}");
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(id.0))
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("removing a channel", e))?;
        Ok(())
    }

    async fn links(&self) -> Result<Vec<(ChannelId, ChannelId)>, StoreError> {
        let sql = self
            .0
            .sql("SELECT low_id, high_id FROM channel_links WHERE server_id = {1}");
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading channel links", e))?;

        rows.iter()
            .map(|row| {
                Ok((
                    ChannelId(u32_from(
                        row.try_get::<i64, _>("low_id").map_err(|e| cell(&e))?,
                    )?),
                    ChannelId(u32_from(
                        row.try_get::<i64, _>("high_id").map_err(|e| cell(&e))?,
                    )?),
                ))
            })
            .collect()
    }

    async fn link(&self, one: ChannelId, other: ChannelId) -> Result<(), StoreError> {
        if one == other {
            // A channel linked to itself is already reachable from itself, and
            // the schema's `CHECK (low < high)` would refuse the row anyway.
            return Ok(());
        }
        let (low, high) = Self::ordered(one, other);
        let sql = self.0.upsert(
            "INSERT INTO channel_links (server_id, low_id, high_id) VALUES ({1}, {2}, {3})",
            &["server_id", "low_id", "high_id"],
            // Nothing to update: the key is the whole row. The upsert form is
            // what makes re-linking an existing pair a no-op rather than an
            // error, which the contract promises.
            &["low_id"],
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(low)
            .bind(high)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("linking channels", e))?;
        Ok(())
    }

    async fn unlink(&self, one: ChannelId, other: ChannelId) -> Result<(), StoreError> {
        let (low, high) = Self::ordered(one, other);
        let sql = self.0.sql(
            "DELETE FROM channel_links WHERE server_id = {1} AND low_id = {2} AND high_id = {3}",
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(low)
            .bind(high)
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("unlinking channels", e))?;
        Ok(())
    }

    async fn listeners(&self) -> Result<Vec<StoredListener>, StoreError> {
        let sql = self.0.sql(
            "SELECT user_id, channel_id, volume_adjustment
             FROM channel_listeners WHERE server_id = {1}",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading channel listeners", e))?;

        rows.iter()
            .map(|row| {
                Ok(StoredListener {
                    user: UserId(u32_from(
                        row.try_get::<i64, _>("user_id").map_err(|e| cell(&e))?,
                    )?),
                    channel: ChannelId(u32_from(
                        row.try_get::<i64, _>("channel_id").map_err(|e| cell(&e))?,
                    )?),
                    volume_adjustment: i32::try_from(
                        row.try_get::<i64, _>("volume_adjustment")
                            .map_err(|e| cell(&e))?,
                    )
                    .unwrap_or(0),
                })
            })
            .collect()
    }

    async fn add_listener(&self, listener: StoredListener) -> Result<(), StoreError> {
        let sql = self.0.upsert(
            "INSERT INTO channel_listeners (server_id, user_id, channel_id, volume_adjustment)
             VALUES ({1}, {2}, {3}, {4})",
            &["server_id", "user_id", "channel_id"],
            &["volume_adjustment"],
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(listener.user.0))
            .bind(i64::from(listener.channel.0))
            .bind(i64::from(listener.volume_adjustment))
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("adding a channel listener", e))?;
        Ok(())
    }

    async fn remove_listener(&self, user: UserId, channel: ChannelId) -> Result<(), StoreError> {
        let sql = self.0.sql(
            "DELETE FROM channel_listeners
             WHERE server_id = {1} AND user_id = {2} AND channel_id = {3}",
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(user.0))
            .bind(i64::from(channel.0))
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("removing a channel listener", e))?;
        Ok(())
    }
}
