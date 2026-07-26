//! Access-control entries and the groups they name.

use async_trait::async_trait;
use sqlx::Row;
use starling_api::{
    AclRepository, AclTarget, StoreError, StoredAcl, StoredGroup, StoredGroupMember,
};
use starling_model::{ChannelId, UserId};

use crate::backend::{Backend, wrap};
use crate::repo::{Scoped, bool_from, cell, u32_from};

/// ACL and group persistence for one virtual server.
#[derive(Debug)]
pub(crate) struct Acls(Scoped);

impl Acls {
    /// Bind to a backend and a virtual server.
    #[must_use]
    pub(crate) fn new(backend: Backend, server_id: i64) -> Self {
        Self(Scoped::new(backend, server_id))
    }
}

#[async_trait]
impl AclRepository for Acls {
    async fn for_channel(&self, channel: ChannelId) -> Result<Vec<StoredAcl>, StoreError> {
        // Ordered by priority *and* then by insertion id, so two entries with
        // the same priority resolve the same way on every read. Without the
        // tiebreak the order is whatever the backend happens to return, and two
        // backends would grant different permissions from identical data.
        let sql = self.0.sql(
            "SELECT priority, target_user_id, target_group, apply_in_current, apply_in_sub,
                    granted, revoked
             FROM acl_entries
             WHERE server_id = {1} AND channel_id = {2}
             ORDER BY priority, entry_id",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(channel.0))
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading ACL entries", e))?;

        rows.iter()
            .map(|row| {
                let user: Option<i64> = row.try_get("target_user_id").map_err(|e| cell(&e))?;
                let group: Option<String> = row.try_get("target_group").map_err(|e| cell(&e))?;

                // The schema's CHECK guarantees exactly one, so a row with
                // neither means the constraint was bypassed — by a migration, or
                // by another tool writing to the same database.
                let target = match (user, group) {
                    (Some(id), None) => AclTarget::User(UserId(u32_from(id)?)),
                    (None, Some(name)) => AclTarget::Group(name),
                    _ => {
                        return Err(StoreError::Corrupt(
                            "an ACL entry names neither exactly one user nor exactly one group"
                                .to_owned(),
                        ));
                    }
                };

                Ok(StoredAcl {
                    channel,
                    priority: i32::try_from(
                        row.try_get::<i64, _>("priority").map_err(|e| cell(&e))?,
                    )
                    .unwrap_or(0),
                    target,
                    apply_in_current: bool_from(
                        row.try_get::<i64, _>("apply_in_current")
                            .map_err(|e| cell(&e))?,
                    ),
                    apply_in_sub: bool_from(
                        row.try_get::<i64, _>("apply_in_sub")
                            .map_err(|e| cell(&e))?,
                    ),
                    granted: u32_from(row.try_get::<i64, _>("granted").map_err(|e| cell(&e))?)?,
                    revoked: u32_from(row.try_get::<i64, _>("revoked").map_err(|e| cell(&e))?)?,
                })
            })
            .collect()
    }

    async fn replace_channel(
        &self,
        channel: ChannelId,
        entries: &[StoredAcl],
    ) -> Result<(), StoreError> {
        // In one transaction. Half-applied ACLs are not a degraded state, they
        // are an arbitrary permission set — quite possibly one that locks every
        // user out of the channel.
        let mut tx = self
            .0
            .pool()
            .begin()
            .await
            .map_err(|e| wrap("beginning an ACL replacement", e))?;

        let clear = self
            .0
            .sql("DELETE FROM acl_entries WHERE server_id = {1} AND channel_id = {2}");
        let _ = sqlx::query(&clear)
            .bind(self.0.server_id())
            .bind(i64::from(channel.0))
            .execute(&mut *tx)
            .await
            .map_err(|e| wrap("clearing ACL entries", e))?;

        let insert = self.0.sql(
            "INSERT INTO acl_entries
                (server_id, channel_id, priority, target_user_id, target_group,
                 apply_in_current, apply_in_sub, granted, revoked)
             VALUES ({1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9})",
        );
        for entry in entries {
            let (user, group) = match &entry.target {
                AclTarget::User(id) => (Some(i64::from(id.0)), None),
                AclTarget::Group(name) => (None, Some(name.as_str())),
            };
            let _ = sqlx::query(&insert)
                .bind(self.0.server_id())
                .bind(i64::from(channel.0))
                .bind(i64::from(entry.priority))
                .bind(user)
                .bind(group)
                .bind(i64::from(entry.apply_in_current))
                .bind(i64::from(entry.apply_in_sub))
                .bind(i64::from(entry.granted))
                .bind(i64::from(entry.revoked))
                .execute(&mut *tx)
                .await
                .map_err(|e| wrap("inserting an ACL entry", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| wrap("committing an ACL replacement", e))
    }

    async fn groups(&self, channel: ChannelId) -> Result<Vec<StoredGroup>, StoreError> {
        let sql = self.0.sql(
            "SELECT group_id, name, inherit, inheritable
             FROM groups WHERE server_id = {1} AND channel_id = {2} ORDER BY group_id",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(i64::from(channel.0))
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading groups", e))?;

        rows.iter()
            .map(|row| {
                Ok(StoredGroup {
                    id: row.try_get("group_id").map_err(|e| cell(&e))?,
                    channel,
                    name: row.try_get("name").map_err(|e| cell(&e))?,
                    inherit: bool_from(row.try_get::<i64, _>("inherit").map_err(|e| cell(&e))?),
                    inheritable: bool_from(
                        row.try_get::<i64, _>("inheritable").map_err(|e| cell(&e))?,
                    ),
                })
            })
            .collect()
    }

    async fn save_group(&self, group: &StoredGroup) -> Result<i64, StoreError> {
        if group.id == 0 {
            // New. The id comes back from the database rather than being chosen
            // here, because two callers choosing concurrently would collide.
            let sql = self.0.sql(
                "INSERT INTO groups (server_id, channel_id, name, inherit, inheritable)
                 VALUES ({1}, {2}, {3}, {4}, {5})",
            );
            let _ = sqlx::query(&sql)
                .bind(self.0.server_id())
                .bind(i64::from(group.channel.0))
                .bind(&group.name)
                .bind(i64::from(group.inherit))
                .bind(i64::from(group.inheritable))
                .execute(self.0.pool())
                .await
                .map_err(|e| wrap("creating a group", e))?;

            // Read it back by its natural key rather than using
            // `last_insert_id`, which `Any` does not expose uniformly across the
            // three backends.
            let find = self.0.sql(
                "SELECT group_id FROM groups
                 WHERE server_id = {1} AND channel_id = {2} AND name = {3}
                 ORDER BY group_id DESC",
            );
            let row = sqlx::query(&find)
                .bind(self.0.server_id())
                .bind(i64::from(group.channel.0))
                .bind(&group.name)
                .fetch_one(self.0.pool())
                .await
                .map_err(|e| wrap("reading back a new group", e))?;
            return row.try_get("group_id").map_err(|e| cell(&e));
        }

        let sql = self.0.sql(
            "UPDATE groups SET name = {3}, inherit = {4}, inheritable = {5}
             WHERE server_id = {1} AND group_id = {2}",
        );
        let _ = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(group.id)
            .bind(&group.name)
            .bind(i64::from(group.inherit))
            .bind(i64::from(group.inheritable))
            .execute(self.0.pool())
            .await
            .map_err(|e| wrap("updating a group", e))?;
        Ok(group.id)
    }

    async fn remove_group(&self, id: i64) -> Result<(), StoreError> {
        let mut tx = self
            .0
            .pool()
            .begin()
            .await
            .map_err(|e| wrap("beginning a group removal", e))?;

        // Memberships are keyed by group but have no foreign key to it: the
        // group table's primary key is the database-assigned id alone, and a
        // composite reference would have to carry the channel too. One extra
        // statement here is cheaper than that.
        for statement in [
            "DELETE FROM group_members WHERE server_id = {1} AND group_id = {2}",
            "DELETE FROM groups WHERE server_id = {1} AND group_id = {2}",
        ] {
            let _ = sqlx::query(&self.0.sql(statement))
                .bind(self.0.server_id())
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|e| wrap("removing a group", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| wrap("committing a group removal", e))
    }

    async fn members(&self, group: i64) -> Result<Vec<StoredGroupMember>, StoreError> {
        let sql = self.0.sql(
            "SELECT user_id, add_member FROM group_members
             WHERE server_id = {1} AND group_id = {2} ORDER BY user_id",
        );
        let rows = sqlx::query(&sql)
            .bind(self.0.server_id())
            .bind(group)
            .fetch_all(self.0.pool())
            .await
            .map_err(|e| wrap("reading group members", e))?;

        rows.iter()
            .map(|row| {
                Ok(StoredGroupMember {
                    group,
                    user: UserId(u32_from(
                        row.try_get::<i64, _>("user_id").map_err(|e| cell(&e))?,
                    )?),
                    add: bool_from(row.try_get::<i64, _>("add_member").map_err(|e| cell(&e))?),
                })
            })
            .collect()
    }

    async fn replace_members(
        &self,
        group: i64,
        members: &[StoredGroupMember],
    ) -> Result<(), StoreError> {
        let mut tx = self
            .0
            .pool()
            .begin()
            .await
            .map_err(|e| wrap("beginning a membership replacement", e))?;

        let clear = self
            .0
            .sql("DELETE FROM group_members WHERE server_id = {1} AND group_id = {2}");
        let _ = sqlx::query(&clear)
            .bind(self.0.server_id())
            .bind(group)
            .execute(&mut *tx)
            .await
            .map_err(|e| wrap("clearing group members", e))?;

        let insert = self.0.sql(
            "INSERT INTO group_members (server_id, group_id, user_id, add_member)
             VALUES ({1}, {2}, {3}, {4})",
        );
        for member in members {
            let _ = sqlx::query(&insert)
                .bind(self.0.server_id())
                .bind(group)
                .bind(i64::from(member.user.0))
                .bind(i64::from(member.add))
                .execute(&mut *tx)
                .await
                .map_err(|e| wrap("inserting a group member", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| wrap("committing a membership replacement", e))
    }
}
