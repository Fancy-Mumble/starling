//! The repository that persists nothing (Null Object).
//!
//! One type implementing every repository trait, so a server configured without
//! a database still has something to call. Reads come back empty and writes
//! succeed without storing.
//!
//! That is a legitimate way to run rather than a failure mode — murmur's
//! in-memory mode is the same — and it keeps `Option<Box<dyn Store>>` out of
//! every consumer, which would otherwise put an `if let` in front of every
//! persistence call in the server.

use async_trait::async_trait;
use starling_api::{
    AclRepository, BanRepository, ChannelRepository, ConfigRepository, LogRepository, StoreError,
    StoredAcl, StoredBan, StoredChannel, StoredGroup, StoredGroupMember, StoredListener,
    StoredUser, UserRepository,
};
use starling_model::{ChannelId, UserId};

/// Persists nothing, successfully.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Nothing;

#[async_trait]
impl ChannelRepository for Nothing {
    async fn all(&self) -> Result<Vec<StoredChannel>, StoreError> {
        Ok(Vec::new())
    }

    async fn save(&self, _channel: &StoredChannel) -> Result<(), StoreError> {
        Ok(())
    }

    async fn remove(&self, _id: ChannelId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn links(&self) -> Result<Vec<(ChannelId, ChannelId)>, StoreError> {
        Ok(Vec::new())
    }

    async fn link(&self, _one: ChannelId, _other: ChannelId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn unlink(&self, _one: ChannelId, _other: ChannelId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn listeners(&self) -> Result<Vec<StoredListener>, StoreError> {
        Ok(Vec::new())
    }

    async fn add_listener(&self, _listener: StoredListener) -> Result<(), StoreError> {
        Ok(())
    }

    async fn remove_listener(&self, _user: UserId, _channel: ChannelId) -> Result<(), StoreError> {
        Ok(())
    }
}

#[async_trait]
impl UserRepository for Nothing {
    async fn all(&self) -> Result<Vec<StoredUser>, StoreError> {
        Ok(Vec::new())
    }

    async fn by_name(&self, _name: &str) -> Result<Option<StoredUser>, StoreError> {
        Ok(None)
    }

    async fn by_id(&self, _id: UserId) -> Result<Option<StoredUser>, StoreError> {
        Ok(None)
    }

    async fn by_cert_hash(&self, _hash: &str) -> Result<Option<StoredUser>, StoreError> {
        Ok(None)
    }

    async fn save(&self, _user: &StoredUser) -> Result<(), StoreError> {
        Ok(())
    }

    async fn remove(&self, _id: UserId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn next_id(&self) -> Result<UserId, StoreError> {
        // `1` rather than `0`: SuperUser is 0, and handing it out would make an
        // ordinary registration an administrator on a server that happens to
        // have no database.
        Ok(UserId(1))
    }

    async fn properties(&self, _id: UserId) -> Result<Vec<(String, String)>, StoreError> {
        Ok(Vec::new())
    }

    async fn set_property(&self, _id: UserId, _key: &str, _value: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

#[async_trait]
impl AclRepository for Nothing {
    async fn for_channel(&self, _channel: ChannelId) -> Result<Vec<StoredAcl>, StoreError> {
        Ok(Vec::new())
    }

    async fn replace_channel(
        &self,
        _channel: ChannelId,
        _entries: &[StoredAcl],
    ) -> Result<(), StoreError> {
        Ok(())
    }

    async fn groups(&self, _channel: ChannelId) -> Result<Vec<StoredGroup>, StoreError> {
        Ok(Vec::new())
    }

    async fn save_group(&self, group: &StoredGroup) -> Result<i64, StoreError> {
        // Its own id back, so a caller that saves and then reads is at least
        // self-consistent within one process.
        Ok(group.id)
    }

    async fn remove_group(&self, _id: i64) -> Result<(), StoreError> {
        Ok(())
    }

    async fn members(&self, _group: i64) -> Result<Vec<StoredGroupMember>, StoreError> {
        Ok(Vec::new())
    }

    async fn replace_members(
        &self,
        _group: i64,
        _members: &[StoredGroupMember],
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

#[async_trait]
impl BanRepository for Nothing {
    async fn all(&self) -> Result<Vec<StoredBan>, StoreError> {
        Ok(Vec::new())
    }

    async fn replace_all(&self, _bans: &[StoredBan]) -> Result<(), StoreError> {
        Ok(())
    }

    async fn prune_expired(&self, _now: i64) -> Result<u64, StoreError> {
        Ok(0)
    }
}

#[async_trait]
impl ConfigRepository for Nothing {
    async fn get(&self, _key: &str) -> Result<Option<String>, StoreError> {
        Ok(None)
    }

    async fn all(&self) -> Result<Vec<(String, String)>, StoreError> {
        Ok(Vec::new())
    }

    async fn set(&self, _key: &str, _value: &str) -> Result<(), StoreError> {
        Ok(())
    }

    async fn clear(&self, _key: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

#[async_trait]
impl LogRepository for Nothing {
    async fn append(&self, _at: i64, _message: &str) -> Result<(), StoreError> {
        Ok(())
    }

    async fn recent(&self, _limit: u32) -> Result<Vec<(i64, String)>, StoreError> {
        Ok(Vec::new())
    }

    async fn prune(&self, _before: i64) -> Result<u64, StoreError> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_succeed_and_read_back_as_absent() {
        // The contract of a null object: never fails, never remembers. A caller
        // that treated a successful write as proof of storage would be wrong
        // here — and equally wrong against a database that lost the row.
        let nothing = Nothing;
        ConfigRepository::set(&nothing, "key", "value")
            .await
            .expect("write");
        assert_eq!(
            ConfigRepository::get(&nothing, "key").await.expect("read"),
            None
        );
    }

    #[tokio::test]
    async fn superuser_is_never_handed_out() {
        // Account 0 is SuperUser. Allocating it to an ordinary registration
        // would make that user an administrator.
        assert_eq!(
            UserRepository::next_id(&Nothing).await.expect("id"),
            UserId(1)
        );
    }
}
