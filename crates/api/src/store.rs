//! What survives a restart.
//!
//! The contract only. `starling-store` implements it over sqlx against SQLite,
//! MySQL or PostgreSQL; the state service consumes it and never learns which —
//! or that SQL is involved at all.
//!
//! # What is here and what is not
//!
//! Persistence is about *registered* things: accounts, channels, ACLs, groups,
//! bans, configuration. It is not about who is connected right now. A
//! `SessionId` is recycled the moment a socket closes and appears nowhere below;
//! a [`UserId`] is an account and outlives every session it ever had.
//!
//! That split is murmur's too, and it is why persistence does not replace
//! `ChannelStore` or `UserRegistry`. Those hold the live tree and the connected
//! users. This is where the durable half is loaded from at boot and written back
//! to on change.
//!
//! # One repository per aggregate, not one `Store` with sixty methods
//!
//! [`Store`] is a facade that hands out repositories; each owns one aggregate
//! and nothing else. A single flat trait would be the same code with the seams
//! removed — and adding a table would widen an interface every consumer already
//! depends on, which is the exact ISP violation the split avoids.
//!
//! # Everything is scoped to one virtual server
//!
//! murmur runs many virtual servers in one process, and every table it has
//! carries a `server_id`. A [`Store`] here is already scoped to one, so that
//! column appears in the schema and in none of these signatures. Multiple
//! servers (P2) then means many stores, not a parameter threaded through every
//! call — which is the version that cannot be forgotten at one call site.
//!
//! # Where this deliberately differs from murmur
//!
//! Wire compatibility is a hard requirement; *storage* compatibility is not, and
//! `starling-migrate` reads the old shape when someone needs to move. Four
//! places where murmur's schema is worth improving on rather than inheriting:
//!
//! | murmur | here | why |
//! |---|---|---|
//! | `channel_properties` as string key/value | typed fields on [`StoredChannel`] | the set is fixed and known; EAV makes `position` a string to parse and impossible to sort by |
//! | ACL target as five nullable columns | [`AclTarget`], a sum type | an entry names a user *or* a group; nullable columns cannot say "exactly one" |
//! | `bans.duration = 0` means permanent | `expires_at: Option<i64>` | a magic value that reads as "expires immediately"; `NULL` reads as what it is, and indexes |
//! | deletes written out by hand | `ON DELETE CASCADE` | removing a channel must take its ACLs, properties, links and listeners; a forgotten `DELETE` leaves rows pointing at nothing |

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use starling_model::{ChannelId, UserId};

/// Why a persistence operation failed.
///
/// Deliberately coarse. A caller can retry, give up, or refuse to start, and
/// nothing finer than these three changes which of those it picks — the SQL
/// state that distinguishes a deadlock from a constraint violation belongs in
/// the log, not in a match arm at every call site.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database could not be reached, or the query failed.
    #[error("database error: {0}")]
    Backend(String),

    /// The stored data is not what the schema promises.
    ///
    /// Separate from [`Self::Backend`] because it is not transient: retrying
    /// reads the same bad row again. It usually means a migration was skipped or
    /// another tool wrote to the database.
    #[error("stored data is malformed: {0}")]
    Corrupt(String),

    /// A write conflicted with something already there.
    #[error("conflict: {0}")]
    Conflict(String),
}

/// A persisted channel.
///
/// Occupants are runtime state, and a *temporary* channel is by definition one
/// that must not survive a restart, so neither appears here.
///
/// murmur keeps everything below `name` in a string key/value table. They are a
/// fixed, known set — not something an operator extends — so they are columns
/// with types: `position` sorts, `max_users` compares, and neither has to be
/// parsed out of a string at every read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredChannel {
    /// Stable id, unique within a server.
    pub id: ChannelId,
    /// The parent, or `None` for the root.
    pub parent: Option<ChannelId>,
    /// Display name.
    pub name: String,
    /// Whether this channel inherits its parent's ACLs.
    pub inherit_acl: bool,
    /// Channel description, possibly HTML.
    pub description: String,
    /// Sort position within the parent; ties broken by name.
    pub position: i32,
    /// Occupancy limit, or `0` for the server default.
    pub max_users: i32,
}

impl StoredChannel {
    /// A channel with only the fields that have no sensible default.
    ///
    /// The four below are genuinely optional at creation, and a constructor
    /// taking seven arguments would be four opportunities to pass them in the
    /// wrong order — three of them are `i32`.
    #[must_use]
    pub fn new(id: ChannelId, parent: Option<ChannelId>, name: impl Into<String>) -> Self {
        Self {
            id,
            parent,
            name: name.into(),
            inherit_acl: true,
            description: String::new(),
            position: 0,
            max_users: 0,
        }
    }
}

/// A registered account.
///
/// The password is a hash and a salt, never a password. `kdf_iterations` is per
/// user rather than global because raising the server's cost must not invalidate
/// every account already registered under the old one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredUser {
    /// Stable account id. `0` is SuperUser, as in murmur.
    pub id: UserId,
    /// Login name.
    pub name: String,
    /// Password hash, absent for an account that authenticates by certificate.
    pub password_hash: Option<String>,
    /// Salt for the hash.
    pub salt: Option<String>,
    /// Work factor this hash was made with.
    pub kdf_iterations: Option<i64>,
    /// SHA-1 digest of the client certificate, when one is registered.
    pub cert_hash: Option<String>,
    /// Where to put them when they reconnect.
    pub last_channel: Option<ChannelId>,
    /// Seconds since the Unix epoch when they were last seen.
    pub last_active: Option<i64>,
    /// Seconds since the Unix epoch when they last disconnected.
    pub last_disconnect: Option<i64>,
}

impl StoredUser {
    /// An account with a name and nothing else decided.
    #[must_use]
    pub fn new(id: UserId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            password_hash: None,
            salt: None,
            kdf_iterations: None,
            cert_hash: None,
            last_channel: None,
            last_active: None,
            last_disconnect: None,
        }
    }
}

/// Who an access-control entry applies to.
///
/// murmur spends five nullable columns on this — `group_name`, `group_id`,
/// `aff_user_id`, `aff_group_id`, `aff_meta_group_id` — and no constraint says
/// exactly one is set. It is a sum type, so it is one here, and the schema
/// enforces the same thing with a `CHECK`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclTarget {
    /// One account.
    User(UserId),
    /// Everyone in a named group.
    ///
    /// A name rather than an id, because groups resolve *by name* through the
    /// channel tree: `admin` on a sub-channel may be a different group from
    /// `admin` on its parent, and an ACL naming the id could not inherit.
    Group(String),
}

/// One access-control entry on a channel.
///
/// Grants and revokes are separate bit sets so "explicitly denied" stays
/// distinguishable from "not mentioned" — which is the whole of how inheritance
/// resolves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAcl {
    /// The channel this entry sits on.
    pub channel: ChannelId,
    /// Evaluation order within the channel, lowest first.
    pub priority: i32,
    /// Who it applies to.
    pub target: AclTarget,
    /// Whether it applies to this channel itself.
    pub apply_in_current: bool,
    /// Whether it applies to sub-channels.
    pub apply_in_sub: bool,
    /// Permission bits granted.
    pub granted: u32,
    /// Permission bits revoked.
    pub revoked: u32,
}

/// A permission group defined on a channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGroup {
    /// Stable id within a server. `0` when not yet saved.
    pub id: i64,
    /// The channel it is defined on.
    pub channel: ChannelId,
    /// Group name, as it appears in ACLs.
    pub name: String,
    /// Whether it inherits members from the same group further up the tree.
    pub inherit: bool,
    /// Whether channels below may inherit from it.
    pub inheritable: bool,
}

/// One account's membership of one group.
///
/// `add` distinguishes the two things a membership row can mean: adding a user
/// to an inherited group, or *removing* one that inheritance would otherwise
/// have granted. Storing removal as a row rather than an absence is what lets a
/// sub-channel override its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGroupMember {
    /// The group.
    pub group: i64,
    /// The account.
    pub user: UserId,
    /// `true` to add, `false` to remove an inherited membership.
    pub add: bool,
}

/// A ban.
///
/// The address is stored with a prefix length so one row can ban a range;
/// IPv4 addresses are mapped into IPv6 so one column serves both families.
///
/// murmur stores a `duration` where `0` means permanent — a magic value that
/// reads as "expires immediately" and cannot be compared against a clock.
/// `expires_at` says what it means and lets the database do the filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBan {
    /// Base address, as text.
    pub address: String,
    /// How many leading bits of the address the ban covers.
    pub prefix_length: i32,
    /// Banned name, if the ban names one.
    pub name: Option<String>,
    /// Banned certificate digest, if the ban names one.
    pub cert_hash: Option<String>,
    /// Operator-visible reason.
    pub reason: Option<String>,
    /// Seconds since the Unix epoch when the ban started.
    pub start: i64,
    /// When it lapses, or `None` for a permanent ban.
    pub expires_at: Option<i64>,
}

impl StoredBan {
    /// Whether this ban is still in force at `now`.
    ///
    /// On the value rather than in a query, so the rule is stated once and both
    /// the store and the caller agree about what "expired" means.
    #[must_use]
    pub fn is_active_at(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|expiry| expiry > now)
    }
}

/// A user listening to a channel they are not in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredListener {
    /// The account.
    pub user: UserId,
    /// The channel they listen to.
    pub channel: ChannelId,
    /// Per-listener gain, in murmur's fixed-point hundredths.
    pub volume_adjustment: i32,
}

/// Channels, their links and their listeners.
#[async_trait]
pub trait ChannelRepository: std::fmt::Debug + Send + Sync {
    /// Every channel, in no particular order.
    ///
    /// The caller rebuilds the tree. Ordering by parent here would still not
    /// guarantee parents come first, so it does not pretend to.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn all(&self) -> Result<Vec<StoredChannel>, StoreError>;

    /// Create or replace a channel.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn save(&self, channel: &StoredChannel) -> Result<(), StoreError>;

    /// Remove a channel, and by cascade its ACLs, groups, links and listeners.
    ///
    /// Removing one that does not exist is not an error: the caller's intent is
    /// "make it absent", and it already is.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn remove(&self, id: ChannelId) -> Result<(), StoreError>;

    /// Every linked channel pair, lower id first.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn links(&self) -> Result<Vec<(ChannelId, ChannelId)>, StoreError>;

    /// Link two channels. Linking an already-linked pair is not an error.
    ///
    /// Order does not matter: links are symmetric, and the store normalises the
    /// pair so it cannot be stored twice under two orderings.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn link(&self, one: ChannelId, other: ChannelId) -> Result<(), StoreError>;

    /// Unlink two channels, in either order.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn unlink(&self, one: ChannelId, other: ChannelId) -> Result<(), StoreError>;

    /// Every stored channel listener.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn listeners(&self) -> Result<Vec<StoredListener>, StoreError>;

    /// Record that a user listens to a channel, or update their gain.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn add_listener(&self, listener: StoredListener) -> Result<(), StoreError>;

    /// Stop a user listening to a channel.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn remove_listener(&self, user: UserId, channel: ChannelId) -> Result<(), StoreError>;
}

/// Registered accounts.
#[async_trait]
pub trait UserRepository: std::fmt::Debug + Send + Sync {
    /// Every account.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn all(&self) -> Result<Vec<StoredUser>, StoreError>;

    /// Look an account up by name, case-sensitively.
    ///
    /// Case-sensitive because murmur is: it treats `Alice` and `alice` as
    /// different registrations, and matching more loosely would let one account
    /// authenticate as another.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn by_name(&self, name: &str) -> Result<Option<StoredUser>, StoreError>;

    /// Look an account up by id.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn by_id(&self, id: UserId) -> Result<Option<StoredUser>, StoreError>;

    /// Look an account up by certificate digest.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn by_cert_hash(&self, hash: &str) -> Result<Option<StoredUser>, StoreError>;

    /// Create or replace an account.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails, including a name that another account
    /// already holds.
    async fn save(&self, user: &StoredUser) -> Result<(), StoreError>;

    /// Remove an account, and by cascade its properties and memberships.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn remove(&self, id: UserId) -> Result<(), StoreError>;

    /// The next free account id.
    ///
    /// Allocated by the store rather than the caller because two callers
    /// choosing concurrently would collide, and the database is the only thing
    /// that can see both.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn next_id(&self) -> Result<UserId, StoreError>;

    /// An account's stored properties, by key.
    ///
    /// Genuinely open-ended, unlike a channel's: plugins and the Fancy surface
    /// attach their own, so this one stays key/value on purpose.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn properties(&self, id: UserId) -> Result<Vec<(String, String)>, StoreError>;

    /// Set one property, replacing any previous value.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn set_property(&self, id: UserId, key: &str, value: &str) -> Result<(), StoreError>;
}

/// Access-control entries and the groups they name.
#[async_trait]
pub trait AclRepository: std::fmt::Debug + Send + Sync {
    /// Every ACL entry on a channel, in priority order.
    ///
    /// Ordered here rather than by the caller because the order *is* the
    /// semantics: later entries override earlier ones, and a caller that sorted
    /// differently would resolve permissions differently.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn for_channel(&self, channel: ChannelId) -> Result<Vec<StoredAcl>, StoreError>;

    /// Replace every entry on a channel.
    ///
    /// Whole-channel replacement because that is how the `ACL` message arrives:
    /// a client sends the complete list, and applying it as a diff would need a
    /// stable identity per entry that the protocol does not give.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn replace_channel(
        &self,
        channel: ChannelId,
        entries: &[StoredAcl],
    ) -> Result<(), StoreError>;

    /// Every group defined on a channel.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn groups(&self, channel: ChannelId) -> Result<Vec<StoredGroup>, StoreError>;

    /// Create or replace a group, returning its id.
    ///
    /// A group with id `0` is new and is assigned one; anything else replaces.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn save_group(&self, group: &StoredGroup) -> Result<i64, StoreError>;

    /// Remove a group, and by cascade its memberships.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn remove_group(&self, id: i64) -> Result<(), StoreError>;

    /// Every membership of a group.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn members(&self, group: i64) -> Result<Vec<StoredGroupMember>, StoreError>;

    /// Replace a group's memberships.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn replace_members(
        &self,
        group: i64,
        members: &[StoredGroupMember],
    ) -> Result<(), StoreError>;
}

/// Bans.
#[async_trait]
pub trait BanRepository: std::fmt::Debug + Send + Sync {
    /// Every ban, including lapsed ones.
    ///
    /// Expiry is the caller's to evaluate through [`StoredBan::is_active_at`]:
    /// it needs a clock, and a repository that filtered by time would be
    /// untestable without controlling one.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn all(&self) -> Result<Vec<StoredBan>, StoreError>;

    /// Replace the whole ban list.
    ///
    /// Whole-list replacement because `BanList` arrives that way, exactly as
    /// with ACLs.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn replace_all(&self, bans: &[StoredBan]) -> Result<(), StoreError>;

    /// Delete bans that lapsed before `now`.
    ///
    /// Returns how many went. Permanent bans are never touched.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn prune_expired(&self, now: i64) -> Result<u64, StoreError>;
}

/// Per-server configuration that outlives the config file.
///
/// murmur keeps settings here as well as in `murmur.ini`, so an operator can
/// change them through the admin interface without editing a file. The database
/// wins where both are set.
#[async_trait]
pub trait ConfigRepository: std::fmt::Debug + Send + Sync {
    /// One setting, or `None` if it has never been set.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Every setting.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn all(&self) -> Result<Vec<(String, String)>, StoreError>;

    /// Set one setting, replacing any previous value.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;

    /// Unset one setting.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn clear(&self, key: &str) -> Result<(), StoreError>;
}

/// The operator-facing server log, kept across restarts.
#[async_trait]
pub trait LogRepository: std::fmt::Debug + Send + Sync {
    /// Append one entry, timestamped in seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn append(&self, at: i64, message: &str) -> Result<(), StoreError>;

    /// The most recent entries, newest first.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the read fails.
    async fn recent(&self, limit: u32) -> Result<Vec<(i64, String)>, StoreError>;

    /// Delete entries older than `before`.
    ///
    /// murmur's `logdays` retention. Returns how many rows went, because an
    /// operator watching a database fill up wants the number.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the write fails.
    async fn prune(&self, before: i64) -> Result<u64, StoreError>;
}

/// Everything that survives a restart, one repository at a time.
///
/// The Facade. It exists so this layer reads in one screen: what is persisted is
/// exactly the list below, and adding a table adds one line here rather than
/// widening an interface every consumer depends on.
pub trait Store: std::fmt::Debug + Send + Sync {
    /// Which backend this is, for logs and the admin surface.
    fn backend(&self) -> &'static str;

    /// Channels, their links and their listeners.
    fn channels(&self) -> &dyn ChannelRepository;

    /// Registered accounts and their properties.
    fn users(&self) -> &dyn UserRepository;

    /// Access-control entries and groups.
    fn acls(&self) -> &dyn AclRepository;

    /// Bans.
    fn bans(&self) -> &dyn BanRepository;

    /// Per-server configuration.
    fn config(&self) -> &dyn ConfigRepository;

    /// The persisted server log.
    fn log(&self) -> &dyn LogRepository;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permanent_ban_never_lapses() {
        // `None` rather than murmur's `duration = 0`, which reads as "expires
        // immediately" and is the wrong answer to the obvious comparison.
        let ban = StoredBan {
            address: "::1".into(),
            prefix_length: 128,
            name: None,
            cert_hash: None,
            reason: None,
            start: 0,
            expires_at: None,
        };
        assert!(ban.is_active_at(i64::MAX));
    }

    #[test]
    fn a_temporary_ban_lapses_at_its_expiry() {
        let ban = StoredBan {
            address: "::1".into(),
            prefix_length: 128,
            name: None,
            cert_hash: None,
            reason: None,
            start: 100,
            expires_at: Some(200),
        };
        assert!(ban.is_active_at(199));
        assert!(!ban.is_active_at(200), "a ban must lapse *at* its expiry");
        assert!(!ban.is_active_at(201));
    }

    #[test]
    fn a_new_channel_inherits_acls_by_default() {
        // The safe default: a channel that did not inherit would silently be
        // unreachable until someone gave it its own ACLs.
        let channel = StoredChannel::new(ChannelId(1), Some(ChannelId(0)), "Lobby");
        assert!(channel.inherit_acl);
        assert_eq!(channel.position, 0);
        assert_eq!(channel.max_users, 0);
    }

    #[test]
    fn a_new_account_has_no_credentials() {
        // Neither a password nor a certificate: both are set explicitly, so an
        // account cannot be created accidentally authenticatable.
        let user = StoredUser::new(UserId(7), "alice");
        assert!(user.password_hash.is_none());
        assert!(user.cert_hash.is_none());
    }
}
