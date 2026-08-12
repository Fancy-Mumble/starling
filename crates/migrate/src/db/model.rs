//! What a murmur database says, in murmur's own terms.
//!
//! Deliberately **not** Starling types. This half of the migration knows only
//! how upstream stores things; the mapping into a channel tree, an account, an
//! ACL set or a settings snapshot is the caller's, and each of those belongs to
//! the service that owns the table it lands in (`docs/STORAGE.md` §1). Keeping
//! the two apart is what lets the reader be tested against a murmur database
//! with no Starling database in sight.
//!
//! Every field here is a value murmur actually stores. Where upstream spreads
//! one idea over several columns -- a password over `password_hash`, `salt` and
//! `kdf_iterations`, a group specification over five -- it is reassembled into
//! the one shape that carries the whole meaning, because a caller handed the
//! parts would have to know murmur's rules to put them back together, and that
//! knowledge is this crate's job.

use std::collections::BTreeMap;

/// One virtual server, and everything stored against it.
///
/// murmur is multi-tenant in the same way Starling is, one `server_id` per
/// virtual server, so this is the unit a migration moves. Nothing here is
/// server-wide: even `config` is per-instance in murmur's schema.
#[derive(Debug, Clone, Default)]
pub struct Server {
    /// murmur's `server_id`.
    pub id: u32,
    /// The `config` table, verbatim.
    ///
    /// Keys are murmur's `.ini` spellings, because they are the same names: the
    /// database table overrides the file key for key. That is why
    /// [`crate::Ini::from_pairs`] exists, the same reader maps both.
    pub config: BTreeMap<String, String>,
    /// The channel tree, parents before children where murmur stored it that
    /// way; nothing here depends on the order.
    pub channels: Vec<Channel>,
    /// Linked channel pairs, as stored: one row per direction murmur wrote.
    pub links: Vec<Link>,
    /// Registered accounts.
    pub users: Vec<User>,
    /// ACL entries, in murmur's `priority` order within a channel.
    pub acls: Vec<Acl>,
    /// Named groups.
    pub groups: Vec<Group>,
    /// Who is in, or explicitly out of, each group.
    pub members: Vec<GroupMember>,
    /// Channel listeners, which upstream only has from schema v9 on.
    pub listeners: Vec<Listener>,
    /// The ban list.
    pub bans: Vec<Ban>,
}

/// One channel.
///
/// The properties murmur keeps in `channel_properties` (`channel_info` before
/// schema v10) are folded in as typed fields, which is the entity-attribute-value
/// unwinding `docs/STORAGE.md` L1 describes. A property row whose text will not
/// parse as its type is reported and the field keeps its default, never silently
/// zeroed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Channel {
    /// murmur's `channel_id`. `0` is the root.
    pub id: u32,
    /// The parent, or `None` for the root and for the Fancy fork's *detached*
    /// channels.
    ///
    /// murmur stores both as self-parents (`parent_id == channel_id`) since
    /// schema v10 and the root as `NULL` before it; both spellings arrive here
    /// as `None`, because "has no parent" is the thing the tree needs to know.
    /// Which of the two this is, is [`Self::detached`].
    pub parent: Option<u32>,
    /// Whether this is a *detached* channel rather than the root.
    ///
    /// Both are parentless, and a consumer that cannot tell them apart draws
    /// every meeting room and friend chat as a second root. murmur says which is
    /// which by the id: the root is 0 and everything else that is self-parented
    /// is detached (`ChannelTable::getDetachedChannelIds`).
    pub detached: bool,
    /// Display name.
    pub name: String,
    /// Whether the channel inherits its parent's ACL entries.
    pub inherit_acl: bool,
    /// `ChannelProperty::Description`, possibly HTML.
    pub description: String,
    /// `ChannelProperty::Position`.
    pub position: i32,
    /// `ChannelProperty::MaxUsers`, `0` for no limit.
    pub max_users: u32,
    /// `ChannelProperty::Hidden`, a Fancy fork property absent upstream.
    pub hidden: bool,
    /// `ChannelProperty::Structural`, likewise.
    pub structural: bool,
    /// `ChannelProperty::ExpiryMode`.
    pub expiry_mode: u32,
    /// `ChannelProperty::ExpiryDuration`, in seconds.
    pub expiry_duration_s: u32,
    /// `ChannelProperty::CreatedAt`, in milliseconds, `0` when unrecorded.
    pub created_at_ms: u64,
}

/// One direction of a channel link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// The channel the link is written on.
    pub channel: u32,
    /// The channel it reaches.
    pub linked: u32,
}

/// One registered account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// murmur's `user_id`. `0` is the SuperUser, in murmur as in Starling.
    pub id: u32,
    /// The registered name.
    pub name: String,
    /// `UserProperty::Email`.
    pub email: String,
    /// `UserProperty::Comment`, the profile text other clients see.
    pub comment: String,
    /// `UserProperty::CertificateHash`, **hex** as murmur stores it.
    ///
    /// Kept as text rather than decoded here so that a value which is not hex
    /// at all can be reported against the account it came from rather than
    /// silently becoming an empty certificate, which would turn a
    /// certificate-authenticated account into a password-only one.
    pub cert_hash: String,
    /// The stored password, in whichever form murmur left it.
    pub password: Password,
    /// `UserProperty::TOTPSecret`, base32, a Fancy fork property.
    pub totp_secret: String,
    /// The raw avatar bytes, murmur's `texture` column.
    pub texture: Vec<u8>,
    /// The channel this user was last in, for `rememberchannel`.
    pub last_channel: u32,
    /// When they were last seen, in seconds since the epoch.
    pub last_active_s: u64,
    /// When they last disconnected, in seconds since the epoch.
    pub last_disconnect_s: u64,
}

/// How murmur stored a password.
///
/// Both forms are hex text in the database, and which one is in front of you is
/// decided by `kdf_iterations`: upstream reads a positive count as "PBKDF2" and
/// anything else as the pre-1.3 unsalted digest
/// (`vendor/server/src/murmur/ServerUser.cpp`, `LegacyPasswordHash.cpp`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Password {
    /// No password at all. Reached by certificate only.
    #[default]
    None,
    /// PBKDF2-HMAC-SHA384 with a recorded iteration count, murmur 1.3 and later.
    Pbkdf2 {
        /// The salt, decoded from murmur's hex.
        salt: Vec<u8>,
        /// The derived key, decoded from murmur's hex. 48 bytes.
        key: Vec<u8>,
        /// The count this key was derived with.
        iterations: u32,
    },
    /// An unsalted SHA-1 of the password, murmur before 1.3.
    Sha1 {
        /// The digest, decoded from murmur's hex. 20 bytes.
        digest: Vec<u8>,
    },
}

impl Password {
    /// Whether there is anything here to check a login against.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// One ACL entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Acl {
    /// The channel the entry is written on.
    pub channel: u32,
    /// Order within the channel. Lower is applied first.
    pub priority: i32,
    /// The account this entry is about, if it names one.
    pub user: Option<u32>,
    /// The **group specification** this entry is about, if it names one.
    ///
    /// Reassembled into murmur's own `!~#$`-prefixed text form even when the
    /// database stores it split across `affected_group_id`,
    /// `affected_meta_group_id`, `access_token` and `group_modifiers`, because
    /// the text form is the whole grammar and it is what an evaluator reads
    /// (`vendor/server/src/murmur/database/ACLCompat.cpp:getLegacyGroupData`).
    pub group: Option<String>,
    /// Whether the entry applies in the channel it is written on.
    pub apply_here: bool,
    /// Whether it applies in that channel's descendants.
    pub apply_subs: bool,
    /// The permission bits granted.
    pub grant: u32,
    /// The permission bits taken away.
    pub deny: u32,
}

/// One named group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Group {
    /// murmur's `group_id`, unique per server rather than per channel.
    pub id: i64,
    /// The channel the group is defined on.
    pub channel: u32,
    /// The name an ACL entry refers to it by.
    pub name: String,
    /// Whether it inherits members from the same-named group above it.
    pub inherit: bool,
    /// Whether channels below may inherit from it.
    pub inheritable: bool,
}

/// One group membership, or one explicit exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMember {
    /// The group's `group_id`.
    pub group: i64,
    /// The account.
    pub user: u32,
    /// `true` adds, `false` removes a member the group would otherwise inherit.
    pub add: bool,
}

/// One stored channel listener.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Listener {
    /// The account listening. Never a session: the row outlives the visit.
    pub user: u32,
    /// The channel being listened to.
    pub channel: u32,
    /// The volume factor, `1.0` for no adjustment.
    pub volume: f32,
    /// Whether the listener is currently on.
    pub enabled: bool,
}

/// One ban.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ban {
    /// The banned address as sixteen bytes, IPv4 in its v6-mapped form.
    ///
    /// murmur stores this as raw bytes before schema v10 and as text after it;
    /// both arrive here as the bytes, which is what a prefix comparison needs.
    pub address: Vec<u8>,
    /// How many leading bits of `address` the ban covers.
    pub prefix_len: u32,
    /// The name the banned user had, for the operator's benefit.
    pub name: String,
    /// The certificate hash banned, **hex** as murmur stores it.
    pub cert_hash: String,
    /// Why.
    pub reason: String,
    /// When it started, in seconds since the epoch.
    pub start_s: u64,
    /// How long it lasts, in seconds. `0` is permanent.
    pub duration_s: u32,
}

/// What could not be carried across, and what was approximated.
///
/// The `.ini` reader's rule, applied to data: *a configuration that used to mean
/// something must not quietly mean less here* (`crate::ini`). A migration whose
/// losses are invisible is a migration nobody can check, so every one of them is
/// a line here and every line is printed.
#[derive(Debug, Clone, Default)]
pub struct Report {
    notes: Vec<String>,
}

impl Report {
    /// An empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record something that was dropped or approximated.
    pub fn note(&mut self, note: impl Into<String>) {
        let note = note.into();
        tracing::warn!("{note}");
        self.notes.push(note);
    }

    /// Everything recorded, in the order it was found.
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Whether anything was lost.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_that_is_absent_says_so() {
        // The distinction decides whether an imported account can be logged
        // into by name at all, so it must not be inferable only from an empty
        // byte string.
        assert!(Password::None.is_none());
        assert!(
            !Password::Sha1 {
                digest: vec![0; 20]
            }
            .is_none()
        );
    }

    #[test]
    fn a_report_keeps_what_it_was_told_in_order() {
        let mut report = Report::new();
        assert!(report.is_empty());
        report.note("first");
        report.note("second");
        assert_eq!(report.notes(), ["first".to_owned(), "second".to_owned()]);
        assert!(!report.is_empty());
    }
}
