//! Reading a murmur database, whichever schema it is on.
//!
//! `docs/STORAGE.md` §4 states the requirements, and the first one shapes
//! everything else: **non-destructive**. This opens murmur's database read-only
//! where the backend can be told to (`?mode=ro` on SQLite) and issues nothing
//! but `SELECT`s where it cannot. The old server keeps working, which is what
//! makes moving to a greenfield schema a decision an operator can undo.
//!
//! # Two schemas, because both are in the wild
//!
//! murmur rewrote its storage layer for 1.5: `acl` became
//! `access_control_lists`, `channel_info` became `channel_properties`, group
//! specifications were split from one string into five columns, dates became
//! epoch seconds and the ban address became text. Upstream migrates a database
//! in place on first start, so an operator who has run 1.5 has the new shape and
//! one who never did has the old one, and neither of them thinks of their
//! database as "a schema version".
//!
//! So the layout is **detected** rather than asked for ([`Layout`]), and the
//! reader speaks both. The mapping between them is not guessed: it is upstream's
//! own migration, `migrate()` on each table in
//! `vendor/server/src/murmur/database/`, which is the one description of the two
//! schemas that has to be right.
//!
//! # What this deliberately does not know
//!
//! Anything about Starling. The output is [`Server`], murmur's data in murmur's
//! terms; turning that into channels, accounts, ACL sets and settings is the
//! caller's job, because each of those lands in a different service's database
//! and each service owns its own schema (`docs/STORAGE.md` §1). A reader that
//! knew both halves would be the one place in the tree that had to be edited
//! whenever either changed.

mod model;
mod rows;

pub use model::{
    Acl, Ban, Channel, Group, GroupMember, Link, Listener, Password, Report, Server, User,
};

use std::collections::BTreeMap;

use starling_runtime::storage::{Backend, Dialect, SqlDialect as _};

use rows::{blob, epoch_seconds, flag, from_hex, int, int_or, real, text, text_or_empty, u32_or};

/// Why a murmur database could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The database could not be opened.
    #[error("{0}")]
    Open(String),
    /// Neither schema was recognised.
    ///
    /// Named rather than guessed at: reading a database that is not murmur's
    /// would produce an import that looks like it worked and is empty.
    #[error(
        "{url} does not look like a murmur database: \
         neither `virtual_servers` (Mumble 1.5 and later) nor `{prefix}servers` \
         (Mumble 1.4 and earlier) is there"
    )]
    NotMurmur {
        /// What was opened.
        url: String,
        /// The table prefix that was looked for.
        prefix: String,
    },
    /// A statement failed.
    #[error("{0}")]
    Query(String),
    /// The table prefix was not something that can name a table.
    #[error(
        "the table prefix {0:?} may only contain letters, digits and underscores; \
         it names a table, and anything else is a way to write SQL rather than a prefix"
    )]
    BadPrefix(String),
}

/// Which schema a murmur database is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Mumble 1.5 and later: `virtual_servers`, `access_control_lists`,
    /// `channel_properties`, epoch seconds, textual ban addresses.
    Modern,
    /// Mumble 1.4 and earlier: `servers`, `acl`, `channel_info`, native dates,
    /// binary ban addresses, and a configurable table prefix.
    Legacy,
}

impl Layout {
    /// The name this reads as in a report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Modern => "Mumble 1.5 or later",
            Self::Legacy => "Mumble 1.4 or earlier",
        }
    }
}

/// An open murmur database.
#[derive(Debug)]
pub struct Murmur {
    backend: Backend,
    layout: Layout,
    prefix: String,
}

impl Murmur {
    /// Open the murmur database at `url` and work out which schema it is on.
    ///
    /// `prefix` is murmur's `dbPrefix`, which only ever applied to the pre-1.5
    /// schema; it is empty in every default deployment and is accepted here
    /// because an operator who set it cannot otherwise be read at all.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadPrefix`] for a prefix that is not an identifier,
    /// [`ReadError::Open`] when the database cannot be reached and
    /// [`ReadError::NotMurmur`] when neither schema is there.
    pub async fn open(url: &str, prefix: &str) -> Result<Self, ReadError> {
        if !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(ReadError::BadPrefix(prefix.to_owned()));
        }

        let read_only = read_only_url(url);
        let backend = Backend::connect(&read_only)
            .await
            .map_err(|error| ReadError::Open(error.to_string()))?;

        let mut source = Self {
            backend,
            // Provisional: `detect` is what decides, and it needs a `Self` to
            // build the probe statements from.
            layout: Layout::Modern,
            prefix: prefix.to_owned(),
        };
        source.layout = source.detect().await.ok_or_else(|| ReadError::NotMurmur {
            url: url.to_owned(),
            prefix: prefix.to_owned(),
        })?;
        Ok(source)
    }

    /// Which schema this database is on.
    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.layout
    }

    /// Every virtual server in this database, in id order.
    ///
    /// # Errors
    ///
    /// [`ReadError::Query`] if the server table cannot be read, which after
    /// detection means the database went away underneath us.
    pub async fn servers(&self) -> Result<Vec<u32>, ReadError> {
        let table = match self.layout {
            Layout::Modern => self.quoted("virtual_servers"),
            Layout::Legacy => self.prefixed("servers"),
        };
        let column = self.dialect().quote("server_id");
        let rows = self
            .fetch(&format!("SELECT {column} FROM {table} ORDER BY {column}"))
            .await?;
        Ok(rows
            .iter()
            .filter_map(|row| int(row, "server_id"))
            .map(|id| id.clamp(0, i64::from(u32::MAX)) as u32)
            .collect())
    }

    /// Everything stored against one virtual server.
    ///
    /// A table this database does not have -- `channel_listeners` predates
    /// nothing older than schema v9, and a Fancy property never exists upstream
    /// -- is a line in `report` and an empty list, never a failure: an operator
    /// migrating a 1.4 database should not be told their whole server is
    /// unreadable because listeners had not been invented yet.
    ///
    /// # Errors
    ///
    /// [`ReadError::Query`] only for the tables every murmur has. Everything
    /// optional degrades into `report`.
    pub async fn read(&self, server: u32, report: &mut Report) -> Result<Server, ReadError> {
        let groups = self.groups(server, report).await;
        Ok(Server {
            id: server,
            config: self.config(server, report).await,
            channels: self.channels(server, report).await?,
            links: self.links(server, report).await,
            users: self.users(server, report).await?,
            acls: self.acls(server, &groups, report).await,
            members: self.members(server, report).await,
            groups,
            listeners: self.listeners(server, report).await,
            bans: self.bans(server, report).await,
        })
    }

    // -- the tables ---------------------------------------------------------

    /// murmur's `config` table: the settings an operator changed while the
    /// server was running, which override the `.ini` key for key.
    async fn config(&self, server: u32, report: &mut Report) -> BTreeMap<String, String> {
        let (table, key, value) = match self.layout {
            Layout::Modern => (self.quoted("config"), "config_name", "config_value"),
            Layout::Legacy => (self.prefixed("config"), "key", "value"),
        };
        let sql = format!(
            "SELECT {} AS config_name, {} AS config_value FROM {table} WHERE {} = {}",
            self.dialect().quote(key),
            self.dialect().quote(value),
            self.dialect().quote("server_id"),
            self.placeholder()
        );
        let rows = match self.fetch_for(&sql, server).await {
            Ok(rows) => rows,
            Err(error) => {
                report.note(format!("the config table could not be read: {error}"));
                return BTreeMap::new();
            }
        };
        rows.iter()
            .filter_map(|row| {
                let key = text(row, "config_name")?;
                Some((
                    config_key(&key).to_owned(),
                    text_or_empty(row, "config_value"),
                ))
            })
            .collect()
    }

    /// The channel tree, with `channel_properties` folded into typed fields.
    async fn channels(&self, server: u32, report: &mut Report) -> Result<Vec<Channel>, ReadError> {
        let sql = match self.layout {
            Layout::Modern => format!(
                "SELECT {id} AS channel_id, {parent} AS parent_id, {name} AS channel_name, \
                        {inherit} AS inherit_acl \
                 FROM {table} WHERE {server} = {mark} ORDER BY {id}",
                id = self.dialect().quote("channel_id"),
                parent = self.dialect().quote("parent_id"),
                name = self.dialect().quote("channel_name"),
                inherit = self.dialect().quote("inherit_acl"),
                table = self.quoted("channels"),
                server = self.dialect().quote("server_id"),
                mark = self.placeholder(),
            ),
            Layout::Legacy => format!(
                "SELECT {id} AS channel_id, {parent} AS parent_id, {name} AS channel_name, \
                        {inherit} AS inherit_acl \
                 FROM {table} WHERE {server} = {mark} ORDER BY {id}",
                id = self.dialect().quote("channel_id"),
                parent = self.dialect().quote("parent_id"),
                name = self.dialect().quote("name"),
                inherit = self.dialect().quote("inheritacl"),
                table = self.prefixed("channels"),
                server = self.dialect().quote("server_id"),
                mark = self.placeholder(),
            ),
        };
        let rows = self.fetch_for(&sql, server).await?;

        let mut channels: Vec<Channel> = rows
            .iter()
            .map(|row| {
                let id = u32_or(row, "channel_id", 0);
                let stored_parent =
                    int(row, "parent_id").map(|parent| parent.clamp(0, i64::from(u32::MAX)) as u32);
                Channel {
                    id,
                    // Two spellings of "no parent", and both are here: `NULL`
                    // before schema v10, and a self-parent after it. Reading a
                    // self-parent as a parent would build a cycle and hang
                    // whatever walks the tree.
                    parent: stored_parent.filter(|parent| *parent != id),
                    // A self-parented channel that is not the root is
                    // *detached*: parentless on purpose, out of the tree
                    // entirely. Losing the distinction here does not lose a
                    // channel, it makes every meeting room and friend chat
                    // arrive as a second root.
                    detached: id != 0 && stored_parent == Some(id),
                    name: text_or_empty(row, "channel_name"),
                    // murmur's own default when the column is NULL
                    // (`ChannelTable.cpp`): a channel inherits unless told not
                    // to, and reading it the other way would detach every
                    // channel from its parent's ACL entries at once.
                    inherit_acl: flag(row, "inherit_acl", true),
                    ..Channel::default()
                }
            })
            .collect();

        self.channel_properties(server, &mut channels, report).await;
        Ok(channels)
    }

    /// `channel_properties`, or `channel_info` before schema v10.
    ///
    /// The entity-attribute-value unwinding of `docs/STORAGE.md` L1: eight of
    /// murmur's twelve keys are numbers stored as text, and a value that will
    /// not parse is reported against the channel it came from rather than
    /// becoming a zero nobody notices.
    async fn channel_properties(&self, server: u32, channels: &mut [Channel], report: &mut Report) {
        let (table, key, value) = match self.layout {
            Layout::Modern => (
                self.quoted("channel_properties"),
                "property_key",
                "property_value",
            ),
            Layout::Legacy => (self.prefixed("channel_info"), "key", "value"),
        };
        let sql = format!(
            "SELECT {channel} AS channel_id, {} AS property_key, {} AS property_value \
             FROM {table} WHERE {server} = {mark}",
            self.dialect().quote(key),
            self.dialect().quote(value),
            channel = self.dialect().quote("channel_id"),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        let rows = match self.fetch_for(&sql, server).await {
            Ok(rows) => rows,
            Err(error) => {
                report.note(format!(
                    "channel descriptions, positions and limits could not be read: {error}"
                ));
                return;
            }
        };

        // Counted and reported once each at the end rather than per channel. A
        // property with no home here is a property *every* channel carries, so
        // one line per channel turns a report an operator reads into sixty
        // lines of the same sentence, and the two genuinely per-channel
        // failures below are lost in it.
        let mut unmapped: BTreeMap<i64, usize> = BTreeMap::new();

        for row in &rows {
            let channel_id = u32_or(row, "channel_id", 0);
            let Some(channel) = channels.iter_mut().find(|c| c.id == channel_id) else {
                report.note(format!(
                    "a channel property names channel {channel_id}, which is not in the tree"
                ));
                continue;
            };
            let property = int_or(row, "property_key", -1);
            let raw = text_or_empty(row, "property_value");
            let number = |report: &mut Report| -> Option<u64> {
                match raw.trim().parse::<u64>() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        report.note(format!(
                            "channel {channel_id} property {property} is {raw:?}, \
                             which is not a number; keeping the default"
                        ));
                        None
                    }
                }
            };
            match property {
                CHANNEL_DESCRIPTION => channel.description = raw.clone(),
                CHANNEL_POSITION => {
                    // Signed, and the only signed one: murmur sorts negative
                    // positions above the unnumbered channels.
                    match raw.trim().parse::<i32>() {
                        Ok(value) => channel.position = value,
                        Err(_) => report.note(format!(
                            "channel {channel_id} has position {raw:?}, \
                             which is not a number; keeping 0"
                        )),
                    }
                }
                CHANNEL_MAX_USERS => {
                    if let Some(value) = number(report) {
                        channel.max_users = value.min(u64::from(u32::MAX)) as u32;
                    }
                }
                CHANNEL_HIDDEN => channel.hidden = raw.trim() != "0" && !raw.trim().is_empty(),
                CHANNEL_STRUCTURAL => {
                    channel.structural = raw.trim() != "0" && !raw.trim().is_empty();
                }
                CHANNEL_EXPIRY_MODE => {
                    if let Some(value) = number(report) {
                        channel.expiry_mode = value.min(u64::from(u32::MAX)) as u32;
                    }
                }
                CHANNEL_EXPIRY_DURATION => {
                    if let Some(value) = number(report) {
                        channel.expiry_duration_s = value.min(u64::from(u32::MAX)) as u32;
                    }
                }
                CHANNEL_CREATED_AT => {
                    // Seconds in murmur (`unsigned int`), milliseconds in
                    // Starling. Converted here rather than at the far end,
                    // because this is the side that knows the unit.
                    if let Some(value) = number(report) {
                        channel.created_at_ms = value.saturating_mul(1_000);
                    }
                }
                other => *unmapped.entry(other).or_default() += 1,
            }
        }

        for (property, channels) in unmapped {
            report.note(format!(
                "{channels} channels carry {}, which has no equivalent here; dropping it",
                channel_property_name(property)
            ));
        }
    }

    /// Linked channels.
    async fn links(&self, server: u32, report: &mut Report) -> Vec<Link> {
        let (table, first, second) = match self.layout {
            Layout::Modern => (
                self.quoted("channel_links"),
                "first_channel_id",
                "second_channel_id",
            ),
            Layout::Legacy => (self.prefixed("channel_links"), "channel_id", "link_id"),
        };
        let sql = format!(
            "SELECT {} AS channel_id, {} AS linked_id FROM {table} WHERE {server} = {mark}",
            self.dialect().quote(first),
            self.dialect().quote(second),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        match self.fetch_for(&sql, server).await {
            Ok(rows) => rows
                .iter()
                .map(|row| Link {
                    channel: u32_or(row, "channel_id", 0),
                    linked: u32_or(row, "linked_id", 0),
                })
                .collect(),
            Err(error) => {
                report.note(format!("channel links could not be read: {error}"));
                Vec::new()
            }
        }
    }

    /// Registered accounts, with `user_properties` folded in.
    async fn users(&self, server: u32, report: &mut Report) -> Result<Vec<User>, ReadError> {
        let sql = match self.layout {
            Layout::Modern => format!(
                "SELECT {id} AS user_id, {name} AS user_name, {pw} AS password_hash, \
                        {salt} AS salt, {kdf} AS kdf_iterations, {channel} AS last_channel_id, \
                        {texture} AS texture, {active} AS last_active, \
                        {disconnect} AS last_disconnect \
                 FROM {table} WHERE {server} = {mark} ORDER BY {id}",
                id = self.dialect().quote("user_id"),
                name = self.dialect().quote("user_name"),
                pw = self.dialect().quote("password_hash"),
                salt = self.dialect().quote("salt"),
                kdf = self.dialect().quote("kdf_iterations"),
                channel = self.dialect().quote("last_channel_id"),
                texture = self.dialect().quote("texture"),
                active = self.dialect().quote("last_active"),
                disconnect = self.dialect().quote("last_disconnect"),
                table = self.quoted("users"),
                server = self.dialect().quote("server_id"),
                mark = self.placeholder(),
            ),
            Layout::Legacy => format!(
                "SELECT {id} AS user_id, {name} AS user_name, {pw} AS password_hash, \
                        {salt} AS salt, {kdf} AS kdf_iterations, {channel} AS last_channel_id, \
                        {texture} AS texture, {active} AS last_active, \
                        {disconnect} AS last_disconnect \
                 FROM {table} WHERE {server} = {mark} ORDER BY {id}",
                id = self.dialect().quote("user_id"),
                name = self.dialect().quote("name"),
                pw = self.dialect().quote("pw"),
                salt = self.dialect().quote("salt"),
                kdf = self.dialect().quote("kdfiterations"),
                channel = self.dialect().quote("lastchannel"),
                texture = self.dialect().quote("texture"),
                active = self.date_to_epoch("last_active"),
                disconnect = self.date_to_epoch("last_disconnect"),
                table = self.prefixed("users"),
                server = self.dialect().quote("server_id"),
                mark = self.placeholder(),
            ),
        };
        let rows = self.fetch_for(&sql, server).await?;

        let mut users: Vec<User> = rows
            .iter()
            .map(|row| {
                let id = u32_or(row, "user_id", 0);
                User {
                    id,
                    name: text_or_empty(row, "user_name"),
                    password: password_of(row, id, report),
                    texture: blob(row, "texture").unwrap_or_default(),
                    last_channel: u32_or(row, "last_channel_id", 0),
                    last_active_s: epoch_seconds(row, "last_active"),
                    last_disconnect_s: epoch_seconds(row, "last_disconnect"),
                    ..User::default()
                }
            })
            .collect();

        self.user_properties(server, &mut users, report).await;
        Ok(users)
    }

    /// `user_properties`, or `user_info` before schema v10.
    async fn user_properties(&self, server: u32, users: &mut [User], report: &mut Report) {
        let (table, key, value) = match self.layout {
            Layout::Modern => (
                self.quoted("user_properties"),
                "property_key",
                "property_value",
            ),
            Layout::Legacy => (self.prefixed("user_info"), "key", "value"),
        };
        let sql = format!(
            "SELECT {user} AS user_id, {} AS property_key, {} AS property_value \
             FROM {table} WHERE {server} = {mark}",
            self.dialect().quote(key),
            self.dialect().quote(value),
            user = self.dialect().quote("user_id"),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        let rows = match self.fetch_for(&sql, server).await {
            Ok(rows) => rows,
            Err(error) => {
                report.note(format!(
                    "account emails, comments and certificates could not be read: {error}"
                ));
                return;
            }
        };

        for row in &rows {
            let user_id = u32_or(row, "user_id", 0);
            let Some(user) = users.iter_mut().find(|u| u.id == user_id) else {
                report.note(format!(
                    "an account property names user {user_id}, which is not registered"
                ));
                continue;
            };
            let raw = text_or_empty(row, "property_value");
            match int_or(row, "property_key", -1) {
                // The name is authoritative in the `users` table, and murmur
                // keeps this key in step with it. Taking the property would
                // make the two disagree in exactly the case where the property
                // row is stale.
                USER_NAME => {}
                USER_EMAIL => user.email = raw,
                USER_COMMENT => user.comment = raw,
                USER_CERTIFICATE_HASH => user.cert_hash = raw,
                USER_TOTP_SECRET => user.totp_secret = raw,
                // Both live in the `users` table's own columns, which is where
                // they were read from; the property keys exist for murmur's
                // property API rather than as a second copy.
                USER_PASSWORD | USER_KDF_ITERATIONS | USER_LAST_ACTIVE => {}
                other => report.note(format!(
                    "account {user_id} carries property {other}, \
                     which has no equivalent here; dropping it"
                )),
            }
        }
    }

    /// Named groups.
    async fn groups(&self, server: u32, report: &mut Report) -> Vec<Group> {
        let (table, name, inheritable) = match self.layout {
            Layout::Modern => (self.quoted("groups"), "group_name", "is_inheritable"),
            Layout::Legacy => (self.prefixed("groups"), "name", "inheritable"),
        };
        let sql = format!(
            "SELECT {id} AS group_id, {} AS group_name, {channel} AS channel_id, \
                    {inherit} AS inherit, {} AS is_inheritable \
             FROM {table} WHERE {server} = {mark}",
            self.dialect().quote(name),
            self.dialect().quote(inheritable),
            id = self.dialect().quote("group_id"),
            channel = self.dialect().quote("channel_id"),
            inherit = self.dialect().quote("inherit"),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        match self.fetch_for(&sql, server).await {
            Ok(rows) => rows
                .iter()
                .map(|row| Group {
                    id: int_or(row, "group_id", 0),
                    channel: u32_or(row, "channel_id", 0),
                    name: text_or_empty(row, "group_name"),
                    inherit: flag(row, "inherit", true),
                    inheritable: flag(row, "is_inheritable", true),
                })
                .collect(),
            Err(error) => {
                report.note(format!("groups could not be read: {error}"));
                Vec::new()
            }
        }
    }

    /// Group membership, and explicit exclusion from a group.
    async fn members(&self, server: u32, report: &mut Report) -> Vec<GroupMember> {
        let (table, add) = match self.layout {
            Layout::Modern => (self.quoted("group_members"), "add_to_group"),
            Layout::Legacy => (self.prefixed("group_members"), "addit"),
        };
        let sql = format!(
            "SELECT {group} AS group_id, {user} AS user_id, {} AS add_to_group \
             FROM {table} WHERE {server} = {mark}",
            self.dialect().quote(add),
            group = self.dialect().quote("group_id"),
            user = self.dialect().quote("user_id"),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        match self.fetch_for(&sql, server).await {
            Ok(rows) => rows
                .iter()
                .map(|row| GroupMember {
                    group: int_or(row, "group_id", 0),
                    user: u32_or(row, "user_id", 0),
                    add: flag(row, "add_to_group", true),
                })
                .collect(),
            Err(error) => {
                report.note(format!("group members could not be read: {error}"));
                Vec::new()
            }
        }
    }

    /// ACL entries, with the group specification put back together.
    async fn acls(&self, server: u32, groups: &[Group], report: &mut Report) -> Vec<Acl> {
        match self.layout {
            Layout::Modern => self.modern_acls(server, groups, report).await,
            Layout::Legacy => self.legacy_acls(server, report).await,
        }
    }

    /// The 1.5 shape: five columns that together mean one specification.
    async fn modern_acls(&self, server: u32, groups: &[Group], report: &mut Report) -> Vec<Acl> {
        let sql = format!(
            "SELECT {channel} AS channel_id, {priority} AS priority, {user} AS affected_user_id, \
                    {group} AS affected_group_id, {meta} AS affected_meta_group_id, \
                    {token} AS access_token, {modifiers} AS group_modifiers, \
                    {here} AS apply_here, {subs} AS apply_subs, \
                    {grant} AS granted, {deny} AS revoked \
             FROM {table} WHERE {server} = {mark} ORDER BY {channel}, {priority}",
            channel = self.dialect().quote("channel_id"),
            priority = self.dialect().quote("priority"),
            user = self.dialect().quote("affected_user_id"),
            group = self.dialect().quote("affected_group_id"),
            meta = self.dialect().quote("affected_meta_group_id"),
            token = self.dialect().quote("access_token"),
            modifiers = self.dialect().quote("group_modifiers"),
            here = self.dialect().quote("apply_in_current_channel"),
            subs = self.dialect().quote("apply_in_sub_channels"),
            grant = self.dialect().quote("granted_privilege_flags"),
            deny = self.dialect().quote("revoked_privilege_flags"),
            table = self.quoted("access_control_lists"),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        let rows = match self.fetch_for(&sql, server).await {
            Ok(rows) => rows,
            Err(error) => {
                report.note(format!("ACL entries could not be read: {error}"));
                return Vec::new();
            }
        };

        rows.iter()
            .map(|row| {
                let channel = u32_or(row, "channel_id", 0);
                // Upstream's own `getLegacyGroupData`: whichever of the three
                // ways of naming a subject is filled in, rendered back into the
                // one text form the grammar is written in, then wrapped in its
                // modifiers.
                let base = if let Some(group_id) = int(row, "affected_group_id") {
                    groups
                        .iter()
                        .find(|group| group.id == group_id)
                        .map(|group| group.name.clone())
                        .or_else(|| {
                            report.note(format!(
                                "an ACL entry on channel {channel} names group {group_id}, \
                                 which does not exist; the entry is dropped"
                            ));
                            None
                        })
                } else if let Some(meta) = int(row, "affected_meta_group_id") {
                    match meta_group_name(meta) {
                        Some(name) => Some(name.to_owned()),
                        None => {
                            report.note(format!(
                                "an ACL entry on channel {channel} names meta group {meta}, \
                                 which this build does not know; the entry is dropped"
                            ));
                            None
                        }
                    }
                } else {
                    text(row, "access_token")
                        .filter(|token| !token.is_empty())
                        .map(|token| format!("#{token}"))
                };

                Acl {
                    channel,
                    priority: int_or(row, "priority", 0) as i32,
                    user: int(row, "affected_user_id")
                        .map(|id| id.clamp(0, i64::from(u32::MAX)) as u32),
                    group: base
                        .map(|base| apply_modifiers(&base, &text_or_empty(row, "group_modifiers"))),
                    apply_here: flag(row, "apply_here", true),
                    apply_subs: flag(row, "apply_subs", true),
                    grant: u32_or(row, "granted", 0),
                    deny: u32_or(row, "revoked", 0),
                }
            })
            .collect()
    }

    /// The pre-1.5 shape: one `group_name` column already in text form.
    async fn legacy_acls(&self, server: u32, report: &mut Report) -> Vec<Acl> {
        let sql = format!(
            "SELECT {channel} AS channel_id, {priority} AS priority, {user} AS affected_user_id, \
                    {group} AS group_name, {here} AS apply_here, {subs} AS apply_subs, \
                    {grant} AS granted, {deny} AS revoked \
             FROM {table} WHERE {server} = {mark} ORDER BY {channel}, {priority}",
            channel = self.dialect().quote("channel_id"),
            priority = self.dialect().quote("priority"),
            user = self.dialect().quote("user_id"),
            group = self.dialect().quote("group_name"),
            here = self.dialect().quote("apply_here"),
            subs = self.dialect().quote("apply_sub"),
            grant = self.dialect().quote("grantpriv"),
            deny = self.dialect().quote("revokepriv"),
            table = self.prefixed("acl"),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        match self.fetch_for(&sql, server).await {
            Ok(rows) => rows
                .iter()
                .map(|row| Acl {
                    channel: u32_or(row, "channel_id", 0),
                    priority: int_or(row, "priority", 0) as i32,
                    user: int(row, "affected_user_id")
                        .map(|id| id.clamp(0, i64::from(u32::MAX)) as u32),
                    group: text(row, "group_name").filter(|name| !name.is_empty()),
                    apply_here: flag(row, "apply_here", true),
                    apply_subs: flag(row, "apply_subs", true),
                    grant: u32_or(row, "granted", 0),
                    deny: u32_or(row, "revoked", 0),
                })
                .collect(),
            Err(error) => {
                report.note(format!("ACL entries could not be read: {error}"));
                Vec::new()
            }
        }
    }

    /// Stored channel listeners, which only exist from schema v9.
    async fn listeners(&self, server: u32, report: &mut Report) -> Vec<Listener> {
        let sql = format!(
            "SELECT {user} AS user_id, {channel} AS channel_id, {volume} AS volume_adjustment, \
                    {enabled} AS enabled \
             FROM {table} WHERE {server} = {mark}",
            user = self.dialect().quote("user_id"),
            channel = self.dialect().quote("channel_id"),
            volume = self.dialect().quote("volume_adjustment"),
            enabled = self.dialect().quote("enabled"),
            table = self.prefixed("channel_listeners"),
            server = self.dialect().quote("server_id"),
            mark = self.placeholder(),
        );
        match self.fetch_for(&sql, server).await {
            Ok(rows) => rows
                .iter()
                .map(|row| Listener {
                    user: u32_or(row, "user_id", 0),
                    channel: u32_or(row, "channel_id", 0),
                    volume: real(row, "volume_adjustment", 1.0),
                    enabled: flag(row, "enabled", true),
                })
                .collect(),
            Err(_) if self.layout == Layout::Legacy => {
                // Not worth a line: the table was introduced in schema v9, so a
                // 1.4 database not having it is the normal case rather than a
                // loss.
                Vec::new()
            }
            Err(error) => {
                report.note(format!("channel listeners could not be read: {error}"));
                Vec::new()
            }
        }
    }

    /// The ban list.
    async fn bans(&self, server: u32, report: &mut Report) -> Vec<Ban> {
        let sql = match self.layout {
            Layout::Modern => format!(
                "SELECT {address} AS address, {prefix} AS prefix_len, {cert} AS cert_hash, \
                        {name} AS banned_name, {reason} AS reason, {start} AS start_date, \
                        {duration} AS duration \
                 FROM {table} WHERE {server} = {mark}",
                address = self.dialect().quote("ipv6_base_address"),
                prefix = self.dialect().quote("prefix_length"),
                cert = self.dialect().quote("banned_user_cert_hash"),
                name = self.dialect().quote("banned_user_name"),
                reason = self.dialect().quote("reason"),
                start = self.dialect().quote("start_date"),
                duration = self.dialect().quote("duration"),
                table = self.quoted("bans"),
                server = self.dialect().quote("server_id"),
                mark = self.placeholder(),
            ),
            Layout::Legacy => format!(
                "SELECT {address} AS address, {prefix} AS prefix_len, {cert} AS cert_hash, \
                        {name} AS banned_name, {reason} AS reason, {start} AS start_date, \
                        {duration} AS duration \
                 FROM {table} WHERE {server} = {mark}",
                address = self.dialect().quote("base"),
                prefix = self.dialect().quote("mask"),
                cert = self.dialect().quote("hash"),
                name = self.dialect().quote("name"),
                reason = self.dialect().quote("reason"),
                start = self.date_to_epoch("start"),
                duration = self.dialect().quote("duration"),
                table = self.prefixed("bans"),
                server = self.dialect().quote("server_id"),
                mark = self.placeholder(),
            ),
        };
        let rows = match self.fetch_for(&sql, server).await {
            Ok(rows) => rows,
            Err(error) => {
                report.note(format!("the ban list could not be read: {error}"));
                return Vec::new();
            }
        };

        rows.iter()
            .map(|row| {
                let name = text_or_empty(row, "banned_name");
                Ban {
                    address: ban_address(row, &name, report),
                    prefix_len: u32_or(row, "prefix_len", 128),
                    name,
                    cert_hash: text_or_empty(row, "cert_hash"),
                    reason: text_or_empty(row, "reason"),
                    start_s: epoch_seconds(row, "start_date"),
                    duration_s: u32_or(row, "duration", 0),
                }
            })
            .collect()
    }

    // -- plumbing -----------------------------------------------------------

    /// Which of the two schemas this database is on, if either.
    async fn detect(&self) -> Option<Layout> {
        if self
            .has_table(&self.quoted("virtual_servers"), "server_id")
            .await
        {
            return Some(Layout::Modern);
        }
        if self.has_table(&self.prefixed("servers"), "server_id").await {
            return Some(Layout::Legacy);
        }
        None
    }

    /// Whether `table` exists and has `column`.
    ///
    /// A `WHERE 1 = 0` select rather than an `information_schema` query: the
    /// three backends describe themselves differently and agree on this.
    async fn has_table(&self, table: &str, column: &str) -> bool {
        let column = self.dialect().quote(column);
        self.fetch(&format!("SELECT {column} FROM {table} WHERE 1 = 0"))
            .await
            .is_ok()
    }

    /// `name` with the operator's prefix, quoted.
    fn prefixed(&self, name: &str) -> String {
        self.dialect().quote(&format!("{}{name}", self.prefix))
    }

    /// `name`, quoted. The 1.5 schema has no prefix.
    fn quoted(&self, name: &str) -> String {
        self.dialect().quote(name)
    }

    /// The placeholder for the one parameter every query here binds.
    fn placeholder(&self) -> String {
        self.dialect().placeholder(1)
    }

    /// A pre-v10 `DATE` column, converted to epoch seconds by the database.
    ///
    /// Not a nicety. sqlx's `Any` driver refuses a column whose *declared* type
    /// is `DATE` outright -- "Any driver does not support the SQLite type
    /// Date" -- so a 1.4 database's `last_active`, `last_disconnect` and `start`
    /// cannot be read at all without asking the backend to hand them over as a
    /// number. The three spellings are murmur's own, from the conversion its
    /// migration uses for exactly these columns
    /// (`vendor/server/src/database/Utils.cpp:dateToEpoch`), and all three
    /// assume UTC, as murmur does.
    fn date_to_epoch(&self, column: &str) -> String {
        let quoted = self.dialect().quote(column);
        match self.dialect() {
            Dialect::Sqlite(_) => format!("STRFTIME('%s', {quoted})"),
            Dialect::MySql(_) => format!("UNIX_TIMESTAMP({quoted})"),
            Dialect::Postgres(_) => {
                format!("CAST(EXTRACT(EPOCH FROM CAST({quoted} AS TIMESTAMP)) AS BIGINT)")
            }
        }
    }

    fn dialect(&self) -> Dialect {
        self.backend.dialect()
    }

    /// Run a statement that binds nothing.
    async fn fetch(&self, sql: &str) -> Result<Vec<sqlx::any::AnyRow>, ReadError> {
        // `AssertSqlSafe` because sqlx will otherwise only take a `&'static
        // str`, and these statements are built rather than written out: they
        // differ by backend quoting, by schema layout and by the operator's
        // table prefix. Nothing interpolated into one comes from a client. The
        // prefix is the only value from outside this file, and `open` refuses
        // any prefix that is not letters, digits and underscores, which is the
        // audit the assertion is asking for.
        sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_all(self.backend.pool())
            .await
            .map_err(|error| ReadError::Query(format!("{error}")))
    }

    /// Run a statement bound to one server id.
    async fn fetch_for(&self, sql: &str, server: u32) -> Result<Vec<sqlx::any::AnyRow>, ReadError> {
        // See `fetch` for why the assertion is sound.
        sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
            .bind(i64::from(server))
            .fetch_all(self.backend.pool())
            .await
            .map_err(|error| ReadError::Query(format!("{error}")))
    }
}

/// The password on one `users` row.
///
/// murmur decides between its two forms by the iteration count, and so does
/// this: a positive count means PBKDF2-HMAC-SHA384, and anything else means the
/// pre-1.3 unsalted SHA-1. Getting that backwards would lock out either every
/// old account or every new one.
fn password_of(row: &sqlx::any::AnyRow, user: u32, report: &mut Report) -> Password {
    let stored = text_or_empty(row, "password_hash");
    let stored = stored.trim();
    if stored.is_empty() {
        return Password::None;
    }
    let iterations = int_or(row, "kdf_iterations", 0);
    if iterations <= 0 {
        return match from_hex(stored) {
            Some(digest) => Password::Sha1 { digest },
            None => {
                report.note(format!(
                    "account {user} has a password hash that is not hex; \
                     the account is imported without a password"
                ));
                Password::None
            }
        };
    }

    let salt = text_or_empty(row, "salt");
    let (Some(salt), Some(key)) = (from_hex(&salt), from_hex(stored)) else {
        report.note(format!(
            "account {user} has a password hash or salt that is not hex; \
             the account is imported without a password"
        ));
        return Password::None;
    };
    Password::Pbkdf2 {
        salt,
        key,
        iterations: iterations.clamp(1, i64::from(u32::MAX)) as u32,
    }
}

/// A ban's address as sixteen bytes, from whichever way it is stored.
///
/// Text since schema v10 and raw bytes before it. An IPv4 ban written before v4
/// is four bytes, which is carried into its v6-mapped form rather than dropped:
/// the alternative is an unbanning nobody asked for.
fn ban_address(row: &sqlx::any::AnyRow, name: &str, report: &mut Report) -> Vec<u8> {
    if let Some(text) = text(row, "address")
        && let Ok(address) = text.trim().parse::<std::net::IpAddr>()
    {
        return match address {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
    }
    match blob(row, "address") {
        Some(bytes) if bytes.len() == 16 => bytes,
        Some(bytes) if bytes.len() == 4 => std::net::Ipv4Addr::new(
            bytes.first().copied().unwrap_or_default(),
            bytes.get(1).copied().unwrap_or_default(),
            bytes.get(2).copied().unwrap_or_default(),
            bytes.get(3).copied().unwrap_or_default(),
        )
        .to_ipv6_mapped()
        .octets()
        .to_vec(),
        _ => {
            // Not fatal, and not silent: a ban with no address is still a ban by
            // certificate hash, which is the half that follows a person.
            report.note(format!(
                "the ban on {name:?} has no address this build can read; \
                 it is imported as a certificate ban only"
            ));
            Vec::new()
        }
    }
}

/// One `config` key under the spelling the `.ini` uses.
///
/// murmur reads the same setting from two places under **two spellings**: the
/// file says `registerName` and the table says `registername`
/// (`vendor/server/src/murmur/Server.cpp:581`). Everything else agrees, because
/// everything else is lowercase in both.
///
/// This matters more than it looks. The `.ini` reader is case-sensitive on
/// purpose, and the public listing is precisely the block an operator is most
/// likely to have set from the admin interface rather than the file -- which
/// means it is in the table and nowhere else. Left unmapped, a migrated server
/// silently stops being listed, and the only symptom is that nobody can find it
/// any more.
fn config_key(key: &str) -> &str {
    match key {
        "registername" => "registerName",
        "registerpassword" => "registerPassword",
        "registerhostname" => "registerHostname",
        "registerlocation" => "registerLocation",
        "registerurl" => "registerUrl",
        other => other,
    }
}

/// What a `ChannelProperty` number is called, for a report somebody reads.
///
/// Only the ones with no home here, which is why this is not the same list as
/// the constants below: a property that *is* mapped never reaches this. Naming
/// them matters because the four persistent-chat properties are the ones every
/// channel on a Fancy fork carries, so "property 3" is what an operator would
/// otherwise be told sixty times.
fn channel_property_name(property: i64) -> String {
    match property {
        3 => "the persistent-chat protocol".to_owned(),
        4 => "the persistent-chat history limit".to_owned(),
        5 => "the persistent-chat retention period".to_owned(),
        6 => "the persistent-chat key custodians".to_owned(),
        other => format!("property {other}"),
    }
}

/// murmur's `DBAcl::MetaGroup`, by value.
///
/// Transcribed from `vendor/server/src/murmur/database/DBAcl.h`. The numbers are
/// what is in the column, so the order is load-bearing and must not be sorted.
const fn meta_group_name(value: i64) -> Option<&'static str> {
    match value {
        0 => Some("none"),
        1 => Some("all"),
        2 => Some("auth"),
        3 => Some("strong"),
        4 => Some("in"),
        5 => Some("out"),
        6 => Some("sub"),
        _ => None,
    }
}

/// Wrap a group name in its modifiers, upstream's way round.
///
/// Every modifier is a prefix except `sub`'s argument list, which starts with a
/// comma and is a suffix (`ACLCompat.cpp:getLegacyGroupData`). They are stored
/// semicolon-separated and applied in order, so `!` then `~` produces `~!name`,
/// which is what murmur wrote in the first place.
fn apply_modifiers(base: &str, modifiers: &str) -> String {
    let mut spec = base.to_owned();
    for modifier in modifiers.split(';').filter(|m| !m.is_empty()) {
        if modifier.starts_with(',') {
            spec.push_str(modifier);
        } else {
            spec.insert_str(0, modifier);
        }
    }
    spec
}

/// `url`, asking for a read-only connection where that can be asked for.
///
/// Requirement 1 of `docs/STORAGE.md` §4 is that the source is never written to,
/// and SQLite will honour that at the driver rather than leaving it to every
/// statement in this file being a `SELECT`. It also stops sqlx creating an empty
/// database file for a path that was mistyped, which would otherwise report a
/// migration of a server with no channels and no users rather than "no such
/// file".
///
/// MySQL and PostgreSQL have no equivalent in the URL; there the guarantee is
/// that nothing here issues anything but `SELECT`, and an operator who wants it
/// enforced can hand this a read-only role.
fn read_only_url(url: &str) -> String {
    if !url.starts_with("sqlite:") || url.contains("mode=") || url.contains(":memory:") {
        return url.to_owned();
    }
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}mode=ro")
}

/// `ChannelProperty`, by value (`vendor/server/src/murmur/database/ChannelProperty.h`).
const CHANNEL_DESCRIPTION: i64 = 0;
/// See [`CHANNEL_DESCRIPTION`].
const CHANNEL_POSITION: i64 = 1;
/// See [`CHANNEL_DESCRIPTION`].
const CHANNEL_MAX_USERS: i64 = 2;
/// See [`CHANNEL_DESCRIPTION`].
const CHANNEL_HIDDEN: i64 = 7;
/// See [`CHANNEL_DESCRIPTION`].
const CHANNEL_EXPIRY_MODE: i64 = 8;
/// See [`CHANNEL_DESCRIPTION`].
const CHANNEL_EXPIRY_DURATION: i64 = 9;
/// See [`CHANNEL_DESCRIPTION`].
const CHANNEL_CREATED_AT: i64 = 10;
/// See [`CHANNEL_DESCRIPTION`].
const CHANNEL_STRUCTURAL: i64 = 11;

/// `UserProperty`, by value (`vendor/server/src/murmur/database/UserProperty.h`).
const USER_NAME: i64 = 0;
/// See [`USER_NAME`].
const USER_EMAIL: i64 = 1;
/// See [`USER_NAME`].
const USER_COMMENT: i64 = 2;
/// See [`USER_NAME`].
const USER_CERTIFICATE_HASH: i64 = 3;
/// See [`USER_NAME`].
const USER_PASSWORD: i64 = 4;
/// See [`USER_NAME`].
const USER_LAST_ACTIVE: i64 = 5;
/// See [`USER_NAME`].
const USER_KDF_ITERATIONS: i64 = 6;
/// See [`USER_NAME`].
const USER_TOTP_SECRET: i64 = 7;

#[cfg(test)]
mod tests;
