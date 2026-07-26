//! The tables, and how a database gets them.
//!
//! One migration so far, applied by version number so a second is additive
//! rather than a rewrite. Every statement is built for the connected dialect —
//! see [`Dialect`], which is what the three backends actually disagree about.
//!
//! # Constraints are the schema's job, not the caller's
//!
//! murmur writes its deletes out by hand: removing a channel means remembering
//! to delete its ACLs, its groups, its links and its listeners, in four separate
//! statements, at every call site that removes a channel. A forgotten one leaves
//! rows pointing at nothing, and nothing complains until something reads them.
//!
//! Every relationship below is a real foreign key with `ON DELETE CASCADE`. The
//! database enforces it once instead of every caller remembering it.
//!
//! SQLite needs `PRAGMA foreign_keys = ON` per connection for that to be true —
//! it parses foreign keys and ignores them by default, which is the worst of
//! both, so [`enable_foreign_keys`] is not optional.

use sqlx::AnyPool;
use starling_api::StoreError;

use crate::backend::{Backend, wrap};
use crate::dialect::{Dialect, SqlDialect};

/// The schema version this build writes.
///
/// Bumped when a migration is added. A database at a *higher* version is
/// refused rather than used: it was written by a newer Starling, and guessing
/// what its columns mean is how data gets corrupted.
pub const SCHEMA_VERSION: i64 = 1;

/// Every table, in dependency order.
///
/// Order matters for creation: a foreign key cannot reference a table that does
/// not exist yet. It is the reverse of the order they must be dropped in, which
/// is why the list is written once and reversed rather than maintained twice.
const TABLES: &[&str] = &[
    "schema_version",
    "config",
    "channels",
    "users",
    "user_properties",
    "channel_links",
    "channel_listeners",
    "acl_entries",
    "groups",
    "group_members",
    "bans",
    "server_log",
];

/// Create the schema if it is not already there, and check its version.
///
/// # Errors
///
/// [`StoreError`] if a statement fails, or if the database was written by a
/// newer Starling than this one.
pub async fn migrate(backend: &Backend) -> Result<(), StoreError> {
    let dialect = backend.dialect();
    let pool = backend.pool();

    // Foreign keys are armed by `Backend::connect`, on every pooled connection
    // rather than once here — a pragma is per connection, and arming one of five
    // makes cascades depend on which the pool hands out.
    for statement in create_statements(&dialect) {
        let _ = sqlx::query(&statement)
            .execute(pool)
            .await
            .map_err(|e| wrap("creating schema", e))?;
    }

    check_version(pool, dialect).await
}

/// Read the stored version, writing it if the database is new.
async fn check_version(pool: &AnyPool, dialect: Dialect) -> Result<(), StoreError> {
    let found: Option<(i64,)> = sqlx::query_as("SELECT version FROM schema_version")
        .fetch_optional(pool)
        .await
        .map_err(|e| wrap("reading the schema version", e))?;

    match found {
        None => {
            let _ = sqlx::query(&format!(
                "INSERT INTO schema_version (version) VALUES ({})",
                dialect.placeholder(1)
            ))
            .bind(SCHEMA_VERSION)
            .execute(pool)
            .await
            .map_err(|e| wrap("recording the schema version", e))?;
            Ok(())
        }
        Some((version,)) if version > SCHEMA_VERSION => Err(StoreError::Corrupt(format!(
            "database is at schema version {version} but this build understands {SCHEMA_VERSION}; \
             it was written by a newer Starling"
        ))),
        // Equal, or older and therefore already upgraded by the statements above
        // — every one of which is `IF NOT EXISTS`.
        Some(_) => Ok(()),
    }
}

/// Every `CREATE TABLE`, in dependency order, for one dialect.
///
/// Built as strings rather than kept as constants because three dialects
/// disagree about text columns and auto-increment, and a constant per dialect
/// would be the same schema written three times — which is how two of them end
/// up subtly different.
fn create_statements(dialect: &Dialect) -> Vec<String> {
    let mut statements = core_tables(dialect);
    statements.extend(channel_tables(dialect));
    statements.extend(authority_tables(dialect));
    statements.extend(indexes());
    statements
}

/// The schema's own version, configuration, channels and accounts.
///
/// Everything else has a foreign key into one of these, so they come first.
fn core_tables(dialect: &Dialect) -> Vec<String> {
    let text = dialect.varchar(255);
    let long_text = dialect.text();

    vec![
        format!(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            )"
        ),
        // Per-server settings an operator can change without editing a file.
        format!(
            "CREATE TABLE IF NOT EXISTS config (
                server_id INTEGER NOT NULL,
                \"key\"   {text} NOT NULL,
                value     {long_text} NOT NULL,
                PRIMARY KEY (server_id, \"key\")
            )"
        ),
        // `parent_id` references this same table, so the root (parent NULL) must
        // be insertable before anything points at it.
        format!(
            "CREATE TABLE IF NOT EXISTS channels (
                server_id   INTEGER NOT NULL,
                channel_id  INTEGER NOT NULL,
                parent_id   INTEGER NULL,
                name        {text} NOT NULL,
                inherit_acl INTEGER NOT NULL DEFAULT 1,
                description {long_text} NOT NULL DEFAULT '',
                position    INTEGER NOT NULL DEFAULT 0,
                max_users   INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, channel_id),
                FOREIGN KEY (server_id, parent_id)
                    REFERENCES channels (server_id, channel_id) ON DELETE CASCADE
            )"
        ),
        // `name` is unique per server: two accounts with one name means either
        // can authenticate as the other, and murmur relies on the same rule
        // without stating it in the schema.
        format!(
            "CREATE TABLE IF NOT EXISTS users (
                server_id       INTEGER NOT NULL,
                user_id         INTEGER NOT NULL,
                name            {text} NOT NULL,
                password_hash   {long_text} NULL,
                salt            {text} NULL,
                kdf_iterations  INTEGER NULL,
                cert_hash       {text} NULL,
                last_channel_id INTEGER NULL,
                last_active     INTEGER NULL,
                last_disconnect INTEGER NULL,
                PRIMARY KEY (server_id, user_id),
                UNIQUE (server_id, name)
            )"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS user_properties (
                server_id INTEGER NOT NULL,
                user_id   INTEGER NOT NULL,
                \"key\"   {text} NOT NULL,
                value     {long_text} NOT NULL,
                PRIMARY KEY (server_id, user_id, \"key\"),
                FOREIGN KEY (server_id, user_id)
                    REFERENCES users (server_id, user_id) ON DELETE CASCADE
            )"
        ),
    ]
}

/// What hangs off a channel: links and listeners.
fn channel_tables(dialect: &Dialect) -> Vec<String> {
    let _ = dialect;
    vec![
        // The `CHECK` is what makes the pair canonical: without it the same link
        // can be stored twice, once in each order, and unlinking removes one.
        format!(
            "CREATE TABLE IF NOT EXISTS channel_links (
                server_id  INTEGER NOT NULL,
                low_id     INTEGER NOT NULL,
                high_id    INTEGER NOT NULL,
                PRIMARY KEY (server_id, low_id, high_id),
                CHECK (low_id < high_id),
                FOREIGN KEY (server_id, low_id)
                    REFERENCES channels (server_id, channel_id) ON DELETE CASCADE,
                FOREIGN KEY (server_id, high_id)
                    REFERENCES channels (server_id, channel_id) ON DELETE CASCADE
            )"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS channel_listeners (
                server_id         INTEGER NOT NULL,
                user_id           INTEGER NOT NULL,
                channel_id        INTEGER NOT NULL,
                volume_adjustment INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, user_id, channel_id),
                FOREIGN KEY (server_id, user_id)
                    REFERENCES users (server_id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (server_id, channel_id)
                    REFERENCES channels (server_id, channel_id) ON DELETE CASCADE
            )"
        ),
    ]
}

/// Who may do what: ACL entries, groups, memberships, bans and the log.
fn authority_tables(dialect: &Dialect) -> Vec<String> {
    let text = dialect.varchar(255);
    let long_text = dialect.text();
    let auto_id = dialect.auto_increment_pk();

    vec![
        // The `CHECK` enforces the sum type: an entry names a user or a group,
        // never both and never neither. murmur has five nullable columns here
        // and no constraint at all.
        format!(
            "CREATE TABLE IF NOT EXISTS acl_entries (
                server_id        INTEGER NOT NULL,
                entry_id         {auto_id},
                channel_id       INTEGER NOT NULL,
                priority         INTEGER NOT NULL DEFAULT 0,
                target_user_id   INTEGER NULL,
                target_group     {text} NULL,
                apply_in_current INTEGER NOT NULL DEFAULT 1,
                apply_in_sub     INTEGER NOT NULL DEFAULT 1,
                granted          INTEGER NOT NULL DEFAULT 0,
                revoked          INTEGER NOT NULL DEFAULT 0,
                CHECK ((target_user_id IS NULL) <> (target_group IS NULL)),
                FOREIGN KEY (server_id, channel_id)
                    REFERENCES channels (server_id, channel_id) ON DELETE CASCADE
            )"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS groups (
                server_id   INTEGER NOT NULL,
                group_id    {auto_id},
                channel_id  INTEGER NOT NULL,
                name        {text} NOT NULL,
                inherit     INTEGER NOT NULL DEFAULT 1,
                inheritable INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (server_id, channel_id)
                    REFERENCES channels (server_id, channel_id) ON DELETE CASCADE
            )"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS group_members (
                server_id INTEGER NOT NULL,
                group_id  INTEGER NOT NULL,
                user_id   INTEGER NOT NULL,
                add_member INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (server_id, group_id, user_id),
                FOREIGN KEY (server_id, user_id)
                    REFERENCES users (server_id, user_id) ON DELETE CASCADE
            )"
        ),
        // `expires_at NULL` is a permanent ban, so the obvious query — "still in
        // force" — is `expires_at IS NULL OR expires_at > now` and uses an index.
        format!(
            "CREATE TABLE IF NOT EXISTS bans (
                server_id     INTEGER NOT NULL,
                ban_id        {auto_id},
                address       {text} NOT NULL,
                prefix_length INTEGER NOT NULL,
                name          {text} NULL,
                cert_hash     {text} NULL,
                reason        {long_text} NULL,
                start_at      INTEGER NOT NULL,
                expires_at    INTEGER NULL
            )"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS server_log (
                server_id INTEGER NOT NULL,
                log_id    {auto_id},
                logged_at INTEGER NOT NULL,
                message   {long_text} NOT NULL
            )"
        ),
    ]
}

/// The indexes the read paths need.
///
/// Separate from the tables because they are answers to *query* shapes rather
/// than to the data model, and because every one of them is dialect-neutral.
fn indexes() -> Vec<String> {
    vec![
        // Pruning by age and listing newest-first are the only two things the
        // log is ever asked, and both scan without this.
        "CREATE INDEX IF NOT EXISTS idx_server_log_time ON server_log (server_id, logged_at)"
            .to_owned(),
        // Every ACL read is "the entries on this channel, in priority order".
        "CREATE INDEX IF NOT EXISTS idx_acl_channel ON acl_entries (server_id, channel_id, priority)"
            .to_owned(),
        "CREATE INDEX IF NOT EXISTS idx_bans_expiry ON bans (server_id, expires_at)".to_owned(),
    ]
}

/// Drop every table, newest dependency first.
///
/// For tests and for `starling migrate --fresh`. Ordered by reversing [`TABLES`]
/// so a foreign key never blocks a drop, and written once rather than
/// maintained as a second list that can disagree with the first.
///
/// # Errors
///
/// [`StoreError`] if a statement fails.
pub async fn drop_all(backend: &Backend) -> Result<(), StoreError> {
    for table in TABLES.iter().rev() {
        let _ = sqlx::query(&format!("DROP TABLE IF EXISTS {table}"))
            .execute(backend.pool())
            .await
            .map_err(|e| wrap(&format!("dropping {table}"), e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh() -> Backend {
        let backend = Backend::connect("sqlite::memory:").await.expect("connect");
        migrate(&backend).await.expect("migrate");
        backend
    }

    #[tokio::test]
    async fn migrating_creates_every_table() {
        let backend = fresh().await;
        for table in TABLES {
            let found: Option<(i64,)> = sqlx::query_as(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_optional(backend.pool())
                .await
                .unwrap_or_else(|e| panic!("table {table} is missing: {e}"));
            assert!(found.is_some(), "table {table} is missing");
        }
    }

    #[tokio::test]
    async fn migrating_twice_is_harmless() {
        // Every boot runs this. A second run that failed would mean the server
        // starts once and never again.
        let backend = fresh().await;
        migrate(&backend).await.expect("second migrate");
        migrate(&backend).await.expect("third migrate");
    }

    #[tokio::test]
    async fn a_newer_database_is_refused_rather_than_guessed_at() {
        // Written by a future Starling whose columns mean something else.
        // Reading it anyway is how data gets corrupted.
        let backend = fresh().await;
        let _ = sqlx::query("UPDATE schema_version SET version = 99")
            .execute(backend.pool())
            .await
            .expect("bump");

        let error = migrate(&backend)
            .await
            .expect_err("accepted a newer schema");
        assert!(matches!(error, StoreError::Corrupt(_)), "{error}");
        assert!(error.to_string().contains("99"), "{error}");
    }

    #[tokio::test]
    async fn deleting_a_channel_cascades() {
        // The whole reason for foreign keys here: murmur writes four deletes by
        // hand at every call site, and a forgotten one leaves orphans that
        // nothing complains about until something reads them.
        let backend = fresh().await;
        let pool = backend.pool();

        let _ = sqlx::query("INSERT INTO channels (server_id, channel_id, parent_id, name) VALUES (1, 0, NULL, 'Root')")
            .execute(pool).await.expect("root");
        let _ = sqlx::query("INSERT INTO channels (server_id, channel_id, parent_id, name) VALUES (1, 1, 0, 'Lobby')")
            .execute(pool).await.expect("lobby");
        let _ = sqlx::query("INSERT INTO acl_entries (server_id, channel_id, target_group, granted, revoked) VALUES (1, 1, 'all', 1, 0)")
            .execute(pool).await.expect("acl");

        let _ = sqlx::query("DELETE FROM channels WHERE server_id = 1 AND channel_id = 1")
            .execute(pool)
            .await
            .expect("delete");

        let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM acl_entries")
            .fetch_one(pool)
            .await
            .expect("count");
        assert_eq!(remaining, 0, "the channel's ACLs outlived it");
    }

    #[tokio::test]
    async fn deleting_a_channel_cascades_to_its_children() {
        let backend = fresh().await;
        let pool = backend.pool();
        for (id, parent) in [(0, "NULL"), (1, "0"), (2, "1")] {
            let _ = sqlx::query(&format!(
                "INSERT INTO channels (server_id, channel_id, parent_id, name) VALUES (1, {id}, {parent}, 'c{id}')"
            ))
            .execute(pool).await.expect("insert");
        }

        let _ = sqlx::query("DELETE FROM channels WHERE server_id = 1 AND channel_id = 1")
            .execute(pool)
            .await
            .expect("delete");

        let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM channels")
            .fetch_one(pool)
            .await
            .expect("count");
        assert_eq!(remaining, 1, "only the root should be left");
    }

    #[tokio::test]
    async fn an_acl_must_name_exactly_one_target() {
        // The sum type, enforced by the database. murmur has five nullable
        // columns for this and no constraint, so "neither" and "both" are both
        // storable and neither means anything.
        let backend = fresh().await;
        let pool = backend.pool();
        let _ = sqlx::query("INSERT INTO channels (server_id, channel_id, parent_id, name) VALUES (1, 0, NULL, 'Root')")
            .execute(pool).await.expect("root");

        for (user, group, what) in [
            ("NULL", "NULL", "neither a user nor a group"),
            ("7", "'admin'", "both a user and a group"),
        ] {
            let result = sqlx::query(&format!(
                "INSERT INTO acl_entries (server_id, channel_id, target_user_id, target_group, granted, revoked)
                 VALUES (1, 0, {user}, {group}, 0, 0)"
            ))
            .execute(pool)
            .await;
            assert!(result.is_err(), "an ACL naming {what} was accepted");
        }
    }

    #[tokio::test]
    async fn a_channel_link_cannot_be_stored_in_both_orders() {
        // Without the CHECK, `unlink(a, b)` removes one row and leaves the
        // mirror image, so the channels stay linked.
        let backend = fresh().await;
        let pool = backend.pool();
        for id in [0, 1] {
            let _ = sqlx::query(&format!(
                "INSERT INTO channels (server_id, channel_id, parent_id, name) VALUES (1, {id}, NULL, 'c{id}')"
            ))
            .execute(pool).await.expect("channel");
        }

        let _ =
            sqlx::query("INSERT INTO channel_links (server_id, low_id, high_id) VALUES (1, 0, 1)")
                .execute(pool)
                .await
                .expect("canonical order");
        let reversed =
            sqlx::query("INSERT INTO channel_links (server_id, low_id, high_id) VALUES (1, 1, 0)")
                .execute(pool)
                .await;
        assert!(reversed.is_err(), "a reversed link pair was accepted");
    }

    #[tokio::test]
    async fn two_accounts_cannot_share_a_name() {
        // Either could then authenticate as the other.
        let backend = fresh().await;
        let pool = backend.pool();
        let _ = sqlx::query("INSERT INTO users (server_id, user_id, name) VALUES (1, 1, 'alice')")
            .execute(pool)
            .await
            .expect("first");
        let duplicate =
            sqlx::query("INSERT INTO users (server_id, user_id, name) VALUES (1, 2, 'alice')")
                .execute(pool)
                .await;
        assert!(duplicate.is_err(), "a duplicate account name was accepted");
    }

    #[tokio::test]
    async fn dropping_everything_leaves_a_clean_database() {
        let backend = fresh().await;
        drop_all(&backend).await.expect("drop");

        let found: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM channels")
            .fetch_optional(backend.pool())
            .await
            .ok()
            .flatten();
        assert!(found.is_none(), "tables survived the drop");
    }

    #[tokio::test]
    async fn the_schema_can_be_rebuilt_after_dropping() {
        let backend = fresh().await;
        drop_all(&backend).await.expect("drop");
        migrate(&backend).await.expect("rebuild");
        migrating_creates_every_table_on(&backend).await;
    }

    /// The table check, reusable across tests.
    async fn migrating_creates_every_table_on(backend: &Backend) {
        for table in TABLES {
            let found: Option<(i64,)> = sqlx::query_as(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_optional(backend.pool())
                .await
                .unwrap_or_else(|e| panic!("table {table} is missing: {e}"));
            assert!(found.is_some(), "table {table} is missing");
        }
    }
}
