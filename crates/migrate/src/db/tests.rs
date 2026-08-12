//! The reader, against real murmur databases.
//!
//! Built here rather than checked in as fixture files, because what is being
//! tested is a *schema*, and a schema written out as `CREATE TABLE` next to the
//! query that reads it is reviewable against upstream's own table definitions.
//! Both layouts are built, because the whole point of [`Layout`] is that both
//! are in the wild.

use super::*;

use starling_runtime::storage::Store;

/// A writable connection to a private in-memory database, and its URL.
///
/// The pool is returned and must be held: an in-memory SQLite database exists
/// only while something is connected to it, so dropping the writer would take
/// the fixture with it half way through the test.
async fn fixture(name: &str, statements: &[&str]) -> (Store, String) {
    let url = format!("sqlite:file:migrate-{name}?mode=memory&cache=shared");
    let store = Store::open(&url, 1).await.expect("an in-memory database");
    for statement in statements {
        store
            .execute(statement)
            .await
            .unwrap_or_else(|error| panic!("{statement}: {error}"));
    }
    (store, url)
}

/// The 1.5-and-later schema, with one of everything in it.
const MODERN: &[&str] = &[
    "CREATE TABLE \"virtual_servers\" (\"server_id\" INTEGER PRIMARY KEY)",
    "INSERT INTO \"virtual_servers\" VALUES (1)",
    "INSERT INTO \"virtual_servers\" VALUES (2)",
    "CREATE TABLE \"config\" (\"server_id\" INTEGER, \"config_name\" TEXT, \"config_value\" TEXT)",
    // `registername`, lowercase, is what the *table* calls it. The `.ini` calls
    // it `registerName`, and the reader that maps both is case-sensitive.
    "INSERT INTO \"config\" VALUES \
        (1, 'welcometext', 'hello'), (1, 'users', '42'), (1, 'registername', 'Frog Pond')",
    "CREATE TABLE \"channels\" (\"server_id\" INTEGER, \"channel_id\" INTEGER, \
        \"parent_id\" INTEGER, \"channel_name\" TEXT, \"inherit_acl\" INTEGER)",
    // The root is self-parented from schema v10 on, and the child names it.
    // Channel 2 is self-parented too and is not the root, which is how the
    // Fancy fork stores a *detached* channel: a meeting room or a friend chat,
    // parentless on purpose and in nobody's tree.
    "INSERT INTO \"channels\" VALUES \
        (1, 0, 0, 'Root', 1), (1, 1, 0, 'Lobby', 1), (1, 2, 2, 'Friends', 1)",
    "CREATE TABLE \"channel_properties\" (\"server_id\" INTEGER, \"channel_id\" INTEGER, \
        \"property_key\" INTEGER, \"property_value\" TEXT)",
    "INSERT INTO \"channel_properties\" VALUES \
        (1, 1, 0, 'a room'), (1, 1, 1, '3'), (1, 1, 2, '10'), (1, 1, 7, '1'), (1, 1, 10, '1700000000')",
    "CREATE TABLE \"channel_links\" (\"server_id\" INTEGER, \"first_channel_id\" INTEGER, \
        \"second_channel_id\" INTEGER)",
    "INSERT INTO \"channel_links\" VALUES (1, 0, 1)",
    "CREATE TABLE \"users\" (\"server_id\" INTEGER, \"user_id\" INTEGER, \"user_name\" TEXT, \
        \"password_hash\" TEXT, \"salt\" TEXT, \"kdf_iterations\" INTEGER, \
        \"last_channel_id\" INTEGER, \"texture\" BLOB, \"last_active\" BIGINT, \
        \"last_disconnect\" BIGINT)",
    "INSERT INTO \"users\" VALUES \
        (1, 0, 'SuperUser', 'aabb', '0011', 42000, 0, NULL, 1700000001, 1700000002), \
        (1, 1, 'alice', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', NULL, NULL, 1, NULL, 0, 0), \
        (1, 2, 'bob', NULL, NULL, NULL, 0, NULL, 0, 0)",
    "CREATE TABLE \"user_properties\" (\"server_id\" INTEGER, \"user_id\" INTEGER, \
        \"property_key\" INTEGER, \"property_value\" TEXT)",
    "INSERT INTO \"user_properties\" VALUES \
        (1, 1, 1, 'alice@example.test'), (1, 1, 2, 'hi'), (1, 1, 3, 'ff00'), (1, 1, 7, 'JBSWY3DP')",
    "CREATE TABLE \"groups\" (\"server_id\" INTEGER, \"group_id\" INTEGER, \"group_name\" TEXT, \
        \"channel_id\" INTEGER, \"inherit\" INTEGER, \"is_inheritable\" INTEGER)",
    "INSERT INTO \"groups\" VALUES (1, 7, 'admin', 0, 1, 1)",
    "CREATE TABLE \"group_members\" (\"server_id\" INTEGER, \"group_id\" INTEGER, \
        \"user_id\" INTEGER, \"add_to_group\" INTEGER)",
    "INSERT INTO \"group_members\" VALUES (1, 7, 1, 1), (1, 7, 2, 0)",
    "CREATE TABLE \"access_control_lists\" (\"server_id\" INTEGER, \"channel_id\" INTEGER, \
        \"priority\" INTEGER, \"affected_user_id\" INTEGER, \"affected_group_id\" INTEGER, \
        \"affected_meta_group_id\" INTEGER, \"access_token\" TEXT, \"group_modifiers\" TEXT, \
        \"apply_in_current_channel\" INTEGER, \"apply_in_sub_channels\" INTEGER, \
        \"granted_privilege_flags\" INTEGER, \"revoked_privilege_flags\" INTEGER)",
    "INSERT INTO \"access_control_lists\" VALUES \
        (1, 0, 0, NULL, 7, NULL, NULL, NULL, 1, 1, 65536, 0), \
        (1, 0, 1, NULL, NULL, 1, NULL, NULL, 1, 1, 12, 0), \
        (1, 1, 0, NULL, NULL, NULL, 'sesame', NULL, 1, 0, 4, 0), \
        (1, 1, 1, NULL, NULL, 4, NULL, '!;~', 1, 1, 0, 8), \
        (1, 1, 2, 3, NULL, NULL, NULL, NULL, 1, 1, 0, 4)",
    "CREATE TABLE \"channel_listeners\" (\"server_id\" INTEGER, \"user_id\" INTEGER, \
        \"channel_id\" INTEGER, \"volume_adjustment\" REAL, \"enabled\" INTEGER)",
    "INSERT INTO \"channel_listeners\" VALUES (1, 1, 1, 0.5, 1)",
    "CREATE TABLE \"bans\" (\"server_id\" INTEGER, \"ipv6_base_address\" VARCHAR(45), \
        \"prefix_length\" INTEGER, \"banned_user_cert_hash\" VARCHAR(255), \
        \"banned_user_name\" VARCHAR(255), \"reason\" TEXT, \"start_date\" BIGINT, \
        \"duration\" INTEGER)",
    "INSERT INTO \"bans\" VALUES \
        (1, '::ffff:192.0.2.7', 128, 'abcd', 'mallory', 'spam', 1700000000, 3600)",
];

/// The pre-1.5 schema, at its default (empty) table prefix.
const LEGACY: &[&str] = &[
    "CREATE TABLE \"servers\" (\"server_id\" INTEGER PRIMARY KEY AUTOINCREMENT)",
    "INSERT INTO \"servers\" VALUES (1)",
    "CREATE TABLE \"config\" (\"server_id\" INTEGER NOT NULL, \"key\" TEXT, \"value\" TEXT)",
    "INSERT INTO \"config\" VALUES (1, 'registerName', 'Frog Pond')",
    "CREATE TABLE \"channels\" (\"server_id\" INTEGER NOT NULL, \"channel_id\" INTEGER NOT NULL, \
        \"parent_id\" INTEGER, \"name\" TEXT, \"inheritacl\" INTEGER)",
    // The root's parent is NULL before schema v10, which is the other spelling
    // of "no parent" the reader has to understand.
    "INSERT INTO \"channels\" VALUES (1, 0, NULL, 'Root', 1), (1, 4, 0, 'Pond', 0)",
    "CREATE TABLE \"channel_info\" (\"server_id\" INTEGER NOT NULL, \"channel_id\" INTEGER NOT NULL, \
        \"key\" INTEGER, \"value\" TEXT)",
    "INSERT INTO \"channel_info\" VALUES (1, 4, 0, 'wet'), (1, 4, 2, '5')",
    "CREATE TABLE \"channel_links\" (\"server_id\" INTEGER NOT NULL, \"channel_id\" INTEGER NOT NULL, \
        \"link_id\" INTEGER NOT NULL)",
    "INSERT INTO \"channel_links\" VALUES (1, 0, 4)",
    "CREATE TABLE \"users\" (\"server_id\" INTEGER NOT NULL, \"user_id\" INTEGER NOT NULL, \
        \"name\" TEXT NOT NULL, \"pw\" TEXT, \"salt\" TEXT, \"kdfiterations\" INTEGER, \
        \"lastchannel\" INTEGER, \"texture\" BLOB, \"last_active\" DATE, \"last_disconnect\" DATE)",
    "INSERT INTO \"users\" VALUES \
        (1, 0, 'SuperUser', 'ccdd', '2233', 100000, 0, NULL, '2023-11-14 22:13:20', '2023-11-14 22:13:21')",
    "CREATE TABLE \"user_info\" (\"server_id\" INTEGER NOT NULL, \"user_id\" INTEGER NOT NULL, \
        \"key\" INTEGER, \"value\" TEXT)",
    "INSERT INTO \"user_info\" VALUES (1, 0, 1, 'root@example.test')",
    "CREATE TABLE \"groups\" (\"group_id\" INTEGER PRIMARY KEY AUTOINCREMENT, \
        \"server_id\" INTEGER NOT NULL, \"name\" TEXT, \"channel_id\" INTEGER NOT NULL, \
        \"inherit\" INTEGER, \"inheritable\" INTEGER)",
    "INSERT INTO \"groups\" VALUES (3, 1, 'moderator', 0, 1, 1)",
    "CREATE TABLE \"group_members\" (\"group_id\" INTEGER NOT NULL, \"server_id\" INTEGER NOT NULL, \
        \"user_id\" INTEGER NOT NULL, \"addit\" INTEGER)",
    "INSERT INTO \"group_members\" VALUES (3, 1, 0, 1)",
    "CREATE TABLE \"acl\" (\"server_id\" INTEGER NOT NULL, \"channel_id\" INTEGER NOT NULL, \
        \"priority\" INTEGER, \"user_id\" INTEGER, \"group_name\" TEXT, \"apply_here\" INTEGER, \
        \"apply_sub\" INTEGER, \"grantpriv\" INTEGER, \"revokepriv\" INTEGER)",
    "INSERT INTO \"acl\" VALUES (1, 0, 0, NULL, '~!moderator', 1, 1, 12, 0)",
    "CREATE TABLE \"bans\" (\"server_id\" INTEGER NOT NULL, \"base\" BLOB, \"mask\" INTEGER, \
        \"name\" TEXT, \"hash\" TEXT, \"reason\" TEXT, \"start\" DATE, \"duration\" INTEGER)",
    "INSERT INTO \"bans\" VALUES \
        (1, X'00000000000000000000ffffc0000207', 128, 'mallory', '', 'spam', '2023-11-14 22:13:20', 0)",
];

#[tokio::test]
async fn a_modern_database_is_recognised_and_read_whole() {
    let (_writer, url) = fixture("modern", MODERN).await;
    let source = Murmur::open(&url, "").await.expect("open");
    assert_eq!(source.layout(), Layout::Modern);
    assert_eq!(source.servers().await.expect("servers"), vec![1, 2]);

    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    assert_eq!(
        server.config.get("welcometext").map(String::as_str),
        Some("hello")
    );
    assert_eq!(server.channels.len(), 3);
    assert_eq!(
        server.links,
        vec![Link {
            channel: 0,
            linked: 1
        }]
    );
    assert_eq!(server.users.len(), 3);
    assert_eq!(server.groups.len(), 1);
    assert_eq!(server.members.len(), 2);
    assert_eq!(server.listeners.len(), 1);
    assert_eq!(server.bans.len(), 1);
}

#[tokio::test]
async fn the_root_is_parentless_however_murmur_spelled_it() {
    // Self-parented since schema v10 and NULL before it. Reading a self-parent
    // as a parent builds a cycle, and whatever walks the tree then hangs.
    let (_writer, modern_url) = fixture("root-modern", MODERN).await;
    let modern = Murmur::open(&modern_url, "").await.expect("open");
    let mut report = Report::new();
    let server = modern.read(1, &mut report).await.expect("read");
    let root = server.channels.iter().find(|c| c.id == 0).expect("a root");
    assert_eq!(root.parent, None);
    assert!(!root.detached, "the root is not a detached channel");
    assert_eq!(
        server
            .channels
            .iter()
            .find(|c| c.id == 1)
            .and_then(|c| c.parent),
        Some(0),
        "a real parent must survive"
    );

    // Parentless *and* detached, which is a different thing from being the
    // root. A consumer that cannot tell them apart draws every meeting room and
    // friend chat as a second root.
    let detached = server.channels.iter().find(|c| c.id == 2).expect("Friends");
    assert_eq!(detached.parent, None);
    assert!(detached.detached);

    let (_legacy_writer, legacy_url) = fixture("root-legacy", LEGACY).await;
    let legacy = Murmur::open(&legacy_url, "").await.expect("open");
    let server = legacy.read(1, &mut report).await.expect("read");
    assert_eq!(
        server
            .channels
            .iter()
            .find(|c| c.id == 0)
            .and_then(|c| c.parent),
        None
    );
}

#[tokio::test]
async fn channel_properties_become_typed_fields() {
    // `docs/STORAGE.md` L1: eight of murmur's twelve keys are numbers stored as
    // text, and a channel is one row here.
    let (_writer, url) = fixture("properties", MODERN).await;
    let source = Murmur::open(&url, "").await.expect("open");
    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    let lobby = server
        .channels
        .iter()
        .find(|c| c.id == 1)
        .expect("the lobby");
    assert_eq!(lobby.description, "a room");
    assert_eq!(lobby.position, 3);
    assert_eq!(lobby.max_users, 10);
    assert!(lobby.hidden);
    assert_eq!(
        lobby.created_at_ms, 1_700_000_000_000,
        "murmur counts seconds and Starling counts milliseconds"
    );
}

#[tokio::test]
async fn a_group_specification_is_put_back_together_from_its_columns() {
    // The 1.5 schema splits `~!moderator` over five columns. An evaluator reads
    // the text form, so an import that handed it a bare group name would apply
    // the entry in the wrong channel and to the wrong people.
    let (_writer, url) = fixture("groupspec", MODERN).await;
    let source = Murmur::open(&url, "").await.expect("open");
    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    let by_priority = |channel: u32, priority: i32| {
        server
            .acls
            .iter()
            .find(|acl| acl.channel == channel && acl.priority == priority)
            .cloned()
            .expect("an entry")
    };

    assert_eq!(by_priority(0, 0).group.as_deref(), Some("admin"));
    assert_eq!(
        by_priority(0, 1).group.as_deref(),
        Some("all"),
        "a meta group is named by its number in the column"
    );
    assert_eq!(
        by_priority(1, 0).group.as_deref(),
        Some("#sesame"),
        "an access token keeps the # the grammar reads it by"
    );
    assert_eq!(
        by_priority(1, 1).group.as_deref(),
        Some("~!in"),
        "modifiers are applied in order, outermost last"
    );
    assert_eq!(by_priority(1, 2).user, Some(3));
    assert_eq!(by_priority(1, 2).group, None);
}

#[tokio::test]
async fn both_password_forms_survive_the_read() {
    let (_writer, url) = fixture("passwords", MODERN).await;
    let source = Murmur::open(&url, "").await.expect("open");
    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    let user = |name: &str| {
        server
            .users
            .iter()
            .find(|u| u.name == name)
            .cloned()
            .expect("a user")
    };

    assert_eq!(
        user("SuperUser").password,
        Password::Pbkdf2 {
            salt: vec![0x00, 0x11],
            key: vec![0xaa, 0xbb],
            iterations: 42_000,
        }
    );
    assert!(
        matches!(user("alice").password, Password::Sha1 { ref digest } if digest.len() == 20),
        "no iteration count means murmur's pre-1.3 unsalted digest"
    );
    assert_eq!(
        user("bob").password,
        Password::None,
        "an account reached by certificate has no password at all"
    );
}

#[tokio::test]
async fn account_properties_land_on_the_account_they_name() {
    let (_writer, url) = fixture("userprops", MODERN).await;
    let source = Murmur::open(&url, "").await.expect("open");
    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    let alice = server
        .users
        .iter()
        .find(|u| u.name == "alice")
        .expect("alice");
    assert_eq!(alice.email, "alice@example.test");
    assert_eq!(alice.comment, "hi");
    assert_eq!(alice.cert_hash, "ff00");
    assert_eq!(alice.totp_secret, "JBSWY3DP");
}

#[tokio::test]
async fn a_legacy_database_is_recognised_and_read_whole() {
    let (_writer, url) = fixture("legacy", LEGACY).await;
    let source = Murmur::open(&url, "").await.expect("open");
    assert_eq!(source.layout(), Layout::Legacy);
    assert_eq!(source.servers().await.expect("servers"), vec![1]);

    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    assert_eq!(
        server.config.get("registerName").map(String::as_str),
        Some("Frog Pond")
    );
    let pond = server
        .channels
        .iter()
        .find(|c| c.id == 4)
        .expect("the pond");
    assert_eq!(pond.description, "wet");
    assert_eq!(pond.max_users, 5);
    assert!(!pond.inherit_acl, "`inheritacl` is the pre-v10 spelling");
    assert_eq!(server.acls.len(), 1);
    assert_eq!(
        server.acls.first().and_then(|acl| acl.group.clone()),
        Some("~!moderator".to_owned()),
        "the old schema already stores the text form"
    );
    assert!(
        server.listeners.is_empty(),
        "listeners were introduced in schema v9 and this is older"
    );
}

#[tokio::test]
async fn a_legacy_date_column_is_read_as_a_time_rather_than_a_zero() {
    // Dropping these would silently expire every temporary ban in a 1.4
    // database and reset every last-seen to 1970.
    let (_writer, url) = fixture("legacy-dates", LEGACY).await;
    let source = Murmur::open(&url, "").await.expect("open");
    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    assert_eq!(
        server.users.first().map(|user| user.last_active_s),
        Some(1_700_000_000)
    );
    assert_eq!(
        server.bans.first().map(|ban| ban.start_s),
        Some(1_700_000_000)
    );
}

#[tokio::test]
async fn a_ban_address_arrives_as_bytes_from_either_representation() {
    let expected = std::net::Ipv4Addr::new(192, 0, 2, 7)
        .to_ipv6_mapped()
        .octets()
        .to_vec();

    let (_modern_writer, modern_url) = fixture("ban-modern", MODERN).await;
    let mut report = Report::new();
    let modern = Murmur::open(&modern_url, "")
        .await
        .expect("open")
        .read(1, &mut report)
        .await
        .expect("read");
    assert_eq!(
        modern.bans.first().map(|ban| ban.address.clone()),
        Some(expected.clone())
    );

    let (_legacy_writer, legacy_url) = fixture("ban-legacy", LEGACY).await;
    let legacy = Murmur::open(&legacy_url, "")
        .await
        .expect("open")
        .read(1, &mut report)
        .await
        .expect("read");
    assert_eq!(
        legacy.bans.first().map(|ban| ban.address.clone()),
        Some(expected)
    );
}

#[tokio::test]
async fn the_operators_table_prefix_is_honoured() {
    // `dbPrefix` is empty in every default deployment and set in some real ones,
    // and a database with one is unreadable without it.
    let prefixed: Vec<String> = LEGACY
        .iter()
        .map(|statement| {
            statement
                .replace("\"servers\"", "\"mb_servers\"")
                .replace("\"config\"", "\"mb_config\"")
                .replace("\"channels\"", "\"mb_channels\"")
                .replace("\"channel_info\"", "\"mb_channel_info\"")
                .replace("\"channel_links\"", "\"mb_channel_links\"")
                .replace("\"users\"", "\"mb_users\"")
                .replace("\"user_info\"", "\"mb_user_info\"")
                .replace("\"groups\"", "\"mb_groups\"")
                .replace("\"group_members\"", "\"mb_group_members\"")
                .replace("\"acl\"", "\"mb_acl\"")
                .replace("\"bans\"", "\"mb_bans\"")
        })
        .collect();
    let statements: Vec<&str> = prefixed.iter().map(String::as_str).collect();
    let (_writer, url) = fixture("prefixed", &statements).await;

    assert!(
        Murmur::open(&url, "").await.is_err(),
        "without the prefix there is no murmur database here to find"
    );
    let source = Murmur::open(&url, "mb_").await.expect("open");
    assert_eq!(source.layout(), Layout::Legacy);
    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");
    assert_eq!(server.channels.len(), 2);
}

#[tokio::test]
async fn a_prefix_that_is_not_an_identifier_is_refused() {
    // It names a table. Anything else is a way to write SQL.
    let error = Murmur::open("sqlite::memory:", "x\"; DROP TABLE users; --")
        .await
        .expect_err("a prefix that is not an identifier");
    assert!(matches!(error, ReadError::BadPrefix(_)), "{error}");
}

#[tokio::test]
async fn a_database_that_is_not_murmurs_is_named_rather_than_read_as_empty() {
    // The failure this heads off: pointing the tool at the wrong file and being
    // told the migration succeeded and moved nothing.
    let (_writer, url) = fixture("not-murmur", &["CREATE TABLE cats (name TEXT)"]).await;
    let error = Murmur::open(&url, "")
        .await
        .expect_err("this is not a murmur database");
    assert!(matches!(error, ReadError::NotMurmur { .. }), "{error}");
}

#[tokio::test]
async fn a_property_with_no_home_is_reported_rather_than_dropped_in_silence() {
    let statements: Vec<String> = MODERN
        .iter()
        .map(|s| (*s).to_owned())
        .chain([
            "INSERT INTO \"channel_properties\" VALUES (1, 1, 99, 'whatever')".to_owned(),
            "INSERT INTO \"channel_properties\" VALUES (1, 1, 1, 'sideways')".to_owned(),
        ])
        .collect();
    let refs: Vec<&str> = statements.iter().map(String::as_str).collect();
    let (_writer, url) = fixture("unmapped", &refs).await;

    let source = Murmur::open(&url, "").await.expect("open");
    let mut report = Report::new();
    let _server = source.read(1, &mut report).await.expect("read");

    assert!(
        report
            .notes()
            .iter()
            .any(|note| note.contains("property 99")),
        "{:?}",
        report.notes()
    );
    assert!(
        report.notes().iter().any(|note| note.contains("sideways")),
        "a position that is not a number must be reported, not read as 0: {:?}",
        report.notes()
    );
}

#[test]
fn a_sqlite_source_is_opened_read_only() {
    // Requirement 1 of `docs/STORAGE.md` §4. It also stops sqlx creating an
    // empty file for a mistyped path, which would report a migration of a
    // server with no channels rather than "no such file".
    assert_eq!(
        read_only_url("sqlite:/data/mumble-server.sqlite"),
        "sqlite:/data/mumble-server.sqlite?mode=ro"
    );
    assert_eq!(
        read_only_url("sqlite:/data/db.sqlite?cache=private"),
        "sqlite:/data/db.sqlite?cache=private&mode=ro"
    );
    assert_eq!(
        read_only_url("sqlite:/data/db.sqlite?mode=rwc"),
        "sqlite:/data/db.sqlite?mode=rwc",
        "a mode the caller asked for is left alone"
    );
    assert_eq!(
        read_only_url("postgres://user@host/mumble"),
        "postgres://user@host/mumble",
        "no other backend states this in the URL"
    );
}

#[tokio::test]
async fn the_public_listing_survives_the_tables_own_spelling_of_it() {
    // The table says `registername` and the `.ini` says `registerName`. The
    // public listing is exactly the block an operator sets from the admin
    // interface rather than the file, so it is in the table and nowhere else;
    // unmapped, a migrated server stops being listed and nothing says why.
    let (_writer, url) = fixture("register", MODERN).await;
    let source = Murmur::open(&url, "").await.expect("open");
    let mut report = Report::new();
    let server = source.read(1, &mut report).await.expect("read");

    let settings = crate::Ini::from_pairs(server.config).to_settings();
    assert_eq!(settings.registry_name.as_deref(), Some("Frog Pond"));
    assert_eq!(settings.max_users, Some(42));
    assert_eq!(settings.welcome_text.as_deref(), Some("hello"));
}

#[test]
fn only_the_keys_the_two_spell_differently_are_rewritten() {
    assert_eq!(config_key("registername"), "registerName");
    assert_eq!(config_key("registerurl"), "registerUrl");
    assert_eq!(
        config_key("welcometext"),
        "welcometext",
        "everything else is lowercase in both and must be left alone"
    );
}

#[test]
fn modifiers_wrap_a_group_name_the_way_murmur_wrote_it() {
    assert_eq!(apply_modifiers("in", "!;~"), "~!in");
    assert_eq!(apply_modifiers("sub", ",1,2"), "sub,1,2");
    assert_eq!(apply_modifiers("admin", ""), "admin");
}

#[test]
fn the_meta_group_numbers_are_the_ones_in_the_column() {
    // Sorting this list alphabetically would rewrite every ACL entry that names
    // a meta group, and the server would still start.
    assert_eq!(meta_group_name(0), Some("none"));
    assert_eq!(meta_group_name(1), Some("all"));
    assert_eq!(meta_group_name(2), Some("auth"));
    assert_eq!(meta_group_name(6), Some("sub"));
    assert_eq!(meta_group_name(7), None);
}
