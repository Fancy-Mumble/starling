//! What the three backends disagree about, one implementation each.
//!
//! sqlx's `Any` driver unifies the wire protocol. It does not unify the SQL, and
//! the differences are not cosmetic: a placeholder written the wrong way, or a
//! `CREATE TABLE` using the wrong auto-increment syntax, fails outright — but
//! only on the backend nobody develops against.
//!
//! # Why this is a trait and not a `match` per question
//!
//! It was a `match` per question, and that is closed against exactly the change
//! it should be open to. Seven methods each matching three ways means adding a
//! fourth backend edits seven places, and the compiler only catches it because
//! the matches are exhaustive — miss one `_ =>` arm and it does not catch it at
//! all.
//!
//! Here each backend is one type implementing [`SqlDialect`], and [`Dialect`]
//! carries it. Adding one is a new file, a new variant, and one arm in
//! [`Dialect::behaviour`] — nothing that already works is touched.
//!
//! # The differences, in one table
//!
//! | | SQLite | MySQL | PostgreSQL |
//! |---|---|---|---|
//! | placeholder | `?` | `?` | `$1` |
//! | indexed string | `TEXT` | `VARCHAR(n)` | `TEXT` |
//! | assigned key | `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGINT AUTO_INCREMENT` | `BIGSERIAL` |
//! | upsert | `ON CONFLICT` | `ON DUPLICATE KEY` | `ON CONFLICT` |
//! | quoting | `"x"` | `` `x` `` | `"x"` |
//! | foreign keys | off unless asked | always | always |

mod mysql;
mod postgres;
mod sqlite;

pub use mysql::MySql;
pub use postgres::Postgres;
pub use sqlite::Sqlite;

use starling_api::StoreError;

/// The SQL one backend speaks.
///
/// Every method answers a question the three genuinely disagree about. A
/// question they agree on does not belong here — it belongs in the query.
pub trait SqlDialect: std::fmt::Debug + Send + Sync {
    /// A short name, for logs and the admin surface.
    fn name(&self) -> &'static str;

    /// The placeholder for parameter `index`, counting from one.
    ///
    /// PostgreSQL numbers its parameters; the other two do not.
    fn placeholder(&self, index: usize) -> String;

    /// The column type for a string that appears in a key or an index.
    ///
    /// MySQL cannot index `TEXT` without a prefix length, so it needs a bound.
    fn varchar(&self, len: u32) -> String;

    /// The column type for unbounded text that is never indexed.
    fn text(&self) -> String {
        // All three spell this the same; the default keeps it out of three files
        // that would then be free to drift.
        "TEXT".to_owned()
    }

    /// A primary key the database assigns.
    fn auto_increment_pk(&self) -> String;

    /// The clause that turns an `INSERT` into an upsert.
    ///
    /// `keys` are the conflict target; `updates` are the columns to overwrite.
    fn upsert_suffix(&self, keys: &[&str], updates: &[&str]) -> String;

    /// Quote an identifier.
    fn quote(&self, identifier: &str) -> String {
        format!("\"{identifier}\"")
    }

    /// A statement that must run per connection before foreign keys are
    /// enforced, if this backend needs one.
    ///
    /// SQLite parses foreign keys and then ignores them by default, which is the
    /// worst of both. The other two enforce them always and return `None`.
    fn foreign_key_pragma(&self) -> Option<&'static str> {
        None
    }
}

/// Which backend a store is talking to.
///
/// Carries the implementation rather than being a bare tag, so the behaviour
/// lives with the backend it belongs to instead of in a `match` at every call
/// site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// SQLite, including in-memory.
    Sqlite(Sqlite),
    /// MySQL and MariaDB.
    MySql(MySql),
    /// PostgreSQL.
    Postgres(Postgres),
}

impl Dialect {
    /// The dialect a connection URL asks for.
    ///
    /// The one place that maps schemes to backends. Adding a fourth is an arm
    /// here and a new file; nothing else in the crate changes.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] for a scheme none of them understand. Named
    /// rather than defaulted: silently choosing SQLite for a typo'd Postgres URL
    /// would start the server against an empty local file and look like data
    /// loss.
    pub fn from_url(url: &str) -> Result<Self, StoreError> {
        match url.split(':').next().unwrap_or_default() {
            "sqlite" => Ok(Self::Sqlite(Sqlite)),
            "mysql" | "mariadb" => Ok(Self::MySql(MySql)),
            "postgres" | "postgresql" => Ok(Self::Postgres(Postgres)),
            other => Err(StoreError::Backend(format!(
                "unsupported database scheme `{other}`; expected sqlite, mysql or postgres"
            ))),
        }
    }

    /// The implementation this variant carries.
    ///
    /// The only `match` over the backends in the crate. Everything else goes
    /// through the trait, which is what makes adding one additive.
    fn behaviour(&self) -> &dyn SqlDialect {
        match self {
            Self::Sqlite(dialect) => dialect,
            Self::MySql(dialect) => dialect,
            Self::Postgres(dialect) => dialect,
        }
    }

    /// A list of `n` placeholders, comma-separated.
    ///
    /// On the enum rather than the trait: it is the same for every backend once
    /// [`SqlDialect::placeholder`] is known, so putting it on the trait would
    /// invite three identical implementations.
    #[must_use]
    pub fn placeholders(&self, n: usize) -> String {
        (1..=n)
            .map(|i| self.placeholder(i))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Delegate every question to the carried implementation.
///
/// So callers hold a `Dialect` and call trait methods on it directly, without
/// unwrapping the variant or knowing there is one.
impl SqlDialect for Dialect {
    fn name(&self) -> &'static str {
        self.behaviour().name()
    }

    fn placeholder(&self, index: usize) -> String {
        self.behaviour().placeholder(index)
    }

    fn varchar(&self, len: u32) -> String {
        self.behaviour().varchar(len)
    }

    fn text(&self) -> String {
        self.behaviour().text()
    }

    fn auto_increment_pk(&self) -> String {
        self.behaviour().auto_increment_pk()
    }

    fn upsert_suffix(&self, keys: &[&str], updates: &[&str]) -> String {
        self.behaviour().upsert_suffix(keys, updates)
    }

    fn quote(&self, identifier: &str) -> String {
        self.behaviour().quote(identifier)
    }

    fn foreign_key_pragma(&self) -> Option<&'static str> {
        self.behaviour().foreign_key_pragma()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every backend, for properties that must hold across all of them.
    fn all() -> Vec<Dialect> {
        vec![
            Dialect::Sqlite(Sqlite),
            Dialect::MySql(MySql),
            Dialect::Postgres(Postgres),
        ]
    }

    #[test]
    fn every_supported_scheme_resolves() {
        for (url, expected) in [
            ("sqlite::memory:", "sqlite"),
            ("sqlite://starling.db", "sqlite"),
            ("mysql://user:pw@host/db", "mysql"),
            ("mariadb://user:pw@host/db", "mysql"),
            ("postgres://user:pw@host/db", "postgres"),
            ("postgresql://user:pw@host/db", "postgres"),
        ] {
            assert_eq!(Dialect::from_url(url).expect(url).name(), expected, "{url}");
        }
    }

    #[test]
    fn an_unknown_scheme_is_named_not_defaulted() {
        // Defaulting to SQLite for a typo'd Postgres URL would start the server
        // against an empty local file, which looks exactly like data loss.
        let error = Dialect::from_url("postgrez://host/db").expect_err("accepted");
        assert!(error.to_string().contains("postgrez"), "{error}");
    }

    #[test]
    fn the_enum_answers_as_the_backend_it_carries() {
        // The delegation, which is the whole point of the shape: a caller holds
        // a `Dialect` and never unwraps it.
        assert_eq!(Dialect::Postgres(Postgres).placeholder(2), "$2");
        assert_eq!(Dialect::Sqlite(Sqlite).placeholder(2), "?");
        assert_eq!(Dialect::MySql(MySql).quote("key"), "`key`");
    }

    #[test]
    fn placeholders_are_numbered_from_one() {
        assert_eq!(Dialect::Postgres(Postgres).placeholders(3), "$1, $2, $3");
        assert_eq!(Dialect::Sqlite(Sqlite).placeholders(3), "?, ?, ?");
    }

    #[test]
    fn every_backend_can_express_an_assigned_key() {
        // None of the three accepts either of the others' syntax, so a missing
        // implementation is a `CREATE TABLE` that fails on that backend alone.
        for dialect in all() {
            let ddl = dialect.auto_increment_pk();
            assert!(
                !ddl.is_empty(),
                "{} has no assigned-key syntax",
                dialect.name()
            );
        }
    }

    #[test]
    fn every_backend_can_express_an_upsert() {
        for dialect in all() {
            let clause = dialect.upsert_suffix(&["server_id", "key"], &["value"]);
            assert!(
                clause.contains("UPDATE"),
                "{} produced no update clause: {clause}",
                dialect.name()
            );
        }
    }

    #[test]
    fn only_sqlite_needs_asking_about_foreign_keys() {
        // The others enforce them always. SQLite parses them and then ignores
        // them unless told otherwise, which is the worst of both.
        assert!(Dialect::Sqlite(Sqlite).foreign_key_pragma().is_some());
        assert!(Dialect::MySql(MySql).foreign_key_pragma().is_none());
        assert!(Dialect::Postgres(Postgres).foreign_key_pragma().is_none());
    }

    #[test]
    fn an_indexed_string_is_bounded_only_where_it_must_be() {
        // MySQL cannot index `TEXT` without a prefix length.
        assert_eq!(Dialect::MySql(MySql).varchar(255), "VARCHAR(255)");
        assert_eq!(Dialect::Sqlite(Sqlite).varchar(255), "TEXT");
        assert_eq!(Dialect::Postgres(Postgres).varchar(255), "TEXT");
    }
}
