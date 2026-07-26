//! SQLite, including in-memory.
//!
//! The default, and the one every test runs against — a real SQL engine with no
//! server to start, which is why the schema is exercised rather than mocked.

use super::SqlDialect;

/// SQLite's SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sqlite;

impl SqlDialect for Sqlite {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn placeholder(&self, _index: usize) -> String {
        // Positional: SQLite reads `?` in order and ignores any number written
        // after it, so numbering would be decoration that PostgreSQL then takes
        // literally.
        "?".to_owned()
    }

    fn varchar(&self, _len: u32) -> String {
        // SQLite has no length limits and stores everything as text anyway; a
        // bound here would be a promise the engine does not keep.
        "TEXT".to_owned()
    }

    fn auto_increment_pk(&self) -> String {
        // `AUTOINCREMENT` rather than a bare `INTEGER PRIMARY KEY`: without it
        // SQLite reuses the ids of deleted rows, so a group id could come back
        // pointing at a different group's memberships.
        "INTEGER PRIMARY KEY AUTOINCREMENT".to_owned()
    }

    fn upsert_suffix(&self, keys: &[&str], updates: &[&str]) -> String {
        let conflict = keys
            .iter()
            .map(|key| format!("\"{key}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let sets = updates
            .iter()
            .map(|column| format!("\"{column}\" = excluded.\"{column}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" ON CONFLICT ({conflict}) DO UPDATE SET {sets}")
    }

    fn foreign_key_pragma(&self) -> Option<&'static str> {
        // SQLite parses foreign keys and then ignores them unless this is set,
        // per connection. Without it every `ON DELETE CASCADE` in the schema is
        // decoration, and orphaned rows accumulate silently.
        Some("PRAGMA foreign_keys = ON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_positional() {
        assert_eq!(Sqlite.placeholder(1), "?");
        assert_eq!(Sqlite.placeholder(9), "?", "SQLite does not number them");
    }

    #[test]
    fn assigned_keys_are_not_reused() {
        // A bare `INTEGER PRIMARY KEY` reuses the ids of deleted rows, so a
        // group id could come back pointing at another group's memberships.
        assert!(Sqlite.auto_increment_pk().contains("AUTOINCREMENT"));
    }

    #[test]
    fn foreign_keys_must_be_asked_for() {
        assert_eq!(
            Sqlite.foreign_key_pragma(),
            Some("PRAGMA foreign_keys = ON")
        );
    }

    #[test]
    fn an_upsert_names_its_conflict_target_and_updates() {
        let clause = Sqlite.upsert_suffix(&["server_id", "key"], &["value"]);
        assert!(
            clause.contains("ON CONFLICT (\"server_id\", \"key\")"),
            "{clause}"
        );
        assert!(
            clause.contains("\"value\" = excluded.\"value\""),
            "{clause}"
        );
    }
}
