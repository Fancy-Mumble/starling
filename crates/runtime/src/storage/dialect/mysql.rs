//! MySQL and MariaDB.
//!
//! The two are treated as one because they still agree on everything this crate
//! asks. Where they diverge — and the upsert clause is the place they nearly do
//! — the older spelling is used, because MariaDB has not adopted the newer one.

use super::SqlDialect;

/// MySQL's and MariaDB's SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MySql;

impl SqlDialect for MySql {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn placeholder(&self, _index: usize) -> String {
        "?".to_owned()
    }

    fn varchar(&self, len: u32) -> String {
        // The one backend that genuinely needs this: MySQL refuses to index a
        // `TEXT` column without a prefix length, so every string in a primary
        // key or unique constraint has to carry a bound.
        format!("VARCHAR({len})")
    }

    fn auto_increment_pk(&self) -> String {
        "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY".to_owned()
    }

    fn upsert_suffix(&self, _keys: &[&str], updates: &[&str]) -> String {
        // MySQL has no `ON CONFLICT`, and infers the conflict target from
        // whichever unique constraint the insert violated — so `keys` is unused
        // here rather than ignored by mistake.
        //
        // `VALUES()` is deprecated in MySQL 8 in favour of a row alias, but
        // MariaDB does not accept the alias form. Both are targets, and only
        // this spelling works on both.
        let sets = updates
            .iter()
            .map(|column| format!("`{column}` = VALUES(`{column}`)"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" ON DUPLICATE KEY UPDATE {sets}")
    }

    fn quote(&self, identifier: &str) -> String {
        // Backticks. MySQL reads a double quote as a string literal unless
        // `ANSI_QUOTES` is set, which is not something to depend on.
        format!("`{identifier}`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_strings_carry_a_length() {
        // MySQL refuses to index `TEXT` without one.
        assert_eq!(MySql.varchar(255), "VARCHAR(255)");
        assert_eq!(MySql.varchar(64), "VARCHAR(64)");
    }

    #[test]
    fn unindexed_text_does_not() {
        assert_eq!(MySql.text(), "TEXT");
    }

    #[test]
    fn identifiers_use_backticks() {
        // A double quote is a string literal here unless `ANSI_QUOTES` is set.
        assert_eq!(MySql.quote("key"), "`key`");
    }

    #[test]
    fn upserts_use_the_spelling_mariadb_also_accepts() {
        // MySQL 8 prefers a row alias; MariaDB rejects it. Both are targets.
        let clause = MySql.upsert_suffix(&["server_id", "key"], &["value"]);
        assert!(clause.contains("ON DUPLICATE KEY UPDATE"), "{clause}");
        assert!(clause.contains("VALUES(`value`)"), "{clause}");
        assert!(!clause.contains("ON CONFLICT"), "{clause}");
    }

    #[test]
    fn foreign_keys_need_no_asking() {
        assert!(MySql.foreign_key_pragma().is_none());
    }
}
