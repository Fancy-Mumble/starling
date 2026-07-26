//! PostgreSQL.
//!
//! The only one of the three that numbers its placeholders, which is the
//! difference most likely to be missed: a statement written with `?` fails here
//! and nowhere else.

use super::SqlDialect;

/// PostgreSQL's SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Postgres;

impl SqlDialect for Postgres {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn placeholder(&self, index: usize) -> String {
        // Numbered from one, and the number is meaningful: the same parameter
        // can be referenced twice by writing `$1` twice, which the positional
        // backends cannot express.
        format!("${index}")
    }

    fn varchar(&self, _len: u32) -> String {
        // PostgreSQL indexes `TEXT` without complaint, and a bound would be an
        // arbitrary limit rather than a requirement.
        "TEXT".to_owned()
    }

    fn auto_increment_pk(&self) -> String {
        // `BIGSERIAL` creates the sequence and the default in one word. The
        // spelled-out `GENERATED ... AS IDENTITY` is more modern but needs a
        // newer server than some deployments run.
        "BIGSERIAL PRIMARY KEY".to_owned()
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_numbered() {
        // The difference most likely to be missed: a statement written with `?`
        // fails here and on neither of the others.
        assert_eq!(Postgres.placeholder(1), "$1");
        assert_eq!(Postgres.placeholder(12), "$12");
    }

    #[test]
    fn text_is_indexable_unbounded() {
        assert_eq!(Postgres.varchar(255), "TEXT");
    }

    #[test]
    fn identifiers_use_double_quotes() {
        assert_eq!(Postgres.quote("key"), "\"key\"");
    }

    #[test]
    fn upserts_name_their_conflict_target() {
        // Unlike MySQL, PostgreSQL will not infer it.
        let clause = Postgres.upsert_suffix(&["server_id", "key"], &["value"]);
        assert!(
            clause.contains("ON CONFLICT (\"server_id\", \"key\")"),
            "{clause}"
        );
        assert!(clause.contains("excluded."), "{clause}");
    }

    #[test]
    fn foreign_keys_need_no_asking() {
        assert!(Postgres.foreign_key_pragma().is_none());
    }
}
