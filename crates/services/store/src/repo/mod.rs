//! The repositories, and what they share.
//!
//! One module per aggregate. Everything common is [`Scoped`]: a pool, a virtual
//! server id, and the two chores every query has — writing placeholders the way
//! the dialect wants them, and remembering the `server_id` bind.
//!
//! # Why queries are written with `{1}` rather than `?` or `$1`
//!
//! PostgreSQL numbers its placeholders and the other two do not, so the same
//! statement cannot be written once for all three. Writing it three times is
//! worse: two of the copies are never exercised on the developer's machine, and
//! they drift.
//!
//! So statements are written with `{n}` and [`Scoped::sql`] rewrites them. The
//! marker looks like a format placeholder deliberately — it numbers the same way
//! and reads the same way — but is substituted here rather than by `format!`,
//! because a value interpolated into SQL is an injection and a placeholder is
//! not.

mod acls;
mod bans;
mod channels;
mod config;
mod log;
mod nothing;
mod users;

pub(crate) use acls::Acls;
pub(crate) use bans::Bans;
pub(crate) use channels::Channels;
pub(crate) use config::Config;
pub(crate) use log::Log;
pub(crate) use nothing::Nothing;
pub(crate) use users::Users;

use sqlx::AnyPool;
use starling_api::StoreError;

use crate::backend::Backend;
use crate::dialect::SqlDialect;

/// A pool, a dialect, and the virtual server every query is scoped to.
#[derive(Debug)]
pub(crate) struct Scoped {
    backend: Backend,
    server_id: i64,
}

impl Scoped {
    /// Bind to a backend and a virtual server.
    #[must_use]
    pub(crate) const fn new(backend: Backend, server_id: i64) -> Self {
        Self { backend, server_id }
    }

    /// The pool to query through.
    #[must_use]
    pub(crate) fn pool(&self) -> &AnyPool {
        self.backend.pool()
    }

    /// The virtual server this repository speaks for.
    #[must_use]
    pub(crate) const fn server_id(&self) -> i64 {
        self.server_id
    }

    /// Rewrite `{n}` markers into the dialect's placeholders.
    ///
    /// Substituting from the highest index down, so `{10}` is not partially
    /// matched by `{1}` — a bug that would only appear on a query with ten or
    /// more parameters, which is exactly the sort nobody writes a test for.
    #[must_use]
    pub(crate) fn sql(&self, template: &str) -> String {
        const MAX_PARAMS: usize = 32;
        let dialect = self.backend.dialect();
        let mut out = template.to_owned();
        for index in (1..=MAX_PARAMS).rev() {
            out = out.replace(&format!("{{{index}}}"), &dialect.placeholder(index));
        }
        out
    }

    /// Rewrite `{n}` markers and append the dialect's upsert clause.
    #[must_use]
    pub(crate) fn upsert(&self, template: &str, keys: &[&str], updates: &[&str]) -> String {
        let mut sql = self.sql(template);
        sql.push_str(&self.backend.dialect().upsert_suffix(keys, updates));
        sql
    }
}

/// A column was missing or the wrong type.
///
/// Always [`StoreError::Corrupt`] rather than `Backend`: the query named the
/// column, so if it is not there the schema is not what this build expects, and
/// retrying reads the same row again.
pub(crate) fn cell(error: &sqlx::Error) -> StoreError {
    StoreError::Corrupt(format!("unexpected column shape: {error}"))
}

/// Read a `u32` id out of the `i64` every backend hands back.
///
/// SQLite has no unsigned types and `Any` normalises everything to `i64`, so a
/// negative or oversized value means the row was written by something that does
/// not share this schema's assumptions. That is corruption, not a backend fault.
///
/// # Errors
///
/// [`StoreError::Corrupt`] if the value does not fit.
pub(crate) fn u32_from(value: i64) -> Result<u32, StoreError> {
    u32::try_from(value)
        .map_err(|_| StoreError::Corrupt(format!("id {value} is out of range for this schema")))
}

/// Read a boolean out of the integer the schema stores it as.
///
/// Non-zero is true, matching every one of the three backends' own conventions
/// and SQLite's lack of a boolean type.
#[must_use]
pub(crate) const fn bool_from(value: i64) -> bool {
    value != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scoped(url: &str) -> Scoped {
        Scoped::new(Backend::connect(url).await.expect("connect"), 7)
    }

    #[tokio::test]
    async fn sqlite_placeholders_are_positional() {
        let scoped = scoped("sqlite::memory:").await;
        assert_eq!(
            scoped.sql("SELECT * FROM t WHERE a = {1} AND b = {2}"),
            "SELECT * FROM t WHERE a = ? AND b = ?"
        );
    }

    #[tokio::test]
    async fn a_template_with_ten_or_more_parameters_is_not_mangled() {
        // The bug substituting upward would cause: `{10}` becomes the
        // substitution for `{1}` followed by a stray `0`. It only appears on
        // wide inserts, which is exactly where nobody looks.
        let scoped = scoped("sqlite::memory:").await;
        let rendered = scoped.sql("VALUES ({1}, {10}, {11})");
        assert_eq!(
            rendered, "VALUES (?, ?, ?)",
            "wide placeholders were mangled"
        );
        assert!(!rendered.contains('0'), "{rendered}");
    }

    #[tokio::test]
    async fn the_server_id_is_carried_not_rediscovered() {
        let scoped = scoped("sqlite::memory:").await;
        assert_eq!(scoped.server_id(), 7);
    }

    #[test]
    fn an_out_of_range_id_is_corruption_not_a_backend_fault() {
        // Retrying reads the same row again, so this must not look transient.
        assert!(matches!(u32_from(-1), Err(StoreError::Corrupt(_))));
        assert!(matches!(
            u32_from(i64::from(u32::MAX) + 1),
            Err(StoreError::Corrupt(_))
        ));
        assert_eq!(u32_from(42).expect("in range"), 42);
    }

    #[test]
    fn booleans_are_non_zero() {
        assert!(!bool_from(0));
        assert!(bool_from(1));
        assert!(bool_from(-1), "any non-zero value is true");
    }
}
