//! Reading one value out of a murmur row, whatever it turns out to be.
//!
//! Two things make this less trivial than `try_get`.
//!
//! **The same column has different types in different murmur versions.** `start`
//! was a native `DATE` and became `start_date`, epoch seconds in a `BIGINT`;
//! `base` was a `BLOB` and became `ipv6_base_address`, text. A reader that
//! assumed either would fail on half the databases in the wild, and fail by
//! returning a default rather than by saying so, so each accessor here takes
//! whichever representation is in front of it.
//!
//! **SQLite has type affinity, not types.** A column declared `INTEGER` holds
//! whatever was written to it, and murmur wrote through Qt and through SOCI over
//! twenty years. Asking for an `i64` and getting a `String` back is not a corrupt
//! database, it is an ordinary Tuesday.
//!
//! Nothing here fails: a value that cannot be read is absent, and the caller
//! decides whether absence is worth a line in the [`Report`](super::Report). A
//! reader that returned `Result` per column would put a migration one malformed
//! `position` away from refusing to run at all.

use sqlx::Row as _;
use sqlx::any::AnyRow;

/// An integer, however it is stored.
///
/// Text is parsed rather than refused, because murmur's older Qt writer stored
/// several of these as strings and its own migration re-reads them the same way.
#[must_use]
pub(crate) fn int(row: &AnyRow, column: &str) -> Option<i64> {
    if let Ok(value) = row.try_get::<i64, _>(column) {
        return Some(value);
    }
    if let Ok(Some(value)) = row.try_get::<Option<i64>, _>(column) {
        return Some(value);
    }
    if let Ok(value) = row.try_get::<f64, _>(column) {
        // Truncating rather than rounding: every use is an id or a count that
        // was written as an integer and read back through a float column.
        return Some(value as i64);
    }
    text(row, column).and_then(|value| value.trim().parse().ok())
}

/// An integer, or `fallback` when the column is absent, null or unreadable.
#[must_use]
pub(crate) fn int_or(row: &AnyRow, column: &str, fallback: i64) -> i64 {
    int(row, column).unwrap_or(fallback)
}

/// A `u32`, clamped at both ends.
///
/// murmur has signed columns holding unsigned quantities (`channel_id` is an
/// `INTEGER`), so a value that does not fit is a corrupt row rather than a
/// number to wrap around. Clamping keeps the row instead of dropping it, and the
/// clamp is visible in the data rather than silent in the arithmetic.
#[must_use]
pub(crate) fn u32_or(row: &AnyRow, column: &str, fallback: u32) -> u32 {
    int(row, column).map_or(fallback, |value| value.clamp(0, i64::from(u32::MAX)) as u32)
}

/// Text, however it is stored.
#[must_use]
pub(crate) fn text(row: &AnyRow, column: &str) -> Option<String> {
    if let Ok(value) = row.try_get::<String, _>(column) {
        return Some(value);
    }
    if let Ok(Some(value)) = row.try_get::<Option<String>, _>(column) {
        return Some(value);
    }
    // A `TEXT` column holding bytes: murmur's `reason` and `name` are free text
    // an operator typed, and one that is not valid UTF-8 should still name the
    // ban it belongs to rather than erase it.
    blob(row, column).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Text, or the empty string. murmur leaves most of its text columns nullable
/// and means "nothing" by it.
#[must_use]
pub(crate) fn text_or_empty(row: &AnyRow, column: &str) -> String {
    text(row, column).unwrap_or_default()
}

/// Bytes, however they are stored.
#[must_use]
pub(crate) fn blob(row: &AnyRow, column: &str) -> Option<Vec<u8>> {
    if let Ok(value) = row.try_get::<Vec<u8>, _>(column) {
        return Some(value);
    }
    row.try_get::<Option<Vec<u8>>, _>(column).unwrap_or_default()
}

/// A boolean. murmur writes `0`/`1`, and `NULL` where it means the default.
#[must_use]
pub(crate) fn flag(row: &AnyRow, column: &str, fallback: bool) -> bool {
    match int(row, column) {
        Some(value) => value != 0,
        None => match text(row, column) {
            Some(value) => matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "yes"),
            None => fallback,
        },
    }
}

/// A float, for the one column that is one.
#[must_use]
pub(crate) fn real(row: &AnyRow, column: &str, fallback: f32) -> f32 {
    if let Ok(value) = row.try_get::<f64, _>(column) {
        return value as f32;
    }
    int(row, column).map_or(fallback, |value| value as f32)
}

/// A moment in time, in seconds since the epoch.
///
/// Epoch seconds since murmur's schema v10, and before it a native `DATE`, which
/// on SQLite is the text `datetime('now')` produces: `YYYY-MM-DD HH:MM:SS`, in
/// UTC. Both are read, because a migration that dropped every timestamp from a
/// 1.4 database would silently expire every temporary ban in it.
#[must_use]
pub(crate) fn epoch_seconds(row: &AnyRow, column: &str) -> u64 {
    if let Some(value) = int(row, column) {
        return value.max(0) as u64;
    }
    text(row, column)
        .as_deref()
        .and_then(parse_sql_datetime)
        .unwrap_or_default()
}

/// `YYYY-MM-DD HH:MM:SS` (or the `T`-separated spelling) as epoch seconds.
///
/// Written out rather than pulled in as a date library: this is the only date
/// format murmur ever wrote, it is always UTC, and the alternative is a
/// dependency on the one code path that reads a legacy database once.
#[must_use]
fn parse_sql_datetime(value: &str) -> Option<u64> {
    let value = value.trim();
    let (date, time) = value
        .split_once(['T', ' '])
        .map_or((value, "00:00:00"), |(date, time)| (date, time));

    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Fractional seconds and a trailing `Z` are both things SQLite will write
    // given the chance, and neither changes the second this names.
    let time = time.trim_end_matches('Z');
    let time = time.split_once('.').map_or(time, |(whole, _)| whole);
    let mut parts = time.split(':');
    let hour: i64 = parts.next()?.parse().ok()?;
    let minute: i64 = parts.next().unwrap_or("0").parse().ok()?;
    let second: i64 = parts.next().unwrap_or("0").parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds).ok()
}

/// Days from 1970-01-01 to `year-month-day`, proleptic Gregorian.
///
/// Howard Hinnant's `days_from_civil`, which is the standard formulation and is
/// exact for every date this will ever see. The shift to a March-based year is
/// what removes the leap-day special case: February becomes the last month, so
/// its length never affects the days before it.
#[must_use]
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Bytes from murmur's hex, which is how it stores every digest.
///
/// `None` rather than a partial decode for anything that is not hex: a
/// certificate hash decoded from the half of a string that happened to parse
/// would authenticate the wrong account, which is a worse outcome than the
/// account arriving without a certificate and being reported.
#[must_use]
pub(crate) fn from_hex(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = nibble(*pair.first()?)?;
        let low = nibble(*pair.get(1)?)?;
        out.push(high << 4 | low);
    }
    Some(out)
}

/// One hex digit's value.
#[must_use]
const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_seconds_reads_murmurs_legacy_date_text() {
        // A 1.4 database stores `datetime('now')`, and reading it as zero would
        // date every ban and every last-seen to 1970.
        assert_eq!(parse_sql_datetime("1970-01-01 00:00:00"), Some(0));
        assert_eq!(parse_sql_datetime("1970-01-02 00:00:00"), Some(86_400));
        assert_eq!(parse_sql_datetime("2000-01-01 00:00:00"), Some(946_684_800));
        assert_eq!(
            parse_sql_datetime("2024-02-29T12:34:56"),
            Some(1_709_210_096),
            "a leap day is the date the formula exists to get right"
        );
    }

    #[test]
    fn a_date_with_no_time_is_midnight_rather_than_nothing() {
        assert_eq!(parse_sql_datetime("2020-06-15"), Some(1_592_179_200));
    }

    #[test]
    fn fractional_seconds_and_a_zulu_suffix_are_tolerated() {
        // SQLite writes both given the chance, and neither changes the second.
        assert_eq!(
            parse_sql_datetime("2000-01-01 00:00:01.500Z"),
            Some(946_684_801)
        );
    }

    #[test]
    fn something_that_is_not_a_date_is_absent_rather_than_zero() {
        assert_eq!(parse_sql_datetime("never"), None);
        assert_eq!(parse_sql_datetime("2020-13-01 00:00:00"), None);
        assert_eq!(parse_sql_datetime(""), None);
    }

    #[test]
    fn hex_decodes_the_way_murmur_writes_it() {
        assert_eq!(from_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(from_hex("00FF10"), Some(vec![0x00, 0xff, 0x10]));
    }

    #[test]
    fn a_hash_that_is_not_hex_decodes_to_nothing_at_all() {
        // A partial decode would produce a certificate hash that authenticates
        // the wrong account; an absent one is reported and refuses everybody.
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("abc"), None, "an odd length is not a hash");
        assert_eq!(from_hex(""), None);
    }
}
