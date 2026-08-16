//! RFC 3339 timestamps, without a date-time dependency.
//!
//! The date arithmetic is Howard Hinnant's `civil_from_days`, which is exact for
//! the whole proleptic Gregorian range and is the algorithm most date libraries
//! use internally. Sixty lines is a fair price for a log crate that pulls in
//! nothing.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format a [`SystemTime`] as RFC 3339 UTC with microseconds.
///
/// Microseconds rather than milliseconds because that is what `tracing`'s
/// default timer prints, and the two share a stderr: two widths of timestamp
/// in one column read as two logs.
///
/// Times before the Unix epoch format as the epoch: a log record cannot
/// meaningfully predate the process, and returning an error here would make
/// every sink handle a case that cannot happen.
#[must_use]
pub fn rfc3339(at: SystemTime) -> String {
    let since_epoch = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since_epoch.as_secs();
    let micros = since_epoch.subsec_micros();

    let days = (secs / 86_400) as i64;
    let time_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    )
}

/// Days since 1970-01-01 → `(year, month, day)`.
///
/// Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms".
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the era so the leap-day lands at the end of the cycle.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64, micros: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, micros * 1_000)
    }

    #[test]
    fn the_epoch_formats_as_the_epoch() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn known_timestamps_match_their_rfc3339_form() {
        // Cross-checked against `date -u -d @<secs>`.
        assert_eq!(rfc3339(at(1_000_000_000, 0)), "2001-09-09T01:46:40.000000Z");
        assert_eq!(rfc3339(at(1_700_000_000, 0)), "2023-11-14T22:13:20.000000Z");
        assert_eq!(rfc3339(at(2_000_000_000, 0)), "2033-05-18T03:33:20.000000Z");
    }

    #[test]
    fn microseconds_are_zero_padded() {
        assert_eq!(rfc3339(at(0, 7)), "1970-01-01T00:00:00.000007Z");
        assert_eq!(rfc3339(at(0, 7_000)), "1970-01-01T00:00:00.007000Z");
        assert_eq!(rfc3339(at(0, 700_000)), "1970-01-01T00:00:00.700000Z");
    }

    #[test]
    fn leap_days_are_handled() {
        // 2000 is a leap year (divisible by 400), 1900 was not.
        assert_eq!(rfc3339(at(951_782_400, 0)), "2000-02-29T00:00:00.000000Z");
        // 2024-02-29.
        assert_eq!(rfc3339(at(1_709_164_800, 0)), "2024-02-29T00:00:00.000000Z");
    }

    #[test]
    fn year_and_century_boundaries_are_exact() {
        assert_eq!(rfc3339(at(946_684_799, 0)), "1999-12-31T23:59:59.000000Z");
        assert_eq!(rfc3339(at(946_684_800, 0)), "2000-01-01T00:00:00.000000Z");
    }

    #[test]
    fn a_time_before_the_epoch_clamps_rather_than_failing() {
        // A sink must never have to handle a formatting error.
        let before = UNIX_EPOCH - Duration::from_secs(60);
        assert_eq!(rfc3339(before), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn output_is_fixed_width_so_log_lines_align() {
        let widths: Vec<_> = [0, 1_000_000_000, 1_700_000_000, 2_000_000_000]
            .iter()
            .map(|s| rfc3339(at(*s, 0)).len())
            .collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{widths:?}");
    }

    #[test]
    fn every_day_of_a_leap_year_round_trips_month_and_day() {
        // Walks 2024 day by day and checks the calendar never skips or repeats.
        let start = 1_704_067_200; // 2024-01-01
        let mut previous = String::new();
        for day in 0..366 {
            let formatted = rfc3339(at(start + day * 86_400, 0));
            assert!(formatted.starts_with("2024-"), "{formatted}");
            assert!(
                formatted > previous,
                "{formatted} did not follow {previous}"
            );
            previous = formatted;
        }
        assert!(rfc3339(at(start + 366 * 86_400, 0)).starts_with("2025-01-01"));
    }
}
