//! The three scalar shapes the configuration uses: durations, sizes and rates.
//!
//! Written the way an operator writes them (`"15m"`, `"512MiB"`, `"10/s"`) and
//! parsed into typed values; a bare `"15"` is refused rather than guessed at.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A duration written as a number and a unit: `500ms`, `5s`, `15m`, `2h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    /// The wrapped duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }

    /// A duration in seconds.
    #[must_use]
    pub const fn secs(seconds: u64) -> Self {
        Self(Duration::from_secs(seconds))
    }
}

impl FromStr for HumanDuration {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let split = text
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("{text:?} has no unit: write 5s, 500ms, 15m or 2h"))?;
        let (value, unit) = text.split_at(split);
        let value: u64 = value
            .parse()
            .map_err(|_| format!("{text:?} does not start with a number"))?;
        // `from_mins`/`from_hours` name the unit instead of spelling out the
        // factor. They panic on overflow, where `value * 60` wrapped silently in
        // a release build, so the range is checked first and something too long
        // to represent comes back as the parse error this function already
        // returns, an operator's typo is not a reason to take the server down.
        let duration = match unit.trim() {
            "ms" => Duration::from_millis(value),
            "s" => Duration::from_secs(value),
            "m" if value <= u64::MAX / 60 => Duration::from_mins(value),
            "h" if value <= u64::MAX / 3600 => Duration::from_hours(value),
            "d" if value <= u64::MAX / 86_400 => Duration::from_hours(value * 24),
            "m" | "h" | "d" => return Err(format!("{text:?} is too long to represent")),
            other => return Err(format!("unknown time unit {other:?}: use ms, s, m, h or d")),
        };
        Ok(Self(duration))
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = self.0.as_millis();
        if ms.is_multiple_of(1000) {
            write!(f, "{}s", ms / 1000)
        } else {
            write!(f, "{ms}ms")
        }
    }
}

/// A byte count written with a binary suffix: `512MiB`, `8KiB`, `2GiB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// The wrapped byte count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl FromStr for ByteSize {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let split = text
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len());
        let (value, unit) = text.split_at(split);
        let value: u64 = value
            .parse()
            .map_err(|_| format!("{text:?} does not start with a number"))?;
        let scale = match unit.trim() {
            "" | "B" => 1,
            "KiB" | "K" => 1024,
            "MiB" | "M" => 1024 * 1024,
            "GiB" | "G" => 1024 * 1024 * 1024,
            other => {
                return Err(format!(
                    "unknown size unit {other:?}: use B, KiB, MiB or GiB"
                ));
            }
        };
        Ok(Self(value * scale))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}B", self.0)
    }
}

/// Serde glue: parse from the string form, emit the string form.
macro_rules! string_serde {
    ($ty:ty) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_string())
            }
        }
    };
}

string_serde!(HumanDuration);
string_serde!(ByteSize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duration_without_a_unit_is_refused_rather_than_guessed() {
        // Guessing is how a 15-second timeout becomes a 15-minute one.
        assert!("15".parse::<HumanDuration>().is_err());
        assert!("15x".parse::<HumanDuration>().is_err());
    }

    #[test]
    fn durations_parse_in_every_documented_unit() {
        assert_eq!(
            "500ms".parse::<HumanDuration>().map(HumanDuration::get),
            Ok(Duration::from_millis(500))
        );
        assert_eq!(
            "15m".parse::<HumanDuration>().map(HumanDuration::get),
            Ok(Duration::from_secs(900))
        );
        assert_eq!(
            "2h".parse::<HumanDuration>().map(HumanDuration::get),
            Ok(Duration::from_secs(7200))
        );
    }

    #[test]
    fn sizes_are_binary_because_the_suffix_says_so() {
        assert_eq!(
            "512MiB".parse::<ByteSize>().map(ByteSize::get),
            Ok(536_870_912)
        );
        assert_eq!("1024".parse::<ByteSize>().map(ByteSize::get), Ok(1024));
        assert!("512MB".parse::<ByteSize>().is_err());
    }
}
