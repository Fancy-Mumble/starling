//! How much attention a record deserves.

/// A record's severity.
///
/// Ordered from least to most urgent, so a sink can filter with `>=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Detail useful only when investigating.
    Debug,
    /// Normal operation worth recording.
    Info,
    /// Normal, but notable, an administrator changed something.
    Notice,
    /// Something was refused or degraded, but the server carried on.
    Warning,
    /// An operation failed.
    Error,
    /// The server cannot continue.
    Critical,
}

impl Severity {
    /// Every severity, for config validation and exhaustiveness tests.
    pub const ALL: &'static [Self] = &[
        Self::Debug,
        Self::Info,
        Self::Notice,
        Self::Warning,
        Self::Error,
        Self::Critical,
    ];

    /// Fixed-width label, right-aligned so console output lines up with
    /// `tracing`'s (` INFO`, ` WARN`, `ERROR`), which shares the same stderr.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => " INFO",
            Self::Notice => " NOTE",
            Self::Warning => " WARN",
            Self::Error => "ERROR",
            Self::Critical => " CRIT",
        }
    }

    /// Its position in [`Self::ALL`], for packing into an atomic.
    ///
    /// The log's threshold is shared with the writer thread and changed while
    /// it runs (`logging.level` is reloadable), and an enum cannot live in an
    /// `AtomicU8` on its own.
    #[must_use]
    pub fn index(self) -> u8 {
        match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Notice => 2,
            Self::Warning => 3,
            Self::Error => 4,
            Self::Critical => 5,
        }
    }

    /// The severity [`Self::index`] produced, or `None` for anything else.
    #[must_use]
    pub fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(index as usize).copied()
    }

    /// Parse a severity name, case-insensitively.
    ///
    /// Kept as an inherent method because [`FromStr`](std::str::FromStr) is the
    /// public entry point and delegates here; callers that already have an
    /// `Option` shape find this convenient.
    #[must_use]
    fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "notice" | "note" => Self::Notice,
            "warning" | "warn" => Self::Warning,
            "error" => Self::Error,
            "critical" | "crit" => Self::Critical,
            _ => return None,
        })
    }
}

/// A name that does not match any [`Severity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSeverity(pub String);

impl std::fmt::Display for UnknownSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown severity {:?}", self.0)
    }
}

impl std::error::Error for UnknownSeverity {}

impl std::str::FromStr for Severity {
    type Err = UnknownSeverity;

    /// Case-insensitive, so a config file may say `Info` or `info`.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::from_name(name).ok_or_else(|| UnknownSeverity(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_round_trips_and_matches_the_ordering() {
        // The atomic the live threshold lives in stores this number, so an
        // index that disagreed with `ALL` would silently change the level.
        for (position, severity) in Severity::ALL.iter().enumerate() {
            assert_eq!(severity.index() as usize, position);
            assert_eq!(Severity::from_index(severity.index()), Some(*severity));
        }
        assert_eq!(Severity::from_index(u8::MAX), None);
    }

    #[test]
    fn severities_order_from_least_to_most_urgent() {
        // Sinks filter with `>=`, so the ordering is load-bearing.
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Notice);
        assert!(Severity::Notice < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn labels_are_fixed_width_so_console_output_aligns() {
        let widths: Vec<_> = Severity::ALL.iter().map(|s| s.label().len()).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{widths:?}");
    }

    #[test]
    fn every_severity_round_trips_through_its_trimmed_label() {
        for severity in Severity::ALL {
            let name = severity.label().trim();
            // CRIT/NOTE are abbreviations the parser also accepts.
            assert_eq!(Severity::from_name(name), Some(*severity), "{name}");
        }
    }

    #[test]
    fn parsing_accepts_the_spellings_a_config_would_use() {
        assert_eq!(Severity::from_name("warn"), Some(Severity::Warning));
        assert_eq!(Severity::from_name("WARNING"), Some(Severity::Warning));
        assert_eq!(Severity::from_name("Info"), Some(Severity::Info));
        assert_eq!(Severity::from_name("critical"), Some(Severity::Critical));
    }

    #[test]
    fn an_unknown_name_reports_none_rather_than_guessing() {
        assert_eq!(Severity::from_name("nonsense"), None);
        assert_eq!(Severity::from_name(""), None);
    }

    #[test]
    fn labels_are_unique() {
        let mut labels: Vec<_> = Severity::ALL.iter().map(|s| s.label()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count);
    }
}
