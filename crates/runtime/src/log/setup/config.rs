//! The configuration a caller can hand to [`LogRuntime`](super::LogRuntime).
//!
//! Lives here rather than in the binary because it *is* logging: the fields, the
//! defaults, and what an unrecognised level name should do are all this crate's
//! business. The binary previously owned this on the argument that it owned the
//! file format — but `serde` field names are format-agnostic, and the section
//! name (`[logging]`) comes from the field the binary declares in its own
//! settings struct, not from anything here. There was no format coupling to
//! protect, only a responsibility in the wrong crate.
//!
//! # Two layers, on purpose
//!
//! [`LogConfig`] is what an operator writes: strings, optional values, absent
//! sections. [`LogSpec`] is what [`LogRuntime`](super::LogRuntime) consumes:
//! parsed, resolved, no strings left to misspell. [`LogConfig::to_spec`] is the
//! only place between them, and it reports every fallback it takes.

use serde::{Deserialize, Serialize};

use crate::log::setup::{
    DEFAULT_KEEP_FILES, DEFAULT_MAX_FILE_BYTES, DEFAULT_MEMORY_RECORDS, DEFAULT_QUEUE, FileSpec,
    LogSpec,
};
use crate::log::{Severity, UnknownSeverity};

/// `[logging]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// Minimum severity to record at all.
    pub level: String,
    /// Categories to record; empty means all of them.
    pub categories: Vec<String>,
    /// Queue depth. Records beyond this are dropped and counted.
    pub queue: usize,
    /// Console output.
    pub console: ConsoleConfig,
    /// File output.
    pub file: FileConfig,
    /// In-memory ring, for the admin API.
    pub memory: MemoryConfig,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            categories: Vec::new(),
            queue: DEFAULT_QUEUE,
            console: ConsoleConfig { enabled: true },
            file: FileConfig::default(),
            memory: MemoryConfig {
                enabled: true,
                records: DEFAULT_MEMORY_RECORDS,
            },
        }
    }
}

/// `[logging.console]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ConsoleConfig {
    /// Whether to write records to stderr.
    pub enabled: bool,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// `[logging.file]`
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileConfig {
    /// Where to append. Empty disables file logging.
    pub path: String,
    /// Rotate past this many bytes. `0` disables rotation.
    pub max_bytes: Option<u64>,
    /// How many rotated generations to keep.
    pub keep: Option<usize>,
}

/// `[logging.memory]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MemoryConfig {
    /// Whether to keep a ring buffer in memory.
    pub enabled: bool,
    /// How many records to retain.
    pub records: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            records: DEFAULT_MEMORY_RECORDS,
        }
    }
}

impl LogConfig {
    /// Resolve into a [`LogSpec`], with a warning for every fallback taken.
    ///
    /// Unrecognised names fall back rather than failing the boot, but are always
    /// reported: silently logging at the wrong level is how an incident ends up
    /// with no evidence.
    #[must_use]
    pub fn to_spec(&self) -> (LogSpec, Vec<String>) {
        let mut warnings = Vec::new();

        let level = self.level.parse().unwrap_or_else(|e: UnknownSeverity| {
            warnings.push(format!("{e}; using \"info\""));
            Severity::Info
        });

        let categories = self
            .categories
            .iter()
            .filter_map(|name| match name.parse() {
                Ok(category) => Some(category),
                Err(e) => {
                    warnings.push(format!("{e}; ignoring"));
                    None
                }
            })
            .collect();

        let spec = LogSpec {
            level,
            categories,
            queue: self.queue,
            console: self.console.enabled,
            file: (!self.file.path.is_empty()).then(|| FileSpec {
                path: self.file.path.clone(),
                max_bytes: self.file.max_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES),
                keep: self.file.keep.unwrap_or(DEFAULT_KEEP_FILES),
            }),
            memory: self.memory.enabled.then_some(self.memory.records),
        };
        (spec, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Category;

    /// What this file is responsible for is the **mapping**. The behaviour that
    /// used to be asserted here — filtering, fallback on an unopenable file,
    /// clamping a zero queue — moved with the code, to
    /// `crate::log::setup::runtime`.
    fn spec_of(section: &LogConfig) -> LogSpec {
        section.to_spec().0
    }

    #[test]
    fn the_default_section_asks_for_console_and_memory() {
        let spec = spec_of(&LogConfig::default());
        assert!(spec.console);
        assert_eq!(spec.memory, Some(DEFAULT_MEMORY_RECORDS));
        assert_eq!(spec.level, Severity::Info);
        assert!(spec.file.is_none(), "no file unless one is configured");
    }

    #[test]
    fn a_configured_level_reaches_the_spec() {
        let section = LogConfig {
            level: "warning".into(),
            ..Default::default()
        };
        assert_eq!(spec_of(&section).level, Severity::Warning);
    }

    #[test]
    fn an_unknown_level_falls_back_and_is_reported() {
        let section = LogConfig {
            level: "shouty".into(),
            ..Default::default()
        };
        let (spec, warnings) = section.to_spec();
        assert_eq!(spec.level, Severity::Info);
        assert!(
            warnings.iter().any(|w| w.contains("shouty")),
            "a silently wrong level is how an incident ends up with no evidence"
        );
    }

    #[test]
    fn a_category_list_is_translated() {
        let section = LogConfig {
            categories: vec!["session".into()],
            ..Default::default()
        };
        assert_eq!(spec_of(&section).categories, vec![Category::Session]);
    }

    #[test]
    fn an_unknown_category_is_reported_and_ignored() {
        let section = LogConfig {
            categories: vec!["session".into(), "nonsense".into()],
            ..Default::default()
        };
        let (spec, warnings) = section.to_spec();
        assert_eq!(spec.categories, vec![Category::Session]);
        assert!(warnings.iter().any(|w| w.contains("nonsense")));
    }

    #[test]
    fn an_empty_category_list_stays_empty_meaning_everything() {
        assert!(spec_of(&LogConfig::default()).categories.is_empty());
    }

    #[test]
    fn a_file_path_produces_a_file_spec_with_the_configured_rotation() {
        let section = LogConfig {
            file: FileConfig {
                path: "starling.log".into(),
                max_bytes: Some(1234),
                keep: Some(2),
            },
            ..Default::default()
        };
        let file = spec_of(&section).file.expect("a path was configured");
        assert_eq!(file.path, "starling.log");
        assert_eq!(file.max_bytes, 1234);
        assert_eq!(file.keep, 2);
    }

    #[test]
    fn an_unset_rotation_policy_takes_the_defaults() {
        let section = LogConfig {
            file: FileConfig {
                path: "starling.log".into(),
                max_bytes: None,
                keep: None,
            },
            ..Default::default()
        };
        let file = spec_of(&section).file.expect("a path was configured");
        assert_eq!(file.max_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(file.keep, DEFAULT_KEEP_FILES);
    }

    #[test]
    fn disabling_a_destination_removes_it_from_the_spec() {
        let section = LogConfig {
            console: ConsoleConfig { enabled: false },
            memory: MemoryConfig {
                enabled: false,
                records: 0,
            },
            ..Default::default()
        };
        let spec = spec_of(&section);
        assert!(!spec.console);
        assert!(spec.memory.is_none());
    }
}
