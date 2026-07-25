//! What a caller wants logged, and where.
//!
//! Deliberately plain data with no `serde`: this is the *vocabulary* an operator's
//! intent is expressed in, not a file format. A binary maps its own configuration
//! onto this — which section names it uses, which defaults it applies, whether it
//! reads TOML or an `.ini` — and this crate never learns any of that.

use crate::{Category, Severity};

/// Where and how to log.
///
/// [`Default`] is the useful configuration rather than the empty one: console on,
/// an in-memory ring for the admin view, `Info` and above, every category. A
/// caller that supplies nothing still gets a working log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSpec {
    /// Minimum severity to record at all.
    pub level: Severity,
    /// Categories to record. Empty means every category.
    pub categories: Vec<Category>,
    /// Queue depth. Records beyond this are dropped and counted.
    pub queue: usize,
    /// Write records to stderr.
    pub console: bool,
    /// Write records to a rotating file.
    pub file: Option<FileSpec>,
    /// Keep the most recent records in memory, for an admin view.
    pub memory: Option<usize>,
}

/// A rotating log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    /// Path to write to.
    pub path: String,
    /// Rotate once the file exceeds this many bytes.
    pub max_bytes: u64,
    /// How many rotated generations to keep.
    pub keep: usize,
}

impl Default for LogSpec {
    fn default() -> Self {
        Self {
            level: Severity::Info,
            categories: Vec::new(),
            queue: DEFAULT_QUEUE,
            console: true,
            file: None,
            memory: Some(DEFAULT_MEMORY_RECORDS),
        }
    }
}

/// Default in-memory ring size, for an admin "recent log" view.
pub const DEFAULT_MEMORY_RECORDS: usize = 1_000;

/// Default queue depth between emitters and the writer thread.
pub const DEFAULT_QUEUE: usize = 4_096;

/// Default file rotation: 10 MiB, five generations.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Default number of rotated files to keep.
pub const DEFAULT_KEEP_FILES: usize = 5;

impl FileSpec {
    /// A file spec with the default rotation policy.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            max_bytes: DEFAULT_MAX_FILE_BYTES,
            keep: DEFAULT_KEEP_FILES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_spec_is_usable_rather_than_empty() {
        // A caller that configures nothing must still get records somewhere.
        let spec = LogSpec::default();
        assert!(spec.console);
        assert!(spec.memory.is_some());
        assert_eq!(spec.level, Severity::Info);
        assert!(
            spec.categories.is_empty(),
            "empty means every category, not none"
        );
    }

    #[test]
    fn a_file_spec_carries_the_default_rotation_policy() {
        let spec = FileSpec::new("starling.log");
        assert_eq!(spec.max_bytes, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(spec.keep, DEFAULT_KEEP_FILES);
    }
}
