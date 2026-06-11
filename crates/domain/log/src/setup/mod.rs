//! Turning an intent into a running log.
//!
//! Two halves, kept apart so neither leaks into the other:
//!
//! | | |
//! |---|---|
//! | [`LogConfig`] | what an *operator* writes — strings, optionals, `serde` |
//! | [`LogSpec`] | what is *meant* — parsed and resolved, nothing left to misspell |
//! | [`LogRuntime`] | *how* it is assembled and run — sinks, fallbacks, shutdown |
//!
//! A binary embeds [`LogConfig`] in its settings and hands the runtime a spec. It
//! does not decide which sinks compose, what happens when a file will not open,
//! in which order the writer stops, or what an unknown level name means — all of
//! which used to live in the composition root.

mod config;
mod runtime;
mod spec;

pub use config::{ConsoleConfig, FileConfig, LogConfig, MemoryConfig};
pub use runtime::LogRuntime;
pub use spec::{
    FileSpec, LogSpec, DEFAULT_KEEP_FILES, DEFAULT_MAX_FILE_BYTES, DEFAULT_MEMORY_RECORDS,
    DEFAULT_QUEUE,
};
