//! `starling-log` — the server event log.
//!
//! Distinct from `tracing`, which carries developer diagnostics. This is the
//! **operator-facing** record: who connected, what was refused, what an
//! administrator changed. It is the thing that gets persisted, queried through
//! the admin API, and kept for as long as the deployment's retention policy
//! says.
//!
//! # Where logs go is a strategy
//!
//! ```text
//!   Logger  ──(bounded queue)──►  writer thread  ──►  dyn LogSink
//!  (never blocks)                                       ├── ConsoleSink
//!                                                       ├── FileSink
//!                                                       ├── MemorySink
//!                                                       ├── FanoutSink ── [ … ]   (Composite)
//!                                                       ├── FilterSink ── sink    (Decorator)
//!                                                       └── NullSink              (Null Object)
//! ```
//!
//! Anything implementing [`LogSink`] can receive events — a file, a database, a
//! syslog socket, an HTTP endpoint, several of those at once via
//! [`FanoutSink`]. The server never learns which.
//!
//! # Two properties that make it usable on a server
//!
//! * **[`Logger::log`] never blocks.** It hands the event to a bounded queue
//!   drained by a dedicated OS thread. A slow disk cannot stall the voice path.
//! * **Overflow is counted, never silent.** When the queue is full the event is
//!   dropped and a counter incremented; the writer emits a `log queue overflowed`
//!   record as soon as it catches up. A log that quietly loses records is worse
//!   than no log, because it is trusted.
//!
//! The writer runs on a plain OS thread rather than an async task on purpose:
//! logging must keep working while the runtime is saturated, which is exactly
//! when the records matter most.

pub mod event;
pub mod logger;
pub mod setup;
pub mod sink;
pub mod sinks;
pub mod timestamp;

pub use event::{
    Category, Field, FieldValue, IntoFieldValue, LogEvent, Severity, UnknownCategory,
    UnknownSeverity,
};
pub use logger::{Logger, LoggerShutdown};
pub use setup::{FileSpec, LogConfig, LogRuntime, LogSpec};
pub use sink::{LogSink, SinkContext, SinkError};
pub use sinks::{
    ConsoleSink, FanoutSink, FileSink, FilterSink, MemoryHandle, MemorySink, NullSink,
};
