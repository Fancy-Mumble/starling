//! Sink implementations.
//!
//! | Sink | Pattern | Use |
//! |---|---|---|
//! | [`ConsoleSink`] | — | Human-readable output to stderr, or any writer |
//! | [`FileSink`] | — | Append to a file, rotating by size |
//! | [`MemorySink`] | — | Ring buffer, for the admin API and tests |
//! | [`FanoutSink`] | Composite | Several sinks at once |
//! | [`FilterSink`] | Decorator | Severity and category gating around any sink |
//! | [`NullSink`] | Null Object | Discard, so "no logging" needs no `Option` |
//!
//! They compose, and the composition is where the expressiveness comes from:
//!
//! ```
//! # use starling_log::{Severity, Category, sinks::*};
//! // Everything to a file; warnings and worse also to the console.
//! let sink = FanoutSink::new()
//!     .with(Box::new(MemorySink::new(1000)))
//!     .with(Box::new(FilterSink::new(
//!         Box::new(ConsoleSink::stderr()),
//!         Severity::Warning,
//!     )));
//! # let _ = sink;
//! ```

mod console;
mod fanout;
mod file;
mod filter;
mod memory;
mod null;

pub use console::ConsoleSink;
pub use fanout::FanoutSink;
pub use file::FileSink;
pub use filter::FilterSink;
pub use memory::{MemoryHandle, MemorySink};
pub use null::NullSink;
