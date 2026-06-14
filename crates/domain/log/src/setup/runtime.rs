//! Assembling the sink tree and running the writer (Abstract Factory).
//!
//! A [`LogSpec`] names *what* is wanted; this builds the composition and owns its
//! lifetime. Adding a destination later — syslog, a database, an HTTP endpoint —
//! means a new [`LogSink`] implementation and one arm in [`LogRuntime::start`],
//! with nothing outside this crate changing.
//!
//! This used to live in the binary, which meant the composition root knew how to
//! assemble sinks, what to do when a log file will not open, and in which order
//! to shut the writer down. None of that is a composition concern.

use crate::setup::LogSpec;
use crate::sinks::{ConsoleSink, FanoutSink, FileSink, FilterSink, MemorySink};
use crate::{Category, LogEvent, LogSink, Logger, LoggerShutdown, MemoryHandle};

/// The running log: emitter, shutdown handle, and the ring an admin view reads.
///
/// # Lifetime
///
/// [`Self::finish`] takes `self`, so the health report cannot be written after
/// the writer has gone — records produced during shutdown still need somewhere
/// to go.
#[derive(Debug)]
pub struct LogRuntime {
    logger: Logger,
    shutdown: LoggerShutdown,
    recent: Option<MemoryHandle>,
}

impl LogRuntime {
    /// Build every sink the spec asks for and start the writer.
    ///
    /// **Never fails.** A destination that cannot be opened is reported as a
    /// warning and skipped: a server that refuses to boot because its log file is
    /// unwritable has turned an observability problem into an outage.
    ///
    /// Warnings are emitted into the log itself, once it is up, so they survive
    /// in the same place as everything else. A caller that also wants them on
    /// stderr can keep the list its own config mapping produced.
    #[must_use]
    pub fn start(spec: &LogSpec) -> Self {
        let mut warnings = Vec::new();
        let mut fanout = FanoutSink::new();
        let mut recent = None;

        if spec.console {
            fanout = fanout.with(Box::new(ConsoleSink::stderr()));
        }

        if let Some(file) = &spec.file {
            match FileSink::open(&file.path, file.max_bytes, file.keep) {
                Ok(sink) => fanout = fanout.with(Box::new(sink)),
                Err(e) => warnings.push(format!("file logging disabled: {e}")),
            }
        }

        if let Some(records) = spec.memory {
            let sink = MemorySink::new(records.max(1));
            recent = Some(sink.handle());
            fanout = fanout.with(Box::new(sink));
        }

        let filtered =
            FilterSink::new(Box::new(fanout), spec.level).with_categories(spec.categories.clone());
        let sink: Box<dyn LogSink> = Box::new(filtered);

        let (logger, shutdown) = Logger::spawn(sink, spec.queue.max(1));
        for warning in warnings {
            logger.log(LogEvent::warning(Category::Server, warning));
        }

        Self {
            logger,
            shutdown,
            recent,
        }
    }

    /// A handle for anything that needs to emit records.
    ///
    /// Clone it freely: every clone feeds the same writer.
    #[must_use]
    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    /// Reader for the in-memory ring, when one is configured.
    #[must_use]
    pub fn recent(&self) -> Option<&MemoryHandle> {
        self.recent.as_ref()
    }

    /// Report what the log itself lost, then stop the writer.
    ///
    /// Both numbers are operator-actionable: dropped records mean the queue is
    /// too shallow for the traffic, evicted ones mean the ring is too small to
    /// serve the admin view it exists for.
    pub fn finish(self) {
        let dropped = self.logger.dropped();
        let evicted = self.recent.as_ref().map_or(0, MemoryHandle::evicted);
        if dropped > 0 || evicted > 0 {
            self.logger.log(
                LogEvent::warning(Category::Server, "log capacity was exceeded")
                    .with("queue_dropped", dropped)
                    .with("ring_evicted", evicted),
            );
        }
        self.shutdown.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;
    use crate::setup::FileSpec;

    fn spec_with_memory() -> LogSpec {
        LogSpec {
            console: false,
            memory: Some(64),
            ..LogSpec::default()
        }
    }

    #[test]
    fn records_reach_the_ring_the_spec_asked_for() {
        let runtime = LogRuntime::start(&spec_with_memory());
        runtime
            .logger()
            .log(LogEvent::info(Category::Server, "hello"));
        let handle = runtime.recent().cloned().expect("memory was requested");
        runtime.finish();
        assert!(handle.recent(10).iter().any(|e| e.message == "hello"));
    }

    #[test]
    fn a_level_below_the_threshold_is_dropped() {
        let runtime = LogRuntime::start(&LogSpec {
            level: Severity::Warning,
            ..spec_with_memory()
        });
        runtime
            .logger()
            .log(LogEvent::info(Category::Server, "chatty"));
        runtime
            .logger()
            .log(LogEvent::warning(Category::Server, "important"));
        let handle = runtime.recent().cloned().expect("memory was requested");
        runtime.finish();

        let seen = handle.recent(10);
        assert!(seen.iter().any(|e| e.message == "important"));
        assert!(!seen.iter().any(|e| e.message == "chatty"));
    }

    #[test]
    fn an_unopenable_file_warns_instead_of_failing_the_boot() {
        // A directory is never a valid log file, so this exercises the fallback
        // without depending on permissions.
        let runtime = LogRuntime::start(&LogSpec {
            file: Some(FileSpec::new(".")),
            ..spec_with_memory()
        });
        let handle = runtime.recent().cloned().expect("memory was requested");
        runtime.finish();

        assert!(
            handle
                .recent(10)
                .iter()
                .any(|e| e.message.contains("file logging disabled")),
            "the failure must be reported into the log, not swallowed"
        );
    }

    #[test]
    fn a_spec_with_no_destination_still_runs() {
        // Nowhere to write is a configuration mistake, not a crash.
        let runtime = LogRuntime::start(&LogSpec {
            console: false,
            memory: None,
            file: None,
            ..LogSpec::default()
        });
        runtime.logger().log(LogEvent::info(Category::Server, "x"));
        runtime.finish();
    }
}
