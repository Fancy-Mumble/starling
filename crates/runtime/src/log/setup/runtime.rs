//! Assembling the sink tree and running the writer (Abstract Factory).
//!
//! A [`LogSpec`] names *what* is wanted; this builds the composition and owns its
//! lifetime. Adding a destination later (syslog, a database, an HTTP endpoint)
//! means a new [`LogSink`] implementation and one arm in [`LogRuntime::start`],
//! with nothing outside this crate changing.
//!
//! This used to live in the binary, which meant the composition root knew how to
//! assemble sinks, what to do when a log file will not open, and in which order
//! to shut the writer down. None of that is a composition concern.

use crate::log::setup::LogSpec;
use crate::log::sinks::{
    ConsoleSink, FanoutSink, FileSink, FilterHandle, FilterSink, MemorySink, SwapHandle, SwapSink,
};
use crate::log::{Category, LogEvent, LogSink, Logger, LoggerShutdown, MemoryHandle};

/// The running log: emitter, shutdown handle, and the ring an admin view reads.
///
/// # Lifetime
///
/// [`Self::finish`] takes `self`, so the health report cannot be written after
/// the writer has gone, records produced during shutdown still need somewhere
/// to go.
#[derive(Debug)]
pub struct LogRuntime {
    logger: Logger,
    shutdown: LoggerShutdown,
    recent: Option<MemoryHandle>,
    handles: LogHandles,
}

/// Everything about a running log that a reload can change.
///
/// Bundled rather than passed one at a time so that adding a reloadable part of
/// `[logging]` does not change the signature at every composition root, and so
/// that "what can a reload move" has one answer to read.
#[derive(Debug, Clone)]
pub struct LogHandles {
    /// Severity threshold and category set.
    pub filter: FilterHandle,
    /// The log file, or the absence of one.
    pub file: SwapHandle,
    /// Console output, or the absence of it.
    pub console: SwapHandle,
    /// The in-memory ring the admin view reads.
    pub memory: MemoryHandle,
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

        // Behind a slot, and so is the file below: both can then be switched on
        // by a reload, not merely reconfigured. A conditionally-built branch
        // leaves nowhere to put one later.
        let console_sink = SwapSink::new(
            "console",
            spec.console
                .then(|| Box::new(ConsoleSink::stderr()) as Box<dyn LogSink>),
        );
        let console = console_sink.handle();
        fanout = fanout.with(Box::new(console_sink));

        // Always present, even with no file in it, so that `[logging.file]`
        // can be switched *on* by a reload rather than only reconfigured: a
        // conditionally-built branch would leave nowhere to put one later.
        let mut file_slot = None;
        if let Some(file) = &spec.file {
            match FileSink::open(&file.path, file.max_bytes, file.keep) {
                Ok(sink) => file_slot = Some(Box::new(sink) as Box<dyn LogSink>),
                Err(e) => warnings.push(format!("file logging disabled: {e}")),
            }
        }
        let file_sink = SwapSink::new("file", file_slot);
        let file = file_sink.handle();
        fanout = fanout.with(Box::new(file_sink));

        // Always built, with a capacity of zero when the ring is switched off,
        // because the admin API holds this handle for the life of the process:
        // a sink added later would leave it reading a ring nothing writes to.
        let memory_sink = MemorySink::new(spec.memory.unwrap_or(0));
        let memory = memory_sink.handle();
        if spec.memory.is_some() {
            recent = Some(memory.clone());
        }
        fanout = fanout.with(Box::new(memory_sink));

        let filtered =
            FilterSink::new(Box::new(fanout), spec.level).with_categories(spec.categories.clone());
        // Taken before the sink is boxed and handed to the writer thread: after
        // that the filter is owned by another thread and unreachable.
        let filter = filtered.handle();
        let sink: Box<dyn LogSink> = Box::new(filtered);

        let (logger, shutdown) = Logger::spawn(sink, spec.queue.max(1));
        for warning in warnings {
            logger.log(LogEvent::warning(Category::Server, warning));
        }

        Self {
            logger,
            shutdown,
            recent,
            handles: LogHandles {
                filter,
                file,
                console,
                memory,
            },
        }
    }

    /// Start from an operator's `[logging]` section.
    ///
    /// [`Self::start`] takes a resolved [`LogSpec`]; this takes the unresolved
    /// [`crate::log::LogConfig`] and carries its fallback warnings, a misspelled level, an
    /// unknown category, into the log itself. Resolving in the composition root
    /// instead would mean every entry point remembering to report them, and the
    /// one that forgot would log at the wrong level in silence.
    #[must_use]
    pub fn start_from(config: &crate::log::LogConfig) -> Self {
        let (spec, warnings) = config.to_spec();
        let runtime = Self::start(&spec);
        for warning in warnings {
            runtime
                .logger
                .log(LogEvent::warning(Category::Server, warning));
        }
        runtime
    }

    /// A handle for anything that needs to emit records.
    ///
    /// Clone it freely: every clone feeds the same writer.
    #[must_use]
    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    /// Everything a reload can change about the running log.
    ///
    /// The whole of `[logging]` except `queue` is reloadable, and for one
    /// reason: every part of it is something an operator discovers is wrong
    /// *while the server is running* -- a level too coarse to diagnose with, a
    /// full disk, a mistyped path, a rotation size far too small -- and none of
    /// them is worth restarting the process that holds every client's
    /// connection to fix.
    #[must_use]
    pub fn handles(&self) -> LogHandles {
        self.handles.clone()
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
    use crate::log::Severity;
    use crate::log::setup::FileSpec;

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
