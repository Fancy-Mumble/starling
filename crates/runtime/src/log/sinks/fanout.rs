//! Deliver to several sinks at once (Composite).

use crate::log::event::LogEvent;
use crate::log::sink::{LogSink, SinkError};

/// Writes every record to each of its children.
///
/// Composite: a `FanoutSink` *is* a [`LogSink`], so it nests, a fanout of a
/// fanout is fine, and nothing that takes a sink needs to know how many are
/// really behind it.
///
/// The load-bearing rule is that **one failing child does not stop the others**.
/// A full disk must not also cost you the console output that would tell you the
/// disk is full.
#[derive(Debug, Default)]
pub struct FanoutSink {
    sinks: Vec<Box<dyn LogSink>>,
}

impl FanoutSink {
    /// A fanout with no children. Writing to it succeeds and does nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a child (Builder).
    #[must_use]
    pub fn with(mut self, sink: Box<dyn LogSink>) -> Self {
        self.sinks.push(sink);
        self
    }

    /// How many children it has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// Whether it has no children.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Run `op` against every child, collecting failures without stopping.
    fn for_each(
        &mut self,
        op: impl Fn(&mut Box<dyn LogSink>) -> Result<(), SinkError>,
    ) -> Result<(), SinkError> {
        let failures: Vec<String> = self
            .sinks
            .iter_mut()
            .filter_map(|sink| op(sink).err())
            .map(|e| e.to_string())
            .collect();

        if failures.is_empty() {
            Ok(())
        } else {
            Err(SinkError::new("fanout", failures.join("; ")))
        }
    }
}

impl LogSink for FanoutSink {
    fn name(&self) -> &str {
        "fanout"
    }

    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
        self.for_each(|sink| sink.write(event))
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.for_each(|sink| sink.flush())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::event::Category;
    use crate::log::sinks::MemorySink;

    /// Always fails, to prove failures do not stop delivery.
    #[derive(Debug)]
    struct Broken(&'static str);

    impl LogSink for Broken {
        fn name(&self) -> &str {
            self.0
        }
        fn write(&mut self, _: &LogEvent) -> Result<(), SinkError> {
            Err(SinkError::new(self.0, "disk on fire"))
        }
        fn flush(&mut self) -> Result<(), SinkError> {
            Err(SinkError::new(self.0, "disk still on fire"))
        }
    }

    fn event() -> LogEvent {
        LogEvent::info(Category::Server, "hello")
    }

    #[test]
    fn every_child_receives_the_record() {
        let mut fanout = FanoutSink::new()
            .with(Box::new(MemorySink::new(10)))
            .with(Box::new(MemorySink::new(10)));
        assert_eq!(fanout.len(), 2);
        assert!(fanout.write(&event()).is_ok());
    }

    #[test]
    fn a_failing_child_does_not_stop_the_others() {
        // The rule the whole type exists for.
        let recorder = MemorySink::new(10);
        let handle = recorder.handle();

        let mut fanout = FanoutSink::new()
            .with(Box::new(Broken("file")))
            .with(Box::new(recorder));

        assert!(fanout.write(&event()).is_err(), "the failure is reported");
        assert_eq!(
            handle.recent(10).len(),
            1,
            "the healthy sink must still have received it"
        );
    }

    #[test]
    fn the_error_names_every_child_that_failed() {
        // With five sinks, "write failed" is not a diagnosis.
        let mut fanout = FanoutSink::new()
            .with(Box::new(Broken("file")))
            .with(Box::new(Broken("database")));

        let err = fanout.write(&event()).expect_err("both failed");
        assert!(err.cause.contains("file"), "{err}");
        assert!(err.cause.contains("database"), "{err}");
    }

    #[test]
    fn an_empty_fanout_succeeds_silently() {
        // "log nowhere" must not be an error condition.
        let mut fanout = FanoutSink::new();
        assert!(fanout.is_empty());
        assert!(fanout.write(&event()).is_ok());
        assert!(fanout.flush().is_ok());
    }

    #[test]
    fn flush_reaches_every_child_even_after_one_fails() {
        let recorder = MemorySink::new(10);
        let handle = recorder.handle();
        let mut fanout = FanoutSink::new()
            .with(Box::new(Broken("file")))
            .with(Box::new(recorder));

        assert!(fanout.flush().is_err());
        assert_eq!(handle.flushes(), 1, "the healthy sink was not flushed");
    }

    #[test]
    fn fanouts_nest() {
        // Composite: a fanout is itself a sink.
        let inner = MemorySink::new(10);
        let handle = inner.handle();
        let mut outer = FanoutSink::new().with(Box::new(FanoutSink::new().with(Box::new(inner))));

        assert!(outer.write(&event()).is_ok());
        assert_eq!(handle.recent(10).len(), 1);
    }
}
