//! Where log records go (Strategy).

use crate::log::event::LogEvent;

/// A sink could not accept a record.
///
/// Never fatal to the server. The writer reports it and carries on, and
/// [`FanoutSink`](crate::log::sinks::FanoutSink) keeps delivering to its other sinks:
/// a full disk must not also cost you the console output that would tell you the
/// disk is full.
#[derive(Debug)]
pub struct SinkError {
    /// Which sink failed.
    pub sink: String,
    /// What went wrong.
    pub cause: String,
}

impl SinkError {
    /// Build an error naming the sink that produced it.
    #[must_use]
    pub fn new(sink: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        Self {
            sink: sink.into(),
            cause: cause.to_string(),
        }
    }
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.sink, self.cause)
    }
}

impl std::error::Error for SinkError {}

/// Somewhere log records can be written.
///
/// Implement this to send the log anywhere, a file, a database, syslog, an
/// HTTP endpoint. The server never learns which.
///
/// # Contract
///
/// 1. **Never panic.** A sink that panics takes the writer thread with it and
///    the server goes deaf. Return [`SinkError`] instead.
/// 2. **Do not block indefinitely.** The writer has its own thread, so a
///    bounded wait (a disk write, a database round trip) is fine; waiting on a
///    lock the server holds is not.
/// 3. **Errors are advisory.** Returning `Err` does not stop delivery to other
///    sinks and does not stop the server.
/// 4. [`Self::flush`] must make everything written so far durable, and is
///    called on shutdown. A buffering sink that ignores it loses the records
///    that matter most, the ones just before the process died.
pub trait LogSink: Send + std::fmt::Debug {
    /// A short name, used in error messages and diagnostics.
    fn name(&self) -> &str;

    /// Write one record.
    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError>;

    /// Make everything written so far durable.
    ///
    /// Defaults to a no-op, which is correct for sinks that do not buffer.
    fn flush(&mut self) -> Result<(), SinkError> {
        Ok(())
    }
}

/// Attach the failing sink's name to an error, so `?` can carry it.
///
/// Ten call sites wrote `.map_err(|e| SinkError::new(name, e))` by hand. The
/// wrapping is not optional, a `SinkError` without a sink name tells an operator
/// nothing about which destination broke, but writing it out at every call was
/// noise around the one thing that mattered, the `?`.
pub trait SinkContext<T> {
    /// Convert into a [`SinkError`] naming `sink`.
    ///
    /// # Errors
    ///
    /// Propagates the receiver's error, wrapped.
    fn sink(self, sink: &str) -> Result<T, SinkError>;
}

impl<T, E: std::fmt::Display> SinkContext<T> for Result<T, E> {
    fn sink(self, sink: &str) -> Result<T, SinkError> {
        self.map_err(|cause| SinkError::new(sink, cause))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::event::Category;

    /// Records what it was given, and can be told to fail.
    #[derive(Debug, Default)]
    struct Spy {
        written: Vec<String>,
        flushed: usize,
        fail: bool,
    }

    impl LogSink for Spy {
        fn name(&self) -> &str {
            "spy"
        }
        fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
            if self.fail {
                return Err(SinkError::new("spy", "asked to fail"));
            }
            self.written.push(event.message.clone());
            Ok(())
        }
        fn flush(&mut self) -> Result<(), SinkError> {
            self.flushed += 1;
            Ok(())
        }
    }

    #[test]
    fn a_sink_receives_what_it_is_written() {
        let mut sink = Spy::default();
        let event = LogEvent::info(Category::Server, "hello");
        assert!(sink.write(&event).is_ok());
        assert_eq!(sink.written, vec!["hello".to_owned()]);
    }

    #[test]
    fn a_failing_sink_reports_rather_than_panicking() {
        let mut sink = Spy {
            fail: true,
            ..Default::default()
        };
        let err = sink
            .write(&LogEvent::info(Category::Server, "x"))
            .expect_err("should fail");
        assert_eq!(err.sink, "spy");
    }

    #[test]
    fn the_default_flush_is_a_no_op_for_unbuffered_sinks() {
        #[derive(Debug)]
        struct Unbuffered;
        impl LogSink for Unbuffered {
            fn name(&self) -> &str {
                "unbuffered"
            }
            fn write(&mut self, _: &LogEvent) -> Result<(), SinkError> {
                Ok(())
            }
        }
        assert!(Unbuffered.flush().is_ok());
    }

    #[test]
    fn sink_errors_name_the_sink_that_produced_them() {
        // With a fanout of five sinks, "write failed" is not a diagnosis.
        let err = SinkError::new("file", "no space left on device");
        assert_eq!(err.to_string(), "file: no space left on device");
    }

    #[test]
    fn sinks_are_usable_behind_a_trait_object() {
        let mut sinks: Vec<Box<dyn LogSink>> = vec![Box::new(Spy::default())];
        for sink in &mut sinks {
            assert!(sink.write(&LogEvent::info(Category::Server, "x")).is_ok());
        }
    }
}
