//! Discard everything (Null Object).

use crate::event::LogEvent;
use crate::sink::{LogSink, SinkError};

/// Accepts every record and keeps none.
///
/// Null Object: it exists so "logging is off" is a *sink* rather than an
/// `Option<Box<dyn LogSink>>` threaded through every call site. Nothing branches
/// on whether logging is configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl LogSink for NullSink {
    fn name(&self) -> &str {
        "null"
    }

    fn write(&mut self, _event: &LogEvent) -> Result<(), SinkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Category, Severity};

    #[test]
    fn every_record_is_accepted_and_discarded() {
        let mut sink = NullSink;
        for severity in [Severity::Debug, Severity::Critical] {
            assert!(sink
                .write(&LogEvent::new(severity, Category::Server, "x"))
                .is_ok());
        }
    }

    #[test]
    fn flushing_succeeds() {
        // So shutdown needs no special case for "logging is off".
        assert!(NullSink.flush().is_ok());
    }

    #[test]
    fn it_is_usable_wherever_a_sink_is_expected() {
        let sink: Box<dyn LogSink> = Box::new(NullSink);
        assert_eq!(sink.name(), "null");
    }
}
