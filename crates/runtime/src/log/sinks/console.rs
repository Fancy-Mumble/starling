//! Human-readable output to a writer.

use std::io::Write;

use crate::log::event::LogEvent;
use crate::log::sink::{LogSink, SinkContext, SinkError};
use crate::log::timestamp;

/// Writes one line per record.
///
/// Generic over the destination so tests can capture the output, but defaults to
/// stderr, stdout belongs to the program's actual output (`migrate-config`
/// prints a config there, and a log line in the middle of it would corrupt the
/// result).
pub struct ConsoleSink {
    out: Box<dyn Write + Send>,
    name: &'static str,
}

impl std::fmt::Debug for ConsoleSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleSink")
            .field("name", &self.name)
            .finish()
    }
}

impl ConsoleSink {
    /// Write to stderr.
    #[must_use]
    pub fn stderr() -> Self {
        Self {
            out: Box::new(std::io::stderr()),
            name: "console",
        }
    }

    /// Write to an arbitrary destination.
    #[must_use]
    pub fn to(out: Box<dyn Write + Send>) -> Self {
        Self {
            out,
            name: "writer",
        }
    }

    /// Render a record as one line.
    ///
    /// `<timestamp> <SEVERITY> <category> <message> key=value ...`
    #[must_use]
    pub fn format(event: &LogEvent) -> String {
        let mut line = format!(
            "{} {} {:<10} {}",
            timestamp::rfc3339(event.at),
            event.severity.label(),
            event.category.label(),
            event.message,
        );
        for field in &event.fields {
            line.push_str(&format!(" {}={}", field.key, field.value));
        }
        line
    }
}

impl LogSink for ConsoleSink {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
        writeln!(self.out, "{}", Self::format(event)).sink(self.name)
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.out.flush().sink(self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::event::{Category, Severity};
    use std::sync::{Arc, Mutex};

    /// A writer that keeps what it was given, so a test can read it back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            let guard = self.0.lock().expect("test lock");
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Reported rather than panicked: this is the `Write` a sink writes
            // into, so a poisoned lock should surface as the sink error the
            // real code path already handles, not as a second panic.
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("the capture buffer is poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn captured() -> (ConsoleSink, Captured) {
        let sink = Captured::default();
        (ConsoleSink::to(Box::new(sink.clone())), sink)
    }

    #[test]
    fn a_record_renders_as_one_line() {
        let (mut console, out) = captured();
        console
            .write(&LogEvent::info(Category::Session, "session established"))
            .expect("write");
        let text = out.text();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("session established"));
        assert!(text.contains("INFO"));
        assert!(text.contains("session"));
    }

    #[test]
    fn fields_are_appended_as_key_equals_value_in_order() {
        let (mut console, out) = captured();
        console
            .write(
                &LogEvent::info(Category::Session, "established")
                    .with("session", 7u32)
                    .with("username", "alice"),
            )
            .expect("write");
        assert!(
            out.text().contains("session=7 username=alice"),
            "{}",
            out.text()
        );
    }

    #[test]
    fn a_record_without_fields_has_no_trailing_separator() {
        let line = ConsoleSink::format(&LogEvent::info(Category::Server, "started"));
        assert!(!line.ends_with(' '), "{line:?}");
        assert!(line.ends_with("started"), "{line:?}");
    }

    #[test]
    fn every_line_starts_with_a_timestamp() {
        let line = ConsoleSink::format(&LogEvent::info(Category::Server, "x"));
        assert!(line.starts_with("20"), "{line:?}");
        assert!(line.contains('T') && line.contains('Z'), "{line:?}");
    }

    #[test]
    fn severity_and_category_columns_align_across_records() {
        // So a human can scan the message column.
        let short = ConsoleSink::format(&LogEvent::info(Category::Server, "x"));
        let long = ConsoleSink::format(&LogEvent::warning(Category::Permission, "x"));
        let offset = |line: &str| line.find(" x").expect("message present");
        assert_eq!(offset(&short), offset(&long));
    }

    #[test]
    fn several_records_produce_several_lines() {
        let (mut console, out) = captured();
        for i in 0..3u32 {
            console
                .write(&LogEvent::info(Category::Server, format!("event {i}")))
                .expect("write");
        }
        assert_eq!(out.text().lines().count(), 3);
    }

    #[test]
    fn the_severity_label_is_the_one_the_event_carries() {
        for severity in [Severity::Debug, Severity::Error, Severity::Critical] {
            let event = LogEvent::new(severity, Category::Server, "x");
            assert!(ConsoleSink::format(&event).contains(severity.label().trim()));
        }
    }
}
