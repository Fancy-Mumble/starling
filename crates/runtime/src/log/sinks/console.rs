//! Human-readable output to a writer.

use std::io::Write;

use crate::log::event::{FieldValue, LogEvent, Severity};
use crate::log::sink::{LogSink, SinkContext, SinkError};
use crate::log::timestamp;

/// Writes one line per record.
///
/// Generic over the destination so tests can capture the output, but defaults to
/// stderr, stdout belongs to the program's actual output (`migrate-config`
/// prints a config there, and a log line in the middle of it would corrupt the
/// result).
///
/// # Shape
///
/// The line is laid out the way `tracing_subscriber`'s default formatter lays
/// out a developer-diagnostic line, deliberately: both write to the same stderr,
/// and an operator reading them interleaved should not have to switch eyes
/// between two shapes.
///
/// ```text
/// 2026-08-16T18:40:10.897432Z  INFO session: client connected conn=1 peer="[::1]:54070"
/// 2026-08-16T18:40:42.089855Z  INFO starling_operator_api::live: a live subscriber attached subject="token:..."
/// ```
///
/// Same timestamp precision, same right-aligned level column, the category
/// where `tracing` puts its target, and string values quoted the way `tracing`
/// quotes them, so `reason="connection reset"` reads as one value rather than
/// two words. On a console the same styles apply too: dimmed timestamp and
/// target, coloured level, italic field names.
pub struct ConsoleSink {
    out: Box<dyn Write + Send>,
    name: &'static str,
    ansi: bool,
}

impl std::fmt::Debug for ConsoleSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleSink")
            .field("name", &self.name)
            .field("ansi", &self.ansi)
            .finish()
    }
}

impl ConsoleSink {
    /// Write to stderr, styled unless `NO_COLOR` says otherwise.
    ///
    /// The rule is `tracing_subscriber`'s: colour by default, off when the
    /// [`NO_COLOR`](https://no-color.org/) variable is set to anything
    /// non-empty. Not "only on a terminal", because `docker logs` is not a
    /// terminal and is where most operators read this, and because the two
    /// emitters sharing stderr must make the same decision or the mix is
    /// worse than either.
    #[must_use]
    pub fn stderr() -> Self {
        Self {
            out: Box::new(std::io::stderr()),
            name: "console",
            ansi: ansi_by_default(),
        }
    }

    /// Write to an arbitrary destination, unstyled.
    #[must_use]
    pub fn to(out: Box<dyn Write + Send>) -> Self {
        Self {
            out,
            name: "writer",
            ansi: false,
        }
    }

    /// Force styling on or off, overriding the environment.
    #[must_use]
    pub fn with_ansi(mut self, ansi: bool) -> Self {
        self.ansi = ansi;
        self
    }

    /// Render a record as one plain line, with no escape sequences.
    ///
    /// `<timestamp> <SEVERITY> <category>: <message> key=value ...`
    ///
    /// This is also what [`FileSink`](crate::log::sinks::FileSink) writes, so
    /// a file and a console read the same, and a file never carries colour.
    #[must_use]
    pub fn format(event: &LogEvent) -> String {
        render(event, &Palette::PLAIN)
    }

    /// Render a record as one line with terminal styling.
    #[must_use]
    pub fn format_ansi(event: &LogEvent) -> String {
        render(event, &Palette::ANSI)
    }
}

impl LogSink for ConsoleSink {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
        let palette = if self.ansi {
            &Palette::ANSI
        } else {
            &Palette::PLAIN
        };
        // One `write_all` with the newline already in it, not `writeln!`.
        // `writeln!` writes the text and the newline as two calls, and stderr
        // is shared with `tracing`'s subscriber on other threads: its line
        // landed between the two often enough to be seen, gluing itself onto
        // ours and leaving our newline on a line of its own.
        let mut line = render(event, palette);
        line.push('\n');
        self.out.write_all(line.as_bytes()).sink(self.name)
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.out.flush().sink(self.name)
    }
}

/// `tracing_subscriber`'s default: on, unless `NO_COLOR` is set and non-empty.
fn ansi_by_default() -> bool {
    std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
}

/// The escape sequences one rendering uses. All empty for plain text, so the
/// layout is written once and the styling is data.
struct Palette {
    dim: &'static str,
    italic: &'static str,
    reset: &'static str,
    /// Whether levels are coloured at all.
    level: bool,
}

impl Palette {
    const PLAIN: Self = Self {
        dim: "",
        italic: "",
        reset: "",
        level: false,
    };

    /// SGR sequences, the ones `nu-ansi-term` emits for `tracing`'s styles.
    const ANSI: Self = Self {
        dim: "\x1b[2m",
        italic: "\x1b[3m",
        reset: "\x1b[0m",
        level: true,
    };

    /// The colour a level is painted, `tracing`'s palette where the two
    /// overlap and a neighbouring hue where they do not.
    ///
    /// `Notice` sits between `Info` and `Warning` and gets cyan, distinct from
    /// both without alarming. `Critical` is `Error`'s red, bold, so the last
    /// line before the server stops is the one that stands out.
    fn level(&self, severity: Severity) -> &'static str {
        if !self.level {
            return "";
        }
        match severity {
            Severity::Debug => "\x1b[34m",
            Severity::Info => "\x1b[32m",
            Severity::Notice => "\x1b[36m",
            Severity::Warning => "\x1b[33m",
            Severity::Error => "\x1b[31m",
            Severity::Critical => "\x1b[1;31m",
        }
    }
}

/// Lay out one record.
fn render(event: &LogEvent, palette: &Palette) -> String {
    let Palette {
        dim, italic, reset, ..
    } = *palette;
    let mut line = format!(
        "{dim}{}{reset} {}{}{reset} {dim}{}:{reset} {}",
        timestamp::rfc3339(event.at),
        palette.level(event.severity),
        event.severity.label(),
        event.category.label(),
        event.message,
    );
    for field in &event.fields {
        line.push_str(&format!(" {italic}{}{reset}{dim}={reset}", field.key));
        match &field.value {
            // Quoted, and escaped, as `tracing` renders a string: a value with a
            // space in it stays one value, and a username with a newline in it
            // stays on its line.
            FieldValue::Text(text) => line.push_str(&format!("{text:?}")),
            other => line.push_str(&other.to_string()),
        }
    }
    line
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
    fn a_line_has_the_shape_tracing_gives_its_own() {
        // `<timestamp> <level> <target>: <message> <fields>`, so the two
        // emitters sharing stderr read as one log.
        let line = ConsoleSink::format(
            &LogEvent::info(Category::Session, "client connected").with("conn", 1u32),
        );
        let (timestamp, rest) = line.split_once(' ').expect("timestamp");
        assert!(timestamp.ends_with('Z'), "{line:?}");
        assert_eq!(rest, " INFO session: client connected conn=1", "{line:?}");
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
            out.text().contains("session=7 username=\"alice\""),
            "{}",
            out.text()
        );
    }

    #[test]
    fn text_values_are_quoted_so_a_space_does_not_split_them() {
        // `reason=connection reset` reads as a value and a stray word;
        // `reason="connection reset"` reads as what it is. Numbers and flags
        // need no quoting, and `tracing` leaves them bare too.
        let line = ConsoleSink::format(
            &LogEvent::info(Category::Session, "client disconnected")
                .with("reason", "connection reset")
                .with("conn", 3u32)
                .with("registered", true),
        );
        assert!(
            line.ends_with("reason=\"connection reset\" conn=3 registered=true"),
            "{line:?}"
        );
    }

    #[test]
    fn a_text_value_cannot_break_out_of_its_line() {
        // A username chosen to look like a second record must stay a value.
        let line = ConsoleSink::format(
            &LogEvent::info(Category::Session, "user authenticated").with(
                "name",
                "x\n2026-01-01T00:00:00.000000Z ERROR server: forged",
            ),
        );
        assert_eq!(line.lines().count(), 1, "{line:?}");
        assert!(line.contains("\\n"), "{line:?}");
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
    fn the_level_column_aligns_across_records() {
        // The level is where an eye scanning stderr stops, so it must sit in
        // the same column whatever the severity, as `tracing`'s does.
        let offset = |line: &str| line.find(" server:").expect("target present");
        let info = ConsoleSink::format(&LogEvent::info(Category::Server, "x"));
        let error = ConsoleSink::format(&LogEvent::error(Category::Server, "x"));
        assert_eq!(offset(&info), offset(&error), "{info:?} vs {error:?}");
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

    #[test]
    fn plain_output_carries_no_escape_sequences() {
        // The same renderer writes log files; a file with colour codes in it
        // is a file that needs a tool to read.
        let line = ConsoleSink::format(
            &LogEvent::warning(Category::Security, "refused").with("peer", "[::1]:1"),
        );
        assert!(!line.contains('\x1b'), "{line:?}");
    }

    #[test]
    fn styled_output_is_the_plain_line_plus_escapes() {
        // Colour must never change what is said, only how it looks: stripping
        // the escapes has to give back exactly the plain rendering.
        let event = LogEvent::warning(Category::Security, "tls handshake failed")
            .with("peer", "[::1]:1")
            .with("attempt", 2u32);
        let styled = ConsoleSink::format_ansi(&event);
        assert!(styled.contains('\x1b'), "{styled:?}");
        assert_eq!(strip_ansi(&styled), ConsoleSink::format(&event));
    }

    #[test]
    fn levels_are_coloured_the_way_tracing_colours_its_own() {
        // Green info, yellow warnings, red errors, so a `WARN` from either
        // emitter looks like the same kind of thing.
        let colour = |severity: Severity| {
            let line = ConsoleSink::format_ansi(&LogEvent::new(severity, Category::Server, "x"));
            let start = line.find(severity.label()).expect("label present");
            let (before, _) = line.split_at(start);
            before.rsplit("\x1b[").next().map(str::to_owned)
        };
        assert_eq!(colour(Severity::Info).as_deref(), Some("32m"));
        assert_eq!(colour(Severity::Warning).as_deref(), Some("33m"));
        assert_eq!(colour(Severity::Error).as_deref(), Some("31m"));
        assert_ne!(colour(Severity::Notice), colour(Severity::Info));
        assert_ne!(colour(Severity::Critical), colour(Severity::Error));
    }

    #[test]
    fn a_sink_given_a_writer_is_plain_unless_asked() {
        let (mut console, out) = captured();
        console
            .write(&LogEvent::info(Category::Server, "x"))
            .expect("write");
        assert!(!out.text().contains('\x1b'));

        let sink = Captured::default();
        let mut styled = ConsoleSink::to(Box::new(sink.clone())).with_ansi(true);
        styled
            .write(&LogEvent::info(Category::Server, "x"))
            .expect("write");
        assert!(sink.text().contains('\x1b'));
    }

    /// Drop every SGR sequence, leaving the text.
    fn strip_ansi(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find('\x1b') {
            let (before, after) = rest.split_at(start);
            out.push_str(before);
            let end = after.find('m').map_or(after.len(), |m| m + 1);
            rest = after.split_at(end).1;
        }
        out.push_str(rest);
        out
    }
}
