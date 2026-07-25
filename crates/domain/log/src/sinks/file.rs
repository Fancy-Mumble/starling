//! Append to a file, rotating by size.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::event::LogEvent;
use crate::sink::{LogSink, SinkContext, SinkError};
use crate::sinks::ConsoleSink;

/// Appends records to a file, rotating when it grows past a limit.
///
/// Rotation renames `starling.log` to `starling.log.1`, `.1` to `.2`, and so on,
/// discarding beyond `keep`. Size-based rather than time-based because the
/// failure being guarded against is a disk filling up, which has nothing to do
/// with the clock.
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    writer: BufWriter<File>,
    written: u64,
    max_bytes: u64,
    keep: usize,
}

impl FileSink {
    /// Open (or create) `path`, rotating past `max_bytes` and keeping `keep`
    /// old files.
    ///
    /// `max_bytes == 0` disables rotation.
    pub fn open(path: impl AsRef<Path>, max_bytes: u64, keep: usize) -> Result<Self, SinkError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).sink("file")?;
        }
        let (file, written) = Self::append_to(&path)?;
        Ok(Self {
            path,
            writer: BufWriter::new(file),
            written,
            max_bytes,
            keep,
        })
    }

    /// Open for append, reporting the current size so rotation is accurate
    /// across restarts.
    fn append_to(path: &Path) -> Result<(File, u64), SinkError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .sink("file")?;
        let written = file.metadata().map(|m| m.len()).sink("file")?;
        Ok((file, written))
    }

    /// Whether the next write would exceed the size limit.
    fn should_rotate(&self, incoming: u64) -> bool {
        self.max_bytes > 0 && self.written + incoming > self.max_bytes
    }

    /// Shift the numbered generations and start a fresh file.
    fn rotate(&mut self) -> Result<(), SinkError> {
        self.writer.flush().sink("file")?;

        // Walk downwards so a generation is never overwritten before it moves.
        for generation in (1..=self.keep).rev() {
            let from = if generation == 1 {
                self.path.clone()
            } else {
                self.numbered(generation - 1)
            };
            if from.exists() {
                let _ = std::fs::rename(&from, self.numbered(generation));
            }
        }
        if self.keep == 0 {
            let _ = std::fs::remove_file(&self.path);
        }

        let (file, written) = Self::append_to(&self.path)?;
        self.writer = BufWriter::new(file);
        self.written = written;
        Ok(())
    }

    fn numbered(&self, generation: usize) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".{generation}"));
        PathBuf::from(name)
    }
}

impl LogSink for FileSink {
    fn name(&self) -> &str {
        "file"
    }

    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
        let line = ConsoleSink::format(event);
        let size = line.len() as u64 + 1;

        if self.should_rotate(size) {
            self.rotate()?;
        }
        writeln!(self.writer, "{line}").sink("file")?;
        self.written += size;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.writer.flush().sink("file")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Category;

    /// A throwaway directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "starling-log-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn event(n: u32) -> LogEvent {
        LogEvent::info(Category::Server, format!("event {n}"))
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn records_are_appended_as_lines() {
        let dir = TempDir::new("append");
        let path = dir.join("starling.log");
        let mut sink = FileSink::open(&path, 0, 3).expect("open");

        sink.write(&event(1)).expect("write");
        sink.write(&event(2)).expect("write");
        sink.flush().expect("flush");

        let text = read(&path);
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("event 1") && text.contains("event 2"));
    }

    #[test]
    fn reopening_appends_rather_than_truncating() {
        // Restarting a server must not erase its log.
        let dir = TempDir::new("reopen");
        let path = dir.join("starling.log");

        let mut first = FileSink::open(&path, 0, 3).expect("open");
        first.write(&event(1)).expect("write");
        first.flush().expect("flush");
        drop(first);

        let mut second = FileSink::open(&path, 0, 3).expect("reopen");
        second.write(&event(2)).expect("write");
        second.flush().expect("flush");

        assert_eq!(read(&path).lines().count(), 2);
    }

    #[test]
    fn the_file_rotates_once_it_exceeds_the_limit() {
        let dir = TempDir::new("rotate");
        let path = dir.join("starling.log");
        let mut sink = FileSink::open(&path, 120, 3).expect("open");

        for n in 0..10 {
            sink.write(&event(n)).expect("write");
        }
        sink.flush().expect("flush");

        assert!(dir.join("starling.log.1").exists(), "no rotation happened");
    }

    #[test]
    fn rotation_keeps_at_most_the_configured_generations() {
        let dir = TempDir::new("keep");
        let path = dir.join("starling.log");
        let mut sink = FileSink::open(&path, 100, 2).expect("open");

        for n in 0..40 {
            sink.write(&event(n)).expect("write");
        }
        sink.flush().expect("flush");

        assert!(dir.join("starling.log.1").exists());
        assert!(dir.join("starling.log.2").exists());
        assert!(
            !dir.join("starling.log.3").exists(),
            "generations beyond `keep` must be discarded"
        );
    }

    #[test]
    fn rotation_preserves_the_older_generation_rather_than_overwriting_it() {
        let dir = TempDir::new("shift");
        let path = dir.join("starling.log");
        let mut sink = FileSink::open(&path, 90, 3).expect("open");

        for n in 0..20 {
            sink.write(&event(n)).expect("write");
        }
        sink.flush().expect("flush");

        // Whatever survived, the generations must be distinct files.
        let first = read(&dir.join("starling.log.1"));
        let second = read(&dir.join("starling.log.2"));
        assert_ne!(
            first, second,
            "a generation was overwritten by its successor"
        );
    }

    #[test]
    fn a_zero_size_limit_disables_rotation() {
        let dir = TempDir::new("no-rotate");
        let path = dir.join("starling.log");
        let mut sink = FileSink::open(&path, 0, 3).expect("open");

        for n in 0..50 {
            sink.write(&event(n)).expect("write");
        }
        sink.flush().expect("flush");

        assert!(!dir.join("starling.log.1").exists());
        assert_eq!(read(&path).lines().count(), 50);
    }

    #[test]
    fn a_missing_parent_directory_is_created() {
        let dir = TempDir::new("mkdir");
        let path = dir.join("nested/deeper/starling.log");
        let mut sink = FileSink::open(&path, 0, 3).expect("open");
        sink.write(&event(1)).expect("write");
        sink.flush().expect("flush");
        assert!(path.exists());
    }

    #[test]
    fn records_survive_a_flush_but_may_buffer_before_it() {
        // The reason `flush` is part of the sink contract at all.
        let dir = TempDir::new("buffered");
        let path = dir.join("starling.log");
        let mut sink = FileSink::open(&path, 0, 3).expect("open");
        sink.write(&event(1)).expect("write");
        sink.flush().expect("flush");
        assert!(read(&path).contains("event 1"));
    }
}
