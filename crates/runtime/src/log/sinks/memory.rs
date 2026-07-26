//! A bounded in-memory ring buffer.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::log::event::LogEvent;
use crate::log::sink::{LogSink, SinkContext, SinkError};

/// State shared between the sink and its read handles.
#[derive(Debug, Default)]
struct Buffer {
    events: VecDeque<LogEvent>,
    flushes: usize,
    /// Records evicted because the buffer was full.
    evicted: u64,
}

/// Keeps the most recent records in memory.
///
/// Two uses: the admin API's "recent log" view, which should not require a round
/// trip to disk, and tests, which need to assert on what was logged.
///
/// Bounded on purpose. An unbounded in-memory log is a memory leak with a
/// respectable name, and it fails at exactly the moment a server is already in
/// trouble.
#[derive(Debug)]
pub struct MemorySink {
    buffer: Arc<Mutex<Buffer>>,
    capacity: usize,
}

/// A read handle onto a [`MemorySink`]'s contents.
///
/// Cloneable and independent of the sink, so the admin API can hold one while
/// the writer thread owns the sink itself.
#[derive(Debug, Clone)]
pub struct MemoryHandle {
    buffer: Arc<Mutex<Buffer>>,
}

impl MemorySink {
    /// A ring buffer holding at most `capacity` records.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Buffer::default())),
            capacity: capacity.max(1),
        }
    }

    /// A handle for reading the buffer from elsewhere.
    #[must_use]
    pub fn handle(&self) -> MemoryHandle {
        MemoryHandle {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

impl MemoryHandle {
    /// The most recent records, newest last, at most `limit` of them.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<LogEvent> {
        let Ok(buffer) = self.buffer.lock() else {
            // A poisoned lock means a previous holder panicked. Reporting an
            // empty log is better than propagating the panic into the caller.
            return Vec::new();
        };
        let skip = buffer.events.len().saturating_sub(limit);
        buffer.events.iter().skip(skip).cloned().collect()
    }

    /// How many records were dropped because the buffer was full.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.buffer.lock().map(|b| b.evicted).unwrap_or_default()
    }

    /// How many times the sink was flushed. Used by tests.
    #[must_use]
    pub fn flushes(&self) -> usize {
        self.buffer.lock().map(|b| b.flushes).unwrap_or_default()
    }
}

impl LogSink for MemorySink {
    fn name(&self) -> &str {
        "memory"
    }

    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
        let mut buffer = self.buffer.lock().sink("memory")?;

        if buffer.events.len() == self.capacity {
            let _ = buffer.events.pop_front();
            buffer.evicted += 1;
        }
        buffer.events.push_back(event.clone());
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        let mut buffer = self.buffer.lock().sink("memory")?;
        buffer.flushes += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::event::Category;

    fn event(n: u32) -> LogEvent {
        LogEvent::info(Category::Server, format!("event {n}"))
    }

    fn messages(events: &[LogEvent]) -> Vec<&str> {
        events.iter().map(|e| e.message.as_str()).collect()
    }

    #[test]
    fn records_are_readable_through_a_handle() {
        let mut sink = MemorySink::new(10);
        let handle = sink.handle();
        sink.write(&event(1)).expect("write");
        assert_eq!(messages(&handle.recent(10)), vec!["event 1"]);
    }

    #[test]
    fn recent_returns_newest_last() {
        let mut sink = MemorySink::new(10);
        let handle = sink.handle();
        for n in 1..=3 {
            sink.write(&event(n)).expect("write");
        }
        assert_eq!(
            messages(&handle.recent(10)),
            vec!["event 1", "event 2", "event 3"]
        );
    }

    #[test]
    fn the_buffer_is_bounded_and_evicts_the_oldest() {
        // An unbounded in-memory log is a memory leak with a respectable name.
        let mut sink = MemorySink::new(3);
        let handle = sink.handle();
        for n in 1..=5 {
            sink.write(&event(n)).expect("write");
        }

        assert_eq!(
            messages(&handle.recent(10)),
            vec!["event 3", "event 4", "event 5"]
        );
        assert_eq!(handle.evicted(), 2, "evictions must be counted, not hidden");
    }

    #[test]
    fn recent_honours_its_limit() {
        let mut sink = MemorySink::new(10);
        let handle = sink.handle();
        for n in 1..=5 {
            sink.write(&event(n)).expect("write");
        }
        assert_eq!(messages(&handle.recent(2)), vec!["event 4", "event 5"]);
    }

    #[test]
    fn a_zero_capacity_still_holds_one_record() {
        // A sink that can hold nothing is a NullSink with extra steps; clamping
        // means a mis-set config degrades rather than silently discarding.
        let mut sink = MemorySink::new(0);
        let handle = sink.handle();
        sink.write(&event(1)).expect("write");
        assert_eq!(handle.recent(10).len(), 1);
    }

    #[test]
    fn an_empty_buffer_reads_as_empty() {
        assert!(MemorySink::new(10).handle().recent(10).is_empty());
    }

    #[test]
    fn handles_share_the_sinks_buffer() {
        let mut sink = MemorySink::new(10);
        let first = sink.handle();
        let second = sink.handle();
        sink.write(&event(1)).expect("write");
        assert_eq!(first.recent(10).len(), second.recent(10).len());
    }
}
