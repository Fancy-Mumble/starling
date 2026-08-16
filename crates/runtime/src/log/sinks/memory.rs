//! A bounded in-memory ring buffer.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// How many records to keep, as the operator has it now.
    ///
    /// Shared with the read handle so `logging.memory.records` can be changed
    /// on a running server, and so that turning the ring off is a capacity of
    /// zero rather than a sink removed from the tree -- which would leave the
    /// admin API holding a handle onto a ring nothing writes to any more.
    capacity: Arc<AtomicUsize>,
}

/// A read handle onto a [`MemorySink`]'s contents.
///
/// Cloneable and independent of the sink, so the admin API can hold one while
/// the writer thread owns the sink itself.
#[derive(Debug, Clone)]
pub struct MemoryHandle {
    buffer: Arc<Mutex<Buffer>>,
    capacity: Arc<AtomicUsize>,
}

impl MemorySink {
    /// A ring buffer holding at most `capacity` records.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Buffer::default())),
            capacity: Arc::new(AtomicUsize::new(capacity)),
        }
    }

    /// A handle for reading the buffer from elsewhere.
    #[must_use]
    pub fn handle(&self) -> MemoryHandle {
        MemoryHandle {
            buffer: Arc::clone(&self.buffer),
            capacity: Arc::clone(&self.capacity),
        }
    }
}

impl MemoryHandle {
    /// Keep at most `records` from now on. Zero switches the ring off.
    pub fn set_capacity(&self, records: usize) {
        self.capacity.store(records, Ordering::Relaxed);
    }

    /// How many records the ring keeps.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

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
        let capacity = self.capacity.load(Ordering::Relaxed);
        let mut buffer = self.buffer.lock().sink("memory")?;

        // Zero is "the operator turned the ring off", not "keep one": the ring
        // is switched off by `logging.memory.enabled`, and a sink that kept a
        // single record would still be holding one an operator asked it not to.
        if capacity == 0 {
            if !buffer.events.is_empty() {
                buffer.events.clear();
            }
            return Ok(());
        }
        while buffer.events.len() >= capacity {
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
    fn a_zero_capacity_is_the_ring_switched_off() {
        // This used to clamp to one, on the argument that a sink holding
        // nothing is a `NullSink` with extra steps. It is now how
        // `logging.memory.enabled = false` is expressed, because the admin API
        // holds this sink's handle for the life of the process and removing the
        // sink from the tree would leave it reading a ring nothing writes to.
        // A ring an operator switched off must hold nothing, not one record.
        let mut sink = MemorySink::new(0);
        let handle = sink.handle();
        sink.write(&event(1)).expect("write");
        assert!(handle.recent(10).is_empty());
    }

    #[test]
    fn resizing_the_ring_takes_effect_on_the_next_record() {
        let mut sink = MemorySink::new(4);
        let handle = sink.handle();
        for n in 1..=4 {
            sink.write(&event(n)).expect("write");
        }
        assert_eq!(handle.recent(10).len(), 4);

        handle.set_capacity(2);
        sink.write(&event(5)).expect("write");
        assert_eq!(
            messages(&handle.recent(10)),
            vec!["event 4", "event 5"],
            "the ring trims to the new bound, keeping the newest"
        );
    }

    #[test]
    fn switching_the_ring_off_releases_what_it_was_holding() {
        // Otherwise "off" would still be pinning however many records happened
        // to be in memory when the operator turned it off.
        let mut sink = MemorySink::new(4);
        let handle = sink.handle();
        sink.write(&event(1)).expect("write");
        handle.set_capacity(0);
        sink.write(&event(2)).expect("write");
        assert!(handle.recent(10).is_empty());
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
