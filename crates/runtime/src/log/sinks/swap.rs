//! A sink slot whose occupant can be replaced while the writer runs (Decorator).
//!
//! The sink tree is built once and handed to the writer thread, which owns it
//! for the life of the process. That is right for everything about the tree's
//! *shape* and wrong for the log file, because the file is the thing an
//! operator needs to move: a full disk, a path that was a typo, a rotation
//! size that turned out to be far too small. Every one of those is discovered
//! while the server is running, and none of them is worth restarting the
//! process that holds every client's connection to fix.
//!
//! So the file lives behind this. The slot is always present, even when there
//! is no file in it, which is what lets file logging be switched *on* without a
//! restart rather than only reconfigured.
//!
//! # Who opens the file
//!
//! Not this. [`SwapHandle::put`] takes a sink that is already open, so a path
//! that cannot be opened fails in the caller -- which has a logger, an operator
//! to report to, and the option of leaving the working sink in place. Opening
//! inside the writer thread would put that decision where nothing can report it
//! and no record could be written about it, since the log is what is broken.
//!
//! The outgoing sink is **flushed before it is dropped**, so records buffered
//! against the old file reach the old file rather than disappearing when the
//! path changes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::log::event::LogEvent;
use crate::log::sink::{LogSink, SinkError};

/// What a [`SwapHandle`] has asked the slot to do next.
enum Pending {
    /// Take this sink, flushing and dropping whatever is there.
    Put(Box<dyn LogSink>),
    /// Empty the slot, flushing and dropping whatever is there.
    Clear,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Put(sink) => f.debug_tuple("Put").field(&sink.name()).finish(),
            Self::Clear => f.write_str("Clear"),
        }
    }
}

#[derive(Debug, Default)]
struct Slot {
    /// Set while a swap is waiting, so the write path costs one relaxed load
    /// rather than a mutex acquisition per record.
    waiting: AtomicBool,
    pending: Mutex<Option<Pending>>,
}

/// A sink whose inner sink can be replaced from another thread.
///
/// Writing to an empty slot succeeds and does nothing, exactly as a
/// [`FanoutSink`](super::FanoutSink) with no children does: "no file
/// configured" is a state, not a failure.
#[derive(Debug)]
pub struct SwapSink {
    name: &'static str,
    inner: Option<Box<dyn LogSink>>,
    slot: Arc<Slot>,
}

/// Replaces a running [`SwapSink`]'s occupant.
///
/// Cheap to clone, and every clone drives the same slot.
#[derive(Debug, Clone)]
pub struct SwapHandle {
    slot: Arc<Slot>,
}

impl SwapHandle {
    /// Put `sink` in the slot, from the next record onwards.
    ///
    /// A swap queued and not yet taken up is replaced rather than queued behind:
    /// two reloads in quick succession mean the second one is what the operator
    /// wants, and opening the first file only to close it unwritten helps
    /// nobody.
    pub fn put(&self, sink: Box<dyn LogSink>) {
        self.set(Some(Pending::Put(sink)));
    }

    /// Empty the slot, from the next record onwards.
    pub fn clear(&self) {
        self.set(Some(Pending::Clear));
    }

    fn set(&self, pending: Option<Pending>) {
        match self.slot.pending.lock() {
            Ok(mut slot) => *slot = pending,
            // Diagnostics must not take the process down, the same rule the
            // pressure registry follows.
            Err(poisoned) => *poisoned.into_inner() = pending,
        }
        self.slot.waiting.store(true, Ordering::Release);
    }
}

impl SwapSink {
    /// A slot named `name`, holding `inner`.
    #[must_use]
    pub fn new(name: &'static str, inner: Option<Box<dyn LogSink>>) -> Self {
        Self {
            name,
            inner,
            slot: Arc::new(Slot::default()),
        }
    }

    /// A handle that replaces this slot's occupant while it runs.
    #[must_use]
    pub fn handle(&self) -> SwapHandle {
        SwapHandle {
            slot: Arc::clone(&self.slot),
        }
    }

    /// Take up a queued swap, if there is one.
    fn take_pending(&mut self) {
        if !self.slot.waiting.swap(false, Ordering::Acquire) {
            return;
        }
        let pending = match self.slot.pending.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        let Some(pending) = pending else {
            return;
        };
        // Before the old sink is dropped: a buffered record belongs in the file
        // it was written against, and a rotation size change would otherwise
        // lose whatever had not reached the disk yet.
        if let Some(outgoing) = &mut self.inner
            && let Err(error) = outgoing.flush()
        {
            tracing::warn!(%error, sink = self.name, "could not flush before swapping");
        }
        self.inner = match pending {
            Pending::Put(sink) => Some(sink),
            Pending::Clear => None,
        };
    }
}

impl LogSink for SwapSink {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
        self.take_pending();
        match &mut self.inner {
            Some(inner) => inner.write(event),
            None => Ok(()),
        }
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        self.take_pending();
        match &mut self.inner {
            Some(inner) => inner.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::event::{Category, Severity};
    use crate::log::sinks::{MemoryHandle, MemorySink};

    fn memory() -> (Box<dyn LogSink>, MemoryHandle) {
        let sink = MemorySink::new(16);
        let handle = sink.handle();
        (Box::new(sink), handle)
    }

    fn event(message: &str) -> LogEvent {
        LogEvent::new(Severity::Info, Category::Server, message)
    }

    #[test]
    fn an_empty_slot_accepts_records_and_discards_them() {
        // "No file configured" is a state, not a failure: reporting an error
        // here would make a fanout with no file look broken.
        let mut sink = SwapSink::new("file", None);
        assert!(sink.write(&event("x")).is_ok());
        assert!(sink.flush().is_ok());
    }

    #[test]
    fn a_record_after_a_swap_reaches_the_new_sink() {
        let (first, first_handle) = memory();
        let mut sink = SwapSink::new("file", Some(first));
        let handle = sink.handle();

        sink.write(&event("before")).expect("write");

        let (second, second_handle) = memory();
        handle.put(second);
        sink.write(&event("after")).expect("write");

        assert_eq!(
            first_handle.recent(10).len(),
            1,
            "the old sink keeps its own"
        );
        assert_eq!(second_handle.recent(10).len(), 1);
        assert_eq!(second_handle.recent(10)[0].message, "after");
    }

    #[test]
    fn clearing_the_slot_stops_writing_without_failing() {
        let (first, first_handle) = memory();
        let mut sink = SwapSink::new("file", Some(first));
        let handle = sink.handle();

        handle.clear();
        sink.write(&event("after")).expect("write");
        assert!(
            first_handle.recent(10).is_empty(),
            "a cleared slot writes nowhere"
        );
    }

    #[test]
    fn a_slot_can_be_filled_from_empty() {
        // Switching file logging on without a restart, which is the half a
        // conditionally-built tree could never do.
        let mut sink = SwapSink::new("file", None);
        let handle = sink.handle();
        let (added, added_handle) = memory();

        handle.put(added);
        sink.write(&event("now recorded")).expect("write");
        assert_eq!(added_handle.recent(10).len(), 1);
    }

    #[test]
    fn the_last_swap_queued_is_the_one_taken_up() {
        // Two reloads in quick succession: the operator means the second.
        let mut sink = SwapSink::new("file", None);
        let handle = sink.handle();
        let (first, first_handle) = memory();
        let (second, second_handle) = memory();

        handle.put(first);
        handle.put(second);
        sink.write(&event("x")).expect("write");

        assert!(first_handle.recent(10).is_empty());
        assert_eq!(second_handle.recent(10).len(), 1);
    }

    #[test]
    fn a_flush_takes_up_a_pending_swap_too() {
        // Otherwise a swap queued during shutdown would never be taken up, and
        // the final flush would go to the sink being replaced.
        let mut sink = SwapSink::new("file", None);
        let handle = sink.handle();
        let (added, added_handle) = memory();
        handle.put(added);

        sink.flush().expect("flush");
        sink.write(&event("x")).expect("write");
        assert_eq!(added_handle.recent(10).len(), 1);
    }
}
