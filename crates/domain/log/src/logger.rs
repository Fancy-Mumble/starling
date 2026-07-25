//! Non-blocking dispatch to a sink.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::event::{Category, LogEvent, Severity};
use crate::sink::LogSink;

/// What the writer thread is asked to do.
enum Message {
    Write(Box<LogEvent>),
    Flush,
    Stop,
}

/// The server's entry point for logging.
///
/// [`Self::log`] **never blocks** and never fails: it hands the record to a
/// bounded queue drained by a dedicated OS thread. A slow disk cannot stall the
/// voice path.
///
/// Cheap to clone — every clone feeds the same writer.
#[derive(Debug, Clone)]
pub struct Logger {
    tx: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
}

/// Stops the writer, flushing what is queued.
///
/// Held by the composition root and dropped last, so records produced during
/// shutdown still reach the sink.
#[derive(Debug)]
pub struct LoggerShutdown {
    tx: SyncSender<Message>,
    thread: Option<JoinHandle<()>>,
}

impl Logger {
    /// Start a writer thread feeding `sink`, queueing at most `capacity`
    /// records.
    #[must_use]
    pub fn spawn(sink: Box<dyn LogSink>, capacity: usize) -> (Self, LoggerShutdown) {
        let (tx, rx) = sync_channel(capacity.max(1));
        let dropped = Arc::new(AtomicU64::new(0));

        let thread = std::thread::Builder::new()
            .name("starling-log".into())
            .spawn({
                let dropped = Arc::clone(&dropped);
                let writer = Writer::new(sink, dropped);
                move || writer.run(&rx)
            })
            .ok();

        let logger = Self {
            tx: tx.clone(),
            dropped,
        };
        (logger, LoggerShutdown { tx, thread })
    }

    /// A logger that discards everything, for tests and for "logging off".
    #[must_use]
    pub fn disabled() -> (Self, LoggerShutdown) {
        Self::spawn(Box::new(crate::sinks::NullSink), 1)
    }

    /// Queue a record. Never blocks; never fails.
    ///
    /// If the queue is full the record is dropped and counted — see
    /// [`Self::dropped`]. Blocking here would let a slow sink apply
    /// backpressure to the server, which is exactly what a log must never do.
    pub fn log(&self, event: LogEvent) {
        if self.tx.try_send(Message::Write(Box::new(event))).is_err() {
            let _ = self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How many records have been dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Ask the writer to make everything queued so far durable.
    ///
    /// Advisory: returns as soon as the request is queued, not once it is done.
    pub fn request_flush(&self) {
        let _ = self.tx.try_send(Message::Flush);
    }
}

impl LoggerShutdown {
    /// Stop the writer, flushing what is queued.
    ///
    /// Blocking is correct here, unlike in [`Logger::log`]: this runs once, on
    /// the way out, and the whole point is to not lose the last records.
    pub fn shutdown(mut self) {
        let _ = self.tx.send(Message::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for LoggerShutdown {
    fn drop(&mut self) {
        let _ = self.tx.send(Message::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// How long a record may sit in a sink's buffer before being made durable.
///
/// A graceful shutdown flushes, but `SIGKILL` and the OOM killer do not — and
/// those are exactly the deaths whose last records matter. This bounds the loss
/// window instead of leaving it open until the buffer happens to fill.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// The writer thread: the only thing that touches the sink.
///
/// A struct because it has state that must survive between messages — the sink,
/// how many drops have already been reported, and whether anything is waiting to
/// be flushed. That state used to live as locals in a `run` function which passed
/// `&mut reported` down to a helper; an accumulator threaded through a call is a
/// field wearing a disguise.
struct Writer {
    sink: Box<dyn LogSink>,
    /// Shared with every [`Logger`] clone, which increments it on a full queue.
    dropped: Arc<AtomicU64>,
    /// Drops already reported, so each overflow is reported once.
    reported: u64,
    /// Whether records have been written but not yet made durable.
    unflushed: bool,
}

impl Writer {
    fn new(sink: Box<dyn LogSink>, dropped: Arc<AtomicU64>) -> Self {
        Self {
            sink,
            dropped,
            reported: 0,
            unflushed: false,
        }
    }

    /// Serve the queue until stopped, then drain what is left.
    fn run(mut self, rx: &Receiver<Message>) {
        loop {
            match rx.recv_timeout(FLUSH_INTERVAL) {
                Ok(Message::Write(event)) => {
                    self.report_drops();
                    self.emit(&event);
                }
                Ok(Message::Flush) => self.flush(),
                Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    // Only when there is something to lose: an idle server should
                    // not wake the disk twice a second.
                    if self.unflushed {
                        self.flush();
                    }
                }
            }
        }

        // Drain whatever is still queued before going away: the records just
        // before a shutdown are the ones most worth having.
        while let Ok(Message::Write(event)) = rx.try_recv() {
            self.emit(&event);
        }
        self.report_drops();
        self.flush();
    }

    /// Emit one record, swallowing sink errors.
    ///
    /// A failing sink must not take the writer thread down; there is nowhere left
    /// to report it to.
    fn emit(&mut self, event: &LogEvent) {
        let _ = self.sink.write(event);
        self.unflushed = true;
    }

    fn flush(&mut self) {
        let _ = self.sink.flush();
        self.unflushed = false;
    }

    /// Record any queue overflow since the last check.
    ///
    /// A log that quietly loses records is worse than no log, because it is
    /// trusted.
    fn report_drops(&mut self) {
        let total = self.dropped.load(Ordering::Relaxed);
        if total <= self.reported {
            return;
        }
        let new = total - self.reported;
        self.reported = total;
        self.emit(
            &LogEvent::warning(Category::Server, "log queue overflowed")
                .with("dropped", new)
                .with("dropped_total", total),
        );
    }
}

/// The severity below which the server should not bother building a record.
///
/// Exposed so hot paths can skip formatting work for records nothing will keep.
#[must_use]
pub fn cheapest_useful_severity() -> Severity {
    Severity::Debug
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sinks::{FanoutSink, MemorySink, NullSink};

    fn logger_with_memory(capacity: usize) -> (Logger, LoggerShutdown, crate::sinks::MemoryHandle) {
        let sink = MemorySink::new(10_000);
        let handle = sink.handle();
        let (logger, shutdown) = Logger::spawn(Box::new(sink), capacity);
        (logger, shutdown, handle)
    }

    fn event(n: u32) -> LogEvent {
        LogEvent::info(Category::Server, format!("event {n}"))
    }

    #[test]
    fn records_reach_the_sink() {
        let (logger, shutdown, handle) = logger_with_memory(64);
        logger.log(event(1));
        logger.log(event(2));
        shutdown.shutdown();

        let messages: Vec<_> = handle.recent(100).into_iter().map(|e| e.message).collect();
        assert!(messages.contains(&"event 1".to_owned()));
        assert!(messages.contains(&"event 2".to_owned()));
    }

    #[test]
    fn records_are_delivered_in_order() {
        let (logger, shutdown, handle) = logger_with_memory(1024);
        for n in 0..50 {
            logger.log(event(n));
        }
        shutdown.shutdown();

        let messages: Vec<_> = handle
            .recent(1000)
            .into_iter()
            .map(|e| e.message)
            .filter(|m| m.starts_with("event "))
            .collect();
        assert_eq!(messages.len(), 50);
        assert_eq!(messages[0], "event 0");
        assert_eq!(messages[49], "event 49");
    }

    #[test]
    fn logging_never_blocks_even_when_the_queue_is_full() {
        // The property the whole design exists for. A capacity-1 queue behind a
        // sink we never let drain: this must return, not hang.
        let (logger, _shutdown) = Logger::spawn(Box::new(NullSink), 1);
        for n in 0..10_000 {
            logger.log(event(n));
        }
        // Reaching here at all is the assertion.
    }

    #[test]
    fn queue_overflow_is_counted_rather_than_silent() {
        let (logger, _shutdown) = Logger::spawn(Box::new(NullSink), 1);
        for n in 0..5_000 {
            logger.log(event(n));
        }
        // With a queue of 1 and 5000 records, some must have been dropped.
        assert!(logger.dropped() > 0, "overflow was not counted");
    }

    #[test]
    fn queue_overflow_is_reported_into_the_log_itself() {
        // Not just counted - an operator reading the log must see the gap.
        let sink = MemorySink::new(10_000);
        let handle = sink.handle();
        let (logger, shutdown) = Logger::spawn(Box::new(sink), 1);

        for n in 0..5_000 {
            logger.log(event(n));
        }
        shutdown.shutdown();

        let overflowed = handle
            .recent(10_000)
            .into_iter()
            .any(|e| e.message == "log queue overflowed");
        assert!(overflowed, "the gap was never reported");
    }

    #[test]
    fn shutdown_flushes_the_sink() {
        let sink = MemorySink::new(100);
        let handle = sink.handle();
        let (logger, shutdown) = Logger::spawn(Box::new(sink), 64);
        logger.log(event(1));
        shutdown.shutdown();
        assert!(handle.flushes() >= 1, "shutdown did not flush");
    }

    #[test]
    fn dropping_the_shutdown_handle_also_stops_the_writer() {
        // So a composition root that forgets to call shutdown still flushes.
        let sink = MemorySink::new(100);
        let handle = sink.handle();
        {
            let (logger, _shutdown) = Logger::spawn(Box::new(sink), 64);
            logger.log(event(1));
        }
        assert!(handle.flushes() >= 1);
    }

    #[test]
    fn a_cloned_logger_feeds_the_same_writer() {
        let (logger, shutdown, handle) = logger_with_memory(64);
        let clone = logger.clone();
        logger.log(event(1));
        clone.log(event(2));
        shutdown.shutdown();
        assert_eq!(handle.recent(100).len(), 2);
    }

    #[test]
    fn a_disabled_logger_accepts_records_and_keeps_none() {
        let (logger, shutdown) = Logger::disabled();
        logger.log(event(1));
        shutdown.shutdown();
        // No panic, no blocking; "logging off" needs no special case.
    }

    #[test]
    fn a_failing_sink_does_not_take_the_writer_down() {
        #[derive(Debug)]
        struct Broken;
        impl LogSink for Broken {
            fn name(&self) -> &str {
                "broken"
            }
            fn write(&mut self, _: &LogEvent) -> Result<(), crate::SinkError> {
                Err(crate::SinkError::new("broken", "always"))
            }
        }

        let recorder = MemorySink::new(100);
        let handle = recorder.handle();
        let sink = FanoutSink::new()
            .with(Box::new(Broken))
            .with(Box::new(recorder));

        let (logger, shutdown) = Logger::spawn(Box::new(sink), 64);
        logger.log(event(1));
        logger.log(event(2));
        shutdown.shutdown();

        assert_eq!(
            handle.recent(100).len(),
            2,
            "the writer stopped after a sink error"
        );
    }

    #[test]
    fn buffered_records_are_flushed_without_waiting_for_shutdown() {
        // A server killed by SIGKILL or the OOM killer never reaches shutdown;
        // this bounds how much of the log dies with it.
        let sink = MemorySink::new(100);
        let handle = sink.handle();
        let (logger, _shutdown) = Logger::spawn(Box::new(sink), 64);

        logger.log(event(1));
        assert_eq!(handle.flushes(), 0, "no flush should have happened yet");

        std::thread::sleep(FLUSH_INTERVAL * 3);
        assert!(
            handle.flushes() >= 1,
            "the periodic flush never ran; buffered records would die with the process"
        );
    }

    #[test]
    fn an_idle_writer_does_not_flush_repeatedly() {
        // Otherwise an idle server wakes the disk twice a second forever.
        let sink = MemorySink::new(100);
        let handle = sink.handle();
        let (_logger, _shutdown) = Logger::spawn(Box::new(sink), 64);

        std::thread::sleep(FLUSH_INTERVAL * 3);
        assert_eq!(handle.flushes(), 0, "an idle writer flushed anyway");
    }

    #[test]
    fn an_explicit_flush_request_is_honoured() {
        let sink = MemorySink::new(100);
        let handle = sink.handle();
        let (logger, shutdown) = Logger::spawn(Box::new(sink), 64);

        logger.log(event(1));
        logger.request_flush();
        shutdown.shutdown();
        assert!(handle.flushes() >= 1);
    }

    #[test]
    fn records_queued_just_before_shutdown_are_not_lost() {
        let (logger, shutdown, handle) = logger_with_memory(1024);
        for n in 0..200 {
            logger.log(event(n));
        }
        shutdown.shutdown();

        let kept = handle
            .recent(1000)
            .into_iter()
            .filter(|e| e.message.starts_with("event "))
            .count();
        assert_eq!(kept, 200);
    }
}
