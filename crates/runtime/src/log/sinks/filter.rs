//! Severity and category gating around any sink (Decorator).

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, Ordering};

use crate::log::event::{Category, LogEvent, Severity};
use crate::log::sink::{LogSink, SinkError};

/// Passes records to an inner sink only if they clear a threshold.
///
/// Decorator: it *is* a [`LogSink`] wrapping a [`LogSink`], so it can gate
/// anything, including a whole [`FanoutSink`](super::FanoutSink), and the
/// wrapped sink never learns it is being filtered.
///
/// This is what lets one configuration say "everything to the file, but only
/// warnings to the console" without either sink knowing about the other.
#[derive(Debug)]
pub struct FilterSink {
    inner: Box<dyn LogSink>,
    /// The threshold, shared with whoever may raise or lower it.
    ///
    /// An atomic rather than a plain [`Severity`] because this sink is owned by
    /// the writer thread: `logging.level` is reloadable, and the alternative to
    /// sharing the number is rebuilding the whole sink tree, which would mean
    /// reopening the log file to change a threshold.
    min_severity: Arc<AtomicU8>,
    /// Which categories pass, as a bitmask, or `0` for "no restriction".
    ///
    /// A mask rather than the `HashSet` this used to be, for the same reason
    /// the severity is an atomic: `logging.categories` is reloadable and this
    /// is read once per record, so a mutex here would be a lock on the path
    /// every log line takes. Zero keeps meaning "the operator did not want to
    /// filter by category", not "drop everything".
    categories: Arc<AtomicU16>,
}

/// Changes a running [`FilterSink`]'s threshold and category set.
///
/// Cheap to clone, and every clone moves the same filter.
#[derive(Debug, Clone)]
pub struct FilterHandle {
    level: Arc<AtomicU8>,
    categories: Arc<AtomicU16>,
}

impl FilterHandle {
    /// Record at `severity` and above from the next record onwards.
    pub fn set_level(&self, severity: Severity) {
        self.level.store(severity.index(), Ordering::Relaxed);
    }

    /// The threshold in force.
    #[must_use]
    pub fn level(&self) -> Severity {
        // An unknown number is not reachable through `set_level`, and falling
        // back to the default is better than a panic in the path every record
        // takes.
        Severity::from_index(self.level.load(Ordering::Relaxed)).unwrap_or(Severity::Info)
    }

    /// Restrict to `categories`. An empty set means no restriction.
    pub fn set_categories(&self, categories: impl IntoIterator<Item = Category>) {
        self.categories.store(mask(categories), Ordering::Relaxed);
    }

    /// The categories in force, empty when unrestricted.
    #[must_use]
    pub fn categories(&self) -> Vec<Category> {
        let mask = self.categories.load(Ordering::Relaxed);
        Category::ALL
            .iter()
            .copied()
            .filter(|category| mask & category.bit() != 0)
            .collect()
    }
}

/// `categories` as a bitmask.
fn mask(categories: impl IntoIterator<Item = Category>) -> u16 {
    categories
        .into_iter()
        .fold(0, |mask, category| mask | category.bit())
}

impl FilterSink {
    /// Pass records at `min_severity` or above.
    #[must_use]
    pub fn new(inner: Box<dyn LogSink>, min_severity: Severity) -> Self {
        Self {
            inner,
            min_severity: Arc::new(AtomicU8::new(min_severity.index())),
            categories: Arc::new(AtomicU16::new(0)),
        }
    }

    /// A handle that changes this filter's threshold and categories while it
    /// runs.
    #[must_use]
    pub fn handle(&self) -> FilterHandle {
        FilterHandle {
            level: Arc::clone(&self.min_severity),
            categories: Arc::clone(&self.categories),
        }
    }

    /// Additionally restrict to these categories.
    ///
    /// An empty set is treated as "no category restriction" rather than "drop
    /// everything": a config that lists no categories means the operator did not
    /// want to filter by category, not that they wanted silence.
    #[must_use]
    pub fn with_categories(self, categories: impl IntoIterator<Item = Category>) -> Self {
        self.categories.store(mask(categories), Ordering::Relaxed);
        self
    }

    /// Whether a record clears this filter.
    #[must_use]
    pub fn passes(&self, event: &LogEvent) -> bool {
        if event.severity.index() < self.min_severity.load(Ordering::Relaxed) {
            return false;
        }
        let categories = self.categories.load(Ordering::Relaxed);
        categories == 0 || categories & event.category.bit() != 0
    }
}

impl LogSink for FilterSink {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn write(&mut self, event: &LogEvent) -> Result<(), SinkError> {
        if self.passes(event) {
            return self.inner.write(event);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), SinkError> {
        // Flush is never filtered: the inner sink may hold records that passed
        // earlier, and losing them on shutdown is the failure this guards.
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::sinks::{MemoryHandle, MemorySink};

    fn filtered(min: Severity) -> (FilterSink, MemoryHandle) {
        let inner = MemorySink::new(100);
        let handle = inner.handle();
        (FilterSink::new(Box::new(inner), min), handle)
    }

    fn event(severity: Severity, category: Category) -> LogEvent {
        LogEvent::new(severity, category, "x")
    }

    #[test]
    fn the_threshold_can_be_raised_while_the_sink_runs() {
        // The point of the handle: an incident is investigated at `debug`
        // without restarting the process holding the evidence.
        let (mut sink, handle) = filtered(Severity::Warning);
        let level = sink.handle();
        sink.write(&event(Severity::Info, Category::Server))
            .expect("write");
        assert!(handle.recent(10).is_empty(), "info is below warning");

        level.set_level(Severity::Debug);
        assert_eq!(level.level(), Severity::Debug);
        sink.write(&event(Severity::Info, Category::Server))
            .expect("write");
        assert_eq!(handle.recent(10).len(), 1, "the next record follows the new level");
    }

    #[test]
    fn records_below_the_threshold_are_dropped() {
        let (mut sink, handle) = filtered(Severity::Warning);
        sink.write(&event(Severity::Info, Category::Server))
            .expect("write");
        assert!(handle.recent(10).is_empty());
    }

    #[test]
    fn records_at_the_threshold_pass() {
        // Inclusive: "warnings and above" must include warnings.
        let (mut sink, handle) = filtered(Severity::Warning);
        sink.write(&event(Severity::Warning, Category::Server))
            .expect("write");
        assert_eq!(handle.recent(10).len(), 1);
    }

    #[test]
    fn records_above_the_threshold_pass() {
        let (mut sink, handle) = filtered(Severity::Warning);
        sink.write(&event(Severity::Critical, Category::Server))
            .expect("write");
        assert_eq!(handle.recent(10).len(), 1);
    }

    #[test]
    fn dropping_a_record_is_not_an_error() {
        // A filtered record is a decision, not a failure; reporting it as an
        // error would make a fanout look broken.
        let (mut sink, _) = filtered(Severity::Error);
        assert!(
            sink.write(&event(Severity::Debug, Category::Server))
                .is_ok()
        );
    }

    #[test]
    fn a_category_restriction_drops_other_categories() {
        let inner = MemorySink::new(100);
        let handle = inner.handle();
        let mut sink =
            FilterSink::new(Box::new(inner), Severity::Debug).with_categories([Category::Security]);

        sink.write(&event(Severity::Error, Category::Message))
            .expect("write");
        assert!(handle.recent(10).is_empty());

        sink.write(&event(Severity::Debug, Category::Security))
            .expect("write");
        assert_eq!(handle.recent(10).len(), 1);
    }

    #[test]
    fn an_empty_category_list_means_no_restriction_not_silence() {
        let inner = MemorySink::new(100);
        let handle = inner.handle();
        let mut sink = FilterSink::new(Box::new(inner), Severity::Debug).with_categories([]);

        sink.write(&event(Severity::Info, Category::Message))
            .expect("write");
        assert_eq!(handle.recent(10).len(), 1);
    }

    #[test]
    fn severity_and_category_are_both_required() {
        let inner = MemorySink::new(100);
        let handle = inner.handle();
        let mut sink = FilterSink::new(Box::new(inner), Severity::Warning)
            .with_categories([Category::Security]);

        // Right category, too quiet.
        sink.write(&event(Severity::Info, Category::Security))
            .expect("write");
        // Loud enough, wrong category.
        sink.write(&event(Severity::Error, Category::Message))
            .expect("write");
        assert!(handle.recent(10).is_empty());
    }

    #[test]
    fn flush_is_never_filtered() {
        // The inner sink may hold records that passed earlier.
        let inner = MemorySink::new(100);
        let handle = inner.handle();
        let mut sink = FilterSink::new(Box::new(inner), Severity::Critical);
        sink.flush().expect("flush");
        assert_eq!(handle.flushes(), 1);
    }

    #[test]
    fn filters_nest() {
        // Decorator: the strictest threshold wins, whichever order they wrap in.
        let inner = MemorySink::new(100);
        let handle = inner.handle();
        let mut sink = FilterSink::new(
            Box::new(FilterSink::new(Box::new(inner), Severity::Error)),
            Severity::Info,
        );

        sink.write(&event(Severity::Warning, Category::Server))
            .expect("write");
        assert!(handle.recent(10).is_empty());

        sink.write(&event(Severity::Error, Category::Server))
            .expect("write");
        assert_eq!(handle.recent(10).len(), 1);
    }
}
