//! Severity and category gating around any sink (Decorator).

use std::collections::HashSet;

use crate::event::{Category, LogEvent, Severity};
use crate::sink::{LogSink, SinkError};

/// Passes records to an inner sink only if they clear a threshold.
///
/// Decorator: it *is* a [`LogSink`] wrapping a [`LogSink`], so it can gate
/// anything — including a whole [`FanoutSink`](super::FanoutSink) — and the
/// wrapped sink never learns it is being filtered.
///
/// This is what lets one configuration say "everything to the file, but only
/// warnings to the console" without either sink knowing about the other.
#[derive(Debug)]
pub struct FilterSink {
    inner: Box<dyn LogSink>,
    min_severity: Severity,
    categories: Option<HashSet<Category>>,
}

impl FilterSink {
    /// Pass records at `min_severity` or above.
    #[must_use]
    pub fn new(inner: Box<dyn LogSink>, min_severity: Severity) -> Self {
        Self {
            inner,
            min_severity,
            categories: None,
        }
    }

    /// Additionally restrict to these categories.
    ///
    /// An empty set is treated as "no category restriction" rather than "drop
    /// everything": a config that lists no categories means the operator did not
    /// want to filter by category, not that they wanted silence.
    #[must_use]
    pub fn with_categories(mut self, categories: impl IntoIterator<Item = Category>) -> Self {
        let set: HashSet<_> = categories.into_iter().collect();
        self.categories = (!set.is_empty()).then_some(set);
        self
    }

    /// Whether a record clears this filter.
    #[must_use]
    pub fn passes(&self, event: &LogEvent) -> bool {
        if event.severity < self.min_severity {
            return false;
        }
        self.categories
            .as_ref()
            .is_none_or(|set| set.contains(&event.category))
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
    use crate::sinks::{MemoryHandle, MemorySink};

    fn filtered(min: Severity) -> (FilterSink, MemoryHandle) {
        let inner = MemorySink::new(100);
        let handle = inner.handle();
        (FilterSink::new(Box::new(inner), min), handle)
    }

    fn event(severity: Severity, category: Category) -> LogEvent {
        LogEvent::new(severity, category, "x")
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
        assert!(sink
            .write(&event(Severity::Debug, Category::Server))
            .is_ok());
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
