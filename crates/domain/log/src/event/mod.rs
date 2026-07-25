//! The log record and its parts.

mod category;
mod field;
mod severity;

pub use category::{Category, UnknownCategory};
pub use field::{Field, FieldValue, IntoFieldValue};
pub use severity::{Severity, UnknownSeverity};

use std::borrow::Cow;
use std::time::SystemTime;

/// One log record.
#[derive(Debug, Clone, PartialEq)]
pub struct LogEvent {
    /// When it happened.
    pub at: SystemTime,
    /// How much attention it deserves.
    pub severity: Severity,
    /// What part of the server it is about.
    pub category: Category,
    /// Human-readable summary. Keep it constant per call site so records group.
    pub message: String,
    /// Structured detail.
    pub fields: Vec<Field>,
}

impl LogEvent {
    /// Build a record, timestamped now.
    #[must_use]
    pub fn new(severity: Severity, category: Category, message: impl Into<String>) -> Self {
        Self {
            at: SystemTime::now(),
            severity,
            category,
            message: message.into(),
            fields: Vec::new(),
        }
    }

    /// A [`Severity::Debug`] record.
    #[must_use]
    pub fn debug(category: Category, message: impl Into<String>) -> Self {
        Self::new(Severity::Debug, category, message)
    }

    /// An [`Severity::Info`] record.
    #[must_use]
    pub fn info(category: Category, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, category, message)
    }

    /// A [`Severity::Notice`] record.
    #[must_use]
    pub fn notice(category: Category, message: impl Into<String>) -> Self {
        Self::new(Severity::Notice, category, message)
    }

    /// A [`Severity::Warning`] record.
    #[must_use]
    pub fn warning(category: Category, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, category, message)
    }

    /// An [`Severity::Error`] record.
    #[must_use]
    pub fn error(category: Category, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, category, message)
    }

    /// Attach a field (Builder).
    #[must_use]
    pub fn with(mut self, key: impl Into<Cow<'static, str>>, value: impl IntoFieldValue) -> Self {
        self.fields.push(Field {
            key: key.into(),
            value: value.into_field_value(),
        });
        self
    }

    /// Look up a field by key.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&FieldValue> {
        self.fields.iter().find(|f| f.key == key).map(|f| &f.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_typed_not_pre_formatted() {
        // So a database sink can map them to columns.
        let event = LogEvent::info(Category::Session, "established")
            .with("session", 7u32)
            .with("username", "alice")
            .with("registered", false);

        assert_eq!(event.field("session"), Some(&FieldValue::Uint(7)));
        assert_eq!(
            event.field("username"),
            Some(&FieldValue::Text("alice".into()))
        );
        assert_eq!(event.field("registered"), Some(&FieldValue::Bool(false)));
    }

    #[test]
    fn fields_keep_insertion_order() {
        let event = LogEvent::info(Category::Server, "x")
            .with("a", 1u32)
            .with("b", 2u32)
            .with("c", 3u32);
        let keys: Vec<_> = event.fields.iter().map(|f| f.key.as_ref()).collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn a_missing_field_reports_none_rather_than_a_default() {
        assert_eq!(LogEvent::info(Category::Server, "x").field("nope"), None);
    }

    #[test]
    fn severity_helpers_set_the_severity_they_name() {
        assert_eq!(
            LogEvent::debug(Category::Server, "x").severity,
            Severity::Debug
        );
        assert_eq!(
            LogEvent::notice(Category::Server, "x").severity,
            Severity::Notice
        );
        assert_eq!(
            LogEvent::warning(Category::Server, "x").severity,
            Severity::Warning
        );
        assert_eq!(
            LogEvent::error(Category::Server, "x").severity,
            Severity::Error
        );
    }

    #[test]
    fn a_new_record_carries_no_fields() {
        assert!(LogEvent::info(Category::Server, "x").fields.is_empty());
    }
}
