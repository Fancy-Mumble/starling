//! Structured detail attached to a record.

use std::borrow::Cow;

/// A typed value attached to a record.
///
/// Typed rather than pre-formatted so a database sink can map it to a column and
/// a console sink can render it, without either having to guess.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// Text.
    Text(String),
    /// Signed integer.
    Int(i64),
    /// Unsigned integer — session and channel ids.
    Uint(u64),
    /// Flag.
    Bool(bool),
}

impl std::fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(v) => write!(f, "{v}"),
            Self::Int(v) => write!(f, "{v}"),
            Self::Uint(v) => write!(f, "{v}"),
            Self::Bool(v) => write!(f, "{v}"),
        }
    }
}

/// A key/value pair attached to a record.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// Field name. `Cow` so a literal key costs no allocation.
    pub key: Cow<'static, str>,
    /// Field value.
    pub value: FieldValue,
}

/// Conversion into a [`FieldValue`], so `with("session", 7u32)` just works.
pub trait IntoFieldValue {
    /// Convert.
    fn into_field_value(self) -> FieldValue;
}

impl IntoFieldValue for FieldValue {
    fn into_field_value(self) -> FieldValue {
        self
    }
}
impl IntoFieldValue for String {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Text(self)
    }
}
impl IntoFieldValue for &str {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Text(self.to_owned())
    }
}
impl IntoFieldValue for bool {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Bool(self)
    }
}
impl IntoFieldValue for u16 {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Uint(u64::from(self))
    }
}
impl IntoFieldValue for u32 {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Uint(u64::from(self))
    }
}
impl IntoFieldValue for u64 {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Uint(self)
    }
}
impl IntoFieldValue for i64 {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Int(self)
    }
}
impl IntoFieldValue for usize {
    fn into_field_value(self) -> FieldValue {
        FieldValue::Uint(self as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_keep_their_signedness() {
        // A database sink maps these to different column types.
        assert_eq!(7u32.into_field_value(), FieldValue::Uint(7));
        assert_eq!((-7i64).into_field_value(), FieldValue::Int(-7));
    }

    #[test]
    fn text_converts_from_both_owned_and_borrowed_forms() {
        assert_eq!(
            "alice".into_field_value(),
            FieldValue::Text("alice".to_owned())
        );
        assert_eq!(
            String::from("alice").into_field_value(),
            FieldValue::Text("alice".to_owned())
        );
    }

    #[test]
    fn a_field_value_converts_to_itself() {
        // So `with("k", some_field_value)` works without a special case.
        let value = FieldValue::Bool(true);
        assert_eq!(value.clone().into_field_value(), value);
    }

    #[test]
    fn every_variant_renders_without_quoting_or_decoration() {
        assert_eq!(FieldValue::Text("alice".into()).to_string(), "alice");
        assert_eq!(FieldValue::Uint(7).to_string(), "7");
        assert_eq!(FieldValue::Int(-7).to_string(), "-7");
        assert_eq!(FieldValue::Bool(false).to_string(), "false");
    }

    #[test]
    fn a_literal_key_borrows_rather_than_allocating() {
        let field = Field {
            key: Cow::Borrowed("session"),
            value: 1u32.into_field_value(),
        };
        assert!(matches!(field.key, Cow::Borrowed(_)));
    }
}
