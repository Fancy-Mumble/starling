//! What part of the server a record is about.

/// A record's subject area.
///
/// Coarse on purpose: an operator filters by this, so it has to be a set they
/// can hold in their head. Detail belongs in [`Field`](super::Field)s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// Startup, shutdown, configuration.
    Server,
    /// Connections, authentication, disconnects.
    Session,
    /// Channel lifecycle and membership.
    Channel,
    /// Chat and voice routing.
    Message,
    /// Refused actions.
    Permission,
    /// Certificates, bans, negotiated suites.
    Security,
    /// Plugin host activity.
    Plugin,
    /// Administrative changes.
    Admin,
}

impl Category {
    /// Every category, for config validation and exhaustiveness tests.
    pub const ALL: &'static [Self] = &[
        Self::Server,
        Self::Session,
        Self::Channel,
        Self::Message,
        Self::Permission,
        Self::Security,
        Self::Plugin,
        Self::Admin,
    ];

    /// Lower-case name, as it appears in output and config.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Session => "session",
            Self::Channel => "channel",
            Self::Message => "message",
            Self::Permission => "permission",
            Self::Security => "security",
            Self::Plugin => "plugin",
            Self::Admin => "admin",
        }
    }

    /// Parse a category name, case-insensitively.
    ///
    /// Kept as an inherent method because [`FromStr`](std::str::FromStr) is the
    /// public entry point and delegates here; callers that already have an
    /// `Option` shape find this convenient.
    #[must_use]
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|c| c.label().eq_ignore_ascii_case(name))
    }
}

/// A name that does not match any [`Category`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCategory(pub String);

impl std::fmt::Display for UnknownCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown category {:?}", self.0)
    }
}

impl std::error::Error for UnknownCategory {}

impl std::str::FromStr for Category {
    type Err = UnknownCategory;

    /// Case-insensitive, so a config file may say `Info` or `info`.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::from_name(name).ok_or_else(|| UnknownCategory(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_category_round_trips_through_its_label() {
        for category in Category::ALL {
            assert_eq!(
                Category::from_name(category.label()),
                Some(*category),
                "{category:?} did not round-trip"
            );
        }
    }

    #[test]
    fn parsing_is_case_insensitive() {
        assert_eq!(Category::from_name("SECURITY"), Some(Category::Security));
        assert_eq!(Category::from_name("Session"), Some(Category::Session));
    }

    #[test]
    fn an_unknown_name_reports_none_rather_than_guessing() {
        assert_eq!(Category::from_name("biscuits"), None);
        assert_eq!(Category::from_name(""), None);
    }

    #[test]
    fn labels_are_unique() {
        let mut labels: Vec<_> = Category::ALL.iter().map(|c| c.label()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count);
    }

    #[test]
    fn labels_are_lower_case_so_config_reads_naturally() {
        for category in Category::ALL {
            let label = category.label();
            assert_eq!(label, label.to_ascii_lowercase(), "{label}");
        }
    }
}
