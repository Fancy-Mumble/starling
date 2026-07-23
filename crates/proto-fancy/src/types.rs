//! The message-type allocation, and the service each number belongs to.
//!
//! | Range | Use |
//! |---|---|
//! | 0-99 | upstream Mumble, flat, **frozen** (0-26 in use) |
//! | 100-999 | **burned**, the interleaved Fancy layout shipped in released clients |
//! | 1000+ | one outer type per service, nested envelope |
//!
//! 100-999 is burned rather than reclaimed because today's numbering is
//! interleaved rather than blocked: `WebRtcSignal` is 120, sitting between
//! pchat's 100-119 and 121. Reusing those numbers risks a deployed client's
//! message landing on a service that would read it as something else, silent
//! misinterpretation, the worst failure class available.
//!
//! See `docs/PROTOCOL-COMPATIBILITY.md` §2-3.

/// Highest type upstream Mumble may ever use.
pub const UPSTREAM_MAX: u16 = 99;

/// First type in the burned range.
pub const BURNED_MIN: u16 = 100;

/// Last type in the burned range.
pub const BURNED_MAX: u16 = 999;

/// First outer type available to a service.
pub const SERVICE_BASE: u16 = 1000;

/// A compressed batch of frames, unwrapped before anything is routed.
///
/// **Not a service, and deliberately far from where they are allocated.** This
/// is a property of the connection rather than a destination on it: the gateway
/// writes it and a client unwraps it, and what comes out is ordinary frames
/// that route as they always did. Numbering it 1018 (the next service slot)
/// would have made it look like the eighteenth service to every reader of this
/// table and to every capture.
///
/// The payload is one or more whole frames, `type ‖ len ‖ payload` each, zstd
/// compressed. Only ever sent to a peer that announced `zstd` in its `Hello`,
/// so a stock Mumble client and an older Fancy one never see it, and a peer
/// that did announce it is by definition able to unwrap it.
pub const COMPRESSED_BATCH: u16 = 1900;

/// A service that owns an outer message type.
///
/// This enum exists for logs, metrics and the operator API. The gateway does
/// **not** consult it to route: routing comes from the TOML, so a service that
/// this build has never heard of still works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ServiceKind {
    /// 1000, negotiation, authentication, resume.
    SessionLifecycle,
    /// 1001, ACL evaluation.
    Permissions,
    /// 1002, the channel tree.
    Metadata,
    /// 1003, accounts and account settings.
    Userdata,
    /// 1004, audio routing.
    Voice,
    /// 1005, chat and its history.
    Text,
    /// 1006, persistent, end-to-end encrypted chat.
    Pchat,
    /// 1007, bans and kicks.
    Moderation,
    /// 1008, screen-share signalling.
    Screenshare,
    /// 1009, bulk transfer.
    Files,
    /// 1010, the plugin host.
    Plugins,
    /// 1011, push notifications.
    Push,
    /// 1012, the operator record.
    Audit,
    /// 1013, runtime-mutable settings.
    ServerConfig,
    /// 1014, onboarding flows.
    Onboarding,
    /// 1015, reactions, receipts, typing, polls, watch, drawing.
    Social,
    /// 1016, link previews.
    LinkPreview,
    /// 1017, plugin-defined menu entries.
    ContextActions,
}

impl ServiceKind {
    /// The outer type this service owns.
    #[must_use]
    pub const fn outer_type(self) -> u16 {
        SERVICE_BASE + self.offset()
    }

    const fn offset(self) -> u16 {
        match self {
            Self::SessionLifecycle => 0,
            Self::Permissions => 1,
            Self::Metadata => 2,
            Self::Userdata => 3,
            Self::Voice => 4,
            Self::Text => 5,
            Self::Pchat => 6,
            Self::Moderation => 7,
            Self::Screenshare => 8,
            Self::Files => 9,
            Self::Plugins => 10,
            Self::Push => 11,
            Self::Audit => 12,
            Self::ServerConfig => 13,
            Self::Onboarding => 14,
            Self::Social => 15,
            Self::LinkPreview => 16,
            Self::ContextActions => 17,
        }
    }

    /// The configuration key and log name for this service.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SessionLifecycle => "session-lifecycle",
            Self::Permissions => "permissions",
            Self::Metadata => "metadata",
            Self::Userdata => "userdata",
            Self::Voice => "voice",
            Self::Text => "text",
            Self::Pchat => "pchat",
            Self::Moderation => "moderation",
            Self::Screenshare => "screenshare",
            Self::Files => "files",
            Self::Plugins => "plugins",
            Self::Push => "push",
            Self::Audit => "audit",
            Self::ServerConfig => "server-config",
            Self::Onboarding => "onboarding",
            Self::Social => "social",
            Self::LinkPreview => "link-preview",
            Self::ContextActions => "context-actions",
        }
    }

    /// Every service with an outer type, in allocation order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::SessionLifecycle,
            Self::Permissions,
            Self::Metadata,
            Self::Userdata,
            Self::Voice,
            Self::Text,
            Self::Pchat,
            Self::Moderation,
            Self::Screenshare,
            Self::Files,
            Self::Plugins,
            Self::Push,
            Self::Audit,
            Self::ServerConfig,
            Self::Onboarding,
            Self::Social,
            Self::LinkPreview,
            Self::ContextActions,
        ]
    }

    /// Which service owns `type_id`, if any known one does.
    #[must_use]
    pub fn from_outer_type(type_id: u16) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|kind| kind.outer_type() == type_id)
    }

    /// Which service owns `name`, if any known one does.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::all().iter().copied().find(|kind| kind.name() == name)
    }
}

/// What a wire type number means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterType {
    /// 0-99: an upstream Mumble message. Flat, frozen, routed by number.
    Upstream(u16),
    /// 100-999: shipped in released clients under the interleaved layout.
    ///
    /// A message arriving with one of these is from a stale client. It is never
    /// routed to a new service, because a new service would read it as
    /// something else entirely.
    Burned(u16),
    /// 1000+: a service envelope. The payload's first field is the inner tag.
    Service(u16),
}

impl OuterType {
    /// Classify a wire type number.
    #[must_use]
    pub const fn classify(type_id: u16) -> Self {
        if type_id <= UPSTREAM_MAX {
            Self::Upstream(type_id)
        } else if type_id <= BURNED_MAX {
            Self::Burned(type_id)
        } else {
            Self::Service(type_id)
        }
    }

    /// Whether this type may be routed to a service at all.
    #[must_use]
    pub const fn routable(self) -> bool {
        !matches!(self, Self::Burned(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_service_has_a_distinct_outer_type_and_name() {
        // A collision here would send two services' messages to one of them,
        // which the gateway cannot detect because it never parses a payload.
        let mut types: Vec<u16> = ServiceKind::all().iter().map(|k| k.outer_type()).collect();
        let count = types.len();
        types.sort_unstable();
        types.dedup();
        assert_eq!(types.len(), count, "duplicate outer type");

        let mut names: Vec<&str> = ServiceKind::all().iter().map(|k| k.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate service name");
    }

    #[test]
    fn a_burned_type_is_never_routable() {
        // The whole point of burning 100-999: a stale client's message must not
        // land on a service that would misread it.
        for type_id in [100_u16, 120, 128, 171, 201, 999] {
            assert!(
                !OuterType::classify(type_id).routable(),
                "type {type_id} must not be routable"
            );
        }
    }

    #[test]
    fn upstream_keeps_the_whole_flat_range_below_one_hundred() {
        assert!(matches!(OuterType::classify(0), OuterType::Upstream(0)));
        assert!(matches!(OuterType::classify(26), OuterType::Upstream(26)));
        assert!(matches!(OuterType::classify(99), OuterType::Upstream(99)));
    }

    #[test]
    fn a_service_type_round_trips_through_its_kind() {
        for kind in ServiceKind::all() {
            assert_eq!(ServiceKind::from_outer_type(kind.outer_type()), Some(*kind));
            assert_eq!(ServiceKind::from_name(kind.name()), Some(*kind));
            assert!(matches!(
                OuterType::classify(kind.outer_type()),
                OuterType::Service(_)
            ));
        }
    }

    #[test]
    fn the_allocation_matches_the_documented_table() {
        // These numbers are shipped in clients; a renumbering is a break.
        assert_eq!(ServiceKind::SessionLifecycle.outer_type(), 1000);
        assert_eq!(ServiceKind::Voice.outer_type(), 1004);
        assert_eq!(ServiceKind::Pchat.outer_type(), 1006);
        assert_eq!(ServiceKind::ServerConfig.outer_type(), 1013);
        assert_eq!(ServiceKind::ContextActions.outer_type(), 1017);
    }
}
