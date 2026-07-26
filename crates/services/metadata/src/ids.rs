//! The channel id.
//!
//! Owned here because metadata is the channel-tree authority
//! (`docs/ARCHITECTURE.md` §4); every other service that needs to name a
//! channel — permissions, session-view, voice — depends on this crate for the
//! type rather than inventing its own.

/// The channel every server has and no one can delete.
pub const ROOT_CHANNEL: ChannelId = ChannelId(0);

/// A channel's id. [`ROOT_CHANNEL`] is always `0`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ChannelId(pub u32);

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
