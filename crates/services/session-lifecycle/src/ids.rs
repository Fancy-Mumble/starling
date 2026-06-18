//! The session id.
//!
//! A value, not a collaborator: no state, no behaviour beyond comparison and
//! display. Allocating one is a different job with different state, and lives
//! in `starling-session-lifecycle`.

/// A connected client's session id, unique for the lifetime of the connection.
///
/// Session ids are **recycled** after a user disconnects (see
/// `SessionAllocator` in `starling-session-lifecycle`), so they identify a
/// *connection*, never a person. Use `UserId` (`starling-userdata`) for
/// anything that must outlive a connection.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct SessionId(pub u32);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
