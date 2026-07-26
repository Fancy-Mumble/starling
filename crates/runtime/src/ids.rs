//! `UUIDv7` for anything with history, and the clock it reads.
//!
//! pchat messages, pins, reactions, offline queues, text history and audit
//! entries are all keyed this way. The reasons are the ones Discord's Snowflake
//! buys them, minus the coordination (`docs/ARCHITECTURE.md` §5):
//!
//! * **time-sortable**, so "newest 50 in this channel" is a backwards range
//!   scan off the end of an index rather than a sort
//! * **coordination-free**, so no central sequence is in the write path
//! * **index-local**, unlike `UUIDv4`, whose randomness scatters inserts across
//!   the whole B-tree and turns an append into a random write
//!
//! Sixteen bytes in storage against thirty-six for the string form, and the
//! wire type does not change (`docs/STORAGE.md` L3).

use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

/// A time-ordered identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid7(Uuid);

impl Uuid7 {
    /// A new identifier stamped with the current time.
    #[must_use]
    pub fn now() -> Self {
        Self(Uuid::now_v7())
    }

    /// The 16-byte storage form.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// The 16-byte storage form, owned.
    #[must_use]
    pub fn to_vec(self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    /// Read a stored identifier back.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Uuid::from_slice(bytes).ok().map(Self)
    }

    /// Read the wire form, which is a string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Uuid::parse_str(text).ok().map(Self)
    }
}

impl std::fmt::Display for Uuid7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Milliseconds since the Unix epoch.
///
/// A clock before 1970 is not a case worth branching on, so it reads as zero
/// rather than as an error nobody handles.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_sort_in_the_order_they_were_created() {
        // The whole reason for v7: sorting by id must be sorting by time, or
        // "newest 50" stops being a range scan.
        let mut ids: Vec<Uuid7> = (0..8).map(|_| Uuid7::now()).collect();
        let created = ids.clone();
        ids.sort();
        assert_eq!(ids, created, "v7 ids must already be in creation order");
    }

    #[test]
    fn an_identifier_round_trips_through_both_of_its_forms() {
        let id = Uuid7::now();
        assert_eq!(Uuid7::from_slice(id.as_bytes()), Some(id));
        assert_eq!(Uuid7::parse(&id.to_string()), Some(id));
    }

    #[test]
    fn a_malformed_cursor_from_a_client_is_none_rather_than_a_panic() {
        // Cursors arrive from an unauthenticated peer.
        assert!(Uuid7::parse("not-a-uuid").is_none());
        assert!(Uuid7::from_slice(&[0_u8; 3]).is_none());
    }
}
