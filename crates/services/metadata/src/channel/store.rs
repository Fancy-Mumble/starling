//! The channel storage boundary (Repository).

use crate::channel::Channel;
use crate::ids::ChannelId;

/// Read/write access to the channel tree.
///
/// Handlers take `&dyn ChannelStore`, so a SQL-backed implementation can go
/// behind it without touching a handler (`docs/DESIGN.md` §1).
///
/// # Contract
///
/// Implementations must maintain these invariants for **all** callers, because
/// no caller is in a position to check them:
///
/// 1. The root ([`ROOT_CHANNEL`](crate::ids::ROOT_CHANNEL)) always exists and
///    can never be removed.
/// 2. Every `Channel::parent` resolves to a channel in the store.
/// 3. `Channel::children` is the exact inverse of `Channel::parent`.
/// 4. Channel ids are never reused, even after removal, a reused id would
///    alias a dead channel in client state and in the database.
/// 5. [`Self::breadth_first`] yields every parent before any of its children.
pub trait ChannelStore: std::fmt::Debug {
    /// Look up a channel.
    fn get(&self, id: ChannelId) -> Option<&Channel>;

    /// Number of channels, including the root. Never zero.
    fn len(&self) -> usize;

    /// Channels in breadth-first order from the root.
    ///
    /// The handshake depends on this ordering: the client resolves
    /// `ChannelState.parent` as messages arrive, so a child that arrived first
    /// would be re-parented to the root.
    fn breadth_first(&self) -> Vec<&Channel>;

    /// Create a channel under `parent`, returning its new id.
    ///
    /// Returns `None` if `parent` does not exist, an orphan would violate
    /// invariant 2.
    fn insert(&mut self, parent: ChannelId, name: &str) -> Option<ChannelId>;

    /// Remove a channel and its entire subtree, returning the removed ids.
    ///
    /// Removing the root returns an empty vector (invariant 1). Callers must
    /// relocate occupants first; the store does not know about users.
    fn remove(&mut self, id: ChannelId) -> Vec<ChannelId>;

    /// Whether the store contains `id`.
    ///
    /// Provided in terms of [`Self::get`]; implementations may override it if
    /// they can answer more cheaply than materialising the channel.
    fn contains(&self, id: ChannelId) -> bool {
        self.get(id).is_some()
    }

    /// Always `false`, the root channel cannot be removed (invariant 1).
    ///
    /// Present because clippy requires `is_empty` alongside `len`, and stating
    /// the invariant is more useful than suppressing the lint.
    fn is_empty(&self) -> bool {
        false
    }
}
