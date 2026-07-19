//! The session-allocation boundary.

use crate::ids::SessionId;

/// Hands out and reclaims session ids.
///
/// # Contract
///
/// 1. [`Self::allocate`] returns `None` when exhausted, implementations must
///    **never** fabricate an id. Reusing a live session's id would let one
///    client's traffic be attributed to another.
/// 2. An id returned by [`Self::release`] may be handed out again, but not
///    before every other free id has been (see
///    [`SessionAllocator`](super::SessionAllocator) for why).
/// 3. `0` is never allocated; it is the wire's "no session" value.
pub trait SessionSource: std::fmt::Debug {
    /// Take the next session id, or `None` when the pool is exhausted.
    fn allocate(&mut self) -> Option<SessionId>;

    /// Return a session id to the pool after the connection is torn down.
    fn release(&mut self, id: SessionId);

    /// How many sessions can still be handed out.
    fn available(&self) -> usize;
}
