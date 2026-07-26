//! Session-id allocation.
//!
//! A session id names a *connection*, so handing one out is a stateful job with
//! a reuse policy — unlike the [`SessionId`](crate::ids::SessionId) newtype
//! itself, which is a plain value. Splitting the two keeps [`crate::ids`] free
//! of behaviour.

mod pool;
mod source;

pub use pool::SessionAllocator;
pub use source::SessionSource;
