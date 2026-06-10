//! `starling-model` — the server's world model.
//!
//! Channel tree, connected users, session allocation and the permission policy.
//! This crate **performs no I/O**: it is data structures, traits, and pure
//! functions. Its only dependency is `starling-proto`, for the wire `Version`
//! type, and that crate is I/O-free too.
//!
//! # Boundaries are traits
//!
//! Each concept exposes a role-shaped trait and one in-memory implementation:
//!
//! | Trait | In-memory implementation | Replaced in |
//! |---|---|---|
//! | [`ChannelStore`] | [`ChannelTree`] | Phase 2 (SQL-backed) |
//! | [`UserRegistry`] | [`Users`] | Phase 2 (presence across nodes) |
//! | [`Permissions`] | [`AllowAll`] | Phase 2 (real ACL evaluation) |
//! | [`SessionSource`] | [`SessionAllocator`] | — |
//!
//! Callers take `&dyn ChannelStore`, never `&ChannelTree`. See `DESIGN.md` §2.
//!
//! # Shape
//!
//! Four concepts, each in its own module, all over the shared id newtypes in
//! [`ids`]. They do not reference each other — the only edges are into `ids`.

pub mod channel;
pub mod ids;
pub mod perm;
pub mod session;
pub mod user;

pub use channel::{Channel, ChannelStore, ChannelTree};
pub use ids::{ChannelId, SessionId, UserId, ROOT_CHANNEL};
pub use perm::{AllowAll, Perm, Permissions};
pub use session::{SessionAllocator, SessionSource};
pub use user::{User, UserRegistry, Users};
