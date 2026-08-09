//! Channels: the entity, the storage boundary, and the in-memory tree.

mod entity;
mod store;
mod tree;

pub use entity::{Channel, is_full, is_full_for};
pub use store::ChannelStore;
pub use tree::ChannelTree;
