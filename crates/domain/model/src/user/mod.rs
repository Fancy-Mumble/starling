//! Users: the entity, the registry boundary, and the in-memory implementation.

mod entity;
mod memory;
mod registry;

pub use entity::User;
pub use memory::Users;
pub use registry::UserRegistry;
