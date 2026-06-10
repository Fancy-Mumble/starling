//! Permissions: the wire-visible bit set, and the policy that evaluates it.

mod bits;
mod policy;

pub use bits::Perm;
pub use policy::{AllowAll, Permissions};
