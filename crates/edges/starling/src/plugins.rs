//! Every plugin linked into this build.
//!
//! **This is the only file to touch when adding a plugin.** Two steps:
//!
//! 1. add the crate to `[dependencies]` in this crate's `Cargo.toml`
//!    (a crate nobody depends on is not built);
//! 2. add its name below.
//!
//! Nothing else changes. The binary never imports a plugin's types, names its
//! handlers, or constructs it — [`starling_api::registered`] returns whatever
//! announced itself with `register_feature!`, and the composition root asks.
//!
//! # Why a list is needed at all
//!
//! rustc does not link an rlib it never resolves a symbol from, so a plugin with
//! no reference here is dropped from a clean build **without an error**. See
//! [`starling_api::register_plugin`] for the measurements behind that, including
//! why `-C link-dead-code` does not fix it.
//!
//! Runtime loading (Phase 3's WASM host) is what removes this file: plugins then
//! come from a directory, not from the linker.

starling_api::register_plugin! {
    starling_feature_permission_query,
    starling_migrate,
    starling_feature_query_users,
}
