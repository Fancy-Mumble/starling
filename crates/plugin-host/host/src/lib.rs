//! Loads Mumble plugin binaries and dispatches lifecycle events to them.
//!
//! Discovers plugin binaries in the configured directories, loads each through
//! [`abi_stable`] (or, with the `wasm-plugins` feature, wasmtime), and hands
//! them synchronous lifecycle events. Plugins own their own `tokio` runtime;
//! this crate has none, and neither does it know what server it is inside.
//!
//! Everything server-shaped -- what a channel is, who is connected, where
//! configuration lives -- arrives through [`HostBridge`], which the embedding
//! server implements. That is the whole seam: give it a bridge and a directory
//! and it gives you loaded plugins.
//!
//! ```ignore
//! let host = Host::new(Arc::new(my_bridge));
//! host.on_client_connected(info);
//! ```
//!
//! Lifted from the C++ server's `3rdparty/mumble-plugin-host`, whose C ABI is
//! what [`HostBridge`] replaces. The plugin-facing contract in
//! [`mumble_plugin_api`] is unchanged and must stay that way: a plugin binary
//! built against either tree has to load in either server.

mod bridge;
mod context;
mod host;
mod info;
mod install;
mod loader;
#[cfg(feature = "wasm-plugins")]
mod wasm;

pub use crate::bridge::{HostBridge, NewChannel, OutboundMessage};
pub use crate::context::ScopedContext;
pub use crate::host::{Host, InstallRequest, PluginAdminInfo, PluginMessageInArgs, RegistryEntry};
pub use crate::info::{ENVELOPE_VERSION, FLAG_ZSTD};
pub use crate::install::{InstallError, MAX_ARTIFACT_BYTES, digest};
pub use crate::loader::{LoadError, cdylib_suffix, wasm_suffix};

/// The contract plugins are built against, re-exported so an embedder needs one
/// dependency rather than two that must be kept in lockstep.
pub use mumble_plugin_api as api;
