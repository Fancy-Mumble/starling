//! Session establishment.
//!
//! The order of messages below is a **protocol contract**, transcribed from
//! `vendor/server/src/murmur/Messages.cpp` with line references. The client
//! resolves references as messages arrive, so reordering these breaks it in
//! ways that look like client bugs:
//!
//! | # | Message | Source | Why here |
//! |---|---|---|---|
//! | 1 | `Version` (server→client) | `Server.cpp:1668` | Sent on TLS-established, before reading anything |
//! | 2 | `CodecVersion` | `Messages.cpp:541` | Negotiated from the client's `Authenticate` |
//! | 3 | `ChannelState` × N | `Messages.cpp:556` | BFS, so parents always precede children |
//! | 4 | own `UserState` | `Messages.cpp:622` | Broadcast: tells everyone the newcomer arrived |
//! | 5 | other `UserState`s | `Messages.cpp:671` | Only to the newcomer |
//! | 6 | `ServerSync` | `Messages.cpp:746` | Ends establishment; carries the client's own session id |
//! | 7 | `ServerConfig` | `Messages.cpp:808` | Limits, after sync |
//! | 8 | `SuggestConfig` | `Messages.cpp:822` | Advisory |
//!
//! Two messages murmur sends here are **deliberately omitted in Phase 0**:
//!
//! * `CryptSetup` — sending UDP keys makes the client open a UDP transport and
//!   start sending audio to a port nothing is listening on. Withholding it makes
//!   the client correctly conclude there is no UDP path
//!   (`mumble-protocol/src/client.rs:914`) and stay on TCP. Phase 1 adds it
//!   together with the UDP socket.
//! * `Version.fancy_version` — see [`crate::FANCY_VERSION`].

mod authenticate;
mod keying;
mod sync;
mod version;

pub use authenticate::AuthenticateHandler;
pub use version::{server_version, VersionHandler};
