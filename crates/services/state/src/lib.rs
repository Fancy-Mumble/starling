//! `starling-server` — the server itself.
//!
//! # Architecture
//!
//! ```text
//!   TCP conn 1 ──read task──┐                    ┌── write task ── socket
//!   TCP conn N ──read task──┤                    └── write task ── socket
//!                           ▼                          ▲
//!                    ┌──────────────┐                  │ Bytes (encoded once,
//!                    │  ServerCore  │──── Outbound ────┘  cloned per recipient)
//!                    │   (1 task)   │
//!                    │  ServerState │──── Dispatcher ──► Handler per message
//!                    └──────────────┘
//! ```
//!
//! [`ServerCore`] **serialises every mutation** and is the only thing that
//! applies one. It owns no domain data itself: it holds [`ServerState`], which
//! delegates to `dyn ChannelStore`, `dyn UserRegistry`, `dyn Permissions` and
//! `dyn SecurityPolicy` — each owning its own slice. What the core guarantees is
//! *ordering*, not omniscience.
//!
//! Connections talk to it exclusively by sending [`Command`]s down one channel,
//! and hear back only through their own outbound queue. There are no locks
//! around server state, so there is no lock ordering to get wrong and no
//! re-entrancy hazard — the failure mode that makes murmur's
//! `qrwlUsers`/`qrwlVoiceThread` pair delicate.
//!
//! # Reading this crate at one level
//!
//! Every arrow above is a trait, so the dataflow can be followed without opening
//! an implementation:
//!
//! | Step | Boundary | Where the detail lives |
//! |---|---|---|
//! | a frame arrives | [`Command`] | `starling-net` |
//! | routed to a handler | [`Handler`] | [`dispatch`] |
//! | handler reads/writes state | [`Sessions`] · [`World`] · [`Settings`] | `starling-api` |
//! | handler describes changes | [`Effects`] | `starling-api` |
//! | changes are applied | [`Outbound`] | [`core`] |
//! | frames go out | [`FrameSink`] | `starling-net` |
//!
//! # Boundaries are traits
//!
//! | Trait | Phase 0 implementation | Why the seam exists |
//! |---|---|---|
//! | [`Handler`] | one per message type | Phases 3–5 add ~70 more by registration |
//! | [`Sessions`] / [`World`] / [`Settings`] | [`ServerState`] | the handler boundary, split by role |
//! | [`Outbound`] | `starling-net`'s registry | Phase 1 adds UDP, Phase 6 gRPC |
//! | [`FrameSink`] | `starling-net`'s sink | a destination, not a channel |
//! | `ChannelStore` / `UserRegistry` | in-memory | Phase 2 puts them in SQL |
//! | `Permissions` | `AllowAll` | Phase 2 evaluates real ACLs |
//! | [`SecurityPolicy`] | `CompatibilityFirst` | `ModernOnly` for controlled fleets |
//!
//! # Security
//!
//! Stock Mumble clients get exactly what murmur gives them; Fancy clients get
//! modern primitives (TLS 1.3, `ChaCha20-Poly1305` voice) chosen by an Abstract
//! Factory over what the peer announced. See `starling-crypto` — that is where
//! upgrade path lives, and why it never costs backwards compatibility.
//!
//! Handlers are pure: `fn(&mut dyn Authority, …) -> Effects`. They receive three
//! small role traits rather than the concrete state, so a handler cannot reach
//! `remove_connection` or `channels_mut`, and can be tested without a socket, a
//! runtime or a database (`PORTING-PLAN.md` §7, `DESIGN.md` §4).
//!
//! # Status
//!
//! Phase 0 (MVP). Implemented: TLS listener, the full session-establishment
//! sequence, channel tree push, `TextMessage` fan-out, `Ping`, self-mute/deaf,
//! channel moves, and disconnect cleanup. Not implemented: UDP voice,
//! persistence, real ACL evaluation, and the Fancy extension messages (carried
//! opaquely and dropped).

pub mod connection;
pub mod core;
pub mod dispatch;
pub mod handlers;
pub mod state;

#[cfg(test)]
mod testing;

pub use core::{Command, ServerCore, ServerHandle};
pub use dispatch::Dispatcher;
pub use starling_api::{
    Access, Authority, ConnId, Connection, Effect, Effects, FrameSink, Handler, NoOutbound,
    Outbound, Recipients, ServerConfig, Sessions, Settings, World,
};
pub use starling_crypto::{PeerCapabilities, SecurityPolicy, SecuritySuite, TlsFloor};
pub use state::ServerState;

/// The Mumble protocol version Starling reports.
///
/// Matching murmur's 1.6.x line matters: the client gates features on it (e.g.
/// channel listen needs >= 1.4, protobuf UDP audio needs >= 1.5).
pub const MUMBLE_VERSION: starling_proto::Version = starling_proto::Version::new(1, 6, 0);

/// The Fancy Mumble extension version Starling will advertise once it has one.
///
/// **Deliberately not sent in Phase 0.** Populating `Version.fancy_version`
/// tells the client that Fancy extension messages are understood, and the client
/// then sends them and waits for replies. Since the MVP carries every Fancy
/// message opaquely and drops it, advertising support would turn "unimplemented"
/// into "hangs", which is far harder to diagnose than a client that correctly
/// concludes it is talking to a stock server.
///
/// `handlers::handshake` starts sending this in Phase 5, when the Fancy surface
/// is actually implemented.
///
/// # It does **not** gate the modern voice cipher
///
/// It used to, and that was the mistake. The client selects its cipher from the
/// shape of the key material `CryptSetup` carries — 16 bytes of AES key against
/// a 32-byte master secret — not from this number. The server decides, from the
/// version the *client* announced, and the material is the announcement.
///
/// So `XChaCha20-Poly1305` works today, with this still unsent. Tying the two
/// together would have made a cipher wait on a message surface it has nothing to
/// do with, purely because one linear ladder encodes both.
pub const FANCY_VERSION: u64 = starling_gate::FancyVersion::new(0, 4, 0).to_wire();
