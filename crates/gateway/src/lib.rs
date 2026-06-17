//! `starling-gateway` — the only component that holds a client's TCP socket.
//!
//! Two facts give it everything else for free (`docs/ARCHITECTURE.md` §2):
//!
//! * **it is the single writer to each client socket**, so per-client ordering
//!   is preserved by construction — a client cannot receive the `UserState`
//!   naming a channel before the `ChannelState` creating it, whatever order the
//!   services produced them in. The in-process design needed a lane rule and a
//!   version counter for this;
//! * **the wire type is in the framing, not the protobuf**
//!   (`vendor/server/src/murmur/Server.cpp:2040` writes it as a big-endian
//!   `u16`), so routing is two bytes and a lookup. The gateway parses no
//!   payload, links no service's stubs, and never recompiles when a service is
//!   added.
//!
//! # Five parts
//!
//! | | |
//! |---|---|
//! | [`listener`] | accept, TLS, mint a connection id |
//! | [`connection`] | one TLS stream, control framing, two queues with two policies |
//! | [`router`] | the `u16` → service table, read from TOML |
//! | [`limiter`] | a bucket per route, never one shared, never a silent drop |
//! | [`resume`] | a sequence number per session and a bounded replay ring |
//!
//! What is deliberately *not* here: the voice cipher (it lives with the UDP
//! socket, so one hop can seal for every listener), audio routing (clients send
//! UDP straight to voice) and any service's schema.

pub mod attach;
pub mod connection;
pub mod limiter;
pub mod listener;
pub mod resume;
pub mod router;
pub mod service;

pub use attach::{Attachments, ServiceLink};
pub use connection::{ClientHandle, Lane, Registry};
pub use limiter::{Limiter, Verdict};
pub use listener::{Gateway, GatewayError};
pub use resume::{ResumeStore, Sequenced};
pub use router::{Route, Router};
pub use service::GatewayService;
