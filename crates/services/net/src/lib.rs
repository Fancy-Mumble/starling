//! `starling-net` — the transport.
//!
//! Everything about getting bytes to and from a peer, and nothing about what
//! they mean. It implements `starling-api`'s [`Outbound`](starling_api::Outbound)
//! and [`FrameSink`](starling_api::FrameSink); the state service consumes those
//! traits and never names this crate.
//!
//! # Why it is separate
//!
//! It lived inside the state service, which meant one crate owned both the TLS
//! accept loop and the authoritative state — two responsibilities with nothing in
//! common but history. The measurement that settled it: the authority half never
//! named a transport type, so the dependency was already one-directional and the
//! split cost nothing but the move.
//!
//! # Contents
//!
//! | | |
//! |---|---|
//! | [`Listener`] | binds, accepts, runs the core |
//! | [`Peer`] | one connection, handshake to disconnect |
//! | [`FrameReader`] / [`FrameWriter`] | the two halves, one per task |
//! | [`ConnectionRegistry`] | the `Outbound` implementation |
//! | [`ConnectionSink`] | the `FrameSink` implementation, over a `tokio` channel |

mod bind;
mod listener;
mod registry;
mod sink;
mod udp;

pub use listener::{FrameReader, FrameWriter, ListenError, Listener, ListenerConfig, Peer};
pub use registry::ConnectionRegistry;
pub use sink::ConnectionSink;
pub use udp::{DatagramSender, VoiceSocket};
