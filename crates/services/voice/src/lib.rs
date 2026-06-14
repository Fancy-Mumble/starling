//! `starling-voice` — audio routing.
//!
//! Handed a decoded frame and told who sent it; says where it goes. It never
//! learns which transport delivered the bytes, which is what lets one
//! implementation serve both the UDP socket and the `UDPTunnel` path over TCP.
//!
//! Upstream settles that question: its `msgUDPTunnel` handler asserts
//! unreachable, because the tunnelled frame is intercepted before dispatch and
//! fed into the same routing. Two implementations would be two copies of this
//! differing only in how the bytes arrived.
//!
//! # The pieces
//!
//! | | |
//! |---|---|
//! | [`RoutingSnapshot`] | who hears whom — published by the authority, read lock-free here |
//! | [`AudioPacket`] | one frame, decoded from either wire format |
//! | [`AudioCodec`] | bytes to and from it — legacy or protobuf, chosen per peer |
//! | [`VoicePeer`] | one client's cipher, codec and return path |
//! | [`Router`] | the packet path, synchronous and testable without a socket |
//! | [`VoiceService`] | the task that owns the router |
//! | [`VoiceBridge`] | the adapter the authority talks to, in `starling-api`'s terms |
//! | [`Target`] | what a speaker aimed at |
//! | [`VoiceTarget`] | a whisper or shout slot a client filled in advance |
//!
//! Which session a datagram came from is **not** here: that is a transport
//! question, and it is `starling-net`'s `PeerTable`. A transport with its own
//! connection identity — QUIC, whose connection IDs survive NAT rebinding —
//! needs no such table at all, and would not want one imposed by the routing
//! crate.
//!
//! Per-peer encryption is `starling-crypto`'s business and per-peer addressing
//! is `starling-net`'s. This crate decides *where* a frame goes — not how it is
//! protected, and not how it gets there.

pub mod bridge;
pub mod packet;
pub mod peer;
pub mod router;
pub mod routing;
pub mod service;
pub mod targets;
pub mod varint;

#[cfg(test)]
mod testing;

pub use bridge::VoiceBridge;
pub use packet::{AudioCodec, AudioPacket, Datagram, PacketError, Ping, ServerDetails, codec_for};
pub use peer::VoicePeer;
pub use router::{Router, RouterStats};
pub use routing::{REGULAR_SPEECH, RoutingSnapshot, SERVER_LOOPBACK, Target};
pub use service::{AudioCommand, ControlCommand, VoiceHandle, VoiceService, report_periodically};
pub use targets::{MAX_TARGET, ShoutTarget, TargetError, TargetRegistry, VoiceTarget};
