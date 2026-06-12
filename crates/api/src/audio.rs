//! Where audio goes, and how it gets back out.
//!
//! Two traits, both deliberately fire-and-forget. Audio that cannot be queued
//! *now* is worthless in a millisecond, so neither has a way to report back
//! pressure and neither returns a `Result` the caller could retry on.
//!
//! # Why audio does not go to the state service
//!
//! It would be one line: hand `UDPTunnel` to the same `Command` channel every
//! control message uses. `crates/kernel/bus/RESULTS.md` §3.3 measured what that
//! costs — a 25 ms hold in the single-writer state actor made 5% of packets miss
//! their frame. Voice needs a lane the authority cannot stall.
//!
//! # Why the source is an enum and not two traits
//!
//! Two transports deliver the same bytes: a UDP datagram, and a `UDPTunnel`
//! control message carrying a byte-identical payload over TCP. The message type
//! records *which transport carried it* and nothing else, so demultiplexing by
//! transport is honest. Parsing by content would not be — that is the routing
//! layer's job, and it never learns which of these two brought the frame.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::effects::ConnId;

/// How a frame of audio reached the server.
///
/// Carried alongside the bytes because the reply has to go back the same way:
/// a peer whose UDP path does not work gets its audio tunnelled, and the only
/// evidence of that is which of these its own packets arrive as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioSource {
    /// Inside a `UDPTunnel` on an established TLS connection.
    ///
    /// The identity is already known — TLS established it — so nothing has to
    /// be attributed. This is the fallback path, used when UDP is blocked.
    Tunnel(ConnId),

    /// A datagram on the voice port.
    ///
    /// Identity is *not* known: anyone can send to an open UDP port, and the
    /// source address is whatever the sender wrote. It has to be earned by
    /// authenticating against a session's key.
    Datagram(SocketAddr),
}

/// Somewhere audio can be delivered for routing.
///
/// Implemented by the voice service's handle. `starling-net` calls it from both
/// the UDP reader and the TCP reader, and knows nothing about what happens next.
pub trait AudioSink: std::fmt::Debug + Send + Sync {
    /// Hand over one frame, still encrypted.
    ///
    /// Never blocks and never fails: a frame that cannot be queued is dropped,
    /// because by the time a queue drains it is already too late to play.
    fn deliver(&self, from: AudioSource, frame: Bytes);
}

/// Discards every frame (Null Object).
///
/// What a server configured without a voice service gets. Silence is the right
/// failure — the alternative is a transport that refuses to start because
/// nobody is listening for audio yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAudio;

impl AudioSink for NoAudio {
    fn deliver(&self, _from: AudioSource, _frame: Bytes) {}
}

/// Sends datagrams to arbitrary addresses.
///
/// The counterpart of [`AudioSink`], and the reason the voice service needs no
/// socket of its own: it holds one of these and never learns it is UDP.
pub trait Datagrams: std::fmt::Debug + Send + Sync {
    /// Queue a datagram. Dropped if it cannot be sent immediately.
    fn send_to(&self, addr: SocketAddr, frame: Bytes);
}

/// Discards every datagram (Null Object).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDatagrams;

impl Datagrams for NoDatagrams {
    fn send_to(&self, _addr: SocketAddr, _frame: Bytes) {}
}
