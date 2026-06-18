//! The small vocabulary the routing core is written against.
//!
//! These were a shared trait hub in the in-process design. They live here now
//! because voice is the only thing that uses them, and a crate everyone depends
//! on for four types is a coupling with no payoff — `docs/ARCHITECTURE.md`
//! supersedes the `starling-api` hub entirely.
//!
//! Both sinks are deliberately fire-and-forget. Audio that cannot be queued
//! *now* is worthless in a millisecond, so neither awaits and neither hands the
//! frame back for a retry against a peer that is already not keeping up.

use std::net::SocketAddr;

use bytes::Bytes;

/// A connection id, as the gateway mints them.
pub type ConnId = u64;

/// A session id: names a *connection*, never a person.
///
/// A newtype rather than a bare `u32` because a channel id is also a `u32`, and
/// the two are swapped silently by every routing bug that has ever existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SessionId(pub u32);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A channel id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ChannelId(pub u32);

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How a frame of audio reached the server.
///
/// Carried alongside the bytes because the reply has to go back the same way: a
/// peer whose UDP path does not work gets its audio tunnelled, and the only
/// evidence of that is which of these its own packets arrive as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioSource {
    /// Inside a `UDPTunnel` on an established TLS connection.
    ///
    /// The identity is already known — TLS established it — so nothing has to
    /// be attributed. This is the fallback for a UDP-blocked client.
    Tunnel(ConnId),
    /// A datagram on the voice port.
    ///
    /// Identity is *not* known: anyone can send to an open UDP port, and the
    /// source address is whatever the sender wrote. It has to be earned by
    /// decrypting under a session's key.
    Datagram(SocketAddr),
}

/// The destination could not accept a frame.
///
/// Deliberately carries no payload: the caller's only recourse is to drop the
/// frame, and handing it back would invite a retry loop against a peer that is
/// already behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the connection's outbound queue is full or closed")]
pub struct Stuck;

/// Somewhere a datagram can be written.
pub trait Datagrams: std::fmt::Debug + Send + Sync {
    /// Send one datagram. Never blocks: **UDP would block means drop, never
    /// queue** (`docs/ARCHITECTURE.md` §5).
    fn send_to(&self, addr: SocketAddr, bytes: Bytes);
}

/// Somewhere an already-framed control message can be written.
///
/// This is the tunnelled audio path, which is per client rather than per
/// listener — the only audio that reaches the control plane at all.
pub trait FrameSink: std::fmt::Debug + Send + Sync {
    /// Try to queue a frame without blocking.
    ///
    /// # Errors
    ///
    /// [`Stuck`] when the destination cannot accept it now.
    fn try_send(&self, frame: Bytes) -> Result<(), Stuck>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_id_and_a_channel_id_cannot_be_confused_for_each_other() {
        // Both are u32 on the wire; the newtypes are what stop a routing bug
        // from compiling.
        let session = SessionId(7);
        let channel = ChannelId(7);
        assert_eq!(session.to_string(), channel.to_string());
        assert_eq!(session.0, channel.0);
    }

    #[test]
    fn the_transport_a_frame_arrived_on_is_carried_with_it() {
        // The reply has to go back the same way; inferring it from content
        // would be the routing layer guessing at a transport question.
        let tunnelled = AudioSource::Tunnel(7);
        let direct = AudioSource::Datagram("127.0.0.1:64738".parse().expect("a valid address"));
        assert_ne!(tunnelled, direct);
    }
}
