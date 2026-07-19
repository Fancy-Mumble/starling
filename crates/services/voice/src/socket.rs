//! The UDP socket this service owns, and the peer table behind it.
//!
//! Which session a datagram came from is a **transport** question, not a
//! routing one: anyone can send to an open UDP port and the source address is
//! whatever the sender wrote, so identity is earned by decrypting under a
//! session's key rather than read off the packet.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::ports::{Datagrams, SessionId};

/// Largest datagram accepted.
///
/// One Opus frame plus framing is far below this; the bound exists because the
/// buffer is allocated before anything about the packet is known.
pub const MAX_DATAGRAM: usize = 1024;

/// The voice socket and the addresses it has learned.
#[derive(Debug)]
pub struct VoiceSocket {
    socket: Arc<UdpSocket>,
    peers: Arc<Mutex<HashMap<SessionId, SocketAddr>>>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl VoiceSocket {
    /// Bind `address`.
    ///
    /// # Errors
    ///
    /// The bind error. A voice service that cannot bind is a voice service that
    /// silently drops every packet, so this is fatal rather than degraded.
    pub async fn bind(address: &str) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(address).await?;
        tracing::info!(%address, "voice bound its own UDP socket");
        Ok(Self {
            socket: Arc::new(socket),
            peers: Arc::new(Mutex::new(HashMap::new())),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Receive one datagram.
    ///
    /// # Errors
    ///
    /// The receive error, which the caller logs and continues from: one bad
    /// datagram must not take the socket down.
    pub async fn recv(&self) -> Result<(SocketAddr, Bytes), std::io::Error> {
        let mut buffer = vec![0_u8; MAX_DATAGRAM];
        let (read, from) = self.socket.recv_from(&mut buffer).await?;
        buffer.truncate(read);
        Ok((from, Bytes::from(buffer)))
    }

    /// Remember which address a session's audio arrives from.
    ///
    /// Recorded only after a datagram has decrypted under that session's key,
    /// otherwise anyone could redirect a session's audio by spoofing a source
    /// address, which is the whole reason identity is earned here.
    pub fn bind_peer(&self, session: SessionId, address: SocketAddr) {
        if let Ok(mut peers) = self.peers.lock() {
            let _ = peers.insert(session, address);
        }
    }

    /// Forget a session's address.
    pub fn forget(&self, session: SessionId) {
        if let Ok(mut peers) = self.peers.lock() {
            let _ = peers.remove(&session);
        }
    }

    /// Which session a datagram from `address` belongs to, if one is known.
    #[must_use]
    pub fn session_at(&self, address: SocketAddr) -> Option<SessionId> {
        let peers = self.peers.lock().ok()?;
        peers
            .iter()
            .find(|(_, known)| **known == address)
            .map(|(session, _)| *session)
    }

    /// Where a session's audio should be sent.
    #[must_use]
    pub fn address_of(&self, session: SessionId) -> Option<SocketAddr> {
        self.peers.lock().ok()?.get(&session).copied()
    }

    /// How many datagrams were dropped rather than sent.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// A sender handle for the router.
    #[must_use]
    pub fn sender(&self) -> UdpSender {
        UdpSender {
            socket: Arc::clone(&self.socket),
            dropped: Arc::clone(&self.dropped),
        }
    }
}

/// The write half, as the router sees it.
#[derive(Debug, Clone)]
pub struct UdpSender {
    socket: Arc<UdpSocket>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl Datagrams for UdpSender {
    fn send_to(&self, addr: SocketAddr, bytes: Bytes) {
        // `try_send_to` rather than an await: **UDP would block means drop,
        // never queue** (`docs/ARCHITECTURE.md` §5). Queueing here would add
        // latency to a frame that is already too late to be worth playing.
        if self.socket.try_send_to(&bytes, addr).is_err() {
            let _ = self
                .dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// The write half of a deployment that has no UDP socket.
///
/// Not a degenerate case to be tolerated; it is a supported configuration. A
/// voice service with no `udp_listen` serves every client over the tunnel, and
/// the router needs *a* transport at construction time either way. Handing it
/// this rather than leaving the router unbuilt is what keeps tunnelled audio
/// working when there is no socket: the alternative was no packet path at all,
/// so a firewalled client and an un-socketed deployment were both silent.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDatagrams;

impl Datagrams for NoDatagrams {
    fn send_to(&self, _addr: SocketAddr, _bytes: Bytes) {
        // Nothing to drop a counter for: no peer can have a proven UDP address
        // without a socket to have proven it on, so the router never routes
        // here in the first place.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_session_is_only_reachable_once_its_address_has_been_learned() {
        // Trusting a source address before it has decrypted would let anyone
        // redirect somebody else's audio.
        let socket = VoiceSocket::bind("127.0.0.1:0").await.expect("bind");
        assert!(socket.address_of(SessionId(7)).is_none());

        let address: SocketAddr = "127.0.0.1:5000".parse().expect("a valid address");
        socket.bind_peer(SessionId(7), address);
        assert_eq!(socket.address_of(SessionId(7)), Some(address));
        assert_eq!(socket.session_at(address), Some(SessionId(7)));

        socket.forget(SessionId(7));
        assert!(socket.address_of(SessionId(7)).is_none());
    }
}
