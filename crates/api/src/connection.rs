//! Connections and the connection ↔ session mapping.
//!
//! Separated from `ServerState` because a connection and a
//! session have different lifetimes: a connection exists from the TLS handshake,
//! a session only from `Authenticate`. murmur conflates them on one `ServerUser`
//! guarded by an `sState` enum; keeping them apart makes the
//! pre-authentication window a type-level fact rather than a convention.

use std::net::SocketAddr;

use starling_model::SessionId;
use starling_proto::Version;

use crate::effects::ConnId;
use starling_crypto::PeerCapabilities;

/// A connection that exists but may not have authenticated yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Internal connection id. Never on the wire, never reused.
    pub id: ConnId,
    /// Peer address, for logging and (from Phase 2) ban matching.
    pub addr: SocketAddr,
    /// Version announced in the client's `Version` message.
    pub version: Version,
    /// Fancy extension version, when announced.
    pub fancy_version: Option<u64>,
    /// The session assigned at `Authenticate`, once that has happened.
    pub session: Option<SessionId>,
    /// Whether the client announced Opus support in `Authenticate`.
    pub opus: bool,
}

impl Connection {
    /// A freshly accepted, unauthenticated connection.
    #[must_use]
    pub fn new(id: ConnId, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            version: Version::new(0, 0, 0),
            fancy_version: None,
            session: None,
            opus: false,
        }
    }

    /// Whether this connection has completed authentication.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// What the peer announced about itself, for security negotiation.
    ///
    /// Derived rather than stored so it cannot drift from the `Version` fields
    /// it summarises.
    #[must_use]
    pub fn capabilities(&self) -> PeerCapabilities {
        PeerCapabilities {
            version: self.version,
            fancy_version: self.fancy_version,
        }
    }
}
