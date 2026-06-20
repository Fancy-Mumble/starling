//! One state machine per connection.
//!
//! Sharded by connection, so a pod holds whatever it accepted and no two
//! connections share anything but the session-id pool
//! (`docs/diagrams/scaling.puml`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto::proto::tcp;
use starling_proto_fancy::control::Opened;
use starling_runtime::ids::now_ms;

use crate::ids::SessionId;
use crate::session::{SessionAllocator, SessionSource as _};

/// Everything known about a connection that has not finished the handshake.
#[derive(Debug, Clone, Default)]
pub struct PendingConnection {
    /// The gateway's connection id.
    pub conn: u64,
    /// Which gateway holds it.
    pub gateway: String,
    /// Its virtual server.
    pub scope: u32,
    /// The peer's address, for the log and for a ban check.
    pub address: String,
    /// SHA-1 of the peer's leaf certificate, empty if it presented none.
    pub cert_hash: Vec<u8>,
    /// Whether the chain validated against a configured CA.
    pub strong_cert: bool,
    /// The Mumble version the peer announced.
    pub mumble_version: u64,
    /// The Fancy version the peer announced, 0 for a stock client.
    pub fancy_version: u64,
    /// The session id, once one has been allocated.
    pub session: u32,
    /// The account, once authenticated.
    pub account: u64,
    /// The name it authenticated as.
    pub name: String,
    /// Its channel.
    pub channel: u32,
    /// Self-mute.
    pub self_mute: bool,
    /// Self-deafen.
    pub self_deaf: bool,
    /// When it connected.
    pub connected_at_ms: u64,
    /// When it was last heard from, for the timeout sweep.
    pub last_seen_ms: u64,
}

/// Every connection this process is holding.
#[derive(Debug, Clone)]
pub struct Connections {
    inner: Arc<Mutex<HashMap<u64, PendingConnection>>>,
    sessions: Arc<Mutex<SessionAllocator>>,
}

impl Connections {
    /// A registry with a session pool sized for `max_users`.
    #[must_use]
    pub fn new(max_users: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(SessionAllocator::new(max_users))),
        }
    }

    /// Record a new connection.
    pub fn opened(&self, opened: &Opened, gateway: &str) {
        let now = now_ms();
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.insert(
                opened.conn,
                PendingConnection {
                    conn: opened.conn,
                    gateway: gateway.to_owned(),
                    scope: opened.virtual_server.max(1),
                    address: opened.peer_addr.clone(),
                    cert_hash: opened.cert_hash.clone(),
                    strong_cert: opened.strong_cert,
                    connected_at_ms: now,
                    last_seen_ms: now,
                    ..PendingConnection::default()
                },
            );
        }
    }

    /// Record what a peer announced in its `Version`.
    pub fn record_version(&self, conn: u64, version: &tcp::Version) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.mumble_version = version
                .version_v2
                .or_else(|| version.version_v1.map(u64::from))
                .unwrap_or_default();
            pending.fancy_version = fancy_version(version);
        }
    }

    /// Allocate a session id for a connection that has authenticated.
    ///
    /// Returns `None` when the pool is exhausted, which refuses the connection
    /// rather than growing — murmur does the same (`Server.cpp:1625`), and an
    /// unbounded pool would mean an unbounded server.
    pub fn allocate(&self, conn: u64, account: u64, name: &str) -> Option<u32> {
        let session = {
            let mut sessions = self.sessions.lock().ok()?;
            sessions.allocate()?.0
        };
        let mut inner = self.inner.lock().ok()?;
        let pending = inner.get_mut(&conn)?;
        pending.session = session;
        pending.account = account;
        pending.name = name.to_owned();
        Some(session)
    }

    /// One connection.
    #[must_use]
    pub fn get(&self, conn: u64) -> Option<PendingConnection> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.get(&conn).cloned())
    }

    /// Record that a connection is still alive.
    pub fn touch(&self, conn: u64) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.last_seen_ms = now_ms();
        }
    }

    /// Record which channel a session is in.
    pub fn set_channel(&self, conn: u64, channel: u32) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.channel = channel;
        }
    }

    /// Apply self-mute and self-deafen, returning the session they belong to.
    pub fn set_self_flags(&self, conn: u64, mute: Option<bool>, deaf: Option<bool>) -> Option<u32> {
        let mut inner = self.inner.lock().ok()?;
        let pending = inner.get_mut(&conn)?;
        if let Some(mute) = mute {
            pending.self_mute = mute;
        }
        if let Some(deaf) = deaf {
            pending.self_deaf = deaf;
            // Deafening implies muting, as it does in every Mumble client: a
            // user who cannot hear the room should not be transmitting into it.
            if deaf {
                pending.self_mute = true;
            }
        }
        (pending.session != 0).then_some(pending.session)
    }

    /// Forget a connection, returning its session id to the pool.
    pub fn close(&self, conn: u64) -> Option<u32> {
        let pending = self.inner.lock().ok()?.remove(&conn)?;
        if pending.session != 0 {
            if let Ok(mut sessions) = self.sessions.lock() {
                sessions.release(SessionId(pending.session));
            }
            return Some(pending.session);
        }
        None
    }

    /// Connections that have not been heard from since `cutoff_ms`.
    #[must_use]
    pub fn timed_out(&self, cutoff_ms: u64) -> Vec<u64> {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .values()
                    .filter(|pending| pending.last_seen_ms < cutoff_ms)
                    .map(|pending| pending.conn)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The Fancy extension version a peer announced, or 0.
///
/// Read from the Fancy field rather than inferred from the Mumble version: a
/// fork could ship Mumble 1.6 without the extensions, and announcing the
/// extension is not the same as implementing a capability added later.
#[must_use]
pub fn fancy_version(version: &tcp::Version) -> u64 {
    version.fancy_version.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(conn: u64) -> Opened {
        Opened {
            conn,
            peer_addr: "127.0.0.1:1234".to_owned(),
            cert_hash: Vec::new(),
            strong_cert: false,
            virtual_server: 1,
        }
    }

    #[test]
    fn a_session_id_is_returned_to_the_pool_when_its_connection_ends() {
        // Otherwise a server that has been up for a week runs out of ids while
        // holding ten clients.
        let connections = Connections::new(2);
        connections.opened(&opened(1), "gw");
        let first = connections.allocate(1, 0, "a").expect("a session id");
        assert_eq!(connections.close(1), Some(first));

        connections.opened(&opened(2), "gw");
        assert!(connections.allocate(2, 0, "b").is_some());
    }

    #[test]
    fn deafening_yourself_also_mutes_you() {
        // Every Mumble client shows it this way; not doing it leaves a user
        // transmitting into a room they cannot hear.
        let connections = Connections::new(4);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, 0, "a");
        let _ = connections.set_self_flags(1, None, Some(true));
        let pending = connections.get(1).expect("the connection");
        assert!(pending.self_mute);
        assert!(pending.self_deaf);
    }

    #[test]
    fn an_exhausted_session_pool_refuses_rather_than_growing() {
        let connections = Connections::new(1);
        for conn in 1..=4 {
            connections.opened(&opened(conn), "gw");
        }
        let mut granted = 0;
        for conn in 1..=4 {
            if connections.allocate(conn, 0, "x").is_some() {
                granted += 1;
            }
        }
        assert!(granted < 4, "the pool must be bounded");
    }

    #[test]
    fn a_stock_client_announces_no_fancy_version() {
        let stock = tcp::Version {
            version_v2: Some(0x0001_0006_0000),
            ..tcp::Version::default()
        };
        assert_eq!(fancy_version(&stock), 0);
    }
}
