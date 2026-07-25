//! Connection bookkeeping.
//!
//! The [`Connection`] record itself is contract — a
//! feature is handed one — so it lives in `starling-api`. What stays here is the
//! *registry*: state, and therefore the state service's.

use std::collections::HashMap;
use std::net::SocketAddr;

use starling_api::{ConnId, Connection};
use starling_model::{SessionAllocator, SessionId, SessionSource};

/// Open connections and their session assignments.
///
/// Owns the [`SessionSource`], so session ids can only be allocated and released
/// alongside the connection that holds them — there is exactly one place that
/// could leak or double-free one, and it is tested.
#[derive(Debug)]
pub struct Connections {
    open: HashMap<ConnId, Connection>,
    by_session: HashMap<SessionId, ConnId>,
    sessions: Box<dyn SessionSource + Send + Sync>,
}

impl Connections {
    /// Build a registry whose session pool is sized for `max_users`.
    #[must_use]
    pub fn new(max_users: u32) -> Self {
        Self::with_session_source(Box::new(SessionAllocator::new(max_users)))
    }

    /// Build a registry over an explicit session source.
    ///
    /// Exists so tests can drive exhaustion without allocating a real pool.
    #[must_use]
    pub fn with_session_source(sessions: Box<dyn SessionSource + Send + Sync>) -> Self {
        Self {
            open: HashMap::new(),
            by_session: HashMap::new(),
            sessions,
        }
    }

    /// Register a newly accepted connection.
    pub fn add(&mut self, id: ConnId, addr: SocketAddr) {
        let _ = self.open.insert(id, Connection::new(id, addr));
    }

    /// Look up a connection.
    #[must_use]
    pub fn get(&self, id: ConnId) -> Option<&Connection> {
        self.open.get(&id)
    }

    /// Mutable access to a connection's pre-authentication fields.
    pub fn get_mut(&mut self, id: ConnId) -> Option<&mut Connection> {
        self.open.get_mut(&id)
    }

    /// Whether the connection exists and holds a session.
    #[must_use]
    pub fn is_authenticated(&self, id: ConnId) -> bool {
        self.get(id).is_some_and(Connection::is_authenticated)
    }

    /// The session a connection holds, if any.
    #[must_use]
    pub fn session_of(&self, id: ConnId) -> Option<SessionId> {
        self.get(id).and_then(|c| c.session)
    }

    /// The connection carrying a session, if it is still open.
    #[must_use]
    pub fn conn_for(&self, session: SessionId) -> Option<ConnId> {
        self.by_session.get(&session).copied()
    }

    /// Assign a session id to a connection.
    ///
    /// Returns `None` when the connection is unknown or the pool is exhausted —
    /// which the caller must turn into a `Reject`, never into a fabricated id.
    pub fn assign_session(&mut self, id: ConnId) -> Option<SessionId> {
        if !self.open.contains_key(&id) {
            // Checked before drawing from the pool, so a message for a dead
            // connection cannot consume a session id.
            return None;
        }
        let session = self.sessions.allocate()?;
        if let Some(c) = self.open.get_mut(&id) {
            c.session = Some(session);
        }
        let _ = self.by_session.insert(session, id);
        Some(session)
    }

    /// Drop a connection, releasing its session id.
    ///
    /// Returns the session it held, if it had authenticated.
    pub fn remove(&mut self, id: ConnId) -> Option<SessionId> {
        let connection = self.open.remove(&id)?;
        let session = connection.session?;
        let _ = self.by_session.remove(&session);
        self.sessions.release(session);
        Some(session)
    }

    /// How many session ids remain.
    #[must_use]
    pub fn sessions_available(&self) -> usize {
        self.sessions.available()
    }

    /// How many connections are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether no connections are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    fn connections() -> Connections {
        Connections::new(4)
    }

    #[test]
    fn a_new_connection_is_unauthenticated() {
        let mut conns = connections();
        conns.add(ConnId(1), addr());
        assert!(!conns.is_authenticated(ConnId(1)));
        assert_eq!(conns.session_of(ConnId(1)), None);
    }

    #[test]
    fn assigning_a_session_links_it_both_ways() {
        let mut conns = connections();
        conns.add(ConnId(1), addr());
        let session = conns.assign_session(ConnId(1)).expect("pool has ids");

        assert_eq!(conns.conn_for(session), Some(ConnId(1)));
        assert_eq!(conns.session_of(ConnId(1)), Some(session));
        assert!(conns.is_authenticated(ConnId(1)));
    }

    #[test]
    fn a_session_cannot_be_assigned_to_an_unknown_connection() {
        let mut conns = connections();
        let before = conns.sessions_available();
        assert_eq!(conns.assign_session(ConnId(42)), None);
        assert_eq!(
            conns.sessions_available(),
            before,
            "a dead connection must not consume a session id"
        );
    }

    #[test]
    fn removing_a_connection_returns_its_session_id_to_the_pool() {
        let mut conns = connections();
        let before = conns.sessions_available();

        conns.add(ConnId(1), addr());
        let session = conns.assign_session(ConnId(1)).expect("pool has ids");
        assert_eq!(conns.sessions_available(), before - 1);

        assert_eq!(conns.remove(ConnId(1)), Some(session));
        assert_eq!(conns.sessions_available(), before, "session id leaked");
        assert_eq!(conns.conn_for(session), None);
        assert!(conns.is_empty());
    }

    #[test]
    fn removing_an_unauthenticated_connection_reports_no_session() {
        let mut conns = connections();
        conns.add(ConnId(1), addr());
        assert_eq!(conns.remove(ConnId(1)), None);
        assert!(conns.get(ConnId(1)).is_none(), "connection must be gone");
    }

    #[test]
    fn removing_the_same_connection_twice_does_not_double_release() {
        let mut conns = connections();
        let before = conns.sessions_available();
        conns.add(ConnId(1), addr());
        let _ = conns.assign_session(ConnId(1)).expect("pool has ids");

        let _ = conns.remove(ConnId(1));
        let _ = conns.remove(ConnId(1));
        assert_eq!(
            conns.sessions_available(),
            before,
            "double release would inflate the pool and alias session ids"
        );
    }

    #[test]
    fn an_exhausted_pool_refuses_rather_than_fabricating_an_id() {
        #[derive(Debug)]
        struct Empty;
        impl SessionSource for Empty {
            fn allocate(&mut self) -> Option<SessionId> {
                None
            }
            fn release(&mut self, _: SessionId) {}
            fn available(&self) -> usize {
                0
            }
        }

        let mut conns = Connections::with_session_source(Box::new(Empty));
        conns.add(ConnId(1), addr());
        assert_eq!(conns.assign_session(ConnId(1)), None);
        assert!(!conns.is_authenticated(ConnId(1)));
    }
}
