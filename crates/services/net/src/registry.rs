//! The default [`Outbound`] implementation: a map of connection sinks.

use std::collections::HashMap;

use bytes::Bytes;

use starling_api::{ConnId, FrameSink, Outbound};

/// Connection id → outbound queue.
#[derive(Debug, Default)]
pub struct ConnectionRegistry {
    sinks: HashMap<ConnId, Box<dyn FrameSink>>,
}

impl ConnectionRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many connections are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// Whether no connections are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl Outbound for ConnectionRegistry {
    fn register(&mut self, conn: ConnId, sink: Box<dyn FrameSink>) {
        let _ = self.sinks.insert(conn, sink);
    }

    fn send(&mut self, conn: ConnId, frame: Bytes) -> bool {
        // Contract rule 3: an unknown connection is not a stuck connection.
        self.sinks
            .get(&conn)
            .is_none_or(|sink| sink.try_send(frame).is_ok())
    }

    fn disconnect(&mut self, conn: ConnId) {
        // Dropping the sink closes the channel; the write task drains what is
        // already queued and only then shuts the socket down.
        let _ = self.sinks.remove(&conn);
    }

    fn is_connected(&self, conn: ConnId) -> bool {
        self.sinks.contains_key(&conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::ConnectionSink;
    use tokio::sync::mpsc;

    fn registered(depth: usize) -> (ConnectionRegistry, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(depth);
        let mut registry = ConnectionRegistry::new();
        registry.register(ConnId(1), Box::new(ConnectionSink::new(tx)));
        (registry, rx)
    }

    /// The [`Outbound`] contract, asserted against any implementation.
    fn assert_outbound_contract(out: &mut dyn Outbound) {
        // 3. Unknown connections are a silent no-op, not a failure.
        assert!(out.send(ConnId(404), Bytes::from_static(b"x")));
        assert!(!out.is_connected(ConnId(404)));

        let (tx, mut rx) = mpsc::channel(4);
        out.register(ConnId(7), Box::new(ConnectionSink::new(tx)));
        assert!(out.is_connected(ConnId(7)));

        // 1. A healthy send succeeds and arrives.
        assert!(out.send(ConnId(7), Bytes::from_static(b"hello")));
        assert_eq!(rx.try_recv().ok(), Some(Bytes::from_static(b"hello")));

        // 2. Disconnect closes the queue after what was queued.
        assert!(out.send(ConnId(7), Bytes::from_static(b"bye")));
        out.disconnect(ConnId(7));
        assert!(!out.is_connected(ConnId(7)));
        assert_eq!(
            rx.try_recv().ok(),
            Some(Bytes::from_static(b"bye")),
            "queued frames must survive the disconnect"
        );
        assert!(rx.try_recv().is_err(), "the queue should now be closed");
    }

    #[test]
    fn the_registry_satisfies_the_outbound_contract() {
        assert_outbound_contract(&mut ConnectionRegistry::new());
    }

    #[test]
    fn a_stuck_connection_reports_failure_rather_than_blocking() {
        let (mut registry, _rx) = registered(1);
        assert!(registry.send(ConnId(1), Bytes::from_static(b"first")));
        assert!(
            !registry.send(ConnId(1), Bytes::from_static(b"second")),
            "the caller must be told so it can drop the connection"
        );
    }

    #[test]
    fn re_registering_a_connection_replaces_its_sink() {
        let (mut registry, mut old_rx) = registered(4);
        let (tx, mut new_rx) = mpsc::channel(4);
        registry.register(ConnId(1), Box::new(ConnectionSink::new(tx)));

        assert!(registry.send(ConnId(1), Bytes::from_static(b"x")));
        assert!(new_rx.try_recv().is_ok(), "the new sink should receive it");
        assert!(old_rx.try_recv().is_err(), "the old sink should be closed");
    }

    #[test]
    fn disconnecting_twice_is_harmless() {
        let (mut registry, _rx) = registered(4);
        registry.disconnect(ConnId(1));
        registry.disconnect(ConnId(1));
        assert!(registry.is_empty());
    }
}
