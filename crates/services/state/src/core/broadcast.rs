//! Turning a recipient set into deliveries (Observer).
//!
//! Split from the actor loop because it is the one piece of the core with a
//! performance contract worth stating and testing on its own: **encode once,
//! clone a refcount per recipient**. A 100-user channel broadcast serialises one
//! protobuf and hands out 100 `Bytes` handles, not 100 serialisations. This is
//! the structural version of murmur's `QByteArray &cache` parameter.

use bytes::Bytes;
use starling_model::SessionId;
use starling_proto::{ControlMessage, codec};
use tracing::warn;

use crate::state::ServerState;
use starling_api::Outbound;
use starling_api::World;
use starling_api::{ConnId, Recipients};

/// Delivers one message to a recipient set.
///
/// A struct because the state to resolve against and the transport to deliver
/// through are one collaborator pair: they were threaded through three functions
/// as `(state, outbound)` before, which is a borrowed object in disguise.
pub(super) struct Broadcast<'a> {
    state: &'a ServerState,
    outbound: &'a mut dyn Outbound,
}

impl<'a> Broadcast<'a> {
    /// Resolve against `state`, deliver through `outbound`.
    pub(super) fn new(state: &'a ServerState, outbound: &'a mut dyn Outbound) -> Self {
        Self { state, outbound }
    }

    /// Deliver `msg` to everyone `to` names.
    ///
    /// Connections whose queue is full are dropped rather than waited on — one
    /// slow peer must never stall the server.
    pub(super) fn send(&mut self, to: Recipients, msg: &ControlMessage) {
        let targets = self.resolve(to);
        if targets.is_empty() {
            return;
        }

        // Encoded once, before the loop. This line is the point of the module.
        let frame: Bytes = codec::encode(msg);

        for conn in targets {
            if !self.outbound.send(conn, frame.clone()) {
                warn!(%conn, message = msg.name(), "outbound queue full; dropping connection");
                self.outbound.disconnect(conn);
            }
        }
    }

    /// Turn a recipient set into connection ids.
    ///
    /// Sessions with no live connection are dropped silently: a user can
    /// disconnect between a handler producing an effect and the core applying it.
    fn resolve(&self, to: Recipients) -> Vec<ConnId> {
        match to {
            Recipients::Connection(conn) => vec![conn],
            Recipients::Session(session) => {
                self.state.conn_for_session(session).into_iter().collect()
            }
            Recipients::All => self.conns_for(self.state.users().sessions()),
            Recipients::AllExcept(excluded) => self.conns_for(
                self.state
                    .users()
                    .sessions()
                    .into_iter()
                    .filter(|s| *s != excluded),
            ),
            Recipients::Channel(channel) => self.conns_for(self.state.channel_members(channel)),
            Recipients::ChannelExcept(channel, excluded) => self.conns_for(
                self.state
                    .channel_members(channel)
                    .into_iter()
                    .filter(|s| *s != excluded),
            ),
        }
    }

    fn conns_for(&self, sessions: impl IntoIterator<Item = SessionId>) -> Vec<ConnId> {
        sessions
            .into_iter()
            .filter_map(|s| self.state.conn_for_session(s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{TestRegistry, TestSink};
    use starling_api::ServerConfig;
    use starling_api::{Sessions, World};
    use starling_model::{ChannelId, ROOT_CHANNEL, User};
    use starling_proto::proto::tcp;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    /// A server with `count` users in the root channel, plus their queues.
    fn populated(count: u32) -> (ServerState, TestRegistry, Vec<mpsc::Receiver<Bytes>>) {
        let mut state = ServerState::new(ServerConfig::default());
        let mut outbound = TestRegistry::new();
        let mut queues = Vec::new();

        for i in 0..count {
            let conn = ConnId(u64::from(i) + 1);
            state.add_connection(conn, addr());
            let session = state.assign_session(conn).expect("pool has ids");
            state
                .users_mut()
                .insert(User::new(session, format!("user{i}"), ROOT_CHANNEL));
            let (tx, rx) = mpsc::channel(16);
            outbound.register(conn, Box::new(TestSink::new(tx)));
            queues.push(rx);
        }
        (state, outbound, queues)
    }

    fn ping() -> ControlMessage {
        ControlMessage::Ping(tcp::Ping {
            timestamp: Some(1),
            ..Default::default()
        })
    }

    fn received(rx: &mut mpsc::Receiver<Bytes>) -> usize {
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    }

    #[test]
    fn all_reaches_every_authenticated_session() {
        let (state, mut outbound, mut queues) = populated(3);
        Broadcast::new(&state, &mut outbound).send(Recipients::All, &ping());
        for (i, rx) in queues.iter_mut().enumerate() {
            assert_eq!(received(rx), 1, "user{i} did not receive the broadcast");
        }
    }

    #[test]
    fn all_except_skips_exactly_one() {
        let (state, mut outbound, mut queues) = populated(3);
        let excluded = state.session_of(ConnId(2)).expect("session");
        Broadcast::new(&state, &mut outbound).send(Recipients::AllExcept(excluded), &ping());

        assert_eq!(received(&mut queues[0]), 1);
        assert_eq!(received(&mut queues[1]), 0, "the excluded user got it");
        assert_eq!(received(&mut queues[2]), 1);
    }

    #[test]
    fn a_broadcast_is_encoded_once_and_shared() {
        // The performance contract. Every recipient must receive byte-identical
        // frames, which is what proves a single encode was cloned rather than
        // repeated.
        let (state, mut outbound, mut queues) = populated(3);
        Broadcast::new(&state, &mut outbound).send(Recipients::All, &ping());

        let frames: Vec<_> = queues
            .iter_mut()
            .map(|rx| rx.try_recv().expect("frame"))
            .collect();
        assert!(frames.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn channel_addressing_reaches_only_that_channel() {
        let (mut state, mut outbound, mut queues) = populated(3);
        let lobby = state
            .channels_mut()
            .insert(ROOT_CHANNEL, "Lobby")
            .expect("root exists");
        let moved = state.session_of(ConnId(1)).expect("session");
        let _ = state.users_mut().move_to(moved, lobby);

        Broadcast::new(&state, &mut outbound).send(Recipients::Channel(lobby), &ping());
        assert_eq!(received(&mut queues[0]), 1);
        assert_eq!(received(&mut queues[1]), 0);
        assert_eq!(received(&mut queues[2]), 0);
    }

    #[test]
    fn channel_except_skips_the_sender() {
        let (state, mut outbound, mut queues) = populated(2);
        let sender = state.session_of(ConnId(1)).expect("session");
        Broadcast::new(&state, &mut outbound)
            .send(Recipients::ChannelExcept(ROOT_CHANNEL, sender), &ping());
        assert_eq!(
            received(&mut queues[0]),
            0,
            "the sender got its own message"
        );
        assert_eq!(received(&mut queues[1]), 1);
    }

    #[test]
    fn an_empty_channel_produces_no_delivery() {
        let (state, mut outbound, mut queues) = populated(1);
        Broadcast::new(&state, &mut outbound).send(Recipients::Channel(ChannelId(999)), &ping());
        assert_eq!(received(&mut queues[0]), 0);
    }

    #[test]
    fn a_session_with_no_live_connection_is_skipped_silently() {
        // A user can disconnect between a handler producing an effect and the
        // core applying it; resolving their session must yield no target rather
        // than panicking or delivering to a stale queue.
        let (mut state, mut outbound, mut queues) = populated(1);
        let session = state.session_of(ConnId(1)).expect("session");
        let _ = state.remove_connection(ConnId(1));

        Broadcast::new(&state, &mut outbound).send(Recipients::Session(session), &ping());
        assert_eq!(
            received(&mut queues[0]),
            0,
            "a departed session must not be delivered to"
        );
    }

    #[test]
    fn a_stuck_connection_is_dropped_rather_than_waited_on() {
        let mut state = ServerState::new(ServerConfig::default());
        state.add_connection(ConnId(1), addr());
        let session = state.assign_session(ConnId(1)).expect("pool has ids");
        state
            .users_mut()
            .insert(User::new(session, "slow", ROOT_CHANNEL));

        let mut outbound = TestRegistry::new();
        let (tx, _rx) = mpsc::channel(1); // never drained
        outbound.register(ConnId(1), Box::new(TestSink::new(tx)));

        Broadcast::new(&state, &mut outbound).send(Recipients::All, &ping()); // fills it
        Broadcast::new(&state, &mut outbound).send(Recipients::All, &ping()); // overruns it
        assert!(!outbound.is_connected(ConnId(1)));
    }

    #[test]
    fn connection_addressing_works_before_a_session_exists() {
        // How `Version` and `Reject` reach an unauthenticated peer.
        let mut state = ServerState::new(ServerConfig::default());
        state.add_connection(ConnId(1), addr());
        let mut outbound = TestRegistry::new();
        let (tx, mut rx) = mpsc::channel(4);
        outbound.register(ConnId(1), Box::new(TestSink::new(tx)));

        Broadcast::new(&state, &mut outbound).send(Recipients::Connection(ConnId(1)), &ping());
        assert_eq!(received(&mut rx), 1);
    }
}
