//! `Ping` — keepalive and UDP crypt statistics.

use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType};

use starling_api::Authority;
use starling_api::Handler;
use starling_api::{ConnId, Effects, Recipients};

/// Echoes pings back to their sender.
///
/// The client measures RTT from the timestamp it sent, so it must come back
/// **unmodified** — a server that helpfully substituted its own clock would make
/// every client report nonsense latency (`client.rs:659`).
///
/// The `good`/`late`/`lost`/`resync` counters describe the UDP crypt stream and
/// stay zero until Phase 1 gives the server a UDP path to count.
#[derive(Debug, Default)]
pub struct PingHandler;

impl Handler for PingHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::Ping
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::Ping(msg) = msg else {
            return Effects::none();
        };
        let Some(session) = state.session_of(conn) else {
            return Effects::none();
        };

        let mut fx = Effects::none();
        let _ = fx.send(
            Recipients::Session(session),
            ControlMessage::Ping(tcp::Ping {
                timestamp: msg.timestamp,
                good: Some(0),
                late: Some(0),
                lost: Some(0),
                resync: Some(0),
                ..Default::default()
            }),
        );
        fx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServerState;
    use starling_api::Effect;
    use starling_api::ServerConfig;
    use starling_api::{Sessions, World};
    use starling_model::{SessionId, User, ROOT_CHANNEL};
    use std::net::SocketAddr;

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    fn authenticated_state() -> (ServerState, ConnId, SessionId) {
        let mut state = ServerState::new(ServerConfig::default());
        state.add_connection(ConnId(1), addr());
        let session = state.assign_session(ConnId(1)).expect("pool has ids");
        state
            .users_mut()
            .insert(User::new(session, "alice", ROOT_CHANNEL));
        (state, ConnId(1), session)
    }

    fn ping(state: &mut dyn Authority, conn: ConnId, timestamp: Option<u64>) -> Effects {
        PingHandler.handle(
            state,
            conn,
            ControlMessage::Ping(tcp::Ping {
                timestamp,
                ..Default::default()
            }),
        )
    }

    fn reply(fx: &Effects) -> tcp::Ping {
        fx.as_slice()
            .iter()
            .find_map(|e| match e {
                Effect::Send { msg, .. } => match msg.as_ref() {
                    ControlMessage::Ping(p) => Some(*p),
                    _ => None,
                },
                _ => None,
            })
            .expect("a Ping reply must be sent")
    }

    #[test]
    fn the_clients_timestamp_is_echoed_verbatim() {
        let (mut state, conn, _) = authenticated_state();
        let fx = ping(&mut state, conn, Some(1_234_567_890));
        assert_eq!(reply(&fx).timestamp, Some(1_234_567_890));
    }

    #[test]
    fn a_ping_without_a_timestamp_replies_without_one() {
        // The client treats a missing timestamp as "no RTT sample", which is
        // correct; inventing one would produce a fabricated measurement.
        let (mut state, conn, _) = authenticated_state();
        assert_eq!(reply(&ping(&mut state, conn, None)).timestamp, None);
    }

    #[test]
    fn the_reply_goes_only_to_the_sender() {
        let (mut state, conn, session) = authenticated_state();
        match ping(&mut state, conn, None).as_slice() {
            [Effect::Send { to, .. }] => assert_eq!(*to, Recipients::Session(session)),
            other => panic!("expected exactly one targeted send, got {other:?}"),
        }
    }

    #[test]
    fn crypt_counters_are_reported_as_zero_until_udp_exists() {
        let (mut state, conn, _) = authenticated_state();
        let reply = reply(&ping(&mut state, conn, None));
        assert_eq!(
            (reply.good, reply.late, reply.lost, reply.resync),
            (Some(0), Some(0), Some(0), Some(0))
        );
    }

    #[test]
    fn a_ping_from_a_connection_without_a_session_is_dropped() {
        let mut state = ServerState::new(ServerConfig::default());
        state.add_connection(ConnId(1), addr());
        assert!(ping(&mut state, ConnId(1), Some(1)).is_empty());
    }
}
