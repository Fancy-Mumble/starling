//! The `Version` exchange.
//!
//! Two version numbers, on two independent axes. The Mumble version decides the
//! audio framing (protobuf from 1.5); the Fancy version decides everything in
//! `starling-gate`'s table, of which the voice cipher is the one that matters
//! today.
//!
//! Both are announced here and both are recorded from the peer, because the
//! gate is symmetric: each end computes what the other may do from the number
//! that other end sent, and no message ever names the result.

use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType, Version};
use tracing::info;

use crate::MUMBLE_VERSION;
use starling_api::Authority;
use starling_api::{Access, Handler};
use starling_api::{ConnId, Effects, Recipients};

/// The server's opening `Version`, sent the moment TLS is established.
///
/// Runs before any client bytes are read, so it takes no state. murmur does the
/// same from its `encrypted()` slot (`Server.cpp:1668`).
#[must_use]
pub fn server_version(conn: ConnId) -> Effects {
    let mut fx = Effects::none();
    let _ = fx.send(
        Recipients::Connection(conn),
        ControlMessage::Version(tcp::Version {
            version_v1: Some(MUMBLE_VERSION.encode_v1()),
            version_v2: Some(MUMBLE_VERSION.encode_v2()),
            release: Some(format!("Starling {}", env!("CARGO_PKG_VERSION"))),
            os: Some(std::env::consts::OS.into()),
            os_version: None,
            // Absent until the Fancy *message* surface exists: announcing it
            // makes a client send those messages and wait for replies. It does
            // not hold back the modern voice cipher, which is selected from the
            // key material instead — see `crate::FANCY_VERSION`.
            fancy_version: None,
        }),
    );
    fx
}

/// Records the peer's announced version.
///
/// Purely bookkeeping, but load-bearing: murmur gates features on the recorded
/// version (`>= 1.2.2` for blob hashes, `>= 1.4` for channel listen), and those
/// gates arrive in Phases 1–2.
#[derive(Debug, Default)]
pub struct VersionHandler;

impl Handler for VersionHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::Version
    }

    fn access(&self) -> Access {
        // The version exchange necessarily precedes authentication.
        Access::Anonymous
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::Version(msg) = msg else {
            return Effects::none();
        };

        let version = Version::from_message(&msg);
        if let Some(c) = state.connection_mut(conn) {
            c.version = version;
            c.fancy_version = msg.fancy_version;
        }
        info!(
            %conn,
            %version,
            release = msg.release.as_deref().unwrap_or("unknown"),
            fancy = msg.fancy_version.is_some(),
            "client version"
        );
        Effects::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServerState;
    use starling_api::Effect;
    use starling_api::ServerConfig;
    use starling_api::Sessions;
    use std::net::SocketAddr;

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    fn state() -> ServerState {
        let mut state = ServerState::new(ServerConfig::default());
        state.add_connection(ConnId(1), addr());
        state
    }

    fn sent_version(fx: &Effects) -> tcp::Version {
        fx.as_slice()
            .iter()
            .find_map(|e| match e {
                Effect::Send { msg, .. } => match msg.as_ref() {
                    ControlMessage::Version(v) => Some(v.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("a Version must be sent")
    }

    #[test]
    fn the_opening_version_carries_both_encodings() {
        let version = sent_version(&server_version(ConnId(1)));
        assert_eq!(version.version_v1, Some(MUMBLE_VERSION.encode_v1()));
        assert_eq!(version.version_v2, Some(MUMBLE_VERSION.encode_v2()));
    }

    #[test]
    fn the_server_never_advertises_fancy_support_it_lacks() {
        // A tripwire, not a preference. Whoever makes this send
        // `crate::FANCY_VERSION` must read that constant's docs first: the
        // number claims `NativeFancyMessages`, and claiming it before the Fancy
        // surface exists turns "unimplemented" into "hangs".
        assert_eq!(sent_version(&server_version(ConnId(1))).fancy_version, None);
    }

    #[test]
    fn the_opening_version_is_addressed_by_connection_not_session() {
        // There is no session yet; addressing by session would drop it.
        match server_version(ConnId(1)).as_slice() {
            [Effect::Send { to, .. }] => assert_eq!(*to, Recipients::Connection(ConnId(1))),
            other => panic!("expected one connection-addressed send, got {other:?}"),
        }
    }

    #[test]
    fn a_clients_version_is_recorded() {
        let mut state = state();
        let _ = VersionHandler.handle(
            &mut state,
            ConnId(1),
            ControlMessage::Version(tcp::Version {
                version_v2: Some(Version::new(1, 5, 0).encode_v2()),
                ..Default::default()
            }),
        );
        assert_eq!(
            state.connection(ConnId(1)).expect("connection").version,
            Version::new(1, 5, 0)
        );
    }

    #[test]
    fn a_fancy_client_is_recorded_as_such() {
        let mut state = state();
        let _ = VersionHandler.handle(
            &mut state,
            ConnId(1),
            ControlMessage::Version(tcp::Version {
                version_v2: Some(Version::new(1, 6, 0).encode_v2()),
                fancy_version: Some(Version::new(0, 3, 0).encode_v2()),
                ..Default::default()
            }),
        );
        assert!(state
            .connection(ConnId(1))
            .expect("connection")
            .fancy_version
            .is_some());
    }

    #[test]
    fn a_version_message_produces_no_reply() {
        // murmur sends its Version unprompted on connect, not in response.
        let mut state = state();
        let fx = VersionHandler.handle(
            &mut state,
            ConnId(1),
            ControlMessage::Version(tcp::Version::default()),
        );
        assert!(fx.is_empty());
    }

    #[test]
    fn the_handler_is_reachable_before_authentication() {
        assert_eq!(VersionHandler.access(), Access::Anonymous);
    }
}
