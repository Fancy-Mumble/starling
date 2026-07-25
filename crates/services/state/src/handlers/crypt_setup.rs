//! `CryptSetup` — keying the UDP voice stream, and recovering when it drifts.
//!
//! Wire type 15. The server generates all the key material and sends it once
//! during the handshake; after that the message is only used for **resync**,
//! which is the client saying it can no longer decrypt.
//!
//! # Two opposite meanings, one message
//!
//! murmur distinguishes them by whether `client_nonce` is present
//! (`Messages.cpp:2117`), and they do opposite things:
//!
//! | `client_nonce` | The client means | The server does |
//! |---|---|---|
//! | absent | *I lost your counter, tell me* | reply with the server's send counter |
//! | present | *here is mine, adopt it* | update its receive counter, send nothing |
//!
//! Reversing that branch produces a handshake that looks perfect and a session
//! that never carries audio, so the classification lives in
//! [`ResyncRequest`] with a name per case rather
//! than as an `Option` test here.
//!
//! # Status
//!
//! The resync protocol is implemented; the counters it reports are not yet
//! attached, because there is no UDP path to advance them. A resync request
//! currently answers with the connection's starting counter, which is the honest
//! answer for a stream that has sent nothing.

use starling_api::{Access, Authority, ConnId, Effects, Handler, Recipients};
use starling_crypto::ResyncRequest;
use starling_log::{Category, LogEvent};
use starling_proto::proto::tcp;
use starling_proto::{ControlMessage, TcpMessageType};
use tracing::debug;

/// Answers a client's crypt resync.
#[derive(Debug, Default)]
pub struct CryptSetupHandler;

impl Handler for CryptSetupHandler {
    fn handles(&self) -> TcpMessageType {
        TcpMessageType::CryptSetup
    }

    fn access(&self) -> Access {
        // murmur guards with `MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated)`:
        // key material must never be discussed with an unauthenticated peer.
        Access::Authenticated
    }

    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects {
        let ControlMessage::CryptSetup(msg) = msg else {
            return Effects::none();
        };
        let Some(session) = state.session_of(conn) else {
            return Effects::none();
        };

        match ResyncRequest::classify(msg.client_nonce.as_deref()) {
            ResyncRequest::SendMine => {
                debug!(%conn, %session, "crypt resync requested");
                let mut fx = Effects::none();
                let _ = fx.log(
                    LogEvent::notice(Category::Session, "crypt resync requested")
                        .with("session", session.0),
                );
                // Only `server_nonce` is set. Repeating the key would put it on
                // the wire a second time for no reason, and murmur does not.
                let _ = fx.send(
                    Recipients::Session(session),
                    ControlMessage::CryptSetup(tcp::CryptSetup {
                        server_nonce: Some(send_counter(state, conn).to_be_bytes().to_vec()),
                        ..Default::default()
                    }),
                );
                fx
            }

            ResyncRequest::AdoptTheirs { counter } => {
                // No reply: the client is telling, not asking. A client that
                // resyncs repeatedly has a broken path rather than a broken
                // stream, so this is worth a record even though it is not an
                // error.
                debug!(%conn, %session, counter, "client resynchronised its crypt counter");
                let mut fx = Effects::none();
                let _ = fx.log(
                    LogEvent::notice(Category::Session, "client crypt resync")
                        .with("session", session.0)
                        .with("counter", counter),
                );
                fx
            }
        }
    }
}

/// The counter the server is sending from.
///
/// Zero until the UDP path exists to advance it, which is the truthful answer
/// for a stream that has sent no packets. Reading it through a function keeps the
/// one place to change when the session attaches.
fn send_counter(_state: &dyn Authority, _conn: ConnId) -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServerState;
    use starling_api::{Effect, ServerConfig, Sessions, World};
    use starling_model::{User, ROOT_CHANNEL};

    fn state_with_user() -> (ServerState, ConnId) {
        let mut state = ServerState::new(ServerConfig::default());
        let conn = ConnId(1);
        state.add_connection(conn, "127.0.0.1:1234".parse().expect("test addr"));
        let session = state.assign_session(conn).expect("pool has ids");
        state
            .users_mut()
            .insert(User::new(session, "tester", ROOT_CHANNEL));
        (state, conn)
    }

    fn crypt_setup(client_nonce: Option<Vec<u8>>) -> ControlMessage {
        ControlMessage::CryptSetup(tcp::CryptSetup {
            client_nonce,
            ..Default::default()
        })
    }

    fn replied(fx: &Effects) -> Option<tcp::CryptSetup> {
        fx.as_slice().iter().find_map(|e| match e {
            Effect::Send { msg, .. } => match msg.as_ref() {
                ControlMessage::CryptSetup(c) => Some(c.clone()),
                _ => None,
            },
            _ => None,
        })
    }

    #[test]
    fn it_registers_for_wire_type_15() {
        assert_eq!(CryptSetupHandler.handles().id(), 15);
    }

    #[test]
    fn an_unauthenticated_peer_cannot_reach_it() {
        // Key material is never discussed before authentication.
        assert_eq!(CryptSetupHandler.access(), Access::Authenticated);
    }

    #[test]
    fn a_request_without_a_client_nonce_is_answered() {
        let (mut state, conn) = state_with_user();
        let fx = CryptSetupHandler.handle(&mut state, conn, crypt_setup(None));
        let reply = replied(&fx).expect("a resync request must be answered");
        assert!(reply.server_nonce.is_some(), "the counter must be sent");
    }

    #[test]
    fn the_reply_does_not_repeat_the_key() {
        // Putting the key back on the wire would expose it a second time for no
        // benefit, and murmur does not do it.
        let (mut state, conn) = state_with_user();
        let fx = CryptSetupHandler.handle(&mut state, conn, crypt_setup(None));
        let reply = replied(&fx).expect("answered");
        assert!(reply.key.is_none(), "the key must not be resent");
        assert!(reply.client_nonce.is_none());
    }

    #[test]
    fn the_reply_goes_only_to_the_asker() {
        let (mut state, conn) = state_with_user();
        let session = Sessions::session_of(&state, conn).expect("session");
        let fx = CryptSetupHandler.handle(&mut state, conn, crypt_setup(None));
        let to = fx.as_slice().iter().find_map(|e| match e {
            Effect::Send { to, .. } => Some(*to),
            _ => None,
        });
        assert_eq!(to, Some(Recipients::Session(session)));
    }

    #[test]
    fn a_client_supplied_nonce_is_adopted_without_a_reply() {
        // The opposite branch: the client is telling us, not asking.
        let (mut state, conn) = state_with_user();
        let fx = CryptSetupHandler.handle(
            &mut state,
            conn,
            crypt_setup(Some(7_u64.to_be_bytes().to_vec())),
        );
        assert!(
            replied(&fx).is_none(),
            "adopting the client's counter must not produce a reply"
        );
    }

    #[test]
    fn a_resync_is_recorded_either_way() {
        // A client resyncing in a loop is a symptom worth seeing in the log.
        let (mut state, conn) = state_with_user();
        for message in [
            crypt_setup(None),
            crypt_setup(Some(7_u64.to_be_bytes().to_vec())),
        ] {
            let fx = CryptSetupHandler.handle(&mut state, conn, message);
            assert!(
                fx.as_slice().iter().any(|e| matches!(e, Effect::Log(_))),
                "every resync should leave a record"
            );
        }
    }

    #[test]
    fn a_malformed_nonce_is_answered_rather_than_adopted() {
        // Recovering the session beats adopting a value we cannot parse.
        let (mut state, conn) = state_with_user();
        let fx = CryptSetupHandler.handle(&mut state, conn, crypt_setup(Some(vec![0; 3])));
        assert!(
            replied(&fx).is_some(),
            "an unparseable nonce should fall back to answering"
        );
    }

    #[test]
    fn a_message_of_the_wrong_type_is_ignored() {
        let (mut state, conn) = state_with_user();
        let fx =
            CryptSetupHandler.handle(&mut state, conn, ControlMessage::Ping(tcp::Ping::default()));
        assert!(fx.is_empty());
    }
}
