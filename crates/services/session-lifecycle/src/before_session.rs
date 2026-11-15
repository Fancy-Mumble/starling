//! What this service handles from a connection that has not authenticated.
//!
//! Every other service handles nothing from one (`plane::dispatch`). This one
//! is the handshake, so it must take the frames a client sends before it has a
//! session, and only those:
//!
//! * `Version`, `Authenticate` and `Ping`, the handshake itself;
//! * a `UserState` carrying nothing but the client's own mute and deafen,
//!   which the Fancy client sends beside `Authenticate` without waiting for
//!   `ServerSync` (`mumble-tauri`, `state/connection.rs`, the initial
//!   self-deaf). It is kept on the connection and applied at login;
//! * the `Hello` and `Resume` of the session envelope, which negotiate the
//!   connection itself rather than act as anybody.
//!
//! Anything else from such a peer (moving, listening, registering, statistics,
//! another user's state) needs somebody to act as, and there is nobody.

use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::fancy::session::{SessionEnvelope, session_envelope};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::Inbound;

use crate::{AUTHENTICATE, PING, USER_STATE, VERSION};

/// Whether `inbound`, from a connection with no session, is the handshake's.
#[must_use]
pub fn handled(inbound: &Inbound) -> bool {
    match inbound.type_id {
        VERSION | AUTHENTICATE | PING => true,
        USER_STATE => tcp::UserState::decode(inbound.payload.as_slice())
            .is_ok_and(|state| is_own_flags_only(&state)),
        id if id == ServiceKind::SessionLifecycle.outer_type() => {
            SessionEnvelope::decode(inbound.payload.as_slice()).is_ok_and(|envelope| {
                matches!(
                    envelope.body,
                    Some(session_envelope::Body::Hello(_) | session_envelope::Body::Resume(_))
                )
            })
        }
        _ => false,
    }
}

/// Whether a `UserState` says nothing but the sender's own mute and deafen.
pub fn is_own_flags_only(state: &tcp::UserState) -> bool {
    let flags = tcp::UserState {
        self_mute: state.self_mute,
        self_deaf: state.self_deaf,
        ..tcp::UserState::default()
    };
    *state == flags && (state.self_mute.is_some() || state.self_deaf.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(type_id: u16, payload: Vec<u8>) -> Inbound {
        Inbound {
            conn: 1,
            session: 0,
            type_id,
            payload,
            gateway: "gw".to_owned(),
            scope: 1,
        }
    }

    fn state(state: &tcp::UserState) -> Inbound {
        frame(USER_STATE, state.encode_to_vec())
    }

    fn envelope(body: session_envelope::Body) -> Inbound {
        frame(
            ServiceKind::SessionLifecycle.outer_type(),
            SessionEnvelope { body: Some(body) }.encode_to_vec(),
        )
    }

    #[test]
    fn the_handshake_is_handled_before_a_session() {
        for type_id in [VERSION, AUTHENTICATE, PING] {
            assert!(handled(&frame(type_id, Vec::new())), "{type_id}");
        }
        assert!(handled(&envelope(session_envelope::Body::Hello(
            Default::default()
        ))));
        assert!(handled(&envelope(session_envelope::Body::Resume(
            Default::default()
        ))));
    }

    #[test]
    fn a_clients_own_deafen_sent_beside_authenticate_is_handled() {
        assert!(handled(&state(&tcp::UserState {
            self_deaf: Some(true),
            self_mute: Some(true),
            ..Default::default()
        })));
        assert!(handled(&state(&tcp::UserState {
            self_mute: Some(false),
            ..Default::default()
        })));
    }

    #[test]
    fn nothing_that_acts_as_somebody_is_handled_before_a_session() {
        // The listener volume is the one that once left a session-0 record in
        // the view; the rest need a user just as much.
        let acting = [
            tcp::UserState {
                listening_volume_adjustment: vec![tcp::user_state::VolumeAdjustment {
                    listening_channel: Some(0),
                    volume_adjustment: Some(0.5),
                }],
                ..Default::default()
            },
            tcp::UserState {
                listening_channel_add: vec![0],
                ..Default::default()
            },
            tcp::UserState {
                channel_id: Some(0),
                ..Default::default()
            },
            tcp::UserState {
                session: Some(3),
                mute: Some(true),
                ..Default::default()
            },
            tcp::UserState {
                self_deaf: Some(true),
                comment: Some("hello".to_owned()),
                ..Default::default()
            },
            tcp::UserState::default(),
        ];
        for acting in &acting {
            assert!(!handled(&state(acting)), "{acting:?}");
        }
        for type_id in [crate::CRYPT_SETUP, crate::USER_STATS, 13, 11] {
            assert!(!handled(&frame(type_id, Vec::new())), "{type_id}");
        }
        assert!(!handled(&frame(USER_STATE, vec![0xff, 0xff])), "garbage");
        assert!(!handled(&envelope(session_envelope::Body::GreetingWant(
            Default::default()
        ))));
        assert!(!handled(&envelope(session_envelope::Body::Subscribe(
            Default::default()
        ))));
    }
}
