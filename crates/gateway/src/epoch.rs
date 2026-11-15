//! The one field the gateway reads inside a client's payload, and what it
//! decides.
//!
//! The gateway routes on the frame header and parses no payload, with this one
//! exception: `Version.fancy_protocol`, the peer's wire epoch
//! (`docs/PROTOCOL-COMPATIBILITY.md` 2a). It is read here rather than told by
//! session-lifecycle because the epoch decides what the gateway itself may
//! write, and the gateway is the only component that sees a connection's frames
//! in order. A peer that asks for the livery without joining pipelines
//! `Version` and the question; the two go to different services, and nothing
//! orders session-lifecycle's word on the first before server-config's answer
//! to the second (`docs/ARCHITECTURE.md` §1).
//!
//! After `SessionUp`, session-lifecycle's record of the same field is the one
//! in force, exactly as before this was read here.

use prost::Message as _;
use starling_proto::TcpMessageType;
use starling_proto::proto::tcp;
use starling_proto_fancy::types::{FANCY_PROTOCOL_EPOCH, SERVICE_BASE, ServiceKind};

/// The wire type of `Version`, the only frame [`announced`] reads.
pub(crate) const VERSION: u16 = TcpMessageType::Version as u16;

/// The service outer types that may be written to a connection with no
/// session yet.
///
/// Only what is fit for somebody who has proved nothing. Most services answer
/// a sessionless frame with something that is not (signed GIF links, minted
/// invites, the plugin list), and until this list existed only the epoch,
/// unannounced before `SessionUp`, kept it off the wire. server-config is here
/// because it answers a sessionless connection with the livery and nothing
/// else (`starling_server_config`, `frame`), which is presentation a client
/// renders before it has authenticated anything (`starling_runtime::livery`).
pub(crate) const BEFORE_SESSION: &[u16] = &[ServiceKind::ServerConfig.outer_type()];

/// Whether a frame of `type_id` from a connection with no session is charged
/// to its route's bucket even though the type is not one murmur rate-limits.
///
/// What may be *answered* before a session is what is worth asking for over
/// and over: the livery is up to about 600 KiB for a few bytes of question.
/// One question per connection, and a retry or two, fit the burst.
pub(crate) fn charged_before_session(type_id: u16) -> bool {
    BEFORE_SESSION.contains(&type_id)
}

/// The epoch a `Version` payload announces.
///
/// 0 when the field is absent, as session-lifecycle reads it, and 0 when the
/// payload cannot be decoded at all: a peer whose `Version` is garbage has not
/// said it can read a service outer type.
pub(crate) fn announced(version: &[u8]) -> u32 {
    tcp::Version::decode(version).map_or(0, |version| version.fancy_protocol.unwrap_or_default())
}

/// Whether a frame of `type_id` may be written to a peer on `epoch`.
///
/// Upstream types always: they are frozen, and they are the whole conversation
/// with a stock Mumble client. A service outer type only to a peer on our
/// epoch, and before it has a session only if [`BEFORE_SESSION`] names it.
pub(crate) fn may_write(type_id: u16, epoch: u32, has_session: bool) -> bool {
    type_id < SERVICE_BASE
        || (epoch == FANCY_PROTOCOL_EPOCH && (has_session || BEFORE_SESSION.contains(&type_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVERY: u16 = ServiceKind::ServerConfig.outer_type();
    const TEXT: u16 = ServiceKind::Text.outer_type();

    fn version(fancy_protocol: Option<u32>) -> Vec<u8> {
        tcp::Version {
            release: Some("probe".to_owned()),
            fancy_protocol,
            ..tcp::Version::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn a_version_announces_the_epoch_it_carries() {
        assert_eq!(announced(&version(Some(FANCY_PROTOCOL_EPOCH))), 1);
        assert_eq!(announced(&version(Some(7))), 7);
    }

    #[test]
    fn a_version_without_the_field_announces_epoch_zero() {
        assert_eq!(announced(&version(None)), 0);
        assert_eq!(announced(&[]), 0, "an empty Version is a valid one");
    }

    #[test]
    fn a_malformed_version_announces_epoch_zero() {
        // A varint field cut off mid-value, and bytes that are no field at all.
        assert_eq!(announced(&[0x38, 0x81]), 0);
        assert_eq!(announced(&[0xff; 16]), 0);
    }

    #[test]
    fn before_a_session_only_the_livery_reaches_a_peer_on_our_epoch() {
        assert!(may_write(LIVERY, FANCY_PROTOCOL_EPOCH, false));
        // Every assigned outer type and well past them: a service added later
        // is withheld until somebody decides it belongs on the list.
        let allowed: Vec<u16> = (SERVICE_BASE..SERVICE_BASE + 100)
            .filter(|type_id| may_write(*type_id, FANCY_PROTOCOL_EPOCH, false))
            .collect();
        assert_eq!(allowed, vec![LIVERY]);
    }

    #[test]
    fn a_peer_on_another_epoch_gets_no_service_frame_with_or_without_a_session() {
        for has_session in [false, true] {
            assert!(!may_write(LIVERY, 0, has_session));
            assert!(!may_write(TEXT, 0, has_session));
            assert!(!may_write(LIVERY, FANCY_PROTOCOL_EPOCH + 1, has_session));
        }
    }

    #[test]
    fn upstream_types_reach_everybody() {
        for (epoch, has_session) in [(0, false), (0, true), (1, false), (1, true)] {
            assert!(may_write(0, epoch, has_session));
            assert!(may_write(SERVICE_BASE - 1, epoch, has_session));
        }
    }

    #[test]
    fn with_a_session_every_service_type_reaches_a_peer_on_our_epoch() {
        assert!(may_write(LIVERY, FANCY_PROTOCOL_EPOCH, true));
        assert!(may_write(TEXT, FANCY_PROTOCOL_EPOCH, true));
    }
}
