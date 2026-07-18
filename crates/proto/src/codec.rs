//! Mumble TCP framing: `[type:u16 BE][length:u32 BE][payload]`.
//!
//! # Hostile input
//!
//! Every function here runs on bytes from an unauthenticated peer. The two
//! rules are:
//!
//! 1. **Bound before you allocate.** The declared length is checked against
//!    [`MAX_PAYLOAD_SIZE`] before a single byte is reserved.
//! 2. **Never panic.** Malformed protobuf yields [`Error::Decode`], which the
//!    caller turns into a disconnect, not an abort.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message as _;

use crate::error::{Error, Result};
use crate::message::{ControlMessage, TcpMessageType};
use crate::proto::tcp;

/// Frame header: 2 bytes type + 4 bytes big-endian length.
pub const HEADER_SIZE: usize = 6;

/// Largest payload accepted from a peer, in bytes.
///
/// Matches the client's limit. `imagemessagelength` in the e2e fixture is 10 MiB
/// of *image data*, which arrives base64-embedded in HTML and so can legitimately
/// exceed 8 MiB. Making the bound the configured
/// `max(textmessagelength, imagemessagelength)` needs config wired through to
/// the connection, which it is not; a fixed bound is the conservative half of
/// that, since it can only refuse a message the configuration would have
/// allowed, never accept one it would have refused.
pub const MAX_PAYLOAD_SIZE: u32 = 8 * 1024 * 1024;

/// Encode a message into a framed buffer ready for the wire.
///
/// Returns `Bytes` rather than `Vec<u8>` so the server can encode a broadcast
/// once and hand a cheap clone to every recipient — see the fan-out rules in
/// `PORTING-PLAN.md` §2.3.
#[must_use]
pub fn encode(msg: &ControlMessage) -> Bytes {
    let payload = serialize(msg);
    let mut buf = BytesMut::with_capacity(HEADER_SIZE + payload.len());
    buf.put_u16(msg.type_id());
    buf.put_u32(payload.len() as u32);
    buf.put_slice(&payload);
    buf.freeze()
}

/// Try to decode one complete frame from `buf`.
///
/// Returns `Ok(None)` when more bytes are needed; the caller should read more
/// and try again. On `Ok(Some(_))` the frame has been consumed from `buf`.
pub fn decode(buf: &mut BytesMut) -> Result<Option<ControlMessage>> {
    // `split_first_chunk` folds the length check into the read, so the header
    // fields come from arrays the compiler knows are the right size rather than
    // from indexing that a future edit to the bound above could leave dangling.
    let Some((type_id, rest)) = buf.split_first_chunk::<2>() else {
        return Ok(None);
    };
    let Some((payload_len, _)) = rest.split_first_chunk::<4>() else {
        return Ok(None);
    };
    let type_id = u16::from_be_bytes(*type_id);
    let payload_len = u32::from_be_bytes(*payload_len);

    // Rule 1: bound before allocating. Checked against the declared length, so a
    // peer claiming a 4 GiB frame is rejected without reserving anything.
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(Error::PayloadTooLarge(payload_len));
    }

    let total = HEADER_SIZE + payload_len as usize;
    if buf.len() < total {
        return Ok(None);
    }

    buf.advance(HEADER_SIZE);
    let payload = buf.split_to(payload_len as usize).freeze();

    deserialize(type_id, payload).map(Some)
}

fn serialize(msg: &ControlMessage) -> Bytes {
    use ControlMessage::*;
    match msg {
        // UDPTunnel carries a raw UDP packet, not protobuf.
        UdpTunnel(raw) => raw.clone(),
        Opaque { payload, .. } => payload.clone(),

        Version(m) => m.encode_to_vec().into(),
        Authenticate(m) => m.encode_to_vec().into(),
        Ping(m) => m.encode_to_vec().into(),
        Reject(m) => m.encode_to_vec().into(),
        ServerSync(m) => m.encode_to_vec().into(),
        ChannelRemove(m) => m.encode_to_vec().into(),
        ChannelState(m) => m.encode_to_vec().into(),
        UserRemove(m) => m.encode_to_vec().into(),
        UserState(m) => m.encode_to_vec().into(),
        BanList(m) => m.encode_to_vec().into(),
        TextMessage(m) => m.encode_to_vec().into(),
        PermissionDenied(m) => m.encode_to_vec().into(),
        Acl(m) => m.encode_to_vec().into(),
        QueryUsers(m) => m.encode_to_vec().into(),
        CryptSetup(m) => m.encode_to_vec().into(),
        ContextActionModify(m) => m.encode_to_vec().into(),
        ContextAction(m) => m.encode_to_vec().into(),
        UserList(m) => m.encode_to_vec().into(),
        VoiceTarget(m) => m.encode_to_vec().into(),
        PermissionQuery(m) => m.encode_to_vec().into(),
        CodecVersion(m) => m.encode_to_vec().into(),
        UserStats(m) => m.encode_to_vec().into(),
        RequestBlob(m) => m.encode_to_vec().into(),
        ServerConfig(m) => m.encode_to_vec().into(),
        SuggestConfig(m) => m.encode_to_vec().into(),
        PluginDataTransmission(m) => m.encode_to_vec().into(),
    }
}

/// A frame that has been split from the stream but not decoded.
///
/// This is what the gateway works in: it reads the type from the framing, looks
/// up a route and forwards the payload verbatim, never linking a service's
/// generated stubs (`docs/ARCHITECTURE.md` §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    /// The wire type from the header.
    pub type_id: u16,
    /// The payload, exactly as it arrived.
    pub payload: Bytes,
}

/// Frame `payload` under `type_id` without knowing what it is.
#[must_use]
pub fn frame(type_id: u16, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER_SIZE + payload.len());
    buf.put_u16(type_id);
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
    buf.freeze()
}

/// Just the header, for a payload written separately.
///
/// The gateway keeps the two apart so one encoded payload can be shared by
/// every recipient of a broadcast while the header varies per connection
/// (`PROTOCOL-REDESIGN.md` §4, Z4 and §5, S2). `seq` is `Some` only for a peer
/// that negotiated resume, and `len` then covers the sequence as well as the
/// payload — a reader takes `len` bytes after the header either way, and the
/// eight it must skip first are the ones it asked for.
#[must_use]
pub fn header(type_id: u16, payload_len: usize, seq: Option<u64>) -> Bytes {
    let extra = if seq.is_some() { 8 } else { 0 };
    let mut buf = BytesMut::with_capacity(HEADER_SIZE + extra);
    buf.put_u16(type_id);
    buf.put_u32((payload_len + extra) as u32);
    if let Some(seq) = seq {
        buf.put_u64(seq);
    }
    buf.freeze()
}

/// Split one complete frame from `buf` without decoding its payload.
///
/// Returns `Ok(None)` when more bytes are needed. The length bound is checked
/// against [`MAX_PAYLOAD_SIZE`] before anything is reserved, because this runs
/// on bytes from an unauthenticated peer.
pub fn decode_raw(buf: &mut BytesMut) -> Result<Option<RawFrame>> {
    // As in `decode`: the bound and the read are one operation.
    let Some((type_id, rest)) = buf.split_first_chunk::<2>() else {
        return Ok(None);
    };
    let Some((payload_len, _)) = rest.split_first_chunk::<4>() else {
        return Ok(None);
    };
    let type_id = u16::from_be_bytes(*type_id);
    let payload_len = u32::from_be_bytes(*payload_len);
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(Error::PayloadTooLarge(payload_len));
    }
    let total = HEADER_SIZE + payload_len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    buf.advance(HEADER_SIZE);
    Ok(Some(RawFrame {
        type_id,
        payload: buf.split_to(payload_len as usize).freeze(),
    }))
}

fn deserialize(type_id: u16, payload: Bytes) -> Result<ControlMessage> {
    let Some(kind) = TcpMessageType::from_id(type_id) else {
        // Not decoded by this build - keep the frame intact so the stream stays
        // in sync. See `ControlMessage::Opaque`.
        return Ok(ControlMessage::Opaque { type_id, payload });
    };

    // UDPTunnel is raw bytes, so it short-circuits before the protobuf path.
    if kind == TcpMessageType::UdpTunnel {
        return Ok(ControlMessage::UdpTunnel(payload));
    }

    decode_proto(kind, &payload).map_err(|source| Error::Decode { type_id, source })
}

/// Decode the protobuf body for a known message type.
///
/// Split out from [`deserialize`] so the framing concerns (length bounds, raw
/// passthrough, unknown ids) stay readable next to a match this wide.
fn decode_proto(
    kind: TcpMessageType,
    payload: &[u8],
) -> std::result::Result<ControlMessage, prost::DecodeError> {
    use TcpMessageType as T;
    Ok(match kind {
        // Handled by the caller; listed so the match stays exhaustive and a new
        // raw-payload message type cannot be added without a decision here.
        T::UdpTunnel => ControlMessage::UdpTunnel(Bytes::copy_from_slice(payload)),

        T::Version => ControlMessage::Version(tcp::Version::decode(payload)?),
        T::Authenticate => ControlMessage::Authenticate(tcp::Authenticate::decode(payload)?),
        T::Ping => ControlMessage::Ping(tcp::Ping::decode(payload)?),
        T::Reject => ControlMessage::Reject(tcp::Reject::decode(payload)?),
        T::ServerSync => ControlMessage::ServerSync(tcp::ServerSync::decode(payload)?),
        T::ChannelRemove => ControlMessage::ChannelRemove(tcp::ChannelRemove::decode(payload)?),
        T::ChannelState => ControlMessage::ChannelState(tcp::ChannelState::decode(payload)?),
        T::UserRemove => ControlMessage::UserRemove(tcp::UserRemove::decode(payload)?),
        T::UserState => ControlMessage::UserState(tcp::UserState::decode(payload)?),
        T::BanList => ControlMessage::BanList(tcp::BanList::decode(payload)?),
        T::TextMessage => ControlMessage::TextMessage(tcp::TextMessage::decode(payload)?),
        T::PermissionDenied => {
            ControlMessage::PermissionDenied(tcp::PermissionDenied::decode(payload)?)
        }
        T::Acl => ControlMessage::Acl(tcp::Acl::decode(payload)?),
        T::QueryUsers => ControlMessage::QueryUsers(tcp::QueryUsers::decode(payload)?),
        T::CryptSetup => ControlMessage::CryptSetup(tcp::CryptSetup::decode(payload)?),
        T::ContextActionModify => {
            ControlMessage::ContextActionModify(tcp::ContextActionModify::decode(payload)?)
        }
        T::ContextAction => ControlMessage::ContextAction(tcp::ContextAction::decode(payload)?),
        T::UserList => ControlMessage::UserList(tcp::UserList::decode(payload)?),
        T::VoiceTarget => ControlMessage::VoiceTarget(tcp::VoiceTarget::decode(payload)?),
        T::PermissionQuery => {
            ControlMessage::PermissionQuery(tcp::PermissionQuery::decode(payload)?)
        }
        T::CodecVersion => ControlMessage::CodecVersion(tcp::CodecVersion::decode(payload)?),
        T::UserStats => ControlMessage::UserStats(tcp::UserStats::decode(payload)?),
        T::RequestBlob => ControlMessage::RequestBlob(tcp::RequestBlob::decode(payload)?),
        T::ServerConfig => ControlMessage::ServerConfig(tcp::ServerConfig::decode(payload)?),
        T::SuggestConfig => ControlMessage::SuggestConfig(tcp::SuggestConfig::decode(payload)?),
        T::PluginDataTransmission => {
            ControlMessage::PluginDataTransmission(tcp::PluginDataTransmission::decode(payload)?)
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_sequenced_header_puts_the_sequence_inside_the_length() {
        // The layout the client's decoder strips. `len` covers the sequence as
        // well as the payload, so a reader takes `len` bytes after the header
        // either way and the eight it skips first are the ones it asked for —
        // which is what keeps an unsequenced peer's parsing untouched.
        let header = header(9, 100, Some(0x0102_0304_0506_0708));
        assert_eq!(header.len(), HEADER_SIZE + 8);
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 9);
        assert_eq!(
            u32::from_be_bytes([header[2], header[3], header[4], header[5]]),
            108,
            "the length must cover the sequence, or the reader stops short"
        );
        assert_eq!(&header[6..], &0x0102_0304_0506_0708_u64.to_be_bytes());
    }

    #[test]
    fn an_unsequenced_header_is_byte_identical_to_the_joined_frame() {
        // The split exists so one payload can be shared by every recipient
        // (Z4); it must not change what a peer that never asked for a sequence
        // sees on the wire.
        let payload = b"opaque";
        let joined = frame(11, payload);
        let split = header(11, payload.len(), None);
        assert_eq!(&joined[..HEADER_SIZE], &split[..]);
        assert_eq!(&joined[HEADER_SIZE..], payload);
    }

    use super::*;

    fn roundtrip(msg: &ControlMessage) -> ControlMessage {
        let framed = encode(msg);
        let mut buf = BytesMut::from(&framed[..]);
        let decoded = decode(&mut buf)
            .expect("frame must decode")
            .expect("frame must be complete");
        assert!(buf.is_empty(), "decode must consume the whole frame");
        decoded
    }

    #[test]
    fn a_raw_frame_round_trips_without_the_payload_being_understood() {
        // The gateway's whole job: type from the framing, payload untouched.
        let payload = Bytes::from_static(b"a service's private protobuf");
        let mut buf = BytesMut::from(&frame(1006, &payload)[..]);
        let raw = decode_raw(&mut buf)
            .expect("well-formed frame")
            .expect("complete frame");
        assert_eq!(raw.type_id, 1006);
        assert_eq!(raw.payload, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_raw_frame_is_bounded_before_anything_is_allocated() {
        let mut buf = BytesMut::new();
        buf.put_u16(1006);
        buf.put_u32(MAX_PAYLOAD_SIZE + 1);
        assert!(matches!(
            decode_raw(&mut buf),
            Err(Error::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn version_roundtrips() {
        let msg = ControlMessage::Version(tcp::Version {
            version_v2: Some(0x0001_0006_0000),
            release: Some("Starling".into()),
            ..Default::default()
        });
        match roundtrip(&msg) {
            ControlMessage::Version(v) => {
                assert_eq!(v.version_v2, Some(0x0001_0006_0000));
                assert_eq!(v.release.as_deref(), Some("Starling"));
            }
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn udp_tunnel_payload_is_not_protobuf_decoded() {
        // A raw UDP packet is very unlikely to be valid protobuf; if the codec
        // tried to decode it, this would fail rather than round-trip.
        let raw = Bytes::from_static(&[0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
        match roundtrip(&ControlMessage::UdpTunnel(raw.clone())) {
            ControlMessage::UdpTunnel(got) => assert_eq!(got, raw),
            other => panic!("expected UdpTunnel, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_id_is_carried_opaquely() {
        // 120 = WebRtcSignal, a Fancy extension this build does not decode.
        let payload = Bytes::from_static(b"fancy payload");
        let msg = ControlMessage::Opaque {
            type_id: 120,
            payload: payload.clone(),
        };
        match roundtrip(&msg) {
            ControlMessage::Opaque {
                type_id,
                payload: got,
            } => {
                assert_eq!(type_id, 120);
                assert_eq!(got, payload);
            }
            other => panic!("expected Opaque, got {other:?}"),
        }
    }

    #[test]
    fn partial_frames_need_more_data() {
        let framed = encode(&ControlMessage::Ping(tcp::Ping {
            timestamp: Some(42),
            ..Default::default()
        }));

        // Every strict prefix must ask for more rather than erroring.
        for cut in 0..framed.len() {
            let mut buf = BytesMut::from(&framed[..cut]);
            assert!(
                matches!(decode(&mut buf), Ok(None)),
                "prefix of {cut} bytes should be incomplete, not an error"
            );
        }
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let mut buf = BytesMut::new();
        buf.put_u16(TcpMessageType::TextMessage.id());
        buf.put_u32(MAX_PAYLOAD_SIZE + 1);
        // Deliberately no payload: a correct implementation rejects on the
        // header alone and never waits for (or reserves) the claimed bytes.
        assert!(matches!(
            decode(&mut buf),
            Err(Error::PayloadTooLarge(len)) if len == MAX_PAYLOAD_SIZE + 1
        ));
    }

    #[test]
    fn malformed_protobuf_errors_without_panicking() {
        let mut buf = BytesMut::new();
        buf.put_u16(TcpMessageType::Authenticate.id());
        buf.put_u32(3);
        // Field header claiming a length-delimited field that runs off the end.
        buf.put_slice(&[0x0A, 0xFF, 0x01]);
        assert!(matches!(decode(&mut buf), Err(Error::Decode { type_id, .. }) if type_id == 2));
    }

    #[test]
    fn two_frames_decode_in_order_from_one_buffer() {
        let mut buf = BytesMut::new();
        buf.put_slice(&encode(&ControlMessage::Ping(tcp::Ping {
            timestamp: Some(1),
            ..Default::default()
        })));
        buf.put_slice(&encode(&ControlMessage::Ping(tcp::Ping {
            timestamp: Some(2),
            ..Default::default()
        })));

        for expected in [1_u64, 2] {
            match decode(&mut buf) {
                Ok(Some(ControlMessage::Ping(p))) => assert_eq!(p.timestamp, Some(expected)),
                other => panic!("expected Ping({expected}), got {other:?}"),
            }
        }
        assert!(buf.is_empty());
    }
}
