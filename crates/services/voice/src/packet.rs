//! The audio wire format, in both of its versions.
//!
//! Mumble changed its audio encoding in 1.5: before that a hand-rolled binary
//! layout, after it protobuf. Both are still on the wire, because a 1.4 client
//! connecting today speaks the old one and always will.
//!
//! # One decoded form, two codecs
//!
//! [`AudioPacket`] is what the server actually works with. [`AudioCodec`] is the
//! strategy that gets it to and from bytes, and [`codec_for`] picks the
//! implementation from the peer's negotiated [`UdpFormat`], decided once at
//! handshake, not sniffed per packet.
//!
//! Sniffing would be the obvious shortcut: the legacy header's type field is 4
//! for Opus and the protobuf prefix is 0 or 1, so they look distinguishable. They
//! are not, reliably, legacy type 0 is CELT alpha, which collides with protobuf
//! Audio. Guessing per packet would mean a peer could switch formats mid-stream,
//! and the server would follow it.
//!
//! # Why the server parses audio at all
//!
//! It could relay opaque bytes, and for the payload it very nearly does, the
//! Opus data is never decoded. But the target field decides who receives the
//! frame, and the sender field has to be *overwritten* with the true session on
//! the way out, or any peer could impersonate any other by writing someone
//! else's id. Those two fields are the whole reason for this module.

use crate::ports::SessionId;
use bytes::Bytes;
use prost::Message as _;
use starling_gate::UdpFormat;
use starling_proto::proto::udp as mumble_udp;

use crate::varint::{Reader, VarintError, Writer};

/// The largest audio payload accepted from a peer.
///
/// A Mumble frame is at most 10 ms of Opus at 96 kbit/s plus slack; upstream
/// caps the whole datagram at 1024 bytes. Enforced at parse rather than at
/// allocation, so a hostile length field is refused before anything reserves
/// memory for it.
pub const MAX_AUDIO_BYTES: usize = 1024;

/// The legacy header's audio-type field, in the top three bits.
///
/// Only the values that can appear in a real packet are named. Everything else
/// is refused rather than mapped to a default: an unknown type means the rest of
/// the packet has an unknown layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyType {
    /// Type 1: a legacy UDP ping, four bytes of opaque timestamp.
    Ping,
    /// Type 4: Opus, the only voice codec any current client sends.
    Opus,
}

impl LegacyType {
    /// The wire value.
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        match self {
            Self::Ping => 1,
            Self::Opus => 4,
        }
    }

    /// Decode the top three bits of a legacy header byte.
    const fn decode(raw: u8) -> Option<Self> {
        match raw >> 5 {
            1 => Some(Self::Ping),
            4 => Some(Self::Opus),
            // 0 and 3 are CELT, 2 is Speex. All three were removed from Mumble
            // in 1.4; a client sending one cannot be served, and pretending to
            // understand it would relay undecodable audio to everyone else.
            _ => None,
        }
    }
}

/// The protobuf prefix byte.
const PROTOBUF_AUDIO: u8 = 0;
const PROTOBUF_PING: u8 = 1;

/// A datagram could not be understood.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// The datagram ended mid-field.
    #[error("truncated packet: {0}")]
    Truncated(#[from] VarintError),

    /// Zero bytes, which not even a header fits in.
    #[error("empty packet")]
    Empty,

    /// A legacy audio type this server cannot serve.
    #[error("unsupported legacy audio type {0}")]
    UnsupportedLegacyType(u8),

    /// A protobuf prefix that is neither audio nor ping.
    #[error("unknown packet type {0}")]
    UnknownType(u8),

    /// The protobuf body did not parse.
    #[error("malformed protobuf audio packet")]
    Malformed,

    /// The payload exceeds [`MAX_AUDIO_BYTES`].
    #[error("audio payload of {0} bytes exceeds the {MAX_AUDIO_BYTES}-byte limit")]
    TooLarge(usize),
}

/// One decoded audio frame.
///
/// The union of what both formats can carry. Fields the legacy format has no
/// room for are `None` after decoding it, and are dropped again when encoding
/// back to legacy, a 1.4 client cannot be told about a volume adjustment, so
/// the server applies what it can and discards the rest rather than pretending.
#[derive(Debug, Clone, PartialEq)]
pub struct AudioPacket {
    /// Inbound: what the speaker aimed at. Outbound: the context it arrived by.
    ///
    /// The same wire field with two meanings depending on direction, which is
    /// why protobuf models it as a `oneof` and this does not: the server always
    /// knows which direction it is encoding.
    pub target: u8,

    /// Who spoke.
    ///
    /// Ignored on the way in, a peer's claim about its own identity is not
    /// evidence, and overwritten with the authenticated session before the
    /// frame is relayed.
    pub sender: SessionId,

    /// Position of this frame in the speaker's stream, for reordering.
    pub frame_number: u64,

    /// Opus payload, never decoded here.
    pub opus: Bytes,

    /// Whether this frame ends the transmission.
    pub terminator: bool,

    /// The speaker's position in a virtual world, if the client sent one.
    pub positional: Option<[f32; 3]>,

    /// A per-listener gain the server asks the client to apply.
    ///
    /// Protobuf only, and `None` rather than `0.0` when unset: protobuf 3 cannot
    /// distinguish an absent float from zero, and zero here would mean silence.
    pub volume_adjustment: Option<f32>,
}

impl AudioPacket {
    /// An empty frame from nobody, for tests and for filling in fields.
    #[must_use]
    pub fn silent() -> Self {
        Self {
            target: 0,
            sender: SessionId(0),
            frame_number: 0,
            opus: Bytes::new(),
            terminator: false,
            positional: None,
            volume_adjustment: None,
        }
    }
}

/// A datagram on the audio port.
///
/// Ping shares the port with audio and must be answered before the peer is
/// authenticated; it is how a client discovers whether UDP works at all, and
/// how the public server list measures a server it has never connected to.
#[derive(Debug, Clone, PartialEq)]
pub enum Datagram {
    /// Voice.
    Audio(AudioPacket),

    /// A connectivity probe, to be echoed.
    Ping(Ping),
}

/// A UDP ping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    /// The client's own timestamp, echoed back untouched.
    ///
    /// Opaque by specification: the client picks the format and the server must
    /// not interpret it. The round trip is measured by the client subtracting
    /// what it gets back from its clock.
    pub timestamp: u64,

    /// Whether the peer asked for user counts and version.
    ///
    /// Legacy pings always want them; the protobuf form asks explicitly.
    pub wants_details: bool,
}

/// What a server reports to a ping that asked for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerDetails {
    /// The server version, in Mumble's v2 packed encoding.
    pub version: u64,
    /// Users connected now.
    pub users: u32,
    /// Users allowed.
    pub max_users: u32,
    /// Per-user audio bandwidth ceiling, in bits per second.
    pub max_bandwidth: u32,
}

/// Bytes to and from [`Datagram`], for one peer's negotiated format.
///
/// The strategy the whole module exists to make swappable. Both implementations
/// are stateless and zero-sized, so holding one per peer costs nothing and the
/// call is monomorphic behind the `dyn`.
pub trait AudioCodec: std::fmt::Debug + Send + Sync {
    /// A name for logs.
    fn name(&self) -> &'static str;

    /// Parse a datagram received **from** a peer.
    ///
    /// Not the inverse of [`Self::encode_audio`], and cannot be: the legacy
    /// format carries a session field only in the server-to-client direction, so
    /// what a client sends and what a server sends are different layouts. The
    /// server only ever does one of each, so the asymmetry costs nothing,
    /// except a contract test that has to state both directions explicitly.
    ///
    /// # Errors
    ///
    /// [`PacketError`] if the bytes are not a datagram this codec understands.
    fn decode(&self, bytes: &[u8]) -> Result<Datagram, PacketError>;

    /// Encode an audio frame for delivery **to** a peer.
    fn encode_audio(&self, packet: &AudioPacket) -> Bytes;

    /// Encode a ping reply.
    fn encode_ping(&self, ping: &Ping, details: Option<ServerDetails>) -> Bytes;
}

/// The codec for a peer that negotiated `format`.
///
/// The Abstract Factory's product for the framing axis, mirroring
/// `starling-crypto`'s `VoiceProfile` for the cipher axis. Both are chosen once,
/// from the version the peer announced, and then carried.
#[must_use]
pub fn codec_for(format: UdpFormat) -> &'static dyn AudioCodec {
    match format {
        UdpFormat::Legacy => &LegacyCodec,
        UdpFormat::Protobuf => &ProtobufCodec,
    }
}

/// Mumble's pre-1.5 binary audio layout.
///
/// ```text
/// header  (type << 5) | target        1 byte
/// session varint                      server -> client only
/// sequence varint
/// length  varint, bit 13 = terminator
/// opus    length bytes
/// position 3 x f32 little-endian      optional, if bytes remain
/// ```
///
/// The session field's presence depends on direction, which is why decoding and
/// encoding are not symmetric here: the server never receives it and always
/// sends it.
#[derive(Debug, Clone, Copy, Default)]
pub struct LegacyCodec;

/// Bit 13 of the length varint carries the terminator flag.
const LEGACY_TERMINATOR_BIT: u64 = 0x2000;
/// The remaining low 13 bits are the payload length.
const LEGACY_LENGTH_MASK: u64 = 0x1FFF;
/// The low five bits of the header byte are the target.
const LEGACY_TARGET_MASK: u8 = 0x1F;

impl AudioCodec for LegacyCodec {
    fn name(&self) -> &'static str {
        "legacy"
    }

    fn decode(&self, bytes: &[u8]) -> Result<Datagram, PacketError> {
        let mut reader = Reader::new(bytes);
        let header = reader.u8().map_err(|_| PacketError::Empty)?;

        match LegacyType::decode(header) {
            Some(LegacyType::Ping) => Ok(Datagram::Ping(Ping {
                // The legacy ping is 12 bytes: four of header-ish padding then
                // eight of timestamp. Upstream treats the whole tail as opaque
                // and echoes it, so the exact split does not matter as long as
                // the reply is byte-identical.
                timestamp: u64::from_be_bytes(
                    reader
                        .take(8)
                        .unwrap_or(&[0; 8])
                        .try_into()
                        .unwrap_or([0; 8]),
                ),
                wants_details: true,
            })),

            Some(LegacyType::Opus) => {
                let target = header & LEGACY_TARGET_MASK;
                // No session field inbound: the server attributes the packet
                // from the socket it arrived on, never from what it claims.
                let frame_number = reader.count()?;
                let header = reader.count()?;
                let length = usize::try_from(header & LEGACY_LENGTH_MASK).unwrap_or(0);
                if length > MAX_AUDIO_BYTES {
                    return Err(PacketError::TooLarge(length));
                }
                let opus = Bytes::copy_from_slice(reader.take(length)?);

                Ok(Datagram::Audio(AudioPacket {
                    target,
                    sender: SessionId(0),
                    frame_number,
                    opus,
                    terminator: header & LEGACY_TERMINATOR_BIT != 0,
                    // Anything left is positional data. Absent is the common
                    // case, most clients never enable it.
                    positional: read_position(&mut reader),
                    volume_adjustment: None,
                }))
            }

            None => Err(PacketError::UnsupportedLegacyType(header >> 5)),
        }
    }

    fn encode_audio(&self, packet: &AudioPacket) -> Bytes {
        let mut writer = Writer::with_capacity(packet.opus.len() + 24);
        writer.u8(LegacyType::Opus.wire_id() << 5 | packet.target & LEGACY_TARGET_MASK);
        writer.varint(u64::from(packet.sender.0));
        writer.varint(packet.frame_number);

        // Truncating rather than splitting: the length field is 13 bits, and a
        // frame that does not fit was refused at parse by `MAX_AUDIO_BYTES`.
        let length = u64::try_from(packet.opus.len()).unwrap_or(0) & LEGACY_LENGTH_MASK;
        writer.varint(if packet.terminator {
            length | LEGACY_TERMINATOR_BIT
        } else {
            length
        });
        writer.bytes(&packet.opus[..usize::try_from(length).unwrap_or(0)]);

        if let Some(position) = packet.positional {
            for axis in position {
                writer.f32(axis);
            }
        }
        // `volume_adjustment` is dropped: the format has nowhere to put it, and
        // a 1.4 client would not know what to do with it if it did.
        Bytes::from(writer.finish())
    }

    fn encode_ping(&self, ping: &Ping, details: Option<ServerDetails>) -> Bytes {
        let mut writer = Writer::with_capacity(24);
        writer.u8(LegacyType::Ping.wire_id() << 5);
        writer.bytes(&ping.timestamp.to_be_bytes());
        if let Some(details) = details {
            // Legacy pings carry the details as fixed big-endian words, not
            // varints: this reply is also what the public server list parses.
            writer.bytes(&u32::try_from(details.version).unwrap_or(0).to_be_bytes());
            writer.bytes(&details.users.to_be_bytes());
            writer.bytes(&details.max_users.to_be_bytes());
            writer.bytes(&details.max_bandwidth.to_be_bytes());
        }
        Bytes::from(writer.finish())
    }
}

/// Mumble 1.5's protobuf audio format.
///
/// One prefix byte naming the message, then a protobuf body. Simpler than the
/// legacy layout in every respect, which is why it replaced it.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtobufCodec;

impl AudioCodec for ProtobufCodec {
    fn name(&self) -> &'static str {
        "protobuf"
    }

    fn decode(&self, bytes: &[u8]) -> Result<Datagram, PacketError> {
        let (&prefix, body) = bytes.split_first().ok_or(PacketError::Empty)?;

        match prefix {
            PROTOBUF_AUDIO => {
                let audio = mumble_udp::Audio::decode(body).map_err(|_| PacketError::Malformed)?;
                if audio.opus_data.len() > MAX_AUDIO_BYTES {
                    return Err(PacketError::TooLarge(audio.opus_data.len()));
                }
                Ok(Datagram::Audio(AudioPacket {
                    // Inbound this is `target`; `context` is what the server
                    // sends. A client setting `context` on the way in is
                    // claiming to be a server, so it is read as target 0.
                    target: match audio.header {
                        Some(mumble_udp::audio::Header::Target(t)) => u8::try_from(t).unwrap_or(0),
                        _ => 0,
                    },
                    sender: SessionId(0),
                    frame_number: audio.frame_number,
                    opus: Bytes::from(audio.opus_data),
                    terminator: audio.is_terminator,
                    positional: <[f32; 3]>::try_from(audio.positional_data.as_slice()).ok(),
                    // Protobuf 3 cannot tell an unset float from zero, and the
                    // proto comment says a value of 0 means unset.
                    volume_adjustment: (audio.volume_adjustment != 0.0)
                        .then_some(audio.volume_adjustment),
                }))
            }

            PROTOBUF_PING => {
                let ping = mumble_udp::Ping::decode(body).map_err(|_| PacketError::Malformed)?;
                Ok(Datagram::Ping(Ping {
                    timestamp: ping.timestamp,
                    wants_details: ping.request_extended_information,
                }))
            }

            other => Err(PacketError::UnknownType(other)),
        }
    }

    fn encode_audio(&self, packet: &AudioPacket) -> Bytes {
        let audio = mumble_udp::Audio {
            // Outbound the field means context, not target: which of speech,
            // shout, whisper or listener brought the frame here.
            header: Some(mumble_udp::audio::Header::Context(u32::from(packet.target))),
            sender_session: packet.sender.0,
            frame_number: packet.frame_number,
            opus_data: packet.opus.to_vec(),
            positional_data: packet.positional.map(Vec::from).unwrap_or_default(),
            volume_adjustment: packet.volume_adjustment.unwrap_or(0.0),
            is_terminator: packet.terminator,
        };
        prefixed(PROTOBUF_AUDIO, &audio)
    }

    fn encode_ping(&self, ping: &Ping, details: Option<ServerDetails>) -> Bytes {
        let details = details.unwrap_or(ServerDetails {
            version: 0,
            users: 0,
            max_users: 0,
            max_bandwidth: 0,
        });
        prefixed(
            PROTOBUF_PING,
            &mumble_udp::Ping {
                timestamp: ping.timestamp,
                request_extended_information: false,
                server_version_v2: details.version,
                user_count: details.users,
                max_user_count: details.max_users,
                max_bandwidth_per_user: details.max_bandwidth,
            },
        )
    }
}

/// Encode `message` behind its one-byte type prefix.
fn prefixed<M: prost::Message>(prefix: u8, message: &M) -> Bytes {
    let mut buffer = Vec::with_capacity(message.encoded_len() + 1);
    buffer.push(prefix);
    // Only fails if the buffer cannot grow, which is an allocation failure.
    let _ = message.encode(&mut buffer);
    Bytes::from(buffer)
}

/// Read three floats if three floats remain.
///
/// Partial positional data is discarded rather than zero-filled: a coordinate
/// invented by the server would place a speaker somewhere they are not.
fn read_position(reader: &mut Reader<'_>) -> Option<[f32; 3]> {
    (reader.remaining() >= 12).then(|| {
        [
            reader.f32().unwrap_or(0.0),
            reader.f32().unwrap_or(0.0),
            reader.f32().unwrap_or(0.0),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: SessionId = SessionId(42);

    fn speech() -> AudioPacket {
        AudioPacket {
            target: 0,
            sender: ALICE,
            frame_number: 1234,
            opus: Bytes::from_static(b"opus payload"),
            terminator: false,
            positional: None,
            volume_adjustment: None,
        }
    }

    /// What a *client* of this format puts on the wire.
    ///
    /// The contract needs both directions, and only one of them is a method:
    /// `decode` reads what a client sent, `encode_audio` writes what a server
    /// sends, and for the legacy format those are different layouts. Spelling
    /// out the inbound shape here is the honest way to test the reader, the
    /// alternative, feeding it the server's own output, would test the codec
    /// against itself and pass even if both halves were wrong the same way.
    fn as_a_client_would_send(format: UdpFormat, packet: &AudioPacket) -> Bytes {
        match format {
            // Identical to the server's encoding but for `target` in place of
            // `context`, which is the whole of the protobuf asymmetry.
            UdpFormat::Protobuf => prefixed(
                PROTOBUF_AUDIO,
                &mumble_udp::Audio {
                    header: Some(mumble_udp::audio::Header::Target(u32::from(packet.target))),
                    sender_session: 0,
                    frame_number: packet.frame_number,
                    opus_data: packet.opus.to_vec(),
                    positional_data: packet.positional.map(Vec::from).unwrap_or_default(),
                    volume_adjustment: packet.volume_adjustment.unwrap_or(0.0),
                    is_terminator: packet.terminator,
                },
            ),

            // The server's encoding minus the session varint.
            UdpFormat::Legacy => {
                let mut writer = Writer::new();
                writer.u8(LegacyType::Opus.wire_id() << 5 | packet.target & LEGACY_TARGET_MASK);
                writer.varint(packet.frame_number);
                let length = u64::try_from(packet.opus.len()).unwrap_or(0) & LEGACY_LENGTH_MASK;
                writer.varint(if packet.terminator {
                    length | LEGACY_TERMINATOR_BIT
                } else {
                    length
                });
                writer.bytes(&packet.opus);
                if let Some(position) = packet.positional {
                    for axis in position {
                        writer.f32(axis);
                    }
                }
                Bytes::from(writer.finish())
            }
        }
    }

    /// Every property both codecs must have, so neither drifts from the other.
    ///
    /// The contract is executable for the same reason `VoiceCipher`'s is: two
    /// implementations of one idea stay honest only if one function tests both.
    #[track_caller]
    fn assert_audio_codec_contract(format: UdpFormat) {
        let codec = codec_for(format);
        let name = codec.name();

        let decode_audio = |bytes: &[u8]| match codec.decode(bytes) {
            Ok(Datagram::Audio(audio)) => audio,
            other => panic!("{name}: expected audio, got {other:?}"),
        };

        // 1. Every field the format can carry survives the trip a real frame
        //    takes: a client encodes it, this server decodes it.
        let packet = speech();
        let inbound = as_a_client_would_send(format, &packet);
        let decoded = decode_audio(&inbound);
        assert_eq!(decoded.opus, packet.opus, "{name}: payload changed");
        assert_eq!(
            decoded.frame_number, packet.frame_number,
            "{name}: frame number changed"
        );
        assert_eq!(decoded.target, packet.target, "{name}: target changed");

        // 2. The terminator flag survives. It is packed into a length field in
        //    one format and a bool in the other, so it is worth asserting.
        let ending = AudioPacket {
            terminator: true,
            ..speech()
        };
        let decoded = decode_audio(&as_a_client_would_send(format, &ending));
        assert!(decoded.terminator, "{name}: terminator lost");
        assert_eq!(
            decoded.opus, ending.opus,
            "{name}: the terminator bit ate the payload length"
        );

        // 3. Positional data survives.
        let located = AudioPacket {
            positional: Some([1.0, -2.5, 3.25]),
            ..speech()
        };
        let decoded = decode_audio(&as_a_client_would_send(format, &located));
        assert_eq!(
            decoded.positional,
            Some([1.0, -2.5, 3.25]),
            "{name}: position lost"
        );

        // 4. The server's own output is well formed: it carries a header, and it
        //    contains the payload verbatim, since Opus is never re-encoded.
        let outbound = codec.encode_audio(&packet);
        assert!(
            outbound.len() > packet.opus.len(),
            "{name}: encoded frame has no header"
        );
        assert!(
            outbound
                .windows(packet.opus.len())
                .any(|w| w == packet.opus),
            "{name}: the payload was altered on the way out"
        );

        // 5. A ping round-trips its timestamp untouched. The client measures its
        //    round trip by subtracting this from its own clock, so a server that
        //    reinterprets it reports nonsense latency.
        let ping = Ping {
            timestamp: 0x0123_4567_89AB_CDEF,
            wants_details: true,
        };
        let Ok(Datagram::Ping(echoed)) = codec.decode(&codec.encode_ping(&ping, None)) else {
            panic!("{name}: an encoded ping did not decode as a ping");
        };
        assert_eq!(
            echoed.timestamp, ping.timestamp,
            "{name}: timestamp changed"
        );

        // 6. An empty datagram is refused, not indexed into.
        assert_eq!(codec.decode(&[]), Err(PacketError::Empty), "{name}");

        // 7. No truncation of a valid packet panics. This is the property that
        //    matters most: every byte here came off an open UDP port.
        for len in 0..inbound.len() {
            let _ = codec.decode(&inbound[..len]);
        }
    }

    #[test]
    fn the_legacy_codec_meets_the_contract() {
        assert_audio_codec_contract(UdpFormat::Legacy);
    }

    #[test]
    fn the_protobuf_codec_meets_the_contract() {
        assert_audio_codec_contract(UdpFormat::Protobuf);
    }

    #[test]
    fn the_format_picks_the_codec() {
        assert_eq!(codec_for(UdpFormat::Legacy).name(), "legacy");
        assert_eq!(codec_for(UdpFormat::Protobuf).name(), "protobuf");
    }

    #[test]
    fn a_claimed_sender_is_ignored_on_the_way_in() {
        // The impersonation this prevents: encode as Alice, decode, and the
        // sender must come back as nobody so the caller has to fill in the
        // authenticated session.
        for format in [UdpFormat::Legacy, UdpFormat::Protobuf] {
            let codec = codec_for(format);
            let claimed = AudioPacket {
                sender: ALICE,
                ..speech()
            };
            let Ok(Datagram::Audio(decoded)) =
                codec.decode(&as_a_client_would_send(format, &claimed))
            else {
                panic!("{}: did not decode", codec.name());
            };
            assert_eq!(
                decoded.sender,
                SessionId(0),
                "{}: trusted the sender field",
                codec.name()
            );
        }
    }

    #[test]
    fn the_outbound_sender_is_written() {
        // The other half: what the server encodes must carry the real session,
        // or no client can tell who is speaking.
        let encoded = codec_for(UdpFormat::Protobuf).encode_audio(&speech());
        let audio = mumble_udp::Audio::decode(&encoded[1..]).expect("valid protobuf");
        assert_eq!(audio.sender_session, ALICE.0);
    }

    #[test]
    fn a_removed_codec_is_refused_not_relayed() {
        // CELT alpha, CELT beta and Speex. Relaying them would hand every other
        // client audio it cannot decode.
        for kind in [0_u8, 2, 3] {
            assert_eq!(
                LegacyCodec.decode(&[kind << 5, 0, 0]),
                Err(PacketError::UnsupportedLegacyType(kind))
            );
        }
    }

    #[test]
    fn an_unknown_protobuf_type_is_refused() {
        assert_eq!(ProtobufCodec.decode(&[7]), Err(PacketError::UnknownType(7)));
    }

    #[test]
    fn a_malformed_protobuf_body_is_an_error() {
        // Field 1, wire type 7, which does not exist.
        assert_eq!(
            ProtobufCodec.decode(&[PROTOBUF_AUDIO, 0x0F, 0xFF]),
            Err(PacketError::Malformed)
        );
    }

    #[test]
    fn an_oversized_legacy_length_is_refused_before_allocating() {
        // The attack: claim 8191 bytes in a 4-byte datagram. Refusing on the
        // length field means the server never reserves memory a peer named.
        let mut writer = Writer::new();
        writer.u8(LegacyType::Opus.wire_id() << 5);
        writer.varint(0);
        writer.varint(LEGACY_LENGTH_MASK);
        assert_eq!(
            LegacyCodec.decode(&writer.finish()),
            Err(PacketError::TooLarge(
                usize::try_from(LEGACY_LENGTH_MASK).expect("fits")
            ))
        );
    }

    #[test]
    fn an_oversized_protobuf_payload_is_refused() {
        let encoded = ProtobufCodec.encode_audio(&AudioPacket {
            opus: Bytes::from(vec![0; MAX_AUDIO_BYTES + 1]),
            ..speech()
        });
        assert_eq!(
            ProtobufCodec.decode(&encoded),
            Err(PacketError::TooLarge(MAX_AUDIO_BYTES + 1))
        );
    }

    #[test]
    fn a_legacy_length_longer_than_the_datagram_is_an_error() {
        let mut writer = Writer::new();
        writer.u8(LegacyType::Opus.wire_id() << 5);
        writer.varint(0);
        writer.varint(64);
        writer.bytes(b"only a few");
        assert!(matches!(
            LegacyCodec.decode(&writer.finish()),
            Err(PacketError::Truncated(_))
        ));
    }

    #[test]
    fn partial_positional_data_is_dropped_not_zero_filled() {
        // Inventing a coordinate would place a speaker somewhere they are not.
        let mut writer = Writer::new();
        writer.u8(LegacyType::Opus.wire_id() << 5);
        writer.varint(0);
        writer.varint(1);
        writer.bytes(b"x");
        writer.f32(1.0);
        writer.f32(2.0); // Only two of three.
        let Ok(Datagram::Audio(decoded)) = LegacyCodec.decode(&writer.finish()) else {
            panic!("did not decode");
        };
        assert_eq!(decoded.positional, None);
    }

    #[test]
    fn a_zero_volume_adjustment_reads_as_unset() {
        // Protobuf 3 cannot distinguish them, and the proto says 0 means unset.
        // Reading it as a real adjustment would silence the speaker.
        let Ok(Datagram::Audio(decoded)) =
            ProtobufCodec.decode(&ProtobufCodec.encode_audio(&speech()))
        else {
            panic!("did not decode");
        };
        assert_eq!(decoded.volume_adjustment, None);
    }

    #[test]
    fn a_client_claiming_to_be_a_server_is_read_as_normal_speech() {
        // `context` is the server's field. A client setting it must not have it
        // read as a whisper target.
        let encoded = prefixed(
            PROTOBUF_AUDIO,
            &mumble_udp::Audio {
                header: Some(mumble_udp::audio::Header::Context(3)),
                ..Default::default()
            },
        );
        let Ok(Datagram::Audio(decoded)) = ProtobufCodec.decode(&encoded) else {
            panic!("did not decode");
        };
        assert_eq!(decoded.target, 0);
    }

    #[test]
    fn a_target_above_five_bits_cannot_survive_legacy_encoding() {
        // The legacy header has five bits for it. Truncating silently would
        // turn a whisper into someone else's whisper, so the encoder masks and
        // `Target::decode` maps anything odd to normal speech.
        let encoded = as_a_client_would_send(
            UdpFormat::Legacy,
            &AudioPacket {
                target: 0xFF,
                ..speech()
            },
        );
        let Ok(Datagram::Audio(decoded)) = LegacyCodec.decode(&encoded) else {
            panic!("did not decode");
        };
        assert_eq!(decoded.target, LEGACY_TARGET_MASK);
    }

    #[test]
    fn ping_details_are_included_when_asked_for() {
        let details = ServerDetails {
            version: 0x0001_0005_0000,
            users: 7,
            max_users: 100,
            max_bandwidth: 72_000,
        };
        let ping = Ping {
            timestamp: 99,
            wants_details: true,
        };

        let encoded = ProtobufCodec.encode_ping(&ping, Some(details));
        let reply = mumble_udp::Ping::decode(&encoded[1..]).expect("valid protobuf");
        assert_eq!(reply.user_count, 7);
        assert_eq!(reply.max_user_count, 100);
        assert_eq!(reply.server_version_v2, details.version);

        // The legacy reply is fixed-width, so its length is the assertion.
        let legacy = LegacyCodec.encode_ping(&ping, Some(details));
        assert_eq!(legacy.len(), 1 + 8 + 16);
    }

    #[test]
    fn no_datagram_of_any_shape_panics_the_decoder() {
        // Anyone can send anything to an open UDP port. A panic here is a remote
        // denial of service, so the property is blunt: nothing crashes.
        for codec in [codec_for(UdpFormat::Legacy), codec_for(UdpFormat::Protobuf)] {
            for lead in 0..=255_u8 {
                for len in 0..24 {
                    let mut bytes = vec![lead];
                    bytes.extend((0..len).map(|i: u8| i.wrapping_mul(37)));
                    let _ = codec.decode(&bytes);
                }
            }
        }
    }
}
