//! A client, for this crate's tests.
//!
//! The router's tests are only worth anything if the bytes they feed it are the
//! bytes a real client would send. [`TestPeer`] is that: it holds the *other*
//! half of a peer's cipher and codec, so `speak` produces a genuinely encrypted
//! packet and `hear` genuinely decrypts one.
//!
//! Hand-built frames would have been easier and would have tested nothing — a
//! router that never decrypted anything would pass them all.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use starling_api::{ConnId, Datagrams, FrameSink, Stuck};
use starling_crypto::ocb2::{Block, Ocb2};
use starling_crypto::VoiceCipher;
use starling_gate::UdpFormat;
use starling_model::SessionId;

use crate::packet::{AudioPacket, Ping};
use crate::peer::VoicePeer;
use crate::routing::REGULAR_SPEECH;
use crate::varint::{Reader, Writer};

use prost::Message as _;
use starling_proto::proto::udp as mumble_udp;

/// The wire format from the *client's* side.
///
/// Not `AudioCodec`: that trait is the server's half, and the two halves are
/// deliberately not inverses. Legacy audio carries a session field only
/// server-to-client, and protobuf audio uses `target` inbound against `context`
/// outbound. Reusing the server's codec here would make every test agree with
/// the implementation by construction and catch none of those asymmetries — it
/// did, until three tests were written that could tell the difference.
#[derive(Debug, Clone, Copy)]
struct ClientCodec(UdpFormat);

impl ClientCodec {
    /// What this client puts on the wire for one frame.
    fn encode_audio(self, packet: &AudioPacket) -> Bytes {
        match self.0 {
            UdpFormat::Protobuf => {
                let mut out = vec![0_u8]; // Audio
                let audio = mumble_udp::Audio {
                    header: Some(mumble_udp::audio::Header::Target(u32::from(packet.target))),
                    sender_session: packet.sender.0,
                    frame_number: packet.frame_number,
                    opus_data: packet.opus.to_vec(),
                    positional_data: packet.positional.map(Vec::from).unwrap_or_default(),
                    volume_adjustment: packet.volume_adjustment.unwrap_or(0.0),
                    is_terminator: packet.terminator,
                };
                let _ = audio.encode(&mut out);
                Bytes::from(out)
            }
            UdpFormat::Legacy => {
                let mut writer = Writer::new();
                writer.u8(4 << 5 | packet.target & 0x1F);
                writer.varint(packet.frame_number);
                let length = u64::try_from(packet.opus.len()).unwrap_or(0) & 0x1FFF;
                writer.varint(if packet.terminator {
                    length | 0x2000
                } else {
                    length
                });
                writer.bytes(&packet.opus);
                Bytes::from(writer.finish())
            }
        }
    }

    /// What this client makes of a frame the server sent it.
    fn decode_audio(self, bytes: &[u8]) -> AudioPacket {
        match self.0 {
            UdpFormat::Protobuf => {
                assert_eq!(bytes.first(), Some(&0), "not an audio packet");
                let audio = mumble_udp::Audio::decode(&bytes[1..]).expect("valid protobuf");
                AudioPacket {
                    // Outbound the field is `context`, which is the whole point
                    // of decoding as a client rather than reusing the server.
                    target: match audio.header {
                        Some(mumble_udp::audio::Header::Context(c)) => u8::try_from(c).unwrap_or(0),
                        _ => 0,
                    },
                    sender: SessionId(audio.sender_session),
                    frame_number: audio.frame_number,
                    opus: Bytes::from(audio.opus_data),
                    terminator: audio.is_terminator,
                    positional: <[f32; 3]>::try_from(audio.positional_data.as_slice()).ok(),
                    volume_adjustment: (audio.volume_adjustment != 0.0)
                        .then_some(audio.volume_adjustment),
                }
            }
            UdpFormat::Legacy => {
                let mut reader = Reader::new(bytes);
                let header = reader.u8().expect("header");
                assert_eq!(header >> 5, 4, "not an Opus packet");
                // The session varint the server adds and the client reads —
                // the field that does not exist in the other direction.
                let sender = reader.count().expect("session");
                let frame_number = reader.count().expect("sequence");
                let length_field = reader.count().expect("length");
                let length = usize::try_from(length_field & 0x1FFF).unwrap_or(0);
                let opus = Bytes::copy_from_slice(reader.take(length).expect("payload"));
                AudioPacket {
                    target: header & 0x1F,
                    sender: SessionId(u32::try_from(sender).unwrap_or(0)),
                    frame_number,
                    opus,
                    terminator: length_field & 0x2000 != 0,
                    positional: None,
                    volume_adjustment: None,
                }
            }
        }
    }

    /// A ping, in this client's format.
    fn encode_ping(self, ping: &Ping) -> Bytes {
        match self.0 {
            UdpFormat::Protobuf => {
                let mut out = vec![1_u8]; // Ping
                let message = mumble_udp::Ping {
                    timestamp: ping.timestamp,
                    request_extended_information: ping.wants_details,
                    ..Default::default()
                };
                let _ = message.encode(&mut out);
                Bytes::from(out)
            }
            UdpFormat::Legacy => {
                let mut writer = Writer::new();
                writer.u8(1 << 5);
                writer.bytes(&ping.timestamp.to_be_bytes());
                Bytes::from(writer.finish())
            }
        }
    }

    /// What this client makes of a ping reply.
    fn decode_ping(self, bytes: &[u8]) -> Ping {
        match self.0 {
            UdpFormat::Protobuf => {
                assert_eq!(bytes.first(), Some(&1), "not a ping");
                let reply = mumble_udp::Ping::decode(&bytes[1..]).expect("valid protobuf");
                Ping {
                    timestamp: reply.timestamp,
                    wants_details: reply.request_extended_information,
                }
            }
            UdpFormat::Legacy => {
                let mut reader = Reader::new(bytes);
                assert_eq!(reader.u8().expect("header") >> 5, 1, "not a ping");
                Ping {
                    timestamp: u64::from_be_bytes(
                        reader
                            .take(8)
                            .expect("timestamp")
                            .try_into()
                            .expect("eight bytes"),
                    ),
                    wants_details: true,
                }
            }
        }
    }
}

/// A [`Datagrams`] that keeps everything it was given.
#[derive(Debug, Default, Clone)]
pub(crate) struct RecordingDatagrams {
    sent: Arc<Mutex<Vec<(std::net::SocketAddr, Bytes)>>>,
}

impl RecordingDatagrams {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Everything sent so far.
    fn all(&self) -> Vec<(std::net::SocketAddr, Bytes)> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_default()
    }

    /// How many datagrams were sent.
    pub(crate) fn count(&self) -> usize {
        self.all().len()
    }

    /// Whether nothing was sent.
    pub(crate) fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Forget everything sent so far.
    ///
    /// For setting up a peer's UDP path — which a client does by *sending*, so
    /// the setup itself produces traffic a test must not then assert on.
    pub(crate) fn clear(&self) {
        if let Ok(mut sent) = self.sent.lock() {
            sent.clear();
        }
    }

    /// The one datagram sent.
    ///
    /// # Panics
    ///
    /// If zero or more than one was sent, which in these tests is always a bug
    /// in the router rather than in the test.
    pub(crate) fn only(&self) -> (std::net::SocketAddr, Bytes) {
        let all = self.all();
        assert_eq!(
            all.len(),
            1,
            "expected exactly one datagram, got {}",
            all.len()
        );
        all.into_iter().next().expect("checked above")
    }
}

impl Datagrams for RecordingDatagrams {
    fn send_to(&self, addr: std::net::SocketAddr, frame: Bytes) {
        if let Ok(mut sent) = self.sent.lock() {
            sent.push((addr, frame));
        }
    }
}

/// A [`FrameSink`] that keeps everything it was given.
#[derive(Debug, Default, Clone)]
struct RecordingSink {
    frames: Arc<Mutex<Vec<Bytes>>>,
}

impl FrameSink for RecordingSink {
    fn try_send(&self, frame: Bytes) -> Result<(), Stuck> {
        self.frames.lock().map_err(|_| Stuck)?.push(frame);
        Ok(())
    }
}

/// A [`FrameSink`] that is always full.
#[derive(Debug, Default, Clone)]
pub(crate) struct FullSink;

impl FrameSink for FullSink {
    fn try_send(&self, _frame: Bytes) -> Result<(), Stuck> {
        Err(Stuck)
    }
}

/// The client half of one peer: its cipher, its codec, and what it has heard.
///
/// Cloneable-by-sharing on the receive side so a test can hold it while the
/// router holds the peer built from it.
pub(crate) struct TestPeer {
    conn: ConnId,
    session: SessionId,
    format: UdpFormat,
    key: [u8; 16],
    client_nonce: Block,
    server_nonce: Block,
    /// The client's own cipher, mirroring the server's.
    cipher: Ocb2,
    tunnelled: RecordingSink,
}

impl TestPeer {
    /// A client keyed as `CryptSetup` would key it.
    pub(crate) fn new(conn: ConnId, session: SessionId, format: UdpFormat) -> Self {
        // Distinct per session so that a packet from one peer cannot decrypt
        // under another's key — which is exactly what attribution relies on.
        let key = [u8::try_from(session.0 & 0xFF).unwrap_or(0) ^ 0x5A; 16];
        let client_nonce = Block::from_padded(&[0x10, u8::try_from(session.0 & 0xFF).unwrap_or(0)]);
        let server_nonce = Block::from_padded(&[0x20, u8::try_from(session.0 & 0xFF).unwrap_or(0)]);

        Self {
            conn,
            session,
            format,
            key,
            client_nonce,
            server_nonce,
            // The client sends under the client nonce and expects the server's.
            cipher: Ocb2::new(key, server_nonce, client_nonce),
            tunnelled: RecordingSink::default(),
        }
    }

    /// The server-side peer for this client.
    ///
    /// Note the crossover in the nonces: what one side sends under, the other
    /// expects. Getting it backwards makes every packet fail its tag.
    pub(crate) fn attach(&self) -> VoicePeer {
        VoicePeer::new(
            self.conn,
            self.session,
            self.format,
            Box::new(Ocb2::new(self.key, self.client_nonce, self.server_nonce)),
            Box::new(self.tunnelled.clone()),
        )
    }

    /// Register this peer's connection and keys with a running service.
    ///
    /// Two commands, in the order the real server sends them: the sink at the
    /// TLS handshake, the keys at authentication.
    pub(crate) fn join(&self, handle: &crate::service::VoiceHandle, host: std::net::IpAddr) {
        handle
            .send(crate::service::ControlCommand::Connected {
                conn: self.conn,
                sink: Box::new(self.tunnelled.clone()),
            })
            .expect("connected");
        self.attach_to(handle, host);
    }

    /// Send only the keys, without having registered a connection.
    pub(crate) fn attach_to(&self, handle: &crate::service::VoiceHandle, host: std::net::IpAddr) {
        handle
            .send(crate::service::ControlCommand::Attach {
                conn: self.conn,
                session: self.session,
                host,
                format: self.format,
                cipher: Box::new(Ocb2::new(self.key, self.client_nonce, self.server_nonce)),
            })
            .expect("attach");
    }

    /// A server-side peer whose outbound queue is permanently full.
    pub(crate) fn attach_stuck(&self) -> VoicePeer {
        VoicePeer::new(
            self.conn,
            self.session,
            self.format,
            Box::new(Ocb2::new(self.key, self.client_nonce, self.server_nonce)),
            Box::new(FullSink),
        )
    }

    fn codec(&self) -> ClientCodec {
        ClientCodec(self.format)
    }

    /// An encrypted frame of normal speech, for the UDP path.
    pub(crate) fn speak(&mut self, opus: &[u8]) -> Bytes {
        self.speak_to(REGULAR_SPEECH, opus)
    }

    /// The same frame **unencrypted**, for the `UDPTunnel` path.
    ///
    /// The tunnel runs inside TLS and carries plaintext. Sealing it here would
    /// hide the very bug this distinction exists to prevent: a router that
    /// decrypts tunnelled audio drops every frame from a client that fell back
    /// to tunnelling, and a test double that also encrypts agrees with it.
    pub(crate) fn speak_tunnelled(&mut self, opus: &[u8]) -> Bytes {
        self.codec().encode_audio(&AudioPacket {
            target: REGULAR_SPEECH,
            sender: SessionId(0),
            opus: Bytes::copy_from_slice(opus),
            ..AudioPacket::silent()
        })
    }

    /// An encrypted frame aimed at `target`.
    pub(crate) fn speak_to(&mut self, target: u8, opus: &[u8]) -> Bytes {
        self.encode_and_seal(target, SessionId(0), opus)
    }

    /// An encrypted frame claiming to be from someone else.
    pub(crate) fn speak_as(&mut self, claimed: SessionId, opus: &[u8]) -> Bytes {
        self.encode_and_seal(REGULAR_SPEECH, claimed, opus)
    }

    fn encode_and_seal(&mut self, target: u8, sender: SessionId, opus: &[u8]) -> Bytes {
        let encoded = self.codec().encode_audio(&AudioPacket {
            target,
            sender,
            opus: Bytes::copy_from_slice(opus),
            ..AudioPacket::silent()
        });
        self.seal_raw(&encoded)
    }

    /// Encrypt arbitrary bytes, for testing what happens after decryption.
    pub(crate) fn seal_raw(&mut self, bytes: &[u8]) -> Bytes {
        Bytes::from(self.cipher.seal(bytes, &[]).expect("client sealing"))
    }

    /// An encrypted ping.
    pub(crate) fn ping(&mut self, timestamp: u64) -> Bytes {
        let encoded = self.codec().encode_ping(&Ping {
            timestamp,
            wants_details: true,
        });
        self.seal_raw(&encoded)
    }

    /// Decrypt and decode a frame the server sent as a datagram.
    ///
    /// # Panics
    ///
    /// If the frame does not decrypt or is not audio, which is the failure the
    /// calling test is checking for.
    pub(crate) fn hear(&mut self, frame: &[u8]) -> AudioPacket {
        let plain = self.cipher.open(frame, &[]).expect("client opening");
        self.codec().decode_audio(&plain)
    }

    /// Decrypt and decode a ping reply.
    ///
    /// # Panics
    ///
    /// If the frame is not a ping.
    pub(crate) fn hear_ping(&mut self, frame: &[u8]) -> Ping {
        let plain = self.cipher.open(frame, &[]).expect("client opening");
        self.codec().decode_ping(&plain)
    }

    /// Everything the server tunnelled to this peer over TCP.
    pub(crate) fn tunnelled(&self) -> Vec<Bytes> {
        self.tunnelled
            .frames
            .lock()
            .map(|frames| frames.clone())
            .unwrap_or_default()
    }

    /// Decode the one frame tunnelled to this peer.
    ///
    /// Unwraps the `UDPTunnel` control framing and does **not** decrypt: what
    /// arrives here is a control message on the TLS connection carrying a
    /// plaintext audio frame, exactly as murmur's `tcpTransmitData` sends it.
    ///
    /// # Panics
    ///
    /// If a number other than one was tunnelled, or it is not a `UDPTunnel`.
    pub(crate) fn hear_tunnelled(&mut self) -> AudioPacket {
        let frames = self.tunnelled();
        assert_eq!(frames.len(), 1, "expected exactly one tunnelled frame");
        let frame = frames.into_iter().next().expect("checked above");

        let mut buffer = bytes::BytesMut::from(&frame[..]);
        let decoded = starling_proto::codec::decode(&mut buffer)
            .expect("tunnelled bytes are not a control message")
            .expect("tunnelled bytes are an incomplete control message");
        let starling_proto::ControlMessage::UdpTunnel(audio) = decoded else {
            panic!("tunnelled frame is not a UDPTunnel: {decoded:?}");
        };

        self.codec().decode_audio(&audio)
    }
}
