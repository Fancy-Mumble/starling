//! One peer's voice path, purpose-built for the client on the other end.
//!
//! The product of the two abstract factories: `starling-crypto`'s
//! `ProfileFactory` picks the cipher from what the peer announced, and
//! [`codec_for`] picks the wire format from its Mumble version. Both are decided
//! once at handshake and then carried, so nothing on the packet path ever
//! re-derives a peer's capabilities from a version number.
//!
//! # Why the cipher is boxed and the codec is not
//!
//! A cipher has per-packet state — counters, replay windows, key schedules —
//! and there is exactly one per peer per direction. A codec has none: it is a
//! pure function of bytes, so every peer on the same format shares one static.
//!
//! [`codec_for`]: crate::packet::codec_for

use std::net::SocketAddr;

use bytes::Bytes;
use starling_api::{ConnId, FrameSink};
use starling_crypto::{VoiceCipher, VoiceError};
use starling_gate::UdpFormat;
use starling_model::SessionId;
use starling_proto::ControlMessage;

use crate::packet::{codec_for, AudioCodec};

/// Everything the packet path needs about one connected client.
pub struct VoicePeer {
    conn: ConnId,
    session: SessionId,
    codec: &'static dyn AudioCodec,
    cipher: Box<dyn VoiceCipher>,
    /// Where this peer's audio goes when TCP is the only path that works.
    tunnel: Box<dyn FrameSink>,
    /// The address its datagrams have been *proven* to come from.
    ///
    /// `None` until a packet from that address authenticates. Until then every
    /// frame for this peer is tunnelled, which is what makes a client behind a
    /// UDP-blocking firewall work at all.
    udp: Option<SocketAddr>,
}

impl VoicePeer {
    /// Assemble a peer from what the handshake negotiated.
    #[must_use]
    pub fn new(
        conn: ConnId,
        session: SessionId,
        format: UdpFormat,
        cipher: Box<dyn VoiceCipher>,
        tunnel: Box<dyn FrameSink>,
    ) -> Self {
        Self {
            conn,
            session,
            codec: codec_for(format),
            cipher,
            tunnel,
            udp: None,
        }
    }

    /// Which connection this is.
    #[must_use]
    pub const fn conn(&self) -> ConnId {
        self.conn
    }

    /// Which session is speaking.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// This peer's wire format.
    #[must_use]
    pub fn codec(&self) -> &'static dyn AudioCodec {
        self.codec
    }

    /// The proven UDP address, if there is one.
    #[must_use]
    pub const fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp
    }

    /// Record the address this peer's audio has been proven to come from.
    ///
    /// Only ever called after a packet from that address authenticated. The
    /// router owns that rule; this type would not be able to check it.
    pub fn bind(&mut self, addr: SocketAddr) {
        self.udp = Some(addr);
    }

    /// Decrypt one received packet.
    ///
    /// # Errors
    ///
    /// [`VoiceError`] when the packet is short, a replay, or not authentic —
    /// which for an unattributed datagram is the *expected* outcome, since the
    /// router tries candidates until one works.
    pub fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>, VoiceError> {
        self.cipher.open(packet, &[])
    }

    /// Encrypt one frame for this peer.
    ///
    /// # Errors
    ///
    /// [`VoiceError`] if the cipher's counter space is exhausted.
    pub fn seal(&mut self, frame: &[u8]) -> Result<Vec<u8>, VoiceError> {
        self.cipher.seal(frame, &[])
    }

    /// Send a frame over the TLS connection, inside a `UDPTunnel`.
    ///
    /// Takes the **plaintext** encoding, not a sealed packet. The tunnel runs
    /// inside TLS, so there is nothing left for the voice cipher to protect
    /// against, and murmur sends the bare audio frame here
    /// (`Server.cpp:tcpTransmitData`). Sealing it would hand the client
    /// ciphertext where it expects a packet — every frame silently discarded.
    ///
    /// Framing it as a control message is not optional either: this shares the
    /// socket with `UserState`, `Ping` and everything else, so raw bytes would
    /// be read as a message header and desynchronise the connection outright.
    ///
    /// Returns `false` if the peer's outbound queue is full, which means it is
    /// not keeping up. The frame is dropped: audio that waits in a queue has
    /// already missed the moment it was for.
    pub fn tunnel(&mut self, frame: &[u8]) -> bool {
        let framed = starling_proto::codec::encode(&ControlMessage::UdpTunnel(
            Bytes::copy_from_slice(frame),
        ));
        self.tunnel.try_send(framed).is_ok()
    }
}

impl std::fmt::Debug for VoicePeer {
    /// Prints no cipher state, which is key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoicePeer")
            .field("conn", &self.conn)
            .field("session", &self.session)
            .field("codec", &self.codec.name())
            .field("udp", &self.udp)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestPeer;

    #[test]
    fn a_new_peer_has_no_udp_path() {
        // So its first frames tunnel, until one of its datagrams proves
        // otherwise. Assuming UDP works would silence every firewalled client.
        let peer = TestPeer::new(ConnId(1), SessionId(1), UdpFormat::Protobuf).attach();
        assert_eq!(peer.udp_addr(), None);
    }

    #[test]
    fn binding_records_the_address() {
        let mut peer = TestPeer::new(ConnId(1), SessionId(1), UdpFormat::Protobuf).attach();
        let addr = "203.0.113.1:5000".parse().expect("address");
        peer.bind(addr);
        assert_eq!(peer.udp_addr(), Some(addr));
    }

    #[test]
    fn the_codec_follows_the_negotiated_format() {
        for (format, name) in [
            (UdpFormat::Legacy, "legacy"),
            (UdpFormat::Protobuf, "protobuf"),
        ] {
            let peer = TestPeer::new(ConnId(1), SessionId(1), format).attach();
            assert_eq!(peer.codec().name(), name);
        }
    }

    #[test]
    fn it_prints_no_cipher_state() {
        let peer = TestPeer::new(ConnId(1), SessionId(7), UdpFormat::Protobuf).attach();
        let printed = format!("{peer:?}");
        assert!(printed.contains("session"), "{printed}");
        assert!(!printed.contains("cipher"), "{printed}");
    }
}
