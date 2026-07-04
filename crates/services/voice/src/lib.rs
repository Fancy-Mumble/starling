//! `voice` — audio routing, and the only service that mints ciphers.
//!
//! **Audio needs no hop.** murmur already binds TCP and UDP as two independent
//! sockets on one port number (`Server.cpp:125` calls `listen()`,
//! `Server.cpp:193` calls `::bind()`), and they can live in different
//! processes. So this service binds UDP:64738 itself, clients send audio
//! straight to it, and the kernel does the demux — no gateway hop, no
//! serialisation, no fan-out amplification. The only audio that reaches the
//! control plane is `UDPTunnel` (type 1), the fallback for UDP-blocked clients,
//! which is per client rather than per listener (`docs/ARCHITECTURE.md` §3).
//!
//! **Voice mints the ciphers, not `session-lifecycle`.** `CryptSetup` (15) is a
//! control message, so session-lifecycle delivers it — but the key is used here
//! to seal UDP, so it is generated here and handed over as a ready-made
//! payload. Key material never crosses a service boundary in a form anything
//! else could use.
//!
//! Two realtime invariants hold throughout: **Opus is forwarded, never
//! transcoded** — Starling is an SFU, not an MCU — and the real per-packet cost
//! is **N seals, not one**, because every listener needs the frame under their
//! own key.

pub mod bandwidth;
pub mod packet;
pub mod peer;
pub mod ports;
pub mod router;
pub mod routing;
pub mod targets;
pub mod varint;

pub mod service;
pub mod socket;
pub mod tree;
pub mod tunnel;
pub mod view;

#[cfg(test)]
mod testing;

pub use bandwidth::Bandwidth;
pub use packet::{AudioCodec, AudioPacket, Datagram, PacketError, Ping, ServerDetails, codec_for};
pub use peer::VoicePeer;
pub use ports::{AudioSource, ChannelId, ConnId, Datagrams, FrameSink, SessionId, Stuck};
pub use router::{Router, RouterStats};
pub use routing::{REGULAR_SPEECH, RoutingSnapshot, SERVER_LOOPBACK, Target};
pub use service::VoiceService;
pub use socket::VoiceSocket;
pub use targets::{MAX_TARGET, ShoutTarget, TargetError, TargetRegistry, VoiceTarget};
pub use tree::ChannelTree;
pub use tunnel::GatewayTunnel;
pub use view::SessionCache;
