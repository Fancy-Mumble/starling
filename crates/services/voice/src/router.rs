//! The packet path: attribute, decrypt, route, encrypt, deliver.
//!
//! Everything the voice service does to a frame, with no `async` anywhere. That
//! is deliberate — this is the part worth testing exhaustively, and a test that
//! needs a runtime and a socket is a test nobody writes enough of.
//!
//! # The shape of one packet
//!
//! ```text
//! bytes in  -> which peer sent this?      (address, or the TLS connection)
//!           -> decrypt with that peer's cipher
//!           -> decode with that peer's codec
//!           -> ask the snapshot who hears it
//!           -> for each listener: re-encode, re-encrypt, send
//! ```
//!
//! Re-encoding per recipient is not waste: two listeners can have negotiated
//! different wire formats and always have different ciphers, so the frame that
//! leaves is never the frame that arrived. murmur has the same fan-out, one
//! `CryptState` per user.
//!
//! # Attribution is the security boundary
//!
//! A datagram arrives with a source address and a claim. Neither is evidence.
//! The peer is whoever's key authenticates the packet, which is why the address
//! index is a *hint* that narrows the search and never a conclusion.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use starling_api::{AudioSource, ConnId, Datagrams};
use starling_model::SessionId;
use tracing::debug;

use crate::packet::{AudioCodec as _, AudioPacket, Datagram, ProtobufCodec, ServerDetails};
use crate::peer::VoicePeer;
use crate::routing::{RoutingSnapshot, Target};

/// Where a frame came from, once it has been attributed to a peer.
///
/// Distinct from [`AudioSource`], which is a claim. This is a conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attributed {
    /// Authenticated by key, from this address.
    Datagram(ConnId, SocketAddr),
    /// Arrived on an established TLS connection.
    Tunnel(ConnId),
}

impl Attributed {
    /// The connection this frame belongs to.
    const fn conn(self) -> ConnId {
        match self {
            Self::Datagram(conn, _) | Self::Tunnel(conn) => conn,
        }
    }
}

/// Counters an operator needs and a log line would drown in.
///
/// Every one of these can be driven by a hostile peer, so none of them is a log
/// line: an attacker who can make the server write to disk per datagram has a
/// denial of service that costs them nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RouterStats {
    /// Datagrams that authenticated against no session.
    pub unattributed: u64,
    /// Frames refused because the speaker is muted or suppressed.
    pub silenced: u64,
    /// Frames that decrypted but did not parse.
    pub malformed: u64,
    /// Frames delivered to at least one listener.
    pub routed: u64,
    /// Individual copies handed to a transport.
    pub delivered: u64,
    /// Copies dropped because a peer's queue was full.
    pub dropped: u64,
    /// Peers currently able to send and receive audio.
    pub attached: usize,
    /// Frames received per speaking session.
    ///
    /// The counter that answers "is this peer transmitting at all", which no
    /// aggregate can: a server relaying one peer's audio perfectly and hearing
    /// nothing from the other looks exactly like one relaying both, unless the
    /// speakers are counted separately.
    pub by_speaker: Vec<(SessionId, u64)>,
}

/// The voice service's whole state, and the packet path over it.
#[derive(Debug)]
pub struct Router {
    snapshot: RoutingSnapshot,
    peers: HashMap<ConnId, VoicePeer>,
    /// The connection a session's audio belongs to.
    by_session: HashMap<SessionId, ConnId>,
    /// The exact address a peer's datagrams arrive from, once proven.
    by_addr: HashMap<SocketAddr, ConnId>,
    /// Connections plausibly behind an address, to narrow an unproven datagram.
    ///
    /// murmur's `qhHostUsers`. Without it, a peer whose NAT changed port would
    /// cost a trial decryption against every session on the server.
    by_host: HashMap<IpAddr, Vec<ConnId>>,
    datagrams: Box<dyn Datagrams>,
    details: ServerDetails,
    stats: RouterStats,
    /// Frames received from each session.
    heard_from: HashMap<SessionId, u64>,
}

impl Router {
    /// A router with nobody connected, sending datagrams through `datagrams`.
    #[must_use]
    pub fn new(datagrams: Box<dyn Datagrams>, details: ServerDetails) -> Self {
        Self {
            snapshot: RoutingSnapshot::new(),
            peers: HashMap::new(),
            by_session: HashMap::new(),
            by_addr: HashMap::new(),
            by_host: HashMap::new(),
            datagrams,
            details,
            stats: RouterStats::default(),
            heard_from: HashMap::new(),
        }
    }

    /// Install the transport sealed audio leaves by.
    ///
    /// Separate from construction because a UDP socket binds later than the
    /// service starts and binding can fail. Until this is called the router
    /// tunnels everything over TCP, which is the same path a client behind a
    /// UDP-blocking firewall uses for its whole session — so "no socket yet" is
    /// a working state, not a broken one.
    pub fn use_datagrams(&mut self, datagrams: Box<dyn Datagrams>) {
        self.datagrams = datagrams;
    }

    /// Replace the view of who hears whom.
    pub fn publish(&mut self, snapshot: RoutingSnapshot) {
        self.snapshot = snapshot;
    }

    /// Take on a peer that has finished its handshake.
    ///
    /// `host` is where its control connection came from, which is the hint that
    /// makes the first datagram cheap to attribute.
    pub fn attach(&mut self, peer: VoicePeer, host: IpAddr) {
        let conn = peer.conn();
        // The host is the hint every unbound datagram is matched against, so a
        // mismatch between this and the address audio actually arrives from is
        // silent and total. Logged once per peer, which is rare.
        debug!(%conn, session = %peer.session(), %host, "voice peer attached, expecting audio from this host");
        let _ = self.by_session.insert(peer.session(), conn);
        let known = self.by_host.entry(host).or_default();
        if !known.contains(&conn) {
            known.push(conn);
        }
        let _ = self.peers.insert(conn, peer);
    }

    /// Forget a peer and every index that mentions it.
    ///
    /// A leak here is unbounded — one entry per disconnect, for the life of the
    /// process — so every map is cleared, not just the obvious one.
    pub fn detach(&mut self, conn: ConnId) {
        let Some(peer) = self.peers.remove(&conn) else {
            return;
        };
        let _ = self.by_session.remove(&peer.session());
        let _ = self.heard_from.remove(&peer.session());
        self.by_addr.retain(|_, bound| *bound != conn);
        self.by_host.retain(|_, known| {
            known.retain(|bound| *bound != conn);
            !known.is_empty()
        });
    }

    /// Whether a connection has a voice path.
    #[must_use]
    pub fn has(&self, conn: ConnId) -> bool {
        self.peers.contains_key(&conn)
    }

    /// How many peers are attached.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.peers.len()
    }

    /// Counters, for the admin surface.
    #[must_use]
    pub fn stats(&self) -> RouterStats {
        let mut by_speaker: Vec<_> = self
            .heard_from
            .iter()
            .map(|(session, frames)| (*session, *frames))
            .collect();
        by_speaker.sort_by_key(|(session, _)| session.0);

        RouterStats {
            attached: self.peers.len(),
            by_speaker,
            ..self.stats.clone()
        }
    }

    /// Handle one frame of audio, from wherever it arrived.
    pub fn accept(&mut self, from: AudioSource, frame: &[u8]) {
        let Some((origin, plain)) = self.attribute(from, frame) else {
            self.stats.unattributed = self.stats.unattributed.saturating_add(1);
            self.report_unattributed(from, frame.len());
            return;
        };

        // Learning the address *after* the packet authenticated is the whole
        // point: binding on arrival would let anyone redirect a victim's audio
        // by sending one spoofed datagram from the right port.
        if let Attributed::Datagram(conn, addr) = origin {
            self.bind(conn, addr);
        }

        let conn = origin.conn();
        let Some(peer) = self.peers.get(&conn) else {
            return;
        };

        match peer.codec().decode(&plain) {
            Ok(Datagram::Audio(packet)) => self.route(conn, packet),
            Ok(Datagram::Ping(ping)) => {
                let details = ping.wants_details.then_some(self.details);
                let reply = peer.codec().encode_ping(&ping, details);
                self.reply(conn, origin, &reply);
            }
            Err(_) => self.stats.malformed = self.stats.malformed.saturating_add(1),
        }
    }

    /// Answer an unauthenticated ping on the voice port.
    ///
    /// Served before anyone has connected, which is how a client discovers
    /// whether UDP works at all and how the public server list measures a
    /// server it has never spoken to. Deliberately not encrypted: there is no
    /// session to encrypt under, and nothing here is secret.
    pub fn accept_anonymous_ping(&mut self, addr: SocketAddr, frame: &[u8]) {
        // Protobuf only. A stock client that has not connected sends the legacy
        // form, but so does every amplification-attack toolkit, and upstream
        // removed the legacy anonymous ping for exactly that reason.
        let Ok(Datagram::Ping(ping)) = ProtobufCodec.decode(frame) else {
            self.stats.unattributed = self.stats.unattributed.saturating_add(1);
            return;
        };
        let details = ping.wants_details.then_some(self.details);
        self.datagrams
            .send_to(addr, ProtobufCodec.encode_ping(&ping, details));
    }

    /// Say something about a datagram nobody claimed — but not every time.
    ///
    /// An open UDP port receives whatever the internet sends it, so a line per
    /// stray datagram is a denial of service anyone can trigger. The first few
    /// are what matter anyway: a misconfiguration shows up immediately and then
    /// repeats forever, so the interesting information is entirely in the start.
    ///
    /// The address and the candidates it was tried against are both here because
    /// the two failures look identical from a counter and have opposite fixes:
    /// *no candidates* means the datagram came from somewhere no session is
    /// known at, and *candidates that all failed* means the keys disagree.
    fn report_unattributed(&self, from: AudioSource, len: usize) {
        /// How many to report before falling silent.
        const LOUD_UNTIL: u64 = 5;

        if self.stats.unattributed > LOUD_UNTIL {
            return;
        }
        let AudioSource::Datagram(addr) = from else {
            debug!(?from, len, "tunnelled audio could not be decrypted");
            return;
        };

        let candidates = self.by_host.get(&addr.ip()).map_or(0, Vec::len);
        debug!(
            %addr,
            len,
            candidates,
            bound_addresses = self.by_addr.len(),
            known_hosts = ?self.by_host.keys().collect::<Vec<_>>(),
            "voice datagram matched no session"
        );
    }

    /// Work out which peer sent `frame`, and decrypt it.
    ///
    /// Returns `None` when nothing authenticates it, which is the normal state
    /// of an open UDP port rather than an error.
    fn attribute(&mut self, from: AudioSource, frame: &[u8]) -> Option<(Attributed, Vec<u8>)> {
        match from {
            // TLS already proved who this is, and already protected the bytes.
            //
            // Tunnelled audio is **not** encrypted: murmur feeds the raw payload
            // straight to its routing (`Server.cpp:1905`), because the frame
            // travelled inside TLS and the voice cipher exists for the UDP path,
            // which has no protection of its own.
            //
            // Decrypting here fails every frame and drops it — and a client that
            // has fallen back to tunnelling never goes back to UDP, so it goes
            // silent for the rest of the session while every counter looks fine.
            AudioSource::Tunnel(conn) => self
                .peers
                .contains_key(&conn)
                .then(|| (Attributed::Tunnel(conn), frame.to_vec())),

            AudioSource::Datagram(addr) => {
                // The bound address first: one trial decryption for essentially
                // every packet on a settled connection.
                if let Some(conn) = self.by_addr.get(&addr).copied() {
                    if let Some(plain) = self.peers.get_mut(&conn).and_then(|p| p.open(frame).ok())
                    {
                        return Some((Attributed::Datagram(conn, addr), plain));
                    }
                }

                // Otherwise the peers known at that host, most likely first. A
                // NAT that changed port costs one or two attempts, not a scan of
                // every session on the server.
                let candidates = self.by_host.get(&addr.ip()).cloned().unwrap_or_default();
                for conn in candidates {
                    if let Some(plain) = self.peers.get_mut(&conn).and_then(|p| p.open(frame).ok())
                    {
                        return Some((Attributed::Datagram(conn, addr), plain));
                    }
                }
                None
            }
        }
    }

    /// Record that `conn`'s datagrams arrive from `addr`.
    fn bind(&mut self, conn: ConnId, addr: SocketAddr) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            if peer.udp_addr() == Some(addr) {
                return; // Already known: the overwhelmingly common case.
            }
            // A peer that moved leaves a stale entry that a later peer could
            // otherwise inherit.
            self.by_addr.retain(|_, bound| *bound != conn);
            peer.bind(addr);
        }
        let _ = self.by_addr.insert(addr, conn);
        self.by_host.entry(addr.ip()).or_default().push(conn);
    }

    /// Fan one decoded frame out to everyone who should hear it.
    fn route(&mut self, from: ConnId, mut packet: AudioPacket) {
        let Some(speaker) = self.peers.get(&from).map(VoicePeer::session) else {
            return;
        };

        // Counted before anything can drop the frame, so a silenced or
        // unrouted speaker still shows as transmitting. "We hear you but send
        // you nowhere" and "we never hear you" need different fixes.
        *self.heard_from.entry(speaker).or_default() += 1;

        let target = Target::decode(packet.target);
        // Overwriting rather than trusting: the sender field arrived from a peer
        // that could have written anyone's id in it.
        packet.sender = speaker;

        let listeners = self.snapshot.recipients(speaker, target);
        if listeners.is_empty() {
            if !self.snapshot.may_speak(speaker) {
                self.stats.silenced = self.stats.silenced.saturating_add(1);
            }
            return;
        }

        // The context a listener sees, which is not the target the speaker set.
        packet.target = context_for(target);
        self.stats.routed = self.stats.routed.saturating_add(1);

        for session in listeners {
            let Some(conn) = self.by_session.get(&session).copied() else {
                continue;
            };
            self.send_to_peer(conn, &packet);
        }
    }

    /// Encode, encrypt and deliver one frame to one peer.
    fn send_to_peer(&mut self, conn: ConnId, packet: &AudioPacket) {
        let Some(peer) = self.peers.get_mut(&conn) else {
            return;
        };
        let encoded = peer.codec().encode_audio(packet);

        let sent = match peer.udp_addr() {
            // The UDP path, once the peer has proven it works. This is the only
            // place the voice cipher belongs: a datagram crosses the network
            // with nothing else protecting it.
            Some(addr) => {
                let Ok(sealed) = peer.seal(&encoded) else {
                    // Counter exhaustion or a cipher fault, and retrying with
                    // the next packet is not the remedy for either.
                    self.stats.dropped = self.stats.dropped.saturating_add(1);
                    return;
                };
                self.datagrams.send_to(addr, Bytes::from(sealed));
                true
            }
            // No working UDP path: tunnel it over the TLS connection, in the
            // clear, because TLS has already done the job. Every client behind a
            // restrictive firewall lives here permanently.
            None => peer.tunnel(&encoded),
        };

        if sent {
            self.stats.delivered = self.stats.delivered.saturating_add(1);
        } else {
            self.stats.dropped = self.stats.dropped.saturating_add(1);
        }
    }

    /// Send a reply back the way the request came, sealed for that peer.
    ///
    /// Sealing matters and is easy to forget: a connected client decrypts
    /// everything on its voice path, so a plaintext reply is not a readable
    /// reply — it is a packet the client discards. Only the *anonymous* ping is
    /// unencrypted, and that one never reaches this method because there is no
    /// session to encrypt it under.
    fn reply(&mut self, conn: ConnId, origin: Attributed, frame: &[u8]) {
        let Some(peer) = self.peers.get_mut(&conn) else {
            return;
        };

        match origin {
            // Sealed, because a datagram crosses the network unprotected.
            Attributed::Datagram(_, addr) => {
                let Ok(sealed) = peer.seal(frame) else {
                    self.stats.dropped = self.stats.dropped.saturating_add(1);
                    return;
                };
                self.datagrams.send_to(addr, Bytes::from(sealed));
            }
            // In the clear, because TLS already protected it.
            Attributed::Tunnel(_) => {
                let _ = peer.tunnel(frame);
            }
        }
    }
}

/// What the listener is told about why it is hearing this.
///
/// The protobuf field is `target` inbound and `context` outbound, and they are
/// not the same numbers: 0 normal, 1 shout, 2 whisper, 3 via a listener.
const fn context_for(target: Target) -> u8 {
    match target {
        Target::Normal | Target::Loopback => 0,
        // Every registered target is reported as a shout until `VoiceTarget`
        // exists to say which kind it was.
        Target::Whisper(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::codec_for;
    use crate::testing::{RecordingDatagrams, TestPeer};
    use starling_gate::UdpFormat;
    use starling_model::ChannelId;

    const LOBBY: ChannelId = ChannelId(0);
    const ALICE: SessionId = SessionId(1);
    const BOB: SessionId = SessionId(2);

    fn addr(port: u16) -> SocketAddr {
        format!("203.0.113.7:{port}").parse().expect("test address")
    }

    fn details() -> ServerDetails {
        ServerDetails {
            version: 1,
            users: 2,
            max_users: 10,
            max_bandwidth: 72_000,
        }
    }

    /// Where each peer's datagrams come from.
    const ALICE_AT: u16 = 50_000;
    const BOB_AT: u16 = 50_100;

    /// A router with Alice and Bob in the lobby, neither with a proven UDP path.
    ///
    /// This is the state every connection starts in, and the one where audio is
    /// tunnelled: a peer's address is only believed once a packet from it has
    /// authenticated.
    fn lobby() -> (Router, RecordingDatagrams, TestPeer, TestPeer) {
        let sent = RecordingDatagrams::new();
        let mut router = Router::new(Box::new(sent.clone()), details());

        let alice = TestPeer::new(ConnId(1), ALICE, UdpFormat::Protobuf);
        let bob = TestPeer::new(ConnId(2), BOB, UdpFormat::Protobuf);
        router.attach(alice.attach(), addr(0).ip());
        router.attach(bob.attach(), addr(0).ip());
        router.publish(
            RoutingSnapshot::new()
                .with_member(ALICE, LOBBY)
                .with_member(BOB, LOBBY),
        );
        (router, sent, alice, bob)
    }

    /// The same lobby, with both peers' UDP paths proven.
    ///
    /// A client proves its path by sending, so the setup produces traffic of its
    /// own — cleared afterwards, or every test would start one datagram behind.
    fn lobby_on_udp() -> (Router, RecordingDatagrams, TestPeer, TestPeer) {
        let (mut router, sent, mut alice, mut bob) = lobby();
        let probe = alice.speak(b"probe");
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &probe);
        let probe = bob.speak(b"probe");
        router.accept(AudioSource::Datagram(addr(BOB_AT)), &probe);
        sent.clear();
        (router, sent, alice, bob)
    }

    #[test]
    fn a_datagram_from_a_known_peer_reaches_the_channel() {
        // The whole point of the crate, in one assertion.
        let (mut router, sent, mut alice, mut bob) = lobby_on_udp();
        let frame = alice.speak(b"hello");

        let before = router.stats().routed;
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &frame);

        assert_eq!(router.stats().routed, before + 1);
        let (to, bytes) = sent.only();
        assert_eq!(to, addr(BOB_AT), "the frame went to the wrong peer");
        assert_eq!(bob.hear(&bytes).opus, Bytes::from_static(b"hello"));
    }

    #[test]
    fn a_peer_is_tunnelled_until_its_udp_path_is_proven() {
        // Every connection starts here, and a client behind a UDP-blocking
        // firewall never leaves. Assuming UDP works would silence all of them.
        let (mut router, sent, mut alice, bob) = lobby();
        router.accept(
            AudioSource::Datagram(addr(ALICE_AT)),
            &alice.speak(b"hello"),
        );

        assert!(sent.is_empty(), "audio went to an address nobody proved");
        assert_eq!(bob.tunnelled().len(), 1);
    }

    #[test]
    fn the_listener_is_told_who_spoke() {
        // Without this nobody can attribute audio, and with it forged the wrong
        // person's talking indicator lights up.
        let (mut router, sent, mut alice, mut bob) = lobby_on_udp();
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &alice.speak(b"x"));
        assert_eq!(bob.hear(&sent.only().1).sender, ALICE);
    }

    #[test]
    fn a_claimed_sender_is_overwritten() {
        // Alice writes Bob's session into her own packet. Every listener must
        // still be told it came from Alice.
        let (mut router, sent, mut alice, mut bob) = lobby_on_udp();
        let frame = alice.speak_as(BOB, b"impersonation");
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &frame);
        assert_eq!(bob.hear(&sent.only().1).sender, ALICE);
    }

    #[test]
    fn a_datagram_nobody_can_decrypt_is_counted_and_dropped() {
        // The normal background noise of an open UDP port.
        let (mut router, sent, _, _) = lobby();
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), b"not a voice packet");
        assert_eq!(router.stats().unattributed, 1);
        assert!(sent.is_empty());
    }

    #[test]
    fn an_address_is_only_bound_once_a_packet_authenticates() {
        // The attack: send one spoofed datagram from Bob's address and take over
        // where his audio goes.
        let (mut router, _, _, _) = lobby();
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), b"garbage");
        assert!(
            router.by_addr.is_empty(),
            "an unauthenticated address bound"
        );
    }

    #[test]
    fn a_peer_whose_port_moved_is_found_and_rebound() {
        // NAT rebinding is routine, and the old entry must not survive: a later
        // peer arriving at that address would inherit the session.
        let (mut router, sent, mut alice, _) = lobby_on_udp();
        router.accept(
            AudioSource::Datagram(addr(ALICE_AT + 1)),
            &alice.speak(b"moved"),
        );

        assert_eq!(router.by_addr.get(&addr(ALICE_AT + 1)), Some(&ConnId(1)));
        assert_eq!(
            router.by_addr.get(&addr(ALICE_AT)),
            None,
            "stale binding kept"
        );
        assert_eq!(sent.count(), 1, "the frame was lost across the rebinding");
    }

    #[test]
    fn a_peer_with_no_udp_path_is_tunnelled() {
        // Everyone behind a restrictive firewall depends on this.
        let (mut router, sent, mut alice, bob) = lobby();
        let frame = alice.speak_tunnelled(b"tunnelled");
        router.accept(AudioSource::Tunnel(ConnId(1)), &frame);

        assert!(
            sent.is_empty(),
            "audio went out over UDP with no bound address"
        );
        assert_eq!(bob.tunnelled().len(), 1);
    }

    #[test]
    fn a_speaker_does_not_hear_themselves() {
        let (mut router, sent, mut alice, _) = lobby_on_udp();
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &alice.speak(b"x"));

        assert_eq!(sent.count(), 1, "the frame came back to its speaker");
        assert_eq!(sent.only().0, addr(BOB_AT));
    }

    #[test]
    fn a_silenced_speaker_is_counted_and_dropped() {
        let (mut router, sent, mut alice, _) = lobby();
        router.publish(
            RoutingSnapshot::new()
                .with_member(ALICE, LOBBY)
                .with_member(BOB, LOBBY)
                .with_silenced(ALICE),
        );
        router.accept(AudioSource::Datagram(addr(50_000)), &alice.speak(b"x"));

        assert!(sent.is_empty());
        assert_eq!(router.stats().silenced, 1);
        assert_eq!(router.stats().routed, 0);
    }

    #[test]
    fn loopback_returns_to_the_speaker() {
        // How a client proves its UDP path works before trusting it with audio.
        let (mut router, sent, mut alice, _) = lobby_on_udp();
        let frame = alice.speak_to(crate::routing::SERVER_LOOPBACK, b"echo");
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &frame);

        let (to, bytes) = sent.only();
        assert_eq!(to, addr(ALICE_AT));
        assert_eq!(alice.hear(&bytes).opus, Bytes::from_static(b"echo"));
    }

    #[test]
    fn a_frame_is_re_encoded_for_a_listener_on_the_other_format() {
        // A 1.4 client and a 1.5 client in one channel. Relaying the bytes
        // unchanged would hand one of them a packet it cannot parse.
        let sent = RecordingDatagrams::new();
        let mut router = Router::new(Box::new(sent.clone()), details());

        let mut alice = TestPeer::new(ConnId(1), ALICE, UdpFormat::Protobuf);
        let mut bob = TestPeer::new(ConnId(2), BOB, UdpFormat::Legacy);
        router.attach(alice.attach(), addr(0).ip());
        router.attach(bob.attach(), addr(0).ip());
        router.publish(
            RoutingSnapshot::new()
                .with_member(ALICE, LOBBY)
                .with_member(BOB, LOBBY),
        );

        let frame = alice.speak_tunnelled(b"crossformat");
        router.accept(AudioSource::Tunnel(ConnId(1)), &frame);
        let heard = bob.hear_tunnelled();
        assert_eq!(heard.opus, Bytes::from_static(b"crossformat"));
        assert_eq!(heard.sender, ALICE);
    }

    #[test]
    fn a_ping_is_answered_on_the_path_it_arrived_by() {
        let (mut router, sent, mut alice, _) = lobby_on_udp();
        let ping = alice.ping(7);
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &ping);

        let (to, bytes) = sent.only();
        assert_eq!(to, addr(ALICE_AT));
        assert_eq!(alice.hear_ping(&bytes).timestamp, 7);
    }

    #[test]
    fn an_anonymous_ping_is_answered_without_a_session() {
        // How the public server list measures a server nobody has connected to.
        let (mut router, sent, _, _) = lobby();
        let probe = codec_for(UdpFormat::Protobuf).encode_ping(
            &crate::packet::Ping {
                timestamp: 99,
                wants_details: true,
            },
            None,
        );
        router.accept_anonymous_ping(addr(ALICE_AT), &probe);
        assert_eq!(sent.count(), 1);
    }

    #[test]
    fn an_anonymous_ping_that_is_not_a_ping_is_dropped() {
        // The port is open to the internet; anything can arrive.
        let (mut router, sent, _, _) = lobby();
        router.accept_anonymous_ping(addr(ALICE_AT), b"amplify me");
        assert!(sent.is_empty());
    }

    #[test]
    fn detaching_clears_every_index() {
        let (mut router, _, mut alice, _) = lobby_on_udp();
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &alice.speak(b"x"));
        router.detach(ConnId(1));

        assert!(!router.has(ConnId(1)));
        assert!(
            !router.by_addr.values().any(|bound| *bound == ConnId(1)),
            "address index leaked"
        );
        assert!(
            !router.by_session.contains_key(&ALICE),
            "session index leaked"
        );
        assert!(
            router
                .by_host
                .values()
                .all(|known| !known.contains(&ConnId(1))),
            "host index leaked"
        );
    }

    #[test]
    fn detaching_one_peer_leaves_another_at_the_same_host() {
        let (mut router, _, _, _) = lobby();
        router.detach(ConnId(1));
        assert!(router.has(ConnId(2)));
        assert_eq!(router.attached(), 1);
    }

    #[test]
    fn detaching_an_unknown_connection_is_harmless() {
        let (mut router, _, _, _) = lobby();
        router.detach(ConnId(99));
        assert_eq!(router.attached(), 2);
    }

    #[test]
    fn audio_for_a_departed_peer_is_dropped_not_delivered_elsewhere() {
        let (mut router, sent, mut alice, _) = lobby();
        router.detach(ConnId(2));
        let frame = alice.speak_tunnelled(b"x");
        router.accept(AudioSource::Tunnel(ConnId(1)), &frame);
        assert!(sent.is_empty());
    }

    #[test]
    fn a_replayed_datagram_is_refused_by_the_cipher() {
        // The cipher's job, asserted here because this is where it matters:
        // a replayed frame reaching the fan-out is audio played twice.
        let (mut router, sent, mut alice, _) = lobby_on_udp();
        let frame = alice.speak(b"once");
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &frame);
        router.accept(AudioSource::Datagram(addr(ALICE_AT)), &frame);

        assert_eq!(sent.count(), 1, "a replay was routed");
        assert_eq!(
            router.stats().unattributed,
            1,
            "a replay must be unattributable"
        );
    }

    #[test]
    fn a_frame_that_decrypts_but_does_not_parse_is_counted() {
        let (mut router, sent, mut alice, _) = lobby();
        router.accept(
            AudioSource::Tunnel(ConnId(1)),
            &alice.seal_raw(&[0xFF, 0xFF]),
        );
        assert_eq!(router.stats().malformed, 1);
        assert!(sent.is_empty());
    }

    #[test]
    fn a_peer_that_cannot_keep_up_is_counted_not_stalled() {
        // One slow client must not be able to hold up everyone else's audio, so
        // its frames are dropped rather than queued.
        let sent = RecordingDatagrams::new();
        let mut router = Router::new(Box::new(sent.clone()), details());
        let mut alice = TestPeer::new(ConnId(1), ALICE, UdpFormat::Protobuf);
        let bob = TestPeer::new(ConnId(2), BOB, UdpFormat::Protobuf);
        router.attach(alice.attach(), addr(0).ip());
        router.attach(bob.attach_stuck(), addr(0).ip());
        router.publish(
            RoutingSnapshot::new()
                .with_member(ALICE, LOBBY)
                .with_member(BOB, LOBBY),
        );

        let frame = alice.speak_tunnelled(b"unheard");
        router.accept(AudioSource::Tunnel(ConnId(1)), &frame);

        assert_eq!(router.stats().dropped, 1);
        assert_eq!(router.stats().delivered, 0);
        assert!(bob.tunnelled().is_empty());
    }

    #[test]
    fn tunnelled_audio_is_not_decrypted() {
        // The bug this file exists to remember: `UDPTunnel` runs inside TLS and
        // carries plaintext (murmur, `Server.cpp:1905`). Decrypting it fails
        // every frame — and a real client that falls back to tunnelling never
        // goes back to UDP, so it is silent for the rest of the session while
        // every aggregate counter still looks healthy.
        let (mut router, _, mut alice, bob) = lobby();
        let plain = alice.speak_tunnelled(b"in the clear");
        router.accept(AudioSource::Tunnel(ConnId(1)), &plain);

        assert_eq!(
            router.stats().routed,
            1,
            "plaintext tunnelled audio was refused"
        );
        assert_eq!(bob.tunnelled().len(), 1);
    }

    #[test]
    fn a_sealed_frame_on_the_tunnel_is_refused() {
        // The other half. Nothing should be encrypting on this path, so a sealed
        // frame arriving here means a peer is confused about the transport —
        // and it must not be mistaken for audio.
        let (mut router, _, mut alice, bob) = lobby();
        let sealed = alice.speak(b"wrongly sealed");
        router.accept(AudioSource::Tunnel(ConnId(1)), &sealed);

        assert_eq!(router.stats().routed, 0);
        assert!(bob.tunnelled().is_empty());
    }

    #[test]
    fn tunnelled_audio_leaves_as_a_control_message() {
        // Raw audio bytes on the TLS socket would be read as a message header
        // and desynchronise the connection outright — a far worse failure than
        // silence, and one that would look like a protocol error somewhere else.
        let (mut router, _, mut alice, bob) = lobby();
        let plain = alice.speak_tunnelled(b"framed");
        router.accept(AudioSource::Tunnel(ConnId(1)), &plain);

        let frames = bob.tunnelled();
        let framed = frames.first().expect("nothing was tunnelled");
        assert_eq!(
            u16::from_be_bytes([framed[0], framed[1]]),
            starling_proto::TcpMessageType::UdpTunnel.id(),
            "tunnelled audio is not framed as a UDPTunnel message"
        );
    }

    #[test]
    fn nothing_in_a_hostile_datagram_panics_the_router() {
        // Every byte here came off an open UDP port.
        let (mut router, _, _, _) = lobby();
        for lead in 0..=255_u8 {
            for len in 0..40 {
                let mut bytes = vec![lead];
                bytes.extend((0..len).map(|i: u8| i.wrapping_mul(31)));
                router.accept(AudioSource::Datagram(addr(ALICE_AT)), &bytes);
                router.accept_anonymous_ping(addr(ALICE_AT), &bytes);
            }
        }
    }
}
