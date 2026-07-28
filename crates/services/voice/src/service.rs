//! The service: the UDP loop, the cipher mint, and the membership cache.
//!
//! **A restarted service has cold caches and no way to say so** — voice holds
//! ciphers and membership, and audio arriving before it has re-subscribed is
//! dropped silently. That is the failure mode with no log line
//! (`PORTING-PLAN.md` R11), so readiness gates on the subscription being warm
//! rather than on the process being alive.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use prost::Message as _;
use starling_crypto::{CompatibilityFirstProfiles, ProfileFactory as _, VoiceSecrets};
use starling_gate::{Gate, MumbleVersion, UdpFormat};
use starling_proto::MUMBLE_VERSION;
use starling_proto::proto::tcp;
use starling_proto_fancy::common::{Ack, Scope};
use starling_proto_fancy::serverconfig::GetRequest as ConfigRequest;
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::sessionview::{SubscribeRequest, ViewEvent, view_event};
use starling_proto_fancy::types::ServiceKind;
use starling_proto_fancy::voice::voice_server::{Voice, VoiceServer};
use starling_proto_fancy::voice::{
    CryptMaterial, EndpointRequest, ForgetRequest, MintRequest, PeerStats, ResyncRequest,
    StatsRequest, VoiceEndpoint,
};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tonic::{Request, Response, Status};

use crate::packet::ServerDetails;
use crate::peer::VoicePeer;
use crate::ports::{AudioSource, SessionId};
use crate::router::Router;
use crate::socket::{NoDatagrams, VoiceSocket};
use crate::tunnel::GatewayTunnel;
use crate::view::SessionCache;

/// Upstream `UDPTunnel`: audio over TCP, for a client whose UDP is blocked.
const UDP_TUNNEL: u16 = 1;
/// Upstream `VoiceTarget`.
const VOICE_TARGET: u16 = 19;

/// How long to wait before re-subscribing to `session-view`.
///
/// Short, because of what a stale membership table costs: a session missing
/// from it is a session nobody hears and who hears nobody, and there is no log
/// line for that — the call simply has a silent participant.
const VIEW_RETRY: Duration = Duration::from_secs(1);

/// The readiness gate this service is useless without.
const VIEW_GATE: &str = "session view";

/// How often the numbers a ping is answered with are refreshed.
///
/// Pushed in on a timer rather than fetched when a ping arrives, for two
/// reasons. **Nothing on the packet path may make a request**
/// (`docs/ARCHITECTURE.md` §3), and a ping is answered from that path. And the
/// peer asking is unauthenticated — a fetch per ping would turn an open UDP
/// port into a lever anyone can pull on `session-view`, which is the one
/// service every other service reads through.
///
/// A user count a few seconds stale in a server browser costs nothing.
const DETAILS_REFRESH: Duration = Duration::from_secs(5);

/// What a ping reports before the first refresh has answered.
///
/// murmur's own defaults, so a server browser reading Starling in the first few
/// seconds after a restart sees what it would have seen from murmur rather than
/// zeroes.
const DEFAULT_MAX_USERS: u32 = 100;
/// Per-user audio bandwidth ceiling reported before the first refresh.
const DEFAULT_MAX_BANDWIDTH: u32 = 72_000;

/// The service.
#[derive(Debug)]
pub struct VoiceService {
    sessions: Mutex<HashMap<u32, Minted>>,
    socket: Option<Arc<VoiceSocket>>,
    endpoint: Option<(String, u32)>,
    fanout: Fanout,
    /// The packet path.
    ///
    /// Always present, including when no UDP socket is configured: that
    /// deployment serves every client over the tunnel, and a router that only
    /// existed alongside a socket meant tunnelled audio did not work either.
    ///
    /// A `std::sync::Mutex` and not tokio's: every router call is synchronous
    /// and short, and an async lock on the audio path would add a scheduling
    /// point per datagram to buy nothing.
    router: Mutex<Router>,
    /// Who is in which channel, and who may be heard.
    view: SessionCache,
}

impl VoiceService {
    /// The packet path, whatever state a previous caller left it in.
    ///
    /// A panic on the audio path must not silence the server for the rest of
    /// the process: continuing from state one frame did not finish updating is
    /// a far better outcome than dropping every frame forever.
    fn router(&self) -> MutexGuard<'_, Router> {
        match self.router.lock() {
            Ok(router) => router,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Mint a session's keys, and put the peer on the packet path.
    ///
    /// Both halves belong here because they are one decision. The cipher is
    /// chosen from the **Fancy** version the client announced and the wire
    /// format from its **Mumble** version — the two axes are independent, and
    /// conflating them is the classic Mumble porting bug (`starling-gate`).
    /// [`CompatibilityFirstProfiles`] is what holds them together: legacy
    /// framing has nowhere to put a cipher id, so a peer on it is served OCB2
    /// whatever its Fancy version claims.
    fn mint(&self, request: &MintRequest) -> CryptMaterial {
        let gate = Gate::for_peer((request.fancy_version != 0).then_some(request.fancy_version));
        let mumble = MumbleVersion::from_wire(request.mumble_version);

        let Ok(profile) = CompatibilityFirstProfiles.build(mumble, gate) else {
            // The default factory serves every client that exists, so this is
            // a deployment running a stricter one — not a client fault.
            tracing::warn!(
                session = request.session,
                "this deployment does not serve this peer's voice profile"
            );
            return CryptMaterial::default();
        };
        let Some(choice) = profile.cipher_choice() else {
            tracing::error!("a UDP peer was given a profile with no cipher");
            return CryptMaterial::default();
        };
        let Ok(secrets) = VoiceSecrets::generate(choice) else {
            // Refusing beats a weaker fallback: a silent downgrade would apply
            // to every session generated after the entropy source faltered.
            tracing::error!("could not generate voice key material");
            return CryptMaterial::default();
        };

        let (key, client_nonce, server_nonce) = secrets.to_wire();
        let payload = tcp::CryptSetup {
            key: Some(key),
            client_nonce: Some(client_nonce),
            server_nonce: Some(server_nonce),
        }
        .encode_to_vec();

        // The two version axes and what they produced, once per session. A
        // peer served the wrong framing is inaudible with no other symptom, and
        // this is the only place both inputs and the decision are together.
        tracing::debug!(
            session = request.session,
            mumble_version = request.mumble_version,
            fancy_version = request.fancy_version,
            format = ?profile.format(),
            cipher = ?choice,
            "voice profile negotiated"
        );
        self.attach(request, profile.format(), &secrets);
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.insert(
                request.session,
                Minted {
                    conn: request.conn,
                    fancy_version: request.fancy_version,
                    mumble_version: request.mumble_version,
                    address: request.address.clone(),
                },
            );
        }
        CryptMaterial {
            crypt_setup: payload,
            cipher: format!("{choice:?}"),
        }
    }

    /// Put one peer on the packet path, or replace the one already there.
    ///
    /// Called from minting rather than from `opened`, because a peer is not
    /// routable until it has both a session id and a key — before that there is
    /// nothing to attribute a datagram to and nothing to seal a frame with.
    ///
    /// A resync goes through here too, and replacing is the correct outcome:
    /// the client has just been handed fresh material, so the cipher held here
    /// is the stale one.
    fn attach(&self, request: &MintRequest, format: UdpFormat, secrets: &VoiceSecrets) {
        let peer = VoicePeer::new(
            request.conn,
            SessionId(request.session),
            format,
            secrets.server_cipher(),
            // Tunnelled until one of this peer's datagrams authenticates —
            // which is where every connection starts, and where a client behind
            // a UDP-blocking firewall stays.
            Box::new(GatewayTunnel::new(self.fanout.clone(), request.session)),
        );
        self.router().attach(peer, host_of(&request.address));
    }

    /// Take a peer off the packet path and forget its keys.
    ///
    /// The linear scan is over sessions, not packets: this runs once per
    /// disconnect. Keeping a second conn-keyed index to avoid it would be two
    /// maps to hold in agreement, and the one that fell behind would leak a
    /// peer per disconnect for the life of the process.
    fn detach(&self, conn: u64) {
        self.router().detach(conn);

        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        let Some(session) = sessions
            .iter()
            .find(|(_, minted)| minted.conn == conn)
            .map(|(session, _)| *session)
        else {
            return;
        };
        let _ = sessions.remove(&session);
        if let Some(socket) = &self.socket {
            socket.forget(SessionId(session));
        }
    }

    /// Follow `session-view`, so the packet path knows who hears whom.
    ///
    /// Re-subscribes on failure: a `session-view` restart is a rolling deploy,
    /// not an incident. The stream is also dropped deliberately when this
    /// subscriber falls behind, because a missed delta cannot be repaired from
    /// the next one — reconnecting replaces the whole table, which is the only
    /// way back to agreement.
    fn follow_view(self: Arc<Self>, ctx: ServiceContext) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let scope = ctx.virtual_servers().first().copied().unwrap_or(1);
            loop {
                self.read_view(&ctx, scope).await;
                tokio::time::sleep(VIEW_RETRY).await;
            }
        })
    }

    /// One subscription, from opening it to the stream ending.
    async fn read_view(&self, ctx: &ServiceContext, scope: u32) {
        let Ok(channel) = ctx.resolver.channel("session-view") else {
            // Worth a line: with no view, every frame is routed to nobody, and
            // that is indistinguishable from every client having a broken
            // microphone at once.
            tracing::warn!("cannot reach session-view; no audio will be routed");
            return;
        };
        let Ok(stream) = SessionViewClient::new(channel)
            .subscribe(SubscribeRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
                subscriber: Self::NAME.to_owned(),
            })
            .await
        else {
            return;
        };

        let mut events = stream.into_inner();
        while let Ok(Some(event)) = events.message().await {
            self.apply_view_event(event);
            // After the first event, not before: a subscription opens with a
            // full snapshot, so this is the moment the cache stops being cold.
            // Declaring readiness any earlier is the race that makes a cold
            // cache look warm for one scrape interval.
            ctx.health.ready(VIEW_GATE);
        }
        tracing::warn!("the session-view subscription ended; audio routing is now stale");
    }

    /// Fold one view event into the snapshot the packet path routes against.
    fn apply_view_event(&self, event: ViewEvent) {
        match event.event {
            Some(view_event::Event::Snapshot(list)) => self.view.replace(list.sessions),
            Some(view_event::Event::Upsert(session)) => self.view.upsert(session),
            Some(view_event::Event::Gone(gone)) => self.view.remove(gone.session),
            // A config change composes nothing here: the numbers a ping reports
            // are refreshed on their own timer, and membership is unaffected.
            Some(view_event::Event::ConfigVersion(_)) | None => return,
        }
        let snapshot = self.view.snapshot();
        self.router().publish(snapshot);
    }

    /// Keep the numbers a ping is answered with current, until aborted.
    ///
    /// Its own task rather than an arm of the UDP loop: the two calls below are
    /// gRPC round trips, and awaiting them where datagrams are read would stall
    /// audio for every peer while the server browser's numbers are refreshed.
    fn refresh_details(self: Arc<Self>, ctx: ServiceContext) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let scope = ctx.virtual_servers().first().copied().unwrap_or(1);
            let mut ticker = tokio::time::interval(DETAILS_REFRESH);
            loop {
                // The first tick is immediate, so a restarted service reports
                // real numbers within one round trip rather than one interval.
                let _ = ticker.tick().await;
                let (details, allow_ping) = self.details(&ctx, scope).await;
                let mut router = self.router();
                router.set_details(details);
                router.set_allow_ping(allow_ping);
            }
        })
    }

    /// What a ping should be answered with right now, and whether to answer.
    ///
    /// Every source is optional on purpose. A ping that reports a stale user
    /// count is worth answering; one that is not answered at all makes the
    /// server look down to a browser, and being absent from the server list is
    /// a worse failure than being listed with yesterday's numbers.
    async fn details(&self, ctx: &ServiceContext, scope: u32) -> (ServerDetails, bool) {
        let mut details = ServerDetails {
            version: MUMBLE_VERSION.encode_v2(),
            users: 0,
            max_users: DEFAULT_MAX_USERS,
            max_bandwidth: DEFAULT_MAX_BANDWIDTH,
        };
        // murmur's default. If server-config cannot be reached, answering is the
        // safer of the two wrong answers: the alternative disappears from every
        // server browser over a dependency being briefly down.
        let mut allow_ping = true;

        // The ceilings are operational settings, so they come from the service
        // that owns them rather than from this deployment's TOML: an operator
        // who raises `max_users` at runtime expects the browser to say so.
        if let Ok(channel) = ctx.resolver.channel("server-config")
            && let Ok(snapshot) = ServerConfigClient::new(channel)
                .get(ConfigRequest {
                    scope: Some(Scope {
                        virtual_server: scope,
                    }),
                })
                .await
        {
            let snapshot = snapshot.into_inner();
            details.max_users = snapshot.max_users;
            details.max_bandwidth = snapshot.max_bandwidth;
            allow_ping = snapshot.allow_ping;
        }

        // The count has to be the whole server's, not this pod's. `session-view`
        // is the only thing that knows it: with more than one gateway, the
        // connections one voice service can see are a fraction of the answer.
        if let Ok(channel) = ctx.resolver.channel("session-view")
            && let Ok(sessions) = SessionViewClient::new(channel)
                .list(SubscribeRequest {
                    scope: Some(Scope {
                        virtual_server: scope,
                    }),
                    subscriber: Self::NAME.to_owned(),
                })
                .await
        {
            details.users = u32::try_from(sessions.into_inner().sessions.len()).unwrap_or(u32::MAX);
        }

        (details, allow_ping)
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct VoiceRpc(Arc<VoiceService>);

#[tonic::async_trait]
impl Voice for VoiceRpc {
    async fn mint(&self, request: Request<MintRequest>) -> Result<Response<CryptMaterial>, Status> {
        Ok(Response::new(self.0.mint(&request.into_inner())))
    }

    async fn resync(
        &self,
        request: Request<ResyncRequest>,
    ) -> Result<Response<CryptMaterial>, Status> {
        let req = request.into_inner();
        // Repeated resyncs for one session mean the client's audio never
        // decrypts, which the user experiences as silence with a connection
        // that looks fine — worth a line, because nothing else reports it.
        tracing::info!(session = req.session, "voice crypt resync requested");

        // Everything but the key material is carried across from the original
        // mint. Re-deriving the cipher from a fresh guess would hand a stock
        // client the modern cipher on its second try — a silent, one-sided
        // upgrade halfway through a call.
        let Some(previous) = self
            .0
            .sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&req.session).map(Minted::remint))
        else {
            // Nothing was ever minted for this session, so there is no cipher
            // to keep faith with and no connection to re-attach.
            tracing::warn!(session = req.session, "resync for an unknown session");
            return Ok(Response::new(CryptMaterial::default()));
        };
        Ok(Response::new(self.0.mint(&MintRequest {
            session: req.session,
            scope: req.scope,
            ..previous
        })))
    }

    async fn forget(&self, request: Request<ForgetRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let conn = self
            .0
            .sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&req.session).map(|minted| minted.conn));
        if let Some(conn) = conn {
            self.0.detach(conn);
        }
        Ok(Response::new(Ack {}))
    }

    async fn stats(&self, request: Request<StatsRequest>) -> Result<Response<PeerStats>, Status> {
        let req = request.into_inner();
        // Asked of the router and not the socket: an address is recorded when a
        // datagram from it authenticates, so the router is the only thing that
        // knows whether this peer's UDP path was ever *proven* rather than
        // merely configured. That distinction is what a client's own
        // connection indicator shows.
        let udp = self.0.router().on_udp(SessionId(req.session));
        Ok(Response::new(PeerStats {
            udp,
            ..PeerStats::default()
        }))
    }

    async fn endpoint(
        &self,
        _request: Request<EndpointRequest>,
    ) -> Result<Response<VoiceEndpoint>, Status> {
        // Only a Fancy client can be told this. A legacy client sends UDP to
        // the port it made TCP to and cannot be redirected, which is why voice
        // scales vertically for them (`docs/ARCHITECTURE.md` §9).
        let (host, port) = self
            .0
            .endpoint
            .clone()
            .unwrap_or_else(|| (String::new(), 64738));
        Ok(Response::new(VoiceEndpoint { host, port }))
    }
}

impl ClientService for VoiceService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            // The tunnelled path: the same bytes a datagram would have carried,
            // demultiplexed onto the same routing. Upstream's own handler
            // asserts unreachable for exactly this reason — two implementations
            // would be two copies differing only in how the bytes arrived.
            //
            // TLS has already proved who sent this and already protected it, so
            // it is **not** decrypted: the voice cipher exists for the UDP path,
            // which has nothing else guarding it. Opening it here would fail
            // every frame, and a client that has fallen back to tunnelling never
            // returns to UDP — so it would be silent for the rest of its session
            // with every counter looking healthy.
            UDP_TUNNEL => {
                self.router()
                    .accept(AudioSource::Tunnel(inbound.conn), &inbound.payload);
                // Nothing is returned. The recipients of this frame are *other*
                // connections, and each was sealed and queued individually on
                // the way through — an `Actions` reply goes back to the sender,
                // who is the one person who must not hear it.
                Actions::new()
            }
            VOICE_TARGET => Actions::new(),
            _ => Actions::new(),
        }
    }

    async fn closed(&self, conn: u64, _reason: &str) -> Actions {
        // Every service is told about every disconnect, so this arrives without
        // voice having to be asked. Skipping it leaks a peer — and its cipher —
        // per connection, for the life of the process.
        self.detach(conn);
        Actions::new()
    }
}

impl Serve for VoiceService {
    const NAME: &'static str = "voice";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("udp socket");
        // Declared here rather than where it is satisfied, so this service
        // cannot report itself ready before it has said what it is waiting for.
        // A voice service that is up with a cold membership cache routes every
        // frame to nobody, which is the failure mode with no log line
        // (`PORTING-PLAN.md` R11).
        ctx.health.gate(VIEW_GATE);
        let service = ctx.service();
        let socket = match service.udp_listen.as_deref() {
            Some(address) => {
                let socket = VoiceSocket::bind(address).await?;
                ctx.health.ready("udp socket");
                Some(Arc::new(socket))
            }
            None => {
                // No socket configured means tunnelled audio only. Said out
                // loud, because silent UDP is indistinguishable from a firewall
                // problem at the other end.
                tracing::warn!("no udp_listen configured; audio will only arrive tunnelled");
                ctx.health.ready("udp socket");
                None
            }
        };

        let endpoint = service
            .public_url
            .as_deref()
            .and_then(|url| url.rsplit_once(':'))
            .map(|(host, port)| (host.to_owned(), port.parse().unwrap_or(64738)));

        // The router always exists. Its datagram half is the socket's write
        // half when there is one and a discard when there is not — because the
        // *other* half, the tunnel, has to work either way: it is the path
        // every connection starts on and the only one a firewalled client ever
        // gets.
        let datagrams: Box<dyn crate::ports::Datagrams> = match socket.as_ref() {
            Some(socket) => Box::new(socket.sender()),
            None => Box::new(NoDatagrams),
        };
        let router = Mutex::new(Router::new(
            datagrams,
            ServerDetails {
                version: MUMBLE_VERSION.encode_v2(),
                users: 0,
                max_users: DEFAULT_MAX_USERS,
                max_bandwidth: DEFAULT_MAX_BANDWIDTH,
            },
        ));

        Ok(Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            socket,
            endpoint,
            fanout: Fanout::default(),
            router,
            view: SessionCache::new(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(VoiceServer::new(VoiceRpc(Arc::clone(&self))))
            .add_service(plane)
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let refresher = self.clone().refresh_details(ctx.clone());
        let follower = self.clone().follow_view(ctx.clone());

        match self.socket.clone() {
            Some(socket) => self.udp_loop(&ctx, &socket).await,
            // No socket, but emphatically not nothing to do: tunnelled audio
            // arrives through the client plane, and the view subscription above
            // is what makes it routable.
            None => ctx.shutdown.wait().await,
        }

        refresher.abort();
        follower.abort();
        Ok(())
    }
}

impl VoiceService {
    /// Read the voice port until shutdown.
    ///
    /// Attribution, the ping reply and the fan-out all live in the router,
    /// which is transport-blind and synchronous; what happens here is only the
    /// demultiplex.
    async fn udp_loop(&self, ctx: &ServiceContext, socket: &VoiceSocket) {
        let dropped = ctx.metrics.counter("starling_voice_datagrams_dropped");
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => return,
                received = socket.recv() => {
                    match received {
                        Ok((from, bytes)) => self.router().accept_datagram(from, &bytes),
                        Err(error) => {
                            // One bad datagram must not take the socket down.
                            tracing::debug!(%error, "voice datagram error");
                            dropped.inc();
                        }
                    }
                }
            }
        }
    }
}

/// The host a peer's datagrams are expected from.
///
/// murmur's `qhHostUsers`, keyed the same way: by the address the *control*
/// connection came from. It is a hint that narrows an unproven datagram to a
/// few candidate keys — never a conclusion, because the peer is whoever's key
/// authenticates the packet.
///
/// An address that will not parse costs this peer its UDP path and nothing
/// else: no candidate is ever tried for it, so its audio tunnels for the whole
/// session. That is a working configuration, which is why it is not an error.
fn host_of(address: &str) -> IpAddr {
    address
        .parse::<SocketAddr>()
        .map(|address| address.ip())
        .or_else(|_| address.parse::<IpAddr>())
        .unwrap_or_else(|_| {
            tracing::debug!(%address, "unparseable peer address; this peer will be tunnelled");
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        })
}

/// The outer type this service owns.
#[must_use]
pub const fn outer_type() -> u16 {
    ServiceKind::Voice.outer_type()
}

/// What a session was minted from.
///
/// Everything a *second* mint for the same session needs, and no key material —
/// the keys went into the peer on the packet path, which is the only thing that
/// uses them.
///
/// Both versions are kept because a resync has to mint under the same profile:
/// handing a stock client `XChaCha20` on its second try, or protobuf framing to
/// a 1.4 client, would be a silent one-sided upgrade halfway through a call.
/// The connection and address are kept because a resync re-attaches, and a peer
/// re-attached at the wrong host loses its UDP path without any other symptom.
#[derive(Debug, Clone)]
pub struct Minted {
    conn: u64,
    fancy_version: u64,
    mumble_version: u64,
    address: String,
}

impl Minted {
    /// The request a resync should mint from.
    ///
    /// Everything but the session and the scope, which the resync carries
    /// itself.
    fn remint(&self) -> MintRequest {
        MintRequest {
            scope: None,
            session: 0,
            fancy_version: self.fancy_version,
            mumble_version: self.mumble_version,
            address: self.address.clone(),
            conn: self.conn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{as_client_hears, as_client_sends};
    use bytes::Bytes;
    use starling_crypto::{LegacyKeys, Ocb2, VoiceCipher, VoiceKeys, XChaCha20Voice, ocb2::Block};
    use starling_gate::{Capability, CipherChoice, FancyVersion};
    use starling_proto::ControlMessage;
    use starling_proto_fancy::control::{ServerAction, server_action};
    use starling_proto_fancy::sessionview::{Session, Sessions};
    use tokio::sync::broadcast::Receiver;

    /// A voice service with no UDP socket.
    ///
    /// Not a stripped-down double: it is the deployment a client behind a
    /// UDP-blocking firewall effectively gets, so everything asserted here is
    /// asserted against the path such a client actually uses.
    fn service() -> Arc<VoiceService> {
        Arc::new(VoiceService {
            sessions: Mutex::new(HashMap::new()),
            socket: None,
            endpoint: None,
            fanout: Fanout::new(64),
            router: Mutex::new(Router::new(
                Box::new(NoDatagrams),
                ServerDetails {
                    version: MUMBLE_VERSION.encode_v2(),
                    users: 0,
                    max_users: DEFAULT_MAX_USERS,
                    max_bandwidth: DEFAULT_MAX_BANDWIDTH,
                },
            )),
            view: SessionCache::new(),
        })
    }

    /// What session-lifecycle sends at the end of a handshake.
    fn mint_request(conn: u64, session: u32, fancy: u64, mumble: u64) -> MintRequest {
        MintRequest {
            scope: None,
            session,
            fancy_version: fancy,
            mumble_version: mumble,
            address: "203.0.113.7:60000".to_owned(),
            conn,
        }
    }

    /// Mumble 1.6, which is what a current client announces.
    const MUMBLE_1_6: u64 = (1_u64 << 48) | (6_u64 << 32);

    /// Put `sessions` in the lobby, as a `session-view` snapshot would.
    fn all_in_the_lobby(service: &VoiceService, sessions: &[u32]) {
        service.apply_view_event(ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                version: 1,
                sessions: sessions
                    .iter()
                    .map(|session| Session {
                        session: *session,
                        channel: 0,
                        ..Session::default()
                    })
                    .collect(),
            })),
        });
    }

    /// The client half of the cipher the server just minted for it.
    ///
    /// Built from the `CryptSetup` bytes the client would receive, so a packet
    /// sealed with it is a packet a real client would put on the wire. Feeding
    /// the router plaintext instead would pass against a server that never
    /// decrypted anything.
    fn client_cipher(material: &CryptMaterial) -> Box<dyn VoiceCipher> {
        let setup = tcp::CryptSetup::decode(material.crypt_setup.as_slice())
            .expect("the mint produced a CryptSetup");
        let (key, client_nonce, server_nonce) = (
            setup.key.expect("a key"),
            setup.client_nonce.expect("a client nonce"),
            setup.server_nonce.expect("a server nonce"),
        );

        if material.cipher.contains("XChaCha20") {
            let keys = VoiceKeys::from_wire(&key, &client_nonce, &server_nonce)
                .expect("well-formed modern material");
            Box::new(XChaCha20Voice::for_client(&keys))
        } else {
            let keys = LegacyKeys::from_wire(&key, &client_nonce, &server_nonce)
                .expect("well-formed legacy material");
            // The client's half: it sends under the client nonce and expects
            // the server's, which is the mirror of what the server built.
            Box::new(Ocb2::new(
                *keys.key(),
                Block(*keys.server_nonce()),
                Block(*keys.client_nonce()),
            ))
        }
    }

    /// One frame of speech, as a 1.6 client puts it on the wire.
    ///
    /// Built with the *client's* encoder, not the server's. The two are not
    /// inverses — the protobuf header field is `target` inbound and `context`
    /// outbound — so a test that speaks with the server's encoder agrees with
    /// the implementation by construction and would catch none of that.
    fn speech(opus: &[u8]) -> Bytes {
        as_client_sends(UdpFormat::Protobuf, opus)
    }

    /// Who the service pushed audio to, and what it pushed.
    fn pushed(gateway: &mut Receiver<ServerAction>) -> Vec<(Vec<u32>, Vec<u8>)> {
        let mut sends = Vec::new();
        while let Ok(action) = gateway.try_recv() {
            if let Some(server_action::Action::Send(send)) = action.action {
                sends.push((send.sessions, send.payload));
            }
        }
        sends
    }

    #[test]
    fn a_stock_client_is_given_the_cipher_every_mumble_client_assumes() {
        // Handing a stock client the modern cipher is a session it cannot
        // decrypt, which looks exactly like a broken microphone.
        let material = service().mint(&mint_request(1, 1, 0, MUMBLE_1_6));
        assert!(material.cipher.contains("Ocb2"));
        assert!(!material.crypt_setup.is_empty());
    }

    #[test]
    fn a_modern_fancy_client_is_held_to_the_modern_cipher() {
        let modern = Capability::ModernVoiceCrypto.since().to_wire();
        let material = service().mint(&mint_request(2, 2, modern, MUMBLE_1_6));
        assert!(material.cipher.contains("XChaCha20"));
    }

    #[test]
    fn a_legacy_framed_peer_is_downgraded_rather_than_given_a_cipher_it_cannot_frame() {
        // A Fancy build on an old protocol base. Legacy framing is the packet
        // type, so there is nowhere to put a cipher id — the peer would fail to
        // decode its very first packet.
        let modern = Capability::ModernVoiceCrypto.since().to_wire();
        let mumble_1_4 = 1_u64 << 48 | 4_u64 << 32;
        let material = service().mint(&mint_request(3, 3, modern, mumble_1_4));
        assert!(
            material.cipher.contains("Ocb2"),
            "legacy framing cannot carry {}",
            material.cipher
        );
    }

    #[test]
    fn a_resync_keeps_the_profile_the_session_was_minted_under() {
        // The alternative is a one-sided upgrade halfway through a call.
        let service = service();
        let first = service.mint(&mint_request(4, 4, 0, MUMBLE_1_6));
        let previous = service
            .sessions
            .lock()
            .expect("lock")
            .get(&4)
            .expect("the session was recorded")
            .remint();

        let second = service.mint(&MintRequest {
            session: 4,
            ..previous
        });
        assert_eq!(first.cipher, second.cipher);
        assert_ne!(first.crypt_setup, second.crypt_setup, "fresh material");
        let _ = FancyVersion::from_wire(0);
        let _ = CipherChoice::Ocb2Aes128;
    }

    #[tokio::test]
    async fn a_tunnelled_frame_reaches_the_other_person_in_the_channel() {
        // The feature, over TCP: what a client behind a UDP-blocking firewall
        // depends on, and the path every connection uses until one of its
        // datagrams authenticates.
        let service = service();
        let mut gateway = service.fanout.subscribe();

        let _ = service.mint(&mint_request(1, 100, 0, MUMBLE_1_6));
        let _ = service.mint(&mint_request(2, 200, 0, MUMBLE_1_6));
        all_in_the_lobby(&service, &[100, 200]);

        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 100,
                type_id: UDP_TUNNEL,
                // Plaintext: the tunnel runs inside TLS, and murmur feeds the
                // raw payload straight to its routing (`Server.cpp:1905`).
                payload: speech(b"hello").to_vec(),
                gateway: String::new(),
                scope: 1,
            })
            .await;
        assert!(
            actions.is_empty(),
            "a reply would go back to the one person who must not hear it"
        );

        let sends = pushed(&mut gateway);
        assert_eq!(sends.len(), 1, "expected exactly one recipient");
        let (sessions, payload) = sends.into_iter().next().expect("checked above");
        assert_eq!(sessions, vec![200], "the frame reached the wrong person");

        let heard = as_client_hears(UdpFormat::Protobuf, &payload);
        assert_eq!(heard.opus, Bytes::from_static(b"hello"));
        assert_eq!(
            heard.sender,
            SessionId(100),
            "the listener must be told who spoke"
        );
    }

    #[tokio::test]
    async fn a_speaker_never_hears_their_own_tunnelled_frame() {
        let service = service();
        let mut gateway = service.fanout.subscribe();
        let _ = service.mint(&mint_request(1, 100, 0, MUMBLE_1_6));
        all_in_the_lobby(&service, &[100]);

        let _ = service
            .frame(Inbound {
                conn: 1,
                session: 100,
                type_id: UDP_TUNNEL,
                payload: speech(b"alone").to_vec(),
                gateway: String::new(),
                scope: 1,
            })
            .await;

        assert!(
            pushed(&mut gateway).is_empty(),
            "a speaker alone in a channel was echoed to themselves"
        );
    }

    #[tokio::test]
    async fn a_muted_speaker_reaches_nobody() {
        let service = service();
        let mut gateway = service.fanout.subscribe();
        let _ = service.mint(&mint_request(1, 100, 0, MUMBLE_1_6));
        let _ = service.mint(&mint_request(2, 200, 0, MUMBLE_1_6));

        service.apply_view_event(ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                version: 1,
                sessions: vec![
                    Session {
                        session: 100,
                        mute: true,
                        ..Session::default()
                    },
                    Session {
                        session: 200,
                        ..Session::default()
                    },
                ],
            })),
        });

        let _ = service
            .frame(Inbound {
                conn: 1,
                session: 100,
                type_id: UDP_TUNNEL,
                payload: speech(b"muted").to_vec(),
                gateway: String::new(),
                scope: 1,
            })
            .await;

        assert!(pushed(&mut gateway).is_empty(), "a muted speaker was heard");
        assert_eq!(service.router().stats().silenced, 1);
    }

    #[tokio::test]
    async fn audio_arriving_before_the_view_is_warm_is_dropped_rather_than_misrouted() {
        // A restarted voice service is in this state until its subscription
        // delivers a snapshot. It is why readiness gates on that subscription:
        // the frames are lost either way, but an unready service is not routed
        // to in the first place.
        let service = service();
        let mut gateway = service.fanout.subscribe();
        let _ = service.mint(&mint_request(1, 100, 0, MUMBLE_1_6));
        let _ = service.mint(&mint_request(2, 200, 0, MUMBLE_1_6));

        let _ = service
            .frame(Inbound {
                conn: 1,
                session: 100,
                type_id: UDP_TUNNEL,
                payload: speech(b"early").to_vec(),
                gateway: String::new(),
                scope: 1,
            })
            .await;

        assert!(pushed(&mut gateway).is_empty());
    }

    #[test]
    fn a_datagram_from_a_minted_peer_is_attributed_and_routed() {
        // The UDP path, driven with a genuinely encrypted packet built from the
        // material the mint handed the client. A test that fed it plaintext
        // would pass against a server that never decrypted anything.
        let service = service();
        let mut gateway = service.fanout.subscribe();

        let material = service.mint(&mint_request(1, 100, 0, MUMBLE_1_6));
        let _ = service.mint(&mint_request(2, 200, 0, MUMBLE_1_6));
        all_in_the_lobby(&service, &[100, 200]);

        let mut client = client_cipher(&material);
        let sealed = client
            .seal(&speech(b"over udp"), &[])
            .expect("the client seals");
        service
            .router()
            .accept_datagram("203.0.113.7:60000".parse().expect("address"), &sealed);

        // Bob has no proven UDP address of his own, so his copy tunnels — which
        // is the mixed case a real server is in constantly.
        let sends = pushed(&mut gateway);
        assert_eq!(sends.len(), 1, "the datagram was not attributed");
        assert_eq!(sends[0].0, vec![200]);
        assert_eq!(service.router().stats().routed, 1);
        assert!(
            service.router().on_udp(SessionId(100)),
            "the speaker's UDP path was not recorded once it authenticated"
        );
    }

    #[test]
    fn a_datagram_that_authenticates_against_nobody_is_counted_and_dropped() {
        // The normal background noise of an open UDP port.
        let service = service();
        let _ = service.mint(&mint_request(1, 100, 0, MUMBLE_1_6));
        service
            .router()
            .accept_datagram("203.0.113.7:60000".parse().expect("address"), b"junk");
        assert_eq!(service.router().stats().unattributed, 1);
    }

    #[tokio::test]
    async fn a_disconnect_takes_the_peer_off_the_packet_path() {
        // A leak here is unbounded: one peer, and its cipher, per disconnect
        // for the life of the process.
        let service = service();
        let _ = service.mint(&mint_request(7, 700, 0, MUMBLE_1_6));
        assert_eq!(service.router().attached(), 1);

        let _ = service.closed(7, "client disconnected").await;

        assert_eq!(service.router().attached(), 0);
        assert!(
            service.sessions.lock().expect("lock").is_empty(),
            "the minted record outlived the connection"
        );
    }

    #[test]
    fn tunnelled_audio_is_framed_as_a_control_message_by_the_gateway() {
        // Raw audio bytes on the TLS socket would be read as a message header
        // and desynchronise the connection outright. The service hands over the
        // type and the payload apart, and the gateway reassembles them — so
        // what must be asserted here is that the type is right and the payload
        // carries no second header.
        let service = service();
        let mut gateway = service.fanout.subscribe();
        let _ = service.mint(&mint_request(1, 100, 0, MUMBLE_1_6));
        let _ = service.mint(&mint_request(2, 200, 0, MUMBLE_1_6));
        all_in_the_lobby(&service, &[100, 200]);

        service
            .router()
            .accept(AudioSource::Tunnel(1), &speech(b"framed"));

        let action = gateway.try_recv().expect("a push");
        let Some(server_action::Action::Send(send)) = action.action else {
            panic!("expected a Send");
        };
        assert_eq!(
            u16::try_from(send.r#type).expect("a wire type"),
            starling_proto::TcpMessageType::UdpTunnel.id()
        );
        assert!(send.audio, "audio must not share the control lane");
        // The payload is the bare audio frame, with no second header on it: a
        // client parses it directly, and a stray control header would make it
        // undecodable rather than merely wrong.
        assert_eq!(
            as_client_hears(UdpFormat::Protobuf, &send.payload).opus,
            Bytes::from_static(b"framed")
        );
        let _ = ControlMessage::UdpTunnel(Bytes::new());
    }

    #[test]
    fn an_unparseable_peer_address_costs_udp_and_nothing_else() {
        // The peer still gets keys and is still attached; its audio simply
        // tunnels, because no candidate is ever tried at that host.
        assert_eq!(host_of(""), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            host_of("198.51.100.4:64738"),
            "198.51.100.4".parse::<IpAddr>().expect("address")
        );
        assert_eq!(
            host_of("198.51.100.4"),
            "198.51.100.4".parse::<IpAddr>().expect("address")
        );
    }
}
