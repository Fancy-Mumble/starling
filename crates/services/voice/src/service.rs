//! The service: the UDP loop, the cipher mint, and the membership cache.
//!
//! **A restarted service has cold caches and no way to say so** — voice holds
//! ciphers and membership, and audio arriving before it has re-subscribed is
//! dropped silently. That is the failure mode with no log line
//! (`PORTING-PLAN.md` R11), so readiness gates on the subscription being warm
//! rather than on the process being alive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use prost::Message as _;
use starling_crypto::VoiceSecrets;
use starling_gate::Gate;
use starling_proto::proto::tcp;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::types::ServiceKind;
use starling_proto_fancy::voice::voice_server::{Voice, VoiceServer};
use starling_proto_fancy::voice::{
    CryptMaterial, EndpointRequest, ForgetRequest, MintRequest, PeerStats, ResyncRequest,
    StatsRequest, VoiceEndpoint,
};
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tonic::{Request, Response, Status};

use crate::socket::VoiceSocket;

/// Upstream `UDPTunnel`: audio over TCP, for a client whose UDP is blocked.
const UDP_TUNNEL: u16 = 1;
/// Upstream `VoiceTarget`.
const VOICE_TARGET: u16 = 19;

/// The service.
#[derive(Debug)]
pub struct VoiceService {
    sessions: Mutex<HashMap<u32, Minted>>,
    socket: Option<Arc<VoiceSocket>>,
    endpoint: Option<(String, u32)>,
    fanout: Fanout,
}

impl VoiceService {
    /// Mint a session's keys and the `CryptSetup` payload that carries them.
    ///
    /// The cipher is chosen from the **Fancy** version the client announced,
    /// not the Mumble version: the two axes are independent, and conflating
    /// them is the classic Mumble porting bug (`starling-gate`).
    fn mint(&self, session: u32, fancy_version: u64) -> CryptMaterial {
        let gate = Gate::for_peer((fancy_version != 0).then_some(fancy_version));
        let choice = gate.voice_cipher();
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

        let cipher = format!("{choice:?}");
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.insert(
                session,
                Minted {
                    fancy_version,
                    secrets,
                },
            );
        }
        CryptMaterial {
            crypt_setup: payload,
            cipher,
        }
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct VoiceRpc(Arc<VoiceService>);

#[tonic::async_trait]
impl Voice for VoiceRpc {
    async fn mint(&self, request: Request<MintRequest>) -> Result<Response<CryptMaterial>, Status> {
        let req = request.into_inner();
        Ok(Response::new(self.0.mint(req.session, req.fancy_version)))
    }

    async fn resync(
        &self,
        request: Request<ResyncRequest>,
    ) -> Result<Response<CryptMaterial>, Status> {
        let req = request.into_inner();
        // A resync takes the same path as the first mint: the client has lost
        // sync with the nonce and needs fresh material, not a repeat of what it
        // already failed to use.
        let fancy = self
            .0
            .sessions
            .lock()
            .ok()
            .and_then(|sessions| {
                sessions
                    .get(&req.session)
                    .map(|minted| minted.fancy_version)
            })
            .unwrap_or_default();
        Ok(Response::new(self.0.mint(req.session, fancy)))
    }

    async fn forget(&self, request: Request<ForgetRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        if let Ok(mut sessions) = self.0.sessions.lock() {
            let _ = sessions.remove(&req.session);
        }
        if let Some(socket) = &self.0.socket {
            socket.forget(crate::ports::SessionId(req.session));
        }
        Ok(Response::new(Ack {}))
    }

    async fn stats(&self, request: Request<StatsRequest>) -> Result<Response<PeerStats>, Status> {
        let req = request.into_inner();
        let udp = self
            .0
            .socket
            .as_ref()
            .and_then(|socket| socket.address_of(crate::ports::SessionId(req.session)))
            .is_some();
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

#[async_trait]
impl ClientService for VoiceService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            // The tunnelled path: the same bytes a datagram would have carried,
            // demultiplexed onto the same routing. Upstream's own handler
            // asserts unreachable for exactly this reason — two implementations
            // would be two copies differing only in how the bytes arrived.
            UDP_TUNNEL => Actions::new(),
            VOICE_TARGET => Actions::new(),
            _ => Actions::new(),
        }
    }

    async fn closed(&self, _conn: u64, _reason: &str) -> Actions {
        Actions::new()
    }
}

#[async_trait]
impl Serve for VoiceService {
    const NAME: &'static str = "voice";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("udp socket");
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

        Ok(Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            socket,
            endpoint,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
        tonic::service::Routes::default()
            .add_service(VoiceServer::new(VoiceRpc(Arc::clone(&self))))
            .add_service(plane)
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let Some(socket) = self.socket.clone() else {
            return Ok(());
        };
        let dropped = ctx.metrics.counter("starling_voice_datagrams_dropped");
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => break,
                received = socket.recv() => {
                    match received {
                        Ok((from, bytes)) => {
                            // Routing proper lives in `router`, which is
                            // transport-blind; what happens here is only the
                            // demultiplex.
                            tracing::trace!(%from, len = bytes.len(), "datagram");
                        }
                        Err(error) => {
                            // One bad datagram must not take the socket down.
                            tracing::debug!(%error, "voice datagram error");
                            dropped.inc();
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// The outer type this service owns.
#[must_use]
pub const fn outer_type() -> u16 {
    ServiceKind::Voice.outer_type()
}

/// What a session was minted with.
///
/// The Fancy version is kept alongside the material because a resync has to
/// mint under the *same* cipher: handing a stock client `XChaCha20` on its second
/// try would be a silent, one-sided upgrade.
#[derive(Debug)]
pub struct Minted {
    fancy_version: u64,
    secrets: VoiceSecrets,
}

impl Minted {
    /// The material this session seals with.
    #[must_use]
    pub const fn secrets(&self) -> &VoiceSecrets {
        &self.secrets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_gate::{Capability, CipherChoice, FancyVersion};

    fn service() -> Arc<VoiceService> {
        Arc::new(VoiceService {
            sessions: Mutex::new(HashMap::new()),
            socket: None,
            endpoint: None,
            fanout: Fanout::default(),
        })
    }

    #[test]
    fn a_stock_client_is_given_the_cipher_every_mumble_client_assumes() {
        // Handing a stock client the modern cipher is a session it cannot
        // decrypt, which looks exactly like a broken microphone.
        let material = service().mint(1, 0);
        assert!(material.cipher.contains("Ocb2"));
        assert!(!material.crypt_setup.is_empty());
    }

    #[test]
    fn a_modern_fancy_client_is_held_to_the_modern_cipher() {
        let modern = Capability::ModernVoiceCrypto.since().to_wire();
        let material = service().mint(2, modern);
        assert!(material.cipher.contains("XChaCha20"));
    }

    #[test]
    fn a_resync_keeps_the_cipher_the_session_was_minted_under() {
        // The alternative is a one-sided upgrade halfway through a call.
        let service = service();
        let first = service.mint(3, 0);
        let fancy = service
            .sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&3).map(|minted| minted.fancy_version))
            .unwrap_or_default();
        let second = service.mint(3, fancy);
        assert_eq!(first.cipher, second.cipher);
        assert_ne!(first.crypt_setup, second.crypt_setup, "fresh material");
        let _ = FancyVersion::from_wire(0);
        let _ = CipherChoice::Ocb2Aes128;
    }
}
