//! Accept, terminate TLS, and pump frames.
//!
//! The event loop is kept separate from the wire format on purpose: "await
//! readiness and pump gRPC" and "speak Mumble's framing" are two jobs, and
//! fused they become one file nobody can review.
//!
//! murmur accepts TLS 1.0 and later (`Server.cpp:1660`). rustls implements only
//! 1.2 and 1.3, so even the most permissive configuration here beats murmur for
//! free — see `starling-crypto` for the per-peer suite negotiation this leaves
//! room for.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use starling_proto::codec;
use starling_proto_fancy::control::{ClientEvent, Frame, Opened, client_event};
use starling_runtime::config::Config;
use starling_runtime::health::Health;
use starling_runtime::ids::now_ms;
use starling_runtime::metrics::Metrics;
use starling_runtime::shutdown::Shutdown;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::attach::{AttachContext, Attachments};
use crate::connection::{self, ClientHandle, Lane, Registry};
use crate::limiter::{Limiter, Verdict};
use crate::resume::ResumeStore;
use crate::router::Router;

/// Why the gateway could not run.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The control port could not be bound.
    #[error("binding {address}: {source}")]
    Bind {
        /// What was being bound.
        address: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The TLS identity could not be obtained.
    #[error(transparent)]
    Tls(#[from] starling_crypto::identity::TlsError),
    /// rustls refused the identity.
    #[error("tls configuration: {0}")]
    TlsConfig(#[from] rustls::Error),
    /// Nothing is routed, so no client could be served.
    #[error("the routing table is empty; check [services] in the configuration")]
    NoRoutes,
}

/// The control-plane front door.
#[derive(Debug)]
pub struct Gateway {
    config: Arc<Config>,
    router: Router,
    registry: Registry,
    attachments: Attachments,
    resume: ResumeStore,
    metrics: Metrics,
    health: Health,
    next_conn: AtomicU64,
    gateway_id: String,
}

impl Gateway {
    /// Build a gateway over `config`.
    ///
    /// # Errors
    ///
    /// [`GatewayError::NoRoutes`] when nothing is routed — a gateway with an
    /// empty table would accept clients and answer none of them, which looks
    /// like a hung server rather than a misconfiguration.
    pub fn new(config: Arc<Config>, metrics: Metrics, health: Health) -> Result<Self, GatewayError> {
        let router = Router::from_config(&config);
        if router.is_empty() {
            return Err(GatewayError::NoRoutes);
        }
        let resume = ResumeStore::new(config.gateway.resume.ring);
        Ok(Self {
            router,
            registry: Registry::new(),
            attachments: Attachments::new(),
            resume,
            metrics,
            health,
            next_conn: AtomicU64::new(1),
            gateway_id: format!("gw-{}", std::process::id()),
            config,
        })
    }

    /// Attach to every routed service and serve until `shutdown` drains.
    ///
    /// # Errors
    ///
    /// [`GatewayError`] if the port cannot be bound or TLS cannot be set up.
    pub async fn run(
        self: Arc<Self>,
        resolver: starling_runtime::channel::Resolver,
        shutdown: Shutdown,
    ) -> Result<(), GatewayError> {
        let ctx = AttachContext {
            gateway_id: self.gateway_id.clone(),
            virtual_server: self.virtual_server(),
            resolver,
            registry: self.registry.clone(),
            resume: self.resume.clone(),
            metrics: self.metrics.clone(),
            breaker_failures: self.config.gateway.breaker_failures,
            breaker_cooldown_ms: self.config.gateway.breaker_cooldown.get().as_millis() as u64,
        };
        for name in self.router.services() {
            let tier = self
                .config
                .services
                .get(&name)
                .map(|service| service.tier)
                .unwrap_or_default();
            self.attachments.spawn(&name, tier, &ctx);
        }

        // The session store is reported as a warning, never as unready: its
        // absence is a lost optimisation, and rejecting logins over one would
        // be worse than the herd it prevents (`docs/ARCHITECTURE.md` §5).
        if !self.config.gateway.resume.enabled {
            self.health
                .set("session store", starling_runtime::health::Readiness::Warning);
        }

        let acceptor = self.acceptor()?;
        let address = self.config.gateway.listen_tcp.clone();
        let listener = TcpListener::bind(&address)
            .await
            .map_err(|source| GatewayError::Bind {
                address: address.clone(),
                source,
            })?;
        tracing::info!(%address, routes = self.router.len(), "gateway listening");
        self.health.ready("listener");

        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { continue };
                    let gateway = Arc::clone(&self);
                    let acceptor = acceptor.clone();
                    drop(tokio::spawn(async move {
                        if let Err(error) = gateway.serve_client(stream, acceptor, peer).await {
                            tracing::debug!(%peer, %error, "client ended");
                        }
                    }));
                }
            }
        }

        tracing::info!("gateway draining");
        Ok(())
    }

    fn virtual_server(&self) -> u32 {
        self.config
            .virtual_servers
            .first()
            .map_or(1, |server| server.id)
    }

    fn acceptor(&self) -> Result<TlsAcceptor, GatewayError> {
        let data_dir = &self.config.runtime.data_dir;
        let cert = self
            .config
            .gateway
            .tls
            .cert
            .clone()
            .unwrap_or_else(|| data_dir.join("cert.pem"));
        let key = self
            .config
            .gateway
            .tls
            .key
            .clone()
            .unwrap_or_else(|| data_dir.join("key.pem"));
        let identity = starling_crypto::identity::load_or_generate(&cert, &key)?;

        // rustls 0.23 no longer picks a default crypto backend on its own; it
        // must be installed once per process before the first `ServerConfig`
        // is built. Ignored if another listener in this process already
        // installed one — the workspace enables exactly one backend
        // (`ring`), so a second install would only ever be this same one.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(identity.certs, identity.key)?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// One client, from TLS handshake to disconnect.
    async fn serve_client(
        self: Arc<Self>,
        stream: tokio::net::TcpStream,
        acceptor: TlsAcceptor,
        peer: std::net::SocketAddr,
    ) -> Result<(), std::io::Error> {
        let tls = acceptor.accept(stream).await?;
        let conn = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let token = format!("{}-{conn}", self.gateway_id);

        let (handle, mut outbound) = connection::channel(
            conn,
            token,
            self.config.gateway.control_queue,
            self.config.gateway.audio_queue,
        );
        self.registry.insert(Arc::clone(&handle));
        self.metrics.counter("starling_gateway_connections").inc();

        self.attachments.broadcast_opened(&Opened {
            conn,
            peer_addr: peer.to_string(),
            cert_hash: Vec::new(),
            strong_cert: false,
            virtual_server: self.virtual_server(),
        });

        let (mut reader, mut writer) = tokio::io::split(tls);
        let writer_handle = Arc::clone(&handle);
        let writer_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    frame = outbound.recv() => {
                        let Some(frame) = frame else { break };
                        if writer.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                    () = writer_handle.audio_ready() => {
                        while let Some(frame) = writer_handle.pop_audio() {
                            if writer.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            let _ = writer.shutdown().await;
        });

        let mut limiter = Limiter::new(&self.config.gateway.limits, now_ms());
        let mut buffer = BytesMut::with_capacity(8 * 1024);
        let mut scratch = vec![0_u8; 8 * 1024];

        let reason = loop {
            let read = reader.read(&mut scratch).await?;
            if read == 0 {
                break "peer closed";
            }
            buffer.extend_from_slice(&scratch[..read]);

            match self.drain_frames(&handle, &mut buffer, &mut limiter) {
                Ok(()) => {}
                // A protocol error closes *that* connection and nothing else —
                // hostile input is per-peer by construction.
                Err(error) => {
                    tracing::debug!(conn, %error, "malformed frame");
                    self.finish(conn, "protocol error", &writer_task);
                    return Ok(());
                }
            }
        };

        self.finish(conn, reason, &writer_task);
        Ok(())
    }

    /// Route every complete frame in `buffer`.
    ///
    /// # Errors
    ///
    /// The decode error, which closes this connection and nothing else.
    fn drain_frames(
        &self,
        handle: &Arc<ClientHandle>,
        buffer: &mut BytesMut,
        limiter: &mut Limiter,
    ) -> Result<(), starling_proto::Error> {
        while let Some(frame) = codec::decode_raw(buffer)? {
            if !self.dispatch(handle, &frame, limiter) {
                break;
            }
        }
        Ok(())
    }

    /// Route one frame. Returns false when the connection should be dropped.
    fn dispatch(
        &self,
        handle: &Arc<ClientHandle>,
        frame: &codec::RawFrame,
        limiter: &mut Limiter,
    ) -> bool {
        let Some(route) = self.router.route(frame.type_id) else {
            // An unroutable type is dropped rather than fatal: a stale client
            // sending a burned type must not lose its session over it.
            self.metrics.counter("starling_gateway_unroutable_frames").inc();
            return true;
        };

        match limiter.check(&route.bucket, now_ms()) {
            Verdict::Allow => {}
            Verdict::Throttle { retry_after_ms } => {
                self.metrics.counter("starling_gateway_throttled").inc();
                self.notify_throttled(handle, frame.type_id, &route.bucket, retry_after_ms);
                return true;
            }
        }

        let Some(link) = self.attachments.get(&route.service) else {
            return true;
        };
        if !link.healthy() && route.tier.sheddable() {
            // Shed at the door rather than making the client wait a deadline
            // for the same answer.
            self.metrics.counter("starling_gateway_shed").inc();
            return true;
        }

        link.forward(ClientEvent {
            event: Some(client_event::Event::Frame(Frame {
                conn: handle.conn,
                r#type: u32::from(frame.type_id),
                payload: frame.payload.to_vec(),
                session: handle.session(),
            })),
        })
    }

    /// Tell a Fancy client it was throttled; leave a legacy client in silence.
    fn notify_throttled(
        &self,
        handle: &Arc<ClientHandle>,
        type_id: u16,
        bucket: &str,
        retry_after_ms: u32,
    ) {
        if !handle.is_fancy() {
            return;
        }
        use prost::Message as _;
        let envelope = starling_proto_fancy::fancy::session::SessionEnvelope {
            body: Some(
                starling_proto_fancy::fancy::session::session_envelope::Body::Throttled(
                    starling_proto_fancy::fancy::session::Throttled {
                        r#type: u32::from(type_id),
                        retry_after_ms,
                        route: bucket.to_owned(),
                    },
                ),
            ),
        };
        let payload = envelope.encode_to_vec();
        let outer = starling_proto_fancy::ServiceKind::SessionLifecycle.outer_type();
        let _ = handle.send(Lane::Control, codec::frame(outer, &payload));
    }

    fn finish(&self, conn: u64, reason: &str, writer: &tokio::task::JoinHandle<()>) {
        writer.abort();
        self.registry.remove(conn);
        self.attachments.broadcast_closed(conn, reason);
        self.metrics.counter("starling_gateway_disconnects").inc();
    }

    /// Who is connected, for the admin surface and tests.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn a_gateway_with_nothing_routed_refuses_to_start() {
        // Accepting clients it can answer none of looks like a hang, and a hang
        // is the hardest failure to attribute.
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        config.services.clear();
        let err = Gateway::new(Arc::new(config), Metrics::new(), Health::new())
            .expect_err("an empty table must be refused");
        assert!(matches!(err, GatewayError::NoRoutes));
    }

    #[test]
    fn a_gateway_over_the_shipped_defaults_routes_every_service() {
        let config = Config::with_defaults(Path::new("/run/starling"));
        let gateway = Gateway::new(Arc::new(config), Metrics::new(), Health::new())
            .expect("the defaults must be servable");
        assert!(gateway.router.route(11).is_some());
        assert_eq!(gateway.router.services().len(), 18);
    }
}
