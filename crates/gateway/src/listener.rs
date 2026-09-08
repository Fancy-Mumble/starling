//! Accept, terminate TLS, and pump frames.
//!
//! The event loop is kept separate from the wire format on purpose: "await
//! readiness and pump gRPC" and "speak Mumble's framing" are two jobs, and
//! fused they become one file nobody can review.
//!
//! murmur accepts TLS 1.0 and later (`Server.cpp:1671`). rustls implements only
//! 1.2 and 1.3, so even the most permissive configuration here beats murmur for
//! free, see `starling-crypto` for the per-peer suite negotiation this leaves
//! room for.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use starling_crypto::peer_cert::{AcceptAnyClientCertificate, PeerCertificate};
use starling_proto::codec;
use starling_proto_fancy::control::{ClientEvent, Frame, Opened, client_event};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::config::{Config, GatewayConfig};
use starling_runtime::health::Health;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::metrics::Metrics;
use starling_runtime::pressure::{Gauge, Pressure};
use starling_runtime::shutdown::Shutdown;
use starling_runtime::tier::Tier;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::admission::Admission;
use crate::attach::{AttachContext, Attachments};
use crate::certs::{self, CertResolver};
use crate::compress;
use crate::connection::Outbound;
use crate::connection::{self, ClientHandle, Lane, Registry};
use crate::limiter::{Limiter, LiveBuckets, MessageLimit, Verdict};
use crate::limits::Limits;
use crate::resume::ResumeStore;
use crate::router::{LiveRouter, Router};

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
    /// The certificate pair could not be turned into something to present.
    #[error("server certificate: {0}")]
    Certificate(String),
    /// Nothing is routed, so no client could be served.
    #[error("the routing table is empty; check [services] in the configuration")]
    NoRoutes,
}

/// Every service the routing table names, with its tier.
fn wanted_services(config: &Config) -> std::collections::BTreeMap<String, Tier> {
    Router::from_config(config)
        .services()
        .into_iter()
        .map(|name| {
            let tier = config
                .services
                .get(&name)
                .map(|service| service.tier)
                .unwrap_or_default();
            (name, tier)
        })
        .collect()
}

/// The control-plane front door.
#[derive(Debug)]
pub struct Gateway {
    config: Arc<Config>,
    router: Arc<LiveRouter>,
    registry: Registry,
    attachments: Attachments,
    resume: ResumeStore,
    /// The ceiling on unauthenticated handshakes. See [`crate::admission`].
    admission: Admission,
    /// What this gateway is holding, for the soak and the dashboard.
    gauges: GatewayGauges,
    metrics: Metrics,
    /// Queue occupancy, handed to every connection.
    ///
    /// Beside `metrics` and not inside it: a counter says how many clients were
    /// disconnected for control overflow, this says how close the next one is.
    /// The first is only ever read after the damage.
    control_pressure: Gauge,
    health: Health,
    logger: Logger,
    next_conn: AtomicU64,
    gateway_id: String,
    /// What `reconcile` needs to attach a service the file has just added.
    ///
    /// Filled in when the accept loop starts, because it holds the resolver
    /// `run` is given. A reload arriving before then finds it empty and does
    /// nothing, which is correct: the first attach has not happened yet, and it
    /// will read the current table when it does.
    attach_ctx: std::sync::OnceLock<AttachContext>,
    /// The certificate presented at each handshake, replaceable while
    /// listening.
    certs: Arc<CertResolver>,
    /// The `[gateway.limits]` table, as the operator has it now.
    ///
    /// Shared with every connection's [`Limiter`] for the same reason
    /// `message_limit` is: the bucket that ate a screen share's SDP offer is
    /// diagnosed on a running server, and widening it must not cost every
    /// other client their session.
    buckets: Arc<LiveBuckets>,
    /// The per-client queue bounds, as the operator has them now.
    ///
    /// Shared with every connection for the same reason `message_limit` is:
    /// raising `control_bytes` during an incident has to reach the clients
    /// already connected, which is the only time anybody raises it.
    limits: Arc<Limits>,
    /// murmur's `messagelimit`/`messageburst`, as the operator has them now.
    ///
    /// Shared with every connection's [`Limiter`]. Held here rather than
    /// copied into each one because the whole point is that changing it
    /// reaches clients that are already connected.
    message_limit: Arc<MessageLimit>,
}

/// The gateway's own occupancy gauges.
///
/// Held rather than looked up per accept: `Pressure::gauge` takes a lock and
/// allocates the name on a miss, and this runs once per connection.
#[derive(Debug, Clone)]
struct GatewayGauges {
    connections: Gauge,
    resume_sessions: Gauge,
    resume_bytes: Gauge,
    pending_handshakes: Gauge,
    /// The per-client control lane, shared by every connection.
    ///
    /// Held here as well as by each `ClientHandle` so that a *departure* can
    /// republish it. Every enqueue writes it; nothing else did, so an idle
    /// gateway reported the queue of whichever client last had something to
    /// send, long after that client had gone.
    control_queue: Gauge,
}

impl GatewayGauges {
    fn new(pressure: &Pressure, config: &GatewayConfig) -> Self {
        Self {
            // No declared ceiling: how many clients a server holds is
            // `max_users`, which lives in the server settings rather than here,
            // and inventing a denominator would turn an unknown into a
            // reassuring percentage.
            connections: pressure.gauge("connections", 0),
            resume_sessions: pressure.gauge("resume.sessions", 0),
            resume_bytes: pressure.gauge("resume.bytes", 0),
            pending_handshakes: pressure
                .gauge("handshakes.pending", config.max_pending_handshakes as u64),
            control_queue: pressure.gauge(connection::CONTROL_QUEUE_GAUGE, 0),
        }
    }
}

/// The per-connection read buffer, and the size it is returned to.
///
/// Frames are small: the ceiling is 8 MiB but the median is a few hundred
/// bytes, so sizing for the common case and growing for the rare one is right.
/// What was missing was giving the growth back.
const READ_BUFFER_BYTES: usize = 8 * 1024;

/// How long the accept loop pauses when the process is out of descriptors.
///
/// Short enough that recovery is immediate once a descriptor frees, long
/// enough that the loop is not spinning: at `EMFILE` the listening socket stays
/// readable, so the failed accept returns instantly and a bare `continue`
/// re-enters it at scheduler speed.
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Whether an accept failure is the process running out of descriptors.
///
/// `EMFILE` is this process's limit and `ENFILE` is the system's; both clear on
/// their own once something closes, and neither is a reason to stop serving.
fn accept_is_exhaustion(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == 24 || code == 23
    )
}

impl Gateway {
    /// Build a gateway over `config`.
    ///
    /// # Errors
    ///
    /// [`GatewayError::NoRoutes`] when nothing is routed, a gateway with an
    /// empty table would accept clients and answer none of them, which looks
    /// like a hung server rather than a misconfiguration.
    pub fn new(
        config: Arc<Config>,
        metrics: Metrics,
        pressure: &Pressure,
        health: Health,
        logger: Logger,
    ) -> Result<Self, GatewayError> {
        let router = Router::from_config(&config);
        if router.is_empty() {
            return Err(GatewayError::NoRoutes);
        }
        let router = Arc::new(LiveRouter::new(router));
        let resume = ResumeStore::from_config(&config.gateway.resume);
        let admission = Admission::from_config(&config.gateway);
        let limits = Arc::new(Limits::from_config(&config.gateway));
        let buckets = Arc::new(LiveBuckets::new(&config.gateway.limits));
        // Loaded here so a broken pair fails the build rather than the first
        // client's handshake, which is where `with_single_cert` used to catch
        // it. Replaced in `acceptor` with the same pair, re-read at listen time.
        let (cert, key) = certs::paths(&config);
        let certs = Arc::new(CertResolver::new(
            certs::load(&cert, &key).map_err(GatewayError::Certificate)?,
        ));
        Ok(Self {
            router,
            registry: Registry::new(),
            attachments: Attachments::new(),
            gauges: GatewayGauges::new(pressure, &config.gateway),
            resume,
            admission,
            metrics,
            control_pressure: pressure.gauge(
                connection::CONTROL_QUEUE_GAUGE,
                config.gateway.control_bytes as u64,
            ),
            health,
            logger,
            next_conn: AtomicU64::new(1),
            gateway_id: format!("gw-{}", std::process::id()),
            message_limit: Arc::new(MessageLimit::default()),
            limits,
            buckets,
            certs,
            attach_ctx: std::sync::OnceLock::new(),
            config,
        })
    }

    /// The queue bounds every connection reads, for whatever follows the file.
    #[must_use]
    pub fn limits(&self) -> Arc<Limits> {
        Arc::clone(&self.limits)
    }

    /// The rate-limit buckets every connection reads, for the same.
    #[must_use]
    pub fn buckets(&self) -> Arc<LiveBuckets> {
        Arc::clone(&self.buckets)
    }

    /// The certificate resolver, for whatever follows the file.
    #[must_use]
    pub fn certs(&self) -> Arc<CertResolver> {
        Arc::clone(&self.certs)
    }

    /// Adopt a changed `[services]` table: routes, tiers and buckets.
    ///
    /// Attaching to a service the file has just added, detaching from one it
    /// has removed, and re-tiering the rest. `endpoint` is deliberately not
    /// among the keys that reach here -- see the classification table.
    pub fn adopt_services(&self, config: &Config) {
        let next = Router::from_config(config);
        if !self.router.replace(next) {
            return;
        }
        let Some(ctx) = self.attach_ctx.get() else {
            return;
        };
        let changed = self.attachments.reconcile(&wanted_services(config), ctx);
        if changed.is_empty() {
            return;
        }
        let mut event = LogEvent::notice(Category::Server, "routing table changed")
            .with("routes", self.router.current().len());
        for (field, names) in [
            ("attached", &changed.attached),
            ("detached", &changed.detached),
            ("retiered", &changed.retiered),
        ] {
            if !names.is_empty() {
                event = event.with(field, names.join(", "));
            }
        }
        self.logger.log(event);
    }

    /// Adopt changed `[gateway]` breaker numbers.
    pub fn retune_breakers(&self, gateway: &GatewayConfig) {
        self.attachments.retune_breakers(
            gateway.breaker_failures,
            gateway
                .breaker_cooldown
                .get()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        );
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
        // The operator's message limit, followed for as long as the gateway
        // runs. Spawned before anything is accepted so the first client is
        // already charged against the number in force rather than the TOML's.
        let limits = self.follow_message_limit(&resolver);

        let ctx = AttachContext {
            gateway_id: self.gateway_id.clone(),
            instance: self.instance(),
            resolver,
            registry: self.registry.clone(),
            resume: self.resume.clone(),
            metrics: self.metrics.clone(),
            breaker_failures: self.config.gateway.breaker_failures,
            breaker_cooldown_ms: self.config.gateway.breaker_cooldown.get().as_millis() as u64,
            default_deadline: self.config.gateway.default_deadline.get(),
        };
        // The first attach: everything the table names is new here.
        let _ = self
            .attachments
            .reconcile(&wanted_services(&self.config), &ctx);
        // Kept for the life of the gateway: reconciling after a reload needs
        // the same context the first attach used, and nothing in it changes.
        let _ = self.attach_ctx.set(ctx.clone());

        // The session store is reported as a warning, never as unready: its
        // absence is a lost optimisation, and rejecting logins over one would
        // be worse than the herd it prevents (`docs/ARCHITECTURE.md` §5).
        if !self.config.gateway.resume.enabled {
            self.health.set(
                "session store",
                starling_runtime::health::Readiness::Warning,
            );
        }

        // From here to the teardown in an inner block, so that the two `?`
        // below leave through it as well: a gateway that cannot bind its port
        // has already attached to every service, and returning straight out
        // would leave those streams open on a set of services that are about to
        // be asked to stop. That start-up failure is the ordinary way a second
        // instance is refused, so it is not a rare path.
        let served = async {
            let acceptor = self.acceptor()?;
            let address = self.config.gateway.listen_tcp.clone();
            let listener =
                TcpListener::bind(&address)
                    .await
                    .map_err(|source| GatewayError::Bind {
                        address: address.clone(),
                        source,
                    })?;
            self.logger.log(
                LogEvent::info(Category::Server, "gateway listening")
                    .with("address", address.clone())
                    .with("routes", self.router.current().len())
                    .with("gateway", self.gateway_id.clone()),
            );
            self.health.ready("listener");

            loop {
                tokio::select! {
                    _ = shutdown.wait() => break,
                    accepted = listener.accept() => {
                        let (stream, peer) = match accepted {
                            Ok(accepted) => accepted,
                            Err(error) => {
                                // Running out of descriptors arrives here, and it
                                // looks exactly like an idle server otherwise.
                                self.logger.log(
                                    LogEvent::warning(Category::Server, "accept failed")
                                        .with("error", error.to_string()),
                                );
                                // Backed off, because the socket stays readable
                                // while the process is out of descriptors: a
                                // bare `continue` spins this loop at the speed
                                // of the scheduler, burning the CPU that the
                                // connections already open need in order to
                                // finish and give a descriptor back.
                                if accept_is_exhaustion(&error) {
                                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                                }
                                continue;
                            }
                        };
                        // TCP_NODELAY, as murmur sets on every accepted socket
                        // (`Connection.cpp:40`). The control stream is small
                        // request/reply frames, exactly what Nagle punishes: with
                        // it on, a frame written after one still unacknowledged
                        // waits for the peer's ACK, and Linux delays that ACK by
                        // up to 40 ms. Measured against a WAN peer, a `Ping` reply
                        // took two round trips instead of one, and 40 ms more
                        // whenever the peer's ACK was delayed.
                        if let Err(error) = stream.set_nodelay(true) {
                            // Not fatal: the connection works without it, only
                            // slower, and murmur ignores the same failure.
                            tracing::debug!(%peer, %error, "could not set TCP_NODELAY");
                        }
                        // Reported before the decision, so a refusal is
                        // visible as a full gauge rather than only as a counter
                        // after the fact.
                        self.observe_admission();
                        // Before the spawn, so a peer that is refused costs a
                        // closed socket rather than a task and a rustls buffer.
                        let Some(ticket) = self.admit(peer) else {
                            drop(stream);
                            continue;
                        };
                        let gateway = Arc::clone(&self);
                        let acceptor = acceptor.clone();
                        drop(tokio::spawn(async move {
                            if let Err(error) =
                                gateway.serve_client(stream, acceptor, peer, ticket).await
                            {
                                tracing::debug!(%peer, %error, "client ended");
                            }
                        }));
                    }
                }
            }
            Ok(())
        }
        .await;

        // Everything this gateway holds open on a service is let go here, and
        // not left to the process ending. Each of these is a live gRPC stream
        // into a service that is draining at the same moment, and a service
        // finishes draining only once the streams into it have ended: the
        // attachments into every routed service, and `server-config`'s `watch`
        // behind the message limit. Left running, they hold every service open
        // against its own drain, and the process that was asked to stop stops
        // on `SIGKILL` instead.
        for task in limits {
            task.abort();
        }
        let detached = self.attachments.detach_all();
        self.logger.log(
            LogEvent::info(Category::Server, "gateway draining")
                .with("connections", self.registry.len())
                .with("detached", detached),
        );
        served
    }

    /// Follow `server-config`'s `message_limit`/`message_burst` forever.
    ///
    /// The gateway is not a service and has no `ServiceContext`, so it does
    /// its own subscription rather than going through the same `build` hook
    /// every service uses, but it reads the same
    /// [`Settings`](starling_runtime::Settings) the services do, so there is
    /// still one definition of what these numbers are and one fallback when
    /// `server-config` is down.
    ///
    /// Returns every task it started, subscription included, because the drain
    /// has to be able to stop them: the subscription is a `watch` stream on
    /// `server-config`, and a service cannot finish draining while a stream
    /// into it is still open.
    fn follow_message_limit(
        &self,
        resolver: &starling_runtime::channel::Resolver,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let settings =
            starling_runtime::Settings::new(resolver.clone()).logging_to(self.logger.clone());
        let scope = self.instance();
        let live = Arc::clone(&self.message_limit);
        let logger = self.logger.clone();
        let mut tasks = settings.watch(&[scope]);

        tasks.push(tokio::spawn(async move {
            /// How often the published numbers are re-read. The subscription
            /// keeps the snapshot current; this only moves it into the atomics,
            /// so it is a poll of local memory rather than of the network.
            const TICK: std::time::Duration = std::time::Duration::from_millis(500);
            let mut last = None;
            loop {
                tokio::time::sleep(TICK).await;
                let snapshot = settings.get(scope);
                // **Only once an operator has configured this server.**
                //
                // `is_warm` was the wrong gate and this is the bug it hid: it
                // asks whether a snapshot *arrived*, and one always does,
                // carrying `server-config`'s own defaults. So a deployment that
                // deliberately tuned `[gateway.limits.control]` had it silently
                // reset to murmur's 1/s the moment `server-config` came up,
                // which reads as the gateway ignoring its own configuration.
                //
                // `version` counts writes and starts at zero, so it is exactly
                // "somebody has set something here". The residual case is
                // narrow and worth stating: an operator who changed some
                // *other* setting bumps the version, and this then applies a
                // `message_limit` they never touched. Telling those apart needs
                // `server-config` to record which fields were ever written,
                // which the snapshot has no room for today.
                if snapshot.version == 0 {
                    continue;
                }
                let current = (snapshot.message_limit, snapshot.message_burst);
                if last == Some(current) {
                    continue;
                }
                last = Some(current);
                live.set(f64::from(current.0), current.1);
                logger.log(
                    LogEvent::info(Category::Server, "message rate limit changed")
                        .with("rate", current.0)
                        .with("burst", current.1),
                );
            }
        }));
        tasks
    }

    fn instance(&self) -> u32 {
        self.config.instances.first().map_or(1, |server| server.id)
    }

    fn acceptor(&self) -> Result<TlsAcceptor, GatewayError> {
        let (cert, key) = certs::paths(&self.config);

        // rustls 0.23 no longer picks a default crypto backend on its own; it
        // must be installed once per process before the first `ServerConfig`
        // is built. Ignored if another listener in this process already
        // installed one, the workspace enables exactly one backend
        // (`ring`), so a second install would only ever be this same one.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Ask for a client certificate. `with_no_client_auth()` was here, and
        // it does not merely skip validation, it means the server never sends
        // a `CertificateRequest`, so no client ever offers one and every peer
        // arrives with an empty hash. Certificate identity is how Mumble binds
        // a registered account, admits a user without a password and enforces a
        // certificate ban; all three were unreachable, silently, because the
        // question was never asked.
        //
        // The verifier accepts any issuer, which is the correct policy for
        // Mumble's self-signed clients rather than a relaxation, see
        // `starling_crypto::peer_cert`. Possession of the private key is still
        // proved during the handshake.
        let provider = rustls::crypto::CryptoProvider::get_default().map_or_else(
            || Arc::new(rustls::crypto::ring::default_provider()),
            Arc::clone,
        );
        // A resolver rather than `with_single_cert`: the certificate is asked
        // for at each handshake, so a renewal reaches the next client instead
        // of the next restart. Renewals are not rare -- cert-manager and Let's
        // Encrypt rotate on a schedule nobody plans around -- and this process
        // holds every client's connection. See `crate::certs`.
        let certified = certs::load(&cert, &key).map_err(GatewayError::Certificate)?;
        self.certs.replace(certified);
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(AcceptAnyClientCertificate::new(provider))
            .with_cert_resolver(
                Arc::clone(&self.certs) as Arc<dyn rustls::server::ResolvesServerCert>
            );
        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Note a new connection, in both logs.
    ///
    /// Split out of [`Self::serve_client`] because it is the one part of
    /// accepting a client that is purely a record: no state changes here, and
    /// the loop below reads better without twenty lines of field-building in
    /// the middle of it.
    fn record_connected(
        &self,
        conn: u64,
        peer: std::net::SocketAddr,
        certificate: Option<&PeerCertificate>,
    ) {
        let mut connected = LogEvent::info(Category::Session, "client connected")
            .with("conn", conn)
            .with("peer", peer.to_string())
            .with("connections", self.registry.len());
        // Only when there is one. A blank field on every guest trains an
        // operator to stop reading it, and the hash is the thing a ban or a
        // registration is keyed by; it is worth seeing when present.
        if let Some(certificate) = certificate {
            connected = connected
                .with("certificate", certificate.hex())
                .with("strong_cert", certificate.strong);
        }
        self.logger.log(connected);
    }

    /// Publish the map sizes this gateway is holding.
    ///
    /// Called on **both** the accept and the disconnect path rather than from a
    /// timer: between them they are every point at which these four numbers
    /// change, and a sweep task would be a second thing to own.
    ///
    /// It was the accept path alone, which made every one of these a
    /// last-accept reading rather than a current one: after the final client
    /// left, `connections` kept whatever it said when the last peer arrived,
    /// forever. On a quiet server that is an operator looking at a dashboard
    /// showing eleven connections and nobody online, and an alert on
    /// `resume.bytes` firing on a figure hours out of date. The soak's quiesce
    /// assertion is what surfaced it: a gauge that does not return to its
    /// baseline when nothing is connected.
    ///
    /// See `scripts/canon-gauges.json`.
    fn observe_admission(&self) {
        self.gauges.connections.observe(self.registry.len() as u64);
        self.gauges
            .resume_sessions
            .observe(self.resume.len() as u64);
        self.gauges
            .resume_bytes
            .observe(self.resume.bytes_total() as u64);
        self.gauges
            .pending_handshakes
            .observe(self.admission.in_flight() as u64);
        // Written by every enqueue as well, but never by a *departure*: the
        // "worst client" was whoever last had something queued, alive or not.
        self.gauges
            .control_queue
            .observe(self.registry.worst_control_queue() as u64);
    }

    /// Take an admission slot for `peer`, recording a refusal.
    ///
    /// `None` means the connection is to be closed without a task: refusing
    /// after a spawn would already have paid most of what the ceiling exists to
    /// avoid.
    fn admit(&self, peer: std::net::SocketAddr) -> Option<crate::admission::Ticket> {
        match self.admission.admit(peer.ip()) {
            Ok(ticket) => Some(ticket),
            Err(refusal) => {
                self.logger.log(
                    LogEvent::notice(Category::Security, "connection refused")
                        .with("peer", peer.to_string())
                        .with("reason", refusal.as_str()),
                );
                self.metrics
                    .counter("starling_gateway_admission_refused")
                    .inc();
                None
            }
        }
    }

    /// Complete the TLS handshake, within the admission deadline.
    ///
    /// # Errors
    ///
    /// The handshake failure, or [`std::io::ErrorKind::TimedOut`]. Unbounded, a
    /// peer that completed TCP and then sent one byte held its task, its
    /// descriptor and a rustls buffer for the life of the process: the 30 s
    /// idle reaper only ever sees connections that registered, which happens
    /// after this returns.
    async fn handshake(
        &self,
        stream: tokio::net::TcpStream,
        acceptor: TlsAcceptor,
        peer: std::net::SocketAddr,
    ) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error> {
        let attempt =
            tokio::time::timeout(self.admission.handshake_timeout(), acceptor.accept(stream));
        match attempt.await {
            Ok(Ok(tls)) => Ok(tls),
            Err(_elapsed) => {
                self.logger.log(
                    LogEvent::notice(Category::Security, "tls handshake timed out")
                        .with("peer", peer.to_string()),
                );
                self.metrics
                    .counter("starling_gateway_tls_handshake_timeouts")
                    .inc();
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the TLS handshake did not complete in time",
                ))
            }
            Ok(Err(error)) => {
                // A failed TLS handshake is the single most common "the client
                // cannot connect and the server says nothing" report: an expired
                // certificate, a client pinned to TLS 1.0, a plaintext probe.
                tracing::debug!(%peer, %error, "tls handshake failed");
                self.logger.log(
                    LogEvent::notice(Category::Security, "tls handshake failed")
                        .with("peer", peer.to_string())
                        .with("error", error.to_string()),
                );
                self.metrics.counter("starling_gateway_tls_failures").inc();
                Err(error)
            }
        }
    }

    /// One client, from TLS handshake to disconnect.
    async fn serve_client(
        self: Arc<Self>,
        stream: tokio::net::TcpStream,
        acceptor: TlsAcceptor,
        peer: std::net::SocketAddr,
        ticket: crate::admission::Ticket,
    ) -> Result<(), std::io::Error> {
        // Bounded. Unbounded, a peer that completed TCP and then sent one byte
        // held this task, its descriptor and a rustls buffer for the life of
        // the process: the 30 s idle reaper only ever sees connections that
        // registered, which happens after this returns.
        let tls = self.handshake(stream, acceptor, peer).await?;
        // The handshake is over, so the slot goes back. Holding it for the
        // life of the connection would make this a connection limit, which is
        // `max_users`' job and is answered with a `Reject` the client can read.
        drop(ticket);

        // Read before the stream is split: the chain lives on the rustls
        // connection, and after `tokio::io::split` there is no handle left that
        // can be asked for it.
        let peer_cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(PeerCertificate::from_chain);

        let conn = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let token = format!("{}-{conn}", self.gateway_id);

        let (handle, outbound) = connection::channel(
            conn,
            token,
            Arc::clone(&self.limits),
            self.control_pressure.clone(),
        );
        self.registry.insert(Arc::clone(&handle));
        self.metrics.counter("starling_gateway_connections").inc();

        self.record_connected(conn, peer, peer_cert.as_ref());

        self.attachments.broadcast_opened(&Opened {
            conn,
            peer_addr: peer.to_string(),
            cert_hash: peer_cert
                .as_ref()
                .map(|certificate| certificate.hash.clone())
                .unwrap_or_default(),
            strong_cert: peer_cert
                .as_ref()
                .is_some_and(|certificate| certificate.strong),
            certificates: peer_cert
                .as_ref()
                .map(|certificate| certificate.chain.clone())
                .unwrap_or_default(),
            instance: self.instance(),
        });

        let (mut reader, writer) = tokio::io::split(tls);
        let writer_task = tokio::spawn(pump_writer(writer, outbound, Arc::clone(&handle)));

        let mut limiter = Limiter::live(&self.buckets, now_ms(), Arc::clone(&self.message_limit));
        let mut buffer = BytesMut::with_capacity(READ_BUFFER_BYTES);
        let mut scratch = vec![0_u8; READ_BUFFER_BYTES];

        let reason = loop {
            let read = tokio::select! {
                // A service asked for this client to go, a kick, a ban, or the
                // handshake evicting a ghost. Without this the read loop sits
                // here until the peer happens to say something, so a kicked
                // client stays connected and keeps talking.
                () = handle.closed() => break "disconnected by the server",
                read = reader.read(&mut scratch) => match read {
                    Ok(read) => read,
                    // This used to be `?`, which returned before `finish` ran,
                    // and an I/O error is how *most* disconnects actually
                    // arrive: a client that crashed, a network that dropped, a
                    // reset. The clean `close_notify` below is the rare one.
                    // Skipping `finish` left the connection in the registry,
                    // never told the services the session was gone, and so left
                    // every other client rendering a user who is no longer
                    // there.
                    Err(error) => {
                        tracing::debug!(conn, %error, "connection ended abruptly");
                        break "connection reset";
                    }
                },
            };
            if read == 0 {
                break "peer closed";
            }
            // `get`, not an index: `read` comes from the TLS layer, and this
            // is the loop every unauthenticated peer's bytes arrive in.
            let Some(fresh) = scratch.get(..read) else {
                break "read past the buffer";
            };
            buffer.extend_from_slice(fresh);

            match self.drain_frames(&handle, &mut buffer, &mut limiter) {
                Ok(()) => {}
                // A protocol error closes *that* connection and nothing else,
                // hostile input is per-peer by construction.
                Err(error) => {
                    tracing::debug!(conn, %error, "malformed frame");
                    self.finish(conn, "protocol error", writer_task).await;
                    return Ok(());
                }
            }

            // Given back once the frames are out of it. `BytesMut` grows to the
            // largest frame a connection ever carried and never shrinks, so one
            // 8 MiB avatar left 8 MiB resident for the rest of that client's
            // session -- and with a thousand clients, for the rest of the
            // server's. Only when empty, so this never copies a partial frame,
            // and only when it has actually grown, so the ordinary case is a
            // comparison.
            if buffer.is_empty() && buffer.capacity() > READ_BUFFER_BYTES {
                buffer = BytesMut::with_capacity(READ_BUFFER_BYTES);
            }
        };

        self.finish(conn, reason, writer_task).await;
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
        // Every inbound frame, at trace. The gateway is the only place that
        // sees a client's traffic as it arrives, so when a UI action appears to
        // do nothing this answers the first question, did anything reach the
        // server at all, without guessing from downstream silence.
        tracing::trace!(
            conn = handle.conn,
            session = handle.session(),
            type_id = frame.type_id,
            len = frame.payload.len(),
            "frame in"
        );
        let router = self.router.current();
        let Some(route) = router.route(frame.type_id) else {
            // An unroutable type is dropped rather than fatal: a stale client
            // sending a burned type must not lose its session over it.
            tracing::debug!(
                conn = handle.conn,
                type_id = frame.type_id,
                "unroutable frame dropped"
            );
            self.metrics
                .counter("starling_gateway_unroutable_frames")
                .inc();
            return true;
        };

        // Buckets are per *service*, so every type a service owns shares one,
        // and `session-lifecycle` owns both `UserState`, which murmur does
        // rate-limit, and `Ping`, which it does not. Charging keepalives to the
        // same bucket as user actions means a client's own liveness traffic
        // eats the allowance its messages need, and the symptom is a text
        // message vanishing with no error: the gateway sheds it, the sender is
        // never told, and nothing retries.
        //
        // murmur applies `RATELIMIT` in named handlers rather than to a
        // connection wholesale (`Messages.cpp:47`), so the set below is that
        // list. Anything outside it is delivered without being charged.
        if is_rate_limited(frame.type_id) {
            match limiter.check(&route.bucket, now_ms()) {
                Verdict::Allow => {}
                Verdict::Throttle { retry_after_ms } => {
                    // On the operator's own record, not just `tracing`. This
                    // discards something a user sent and believes was
                    // delivered, and nothing retries it, the same class of
                    // event as a permission denial, which is also logged here.
                    // It was `tracing::debug!` alone, which on any normal
                    // deployment is invisible: a shed text message looked
                    // exactly like the server silently losing it.
                    tracing::info!(
                        conn = handle.conn,
                        session = handle.session(),
                        bucket = %route.bucket,
                        type_id = frame.type_id,
                        retry_after_ms,
                        "throttled; frame dropped"
                    );
                    self.logger.log(
                        LogEvent::notice(Category::Server, "frame dropped: rate limited")
                            .with("conn", handle.conn)
                            .with("session", handle.session())
                            .with("bucket", route.bucket.clone())
                            .with("type", frame.type_id)
                            .with("retry_after_ms", retry_after_ms),
                    );
                    self.metrics.counter("starling_gateway_throttled").inc();
                    self.notify_throttled(handle, frame.type_id, &route.bucket, retry_after_ms);
                    return true;
                }
            }
        }

        let Some(link) = self.attachments.get(&route.service) else {
            // Nothing is attached for this service, so the client's frame goes
            // nowhere and it will simply never be answered.
            tracing::warn!(
                conn = handle.conn,
                service = %route.service,
                type_id = frame.type_id,
                "no attachment for the routed service; frame dropped"
            );
            return true;
        };
        if !link.healthy() && route.tier.sheddable() {
            // Shed at the door rather than making the client wait a deadline
            // for the same answer.
            tracing::debug!(
                conn = handle.conn,
                service = %route.service,
                "shed: the service is unhealthy"
            );
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
        let outer = ServiceKind::SessionLifecycle.outer_type();
        // On the epoch, not on `is_fancy()`. This notice *is* a service outer
        // type, so the question is whether the peer can read one, and a Fancy
        // 0.3.0 client answers `is_fancy()` yes while having no reading for
        // 1000 at all -- its decoder treats the unknown id as a fatal read
        // error, so the courtesy of explaining a throttle cost it the
        // connection. Silence is the correct thing to give a peer that cannot
        // parse the explanation.
        if !handle.accepts(outer) {
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
        let _ = handle.send(
            Lane::Control,
            Outbound::whole(codec::frame(outer, &payload)),
        );
    }

    /// Tear one connection down, giving the writer a moment to say why.
    ///
    /// The flush is bounded and then the writer is aborted regardless: a peer
    /// that has stopped reading its socket must not be able to hold a
    /// connection slot open by refusing to drain. `FLUSH_GRACE` is far longer
    /// than a healthy client needs for the one queued frame and far shorter
    /// than anything a user would notice.
    async fn finish(&self, conn: u64, reason: &str, writer: tokio::task::JoinHandle<()>) {
        /// How long the writer may spend flushing before it is cut off.
        const FLUSH_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

        if let Some(handle) = self.registry.by_conn(conn) {
            handle.drain();
        }
        // Aborted only if it overran: on the ordinary path the writer has
        // already flushed and returned, and awaiting it is what guarantees
        // the refusal reached the wire before the socket closed.
        let mut writer = writer;
        if tokio::time::timeout(FLUSH_GRACE, &mut writer)
            .await
            .is_err()
        {
            tracing::debug!(conn, "writer did not flush in time; cutting it off");
            writer.abort();
        }
        // Read before the removal: afterwards there is no handle to ask, and
        // the session is the only id the rest of the log is keyed by.
        let handle = self.registry.by_conn(conn);
        let session = handle.as_ref().map_or(0, |h| h.session());
        let dropped_audio = handle.as_ref().map_or(0, |h| h.dropped_audio());

        self.registry.remove(conn);
        self.attachments.broadcast_closed(conn, reason);
        self.metrics.counter("starling_gateway_disconnects").inc();
        // After the removal, so the reading is what the gateway holds now and
        // not what it held a moment ago.
        self.observe_admission();

        let mut event = LogEvent::info(Category::Session, "client disconnected")
            .with("conn", conn)
            .with("session", session)
            .with("reason", reason.to_owned())
            .with("connections", self.registry.len());
        // Only when it happened: a zero on every disconnect trains an operator
        // to stop reading the field.
        if dropped_audio > 0 {
            event = event.with("dropped_audio", dropped_audio);
        }
        self.logger.log(event);
    }

    /// Who is connected, for the admin surface and tests.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

/// Write frames to one client until both lanes are done.
///
/// A free function rather than an inline `spawn` body, because it is the whole
/// of the *outbound* half of a connection and `serve_client` is the inbound
/// half: the two share nothing but the socket they split.
///
/// The two lanes are not interchangeable. Control frames are queued and must
/// all arrive; audio is popped in a burst and a write failure there returns
/// immediately, because a late voice frame is worthless and a peer whose socket
/// is failing has nothing to gain from the rest of the queue.
/// How many queued frames one batch may hold.
///
/// Bounded so a client that has stopped reading cannot make the writer hold an
/// unbounded slice while it compresses: the queue is already byte-bounded, and
/// this bounds the working set on top of it.
const MAX_BATCH: usize = 64;

async fn pump_writer(
    mut writer: tokio::io::WriteHalf<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    mut outbound: tokio::sync::mpsc::Receiver<Outbound>,
    handle: Arc<ClientHandle>,
) {
    loop {
        tokio::select! {
            frame = outbound.recv() => {
                let Some(frame) = frame else { break };
                // Credited back before the write, not after: the bytes have
                // left the queue and are this task's business now, and a slow
                // write must not make the queue look fuller than it is and
                // disconnect a client for the writer's own backlog.
                handle.control_sent(frame.len());
                // Drain whatever else is already queued before writing. A burst
                // is where compression pays, a reconnect flood or a page of
                // history, and a batch of one is exactly the case `batch`
                // declines, so a quiet connection is unaffected.
                let mut queued = vec![frame];
                while let Ok(more) = outbound.try_recv() {
                    handle.control_sent(more.len());
                    queued.push(more);
                    if queued.len() >= MAX_BATCH {
                        break;
                    }
                }

                let batched = handle.compresses().then(|| compress::batch(&queued)).flatten();
                let to_write: &[Outbound] = match &batched {
                    Some(one) => std::slice::from_ref(one),
                    None => &queued,
                };

                let mut failed = false;
                for frame in to_write {
                    if write_frame(&mut writer, frame).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed {
                    break;
                }
            }
            () = handle.audio_ready() => {
                while let Some(frame) = handle.pop_audio() {
                    if write_frame(&mut writer, &frame).await.is_err() {
                        return;
                    }
                }
            }
            // The connection is ending. Write out what is already queued
            // before going, because the frame that explains *why* is queued
            // immediately before the disconnect that follows it: `Reject` on
            // a refused login, `UserRemove` on a kick or a ban. Stopping here
            // instead delivers the disconnect and drops the reason, which
            // leaves the user staring at a connection that closed itself.
            //
            // Only what is already queued (`try_recv` rather than `recv`)
            // so a peer that has stopped reading cannot hold the teardown
            // open by never draining its socket. `finish` bounds it as well.
            () = handle.draining() => {
                while let Ok(frame) = outbound.try_recv() {
                    handle.control_sent(frame.len());
                    if write_frame(&mut writer, &frame).await.is_err() {
                        break;
                    }
                }
                break;
            }
        }
    }
    let _ = writer.shutdown().await;
}

/// Write one frame, header and payload together.
///
/// One vectored write, so rustls seals both into a single TLS record and the
/// kernel sends one segment. They are still never joined in memory: the payload
/// is shared across every recipient of a broadcast and the header is not
/// (`PROTOCOL-REDESIGN.md` §4, Z4), and a vectored write carries the two halves
/// to the socket without copying either.
///
/// Two plain writes here cost two TLS records and two segments per frame, and
/// with Nagle on the second waited for the first to be acknowledged: an extra
/// round trip per frame on a WAN, plus the peer's delayed-ACK timer whenever
/// that fired.
async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Outbound,
) -> std::io::Result<()> {
    use bytes::Buf as _;
    if frame.prefix.is_empty() {
        return writer.write_all(&frame.payload).await;
    }
    let mut joined = frame.prefix.clone().chain(frame.payload.clone());
    writer.write_all_buf(&mut joined).await
}

/// Whether an inbound type is charged to its route's rate-limit bucket.
///
/// murmur does not rate-limit a connection wholesale. It applies `RATELIMIT`
/// inside named handlers (`vendor/server/src/murmur/Messages.cpp:47`), and this
/// is that list: `Version`(0), `ChannelState`(7), `UserState`(9),
/// `TextMessage`(11) and `ACL`(13). Fancy adds its own charged types, WebRTC
/// signalling, typing and watch-sync, which reach their services on the outer
/// types below rather than upstream numbers.
///
/// **What is deliberately absent matters more than what is present.** `Ping`(3)
/// is the one to notice: it is a keepalive a client emits on a timer, murmur
/// never charges it, and because Starling's buckets are per *service* it shared
/// one with `UserState`. A client's own liveness traffic therefore spent the
/// allowance its text messages needed, and a shed frame is not retried or
/// reported, so messages went missing with nothing in any log to say why.
/// `Authenticate`(2), `CryptSetup`(15), `CodecVersion`(21) and `UserStats`(22)
/// are absent for the same reason: handshake and diagnostics, unlimited
/// upstream.
///
/// Audio is not here either, and must never be: it has its own bucket sized for
/// speech, and `UDPTunnel`(1) is returned from before the rate check upstream
/// (`Server.cpp:1905`).
const fn is_rate_limited(type_id: u16) -> bool {
    // Named rather than written as numbers: the outer types are assigned by
    // `ServiceKind`, and a literal here would silently point at a different
    // service the moment one is inserted before it.
    const VOICE: u16 = ServiceKind::Voice.outer_type();
    const SCREENSHARE: u16 = ServiceKind::Screenshare.outer_type();
    const SOCIAL: u16 = ServiceKind::Social.outer_type();

    matches!(
        type_id,
        0    // Version
        | 7  // ChannelState
        | 9  // UserState
        | 11 // TextMessage
        | 13 // ACL
        | VOICE // carries WebRTC signalling
        | SCREENSHARE // SDP offers, murmur's rate-limited path
        | SOCIAL // typing and watch-sync
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn a_keepalive_is_not_charged_to_the_bucket_a_users_messages_need() {
        // The bug this predicate exists for. Buckets are per service, so `Ping`
        // and `UserState` share one; charging the keepalive meant a client's
        // own liveness traffic could exhaust the allowance, and the gateway
        // sheds a frame without retrying or telling the sender. A text message
        // simply disappeared.
        assert!(
            !is_rate_limited(3),
            "Ping is a keepalive; murmur never charges it"
        );
        assert!(!is_rate_limited(2), "Authenticate is the handshake");
        assert!(!is_rate_limited(15), "CryptSetup is the handshake");
        assert!(!is_rate_limited(22), "UserStats is diagnostics");
    }

    #[test]
    fn the_types_murmur_rate_limits_are_still_charged() {
        // Parity in the other direction: dropping the charge entirely would
        // make the server trivially floodable, which is what the bucket is for.
        for type_id in [0_u16, 7, 9, 11, 13] {
            assert!(is_rate_limited(type_id), "murmur rate-limits {type_id}");
        }
    }

    #[test]
    fn audio_is_never_charged_to_a_message_bucket() {
        // `UDPTunnel` is answered and returned from before upstream's rate
        // check (`Server.cpp:1905`). Charging it once throttled a tunnelled
        // client off the air mid-sentence.
        assert!(
            !is_rate_limited(1),
            "UDPTunnel must never be message-limited"
        );
    }

    /// A directory this test owns, gone when it goes out of scope.
    struct TempDataDir(std::path::PathBuf);

    impl TempDataDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "starling-gateway-test-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The shipped defaults, with a data directory belonging to this test.
    ///
    /// Building a gateway over the defaults untouched generates a self-signed
    /// identity into `starling-data`, which is *relative* - so every test doing
    /// it wrote into whatever directory the test binary was started in, and two
    /// of them doing it at once raced. `File::create_new` refuses the second,
    /// which is `os error 80` on Windows and a test failing for what another
    /// test did on any platform. It only ever showed up on CI, because a fresh
    /// checkout has no `starling-data` and a working tree has had one since the
    /// first time these tests ran.
    fn shipped_defaults(tag: &str) -> (Config, TempDataDir) {
        let dir = TempDataDir::new(tag);
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        config.runtime.data_dir = dir.0.clone();
        (config, dir)
    }

    #[test]
    fn a_gateway_with_nothing_routed_refuses_to_start() {
        // Accepting clients it can answer none of looks like a hang, and a hang
        // is the hardest failure to attribute.
        let (mut config, _data) = shipped_defaults("no-routes");
        config.services.clear();
        let err = Gateway::new(
            Arc::new(config),
            Metrics::new(),
            &Pressure::new(),
            Health::new(),
            Logger::null(),
        )
        .expect_err("an empty table must be refused");
        assert!(matches!(err, GatewayError::NoRoutes));
    }

    /// A gateway wired over the shipped defaults, for a gauge assertion.
    ///
    /// The directory comes back with it: the identity is read at construction
    /// and held in memory, but a caller that drops it early is asking a
    /// question about a gateway whose data directory has gone.
    fn shipped_gateway(pressure: &Pressure) -> (Gateway, TempDataDir) {
        let (config, data) = shipped_defaults("gauges");
        let gateway = Gateway::new(
            Arc::new(config),
            Metrics::new(),
            pressure,
            Health::new(),
            Logger::null(),
        )
        .expect("the defaults must be servable");
        (gateway, data)
    }

    #[tokio::test]
    async fn the_connection_gauges_come_back_down_when_the_last_client_leaves() {
        // These were published on the accept path alone, so every reading was
        // "what this gateway held when the last peer arrived". After the final
        // client left, `connections` kept saying whatever it said then, for as
        // long as the process ran: a dashboard showing eleven connections on an
        // empty server, and an alert on `resume.bytes` firing on an hours-old
        // figure.
        //
        // Asserted here rather than only by the soak's quiesce check, because
        // this is the deterministic half: a stale gauge does not need load or
        // time to reproduce, only an arrival followed by a departure.
        let pressure = Pressure::new();
        let (gateway, _data) = shipped_gateway(&pressure);
        // Limits are read off the config and copied, so this one needs no
        // directory of its own - nothing here loads an identity.
        let limits = Arc::new(Limits::from_config(
            &Config::with_defaults(Path::new("/run/starling")).gateway,
        ));

        let (handle, _rx) = connection::channel(
            1,
            String::new(),
            limits,
            pressure.gauge("control queue (worst client)", 0),
        );
        // Something queued, so the control gauge is genuinely non-zero before
        // the departure. Without this the assertion after it would pass against
        // a gauge nothing had ever written.
        handle
            .send(
                Lane::Control,
                Outbound::whole(bytes::Bytes::from_static(&[0_u8; 128])),
            )
            .expect("the queue is empty");
        gateway.registry.insert(handle);
        gateway.observe_admission();
        assert_eq!(
            gauge_used(&pressure, "connections"),
            1,
            "an arrival must be visible"
        );
        assert_eq!(
            gauge_used(&pressure, connection::CONTROL_QUEUE_GAUGE),
            128,
            "and so must what it has queued"
        );

        // Through the real teardown, not by calling the observer directly: the
        // defect was never that `observe_admission` computed the wrong number,
        // it was that nothing called it when a client left.
        gateway
            .finish(1, "connection reset", tokio::spawn(async {}))
            .await;
        assert_eq!(
            gauge_used(&pressure, "connections"),
            0,
            "and so must the departure; a gauge that only counts up is a \
             dashboard that lies about an idle server"
        );
        assert_eq!(
            gauge_used(&pressure, connection::CONTROL_QUEUE_GAUGE),
            0,
            "with nobody connected there is no worst client, and reporting the \
             queue of one that has gone is worse than reporting nothing"
        );
    }

    /// One gauge's current reading, without disturbing its peak.
    ///
    /// Through `sample` rather than by holding the `Gauge`, because that is how
    /// the collector reads it, and a test that reads it another way would not
    /// notice the collector seeing something different.
    fn gauge_used(pressure: &Pressure, name: &str) -> u64 {
        pressure
            .sample()
            .into_iter()
            .find(|load| load.name == name)
            .map_or(u64::MAX, |load| load.used)
    }

    #[test]
    fn a_gateway_over_the_shipped_defaults_routes_every_service() {
        let (config, _data) = shipped_defaults("routes");
        let gateway = Gateway::new(
            Arc::new(config),
            Metrics::new(),
            &Pressure::new(),
            Health::new(),
            Logger::null(),
        )
        .expect("the defaults must be servable");
        assert!(gateway.router.current().route(11).is_some());
        assert_eq!(gateway.router.current().services().len(), 19);
    }

    /// A writer that records each write call as one entry, vectored or not.
    ///
    /// Stands in for the TLS stream, which seals every write into its own
    /// record: two calls here would be two records on the wire.
    #[derive(Default)]
    struct RecordingWriter {
        writes: Vec<Vec<u8>>,
    }

    impl tokio::io::AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes.push(buf.to_vec());
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_write_vectored(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let joined: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
            let len = joined.len();
            self.writes.push(joined);
            std::task::Poll::Ready(Ok(len))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_frame_goes_to_the_socket_in_one_write() {
        // Header and payload were once two writes, so two TLS records and two
        // segments, and with Nagle on the second waited for the first to be
        // acknowledged: a `Ping` reply cost two round trips on a WAN, and the
        // peer's delayed-ACK timer on top. One write is one record.
        let frame = Outbound {
            prefix: bytes::Bytes::from_static(&[0, 3, 0, 0, 0, 2]),
            payload: bytes::Bytes::from_static(&[8, 1]),
        };
        let mut writer = RecordingWriter::default();
        write_frame(&mut writer, &frame).await.expect("a write");
        assert_eq!(writer.writes, vec![vec![0, 3, 0, 0, 0, 2, 8, 1]]);

        // Audio arrives already joined, and must not be split to fit the rule.
        let mut writer = RecordingWriter::default();
        write_frame(
            &mut writer,
            &Outbound::whole(bytes::Bytes::from_static(&[1, 2, 3])),
        )
        .await
        .expect("a write");
        assert_eq!(writer.writes, vec![vec![1, 2, 3]]);
    }
}
