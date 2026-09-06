//! The e2e harness: a whole deployment, and a client that speaks its wire.
//!
//! Extracted from `crates/starling/src/e2e.rs`, which was a `#[cfg(test)] mod`
//! inside a binary crate and so reachable from nothing else. The e2e suite, the
//! soak (`crates/starling/tests/soak.rs`) and the chaos runs all drive a server
//! the same way; a second copy of [`Deployment`] would drift from this one
//! within a release.
//!
//! Every other test in the workspace exercises one crate. This is what proves
//! the composition in `starling::compose::all_in_one` actually wires a client
//! through the real handshake
//! (`crates/services/session-lifecycle/src/handshake.rs`) end to end, over a
//! real TCP+TLS socket, not an in-memory `Inbound`.
//!
//! TLS verification is disabled on the client, matching how every Mumble
//! client actually trusts a server: by fingerprint on first use, not by CA
//! chain (`crates/crypto/src/identity.rs`).
//!
//! Not published, and a `dev-dependency` everywhere it is used, so none of this
//! reaches a shipping artifact.

// Test scaffolding, so the panic lints do not apply: an assumption that fails
// while starting a deployment *is* the test result, and naming it is the whole
// point. `scripts/check-panic-audit.py` skips this crate for the same reason it
// skips `tests/`, and `publish = false` keeps it out of any artifact.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failed assumption is the test result"
)]
// The soak driver reports as it runs: a nightly that fails after two hours has
// to say on its first line what reproduces it, and nothing reads its stdout but
// a person.
#![allow(clippy::print_stdout, reason = "the soak run's own progress report")]

pub mod soak;

use std::net::{
    IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use prost::Message as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use starling_crypto::ocb2::{Block, Ocb2};
use starling_proto::codec;
use starling_proto::proto::tcp;
use starling_proto::proto::udp;
use starling_runtime::config::Config;
use starling_runtime::inproc::Broker;
use starling_runtime::log::{LogRuntime, LogSpec, Severity};
use starling_runtime::serve::{ServiceError, context};
use starling_runtime::shutdown::Shutdown;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The Mumble version Starling's own client half announces.
///
/// Encoded, not written out, for the reason `handshake.rs` records about
/// the identical literal on the server side: `0x0001_0006_0000` is missing the
/// sixteen-bit patch shift and decodes to **0.1.6**, which is below every
/// feature gate the number exists to pass.
///
/// It was invisible here for exactly as long as nothing depended on it, the
/// handshake completes either way. The moment audio was wired up, this client
/// was handed the pre-1.5 legacy framing and then sent protobuf audio, and
/// every frame it spoke was dropped as malformed.
pub const MUMBLE_VERSION_V2: u64 = starling_proto::MUMBLE_VERSION.encode_v2();
/// How long to wait for a frame before deciding the wiring is broken.
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// How long every service together has to return once the deployment drains.
///
/// One budget for the whole teardown, not one per service. Generous because a
/// loaded machine running the suite serially is the normal case and a drain
/// that takes two seconds is not a defect; short enough that the deadlock this
/// replaced, where a service waited on a stream that waited on the drain, is a
/// named failure rather than a hung test.
pub const DRAIN_GRACE: Duration = Duration::from_secs(30);
/// How long to wait for the live channel to report itself started.
///
/// Generous on purpose: see `started`. It bounds a whole deployment coming
/// up, not the delivery of a frame, and the two have no reason to share a
/// number.
pub const LIVE_START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for a deployment's services to bind their endpoints.
///
/// Like [`LIVE_START_TIMEOUT`] and unlike [`FRAME_TIMEOUT`], this bounds cold
/// startup rather than a frame. On a loaded Windows runner one service's named
/// pipe can take well past the frame budget to appear, which surfaced as an
/// intermittent "never bound" on whichever test lost the race.
pub const SERVICE_BIND_TIMEOUT: Duration = Duration::from_secs(60);

/// Upstream `UDPTunnel`: audio over the control connection.
pub const UDP_TUNNEL: u16 = 1;
/// Target 0: everyone else in the speaker's channel.
pub const REGULAR_SPEECH: u32 = 0;
/// Target 31: the server echoes the frame back to the speaker alone.
pub const SERVER_LOOPBACK: u32 = 31;

/// How long to keep re-sending a frame before deciding audio does not route.
///
/// A real client transmits fifty frames a second, so re-sending is what one
/// actually does, and it is what makes this test insensitive to *when* voice's
/// membership subscription happens to warm, without pretending that a single
/// dropped frame at start-up is a failure.
pub const AUDIO_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one attempt waits before the frame is sent again.
pub const AUDIO_ATTEMPT: Duration = Duration::from_millis(250);

/// One deployment at a time, however many threads the test harness uses.
///
/// Each of these tests starts a **whole server**, twenty services, most of them
/// opening their own database pool, inside this one process. Three of those at
/// once do not fail because anything is wrong with them; they fail because sixty
/// services contending on start-up push `userdata` past the two-second window a
/// caller retries a cold dial for, and the first login is then refused for real.
///
/// Serialising them is not hiding a race. What these tests exercise is one
/// deployment answering a client, and running three servers in one process is a
/// property no deployment has. The alternative, raising every timeout until it
/// fits, would make a genuine startup regression invisible.
pub static ONE_AT_A_TIME: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Every service plus the gateway, over a real TCP port instead of a socket
/// nobody outside the process can dial.
#[derive(Debug)]
pub struct Deployment {
    /// The gateway's TCP port, which is what a client dials.
    pub port: u16,
    /// Where voice is listening for audio, so a test can send it a datagram.
    pub voice_port: u16,
    shutdown: Shutdown,
    /// Named, because "a service panicked" is not actionable and "`voice`
    /// panicked" is. The name is the one `units::spawn` was called with.
    handles: Vec<(&'static str, JoinHandle<Result<(), ServiceError>>)>,
    log: LogRuntime,
    /// Kept so a test can call a service's gRPC surface directly, for the
    /// set-up a client is not permitted to do for itself.
    pub resolver: starling_runtime::channel::Resolver,
    /// Cleared by [`Deployment::stop`]. Still set at drop means the test
    /// returned without asserting its own teardown, which [`Drop`] reports.
    running: bool,
    /// Released when this deployment is dropped, letting the next test start.
    _exclusive: tokio::sync::MutexGuard<'static, ()>,
}

impl Deployment {
    /// Start everything `--all-in-one` starts, bound to an ephemeral port.
    pub async fn start(data_dir: &Path) -> Self {
        Self::start_with(data_dir, |_| {}).await
    }

    /// The same, with the configuration adjusted first.
    ///
    /// Exists for the surfaces that are **off by default** and so are absent
    /// from a plain deployment: `operator-api` is one, and a test that wants it
    /// has to say so the way an operator does, by configuring it.
    pub async fn start_with(data_dir: &Path, adjust: impl FnOnce(&mut Config)) -> Self {
        let exclusive = ONE_AT_A_TIME.lock().await;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        let port = free_port();
        let mut config = Config::with_defaults(data_dir);
        config.runtime.all_in_one = true;
        config.runtime.data_dir = data_dir.to_path_buf();
        config.gateway.listen_tcp = format!("127.0.0.1:{port}");
        // Voice binds a *real* UDP socket, and the shipped default is the fixed
        // 0.0.0.0:64738 every Mumble server wants. In a test that makes two
        // deployments fight over one port, two of these tests in parallel, or
        // one of them next to a server the developer happens to be running, and
        // the loser reports `Address already in use` and never starts. Ephemeral
        // and loopback-only, for the same reason the gateway's port above is.
        //
        // Reserved here, not left as `:0`, because a test that sends
        // audio has to know where to send it, and nothing reports the port a
        // service picked for itself.
        let voice_port = free_udp_port();
        if let Some(voice) = config.services.get_mut("voice") {
            voice.udp_listen = Some(format!("127.0.0.1:{voice_port}"));
        }
        adjust(&mut config);
        let config = Arc::new(config);
        let shutdown = Shutdown::new();
        let broker = Broker::new();

        // A real log runtime, not `Logger::null()`, so a deployment
        // under test exercises the same path a deployed one does, and so a
        // failing test can be read with the records that led to it. It keeps
        // the ring the admin surface reads, and stays off the console, where it
        // would interleave with the tracing output above.
        let log = LogRuntime::start(&LogSpec {
            console: false,
            memory: Some(1024),
            ..LogSpec::default()
        });
        let logger = log.logger().clone();

        let mut handles = Vec::new();
        for name in starling::units::names() {
            if !starling::compose::enabled(&config, name) {
                continue;
            }
            let ctx = context(
                name,
                Arc::clone(&config),
                broker.clone(),
                shutdown.clone(),
                logger.clone(),
            );
            if let Some(handle) = starling::units::spawn(name, ctx) {
                handles.push((*name, handle));
            }
        }

        let gateway_ctx = context(
            "gateway",
            Arc::clone(&config),
            broker.clone(),
            shutdown.clone(),
            logger,
        );
        handles.push((
            "gateway",
            starling::units::spawn("gateway", gateway_ctx).expect("\"gateway\" is a known unit"),
        ));

        // Wait for the services the handshake calls, not just for the gateway's
        // port. Everything is spawned concurrently and each service opens its own
        // database, so "the gateway is accepting" arrives well before "a login
        // can be answered". A client that authenticates in that gap is refused
        // for real: the caller's dial retry window is two seconds and a cold
        // start under load is longer, and `Authenticate` is answered once rather
        // than retried.
        //
        // This is the readiness the runtime does not expose. `/readyz` is an
        // in-process gate with no listener behind it, and the in-process broker
        // is not the signal either, a service resolves its *own* endpoint
        // through `broker.has`, which is false until it has registered, so under
        // `--all-in-one` it binds the configured socket rather than a pipe and
        // never registers at all. What is observable is the socket appearing.
        wait_until_serving(
            &config,
            &["userdata", "session-view", "metadata", "server-config"],
        )
        .await;

        Self {
            port,
            voice_port,
            shutdown,
            handles,
            log,
            resolver: starling_runtime::channel::Resolver::new(Arc::clone(&config), broker),
            running: true,
            _exclusive: exclusive,
        }
    }

    /// Create a channel, as an operator would.
    ///
    /// Through metadata's own gRPC, not the client plane, because
    /// creating a channel takes `MakeChannel` and the default ACL deliberately
    /// withholds it; this is deployment set-up, not the behaviour under test.
    pub async fn create_channel(&self, name: &str) -> u32 {
        self.create_described_channel(name, String::new()).await
    }

    /// The same, with a description.
    ///
    /// Separate because a description is what a channel carries *artwork* in,
    /// and one test is about a server whose artwork outgrew what a service
    /// would accept; every other caller wants the plain form above.
    pub async fn create_described_channel(&self, name: &str, description: String) -> u32 {
        use starling_proto_fancy::metadata::metadata_client::MetadataClient;
        use starling_proto_fancy::metadata::{Channel, CreateRequest};

        // Retried, because this is the first thing to dial metadata and it does
        // so the instant the service is up. `wait_until_serving` cannot help:
        // it waits on a `unix:` socket file appearing, and this platform serves
        // over named pipes, so it skips every service and returns at once. A
        // pipe that is not accepting yet reports "all pipe instances are busy",
        // which is a race to wait out, not a failure to report.
        let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
        let result = loop {
            let attempt = async {
                let transport = self.resolver.channel("metadata").ok()?;
                let created = MetadataClient::new(transport)
                    .create(CreateRequest {
                        scope: None,
                        // Internal: this is deployment set-up, not a user acting.
                        actor: None,
                        channel: Some(Channel {
                            name: name.to_owned(),
                            parent: Some(0),
                            description: description.clone(),
                            ..Channel::default()
                        }),
                        temporary: false,
                        invitee_user_ids: Vec::new(),
                        // Deployment set-up runs once; a name that is already
                        // there is a bug worth seeing, not one to absorb.
                        reuse_existing: false,
                    })
                    .await
                    .ok()?;
                Some(created.into_inner())
            }
            .await;
            if let Some(result) = attempt {
                break result;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "metadata never accepted a connection"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        result
            .channel
            .expect("the channel must have been created")
            .id
    }

    /// Install a channel's ACL table over gRPC.
    ///
    /// Deployment set-up, not a user acting: `SetAcl` is the operator surface,
    /// so it performs no permission check and is exactly what an administrator
    /// configuring a server through `operator-api` reaches. What the tests below
    /// then assert is what a **client** can do against the table this put there.
    ///
    /// Retried on the same grounds as [`Self::create_channel`]: a service that
    /// has not finished binding reports a busy pipe, which is a race to wait out.
    pub async fn set_acl(&self, acls: starling_proto_fancy::permissions::AclSet) {
        use starling_proto_fancy::permissions::SetAclRequest;
        use starling_proto_fancy::permissions::permissions_client::PermissionsClient;

        let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
        let result = loop {
            let attempt = async {
                let transport = self.resolver.channel("permissions").ok()?;
                PermissionsClient::new(transport)
                    .set_acl(SetAclRequest {
                        scope: None,
                        actor: None,
                        acls: Some(acls.clone()),
                    })
                    .await
                    .ok()
            }
            .await;
            if let Some(result) = attempt {
                break result.into_inner();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "permissions never accepted a connection"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(result.applied, "the ACL was refused: {}", result.refused);
    }

    /// Put a live session in a group, over the gRPC surface `operator-api`
    /// calls.
    ///
    /// This is the external-authority action murmur exposes as Ice's
    /// `addUserToGroup`, and it is deployment set-up here for the same reason
    /// `set_acl` is: no client can perform it, which is precisely what makes it
    /// the only way to put an *unregistered* user in a named group.
    pub async fn add_temporary_group(&self, channel: u32, group: &str, session: u32) {
        let result = self.temporary_group(channel, group, session, true).await;
        assert!(result.applied, "refused: {}", result.refused);
    }

    /// The same, in either direction and without asserting the outcome.
    ///
    /// Returned, not asserted: a *refusal* is the point of two of the tests
    /// below, since naming a session that has gone must not be recorded.
    pub async fn temporary_group(
        &self,
        channel: u32,
        group: &str,
        session: u32,
        add: bool,
    ) -> starling_proto_fancy::permissions::AclResult {
        use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
        use starling_proto_fancy::permissions::{TemporaryGroupRequest, temporary_group_request};

        let transport = self
            .resolver
            .channel("permissions")
            .expect("permissions is reachable");
        let request = TemporaryGroupRequest {
            scope: None,
            actor: None,
            channel,
            group: group.to_owned(),
            member: Some(temporary_group_request::Member::Session(session)),
        };
        let mut client = PermissionsClient::new(transport);
        if add {
            client.add_temporary_group(request).await
        } else {
            client.remove_temporary_group(request).await
        }
        .expect("the call itself succeeds")
        .into_inner()
    }

    /// Block until `permissions` grants `session` the `permission` in `channel`.
    ///
    /// For a test whose grant reaches `channel` only by **inheritance**.
    /// `permissions` learns the tree by subscribing to `metadata`
    /// (`follow_tree`), and that subscription is dialled the instant
    /// `permissions` is up, which on a cold deployment is seconds before
    /// `metadata` is. Until it connects, every channel evaluates as a root, a
    /// grant on the parent reaches nothing, and the test is refused for a
    /// reason that has nothing to do with what it asserts. `wait_until_serving`
    /// cannot cover it: it watches sockets, and this is a stream between two
    /// services that are both already serving.
    ///
    /// Asked over the same gRPC every service asks, so what it waits for is the
    /// answer the service under test is about to get.
    pub async fn wait_until_permitted(&self, session: u32, channel: u32, permission: u32) {
        use starling_proto_fancy::permissions::SessionCheckRequest;
        use starling_proto_fancy::permissions::permissions_client::PermissionsClient;

        let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
        loop {
            let allowed = async {
                let transport = self.resolver.channel("permissions").ok()?;
                let decision = PermissionsClient::new(transport)
                    .check_session(SessionCheckRequest {
                        scope: None,
                        session,
                        channel,
                        permission,
                        temporary_tokens: Vec::new(),
                    })
                    .await
                    .ok()?;
                Some(decision.into_inner().allowed)
            }
            .await;
            if allowed == Some(true) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "permissions never granted {permission:#x} in channel {channel} to session {session}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Every service's health, load and counters, through the collector.
    ///
    /// The soak harness's window onto the whole deployment: gauges and counters
    /// for all twenty-three units in one call, without a scrape and without
    /// touching `Pressure::sample`, which the `health` service owns.
    pub async fn overview(&self) -> starling_proto_fancy::health::Overview {
        use starling_proto_fancy::health::OverviewRequest;
        use starling_proto_fancy::health::health_overview_client::HealthOverviewClient;

        let channel = self
            .resolver
            .channel("health")
            .expect("the health collector is part of every deployment");
        HealthOverviewClient::new(channel)
            .get(OverviewRequest {
                scope: Some(starling_proto_fancy::common::Scope { instance: 1 }),
            })
            .await
            .expect("the collector answers")
            .into_inner()
    }

    /// The records this deployment has written so far.
    pub fn records(&self) -> Vec<starling_runtime::log::LogEvent> {
        self.log
            .recent()
            .map(|handle| handle.recent(1024))
            .unwrap_or_default()
    }

    /// Drain every service, then assert this deployment came down cleanly.
    ///
    /// This used to call `abort()` on each handle without awaiting it, which
    /// threw away the one thing a `JoinHandle` is worth holding: a service that
    /// panicked took its `JoinError` to the floor, and the test that noticed
    /// was a *later* one timing out on a client the dead service should have
    /// answered. Draining and joining is what puts a panic on the test that
    /// caused it, with the panic's own message.
    ///
    /// Panics rather than returning a result, because every caller is a test
    /// and the failure is the point.
    pub async fn stop(self) {
        self.stop_allowing(&[]).await;
    }

    /// The same, tolerating the error records a test provokes on purpose.
    ///
    /// Matched against `LogEvent::message`, which is constant per call site by
    /// convention, so an entry names one call site rather than waving through a
    /// whole class of failure.
    pub async fn stop_allowing(mut self, allowed: &[&str]) {
        // Cleared first. Every assertion below panics on failure, and a
        // panicking `stop` must not also trip the `Drop` guard, whose message
        // would replace the one naming the real fault.
        self.running = false;
        self.shutdown.drain();

        // One deadline for the whole teardown rather than one per service:
        // twenty-three services each allowed the full grace is a wedge that
        // takes minutes to report, and they drain concurrently anyway.
        let deadline = tokio::time::Instant::now() + DRAIN_GRACE;
        let mut panicked = Vec::new();
        let mut failed = Vec::new();
        let mut stuck = Vec::new();
        for (name, handle) in std::mem::take(&mut self.handles) {
            let aborter = handle.abort_handle();
            match tokio::time::timeout_at(deadline, handle).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => failed.push(format!("{name}: {error}")),
                Ok(Err(error)) if error.is_panic() => {
                    panicked.push(format!("{name}: {}", panic_message(error)));
                }
                // Cancelled, without this call having asked for it. Nothing
                // aborts a service handle any more, so this is no longer the
                // routine outcome it was and is worth naming.
                Ok(Err(error)) => failed.push(format!("{name}: {error}")),
                Err(_) => {
                    // Left running, it would outlive this test only to be
                    // dropped with its runtime, after racing the next test for
                    // the ports this one is about to release.
                    aborter.abort();
                    stuck.push(name);
                }
            }
        }

        let logged: Vec<String> = self
            .records()
            .into_iter()
            .filter(|event| event.severity >= Severity::Error)
            .filter(|event| !allowed.contains(&event.message.as_str()))
            .map(|event| format!("{:?}/{}", event.category, event.message))
            .collect();

        // Ordered by how much each says about what went wrong: a panic names
        // the line, a returned error names the service, a stalled drain names
        // only that something did not finish.
        assert!(panicked.is_empty(), "a service panicked: {panicked:#?}");
        assert!(
            failed.is_empty(),
            "a service stopped with an error: {failed:#?}"
        );
        assert!(
            stuck.is_empty(),
            "services did not drain within {DRAIN_GRACE:?}: {stuck:?}"
        );
        assert!(
            logged.is_empty(),
            "the deployment logged errors: {logged:#?}\n\
             If the test provokes one deliberately, name its message in \
             `stop_allowing` instead of dropping this assertion."
        );
    }
}

impl Drop for Deployment {
    /// A deployment dropped without [`Deployment::stop`] asserted nothing about
    /// its own teardown, so a service that panicked inside it goes unreported.
    ///
    /// Guarded on `panicking()`: during an unwind this would be a *second*
    /// panic, which aborts the process and loses the assertion the test
    /// actually failed on.
    fn drop(&mut self) {
        assert!(
            !self.running || std::thread::panicking(),
            "this deployment was dropped without `stop().await`, so nothing \
             checked whether its services came down cleanly"
        );
    }
}

/// The message a panicking task carried, for the teardown report.
///
/// A panic payload is `Box<dyn Any>`; the two shapes `panic!` produces are a
/// `&'static str` for a literal and a `String` for a format.
pub fn panic_message(error: tokio::task::JoinError) -> String {
    let payload = error.into_panic();
    payload
        .downcast_ref::<&'static str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panicked with a payload that is not a string".to_owned())
}

/// Block until each of `services` has bound the endpoint it was configured with.
///
/// **Both local transports are waited on.** This used to look only for a
/// `unix:` path, which meant that on Windows, where every local endpoint is a
/// named pipe, it matched nothing, skipped every service, and returned
/// immediately. The wait was a no-op on that platform, so a client connected to
/// a deployment whose services had not finished binding and the handshake timed
/// out. It presented as intermittent, and looked like a transport fault
/// instead of the missing wait it was.
///
/// A service reached over `http://` is left alone: it has no local artefact to
/// watch, and the deadline below is what catches a genuine hang.
pub async fn wait_until_serving(config: &Config, services: &[&str]) {
    let deadline = tokio::time::Instant::now() + SERVICE_BIND_TIMEOUT;
    for service in services {
        // Read off the configured string rather than through a parsed endpoint
        // type. All this needs is what the endpoint binds, and depending on the
        // transport layer's own representation for that ties a test helper to a
        // type that has already been moved once.
        let Some(endpoint) = config
            .services
            .get(*service)
            .and_then(|service| service.endpoint.as_deref())
            .map(str::to_owned)
        else {
            continue;
        };
        while !is_bound(&endpoint) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{service} never bound {endpoint}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Whether whatever `endpoint` names is being served yet.
pub fn is_bound(endpoint: &str) -> bool {
    if let Some(path) = endpoint.strip_prefix("unix:") {
        return PathBuf::from(path).exists();
    }
    if let Some(name) = endpoint.strip_prefix("pipe:") {
        return pipe_bound(name);
    }
    // `http://` and anything else: nothing local to watch for.
    true
}

/// Whether a named pipe has been created.
///
/// Opened and dropped, not enumerated. The pipe namespace *can* be
/// listed as a directory, but `local_endpoint` derives a pipe's name from a
/// filesystem path and so produces one containing `/`, which does not survive
/// being read back as a directory entry. Opening it is the question actually
/// being asked, and the accept loop creates each instance's replacement before
/// handing the connected one on (`transport/pipe.rs`), so this probe never
/// takes the instance a real caller is about to need.
#[cfg(windows)]
pub fn pipe_bound(name: &str) -> bool {
    tokio::net::windows::named_pipe::ClientOptions::new()
        .open(format!(r"\\.\pipe\{name}"))
        .is_ok()
}

/// Never reached: a pipe endpoint is rejected at startup off Windows.
#[cfg(not(windows))]
pub const fn pipe_bound(_name: &str) -> bool {
    true
}

/// Reserve a loopback port the gateway can bind next.
///
/// The listener is dropped immediately, so there is a race in principle; in
/// practice nothing else in this process binds a port between the two calls.
pub fn free_port() -> u16 {
    let listener = StdTcpListener::bind(SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        .expect("an ephemeral port is always available");
    listener
        .local_addr()
        .expect("a bound listener has a local address")
        .port()
}

/// Reserve a loopback UDP port for voice to bind next.
///
/// The same trade as [`free_port`], for the other protocol: voice picks its own
/// port when told `:0`, and reports it nowhere a test can read.
pub fn free_udp_port() -> u16 {
    let socket = StdUdpSocket::bind(SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        .expect("an ephemeral port is always available");
    socket
        .local_addr()
        .expect("a bound socket has a local address")
        .port()
}

/// One frame of speech, as a 1.5-or-later client puts it on the wire.
pub fn audio_frame(target: u32, opus: &[u8]) -> Vec<u8> {
    // A leading 0 is the protobuf format's `Audio` discriminator.
    let mut out = vec![0_u8];
    let _ = udp::Audio {
        // `target` inbound. The server answers with `context`, which is a
        // different field of the same oneof; they are not interchangeable.
        header: Some(udp::audio::Header::Target(target)),
        sender_session: 0,
        frame_number: 1,
        opus_data: opus.to_vec(),
        ..udp::Audio::default()
    }
    .encode(&mut out);
    out
}

/// Who spoke, and what they said, out of a frame the server sent.
pub fn heard(payload: &[u8]) -> (u32, Vec<u8>) {
    assert_eq!(payload.first(), Some(&0), "not an audio packet");
    let audio = udp::Audio::decode(&payload[1..]).expect("a well-formed audio frame");
    (audio.sender_session, audio.opus_data)
}

/// A throwaway directory, removed when the test drops it.
/// A data directory that goes away when the test does.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    /// A fresh directory named for `tag`, this process and this thread.
    ///
    /// Named rather than random so a run left behind by a killed test is
    /// identifiable, and removed first so a second run is not polluted by it.
    #[must_use]
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "starling-e2e-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the temp data dir");
        Self(path)
    }

    /// Where the deployment should keep its state.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Accepts any server certificate. Standing in for trust-on-first-use, which
/// a real Mumble client implements by pinning the fingerprint after this
/// point, not by chain validation.
#[derive(Debug)]
pub struct TrustAnyCertificate;

impl ServerCertVerifier for TrustAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Connect once the gateway's listener is actually up.
///
/// Every service, including the gateway, is spawned concurrently and binds
/// its listener asynchronously, so a connect attempt immediately after
/// `Deployment::start` returns is a startup-ordering race, not a real
/// failure, so retry until the deadline. The caller has no way to know how
/// long that takes.
pub async fn connect_with_retry(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("the gateway never started listening: {error}"),
        }
    }
}

/// A raw Mumble client: frames in, frames out, no generated stubs, the same
/// view of the wire the gateway itself has (`docs/ARCHITECTURE.md` §1).
#[derive(Debug)]
pub struct Client {
    stream: TlsStream<TcpStream>,
    buffer: BytesMut,
    /// The `CryptSetup` the server minted for this connection.
    ///
    /// Kept as it goes past, not fished out afterwards: it arrives in the
    /// middle of the handshake flood, and it is the only thing that makes a
    /// datagram from this client decryptable by the server.
    crypt_setup: Option<tcp::CryptSetup>,
    /// The `fancy_version` the server volunteered, if it did.
    ///
    /// Kept the same way and for the same reason as `crypt_setup`: it arrives
    /// unprompted in the middle of the handshake flood, in a *second* `Version`
    /// the server sends only once it knows the peer's epoch. A real client gates
    /// features on it, so a test that wants to know whether a feature could work
    /// at all is asking about this field.
    pub announced_fancy_version: Option<u64>,
}

impl Client {
    /// Dial the gateway and complete TLS, trusting whatever certificate it has.
    pub async fn connect(port: u16) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAnyCertificate))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = connect_with_retry(port).await;
        let name = ServerName::try_from("localhost").expect("a valid server name");
        let stream = connector
            .connect(name, tcp)
            .await
            .expect("the gateway completes a TLS handshake");
        Self {
            stream,
            buffer: BytesMut::with_capacity(8 * 1024),
            crypt_setup: None,
            announced_fancy_version: None,
        }
    }

    /// The same client, presenting a certificate of its own.
    ///
    /// Mumble's durable identity: the server asks for one
    /// (`crates/crypto/src/peer_cert.rs`) and never requires it, so most tests
    /// here connect without. Anything that has to outlive the connection needs
    /// it, which for now means scheduling a message for later.
    pub async fn connect_with_certificate(port: u16, dir: &Path) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Self-signed and generated here, exactly as a real client's is: the
        // server pins the hash of whatever it is shown and asks no CA.
        let identity = starling_crypto::identity::load_or_generate(
            &dir.join("client-cert.pem"),
            &dir.join("client-key.pem"),
        )
        .expect("a client certificate");
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAnyCertificate))
            .with_client_auth_cert(identity.certs, identity.key)
            .expect("the generated certificate is usable");
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = connect_with_retry(port).await;
        let name = ServerName::try_from("localhost").expect("a valid server name");
        let stream = connector
            .connect(name, tcp)
            .await
            .expect("the gateway completes a TLS handshake");
        Self {
            stream,
            buffer: BytesMut::with_capacity(8 * 1024),
            crypt_setup: None,
            announced_fancy_version: None,
        }
    }

    /// Put one framed control message on the wire.
    pub async fn send(&mut self, type_id: u16, message: &impl prost::Message) {
        let frame = codec::frame(type_id, &message.encode_to_vec());
        self.stream
            .write_all(&frame)
            .await
            .expect("the connection is still open");
    }

    /// Send an already-encoded payload, for the types that are not protobuf.
    ///
    /// `UDPTunnel` is the only one: its payload is an audio frame, not a
    /// message, which is exactly why it needs its own door.
    pub async fn send_raw(&mut self, type_id: u16, payload: &[u8]) {
        let frame = codec::frame(type_id, payload);
        self.stream
            .write_all(&frame)
            .await
            .expect("the connection is still open");
    }

    /// The next complete frame, waiting for more bytes as needed.
    pub async fn recv(&mut self) -> (u16, Vec<u8>) {
        self.next_frame(FRAME_TIMEOUT)
            .await
            .expect("a frame arrives within the timeout")
    }

    /// The next complete frame, or `None` if `within` elapses first.
    ///
    /// The fallible half of [`Self::recv`], for the callers that are *waiting*
    /// for something instead of asserting on what comes next: a client that
    /// keeps talking has to be able to try again, and a panic is not a retry.
    pub async fn next_frame(&mut self, within: Duration) -> Option<(u16, Vec<u8>)> {
        let deadline = tokio::time::Instant::now() + within;
        let mut scratch = [0_u8; 8 * 1024];
        loop {
            if let Some(frame) =
                codec::decode_raw(&mut self.buffer).expect("the gateway sends well-formed frames")
            {
                let payload = frame.payload.to_vec();
                if frame.type_id == 15
                    && let Ok(setup) = tcp::CryptSetup::decode(payload.as_slice())
                {
                    self.crypt_setup = Some(setup);
                }
                // Only when it carries one: the opening `Version` does not, and
                // letting that overwrite the second would record the absence
                // rather than the announcement.
                if frame.type_id == 0
                    && let Ok(version) = tcp::Version::decode(payload.as_slice())
                    && let Some(fancy) = version.fancy_version
                {
                    self.announced_fancy_version = Some(fancy);
                }
                return Some((frame.type_id, payload));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let read = timeout(remaining, self.stream.read(&mut scratch))
                .await
                .ok()?
                .expect("the socket stays readable");
            assert!(read > 0, "the gateway closed the connection early");
            self.buffer.extend_from_slice(&scratch[..read]);
        }
    }

    /// Whether the server hangs up within `within`.
    ///
    /// The fallible counterpart to [`Self::next_frame`], which asserts the
    /// connection stays open, right for every test that expects to keep
    /// talking, and useless for the one asserting the server rings off.
    ///
    /// Anything still arriving is consumed and discarded: a refusal is
    /// followed by a close, but the close is the assertion, not what happens
    /// to be in flight ahead of it.
    pub async fn closed_by_server(&mut self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        let mut scratch = [0_u8; 8 * 1024];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match timeout(remaining, self.stream.read(&mut scratch)).await {
                // EOF, or the TLS session ending: the server closed.
                Ok(Ok(0) | Err(_)) => return true,
                Ok(Ok(_)) => {}
                // Still open and still quiet, which is the bug this guards.
                Err(_) => return false,
            }
        }
    }

    /// The `UserRemove` naming `session`, or `None` if the server hung up first.
    ///
    /// The tolerant sibling of [`Self::next_frame`], which asserts the socket
    /// stays open: here the close is the *other* outcome under test, so
    /// reaching it has to be an answer rather than a panic.
    pub async fn next_removal_of(
        &mut self,
        session: u32,
        within: Duration,
    ) -> Option<tcp::UserRemove> {
        let deadline = tokio::time::Instant::now() + within;
        let mut scratch = [0_u8; 8 * 1024];
        loop {
            while let Some(frame) =
                codec::decode_raw(&mut self.buffer).expect("the gateway sends well-formed frames")
            {
                if frame.type_id != 8 {
                    continue;
                }
                let removal = tcp::UserRemove::decode(frame.payload.as_ref())
                    .expect("a well-formed UserRemove");
                if removal.session == session {
                    return Some(removal);
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match timeout(remaining, self.stream.read(&mut scratch)).await {
                // EOF or the TLS session ending: hung up without saying why.
                Ok(Ok(0) | Err(_)) | Err(_) => return None,
                Ok(Ok(read)) => self.buffer.extend_from_slice(&scratch[..read]),
            }
        }
    }

    /// This connection's half of the voice cipher.
    ///
    /// OCB2, because this client announces no Fancy version, the same cipher
    /// every stock Mumble client is given.
    ///
    /// Note the crossover: the client sends under the *client* nonce and expects
    /// the *server's*, which is the mirror of what the server built from the
    /// same three fields. Getting it backwards makes every packet fail its tag,
    /// in both directions, and looks exactly like silence.
    pub fn voice_cipher(&self) -> Ocb2 {
        let setup = self
            .crypt_setup
            .as_ref()
            .expect("the handshake delivered a CryptSetup");
        let key: [u8; 16] = setup
            .key
            .as_deref()
            .expect("a key")
            .try_into()
            .expect("sixteen bytes of key");
        let client: [u8; 16] = setup
            .client_nonce
            .as_deref()
            .expect("a client nonce")
            .try_into()
            .expect("sixteen bytes of nonce");
        let server: [u8; 16] = setup
            .server_nonce
            .as_deref()
            .expect("a server nonce")
            .try_into()
            .expect("sixteen bytes of nonce");
        Ocb2::new(key, Block(server), Block(client))
    }

    /// The `UserState` that next reports `session` to have changed channel.
    ///
    /// Skips everything else: a move arrives as a `UserState` among whatever
    /// the server happens to be sending at the time, so waiting for "the next
    /// frame" would race a join notification.
    pub async fn next_move_of(&mut self, session: u32) -> tcp::UserState {
        loop {
            let (type_id, payload) = self.recv().await;
            if type_id != 9 {
                continue;
            }
            let state =
                tcp::UserState::decode(payload.as_slice()).expect("a well-formed UserState");
            if state.session == Some(session) && state.channel_id.is_some() {
                return state;
            }
        }
    }

    /// The next `UserState` about `session` that `carries` something.
    ///
    /// Skips everything else, for the same reason [`Self::next_move_of`] does: a
    /// server broadcasting joins, pings and channel state does not stop because
    /// a test is waiting for one field, and requiring it to be the very next
    /// frame fails on whatever else was in flight.
    pub async fn next_state_of(
        &mut self,
        session: u32,
        carries: impl Fn(&tcp::UserState) -> Option<bool>,
    ) -> tcp::UserState {
        loop {
            let (type_id, payload) = self.recv().await;
            if type_id != 9 {
                continue;
            }
            let state =
                tcp::UserState::decode(payload.as_slice()).expect("a well-formed UserState");
            if state.session == Some(session) && carries(&state).is_some() {
                return state;
            }
        }
    }

    /// The next tunnelled audio frame, or `None` if `within` elapses.
    ///
    /// Skips everything else: a server that is broadcasting joins, pings and
    /// channel state does not stop doing so because a test is listening for
    /// audio, and requiring audio to be the very next frame would fail on
    /// whatever else happened to be in flight.
    pub async fn next_audio(&mut self, within: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (type_id, payload) = self.next_frame(remaining).await?;
            if type_id == UDP_TUNNEL {
                return Some(payload);
            }
        }
    }

    /// The channel `session` is next reported to be in.
    pub async fn next_channel_of(&mut self, session: u32) -> u32 {
        self.next_move_of(session)
            .await
            .channel_id
            .expect("next_move_of yields only a state that carries one")
    }

    /// Hang up, and wait for the server to notice.
    ///
    /// Closing the socket is not the same as the server having processed the
    /// disconnect, and a test that depends on the *consequences* of a departure
    /// a session id returning to the pool, a session-scoped grant being
    /// dropped, has to wait for the second thing, not the first.
    pub async fn close(mut self) {
        let _ = self.stream.shutdown().await;
        drop(self);
        // Short: the gateway reports a closed connection as soon as its reader
        // sees EOF, and everything downstream of that is in-process.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    /// The server's answer to a channel-switch request: the move, or the refusal.
    ///
    /// Both are legitimate answers and a test asserting one has to be able to
    /// see the other, a locked channel that quietly moves nobody and a locked
    /// channel that says so are the same timeout otherwise.
    /// Ask to enter `channel`, and wait for the server's answer.
    ///
    /// The pair is always used together, a bare `UserState` with no answer
    /// read proves nothing, and reading an answer nobody asked for hangs, so
    /// they are one call. `why` names the step, because a timeout here is
    /// otherwise an unattributed ten seconds in a test with several of them.
    pub async fn enter(
        &mut self,
        session: u32,
        channel: u32,
        why: &str,
    ) -> Result<u32, tcp::PermissionDenied> {
        self.send(
            9,
            &tcp::UserState {
                session: Some(session),
                channel_id: Some(channel),
                ..tcp::UserState::default()
            },
        )
        .await;
        timeout(FRAME_TIMEOUT, self.next_entry_answer(session))
            .await
            .unwrap_or_else(|_| panic!("{why}"))
    }

    /// The server's answer to a channel entry: the channel, or the refusal.
    pub async fn next_entry_answer(&mut self, session: u32) -> Result<u32, tcp::PermissionDenied> {
        loop {
            let (type_id, payload) = self.recv().await;
            match type_id {
                9 => {
                    let state = tcp::UserState::decode(payload.as_slice())
                        .expect("a well-formed UserState");
                    if state.session == Some(session)
                        && let Some(channel) = state.channel_id
                    {
                        return Ok(channel);
                    }
                }
                12 => {
                    return Err(tcp::PermissionDenied::decode(payload.as_slice())
                        .expect("a well-formed PermissionDenied"));
                }
                _ => {}
            }
        }
    }

    /// Frames up to and not including `target`, plus `target`'s own payload.
    ///
    /// Used for handshake steps whose count varies (how many channels, how
    /// many other users) but whose *next fixed point* does not.
    pub async fn recv_until(&mut self, target: u16) -> (Vec<u16>, Vec<u8>) {
        let mut seen = Vec::new();
        loop {
            let (type_id, payload) = self.recv().await;
            if type_id == target {
                return (seen, payload);
            }
            seen.push(type_id);
            assert!(
                seen.len() < 64,
                "type {target} did not arrive within 64 frames; saw {seen:?}"
            );
        }
    }
}

/// Drive one client through the full handshake and return its session id.
///
/// Order asserted here is `docs/PORTING-PLAN.md` §4's murmur-derived contract:
/// server `Version` first, then `CryptSetup`/`CodecVersion`/`ChannelState`/
/// `UserState` in any relative order but all before `ServerSync`, then
/// `ServerConfig` immediately, then `SuggestConfig`.
pub async fn handshake(client: &mut Client, username: &str) -> u32 {
    handshake_with_tokens(client, username, Vec::new()).await
}

/// The same handshake, presenting access tokens.
///
/// `Authenticate` is the only message that carries them, and a client sends the
/// ones it has stored for this server at login, which is how a channel
/// password the user saved once opens the channel on every later connection.
pub async fn handshake_with_tokens(
    client: &mut Client,
    username: &str,
    tokens: Vec<String>,
) -> u32 {
    handshake_as(
        client,
        tcp::Authenticate {
            username: Some(username.to_owned()),
            tokens,
            ..tcp::Authenticate::default()
        },
        None,
    )
    .await
}

/// The same handshake, with the credentials and client build spelled out.
///
/// `fancy` is the version a Fancy client advertises, and `None` is a stock
/// Mumble client. The two are not interchangeable to the server: a stock client
/// is never sent an out-of-tree channel, because it would render one under the
/// root.
pub async fn handshake_as(
    client: &mut Client,
    authenticate: tcp::Authenticate,
    fancy: Option<u64>,
) -> u32 {
    let (greeting_type, greeting_payload) = client.recv().await;
    assert_eq!(
        greeting_type, 0,
        "the server must speak Version first, unprompted"
    );
    let greeting =
        tcp::Version::decode(greeting_payload.as_slice()).expect("a well-formed Version");
    assert!(
        greeting.version_v2.is_some(),
        "the greeting must carry the v2 version field"
    );

    client
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                fancy_version: fancy,
                ..tcp::Version::default()
            },
        )
        .await;
    client.send(2, &authenticate).await;

    let (before_sync, sync_payload) = client.recv_until(5).await;
    assert!(
        before_sync.contains(&15),
        "CryptSetup must precede ServerSync"
    );
    assert!(
        before_sync.contains(&21),
        "CodecVersion must precede ServerSync"
    );
    assert!(
        before_sync.contains(&7),
        "the channel tree must precede ServerSync"
    );
    assert!(
        before_sync.contains(&9),
        "the client's own UserState must precede ServerSync"
    );
    let sync = tcp::ServerSync::decode(sync_payload.as_slice()).expect("a well-formed ServerSync");
    let session = sync.session.expect("ServerSync carries the session id");

    let (before_config, _) = client.recv_until(24).await;
    assert!(
        before_config.is_empty(),
        "ServerConfig must follow ServerSync directly, saw {before_config:?} first"
    );
    let (next_type, _) = client.recv().await;
    assert_eq!(next_type, 25, "SuggestConfig must follow ServerConfig");

    session
}

/// The handshake for a test whose subject is a Fancy service.
///
/// Every service outer type is epoch-1 only, and the gateway withholds one from
/// a peer that never announced the epoch, so a test that talks to a service has
/// to connect the way a real Fancy client does -- which is the point: these
/// used to pass over an ungated fan-out, and an epoch-0 client was being handed
/// frames its decoder treats as a fatal read error.
///
/// Returns just the session id, which is all these callers want; the announced
/// feature version is what `handshake_epoch1` exists to assert on.
pub async fn handshake_fancy(client: &mut Client, username: &str) -> u32 {
    handshake_epoch1(client, username).await.0
}

/// The wire epoch this server speaks, as a client announces it.
///
/// `handshake_as` above deliberately does not send this: its clients are the
/// epoch-0 shape, which is what most of these tests are about. A client that
/// does send it is told which Fancy features exist, and that is a different
/// handshake with one more frame in it.
pub const CLIENT_FANCY_PROTOCOL: u32 = 1;

/// Where persistent chat lives on the wire, from the one table that owns it.
pub const PCHAT_OUTER_TYPE: u16 = starling_proto_fancy::types::ServiceKind::Pchat.outer_type();

/// Handshake as a client that speaks epoch 1, returning `(session, announced)`.
///
/// `announced` is the `fancy_version` the server volunteered in its **second**
/// `Version`. A client gates real features on that number, so "did it arrive"
/// is the whole question this helper exists to answer.
pub async fn handshake_epoch1(client: &mut Client, username: &str) -> (u32, Option<u64>) {
    let (greeting_type, greeting_payload) = client.recv().await;
    assert_eq!(greeting_type, 0, "the server speaks Version first");
    let greeting =
        tcp::Version::decode(greeting_payload.as_slice()).expect("a well-formed Version");
    assert_eq!(
        greeting.fancy_version, None,
        "the opening Version cannot know the peer's epoch yet, so it must not claim features"
    );

    client
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                fancy_protocol: Some(CLIENT_FANCY_PROTOCOL),
                ..tcp::Version::default()
            },
        )
        .await;
    client
        .send(
            2,
            &tcp::Authenticate {
                username: Some(username.to_owned()),
                opus: Some(true),
                ..tcp::Authenticate::default()
            },
        )
        .await;

    let (before_sync, sync_payload) = client.recv_until(5).await;
    // The ordering that matters for this frame specifically: a client reads its
    // voice cipher off the announced version, so a version arriving after the
    // keys would leave the two ends on different ciphers.
    let version_at = before_sync
        .iter()
        .position(|&kind| kind == 0)
        .expect("the second Version arrives before ServerSync");
    let crypt_at = before_sync
        .iter()
        .position(|&kind| kind == 15)
        .expect("CryptSetup precedes ServerSync");
    assert!(
        version_at < crypt_at,
        "the feature version must precede CryptSetup, saw {before_sync:?}"
    );

    let sync = tcp::ServerSync::decode(sync_payload.as_slice()).expect("a well-formed ServerSync");
    let session = sync.session.expect("ServerSync carries the session id");
    (session, client.announced_fancy_version)
}

impl Client {
    /// The next `ChannelState` describing `channel`, or `None` within `within`.
    ///
    /// Skips everything else, for the reason [`Self::next_move_of`] does, and
    /// returns an `Option` because both answers are assertions here: a private
    /// room the invitee is told about, and the same room the uninvited are not.
    pub async fn next_channel_state(
        &mut self,
        channel: u32,
        within: Duration,
    ) -> Option<tcp::ChannelState> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let (type_id, payload) = self.next_frame(remaining).await?;
            if type_id != 7 {
                continue;
            }
            let state =
                tcp::ChannelState::decode(payload.as_slice()).expect("a well-formed ChannelState");
            if state.channel_id == Some(channel) {
                return Some(state);
            }
        }
    }

    /// Whether the server tells this client `channel` is gone, within `within`.
    pub async fn told_channel_gone(&mut self, channel: u32, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let Some((type_id, payload)) = self.next_frame(remaining).await else {
                return false;
            };
            if type_id != 6 {
                continue;
            }
            let gone = tcp::ChannelRemove::decode(payload.as_slice())
                .expect("a well-formed ChannelRemove");
            if gone.channel_id == channel {
                return true;
            }
        }
    }
}
