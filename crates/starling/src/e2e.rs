//! The one test that starts every service plus the gateway and speaks the
//! wire protocol from outside, the way a real client does.
//!
//! Every other test in the workspace exercises one crate. This is the only
//! place that proves the composition in `compose::all_in_one` actually wires
//! a client through the real handshake (`docs/PORTING-PLAN.md` §2.5,
//! `crates/services/session-lifecycle/src/handshake.rs`) end to end, over a
//! real TCP+TLS socket rather than an in-memory `Inbound`.
//!
//! TLS verification is disabled on the client, matching how every Mumble
//! client actually trusts a server: by fingerprint on first use, not by CA
//! chain (`crates/crypto/src/identity.rs`).

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
use starling_crypto::VoiceCipher as _;
use starling_crypto::ocb2::{Block, Ocb2};
use starling_proto::codec;
use starling_proto::proto::tcp;
use starling_proto::proto::udp;
use starling_runtime::config::Config;
use starling_runtime::inproc::Broker;
use starling_runtime::log::{Category, FieldValue, LogRuntime, LogSpec};
use starling_runtime::serve::{ServiceError, context};
use starling_runtime::shutdown::Shutdown;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The Mumble version Starling's own client half announces.
///
/// Encoded rather than written out, for the reason `handshake.rs` records about
/// the identical literal on the server side: `0x0001_0006_0000` is missing the
/// sixteen-bit patch shift and decodes to **0.1.6**, which is below every
/// feature gate the number exists to pass.
///
/// It was invisible here for exactly as long as nothing depended on it — the
/// handshake completes either way. The moment audio was wired up, this client
/// was handed the pre-1.5 legacy framing and then sent protobuf audio, and
/// every frame it spoke was dropped as malformed.
const MUMBLE_VERSION_V2: u64 = starling_proto::MUMBLE_VERSION.encode_v2();
/// How long to wait for a frame before deciding the wiring is broken.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for the live channel to report itself started.
///
/// Generous on purpose: see [`started`]. It bounds a whole deployment coming
/// up, not the delivery of a frame, and the two have no reason to share a
/// number.
const LIVE_START_TIMEOUT: Duration = Duration::from_secs(60);

/// Upstream `UDPTunnel`: audio over the control connection.
const UDP_TUNNEL: u16 = 1;
/// Target 0: everyone else in the speaker's channel.
const REGULAR_SPEECH: u32 = 0;
/// Target 31: the server echoes the frame back to the speaker alone.
const SERVER_LOOPBACK: u32 = 31;

/// How long to keep re-sending a frame before deciding audio does not route.
///
/// A real client transmits fifty frames a second, so re-sending is what one
/// actually does — and it is what makes this test insensitive to *when* voice's
/// membership subscription happens to warm, without pretending that a single
/// dropped frame at start-up is a failure.
const AUDIO_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one attempt waits before the frame is sent again.
const AUDIO_ATTEMPT: Duration = Duration::from_millis(250);

/// One deployment at a time, however many threads the test harness uses.
///
/// Each of these tests starts a **whole server** — twenty services, most of them
/// opening their own database pool — inside this one process. Three of those at
/// once do not fail because anything is wrong with them; they fail because sixty
/// services contending on start-up push `userdata` past the two-second window a
/// caller retries a cold dial for, and the first login is then refused for real.
///
/// Serialising them is not hiding a race. What these tests exercise is one
/// deployment answering a client, and running three servers in one process is a
/// property no deployment has. The alternative — raising every timeout until it
/// fits — would make a genuine startup regression invisible.
static ONE_AT_A_TIME: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Every service plus the gateway, over a real TCP port instead of a socket
/// nobody outside the process can dial.
struct Deployment {
    port: u16,
    /// Where voice is listening for audio, so a test can send it a datagram.
    voice_port: u16,
    shutdown: Shutdown,
    handles: Vec<JoinHandle<Result<(), ServiceError>>>,
    log: LogRuntime,
    /// Kept so a test can call a service's gRPC surface directly, for the
    /// set-up a client is not permitted to do for itself.
    resolver: starling_runtime::channel::Resolver,
    /// Released when this deployment is dropped, letting the next test start.
    _exclusive: tokio::sync::MutexGuard<'static, ()>,
}

impl Deployment {
    /// Start everything `--all-in-one` starts, bound to an ephemeral port.
    async fn start(data_dir: &Path) -> Self {
        Self::start_with(data_dir, |_| {}).await
    }

    /// The same, with the configuration adjusted first.
    ///
    /// Exists for the surfaces that are **off by default** and so are absent
    /// from a plain deployment: `operator-api` is one, and a test that wants it
    /// has to say so the way an operator does, by configuring it.
    async fn start_with(data_dir: &Path, adjust: impl FnOnce(&mut Config)) -> Self {
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
        // deployments fight over one port — two of these tests in parallel, or
        // one of them next to a server the developer happens to be running — and
        // the loser reports `Address already in use` and never starts. Ephemeral
        // and loopback-only, for the same reason the gateway's port above is.
        //
        // Reserved here rather than left as `:0` because a test that sends
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

        // A real log runtime rather than `Logger::null()`, so a deployment
        // under test exercises the same path a deployed one does — and so a
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
        for name in crate::units::names() {
            if !crate::compose::enabled(&config, name) {
                continue;
            }
            let ctx = context(
                name,
                Arc::clone(&config),
                broker.clone(),
                shutdown.clone(),
                logger.clone(),
            );
            if let Some(handle) = crate::units::spawn(name, ctx) {
                handles.push(handle);
            }
        }

        let gateway_ctx = context(
            "gateway",
            Arc::clone(&config),
            broker.clone(),
            shutdown.clone(),
            logger,
        );
        handles.push(
            crate::units::spawn("gateway", gateway_ctx).expect("\"gateway\" is a known unit"),
        );

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
        // is not the signal either — a service resolves its *own* endpoint
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
            _exclusive: exclusive,
        }
    }

    /// Create a channel, as an operator would.
    ///
    /// Through metadata's own gRPC rather than the client plane, because
    /// creating a channel takes `MakeChannel` and the default ACL deliberately
    /// withholds it — this is deployment set-up, not the behaviour under test.
    async fn create_channel(&self, name: &str) -> u32 {
        use starling_proto_fancy::metadata::metadata_client::MetadataClient;
        use starling_proto_fancy::metadata::{Channel, CreateRequest};

        // Retried, because this is the first thing to dial metadata and it does
        // so the instant the service is up. `wait_until_serving` cannot help:
        // it waits on a `unix:` socket file appearing, and this platform serves
        // over named pipes, so it skips every service and returns at once. A
        // pipe that is not accepting yet reports "all pipe instances are busy",
        // which is a race to wait out rather than a failure to report.
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
                            ..Channel::default()
                        }),
                        temporary: false,
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
    async fn set_acl(&self, acls: starling_proto_fancy::permissions::AclSet) {
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
    async fn add_temporary_group(&self, channel: u32, group: &str, session: u32) {
        let result = self.temporary_group(channel, group, session, true).await;
        assert!(result.applied, "refused: {}", result.refused);
    }

    /// The same, in either direction and without asserting the outcome.
    ///
    /// Returned rather than asserted because a *refusal* is the point of two of
    /// the tests below: naming a session that has gone must not be recorded.
    async fn temporary_group(
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

    /// The records this deployment has written so far.
    fn records(&self) -> Vec<starling_runtime::log::LogEvent> {
        self.log
            .recent()
            .map(|handle| handle.recent(1024))
            .unwrap_or_default()
    }

    /// Drain and abort every service this deployment started.
    fn stop(self) {
        self.shutdown.drain();
        for handle in self.handles {
            handle.abort();
        }
    }
}

/// Block until each of `services` has bound the endpoint it was configured with.
///
/// **Both local transports are waited on.** This used to look only for a
/// `unix:` path, which meant that on Windows — where every local endpoint is a
/// named pipe — it matched nothing, skipped every service, and returned
/// immediately. The wait was a no-op on that platform, so a client connected to
/// a deployment whose services had not finished binding and the handshake timed
/// out. It presented as intermittent, and as a transport fault rather than as
/// the missing wait it was.
///
/// A service reached over `http://` is left alone: it has no local artefact to
/// watch, and the deadline below is what catches a genuine hang.
async fn wait_until_serving(config: &Config, services: &[&str]) {
    let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
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
fn is_bound(endpoint: &str) -> bool {
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
/// Opened and dropped rather than enumerated. The pipe namespace *can* be
/// listed as a directory, but `local_endpoint` derives a pipe's name from a
/// filesystem path and so produces one containing `/`, which does not survive
/// being read back as a directory entry. Opening it is the question actually
/// being asked, and the accept loop creates each instance's replacement before
/// handing the connected one on (`transport/pipe.rs`), so this probe never
/// takes the instance a real caller is about to need.
#[cfg(windows)]
fn pipe_bound(name: &str) -> bool {
    tokio::net::windows::named_pipe::ClientOptions::new()
        .open(format!(r"\\.\pipe\{name}"))
        .is_ok()
}

/// Never reached: a pipe endpoint is rejected at startup off Windows.
#[cfg(not(windows))]
const fn pipe_bound(_name: &str) -> bool {
    true
}

/// Reserve a loopback port the gateway can bind next.
///
/// The listener is dropped immediately, so there is a race in principle; in
/// practice nothing else in this process binds a port between the two calls.
fn free_port() -> u16 {
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
fn free_udp_port() -> u16 {
    let socket = StdUdpSocket::bind(SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        .expect("an ephemeral port is always available");
    socket
        .local_addr()
        .expect("a bound socket has a local address")
        .port()
}

/// One frame of speech, as a 1.5-or-later client puts it on the wire.
fn audio_frame(target: u32, opus: &[u8]) -> Vec<u8> {
    // A leading 0 is the protobuf format's `Audio` discriminator.
    let mut out = vec![0_u8];
    let _ = udp::Audio {
        // `target` inbound. The server answers with `context`, which is a
        // different field of the same oneof — they are not interchangeable.
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
fn heard(payload: &[u8]) -> (u32, Vec<u8>) {
    assert_eq!(payload.first(), Some(&0), "not an audio packet");
    let audio = udp::Audio::decode(&payload[1..]).expect("a well-formed audio frame");
    (audio.sender_session, audio.opus_data)
}

/// A throwaway directory, removed when the test drops it.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "starling-e2e-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the temp data dir");
        Self(path)
    }

    fn path(&self) -> &Path {
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
/// point rather than by chain validation.
#[derive(Debug)]
struct TrustAnyCertificate;

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
/// failure — retry until the deadline rather than requiring the caller to
/// know how long that takes.
async fn connect_with_retry(port: u16) -> TcpStream {
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

/// A raw Mumble client: frames in, frames out, no generated stubs — the same
/// view of the wire the gateway itself has (`docs/ARCHITECTURE.md` §1).
struct Client {
    stream: TlsStream<TcpStream>,
    buffer: BytesMut,
    /// The `CryptSetup` the server minted for this connection.
    ///
    /// Kept as it goes past rather than fished out afterwards: it arrives in the
    /// middle of the handshake flood, and it is the only thing that makes a
    /// datagram from this client decryptable by the server.
    crypt_setup: Option<tcp::CryptSetup>,
}

impl Client {
    async fn connect(port: u16) -> Self {
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
        }
    }

    async fn send(&mut self, type_id: u16, message: &impl prost::Message) {
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
    async fn send_raw(&mut self, type_id: u16, payload: &[u8]) {
        let frame = codec::frame(type_id, payload);
        self.stream
            .write_all(&frame)
            .await
            .expect("the connection is still open");
    }

    /// The next complete frame, waiting for more bytes as needed.
    async fn recv(&mut self) -> (u16, Vec<u8>) {
        self.next_frame(FRAME_TIMEOUT)
            .await
            .expect("a frame arrives within the timeout")
    }

    /// The next complete frame, or `None` if `within` elapses first.
    ///
    /// The fallible half of [`Self::recv`], for the callers that are *waiting*
    /// for something rather than asserting on what comes next: a client that
    /// keeps talking has to be able to try again, and a panic is not a retry.
    async fn next_frame(&mut self, within: Duration) -> Option<(u16, Vec<u8>)> {
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
    /// connection stays open — right for every test that expects to keep
    /// talking, and useless for the one asserting the server rings off.
    ///
    /// Anything still arriving is consumed and discarded: a refusal is
    /// followed by a close, but the close is the assertion, not what happens
    /// to be in flight ahead of it.
    async fn closed_by_server(&mut self, within: Duration) -> bool {
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

    /// This connection's half of the voice cipher.
    ///
    /// OCB2, because this client announces no Fancy version — the same cipher
    /// every stock Mumble client is given.
    ///
    /// Note the crossover: the client sends under the *client* nonce and expects
    /// the *server's*, which is the mirror of what the server built from the
    /// same three fields. Getting it backwards makes every packet fail its tag,
    /// in both directions, and looks exactly like silence.
    fn voice_cipher(&self) -> Ocb2 {
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
    async fn next_move_of(&mut self, session: u32) -> tcp::UserState {
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
    async fn next_state_of(
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
    async fn next_audio(&mut self, within: Duration) -> Option<Vec<u8>> {
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
    async fn next_channel_of(&mut self, session: u32) -> u32 {
        self.next_move_of(session)
            .await
            .channel_id
            .expect("next_move_of yields only a state that carries one")
    }

    /// Hang up, and wait for the server to notice.
    ///
    /// Closing the socket is not the same as the server having processed the
    /// disconnect, and a test that depends on the *consequences* of a departure
    /// — a session id returning to the pool, a session-scoped grant being
    /// dropped — has to wait for the second thing, not the first.
    async fn close(mut self) {
        let _ = self.stream.shutdown().await;
        drop(self);
        // Short: the gateway reports a closed connection as soon as its reader
        // sees EOF, and everything downstream of that is in-process.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    /// The server's answer to a channel-switch request: the move, or the refusal.
    ///
    /// Both are legitimate answers and a test asserting one has to be able to
    /// see the other — a locked channel that quietly moves nobody and a locked
    /// channel that says so are the same timeout otherwise.
    /// Ask to enter `channel`, and wait for the server's answer.
    ///
    /// The pair is always used together — a bare `UserState` with no answer
    /// read proves nothing, and reading an answer nobody asked for hangs — so
    /// they are one call. `why` names the step, because a timeout here is
    /// otherwise an unattributed ten seconds in a test with several of them.
    async fn enter(
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

    async fn next_entry_answer(&mut self, session: u32) -> Result<u32, tcp::PermissionDenied> {
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
    async fn recv_until(&mut self, target: u16) -> (Vec<u16>, Vec<u8>) {
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
/// Order asserted here is `PORTING-PLAN.md` §2.5's murmur-derived contract:
/// server `Version` first, then `CryptSetup`/`CodecVersion`/`ChannelState`/
/// `UserState` in any relative order but all before `ServerSync`, then
/// `ServerConfig` immediately, then `SuggestConfig`.
async fn handshake(client: &mut Client, username: &str) -> u32 {
    handshake_with_tokens(client, username, Vec::new()).await
}

/// The same handshake, presenting access tokens.
///
/// `Authenticate` is the only message that carries them, and a client sends the
/// ones it has stored for this server at login — which is how a channel
/// password the user saved once opens the channel on every later connection.
async fn handshake_with_tokens(client: &mut Client, username: &str, tokens: Vec<String>) -> u32 {
    let (greeting_type, greeting_payload) = client.recv().await;
    assert_eq!(
        greeting_type, 0,
        "the server must speak Version first, unprompted"
    );
    let greeting =
        tcp::Version::decode(greeting_payload.as_slice()).expect("a well-formed Version");
    assert!(greeting.version_v2.is_some());

    client
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                ..tcp::Version::default()
            },
        )
        .await;
    client
        .send(
            2,
            &tcp::Authenticate {
                username: Some(username.to_owned()),
                tokens,
                ..tcp::Authenticate::default()
            },
        )
        .await;

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

#[tokio::test]
async fn two_clients_complete_the_handshake_and_exchange_text() {
    let data_dir = TempDir::new("text");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;

    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    assert_ne!(alice_session, bob_session);

    alice
        .send(
            11,
            &tcp::TextMessage {
                actor: Some(alice_session),
                channel_id: vec![0],
                message: "hello from alice".to_owned(),
                ..tcp::TextMessage::default()
            },
        )
        .await;

    // Not `recv`: the handshake is followed by a pushed `PermissionQuery` for
    // the channel the client landed in, as murmur sends one on every entry
    // (`Server.cpp:2319`). It is a server-initiated frame with no request
    // behind it, so it can be the first thing waiting here — asserting on the
    // *next* frame made this test fail for a message it was not about.
    let (before_text, bob_payload) = bob.recv_until(11).await;
    assert!(
        before_text.iter().all(|&kind| kind == 20),
        "only the pushed PermissionQuery may precede alice's text, saw {before_text:?}"
    );
    let received =
        tcp::TextMessage::decode(bob_payload.as_slice()).expect("a well-formed TextMessage");
    assert_eq!(received.message, "hello from alice");
    assert_eq!(received.actor, Some(alice_session));

    // Mumble never echoes a message back to its own sender. Alice may still
    // see bob's join broadcast (UserState, 9) land before her pong — that is
    // a real, unrelated notification racing the reply, not an echo — so scan
    // past anything but a TextMessage rather than requiring the very next
    // frame to be the pong.
    alice
        .send(
            3,
            &tcp::Ping {
                timestamp: Some(7),
                ..tcp::Ping::default()
            },
        )
        .await;
    let (before_pong, alice_payload) = alice.recv_until(3).await;
    assert!(
        !before_pong.contains(&11),
        "alice's text message must not echo back to her"
    );
    let pong = tcp::Ping::decode(alice_payload.as_slice()).expect("a well-formed Ping");
    assert_eq!(pong.timestamp, Some(7));

    deployment.stop();
}

#[tokio::test]
async fn one_client_is_heard_by_another_over_the_tunnel() {
    // Audio over TCP: what a client behind a UDP-blocking firewall depends on,
    // and the path *every* connection uses until one of its datagrams
    // authenticates. Asserted end to end because nothing else can: the routing
    // core is covered by unit tests, but whether the gateway hands type 1 to
    // voice, whether voice's membership subscription warms in a real
    // deployment, and whether the fan-out reaches another socket are all
    // properties of the wiring rather than of the router.
    let data_dir = TempDir::new("tunnel-audio");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    // Re-sent until it lands, as a real client transmitting fifty frames a
    // second effectively does. Voice subscribes to `session-view` on start-up
    // and retries a second later if that service was not up yet, so *when* the
    // first routable frame is accepted is a start-up race — and one dropped
    // frame at start-up is not the failure this test is looking for.
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let received = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"hello"))
            .await;

        if let Some(payload) = bob.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };

    let payload = received.expect("bob never heard alice");
    let (speaker, opus) = heard(&payload);
    assert_eq!(opus, b"hello", "the audio was altered on the way through");
    assert_eq!(
        speaker, alice_session,
        "the listener must be told who spoke, or nobody's talking indicator works"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_datagram_on_the_voice_port_is_relayed_to_the_channel() {
    // Audio over UDP, which is how every client that can reach the port sends
    // it. Three separate things have to hold and none is visible from a unit
    // test: the socket is bound where the deployment said, a datagram is
    // *attributed* to a session by decrypting under that session's key, and the
    // frame is re-encoded for a listener on a different transport.
    //
    // Bob is tunnelled — he has sent no datagram, so the server has no proven
    // address for him — which makes this the mixed case a real server is in
    // constantly: UDP in, TCP out.
    let data_dir = TempDir::new("udp-audio");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    let mut cipher = alice.voice_cipher();
    let voice = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), deployment.voice_port));
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port is always available");

    // The connectivity probe a real client sends before trusting UDP with
    // anything: the server echoes target 31 back to the speaker alone. It also
    // proves the return direction, which nothing else here does — bob receives
    // over TCP.
    let echo = loop_back(&socket, voice, &mut cipher).await;
    assert_eq!(echo, b"probe", "voice did not echo the loopback target");

    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let received = loop {
        let sealed = cipher
            .seal(&audio_frame(REGULAR_SPEECH, b"over udp"), &[])
            .expect("the client seals its own audio");
        let _ = socket.send_to(&sealed, voice).await;

        if let Some(payload) = bob.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };

    let payload = received.expect("a datagram from alice never reached bob");
    let (speaker, opus) = heard(&payload);
    assert_eq!(opus, b"over udp");
    assert_eq!(speaker, alice_session);

    deployment.stop();
}

#[tokio::test]
async fn a_client_whose_nonce_drifted_asks_for_a_resync_and_is_answered() {
    // `CryptSetup`(15) inbound, which is the whole of the recovery a Mumble
    // client has when its UDP cipher falls out of step. It asks once every five
    // seconds while its audio is failing (`ServerHandler::message`) and does
    // nothing else: it does not reconnect and it does not fall back to the
    // tunnel. Unanswered, the client is deaf for the rest of its session with
    // every counter at both ends looking healthy.
    //
    // Driven end to end because the failure this covers is entirely in the
    // wiring. The classifier and the cipher's two halves are unit-tested; what
    // nothing below this level can show is whether the gateway hands type 15 to
    // session-lifecycle, whether that service asks voice, and whether what comes
    // back is a message this client can act on.
    let data_dir = TempDir::new("crypt-resync");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;

    let mut cipher = alice.voice_cipher();
    let voice = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), deployment.voice_port));
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port is always available");

    // A working UDP path first, or the rest of this proves nothing: a client
    // that was never able to hear the server cannot demonstrate recovering.
    assert_eq!(
        loop_back(&socket, voice, &mut cipher).await,
        b"probe",
        "voice did not echo the loopback target"
    );

    // Now break exactly what packet loss breaks — this client's idea of where
    // the server's counter has got to. Its *sending* half is untouched, which is
    // what makes this the real failure rather than a dead connection: the server
    // still hears alice perfectly while alice hears nothing.
    cipher.resync_to(Block([0xAB; 16]));
    assert!(
        try_loop_back(&socket, voice, &mut cipher).await.is_none(),
        "the client should now be unable to open the server's echo"
    );

    // The request, byte for byte what a Mumble client sends: a `CryptSetup` with
    // nothing in it. The absence of `client_nonce` is the entire message.
    alice.send(15, &tcp::CryptSetup::default()).await;
    let (_, payload) = alice.recv_until(15).await;
    let answer = tcp::CryptSetup::decode(payload.as_slice()).expect("a well-formed CryptSetup");

    assert_eq!(
        answer.key, None,
        "a key here reads as a whole new session to a client that asked only where the counter was"
    );
    assert_eq!(answer.client_nonce, None);
    let nonce = answer
        .server_nonce
        .expect("the answer is the nonce the server seals under");
    assert_eq!(nonce.len(), 16, "an AES block, which is what OCB2 installs");

    // And it is usable. This is the assertion the whole test exists for: an
    // answer the client cannot act on is indistinguishable from no answer.
    assert!(cipher.adopt_recv_nonce(&nonce));
    assert_eq!(
        loop_back(&socket, voice, &mut cipher).await,
        b"probe",
        "the resync was answered and the client is still deaf"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_refused_login_is_told_why_and_then_hung_up_on() {
    // The reported bug, both halves of it.
    //
    // Starling sent the `Reject` and left the socket open. murmur sends it and
    // calls `disconnectSocket()` immediately (`Messages.cpp:568`). What the
    // difference looked like to a user: "Server connection rejected: Wrong
    // certificate or password", then a client still sitting there rendering
    // the root channel, still pinging, still switching to TCP when its UDP
    // probe failed thirty seconds later. A session that is half present —
    // no audio, no roster, nothing it can do, and no disconnect either.
    //
    // The idle sweep never rescued it: a connection that keeps pinging is
    // never timed out, so the refused peer held its slot for as long as it
    // felt like.
    let data_dir = TempDir::new("refused-login");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut client = Client::connect(deployment.port).await;
    let (greeting, _) = client.recv().await;
    assert_eq!(greeting, 0, "the server speaks Version first");
    client
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                ..tcp::Version::default()
            },
        )
        .await;

    // SuperUser is registered on every deployment and has a password, so
    // getting it wrong is a refusal that needs no set-up to arrange — and it
    // is exactly the refusal in the report.
    client
        .send(
            2,
            &tcp::Authenticate {
                username: Some("SuperUser".to_owned()),
                password: Some("not-the-password".to_owned()),
                ..tcp::Authenticate::default()
            },
        )
        .await;

    let (_, payload) = client.recv_until(4).await;
    let refusal = tcp::Reject::decode(payload.as_slice()).expect("a well-formed Reject");
    assert_eq!(
        refusal.r#type,
        Some(tcp::reject::RejectType::WrongUserPw as i32),
        "the client renders this as the reason; a generic refusal sends the user hunting"
    );

    // The half that was missing. Generous, because it must not be a race:
    // the gateway flushes the queued `Reject` before closing, and this is
    // asserting the close still arrives promptly afterwards.
    assert!(
        client.closed_by_server(Duration::from_secs(5)).await,
        "the server refused the login and left the connection open; the client stays half \
         connected, keeps pinging, and is never reaped"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_self_muted_speaker_stops_being_relayed() {
    // Mute has to reach the *packet path*, not just the user list. A server that
    // renders alice as muted while still forwarding her audio is the worst
    // version of this bug: every client's UI says she is not being heard.
    //
    // Driven end to end because the enforcement and the fact are three services
    // apart — session-lifecycle records the flag, session-view publishes it, and
    // voice reads it off a subscription — and each of the three can be right on
    // its own while the chain does nothing.
    let data_dir = TempDir::new("self-mute");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    // Audible first, or a silent second half proves nothing: a test that only
    // checks bob hears nothing after the mute passes on a server that never
    // routed anything at all.
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let heard_before = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"before"))
            .await;
        if bob.next_audio(AUDIO_ATTEMPT).await.is_some() {
            break true;
        }
        if tokio::time::Instant::now() >= deadline {
            break false;
        }
    };
    assert!(
        heard_before,
        "bob never heard alice, so the mute proves nothing"
    );

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                self_mute: Some(true),
                ..tcp::UserState::default()
            },
        )
        .await;
    // The echo every client is sent, which is also the point the server has
    // finished applying it. Waiting on a timer instead would race the
    // announcement to session-view and voice's subscription behind it.
    let muted = bob
        .next_state_of(alice_session, |state| state.self_mute)
        .await;
    assert_eq!(muted.self_mute, Some(true));

    // Anything still in flight lands, then a clean window.
    let _ = bob.next_audio(AUDIO_ATTEMPT).await;
    for _ in 0..10 {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"after"))
            .await;
    }
    assert!(
        bob.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "a self-muted speaker was still relayed; mute is in the user list and not on the packet path"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_whisper_reaches_the_person_it_names_and_not_the_room() {
    // `VoiceTarget`(19), which is what fills in one of the thirty slots Mumble's
    // five-bit target field addresses. Without it a client can register a
    // whisper, see no error, press the key, and reach nobody — the routing core
    // resolves slots correctly and no slot was ever filled.
    //
    // Bob is the control. He shares alice's channel, so nothing but the target
    // itself can keep him out of a frame she sends; carol is named personally,
    // so nothing but the target can carry one to her.
    let data_dir = TempDir::new("whisper");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;
    let mut carol = Client::connect(deployment.port).await;
    let carol_session = handshake(&mut carol, "carol").await;

    // Slot 3 means "carol", and nothing else. Whispering takes `Whisper` in the
    // target's channel, which the default ACL grants — so this is the ordinary
    // case rather than one propped up by an ACL the test installed.
    alice
        .send(
            19,
            &tcp::VoiceTarget {
                id: Some(3),
                targets: vec![tcp::voice_target::Target {
                    session: vec![carol_session],
                    ..tcp::voice_target::Target::default()
                }],
            },
        )
        .await;

    // Re-sent until it lands, as a real client transmitting fifty frames a
    // second effectively does: the registration and the first frame travel on
    // one connection but are handled by a service that awaits a permission check
    // between them, so *which* frame is the first routable one is a race and not
    // the behaviour under test.
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let received = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(3, b"only for carol"))
            .await;
        if let Some(payload) = carol.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };

    let payload = received.expect("carol never heard the whisper aimed at her");
    let audio = udp::Audio::decode(&payload[1..]).expect("a well-formed audio frame");
    assert_eq!(audio.opus_data, b"only for carol");
    assert_eq!(
        audio.header,
        Some(udp::audio::Header::Context(2)),
        "somebody named personally must be told it is a whisper, not a shout"
    );

    // The other half, and the one that matters for privacy: bob is in the same
    // channel and was not named, so a whisper that reached him would be a
    // private conversation leaking into the room it was aimed away from.
    assert!(
        bob.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "a whisper reached somebody it did not name"
    );

    deployment.stop();
}

/// Send a loopback frame until the server echoes it, and return what came back.
///
/// Also what binds this client's address server-side: an address is only
/// believed once a packet from it has authenticated, so until this succeeds the
/// server has no UDP path for this peer at all.
/// One loopback attempt, tolerating a reply this client cannot open.
///
/// The fallible half of [`loop_back`], for the one caller that is *asserting*
/// the client has gone deaf. `loop_back` panics on a reply it cannot decrypt,
/// which is right for every other use and useless for proving a cipher is out
/// of step.
///
/// Deliberately short: a negative assertion should not cost fifteen seconds, and
/// a client whose nonce has drifted fails on the first packet rather than the
/// fiftieth.
async fn try_loop_back(
    socket: &UdpSocket,
    voice: SocketAddr,
    cipher: &mut Ocb2,
) -> Option<Vec<u8>> {
    let mut scratch = [0_u8; 2048];
    let sealed = cipher
        .seal(&audio_frame(SERVER_LOOPBACK, b"probe"), &[])
        .expect("the client seals its own audio");
    let _ = socket.send_to(&sealed, voice).await;

    let (read, _) = timeout(AUDIO_ATTEMPT, socket.recv_from(&mut scratch))
        .await
        .ok()?
        .ok()?;
    let plain = cipher.open(&scratch[..read], &[]).ok()?;
    Some(heard(&plain).1)
}

async fn loop_back(socket: &UdpSocket, voice: SocketAddr, cipher: &mut Ocb2) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let mut scratch = [0_u8; 2048];
    loop {
        let sealed = cipher
            .seal(&audio_frame(SERVER_LOOPBACK, b"probe"), &[])
            .expect("the client seals its own audio");
        let _ = socket.send_to(&sealed, voice).await;

        if let Ok(Ok((read, _))) = timeout(AUDIO_ATTEMPT, socket.recv_from(&mut scratch)).await {
            let plain = cipher
                .open(&scratch[..read], &[])
                .expect("the echo is sealed under this session's key");
            return heard(&plain).1;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "voice never answered on its UDP port"
        );
    }
}

#[tokio::test]
async fn a_client_can_switch_channels_and_everyone_is_told() {
    // Reported as "I can't switch channels". The request is a `UserState`
    // carrying `channel_id`, and nothing read that field — so the server parsed
    // it, ignored it, and replied with the self-mute echo, which looks like a
    // successful answer and moves nobody.
    //
    // Asserted from *both* clients on purpose: a client builds its user tree
    // from these broadcasts, so a move only the mover hears about leaves the
    // same person rendered in two channels everywhere else.
    let data_dir = TempDir::new("switch");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Testing").await;
    assert_ne!(target, 0, "the new channel must not be the root");

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;

    // Both are told, and both are told the same thing.
    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let moved = timeout(FRAME_TIMEOUT, client.next_channel_of(alice_session)).await;
        assert_eq!(
            moved.ok(),
            Some(target),
            "{who} was never told alice moved to {target}"
        );
    }

    deployment.stop();
}

#[tokio::test]
async fn an_operator_can_moderate_a_live_session_from_outside() {
    // murmur's `setState`, which Starling had no equivalent of at all: every
    // moderation path went through a Mumble client holding a connection, so an
    // external bot could watch somebody misbehave and do nothing about them.
    //
    // Driven over gRPC and asserted on the *socket*, because the two halves fail
    // separately — a change that lands in the connection table and is never
    // broadcast leaves every other client rendering the old state, which is the
    // same class of bug as the missing `actor` above.
    use starling_proto_fancy::sessioncontrol::SetStateRequest;
    use starling_proto_fancy::sessioncontrol::session_control_client::SessionControlClient;

    let data_dir = TempDir::new("operator-moderation");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Naughty Step").await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    let transport = deployment
        .resolver
        .channel("session-lifecycle")
        .expect("session-lifecycle resolves");
    let applied = SessionControlClient::new(transport)
        .set_state(SetStateRequest {
            scope: None,
            actor: None,
            session: alice_session,
            channel: Some(target),
            // Deafen without muting, to prove the coupling is applied on this
            // path too: murmur's deafen implies mute, and an operator told only
            // what they asked for would render a user deaf but not muted.
            deaf: Some(true),
            ..SetStateRequest::default()
        })
        .await
        .expect("the operator plane answers")
        .into_inner();

    assert!(applied.applied, "refused: {}", applied.refused);
    assert_eq!(applied.channel, target, "the move was not applied");
    assert!(applied.deaf, "the deafen was not applied");
    assert!(applied.mute, "deafening must imply muting, as it does in murmur");

    // And everyone is told — the mover included. Asserted from bob as well
    // because a client builds its user list from these: a moderation action only
    // the subject hears about leaves everybody else rendering them unmuted and
    // in the wrong channel.
    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let moved = timeout(FRAME_TIMEOUT, client.next_move_of(alice_session))
            .await
            .unwrap_or_else(|_| panic!("{who} was never told alice was moved"));
        assert_eq!(moved.channel_id, Some(target), "{who} saw the wrong channel");
        assert_eq!(moved.deaf, Some(true), "{who} was not told alice is deaf");
    }

    deployment.stop();
}

#[tokio::test]
async fn a_move_names_who_made_it_and_not_the_server() {
    // Reported as the client logging "You were moved to X by the server." for an
    // ordinary channel click, where murmur produces "You joined X."
    //
    // The difference is one field. `actor` names who caused the change, murmur
    // sets it on every `UserState` it rebroadcasts
    // (`vendor/server/src/murmur/Messages.cpp:1052`), and Starling set it on
    // none — so a client had nobody to attribute the move to and fell back to
    // blaming the server. Every voluntary move then read as an administrator
    // dragging the user around, which is alarming rather than merely wrong.
    let data_dir = TempDir::new("attribution");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Beginner Lobby").await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;

    // Asserted from both clients: alice needs the attribution to know she moved
    // herself, and bob needs it to render who moved whom. A server that set it
    // only in the echo to the mover would leave everyone else with the same
    // "by the server" line about somebody who walked in on their own.
    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let moved = timeout(FRAME_TIMEOUT, client.next_move_of(alice_session))
            .await
            .unwrap_or_else(|_| panic!("{who} was never told alice moved"));
        assert_eq!(
            moved.channel_id,
            Some(target),
            "{who} saw the wrong channel"
        );
        assert_eq!(
            moved.actor,
            Some(alice_session),
            "{who} was not told who moved alice, and an unset actor reads as the server"
        );
    }

    deployment.stop();
}

/// An ACL entry addressing `group`, applying here and to everything below.
fn entry(
    group: &str,
    grant: starling_proto_fancy::perm::Perm,
    deny: starling_proto_fancy::perm::Perm,
) -> starling_proto_fancy::permissions::AclEntry {
    starling_proto_fancy::permissions::AclEntry {
        apply_here: true,
        apply_subs: true,
        group: Some(group.to_owned()),
        grant: grant.bits(),
        deny: deny.bits(),
        ..starling_proto_fancy::permissions::AclEntry::default()
    }
}

#[tokio::test]
async fn a_client_holding_write_can_save_an_acl_table_and_read_it_back() {
    // `docs/GAP-ANALYSIS.md` G1, end to end and from outside. The ACL editor in
    // every Mumble client is built on this one message: `ACL`(13) with `query`
    // unset is a save. Starling refused every one of them for everybody,
    // including the SuperUser, and said nothing — so a role was created in the
    // editor, appeared to stick, and was gone on the next read.
    //
    // Asserted through a *second* read rather than only through the reply,
    // because the reply is generated on the write path: a handler that echoed
    // its input without storing it would satisfy the first assertion and fail
    // the users of this feature in exactly the way it already had.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("acl-write");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Moderated").await;

    // What an operator does once so the editor is usable at all. Reading an ACL
    // takes `Write` too, so without this the client cannot even open the dialog.
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("all", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;

    let submitted = tcp::Acl {
        channel_id: target,
        inherit_acls: Some(true),
        query: Some(false),
        groups: vec![tcp::acl::ChanGroup {
            name: "moderators".to_owned(),
            add: vec![4],
            ..tcp::acl::ChanGroup::default()
        }],
        acls: vec![tcp::acl::ChanAcl {
            apply_here: Some(true),
            apply_subs: Some(true),
            group: Some("moderators".to_owned()),
            grant: Some(Perm::MUTE_DEAFEN.bits()),
            ..tcp::acl::ChanAcl::default()
        }],
    };
    alice.send(13, &submitted).await;

    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(13))
        .await
        .expect("the save was never answered");
    let saved = tcp::Acl::decode(payload.as_slice()).expect("a well-formed ACL");
    assert_eq!(saved.channel_id, target);
    assert_eq!(saved.acls.len(), 1, "the entry was not kept: {saved:?}");
    assert_eq!(saved.acls[0].grant, Some(Perm::MUTE_DEAFEN.bits()));
    assert_eq!(saved.groups.len(), 1);
    assert_eq!(saved.groups[0].name, "moderators");

    // The read the editor performs when it is next opened. This is the one that
    // used to come back empty.
    alice
        .send(
            13,
            &tcp::Acl {
                channel_id: target,
                query: Some(true),
                ..tcp::Acl::default()
            },
        )
        .await;
    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(13))
        .await
        .expect("the read was never answered");
    let reread = tcp::Acl::decode(payload.as_slice()).expect("a well-formed ACL");
    assert_eq!(
        reread.acls.len(),
        1,
        "the saved table did not survive to the next read: {reread:?}"
    );
    assert_eq!(reread.groups[0].add, vec![4]);

    deployment.stop();
}

#[tokio::test]
async fn a_channel_password_admits_whoever_presents_it_and_nobody_else() {
    // G2 and G3 together, which is how a user meets them: a channel password is
    // an `Enter` denied to `all` and granted back to `#token`, and it needs the
    // grammar to parse `#hunter2` as a token *and* the token itself to reach the
    // evaluator. Either half missing leaves the same symptom — a channel nobody
    // can enter, including the people who were given the password.
    //
    // Both ways a client can present one are covered, because they are different
    // paths: stored and sent at login, and typed into the dialog and sent with
    // the request it authorises.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("acl-token");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Private").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                // Deny first and grant second is not the reason this works —
                // deny wins at the same level regardless of order. What admits
                // the holder is that the second entry does not match anybody
                // else at all.
                entry("#hunter2", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session =
        handshake_with_tokens(&mut alice, "alice", vec!["hunter2".to_owned()]).await;
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;
    let admitted = timeout(FRAME_TIMEOUT, alice.next_entry_answer(alice_session))
        .await
        .expect("alice was never answered");
    assert_eq!(
        admitted,
        Ok(target),
        "the token presented at login must open the channel"
    );

    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    bob.send(
        9,
        &tcp::UserState {
            session: Some(bob_session),
            channel_id: Some(target),
            ..tcp::UserState::default()
        },
    )
    .await;
    let refusal = timeout(FRAME_TIMEOUT, bob.next_entry_answer(bob_session))
        .await
        .expect("bob was never answered");
    let refusal = refusal.expect_err("a channel with no token must not admit bob");
    assert_eq!(refusal.channel_id, Some(target));
    assert_eq!(refusal.permission, Some(Perm::ENTER.bits()));

    // Now bob types the password into the dialog. The client sends it *with*
    // the request rather than storing it, and it must authorise this entry and
    // leave nothing behind.
    bob.send(
        9,
        &tcp::UserState {
            session: Some(bob_session),
            channel_id: Some(target),
            temporary_access_tokens: vec!["HUNTER2".to_owned()],
            ..tcp::UserState::default()
        },
    )
    .await;
    let admitted = timeout(FRAME_TIMEOUT, bob.next_entry_answer(bob_session))
        .await
        .expect("bob was never answered the second time");
    assert_eq!(
        admitted,
        Ok(target),
        "a token sent with the request must open the channel, in any case"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_second_authenticate_replaces_the_access_tokens_without_a_second_login() {
    // How a stock Mumble client actually submits a password it has just been
    // given: it re-sends `Authenticate` on the same connection with its whole
    // token list (`vendor/server/src/murmur/Messages.cpp:367`). Starling read
    // that as a fresh login, which would allocate a second session for one
    // connection and announce the same user twice.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("acl-retoken");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Private").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("#hunter2", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;

    alice
        .send(
            2,
            &tcp::Authenticate {
                username: Some("alice".to_owned()),
                tokens: vec!["hunter2".to_owned()],
                ..tcp::Authenticate::default()
            },
        )
        .await;

    // The edit is acknowledged with a fresh `PermissionQuery`, which is also
    // what tells the client its menus have changed.
    let (_, _) = timeout(FRAME_TIMEOUT, alice.recv_until(20))
        .await
        .expect("the token edit was never acknowledged");

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;
    let admitted = timeout(FRAME_TIMEOUT, alice.next_entry_answer(alice_session))
        .await
        .expect("alice was never answered");
    assert_eq!(
        admitted,
        Ok(target),
        "a token added mid-session must take effect"
    );

    // And she is still one user. A second `Authenticate` read as a login would
    // have allocated another session and announced her again.
    assert_eq!(
        deployment
            .records()
            .iter()
            .filter(|event| event.message == "user authenticated")
            .count(),
        1,
        "a token edit must not log in a second time"
    );

    deployment.stop();
}

#[tokio::test]
async fn an_external_authority_can_admit_a_guest_to_a_group_gated_channel() {
    // Temporary group membership, end to end, and the case it exists for.
    //
    // A channel gated on a named group is shut to every unregistered visitor
    // and cannot be opened to one by editing the ACL table: membership is
    // recorded by *account* id, and a guest has no account — they go on the
    // wire as account 0, which is the SuperUser's. A session-scoped grant is
    // the only mechanism upstream has for it (`Group.cpp:242`, reading
    // `qsTemporary` for `-session`), and it is what an external authenticator
    // uses to map something the server cannot know — a game lobby, a rota —
    // onto somebody who never registered.
    //
    // Asserted from outside because every part of this is wiring: the grant is
    // made over gRPC, the subject is resolved through `session-view`, and the
    // answer comes back as a `UserState` or a `PermissionDenied` on a socket.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("temp-groups");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("VIP").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("vip", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;

    // Shut, as it is to everybody, before the grant.
    let refusal = alice
        .enter(alice_session, target, "alice was never answered")
        .await
        .expect_err("a channel gated on a group must not admit a guest");
    assert_eq!(refusal.permission, Some(Perm::ENTER.bits()));

    deployment
        .add_temporary_group(target, "vip", alice_session)
        .await;

    let admitted = alice
        .enter(
            alice_session,
            target,
            "alice was never answered after the grant",
        )
        .await;
    assert_eq!(
        admitted,
        Ok(target),
        "a session-scoped grant must admit an unregistered user"
    );

    // Revoked, and the door shuts again. Asserted here rather than in its own
    // test because it needs a subject already inside the group, and because a
    // grant that cannot be taken back is the more dangerous half of the pair.
    assert!(
        deployment
            .temporary_group(target, "vip", alice_session, false)
            .await
            .applied
    );
    let _ = alice
        .enter(alice_session, 0, "alice was never moved back to the root")
        .await;
    let after_revoke = alice
        .enter(
            alice_session,
            target,
            "alice was never answered after the revocation",
        )
        .await;
    assert!(
        after_revoke.is_err(),
        "a revoked membership must stop admitting"
    );

    // And it belongs to that session alone. Bob is the same kind of visitor and
    // was granted nothing.
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    let refusal = bob
        .enter(bob_session, target, "bob was never answered")
        .await
        .expect_err("the grant must not admit anybody else");
    assert_eq!(refusal.channel_id, Some(target));

    deployment.stop();
}

#[tokio::test]
async fn a_session_scoped_grant_does_not_pass_to_the_next_holder_of_that_session() {
    // The hazard that makes clearing this on disconnect a requirement rather
    // than tidiness: session ids are pooled and reissued — murmur re-queues
    // them at `Server.cpp:1904` and Starling's allocator does the same — so a
    // grant that outlived its holder would silently admit whoever is handed
    // that id next.
    //
    // Driven by connecting, granting, disconnecting, and connecting again until
    // the same id comes back round, because asserting on the id directly is the
    // only way to know the reuse actually happened.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("temp-groups-reuse");
    // A pool of exactly one id, so the reuse this is about happens on the very
    // next connection instead of after two hundred. The pool is `max_users * 2`
    // and FIFO — sized and ordered to *delay* reuse, which is the right default
    // and the reason a test cannot wait for it.
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        if let Some(service) = config.services.get_mut("session-lifecycle") {
            let _ = service
                .options
                .insert("max_users".to_owned(), "1".to_owned());
        }
    })
    .await;
    let target = deployment.create_channel("VIP").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("vip", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let granted_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(target, "vip", granted_session)
        .await;
    alice.close().await;

    // Granting to an id that has already gone is refused, which is murmur's
    // rule (`InvalidSessionException`, and the reason this test exists at all):
    // a departure is what clears these grants, so one made *after* the
    // departure has missed its only cleanup and would wait in the table for
    // whoever is issued that id next.
    let refused = deployment
        .temporary_group(target, "vip", granted_session, true)
        .await;
    assert!(
        !refused.applied,
        "a grant naming a departed session must be refused, not recorded"
    );

    let mut mallory = Client::connect(deployment.port).await;
    let reissued = handshake(&mut mallory, "mallory").await;
    assert_eq!(
        reissued, granted_session,
        "the pool was meant to hand the same id straight back, so nothing is being proven"
    );

    mallory
        .send(
            9,
            &tcp::UserState {
                session: Some(granted_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;
    let answer = timeout(FRAME_TIMEOUT, mallory.next_entry_answer(granted_session))
        .await
        .expect("mallory was never answered");
    assert!(
        answer.is_err(),
        "the new holder of session {granted_session} inherited a stranger's group membership"
    );

    deployment.stop();
}

#[tokio::test]
async fn the_same_name_twice_replaces_the_first_rather_than_joining_it() {
    // Reported from a live deployment: the same user connected three times and
    // the server held three sessions, so every client rendered three copies of
    // one person. murmur never allows that (`Messages.cpp:418`) — the second
    // connection is the same user coming back from the same address, so it is
    // admitted and the first is disconnected as a ghost.
    let data_dir = TempDir::new("dupe");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut first = Client::connect(deployment.port).await;
    let first_session = handshake(&mut first, "alice").await;

    let mut second = Client::connect(deployment.port).await;
    let second_session = handshake(&mut second, "alice").await;
    assert_ne!(first_session, second_session);

    // The ghost is disconnected, which is what was not happening: the older
    // connection has to actually end, not merely be forgotten.
    let ended = timeout(FRAME_TIMEOUT, async {
        loop {
            if deployment.records().iter().any(|event| {
                event.message == "user left"
                    && event.field("session") == Some(&FieldValue::Uint(first_session.into()))
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the first session must be disconnected when the same user reconnects"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_login_and_a_refusal_both_reach_the_operator_log() {
    // The whole point of the operator log: reading it afterwards answers who
    // connected and who was turned away. Asserted end to end, because every
    // piece of this — the config section, the runtime, the logger on the
    // context, the call in the handshake — can be present and still not
    // produce a record if one of them is not wired to the next.
    let data_dir = TempDir::new("operator-log");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let session = handshake(&mut alice, "alice").await;

    let records = deployment.records();
    let login = records
        .iter()
        .find(|event| event.message == "user authenticated")
        .expect("a completed handshake must be recorded");
    assert_eq!(login.category, Category::Session);
    assert_eq!(
        login.field("name"),
        Some(&FieldValue::Text("alice".to_owned()))
    );
    assert_eq!(
        login.field("session"),
        Some(&FieldValue::Uint(session.into()))
    );

    assert!(
        records
            .iter()
            .any(|event| event.message == "client connected"),
        "the gateway must record the connection itself, before any handshake"
    );

    // An empty username, which userdata refuses as `InvalidName`. The client
    // is sent a `Reject`; this asserts the server also keeps its own reason,
    // which the client is never told in that detail.
    let mut nobody = Client::connect(deployment.port).await;
    let _ = nobody.recv().await; // the server's unprompted Version
    nobody
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                ..tcp::Version::default()
            },
        )
        .await;
    nobody
        .send(
            2,
            &tcp::Authenticate {
                username: Some(String::new()),
                ..tcp::Authenticate::default()
            },
        )
        .await;
    let refused = timeout(FRAME_TIMEOUT, async {
        loop {
            if deployment
                .records()
                .iter()
                .any(|event| event.message == "login refused")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(refused.is_ok(), "a refused login must be recorded");

    deployment.stop();
}

#[cfg(test)]
mod example_config {
    use starling_runtime::config::Config;

    fn shipped(name: &str) -> Config {
        // `deny_unknown_fields` means a stale file is a startup failure for
        // whoever copies it, and they find out at deploy time.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(name);
        let config =
            Config::load(&path).unwrap_or_else(|error| panic!("{name} must load: {error}"));
        config
            .validate()
            .unwrap_or_else(|error| panic!("{name} must be a valid routing table: {error}"));
        config
    }

    #[test]
    fn the_shipped_example_configuration_loads() {
        let _ = shipped("starling.example.toml");
    }

    #[test]
    fn a_shipped_file_routes_every_type_where_the_defaults_do() {
        // The routing table exists twice — once as the built-in defaults, once
        // per shipped file — and nothing made them agree. They drifted, and the
        // drift was invisible: `UserState` and `UserStats` were moved to
        // session-lifecycle in code, both files went on naming userdata, and so
        // the fix worked under `--all-in-one` and did nothing whatsoever in the
        // Docker deployment, where a file is what is actually loaded.
        //
        // Compared by *type* rather than by whole service block, because a file
        // is entitled to differ on endpoints, tiers and limits. Where a client's
        // frame is delivered is not that kind of choice.
        let defaults = Config::with_defaults(std::path::Path::new("/run/starling"));
        for name in ["starling.example.toml", "deploy/starling.toml"] {
            let shipped = shipped(name);
            for service in defaults.services.values() {
                for type_id in &service.types {
                    let expected = defaults.route(*type_id).map(|(service, _)| service);
                    let actual = shipped.route(*type_id).map(|(service, _)| service);
                    assert_eq!(
                        actual, expected,
                        "{name} routes type {type_id} to {actual:?}, the defaults to {expected:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_shipped_file_charges_every_service_to_the_bucket_the_defaults_do() {
        // The same drift as the test above, on the axis that silences people
        // rather than misrouting them. Voice was charged to `control` —
        // murmur's 1 message per second — and tunnelled audio is a hundred
        // frames a second, so a client behind a UDP-blocking firewall was cut
        // off after its first few frames with no error anywhere.
        //
        // A bucket named in a service block but missing from `[gateway.limits]`
        // is not an error either: the limiter allows what it has no bucket for,
        // so the mistake shows up as *no* limit rather than as a failure.
        let defaults = Config::with_defaults(std::path::Path::new("/run/starling"));
        for name in ["starling.example.toml", "deploy/starling.toml"] {
            let shipped = shipped(name);
            for (service, expected) in &defaults.services {
                let actual = shipped
                    .services
                    .get(service)
                    .and_then(|service| service.limits.as_deref());
                assert_eq!(
                    actual,
                    expected.limits.as_deref(),
                    "{name} charges {service} to {actual:?}, the defaults to {:?}",
                    expected.limits
                );
                if let Some(bucket) = actual {
                    assert!(
                        shipped.gateway.limits.contains_key(bucket),
                        "{name} charges {service} to a bucket \"{bucket}\" it never defines, \
                         so that traffic is not limited at all"
                    );
                }
            }
        }
    }

    #[test]
    fn the_compose_configuration_loads_and_is_reachable_over_tcp() {
        // docker-compose.yml puts every service in its own container, so the
        // Unix sockets the example ships are unreachable there. A `unix:`
        // endpoint surviving into this file would bind a socket inside one
        // container that no other container can dial — a stack that comes up
        // healthy and answers nothing.
        let config = shipped("deploy/starling.toml");
        for (name, service) in &config.services {
            let Some(endpoint) = service.endpoint.as_deref() else {
                // `directory` is the one service nothing dials: it has no gRPC
                // surface, so an endpoint would be a socket with no purpose.
                // Any *other* service without one is a container the rest of
                // the stack cannot reach.
                assert_eq!(
                    name, "directory",
                    "{name} has no endpoint, so nothing can reach it"
                );
                continue;
            };
            assert!(
                endpoint.starts_with("http://"),
                "{name} is at {endpoint}, which no other container can reach"
            );
        }
        assert!(
            !config.runtime.all_in_one,
            "the file is the multi-container deployment; --all-in-one is a flag, not a second file"
        );
    }
}

// ── The live channel ────────────────────────────────────────────────────────
//
// Every test below runs on a **multi-threaded** runtime, and that is load
// bearing rather than tidiness.
//
// `#[tokio::test]` gives a current-thread runtime, and these tests start a whole
// deployment — twenty-one services plus the gateway — on it. A real Starling
// process runs multi-threaded, so a single-threaded one is not a smaller
// deployment, it is a different one.
//
// It bites here in particular because the event bridges are background tasks
// nothing else awaits. On one thread they are scheduled only when everything
// else yields, and during a cold start they lose that race often enough to be
// flaky — the subscriber attaches, no bridge has run, and a task that never
// executed writes no log. The symptom is silence, which is exactly why it first
// read as a transport fault.

/// The token the live-channel tests authenticate with.
///
/// Named rather than inlined because the configuration holds the *variable's
/// name* and never the secret, so the test has to set the same variable the
/// deployment reads.
const LIVE_TOKEN_VAR: &str = "STARLING_E2E_LIVE_TOKEN";
const LIVE_TOKEN: &str = "e2e-live-channel-token";

/// A deployment with the admin plane switched on, and the port it listens on.
///
/// `operator-api` ships disabled, so a plain [`Deployment::start`] does not run
/// it — which is correct, and means a test that wants it has to configure it
/// the way an operator would.
#[expect(
    unsafe_code,
    reason = "edition 2024 has no safe way to set an environment variable, and               token auth deliberately names a variable rather than holding a               secret — so a test of it has to set one"
)]
async fn deployment_with_operator_api(data_dir: &Path) -> (Deployment, u16) {
    use starling_runtime::config::{AuthMode, OperatorAuth, ServiceConfig, StaticToken, TokenAuth};

    // SAFETY: setting an environment variable is only unsound alongside a
    // concurrent read from another thread. These tests are serialised by
    // `ONE_AT_A_TIME`, and this runs before the deployment that reads it exists.
    unsafe { std::env::set_var(LIVE_TOKEN_VAR, LIVE_TOKEN) };

    let port = free_port();
    let data_dir_for_endpoint = data_dir.to_path_buf();
    let deployment = Deployment::start_with(data_dir, move |config| {
        // Inserted rather than adjusted: `operator-api` is not a `ServiceKind`
        // — it owns no wire type and the gateway never routes to it — so
        // `Config::with_defaults` creates no entry for it, and an absent entry
        // is exactly what `compose::enabled` reads as "off" for this one
        // service.
        let service = config
            .services
            .entry("operator-api".to_owned())
            .or_insert_with(|| {
                ServiceConfig::new(
                    // The deployment's own directory, never a fixed path: on
                    // Windows the local endpoint is a named pipe whose name is
                    // derived from it, so a hard-coded root would give every
                    // deployment in this process the same pipe — and the second
                    // one to start would find it busy.
                    &starling_runtime::transport::local_endpoint(
                        &data_dir_for_endpoint,
                        "operator-api",
                    ),
                    starling_runtime::tier::Tier::Optional,
                    &[],
                )
            });
        service.enabled = true;
        service.listen = Some(format!("127.0.0.1:{port}"));
        service.auth = Some(OperatorAuth {
            mode: AuthMode::Token,
            token: Some(TokenAuth {
                tokens: vec![StaticToken {
                    value_env: LIVE_TOKEN_VAR.to_owned(),
                    scopes: vec!["*".to_owned()],
                }],
            }),
            ..OperatorAuth::default()
        });
    })
    .await;

    (deployment, port)
}

/// The live channel's socket type, spelled once.
type LiveSocket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

/// Open the live channel, presenting the bearer token.
async fn open_live_channel(port: u16) -> LiveSocket {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    // Retried because the API's listener is spawned alongside the rest of the
    // deployment: the port can be a moment behind everything else being up.
    let deadline = std::time::Instant::now() + FRAME_TIMEOUT;
    loop {
        let mut request = format!("ws://127.0.0.1:{port}/v1/events")
            .into_client_request()
            .expect("a valid websocket URL");
        let _ = request.headers_mut().insert(
            "authorization",
            format!("Bearer {LIVE_TOKEN}")
                .parse()
                .expect("a valid header value"),
        );

        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => return socket,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the live channel never accepted a subscriber: {error}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Read events until one satisfies `wanted`.
///
/// Reads rather than inspecting only the next frame: the channel carries
/// everything that happens on the server, so a test asserting on one event has
/// to skip the others rather than demand its own arrive first.
async fn next_event(
    socket: &mut LiveSocket,
    wanted: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    next_event_within(socket, wanted, FRAME_TIMEOUT).await
}

/// Wait for the bridge's opening `started`.
///
/// Longer than [`FRAME_TIMEOUT`], because it is not waiting for a frame — it is
/// waiting for twenty services to finish coming up. `started` is sent to a
/// joining subscriber only once the state below the bridge is readable
/// (`operator-api/src/live.rs:86`), so a subscriber that attaches during
/// start-up waits for the deployment, not for the channel. On a loaded machine
/// that is well past ten seconds: the gateway is still logging "All pipe
/// instances are busy" retries at that point, and the test failed for a server
/// that was merely slow.
async fn started(socket: &mut LiveSocket) {
    let _ = next_event_within(socket, |event| is(event, "started"), LIVE_START_TIMEOUT).await;
}

/// [`next_event`], with the caller choosing how long to wait.
async fn next_event_within(
    socket: &mut LiveSocket,
    wanted: impl Fn(&serde_json::Value) -> bool,
    within: Duration,
) -> serde_json::Value {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let deadline = tokio::time::Instant::now() + within;
    let mut seen: Vec<String> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let message = timeout(remaining, socket.next())
            .await
            .unwrap_or_else(|_| panic!("no matching event arrived; saw {seen:?}"))
            .expect("the live channel closed")
            .expect("a readable frame");

        if let Message::Text(text) = message {
            let event: serde_json::Value =
                serde_json::from_str(&text).expect("every frame on this channel is JSON");
            if wanted(&event) {
                return event;
            }
            seen.push(event["event"].as_str().unwrap_or("?").to_owned());
        }
    }
}

/// Whether an event is of the named kind.
fn is(event: &serde_json::Value, kind: &str) -> bool {
    event["event"].as_str() == Some(kind)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_change_reaches_a_live_subscriber_as_the_right_kind_of_event() {
    // The whole path in one test: `metadata` publishes a tree change, the
    // bridge turns it into an event, and a real WebSocket client is handed it.
    // Every unit test around this can pass while the wiring between them does
    // not, which is the gap this closes.
    let data_dir = TempDir::new("live-channel");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    let mut socket = open_live_channel(port).await;

    // The bridge announces itself once the state below it is readable.
    started(&mut socket).await;

    // Created over the same gRPC surface the REST route calls, so this asserts
    // the bridge observed a real change rather than one the test published into
    // the hub itself.
    use starling_proto_fancy::common::Scope;
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest, UpdateRequest};

    let grpc = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    let created = MetadataClient::new(grpc)
        .create(CreateRequest {
            scope: Some(Scope { virtual_server: 1 }),
            actor: None,
            channel: Some(Channel {
                parent: Some(0),
                name: "Observed".to_owned(),
                ..Channel::default()
            }),
            temporary: false,
        })
        .await
        .expect("the channel is created")
        .into_inner();
    assert!(created.applied, "refused: {}", created.refused);
    let id = created.channel.expect("a created channel").id;

    let event = next_event(&mut socket, |event| is(event, "channelCreated")).await;
    assert_eq!(event["channel"]["name"].as_str(), Some("Observed"));
    assert_eq!(
        event["channel"]["parent"].as_u64(),
        Some(0),
        "a channel under the root reports parent 0"
    );

    // And an edit arrives as a *change*, not a second creation. This is the
    // distinction the bridge exists to reconstruct: `metadata` publishes one
    // upsert for both, and a consumer cannot recover it from that alone.
    let grpc = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    let renamed = MetadataClient::new(grpc)
        .update(UpdateRequest {
            scope: Some(Scope { virtual_server: 1 }),
            actor: None,
            channel: id,
            fields: vec!["name".to_owned()],
            values: Some(Channel {
                name: "Renamed".to_owned(),
                ..Channel::default()
            }),
        })
        .await
        .expect("the channel is renamed")
        .into_inner();
    assert!(renamed.applied, "refused: {}", renamed.refused);

    let event = next_event(&mut socket, |event| is(event, "channelStateChanged")).await;
    assert_eq!(event["channel"]["name"].as_str(), Some("Renamed"));
    assert_eq!(event["channel"]["id"].as_u64(), Some(u64::from(id)));

    deployment.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connecting_client_is_reported_to_a_live_subscriber() {
    // `session-view` publishes an upsert for an arrival and for a change alike.
    // This asserts the first one a session produces is reported as a connect.
    let data_dir = TempDir::new("live-users");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    let mut socket = open_live_channel(port).await;
    started(&mut socket).await;

    let mut client = Client::connect(deployment.port).await;
    let session = handshake(&mut client, "observed-user").await;

    let event = next_event(&mut socket, |event| is(event, "userConnected")).await;
    assert_eq!(event["user"]["name"].as_str(), Some("observed-user"));
    assert_eq!(event["user"]["session"].as_u64(), Some(u64::from(session)));
    // An unregistered guest carries no account. Account 0 is the SuperUser, so
    // a guest reported as 0 would read as the administrator.
    assert!(
        event["user"]["user_id"].is_null(),
        "an unregistered guest must not carry an account: {event}"
    );

    deployment.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_live_channel_answers_a_command_and_refuses_an_unknown_one() {
    // The channel is bidirectional, and a command that goes unanswered is
    // indistinguishable from one the server chose not to honour.
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let data_dir = TempDir::new("live-commands");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    let mut socket = open_live_channel(port).await;

    socket
        .send(Message::Text(r#"{"command":"ping"}"#.into()))
        .await
        .expect("the command is sent");
    let _ = next_event(&mut socket, |event| is(event, "pong")).await;

    socket
        .send(Message::Text(r#"{"command":"detonate"}"#.into()))
        .await
        .expect("the command is sent");
    let event = next_event(&mut socket, |event| is(event, "error")).await;
    assert!(
        event["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "a refusal must say why: {event}"
    );

    deployment.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_live_channel_refuses_a_subscriber_without_a_credential() {
    // The highest-privilege surface in the system. The refusal happens before
    // the upgrade, because a socket that opens and then closes is — to most
    // clients — indistinguishable from a network fault.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let data_dir = TempDir::new("live-unauthorised");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    // One authorised connection first, so a refusal below cannot be the
    // listener simply not being up yet.
    drop(open_live_channel(port).await);

    let request = format!("ws://127.0.0.1:{port}/v1/events")
        .into_client_request()
        .expect("a valid websocket URL");
    assert!(
        tokio_tungstenite::connect_async(request).await.is_err(),
        "the live channel accepted a subscriber with no credential"
    );

    deployment.stop();
}

// -- The registered-user directory, moving somebody, and clearing their profile

/// Register an account the way an operator does, over userdata's own gRPC.
///
/// Deployment set-up rather than the behaviour under test, on the same grounds
/// as [`Deployment::create_channel`] — and for one more: registering *from a
/// client* requires the target to have presented a certificate, and this
/// harness dials with `with_no_client_auth`. What the tests below assert is
/// what a client can then see and do about the accounts this put there.
async fn register_account(deployment: &Deployment, name: &str) -> u64 {
    use starling_proto_fancy::userdata::user_data_client::UserDataClient;
    use starling_proto_fancy::userdata::{Account, RegisterRequest};

    let transport = deployment
        .resolver
        .channel("userdata")
        .expect("userdata is reachable");
    UserDataClient::new(transport)
        .register(RegisterRequest {
            scope: None,
            actor: None,
            account: Some(Account {
                name: name.to_owned(),
                cert_hash: name.as_bytes().to_vec(),
                ..Account::default()
            }),
            password: String::new(),
        })
        .await
        .expect("the account is registered")
        .into_inner()
        .id
}

/// The `UserList` the server sends back, or the refusal it sends instead.
///
/// Both are legitimate answers, and a test asserting one has to be able to see
/// the other: a directory that is refused and a directory that is never
/// answered are the same timeout otherwise, and the second was the bug.
async fn next_directory(client: &mut Client) -> Result<tcp::UserList, tcp::PermissionDenied> {
    loop {
        let (type_id, payload) = client.recv().await;
        match type_id {
            18 => {
                return Ok(
                    tcp::UserList::decode(payload.as_slice()).expect("a well-formed UserList")
                );
            }
            12 => {
                return Err(tcp::PermissionDenied::decode(payload.as_slice())
                    .expect("a well-formed PermissionDenied"));
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn the_registered_user_directory_shows_an_operator_more_than_a_guest() {
    // `docs/GAP-ANALYSIS.md` UserList(18)/A1. The message was routed to
    // `userdata`, which had no arm for it, so an operator registered somebody
    // successfully and found the dialog they would check it in empty — with
    // nothing logged, because dropping an unhandled frame is normal and silent.
    //
    // Both views are asserted from one deployment because the *difference* is
    // the rule (`Messages.cpp:3153`), and a server that answered everybody with
    // the administrator's view would pass any test that looked at only one of
    // them. `Register` manages the directory and comes with the whole record;
    // `ReadRegister` is a lookup permission — enough to find somebody who is
    // offline and invite them, not enough to learn when they were last here.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("user-list");
    let deployment = Deployment::start(data_dir.path()).await;
    let fred = register_account(&deployment, "offline-fred").await;

    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![
                // Everybody may look somebody up…
                entry("all", Perm::READ_REGISTER, Perm::empty()),
                // …and the operators may manage the directory.
                entry("ops", Perm::REGISTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(0, "ops", alice_session)
        .await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    for client in [&mut alice, &mut bob] {
        client.send(18, &tcp::UserList::default()).await;
    }

    let operator = next_directory(&mut alice)
        .await
        .expect("an operator holding Register may read the directory");
    let listed = operator
        .users
        .iter()
        .find(|user| u64::from(user.user_id) == fred)
        .expect("the account that was just registered is in the directory");
    assert_eq!(listed.name.as_deref(), Some("offline-fred"));
    assert!(
        listed.last_seen.is_some(),
        "an operator is shown when the account was last active"
    );
    assert!(
        operator.users.iter().all(|user| user.user_id != 0),
        "the SuperUser is not somebody to be renamed or unregistered, and murmur \
         leaves it out of the dialog that offers both"
    );

    let guest = next_directory(&mut bob)
        .await
        .expect("ReadRegister is enough to look somebody up");
    let seen = guest
        .users
        .iter()
        .find(|user| u64::from(user.user_id) == fred)
        .expect("the reduced view still names the account");
    assert_eq!(seen.name.as_deref(), Some("offline-fred"));
    assert_eq!(
        seen.last_seen, None,
        "presence is not part of a lookup: ReadRegister must not report when \
         somebody was last on the server"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_guest_with_no_grant_at_all_is_refused_the_directory() {
    // The other direction, and the one that matters: the account list of
    // everyone who has ever been on this server is not public. Refused *out
    // loud*, because a silent drop here is indistinguishable from the bug the
    // handler was written to fix.
    let data_dir = TempDir::new("user-list-refused");
    let deployment = Deployment::start(data_dir.path()).await;
    let _ = register_account(&deployment, "offline-fred").await;

    // No ACL table at all. The default set grants `ReadRegister` to registered
    // users only (`permissions/src/evaluate.rs:182`), and this client is a guest.
    let mut mallory = Client::connect(deployment.port).await;
    let _ = handshake(&mut mallory, "mallory").await;
    mallory.send(18, &tcp::UserList::default()).await;

    let refusal = next_directory(&mut mallory)
        .await
        .expect_err("a guest must not be handed the account directory");
    assert_eq!(
        refusal.permission,
        Some(starling_proto_fancy::perm::Perm::READ_REGISTER.bits()),
        "the refusal names the permission that was missing, or it is a support ticket"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_moderator_moves_another_user_by_either_half_of_murmurs_rule() {
    // `docs/GAP-ANALYSIS.md` U2, and the shape of the gap is worth recording:
    // `on_move` already held the whole rule — `Move` on the channel the user is
    // being taken out of, then `Move` on the destination **or** the moved
    // user's own `Enter` — and was unreachable for anybody but the sender,
    // because the cross-session refusal above it dropped the message first.
    // Nothing failed and nothing was logged; the user simply did not move.
    //
    // Both halves of the *or* are exercised, because implementing one of them
    // is indistinguishable from implementing both until the day an operator
    // drags somebody into a room that person cannot enter alone — which is the
    // entire point of a `Move` permission.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::{AclEntry, AclSet};

    let data_dir = TempDir::new("move-another");
    let deployment = Deployment::start(data_dir.path()).await;
    let lobby = deployment.create_channel("Lobby").await;
    let vault = deployment.create_channel("Vault").await;

    // `apply_subs` off, so this grants Move in the **root only**: alice may take
    // people out of the room they start in and nowhere else. Left on, the grant
    // would inherit into every channel below and the destination half of the
    // rule would pass for the wrong reason.
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![AclEntry {
                apply_here: true,
                apply_subs: false,
                group: Some("ops".to_owned()),
                grant: Perm::MOVE.bits(),
                ..AclEntry::default()
            }],
            groups: Vec::new(),
        })
        .await;
    // A room nobody may walk into and an operator may still put people in.
    deployment
        .set_acl(AclSet {
            channel: vault,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("ops", Perm::MOVE, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(0, "ops", alice_session)
        .await;
    deployment
        .add_temporary_group(vault, "ops", alice_session)
        .await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;

    // Bob cannot get into the Vault on his own, which is what makes the first
    // move below a real exercise of alice's `Move` rather than of bob's `Enter`.
    bob.send(
        9,
        &tcp::UserState {
            session: Some(bob_session),
            channel_id: Some(vault),
            ..tcp::UserState::default()
        },
    )
    .await;
    let refusal = bob
        .next_entry_answer(bob_session)
        .await
        .expect_err("Enter is denied to everyone in the Vault");
    assert_eq!(refusal.permission, Some(Perm::ENTER.bits()));

    // Half one: the **mover's** `Move` on the destination, into a room the moved
    // user was just refused. This is the case an operator reaches for, and the
    // one a server implementing only the `Enter` branch would refuse.
    //
    // Bob starts in the root, where alice's grant applies, so the *source* half
    // of the rule is satisfied and what is under test is the destination.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                channel_id: Some(vault),
                ..tcp::UserState::default()
            },
        )
        .await;
    let dragged = timeout(FRAME_TIMEOUT, bob.next_move_of(bob_session))
        .await
        .expect("an operator holding Move on the destination may put somebody there");
    assert_eq!(
        dragged.channel_id,
        Some(vault),
        "the mover's Move on the destination has to be enough on its own"
    );
    assert_eq!(
        dragged.actor,
        Some(alice_session),
        "a move done *to* somebody has to name who did it, or the client reports \
         it as the server acting on its own"
    );

    // Half two: the **moved user's** own `Enter`. Alice holds `Move` in the
    // Vault, so she may take bob out of it — and holds none in the Lobby, so
    // putting him *there* can only be allowed by bob's own default `Enter`.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                channel_id: Some(lobby),
                ..tcp::UserState::default()
            },
        )
        .await;
    let moved = timeout(FRAME_TIMEOUT, bob.next_move_of(bob_session))
        .await
        .expect("bob was never told he had been moved");
    assert_eq!(
        moved.channel_id,
        Some(lobby),
        "the moved user's own Enter has to be enough, with no Move on the mover"
    );

    deployment.stop();
}

#[tokio::test]
async fn an_operator_clears_another_users_comment_but_cannot_write_one() {
    // `docs/GAP-ANALYSIS.md` U6. Both halves are the feature: murmur's rule is
    // `ResetUserContent` on the root **and** an empty value
    // (`Messages.cpp:1236`), so a moderator can take down a comment nobody
    // should have to read and cannot replace it with one of their own choosing.
    // Enforcing only the permission would let an administrator put words into
    // somebody else's profile, under that person's name, on every client.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("reset-content");
    let deployment = Deployment::start(data_dir.path()).await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("ops", Perm::RESET_USER_CONTENT, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(0, "ops", alice_session)
        .await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;

    // Bob's own comment, which needs no permission at all.
    bob.send(
        9,
        &tcp::UserState {
            comment: Some("something regrettable".to_owned()),
            ..tcp::UserState::default()
        },
    )
    .await;
    let posted = timeout(
        FRAME_TIMEOUT,
        alice.next_state_of(bob_session, |state| {
            state.comment_hash.as_ref().map(|_| true)
        }),
    )
    .await
    .expect("everyone is told bob set a comment");
    assert!(
        posted.comment_hash.is_some_and(|hash| !hash.is_empty()),
        "the hash is what a client fetches the body with"
    );

    // Bob may not be *given* a comment by somebody else, however privileged.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                comment: Some("words alice put in bob's mouth".to_owned()),
                ..tcp::UserState::default()
            },
        )
        .await;
    let (type_id, payload) = timeout(FRAME_TIMEOUT, alice.recv())
        .await
        .expect("the write is answered rather than dropped");
    assert_eq!(
        type_id, 12,
        "writing another user's comment must be refused"
    );
    let refusal = tcp::PermissionDenied::decode(payload.as_slice()).expect("well-formed");
    assert_eq!(
        refusal.r#type,
        Some(tcp::permission_denied::DenyType::TextTooLong as i32),
        "the permitted length of somebody else's comment is zero, and murmur says \
         so with TextTooLong rather than with a permission the operator does hold"
    );

    // Clearing it is exactly what the permission is for.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                comment: Some(String::new()),
                ..tcp::UserState::default()
            },
        )
        .await;
    let cleared = timeout(
        FRAME_TIMEOUT,
        bob.next_state_of(bob_session, |state| state.comment.as_ref().map(|_| true)),
    )
    .await
    .expect("bob is told his comment was cleared");
    assert_eq!(
        cleared.comment.as_deref(),
        Some(""),
        "an empty body, not an empty hash: a client reads the first as blank and \
         the second as something to go and fetch"
    );
    assert_eq!(
        cleared.actor,
        Some(alice_session),
        "a reset done to somebody names who did it"
    );

    deployment.stop();
}

#[tokio::test]
async fn a_peer_that_never_authenticated_reaches_nobody() {
    // Defence in depth, asserted rather than assumed.
    //
    // The gateway has **no authentication gate**: `dispatch` routes any frame
    // whose type has a route, and an unauthenticated connection simply carries
    // `session = 0`. What actually stops it is the layer below — `Permit`
    // refuses session 0 without even asking `permissions` — so the safety of
    // the whole front door rests on every service failing closed.
    //
    // That is a real property and worth a test, because it is invisible: it
    // holds by everything downstream being careful, not by anything at the
    // door saying no. A service that grew a path acting on `conn` rather than
    // `session` would open a hole with nothing to catch it.
    //
    // Companion to `a_refused_login_is_told_why_and_then_hung_up_on`, which
    // covers the peer that *tried* and failed; this one never tries at all,
    // so no `Reject` and no disconnect is due to it.
    let data_dir = TempDir::new("unauthenticated");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    // Completes TLS and `Version`, then skips `Authenticate` entirely and
    // starts talking — which a stock client cannot do and a hostile one can.
    let mut intruder = Client::connect(deployment.port).await;
    let _ = intruder.recv().await;
    intruder
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                ..tcp::Version::default()
            },
        )
        .await;
    intruder
        .send(
            11,
            &tcp::TextMessage {
                // Claiming somebody else's session, because a peer with none
                // of its own has nothing to lose by trying.
                actor: Some(1),
                channel_id: vec![0],
                message: "INTRUDER".to_owned(),
                ..tcp::TextMessage::default()
            },
        )
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let Some((type_id, payload)) = bob.next_frame(Duration::from_millis(500)).await else {
            continue;
        };
        if type_id != 11 {
            continue;
        }
        let message = tcp::TextMessage::decode(payload.as_slice()).expect("a well-formed message");
        assert!(
            !message.message.contains("INTRUDER"),
            "a peer that never authenticated had its text delivered to a real user"
        );
    }

    deployment.stop();
}

#[tokio::test]
async fn the_health_collector_reports_every_service_in_a_live_deployment() {
    // The whole feature, against a real deployment. Each half is easy to get
    // right on its own and worthless alone: a service reporting its own gates
    // that nothing collects, or a collector that reaches nobody.
    //
    // What only this level can show is that the runtime's injected health RPC
    // is actually *served* by every service — it is added in `serve`, so a
    // service that composes its routes unusually could silently lack it, and
    // the collector would report the healthiest service on the server as
    // unreachable.
    use starling_proto_fancy::health::health_overview_client::HealthOverviewClient;
    use starling_proto_fancy::health::{OverviewRequest, State};

    let data_dir = TempDir::new("health-overview");
    let deployment = Deployment::start(data_dir.path()).await;

    // The first sweep runs immediately, but "immediately" is still after the
    // services it asks have bound. Retried rather than slept on: how long a
    // whole deployment takes to come up is not what this asserts.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let overview = loop {
        let attempt = async {
            let channel = deployment.resolver.channel("health").ok()?;
            let overview = HealthOverviewClient::new(channel)
                .get(OverviewRequest { scope: None })
                .await
                .ok()?
                .into_inner();
            (!overview.services.is_empty()).then_some(overview)
        }
        .await;
        if let Some(overview) = attempt {
            break overview;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the health collector never produced a sweep"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };

    // Every enabled service is in the sweep, including the ones with no wire
    // type. A collector that only knew the client-facing services would miss
    // session-view, which everything else reads through.
    for expected in [
        "voice",
        "metadata",
        "userdata",
        "session-view",
        "permissions",
    ] {
        let found = overview
            .services
            .iter()
            .find(|service| service.service == expected)
            .unwrap_or_else(|| panic!("{expected} is missing from the sweep"));
        assert_ne!(
            found.state,
            i32::from(State::Unreachable),
            "{expected} was unreachable: {}",
            found.error
        );
    }

    // The gates themselves survive, which is the difference between a
    // dashboard that says "something is wrong" and one that says what.
    let voice = overview
        .services
        .iter()
        .find(|service| service.service == "voice")
        .expect("voice is in the sweep");
    assert!(
        voice.gates.iter().any(|gate| gate.name == "session view"),
        "voice's own readiness gates did not reach the collector: {:?}",
        voice.gates
    );

    // And the snapshot says when it was taken, so a dashboard can show a
    // stale picture as stale rather than as current.
    assert!(overview.observed_at_ms > 0);

    deployment.stop();
}

#[tokio::test]
async fn a_channel_listener_hears_a_room_without_being_in_it() {
    // `docs/GAP-ANALYSIS.md` V5. The routing core could already fan out to a
    // listener and the tree could already hold one, but `UserState`'s
    // `listening_channel_add` was never read — so a user clicked "listen" in
    // their client, the server parsed the message, ignored it, and answered
    // nothing. Every piece worked and the feature did not exist.
    //
    // Driven end to end because that is exactly the shape of the bug: the wire
    // handler, metadata's tree, the session view and voice's subscription are
    // four services, and each was right on its own.
    //
    // Bob is the control. He is in the lobby with alice and must keep hearing
    // her; carol never leaves the lobby either, but listens to the annex.
    let data_dir = TempDir::new("channel-listener");
    let deployment = Deployment::start(data_dir.path()).await;
    let annex = deployment.create_channel("Annex").await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut carol = Client::connect(deployment.port).await;
    let carol_session = handshake(&mut carol, "carol").await;

    // Alice moves to the annex, so that anything carol hears from her can only
    // have arrived through the listener.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(annex),
                ..tcp::UserState::default()
            },
        )
        .await;
    assert_eq!(carol.next_channel_of(alice_session).await, annex);

    // Silent first, or the second half proves nothing: a test that only checks
    // carol hears alice after the listener passes on a server that routes every
    // frame to everybody.
    for _ in 0..10 {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"unheard"))
            .await;
    }
    assert!(
        carol.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "carol heard another channel before she listened to it; the annex is not isolated, \
         so nothing below can be attributed to the listener"
    );

    carol
        .send(
            9,
            &tcp::UserState {
                session: Some(carol_session),
                listening_channel_add: vec![annex],
                ..tcp::UserState::default()
            },
        )
        .await;

    // The echo, which is also the point the server has finished applying it.
    // Waiting on a timer would race the announcement to session-view and
    // voice's subscription behind it.
    let listening = carol
        .next_state_of(carol_session, |state| {
            (!state.listening_channel_add.is_empty()).then_some(true)
        })
        .await;
    assert_eq!(
        listening.listening_channel_add,
        vec![annex],
        "the client is told which listener was registered, or its own UI never lights up"
    );

    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let reached = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"heard"))
            .await;
        if let Some(payload) = carol.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };
    let payload = reached.expect(
        "carol registered a listener on the annex and never heard it; the wire handler, the \
         tree, the session view and voice's snapshot are four places this can stop",
    );
    let (speaker, opus) = heard(&payload);
    assert_eq!(speaker, alice_session);
    assert_eq!(opus, b"heard");

    // Context 3, and it is not cosmetic: a client renders a listener frame
    // differently from someone in the room, and reporting it as normal speech
    // tells carol that alice has joined her channel.
    assert_eq!(
        listener_context(&payload),
        3,
        "a frame reached through a channel listener must say so"
    );

    // And it stops when she says so — the half that a server which only ever
    // adds listeners passes without implementing.
    carol
        .send(
            9,
            &tcp::UserState {
                session: Some(carol_session),
                listening_channel_remove: vec![annex],
                ..tcp::UserState::default()
            },
        )
        .await;
    let _ = carol
        .next_state_of(carol_session, |state| {
            (!state.listening_channel_remove.is_empty()).then_some(true)
        })
        .await;

    let _ = carol.next_audio(AUDIO_ATTEMPT).await;
    for _ in 0..10 {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"after"))
            .await;
    }
    assert!(
        carol.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "carol stopped listening and still heard the annex; a listener that cannot be \
         cancelled is a subscription the user is stuck with"
    );

    deployment.stop();
}

/// The `context` the server put on a frame — 0 normal, 1 shout, 2 whisper,
/// 3 through a channel listener.
fn listener_context(payload: &[u8]) -> u32 {
    assert_eq!(payload.first(), Some(&0), "not an audio packet");
    let audio = udp::Audio::decode(&payload[1..]).expect("a well-formed audio frame");
    match audio.header {
        Some(udp::audio::Header::Context(context)) => context,
        // Outbound frames carry `context`; `target` is the inbound spelling of
        // the same oneof, and the two are not interchangeable.
        other => panic!("the server sent a frame with no context: {other:?}"),
    }
}
