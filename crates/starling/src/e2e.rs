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

/// Send a loopback frame until the server echoes it, and return what came back.
///
/// Also what binds this client's address server-side: an address is only
/// believed once a packet from it has authenticated, so until this succeeds the
/// server has no UDP path for this peer at all.
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
