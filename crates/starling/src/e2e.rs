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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use prost::Message as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use starling_proto::codec;
use starling_proto::proto::tcp;
use starling_runtime::config::Config;
use starling_runtime::inproc::Broker;
use starling_runtime::serve::{ServiceError, context};
use starling_runtime::shutdown::Shutdown;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The Mumble version Starling's own client half announces.
const MUMBLE_VERSION_V2: u64 = 0x0001_0006_0000;
/// How long to wait for a frame before deciding the wiring is broken.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// Every service plus the gateway, over a real TCP port instead of a socket
/// nobody outside the process can dial.
struct Deployment {
    port: u16,
    shutdown: Shutdown,
    handles: Vec<JoinHandle<Result<(), ServiceError>>>,
}

impl Deployment {
    /// Start everything `--all-in-one` starts, bound to an ephemeral port.
    async fn start(data_dir: &Path) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        let port = free_port();
        let mut config = Config::with_defaults(data_dir);
        config.runtime.all_in_one = true;
        config.runtime.data_dir = data_dir.to_path_buf();
        config.gateway.listen_tcp = format!("127.0.0.1:{port}");
        let config = Arc::new(config);
        let shutdown = Shutdown::new();
        let broker = Broker::new();

        let mut handles = Vec::new();
        for name in crate::units::names() {
            if !crate::compose::enabled(&config, name) {
                continue;
            }
            let ctx = context(name, Arc::clone(&config), broker.clone(), shutdown.clone());
            if let Some(handle) = crate::units::spawn(name, ctx) {
                handles.push(handle);
            }
        }

        let gateway_ctx = context(
            "gateway",
            Arc::clone(&config),
            broker.clone(),
            shutdown.clone(),
        );
        handles.push(
            crate::units::spawn("gateway", gateway_ctx).expect("\"gateway\" is a known unit"),
        );

        Self {
            port,
            shutdown,
            handles,
        }
    }

    /// Drain and abort every service this deployment started.
    async fn stop(self) {
        self.shutdown.drain();
        for handle in self.handles {
            handle.abort();
        }
    }
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
        }
    }

    async fn send(&mut self, type_id: u16, message: &impl prost::Message) {
        let frame = codec::frame(type_id, &message.encode_to_vec());
        self.stream
            .write_all(&frame)
            .await
            .expect("the connection is still open");
    }

    /// The next complete frame, waiting for more bytes as needed.
    async fn recv(&mut self) -> (u16, Vec<u8>) {
        let mut scratch = [0_u8; 8 * 1024];
        loop {
            if let Some(frame) =
                codec::decode_raw(&mut self.buffer).expect("the gateway sends well-formed frames")
            {
                return (frame.type_id, frame.payload.to_vec());
            }
            let read = timeout(FRAME_TIMEOUT, self.stream.read(&mut scratch))
                .await
                .expect("a frame arrives within the timeout")
                .expect("the socket stays readable");
            assert!(read > 0, "the gateway closed the connection early");
            self.buffer.extend_from_slice(&scratch[..read]);
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

    let (bob_frame_type, bob_payload) = bob.recv().await;
    assert_eq!(bob_frame_type, 11, "bob must receive alice's text message");
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

    deployment.stop().await;
}

#[cfg(test)]
mod example_config {
    use starling_runtime::config::Config;

    #[test]
    fn the_shipped_example_configuration_loads() {
        // `deny_unknown_fields` means a stale example is a startup failure for
        // whoever copies it, and they find out at deploy time.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../starling.example.toml");
        let config = Config::load(&path).expect("the shipped example must load");
        config
            .validate()
            .expect("the shipped example must be a valid routing table");
    }
}
