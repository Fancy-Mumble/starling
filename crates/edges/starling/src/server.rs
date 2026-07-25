//! Assembling and running the server.
//!
//! This is the composition root's payload: the one place that names concrete
//! implementations and wires them into the traits everything below works
//! against (`DESIGN.md` §1).
//!
//! Split into two steps on purpose. [`Server::new`] does everything that
//! can fail — crypto provider, certificate, socket configuration — and returns a
//! value that is ready to run. [`Server::run`] cannot fail at assembly, only at
//! serving. A single function doing both had to interleave fallible setup with
//! lifecycle teardown, which is what made the previous version 57 lines with the
//! logger threaded through locals.

use std::sync::Arc;

use starling_log::LogRuntime;
use starling_net::{ConnectionRegistry, Listener, ListenerConfig, VoiceSocket};
use starling_server::{handlers, ServerCore, ServerHandle, ServerState, TlsFloor};
use starling_voice::{ServerDetails, VoiceBridge, VoiceService};
use tracing::info;

use crate::error::StartupError;
use starling_cli::Settings;

/// A fully wired server, ready to accept connections.
pub(crate) struct Server {
    core: ServerCore,
    handle: ServerHandle,
    listener: Listener,
    voice: VoiceService,
    /// What the listener hands tunnelled audio to, and the UDP reader too.
    audio: VoiceBridge,
    /// Bound in [`Self::run`], because binding is fallible and async.
    voice_addr: String,
    /// Kept so the counters can be polled on a timer.
    voice_handle: starling_voice::VoiceHandle,
    logging: LogRuntime,
}

impl Server {
    /// Wire every concrete implementation from resolved settings.
    ///
    /// Fallible, so this is `new` returning a `Result` rather than a separate
    /// verb — Rust's convention is that the inherent constructor is called `new`
    /// (`FileSink::open` earns its name by mirroring `File::open`; "assemble"
    /// earned nothing).
    ///
    /// # Errors
    ///
    /// [`StartupError`] if the crypto provider cannot be installed or the TLS
    /// identity cannot be loaded or generated.
    pub(crate) fn new(settings: Settings) -> Result<Self, StartupError> {
        // rustls needs a process-wide provider before any TLS config is built.
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| StartupError::CryptoProvider)?;

        let identity =
            starling_tls::load_or_generate(&settings.tls.certificate, &settings.tls.key)?;
        let (spec, warnings) = settings.logging.to_spec();
        let logging = LogRuntime::start(&spec);
        // Also to stderr: an operator debugging a misconfigured log may be
        // watching the terminal precisely because the log is not working.
        for warning in warnings {
            tracing::warn!(warning, "logging configuration");
            logging.logger().log(starling_log::LogEvent::warning(
                starling_log::Category::Server,
                warning,
            ));
        }

        // The transport floor must admit every client we intend to serve; Fancy
        // clients are held to their suite's stricter floor after the handshake.
        // See `starling-crypto`.
        let tls_floor = TlsFloor::default();
        let addr = format!("{}:{}", settings.server.host, settings.server.port);

        info!(
            version = env!("CARGO_PKG_VERSION"),
            %addr,
            server_name = settings.server.register_name,
            tls = tls_floor.label(),
            "starting Starling (voice; no persistence, no ACLs)"
        );

        // The voice service is built before the core because the core holds a
        // link to it. Its `Datagrams` is filled in when the socket binds — until
        // then audio still works, through the TCP tunnel.
        let details = ServerDetails {
            version: starling_proto::Version::new(1, 5, 0).encode_v2(),
            users: 0,
            max_users: settings.server.limits.max_users,
            max_bandwidth: settings.server.limits.max_bandwidth,
        };
        let voice_addr = format!("{}:{}", settings.server.host, settings.server.port);
        let (voice, voice_handle) = VoiceService::new(Box::new(starling_api::NoDatagrams), details);
        let audio = VoiceBridge::new(voice_handle.control(), voice_handle.clone());

        let (core, handle) = ServerCore::with_parts(
            ServerState::new(settings.server),
            Self::dispatcher(logging.logger()),
            Box::new(ConnectionRegistry::new()),
            Box::new(VoiceBridge::clone(&audio)),
            // Cloned: every clone feeds the same writer, and `logging` stays
            // behind to report the log's own health on the way out.
            logging.logger().clone(),
        );

        Ok(Self {
            core,
            handle,
            listener: Listener::new(ListenerConfig {
                addr,
                identity,
                tls_floor,
            })?,
            voice,
            audio,
            voice_addr,
            voice_handle,
            logging,
        })
    }

    /// The stock handler set, plus every feature linked into this build.
    ///
    /// No feature is named here. `starling_api::registered()` returns whatever
    /// announced itself with `register_feature!`, so adding one is a dependency
    /// edge in `Cargo.toml` and nothing else.
    fn dispatcher(logger: &starling_log::Logger) -> starling_server::Dispatcher {
        let mut dispatcher = handlers::default_dispatcher();
        for feature in starling_api::registered() {
            let handlers = feature.handlers();
            logger.log(
                starling_log::LogEvent::info(starling_log::Category::Server, "feature loaded")
                    .with("feature", feature.name())
                    .with("handlers", handlers.len() as u64),
            );
            info!(
                feature = feature.name(),
                handlers = handlers.len(),
                "feature loaded"
            );
            for handler in handlers {
                dispatcher = dispatcher.register(handler);
            }
        }
        dispatcher
    }

    /// Serve until the listener fails or the process is interrupted.
    ///
    /// # Errors
    ///
    /// [`StartupError::Listen`] if the socket cannot be bound or serving fails.
    /// `Ctrl-C` is a clean stop, not an error.
    pub(crate) async fn run(self) -> Result<(), StartupError> {
        // The voice port shares the control port's number, as Mumble requires:
        // a client sends UDP to the address it connected to.
        let socket = match self.voice_addr.parse() {
            Ok(addr) => VoiceSocket::bind(addr).await.ok(),
            Err(_) => None,
        };

        // A voice port that will not bind is not fatal. Every client falls back
        // to tunnelling audio over its TLS connection, which is exactly what a
        // client behind a UDP-blocking firewall already does — so the server
        // still carries voice, just less efficiently.
        let sender = match &socket {
            Some(socket) => Some(socket.sender()),
            None => {
                tracing::warn!(addr = %self.voice_addr, "voice port unavailable; audio will tunnel over TCP");
                None
            }
        };
        self.audio.use_datagrams(
            sender.map(|sender| Box::new(sender) as Box<dyn starling_api::Datagrams>),
        );

        let reading = socket.map(|socket| {
            tokio::spawn(
                socket.serve(Arc::new(self.audio.clone()) as Arc<dyn starling_api::AudioSink>),
            )
        });
        let voicing = tokio::spawn(self.voice.run());
        // Without this the voice path is entirely mute in the logs: it has
        // counters and nothing ever read them.
        let reporting = tokio::spawn(starling_voice::report_periodically(self.voice_handle));

        let result = tokio::select! {
            result = self.listener.serve(
                self.core,
                self.handle,
                Arc::new(self.audio.clone()) as Arc<dyn starling_api::AudioSink>,
            ) => result.map_err(StartupError::Listen),
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                Ok(())
            }
        };

        if let Some(reading) = reading {
            reading.abort();
        }
        reporting.abort();
        voicing.abort();

        // Consumes the runtime: health is reported while the writer is still up.
        self.logging.finish();
        result
    }
}
