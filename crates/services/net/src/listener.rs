//! The TLS listener and the per-connection halves it composes.
//!
//! Four types, each owning exactly the state its job needs:
//!
//! | Type | Owns | Lives for |
//! |---|---|---|
//! | [`Listener`] | the TLS acceptor and bind address | the process |
//! | [`Peer`] | one connection's id, address and core handle | one connection |
//! | [`FrameReader`] | the read half and its reassembly buffer | one connection |
//! | [`FrameWriter`] | the write half and its outbound queue | one connection |
//!
//! A connection genuinely has state — an id, a peer address, a partially
//! received frame — so it is a value, not a function with five parameters. The
//! reassembly buffer in particular is the giveaway: a buffer that must survive
//! between reads is a field, and threading it through a call is how C does it.
//!
//! Read and write are separate types because they are separate tasks: a client
//! that stops reading must not block the server from reading *its* traffic, and
//! the write queue closing is what implements "flush, then disconnect" for
//! [`Effect::Disconnect`].
//!
//! # Two destinations, not one
//!
//! [`FrameReader`] demultiplexes by transport: control messages go to the state
//! service, and `UDPTunnel` — whose payload is a byte-identical UDP frame that
//! took the TCP path because UDP was blocked — goes to the audio sink.
//!
//! That is not a special case smuggled into the reader. The `UDPTunnel` message
//! type records *which transport carried the bytes* and nothing else, and which
//! transport carried the bytes is exactly what this layer knows. The line to
//! hold is that demultiplexing by transport belongs here and parsing by content
//! does not: this never looks inside the payload.
//!
//! Sending it through the dispatcher instead would put audio in the single-writer
//! state actor's queue, which `crates/kernel/bus/RESULTS.md` §3.3 measured as
//! where voice dies — a 25 ms hold made 5% of packets miss their frame.
//!
//! [`Effect::Disconnect`]: starling_api::Effect::Disconnect

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use starling_crypto::TlsFloor;
use starling_proto::{codec, ControlMessage};
use starling_tls::TlsIdentity;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{rustls, TlsAcceptor};
use tracing::{debug, info, warn};

use crate::sink::ConnectionSink;
use starling_api::{AudioSink, AudioSource, ConnId};
use starling_server::{Command, ServerCore, ServerHandle};

/// Read buffer size. Comfortably above the ~1 KiB typical control message so a
/// handshake burst is usually one syscall.
const READ_BUFFER: usize = 8 * 1024;

/// Errors that stop the listener.
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    /// The listen socket could not be bound.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: String,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },
    /// The certificate or key was not usable.
    #[error("invalid TLS configuration: {0}")]
    Tls(#[from] rustls::Error),
}

/// How to bind and secure the listener.
///
/// A struct rather than a growing parameter list, so adding the UDP socket in
/// Phase 1 does not change every call site.
#[derive(Debug)]
pub struct ListenerConfig {
    /// Address to bind, as `host:port`.
    pub addr: String,
    /// The certificate and key to present.
    pub identity: TlsIdentity,
    /// The oldest TLS version any peer may negotiate.
    ///
    /// This is the **transport-wide** floor, so it must admit every client the
    /// server intends to serve. Per-peer tightening is the job of
    /// [`SecurityPolicy`](starling_crypto::SecurityPolicy): a Fancy client is
    /// held to its suite's stricter floor after the handshake, whereas raising
    /// this value would lock stock clients out at the TCP level, before they can
    /// say who they are.
    pub tls_floor: TlsFloor,
}

/// Accepts TLS connections and gives each one to a [`Peer`].
///
/// `Debug` is hand-written: `TlsAcceptor` does not implement it, and a derive
/// would leak the certificate chain into logs if it ever did.
pub struct Listener {
    acceptor: TlsAcceptor,
    addr: String,
    floor: TlsFloor,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.addr)
            .field("floor", &self.floor)
            .finish_non_exhaustive()
    }
}

impl Listener {
    /// Build the TLS acceptor the configuration describes.
    ///
    /// Fallible, and separate from [`Self::serve`], so the certificate is
    /// rejected before anything is bound or spawned.
    ///
    /// # Errors
    ///
    /// [`ListenError::Tls`] if the certificate and key cannot make a server
    /// config.
    pub fn new(config: ListenerConfig) -> Result<Self, ListenError> {
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(config.tls_floor.versions())
                .with_no_client_auth()
                .with_single_cert(config.identity.certs, config.identity.key)?;
        // Mumble clients present certificates that are usually self-signed and
        // are identified by their SHA-1 fingerprint, not by a CA chain. ALPN is
        // unused.
        tls.alpn_protocols.clear();

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            addr: config.addr,
            floor: config.tls_floor,
        })
    }

    /// Bind, run the core, and accept until the process ends.
    ///
    /// Never returns under normal operation.
    ///
    /// # Errors
    ///
    /// [`ListenError::Bind`] if the address is unavailable. A *per-connection*
    /// accept failure — fd exhaustion, a peer that vanished — is logged and
    /// skipped, because one bad connection must not take the listener down.
    pub async fn serve(
        self,
        core: ServerCore,
        handle: ServerHandle,
        audio: Arc<dyn AudioSink>,
    ) -> Result<(), ListenError> {
        let socket = bind_listener(&self.addr)
            .await
            .map_err(|source| ListenError::Bind {
                addr: self.addr.clone(),
                source,
            })?;
        // The address actually bound, not the one configured. A wildcard binds
        // `[::]` to hear both families, and this whole class of bug is invisible
        // when a log reports the intent instead of the result — a server that
        // says `0.0.0.0` while listening on `[::]` teaches an operator nothing,
        // and one that says it while *not* hearing IPv6 actively misleads them.
        let bound = socket
            .local_addr()
            .map_or_else(|_| self.addr.clone(), |addr| addr.to_string());
        info!(addr = %bound, configured = %self.addr, tls = self.floor.label(), "listening");

        // Detached on purpose: the core lives as long as the process, and the
        // accept loop below never returns under normal operation.
        drop(tokio::spawn(core.run()));

        loop {
            let (stream, addr) = match socket.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    continue;
                }
            };

            let conn = handle.next_conn_id();
            let peer = Peer::new(conn, addr, handle.clone(), Arc::clone(&audio));
            let acceptor = self.acceptor.clone();
            drop(tokio::spawn(async move {
                if let Err(e) = peer.serve(stream, acceptor).await {
                    debug!(%conn, error = %e, "connection ended");
                }
            }));
        }
    }
}

/// Bind the control port, hearing both address families on a wildcard.
///
/// The address is a string from configuration, so it may name a host rather than
/// an address. Resolution comes first and the dual-stack rule is applied to the
/// result — see `crate::bind`.
async fn bind_listener(addr: &str) -> io::Result<TcpListener> {
    let resolved = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address for host"))?;
    TcpListener::from_std(crate::bind::tcp(resolved)?)
}

/// One accepted connection, from TLS handshake to disconnect.
#[derive(Debug)]
pub struct Peer {
    conn: ConnId,
    addr: SocketAddr,
    handle: ServerHandle,
    /// Where this connection's tunnelled audio goes, bypassing the state actor.
    audio: Arc<dyn AudioSink>,
}

impl Peer {
    /// Identify a newly accepted connection.
    #[must_use]
    pub fn new(
        conn: ConnId,
        addr: SocketAddr,
        handle: ServerHandle,
        audio: Arc<dyn AudioSink>,
    ) -> Self {
        Self {
            conn,
            addr,
            handle,
            audio,
        }
    }

    /// Complete the handshake, then run until the peer goes away.
    ///
    /// # Errors
    ///
    /// Any I/O failure on the socket, including a failed TLS handshake. The
    /// caller decides what to do with it — spawning this as a task means logging
    /// it, because there is nobody left to return it to.
    async fn serve(self, stream: TcpStream, acceptor: TlsAcceptor) -> io::Result<()> {
        // Nagle would add up to 40 ms to every control message for no benefit:
        // Mumble writes whole frames.
        stream.set_nodelay(true)?;

        let (reader, writer) = tokio::io::split(acceptor.accept(stream).await?);
        let (frames_tx, frames_rx) = mpsc::channel::<Bytes>(ServerHandle::outbound_queue_depth());

        // Registering *before* the write task starts guarantees the core's
        // opening `Version` cannot be produced before there is somewhere to put
        // it.
        if !self.register(frames_tx).await {
            return Ok(()); // core is shutting down
        }

        let writing = tokio::spawn(FrameWriter::new(self.conn, writer, frames_rx).drain());
        let result = FrameReader::new(self.conn, reader, Arc::clone(&self.audio))
            .pump(&self.handle)
            .await;

        // Tell the core first so it releases the session, then stop the writer —
        // whatever the disconnect produced has already been queued.
        let _ = self
            .handle
            .send(Command::Disconnected { conn: self.conn })
            .await;
        writing.abort();
        result
    }

    /// Announce the connection to the core. `false` means the core has stopped.
    async fn register(&self, frames: mpsc::Sender<Bytes>) -> bool {
        self.handle
            .send(Command::Connected {
                conn: self.conn,
                addr: self.addr,
                // Two handles onto one queue: the state service writes control
                // messages through the first, the voice service writes
                // tunnelled audio through the second, and the writer task
                // interleaves them onto the socket.
                sink: Box::new(ConnectionSink::new(frames.clone())),
                audio_sink: Box::new(ConnectionSink::new(frames)),
            })
            .await
            .is_ok()
    }
}

/// Decodes frames from one connection's read half.
///
/// Owns the reassembly buffer, which is why this is a type: TCP splits and
/// coalesces freely, so a partially received frame has to survive between reads.
#[derive(Debug)]
pub struct FrameReader<R> {
    conn: ConnId,
    reader: R,
    buf: BytesMut,
    audio: Arc<dyn AudioSink>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Start reading from `reader` on behalf of `conn`.
    #[must_use]
    pub fn new(conn: ConnId, reader: R, audio: Arc<dyn AudioSink>) -> Self {
        Self {
            conn,
            reader,
            buf: BytesMut::with_capacity(READ_BUFFER),
            audio,
        }
    }

    /// Forward every frame to the core until EOF or a protocol error.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`] on malformed input, which is a disconnect
    /// — never a panic, and never a partial apply. A truncated frame at EOF is
    /// *not* an error: that is what every normal disconnect looks like.
    pub async fn pump(&mut self, handle: &ServerHandle) -> io::Result<()> {
        loop {
            if !self.drain_buffered(handle).await? {
                return Ok(()); // core is shutting down
            }
            if self.reader.read_buf(&mut self.buf).await? == 0 {
                return Ok(()); // clean EOF
            }
        }
    }

    /// Deliver every complete frame already buffered. `false` if the core stopped.
    ///
    /// Separate from [`Self::pump`] because TCP happily delivers several control
    /// messages in one segment, and all of them must be handled before the next
    /// read.
    async fn drain_buffered(&mut self, handle: &ServerHandle) -> io::Result<bool> {
        loop {
            match codec::decode(&mut self.buf) {
                // Audio, which took the TCP path because UDP was blocked. It
                // goes to the voice lane, never into the state actor's queue.
                Ok(Some(ControlMessage::UdpTunnel(frame))) => {
                    self.audio.deliver(AudioSource::Tunnel(self.conn), frame);
                }

                Ok(Some(msg)) => {
                    let sent = handle
                        .send(Command::Message {
                            conn: self.conn,
                            msg: Box::new(msg),
                        })
                        .await;
                    if sent.is_err() {
                        return Ok(false);
                    }
                }
                Ok(None) => return Ok(true),
                Err(e) => {
                    warn!(conn = %self.conn, error = %e, "protocol error; closing connection");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
            }
        }
    }
}

/// Drains one connection's outbound queue onto its write half.
#[derive(Debug)]
pub struct FrameWriter<W> {
    conn: ConnId,
    writer: W,
    frames: mpsc::Receiver<Bytes>,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// Write frames arriving on `frames` to `writer`.
    #[must_use]
    pub fn new(conn: ConnId, writer: W, frames: mpsc::Receiver<Bytes>) -> Self {
        Self {
            conn,
            writer,
            frames,
        }
    }

    /// Write until the queue closes, then shut the socket down.
    ///
    /// The queue closing means either the peer went away or the core dropped
    /// this connection's sender to disconnect it. Either way everything already
    /// queued has been written, which is what makes
    /// [`Effect::Disconnect`](starling_api::Effect::Disconnect) a flush rather
    /// than a truncation.
    pub async fn drain(mut self) {
        while let Some(frame) = self.frames.recv().await {
            if let Err(e) = self.writer.write_all(&frame).await {
                debug!(conn = %self.conn, error = %e, "write failed");
                break;
            }
        }
        let _ = self.writer.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto::proto::tcp;
    use starling_proto::ControlMessage;

    use starling_api::ServerConfig;

    fn ping(timestamp: u64) -> Bytes {
        codec::encode(&ControlMessage::Ping(tcp::Ping {
            timestamp: Some(timestamp),
            ..Default::default()
        }))
    }

    /// An [`AudioSink`] that records what the demultiplexer sent it.
    #[derive(Debug, Default)]
    struct RecordedAudio {
        frames: std::sync::Mutex<Vec<Bytes>>,
    }

    impl AudioSink for RecordedAudio {
        fn deliver(&self, _from: AudioSource, frame: Bytes) {
            if let Ok(mut frames) = self.frames.lock() {
                frames.push(frame);
            }
        }
    }

    impl RecordedAudio {
        fn all(&self) -> Vec<Bytes> {
            self.frames
                .lock()
                .map(|frames| frames.clone())
                .unwrap_or_default()
        }
    }

    /// Read `bytes` as if they arrived on a socket, discarding any audio.
    async fn read(bytes: Vec<u8>) -> io::Result<()> {
        read_with(bytes, Arc::new(RecordedAudio::default())).await
    }

    /// Read `bytes`, sending any tunnelled audio to `audio`.
    async fn read_with(bytes: Vec<u8>, audio: Arc<RecordedAudio>) -> io::Result<()> {
        let (_core, handle) = ServerCore::new(ServerConfig::default());
        FrameReader::new(ConnId(1), io::Cursor::new(bytes), audio)
            .pump(&handle)
            .await
    }

    /// One `UDPTunnel` frame carrying `payload`.
    fn tunnelled(payload: &[u8]) -> Bytes {
        codec::encode(&ControlMessage::UdpTunnel(Bytes::copy_from_slice(payload)))
    }

    #[tokio::test]
    async fn tunnelled_audio_goes_to_the_audio_sink() {
        // The demultiplex, in one assertion: this frame must not reach the
        // state actor, because audio behind that queue is audio that arrives
        // late (`crates/kernel/bus/RESULTS.md` §3.3).
        let audio = Arc::new(RecordedAudio::default());
        assert!(
            read_with(tunnelled(b"an audio frame").to_vec(), Arc::clone(&audio))
                .await
                .is_ok()
        );

        assert_eq!(audio.all(), vec![Bytes::from_static(b"an audio frame")]);
    }

    #[tokio::test]
    async fn the_tunnelled_payload_is_passed_through_untouched() {
        // The reader must never look inside: parsing by content is the routing
        // layer's job, and this one only knows which transport carried it.
        let payload: Vec<u8> = (0..=255_u8).collect();
        let audio = Arc::new(RecordedAudio::default());
        assert!(read_with(tunnelled(&payload).to_vec(), Arc::clone(&audio))
            .await
            .is_ok());
        assert_eq!(audio.all()[0], Bytes::from(payload));
    }

    #[tokio::test]
    async fn control_messages_do_not_go_to_the_audio_sink() {
        // The other half of the split, and the one a careless `match` breaks.
        let audio = Arc::new(RecordedAudio::default());
        assert!(read_with(ping(1).to_vec(), Arc::clone(&audio))
            .await
            .is_ok());
        assert!(audio.all().is_empty());
    }

    #[tokio::test]
    async fn audio_and_control_interleaved_are_each_routed() {
        // What a real connection looks like: pings and audio in one stream.
        let mut bytes = ping(1).to_vec();
        bytes.extend_from_slice(&tunnelled(b"frame one"));
        bytes.extend_from_slice(&ping(2));
        bytes.extend_from_slice(&tunnelled(b"frame two"));

        let audio = Arc::new(RecordedAudio::default());
        assert!(read_with(bytes, Arc::clone(&audio)).await.is_ok());
        assert_eq!(
            audio.all(),
            vec![
                Bytes::from_static(b"frame one"),
                Bytes::from_static(b"frame two")
            ]
        );
    }

    #[tokio::test]
    async fn an_empty_tunnel_frame_is_still_delivered() {
        // The voice service decides what is too short. Filtering here would be
        // a protocol decision this layer cannot see enough to make.
        let audio = Arc::new(RecordedAudio::default());
        assert!(read_with(tunnelled(b"").to_vec(), Arc::clone(&audio))
            .await
            .is_ok());
        assert_eq!(audio.all().len(), 1);
    }

    #[tokio::test]
    async fn several_frames_in_one_read_are_all_delivered() {
        // Two complete frames concatenated, as TCP coalescing produces.
        let mut bytes = ping(1).to_vec();
        bytes.extend_from_slice(&ping(2));
        assert!(read(bytes).await.is_ok());
    }

    #[tokio::test]
    async fn a_frame_split_across_reads_is_reassembled() {
        // Cursor hands out everything at once, but the decoder still has to cope
        // with a partial buffer on the first pass through the inner loop.
        assert!(read(ping(7).to_vec()).await.is_ok());
    }

    #[tokio::test]
    async fn a_truncated_frame_at_eof_is_a_clean_close_not_an_error() {
        let frame = ping(7);
        let truncated = frame[..frame.len() - 2].to_vec();
        // EOF mid-frame is how every normal disconnect looks; treating it as a
        // protocol error would fill the logs with false alarms.
        assert!(read(truncated).await.is_ok());
    }

    #[tokio::test]
    async fn an_oversized_length_header_closes_the_connection() {
        // type=TextMessage, length = MAX + 1.
        let mut bytes = vec![0x00, 0x0B];
        bytes.extend_from_slice(&(codec::MAX_PAYLOAD_SIZE + 1).to_be_bytes());

        let err = read(bytes)
            .await
            .expect_err("an oversized frame must close the connection");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn malformed_protobuf_closes_the_connection_without_panicking() {
        let mut bytes = vec![0x00, 0x02]; // Authenticate
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&[0x0A, 0xFF, 0x01]);
        assert!(read(bytes).await.is_err());
    }

    #[tokio::test]
    async fn a_writer_flushes_what_is_queued_before_the_socket_closes() {
        let (tx, rx) = mpsc::channel(4);
        let sink = Vec::new();
        tx.send(ping(1)).await.expect("queue accepts a frame");
        drop(tx); // as the core does to disconnect a peer

        FrameWriter::new(ConnId(1), sink, rx).drain().await;
    }
}
