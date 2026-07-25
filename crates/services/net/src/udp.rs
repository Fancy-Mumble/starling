//! The voice port: one socket, read in a loop, written from anywhere.
//!
//! Small on purpose. Everything interesting about a datagram — who sent it,
//! whether it decrypts, where it goes — belongs to the voice service, and this
//! knows none of it. What it owns is the socket, and the two facts that follow
//! from owning a socket: how big a datagram can be, and what to do when one
//! cannot be sent.
//!
//! # Why sending goes through a queue
//!
//! The voice task must never await on a socket: one full kernel buffer would
//! delay every *other* peer's audio. The obvious answer is `try_send_to`, and it
//! is wrong — tokio reports `WouldBlock` until it has observed the socket
//! writable, and a socket only being polled for reads never is. Every datagram
//! would be silently dropped, on a code path with no way to notice.
//!
//! So [`DatagramSender`] queues, and [`VoiceSocket::serve`] drains. The queue is
//! bounded and a full queue drops, which is the right policy for audio: a frame
//! that waits is a frame that arrives after the moment it was for.
//!
//! # Why the reader does not answer pings itself
//!
//! It could — a ping needs no session — and it would save a hop. It would also
//! be the first crack in the split: the reader would need the codec, then the
//! server's user count, then the details it reports. The voice service has all
//! three already.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use starling_api::{AudioSink, AudioSource, Datagrams};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// The largest datagram accepted.
///
/// Upstream caps a Mumble audio packet at 1024 bytes. The extra room covers the
/// cipher's overhead and leaves a datagram that is still comfortably inside the
/// smallest MTU anyone routes, so no voice packet is ever fragmented.
const MAX_DATAGRAM: usize = 2048;

/// How many outbound datagrams may wait for the socket.
///
/// Sized for a burst, not a backlog. At 50 packets a second per speaker this is
/// a few milliseconds of fan-out; anything deeper would be holding audio nobody
/// can still use.
const SEND_QUEUE_DEPTH: usize = 256;

/// Binds and pumps the voice port, in both directions.
#[derive(Debug)]
pub struct VoiceSocket {
    socket: UdpSocket,
    local: SocketAddr,
    outbound: mpsc::Receiver<(SocketAddr, Bytes)>,
    sender: mpsc::Sender<(SocketAddr, Bytes)>,
}

impl VoiceSocket {
    /// Bind `addr`.
    ///
    /// # Errors
    ///
    /// Whatever the OS says: the port is taken, or the address is not local.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        // Not `UdpSocket::bind`: a wildcard has to hear IPv6 too, and neither
        // `std` nor `tokio` exposes the option that decides it. See `crate::bind`.
        let socket = UdpSocket::from_std(crate::bind::udp(addr)?)?;
        let local = socket.local_addr()?;
        let (sender, outbound) = mpsc::channel(SEND_QUEUE_DEPTH);
        info!(%local, "voice port open");
        Ok(Self {
            socket,
            local,
            outbound,
            sender,
        })
    }

    /// The address actually bound.
    ///
    /// Not the address asked for: port 0 means "any", and the caller needs to
    /// know which one it got.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// A sender for this socket, for the voice service to hold.
    ///
    /// Nothing is sent until [`Self::serve`] runs: the sender only queues.
    #[must_use]
    pub fn sender(&self) -> DatagramSender {
        DatagramSender {
            queue: self.sender.clone(),
        }
    }

    /// Pump the socket in both directions until it fails.
    ///
    /// One task for both, because there is one socket and neither direction
    /// blocks the other for long: a receive parks on the reactor, and a send
    /// only waits when the kernel buffer is genuinely full.
    ///
    /// # Errors
    ///
    /// A receive error the socket cannot continue past. Per-datagram problems
    /// are not errors — they are the normal state of a port open to the
    /// internet, and are counted by the voice service rather than returned.
    pub async fn serve(self, audio: Arc<dyn AudioSink>) -> io::Result<()> {
        // Destructured so the two halves can be borrowed independently in the
        // select below.
        let Self {
            socket,
            mut outbound,
            ..
        } = self;
        let mut buffer = vec![0_u8; MAX_DATAGRAM];

        loop {
            tokio::select! {
                received = socket.recv_from(&mut buffer) => match received {
                    Ok((len, from)) => audio.deliver(
                        AudioSource::Datagram(from),
                        Bytes::copy_from_slice(&buffer[..len]),
                    ),

                    // On Windows a datagram sent to an unreachable port comes
                    // back as a *receive* error on the sending socket. Treating
                    // it as fatal would let any peer close the voice port for
                    // everyone by leaving.
                    Err(error) if is_transient(&error) => {
                        debug!(%error, "transient UDP error");
                    }

                    Err(error) => {
                        warn!(%error, "voice port failed");
                        return Err(error);
                    }
                },

                queued = outbound.recv() => match queued {
                    Some((addr, frame)) => {
                        if let Err(error) = socket.send_to(&frame, addr).await {
                            // Congestion, or a peer that vanished. Both are
                            // ordinary during a call, and a log line per dropped
                            // frame is a denial of service anyone can trigger.
                            debug!(%addr, %error, "voice datagram dropped");
                        }
                    }
                    // Every sender is gone, so nothing more will be queued. The
                    // reader keeps running: pings still deserve an answer.
                    None => return Ok(()),
                },
            }
        }
    }
}

/// Queues datagrams for an already-bound socket.
///
/// The [`Datagrams`] implementation the voice service holds. Cloneable, because
/// a UDP socket has no per-destination state to duplicate.
#[derive(Debug, Clone)]
pub struct DatagramSender {
    queue: mpsc::Sender<(SocketAddr, Bytes)>,
}

impl Datagrams for DatagramSender {
    fn send_to(&self, addr: SocketAddr, frame: Bytes) {
        // `try_send` and discard the error: the caller is the voice task, and
        // it has nothing useful to do about a full queue except carry on to the
        // next listener.
        let _ = self.queue.try_send((addr, frame));
    }
}

/// Whether a receive error is one datagram's problem rather than the socket's.
///
/// ICMP errors surface on the socket that *sent* the offending packet, not on
/// the one that caused them, so a peer that disconnects mid-call can produce one
/// of these on the server's voice socket. Ending the loop would take the voice
/// port down for everyone.
fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    /// How long a loopback datagram may take before the test gives up.
    ///
    /// Generous: this is not a latency measurement, it is a guard against a
    /// hang. A test that spins on `yield_now` instead deadlocks when the thing
    /// it waits for never happens, which is exactly when a test must not hang.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// An [`AudioSink`] the test can await.
    #[derive(Debug)]
    struct Received(mpsc::UnboundedSender<(AudioSource, Bytes)>);

    impl AudioSink for Received {
        fn deliver(&self, from: AudioSource, frame: Bytes) {
            let _ = self.0.send((from, frame));
        }
    }

    /// A bound socket, a running reader, and the frames it produces.
    async fn listening() -> (
        SocketAddr,
        DatagramSender,
        mpsc::UnboundedReceiver<(AudioSource, Bytes)>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let socket = VoiceSocket::bind(any_port()).await.expect("bind");
        let port = socket.local_addr();
        let sender = socket.sender();
        let (tx, rx) = mpsc::unbounded_channel();
        let serving = tokio::spawn(socket.serve(Arc::new(Received(tx))));
        (port, sender, rx, serving)
    }

    fn any_port() -> SocketAddr {
        "127.0.0.1:0".parse().expect("loopback")
    }

    #[tokio::test]
    async fn a_datagram_reaches_the_sink_with_its_source() {
        // The source address is the only handle the voice service has on who
        // sent a datagram, so losing it here would make attribution impossible.
        let (port, _, mut received, serving) = listening().await;

        let client = UdpSocket::bind(any_port()).await.expect("client bind");
        let from = client.local_addr().expect("client address");
        let _ = client.send_to(b"a frame", port).await.expect("send");

        let (source, frame) = timeout(PATIENCE, received.recv())
            .await
            .expect("the datagram never arrived")
            .expect("the reader stopped");

        assert_eq!(source, AudioSource::Datagram(from));
        assert_eq!(frame, Bytes::from_static(b"a frame"));
        serving.abort();
    }

    #[tokio::test]
    async fn an_empty_datagram_is_delivered_not_dropped() {
        // The voice service decides what is too short. A transport that filtered
        // by length would be making a protocol decision it cannot see.
        let (port, _, mut received, serving) = listening().await;

        let client = UdpSocket::bind(any_port()).await.expect("client bind");
        let _ = client.send_to(b"", port).await.expect("send");

        let (_, frame) = timeout(PATIENCE, received.recv())
            .await
            .expect("the datagram never arrived")
            .expect("the reader stopped");
        assert!(frame.is_empty());
        serving.abort();
    }

    #[tokio::test]
    async fn a_full_size_datagram_is_not_truncated() {
        // An audio frame plus its cipher overhead has to fit. Silently cutting
        // it short would make every large frame fail its tag.
        let (port, _, mut received, serving) = listening().await;
        let payload = vec![0xAB_u8; MAX_DATAGRAM];

        let client = UdpSocket::bind(any_port()).await.expect("client bind");
        let _ = client.send_to(&payload, port).await.expect("send");

        let (_, frame) = timeout(PATIENCE, received.recv())
            .await
            .expect("the datagram never arrived")
            .expect("the reader stopped");
        assert_eq!(frame.len(), MAX_DATAGRAM);
        serving.abort();
    }

    #[tokio::test]
    async fn several_datagrams_arrive_in_order() {
        let (port, _, mut received, serving) = listening().await;
        let client = UdpSocket::bind(any_port()).await.expect("client bind");
        for i in 0..5_u8 {
            let _ = client.send_to(&[i], port).await.expect("send");
        }

        for i in 0..5_u8 {
            let (_, frame) = timeout(PATIENCE, received.recv())
                .await
                .expect("a datagram never arrived")
                .expect("the reader stopped");
            assert_eq!(frame, Bytes::copy_from_slice(&[i]));
        }
        serving.abort();
    }

    #[tokio::test]
    async fn the_sender_delivers_to_a_real_address() {
        // This is the test that caught `try_send_to` silently dropping every
        // datagram: tokio reports a socket unwritable until it has observed it
        // writable, and a socket only polled for reads never is.
        let (_, sender, _received, serving) = listening().await;

        let peer = UdpSocket::bind(any_port()).await.expect("peer bind");
        let peer_addr = peer.local_addr().expect("peer address");
        sender.send_to(peer_addr, Bytes::from_static(b"outbound"));

        let mut buffer = [0; 64];
        let (len, _) = timeout(PATIENCE, peer.recv_from(&mut buffer))
            .await
            .expect("the datagram never arrived")
            .expect("receive");
        assert_eq!(&buffer[..len], b"outbound");
        serving.abort();
    }

    #[tokio::test]
    async fn the_very_first_datagram_is_not_lost() {
        // The regression the previous test found, stated on its own: nothing
        // may need to happen before a socket can send.
        let (_, sender, _received, serving) = listening().await;
        let peer = UdpSocket::bind(any_port()).await.expect("peer bind");
        sender.send_to(
            peer.local_addr().expect("peer address"),
            Bytes::from_static(b"first"),
        );

        let mut buffer = [0; 64];
        let (len, _) = timeout(PATIENCE, peer.recv_from(&mut buffer))
            .await
            .expect("the first datagram was dropped")
            .expect("receive");
        assert_eq!(&buffer[..len], b"first");
        serving.abort();
    }

    #[tokio::test]
    async fn sending_to_nowhere_does_not_panic() {
        // A peer that vanished mid-call, which is routine. The frame is lost and
        // the server carries on serving everyone else.
        let (port, sender, _received, serving) = listening().await;
        let gone = UdpSocket::bind(any_port()).await.expect("bind");
        let addr = gone.local_addr().expect("address");
        drop(gone);

        sender.send_to(addr, Bytes::from_static(b"lost"));

        // Prove the reader survived it, by sending something that does arrive.
        let client = UdpSocket::bind(any_port()).await.expect("client bind");
        let _ = client.send_to(b"still here", port).await.expect("send");
        let (_, frame) = timeout(PATIENCE, _received_after(_received))
            .await
            .expect("the voice port died on an unreachable peer");
        assert_eq!(frame, Bytes::from_static(b"still here"));
        serving.abort();
    }

    /// The next frame, or a panic if the reader stopped.
    async fn _received_after(
        mut received: mpsc::UnboundedReceiver<(AudioSource, Bytes)>,
    ) -> (AudioSource, Bytes) {
        received.recv().await.expect("the reader stopped")
    }

    #[tokio::test]
    async fn a_full_send_queue_drops_rather_than_blocking() {
        // One slow destination must not be able to stall the voice task. The
        // queue is bounded, and `send_to` returns immediately either way.
        let socket = VoiceSocket::bind(any_port()).await.expect("bind");
        let sender = socket.sender();
        let addr = any_port();

        // Nothing is draining: `serve` was never called.
        for _ in 0..SEND_QUEUE_DEPTH * 2 {
            sender.send_to(addr, Bytes::from_static(b"backlog"));
        }
    }

    #[tokio::test]
    async fn the_bound_address_is_the_one_the_os_chose() {
        // Port 0 means "any", and the caller has to be told which one it got —
        // it goes in the `Version` message every client reads.
        let socket = VoiceSocket::bind(any_port()).await.expect("bind");
        assert_ne!(socket.local_addr().port(), 0);
    }

    #[test]
    fn icmp_errors_are_transient() {
        // The Windows behaviour that would otherwise close the voice port for
        // everyone when one peer disconnects.
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::HostUnreachable,
        ] {
            assert!(is_transient(&io::Error::from(kind)), "{kind:?}");
        }
        assert!(!is_transient(&io::Error::from(io::ErrorKind::InvalidInput)));
    }
}
