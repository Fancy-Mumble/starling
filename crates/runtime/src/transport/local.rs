//! The connection wrapper every transport hands to tonic.
//!
//! tonic ships a TCP listener and nothing else, because everything else is a
//! deployment question. Each transport therefore supplies the small amount of
//! glue tonic asks for on the server side: a type implementing [`Connected`].

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tonic::transport::server::Connected;

use super::{BoxedIo, Io};

/// A byte stream tonic will accept as a server connection.
///
/// The wrapper exists only to carry [`Connected`]; every read and write is
/// delegated. `ConnectInfo` is `()` because neither a Unix socket nor an
/// in-memory pipe has a peer address worth reporting, the peer is the same
/// host by construction, and inventing one would put a fake into a log.
#[derive(Debug)]
pub struct LocalStream<T>(T);

impl<T> LocalStream<T> {
    /// Wrap a stream so tonic will serve over it.
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: Io> LocalStream<T> {
    /// Forget which transport produced this connection.
    ///
    /// tonic serves one stream type per call, so the transports have to agree
    /// on one. Erasing here rather than making each transport's listener type
    /// visible is what keeps [`super::Transport`] object-safe, and since the
    /// wrapper is already pure delegation it costs one vtable hop per read,
    /// and nothing per byte.
    #[must_use]
    pub fn erase(self) -> LocalStream<BoxedIo> {
        LocalStream(Box::new(self.0))
    }
}

impl<T> Connected for LocalStream<T> {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl<T: AsyncRead + Unpin> AsyncRead for LocalStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for LocalStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// An in-memory connection, as served.
pub type InProcessStream = LocalStream<DuplexStream>;

/// How much a single in-memory connection buffers before the writer waits.
///
/// The pipe is the transport under `--all-in-one`, so this is the analogue of a
/// socket buffer: too small costs a wake-up per frame, and unbounded would make
/// a slow reader a memory leak rather than backpressure.
pub const IN_PROCESS_BUFFER: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_wrapped_stream_still_carries_bytes_in_both_directions() {
        // The wrapper is pure delegation; a bug here would look like a hung
        // service under --all-in-one and nowhere else.
        let (client, server) = tokio::io::duplex(IN_PROCESS_BUFFER);
        let mut client = LocalStream::new(client);
        let mut server = LocalStream::new(server);

        client.write_all(b"ping").await.expect("write");
        let mut buf = [0_u8; 4];
        let _ = server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.expect("write back");
        let _ = client.read_exact(&mut buf).await.expect("read back");
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn an_erased_stream_still_carries_bytes() {
        // Erasure is what lets three transports share one serve call; if it
        // broke, every transport would break at once and identically.
        let (client, server) = tokio::io::duplex(IN_PROCESS_BUFFER);
        let mut client = LocalStream::new(client);
        let mut server = LocalStream::new(server).erase();

        client.write_all(b"ping").await.expect("write");
        let mut buf = [0_u8; 4];
        let _ = server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
    }
}
