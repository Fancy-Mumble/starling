//! The write half of a connection, as the core sees it.

use bytes::Bytes;
use starling_api::{FrameSink, Stuck};
use tokio::sync::mpsc;

/// A connection's outbound queue over a `tokio` channel.
///
/// A newtype over the sender so no `tokio` type reaches [`FrameSink`]'s
/// signature: swapping the runtime touches this file only.
///
/// Dropping a `ConnectionSink` closes the channel, which is exactly how
/// "flush, then disconnect" is implemented — the write task drains what is
/// already queued, sees the channel close, and shuts the socket down.
#[derive(Debug)]
pub struct ConnectionSink(mpsc::Sender<Bytes>);

impl ConnectionSink {
    /// Wrap a connection's outbound queue.
    #[must_use]
    pub fn new(sender: mpsc::Sender<Bytes>) -> Self {
        Self(sender)
    }
}

impl FrameSink for ConnectionSink {
    fn try_send(&self, frame: Bytes) -> Result<(), Stuck> {
        self.0.try_send(frame).map_err(|_| Stuck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sink_reports_failure_when_its_queue_is_full() {
        let (tx, _rx) = mpsc::channel(1);
        let sink = ConnectionSink::new(tx);
        assert!(sink.try_send(Bytes::from_static(b"first")).is_ok());
        assert_eq!(
            sink.try_send(Bytes::from_static(b"second")),
            Err(Stuck),
            "a full queue must report failure rather than block"
        );
    }

    #[test]
    fn a_sink_reports_failure_once_the_reader_is_gone() {
        let (tx, rx) = mpsc::channel(4);
        drop(rx);
        assert_eq!(
            ConnectionSink::new(tx).try_send(Bytes::from_static(b"x")),
            Err(Stuck)
        );
    }

    #[test]
    fn dropping_a_sink_closes_the_queue_for_the_write_task() {
        // This is the mechanism behind Outbound::disconnect's flush-then-close.
        let (tx, mut rx) = mpsc::channel(4);
        let sink = ConnectionSink::new(tx);
        assert!(sink.try_send(Bytes::from_static(b"queued")).is_ok());
        drop(sink);

        assert_eq!(rx.try_recv().ok(), Some(Bytes::from_static(b"queued")));
        assert!(rx.try_recv().is_err(), "the queue should now be closed");
    }
}
