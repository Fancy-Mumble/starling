//! Delivering encoded frames to a peer.
//!
//! The contract only. `starling-net` implements it over TCP; the state service
//! consumes it and never learns which transport it holds.
//!
//! Splitting the trait from the implementation is what let transport move out of
//! the state service: the consumer keeps the abstraction, the transport crate
//! takes the concretion, and neither depends on the other.

use bytes::Bytes;

use crate::effects::ConnId;

/// Somewhere an encoded frame can be delivered.
///
/// `Sync` as well as `Send` because the voice service holds one per peer behind
/// a shared handle. Every implementation is a channel sender, which is already
/// `Sync`; the bound just says so.
///
/// The abstraction [`Outbound`] registers, so that it names a
/// *destination* rather than a channel. `ConnectionSink` in `starling-net` is the TCP
/// implementation; Phase 1's UDP path and Phase 6's gRPC path are others, and
/// neither is mpsc-shaped. Before this trait existed, `Outbound::register` took
/// a `ConnectionSink` concretely — an abstraction depending on a concretion,
/// which would have forced every future transport through a channel.
pub trait FrameSink: std::fmt::Debug + Send + Sync {
    /// Try to queue a frame without blocking.
    ///
    /// Never awaits: backpressure from one slow client must not reach the single
    /// state actor.
    ///
    /// # Errors
    ///
    /// [`Stuck`] if the destination cannot accept the frame now. Returns a
    /// `Result` rather than a `bool` because `try_*` returning `Result` is the
    /// convention `tokio::sync::mpsc::Sender::try_send` — which this wraps —
    /// already follows.
    fn try_send(&self, frame: Bytes) -> Result<(), Stuck>;
}

/// The destination could not accept a frame.
///
/// Deliberately carries no payload: the caller's only recourse is to drop the
/// connection, and handing the frame back would invite a retry loop against a
/// peer that is already not keeping up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the connection's outbound queue is full or closed")]
pub struct Stuck;

/// Delivers already-encoded frames to connections.
///
/// # Contract
///
/// 1. [`Self::send`] must **never block**. One slow peer must not be able to
///    stall the server; an implementation that cannot accept the frame reports
///    `false` and the caller drops that connection.
/// 2. [`Self::disconnect`] must flush whatever is already queued before closing.
///    murmur sends a `Reject` and *then* closes so the user sees a reason
///    instead of a bare connection reset; anything else loses that message.
/// 3. Sending to an unregistered connection is a no-op returning `true`, not a
///    failure: a connection can legitimately vanish between a handler producing
///    an effect and the core applying it, and that must not be reported as the
///    peer being stuck.
pub trait Outbound: std::fmt::Debug {
    /// Register where a connection's frames should go.
    fn register(&mut self, conn: ConnId, sink: Box<dyn FrameSink>);

    /// Queue an encoded frame. Returns `false` only if the connection is stuck.
    fn send(&mut self, conn: ConnId, frame: Bytes) -> bool;

    /// Flush and close a connection.
    fn disconnect(&mut self, conn: ConnId);

    /// Whether a connection is still registered.
    fn is_connected(&self, conn: ConnId) -> bool;
}

/// Discards every frame (Null Object).
///
/// What `ServerCore::new` installs when no transport
/// was supplied. It used to install a TCP registry — a detail chosen
/// by the layer that should not know TCP exists, and the one edge that kept
/// transport from moving into its own crate.
///
/// A core with no transport configured should *drop* frames, not invent a
/// socket. Production never sees this: the composition root passes a real
/// [`Outbound`] to
/// `ServerCore::with_parts`.
#[derive(Debug, Default)]
pub struct NoOutbound;

impl Outbound for NoOutbound {
    fn register(&mut self, _conn: ConnId, _sink: Box<dyn FrameSink>) {}

    fn send(&mut self, _conn: ConnId, _frame: Bytes) -> bool {
        // Not "stuck" — there is simply nowhere to deliver. Reporting failure
        // would make the core disconnect a peer for the absence of a transport.
        true
    }

    fn disconnect(&mut self, _conn: ConnId) {}

    fn is_connected(&self, _conn: ConnId) -> bool {
        false
    }
}
