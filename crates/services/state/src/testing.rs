//! Transport doubles for this crate's tests.
//!
//! The real [`Outbound`] implementation lives in `starling-net`, and depending on
//! it here — even as a dev-dependency — would make the state service's tests
//! require the transport crate to compile. That would undo the reason the two
//! were split, and quietly contradict the claim that handlers are testable
//! without a socket.
//!
//! What the tests actually need is a **spy**: somewhere frames land so an
//! assertion can read them. These are forty lines of exactly that.

use std::collections::HashMap;

use bytes::Bytes;
use starling_api::{AudienceView, ConnId, FrameSink, Outbound, Stuck, VoiceKeying, VoiceLink};
use tokio::sync::mpsc;

/// A [`FrameSink`] that puts frames on a channel a test can drain.
///
/// Mirrors `starling-net`'s `ConnectionSink` — deliberately, so a test reads the
/// same way whichever it uses.
#[derive(Debug)]
pub(crate) struct TestSink(mpsc::Sender<Bytes>);

impl TestSink {
    /// Deliver frames to `sender`.
    pub(crate) fn new(sender: mpsc::Sender<Bytes>) -> Self {
        Self(sender)
    }
}

impl FrameSink for TestSink {
    fn try_send(&self, frame: Bytes) -> Result<(), Stuck> {
        self.0.try_send(frame).map_err(|_| Stuck)
    }
}

/// An [`Outbound`] that records where frames went.
#[derive(Debug, Default)]
pub(crate) struct TestRegistry {
    sinks: HashMap<ConnId, Box<dyn FrameSink>>,
}

impl TestRegistry {
    /// An empty registry.
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl Outbound for TestRegistry {
    fn register(&mut self, conn: ConnId, sink: Box<dyn FrameSink>) {
        let _ = self.sinks.insert(conn, sink);
    }

    fn send(&mut self, conn: ConnId, frame: Bytes) -> bool {
        // Matches the real registry's contract: an unregistered connection is a
        // no-op returning `true`, not a failure. A connection can vanish between
        // a handler producing an effect and the core applying it.
        self.sinks
            .get(&conn)
            .is_none_or(|sink| sink.try_send(frame).is_ok())
    }

    fn disconnect(&mut self, conn: ConnId) {
        // Dropping the sink closes the channel, which is how the real transport
        // implements flush-then-close.
        let _ = self.sinks.remove(&conn);
    }

    fn is_connected(&self, conn: ConnId) -> bool {
        self.sinks.contains_key(&conn)
    }
}

/// A [`VoiceLink`] that records what the authority told it.
///
/// The core's tests must be able to assert that a login keys the voice path and
/// that a disconnect republishes the view, without a voice service running —
/// which is the whole reason `VoiceLink` is a trait in `starling-api`.
#[derive(Debug, Default)]
pub(crate) struct RecordingVoice {
    attached: std::sync::Mutex<Vec<ConnId>>,
    detached: std::sync::Mutex<Vec<ConnId>>,
    published: std::sync::Mutex<Vec<AudienceView>>,
}

impl RecordingVoice {
    /// Connections given voice keys.
    pub(crate) fn attached(&self) -> Vec<ConnId> {
        self.attached.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// Connections whose voice path was removed.
    pub(crate) fn detached(&self) -> Vec<ConnId> {
        self.detached.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// Every view published, in order.
    pub(crate) fn published(&self) -> Vec<AudienceView> {
        self.published.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

/// A handle to a [`RecordingVoice`] the core also owns.
///
/// The core takes `Box<dyn VoiceLink>` by value, which is right — it owns its
/// collaborators — and leaves a test with no way to see what it was told. A
/// newtype around the shared pointer is the answer the orphan rule allows, and
/// it needs no change to the trait.
#[derive(Debug, Clone)]
pub(crate) struct SharedVoice(pub(crate) std::sync::Arc<RecordingVoice>);

impl VoiceLink for SharedVoice {
    fn connected(&self, conn: ConnId, sink: Box<dyn FrameSink>) {
        self.0.connected(conn, sink);
    }

    fn attach(&self, keying: Box<VoiceKeying>) {
        self.0.attach(keying);
    }

    fn detach(&self, conn: ConnId) {
        self.0.detach(conn);
    }

    fn publish(&self, view: Box<AudienceView>) {
        self.0.publish(view);
    }
}

impl VoiceLink for RecordingVoice {
    fn connected(&self, _conn: ConnId, _sink: Box<dyn FrameSink>) {}

    fn attach(&self, keying: Box<VoiceKeying>) {
        if let Ok(mut attached) = self.attached.lock() {
            attached.push(keying.conn);
        }
    }

    fn detach(&self, conn: ConnId) {
        if let Ok(mut detached) = self.detached.lock() {
            detached.push(conn);
        }
    }

    fn publish(&self, view: Box<AudienceView>) {
        if let Ok(mut published) = self.published.lock() {
            published.push(*view);
        }
    }
}
