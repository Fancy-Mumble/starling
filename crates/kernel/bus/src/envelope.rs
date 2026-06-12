//! What travels on the bus.

use std::time::Instant;

use bytes::Bytes;

/// A registered endpoint. Opaque to senders — you address a port, and the bus
/// decides which lane and which receiver that means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortId(pub u32);

impl std::fmt::Display for PortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "port:{}", self.0)
    }
}

/// One routed message.
///
/// # Why this is a struct and not a trait
///
/// It is a value, not a collaborator. A `dyn Envelope` would mean boxing every
/// message and a virtual call to reach the payload, on the hot path, to buy
/// variation that does not exist — the only thing that plausibly varies is the
/// payload representation, and that is what [`Bytes`] already abstracts.
///
/// When bulk data needs to stay host-side (the file-server case), the extension
/// is a `Payload` **enum** — `Inline(Bytes) | Blob(BlobId)` — not a trait: a
/// closed set, pattern-matchable, no dispatch.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Where it is going.
    pub to: PortId,
    /// Opaque bytes. The bus never looks inside — **a bus that cannot parse
    /// cannot couple**, which is the mechanical form of the opacity rule.
    ///
    /// [`Bytes`] rather than `Vec<u8>` because the core encodes a broadcast once
    /// and hands every recipient a refcount clone; forcing `Vec<u8>` here would
    /// reintroduce a copy per envelope.
    pub payload: Bytes,
    /// When it entered the bus, for queue-wait measurement.
    pub enqueued_at: Instant,
}

impl Envelope {
    /// Address an envelope to a port.
    #[must_use]
    pub fn new(to: PortId, payload: impl Into<Bytes>) -> Self {
        Self {
            to,
            payload: payload.into(),
            enqueued_at: Instant::now(),
        }
    }

    /// How long this envelope has waited in the bus so far.
    #[must_use]
    pub fn waited(&self) -> std::time::Duration {
        self.enqueued_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_records_when_it_entered_the_bus() {
        let env = Envelope::new(PortId(1), vec![1, 2, 3]);
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(env.waited() >= std::time::Duration::from_millis(2));
    }

    #[test]
    fn the_payload_is_carried_verbatim() {
        // The bus must never transform what it routes.
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            Envelope::new(PortId(1), payload.clone()).payload.as_ref(),
            payload.as_slice()
        );
    }

    #[test]
    fn cloning_an_envelope_shares_the_payload_rather_than_copying_it() {
        // The property `Bytes` is here for: fan-out clones a refcount.
        let env = Envelope::new(PortId(1), vec![0u8; 4096]);
        let copy = env.clone();
        assert_eq!(copy.payload.as_ptr(), env.payload.as_ptr());
    }

    #[test]
    fn ports_display_readably_for_logs() {
        assert_eq!(PortId(7).to_string(), "port:7");
    }
}
