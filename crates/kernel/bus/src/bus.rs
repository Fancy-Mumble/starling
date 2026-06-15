//! The routing boundary, and two implementations of it.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::envelope::{Envelope, PortId};
use crate::lane::Lane;
use crate::metrics::Metrics;
use crate::queue::{LockedQueue, MessageQueue, SendError};

/// Routes envelopes to registered ports.
///
/// **A dumb bus with smart endpoints.** An implementation looks up a
/// registration and moves bytes; it never inspects a payload. Any feature that
/// would require the bus to understand what it carries is a design error — that
/// is what stops this becoming an enterprise service bus, and it is the
/// mechanical form of the opacity rule.
///
/// # Contract
///
/// 1. **The lane comes from the registration, never from the envelope.** A
///    sender that could choose its lane could promote its traffic above the
///    control plane.
/// 2. Sending to an unregistered port fails; it is never queued somewhere
///    plausible.
/// 3. [`Self::close`] wakes every waiter on every lane.
/// 4. Payloads are delivered byte-identical.
pub trait MessageBus: Send + Sync + std::fmt::Debug {
    /// Register a port on a lane. Called by the kernel; the registrant does not
    /// choose.
    fn register(&self, port: PortId, lane: Lane);

    /// Remove a registration. Traffic to it is refused afterwards.
    fn unregister(&self, port: PortId);

    /// The lane a port is registered on, if any.
    fn lane_of(&self, port: PortId) -> Option<Lane>;

    // There is deliberately no `call(&self, env) -> Envelope`.
    //
    // An earlier note here argued one was required, because "nothing bypasses
    // the bus" seemed to mean a synchronous query — "load the channel tree",
    // "may this user text here?" — had to be a blocking round trip. It then
    // spent a paragraph on how to make that safe without priority inheritance,
    // which needs `CAP_SYS_NICE` that the deployment budget forbids.
    //
    // That was solving the wrong problem. This is a reactor: a requester posts
    // an envelope naming `Envelope::reply_to` and returns to its loop; the
    // service does the work and posts the answer back; the requester resumes on
    // it as an ordinary received message. Nothing waits, so no lane is held, no
    // thread parks, and the priority question never arises.
    //
    // Where an answer is needed *often*, it should not be a request at all —
    // it should be a published snapshot the reader consults locally, which is
    // what `Lane::Realtime` already does for routing and what permissions will
    // do. The bus carries changes, not questions.
    //
    // The reply must not travel as an ordinary lane post, or a busy lane would
    // delay every reply on it.
    //
    // Until this exists, `Lane::Feature`'s "request/reply" is a promise this
    // trait does not keep, and features cannot be written without a bypass.
    // See `docs/ARCHITECTURE.md` §6.1.

    /// Send an envelope to its registered port.
    fn send(&self, env: Envelope) -> Result<(), SendError>;

    /// Take the next envelope a consumer of `lane` should handle.
    fn take(&self, lane: Lane, timeout: Duration) -> Option<Envelope>;

    /// Counters for a lane.
    fn metrics(&self, lane: Lane) -> &dyn Metrics;

    /// Shut every lane down.
    fn close(&self);
}

/// Shared registration table used by both implementations.
#[derive(Debug, Default)]
struct Routes(RwLock<HashMap<PortId, Lane>>);

impl Routes {
    fn set(&self, port: PortId, lane: Lane) {
        if let Ok(mut r) = self.0.write() {
            let _ = r.insert(port, lane);
        }
    }
    fn clear(&self, port: PortId) {
        if let Ok(mut r) = self.0.write() {
            let _ = r.remove(&port);
        }
    }
    fn get(&self, port: PortId) -> Option<Lane> {
        self.0.read().ok()?.get(&port).copied()
    }
}

/// **The design:** one queue per lane, drained by that lane's own threads.
///
/// There is deliberately no cross-lane arbitration here. Priority comes from
/// the OS scheduling the lanes' threads — which is preemptive, where a
/// userspace picker would not be.
#[derive(Debug)]
pub struct LaneBus {
    routes: Routes,
    lanes: Vec<Arc<dyn MessageQueue>>,
}

impl Default for LaneBus {
    fn default() -> Self {
        Self::new()
    }
}

impl LaneBus {
    /// One queue per lane, at each lane's default policy.
    #[must_use]
    pub fn new() -> Self {
        Self::with_queues(
            Lane::ALL
                .iter()
                .map(|l| Arc::new(LockedQueue::new(*l)) as Arc<dyn MessageQueue>)
                .collect(),
        )
    }

    /// Build over explicit queues — the seam for a lock-free implementation.
    #[must_use]
    pub fn with_queues(lanes: Vec<Arc<dyn MessageQueue>>) -> Self {
        Self {
            routes: Routes::default(),
            lanes,
        }
    }

    /// Direct access to a lane's queue.
    #[must_use]
    pub fn queue(&self, lane: Lane) -> &Arc<dyn MessageQueue> {
        &self.lanes[lane.index()]
    }
}

impl MessageBus for LaneBus {
    fn register(&self, port: PortId, lane: Lane) {
        self.routes.set(port, lane);
    }
    fn unregister(&self, port: PortId) {
        self.routes.clear(port);
    }
    fn lane_of(&self, port: PortId) -> Option<Lane> {
        self.routes.get(port)
    }

    fn send(&self, env: Envelope) -> Result<(), SendError> {
        let lane = self.lane_of(env.to).ok_or(SendError::Closed)?;
        self.lanes[lane.index()].offer(env)
    }

    fn take(&self, lane: Lane, timeout: Duration) -> Option<Envelope> {
        self.lanes[lane.index()].take(timeout)
    }

    fn metrics(&self, lane: Lane) -> &dyn Metrics {
        self.lanes[lane.index()].metrics()
    }

    fn close(&self) {
        for q in &self.lanes {
            q.close();
        }
    }
}

/// **The control:** every lane shares one queue, drained FIFO.
///
/// This is what the design is being compared *against* — it models a bus with
/// no priority at all, where a control envelope waits behind whatever feature
/// traffic arrived first. `examples/isolation.rs` measures the difference.
///
/// It is also a genuine second implementation, which is what earns
/// [`MessageBus`] its keep as a trait.
#[derive(Debug)]
pub struct SharedQueueBus {
    routes: Routes,
    queue: Arc<dyn MessageQueue>,
}

impl Default for SharedQueueBus {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedQueueBus {
    /// One queue for everything, sized to the **sum of the lane capacities** so
    /// the comparison against [`LaneBus`] measures topology rather than a
    /// difference in total buffering.
    #[must_use]
    pub fn new() -> Self {
        let capacity: usize = Lane::ALL.iter().map(|l| l.default_capacity()).sum();
        Self::with_capacity(capacity)
    }

    /// One queue of an explicit size.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            routes: Routes::default(),
            queue: Arc::new(LockedQueue::with_policy(
                Lane::Control,
                capacity,
                crate::lane::Overflow::Reject,
            )),
        }
    }
}

impl MessageBus for SharedQueueBus {
    fn register(&self, port: PortId, lane: Lane) {
        self.routes.set(port, lane);
    }
    fn unregister(&self, port: PortId) {
        self.routes.clear(port);
    }
    fn lane_of(&self, port: PortId) -> Option<Lane> {
        self.routes.get(port)
    }

    fn send(&self, env: Envelope) -> Result<(), SendError> {
        // Registration is still checked — only the *routing* is flattened.
        let _ = self.lane_of(env.to).ok_or(SendError::Closed)?;
        self.queue.offer(env)
    }

    /// Ignores `lane`: a single-queue consumer takes whatever is next, which is
    /// exactly the behaviour being measured.
    fn take(&self, _lane: Lane, timeout: Duration) -> Option<Envelope> {
        self.queue.take(timeout)
    }

    fn metrics(&self, _lane: Lane) -> &dyn Metrics {
        self.queue.metrics()
    }

    fn close(&self) {
        self.queue.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(50);

    /// The [`MessageBus`] contract, asserted against any implementation.
    fn assert_bus_contract(bus: &dyn MessageBus) {
        let port = PortId(1);

        // 2. unregistered ports are refused, not queued somewhere plausible.
        assert_eq!(
            bus.send(Envelope::new(port, vec![1])),
            Err(SendError::Closed)
        );

        bus.register(port, Lane::Control);
        assert_eq!(bus.lane_of(port), Some(Lane::Control));

        // 4. payloads survive verbatim.
        bus.send(Envelope::new(port, vec![0xDE, 0xAD]))
            .expect("routed");
        assert_eq!(
            bus.take(Lane::Control, SHORT).map(|e| e.payload.to_vec()),
            Some(vec![0xDE, 0xAD])
        );

        bus.unregister(port);
        assert_eq!(bus.lane_of(port), None);
        assert!(bus.send(Envelope::new(port, vec![1])).is_err());

        // 3. close refuses further traffic.
        bus.register(port, Lane::Control);
        bus.close();
        assert_eq!(
            bus.send(Envelope::new(port, vec![1])),
            Err(SendError::Closed)
        );
    }

    #[test]
    fn the_lane_bus_satisfies_the_contract() {
        assert_bus_contract(&LaneBus::new());
    }

    #[test]
    fn the_shared_queue_bus_satisfies_the_contract() {
        assert_bus_contract(&SharedQueueBus::new());
    }

    #[test]
    fn the_sender_cannot_choose_the_lane() {
        // Contract rule 1, and the security property the type exists for: an
        // envelope carries no lane, so a feature cannot promote itself.
        let bus = LaneBus::new();
        bus.register(PortId(1), Lane::Feature);
        bus.send(Envelope::new(PortId(1), vec![1])).expect("routed");

        assert!(bus.take(Lane::Realtime, Duration::from_millis(5)).is_none());
        assert!(bus.take(Lane::Control, Duration::from_millis(5)).is_none());
        assert!(bus.take(Lane::Feature, SHORT).is_some());
    }

    #[test]
    fn lane_bus_keeps_lanes_independent() {
        let bus = LaneBus::new();
        bus.register(PortId(1), Lane::Control);
        bus.register(PortId(2), Lane::Feature);

        bus.send(Envelope::new(PortId(2), vec![2])).expect("routed");
        bus.send(Envelope::new(PortId(1), vec![1])).expect("routed");

        // Control drains without touching the feature backlog.
        assert_eq!(
            bus.take(Lane::Control, SHORT).map(|e| e.payload[0]),
            Some(1)
        );
        assert_eq!(bus.queue(Lane::Feature).depth(), 1);
    }

    #[test]
    fn shared_queue_bus_makes_control_wait_behind_feature_traffic() {
        // The behaviour being measured: with one queue, ordering is arrival
        // order and priority does not exist.
        let bus = SharedQueueBus::new();
        bus.register(PortId(1), Lane::Control);
        bus.register(PortId(2), Lane::Feature);

        bus.send(Envelope::new(PortId(2), vec![2])).expect("routed");
        bus.send(Envelope::new(PortId(1), vec![1])).expect("routed");

        assert_eq!(
            bus.take(Lane::Control, SHORT).map(|e| e.payload[0]),
            Some(2),
            "the feature envelope arrived first, so it comes out first"
        );
    }

    #[test]
    fn re_registering_moves_a_port_between_lanes() {
        let bus = LaneBus::new();
        bus.register(PortId(1), Lane::Feature);
        bus.register(PortId(1), Lane::Control);
        assert_eq!(bus.lane_of(PortId(1)), Some(Lane::Control));
    }

    #[test]
    fn buses_are_usable_behind_a_trait_object() {
        let buses: Vec<Box<dyn MessageBus>> =
            vec![Box::new(LaneBus::new()), Box::new(SharedQueueBus::new())];
        for bus in &buses {
            bus.register(PortId(1), Lane::Control);
            assert!(bus.send(Envelope::new(PortId(1), vec![1])).is_ok());
        }
    }
}
