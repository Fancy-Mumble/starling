//! The lane-queue boundary, and the queue Phase 0 ships.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::envelope::Envelope;
use crate::lane::{Lane, Overflow};
use crate::metrics::{AtomicMetrics, Metrics};

/// Why a send did not land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The lane was full and its policy is [`Overflow::Reject`].
    LaneFull,
    /// The lane was full and its policy is [`Overflow::DisconnectPeer`] — the
    /// caller should close the originating connection.
    DisconnectPeer,
    /// The bus is shutting down, or the port is not registered.
    Closed,
}

/// A bounded queue for one lane.
///
/// # Contract
///
/// 1. **FIFO**, except where [`Overflow::DropOldest`] discards from the front.
/// 2. [`Self::offer`] applies the lane's overflow policy and never blocks —
///    *except* under [`Overflow::BlockProducer`], which is the one policy that
///    is allowed to park the caller.
/// 3. [`Self::take`] returns `None` on timeout or shutdown, never blocks
///    forever.
/// 4. [`Self::close`] wakes **every** waiter, both producers and consumers.
///    A blocked producer that is never woken deadlocks shutdown.
/// 5. Every accept, drop, rejection and block is counted. Silent loss is what
///    makes a queue untrustworthy.
pub trait MessageQueue: Send + Sync + std::fmt::Debug {
    /// Which lane this queue serves.
    fn lane(&self) -> Lane;

    /// Offer an envelope, applying the lane's overflow policy.
    fn offer(&self, env: Envelope) -> Result<(), SendError>;

    /// Take the next envelope, waiting up to `timeout`.
    fn take(&self, timeout: Duration) -> Option<Envelope>;

    /// How many envelopes are queued right now.
    fn depth(&self) -> usize;

    /// Counters for this lane.
    fn metrics(&self) -> &dyn Metrics;

    /// Wake every waiter and refuse further traffic.
    fn close(&self);
}

/// The queue Phase 0 ships: `Mutex<VecDeque>` plus two condvars.
///
/// Chosen because it expresses all four overflow policies uniformly and
/// correctly. It is deliberately the *simple* implementation — a lock-free MPMC
/// alternative can be dropped in behind [`MessageQueue`] if measurement shows
/// the lock is the bottleneck, without touching a caller.
#[derive(Debug)]
pub struct LockedQueue {
    lane: Lane,
    capacity: usize,
    overflow: Overflow,
    inner: Mutex<Inner>,
    ready: Condvar,
    space: Condvar,
    metrics: Arc<dyn Metrics>,
}

#[derive(Debug)]
struct Inner {
    queue: VecDeque<Envelope>,
    closed: bool,
}

impl LockedQueue {
    /// A queue with the lane's default capacity and policy.
    #[must_use]
    pub fn new(lane: Lane) -> Self {
        Self::with_policy(lane, lane.default_capacity(), lane.default_overflow())
    }

    /// A queue with an explicit capacity and policy, for tests and tuning.
    #[must_use]
    pub fn with_policy(lane: Lane, capacity: usize, overflow: Overflow) -> Self {
        Self::with_metrics(lane, capacity, overflow, Arc::new(AtomicMetrics::default()))
    }

    /// A queue recording into an explicit [`Metrics`] implementation.
    #[must_use]
    pub fn with_metrics(
        lane: Lane,
        capacity: usize,
        overflow: Overflow,
        metrics: Arc<dyn Metrics>,
    ) -> Self {
        Self {
            lane,
            capacity: capacity.max(1),
            overflow,
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                closed: false,
            }),
            ready: Condvar::new(),
            space: Condvar::new(),
            metrics,
        }
    }
}

impl MessageQueue for LockedQueue {
    fn lane(&self) -> Lane {
        self.lane
    }

    fn offer(&self, env: Envelope) -> Result<(), SendError> {
        let Ok(mut inner) = self.inner.lock() else {
            return Err(SendError::Closed);
        };
        if inner.closed {
            return Err(SendError::Closed);
        }

        if inner.queue.len() >= self.capacity {
            match self.overflow {
                Overflow::DropOldest => {
                    let _ = inner.queue.pop_front();
                    self.metrics.dropped();
                }
                Overflow::Reject => {
                    self.metrics.rejected();
                    return Err(SendError::LaneFull);
                }
                Overflow::DisconnectPeer => {
                    self.metrics.rejected();
                    return Err(SendError::DisconnectPeer);
                }
                Overflow::BlockProducer => {
                    self.metrics.blocked();
                    inner = match self
                        .space
                        .wait_while(inner, |i| !i.closed && i.queue.len() >= self.capacity)
                    {
                        Ok(guard) => guard,
                        Err(_) => return Err(SendError::Closed),
                    };
                    if inner.closed {
                        return Err(SendError::Closed);
                    }
                }
            }
        }

        inner.queue.push_back(env);
        self.metrics.offered();
        self.metrics.depth(inner.queue.len());
        drop(inner);
        self.ready.notify_one();
        Ok(())
    }

    fn take(&self, timeout: Duration) -> Option<Envelope> {
        let mut inner = self.inner.lock().ok()?;
        while inner.queue.is_empty() {
            if inner.closed {
                return None;
            }
            let (guard, wait) = self.ready.wait_timeout(inner, timeout).ok()?;
            inner = guard;
            if wait.timed_out() && inner.queue.is_empty() {
                return None;
            }
        }
        let env = inner.queue.pop_front()?;
        drop(inner);
        self.space.notify_one();
        self.metrics.delivered(env.waited());
        Some(env)
    }

    fn depth(&self) -> usize {
        self.inner.lock().map(|i| i.queue.len()).unwrap_or(0)
    }

    fn metrics(&self) -> &dyn Metrics {
        self.metrics.as_ref()
    }

    fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.closed = true;
        }
        self.ready.notify_all();
        self.space.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::PortId;
    use std::sync::Arc;

    fn env(n: u8) -> Envelope {
        Envelope::new(PortId(1), vec![n])
    }

    fn queue(overflow: Overflow, capacity: usize) -> LockedQueue {
        LockedQueue::with_policy(Lane::Feature, capacity, overflow)
    }

    const SHORT: Duration = Duration::from_millis(50);

    /// The [`MessageQueue`] contract, asserted against any implementation.
    fn assert_queue_contract(q: &dyn MessageQueue) {
        // 3. take on an empty queue times out rather than hanging.
        assert!(q.take(Duration::from_millis(5)).is_none());

        // 1. FIFO.
        for n in 0..3 {
            let _ = q.offer(env(n));
        }
        let got: Vec<_> = (0..3)
            .filter_map(|_| q.take(SHORT).map(|e| e.payload[0]))
            .collect();
        assert_eq!(got, vec![0, 1, 2]);

        // 5. traffic is counted.
        assert!(q.metrics().snapshot().offered >= 3);
        assert!(q.metrics().snapshot().delivered >= 3);

        // 4. close refuses further traffic.
        q.close();
        assert_eq!(q.offer(env(9)), Err(SendError::Closed));
    }

    #[test]
    fn the_locked_queue_satisfies_the_contract() {
        assert_queue_contract(&queue(Overflow::Reject, 8));
    }

    #[test]
    fn reject_refuses_once_full_and_keeps_what_it_has() {
        let q = queue(Overflow::Reject, 2);
        q.offer(env(1)).expect("space");
        q.offer(env(2)).expect("space");
        assert_eq!(q.offer(env(3)), Err(SendError::LaneFull));
        assert_eq!(q.depth(), 2, "the refusal must not disturb the queue");
        assert_eq!(q.metrics().snapshot().rejected, 1);
    }

    #[test]
    fn disconnect_peer_reports_a_distinct_error() {
        // The caller must close a connection, not just log a drop.
        let q = queue(Overflow::DisconnectPeer, 1);
        q.offer(env(1)).expect("space");
        assert_eq!(q.offer(env(2)), Err(SendError::DisconnectPeer));
    }

    #[test]
    fn drop_oldest_discards_the_stale_end_not_the_fresh_one() {
        let q = queue(Overflow::DropOldest, 2);
        for n in 1..=3 {
            q.offer(env(n)).expect("drop-oldest always accepts");
        }
        let got: Vec<_> = (0..2)
            .filter_map(|_| q.take(SHORT).map(|e| e.payload[0]))
            .collect();
        assert_eq!(got, vec![2, 3], "the oldest should have been discarded");
        assert_eq!(q.metrics().snapshot().dropped, 1);
    }

    #[test]
    fn block_producer_waits_for_space_rather_than_failing() {
        let q = Arc::new(queue(Overflow::BlockProducer, 1));
        q.offer(env(1)).expect("space");

        let producer = {
            let q = Arc::clone(&q);
            std::thread::spawn(move || q.offer(env(2)))
        };

        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(q.take(SHORT).map(|e| e.payload[0]), Some(1));
        assert_eq!(producer.join().expect("producer thread"), Ok(()));
        assert_eq!(q.metrics().snapshot().blocked, 1);
    }

    #[test]
    fn closing_wakes_a_blocked_producer() {
        // Otherwise shutdown deadlocks on a full io lane.
        let q = Arc::new(queue(Overflow::BlockProducer, 1));
        q.offer(env(1)).expect("space");

        let producer = {
            let q = Arc::clone(&q);
            std::thread::spawn(move || q.offer(env(2)))
        };
        std::thread::sleep(Duration::from_millis(20));
        q.close();
        assert_eq!(
            producer.join().expect("producer thread"),
            Err(SendError::Closed)
        );
    }

    #[test]
    fn a_zero_capacity_lane_is_clamped_rather_than_deadlocking() {
        assert!(queue(Overflow::Reject, 0).offer(env(1)).is_ok());
    }

    #[test]
    fn high_water_records_the_peak_depth() {
        let q = queue(Overflow::Reject, 8);
        for n in 0..3 {
            q.offer(env(n)).expect("space");
        }
        let _ = q.take(SHORT);
        assert_eq!(q.metrics().snapshot().high_water, 3);
    }
}
