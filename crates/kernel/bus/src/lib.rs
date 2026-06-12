//! `starling-bus` — QNX-style message routing with priority lanes.
//!
//! The kernel's transport fabric. Participants register a [`PortId`] on a
//! [`Lane`]; senders address a port and the bus decides everything else.
//!
//! ```text
//!   send(Envelope{to: PortId}) ──► [routing table] ──► lane queue ──► receiver
//!                                        │
//!                     the lane comes from the REGISTRATION,
//!                     never from the envelope
//! ```
//!
//! # Boundaries are traits
//!
//! | Trait | Implementations |
//! |---|---|
//! | [`MessageBus`] | [`LaneBus`] (the design) · [`SharedQueueBus`] (the control it is measured against) |
//! | [`MessageQueue`] | [`LockedQueue`] — a lock-free MPMC can replace it without touching a caller |
//! | [`Metrics`] | [`AtomicMetrics`] · [`NoMetrics`] |
//!
//! Deliberately **not** traits: [`Lane`] is a closed capability set (an open one
//! would let a feature invent a lane), and [`Envelope`] is a value, not a
//! collaborator — see its docs.
//!
//! # Two properties worth stating
//!
//! * **A dumb bus with smart endpoints.** The bus never inspects a payload. A
//!   bus that cannot parse cannot couple, which is the mechanical form of the
//!   plugin-opacity rule — and the thing that stops this becoming an enterprise
//!   service bus.
//! * **The lane is a capability, not a claim.** [`Envelope`] carries no lane, so
//!   a feature cannot promote its own traffic above the control plane.
//!
//! # Priority comes from the OS, not from here
//!
//! There is no cross-lane arbitration in this crate. Each lane is drained by its
//! own threads and the OS scheduler arbitrates — which is *preemptive*, where a
//! userspace picker would only reschedule at yield points. `examples/isolation.rs`
//! measures whether that actually works.

pub mod bus;
pub mod envelope;
pub mod lane;
pub mod metrics;
pub mod queue;

pub use bus::{LaneBus, MessageBus, SharedQueueBus};
pub use envelope::{Envelope, PortId};
pub use lane::{Lane, Overflow};
pub use metrics::{AtomicMetrics, Metrics, NoMetrics, Snapshot};
pub use queue::{LockedQueue, MessageQueue, SendError};
