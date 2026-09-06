//! Who may start a handshake, how many at once, and for how long.
//!
//! Everything here happens **before** a peer has proved anything. A TCP
//! connection that completes the three-way handshake and then trickles one byte
//! costs a task, a file descriptor and a rustls buffer, and until this module
//! existed it cost them forever: `max_users` is checked after TLS *and* after
//! authentication, and the idle reaper only sees connections that finished the
//! handshake and registered. The cheapest attack on the server was to open
//! sockets and say nothing.
//!
//! Three limits, each answering a different shape of that:
//!
//! * a **deadline**, so one peer cannot hold a slot indefinitely;
//! * a **ceiling** on handshakes in flight, so the whole server has a bound;
//! * a **per-address ceiling**, so one peer cannot occupy the whole ceiling and
//!   lock every other client out.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use starling_runtime::config::GatewayConfig;

/// The admission control in front of the TLS handshake.
#[derive(Debug, Clone)]
pub struct Admission {
    /// One permit per handshake in flight.
    slots: Arc<Semaphore>,
    /// Handshakes in flight per peer address.
    per_ip: Arc<Mutex<HashMap<IpAddr, u32>>>,
    max_per_ip: u32,
    handshake_timeout: Duration,
}

/// Why a connection was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The server-wide ceiling on handshakes in flight is full.
    Busy,
    /// This address already holds as many handshakes as it may.
    PerAddress,
}

impl Refusal {
    /// A short reason, for the log and the metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "too many handshakes in flight",
            Self::PerAddress => "too many handshakes from that address",
        }
    }
}

/// A held admission slot, released when dropped.
///
/// Held only across the handshake. Once a connection is registered it is the
/// idle reaper's to look after, and keeping a permit for its whole life would
/// make this a connection limit, which is `max_users`' job and is answered with
/// a `Reject` a client can read rather than a silent close.
#[derive(Debug)]
pub struct Ticket {
    _permit: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, u32>>>,
    peer: IpAddr,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut per_ip) = self.per_ip.lock() {
            // Removed at zero rather than left at zero: the map is keyed by a
            // peer-chosen address, so an entry that survives its last
            // connection is an entry anybody can mint one of.
            if let Some(held) = per_ip.get_mut(&self.peer) {
                *held = held.saturating_sub(1);
                if *held == 0 {
                    let _ = per_ip.remove(&self.peer);
                }
            }
        }
    }
}

impl Admission {
    /// The admission control an operator configured.
    #[must_use]
    pub fn from_config(config: &GatewayConfig) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(config.max_pending_handshakes)),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip: config.max_pending_per_address,
            handshake_timeout: config.handshake_timeout.get(),
        }
    }

    /// How long a peer has to complete its TLS handshake.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Take a slot for a handshake from `peer`, if there is one.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming which ceiling was reached, for the log.
    pub fn admit(&self, peer: IpAddr) -> Result<Ticket, Refusal> {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Refusal::Busy)?;

        {
            let Ok(mut per_ip) = self.per_ip.lock() else {
                return Err(Refusal::Busy);
            };
            let held = per_ip.entry(peer).or_insert(0);
            if *held >= self.max_per_ip {
                // Left as it was: this peer's existing handshakes still hold
                // their entry, and an entry at zero would be removed by the
                // ticket that is about to not exist.
                if *held == 0 {
                    let _ = per_ip.remove(&peer);
                }
                return Err(Refusal::PerAddress);
            }
            *held += 1;
        }

        Ok(Ticket {
            _permit: permit,
            per_ip: Arc::clone(&self.per_ip),
            peer,
        })
    }

    /// Handshakes in flight, for the tests and the gauge work.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.per_ip
            .lock()
            .map(|per_ip| per_ip.values().map(|held| *held as usize).sum())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission(total: usize, per_ip: u32) -> Admission {
        Admission::from_config(&GatewayConfig {
            max_pending_handshakes: total,
            max_pending_per_address: per_ip,
            ..Default::default()
        })
    }

    fn peer(last: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, last])
    }

    #[test]
    fn a_slot_is_released_when_its_ticket_is_dropped() {
        let admission = admission(4, 4);
        {
            let _held = admission.admit(peer(1)).expect("the first is admitted");
            assert_eq!(admission.in_flight(), 1);
        }
        assert_eq!(admission.in_flight(), 0, "the map must not keep the entry");
    }

    /// Defect 2: no accept cap, so slow handshakes were unbounded.
    #[test]
    fn the_server_wide_ceiling_refuses_rather_than_queueing() {
        let admission = admission(2, 8);
        let _one = admission.admit(peer(1)).expect("first");
        let _two = admission.admit(peer(2)).expect("second");
        assert!(matches!(admission.admit(peer(3)), Err(Refusal::Busy)));
    }

    /// Defect 2: no per-IP cap, so one peer could hold every slot.
    #[test]
    fn one_address_cannot_take_every_slot() {
        let admission = admission(64, 2);
        let _one = admission.admit(peer(1)).expect("first");
        let _two = admission.admit(peer(1)).expect("second");

        assert!(
            matches!(admission.admit(peer(1)), Err(Refusal::PerAddress)),
            "a third from the same address must be refused"
        );
        // And the point of refusing it: somebody else still gets in.
        let _other = admission
            .admit(peer(2))
            .expect("a different peer is unaffected");
    }

    /// A refusal must not consume the slot it was refused.
    #[test]
    fn a_refused_peer_does_not_leak_the_ceiling() {
        let admission = admission(8, 1);
        let held = admission.admit(peer(1)).expect("first");
        for _ in 0..100 {
            assert!(matches!(admission.admit(peer(1)), Err(Refusal::PerAddress)));
        }
        drop(held);

        assert_eq!(admission.in_flight(), 0);
        let _again = admission
            .admit(peer(1))
            .expect("the ceiling recovered once the handshake finished");
    }
}
