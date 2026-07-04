//! What one peer is allowed to send, per second.
//!
//! `max_bandwidth` was advertised in `ServerSync`, in `ServerConfig` and in the
//! server-browser ping, and enforced by nothing (`docs/GAP-ANALYSIS.md` §5). A
//! client that ignored the number — or was built to — could transmit at any
//! rate the network carried, and every other client in the channel paid for it
//! in bytes they had to receive.
//!
//! # The unit is bytes, and the packet is bigger than its payload
//!
//! murmur charges `20 + 8 + 4 + payload` per frame (`Server.cpp:1339`): an IPv4
//! header, a UDP header and the crypt header. The wire cost of a voice packet
//! is what the cap is about, so counting only the Opus payload would let a peer
//! sending tiny frames very fast pass a limit it is in fact exceeding.
//!
//! And `max_bandwidth` is quoted in **bits** per second, as every Mumble
//! setting of that name is, so the budget is a *eighth* of it.

use std::collections::HashMap;

use starling_runtime::ratelimit::{Rate, TokenBucket};

use crate::ports::ConnId;

/// murmur's per-packet overhead: IP + UDP + crypt header.
///
/// Charged for tunnelled frames too, though those ride a TCP connection with a
/// different overhead. Not an oversight: the cap exists to bound what one peer
/// costs everybody else, and a client that fell back to tunnelling must not
/// thereby get a larger allowance than one that did not.
pub const PACKET_OVERHEAD: usize = 20 + 8 + 4;

/// How many seconds of budget a peer may bank.
///
/// One. A talkspurt is bursty at its start — a client sends several frames back
/// to back when transmission opens — and a bucket with no headroom would clip
/// the first word of every sentence. More than a second would let a peer save
/// up a quiet minute and spend it at once, which is the thing being prevented.
const BURST_SECONDS: f64 = 1.0;

/// Per-peer voice budgets.
#[derive(Debug, Default)]
pub struct Bandwidth {
    buckets: HashMap<ConnId, TokenBucket>,
    /// The budget every bucket is currently sized for, in bytes per second.
    ///
    /// Kept so a change of `max_bandwidth` can be applied to peers that are
    /// already connected — which is the whole difference between a live
    /// setting and one that takes effect at the next reconnect.
    budget: u32,
}

impl Bandwidth {
    /// Charge one frame of `payload` bytes to `conn`.
    ///
    /// Returns whether it may be routed. `max_bandwidth` of zero is unlimited,
    /// as every other limit here is, and is also what a voice service that has
    /// not yet heard from `server-config` holds — so an unconfigured server
    /// relays audio rather than silencing everybody.
    pub fn admit(&mut self, conn: ConnId, payload: usize, max_bandwidth: u32, now_ms: u64) -> bool {
        if max_bandwidth == 0 {
            return true;
        }
        let budget = max_bandwidth / 8;
        if budget != self.budget {
            self.retune(budget);
        }
        let cost = (payload + PACKET_OVERHEAD) as f64;
        self.buckets
            .entry(conn)
            .or_insert_with(|| Self::bucket(budget, now_ms))
            .take_many(cost, now_ms)
            .is_ok()
    }

    /// Forget a peer that has gone.
    pub fn forget(&mut self, conn: ConnId) {
        let _ = self.buckets.remove(&conn);
    }

    /// Re-size every live bucket, for an operator who changed the cap.
    fn retune(&mut self, budget: u32) {
        let rate = Rate::per_second(f64::from(budget));
        let burst = burst_for(budget);
        for bucket in self.buckets.values_mut() {
            bucket.retune(rate, burst);
        }
        self.budget = budget;
    }

    fn bucket(budget: u32, now_ms: u64) -> TokenBucket {
        TokenBucket::new(
            Rate::per_second(f64::from(budget)),
            burst_for(budget),
            now_ms,
        )
    }
}

/// The largest voice frame Mumble puts on the wire, near enough.
///
/// Only used as the floor below: an exact figure would be per codec and per
/// frame length, and what this number has to be is "big enough that a real
/// packet fits".
const LARGEST_FRAME: usize = 1_024;

/// One second of budget, and never less than a single full-size packet.
///
/// The floor matters: a cap low enough that one frame does not fit would refuse
/// every packet for ever, which is a silence with no explanation rather than
/// the throttle the operator asked for. A mistyped setting should throttle a
/// server, not mute it.
fn burst_for(budget: u32) -> u32 {
    let floor = (PACKET_OVERHEAD + LARGEST_FRAME) as u32;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "budget is a u32 and BURST_SECONDS is 1.0"
    )]
    let seconds = (f64::from(budget) * BURST_SECONDS) as u32;
    seconds.max(floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: ConnId = 1;

    /// A frame big enough that a realistic budget clears the burst floor.
    ///
    /// The floor exists so a cap too small for a single packet does not silence
    /// a peer forever; it also means a test with a toy budget measures the
    /// floor rather than the setting, which is why these use full-size frames.
    const FRAME: usize = 600;

    /// A budget in bits per second that admits `frames` frames of `size` bytes.
    fn bits_for(frames: u32, size: usize) -> u32 {
        (frames * (size + PACKET_OVERHEAD) as u32) * 8
    }

    #[test]
    fn a_peer_within_its_budget_is_admitted() {
        let mut bandwidth = Bandwidth::default();
        let budget = bits_for(50, 100);
        for _ in 0..50 {
            assert!(bandwidth.admit(PEER, 100, budget, 0));
        }
    }

    #[test]
    fn a_peer_over_its_budget_is_refused_rather_than_relayed() {
        // The §5 property: the setting decides. Same peer, same frames, and
        // the only difference is the number an operator set.
        let mut bandwidth = Bandwidth::default();
        let budget = bits_for(10, 100);
        let mut admitted = 0;
        for _ in 0..50 {
            if bandwidth.admit(PEER, 100, budget, 0) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 10, "exactly one second of budget");

        let mut generous = Bandwidth::default();
        let admitted = (0..50)
            .filter(|_| generous.admit(PEER, 100, bits_for(50, 100), 0))
            .count();
        assert_eq!(admitted, 50, "a larger cap admits every frame");
    }

    #[test]
    fn a_bandwidth_of_zero_is_unlimited_rather_than_silent() {
        // What a voice service holds before `server-config` has answered. The
        // other reading would silence every peer on a server that is merely
        // starting up.
        let mut bandwidth = Bandwidth::default();
        for _ in 0..10_000 {
            assert!(bandwidth.admit(PEER, 1_000, 0, 0));
        }
    }

    #[test]
    fn the_budget_refills_over_time_rather_than_being_spent_once() {
        let mut bandwidth = Bandwidth::default();
        let budget = bits_for(10, 100);
        for _ in 0..10 {
            assert!(bandwidth.admit(PEER, 100, budget, 0));
        }
        assert!(!bandwidth.admit(PEER, 100, budget, 0));
        assert!(
            bandwidth.admit(PEER, 100, budget, 1_000),
            "a second later there is budget again"
        );
    }

    #[test]
    fn one_peer_over_its_budget_does_not_silence_another() {
        // Per peer, because the cap is per peer: murmur's is on `ServerUser`.
        let mut bandwidth = Bandwidth::default();
        let budget = bits_for(2, FRAME);
        for _ in 0..5 {
            let _ = bandwidth.admit(PEER, FRAME, budget, 0);
        }
        assert!(!bandwidth.admit(PEER, FRAME, budget, 0));
        assert!(bandwidth.admit(2, FRAME, budget, 0));
    }

    #[test]
    fn raising_the_cap_reaches_a_peer_that_is_already_connected() {
        // murmur's `setLiveConf` sends a new `ServerConfig` to everybody and
        // starts enforcing the new number; a budget fixed at connect time would
        // apply it only to whoever dialled next.
        let mut bandwidth = Bandwidth::default();
        let tight = bits_for(2, FRAME);
        for _ in 0..2 {
            assert!(bandwidth.admit(PEER, FRAME, tight, 0));
        }
        // A tenth of a second later the tight budget has still not refilled
        // enough for another frame, which is what makes the next assertion
        // about the cap rather than about the passage of time.
        assert!(!bandwidth.admit(PEER, FRAME, tight, 100));
        assert!(
            bandwidth.admit(PEER, FRAME, bits_for(100, FRAME), 200),
            "the raised cap must apply without a reconnect"
        );
    }

    #[test]
    fn the_overhead_is_charged_and_not_only_the_payload() {
        // A peer sending very small frames very fast is using the network, and
        // counting only the Opus bytes would let it past a cap it is over.
        let mut bandwidth = Bandwidth::default();
        // Budget for exactly ten *payloads*, with the header unaccounted for.
        let budget = 10 * FRAME as u32 * 8;
        let admitted = (0..10)
            .filter(|_| bandwidth.admit(PEER, FRAME, budget, 0))
            .count();
        assert!(
            admitted < 10,
            "the packet header has to be part of the cost"
        );
    }

    #[test]
    fn a_cap_too_small_for_one_packet_still_lets_something_through() {
        // A budget below one frame would otherwise refuse every packet for
        // ever: a silence with no explanation rather than the throttle the
        // operator asked for. The floor is what stops a mistyped setting from
        // muting a server.
        let mut bandwidth = Bandwidth::default();
        assert!(
            bandwidth.admit(PEER, FRAME, 8, 0),
            "a one-bit cap must not be a mute button"
        );
    }

    #[test]
    fn a_forgotten_peer_starts_again_rather_than_leaking() {
        let mut bandwidth = Bandwidth::default();
        let budget = bits_for(1, FRAME);
        assert!(bandwidth.admit(PEER, FRAME, budget, 0));
        assert!(!bandwidth.admit(PEER, FRAME, budget, 0));
        bandwidth.forget(PEER);
        assert!(bandwidth.admit(PEER, FRAME, budget, 0));
    }
}
