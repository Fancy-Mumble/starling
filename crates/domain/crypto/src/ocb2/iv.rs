//! Reconstructing a 128-bit nonce from the one byte on the wire.
//!
//! OCB2's nonce is a full block, but Mumble sends only its lowest byte. The rest
//! is inferred from the receiver's own counter, which works because UDP reorders
//! by a little and loses a little, never by 128 packets at a time.
//!
//! This is the same problem SRTP solves with a rollover counter, and murmur's
//! answer is the same in substance: keep the expected next value, decide from
//! the delta whether the arrival is in order, late, or has skipped some, and
//! reject anything too far away to be either.
//!
//! # Why replay detection cannot be a window
//!
//! `starling-crypto`'s `SequenceWindow` uses a 64-bit bitmap over recent
//! sequence numbers, which is the better construction. It cannot be used here:
//! only eight bits reach the wire, so "recent" is at most 256 packets and the
//! high bits are guesses. murmur keeps a 256-entry table mapping each low byte
//! to the next byte up, which detects a replay exactly when the guess agrees.
//!
//! # One deliberate deviation
//!
//! murmur's table starts zeroed and it cannot tell "never seen" from "seen when
//! the byte above was zero", so early in a connection it rejects the occasional
//! honest out-of-order packet. Recording absence explicitly costs 256 bytes a
//! peer and drops nothing. It is safe to differ because the sender never learns
//! which packets were dropped — this is UDP, and there is no acknowledgement.

#[cfg(test)]
use super::block::BLOCK_LEN;
/// A full OCB2 nonce, and the machinery to keep it in step with a peer's.
use super::block::Block;

/// How far behind the expected value a packet may be and still be accepted.
///
/// murmur's constant. Thirty packets is 600 ms of audio at Mumble's 20 ms
/// frames — beyond any jitter buffer, so anything later is indistinguishable
/// from an attack and is treated as one.
const LATE_TOLERANCE: i32 = 30;

/// Why a nonce could not be reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// Too far from the expected value in either direction.
    #[error("packet is too far out of sequence to place")]
    OutOfRange,

    /// This low byte has already been seen at this high byte.
    #[error("packet is a replay")]
    Replay,
}

/// How a received packet sat relative to what was expected.
///
/// Reported so the caller can keep the statistics `UserStats` exposes, which is
/// how an operator distinguishes a lossy network from a broken one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Arrival {
    /// Packets that never came, inferred from the gap.
    pub lost: u32,
    /// Whether this packet arrived after one that supersedes it.
    pub late: bool,
}

/// The sending half: a counter that only ever goes up.
#[derive(Debug, Clone)]
pub(super) struct SendNonce(Block);

impl SendNonce {
    /// Start from a peer-supplied nonce.
    #[must_use]
    pub(super) const fn new(seed: Block) -> Self {
        Self(seed)
    }

    /// The current value, for `CryptSetup`.
    #[must_use]
    pub(super) const fn get(&self) -> Block {
        self.0
    }

    /// Advance and return the nonce for the next packet.
    ///
    /// A 128-bit little-endian increment: carry propagates from byte 0 upward,
    /// which is why the wire byte is byte 0 and why it changes every packet.
    pub(super) fn advance(&mut self) -> Block {
        for byte in &mut self.0.0 {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        self.0
    }
}

/// The receiving half: an expected nonce plus a replay table.
#[derive(Debug, Clone)]
pub(super) struct RecvNonce {
    expected: Block,
    /// For each low byte seen, the byte above it at the time.
    ///
    /// Indexed by the wire byte. A replay is a low byte arriving again with the
    /// same byte above it, which is what makes the table both the history and
    /// the wrap detector. `None` is "not seen yet", which murmur cannot express
    /// and which costs it the occasional honest packet.
    seen: [Option<u8>; 256],
}

impl RecvNonce {
    /// Start from a peer-supplied nonce.
    #[must_use]
    pub(super) const fn new(seed: Block) -> Self {
        Self {
            expected: seed,
            seen: [None; 256],
        }
    }

    /// The current expectation, for `CryptSetup` resynchronisation.
    #[must_use]
    pub(super) const fn get(&self) -> Block {
        self.expected
    }

    /// Work out the full nonce for a packet whose low byte is `wire`.
    ///
    /// Returns the nonce to try, and how to update state **if** the packet then
    /// authenticates. Nothing is committed here: a nonce that fails its tag
    /// check must leave no trace, or an attacker could walk the counter forward
    /// with garbage and cut the peer off.
    ///
    /// # Errors
    ///
    /// [`NonceError`] if the packet cannot be placed, or has been seen.
    pub(super) fn place(&self, wire: u8) -> Result<Candidate, NonceError> {
        let expected = self.expected.0[0];

        // The overwhelmingly common case: exactly the next packet.
        if expected.wrapping_add(1) == wire {
            let mut nonce = self.expected;
            nonce.0[0] = wire;
            // A wrap in the low byte carries into the rest.
            if wire < expected {
                carry(&mut nonce.0[1..]);
            }
            return Ok(Candidate {
                nonce,
                restore: false,
                arrival: Arrival::default(),
            });
        }

        // Everything else is late, a gap, or hostile. `diff` is the signed
        // distance the short way round the 256-wide circle.
        let diff = signed_delta(wire, expected);
        let mut nonce = self.expected;
        nonce.0[0] = wire;

        let (restore, arrival) = match (wire.cmp(&expected), diff) {
            // Late, no wrap: an older packet caught up.
            (std::cmp::Ordering::Less, d) if (-LATE_TOLERANCE..0).contains(&d) => (
                true,
                Arrival {
                    lost: 0,
                    late: true,
                },
            ),

            // Late, across a wrap: the high bytes must come *down*.
            (std::cmp::Ordering::Greater, d) if (-LATE_TOLERANCE..0).contains(&d) => {
                borrow(&mut nonce.0[1..]);
                (
                    true,
                    Arrival {
                        lost: 0,
                        late: true,
                    },
                )
            }

            // A gap, no wrap.
            (std::cmp::Ordering::Greater, d) if d > 0 => (
                false,
                Arrival {
                    lost: u32::from(wire - expected - 1),
                    late: false,
                },
            ),

            // A gap across a wrap.
            (std::cmp::Ordering::Less, d) if d > 0 => {
                carry(&mut nonce.0[1..]);
                (
                    false,
                    Arrival {
                        lost: 256 - u32::from(expected) + u32::from(wire) - 1,
                        late: false,
                    },
                )
            }

            // The byte just accepted, arriving again: the immediate replay,
            // and the only one the fast path above cannot catch.
            (std::cmp::Ordering::Equal, _) => return Err(NonceError::Replay),

            // Further away than loss or reordering explains.
            _ => return Err(NonceError::OutOfRange),
        };

        if self.seen[usize::from(wire)] == Some(nonce.0[1]) {
            return Err(NonceError::Replay);
        }

        Ok(Candidate {
            nonce,
            restore,
            arrival,
        })
    }

    /// Commit a candidate whose tag verified.
    ///
    /// Separate from [`Self::place`] so that a forged packet cannot move the
    /// counter. Upstream does this by saving and restoring the IV around the
    /// attempt; not mutating in the first place is the same guarantee without
    /// the window in which the state is wrong.
    pub(super) fn accept(&mut self, candidate: &Candidate) {
        self.seen[usize::from(candidate.nonce.0[0])] = Some(candidate.nonce.0[1]);
        // A late packet must not drag the expectation backwards, or the packets
        // already accepted after it would all look like replays.
        if !candidate.restore {
            self.expected = candidate.nonce;
        }
    }
}

/// A nonce that might be right, pending the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Candidate {
    /// The reconstructed nonce to decrypt under.
    pub nonce: Block,
    /// Whether this packet is late, so the expectation must not move to it.
    restore: bool,
    /// How this packet sat relative to expectations.
    pub arrival: Arrival,
}

/// Add one to a little-endian integer, stopping at the first byte that does not
/// wrap.
fn carry(bytes: &mut [u8]) {
    for byte in bytes {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Subtract one from a little-endian integer.
fn borrow(bytes: &mut [u8]) {
    for byte in bytes {
        let had_value = *byte != 0;
        *byte = byte.wrapping_sub(1);
        if had_value {
            break;
        }
    }
}

/// The distance from `expected` to `wire` the short way round.
///
/// murmur computes this as an `int` difference folded into ±128. The fold is the
/// point: without it, a packet one before the wrap looks 255 ahead.
fn signed_delta(wire: u8, expected: u8) -> i32 {
    let raw = i32::from(wire) - i32::from(expected);
    if raw > 128 {
        raw - 256
    } else if raw < -128 {
        raw + 256
    } else {
        raw
    }
}

/// The seed both halves start from, when nothing better is known.
///
/// Test-only: production always has real key material from `CryptSetup`, and a
/// zero nonce there would be a bug worth failing loudly on rather than a default
/// worth providing.
#[cfg(test)]
const fn zero_nonce() -> Block {
    Block([0; BLOCK_LEN])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A receiver whose expectation is `at`, having already accepted a packet.
    fn receiver_at(at: u8) -> RecvNonce {
        let mut nonce = zero_nonce();
        nonce.0[0] = at;
        RecvNonce::new(nonce)
    }

    #[test]
    fn the_sender_increments_the_low_byte_first() {
        // Which is why the low byte is the one on the wire: it changes every
        // packet, and the rest almost never does.
        let mut sender = SendNonce::new(zero_nonce());
        assert_eq!(sender.advance().0[0], 1);
        assert_eq!(sender.advance().0[0], 2);
        assert_eq!(sender.get().0[1], 0);
    }

    #[test]
    fn the_sender_carries_into_the_next_byte() {
        let mut nonce = zero_nonce();
        nonce.0[0] = 0xFF;
        let mut sender = SendNonce::new(nonce);
        let next = sender.advance();
        assert_eq!(next.0[0], 0);
        assert_eq!(next.0[1], 1);
    }

    #[test]
    fn the_sender_carries_all_the_way_up() {
        let mut sender = SendNonce::new(Block([0xFF; BLOCK_LEN]));
        assert_eq!(sender.advance(), zero_nonce());
    }

    #[test]
    fn the_next_packet_in_order_is_placed() {
        let recv = receiver_at(5);
        let candidate = recv.place(6).expect("in order");
        assert_eq!(candidate.nonce.0[0], 6);
        assert_eq!(
            candidate.arrival,
            Arrival::default(),
            "the expected next packet is neither late nor a gap"
        );
    }

    #[test]
    fn an_in_order_wrap_carries_the_high_bytes() {
        let recv = receiver_at(0xFF);
        let candidate = recv.place(0).expect("in order across the wrap");
        assert_eq!(candidate.nonce.0[0], 0);
        assert_eq!(candidate.nonce.0[1], 1, "the wrap did not carry");
    }

    #[test]
    fn a_gap_is_placed_and_counted() {
        let recv = receiver_at(5);
        let candidate = recv.place(9).expect("a gap is not an error");
        assert_eq!(candidate.arrival.lost, 3);
        assert!(!candidate.arrival.late);
    }

    #[test]
    fn a_gap_across_the_wrap_counts_correctly() {
        let recv = receiver_at(0xFE);
        let candidate = recv.place(2).expect("a gap across the wrap");
        assert_eq!(candidate.arrival.lost, 3, "0xFF, 0x00 and 0x01 were lost");
        assert_eq!(candidate.nonce.0[1], 1);
    }

    #[test]
    fn a_late_packet_is_accepted_but_does_not_move_the_expectation() {
        // A jitter buffer needs the packet; moving the counter back to it would
        // make everything already received look like a replay.
        let mut recv = receiver_at(10);
        let candidate = recv.place(8).expect("late but within tolerance");
        assert!(candidate.arrival.late);

        recv.accept(&candidate);
        assert_eq!(recv.get().0[0], 10, "a late packet moved the expectation");
    }

    #[test]
    fn a_late_packet_across_the_wrap_borrows() {
        // Expecting 0x02, and 0xFF arrives from the previous round: the high
        // bytes have to come back down or the nonce is from the future.
        let mut nonce = zero_nonce();
        nonce.0[0] = 0x02;
        nonce.0[1] = 0x01;
        let recv = RecvNonce::new(nonce);

        let candidate = recv.place(0xFF).expect("late across the wrap");
        assert_eq!(candidate.nonce.0[0], 0xFF);
        assert_eq!(candidate.nonce.0[1], 0, "the borrow did not happen");
        assert!(candidate.arrival.late);
    }

    #[test]
    fn a_packet_too_late_is_refused() {
        // Beyond any jitter buffer, so indistinguishable from an attack.
        let recv = receiver_at(100);
        assert_eq!(recv.place(100 - 40), Err(NonceError::OutOfRange));
    }

    #[test]
    fn the_expected_byte_repeating_is_a_replay() {
        // The immediate replay of the packet just accepted. The fast path checks
        // for `expected + 1`, so this is the one case it cannot catch.
        let recv = receiver_at(7);
        assert_eq!(recv.place(7), Err(NonceError::Replay));
    }

    #[test]
    fn an_unseen_slot_is_not_mistaken_for_a_replay() {
        // murmur's bug: a zeroed history slot is indistinguishable from one
        // recorded when the byte above happened to be zero, so the first
        // out-of-order packet of a connection is dropped for no reason.
        let recv = receiver_at(5);
        assert!(recv.place(9).is_ok(), "an unseen slot read as a replay");
    }

    #[test]
    fn a_replayed_packet_is_caught_by_the_history() {
        let mut recv = receiver_at(5);
        let first = recv.place(9).expect("a gap");
        recv.accept(&first);

        // Now walk on and come back to 9.
        let next = recv.place(10).expect("in order");
        recv.accept(&next);
        assert_eq!(recv.place(9), Err(NonceError::Replay));
    }

    #[test]
    fn placing_a_packet_does_not_move_the_counter() {
        // The attack this stops: send garbage with a plausible nonce, and the
        // peer's counter walks forward past the real packets.
        let recv = receiver_at(5);
        let _ = recv.place(6).expect("in order");
        let _ = recv.place(60).expect("a gap");
        assert_eq!(recv.get().0[0], 5, "placing mutated the receiver");
    }

    #[test]
    fn accepting_moves_the_counter() {
        let mut recv = receiver_at(5);
        let candidate = recv.place(6).expect("in order");
        recv.accept(&candidate);
        assert_eq!(recv.get().0[0], 6);
    }

    #[test]
    fn a_long_in_order_run_stays_in_step_with_the_sender() {
        // The property that matters most: over a wrap, both sides must agree on
        // all sixteen bytes, not just the one on the wire.
        let mut sender = SendNonce::new(zero_nonce());
        let mut recv = RecvNonce::new(zero_nonce());

        for _ in 0..1000 {
            let sent = sender.advance();
            let candidate = recv.place(sent.0[0]).expect("in order");
            assert_eq!(candidate.nonce, sent, "the nonces diverged");
            recv.accept(&candidate);
        }
    }

    #[test]
    fn the_signed_delta_folds_at_the_wrap() {
        assert_eq!(signed_delta(0, 0xFF), 1);
        assert_eq!(signed_delta(0xFF, 0), -1);
        assert_eq!(signed_delta(10, 5), 5);
        assert_eq!(signed_delta(5, 10), -5);
    }

    #[test]
    fn borrowing_propagates_across_zero_bytes() {
        let mut bytes = [0, 0, 1];
        borrow(&mut bytes);
        assert_eq!(bytes, [0xFF, 0xFF, 0]);
    }

    #[test]
    fn carrying_propagates_across_full_bytes() {
        let mut bytes = [0xFF, 0xFF, 0];
        carry(&mut bytes);
        assert_eq!(bytes, [0, 0, 1]);
    }
}
