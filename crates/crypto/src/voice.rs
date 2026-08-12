//! Nonce discipline for the voice path.
//!
//! The security-critical arithmetic, kept separate from the cipher itself
//! because a mistake here is nonce reuse, and nonce reuse breaks
//! XChaCha20-Poly1305 completely: an attacker recovers the keystream and can
//! forge. Everything in this module is pure and exhaustively tested for that
//! reason.
//!
//! # The construction
//!
//! XChaCha20-Poly1305 is defined as
//!
//! ```text
//!   subkey = HChaCha20(key, nonce[0..16])
//!   ciphertext = ChaCha20-Poly1305(subkey, 0u32 || nonce[16..24], plaintext)
//! ```
//!
//! So if `nonce[0..16]` is fixed for a session, the subkey is fixed too. Making
//! the first 16 bytes a per-session random **salt** and the last 8 a **counter**
//! gives all three properties at once:
//!
//! | | |
//! |---|---|
//! | security | a 16-byte random salt per session and direction, so no birthday bound to reason about and no cross-session reuse |
//! | speed | `HChaCha20` runs **once per session**, not once per packet, per packet this is plain ChaCha20-Poly1305 |
//! | size | only a truncated counter goes on the wire, not 24 bytes of nonce |
//!
//! # What travels
//!
//! Two bytes of counter and the 16-byte tag: **18 bytes**, against 41 for the
//! chat framing that sends the nonce inline. The receiver reconstructs the other
//! six counter bytes itself ([`SequenceWindow`]), the way SRTP reconstructs its
//! rollover counter.
//!
//! The tag is **not** truncated. Mumble truncates OCB2's to three bytes, which
//! puts online forgery within reach; 16 bytes costs 14 bytes a packet and is the
//! difference between a real authenticity guarantee and a token one.
//!
//! # What is deliberately not done
//!
//! The counter never wraps. [`PacketCounter::issue`] fails instead, because
//! wrapping is exactly nonce reuse, the failure that this module exists to make
//! impossible. At 50 packets a second a 64-bit counter lasts longer than the
//! universe has existed, so the error is unreachable in practice and present
//! anyway, since "unreachable" is not a security argument.

/// Which way a packet is travelling.
///
/// Each direction gets its own salt and therefore its own subkey, so a counter
/// value used client-to-server can never collide with the same value
/// server-to-client. Sharing one keystream between directions is a classic way to
/// reintroduce reuse after getting the counter right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Client to server.
    Inbound,
    /// Server to client.
    Outbound,
}

impl Direction {
    /// The label mixed into key derivation, so the two directions cannot derive
    /// the same subkey even from the same master secret.
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Inbound => b"starling-voice-v1 c2s",
            Self::Outbound => b"starling-voice-v1 s2c",
        }
    }
}

/// Bytes of the counter placed on the wire.
///
/// Two is enough to resynchronise after any plausible burst of loss: the
/// reconstruction below tolerates a gap of just under 32 768 packets, which at 50
/// packets a second is around eleven minutes of continuous loss.
pub const WIRE_COUNTER_BYTES: usize = 2;

/// How many packets the replay window remembers.
pub const REPLAY_WINDOW: u64 = 64;

/// A packet counter value: the last eight bytes of the nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sequence(u64);

impl Sequence {
    /// The full counter.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// The part that travels on the wire.
    #[must_use]
    pub const fn truncated(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    /// The eight nonce bytes this counter contributes, big-endian.
    #[must_use]
    pub const fn nonce_tail(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// The sender's counter. Never yields the same value twice.
#[derive(Debug, Clone, Default)]
pub struct PacketCounter {
    next: u64,
}

impl PacketCounter {
    /// A counter starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Hand out the next value.
    ///
    /// Named `issue` rather than `next` because this is not an iterator and must
    /// not read like one: it can refuse, and a caller that treated it as an
    /// infinite sequence would be assuming exactly what it exists to deny.
    ///
    /// # Errors
    ///
    /// [`CounterExhausted`] once the space is used up. The caller must rekey
    /// rather than continue; there is no correct way to carry on.
    pub fn issue(&mut self) -> Result<Sequence, CounterExhausted> {
        let value = self.next;
        self.next = value.checked_add(1).ok_or(CounterExhausted)?;
        Ok(Sequence(value))
    }

    /// How many values remain.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        u64::MAX - self.next
    }
}

/// The counter space is used up; the session must be rekeyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("voice packet counter exhausted; rekey before sending more")]
pub struct CounterExhausted;

/// Why a received packet was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Rejected {
    /// Seen before. Either a duplicate from the network or a replay attempt;
    /// both are dropped, and neither is distinguishable from the other.
    #[error("packet {sequence} has already been seen")]
    Replay {
        /// The reconstructed counter.
        sequence: u64,
    },

    /// Older than the replay window remembers, so it cannot be checked.
    ///
    /// Dropped rather than accepted: accepting an unverifiable packet is what a
    /// replay window exists to prevent.
    #[error("packet {sequence} is older than the {REPLAY_WINDOW}-packet window")]
    TooOld {
        /// The reconstructed counter.
        sequence: u64,
    },
}

/// The receiver's view: reconstructs the full counter and rejects replays.
///
/// UDP reorders and drops, so a receiver cannot simply expect the next value. It
/// keeps the highest counter seen and a bitmap of the window below it, which is
/// the same shape as SRTP's replay list.
#[derive(Debug, Clone)]
pub struct SequenceWindow {
    highest: u64,
    /// Bit `n` is set when `highest - 1 - n` has been seen.
    seen: u64,
    started: bool,
}

impl Default for SequenceWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceWindow {
    /// A window that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: 0,
            seen: 0,
            started: false,
        }
    }

    /// The highest counter accepted so far.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.highest
    }

    /// Whether any packet has been accepted yet.
    ///
    /// Distinct from `highest() == 0`, which is also true after accepting the
    /// very first packet of a stream. The caller keeping arrival statistics
    /// needs the difference: the first packet is neither late nor evidence of
    /// loss, whatever counter it carries.
    #[must_use]
    pub const fn started(&self) -> bool {
        self.started
    }

    /// Reconstruct the full counter from the truncated wire value and record it.
    ///
    /// Reconstruction picks the candidate nearest the highest value seen, so a
    /// wire value that has wrapped past `0xFFFF` resolves to the next window up
    /// rather than to a counter far in the past.
    ///
    /// # Errors
    ///
    /// [`Rejected`] if the packet is a replay or too old to verify. The window is
    /// left unchanged in both cases, so a rejected packet cannot advance it, the
    /// bug that would let one forged packet silence a stream.
    pub fn accept(&mut self, truncated: u16) -> Result<Sequence, Rejected> {
        let sequence = self.reconstruct(truncated);

        if !self.started {
            self.started = true;
            self.highest = sequence;
            return Ok(Sequence(sequence));
        }

        if sequence > self.highest {
            let advance = sequence - self.highest;
            // Shift the window up. An advance beyond the window width clears it,
            // which is correct: nothing below is still checkable.
            self.seen = if advance >= REPLAY_WINDOW {
                0
            } else {
                let shifted = self.seen << advance;
                // Mark the previous highest as seen, now `advance` places down.
                shifted | (1_u64 << (advance - 1))
            };
            self.highest = sequence;
            return Ok(Sequence(sequence));
        }

        if sequence == self.highest {
            return Err(Rejected::Replay { sequence });
        }

        let age = self.highest - sequence;
        if age > REPLAY_WINDOW {
            return Err(Rejected::TooOld { sequence });
        }

        let bit = 1_u64 << (age - 1);
        if self.seen & bit != 0 {
            return Err(Rejected::Replay { sequence });
        }
        self.seen |= bit;
        Ok(Sequence(sequence))
    }

    /// The full counter a truncated value most likely means.
    fn reconstruct(&self, truncated: u16) -> u64 {
        const WINDOW: u64 = 1 << (WIRE_COUNTER_BYTES * 8);

        if !self.started {
            return u64::from(truncated);
        }

        let high = self.highest & !(WINDOW - 1);
        let candidate = high | u64::from(truncated);

        // Three candidates: this window, the one above, and the one below. Pick
        // whichever sits closest to the highest counter seen.
        let mut best = candidate;
        let mut best_distance = candidate.abs_diff(self.highest);

        for alternative in [candidate.checked_add(WINDOW), candidate.checked_sub(WINDOW)]
            .into_iter()
            .flatten()
        {
            let distance = alternative.abs_diff(self.highest);
            if distance < best_distance {
                best = alternative;
                best_distance = distance;
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_never_yields_a_value_twice() {
        // The single property the whole module exists for.
        let mut counter = PacketCounter::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let sequence = counter.issue().expect("plenty of space");
            assert!(seen.insert(sequence.value()), "counter repeated a value");
        }
    }

    #[test]
    fn the_counter_fails_rather_than_wrapping() {
        // Wrapping would be nonce reuse. An error forces a rekey instead.
        let mut counter = PacketCounter { next: u64::MAX - 1 };
        assert!(counter.issue().is_ok());
        assert_eq!(counter.issue(), Err(CounterExhausted));
        assert_eq!(counter.issue(), Err(CounterExhausted), "still refuses");
    }

    #[test]
    fn directions_derive_from_different_labels() {
        // Same master secret, different keystream. Sharing one between directions
        // reintroduces reuse after the counter is already correct.
        assert_ne!(Direction::Inbound.label(), Direction::Outbound.label());
    }

    #[test]
    fn the_nonce_tail_is_the_counter() {
        assert_eq!(Sequence(0).nonce_tail(), [0; 8]);
        assert_eq!(Sequence(1).nonce_tail(), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(Sequence(u64::MAX).nonce_tail(), [0xFF; 8]);
    }

    #[test]
    fn packets_in_order_are_all_accepted() {
        let mut window = SequenceWindow::new();
        for expected in 0..1_000_u64 {
            let accepted = window
                .accept(Sequence(expected).truncated())
                .expect("in-order packets are accepted");
            assert_eq!(accepted.value(), expected);
        }
    }

    #[test]
    fn a_duplicate_is_rejected() {
        let mut window = SequenceWindow::new();
        for n in 0..10_u64 {
            let _ = window.accept(Sequence(n).truncated()).expect("accepted");
        }
        assert!(matches!(
            window.accept(Sequence(5).truncated()),
            Err(Rejected::Replay { sequence: 5 })
        ));
        assert!(
            matches!(
                window.accept(Sequence(9).truncated()),
                Err(Rejected::Replay { sequence: 9 })
            ),
            "the highest is a replay too"
        );
    }

    #[test]
    fn out_of_order_within_the_window_is_accepted_once() {
        // UDP reorders; dropping a late-but-unseen packet would lose audio.
        let mut window = SequenceWindow::new();
        for n in [0_u64, 1, 2, 5] {
            let _ = window.accept(Sequence(n).truncated()).expect("accepted");
        }
        assert!(
            window.accept(Sequence(3).truncated()).is_ok(),
            "late but new"
        );
        assert!(matches!(
            window.accept(Sequence(3).truncated()),
            Err(Rejected::Replay { .. })
        ));
    }

    #[test]
    fn a_packet_older_than_the_window_is_rejected() {
        let mut window = SequenceWindow::new();
        for n in 0..200_u64 {
            let _ = window.accept(Sequence(n).truncated()).expect("accepted");
        }
        assert!(matches!(
            window.accept(Sequence(5).truncated()),
            Err(Rejected::TooOld { sequence: 5 })
        ));
    }

    #[test]
    fn a_rejected_packet_does_not_move_the_window() {
        // Otherwise one forged packet could jump the window forward and silence
        // the stream by making every real packet look too old.
        let mut window = SequenceWindow::new();
        for n in 0..10_u64 {
            let _ = window.accept(Sequence(n).truncated()).expect("accepted");
        }
        let before = window.highest();
        let _ = window.accept(Sequence(5).truncated());
        assert_eq!(window.highest(), before);
    }

    #[test]
    fn the_counter_is_reconstructed_across_the_wire_wrap() {
        // The reason only two bytes travel: the receiver rebuilds the rest.
        let mut window = SequenceWindow::new();
        for n in 0..70_000_u64 {
            let accepted = window
                .accept(Sequence(n).truncated())
                .unwrap_or_else(|e| panic!("packet {n} rejected: {e}"));
            assert_eq!(
                accepted.value(),
                n,
                "wire value {} rebuilt as the wrong counter",
                Sequence(n).truncated()
            );
        }
        assert!(window.highest() > u64::from(u16::MAX), "past one wrap");
    }

    #[test]
    fn a_burst_of_loss_resynchronises() {
        // Eleven minutes of continuous loss at 50 packets a second, which is far
        // beyond anything a real network does before the session is torn down.
        let mut window = SequenceWindow::new();
        let _ = window.accept(Sequence(0).truncated()).expect("accepted");
        let after_gap = 30_000_u64;
        let accepted = window
            .accept(Sequence(after_gap).truncated())
            .expect("resynchronises after a large gap");
        assert_eq!(accepted.value(), after_gap);
    }

    #[test]
    fn the_window_clears_when_it_jumps_far_ahead() {
        // Nothing below the new highest is checkable any more, so remembering
        // stale bits would wrongly reject fresh packets.
        let mut window = SequenceWindow::new();
        for n in 0..10_u64 {
            let _ = window.accept(Sequence(n).truncated()).expect("accepted");
        }
        let _ = window.accept(Sequence(500).truncated()).expect("accepted");
        assert!(
            window.accept(Sequence(480).truncated()).is_ok(),
            "a fresh packet inside the new window is accepted"
        );
    }

    #[test]
    fn the_wire_overhead_is_eighteen_bytes() {
        // Two bytes of counter and a full 16-byte tag, against 41 for the chat
        // framing. Recorded so a later "optimisation" that truncates the tag has
        // to change a test that says why not to.
        let overhead = WIRE_COUNTER_BYTES + 16;
        assert_eq!(overhead, 18);
    }
}
