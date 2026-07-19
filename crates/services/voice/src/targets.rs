//! Whisper and shout targets, as registered by `VoiceTarget`.
//!
//! Mumble's audio header has five bits of target. Zero is normal speech and 31
//! is the server loopback; the thirty in between are *slots a client fills in
//! advance*. A client sends `VoiceTarget` over TCP saying "target 3 means these
//! two channels and this user", and afterwards sends audio at target 3.
//!
//! # Why the registration is per session and not global
//!
//! Target 3 means something different for every speaker. Two clients both using
//! slot 3 for unrelated groups is the normal case, not a collision, which is
//! why this is a map from session to slots rather than a table of routes.
//!
//! # What the words mean
//!
//! | | |
//! |---|---|
//! | *whisper* | to specific users |
//! | *shout* | to a channel, optionally its links and children |
//!
//! One target can be both at once, and upstream sends the union.

use std::collections::HashMap;

use crate::ports::{ChannelId, SessionId};

/// The highest slot a client may register.
///
/// Slots run 1..=30: 0 is normal speech and 31 is the loopback, and neither can
/// be reassigned. A client asking for either is refused rather than clamped,
/// silently rewriting slot 31 would break the client's connectivity probe.
pub const MAX_TARGET: u8 = 30;

/// How many slots one session may hold.
///
/// Every slot is a fan-out the server evaluates per packet, so this is the bound
/// on how much work one client can make the voice path do. Upstream allows the
/// full range and this matches it; the constant exists so the limit has a name.
pub const MAX_SLOTS: usize = MAX_TARGET as usize;

/// One registered target.
///
/// Both halves can be populated: upstream's `VoiceTarget` message carries a
/// repeated group of which each entry may name users, a channel, or both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VoiceTarget {
    /// Specific users to whisper to.
    users: Vec<SessionId>,
    /// Channels to shout into.
    channels: Vec<ShoutTarget>,
}

/// A channel a target shouts into, and how far the shout carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShoutTarget {
    /// The channel itself.
    pub channel: ChannelId,
    /// Also everyone in channels linked to it.
    pub include_links: bool,
    /// Also everyone in its sub-channels, recursively.
    pub include_children: bool,
}

impl VoiceTarget {
    /// An empty target.
    ///
    /// A client may legitimately register one: it is how a client *clears* a
    /// slot, and murmur treats an empty target as "reaches nobody" rather than
    /// as an error.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user to whisper to.
    #[must_use]
    pub fn whispering_to(mut self, session: SessionId) -> Self {
        self.users.push(session);
        self
    }

    /// Add a channel to shout into.
    #[must_use]
    pub fn shouting_to(mut self, shout: ShoutTarget) -> Self {
        self.channels.push(shout);
        self
    }

    /// The users this target names directly.
    #[must_use]
    pub fn users(&self) -> &[SessionId] {
        &self.users
    }

    /// The channels this target shouts into.
    #[must_use]
    pub fn channels(&self) -> &[ShoutTarget] {
        &self.channels
    }

    /// Whether this target reaches nobody.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty() && self.channels.is_empty()
    }
}

/// Every session's registered targets.
#[derive(Debug, Default, Clone)]
pub struct TargetRegistry {
    slots: HashMap<SessionId, HashMap<u8, VoiceTarget>>,
}

/// Why a target could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// Slot 0 or 31, which the protocol reserves.
    #[error("target {0} is reserved: 0 is normal speech and 31 is the loopback")]
    Reserved(u8),

    /// The session already holds [`MAX_SLOTS`] targets.
    #[error("a session may hold at most {MAX_SLOTS} targets")]
    TooMany,
}

impl TargetRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `target` in `slot` for `session`.
    ///
    /// Replaces whatever was there: a client re-registering a slot is changing
    /// its mind, not adding to it, and upstream overwrites for the same reason.
    ///
    /// # Errors
    ///
    /// [`TargetError`] for a reserved slot or one session too many.
    pub fn set(
        &mut self,
        session: SessionId,
        slot: u8,
        target: VoiceTarget,
    ) -> Result<(), TargetError> {
        if slot == 0 || slot > MAX_TARGET {
            return Err(TargetError::Reserved(slot));
        }

        let held = self.slots.entry(session).or_default();
        if held.len() >= MAX_SLOTS && !held.contains_key(&slot) {
            return Err(TargetError::TooMany);
        }

        // An empty target clears the slot rather than occupying one, which is
        // how a client releases a target it no longer wants.
        if target.is_empty() {
            let _ = held.remove(&slot);
        } else {
            let _ = held.insert(slot, target);
        }
        Ok(())
    }

    /// What `session` registered in `slot`.
    #[must_use]
    pub fn get(&self, session: SessionId, slot: u8) -> Option<&VoiceTarget> {
        self.slots.get(&session)?.get(&slot)
    }

    /// Forget every target a session registered.
    ///
    /// Called on disconnect. Without it the registry grows by one entry per
    /// session for the life of the process.
    pub fn forget(&mut self, session: SessionId) {
        let _ = self.slots.remove(&session);
    }

    /// How many sessions hold at least one target.
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: SessionId = SessionId(1);
    const BOB: SessionId = SessionId(2);
    const LOBBY: ChannelId = ChannelId(0);

    fn shout(channel: ChannelId) -> ShoutTarget {
        ShoutTarget {
            channel,
            include_links: false,
            include_children: false,
        }
    }

    fn whisper_to_bob() -> VoiceTarget {
        VoiceTarget::new().whispering_to(BOB)
    }

    #[test]
    fn a_registered_target_comes_back() {
        let mut registry = TargetRegistry::new();
        registry.set(ALICE, 3, whisper_to_bob()).expect("set");
        assert_eq!(registry.get(ALICE, 3), Some(&whisper_to_bob()));
    }

    #[test]
    fn an_unregistered_slot_is_empty() {
        assert_eq!(TargetRegistry::new().get(ALICE, 3), None);
    }

    #[test]
    fn one_slot_means_different_things_for_different_speakers() {
        // The reason this is keyed by session. Two clients using slot 3 for
        // unrelated groups is the normal case, not a collision.
        let mut registry = TargetRegistry::new();
        registry.set(ALICE, 3, whisper_to_bob()).expect("set");
        registry
            .set(BOB, 3, VoiceTarget::new().shouting_to(shout(LOBBY)))
            .expect("set");

        assert_eq!(
            registry.get(ALICE, 3).map(VoiceTarget::users),
            Some(&[BOB][..])
        );
        assert!(registry.get(BOB, 3).expect("set").users().is_empty());
    }

    #[test]
    fn re_registering_a_slot_replaces_it() {
        // The client changed its mind. Merging would leave it whispering to
        // someone it deliberately removed.
        let mut registry = TargetRegistry::new();
        registry.set(ALICE, 3, whisper_to_bob()).expect("set");
        registry
            .set(ALICE, 3, VoiceTarget::new().whispering_to(SessionId(9)))
            .expect("set");

        assert_eq!(
            registry.get(ALICE, 3).map(VoiceTarget::users),
            Some(&[SessionId(9)][..])
        );
    }

    #[test]
    fn the_reserved_slots_are_refused() {
        // Slot 0 is normal speech and 31 is the connectivity probe. Silently
        // clamping either would break the client rather than the request.
        let mut registry = TargetRegistry::new();
        assert_eq!(
            registry.set(ALICE, 0, whisper_to_bob()),
            Err(TargetError::Reserved(0))
        );
        assert_eq!(
            registry.set(ALICE, 31, whisper_to_bob()),
            Err(TargetError::Reserved(31))
        );
    }

    #[test]
    fn a_slot_beyond_five_bits_is_refused() {
        // Cannot arrive honestly (the field is five bits) but a hostile peer
        // writes what it likes into a TCP message.
        let mut registry = TargetRegistry::new();
        for slot in [32, 100, 255] {
            assert_eq!(
                registry.set(ALICE, slot, whisper_to_bob()),
                Err(TargetError::Reserved(slot))
            );
        }
    }

    #[test]
    fn every_legal_slot_is_accepted() {
        let mut registry = TargetRegistry::new();
        for slot in 1..=MAX_TARGET {
            registry
                .set(ALICE, slot, whisper_to_bob())
                .unwrap_or_else(|_| panic!("slot {slot} was refused"));
        }
    }

    #[test]
    fn an_empty_target_clears_the_slot() {
        // How a client releases a target. Storing it would leave a slot that
        // reaches nobody occupying the session's budget.
        let mut registry = TargetRegistry::new();
        registry.set(ALICE, 3, whisper_to_bob()).expect("set");
        registry.set(ALICE, 3, VoiceTarget::new()).expect("clear");
        assert_eq!(registry.get(ALICE, 3), None);
    }

    #[test]
    fn a_target_can_whisper_and_shout_at_once() {
        // Upstream sends the union; treating them as exclusive would silently
        // drop half of what the client asked for.
        let target = VoiceTarget::new()
            .whispering_to(BOB)
            .shouting_to(shout(LOBBY));
        assert_eq!(target.users(), &[BOB]);
        assert_eq!(target.channels().len(), 1);
        assert!(!target.is_empty());
    }

    #[test]
    fn forgetting_a_session_clears_its_slots() {
        // A leak here is one entry per disconnect, forever.
        let mut registry = TargetRegistry::new();
        registry.set(ALICE, 3, whisper_to_bob()).expect("set");
        registry.forget(ALICE);
        assert_eq!(registry.get(ALICE, 3), None);
        assert_eq!(registry.sessions(), 0);
    }

    #[test]
    fn forgetting_one_session_leaves_another() {
        let mut registry = TargetRegistry::new();
        registry.set(ALICE, 3, whisper_to_bob()).expect("set");
        registry.set(BOB, 3, whisper_to_bob()).expect("set");
        registry.forget(ALICE);
        assert_eq!(registry.sessions(), 1);
        assert!(registry.get(BOB, 3).is_some());
    }

    #[test]
    fn forgetting_an_unknown_session_is_harmless() {
        let mut registry = TargetRegistry::new();
        registry.forget(ALICE);
        assert_eq!(registry.sessions(), 0);
    }
}
