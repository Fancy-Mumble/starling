//! Who hears whom.
//!
//! A pure function of a snapshot: given who is speaking and what they aimed at,
//! produce the sessions that should receive the frame. No I/O, no locks, no
//! state service, which is the point, because this runs once per packet at 50
//! packets a second per speaker.
//!
//! # Why a snapshot rather than asking the authority
//!
//! Fan-out needs channel membership, and membership lives in the state service.
//! Asking it per packet would put voice behind its hold time, and
//! `crates/kernel/bus/RESULTS.md` §3.3 measured what that costs: a 25 ms hold
//! made 5% of packets miss their frame. Membership changes are rare and packets
//! are not, so the authority *publishes* and this *reads*.
//!
//! murmur solves the same problem with a read-write lock (`qrwlVoiceThread`);
//! this is the same idea with the lock replaced by an atomic swap.

use std::collections::{HashMap, HashSet};

use crate::ports::{ChannelId, SessionId};

use crate::targets::{ShoutTarget, TargetRegistry, VoiceTarget};

/// What a speaker aimed the frame at.
///
/// The wire carries a single number that means different things by range, so it
/// is decoded into cases here rather than compared against magic values at every
/// use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Target 0: everyone who can hear the speaker's channel.
    Normal,

    /// Target 31: the server echoes the frame to the speaker alone.
    ///
    /// A connectivity test, the client uses it to prove its UDP path works
    /// before trusting it with real audio.
    Loopback,

    /// Targets 1-30: a whisper or shout to a set the speaker registered earlier
    /// with `VoiceTarget`.
    Whisper(u8),
}

/// Target 0 (`ReservedTargetIDs::REGULAR_SPEECH`).
pub const REGULAR_SPEECH: u8 = 0;

/// Target 31 (`ReservedTargetIDs::SERVER_LOOPBACK`).
pub const SERVER_LOOPBACK: u8 = 31;

impl Target {
    /// Decode the target field of an audio packet.
    ///
    /// Anything above 31 cannot appear (the field is five bits) but a hostile
    /// peer can put whatever it likes on the wire, so out-of-range values are
    /// mapped to [`Self::Normal`] rather than trusted or panicked on.
    #[must_use]
    pub const fn decode(raw: u8) -> Self {
        match raw {
            REGULAR_SPEECH => Self::Normal,
            SERVER_LOOPBACK => Self::Loopback,
            n if n < SERVER_LOOPBACK => Self::Whisper(n),
            _ => Self::Normal,
        }
    }
}

/// What a recipient is told about why it is hearing a frame.
///
/// The wire field is `target` inbound and `context` outbound, and they are not
/// the same numbers (`MumbleUDP.proto`). Ordered by directness, which is what
/// makes [`Audience::add`] able to fold two ways of being reached with `min`.
pub mod context {
    /// Someone in the speaker's own channel.
    pub const NORMAL: u8 = 0;
    /// Reached because the speaker shouted into their channel.
    pub const SHOUT: u8 = 1;
    /// Named personally by a whisper target.
    pub const WHISPER: u8 = 2;
    /// Reached through a channel listener rather than by being anywhere near it.
    pub const LISTEN: u8 = 3;
}

/// One recipient of a frame, and how they hear it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reception {
    /// Who receives it.
    pub session: SessionId,

    /// The `context` value to put on the wire for this recipient, see
    /// [`context`]. Per recipient and not per frame, because one registered
    /// target can whisper to a person and shout into a room at once, and one
    /// channel can be both stood in and listened to.
    pub context: u8,

    /// The gain the server asks this client to apply, when it is not unity.
    ///
    /// `None` rather than `1.0` so the common path puts nothing on the wire:
    /// protobuf 3 cannot tell an absent float from zero, and the field's own
    /// documentation makes zero mean unset.
    pub gain: Option<f32>,
}

/// Who can hear whom, as of one moment.
///
/// Published by the state service whenever membership changes; never mutated by
/// the voice path. Cheap to clone-and-replace because it is rebuilt rarely.
#[derive(Debug, Clone, Default)]
pub struct RoutingSnapshot {
    channel_of: HashMap<SessionId, ChannelId>,
    members: HashMap<ChannelId, Vec<SessionId>>,
    listeners: HashMap<ChannelId, Vec<SessionId>>,
    /// Per-listener gain, keyed by the listener it belongs to.
    ///
    /// Sparse: a listener that never touched the slider has no entry, and unity
    /// is the answer for every session absent from here.
    listener_gain: HashMap<(SessionId, ChannelId), f32>,
    /// Cannot receive: deafened, by themselves or by a moderator.
    deaf: HashSet<SessionId>,
    /// Cannot send: muted, self-muted, or suppressed.
    silenced: HashSet<SessionId>,
    /// Channels linked to each channel, for a shout that carries across links.
    links: HashMap<ChannelId, Vec<ChannelId>>,
    /// The parent of each channel, for a shout that carries into children.
    ///
    /// Stored parent-ward rather than child-ward because that is the direction
    /// the tree is walked to answer "is this channel below that one" without
    /// recursing through every branch.
    parent_of: HashMap<ChannelId, ChannelId>,
    /// Every session's registered whisper and shout targets.
    targets: TargetRegistry,
}

impl RoutingSnapshot {
    /// An empty snapshot, nobody connected.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Place a session in a channel.
    #[must_use]
    pub fn with_member(mut self, session: SessionId, channel: ChannelId) -> Self {
        let _ = self.channel_of.insert(session, channel);
        self.members.entry(channel).or_default().push(session);
        self
    }

    /// Let a session hear a channel without joining it.
    #[must_use]
    pub fn with_listener(mut self, session: SessionId, channel: ChannelId) -> Self {
        self.listeners.entry(channel).or_default().push(session);
        self
    }

    /// Set the gain a listener has asked for on one of its channels.
    ///
    /// Recorded even for a session that is not (yet) a listener of that channel:
    /// murmur keeps the adjustment alive across the listener being removed and
    /// re-added, so that turning a channel off and on again does not silently
    /// reset a slider the user set deliberately.
    #[must_use]
    pub fn with_listener_gain(mut self, session: SessionId, channel: ChannelId, gain: f32) -> Self {
        let _ = self.listener_gain.insert((session, channel), gain);
        self
    }

    /// Mark a session as unable to receive.
    #[must_use]
    pub fn with_deaf(mut self, session: SessionId) -> Self {
        let _ = self.deaf.insert(session);
        self
    }

    /// Mark a session as unable to send.
    #[must_use]
    pub fn with_silenced(mut self, session: SessionId) -> Self {
        let _ = self.silenced.insert(session);
        self
    }

    /// Link two channels, so a shout into one carries into the other.
    ///
    /// Links are symmetric in Mumble: linking A to B means audio flows both
    /// ways, and recording only one direction would make shouts work depending
    /// on which channel the operator named first.
    #[must_use]
    pub fn with_link(mut self, one: ChannelId, other: ChannelId) -> Self {
        self.links.entry(one).or_default().push(other);
        self.links.entry(other).or_default().push(one);
        self
    }

    /// Place a channel under a parent, so a shout can carry into it.
    #[must_use]
    pub fn with_parent(mut self, child: ChannelId, parent: ChannelId) -> Self {
        let _ = self.parent_of.insert(child, parent);
        self
    }

    /// Register a session's whisper or shout target.
    #[must_use]
    pub fn with_target(mut self, session: SessionId, slot: u8, target: VoiceTarget) -> Self {
        // A rejected slot is dropped rather than propagated: this builder is fed
        // by the authority, which has already validated the client's request.
        let _ = self.targets.set(session, slot, target);
        self
    }

    /// Replace the whole target registry.
    ///
    /// Used when the authority rebuilds a snapshot: targets outlive membership
    /// changes, so they are carried across rather than re-registered one by one.
    #[must_use]
    pub fn with_targets(mut self, targets: TargetRegistry) -> Self {
        self.targets = targets;
        self
    }

    /// The channel a session is in.
    #[must_use]
    pub fn channel_of(&self, session: SessionId) -> Option<ChannelId> {
        self.channel_of.get(&session).copied()
    }

    /// Whether a session may send audio at all.
    ///
    /// Checked before routing, not after: murmur drops the packet at the top of
    /// `processMsg` for a muted or suppressed speaker, so no recipient list is
    /// ever built.
    #[must_use]
    pub fn may_speak(&self, session: SessionId) -> bool {
        !self.silenced.contains(&session)
    }

    /// Everyone who should receive a frame from `speaker` aimed at `target`.
    ///
    /// Returns empty when the speaker may not send, when the target resolves to
    /// nobody, or when every candidate is deafened. An empty list is a normal
    /// outcome, not an error: one person alone in a channel produces it on every
    /// packet.
    #[must_use]
    pub fn recipients(&self, speaker: SessionId, target: Target) -> Vec<SessionId> {
        self.fan_out(speaker, target)
            .into_iter()
            .map(|reception| reception.session)
            .collect()
    }

    /// Everyone who should receive the frame, each with the context and gain
    /// their copy carries.
    ///
    /// The same question as [`Self::recipients`] and the one the packet path
    /// actually asks, because a recipient's context is not a property of the
    /// frame: being in the channel *and* listening to it are two ways to be
    /// reached, and murmur folds them (`AudioReceiverBuffer.cpp:88`) rather than
    /// sending two copies.
    #[must_use]
    pub fn fan_out(&self, speaker: SessionId, target: Target) -> Vec<Reception> {
        if !self.may_speak(speaker) {
            return Vec::new();
        }

        match target {
            // The echo is deliberately exempt from the deaf check: it is a
            // connectivity test, and a deafened client still needs to know
            // whether its UDP path works. It is also exempt from `Audience`,
            // which would drop it for being addressed to the speaker.
            Target::Loopback => vec![Reception {
                session: speaker,
                context: context::NORMAL,
                gain: None,
            }],

            Target::Normal => {
                let Some(channel) = self.channel_of(speaker) else {
                    return Vec::new();
                };
                let mut audience = Audience::new(speaker, &self.deaf);
                self.gather_channel(&mut audience, channel, context::NORMAL);
                audience.finish()
            }

            // A slot the speaker filled in advance with `VoiceTarget`. An
            // unregistered slot reaches nobody: falling back to the speaker's
            // channel would send a whisper to exactly the people they excluded.
            Target::Whisper(slot) => self.whisper_fan_out(speaker, slot),
        }
    }

    /// Everyone a registered target reaches.
    ///
    /// The union of the users it names and the channels it shouts into, minus
    /// the speaker and anyone deafened. Deduplicated by [`Audience`]: a session
    /// named both directly and by channel must hear the frame once, not twice.
    ///
    /// The users it names get [`context::WHISPER`] and the channels it shouts
    /// into get [`context::SHOUT`], which is a distinction the client shows:
    /// murmur sends `SpeechFlags::Whisper` and `SpeechFlags::Shout`, and a
    /// Mumble client renders and logs the two differently. Telling someone being
    /// whispered to that they are hearing a room is the failure this avoids.
    fn whisper_fan_out(&self, speaker: SessionId, slot: u8) -> Vec<Reception> {
        let Some(target) = self.targets.get(speaker, slot) else {
            return Vec::new();
        };

        let mut audience = Audience::new(speaker, &self.deaf);
        for named in target.users() {
            // A target outlives the sessions it names, so whispering at somebody
            // who has since disconnected is routine rather than exceptional.
            if self.channel_of(*named).is_some() {
                audience.add(*named, context::WHISPER, None);
            }
        }
        for shout in target.channels() {
            self.gather_shout(&mut audience, *shout);
        }
        audience.finish()
    }

    /// Everyone a single shout reaches.
    fn gather_shout(&self, audience: &mut Audience, shout: ShoutTarget) {
        let mut channels = vec![shout.channel];

        if shout.include_links {
            channels.extend(
                self.links
                    .get(&shout.channel)
                    .into_iter()
                    .flatten()
                    .copied(),
            );
        }

        if shout.include_children {
            // Every channel whose ancestry reaches the shouted-at one. Walking
            // upward from each channel rather than downward from the target
            // needs no child index and cannot loop forever on a malformed tree.
            channels.extend(
                self.members
                    .keys()
                    .filter(|candidate| self.is_below(**candidate, shout.channel))
                    .copied(),
            );
        }

        for channel in channels {
            self.gather_channel(audience, channel, context::SHOUT);
        }
    }

    /// Whether `channel` is anywhere below `ancestor`.
    ///
    /// Bounded by the number of channels: a cycle in `parent_of` would otherwise
    /// hang the voice task, and the authority is not the only thing that can put
    /// one there, a corrupt database can too.
    fn is_below(&self, channel: ChannelId, ancestor: ChannelId) -> bool {
        let mut at = channel;
        for _ in 0..self.parent_of.len() {
            let Some(parent) = self.parent_of.get(&at).copied() else {
                return false;
            };
            if parent == ancestor {
                return true;
            }
            at = parent;
        }
        false
    }

    /// Members of a channel plus anyone listening to it.
    ///
    /// `standing` is the context for people actually in the channel, normal
    /// speech or a shout, depending on how the channel was reached. Listeners
    /// always get [`context::LISTEN`] and their own gain, whichever way the
    /// audio arrived at the channel they are listening to.
    fn gather_channel(&self, audience: &mut Audience, channel: ChannelId, standing: u8) {
        for session in self.members.get(&channel).into_iter().flatten() {
            audience.add(*session, standing, None);
        }
        for session in self.listeners.get(&channel).into_iter().flatten() {
            let gain = self.listener_gain.get(&(*session, channel)).copied();
            audience.add(*session, context::LISTEN, gain);
        }
    }
}

/// The recipients of one frame, being accumulated.
///
/// murmur's `AudioReceiverBuffer`: an ordered list with an index beside it, so
/// that reaching the same person twice updates their entry instead of appending
/// a second one. Two copies of a frame is not a wasted packet, it is an audible
/// echo.
struct Audience<'a> {
    /// Excluded from their own fan-out, normal speech echoed back would double
    /// every speaker's own audio.
    speaker: SessionId,
    /// Excluded because they receive nothing at all.
    deaf: &'a HashSet<SessionId>,
    order: Vec<Reception>,
    index: HashMap<SessionId, usize>,
}

impl<'a> Audience<'a> {
    fn new(speaker: SessionId, deaf: &'a HashSet<SessionId>) -> Self {
        Self {
            speaker,
            deaf,
            order: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Record one way of reaching `session`, folding it with any other.
    ///
    /// Both folds are murmur's (`AudioReceiverBuffer.cpp:87-90`) and neither is
    /// arbitrary:
    ///
    /// * **context takes the minimum**, the most direct way of being reached
    ///   wins, so somebody standing in the channel they also listen to is told
    ///   they are hearing their own room rather than a remote one.
    /// * **gain takes the maximum**, a listener gain must never quieten audio
    ///   the session was going to receive anyway at full volume. Being in the
    ///   channel is unity, so a listener who turned that channel down to 0.2 and
    ///   then walked into it hears it at 1.0.
    fn add(&mut self, session: SessionId, context: u8, gain: Option<f32>) {
        if session == self.speaker || self.deaf.contains(&session) {
            return;
        }
        match self.index.get(&session).copied() {
            None => {
                let _ = self.index.insert(session, self.order.len());
                self.order.push(Reception {
                    session,
                    context,
                    gain,
                });
            }
            Some(at) => {
                let existing = &mut self.order[at];
                existing.context = existing.context.min(context);
                // `None` is unity, and unity beats any attenuation.
                existing.gain = match (existing.gain, gain) {
                    (Some(held), Some(new)) => Some(held.max(new)),
                    _ => None,
                };
            }
        }
    }

    fn finish(self) -> Vec<Reception> {
        self.order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOBBY: ChannelId = ChannelId(0);
    const ANNEX: ChannelId = ChannelId(1);
    const ALICE: SessionId = SessionId(1);
    const BOB: SessionId = SessionId(2);
    const CAROL: SessionId = SessionId(3);

    fn shout(channel: ChannelId) -> ShoutTarget {
        ShoutTarget {
            channel,
            include_links: false,
            include_children: false,
        }
    }

    fn lobby_with_three() -> RoutingSnapshot {
        RoutingSnapshot::new()
            .with_member(ALICE, LOBBY)
            .with_member(BOB, LOBBY)
            .with_member(CAROL, LOBBY)
    }

    #[test]
    fn targets_decode_by_range() {
        assert_eq!(Target::decode(0), Target::Normal);
        assert_eq!(Target::decode(31), Target::Loopback);
        assert_eq!(Target::decode(1), Target::Whisper(1));
        assert_eq!(Target::decode(30), Target::Whisper(30));
    }

    #[test]
    fn an_out_of_range_target_is_not_trusted() {
        // The field is five bits, so this cannot occur honestly, but a hostile
        // peer writes whatever it likes.
        for raw in [32, 100, 255] {
            assert_eq!(Target::decode(raw), Target::Normal, "raw {raw}");
        }
    }

    #[test]
    fn normal_speech_reaches_the_rest_of_the_channel() {
        let snapshot = lobby_with_three();
        let mut heard = snapshot.recipients(ALICE, Target::Normal);
        heard.sort_by_key(|s| s.0);
        assert_eq!(heard, vec![BOB, CAROL]);
    }

    #[test]
    fn a_speaker_does_not_hear_themselves() {
        // Echoing normal speech back would double every speaker's own audio.
        assert!(
            !lobby_with_three()
                .recipients(ALICE, Target::Normal)
                .contains(&ALICE)
        );
    }

    #[test]
    fn another_channel_hears_nothing() {
        let snapshot = lobby_with_three().with_member(SessionId(4), ANNEX);
        assert!(
            !snapshot
                .recipients(ALICE, Target::Normal)
                .contains(&SessionId(4))
        );
    }

    #[test]
    fn a_deafened_listener_is_skipped() {
        let snapshot = lobby_with_three().with_deaf(BOB);
        assert_eq!(snapshot.recipients(ALICE, Target::Normal), vec![CAROL]);
    }

    #[test]
    fn a_silenced_speaker_reaches_nobody() {
        // Dropped before a recipient list is built, as murmur does at the top of
        // `processMsg`.
        let snapshot = lobby_with_three().with_silenced(ALICE);
        assert!(snapshot.recipients(ALICE, Target::Normal).is_empty());
        assert!(!snapshot.may_speak(ALICE));
    }

    #[test]
    fn a_listener_hears_a_channel_without_joining_it() {
        let snapshot = lobby_with_three().with_listener(SessionId(9), LOBBY);
        assert!(
            snapshot
                .recipients(ALICE, Target::Normal)
                .contains(&SessionId(9))
        );
    }

    /// How `session` hears the frame, or `None` if they do not.
    fn heard_by(
        snapshot: &RoutingSnapshot,
        session: SessionId,
        target: Target,
    ) -> Option<Reception> {
        snapshot
            .fan_out(ALICE, target)
            .into_iter()
            .find(|reception| reception.session == session)
    }

    #[test]
    fn a_listener_is_told_it_is_hearing_a_channel_it_is_not_in() {
        // Context 3, which is what makes a client render it as a listener rather
        // than as somebody in the room.
        let listener = SessionId(9);
        let snapshot = lobby_with_three().with_listener(listener, LOBBY);
        let reception =
            heard_by(&snapshot, listener, Target::Normal).expect("the listener heard nothing");
        assert_eq!(reception.context, context::LISTEN);
        assert_eq!(reception.gain, None, "an untouched slider is not a gain");
    }

    #[test]
    fn a_listener_gain_rides_along_with_the_frame() {
        let listener = SessionId(9);
        let snapshot = lobby_with_three()
            .with_listener(listener, LOBBY)
            .with_listener_gain(listener, LOBBY, 0.25);
        assert_eq!(
            heard_by(&snapshot, listener, Target::Normal).and_then(|r| r.gain),
            Some(0.25)
        );
    }

    #[test]
    fn standing_in_a_channel_you_also_listen_to_is_heard_once_and_plainly() {
        // murmur folds the two ways of being reached rather than sending two
        // copies, and takes the *minimum* context: Bob is in the lobby, so he is
        // told he is hearing his own room, not a remote one.
        let snapshot = lobby_with_three().with_listener(BOB, LOBBY);
        let heard = snapshot.fan_out(ALICE, Target::Normal);
        assert_eq!(
            heard.iter().filter(|r| r.session == BOB).count(),
            1,
            "two copies of a frame is an audible echo, not a wasted packet"
        );
        assert_eq!(
            heard_by(&snapshot, BOB, Target::Normal).map(|r| r.context),
            Some(context::NORMAL)
        );
    }

    #[test]
    fn a_listener_gain_never_quietens_audio_that_was_already_unity() {
        // Bob turned the lobby down to a fifth and then walked into it. Being in
        // the channel is unity, and murmur takes the louder of the two, the
        // slider is for a room you are listening to from elsewhere.
        let snapshot = lobby_with_three()
            .with_listener(BOB, LOBBY)
            .with_listener_gain(BOB, LOBBY, 0.2);
        assert_eq!(
            heard_by(&snapshot, BOB, Target::Normal).and_then(|r| r.gain),
            None
        );
    }

    #[test]
    fn a_listener_hears_a_shout_into_the_channel_it_listens_to() {
        // The shout reaches the channel; the listener is attached to the
        // channel, so it reaches them too, but as a listener, with their gain.
        let listener = SessionId(9);
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), ANNEX)
            .with_listener(listener, ANNEX)
            .with_listener_gain(listener, ANNEX, 0.5)
            .with_target(ALICE, 4, VoiceTarget::new().shouting_to(shout(ANNEX)));
        let reception =
            heard_by(&snapshot, listener, Target::Whisper(4)).expect("the listener heard nothing");
        assert_eq!(reception.context, context::LISTEN);
        assert_eq!(reception.gain, Some(0.5));
    }

    #[test]
    fn a_deafened_listener_hears_nothing() {
        let listener = SessionId(9);
        let snapshot = lobby_with_three()
            .with_listener(listener, LOBBY)
            .with_deaf(listener);
        assert!(heard_by(&snapshot, listener, Target::Normal).is_none());
    }

    #[test]
    fn listening_to_your_own_channel_does_not_echo_you_back() {
        // A client that listens to the room it is standing in must not start
        // hearing its own voice.
        let snapshot = lobby_with_three().with_listener(ALICE, LOBBY);
        assert!(heard_by(&snapshot, ALICE, Target::Normal).is_none());
    }

    #[test]
    fn loopback_returns_to_the_speaker_alone() {
        let snapshot = lobby_with_three();
        assert_eq!(snapshot.recipients(ALICE, Target::Loopback), vec![ALICE]);
    }

    #[test]
    fn loopback_works_for_a_deafened_client() {
        // It is a connectivity test: a deafened client still needs to learn
        // whether its UDP path is usable.
        let snapshot = lobby_with_three().with_deaf(ALICE);
        assert_eq!(snapshot.recipients(ALICE, Target::Loopback), vec![ALICE]);
    }

    #[test]
    fn a_silenced_speaker_cannot_even_loop_back() {
        let snapshot = lobby_with_three().with_silenced(ALICE);
        assert!(snapshot.recipients(ALICE, Target::Loopback).is_empty());
    }

    #[test]
    fn an_unregistered_whisper_slot_reaches_nobody() {
        // Falling back to the speaker's channel would send a whisper to exactly
        // the people the speaker excluded, which is worse than silence.
        let snapshot = lobby_with_three();
        assert!(snapshot.recipients(ALICE, Target::Whisper(3)).is_empty());
    }

    #[test]
    fn a_whisper_reaches_the_users_it_names() {
        let snapshot =
            lobby_with_three().with_target(ALICE, 3, VoiceTarget::new().whispering_to(BOB));
        assert_eq!(snapshot.recipients(ALICE, Target::Whisper(3)), vec![BOB]);
    }

    #[test]
    fn a_whisper_does_not_reach_the_rest_of_the_channel() {
        // The whole point of a whisper. Carol is in the lobby and must not hear
        // a frame Alice aimed only at Bob.
        let snapshot =
            lobby_with_three().with_target(ALICE, 3, VoiceTarget::new().whispering_to(BOB));
        assert!(
            !snapshot
                .recipients(ALICE, Target::Whisper(3))
                .contains(&CAROL)
        );
    }

    #[test]
    fn a_shout_reaches_a_whole_channel() {
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), ANNEX)
            .with_target(ALICE, 4, VoiceTarget::new().shouting_to(shout(ANNEX)));
        assert_eq!(
            snapshot.recipients(ALICE, Target::Whisper(4)),
            vec![SessionId(4)]
        );
    }

    #[test]
    fn a_shout_can_carry_across_a_link() {
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), ANNEX)
            .with_link(LOBBY, ANNEX)
            .with_target(
                ALICE,
                5,
                VoiceTarget::new().shouting_to(ShoutTarget {
                    channel: LOBBY,
                    include_links: true,
                    include_children: false,
                }),
            );

        let heard = snapshot.recipients(ALICE, Target::Whisper(5));
        assert!(heard.contains(&SessionId(4)), "the link was not followed");
        assert!(heard.contains(&BOB));
    }

    #[test]
    fn a_link_works_in_both_directions() {
        // Recording one direction only would make shouts depend on which
        // channel the operator happened to name first.
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), ANNEX)
            .with_link(ANNEX, LOBBY)
            .with_target(
                ALICE,
                5,
                VoiceTarget::new().shouting_to(ShoutTarget {
                    channel: LOBBY,
                    include_links: true,
                    include_children: false,
                }),
            );
        assert!(
            snapshot
                .recipients(ALICE, Target::Whisper(5))
                .contains(&SessionId(4))
        );
    }

    #[test]
    fn a_shout_does_not_cross_a_link_unless_asked() {
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), ANNEX)
            .with_link(LOBBY, ANNEX)
            .with_target(ALICE, 5, VoiceTarget::new().shouting_to(shout(LOBBY)));
        assert!(
            !snapshot
                .recipients(ALICE, Target::Whisper(5))
                .contains(&SessionId(4))
        );
    }

    #[test]
    fn a_shout_can_carry_into_children() {
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), ANNEX)
            .with_parent(ANNEX, LOBBY)
            .with_target(
                ALICE,
                6,
                VoiceTarget::new().shouting_to(ShoutTarget {
                    channel: LOBBY,
                    include_links: false,
                    include_children: true,
                }),
            );
        assert!(
            snapshot
                .recipients(ALICE, Target::Whisper(6))
                .contains(&SessionId(4))
        );
    }

    #[test]
    fn a_shout_into_children_reaches_grandchildren() {
        let deep = ChannelId(2);
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), deep)
            .with_parent(ANNEX, LOBBY)
            .with_parent(deep, ANNEX)
            .with_target(
                ALICE,
                6,
                VoiceTarget::new().shouting_to(ShoutTarget {
                    channel: LOBBY,
                    include_links: false,
                    include_children: true,
                }),
            );
        assert!(
            snapshot
                .recipients(ALICE, Target::Whisper(6))
                .contains(&SessionId(4))
        );
    }

    #[test]
    fn a_cycle_in_the_channel_tree_does_not_hang() {
        // The authority should never produce one, but a corrupt database can,
        // and a hang here takes every call on the server down.
        let snapshot = lobby_with_three()
            .with_member(SessionId(4), ANNEX)
            .with_parent(LOBBY, ANNEX)
            .with_parent(ANNEX, LOBBY)
            .with_target(
                ALICE,
                6,
                VoiceTarget::new().shouting_to(ShoutTarget {
                    channel: LOBBY,
                    include_links: false,
                    include_children: true,
                }),
            );
        let _ = snapshot.recipients(ALICE, Target::Whisper(6));
    }

    #[test]
    fn a_listener_named_twice_hears_the_frame_once() {
        // Named directly and reached by the shout. Two copies is audible.
        let snapshot = lobby_with_three().with_target(
            ALICE,
            7,
            VoiceTarget::new()
                .whispering_to(BOB)
                .shouting_to(shout(LOBBY)),
        );
        let heard = snapshot.recipients(ALICE, Target::Whisper(7));
        assert_eq!(heard.iter().filter(|s| **s == BOB).count(), 1);
    }

    #[test]
    fn a_whisper_does_not_return_to_its_speaker() {
        let snapshot = lobby_with_three().with_target(
            ALICE,
            7,
            VoiceTarget::new()
                .whispering_to(ALICE)
                .shouting_to(shout(LOBBY)),
        );
        assert!(
            !snapshot
                .recipients(ALICE, Target::Whisper(7))
                .contains(&ALICE)
        );
    }

    #[test]
    fn a_deafened_user_is_skipped_by_a_whisper_too() {
        let snapshot = lobby_with_three().with_deaf(BOB).with_target(
            ALICE,
            3,
            VoiceTarget::new().whispering_to(BOB),
        );
        assert!(snapshot.recipients(ALICE, Target::Whisper(3)).is_empty());
    }

    #[test]
    fn a_silenced_speaker_cannot_whisper_either() {
        let snapshot = lobby_with_three().with_silenced(ALICE).with_target(
            ALICE,
            3,
            VoiceTarget::new().whispering_to(BOB),
        );
        assert!(snapshot.recipients(ALICE, Target::Whisper(3)).is_empty());
    }

    #[test]
    fn whispering_to_a_departed_session_reaches_nobody() {
        // Targets outlive the sessions they name, so this is routine rather
        // than exceptional.
        let snapshot = lobby_with_three().with_target(
            ALICE,
            3,
            VoiceTarget::new().whispering_to(SessionId(99)),
        );
        assert!(snapshot.recipients(ALICE, Target::Whisper(3)).is_empty());
    }

    #[test]
    fn a_speaker_in_no_channel_reaches_nobody() {
        let snapshot = RoutingSnapshot::new();
        assert!(snapshot.recipients(ALICE, Target::Normal).is_empty());
    }

    #[test]
    fn speaking_alone_is_an_empty_list_not_an_error() {
        let snapshot = RoutingSnapshot::new().with_member(ALICE, LOBBY);
        assert!(snapshot.recipients(ALICE, Target::Normal).is_empty());
    }
}
