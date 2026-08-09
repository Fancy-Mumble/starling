//! Between metadata's `Channel` and upstream's `ChannelState`.
//!
//! Here rather than in `metadata` because `session-lifecycle` announces the
//! same channels on the handshake and must not carry a second copy of this: it
//! drifted once already, when metadata learned to publish `pchat_protocol` and
//! the handshake did not, so a channel was encrypted for whoever watched it
//! being created and an ordinary room to everyone who connected afterwards.
//! Services may not link each other (`docs/ARCHITECTURE.md`), and this is
//! proto-level anyway - a `Channel` in, a `ChannelState` out.

use starling_proto::proto::tcp;

use crate::metadata::Channel;

/// Flags packed into `Channel::flags`, in the order `docs/STORAGE.md` lists.
pub const FLAG_HIDDEN: u32 = 1;
/// The channel disappears when its last member leaves.
pub const FLAG_TEMPORARY: u32 = 2;
/// The channel is **out of the tree**: parentless like the root, in nobody's
/// channel list, and sent only to clients that understand a parentless channel.
///
/// What meeting rooms and friend DMs are made of (`vendor/server/src/Channel.h`,
/// `ChannelAttribute::Detached`). It is not "ACL inheritance off", which is what
/// this said while nothing set it: dropping its parents' ACL entries is a
/// consequence of having no parents, and a channel that merely stopped
/// inheriting would still be somewhere in the tree.
///
/// Fixed at creation. A channel that gained the flag later would keep a parent
/// while claiming to have none; one that lost it would surface in every
/// client's tree under the root.
pub const FLAG_DETACHED: u32 = 4;
/// A grouping node nobody can enter.
pub const FLAG_STRUCTURAL: u32 = 8;

/// Whether `channel` is out of the tree.
///
/// A free function on the record rather than a method, because `parent: None`
/// is true of the root as well and every caller that walks by parent id has to
/// tell the two apart. Named so that the test reads as the question.
#[must_use]
pub const fn is_detached(channel: &Channel) -> bool {
    channel.flags & FLAG_DETACHED != 0
}

/// Seconds in a millisecond, for turning a creation time into a deadline.
const MILLIS: u64 = 1_000;

/// The upstream `ChannelState` for a channel.
#[must_use]
pub fn channel_state(channel: &Channel) -> tcp::ChannelState {
    let mut state = tcp::ChannelState {
        channel_id: Some(channel.id),
        // A detached channel is parentless, and unlike the root it is not the
        // one channel every client already has: it is sent as a channel with no
        // parent, which is exactly what the DETACHED attribute below warns the
        // client to expect. `Channel::parent` is already `None` for it, so this
        // is the same line either way - stated because the two parentless cases
        // reaching one field is the thing to know when reading it.
        parent: channel.parent,
        name: Some(channel.name.clone()),
        links: channel.links.clone(),
        description: Some(channel.description.clone()),
        position: Some(channel.position),
        max_users: Some(channel.max_users),
        ..tcp::ChannelState::default()
    };
    set_legacy_temporary(&mut state, channel.flags & FLAG_TEMPORARY != 0);
    // The one Fancy field written here rather than left to the envelope, because
    // it is the only signal the client has that a channel is encrypted at all:
    // it reads `ChannelState.pchat_protocol` (upstream field 1000) directly and
    // derives the persistence mode from it. Announced only when set, so a stock
    // client sees exactly what it did before.
    if channel.pchat_protocol != 0 {
        state.pchat_protocol = Some(channel.pchat_protocol as i32);
    }
    // Hidden is only ever *observed* by somebody who may already see the
    // channel - the announcement never reaches anybody else - so sending it
    // discloses nothing and is what lets a client render the room as private.
    if channel.flags & FLAG_HIDDEN != 0 {
        state.hidden = Some(true);
    }
    // Expiry, with the deadline computed here rather than left to the client:
    // `expires_at` is output-only, and a client counting down from a duration
    // and a creation time it also has to be told is a countdown that drifts.
    if channel.expiry_mode != 0 && channel.expiry_duration_s != 0 {
        state.expiry_mode = Some(channel.expiry_mode);
        state.expiry_duration_secs = Some(channel.expiry_duration_s);
        state.expires_at =
            Some(channel.created_at_ms / MILLIS + u64::from(channel.expiry_duration_s));
    }
    state.attributes = attributes(channel);
    state
}

/// The channel's own attributes, as `ChannelState.attributes` numbers them.
///
/// Only the two that are properties of the *channel*. The rest of
/// `ChannelAttribute` (`CAN_ENTER`, `ENTER_RESTRICTED`, `HIDDEN`, `TEMPORARY`)
/// is computed per recipient or duplicates a dedicated field, and this function
/// has no recipient to compute them for.
///
/// `DETACHED` is the one that has to be here: a client that is not told a
/// parentless channel is deliberately out of tree hangs it under the root,
/// which is how every private room on the server ends up in somebody's channel
/// list (`vendor/server/src/murmur/Server.cpp:3646`).
fn attributes(channel: &Channel) -> Vec<i32> {
    use tcp::ChannelAttribute;

    let mut attributes = Vec::new();
    if is_detached(channel) {
        attributes.push(ChannelAttribute::Detached as i32);
    }
    if channel.flags & FLAG_STRUCTURAL != 0 {
        attributes.push(ChannelAttribute::Structural as i32);
    }
    attributes
}

/// Write the deprecated `temporary` field.
///
/// `ChannelState.temporary` is proto-deprecated but is still the only
/// temporary-channel signal a *stock* client understands; murmur writes it for
/// the same reason (`Messages.cpp:189`). Scoped to three lines, and `expect`
/// rather than `allow` so it deletes itself if the field is ever un-deprecated.
#[expect(deprecated, reason = "the only temporary signal a stock client reads")]
fn set_legacy_temporary(state: &mut tcp::ChannelState, temporary: bool) {
    state.temporary = Some(temporary);
}
