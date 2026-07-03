//! Between the service's `Channel` and upstream's `ChannelState`.
//!
//! Upstream owns field numbers 1–99 in every upstream message and Fancy fields
//! start at 100 (`docs/PROTOCOL-COMPATIBILITY.md` §1). This module therefore
//! writes only upstream fields into `ChannelState`; the Fancy channel
//! properties travel in metadata's own envelope, where they cannot collide with
//! upstream's next field number.

use starling_proto::proto::tcp;
use starling_proto_fancy::metadata::Channel;

use crate::tree_actor::{FLAG_HIDDEN, FLAG_TEMPORARY};

/// The upstream `ChannelState` for a channel.
#[must_use]
pub fn channel_state(channel: &Channel) -> tcp::ChannelState {
    let mut state = tcp::ChannelState {
        channel_id: Some(channel.id),
        parent: channel.parent,
        name: Some(channel.name.clone()),
        links: channel.links.clone(),
        description: Some(channel.description.clone()),
        position: Some(channel.position),
        max_users: Some(channel.max_users),
        ..tcp::ChannelState::default()
    };
    set_legacy_temporary(&mut state, channel.flags & FLAG_TEMPORARY != 0);
    state
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

/// A `ChannelState` announcing only a change of links.
///
/// A **delta**, not the whole record, and that is not an optimisation. A stock
/// client reads a non-empty `links` as the complete set — it unlinks
/// everything and re-links what is listed (`vendor/server/src/mumble/Messages.cpp:935`)
/// — so an *unlink* announced as full state arrives as an empty repeated field,
/// which the client skips entirely and the removed edge stays on its screen
/// forever. `links_remove` is the only thing that takes a link away.
#[must_use]
pub fn link_state(channel: u32, added: &[u32], removed: &[u32]) -> tcp::ChannelState {
    tcp::ChannelState {
        channel_id: Some(channel),
        links_add: added.to_vec(),
        links_remove: removed.to_vec(),
        ..tcp::ChannelState::default()
    }
}

/// What an inbound `ChannelState` asked for.
///
/// The link deltas are kept apart from `fields` because they are not a field
/// write: `links_add` names channels to link *to*, each of which is a
/// separately permissioned edit of a channel other than the one being edited.
/// Folding them into the field list would have made them look like a property
/// of this channel, which is how a link ends up applied without asking the far
/// end's ACL.
#[derive(Debug, Default, Clone)]
pub struct ChannelEdit {
    /// The values the client sent.
    pub channel: Channel,
    /// Which of them it actually named.
    pub fields: Vec<String>,
    /// Channels to link to.
    pub links_add: Vec<u32>,
    /// Channels to unlink from.
    pub links_remove: Vec<u32>,
}

impl ChannelEdit {
    /// Whether the client asked to change any links.
    #[must_use]
    pub fn touches_links(&self) -> bool {
        !self.links_add.is_empty() || !self.links_remove.is_empty()
    }
}

/// Read an inbound `ChannelState` into a channel and the fields it names.
///
/// Returning the field list rather than a whole channel is what lets an update
/// touch only what the client sent — the same rule server-config follows, and
/// for the same reason.
#[must_use]
pub fn to_proto(state: &tcp::ChannelState, id: u32) -> ChannelEdit {
    let mut fields = Vec::new();
    let mut channel = Channel {
        id,
        parent: state.parent,
        ..Channel::default()
    };
    if let Some(name) = &state.name {
        channel.name = name.clone();
        fields.push("name".to_owned());
    }
    if state.parent.is_some() {
        fields.push("parent".to_owned());
    }
    if let Some(description) = &state.description {
        channel.description = description.clone();
        fields.push("description".to_owned());
    }
    if let Some(position) = state.position {
        channel.position = position;
        fields.push("position".to_owned());
    }
    if let Some(max_users) = state.max_users {
        channel.max_users = max_users;
        fields.push("max_users".to_owned());
    }
    // `links` is not applied here. A client sends it as a *complete* set and
    // the server's answer to that is a pair of deltas, so it is turned into one
    // below rather than written over `channel.links` — which the field-wise
    // update would then have had to special-case anyway.

    // `hidden` was read by nothing, so a client asking for a private room got an
    // ordinary one: the flag never reached `flags`, `is_hidden` was dead code,
    // and every visibility check downstream had nothing to test. The room was
    // then announced to everybody, which is the opposite of what was asked for.
    //
    // Folded into `flags` rather than kept as its own column because that is
    // where the tree stores it and what `Channel.flags` publishes.
    // Expiry, read for the same reason `hidden` is: the columns exist and the
    // tree loads them, but nothing ever took them off the wire, so a client
    // asking for a room that expires got one that never does.
    //
    // Mode and duration travel together — a mode with no duration has no
    // deadline to compute, and a duration with no mode is never consulted — so
    // a client that sends only one of them is asking for something incoherent
    // and neither is applied.
    if let (Some(mode), Some(duration)) = (state.expiry_mode, state.expiry_duration_secs) {
        channel.expiry_mode = mode;
        channel.expiry_duration_s = duration;
        fields.push("expiry_mode".to_owned());
        fields.push("expiry_duration_s".to_owned());
    }
    if let Some(hidden) = state.hidden {
        channel.flags = if hidden {
            channel.flags | FLAG_HIDDEN
        } else {
            channel.flags & !FLAG_HIDDEN
        };
        fields.push("flags".to_owned());
    }
    ChannelEdit {
        channel,
        fields,
        links_add: state.links_add.clone(),
        links_remove: state.links_remove.clone(),
    }
}

/// Whether a channel is hidden from clients that may not see it.
#[must_use]
pub fn is_hidden(channel: &Channel) -> bool {
    channel.flags & FLAG_HIDDEN != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stock_client_is_still_told_a_channel_is_temporary() {
        // The field is deprecated and remains the only signal a stock client
        // reads; dropping it would make temporary channels look permanent.
        let channel = Channel {
            id: 3,
            name: "Scratch".to_owned(),
            flags: FLAG_TEMPORARY,
            ..Channel::default()
        };
        #[expect(deprecated, reason = "asserting on the field the client reads")]
        let temporary = channel_state(&channel).temporary;
        assert_eq!(temporary, Some(true));
    }

    #[test]
    fn an_update_names_only_the_fields_the_client_actually_sent() {
        // Otherwise renaming a channel would silently reset its description.
        let state = tcp::ChannelState {
            channel_id: Some(4),
            name: Some("Renamed".to_owned()),
            ..tcp::ChannelState::default()
        };
        let edit = to_proto(&state, 4);
        assert_eq!(edit.channel.name, "Renamed");
        assert_eq!(edit.fields, vec!["name".to_owned()]);
        assert!(!edit.touches_links());
    }

    #[test]
    fn the_link_deltas_are_read_off_the_wire_rather_than_the_link_set() {
        // C1's actual bug: `links_add` and `links_remove` were read by nothing,
        // so a client's link button reached a server that had no field for it.
        let state = tcp::ChannelState {
            channel_id: Some(4),
            links: vec![9],
            links_add: vec![5, 6],
            links_remove: vec![7],
            ..tcp::ChannelState::default()
        };
        let edit = to_proto(&state, 4);
        assert_eq!(edit.links_add, vec![5, 6]);
        assert_eq!(edit.links_remove, vec![7]);
        assert!(edit.touches_links());
        assert!(
            edit.channel.links.is_empty(),
            "the complete-set field is not a field write"
        );
        assert!(
            !edit.fields.iter().any(|field| field.contains("link")),
            "links must not travel as a field, or the far end's ACL is never asked"
        );
    }

    #[test]
    fn an_unlink_is_announced_as_a_removal_and_not_as_an_empty_set() {
        // A stock client skips `links` when it is empty, so an unlink sent as
        // full state would leave the edge on its screen forever.
        let state = link_state(4, &[], &[7]);
        assert_eq!(state.links_remove, vec![7]);
        assert!(state.links.is_empty());
        assert_eq!(state.channel_id, Some(4));
    }
}
