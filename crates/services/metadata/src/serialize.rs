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

/// Read an inbound `ChannelState` into a channel and the fields it names.
///
/// Returning the field list rather than a whole channel is what lets an update
/// touch only what the client sent — the same rule server-config follows, and
/// for the same reason.
#[must_use]
pub fn to_proto(state: &tcp::ChannelState, id: u32) -> (Channel, Vec<String>) {
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
    if !state.links.is_empty() {
        channel.links = state.links.clone();
    }
    (channel, fields)
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
        let (channel, fields) = to_proto(&state, 4);
        assert_eq!(channel.name, "Renamed");
        assert_eq!(fields, vec!["name".to_owned()]);
    }
}
