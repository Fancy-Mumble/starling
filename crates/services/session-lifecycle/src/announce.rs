//! Telling clients that a user's state changed.
//!
//! One user may be several devices ([`crate::presence`]). Each device is told
//! about itself under its own id, and everyone else about the user under the
//! one id they know it by, with the user's devices left out: they never see
//! each other, so the owner's own tree does not list them twice.

use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{Actions, broadcast_excluding, to_sessions};

use crate::state::Connections;

/// Upstream `UserState`.
const USER_STATE: u16 = 9;

/// Announce a change to `subject` alone: its own device, then everyone else.
pub fn user_state(connections: &Connections, subject: u32, state: &tcp::UserState) -> Actions {
    let mut actions = device(connections, subject, state);
    actions.extend(others(connections, subject, state));
    actions
}

/// Announce a change made to every device of the user shown as `shown`.
pub fn whole_user(connections: &Connections, shown: u32, state: &tcp::UserState) -> Actions {
    let devices = connections.devices_of(shown);
    let mut actions: Actions = devices
        .iter()
        .flat_map(|pending| device(connections, pending.session, state))
        .collect();
    let subject = devices.first().map_or(shown, |pending| pending.session);
    actions.extend(others(connections, subject, state));
    actions
}

/// Announce that every device of the user shown as `shown` changed channel.
///
/// To everyone, not the channel's audience: a client builds its user tree
/// from these, so a move only the destination hears about is a user who
/// appears in two channels at once.
pub fn moved(connections: &Connections, shown: u32, state: &tcp::UserState) -> Actions {
    let devices = connections.devices_of(shown);
    let mut actions: Actions = devices
        .iter()
        .flat_map(|pending| device(connections, pending.session, state))
        .collect();
    let public = tcp::UserState {
        session: Some(shown),
        actor: state.actor.map(|actor| connections.shown_of(actor)),
        ..state.clone()
    };
    actions.push(broadcast_excluding(
        devices.iter().map(|pending| pending.session).collect(),
        USER_STATE,
        public.encode_to_vec(),
    ));
    actions
}

/// Re-announce the self-mute and self-deafen everyone else sees for `shown`,
/// after a device of it changed its own or left.
pub fn merged_flags(connections: &Connections, shown: u32) -> Actions {
    let Some(subject) = connections.devices_of(shown).first().map(|p| p.session) else {
        return Actions::new();
    };
    let (self_mute, self_deaf) = connections.merged_self_flags(shown);
    let state = tcp::UserState {
        session: Some(subject),
        self_mute: Some(self_mute),
        self_deaf: Some(self_deaf),
        ..tcp::UserState::default()
    };
    others(connections, subject, &state)
}

/// `state` as `subject`'s own device reads it.
fn device(connections: &Connections, subject: u32, state: &tcp::UserState) -> Actions {
    let own = tcp::UserState {
        session: Some(subject),
        actor: state.actor.map(|actor| connections.seen_by(subject, actor)),
        ..state.clone()
    };
    vec![to_sessions(vec![subject], USER_STATE, own.encode_to_vec())]
}

/// `state` as everyone but the user's own devices reads it.
///
/// murmur broadcasts to everybody, which is why its control fan-out grows with
/// the square of the population (`PROTOCOL-REDESIGN.md` §5, S1). Subscribers
/// get a `SyncDelta` only if they are looking at the channel the change
/// happened in, and one looking elsewhere gets nothing; that omission is the
/// saving. Encoded once for both (§4, Z3).
fn others(connections: &Connections, subject: u32, state: &tcp::UserState) -> Actions {
    let shown = connections.shown_of(subject);
    let (self_mute, self_deaf) = connections.merged_self_flags(shown);
    let public = tcp::UserState {
        session: Some(shown),
        actor: state.actor.map(|actor| connections.shown_of(actor)),
        self_mute: state.self_mute.map(|_| self_mute),
        self_deaf: state.self_deaf.map(|_| self_deaf),
        ..state.clone()
    };
    let payload = public.encode_to_vec();
    let devices: Vec<u32> = connections
        .devices_of(shown)
        .iter()
        .map(|pending| pending.session)
        .collect();
    let channel = connections
        .by_session(subject)
        .map_or(0, |pending| pending.channel);
    let (mut flood, mut subscribed) = connections.audience(channel);

    // The roster is empty or a lock was lost. Falling back to the unaddressed
    // broadcast is what this did before subscriptions existed, and it is the
    // safe direction: a state change that reaches nobody leaves a client
    // rendering a world that has moved on.
    if flood.is_empty() && subscribed.is_empty() {
        return vec![broadcast_excluding(devices, USER_STATE, payload)];
    }
    flood.retain(|session| !devices.contains(session));
    subscribed.retain(|session| !devices.contains(session));

    let mut actions = Actions::new();
    if !flood.is_empty() {
        actions.push(to_sessions(flood, USER_STATE, payload.clone()));
    }
    if !subscribed.is_empty() {
        let delta = starling_proto_fancy::fancy::domain::MetadataEnvelope {
            body: Some(
                starling_proto_fancy::fancy::domain::metadata_envelope::Body::Delta(
                    starling_proto_fancy::fancy::domain::SyncDelta {
                        user_states: vec![payload],
                        ..Default::default()
                    },
                ),
            ),
        };
        actions.push(to_sessions(
            subscribed,
            ServiceKind::Metadata.outer_type(),
            delta.encode_to_vec(),
        ));
    }
    actions
}
