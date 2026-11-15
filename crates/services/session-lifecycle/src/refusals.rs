//! Refusals about another user, which name the caller's own channel.
//!
//! A refusal carries a channel, and naming the channel the *target* stands in
//! told the caller where somebody is, a hidden room included, which the tree
//! they were sent never shows them. murmur names the target's channel, but
//! murmur has no hidden rooms. A refusal names the channel the caller asked
//! about, or their own.

use starling_proto_fancy::control::ServerAction;
use starling_proto_fancy::perm::Perm;
use starling_runtime::permit::permission_denied;
use starling_runtime::plane::Inbound;

use crate::SessionLifecycleService;

impl SessionLifecycleService {
    /// The channel the caller stands in, or the root if it is not known.
    fn own_channel(&self, inbound: &Inbound) -> u32 {
        self.connections
            .get(inbound.conn)
            .map_or(0, |pending| pending.channel)
    }

    /// A mute, deafen or suppress of somebody that may not be done.
    pub(crate) fn refused_speak_state(&self, inbound: &Inbound) -> ServerAction {
        permission_denied(inbound, Perm::MUTE_DEAFEN, self.own_channel(inbound))
    }

    /// Moving somebody who may not be moved by this caller, or is not here.
    pub(crate) fn refused_move(&self, inbound: &Inbound) -> ServerAction {
        permission_denied(inbound, Perm::MOVE, self.own_channel(inbound))
    }
}
