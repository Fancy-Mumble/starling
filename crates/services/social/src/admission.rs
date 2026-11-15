//! Whether a social frame is acted on at all: the one check every body passes
//! before its handler.
//!
//! murmur's Fancy server checks none of these (`Messages.cpp`, the
//! `msgFancy*` handlers for typing, receipts, watch-sync, drawing and polls),
//! so anybody could type into, mark read, start a watch in, draw on, or poll
//! any room on the server. The floors here are the permission the action
//! stands for:
//!
//! | Body | Needs |
//! |---|---|
//! | typing, a new poll | `TextMessage` in the channel: it is writing there |
//! | a read receipt, a vote | `Enter` in the channel: it is reading there |
//! | watch-sync, drawing, clearing | standing in the channel: a share is watched and drawn on by who is in the room |
//!
//! A reaction asks its own question (`may_react`), and a vote on a poll the
//! caller may not see is answered exactly as one on a poll that does not exist.

use starling_proto_fancy::fancy::social::{PollVote, WatchSync, social_envelope, watch_sync};
use starling_proto_fancy::perm::Perm;
use starling_runtime::plane::{Actions, Inbound};

use crate::SocialService;

/// What a vote on a poll that is not there, or not the voter's to see, is told.
pub(crate) const NO_SUCH_POLL: &str = "That poll no longer exists on this server.";

impl SocialService {
    /// `None` to go on to the handler; otherwise what to answer instead.
    pub(crate) async fn admission(
        &self,
        inbound: &Inbound,
        body: Option<&social_envelope::Body>,
    ) -> Option<Actions> {
        use social_envelope::Body;

        let admitted = match body? {
            Body::Typing(typing) => self.may(inbound, typing.channel, Perm::TEXT_MESSAGE).await,
            Body::Poll(poll) => self.may(inbound, poll.channel, Perm::TEXT_MESSAGE).await,
            Body::Receipt(receipt) => self.may(inbound, receipt.channel, Perm::ENTER).await,
            Body::Vote(vote) => return self.vote_admission(inbound, vote).await,
            Body::Watch(sync) => self.may_watch(inbound, sync),
            Body::Stroke(stroke) => self.stands_in(inbound, stroke.channel),
            Body::Clear(clear) => self.stands_in(inbound, clear.channel),
            Body::Reaction(_) | Body::PollState(_) | Body::WatchState(_) => true,
        };
        if !admitted {
            tracing::debug!(
                session = inbound.session,
                "a social frame refused at admission"
            );
        }
        (!admitted).then(Actions::new)
    }

    async fn may(&self, inbound: &Inbound, channel: u32, permission: Perm) -> bool {
        self.permit
            .allows(inbound, channel, permission.bits())
            .await
    }

    /// Whether the sending device stands in `channel`. Every device of one
    /// user stands in one channel (`docs/SERVICES.md`, "One user, several
    /// devices"), so the device is the user here.
    fn stands_in(&self, inbound: &Inbound, channel: u32) -> bool {
        self.roster.channel_of(inbound.session) == Some(channel)
    }

    /// A watch is joined, driven and handed on from its own channel, which is
    /// the one it was started in; leaving is always allowed.
    fn may_watch(&self, inbound: &Inbound, sync: &WatchSync) -> bool {
        if sync.kind == watch_sync::Kind::Leave as i32 {
            return true;
        }
        let channel = self
            .watches
            .lock()
            .ok()
            .and_then(|watches| {
                watches
                    .get(&sync.session_id)
                    .map(|record| record.state.channel)
            })
            .unwrap_or(sync.channel);
        self.stands_in(inbound, channel)
    }

    /// A vote goes on only on a poll the voter may see; on any other the
    /// answer is the one a poll that does not exist gets, so a refusal says
    /// nothing about what is there.
    async fn vote_admission(&self, inbound: &Inbound, vote: &PollVote) -> Option<Actions> {
        let channel = self.poll_channel(inbound.scope, &vote.poll_id).await;
        match channel {
            Some(channel) if self.may(inbound, channel, Perm::ENTER).await => None,
            _ => Some(crate::refuse_vote(inbound, NO_SUCH_POLL)),
        }
    }

    /// The channel a live poll belongs to, from the cache or storage.
    async fn poll_channel(&self, scope: u32, poll_id: &str) -> Option<u32> {
        let now_ms = starling_runtime::ids::now_ms();
        let key = (scope, poll_id.to_owned());
        if self.cached(&key, now_ms) {
            return self
                .polls
                .lock()
                .ok()?
                .by_id
                .get(&key)
                .map(|record| record.poll.channel);
        }
        self.load(scope, poll_id, now_ms)
            .await
            .ok()
            .flatten()
            .map(|record| record.poll.channel)
    }
}
