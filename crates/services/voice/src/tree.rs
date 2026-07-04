//! The channel tree, as far as a shout needs to know it.
//!
//! A shout may carry into a channel's **links** and into its **children**
//! ([`crate::targets::ShoutTarget`]), and the routing core already resolves
//! both. What it resolves them *against* is a snapshot, and until this module
//! existed nothing ever filled that half in: `session-view` publishes who is in
//! which channel and says nothing about how the channels relate, so
//! `include_links` and `include_children` were read, honoured, and matched
//! nothing.
//!
//! That is the worst shape a feature can fail in. A shout with links ticked
//! reaches the base channel and stops, which is indistinguishable from a shout
//! that worked — the speaker is heard by *someone*, so nobody reports it, and
//! the people the operator linked the channel for hear nothing.
//!
//! # Why a subscription and not a lookup
//!
//! The same rule the membership cache follows: **nothing on the packet path may
//! make a request** (`docs/ARCHITECTURE.md` §3). `metadata` owns the tree and
//! publishes it — snapshot first, then deltas — so this keeps a copy and the
//! packet path reads it without asking anyone.
//!
//! # What a stale tree costs
//!
//! Less than a stale membership table, which is why voice's readiness does not
//! gate on it. A tree that is behind makes a shout carry into the links a
//! channel had a moment ago; a membership table that is behind makes a session
//! inaudible. Both are wrong, only one is silence.

use std::collections::BTreeMap;
use std::sync::Mutex;

use starling_proto_fancy::metadata::Channel;

use crate::ports::ChannelId;
use crate::routing::RoutingSnapshot;

/// Every channel's parent and links, as `metadata` last described them.
#[derive(Debug, Default)]
pub struct ChannelTree {
    channels: Mutex<BTreeMap<u32, Relations>>,
}

/// One channel's place in the tree.
///
/// Only the two fields a shout can travel along. The rest of a `Channel` — its
/// name, description, position, flags — is `metadata`'s business and copying it
/// here would be a second tree to keep in agreement with the first.
#[derive(Debug, Clone, Default)]
struct Relations {
    /// Absent on the root, and only there.
    parent: Option<u32>,
    /// Channels audio flows into, in both directions.
    links: Vec<u32>,
}

impl ChannelTree {
    /// An empty tree — every channel an island.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace everything with a fresh snapshot.
    ///
    /// A subscription opens with one of these, so a reconnect after `metadata`
    /// restarted converges rather than merging the two worlds: a link that was
    /// cut while the stream was down is only forgotten because this replaces.
    pub fn replace(&self, channels: Vec<Channel>) {
        if let Ok(mut held) = self.channels.lock() {
            *held = channels
                .into_iter()
                .map(|channel| (channel.id, relations(&channel)))
                .collect();
        }
    }

    /// Add or update one channel.
    pub fn upsert(&self, channel: &Channel) {
        if let Ok(mut held) = self.channels.lock() {
            let _ = held.insert(channel.id, relations(channel));
        }
    }

    /// Forget one channel.
    ///
    /// Its children are left naming a parent that no longer exists, which is the
    /// correct outcome for the one question this tree answers: a shout into a
    /// removed channel reaches nobody, and inventing a new parent for its
    /// children would carry audio into a channel the operator never named.
    /// `metadata` reparents them and says so in its own event.
    pub fn remove(&self, channel: u32) {
        if let Ok(mut held) = self.channels.lock() {
            let _ = held.remove(&channel);
        }
    }

    /// How many channels are known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.channels.lock().map_or(0, |held| held.len())
    }

    /// Whether nothing is known yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write this tree's relations into a snapshot built from membership.
    ///
    /// A layer rather than a second `compose`: membership, the tree and the
    /// registered targets each come from a different authority and each fills in
    /// a different part of the same snapshot. Stacking them keeps every source
    /// responsible for exactly its own fields.
    #[must_use]
    pub fn apply(&self, mut snapshot: RoutingSnapshot) -> RoutingSnapshot {
        let Ok(held) = self.channels.lock() else {
            // A poisoned lock costs shouts their links for one publish, not the
            // server its audio. Propagating the panic would end the subscription
            // task and make it permanent.
            return snapshot;
        };

        for (id, relations) in held.iter() {
            if let Some(parent) = relations.parent {
                snapshot = snapshot.with_parent(ChannelId(*id), ChannelId(parent));
            }
            for link in &relations.links {
                // Only one direction of each pair is written. `with_link` records
                // both, so writing the mirror when the other end reports it would
                // put every link in the snapshot twice — and a shout would then
                // resolve the same audience once per copy.
                if *id < *link {
                    snapshot = snapshot.with_link(ChannelId(*id), ChannelId(*link));
                }
            }
        }
        snapshot
    }
}

/// The two fields a shout can travel along.
fn relations(channel: &Channel) -> Relations {
    Relations {
        parent: channel.parent,
        links: channel.links.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::SessionId;
    use crate::routing::Target;
    use crate::targets::{ShoutTarget, VoiceTarget};

    const LOBBY: u32 = 0;
    const ANNEX: u32 = 1;
    const CORNER: u32 = 2;

    const ALICE: SessionId = SessionId(1);
    const BOB: SessionId = SessionId(2);

    fn channel(id: u32, parent: Option<u32>, links: &[u32]) -> Channel {
        Channel {
            id,
            parent,
            links: links.to_vec(),
            ..Channel::default()
        }
    }

    /// Alice in the lobby, Bob wherever the caller puts him.
    fn membership(bob_in: u32) -> RoutingSnapshot {
        RoutingSnapshot::new()
            .with_member(ALICE, ChannelId(LOBBY))
            .with_member(BOB, ChannelId(bob_in))
    }

    /// Alice shouting into the lobby, with whatever reach the caller asks for.
    fn shouting(links: bool, children: bool) -> VoiceTarget {
        VoiceTarget::new().shouting_to(ShoutTarget {
            channel: ChannelId(LOBBY),
            include_links: links,
            include_children: children,
        })
    }

    #[test]
    fn a_shout_carries_into_a_linked_channel() {
        // The whole reason this module exists. Without the tree the snapshot has
        // no links, `include_links` matches nothing, and the shout reaches the
        // base channel only — which looks like a shout that worked.
        let tree = ChannelTree::new();
        tree.replace(vec![
            channel(LOBBY, None, &[ANNEX]),
            channel(ANNEX, Some(LOBBY), &[LOBBY]),
        ]);

        let snapshot = tree
            .apply(membership(ANNEX))
            .with_target(ALICE, 1, shouting(true, false));
        assert_eq!(snapshot.recipients(ALICE, Target::Whisper(1)), vec![BOB]);
    }

    #[test]
    fn a_link_is_not_doubled_when_both_ends_report_it() {
        // `metadata` records links on both channels and `with_link` already
        // records both directions, so writing every reported edge would put each
        // link in twice — and a shout would then resolve its audience once per
        // copy. Deduplication is invisible until something counts recipients.
        let tree = ChannelTree::new();
        tree.replace(vec![
            channel(LOBBY, None, &[ANNEX]),
            channel(ANNEX, Some(LOBBY), &[LOBBY]),
        ]);

        let snapshot = tree
            .apply(membership(ANNEX))
            .with_target(ALICE, 1, shouting(true, false));
        assert_eq!(
            snapshot.recipients(ALICE, Target::Whisper(1)).len(),
            1,
            "bob heard the same shout more than once"
        );
    }

    #[test]
    fn a_shout_carries_into_a_child_channel() {
        let tree = ChannelTree::new();
        tree.replace(vec![
            channel(LOBBY, None, &[]),
            channel(ANNEX, Some(LOBBY), &[]),
        ]);

        let snapshot = tree
            .apply(membership(ANNEX))
            .with_target(ALICE, 1, shouting(false, true));
        assert_eq!(snapshot.recipients(ALICE, Target::Whisper(1)), vec![BOB]);
    }

    #[test]
    fn a_shout_carries_into_a_grandchild() {
        // The tree is walked upward from each candidate, so depth is not a
        // special case — but nothing else asserts it, and a walk that stopped at
        // one level would pass every other test here.
        let tree = ChannelTree::new();
        tree.replace(vec![
            channel(LOBBY, None, &[]),
            channel(ANNEX, Some(LOBBY), &[]),
            channel(CORNER, Some(ANNEX), &[]),
        ]);

        let snapshot = tree
            .apply(membership(CORNER))
            .with_target(ALICE, 1, shouting(false, true));
        assert_eq!(snapshot.recipients(ALICE, Target::Whisper(1)), vec![BOB]);
    }

    #[test]
    fn a_shout_without_links_or_children_stays_where_it_was_aimed() {
        // The other direction, and the one that matters for privacy: a plain
        // shout must not leak into a channel merely because it is linked.
        let tree = ChannelTree::new();
        tree.replace(vec![
            channel(LOBBY, None, &[ANNEX]),
            channel(ANNEX, Some(LOBBY), &[LOBBY]),
        ]);

        let snapshot = tree
            .apply(membership(ANNEX))
            .with_target(ALICE, 1, shouting(false, false));
        assert!(snapshot.recipients(ALICE, Target::Whisper(1)).is_empty());
    }

    #[test]
    fn a_cut_link_is_forgotten_on_the_next_update() {
        let tree = ChannelTree::new();
        tree.replace(vec![
            channel(LOBBY, None, &[ANNEX]),
            channel(ANNEX, Some(LOBBY), &[LOBBY]),
        ]);
        tree.upsert(&channel(LOBBY, None, &[]));
        tree.upsert(&channel(ANNEX, Some(LOBBY), &[]));

        let snapshot = tree
            .apply(membership(ANNEX))
            .with_target(ALICE, 1, shouting(true, false));
        assert!(
            snapshot.recipients(ALICE, Target::Whisper(1)).is_empty(),
            "a shout still carried along a link the operator cut"
        );
    }

    #[test]
    fn a_fresh_snapshot_replaces_rather_than_merges() {
        // What a reconnect delivers. Merging would resurrect every link cut
        // while the stream was down, and they would never be cut again.
        let tree = ChannelTree::new();
        tree.replace(vec![channel(LOBBY, None, &[ANNEX])]);
        tree.replace(vec![channel(LOBBY, None, &[])]);
        assert_eq!(tree.len(), 1);

        let snapshot = tree
            .apply(membership(ANNEX))
            .with_target(ALICE, 1, shouting(true, false));
        assert!(snapshot.recipients(ALICE, Target::Whisper(1)).is_empty());
    }

    #[test]
    fn an_empty_tree_leaves_a_snapshot_it_can_still_route_with() {
        // The state voice is in before `metadata` answers. Normal speech must
        // work throughout: readiness does not gate on this subscription, and a
        // tree that panicked or emptied the snapshot would silence the server
        // over a feature almost nobody is using at that moment.
        let snapshot = ChannelTree::new().apply(membership(LOBBY));
        assert_eq!(snapshot.recipients(ALICE, Target::Normal), vec![BOB]);
    }

    #[test]
    fn removing_a_channel_leaves_its_children_unadopted() {
        // Not a tidy-up: reparenting an orphan here would carry a shout into a
        // channel nobody named. `metadata` owns reparenting and announces it.
        let tree = ChannelTree::new();
        tree.replace(vec![
            channel(LOBBY, None, &[]),
            channel(ANNEX, Some(LOBBY), &[]),
            channel(CORNER, Some(ANNEX), &[]),
        ]);
        tree.remove(ANNEX);

        let snapshot = tree
            .apply(membership(CORNER))
            .with_target(ALICE, 1, shouting(false, true));
        assert!(
            snapshot.recipients(ALICE, Target::Whisper(1)).is_empty(),
            "a shout reached a channel whose path to the target was removed"
        );
    }
}
