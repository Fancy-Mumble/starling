//! Which persistent-chat protocol each channel runs, for services that store
//! what people say.
//!
//! `metadata` owns the setting; `pchat` and `text` are the two services whose
//! behaviour depends on it, and neither could see it. The consequences were
//! real in both directions:
//!
//! - `pchat` decided whether to archive a message from the protocol the
//!   *message* declared, so a client that mislabelled its own message got it
//!   archived anyway. Harmless while every protocol was end-to-end and the
//!   ciphertext was opaque either way; not harmless once one of them means "the
//!   server holds the key", because then a client's word is what decides
//!   whether the server stores plaintext.
//! - `text` archived and served every `TextMessage` regardless of the channel's
//!   mode, which is how the plaintext half of an end-to-end channel's dual-path
//!   send ended up in a table that anyone who could reach the service could
//!   page through.
//!
//! A subscription rather than a lookup, for the reason
//! [`crate::permit`] and the permissions evaluator give: this is read on the
//! path of every message, and nothing on that path may make a request.
//! `metadata` sends a snapshot first and deltas after, so the table is complete
//! from the first event.
//!
//! # Cold fails open for reads and closed for writes
//!
//! Not the [`Roster`](crate::roster) rule, and deliberately not. A cold roster
//! addresses nobody because a broadcast is the leak. Here the two directions
//! have different worst cases: refusing to *serve* a page because the mode
//! table has not arrived breaks history for every channel during a metadata
//! restart, while authorisation is already covered by a separate permission
//! check. But storing a message under the wrong mode cannot be undone later,
//! and the mode that matters is the one where the server keeps a readable copy.
//! So an unknown channel reads as "no opinion" and writes as "not yet".

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::metadata::{TreeEvent, TreeRequest, tree_event};

use crate::serve::ServiceContext;

/// How long to wait before re-subscribing.
const RETRY: Duration = Duration::from_secs(1);

/// Every channel's persistent-chat protocol, as `metadata` last described it.
///
/// The value is the wire number of `ChannelState.pchat_protocol`, not an enum:
/// this type is in the runtime, below the services that give the numbers
/// meaning, and a channel configured with a value this build does not know
/// should read back as that value rather than as zero.
#[derive(Debug, Default)]
pub struct ChannelModes {
    modes: Mutex<HashMap<u32, u32>>,
    warm: AtomicBool,
}

impl ChannelModes {
    /// Nothing known yet, so nothing may be stored under a mode.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a snapshot has ever arrived.
    #[must_use]
    pub fn is_warm(&self) -> bool {
        self.warm.load(Ordering::Acquire)
    }

    /// The protocol `channel` runs, or `None` while that is unknown.
    ///
    /// `Some(0)` and `None` are different answers and callers must keep them
    /// apart: the first says the channel is a plain one, the second says this
    /// table cannot say yet.
    #[must_use]
    pub fn get(&self, channel: u32) -> Option<u32> {
        self.modes.lock().ok()?.get(&channel).copied()
    }

    /// Whether `channel` is known to run end-to-end persistent chat.
    ///
    /// False for a channel nobody has described, which is the read-side
    /// fail-open: the caller is deciding whether to *withhold* something, and
    /// withholding on a cold table breaks every channel at once.
    #[must_use]
    pub fn is_persistent(&self, channel: u32) -> bool {
        self.get(channel).is_some_and(|mode| mode != 0)
    }

    /// Whether a message declaring `protocol` may be stored for `channel`.
    ///
    /// The write-side fail-closed. A message must declare the mode its channel
    /// is configured for, so that the archive's contents match what the channel
    /// promised its members, and an unknown channel refuses everything but the
    /// plain mode, which stores nothing here anyway.
    ///
    /// Zero is accepted against any channel because it is what a client too old
    /// to set the field sends, and refusing those would break every existing
    /// client the moment this check landed. Such a message is archived under
    /// the channel's own mode, which is the same thing that happened before.
    #[must_use]
    pub fn accepts(&self, channel: u32, protocol: u32) -> bool {
        if protocol == 0 {
            return true;
        }
        self.get(channel) == Some(protocol)
    }

    /// Fold one tree event in.
    ///
    /// Returns whether anything changed, so a caller can skip derived work.
    pub fn apply(&self, event: TreeEvent) -> bool {
        match event.event {
            Some(tree_event::Event::Snapshot(tree)) => {
                let replaced = tree
                    .channels
                    .into_iter()
                    .map(|channel| (channel.id, channel.pchat_protocol))
                    .collect();
                if let Ok(mut held) = self.modes.lock() {
                    *held = replaced;
                }
                self.warm.store(true, Ordering::Release);
                true
            }
            Some(tree_event::Event::Upsert(channel)) => {
                if let Ok(mut held) = self.modes.lock() {
                    let _ = held.insert(channel.id, channel.pchat_protocol);
                }
                true
            }
            Some(tree_event::Event::Removed(channel)) => {
                if let Ok(mut held) = self.modes.lock() {
                    let _ = held.remove(&channel);
                }
                true
            }
            // A membership move says nothing about a channel's mode.
            _ => false,
        }
    }

    /// Keep this table up to date from `metadata`, until aborted.
    ///
    /// Re-subscribes on failure, on the short retry the permissions evaluator
    /// uses for the same stream: a metadata restart is a rolling deploy rather
    /// than an incident, but every second spent stale is a second in which a
    /// server-managed channel refuses to store anything.
    pub fn follow(
        self: Arc<Self>,
        ctx: ServiceContext,
        subscriber: &'static str,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let scope = ctx.instances().first().copied().unwrap_or(1);
            loop {
                self.read(&ctx, scope, subscriber).await;
                tokio::time::sleep(RETRY).await;
            }
        })
    }

    /// One subscription, from opening it to the stream ending.
    async fn read(&self, ctx: &ServiceContext, scope: u32, subscriber: &str) {
        let Ok(transport) = ctx.resolver.channel("metadata") else {
            tracing::warn!(
                subscriber,
                "cannot reach metadata; channel modes are unknown"
            );
            return;
        };
        let stream = MetadataClient::new(transport)
            .max_decoding_message_size(ctx.resolver.max_tree_message())
            .watch(TreeRequest {
                scope: Some(Scope { instance: scope }),
            })
            .await;
        let Ok(stream) = stream else {
            // Debug, not warn: on a cold start this fires once a second until
            // metadata is up, which is the boot order rather than a fault.
            tracing::debug!(
                subscriber,
                "metadata is not taking the tree subscription yet; retrying"
            );
            return;
        };

        let mut events = stream.into_inner();
        while let Ok(Some(event)) = events.message().await {
            let _ = self.apply(event);
        }
        tracing::warn!(
            subscriber,
            "the metadata subscription ended; channel modes are now stale"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::metadata::{Channel, Tree};

    fn channel(id: u32, pchat_protocol: u32) -> Channel {
        Channel {
            id,
            pchat_protocol,
            ..Channel::default()
        }
    }

    fn snapshot(channels: Vec<Channel>) -> TreeEvent {
        TreeEvent {
            event: Some(tree_event::Event::Snapshot(Tree {
                channels,
                ..Tree::default()
            })),
        }
    }

    #[test]
    fn nothing_is_known_before_a_snapshot_arrives() {
        let modes = ChannelModes::new();
        assert!(!modes.is_warm());
        assert_eq!(modes.get(4), None);
    }

    #[test]
    fn an_unknown_channel_reads_as_not_persistent_and_writes_as_refused() {
        // The two directions of the cold rule, in one place because they are
        // easy to conflate: withholding history from every channel during a
        // metadata restart is worse than serving it, but storing plaintext
        // under a guess cannot be undone.
        let modes = ChannelModes::new();
        assert!(!modes.is_persistent(4), "a read must not withhold");
        assert!(!modes.accepts(4, 2), "a write must not guess");
    }

    #[test]
    fn a_snapshot_replaces_rather_than_merges() {
        let modes = ChannelModes::new();
        let _ = modes.apply(snapshot(vec![channel(4, 2), channel(9, 4)]));
        assert!(modes.is_warm());
        assert_eq!(modes.get(4), Some(2));

        // A channel that is not in the new snapshot is gone, not remembered:
        // a reconnect replaces the whole table because a missed delta cannot be
        // repaired from the next one.
        let _ = modes.apply(snapshot(vec![channel(9, 4)]));
        assert_eq!(modes.get(4), None);
        assert_eq!(modes.get(9), Some(4));
    }

    #[test]
    fn an_upsert_moves_one_channel_and_a_removal_forgets_it() {
        let modes = ChannelModes::new();
        let _ = modes.apply(snapshot(vec![channel(4, 0)]));
        let _ = modes.apply(TreeEvent {
            event: Some(tree_event::Event::Upsert(channel(4, 3))),
        });
        assert_eq!(modes.get(4), Some(3));

        let _ = modes.apply(TreeEvent {
            event: Some(tree_event::Event::Removed(4)),
        });
        assert_eq!(modes.get(4), None);
    }

    #[test]
    fn a_message_must_declare_the_mode_its_channel_runs() {
        let modes = ChannelModes::new();
        let _ = modes.apply(snapshot(vec![channel(4, 2), channel(9, 3)]));

        assert!(modes.accepts(4, 2), "the channel's own mode");
        assert!(
            !modes.accepts(4, 3),
            "server-managed into an end-to-end channel is how a client would \
             ask this server to store plaintext members were promised it \
             could not read"
        );
        assert!(
            !modes.accepts(9, 2),
            "and the mislabel in the other direction"
        );
    }

    #[test]
    fn a_client_that_declares_nothing_is_still_served() {
        // Zero is what a client too old to set the field sends. Refusing it
        // would have broken every shipping client the day this landed.
        let modes = ChannelModes::new();
        let _ = modes.apply(snapshot(vec![channel(4, 2)]));
        assert!(modes.accepts(4, 0));
    }

    #[test]
    fn a_plain_channel_is_known_to_be_plain() {
        // `Some(0)` and `None` are different answers: one says the channel is
        // plain, the other says the table cannot say yet.
        let modes = ChannelModes::new();
        let _ = modes.apply(snapshot(vec![channel(4, 0)]));
        assert_eq!(modes.get(4), Some(0));
        assert!(!modes.is_persistent(4));
    }
}
