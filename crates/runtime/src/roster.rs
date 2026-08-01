//! Who is in which channel, for any service that has to address a channel.
//!
//! A [`Send`] naming no conns and no sessions is delivered to **every**
//! authenticated client the gateway holds (`gateway::attach::deliver`). That is
//! the right default for something genuinely server-wide and the wrong one for
//! anything channel-scoped: a chat message addressed at nobody in particular
//! reaches everybody, and "the payload is encrypted" does not cover who sent it,
//! when, or in which channel.
//!
//! `session-view` is the only thing that knows the whole server's membership —
//! with more than one gateway attached, the connections any single process sees
//! are a fraction of it. So a service subscribes there and folds every event
//! into this table, which is then a local lookup.
//!
//! This is the shape [`voice`] already uses for the packet path, lifted so it
//! is not written a third time. Voice keeps its own richer cache because it
//! composes a routing snapshot out of it; a service that only needs "who is in
//! this channel" wants this.
//!
//! # A cold roster addresses nobody
//!
//! Deliberately, and it is the whole point. Falling back to a broadcast when
//! membership is unknown is the leak this type exists to close, so a caller that
//! gets an empty answer must send nothing rather than send it to everyone. Gate
//! readiness on [`Roster::is_warm`] so a pod with a cold roster is not handed
//! traffic in the first place.
//!
//! [`Send`]: starling_proto_fancy::control::Send
//! [`voice`]: https://docs.rs/starling-voice

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::sessionview::{Session, SubscribeRequest, ViewEvent, view_event};

use crate::serve::ServiceContext;

/// How long to wait before re-subscribing.
const RETRY: Duration = Duration::from_secs(2);

/// Every session on the server and the channel it is in, as `session-view` last
/// described it.
#[derive(Debug, Default)]
pub struct Roster {
    /// Session id to channel id.
    ///
    /// Not indexed the other way round. Membership is read once per chat
    /// message rather than once per audio frame, so a scan over the connected
    /// users is cheaper than the bookkeeping a reverse index would cost on
    /// every move.
    channels: Mutex<HashMap<u32, u32>>,
    warm: AtomicBool,
}

impl Roster {
    /// An empty roster: nobody known, so nobody addressable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one `session-view` event in.
    ///
    /// Returns whether the roster changed shape, which a caller can use to
    /// avoid recomputing anything derived.
    pub fn apply(&self, event: ViewEvent) -> bool {
        match event.event {
            Some(view_event::Event::Snapshot(list)) => {
                self.replace(list.sessions);
                true
            }
            Some(view_event::Event::Upsert(session)) => {
                self.upsert(&session);
                true
            }
            Some(view_event::Event::Gone(gone)) => {
                self.remove(gone.session);
                true
            }
            // Membership is unaffected by a config bump.
            Some(view_event::Event::ConfigVersion(_)) | None => false,
        }
    }

    /// Replace everything with a fresh snapshot.
    ///
    /// A subscription opens with one of these, so a reconnect after
    /// `session-view` restarted converges rather than merging two worlds:
    /// sessions that went away while the stream was down are forgotten only
    /// because this replaces rather than merges.
    pub fn replace(&self, sessions: Vec<Session>) {
        if let Ok(mut held) = self.channels.lock() {
            *held = sessions
                .into_iter()
                .map(|session| (session.session, session.channel))
                .collect();
        }
        self.warm.store(true, Ordering::Release);
    }

    /// Add or move one session.
    pub fn upsert(&self, session: &Session) {
        if let Ok(mut held) = self.channels.lock() {
            let _ = held.insert(session.session, session.channel);
        }
    }

    /// Forget one session.
    ///
    /// Session ids are reused, so a stale entry is not merely a leak: it is a
    /// stranger inheriting somebody else's channel membership.
    pub fn remove(&self, session: u32) {
        if let Ok(mut held) = self.channels.lock() {
            let _ = held.remove(&session);
        }
    }

    /// Everyone in `channel`, except `except`.
    ///
    /// Empty when the roster is cold, which the caller must treat as "send to
    /// nobody" rather than "send to everybody".
    #[must_use]
    pub fn in_channel(&self, channel: u32, except: u32) -> Vec<u32> {
        let Ok(held) = self.channels.lock() else {
            return Vec::new();
        };
        held.iter()
            .filter(|(session, member)| **member == channel && **session != except)
            .map(|(session, _)| *session)
            .collect()
    }

    /// The channel a session is in, if it is known at all.
    #[must_use]
    pub fn channel_of(&self, session: u32) -> Option<u32> {
        self.channels.lock().ok()?.get(&session).copied()
    }

    /// Whether a snapshot has ever arrived.
    ///
    /// False means "membership is unknown", which is not the same as "the
    /// server is empty" and must not be treated as it.
    #[must_use]
    pub fn is_warm(&self) -> bool {
        self.warm.load(Ordering::Acquire)
    }

    /// How many sessions are known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.channels.lock().map_or(0, |held| held.len())
    }

    /// Whether nothing is known yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Keep this roster up to date from `session-view`, until aborted.
    ///
    /// Re-subscribes on failure: a `session-view` restart is a rolling deploy,
    /// not an incident. The stream is also dropped deliberately when a
    /// subscriber falls behind, because a missed delta cannot be repaired from
    /// the next one — reconnecting replaces the whole table, which is the only
    /// way back to agreement.
    ///
    /// `gate` is opened after the first event rather than before, because a
    /// subscription opens with a full snapshot: that is the moment the roster
    /// stops being cold, and declaring readiness any earlier is the race that
    /// makes a cold roster look warm for one scrape interval.
    pub fn follow(
        self: Arc<Self>,
        ctx: ServiceContext,
        subscriber: &'static str,
        gate: &'static str,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let scope = ctx.virtual_servers().first().copied().unwrap_or(1);
            loop {
                self.read(&ctx, scope, subscriber, gate).await;
                tokio::time::sleep(RETRY).await;
            }
        })
    }

    /// One subscription, from opening it to the stream ending.
    async fn read(&self, ctx: &ServiceContext, scope: u32, subscriber: &str, gate: &str) {
        let Ok(channel) = ctx.resolver.channel("session-view") else {
            // Worth a line: with no roster, every channel-scoped send is
            // addressed at nobody, and that is indistinguishable from a server
            // where nobody is talking.
            tracing::warn!(
                subscriber,
                "cannot reach session-view; nothing will be delivered"
            );
            return;
        };
        let Ok(stream) = SessionViewClient::new(channel)
            .subscribe(SubscribeRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
                subscriber: subscriber.to_owned(),
            })
            .await
        else {
            return;
        };

        let mut events = stream.into_inner();
        while let Ok(Some(event)) = events.message().await {
            let _ = self.apply(event);
            ctx.health.ready(gate);
        }
        tracing::warn!(
            subscriber,
            "the session-view subscription ended; membership is now stale"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::sessionview::{Gone, Sessions};

    fn session(session: u32, channel: u32) -> Session {
        Session {
            session,
            channel,
            ..Session::default()
        }
    }

    fn snapshot(sessions: Vec<Session>) -> ViewEvent {
        ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                sessions,
                ..Sessions::default()
            })),
        }
    }

    #[test]
    fn a_cold_roster_addresses_nobody_rather_than_everybody() {
        // The whole reason this type exists: the alternative to an empty answer
        // is a broadcast, which is the leak.
        let roster = Roster::new();
        assert!(!roster.is_warm());
        assert!(roster.in_channel(4, 0).is_empty());
    }

    #[test]
    fn a_channel_lists_only_its_own_members_and_never_the_sender() {
        let roster = Roster::new();
        let _ = roster.apply(snapshot(vec![session(1, 4), session(2, 4), session(3, 9)]));

        let mut members = roster.in_channel(4, 1);
        members.sort_unstable();
        assert_eq!(members, vec![2]);
        assert!(roster.is_warm());
    }

    #[test]
    fn a_snapshot_replaces_rather_than_merges() {
        // A resubscribe after session-view restarted must not resurrect
        // sessions that left while the stream was down.
        let roster = Roster::new();
        let _ = roster.apply(snapshot(vec![session(1, 4), session(2, 4)]));
        let _ = roster.apply(snapshot(vec![session(2, 4)]));

        assert_eq!(roster.in_channel(4, 0), vec![2]);
    }

    #[test]
    fn a_session_that_left_stops_being_addressable() {
        // Session ids are reused, so a stale entry hands a stranger somebody
        // else's channel.
        let roster = Roster::new();
        let _ = roster.apply(snapshot(vec![session(1, 4), session(2, 4)]));
        let _ = roster.apply(ViewEvent {
            event: Some(view_event::Event::Gone(Gone {
                session: 1,
                ..Gone::default()
            })),
        });

        assert_eq!(roster.in_channel(4, 0), vec![2]);
        assert_eq!(roster.channel_of(1), None);
    }

    #[test]
    fn a_move_re_homes_a_session_rather_than_duplicating_it() {
        let roster = Roster::new();
        let _ = roster.apply(snapshot(vec![session(1, 4)]));
        let _ = roster.apply(ViewEvent {
            event: Some(view_event::Event::Upsert(session(1, 9))),
        });

        assert!(roster.in_channel(4, 0).is_empty());
        assert_eq!(roster.in_channel(9, 0), vec![1]);
        assert_eq!(roster.channel_of(1), Some(9));
    }
}
