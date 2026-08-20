//! Who is in which channel, for any service that has to address a channel.
//!
//! A [`Send`] naming no conns and no sessions is delivered to **every**
//! authenticated client the gateway holds (`gateway::attach::deliver`). That is
//! the right default for something genuinely server-wide and the wrong one for
//! anything channel-scoped: a chat message addressed at nobody in particular
//! reaches everybody, and "the payload is encrypted" does not cover who sent it,
//! when, or in which channel.
//!
//! `session-view` is the only thing that knows the whole server's membership,
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
    /// Session id to the account behind it, absent for an unregistered guest.
    ///
    /// Session ids are per connection and get recycled; an account is the
    /// person. Anything that has to outlive a connection, what a user
    /// answered, what they were sent, must be keyed on this and never on the
    /// session, or a reconnect looks like a stranger and a recycled id looks
    /// like the wrong one.
    accounts: Mutex<HashMap<u32, Option<u64>>>,
    /// Session id to the SHA-1 of the peer's leaf certificate, empty when it
    /// presented none.
    ///
    /// The other durable identity, and the one end-to-end crypto needs: an
    /// account says *who* a person is to this server, a certificate says which
    /// keypair they hold. A guest has no account but may still hold a
    /// certificate, and pchat's key ladder is keyed on exactly this, peer
    /// keys, channel originators and key holders are all `cert_hash`.
    certs: Mutex<HashMap<u32, Vec<u8>>>,
    /// Session id to the display name it is using.
    ///
    /// A *label*, never an identity: it is chosen by the user, changes with a
    /// rename, and two people can hold it in sequence. Anything deciding who
    /// may do what reads [`Self::account_of`] or [`Self::cert_of`]; this is
    /// for the copy a human reads, which otherwise costs a `session-view`
    /// round trip per message.
    names: Mutex<HashMap<u32, String>>,
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
        if let Ok(mut held) = self.accounts.lock() {
            *held = sessions
                .iter()
                .map(|session| {
                    (
                        session.session,
                        starling_proto_fancy::identity::account(
                            session.registered,
                            session.account,
                        ),
                    )
                })
                .collect();
        }
        if let Ok(mut held) = self.certs.lock() {
            *held = sessions
                .iter()
                .map(|session| (session.session, session.cert_hash.clone()))
                .collect();
        }
        if let Ok(mut held) = self.names.lock() {
            *held = sessions
                .iter()
                .map(|session| (session.session, session.name.clone()))
                .collect();
        }
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
        if let Ok(mut held) = self.accounts.lock() {
            let _ = held.insert(
                session.session,
                starling_proto_fancy::identity::account(session.registered, session.account),
            );
        }
        if let Ok(mut held) = self.channels.lock() {
            let _ = held.insert(session.session, session.channel);
        }
        if let Ok(mut held) = self.certs.lock() {
            let _ = held.insert(session.session, session.cert_hash.clone());
        }
        if let Ok(mut held) = self.names.lock() {
            let _ = held.insert(session.session, session.name.clone());
        }
    }

    /// Forget one session.
    ///
    /// Session ids are reused, so a stale entry is not merely a leak: it is a
    /// stranger inheriting somebody else's channel membership.
    pub fn remove(&self, session: u32) {
        if let Ok(mut held) = self.accounts.lock() {
            let _ = held.remove(&session);
        }
        if let Ok(mut held) = self.channels.lock() {
            let _ = held.remove(&session);
        }
        if let Ok(mut held) = self.certs.lock() {
            let _ = held.remove(&session);
        }
        if let Ok(mut held) = self.names.lock() {
            let _ = held.remove(&session);
        }
    }

    /// The certificate hash behind `session`, or `None` for a session that
    /// presented none, an unknown session, or a cold roster.
    ///
    /// Read by anything that has to record *who wrote this* durably. A session
    /// id cannot serve: it is handed out per connection and reused, so an
    /// archive keyed on one attributes old messages to whoever holds the
    /// number now.
    #[must_use]
    pub fn cert_of(&self, session: u32) -> Option<Vec<u8>> {
        self.certs
            .lock()
            .ok()?
            .get(&session)
            .filter(|cert| !cert.is_empty())
            .cloned()
    }

    /// The session holding `cert`, if one is connected.
    ///
    /// A linear scan, like [`Self::in_channel`]: this is read when something
    /// durable has to find the live connection behind it (a message queued
    /// before the sender reconnected, say), which is rare enough that a second
    /// index would cost more to maintain than it saves.
    ///
    /// An empty `cert` matches nothing: every peer that presented no
    /// certificate would otherwise match it, and they are not the same person.
    #[must_use]
    pub fn session_with_cert(&self, cert: &[u8]) -> Option<u32> {
        if cert.is_empty() {
            return None;
        }
        self.certs
            .lock()
            .ok()?
            .iter()
            .find(|(_, held)| held.as_slice() == cert)
            .map(|(session, _)| *session)
    }

    /// The display name `session` is using, if it is known.
    #[must_use]
    pub fn name_of(&self, session: u32) -> Option<String> {
        self.names
            .lock()
            .ok()?
            .get(&session)
            .filter(|name| !name.is_empty())
            .cloned()
    }

    /// The session using `name`, matched exactly.
    ///
    /// A linear scan for the same reason [`Self::session_with_cert`] is one,
    /// and read from the same kind of caller: something that was handed a name
    /// by a user and has to find the connection behind it. An empty `name`
    /// matches nothing, so a session that has not picked one is not everybody.
    ///
    /// A *label* lookup, never an identity one: two people can hold a name in
    /// sequence, so nothing deciding who may do what may key on this.
    #[must_use]
    pub fn session_named(&self, name: &str) -> Option<u32> {
        if name.is_empty() {
            return None;
        }
        self.names
            .lock()
            .ok()?
            .iter()
            .find(|(_, held)| held.as_str() == name)
            .map(|(session, _)| *session)
    }

    /// Every session known to be connected.
    ///
    /// Empty on a cold roster, which means "membership is unknown" and must be
    /// treated the way [`Self::in_channel`] is: as nobody to address, never as
    /// a server with nobody on it.
    #[must_use]
    pub fn sessions(&self) -> Vec<u32> {
        let Ok(held) = self.channels.lock() else {
            return Vec::new();
        };
        let mut sessions: Vec<u32> = held.keys().copied().collect();
        sessions.sort_unstable();
        sessions
    }

    /// The account behind `session`, or `None` for an unregistered guest, an
    /// unknown session, or a cold roster.
    ///
    /// All three answer "nothing durable to key on", which is the only
    /// question a caller storing something per person needs answered. They
    /// differ for diagnostics, not for the decision.
    #[must_use]
    pub fn account_of(&self, session: u32) -> Option<u64> {
        self.accounts.lock().ok()?.get(&session).copied().flatten()
    }

    /// Every account with a session on this server right now.
    ///
    /// Guests are not in it: they have no account, so there is nothing to
    /// compare a stored registration against.
    ///
    /// The question this answers is "who does **not** need telling", asked by
    /// push before it notifies somebody's phone about a message already on
    /// their screen. That direction matters when the roster is cold: it comes
    /// back empty, which means nobody is skipped rather than nobody is
    /// notified, so the failure is a duplicate notification and never a silent
    /// one.
    #[must_use]
    pub fn connected_accounts(&self) -> Vec<u64> {
        let Ok(held) = self.accounts.lock() else {
            return Vec::new();
        };
        let mut accounts: Vec<u64> = held.values().copied().flatten().collect();
        accounts.sort_unstable();
        accounts.dedup();
        accounts
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
    /// the next one, reconnecting replaces the whole table, which is the only
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
            let scope = ctx.instances().first().copied().unwrap_or(1);
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
                scope: Some(Scope { instance: scope }),
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
    fn the_connected_accounts_are_the_people_and_not_the_connections() {
        // Read by push to decide who does *not* need telling. Two windows are
        // one person who has already seen the message, and a guest is nobody
        // there is anything to compare against.
        let registered = |session: u32, account: u64| Session {
            session,
            channel: 4,
            account,
            registered: true,
            ..Session::default()
        };
        let roster = Roster::new();
        let _ = roster.apply(snapshot(vec![
            registered(1, 42),
            registered(2, 42),
            session(3, 4),
        ]));

        assert_eq!(roster.connected_accounts(), vec![42]);
    }

    #[test]
    fn a_cold_roster_skips_nobody_so_a_notification_is_never_lost_to_it() {
        // The opposite direction from `in_channel`, deliberately: an empty
        // answer here means "skip nobody", so the cost of not knowing is a
        // phone buzzing about something already on screen rather than a
        // message nobody is told about.
        assert!(Roster::new().connected_accounts().is_empty());
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
    fn a_name_resolves_to_the_session_holding_it_and_nothing_resolves_to_none() {
        let named = |session: u32, name: &str| Session {
            session,
            channel: 4,
            name: name.to_owned(),
            ..Session::default()
        };
        let roster = Roster::new();
        let _ = roster.apply(snapshot(vec![
            named(1, "ada"),
            named(2, ""),
            named(3, "grace"),
        ]));

        assert_eq!(roster.session_named("grace"), Some(3));
        assert_eq!(roster.session_named("nobody"), None);
        // A session that has picked no name must not be what the empty string
        // finds, or every anonymous lookup lands on whoever is first.
        assert_eq!(roster.session_named(""), None);
    }

    #[test]
    fn every_session_is_listed_and_a_cold_roster_lists_none() {
        let roster = Roster::new();
        assert!(
            roster.sessions().is_empty(),
            "cold means unknown, not empty"
        );
        let _ = roster.apply(snapshot(vec![session(3, 4), session(1, 9)]));
        assert_eq!(roster.sessions(), vec![1, 3]);
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
