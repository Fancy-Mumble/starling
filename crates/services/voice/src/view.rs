//! Who is in which channel, and who may be heard.
//!
//! The routing core is a pure function of a snapshot ([`crate::routing`]), and
//! this is where the snapshot comes from. `session-view` is the only thing that
//! knows the whole server's membership — with more than one gateway attached,
//! the connections this process can see are a fraction of it — so voice
//! subscribes there and folds every event into a table it can rebuild from.
//!
//! # Why a cache and not a lookup
//!
//! **Nothing on the packet path may make a request** (`docs/ARCHITECTURE.md`
//! §3). At 50 packets a second per speaker, a membership lookup per frame would
//! put voice behind `session-view`'s hold time; `crates/kernel/bus/RESULTS.md`
//! §3.3 measured a 25 ms hold making 5% of packets miss their frame. Membership
//! changes are rare and packets are not, so the authority publishes and this
//! reads.
//!
//! # What a stale table costs
//!
//! Exactly one thing, and it is worth naming because it has no log line: a
//! session missing from here is a session nobody hears and who hears nobody.
//! Voice's readiness therefore gates on this subscription being warm rather
//! than on the process being alive — a voice service that is up with a cold
//! cache is a voice service that silently drops every frame.

use std::collections::HashMap;
use std::sync::Mutex;

use starling_proto_fancy::sessionview::Session;

use crate::ports::{ChannelId, SessionId};
use crate::routing::RoutingSnapshot;

/// Every session on the server, as `session-view` last described it.
#[derive(Debug, Default)]
pub struct SessionCache {
    sessions: Mutex<HashMap<u32, Session>>,
}

impl SessionCache {
    /// An empty cache — nobody connected, and nobody audible.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace everything with a fresh snapshot.
    ///
    /// A subscription opens with one of these, so a reconnect after
    /// `session-view` restarted converges rather than merging the two worlds:
    /// sessions that went away while the stream was down are only forgotten
    /// because this replaces rather than merges.
    pub fn replace(&self, sessions: Vec<Session>) {
        if let Ok(mut held) = self.sessions.lock() {
            *held = sessions
                .into_iter()
                .map(|session| (session.session, session))
                .collect();
        }
    }

    /// Add or update one session.
    pub fn upsert(&self, session: Session) {
        if let Ok(mut held) = self.sessions.lock() {
            let _ = held.insert(session.session, session);
        }
    }

    /// Forget one session.
    pub fn remove(&self, session: u32) {
        if let Ok(mut held) = self.sessions.lock() {
            let _ = held.remove(&session);
        }
    }

    /// How many sessions are known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.lock().map_or(0, |held| held.len())
    }

    /// Whether nothing is known yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Build the view the packet path routes against.
    #[must_use]
    pub fn snapshot(&self) -> RoutingSnapshot {
        let Ok(held) = self.sessions.lock() else {
            // A poisoned lock must not silence the server. An empty snapshot
            // routes nothing, which is wrong, but it is recoverable on the next
            // event; propagating the panic would end the subscription task and
            // make it permanent.
            return RoutingSnapshot::new();
        };
        compose(held.values())
    }
}

/// Fold a set of sessions into a routing snapshot.
///
/// Free-standing so the mapping can be tested against sessions built by hand,
/// which is the part worth testing: every field here is a rule about who is
/// heard, and getting one backwards is silence rather than a crash.
#[must_use]
pub fn compose<'a>(sessions: impl Iterator<Item = &'a Session>) -> RoutingSnapshot {
    let mut snapshot = RoutingSnapshot::new();
    for session in sessions {
        let id = SessionId(session.session);
        snapshot = snapshot.with_member(id, ChannelId(session.channel));

        // Listening to a channel without being in it. Nothing writes these yet
        // — `UserState.listening_channel_add` is unhandled — but reading them
        // here is what makes that a one-sided change when it lands.
        for channel in &session.listening {
            snapshot = snapshot.with_listener(id, ChannelId(*channel));
        }

        if cannot_hear(session) {
            snapshot = snapshot.with_deaf(id);
        }
        if cannot_speak(session) {
            snapshot = snapshot.with_silenced(id);
        }
    }
    snapshot
}

/// Whether this session receives nothing.
const fn cannot_hear(session: &Session) -> bool {
    session.deaf || session.self_deaf
}

/// Whether this session sends nothing.
///
/// murmur drops the frame at the top of `processMsg` for `bMute`, `bSuppress`
/// and `bSelfMute`, and separately guarantees that deafening yourself mutes you
/// by forcing `bSelfMute` when `bSelfDeaf` arrives in a `UserState`. Folding
/// `self_deaf` in here reproduces the second guarantee on the path that
/// depends on it, rather than trusting another service to have enforced it —
/// a user whose client shows a crossed-out headphone and who is still audible
/// is a bug nobody reports, because the person it affects cannot hear it.
const fn cannot_speak(session: &Session) -> bool {
    session.mute || session.self_mute || session.suppress || session.self_deaf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Target;

    const LOBBY: u32 = 0;
    const ANNEX: u32 = 1;

    fn session(id: u32, channel: u32) -> Session {
        Session {
            session: id,
            channel,
            ..Session::default()
        }
    }

    fn cache_of(sessions: Vec<Session>) -> SessionCache {
        let cache = SessionCache::new();
        cache.replace(sessions);
        cache
    }

    #[test]
    fn two_people_in_one_channel_hear_each_other() {
        // The whole feature, at the level this module is responsible for.
        let snapshot = cache_of(vec![session(1, LOBBY), session(2, LOBBY)]).snapshot();
        assert_eq!(
            snapshot.recipients(SessionId(1), Target::Normal),
            vec![SessionId(2)]
        );
    }

    #[test]
    fn a_different_channel_hears_nothing() {
        let snapshot = cache_of(vec![session(1, LOBBY), session(2, ANNEX)]).snapshot();
        assert!(snapshot.recipients(SessionId(1), Target::Normal).is_empty());
    }

    #[test]
    fn a_moderator_mute_silences_the_speaker() {
        let snapshot = cache_of(vec![
            Session {
                mute: true,
                ..session(1, LOBBY)
            },
            session(2, LOBBY),
        ])
        .snapshot();
        assert!(!snapshot.may_speak(SessionId(1)));
        assert!(snapshot.recipients(SessionId(1), Target::Normal).is_empty());
    }

    #[test]
    fn every_way_of_being_silenced_silences() {
        // Four independent flags with one meaning between them. A missing arm
        // here is a user who is muted in every client's user list and audible
        // to everyone.
        for silence in [
            |s: Session| Session { mute: true, ..s },
            |s: Session| Session {
                self_mute: true,
                ..s
            },
            |s: Session| Session {
                suppress: true,
                ..s
            },
            |s: Session| Session {
                self_deaf: true,
                ..s
            },
        ] {
            let snapshot = cache_of(vec![silence(session(1, LOBBY)), session(2, LOBBY)]).snapshot();
            assert!(
                !snapshot.may_speak(SessionId(1)),
                "a silenced speaker was left audible"
            );
        }
    }

    #[test]
    fn a_deafened_listener_is_skipped_but_others_are_not() {
        let snapshot = cache_of(vec![
            session(1, LOBBY),
            Session {
                self_deaf: true,
                ..session(2, LOBBY)
            },
            session(3, LOBBY),
        ])
        .snapshot();
        assert_eq!(
            snapshot.recipients(SessionId(1), Target::Normal),
            vec![SessionId(3)]
        );
    }

    #[test]
    fn a_session_that_moved_channel_is_routed_by_where_it_is_now() {
        // An upsert is how every channel change arrives, and the old membership
        // has to go with it — otherwise a user hears their previous channel
        // forever, which sounds like a leak of a private conversation.
        let cache = cache_of(vec![session(1, LOBBY), session(2, LOBBY)]);
        cache.upsert(session(2, ANNEX));

        let snapshot = cache.snapshot();
        assert!(
            snapshot.recipients(SessionId(1), Target::Normal).is_empty(),
            "the speaker still reaches the channel the listener left"
        );
        assert_eq!(snapshot.channel_of(SessionId(2)), Some(ChannelId(ANNEX)));
    }

    #[test]
    fn a_departed_session_reaches_nobody_and_is_reached_by_nobody() {
        let cache = cache_of(vec![session(1, LOBBY), session(2, LOBBY)]);
        cache.remove(2);
        assert!(
            cache
                .snapshot()
                .recipients(SessionId(1), Target::Normal)
                .is_empty()
        );
    }

    #[test]
    fn a_fresh_snapshot_replaces_rather_than_merges() {
        // What a reconnect delivers. Merging would resurrect everyone who left
        // while the stream was down, and they would never leave again.
        let cache = cache_of(vec![session(1, LOBBY), session(2, LOBBY)]);
        cache.replace(vec![session(1, LOBBY)]);
        assert_eq!(cache.len(), 1);
        assert!(
            cache
                .snapshot()
                .recipients(SessionId(1), Target::Normal)
                .is_empty()
        );
    }

    #[test]
    fn a_listener_hears_a_channel_it_is_not_in() {
        let snapshot = cache_of(vec![
            session(1, LOBBY),
            Session {
                listening: vec![LOBBY],
                ..session(2, ANNEX)
            },
        ])
        .snapshot();
        assert!(
            snapshot
                .recipients(SessionId(1), Target::Normal)
                .contains(&SessionId(2))
        );
    }

    #[test]
    fn an_empty_cache_routes_nothing_rather_than_panicking() {
        // The state a restarted voice service is in before its subscription
        // warms, and the reason readiness gates on that subscription.
        let cache = SessionCache::new();
        assert!(cache.is_empty());
        assert!(
            cache
                .snapshot()
                .recipients(SessionId(1), Target::Normal)
                .is_empty()
        );
    }
}
