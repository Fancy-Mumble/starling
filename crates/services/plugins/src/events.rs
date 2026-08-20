//! Turning `session-view` snapshots into the events a plugin is told about.
//!
//! A plugin hears about exactly four things, and they are the four the C++
//! server's distributor fed its host: a client arrived, a client left, a client
//! that was a guest registered mid-session, and a plugin message. The first
//! three are not events Starling emits anywhere -- `session-view` publishes
//! *state*, a snapshot and a stream of upserts -- so somebody has to diff one
//! against the last to get back to "arrived" and "left". This is that somebody.
//!
//! `operator-api` does the same fold for its own live channel and names the
//! results after the same upstream callbacks. Two folds is one more than there
//! should be; they are separate today because the shapes they produce differ
//! (JSON for a websocket, an ABI struct for a plugin) and merging them would
//! mean one of the two depending on the other's vocabulary.
//!
//! # Eventually consistent, and that is fine
//!
//! The C++ distributor called its subscribers synchronously on the server
//! thread, so a plugin saw a connect before the client could send anything.
//! Here the same event arrives when the next snapshot does. None of the four
//! can refuse anything -- there is no veto in this direction -- so the cost of
//! lag is a greeter that greets a few milliseconds late, never a decision made
//! on stale facts.

use std::collections::HashMap;

use starling_plugin_host::api::ClientInfo;
use starling_proto_fancy::sessionview::{Session, ViewEvent, view_event};

/// What changed, in the vocabulary a plugin understands.
#[derive(Debug, Clone)]
pub(crate) enum Presence {
    /// A client is now here. Also emitted when a session that was already here
    /// becomes registered, because that changes who the plugin is talking to
    /// and every plugin keying on `user_id` would otherwise hold the guest
    /// value for the rest of the session.
    Arrived(ClientInfo),
    /// A client is gone.
    Left {
        /// Which server instance.
        server_id: u32,
        /// Which session.
        session: u32,
    },
}

/// Hand-written because [`ClientInfo`] comes from the plugin ABI and does not
/// derive it: the FFI-safe types it is built from carry no `PartialEq`. Only
/// the tests below compare these, and identity here is the session and who is
/// on it.
impl PartialEq for Presence {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Arrived(ours), Self::Arrived(theirs)) => {
                ours.server_id == theirs.server_id
                    && ours.session_id == theirs.session_id
                    && ours.user_id == theirs.user_id
                    && ours.username.as_str() == theirs.username.as_str()
                    && ours.cert_hash.as_str() == theirs.cert_hash.as_str()
            }
            (
                Self::Left {
                    server_id: ours,
                    session: our_session,
                },
                Self::Left {
                    server_id: theirs,
                    session: their_session,
                },
            ) => ours == theirs && our_session == their_session,
            _ => false,
        }
    }
}

/// Who was here last time we looked.
#[derive(Debug)]
pub(crate) struct Presences {
    server_id: u32,
    /// Session to the registered account id last seen on it, `-1` for a guest.
    ///
    /// The value is what makes a mid-session registration visible: without it
    /// the second upsert for a session is indistinguishable from a channel
    /// move, and a plugin never learns the guest it greeted has a name now.
    seen: HashMap<u32, i64>,
}

impl Presences {
    /// An empty table: nobody is here yet, so the first snapshot is all
    /// arrivals.
    pub(crate) fn new(server_id: u32) -> Self {
        Self {
            server_id,
            seen: HashMap::new(),
        }
    }

    /// Fold one view event in and say what a plugin should be told.
    pub(crate) fn apply(&mut self, event: &ViewEvent) -> Vec<Presence> {
        match &event.event {
            Some(view_event::Event::Snapshot(list)) => self.replace(&list.sessions),
            Some(view_event::Event::Upsert(session)) => self.upsert(session),
            Some(view_event::Event::Gone(gone)) => self.remove(gone.session),
            // A configuration bump says nothing about who is connected.
            Some(view_event::Event::ConfigVersion(_)) | None => Vec::new(),
        }
    }

    /// Reconcile against a full snapshot.
    ///
    /// A subscription opens with one, and so does every re-subscription after
    /// `session-view` restarted. Diffing rather than replaying is what stops a
    /// reconnect from re-announcing the whole server to every plugin: a plugin
    /// that was told about a session and is told again has no way to know the
    /// second one was not a new arrival.
    fn replace(&mut self, sessions: &[Session]) -> Vec<Presence> {
        let mut changes = Vec::new();
        let mut next: HashMap<u32, i64> = HashMap::with_capacity(sessions.len());
        for session in sessions {
            let user_id = user_id_of(session);
            let _ = next.insert(session.session, user_id);
            if self.seen.get(&session.session) != Some(&user_id) {
                changes.push(Presence::Arrived(self.info(session)));
            }
        }
        // Anything in the old table and not the new one left while we were not
        // looking, which is exactly the case a reconnect has to repair.
        let mut departed: Vec<u32> = self
            .seen
            .keys()
            .filter(|session| !next.contains_key(session))
            .copied()
            .collect();
        departed.sort_unstable();
        for session in departed {
            changes.push(Presence::Left {
                server_id: self.server_id,
                session,
            });
        }
        self.seen = next;
        changes
    }

    fn upsert(&mut self, session: &Session) -> Vec<Presence> {
        let user_id = user_id_of(session);
        if self.seen.insert(session.session, user_id) == Some(user_id) {
            // Known, and still the same person: a move or a rename, neither of
            // which is one of the four events.
            return Vec::new();
        }
        vec![Presence::Arrived(self.info(session))]
    }

    fn remove(&mut self, session: u32) -> Vec<Presence> {
        if self.seen.remove(&session).is_none() {
            return Vec::new();
        }
        vec![Presence::Left {
            server_id: self.server_id,
            session,
        }]
    }

    fn info(&self, session: &Session) -> ClientInfo {
        ClientInfo {
            server_id: self.server_id,
            session_id: session.session,
            username: session.name.clone().into(),
            cert_hash: hex(&session.cert_hash).into(),
            user_id: user_id_of(session),
        }
    }
}

/// The registered account behind a session, or `-1` for a guest.
///
/// Through `identity::account` rather than reading `account` directly: an
/// unregistered session carries 0 there, and 0 is the SuperUser's id, so the
/// bare field identifies every guest as the administrator.
fn user_id_of(session: &Session) -> i64 {
    starling_proto_fancy::identity::account(session.registered, session.account)
        .and_then(|account| i64::try_from(account).ok())
        .unwrap_or(-1)
}

/// Lowercase hex, which is the shape the plugin ABI's `cert_hash` is in.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        // Writing hex into a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::sessionview::{Gone, Sessions};

    fn guest(session: u32) -> Session {
        Session {
            session,
            channel: 4,
            name: format!("guest{session}"),
            ..Session::default()
        }
    }

    fn registered(session: u32, account: u64) -> Session {
        Session {
            account,
            registered: true,
            ..guest(session)
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

    fn upsert(session: Session) -> ViewEvent {
        ViewEvent {
            event: Some(view_event::Event::Upsert(session)),
        }
    }

    #[test]
    fn the_first_snapshot_is_every_session_arriving() {
        let mut presences = Presences::new(1);
        let changes = presences.apply(&snapshot(vec![guest(1), guest(2)]));
        assert_eq!(changes.len(), 2);
        assert!(matches!(changes[0], Presence::Arrived(_)));
    }

    #[test]
    fn a_resubscription_re_announces_nobody_who_was_already_here() {
        // The failure this guards: `session-view` restarts, the stream reopens
        // with a full snapshot, and every plugin is told the whole server just
        // connected. A greeter would greet everyone a second time.
        let mut presences = Presences::new(1);
        let _ = presences.apply(&snapshot(vec![guest(1), guest(2)]));
        let changes = presences.apply(&snapshot(vec![guest(1), guest(2)]));
        assert!(changes.is_empty(), "nothing changed, so nothing is said");
    }

    #[test]
    fn a_session_that_vanished_between_snapshots_is_reported_as_having_left() {
        // The other half of a reconnect: a client that disconnected while the
        // stream was down never produced a `Gone`, and a plugin holding it
        // forever would keep addressing a session that is not there.
        let mut presences = Presences::new(1);
        let _ = presences.apply(&snapshot(vec![guest(1), guest(2)]));
        let changes = presences.apply(&snapshot(vec![guest(2)]));
        assert_eq!(
            changes,
            vec![Presence::Left {
                server_id: 1,
                session: 1
            }]
        );
    }

    #[test]
    fn a_guest_who_registers_mid_session_arrives_again() {
        // The C++ host re-emitted `on_client_connected` for exactly this, and
        // tracked the last user id per session to spot it. A plugin keyed on
        // `user_id` would otherwise hold -1 for somebody who now has an
        // account, and friend chats are registered-only.
        let mut presences = Presences::new(1);
        let _ = presences.apply(&snapshot(vec![guest(7)]));
        let changes = presences.apply(&upsert(registered(7, 42)));
        assert_eq!(changes.len(), 1);
        let Presence::Arrived(info) = &changes[0] else {
            panic!("expected an arrival");
        };
        assert_eq!(info.user_id, 42);
        assert_eq!(info.session_id, 7);
    }

    #[test]
    fn moving_channel_or_renaming_is_not_an_arrival() {
        let mut presences = Presences::new(1);
        let _ = presences.apply(&snapshot(vec![registered(7, 42)]));
        let moved = Session {
            channel: 9,
            name: "renamed".to_owned(),
            ..registered(7, 42)
        };
        assert!(presences.apply(&upsert(moved)).is_empty());
    }

    #[test]
    fn a_guest_is_minus_one_and_never_the_superuser() {
        // Reading `account` directly would make every guest account 0, which is
        // the SuperUser. `is_registered` is what plugins gate on.
        let mut presences = Presences::new(1);
        let changes = presences.apply(&snapshot(vec![guest(1)]));
        let Presence::Arrived(info) = &changes[0] else {
            panic!("expected an arrival");
        };
        assert_eq!(info.user_id, -1);
        assert!(!info.is_registered());
    }

    #[test]
    fn a_departure_for_somebody_who_was_never_here_says_nothing() {
        let mut presences = Presences::new(1);
        let changes = presences.apply(&ViewEvent {
            event: Some(view_event::Event::Gone(Gone {
                session: 99,
                ..Gone::default()
            })),
        });
        assert!(changes.is_empty());
    }

    #[test]
    fn a_certificate_reaches_the_plugin_as_hex() {
        let mut presences = Presences::new(1);
        let with_cert = Session {
            cert_hash: vec![0x0a, 0xff, 0x01],
            ..guest(1)
        };
        let changes = presences.apply(&snapshot(vec![with_cert]));
        let Presence::Arrived(info) = &changes[0] else {
            panic!("expected an arrival");
        };
        assert_eq!(info.cert_hash.as_str(), "0aff01");
    }
}
