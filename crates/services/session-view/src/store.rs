//! The composed view itself: sessions by virtual server.
//!
//! Sharded by session id in the deployment model (`docs/diagrams/scaling.puml`)
//! — unsharded, one actor performs every domain read, which is Discord's
//! guild-process bottleneck relocated. The shard key is designed in now because
//! it cannot be retrofitted: every service in the domain calls this one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto_fancy::sessionview::{Session, Sessions as SessionList};

/// Every connected session, by virtual server.
#[derive(Debug, Clone, Default)]
pub struct Sessions {
    inner: Arc<Mutex<HashMap<u32, Shard>>>,
}

#[derive(Debug, Default)]
struct Shard {
    version: u64,
    sessions: HashMap<u32, Session>,
}

impl Sessions {
    /// An empty view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a session.
    pub fn upsert(&self, scope: u32, session: Session) {
        if let Ok(mut inner) = self.inner.lock() {
            let shard = inner.entry(scope).or_default();
            shard.version += 1;
            let _ = shard.sessions.insert(session.session, session);
        }
    }

    /// Forget a session.
    ///
    /// The removal happens before the caller is acknowledged, which is what
    /// makes "a stale deny is safe, a stale grant is a security bug" true here:
    /// a departed session can never be answered for.
    pub fn remove(&self, scope: u32, session: u32) {
        if let Ok(mut inner) = self.inner.lock() {
            let shard = inner.entry(scope).or_default();
            shard.version += 1;
            let _ = shard.sessions.remove(&session);
        }
    }

    /// One session.
    #[must_use]
    pub fn get(&self, scope: u32, session: u32) -> Option<Session> {
        self.inner.lock().ok().and_then(|inner| {
            inner
                .get(&scope)
                .and_then(|s| s.sessions.get(&session).cloned())
        })
    }

    /// Every session in `scope`, with the version they were read at.
    #[must_use]
    pub fn snapshot(&self, scope: u32) -> SessionList {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.get(&scope).map(|shard| SessionList {
                    version: shard.version,
                    sessions: shard.sessions.values().cloned().collect(),
                })
            })
            .unwrap_or_default()
    }

    /// Every session in a channel, which is what a fan-out needs.
    #[must_use]
    pub fn in_channel(&self, scope: u32, channel: u32) -> Vec<u32> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.get(&scope).map(|shard| {
                    shard
                        .sessions
                        .values()
                        .filter(|session| session.channel == channel)
                        .map(|session| session.session)
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    /// How many sessions are held in `scope`.
    #[must_use]
    pub fn len(&self, scope: u32) -> usize {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.get(&scope).map(|shard| shard.sessions.len()))
            .unwrap_or_default()
    }

    /// Whether `scope` holds nothing.
    #[must_use]
    pub fn is_empty(&self, scope: u32) -> bool {
        self.len(scope) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: u32, channel: u32) -> Session {
        Session {
            session: id,
            channel,
            ..Session::default()
        }
    }

    #[test]
    fn the_version_moves_on_every_change_so_a_reader_can_tell_it_missed_one() {
        let sessions = Sessions::new();
        sessions.upsert(1, session(1, 0));
        let first = sessions.snapshot(1).version;
        sessions.upsert(1, session(2, 0));
        assert!(sessions.snapshot(1).version > first);
    }

    #[test]
    fn a_channel_fan_out_reads_only_that_channel() {
        let sessions = Sessions::new();
        sessions.upsert(1, session(1, 5));
        sessions.upsert(1, session(2, 5));
        sessions.upsert(1, session(3, 6));
        let mut members = sessions.in_channel(1, 5);
        members.sort_unstable();
        assert_eq!(members, vec![1, 2]);
    }

    #[test]
    fn removing_a_session_takes_effect_immediately() {
        let sessions = Sessions::new();
        sessions.upsert(1, session(1, 0));
        sessions.remove(1, 1);
        assert!(sessions.get(1, 1).is_none());
        assert!(sessions.is_empty(1));
    }
}
