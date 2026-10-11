//! Who wrote a message, so that only its author may edit it.
//!
//! An edit is an ordinary `TextMessage` carrying `edit_id`, the id of the
//! message it replaces. Relayed without a check, any member of a channel could
//! put somebody else's id there and every Fancy client would rewrite that
//! person's words in place. murmur's fork kept a `message_id -> session` map
//! for exactly this (`Messages.cpp`, `m_messageOwners`) and refused an edit
//! naming an id it did not know or one somebody else sent.
//!
//! Two things differ here. The identity is the **certificate** where there is
//! one, not the session: a session id is reused, and changes across a
//! reconnect, so keyed by session the author lost the right to edit the moment
//! their connection blipped, and the next person handed that number gained it.
//! And the map is **bounded**: murmur's grew for as long as the server ran,
//! which is a memory leak paced by how much people talk. The oldest entries
//! fall out first, and an edit of a message that old is refused the way one
//! naming an unknown id is, unless the archive still holds it.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// How many recent messages keep a known author.
///
/// Edits are overwhelmingly of something just sent, so a few thousand recent
/// messages per server is the whole of the useful window, and a fixed cap is
/// what keeps the map from being a slow leak.
pub const CAPACITY: usize = 16_384;

/// The identity an edit is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    /// The certificate hash, when the sender presented one.
    pub cert: Option<Vec<u8>>,
    /// The session, which is all an anonymous sender has.
    ///
    /// `None` for an author read back from the archive: the session that
    /// wrote a stored row is long gone, and a guess would hand the edit right
    /// to whoever holds that number now.
    pub session: Option<u32>,
}

impl Author {
    /// The author of a message sent on `session` with `cert`.
    ///
    /// An empty certificate is no certificate: the roster reports one for a
    /// session that never presented any, and two of those must not compare
    /// equal.
    #[must_use]
    pub fn new(session: u32, cert: Option<Vec<u8>>) -> Self {
        Self {
            cert: cert.filter(|cert| !cert.is_empty()),
            session: Some(session),
        }
    }

    /// Whether `other` is the same person as this one.
    ///
    /// By certificate when both have one, which is the identity that survives
    /// a reconnect. By session only when neither does, because a sender with
    /// no certificate has nothing else. One with and one without is a no: the
    /// certificate holder did not lose it in between.
    #[must_use]
    pub fn is(&self, other: &Self) -> bool {
        match (&self.cert, &other.cert) {
            (Some(mine), Some(theirs)) => mine == theirs,
            (None, None) => self.session.is_some() && self.session == other.session,
            _ => false,
        }
    }
}

/// The recent message ids of every tenant, and who wrote each.
#[derive(Debug, Default)]
pub struct Owners {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    authors: HashMap<(u32, String), Author>,
    /// Insertion order, for eviction. A re-recorded id is not moved, which
    /// only means it is evicted a little early; ids are minted fresh per
    /// message, so that is a case for a retry and nothing else.
    order: VecDeque<(u32, String)>,
}

impl Owners {
    /// Remember that `author` sent message `id` on tenant `scope`.
    pub fn record(&self, scope: u32, id: &str, author: Author) {
        if id.is_empty() {
            return;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let key = (scope, id.to_owned());
        if inner.authors.insert(key.clone(), author).is_none() {
            inner.order.push_back(key);
        }
        while inner.order.len() > CAPACITY {
            if let Some(oldest) = inner.order.pop_front() {
                let _ = inner.authors.remove(&oldest);
            }
        }
    }

    /// Who sent message `id` on tenant `scope`, if it is recent enough to be
    /// remembered.
    #[must_use]
    pub fn author_of(&self, scope: u32, id: &str) -> Option<Author> {
        self.inner
            .lock()
            .ok()?
            .authors
            .get(&(scope, id.to_owned()))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_certificate_on_a_new_session_is_still_the_author() {
        // The reconnect case: the session id changed, the person did not.
        let before = Author::new(7, Some(b"alice".to_vec()));
        let after = Author::new(12, Some(b"alice".to_vec()));
        assert!(after.is(&before));
    }

    #[test]
    fn a_different_certificate_on_the_same_session_is_not() {
        // The reuse case: somebody else was handed the number.
        let alice = Author::new(7, Some(b"alice".to_vec()));
        let mallory = Author::new(7, Some(b"mallory".to_vec()));
        assert!(!mallory.is(&alice));
    }

    #[test]
    fn without_certificates_the_session_decides() {
        let anon = Author::new(7, None);
        assert!(Author::new(7, Some(Vec::new())).is(&anon));
        assert!(!Author::new(8, None).is(&anon));
    }

    #[test]
    fn an_archived_author_without_a_certificate_matches_nobody() {
        let archived = Author {
            cert: None,
            session: None,
        };
        assert!(!Author::new(7, None).is(&archived));
    }

    #[test]
    fn the_oldest_authors_are_forgotten_first() {
        let owners = Owners::default();
        for n in 0..=CAPACITY {
            owners.record(1, &n.to_string(), Author::new(7, None));
        }
        assert!(owners.author_of(1, "0").is_none(), "the oldest was kept");
        assert!(owners.author_of(1, &CAPACITY.to_string()).is_some());
    }

    #[test]
    fn tenants_do_not_share_ids() {
        let owners = Owners::default();
        owners.record(1, "m", Author::new(7, None));
        assert!(owners.author_of(2, "m").is_none());
    }
}
