//! The picture and comment each connected user was announced with.
//!
//! `session-lifecycle` puts the hash of what a user sets about themselves on
//! their session record, for anybody, registered or not, and announces that
//! hash; a client then redeems it with `RequestBlob`. So the record is what
//! names the blob to serve: answering from the account alone left a guest's
//! picture and comment announced to everyone and fetchable by nobody. murmur
//! serves a guest's too, for as long as they are connected
//! (`vendor/server/src/murmur/Messages.cpp`, `msgRequestBlob`).

use starling_proto_fancy::sessionview::Session;
use starling_runtime::roster::Roster;

/// Which of the two a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Content {
    /// `UserState.texture`, the picture.
    Texture,
    /// `UserState.comment`.
    Comment,
}

/// Every connected session, read for the hashes they were announced with.
#[derive(Debug)]
pub(crate) struct Announced {
    roster: Roster,
    sessions: Vec<Session>,
}

impl Announced {
    /// The view of `sessions`, as `session-view` listed them.
    pub(crate) fn new(sessions: Vec<Session>) -> Self {
        Self {
            roster: Roster::of(sessions.clone()),
            sessions,
        }
    }

    /// The hash announced for the user a client knows as `presented`.
    ///
    /// Through every device of that user, because the id a client asks about
    /// may be one shown for a user whose first device has since left, and the
    /// first device that names one wins, as it does in the roster a client is
    /// handed on connect. `None` for a user who set nothing.
    pub(crate) fn hash(&self, presented: u32, what: Content) -> Option<Vec<u8>> {
        let devices = self.roster.devices_of(presented);
        self.sessions
            .iter()
            .filter(|session| devices.contains(&session.session))
            .map(|session| match what {
                Content::Texture => &session.texture_hash,
                Content::Comment => &session.comment_hash,
            })
            .find(|hash| !hash.is_empty())
            .cloned()
    }

    /// The account behind the user a client knows as `presented`, if any.
    pub(crate) fn account(&self, presented: u32) -> Option<u64> {
        self.roster
            .devices_of(presented)
            .into_iter()
            .find_map(|device| self.roster.account_of(device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: u32, shown: u32, texture: &[u8], comment: &[u8]) -> Session {
        Session {
            session: id,
            presented_as: shown,
            texture_hash: texture.to_vec(),
            comment_hash: comment.to_vec(),
            ..Session::default()
        }
    }

    #[test]
    fn a_guests_picture_and_comment_are_named_by_their_own_record() {
        // A guest has no account, and the record is the only place their
        // hashes live: this is the case that was announced and never served.
        let announced = Announced::new(vec![session(4, 4, b"pic", b"words")]);
        assert_eq!(announced.account(4), None);
        assert_eq!(
            announced.hash(4, Content::Texture).as_deref(),
            Some(&b"pic"[..])
        );
        assert_eq!(
            announced.hash(4, Content::Comment).as_deref(),
            Some(&b"words"[..])
        );
    }

    #[test]
    fn a_user_who_set_nothing_names_no_hash() {
        let announced = Announced::new(vec![session(4, 4, b"", b"")]);
        assert_eq!(announced.hash(4, Content::Texture), None);
        assert_eq!(announced.hash(4, Content::Comment), None);
        assert_eq!(announced.hash(9, Content::Texture), None, "nobody holds 9");
    }

    #[test]
    fn a_user_on_two_devices_is_answered_through_either_of_them() {
        // Shown to everyone as 3; the device that holds 3 has left, the
        // other one set the picture.
        let announced = Announced::new(vec![session(7, 3, b"phone pic", b"")]);
        assert_eq!(
            announced.hash(3, Content::Texture).as_deref(),
            Some(&b"phone pic"[..])
        );
        // And while both are there, the first device that names one.
        let both = Announced::new(vec![
            session(3, 3, b"", b"said"),
            session(7, 3, b"pic", b""),
        ]);
        assert_eq!(both.hash(3, Content::Texture).as_deref(), Some(&b"pic"[..]));
        assert_eq!(
            both.hash(3, Content::Comment).as_deref(),
            Some(&b"said"[..])
        );
    }
}
