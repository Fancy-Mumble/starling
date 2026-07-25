//! The connected-user entity.

use starling_proto::Version;

use crate::ids::{ChannelId, SessionId, UserId};

/// A connected, authenticated user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Connection-scoped id. Recycled after disconnect.
    pub session: SessionId,
    /// Display name.
    pub name: String,
    /// Registered account id, or `None` for an anonymous connection.
    pub user_id: Option<UserId>,
    /// The channel the user currently occupies.
    pub channel: ChannelId,
    /// Muted by an administrator.
    pub mute: bool,
    /// Deafened by an administrator.
    pub deaf: bool,
    /// Suppressed by the server (e.g. lacks Speak).
    pub suppress: bool,
    /// Muted themselves.
    pub self_mute: bool,
    /// Deafened themselves.
    pub self_deaf: bool,
    /// Announced they are recording.
    pub recording: bool,
    /// SHA-1 hex digest of the client certificate, when one was presented.
    pub cert_hash: Option<String>,
    /// The Mumble version the client announced.
    pub version: Version,
    /// The Fancy extension version, when the client announced one.
    pub fancy_version: Option<u64>,
}

impl User {
    /// Create a user in `channel` with everything else at its default.
    #[must_use]
    pub fn new(session: SessionId, name: impl Into<String>, channel: ChannelId) -> Self {
        Self {
            session,
            name: name.into(),
            user_id: None,
            channel,
            mute: false,
            deaf: false,
            suppress: false,
            self_mute: false,
            self_deaf: false,
            recording: false,
            cert_hash: None,
            version: Version::new(0, 0, 0),
            fancy_version: None,
        }
    }

    /// Whether this client understands Fancy Mumble extension messages.
    #[must_use]
    pub fn is_fancy_client(&self) -> bool {
        self.fancy_version.is_some()
    }

    /// Whether the user is registered (as opposed to connecting anonymously).
    #[must_use]
    pub fn is_registered(&self) -> bool {
        self.user_id.is_some()
    }

    /// Whether the user can currently transmit audio.
    ///
    /// Deafening implies muting, and an administrative mute or suppression
    /// overrides the user's own choice — so this is the single place that
    /// decides, rather than four separate boolean checks at call sites.
    #[must_use]
    pub fn can_transmit(&self) -> bool {
        !(self.mute || self.deaf || self.suppress || self.self_mute || self.self_deaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ROOT_CHANNEL;

    fn user() -> User {
        User::new(SessionId(1), "alice", ROOT_CHANNEL)
    }

    #[test]
    fn a_new_user_is_anonymous_and_unmuted() {
        let u = user();
        assert!(!u.is_registered());
        assert!(!u.is_fancy_client());
        assert!(u.can_transmit());
    }

    #[test]
    fn fancy_clients_are_identified_by_an_announced_version() {
        let mut u = user();
        u.fancy_version = Some(0x0000_0003_0000_0000);
        assert!(u.is_fancy_client());
    }

    #[test]
    fn every_mute_flavour_blocks_transmission() {
        for (label, apply) in [
            (
                "admin mute",
                (|u: &mut User| u.mute = true) as fn(&mut User),
            ),
            ("admin deaf", |u: &mut User| u.deaf = true),
            ("suppress", |u: &mut User| u.suppress = true),
            ("self mute", |u: &mut User| u.self_mute = true),
            ("self deaf", |u: &mut User| u.self_deaf = true),
        ] {
            let mut u = user();
            apply(&mut u);
            assert!(!u.can_transmit(), "{label} should block transmission");
        }
    }
}
