//! Whether a login is banned, asked of `moderation` before any password is
//! looked at.
//!
//! murmur turns a banned address away at accept and a banned certificate as
//! soon as TLS is up (`Server.cpp:1587`, `:1724`), and in both cases closes the
//! socket without a word. Here both are asked at `Authenticate`, the first
//! moment a refusal can be *said*: a client told it is banned stops, one whose
//! socket simply closes reconnects in a loop. Nobody is exempt, the SuperUser
//! included, as in murmur.
//!
//! `moderation` is a core service, and a core service being down admits logins
//! (`Tier::Core`): a ban list that cannot be read lets the login through, and
//! says so in the log.

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::moderation::BanCheck;
use starling_proto_fancy::moderation::moderation_client::ModerationClient;
use starling_runtime::channel::Resolver;

use crate::PendingConnection;

/// A ban that covers a login, as the person turned away is told it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banned {
    /// What the moderator wrote, possibly nothing.
    pub reason: String,
    /// When it runs out, in milliseconds since the epoch; 0 for never.
    pub until_ms: u64,
}

impl Banned {
    /// The words of the `Reject`.
    ///
    /// Without "password" or "certificate" in them: a client that reads a
    /// refusal's words where it has no type takes those as a wrong password
    /// and asks for one (`mumble-tauri`, `Wanted::of`).
    #[must_use]
    pub fn message(&self) -> String {
        let mut message = "You are banned from this server".to_owned();
        if !self.reason.is_empty() {
            message.push_str(": ");
            message.push_str(&self.reason);
        }
        if self.until_ms != 0 {
            let at = std::time::UNIX_EPOCH + std::time::Duration::from_millis(self.until_ms);
            let stamp = starling_runtime::log::timestamp::rfc3339(at);
            // To the minute: "2026-11-14 18:30 UTC".
            if let Some(minute) = stamp.get(..16) {
                message.push_str(&format!(" (until {} UTC)", minute.replace('T', " ")));
            }
        }
        message
    }
}

/// The ban list, as a login asks it.
#[derive(Debug, Clone, Copy)]
pub struct Bans<'a>(pub &'a Resolver);

impl Bans<'_> {
    /// The ban covering `pending` logging in as `name`, if there is one.
    pub async fn covering(&self, pending: &PendingConnection, name: &str) -> Option<Banned> {
        let transport = match self.0.channel("moderation") {
            Ok(transport) => transport,
            Err(error) => {
                tracing::warn!(%error, "moderation is unreachable; a login is not checked for bans");
                return None;
            }
        };
        let verdict = ModerationClient::new(transport)
            .check_ban(BanCheck {
                scope: Some(Scope {
                    instance: pending.scope,
                }),
                address: crate::address_bytes(&pending.address),
                cert_hash: pending.cert_hash.clone(),
                name: name.to_owned(),
            })
            .await;
        match verdict {
            Ok(verdict) => {
                let verdict = verdict.into_inner();
                verdict.banned.then_some(Banned {
                    reason: verdict.reason,
                    until_ms: verdict.expires_at_ms,
                })
            }
            Err(status) => {
                tracing::warn!(%status, "the ban check failed; a login is not checked for bans");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permanent_ban_says_so_and_why() {
        let banned = Banned {
            reason: "spam".to_owned(),
            until_ms: 0,
        };
        assert_eq!(banned.message(), "You are banned from this server: spam");
    }

    #[test]
    fn a_timed_ban_says_until_when() {
        // 2026-11-14 18:30:00 UTC.
        let banned = Banned {
            reason: String::new(),
            until_ms: 1_794_681_000_000,
        };
        assert_eq!(
            banned.message(),
            "You are banned from this server (until 2026-11-14 18:30 UTC)"
        );
    }

    #[test]
    fn the_words_never_read_as_a_password_refusal() {
        let banned = Banned {
            reason: "x".to_owned(),
            until_ms: 1,
        };
        let words = banned.message().to_lowercase();
        assert!(!words.contains("password") && !words.contains("certificate"));
    }
}
