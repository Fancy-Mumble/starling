//! The handshake's half of invite links: noticing one, and asking whether it
//! lets this login in.
//!
//! The code arrives as an access token spelled `invite:<code>`, so it can be
//! typed into any Mumble client's token box, and it is taken **out** of the
//! token list before that list is stored: an invite is a way through the front
//! door, never a key to a `#token`-gated channel, and a code sitting in
//! `session-view` for the rest of the connection would be a secret on display
//! to every service that reads a session.

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::invites::RedeemRequest;
use starling_proto_fancy::invites::invites_client::InvitesClient;
use starling_proto_fancy::serverconfig::Snapshot;
use starling_runtime::channel::Resolver;

/// The prefix a token carries when it is an invite code.
pub const TOKEN_PREFIX: &str = "invite:";

/// The access tokens with every invite taken out, and the first invite code
/// among them.
///
/// Only one is honoured. A client has no reason to send two, and trying each
/// in turn would make a login a way to test codes several at a time.
#[must_use]
pub fn split_tokens(tokens: &[String]) -> (Vec<String>, Option<String>) {
    let mut code = None;
    let kept = tokens
        .iter()
        .filter(|token| match token.trim().strip_prefix(TOKEN_PREFIX) {
            Some(found) => {
                if code.is_none() && !found.is_empty() {
                    code = Some(found.trim().to_owned());
                }
                false
            }
            None => true,
        })
        .cloned()
        .collect();
    (kept, code)
}

/// Whether the operator has invites on at all.
///
/// Read from the snapshot the handshake already holds, so a server with them
/// off never makes the call. An unreadable snapshot - server-config down, so
/// the handshake is on its fallback - reads as off: skipping the password is
/// not something to do on a guess.
#[must_use]
pub fn enabled(config: &Snapshot) -> bool {
    use starling_runtime::settings::{INVITES_ADMINS, INVITES_EVERYONE, INVITES_REGISTERED};
    [INVITES_ADMINS, INVITES_REGISTERED, INVITES_EVERYONE].contains(&config.invites.as_str())
}

/// What presenting an invite came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// No invite was presented.
    None,
    /// One was presented and it lets them in.
    Admitted {
        /// Where it lands them, zero for nowhere in particular.
        channel: u32,
    },
    /// One was presented and it does not: expired, revoked, used up, or
    /// invites are off. The password still decides.
    Refused,
}

/// Redeem `code` for this login.
///
/// Every failure is [`Outcome::Refused`], never an error: an unreachable
/// `invites` service leaves the ordinary password check in charge, which is
/// exactly the server as it was before invites existed.
pub async fn redeem(
    resolver: &Resolver,
    scope: u32,
    code: &str,
    cert_hash: &[u8],
    name: &str,
) -> Outcome {
    let Ok(channel) = resolver.channel("invites") else {
        tracing::debug!("an invite was presented but no invites service is configured");
        return Outcome::Refused;
    };
    match InvitesClient::new(channel)
        .redeem(RedeemRequest {
            scope: Some(Scope { instance: scope }),
            code: code.to_owned(),
            cert_hash: cert_hash.to_vec(),
            name: name.to_owned(),
        })
        .await
    {
        Ok(reply) => {
            let reply = reply.into_inner();
            if reply.admitted {
                Outcome::Admitted {
                    channel: reply.channel,
                }
            } else {
                // Logged here and never sent: the person refused is told only
                // that the password is wrong, the same as without an invite,
                // so a login cannot be used to learn which codes exist.
                tracing::info!(%name, reason = %reply.reason, "an invite was presented and refused");
                Outcome::Refused
            }
        }
        Err(status) => {
            tracing::warn!(%status, "the invites service could not be asked; the password decides");
            Outcome::Refused
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(list: &[&str]) -> Vec<String> {
        list.iter().map(|&token| token.to_owned()).collect()
    }

    #[test]
    fn an_invite_is_taken_out_of_the_tokens_and_everything_else_stays() {
        let (kept, code) = split_tokens(&tokens(&["hunter2", "invite:abcdefghjkmn", "lobby"]));
        assert_eq!(kept, tokens(&["hunter2", "lobby"]));
        assert_eq!(code.as_deref(), Some("abcdefghjkmn"));
    }

    #[test]
    fn only_the_first_invite_counts_and_every_one_is_removed() {
        let (kept, code) = split_tokens(&tokens(&["invite:first", "invite:second"]));
        assert!(kept.is_empty(), "no invite may reach the ACL tokens");
        assert_eq!(code.as_deref(), Some("first"));
    }

    #[test]
    fn a_bare_prefix_is_no_invite_and_ordinary_tokens_are_untouched() {
        let (kept, code) = split_tokens(&tokens(&["invite:", "plain"]));
        assert_eq!(kept, tokens(&["plain"]));
        assert_eq!(code, None);
    }

    #[test]
    fn invites_are_off_unless_the_setting_names_who_may_mint_them() {
        let mut config = starling_runtime::settings::defaults(1);
        assert!(enabled(&config), "on for admins by default");
        config.invites = "off".to_owned();
        assert!(!enabled(&config));
        // The handshake's fallback when server-config is down.
        assert!(!enabled(&Snapshot::default()));
    }
}
