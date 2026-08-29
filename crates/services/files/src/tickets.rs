//! Single-use tickets, so a password never travels in a URL.
//!
//! A password share is opened in two steps: `POST` the password and get a
//! ticket, then `GET` the object with the ticket on the query string. The
//! split exists because a URL is the one part of a request that is written
//! down everywhere - browser history, proxy logs, the `Referer` of whatever
//! the file links to - and a password in it is a password in all of those. A
//! ticket in the same place is worth nothing a moment later.
//!
//! The ticket also carries the object's decryption key. That key only exists
//! while somebody who knows the password is asking for the file, which is the
//! whole reason the server cannot read its own password shares: deriving it
//! costs an Argon2id pass and a secret the server never keeps.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use rand::TryRng as _;
use rand::rngs::SysRng;
use starling_runtime::ids::now_ms;
use zeroize::Zeroizing;

/// How long a ticket is worth anything.
///
/// Long enough to be redeemed by the request that follows the one which
/// minted it, and short enough that a leaked one is a curiosity. The browser
/// spends it immediately; nothing waits on a user here.
pub(crate) const TICKET_TTL: Duration = Duration::from_secs(30);

/// A ticket that has been issued and not yet spent.
struct Ticket {
    /// The one object this ticket opens.
    key: String,
    expires_at_ms: u64,
    /// The object's decryption key, for a sealed object.
    enc_key: Option<Zeroizing<[u8; 32]>>,
}

/// What redeeming a ticket did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Redeemed {
    /// It was good, and it is now spent.
    Ok,
    /// It was good for a different object.
    WrongObject,
    /// No such ticket: never issued, already spent, or expired.
    Unknown,
}

/// Tickets in flight.
#[derive(Default)]
pub(crate) struct Tickets {
    issued: RwLock<HashMap<String, Ticket>>,
}

impl std::fmt::Debug for Tickets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately says nothing about what is held: these carry file keys,
        // and a `{:?}` in a log line should not be how one escapes.
        formatter.write_str("Tickets")
    }
}

impl Tickets {
    /// Mint a ticket for `key`, carrying `enc_key` if the object is sealed.
    pub(crate) fn issue(&self, key: &str, enc_key: Option<Zeroizing<[u8; 32]>>) -> Option<String> {
        let mut raw = [0u8; 32];
        SysRng.try_fill_bytes(&mut raw).ok()?;
        let ticket = hex(&raw);
        let mut issued = self.issued.write().ok()?;
        // Swept on the way in rather than on a timer: tickets are only ever
        // created by a request, so there is no quiet period in which a stale
        // one matters, and a map that only grows would be a leak.
        let now = now_ms();
        issued.retain(|_, held| held.expires_at_ms > now);
        let _ = issued.insert(
            ticket.clone(),
            Ticket {
                key: key.to_owned(),
                expires_at_ms: now + TICKET_TTL.as_millis() as u64,
                enc_key,
            },
        );
        Some(ticket)
    }

    /// Spend `ticket` on `key`, taking whatever it carried.
    ///
    /// A ticket presented for the wrong object is still spent: it was minted
    /// for one thing, and letting it be tried against another until it hits
    /// would make it a probe.
    pub(crate) fn redeem(
        &self,
        ticket: &str,
        key: &str,
    ) -> (Redeemed, Option<Zeroizing<[u8; 32]>>) {
        let Ok(mut issued) = self.issued.write() else {
            return (Redeemed::Unknown, None);
        };
        let Some(held) = issued.remove(ticket) else {
            return (Redeemed::Unknown, None);
        };
        if held.expires_at_ms <= now_ms() {
            return (Redeemed::Unknown, None);
        }
        if held.key != key {
            return (Redeemed::WrongObject, None);
        }
        (Redeemed::Ok, held.enc_key)
    }
}

/// Lowercase hex, for a ticket that has to survive a query string.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_opens_its_own_object_once() {
        let tickets = Tickets::default();
        let ticket = tickets.issue("7/abc/file.txt", None).expect("issue");
        assert_eq!(tickets.redeem(&ticket, "7/abc/file.txt").0, Redeemed::Ok);
        // Spent: the second attempt is not a second download.
        assert_eq!(
            tickets.redeem(&ticket, "7/abc/file.txt").0,
            Redeemed::Unknown
        );
    }

    #[test]
    fn a_ticket_for_one_object_does_not_open_another() {
        let tickets = Tickets::default();
        let ticket = tickets.issue("7/abc/file.txt", None).expect("issue");
        assert_eq!(
            tickets.redeem(&ticket, "7/def/other.txt").0,
            Redeemed::WrongObject
        );
        // And it is spent even so, so it cannot be walked across keys.
        assert_eq!(
            tickets.redeem(&ticket, "7/abc/file.txt").0,
            Redeemed::Unknown
        );
    }

    #[test]
    fn an_unknown_ticket_is_not_honoured() {
        let tickets = Tickets::default();
        assert_eq!(
            tickets.redeem("nope", "7/abc/file.txt").0,
            Redeemed::Unknown
        );
    }

    #[test]
    fn a_ticket_carries_the_key_that_opens_the_object() {
        let tickets = Tickets::default();
        let ticket = tickets
            .issue("7/abc/file.txt", Some(Zeroizing::new([3u8; 32])))
            .expect("issue");
        let (result, key) = tickets.redeem(&ticket, "7/abc/file.txt");
        assert_eq!(result, Redeemed::Ok);
        assert_eq!(key.expect("a key").as_slice(), [3u8; 32]);
    }
}
