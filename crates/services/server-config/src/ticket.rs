//! Short-lived operator tickets.
//!
//! Minted for a session that has already proven, over the control channel,
//! that it holds the permission [`starling_runtime::operator_scope`] requires
//! for the scopes it asked for -- see [`super::on_ticket_request`]. Verified
//! from a different process a request away: `operator-api` calls
//! `VerifyTicket` when its own configured authenticator does not recognise a
//! bearer, so this store is the only place that needs to agree with itself
//! about what a ticket token means.
//!
//! Not persisted, and not shared across a fleet of `server-config` replicas:
//! a restart, or a second pod a load balancer happened to route the upload
//! to, simply does not honour a ticket minted by the other. That reads to a
//! client exactly as an expired ticket does, and the shipped deployment runs
//! one `server-config` replica.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::TryRng as _;
use rand::rngs::SysRng;
use sha2::{Digest as _, Sha256};

/// How long a minted ticket lives, at most -- long enough to pick a file and
/// upload it over a slow connection, short enough that one written to a log
/// by accident is not useful for long after.
const MAX_TTL: Duration = Duration::from_secs(300);

struct Entry {
    subject: String,
    scopes: Vec<String>,
    expires_at: Instant,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("subject", &self.subject)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// What minting a ticket hands back.
#[derive(Debug)]
pub struct Issued {
    /// The bearer value to present to the operator API. Shown to nobody else:
    /// the store keeps only its digest, so this is the only place it exists
    /// in the clear.
    pub token: String,
    /// When it stops verifying, milliseconds since the epoch.
    pub expires_at_ms: u64,
}

/// One process's live tickets, keyed by the SHA-256 of the token rather than
/// the token itself, so a memory dump of this process does not hand out live
/// bearer credentials -- the same reasoning `operator-api`'s own audit log
/// follows for a static token's *name*.
#[derive(Debug, Default)]
pub struct TicketStore {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
}

impl TicketStore {
    /// Mint a ticket good for `scopes`, attributed to `subject`.
    ///
    /// `None` only when the OS entropy source is unavailable, in which case
    /// there is nothing safer to fall back to: a token drawn from anything
    /// weaker would be a silent downgrade of the credential it stands in for.
    pub fn issue(&self, subject: String, scopes: Vec<String>) -> Option<Issued> {
        self.sweep();

        let mut bytes = [0u8; 32];
        SysRng.try_fill_bytes(&mut bytes).ok()?;
        let token = hex(&bytes);

        let expires_at = Instant::now() + MAX_TTL;
        let expires_at_ms = epoch_ms_in(MAX_TTL);
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let _ = lock(&self.entries).insert(
            key,
            Entry {
                subject,
                scopes,
                expires_at,
            },
        );
        Some(Issued {
            token,
            expires_at_ms,
        })
    }

    /// The subject and scopes behind `token`, or `None` when it is unknown,
    /// expired, or was never issued by this process.
    ///
    /// An expired entry is removed on the way out rather than left for the
    /// next [`Self::issue`] to sweep, so a token nobody ever mints again does
    /// not sit in memory forever.
    pub fn verify(&self, token: &str) -> Option<(String, Vec<String>)> {
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut entries = lock(&self.entries);
        let entry = entries.get(&key)?;
        if entry.expires_at < Instant::now() {
            let _ = entries.remove(&key);
            return None;
        }
        Some((entry.subject.clone(), entry.scopes.clone()))
    }

    /// Drop everything that has expired. Run on every mint rather than on a
    /// timer, so a store nobody uses carries no background task of its own.
    fn sweep(&self) {
        let now = Instant::now();
        lock(&self.entries).retain(|_, entry| entry.expires_at >= now);
    }
}

/// A poisoned lock still holds every ticket that was ever valid; refusing to
/// read it would turn one panicking caller into an outage for the credential
/// every other session's upload depends on.
fn lock(
    entries: &Mutex<HashMap<[u8; 32], Entry>>,
) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Entry>> {
    entries
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Milliseconds since the epoch, `ttl` from now.
///
/// Wall-clock, unlike the [`Instant`] the store checks expiry against: this
/// value only ever travels to a client to display or compare, and a client
/// has no way to interpret a monotonic instant that means nothing outside
/// this process.
fn epoch_ms_in(ttl: Duration) -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(ttl)
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_ticket_verifies_to_the_scopes_it_was_issued_with() {
        let store = TicketStore::default();
        let issued = store
            .issue(
                "session:7".to_owned(),
                vec!["server-config:write".to_owned()],
            )
            .expect("the OS entropy source is available in tests");
        let (subject, scopes) = store.verify(&issued.token).expect("just issued");
        assert_eq!(subject, "session:7");
        assert_eq!(scopes, vec!["server-config:write".to_owned()]);
    }

    #[test]
    fn an_unknown_token_does_not_verify() {
        let store = TicketStore::default();
        assert!(store.verify("never issued").is_none());
    }

    #[test]
    fn two_tickets_never_share_a_token() {
        let store = TicketStore::default();
        let a = store.issue("a".to_owned(), vec![]).expect("issued");
        let b = store.issue("b".to_owned(), vec![]).expect("issued");
        assert_ne!(a.token, b.token);
    }

    #[test]
    fn a_verified_ticket_does_not_carry_a_stale_wall_clock_reading() {
        let store = TicketStore::default();
        let before = epoch_ms_in(Duration::ZERO);
        let issued = store.issue("s".to_owned(), vec![]).expect("issued");
        assert!(issued.expires_at_ms >= before);
    }

    #[test]
    fn an_expired_ticket_stops_verifying() {
        let store = TicketStore::default();
        let key: [u8; 32] = Sha256::digest(b"stale").into();
        let _ = lock(&store.entries).insert(
            key,
            Entry {
                subject: "s".to_owned(),
                scopes: vec![],
                // Already in the past, so `verify` finds it expired without
                // this test needing to sleep past a real TTL.
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(store.verify("stale").is_none());
    }
}
