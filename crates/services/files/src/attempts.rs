//! How many wrong passwords a caller may try, and how fast.
//!
//! A share link is a public address with a secret behind it, which is the one
//! shape in this server that can simply be guessed at. Without a limit the
//! Argon2id cost is the only thing between an attacker and the file, and that
//! is a cost measured in milliseconds against an attacker measured in cores.
//!
//! Counted per object rather than per caller. An IP is what the epoch-0 plugin
//! keyed on, and behind a reverse proxy - which is where every one of these
//! deployments sits - every request arrives from the same one, so keying on it
//! here would lock out the whole internet the first time one person mistyped.
//! Per object is the property actually worth protecting: the file, not the
//! network.
//!
//! Only failures are counted, and a success clears the record, so the person
//! who fumbles a password twice and then gets it right is never delayed.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use starling_runtime::ids::now_ms;

/// Wrong guesses one object tolerates inside [`WINDOW`].
pub(crate) const MAX_FAILURES: usize = 10;

/// How long a wrong guess is remembered.
pub(crate) const WINDOW: Duration = Duration::from_secs(300);

/// Wrong guesses, by object key.
#[derive(Default)]
pub(crate) struct Attempts {
    failures: RwLock<HashMap<String, Vec<u64>>>,
}

impl std::fmt::Debug for Attempts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Attempts")
    }
}

impl Attempts {
    /// Whether `key` may be guessed at again right now.
    pub(crate) fn allowed(&self, key: &str) -> bool {
        let Ok(failures) = self.failures.read() else {
            // A poisoned lock must not become a way to turn the limit off.
            return false;
        };
        let cutoff = now_ms().saturating_sub(WINDOW.as_millis() as u64);
        failures
            .get(key)
            .is_none_or(|at| at.iter().filter(|&&at| at > cutoff).count() < MAX_FAILURES)
    }

    /// Note a wrong guess at `key`.
    pub(crate) fn failed(&self, key: &str) {
        let Ok(mut failures) = self.failures.write() else {
            return;
        };
        let now = now_ms();
        let cutoff = now.saturating_sub(WINDOW.as_millis() as u64);
        // Swept here rather than on a timer: nothing is added except by a
        // failure, so there is no quiet period in which a stale entry matters.
        failures.retain(|_, at| at.iter().any(|&at| at > cutoff));
        let entry = failures.entry(key.to_owned()).or_default();
        entry.retain(|&at| at > cutoff);
        entry.push(now);
    }

    /// Forget the wrong guesses at `key`, because one was right.
    pub(crate) fn cleared(&self, key: &str) {
        if let Ok(mut failures) = self.failures.write() {
            let _ = failures.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guessing_is_allowed_until_it_has_been_wrong_too_often() {
        let attempts = Attempts::default();
        assert!(attempts.allowed("k"));
        for _ in 0..MAX_FAILURES - 1 {
            attempts.failed("k");
        }
        assert!(attempts.allowed("k"), "still under the limit");
        attempts.failed("k");
        assert!(!attempts.allowed("k"), "and blocked once it is reached");
    }

    #[test]
    fn one_object_being_guessed_at_does_not_lock_another() {
        // The failure the per-object key exists to avoid: behind a proxy every
        // request shares a source address, so a per-caller limit would make
        // one person's typo everyone else's problem.
        let attempts = Attempts::default();
        for _ in 0..MAX_FAILURES {
            attempts.failed("k");
        }
        assert!(!attempts.allowed("k"));
        assert!(attempts.allowed("other"));
    }

    #[test]
    fn a_right_guess_forgets_the_wrong_ones() {
        // Otherwise somebody who fumbled their password twice would spend the
        // rest of the window paying for it.
        let attempts = Attempts::default();
        for _ in 0..MAX_FAILURES {
            attempts.failed("k");
        }
        assert!(!attempts.allowed("k"));
        attempts.cleared("k");
        assert!(attempts.allowed("k"));
    }
}
