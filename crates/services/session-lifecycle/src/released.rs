//! Letting go of a guest's comment and avatar.
//!
//! Content is stored in `userdata`'s blob store, one reference per `PutBlob`.
//! A registered account holds what it shows, and `userdata` releases what the
//! account replaces. A guest has no account to hold anything: its content is
//! held by its connection here, so this service releases what a guest
//! replaces, and all of it when the guest leaves. Before, nothing did, and
//! every avatar and comment a guest ever set stayed stored for good. A guest
//! who registers hands what it holds to the new account (`on_register`),
//! which `userdata` then releases like any other account content.
//!
//! Who holds a hash is decided by reading the connection and acting on it
//! across awaits, so every path that does (replace, reset, leave, register)
//! holds the connection's [`ContentGate`] from the read to the release.
//! Without it, an avatar replaced while a registration was in flight released
//! the hash the new account had just been handed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use starling_proto_fancy::userdata::BlobRef;
use starling_proto_fancy::userdata::user_data_client::UserDataClient;
use tokio::sync::OwnedMutexGuard;

use crate::SessionLifecycleService;

/// One lock per connection over who holds its content.
#[derive(Debug, Default)]
pub(crate) struct ContentGate {
    held: Mutex<HashMap<u64, Weak<tokio::sync::Mutex<()>>>>,
}

impl ContentGate {
    /// Wait until nothing else is deciding about `conn`'s content, and hold
    /// that until the guard drops. Other connections are not held up.
    pub(crate) async fn hold(&self, conn: u64) -> OwnedMutexGuard<()> {
        let lock = {
            // The map is valid whatever panicked while holding it.
            let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            held.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = held.get(&conn).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                let _ = held.insert(conn, Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}

impl SessionLifecycleService {
    /// Drop the reference this service took for each of `hashes`.
    pub(crate) async fn release_content(&self, hashes: &[&[u8]]) {
        let held: Vec<&[u8]> = hashes
            .iter()
            .copied()
            .filter(|hash| !hash.is_empty())
            .collect();
        if held.is_empty() {
            return;
        }
        let Ok(channel) = self.handshake.resolver().channel("userdata") else {
            tracing::warn!("userdata is unreachable; a guest's content stays stored");
            return;
        };
        let mut userdata = UserDataClient::new(channel);
        for hash in held {
            if let Err(status) = userdata
                .release_blob(BlobRef {
                    hash: hash.to_vec(),
                    size: 0,
                })
                .await
            {
                tracing::warn!(%status, "could not release a guest's content");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::ContentGate;

    #[tokio::test]
    async fn a_second_decision_about_one_connections_content_waits_for_the_first() {
        let gate = ContentGate::default();
        let first = gate.hold(7).await;
        let waiting = tokio::time::timeout(Duration::from_millis(50), gate.hold(7)).await;
        assert!(waiting.is_err(), "a replace during a hand-over must wait");
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(1), gate.hold(7)).await;
        assert!(second.is_ok(), "and goes ahead once the hand-over is done");
    }

    #[tokio::test]
    async fn other_connections_are_not_held_up_and_nothing_is_kept_after() {
        let gate = ContentGate::default();
        let held = gate.hold(7).await;
        let other = tokio::time::timeout(Duration::from_millis(50), gate.hold(8)).await;
        assert!(other.is_ok());
        drop((held, other));
        let _again = gate.hold(9).await;
        let kept = gate.held.lock().map(|held| held.len()).unwrap_or_default();
        assert_eq!(kept, 1, "a connection nobody holds is forgotten");
    }
}
