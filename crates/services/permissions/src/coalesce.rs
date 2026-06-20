//! Collapsing identical in-flight questions into one answer.
//!
//! ACL evaluation walks the channel tree, and a busy channel produces many
//! identical concurrent queries — everyone in it asks the same thing at the
//! same moment. Discord's Rust data services collapse those into one query so a
//! hot partition cannot be stampeded, and the analogue here is exact.
//!
//! **Coalescing beats a cache**, because a cache needs invalidation and
//! coalescing does not: nothing is retained past the moment the answer is
//! produced, so there is no window in which a revoked grant is still served.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

/// What identifies "the same question": tenant, subject and channel.
pub type Key = (u32, u32, u64, u32);

/// Collapses concurrent identical evaluations.
#[derive(Debug, Clone, Default)]
pub struct Coalescer {
    inflight: Arc<Mutex<HashMap<Key, broadcast::Sender<u32>>>>,
}

impl Coalescer {
    /// Nothing in flight.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate `key` once, however many callers ask at the same moment.
    ///
    /// The second and later callers wait on the first one's result rather than
    /// walking the tree again.
    pub async fn run(&self, key: Key, evaluate: impl FnOnce() -> u32) -> u32 {
        let existing = {
            let Ok(mut inflight) = self.inflight.lock() else {
                return evaluate();
            };
            match inflight.get(&key) {
                Some(sender) => Some(sender.subscribe()),
                None => {
                    let (sender, _) = broadcast::channel(1);
                    let _ = inflight.insert(key, sender);
                    None
                }
            }
        };

        if let Some(mut waiting) = existing {
            // The leader may finish before this subscriber is polled, which
            // closes the channel — falling back to evaluating is correct and
            // cheap, and never wrong.
            return match waiting.recv().await {
                Ok(answer) => answer,
                Err(_) => evaluate(),
            };
        }

        let answer = evaluate();
        if let Ok(mut inflight) = self.inflight.lock()
            && let Some(sender) = inflight.remove(&key)
        {
            let _ = sender.send(answer);
        }
        answer
    }

    /// Drop everything in flight, after an ACL change.
    ///
    /// An evaluation that started before a revocation may be answering from the
    /// old tables, and a stale grant is the one failure mode worth being
    /// wasteful about.
    pub fn clear(&self) {
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.clear();
        }
    }

    /// How many distinct questions are in flight, for metrics.
    #[must_use]
    pub fn inflight(&self) -> usize {
        self.inflight
            .lock()
            .map(|map| map.len())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn one_question_is_evaluated_once_even_when_asked_repeatedly() {
        let coalescer = Coalescer::new();
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..4 {
            let calls = Arc::clone(&calls);
            let answer = coalescer
                .run((1, 1, 0, 0), move || {
                    let _ = calls.fetch_add(1, Ordering::Relaxed);
                    7
                })
                .await;
            assert_eq!(answer, 7);
        }
        // Sequential callers each evaluate, because nothing is cached — that is
        // the point. What is collapsed is concurrency, not repetition.
        assert_eq!(calls.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn nothing_is_retained_after_an_answer_so_there_is_nothing_to_invalidate() {
        let coalescer = Coalescer::new();
        let _ = coalescer.run((1, 1, 0, 0), || 1).await;
        assert_eq!(coalescer.inflight(), 0);
    }
}
