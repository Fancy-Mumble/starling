//! What services say to the persistence port.
//!
//! The bus carries opaque bytes — *a bus that cannot parse cannot couple* — so
//! two endpoints that talk need an encoding they share and the bus does not
//! know. This is that encoding's shape; `postcard` turns it into bytes.
//!
//! # Why this is a message and not a method call
//!
//! Because it is I/O, and I/O in a reactor is a request and a completion, never
//! a wait. A caller posts a [`StoreRequest`] naming `Envelope::reply_to`, returns
//! to its loop, and is resumed when the matching [`StoreReply`] arrives. Nothing
//! holds a lane, nothing parks a thread, and the question of running the
//! database at the caller's priority never comes up.
//!
//! That is the whole reason this bus has no `call`.
//!
//! # Why the reads are coarse
//!
//! [`StoreRequest::LoadEverything`] fetches the world in one message rather than
//! offering a query per table. Persistence is read once at boot and written
//! incrementally afterwards, so a fine-grained read API would be surface nobody
//! uses — and each of those calls would be a round trip that the coarse one
//! makes in a single pass.
//!
//! Writes are the opposite: one message per change, each fire-and-forget,
//! because a change has already happened by the time it is worth persisting and
//! nothing is waiting to hear that it landed.

use serde::{Deserialize, Serialize};

use crate::store::{StoredBan, StoredChannel, StoredListener, StoredUser};

/// Something a service asks the persistence port to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoreRequest {
    /// Read the durable world, once, at boot.
    ///
    /// Expects a [`StoreReply::Everything`] at the envelope's `reply_to`.
    LoadEverything,

    /// Create or replace a channel.
    SaveChannel(StoredChannel),

    /// Remove a channel, and by cascade everything hanging off it.
    RemoveChannel(u32),

    /// Link two channels, in either order.
    LinkChannels(u32, u32),

    /// Unlink two channels, in either order.
    UnlinkChannels(u32, u32),

    /// Create or replace an account.
    SaveUser(StoredUser),

    /// Remove an account and everything keyed to it.
    RemoveUser(u32),

    /// Set one of an account's properties.
    SetUserProperty {
        /// Which account.
        user: u32,
        /// Property name.
        key: String,
        /// Property value.
        value: String,
    },

    /// Record that a user listens to a channel.
    AddListener(StoredListener),

    /// Stop a user listening to a channel.
    RemoveListener {
        /// Which account.
        user: u32,
        /// Which channel.
        channel: u32,
    },

    /// Replace the whole ban list.
    ReplaceBans(Vec<StoredBan>),

    /// Set one configuration value.
    SetConfig {
        /// Setting name.
        key: String,
        /// Setting value.
        value: String,
    },

    /// Append one line to the persisted server log.
    AppendLog {
        /// Seconds since the Unix epoch.
        at: i64,
        /// What happened.
        message: String,
    },
}

/// What the persistence port says back.
///
/// Only requests that asked for something produce one. A write that fails is
/// reported as [`Self::Failed`] rather than silently dropped — the caller cannot
/// undo it, but an operator needs to know the database is refusing writes before
/// the disk fills or the connection drops for good.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoreReply {
    /// The durable world, as of the moment it was read.
    Everything(Box<StoredWorld>),

    /// An operation failed. Carries the message, not the error type: the
    /// recipient logs it and has no branch that depends on which kind it was.
    Failed(String),
}

/// Everything persistence holds, in one reply.
///
/// Boxed inside [`StoreReply`] because it is far larger than the other variant
/// and every envelope would otherwise be sized for it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredWorld {
    /// Every channel, in no particular order; the reader rebuilds the tree.
    pub channels: Vec<StoredChannel>,
    /// Linked channel pairs, lower id first.
    pub links: Vec<(u32, u32)>,
    /// Every registered account.
    pub users: Vec<StoredUser>,
    /// Every stored channel listener.
    pub listeners: Vec<StoredListener>,
    /// Every ban, including lapsed ones.
    pub bans: Vec<StoredBan>,
    /// Every configuration value set in the database.
    pub config: Vec<(String, String)>,
}

impl StoredWorld {
    /// Whether this is a database that has never been written to.
    ///
    /// Distinct from a failed read, which is a [`StoreReply::Failed`]. A fresh
    /// database is the normal first boot and the caller seeds it; a failed read
    /// means the caller must not seed anything, because doing so over data it
    /// could not see would destroy it.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.channels.is_empty() && self.users.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_survives_the_wire() {
        // The bus carries bytes, so every message crosses an encoder. A type
        // that does not round-trip is a message that arrives as something else.
        let request = StoreRequest::SetConfig {
            key: "welcometext".into(),
            value: "hello".into(),
        };
        let bytes = postcard::to_allocvec(&request).expect("encode");
        let back: StoreRequest = postcard::from_bytes(&bytes).expect("decode");
        assert!(matches!(back, StoreRequest::SetConfig { .. }));
    }

    #[test]
    fn a_world_survives_the_wire() {
        let world = StoredWorld {
            config: vec![("port".into(), "64738".into())],
            ..StoredWorld::default()
        };
        let bytes = postcard::to_allocvec(&StoreReply::Everything(Box::new(world)))
            .expect("encode");
        let back: StoreReply = postcard::from_bytes(&bytes).expect("decode");
        match back {
            StoreReply::Everything(world) => assert_eq!(world.config.len(), 1),
            other => panic!("expected a world, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_world_is_fresh_and_a_populated_one_is_not() {
        // The distinction that decides whether the caller seeds a root channel.
        assert!(StoredWorld::default().is_fresh());

        let populated = StoredWorld {
            channels: vec![StoredChannel::new(starling_model::ChannelId(0), None, "Root")],
            ..StoredWorld::default()
        };
        assert!(!populated.is_fresh());
    }
}
