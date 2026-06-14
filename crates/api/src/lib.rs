//! `starling-api` — the feature contract.
//!
//! Everything a feature is allowed to see, do, and return. Traits and values
//! only: no state, no transport, no bus, no I/O.
//!
//! # Why this crate exists
//!
//! Before it, a feature crate had to depend on `starling-server` — the whole
//! state service — to reach the one trait it needed. It could then see
//! `ServerState`, `ServerCore`, `Listener` and everything else that crate
//! exports. Nothing stopped it reaching further than its contract.
//!
//! The dependency list above is the enforcement: this crate depends on domain
//! crates only, so a feature built against it **cannot** name a service, a
//! socket or the bus. `scripts/check-crate-layering.sh` asserts the edge stays
//! that way.
//!
//! # The contract
//!
//! | Direction | Item |
//! |---|---|
//! | a feature declares itself | [`Feature`], [`Handler`], [`Access`] |
//! | it reads state | [`Authority`] — [`Sessions`], [`World`], [`Settings`] |
//! | it describes changes | [`Effects`], [`Effect`], [`Recipients`] |
//! | it names a peer | [`ConnId`], [`Connection`] |
//!
//! A feature returns [`Effects`] and never performs one. That is what keeps it
//! testable without a socket, and what lets the writer decide the order.

/// Re-exported so [`register_feature!`](crate::register_feature) resolves without the feature crate
/// depending on `inventory` itself.
pub use inventory;

pub mod audio;
pub mod authority;
pub mod connection;
pub mod effects;
pub mod feature;
pub mod handler;
pub mod outbound;
pub mod voice;

pub use audio::{AudioSink, AudioSource, Datagrams, NoAudio, NoDatagrams};
pub use authority::{Authority, Sessions, Settings, World};
pub use connection::Connection;
pub use effects::{ConnId, Effect, Effects, Recipients};
pub use feature::{Feature, registered};
pub use handler::{Access, Handler};
pub use outbound::{FrameSink, NoOutbound, Outbound, Stuck};
pub use starling_config::{Limits, ServerConfig};
pub use voice::{
    AudienceView, NoVoice, Shout, VoiceKeying, VoiceLink, VoiceTargetSlot, VoiceUpdate,
};
