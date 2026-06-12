//! What a handler is allowed to do.
//!
//! Handlers used to receive `&mut ServerState` — the concrete struct, with all
//! 23 of its public methods. `DESIGN.md` §2 says to pass the trait, so these are
//! those traits.
//!
//! # Three roles, not one interface
//!
//! [`Authority`] is deliberately *empty*: it is the sum of three role traits,
//! each with one reason to change.
//!
//! | Trait | Reason to change |
//! |---|---|
//! | [`Sessions`] | how a connection acquires and holds an identity |
//! | [`World`] | the domain model — channels, users, permissions |
//! | [`Settings`] | what is configurable |
//!
//! A handler that only reads the world (`Ping`) is written against [`World`] and
//! cannot touch session assignment. A test double for one role does not have to
//! implement the other two. Splitting this way keeps every trait small enough to
//! substitute — and `&mut dyn Authority` still works, because a supertrait of
//! object-safe traits is object-safe.
//!
//! # Not the same as `StateQuery`
//!
//! `StateQuery` (`docs/ARCHITECTURE.md` §6.1) is the *feature* view: it crosses
//! the bus, so every method returns an owned value. These are the in-process
//! view — a handler runs on the writer's own thread, so borrows are fine and no
//! copy is needed. Two views of the same state, for callers on opposite sides of
//! the bus.

use starling_crypto::{ProfileError, SecuritySuite, VoiceProfile};
use starling_model::{ChannelStore, Permissions, SessionId, UserRegistry};

use crate::connection::Connection;
use crate::effects::ConnId;
use crate::voice::VoiceTargetSlot;
use starling_config::Limits;

/// Connection identity and lifecycle.
///
/// Everything about *who is on the other end* and whether they have earned a
/// session yet. Deliberately excludes `add_connection` and `remove_connection`:
/// a connection appearing or vanishing is the transport's news to deliver, not a
/// handler's to invent.
pub trait Sessions {
    /// One connection's record.
    fn connection(&self, id: ConnId) -> Option<&Connection>;

    /// One connection's record, mutably.
    fn connection_mut(&mut self, id: ConnId) -> Option<&mut Connection>;

    /// Whether the connection has completed authentication.
    fn is_authenticated(&self, id: ConnId) -> bool;

    /// The session a connection holds, if it has been assigned one.
    fn session_of(&self, id: ConnId) -> Option<SessionId>;

    /// Take a session id for a connection, or `None` when the pool is empty.
    fn assign_session(&mut self, conn: ConnId) -> Option<SessionId>;

    /// Whether the server has reached `max_users`.
    fn is_full(&self) -> bool;

    /// The negotiated security suite for a connection, if it has one.
    fn suite_for(&self, conn: ConnId) -> Option<Box<dyn SecuritySuite>>;

    /// The voice profile this peer's client version earns.
    ///
    /// One call, not a chain of version tests at the call site: the profile
    /// factory is the single place that maps what a peer announced onto the
    /// framing and cipher it gets, and it already knows the rules a handler
    /// would otherwise re-derive — a legacy-framed peer is downgraded to OCB2
    /// however new its Fancy version claims to be, because the legacy packet
    /// type *is* the codec and has nowhere to name a cipher.
    ///
    /// `None` for an unknown connection, `Err` when the configured factory
    /// refuses to serve this client at all.
    fn voice_profile(&self, conn: ConnId) -> Option<Result<VoiceProfile, ProfileError>>;

    /// Register a session's whisper or shout slot.
    ///
    /// Returns `false` for a reserved slot (0 and 31) or one the session may not
    /// have. The targets are protobuf as they arrived, because unwrapping them
    /// is the state layer's job and doing it here would put the wire format in
    /// the trait.
    fn set_voice_target(
        &mut self,
        session: SessionId,
        slot: u8,
        targets: &[starling_proto::proto::tcp::voice_target::Target],
    ) -> bool;

    /// What a session registered in a slot, if anything.
    fn voice_target(&self, session: SessionId, slot: u8) -> Option<&VoiceTargetSlot>;

    /// Every registered target, for building the routing view.
    fn voice_targets(&self) -> Vec<(SessionId, u8, &VoiceTargetSlot)>;
}

/// The domain model, as a handler may see it.
///
/// Each accessor hands out a `dyn` from `starling-model`, so a handler depends on
/// the domain trait and never on which implementation is installed — in-memory
/// today, SQL-backed in Phase 2, with no handler change.
pub trait World {
    /// The channel tree.
    fn channels(&self) -> &dyn ChannelStore;

    /// The connected users.
    fn users(&self) -> &dyn UserRegistry;

    /// The connected users, mutably.
    fn users_mut(&mut self) -> &mut dyn UserRegistry;

    /// The permission evaluator.
    ///
    /// Handed out rather than wrapped, so exactly one implementation answers
    /// permission questions. In-process only — the bus-facing `StateQuery`
    /// cannot do this, because a `&dyn` does not fit in an envelope.
    fn permissions(&self) -> &dyn Permissions;
}

/// Read access to what a client is told, and to the password as a predicate.
pub trait Settings {
    /// The settings a connected client is told anyway.
    ///
    /// Handed over whole rather than as one getter per field — handlers read
    /// seven of them, and seven near-identical accessors is the repetition this
    /// project treats as a smell. Safe to hand over because every field is sent
    /// to clients during the handshake, so a caller learns nothing new.
    ///
    /// This used to be the whole `ServerConfig`, which included
    /// `server_password`. No feature ever read configuration, and none needed the
    /// secret; the split follows the line the protocol already draws
    /// (`starling-config`).
    fn limits(&self) -> &Limits;

    /// Whether `candidate` is the configured server password.
    ///
    /// A predicate, not an accessor: the caller learns whether it guessed right,
    /// never what right is. `Authenticate` is the only handler that needs this,
    /// and it needs exactly this much.
    fn password_accepted(&self, candidate: &str) -> bool;
}

/// The authoritative state, as a handler may see it.
///
/// # Contract
///
/// Implementations mutate state and nothing else. No method reachable from here
/// may perform I/O, block, or do unbounded work: the single writer holds the only
/// mutable copy, so anything slow behind one of these calls delays every other
/// request (`crates/kernel/bus/RESULTS.md` §3.3 measures exactly this).
pub trait Authority: Sessions + World + Settings {}

/// Blanket implementation: anything with all three roles *is* an `Authority`.
///
/// So a new implementation — a test double, a sharded store — satisfies the
/// handler boundary by implementing the three roles, and never mentions
/// `Authority` itself.
impl<T> Authority for T where T: Sessions + World + Settings {}
