//! What the authority tells the voice path.
//!
//! Two crates that must not depend on each other: the state service decides who
//! is in which channel and who may speak, and the voice service moves audio.
//! Neither belongs above the other, so the contract lives here and both depend
//! on it — the fifth SOLID letter, in three types.
//!
//! # Why this is plain data and not a `RoutingSnapshot`
//!
//! `starling-voice` owns a rich snapshot with indexes built for the packet path.
//! Naming it here would make this crate depend on the voice service, and every
//! handler transitively. [`AudienceView`] is the same information as flat lists;
//! the voice service builds its indexes from it, which is the only place that
//! knows what they should be indexed for.

use std::net::IpAddr;

use starling_crypto::VoiceSecrets;
use starling_gate::UdpFormat;
use starling_model::{ChannelId, SessionId};

use crate::effects::ConnId;
use crate::outbound::FrameSink;

/// Everything needed to give one peer a voice path.
///
/// Produced by the handler that finished the peer's authentication, because
/// that is where the key material is generated and put on the wire — carrying it
/// in the effect keeps it from having to be stored on the connection and fetched
/// back out later.
#[derive(Debug, Clone)]
pub struct VoiceKeying {
    /// The connection this belongs to.
    pub conn: ConnId,
    /// The session that will be named as the speaker.
    pub session: SessionId,
    /// Where the control connection came from, to narrow UDP attribution.
    pub host: IpAddr,
    /// The audio wire format this client negotiated.
    pub format: UdpFormat,
    /// The key material, shaped for whichever cipher this client earned.
    ///
    /// An enum rather than three byte arrays: OCB2 takes a 16-byte AES key and
    /// two IVs, `XChaCha20-Poly1305` a 32-byte master secret and two salts, and
    /// a flat carrier would let one cipher be handed the other's material.
    pub secrets: VoiceSecrets,
}

/// One registered whisper or shout slot.
///
/// The authority's own shape, without protobuf's `Option` wrappers. It lives
/// here rather than in `starling-voice` for the same reason [`AudienceView`]
/// does: both crates need to name it and neither may depend on the other.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VoiceTargetSlot {
    /// Sessions to whisper to.
    pub sessions: Vec<SessionId>,
    /// Channels to shout into, and how far each shout carries.
    pub shouts: Vec<Shout>,
}

impl VoiceTargetSlot {
    /// Whether this slot reaches nobody.
    ///
    /// A client clears a slot by registering an empty one, so this is a normal
    /// value rather than a malformed request.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.shouts.is_empty()
    }
}

/// A channel a slot shouts into.
///
/// No `Default`: `ChannelId` has none, and inventing one would make the root
/// channel the silent fallback for a malformed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shout {
    /// The channel itself.
    pub channel: ChannelId,
    /// Also everyone in channels linked to it.
    pub links: bool,
    /// Also everyone in its sub-channels.
    pub children: bool,
}

/// Who can hear whom, as flat lists.
///
/// Rebuilt and republished whenever membership, mute state or listeners change.
/// Whole-snapshot replacement rather than incremental updates: the packet path
/// reads this thousands of times a second and changes to it are rare, so the
/// cost belongs on the side that changes.
#[derive(Debug, Clone, Default)]
pub struct AudienceView {
    /// Every session and the channel it occupies.
    pub members: Vec<(SessionId, ChannelId)>,
    /// Sessions hearing a channel without being in it.
    pub listeners: Vec<(SessionId, ChannelId)>,
    /// Sessions that cannot receive: deafened, by themselves or a moderator.
    pub deaf: Vec<SessionId>,
    /// Sessions that cannot send: muted, self-muted or suppressed.
    pub silenced: Vec<SessionId>,
    /// Linked channel pairs, for shouts that carry across links.
    pub links: Vec<(ChannelId, ChannelId)>,
    /// Child-to-parent edges, for shouts that carry into sub-channels.
    pub parents: Vec<(ChannelId, ChannelId)>,
    /// Every session's registered whisper and shout slots.
    pub targets: Vec<(SessionId, u8, VoiceTargetSlot)>,
}

/// The voice path, as the authority sees it.
///
/// Every method is fire-and-forget: the authority is a single writer and must
/// never wait on another service, or the hold time that
/// `crates/kernel/bus/RESULTS.md` §3.3 measured would be back with an extra hop
/// in it.
pub trait VoiceLink: std::fmt::Debug + Send {
    /// Note a connection, so its tunnel path exists before it authenticates.
    ///
    /// Separate from [`Self::attach`] because the sink arrives at TLS handshake
    /// and the keys at authentication, and the voice service needs both.
    fn connected(&self, conn: ConnId, sink: Box<dyn FrameSink>);

    /// Give a peer a voice path.
    fn attach(&self, keying: Box<VoiceKeying>);

    /// Take a peer's voice path away.
    fn detach(&self, conn: ConnId);

    /// Replace the view of who hears whom.
    fn publish(&self, view: Box<AudienceView>);
}

/// Discards everything (Null Object).
///
/// A server assembled without a voice service. Every control path still works;
/// audio simply goes nowhere, which is what a server with no voice port should
/// do rather than refusing to start.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoVoice;

impl VoiceLink for NoVoice {
    fn connected(&self, _conn: ConnId, _sink: Box<dyn FrameSink>) {}
    fn attach(&self, _keying: Box<VoiceKeying>) {}
    fn detach(&self, _conn: ConnId) {}
    fn publish(&self, _view: Box<AudienceView>) {}
}

/// Something the voice path needs to be told about.
///
/// An effect rather than a direct call, so handlers stay pure and a test can
/// assert on what a handler decided without a voice service running.
#[derive(Debug, Clone)]
pub enum VoiceUpdate {
    /// This peer finished authenticating; here are its keys.
    Attach(Box<VoiceKeying>),

    /// Membership, mute state, listeners or targets changed.
    ///
    /// Carries nothing: the core rebuilds the view from the authority it already
    /// holds. A handler that had to assemble the whole view would need to walk
    /// every user on every mute toggle.
    Rebuild,
}
