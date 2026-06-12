//! The message-handler boundary.

use starling_proto::{ControlMessage, TcpMessageType};

use crate::authority::Authority;
use crate::effects::{ConnId, Effects};

/// Whether a message may be processed before the peer has authenticated.
///
/// Declared per handler and enforced centrally by the
/// `Dispatcher`, so a new handler cannot accidentally be
/// reachable pre-authentication. murmur guards this with a
/// `MSG_SETUP(ServerUser::Authenticated)` macro at the top of each handler —
/// one that is easy to omit, and invisible when omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Processed on any connection, authenticated or not.
    ///
    /// Only session establishment needs this. Anything else is a security bug.
    Anonymous,
    /// Processed only once the peer holds a session.
    Authenticated,
}

/// Handles one kind of control message.
///
/// # Contract
///
/// Implementations are **pure**: they mutate the [`Authority`] and return
/// [`Effects`], and must not perform I/O, block, or await. Everything a handler
/// wants to happen in the outside world is expressed as an effect and applied by
/// the core. This is what lets handler tests run without a socket, a runtime or
/// a database (`DESIGN.md` §4).
///
/// [`Self::handles`] must be a constant: the dispatcher indexes by it once, at
/// registration.
pub trait Handler: std::fmt::Debug + Send + Sync {
    /// The message type this handler is registered for.
    fn handles(&self) -> TcpMessageType;

    /// Whether the message is accepted before authentication.
    ///
    /// Defaults to [`Access::Authenticated`] — the safe answer, so a handler
    /// that forgets to think about it is not exposed to anonymous peers.
    fn access(&self) -> Access {
        Access::Authenticated
    }

    /// Process the message.
    ///
    /// `msg` is guaranteed to be the variant matching [`Self::handles`];
    /// handlers may treat any other variant as unreachable and return
    /// [`Effects::none`].
    fn handle(&self, state: &mut dyn Authority, conn: ConnId, msg: ControlMessage) -> Effects;
}
