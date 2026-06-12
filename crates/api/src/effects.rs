//! What a handler wants to happen, expressed as data.
//!
//! Handlers never touch a socket. They return [`Effects`], and `ServerCore`
//! applies them. That is what makes every handler testable without a runtime:
//! a test calls the handler and asserts on the returned effects.
//!

use starling_log::LogEvent;
use starling_model::{ChannelId, SessionId};
use starling_proto::ControlMessage;

/// Internal, never-on-the-wire id for a TCP connection.
///
/// A connection exists (and must be addressable, e.g. to send `Version` or
/// `Reject`) *before* it has a [`SessionId`]. murmur conflates the two on one
/// `ServerUser` object guarded by an `sState` enum; separating them makes the
/// pre-authentication window explicit and impossible to forget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(pub u64);

impl std::fmt::Display for ConnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Who an outbound message goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipients {
    /// One connection, which may not be authenticated yet.
    Connection(ConnId),
    /// One authenticated session.
    Session(SessionId),
    /// Every authenticated session.
    All,
    /// Every authenticated session except one — the usual shape for fan-out
    /// where the originator already applied the change locally.
    AllExcept(SessionId),
    /// Every session in a channel.
    Channel(ChannelId),
    /// Every session in a channel except one.
    ChannelExcept(ChannelId, SessionId),
}

/// A single thing the core should do.
#[derive(Debug, Clone)]
pub enum Effect {
    /// Send a control message.
    Send {
        /// Who receives it.
        to: Recipients,
        /// What to send.
        msg: Box<ControlMessage>,
    },
    /// Close a connection after flushing whatever is already queued.
    ///
    /// Used for `Reject`: murmur sends the rejection and *then* disconnects, so
    /// the client can show a reason instead of a bare connection reset.
    Disconnect {
        /// The connection to close.
        conn: ConnId,
        /// Human-readable reason, for logs.
        reason: String,
    },
    /// Record an operator-facing event in the server log.
    ///
    /// An effect rather than a direct call so handlers stay pure — and so a
    /// test can assert on what was logged without installing a sink.
    Log(Box<LogEvent>),

    /// Tell the voice path something changed.
    ///
    /// An effect for the same reason as [`Self::Log`]: a handler that reached
    /// the voice service directly could not be tested without one running.
    Voice(crate::voice::VoiceUpdate),
}

/// An ordered list of effects.
///
/// Order is significant. The session-establishment sequence in particular is a
/// protocol contract, not a preference: the client resolves channel parents on
/// arrival and needs its own session id before it can process listeners
/// (`Messages.cpp:775`).
#[derive(Debug, Clone, Default)]
pub struct Effects(Vec<Effect>);

impl Effects {
    /// No effects.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Tell the voice path something changed.
    ///
    /// Returns the count so it composes with the other builders, which return
    /// it for the same reason: `#[must_use]` on `Effects` would otherwise fire
    /// on every line that adds one.
    pub fn voice(&mut self, update: crate::voice::VoiceUpdate) -> usize {
        self.0.push(Effect::Voice(update));
        self.0.len()
    }

    /// Queue a message.
    pub fn send(&mut self, to: Recipients, msg: ControlMessage) -> &mut Self {
        self.0.push(Effect::Send {
            to,
            msg: Box::new(msg),
        });
        self
    }

    /// Queue a disconnect.
    pub fn disconnect(&mut self, conn: ConnId, reason: impl Into<String>) -> &mut Self {
        self.0.push(Effect::Disconnect {
            conn,
            reason: reason.into(),
        });
        self
    }

    /// Queue a server-log record.
    pub fn log(&mut self, event: LogEvent) -> &mut Self {
        self.0.push(Effect::Log(Box::new(event)));
        self
    }

    /// The log records queued so far, so tests can assert on them.
    #[must_use]
    pub fn logged(&self) -> Vec<&LogEvent> {
        self.0
            .iter()
            .filter_map(|e| match e {
                Effect::Log(event) => Some(event.as_ref()),
                _ => None,
            })
            .collect()
    }

    /// Append another effect list, preserving order.
    pub fn extend(&mut self, other: Self) -> &mut Self {
        self.0.extend(other.0);
        self
    }

    /// The effects, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Effect] {
        &self.0
    }

    /// Whether anything is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many effects are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl IntoIterator for Effects {
    type Item = Effect;
    type IntoIter = std::vec::IntoIter<Effect>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto::proto::tcp;

    #[test]
    fn effects_preserve_insertion_order() {
        let mut fx = Effects::none();
        let _ = fx.send(
            Recipients::Connection(ConnId(1)),
            ControlMessage::Version(tcp::Version::default()),
        );
        let _ = fx.send(
            Recipients::All,
            ControlMessage::ServerSync(tcp::ServerSync::default()),
        );
        let _ = fx.disconnect(ConnId(1), "bye");

        let names: Vec<_> = fx
            .as_slice()
            .iter()
            .map(|e| match e {
                Effect::Send { msg, .. } => msg.name(),
                Effect::Disconnect { .. } => "Disconnect",
                Effect::Log(_) => "Log",
                Effect::Voice(_) => "Voice",
            })
            .collect();
        assert_eq!(names, vec!["Version", "ServerSync", "Disconnect"]);
    }

    #[test]
    fn extend_appends_rather_than_interleaving() {
        let mut first = Effects::none();
        let _ = first.send(
            Recipients::All,
            ControlMessage::Ping(tcp::Ping {
                timestamp: Some(1),
                ..Default::default()
            }),
        );

        let mut second = Effects::none();
        let _ = second.send(
            Recipients::All,
            ControlMessage::Ping(tcp::Ping {
                timestamp: Some(2),
                ..Default::default()
            }),
        );

        let _ = first.extend(second);
        assert_eq!(first.len(), 2);
        let timestamps: Vec<_> = first
            .as_slice()
            .iter()
            .filter_map(|e| match e {
                Effect::Send { msg, .. } => match msg.as_ref() {
                    ControlMessage::Ping(p) => p.timestamp,
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(timestamps, vec![1, 2]);
    }

    #[test]
    fn a_fresh_effects_list_is_empty() {
        assert!(Effects::none().is_empty());
    }
}
