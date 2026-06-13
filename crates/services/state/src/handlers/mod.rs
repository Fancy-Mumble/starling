//! Message handlers, and the registration that wires them up.
//!
//! Every handler implements [`Handler`](starling_api::Handler): it mutates
//! [`ServerState`](crate::ServerState) and returns
//! [`Effects`](crate::Effects), with no I/O and no `await`. Adding a message
//! type means writing a handler and adding one line to [`default_dispatcher`],
//! never editing a `match` (`DESIGN.md` §1, open/closed).

pub mod crypt_setup;
pub mod handshake;
pub mod ping;
pub mod serialize;
pub mod text_message;
pub mod user_state;
pub mod voice_target;

use crate::dispatch::Dispatcher;

/// The handlers this build implements.
///
/// Phases 1–5 extend this list. Message types with no entry are logged once and
/// dropped by the dispatcher, which is the correct behaviour for a staged port:
/// the stream stays in sync and the log says exactly what is missing.
#[must_use]
pub fn default_dispatcher() -> Dispatcher {
    Dispatcher::new()
        // Session establishment.
        .register(Box::new(handshake::VersionHandler))
        .register(Box::new(handshake::AuthenticateHandler))
        // Steady state.
        .register(Box::new(ping::PingHandler))
        .register(Box::new(crypt_setup::CryptSetupHandler))
        .register(Box::new(text_message::TextMessageHandler))
        .register(Box::new(user_state::UserStateHandler))
        .register(Box::new(voice_target::VoiceTargetHandler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_api::Access;
    use starling_proto::TcpMessageType;

    #[test]
    fn the_default_dispatcher_registers_every_phase_0_handler() {
        let dispatcher = default_dispatcher();
        for kind in [
            TcpMessageType::Version,
            TcpMessageType::Authenticate,
            TcpMessageType::Ping,
            TcpMessageType::TextMessage,
            TcpMessageType::UserState,
            TcpMessageType::CryptSetup,
            TcpMessageType::VoiceTarget,
        ] {
            assert!(dispatcher.handles(kind), "{kind:?} is not registered");
        }
    }

    #[test]
    fn only_the_handshake_handlers_are_reachable_anonymously() {
        // A regression here is a security bug, so it is asserted directly
        // rather than left to the dispatcher's own tests.
        let anonymous: Vec<_> = [
            (
                "Version",
                Box::new(handshake::VersionHandler) as Box<dyn starling_api::Handler>,
            ),
            ("Authenticate", Box::new(handshake::AuthenticateHandler)),
            ("Ping", Box::new(ping::PingHandler)),
            ("TextMessage", Box::new(text_message::TextMessageHandler)),
            ("UserState", Box::new(user_state::UserStateHandler)),
        ]
        .into_iter()
        .filter(|(_, h)| h.access() == Access::Anonymous)
        .map(|(name, _)| name)
        .collect();

        assert_eq!(anonymous, vec!["Version", "Authenticate"]);
    }

    #[test]
    fn every_handler_is_registered_under_the_type_it_declares() {
        // Counted from the handlers themselves rather than a literal: the
        // property under test is that no two collide, and a hardcoded number
        // tests that plus "somebody remembered to edit this test".
        let declared: Vec<_> = handlers().iter().map(|h| h.handles()).collect();
        let mut distinct = declared.clone();
        distinct.sort_by_key(|t| t.id());
        distinct.dedup_by_key(|t| t.id());

        assert_eq!(
            distinct.len(),
            declared.len(),
            "two handlers declare the same message type"
        );
        assert_eq!(
            default_dispatcher().len(),
            declared.len(),
            "a handler registered under the wrong type would collide and shrink this"
        );
    }

    /// Every handler the default dispatcher installs.
    fn handlers() -> Vec<Box<dyn starling_api::Handler>> {
        vec![
            Box::new(handshake::VersionHandler),
            Box::new(handshake::AuthenticateHandler),
            Box::new(ping::PingHandler),
            Box::new(crypt_setup::CryptSetupHandler),
            Box::new(text_message::TextMessageHandler),
            Box::new(user_state::UserStateHandler),
            Box::new(voice_target::VoiceTargetHandler),
        ]
    }
}
