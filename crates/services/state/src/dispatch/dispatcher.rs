//! The handler registry.

use std::collections::HashMap;

use starling_proto::{ControlMessage, TcpMessageType};
use tracing::{debug, warn};

use starling_api::Authority;
use starling_api::{Access, Handler};
use starling_api::{ConnId, Effects};

/// Routes control messages to registered [`Handler`]s.
///
/// Enforces the pre-authentication gate centrally (see [`Access`]) so it cannot
/// be forgotten in a handler, and reports unhandled message types once per
/// message rather than dropping them silently.
#[derive(Debug, Default)]
pub struct Dispatcher {
    handlers: HashMap<TcpMessageType, Box<dyn Handler>>,
}

impl Dispatcher {
    /// An empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler for its declared message type.
    ///
    /// Returns `self` so registration reads as a list at the composition root.
    /// Registering twice for the same type replaces the earlier handler; that is
    /// deliberate, so a test can substitute one, but it is logged because in
    /// production it means two handlers were written for one message.
    #[must_use]
    pub fn register(mut self, handler: Box<dyn Handler>) -> Self {
        let kind = handler.handles();
        if self.handlers.insert(kind, handler).is_some() {
            warn!(?kind, "handler replaced an earlier registration");
        }
        self
    }

    /// Route a message to its handler.
    pub fn dispatch(
        &self,
        state: &mut dyn Authority,
        conn: ConnId,
        msg: ControlMessage,
    ) -> Effects {
        let Some(kind) = TcpMessageType::from_id(msg.type_id()) else {
            debug!(
                %conn,
                type_id = msg.type_id(),
                "Fancy extension message carried opaquely and dropped (Phases 3-5)"
            );
            return Effects::none();
        };

        let Some(handler) = self.handlers.get(&kind) else {
            debug!(%conn, message = msg.name(), "no handler registered yet");
            return Effects::none();
        };

        if handler.access() == Access::Authenticated && !state.is_authenticated(conn) {
            warn!(
                %conn,
                message = msg.name(),
                "message received before authentication; ignoring"
            );
            return Effects::none();
        }

        handler.handle(state, conn, msg)
    }

    /// Whether a handler is registered for `kind`.
    #[must_use]
    pub fn handles(&self, kind: TcpMessageType) -> bool {
        self.handlers.contains_key(&kind)
    }

    /// How many handlers are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether no handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_api::Recipients;
    use starling_api::ServerConfig;
    use starling_api::Sessions;
    use starling_proto::proto::tcp;
    use std::net::SocketAddr;

    /// Records that it ran, so tests can assert on reachability.
    #[derive(Debug)]
    struct Spy {
        kind: TcpMessageType,
        access: Access,
    }

    impl Handler for Spy {
        fn handles(&self) -> TcpMessageType {
            self.kind
        }
        fn access(&self) -> Access {
            self.access
        }
        fn handle(&self, _: &mut dyn Authority, conn: ConnId, _: ControlMessage) -> Effects {
            let mut fx = Effects::none();
            let _ = fx.disconnect(conn, "spy ran");
            fx
        }
    }

    fn spy(kind: TcpMessageType, access: Access) -> Box<dyn Handler> {
        Box::new(Spy { kind, access })
    }

    fn state() -> crate::state::ServerState {
        let mut state = crate::state::ServerState::new(ServerConfig::default());
        let addr: SocketAddr = "127.0.0.1:1234".parse().expect("valid test address");
        state.add_connection(ConnId(1), addr);
        state
    }

    fn ran(fx: &Effects) -> bool {
        !fx.is_empty()
    }

    #[test]
    fn a_registered_handler_receives_its_message() {
        let dispatcher =
            Dispatcher::new().register(spy(TcpMessageType::Ping, Access::Authenticated));
        let mut state = state();
        let _ = state.assign_session(ConnId(1));

        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(1),
            ControlMessage::Ping(tcp::Ping::default()),
        );
        assert!(ran(&fx));
    }

    #[test]
    fn an_unregistered_message_type_is_dropped_without_panicking() {
        let dispatcher = Dispatcher::new();
        let mut state = state();
        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(1),
            ControlMessage::Ping(tcp::Ping::default()),
        );
        assert!(!ran(&fx));
    }

    #[test]
    fn an_opaque_fancy_message_is_dropped_without_panicking() {
        let dispatcher = Dispatcher::new();
        let mut state = state();
        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(1),
            ControlMessage::Opaque {
                type_id: 120,
                payload: bytes::Bytes::from_static(b"webrtc"),
            },
        );
        assert!(!ran(&fx));
    }

    #[test]
    fn authenticated_handlers_are_unreachable_before_authentication() {
        // The gate is central: the handler itself has no check at all.
        let dispatcher =
            Dispatcher::new().register(spy(TcpMessageType::TextMessage, Access::Authenticated));
        let mut state = state(); // connection added, no session assigned

        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(1),
            ControlMessage::TextMessage(tcp::TextMessage::default()),
        );
        assert!(!ran(&fx), "an unauthenticated peer reached a gated handler");
    }

    #[test]
    fn anonymous_handlers_are_reachable_before_authentication() {
        let dispatcher =
            Dispatcher::new().register(spy(TcpMessageType::Version, Access::Anonymous));
        let mut state = state();

        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(1),
            ControlMessage::Version(tcp::Version::default()),
        );
        assert!(ran(&fx));
    }

    #[test]
    fn access_defaults_to_authenticated_so_a_forgetful_handler_is_not_exposed() {
        #[derive(Debug)]
        struct Forgetful;
        impl Handler for Forgetful {
            fn handles(&self) -> TcpMessageType {
                TcpMessageType::TextMessage
            }
            // access() deliberately not overridden.
            fn handle(&self, _: &mut dyn Authority, conn: ConnId, _: ControlMessage) -> Effects {
                let mut fx = Effects::none();
                let _ = fx.disconnect(conn, "ran");
                fx
            }
        }

        let dispatcher = Dispatcher::new().register(Box::new(Forgetful));
        let mut state = state();
        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(1),
            ControlMessage::TextMessage(tcp::TextMessage::default()),
        );
        assert!(!ran(&fx));
    }

    #[test]
    fn a_message_from_an_unknown_connection_is_dropped() {
        let dispatcher =
            Dispatcher::new().register(spy(TcpMessageType::Ping, Access::Authenticated));
        let mut state = crate::state::ServerState::new(ServerConfig::default());
        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(999),
            ControlMessage::Ping(tcp::Ping::default()),
        );
        assert!(!ran(&fx));
    }

    #[test]
    fn registration_is_indexed_by_the_handlers_own_declared_type() {
        let dispatcher = Dispatcher::new()
            .register(spy(TcpMessageType::Ping, Access::Authenticated))
            .register(spy(TcpMessageType::TextMessage, Access::Authenticated));

        assert_eq!(dispatcher.len(), 2);
        assert!(dispatcher.handles(TcpMessageType::Ping));
        assert!(dispatcher.handles(TcpMessageType::TextMessage));
        assert!(!dispatcher.handles(TcpMessageType::Acl));
    }

    #[test]
    fn registering_twice_for_one_type_keeps_only_the_later_handler() {
        let dispatcher = Dispatcher::new()
            .register(spy(TcpMessageType::Ping, Access::Anonymous))
            .register(spy(TcpMessageType::Ping, Access::Anonymous));
        assert_eq!(dispatcher.len(), 1);
    }

    #[test]
    fn effects_from_a_handler_are_returned_unchanged() {
        #[derive(Debug)]
        struct Sends;
        impl Handler for Sends {
            fn handles(&self) -> TcpMessageType {
                TcpMessageType::Version
            }
            fn access(&self) -> Access {
                Access::Anonymous
            }
            fn handle(&self, _: &mut dyn Authority, conn: ConnId, _: ControlMessage) -> Effects {
                let mut fx = Effects::none();
                let _ = fx.send(
                    Recipients::Connection(conn),
                    ControlMessage::Ping(tcp::Ping::default()),
                );
                fx
            }
        }

        let dispatcher = Dispatcher::new().register(Box::new(Sends));
        let mut state = state();
        let fx = dispatcher.dispatch(
            &mut state,
            ConnId(1),
            ControlMessage::Version(tcp::Version::default()),
        );
        assert_eq!(fx.len(), 1);
    }
}
