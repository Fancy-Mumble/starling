//! `session-lifecycle` — a connection's existence.
//!
//! Negotiate the version, authenticate, hand over `CryptSetup`, answer `Ping`,
//! notice a timeout, tear down. It is a state machine per connection, and it is
//! **the only half of session a client ever talks to** — `session-view` owns
//! the composed read model and has no client-facing type at all
//! (`docs/ARCHITECTURE.md` §4).
//!
//! Splitting them matters because they change for different reasons: this one
//! changes when the handshake changes, the other when a service needs a new
//! fact.
//!
//! The handshake order is murmur's, transcribed with line references in
//! [`handshake`]. Getting it wrong produces a client that connects in
//! development and hangs in the wild (`PORTING-PLAN.md` R4).

pub mod ids;
pub mod session;

pub mod handshake;
pub mod state;

pub use handshake::Handshake;
pub use ids::SessionId;
pub use session::{SessionAllocator, SessionSource};
pub use state::{Connections, PendingConnection};

// The async test harness, and nothing else in this crate, needs tokio.
#[cfg(test)]
use tokio as _;

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_proto_fancy::control::{Opened, ServerAction, server_action};

/// Upstream types this service answers for.
const VERSION: u16 = 0;
/// Upstream `Authenticate`.
const AUTHENTICATE: u16 = 2;
/// Upstream `Ping`.
const PING: u16 = 3;
/// Upstream `UserState`, which carries self-mute and self-deafen.
const USER_STATE: u16 = 9;

/// The service.
#[derive(Debug)]
pub struct SessionLifecycleService {
    connections: Connections,
    handshake: Handshake,
    fanout: Fanout,
}

impl SessionLifecycleService {
    /// The connections in flight, for tests and the operator surface.
    #[must_use]
    pub fn connections(&self) -> &Connections {
        &self.connections
    }
}

#[async_trait]
impl ClientService for SessionLifecycleService {
    async fn opened(&self, opened: &Opened, gateway: &str) -> Actions {
        self.connections.opened(opened, gateway);
        vec![to_conn(
            opened.conn,
            VERSION,
            handshake::server_version().encode_to_vec(),
        )]
    }

    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            VERSION => self.on_version(&inbound),
            AUTHENTICATE => self.handshake.authenticate(&self.connections, &inbound).await,
            PING => self.on_ping(&inbound),
            USER_STATE => self.on_user_state(&inbound).await,
            id if id == ServiceKind::SessionLifecycle.outer_type() => {
                self.handshake.fancy(&self.connections, &inbound).await
            }
            _ => Actions::new(),
        }
    }

    async fn closed(&self, conn: u64, reason: &str) -> Actions {
        let Some(session) = self.connections.close(conn) else {
            return Actions::new();
        };
        self.handshake.announce_down(session, reason).await;

        // Everyone else is told, because a client that never hears a
        // `UserRemove` renders a ghost for the rest of its connection.
        let removal = tcp::UserRemove {
            session,
            reason: Some(reason.to_owned()),
            ..tcp::UserRemove::default()
        };
        vec![
            to_sessions(Vec::new(), 8, removal.encode_to_vec()),
            ServerAction {
                action: Some(server_action::Action::SessionDown(
                    starling_proto_fancy::control::SessionDown { conn, session },
                )),
            },
        ]
    }
}

impl SessionLifecycleService {
    /// The client's `Version`.
    ///
    /// Starling already sent its own `Version` first, on TLS establishment
    /// (`opened`, matching `Server.cpp:1668`), so the client's copy is recorded
    /// rather than answered — the next thing the client sends is `Authenticate`,
    /// and answering twice confuses a stock client.
    fn on_version(&self, inbound: &Inbound) -> Actions {
        let Ok(version) = tcp::Version::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        self.connections.record_version(inbound.conn, &version);
        Actions::new()
    }

    /// `Ping` is echoed with the counters murmur reports.
    ///
    /// The timestamp is echoed verbatim: the client measures the round trip
    /// from it, and rewriting it makes every client's latency graph wrong.
    fn on_ping(&self, inbound: &Inbound) -> Actions {
        let Ok(ping) = tcp::Ping::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        self.connections.touch(inbound.conn);
        let reply = tcp::Ping {
            timestamp: ping.timestamp,
            good: Some(0),
            late: Some(0),
            lost: Some(0),
            resync: Some(0),
            ..tcp::Ping::default()
        };
        vec![to_conn(inbound.conn, PING, reply.encode_to_vec())]
    }

    /// Self-mute and self-deafen, which are the only `UserState` fields a
    /// client may set on itself without a permission check.
    async fn on_user_state(&self, inbound: &Inbound) -> Actions {
        let Ok(state) = tcp::UserState::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        if state.session.is_some_and(|session| session != inbound.session) {
            // Muting somebody else is a moderation action and takes a
            // permission check this service does not perform.
            return Actions::new();
        }
        let updated = self
            .connections
            .set_self_flags(inbound.conn, state.self_mute, state.self_deaf);
        let Some(session) = updated else {
            return Actions::new();
        };
        self.handshake.announce_changed(&self.connections, inbound.conn).await;

        let echo = tcp::UserState {
            session: Some(session),
            self_mute: state.self_mute,
            self_deaf: state.self_deaf,
            ..tcp::UserState::default()
        };
        vec![to_sessions(Vec::new(), USER_STATE, echo.encode_to_vec())]
    }
}

#[async_trait]
impl Serve for SessionLifecycleService {
    const NAME: &'static str = "session-lifecycle";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let fanout = Fanout::default();
        Ok(Arc::new(Self {
            connections: Connections::new(max_users(&ctx)),
            handshake: Handshake::new(Resolver::clone(&ctx.resolver), fanout.clone(), ctx.clone()),
            fanout,
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
        tonic::service::Routes::default().add_service(plane)
    }
}

/// How many session ids to mint, from the deployment's own limit.
fn max_users(ctx: &ServiceContext) -> u32 {
    ctx.service().option::<u32>("max_users").unwrap_or(100)
}
