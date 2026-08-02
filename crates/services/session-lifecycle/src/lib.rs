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
pub use state::{Connections, PendingConnection, ReportedStats};

use std::collections::HashMap;
use std::sync::Arc;

use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::control::{Opened, ServerAction, server_action};
use starling_proto_fancy::identity;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent};
use starling_runtime::permit::{Permit, permission_denied, refused as refused_with};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, disconnect, to_conn, to_sessions,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// Upstream types this service answers for.
const VERSION: u16 = 0;
/// Upstream `Authenticate`.
const AUTHENTICATE: u16 = 2;
/// Upstream `Ping`.
const PING: u16 = 3;
/// Upstream `UserState`, which carries self-mute and self-deafen.
const USER_STATE: u16 = 9;
/// Upstream `CryptSetup`, sent again mid-session to resynchronise the UDP nonce.
const CRYPT_SETUP: u16 = 15;
/// Upstream `UserStats`, behind a client's right-click → Information.
const USER_STATS: u16 = 22;
/// Upstream `CodecVersion`, which is where a client says whether it has Opus.
const CODEC_VERSION: u16 = 21;

/// Upstream `PermissionDenied`.
const PERMISSION_DENIED: u16 = 12;

/// The root channel, which is always id 0.
const ROOT_CHANNEL: u32 = 0;

/// `ChanACL::Ban` (`vendor/server/src/ACL.h:21`).
///
/// Written out rather than taken from `starling-permissions`, because a service
/// depending on another service's crate is exactly the coupling the gRPC
/// boundary exists to prevent. The permission *set* is protocol, not
/// implementation: it is the same 24-bit layout every Mumble client knows.
const BAN: u32 = 0x0002_0000;

/// The service.
#[derive(Debug)]
pub struct SessionLifecycleService {
    connections: Connections,
    handshake: Handshake,
    fanout: Fanout,
    /// Asks `permissions` before a client is moved into a channel.
    permit: Permit,
}

impl SessionLifecycleService {
    /// The connections in flight, for tests and the operator surface.
    #[must_use]
    pub fn connections(&self) -> &Connections {
        &self.connections
    }
}

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
        // Anything at all counts as being alive, not just `Ping`. A client that
        // is talking is plainly still there, and reaping it because its pings
        // happened to be the frames that were lost would be a self-inflicted
        // disconnect.
        self.connections.touch(inbound.conn);
        match inbound.type_id {
            VERSION => self.on_version(&inbound),
            AUTHENTICATE => {
                self.handshake
                    .authenticate(&self.connections, &inbound)
                    .await
            }
            PING => self.on_ping(&inbound),
            USER_STATS => self.on_user_stats(&inbound).await,
            // `CodecVersion` travels server→client only. A client never sends
            // one, so there is nothing to handle — reading Opus support from it
            // meant waiting for a message that never comes and reporting every
            // client as having no Opus. It is announced in `Authenticate`
            // instead, and read there.
            CODEC_VERSION => Actions::new(),
            CRYPT_SETUP => self.on_crypt_setup(&inbound).await,
            USER_STATE => self.on_user_state(&inbound).await,
            id if id == ServiceKind::SessionLifecycle.outer_type() => {
                self.handshake.fancy(&self.connections, &inbound)
            }
            _ => Actions::new(),
        }
    }

    async fn closed(&self, conn: u64, reason: &str) -> Actions {
        // Asked before the close, which is what drops the entry the name lives
        // in — afterwards there is only a session number to report.
        let name = self
            .connections
            .get(conn)
            .map(|pending| pending.name)
            .unwrap_or_default();
        let Some(session) = self.connections.close(conn) else {
            // No session means the connection never finished the handshake, so
            // nobody ever "left"; the gateway already recorded the disconnect.
            return Actions::new();
        };

        self.handshake.context().logger.log(
            LogEvent::info(Category::Session, "user left")
                .with("conn", conn)
                .with("session", session)
                .with("name", name)
                .with("reason", reason.to_owned()),
        );
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
            tracing::debug!(conn = inbound.conn, "undecodable Version");
            return Actions::new();
        };
        // What the client actually is answers most "it works for me" reports,
        // and this is the only moment the server is told.
        tracing::debug!(
            conn = inbound.conn,
            release = version.release.as_deref().unwrap_or("unknown"),
            os = version.os.as_deref().unwrap_or("unknown"),
            "client version"
        );
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

        // Everything the Information window shows under "Ping Statistics" and
        // the "To Client" row arrives here, measured by the client
        // (`Messages.cpp:2918`). The server stores the latest set so it can
        // repeat them to whoever asks about this user — including the user
        // themselves. Without this the whole panel reads zero, which looks like
        // a dead link rather than an unreported one.
        self.connections.record_reported(
            inbound.conn,
            ReportedStats {
                good: ping.good.unwrap_or_default(),
                late: ping.late.unwrap_or_default(),
                lost: ping.lost.unwrap_or_default(),
                resync: ping.resync.unwrap_or_default(),
                udp_packets: ping.udp_packets.unwrap_or_default(),
                tcp_packets: ping.tcp_packets.unwrap_or_default(),
                udp_ping_avg: ping.udp_ping_avg.unwrap_or_default(),
                udp_ping_var: ping.udp_ping_var.unwrap_or_default(),
                tcp_ping_avg: ping.tcp_ping_avg.unwrap_or_default(),
                tcp_ping_var: ping.tcp_ping_var.unwrap_or_default(),
            },
        );
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

    /// `CryptSetup` arriving *from* a client: a request to resynchronise.
    ///
    /// The same wire type the handshake sends outbound, and the direction is the
    /// whole difference. Outbound it is the key material; inbound it means the
    /// peer's UDP nonce has drifted far enough that nothing decrypts, and it is
    /// how a client recovers without reconnecting.
    ///
    /// # What silence here costs
    ///
    /// Everything, for the rest of the session. A Mumble client asks once every
    /// five seconds while its audio is failing (`ServerHandler::message`), and it
    /// has no other recovery: it does not reconnect, it does not fall back to the
    /// tunnel, it simply keeps sending frames nobody can open and receiving
    /// frames it cannot open. Both counters look healthy at both ends. This arm
    /// costs one round trip and turns that into a two-second interruption.
    ///
    /// # Why it goes to voice
    ///
    /// The nonce belongs to the cipher, and the cipher lives on the packet path
    /// — this service has never held one, and key material does not cross a
    /// service boundary in a form anything else could read
    /// (`docs/ARCHITECTURE.md` §4). What comes back is a ready-made payload, or
    /// nothing when the peer handed over its own nonce and murmur would send no
    /// reply.
    async fn on_crypt_setup(&self, inbound: &Inbound) -> Actions {
        use starling_proto_fancy::voice::ResyncRequest;
        use starling_proto_fancy::voice::voice_client::VoiceClient;

        let Ok(request) = tcp::CryptSetup::decode(inbound.payload.as_slice()) else {
            tracing::debug!(conn = inbound.conn, "undecodable CryptSetup");
            return Actions::new();
        };

        let Ok(channel) = self.handshake.resolver().channel("voice") else {
            // Nothing to say. A refusal would be worse than silence here: the
            // client is not being denied anything, and there is no `CryptSetup`
            // that means "ask again later".
            tracing::warn!(
                session = inbound.session,
                "voice is unreachable; a peer's crypt resync goes unanswered"
            );
            return Actions::new();
        };

        let answer = VoiceClient::new(channel)
            .resync(ResyncRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: inbound.scope,
                }),
                session: inbound.session,
                // Forwarded as it arrived, absence and all: whether this field is
                // present is the entire request. Defaulting it to empty bytes
                // would turn every "tell me yours" into "adopt this", and the
                // peer would be answered with silence instead of a nonce.
                client_nonce: request.client_nonce,
            })
            .await;

        let payload = match answer {
            Ok(material) => material.into_inner().crypt_setup,
            Err(status) => {
                tracing::warn!(
                    session = inbound.session,
                    %status,
                    "voice refused a crypt resync"
                );
                return Actions::new();
            }
        };

        // Empty is a decision, not a failure: the peer offered its own nonce,
        // voice adopted it, and murmur sends nothing back for that case.
        if payload.is_empty() {
            return Actions::new();
        }
        vec![to_conn(inbound.conn, CRYPT_SETUP, payload)]
    }

    /// `UserStats`: what a client shows under right-click → Information.
    ///
    /// This request used to be routed to `userdata`, which had no arm for it
    /// and returned no actions — so the window never opened and nothing was
    /// logged, because dropping an unhandled frame is normal and silent. The
    /// data it wants is connection state, which is this service's.
    ///
    /// # What the client does with this
    ///
    /// The dialog is mostly two group boxes, and **each is hidden unless the
    /// reply carries the fields that fill it** (`UserInformation.cpp:154`):
    ///
    /// * *Connection* — shown only if `certificates`, `address` or `version` is
    ///   present. These are murmur's `details`.
    /// * *UDP statistics* — shown only if `from_client` **and** `from_server`
    ///   are present. These are murmur's `local`.
    ///
    /// Omit both and the window opens empty, which is what an earlier version
    /// of this did for everyone but the user asking about themselves: correct
    /// data, no visible dialog. So the gates below are murmur's, not a
    /// simplification of them.
    async fn on_user_stats(&self, inbound: &Inbound) -> Actions {
        let Ok(request) = tcp::UserStats::decode(inbound.payload.as_slice()) else {
            tracing::debug!(conn = inbound.conn, "undecodable UserStats");
            return Actions::new();
        };

        // No session named means "tell me about myself", which is how a client
        // asks for its own connection information.
        let wanted = request.session.unwrap_or(inbound.session);
        let Some(target) = self.connections.by_session(wanted) else {
            // Asking about somebody who has just gone is ordinary, not an
            // error, but it is worth seeing when a window stays empty.
            tracing::debug!(
                conn = inbound.conn,
                session = wanted,
                "UserStats for a session that is not here"
            );
            return Actions::new();
        };

        // murmur's `extend` (`Messages.cpp:3206`): yourself, or an
        // administrator — one holding Ban on the root channel.
        let extend = wanted == inbound.session || self.may_see_everything(inbound).await;
        let details = extend && !request.stats_only.unwrap_or(false);
        // murmur's `local` (`Messages.cpp:3214`): the packet counters go to
        // anyone in the same channel, which is what makes the statistics box
        // appear for an ordinary user looking at somebody else.
        let local = extend || target.channel == self.channel_of(inbound.session);

        let reply = user_stats(&target, details, local, now_ms());
        tracing::debug!(
            conn = inbound.conn,
            session = wanted,
            details,
            local,
            "answering UserStats"
        );
        vec![to_conn(inbound.conn, USER_STATS, reply.encode_to_vec())]
    }

    /// Whether the asker is an administrator, by murmur's test for it.
    ///
    /// Ban on the root channel (`Messages.cpp:3206`). Asked of the permissions
    /// service rather than decided here, so that "who is an admin" has one
    /// answer in this system rather than one per service — and the superuser
    /// short-circuit already lives there.
    ///
    /// Any failure is a `false`: the consequence is a sparser dialog, whereas
    /// guessing `true` because permissions is unreachable would hand out
    /// addresses and certificates on the strength of an outage.
    async fn may_see_everything(&self, inbound: &Inbound) -> bool {
        use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
        use starling_proto_fancy::permissions::{CheckRequest, Subject};

        let Some(asker) = self.connections.by_session(inbound.session) else {
            return false;
        };
        let Ok(channel) = self.handshake.context().resolver.channel("permissions") else {
            tracing::debug!("permissions is unreachable; answering UserStats without details");
            return false;
        };
        let (account, registered) = identity::wire(asker.account);
        let decision = PermissionsClient::new(channel)
            .check(CheckRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: inbound.scope,
                }),
                subject: Some(Subject {
                    session: asker.session,
                    account,
                    name: asker.name.clone(),
                    registered,
                    tokens: asker.tokens.clone(),
                    cert_hash: asker.cert_hash.clone(),
                    channel: asker.channel,
                    strong_cert: asker.strong_cert,
                }),
                channel: ROOT_CHANNEL,
                permission: BAN,
            })
            .await;
        decision.is_ok_and(|decision| decision.into_inner().allowed)
    }

    /// The channel a session is in, or the root.
    fn channel_of(&self, session: u32) -> u32 {
        self.connections
            .by_session(session)
            .map_or(ROOT_CHANNEL, |pending| pending.channel)
    }

    /// Mute, deafen, suppress or make a priority speaker.
    ///
    /// murmur treats these as one group with one rule
    /// (`Messages.cpp:1130`): `MuteDeafen` on the *target's* channel, never on
    /// the actor's. That is what makes it a moderator power over a room rather
    /// than a property of the person exercising it — and it is why this is
    /// refused for a user's own session too unless they hold it.
    async fn on_speak_state(&self, inbound: &Inbound, state: &tcp::UserState) -> Actions {
        let target_session = state.session.unwrap_or(inbound.session);
        let Some(target) = self.connections.by_session(target_session) else {
            tracing::debug!(
                session = target_session,
                "speak-state for an unknown session"
            );
            return Actions::new();
        };

        // The administrator cannot be muted, deafened or suppressed by anybody
        // (`Messages.cpp:1131`). Without this, `MuteDeafen` in the root channel
        // is enough to silence the one account that can undo it.
        //
        // **Priority speaker is deliberately outside the guard, and murmur has
        // it inside.** Upstream refuses all four flags in one block, so there is
        // no account on a murmur server — not even the SuperUser acting on
        // itself — that can make the administrator a priority speaker. That
        // looks like the four flags travelling together rather than a rule about
        // this one: the guard exists so that nothing can be *taken away* from
        // the account that repairs a broken ACL table, and priority speaker
        // hands something over. Silencing the administrator is still refused, by
        // this same guard.
        let (account, registered) = identity::wire(target.account);
        if identity::is_superuser(registered, account) && restricts(state) {
            tracing::info!(
                session = target_session,
                "refusing a speak-state change against the superuser"
            );
            return vec![deny(inbound, tcp::permission_denied::DenyType::SuperUser)];
        }

        // `suppress` is the server's own statement that a user lacks `Speak`
        // here. murmur refuses any client that sets it, however privileged
        // (`Messages.cpp:1135`) — a moderator who wants silence uses `mute`.
        if state.suppress.is_some() {
            tracing::info!(
                session = inbound.session,
                "refusing a client-set suppress; it is server-owned"
            );
            return vec![permission_denied(
                inbound,
                Perm::MUTE_DEAFEN,
                target.channel,
            )];
        }

        if !self
            .permit
            .allows(inbound, target.channel, Perm::MUTE_DEAFEN.bits())
            .await
        {
            tracing::info!(
                actor = inbound.session,
                session = target_session,
                channel = target.channel,
                "speak-state change refused"
            );
            return vec![permission_denied(
                inbound,
                Perm::MUTE_DEAFEN,
                target.channel,
            )];
        }

        let updated = self.connections.set_speak_state(
            target.conn,
            state.mute,
            state.deaf,
            state.priority_speaker,
        );
        let Some(session) = updated else {
            return Actions::new();
        };
        let Some(applied) = self.connections.by_session(session) else {
            return Actions::new();
        };

        self.handshake.context().logger.log(
            LogEvent::notice(Category::Admin, "speak state changed")
                .with("actor", inbound.session)
                .with("session", session)
                .with("name", applied.name.clone())
                .with("mute", applied.mute)
                .with("deaf", applied.deaf)
                .with("priority_speaker", applied.priority_speaker),
        );
        self.handshake
            .announce_changed(&self.connections, target.conn)
            .await;

        // Asked for, or changed underneath — never simply "all of them".
        //
        // A Mumble client logs one line per field **present** in this message,
        // not per field changed (`vendor/server/src/mumble/Messages.cpp:600`
        // tests `msg.has_priority_speaker()` and nothing else). Sending all
        // three every time therefore narrated two things that never happened on
        // every mute: "You gave priority speaker status to X" and "You
        // undeafened X", both from fields that were merely restated as `false`.
        //
        // murmur sends the client's own message back with the couplings it
        // actually forced written into it (`Messages.cpp:1303`) — so a field it
        // did not touch is absent, and that absence is what keeps the log
        // honest. The applied value is still what travels, because deafening
        // also mutes and a client told only what it asked for would render a
        // user who is deaf but not muted.
        //
        // `actor` is the moderator, not the target: it is what lets a client
        // say who did the muting, and without it a moderator action is
        // indistinguishable from one the server took by itself.
        let echo = tcp::UserState {
            session: Some(session),
            actor: Some(inbound.session),
            mute: echoed(state.mute, target.mute, applied.mute),
            deaf: echoed(state.deaf, target.deaf, applied.deaf),
            priority_speaker: echoed(
                state.priority_speaker,
                target.priority_speaker,
                applied.priority_speaker,
            ),
            ..tcp::UserState::default()
        };
        vec![to_sessions(Vec::new(), USER_STATE, echo.encode_to_vec())]
    }

    /// Register a user, or oneself (`UserState.user_id`).
    ///
    /// murmur's rule (`Messages.cpp:1203`): `SelfRegister` on the **root**
    /// channel when the target is the sender and `Register` on root when it is
    /// somebody else — two permissions because a server may well let people
    /// claim their own name while reserving the right to name anyone else. In
    /// both cases the target must not already be registered, and must have
    /// presented a certificate.
    ///
    /// **The certificate requirement is load-bearing, not ceremony.** This path
    /// stores no password, and userdata keeps none for an empty one
    /// (`accounts.rs:336`). An account is then claimed on the next connection
    /// either by certificate or by password, and `authenticate` refuses a
    /// password-less account claimed by name alone (`accounts.rs:227`) —
    /// correctly, since anyone could type the name. So registering a
    /// certificate-less user would write an account its own owner cannot log
    /// into, while permanently taking the name: every later connection under it
    /// is refused as `NameTaken`. Upstream denies it, and this is why.
    async fn on_register(&self, inbound: &Inbound, state: &tcp::UserState) -> Actions {
        use starling_proto_fancy::userdata::user_data_client::UserDataClient;
        use starling_proto_fancy::userdata::{Account, RegisterRequest};

        let target_session = state.session.unwrap_or(inbound.session);
        let Some(target) = self.connections.by_session(target_session) else {
            tracing::debug!(
                session = target_session,
                "registration for an unknown session"
            );
            return Actions::new();
        };
        let own = target_session == inbound.session;
        let permission = registration_permission(own);

        // Already registered. murmur folds this into the same refusal as a
        // missing permission (`Messages.cpp:1205` tests both in one condition),
        // and the alternative — registering again — would mint a second account
        // for somebody who has one and strand the first.
        if target.account.is_some() {
            tracing::info!(
                actor = inbound.session,
                session = target_session,
                "refusing to register an already-registered user"
            );
            return vec![permission_denied(inbound, permission, ROOT_CHANNEL)];
        }

        if !self
            .permit
            .allows(inbound, ROOT_CHANNEL, permission.bits())
            .await
        {
            tracing::info!(
                actor = inbound.session,
                session = target_session,
                own,
                "registration refused"
            );
            return vec![permission_denied(inbound, permission, ROOT_CHANNEL)];
        }

        if target.cert_hash.is_empty() {
            tracing::info!(
                session = target_session,
                "refusing to register a user with no certificate"
            );
            return vec![deny(
                inbound,
                tcp::permission_denied::DenyType::MissingCertificate,
            )];
        }

        let Ok(channel) = self.handshake.context().resolver.channel("userdata") else {
            tracing::warn!("userdata is unreachable; cannot register");
            return vec![refused(inbound, "the account service is unavailable")];
        };
        let registered = UserDataClient::new(channel)
            .register(RegisterRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: inbound.scope,
                }),
                // Whose action this was, for userdata's own record. Self- and
                // other-registration are the same call, and only this
                // distinguishes them once it has left here.
                actor: Some(starling_proto_fancy::common::Actor {
                    who: Some(starling_proto_fancy::common::actor::Who::Session(
                        inbound.session,
                    )),
                }),
                account: Some(Account {
                    name: target.name.clone(),
                    // What the account is claimed by on every later connection.
                    // Omitting it is the dead-account case in this method's
                    // documentation.
                    cert_hash: target.cert_hash.clone(),
                    ..Account::default()
                }),
                password: String::new(),
            })
            .await;

        let account = match registered {
            Ok(account) => account.into_inner(),
            Err(status) => {
                // The name is taken, most likely. Said to the client rather
                // than dropped: a register button that does nothing at all is
                // the failure this whole path exists to remove.
                tracing::info!(
                    session = target_session,
                    name = %target.name,
                    %status,
                    "userdata refused the registration"
                );
                return vec![refused(inbound, status.message())];
            }
        };

        let Some(session) = self.connections.set_account(target.conn, account.id) else {
            return Actions::new();
        };
        self.handshake.context().logger.log(
            LogEvent::notice(Category::Admin, "user registered")
                .with("actor", inbound.session)
                .with("session", session)
                .with("name", target.name.clone())
                .with("account", account.id)
                .with("self", own),
        );

        // Before the broadcast: session-view is what every other service reads
        // an identity from, and a client told the user is registered while
        // `permissions` still evaluates them as a guest is a user whose new
        // rights do not work until they reconnect.
        self.handshake
            .announce_changed(&self.connections, target.conn)
            .await;

        // `user_id` is what moves a user into the client's "Registered Users"
        // list (`handshake.rs:484`), and everyone is told because everyone
        // renders that list.
        let echo = tcp::UserState {
            session: Some(session),
            actor: Some(inbound.session),
            user_id: Some(account.id as u32),
            ..tcp::UserState::default()
        };
        vec![to_sessions(Vec::new(), USER_STATE, echo.encode_to_vec())]
    }

    /// Move `moved` into `target`, whether or not that is the caller.
    ///
    /// murmur asks three questions in two steps (`Messages.cpp:1075`, `:1080`):
    ///
    /// 1. dragging *somebody else* takes `Move` on the channel they are in now —
    ///    the power is over the room they are being taken out of;
    /// 2. and then, for the destination, either the mover holds `Move` there
    ///    **or** the person being moved holds `Enter` there.
    ///
    /// The second is an *or*, asked as two calls, because [`Permit::allows`]
    /// requires every bit it is given and a single two-bit request would demand
    /// both. Moving oneself skips the first question and collapses the second to
    /// `Enter`, which is the permission an operator revokes to make a channel
    /// private.
    ///
    /// A refusal is *told to the client*. Silence is what made this look like a
    /// broken server rather than a locked channel: the user clicks, nothing
    /// moves, and no message says why.
    ///
    /// A refusal is *told to the client*. Silence is what made this look like a
    /// broken server rather than a locked channel: the user clicks, nothing
    /// moves, and no message says why.
    ///
    /// `tokens` are the channel's password, sent with the request rather than
    /// stored on the session. They apply to the `Enter` check below and to
    /// nothing else, which is what makes a password a key to one door: the
    /// person moved may enter because they knew it, and the moment the request
    /// is answered they hold nothing extra.
    async fn on_move(
        &self,
        inbound: &Inbound,
        moved: u32,
        target: u32,
        tokens: Vec<String>,
    ) -> Actions {
        let Some(subject) = self.connections.by_session(moved) else {
            tracing::debug!(session = moved, "move for an unknown session");
            return Actions::new();
        };
        // Already there. murmur returns early on this rather than re-entering,
        // and re-entering would broadcast a move that did not happen.
        if subject.channel == target {
            return Actions::new();
        }

        // Dragging *somebody else* takes `Move` on the channel they are in
        // now (`vendor/server/src/murmur/Messages.cpp:1075`) — the power is
        // over the room they are being taken out of, which is why it is checked
        // there and not on the mover.
        if moved != inbound.session
            && !self
                .permit
                .allows(inbound, subject.channel, Perm::MOVE.bits())
                .await
        {
            tracing::info!(
                actor = inbound.session,
                session = moved,
                from = subject.channel,
                "move refused: no Move in the channel they are in"
            );
            return vec![permission_denied(inbound, Perm::MOVE, subject.channel)];
        }

        // The destination rule is an *or* (`Messages.cpp:1080`): the mover may
        // hold `Move` there, or the person being moved may hold `Enter`. Asked
        // as two questions because `Permit::allows` requires every bit it is
        // given, so one two-bit request would demand both.
        //
        // The tokens ride on the `Enter` half only. `Move` is a moderator's
        // authority over a room, and letting a password stand in for it would
        // mean anyone who knows a channel's password can drag other people into
        // it.
        let may_enter = self
            .permit
            .allows_session_with_tokens(inbound.scope, moved, target, Perm::ENTER.bits(), tokens)
            .await
            || self.permit.allows(inbound, target, Perm::MOVE.bits()).await;
        if !may_enter {
            tracing::info!(
                actor = inbound.session,
                session = moved,
                channel = target,
                "channel move refused"
            );
            return vec![permission_denied(inbound, Perm::ENTER, target)];
        }

        let Some(result) = self.handshake.enter(inbound.scope, moved, target).await else {
            // metadata is unreachable. Not a refusal — saying "you lack Enter"
            // would blame the user for an outage.
            tracing::error!(
                session = moved,
                channel = target,
                "metadata is unreachable; cannot move"
            );
            return Actions::new();
        };
        if !result.applied {
            tracing::info!(
                session = moved,
                channel = target,
                refused = %result.refused,
                "channel move refused by metadata"
            );
            return vec![permission_denied(inbound, Perm::ENTER, target)];
        }

        // Kept in step so that `UserStats` and the timeout sweep agree with the
        // tree about where this session is. `set_channel` existed and was never
        // called, which is why every session read as being in the root.
        self.connections.set_channel(subject.conn, target);
        self.handshake
            .announce_changed(&self.connections, subject.conn)
            .await;

        // Everyone is told, not just the mover: a client builds its user tree
        // from these, so a move only one client hears about is a user who
        // appears in two channels at once.
        //
        // `actor` is who caused the change, and it is what makes this read as a
        // move the user *made* rather than one done to them: a client with no
        // actor to attribute the change to logs "You were moved to X by the
        // server", so omitting it turns every ordinary channel click into what
        // looks like an administrator dragging the user around.
        let announce = tcp::UserState {
            // The session that moved, which is not always the one that asked.
            session: Some(moved),
            actor: Some(inbound.session),
            channel_id: Some(target),
            ..tcp::UserState::default()
        };
        vec![to_sessions(
            Vec::new(),
            USER_STATE,
            announce.encode_to_vec(),
        )]
    }

    /// Self-mute and self-deafen, which are the only `UserState` fields a
    /// client may set on itself without a permission check.
    async fn on_user_state(&self, inbound: &Inbound) -> Actions {
        let Ok(state) = tcp::UserState::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        // Registering somebody else is the *point* of `Register`, so this is
        // routed ahead of the cross-session refusal below rather than falling
        // foul of it, exactly as the speak-state flags are. It comes first
        // because it is the more specific action: a message carrying `user_id`
        // is a registration whatever else is set on it.
        if state.user_id.is_some() {
            return self.on_register(inbound, &state).await;
        }

        let elsewhere = state
            .session
            .is_some_and(|session| session != inbound.session);
        if elsewhere && !moderates(&state) {
            // Everything below this point acts on the sender's own session.
            // Moderation is the exception — acting on somebody else is the
            // *usual* case for those fields — so they are let through to their
            // own permission check rather than refused here.
            return Actions::new();
        }

        // Mute, deafen, suppress and priority speaker are one group in murmur
        // (`vendor/server/src/murmur/Messages.cpp:1130`), sharing one
        // permission and one refusal. None of them were read at all, so
        // "make priority speaker" sent a request the server ignored.
        if is_speak_state(&state) {
            return self.on_speak_state(inbound, &state).await;
        }

        // A client announcing it has *started* recording, on a server that
        // forbids it. `allow_recording` was advertised in `ServerConfig` and
        // enforced nowhere (`docs/GAP-ANALYSIS.md` §5), so a client that
        // ignored the flag recorded the channel and the server said nothing.
        //
        // murmur kicks (`Messages.cpp:1417`), and the severity is the point:
        // the flag is the client's own voluntary disclosure, so the only
        // client this can catch is an honest one — and the answer to an honest
        // client doing a forbidden thing is to stop the session, not to drop
        // the field and leave it recording in the belief that it may.
        if state.recording == Some(true) {
            let config = self.handshake.config(inbound.scope).await;
            if !config.allow_recording {
                self.handshake.context().logger.log(
                    LogEvent::notice(Category::Session, "recording refused")
                        .with("session", inbound.session)
                        .with("conn", inbound.conn)
                        .with("scope", inbound.scope),
                );
                return vec![disconnect(
                    inbound.conn,
                    "Recording is not allowed on this server",
                )];
            }
        }

        // A channel switch is a `UserState` carrying `channel_id`
        // (`vendor/server/src/murmur/Messages.cpp:1070`). This was not read at
        // all, so clicking a channel sent a request the server parsed, ignored,
        // and answered with the self-mute echo below — a reply that looks like
        // success and moves nobody.
        if let Some(channel) = state.channel_id {
            let moved = state.session.unwrap_or(inbound.session);
            // The password the user typed into the "this channel is locked"
            // dialog, carried on the request that it authorises and stored
            // nowhere (`vendor/server/src/murmur/Messages.cpp:1133`).
            let mut actions = self
                .on_move(
                    inbound,
                    moved,
                    channel,
                    state.temporary_access_tokens.clone(),
                )
                .await;
            // After the move, never before, and murmur is explicit about it
            // (`Messages.cpp:1468`): one `UserState` can both join a channel and
            // start listening to another, and evaluating the listener first
            // would check `Listen` against the room the user is leaving.
            if is_listen_state(&state) {
                actions.extend(self.on_listen(inbound, &state).await);
            }
            return actions;
        }

        if is_listen_state(&state) {
            return self.on_listen(inbound, &state).await;
        }

        // Clearing somebody else's comment or avatar is its own permission and
        // its own handler, because it is the opposite of the path below: that
        // one *stores* what arrived, and this one is only ever allowed to erase.
        if elsewhere && is_user_content(&state) {
            return self.on_reset_content(inbound, &state).await;
        }

        let updated =
            self.connections
                .set_self_flags(inbound.conn, state.self_mute, state.self_deaf);
        let Some(session) = updated else {
            return Actions::new();
        };

        // Setting your *own* comment or avatar needs no permission, as in murmur
        // — only clearing somebody else's does, and this method already refused
        // every cross-session edit above. What they do need is a size limit,
        // because both are stored and then handed to every client that asks.
        let mut comment_hash = None;
        let mut texture_hash = None;
        if state.comment.is_some() || state.texture.is_some() {
            // Fetched only when there is something to measure. A `UserState` is
            // also every self-mute toggle, and putting a round trip on that path
            // would be a gRPC call per keypress on a push-to-mute binding.
            let limits = self.handshake.config(inbound.scope).await;

            if let Some(comment) = &state.comment {
                if over(comment.len(), limits.text_message_length) {
                    return vec![too_long(inbound)];
                }
                comment_hash = self
                    .store_content(inbound, UserContent::Comment, comment.as_bytes())
                    .await;
            }
            if let Some(texture) = &state.texture {
                if over(texture.len(), limits.image_message_length) {
                    return vec![too_long(inbound)];
                }
                texture_hash = self
                    .store_content(inbound, UserContent::Texture, texture)
                    .await;
            }

            // Before the announcement, and this is the line that makes the new
            // picture visible to anybody but its owner. `session-view` is built
            // from the connection record and nothing else (`handshake.rs:125`),
            // so a hash written only to the account row reaches the people who
            // reconnect after it and nobody who is here now.
            let _ = self.connections.set_content(
                inbound.conn,
                comment_hash.clone(),
                texture_hash.clone(),
            );
        }

        self.handshake
            .announce_changed(&self.connections, inbound.conn)
            .await;

        // The hashes, not the bodies. Clients from 1.2.2 are sent
        // `comment_hash` and `texture_hash` and fetch the body with
        // `RequestBlob` if they want it
        // (`vendor/server/src/murmur/Messages.cpp:1517`), which keeps an avatar
        // out of a broadcast to every connected client — the whole reason the
        // hash fields exist.
        let echo = tcp::UserState {
            session: Some(session),
            actor: Some(inbound.session),
            self_mute: state.self_mute,
            self_deaf: state.self_deaf,
            comment_hash,
            texture_hash,
            ..tcp::UserState::default()
        };
        vec![to_sessions(Vec::new(), USER_STATE, echo.encode_to_vec())]
    }

    /// Start or stop listening to channels, and re-weight the ones already on.
    ///
    /// The feature murmur calls a `ChannelListener`: hearing a room without being
    /// in it, chosen per user rather than configured by an operator the way a
    /// channel link is.
    ///
    /// **Strictly the sender's own.** murmur refuses a `UserState` that names
    /// somebody else and carries `listening_channel_add` or `_remove`
    /// (`Messages.cpp:1285`), and this refuses the volume adjustments too —
    /// upstream leaves those out of the same guard, which lets a moderator turn
    /// down a room in another person's client. Subscribing or re-mixing
    /// somebody else's audio is not a moderation power that exists.
    async fn on_listen(&self, inbound: &Inbound, state: &tcp::UserState) -> Actions {
        if state
            .session
            .is_some_and(|session| session != inbound.session)
        {
            tracing::debug!(
                actor = inbound.session,
                target = state.session,
                "refused a listener change aimed at another session"
            );
            return Actions::new();
        }

        // Who to persist this under. `None` for a guest, and metadata stores
        // nothing for one: there is no identity for a later visit to match, so a
        // guest's listeners last exactly as long as the session does.
        let account = self
            .connections
            .get(inbound.conn)
            .and_then(|pending| pending.account);

        // `Listen` on each channel, and only on the ones being *added*: giving
        // up a listener is not an exercise of a permission, and a user whose
        // access was revoked while listening must still be able to stop.
        let (listen, mut denials) = self.permitted_listens(inbound, state).await;

        let volume: HashMap<u32, f32> = state
            .listening_volume_adjustment
            .iter()
            .filter_map(|adjustment| {
                Some((
                    adjustment.listening_channel?,
                    adjustment.volume_adjustment(),
                ))
            })
            .collect();

        let Some(outcome) = self
            .handshake
            .listen(
                inbound.scope,
                inbound.session,
                account,
                listen,
                state.listening_channel_remove.clone(),
                volume,
            )
            .await
        else {
            // metadata is unreachable. Not a refusal: telling the user they lack
            // `Listen` would blame them for an outage.
            tracing::error!(
                session = inbound.session,
                "metadata is unreachable; cannot change listeners"
            );
            return denials;
        };

        // A limit met is not a permission missing, and a client told the wrong
        // one renders "you lack the Listen permission" for a room that is simply
        // full — a condition an operator can lift and a user can wait out.
        denials.extend(
            outcome
                .refused
                .iter()
                .map(|refusal| listener_limit_denied(inbound, refusal)),
        );

        if outcome.added.is_empty() && outcome.removed.is_empty() && outcome.volume.is_empty() {
            return denials;
        }

        // This copy first, then the announcement that reads it: `voice` builds
        // its routing snapshot from the session view and nothing else, so a
        // listener that stops here is one no audio is ever routed to.
        self.connections.apply_listeners(
            inbound.conn,
            &outcome.added,
            &outcome.removed,
            &outcome.volume,
        );
        self.handshake
            .announce_changed(&self.connections, inbound.conn)
            .await;

        // Whether everyone hears the gains or only their owner. murmur's
        // `broadcastlistenervolumeadjustments`, off by default.
        let config = self.handshake.config(inbound.scope).await;
        denials.extend(announce_listeners(
            inbound,
            &outcome,
            config.broadcast_listener_volume_adjustments,
        ));
        denials
    }

    /// Split the requested additions into the ones this client may have and a
    /// refusal for each of the rest.
    ///
    /// Per channel and carrying on, as murmur does (`Messages.cpp:1171`
    /// continues rather than returning): a client that asks for everything it
    /// can see should get what it may have, not lose the lot to one forbidden
    /// room.
    async fn permitted_listens(
        &self,
        inbound: &Inbound,
        state: &tcp::UserState,
    ) -> (Vec<u32>, Actions) {
        let mut allowed = Vec::with_capacity(state.listening_channel_add.len());
        let mut denials = Actions::new();
        for channel in &state.listening_channel_add {
            if self
                .permit
                .allows(inbound, *channel, Perm::LISTEN.bits())
                .await
            {
                allowed.push(*channel);
            } else {
                denials.push(permission_denied(inbound, Perm::LISTEN, *channel));
            }
        }
        (allowed, denials)
    }

    /// Clear another user's comment or avatar (`ResetUserContent`).
    ///
    /// murmur's rule, and both halves of it matter (`Messages.cpp:1236` for the
    /// comment, `:1263` for the avatar):
    ///
    /// * `ResetUserContent` on the **root** channel — it is a server-wide power
    ///   over people, not a power over a room, so it is not checked where the
    ///   target happens to be standing;
    /// * **the value must be empty.** It is a *reset*, not an edit. A moderator
    ///   may take down a comment nobody should have to read; replacing it with
    ///   one of their own choosing would be putting words in somebody else's
    ///   profile, under that person's name, to every client on the server.
    ///
    /// A non-empty value is refused as `TextTooLong` rather than as a permission
    /// failure, which is upstream's choice too and reads oddly until you notice
    /// what it is saying: the *permitted* length for somebody else's content is
    /// zero, so anything at all is over it.
    async fn on_reset_content(&self, inbound: &Inbound, state: &tcp::UserState) -> Actions {
        let target_session = state.session.unwrap_or(inbound.session);
        let Some(target) = self.connections.by_session(target_session) else {
            tracing::debug!(
                session = target_session,
                "content reset for an unknown session"
            );
            return Actions::new();
        };

        let setting = state.comment.as_ref().is_some_and(|text| !text.is_empty())
            || state
                .texture
                .as_ref()
                .is_some_and(|bytes| !bytes.is_empty());
        if setting {
            tracing::info!(
                actor = inbound.session,
                session = target_session,
                "refusing to write content into another user's profile"
            );
            return vec![too_long(inbound)];
        }

        if !self
            .permit
            .allows(inbound, ROOT_CHANNEL, Perm::RESET_USER_CONTENT.bits())
            .await
        {
            tracing::info!(
                actor = inbound.session,
                session = target_session,
                "content reset refused"
            );
            return vec![permission_denied(
                inbound,
                Perm::RESET_USER_CONTENT,
                ROOT_CHANNEL,
            )];
        }

        // Cleared in both places, because they answer different questions. The
        // connection record is what every connected client's view is rebuilt
        // from; the account row is what the target gets back when they
        // reconnect. Clearing only one leaves the content gone until the next
        // login, or back again after it.
        let cleared_comment = state.comment.is_some();
        let cleared_texture = state.texture.is_some();
        let _ = self.connections.set_content(
            target.conn,
            cleared_comment.then(Vec::new),
            cleared_texture.then(Vec::new),
        );
        if let Some(account) = target.account {
            self.clear_stored_content(inbound, account, cleared_comment, cleared_texture)
                .await;
        }

        self.handshake.context().logger.log(
            LogEvent::notice(Category::Admin, "user content reset")
                .with("actor", inbound.session)
                .with("session", target_session)
                .with("name", target.name.clone())
                .with("comment", cleared_comment)
                .with("texture", cleared_texture),
        );
        self.handshake
            .announce_changed(&self.connections, target.conn)
            .await;

        // The empty **body**, not an empty hash. murmur only swaps a body for
        // its hash when the hash is non-empty (`Messages.cpp:1591`), and after a
        // reset it is not — so what travels is `comment = ""`, which is the one
        // form every client reads as "this is now blank" rather than as "fetch
        // it yourself".
        let echo = tcp::UserState {
            session: Some(target_session),
            actor: Some(inbound.session),
            comment: cleared_comment.then(String::new),
            texture: cleared_texture.then(Vec::new),
            ..tcp::UserState::default()
        };
        vec![to_sessions(Vec::new(), USER_STATE, echo.encode_to_vec())]
    }

    /// Clear the stored comment or avatar on a registered account.
    ///
    /// Best-effort, and reported rather than propagated: the reset has already
    /// happened everywhere a client can see it, and failing the whole action
    /// here would leave the operator being told nothing worked when most of it
    /// did. What the log records is the part that will come back on reconnect.
    async fn clear_stored_content(
        &self,
        inbound: &Inbound,
        account: u64,
        comment: bool,
        texture: bool,
    ) {
        use starling_proto_fancy::userdata::user_data_client::UserDataClient;
        use starling_proto_fancy::userdata::{Account, UpdateRequest};

        let mut fields = Vec::new();
        if comment {
            fields.push(UserContent::Comment.field().to_owned());
        }
        if texture {
            fields.push(UserContent::Texture.field().to_owned());
        }
        let Ok(channel) = self.handshake.resolver().channel("userdata") else {
            tracing::warn!(account, "userdata is unreachable; the reset is not durable");
            return;
        };
        // `Account::default()` is the point: every hash on it is empty, and
        // `update` writes exactly the named fields from it.
        let update = UserDataClient::new(channel)
            .update(UpdateRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: inbound.scope,
                }),
                actor: None,
                id: account,
                fields,
                values: Some(Account::default()),
                password: String::new(),
                current_password: String::new(),
            })
            .await;
        if let Err(status) = update {
            tracing::warn!(
                %status,
                account,
                "could not clear stored user content; it will return on reconnect"
            );
        }
    }

    /// Store one piece of a user's own content, and return its hash.
    ///
    /// The body goes to `userdata`'s content-addressed blob store, which is what
    /// `RequestBlob` already serves — so storing it here is what makes it
    /// fetchable, for a guest as much as for a registered user. Content
    /// addressing earns its keep on avatars in particular: everyone using the
    /// same default picture stores it once.
    ///
    /// A registered account additionally gets the hash written to it, so the
    /// content survives a reconnect. A guest's does not, which is murmur's
    /// behaviour too: there is no account to hang it on.
    async fn store_content(
        &self,
        inbound: &Inbound,
        what: UserContent,
        bytes: &[u8],
    ) -> Option<Vec<u8>> {
        use starling_proto_fancy::userdata::user_data_client::UserDataClient;
        use starling_proto_fancy::userdata::{Account, Blob, UpdateRequest};

        let scope = Some(starling_proto_fancy::common::Scope {
            virtual_server: inbound.scope,
        });
        let channel = self.handshake.resolver().channel("userdata").ok()?;
        let mut userdata = UserDataClient::new(channel);

        let stored = userdata
            .put_blob(Blob {
                scope,
                hash: Vec::new(),
                bytes: bytes.to_vec(),
            })
            .await
            .ok()?
            .into_inner();

        // Only a registered account has somewhere durable to keep it.
        if let Some(account) = self.connections.get(inbound.conn).and_then(|p| p.account) {
            let values = match what {
                UserContent::Comment => Account {
                    comment_hash: stored.hash.clone(),
                    ..Account::default()
                },
                UserContent::Texture => Account {
                    texture_hash: stored.hash.clone(),
                    ..Account::default()
                },
            };
            let update = userdata
                .update(UpdateRequest {
                    scope,
                    actor: None,
                    id: account,
                    fields: vec![what.field().to_owned()],
                    values: Some(values),
                    password: String::new(),
                    current_password: String::new(),
                })
                .await;
            if let Err(status) = update {
                // Still readable this session — the blob is stored — but it will
                // not come back after a reconnect.
                tracing::warn!(
                    %status,
                    account,
                    what = what.field(),
                    "could not attach user content to an account"
                );
            }
        }

        Some(stored.hash)
    }
}

/// A piece of content a user sets about themselves.
///
/// The two travel identically — a blob plus a hash on the account — and differ
/// only in which account field the hash lands in and which limit bounds them.
/// One enum rather than two near-identical methods, because the pair that got
/// out of step was exactly this: comments were handled and avatars were decoded
/// and dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserContent {
    /// `UserState.comment`, bounded by `text_message_length`.
    Comment,
    /// `UserState.texture` — the avatar — bounded by `image_message_length`.
    Texture,
}

impl UserContent {
    /// The account field the hash is written to.
    const fn field(self) -> &'static str {
        match self {
            Self::Comment => "comment_hash",
            Self::Texture => "texture_hash",
        }
    }
}

/// Whether `len` exceeds a configured limit.
///
/// Zero means no limit, as it does throughout murmur's configuration — so a
/// limit that has been switched off must not be read as "nothing is allowed".
const fn over(len: usize, limit: u32) -> bool {
    limit != 0 && len > limit as usize
}

/// Refuse content that is too large, and say which kind of refusal it is.
///
/// `TextTooLong` rather than `Permission`: the client is not being told it lacks
/// a right, it is being told the thing it sent will not fit. A Mumble client
/// renders those differently, and the second one is actionable.
fn too_long(inbound: &Inbound) -> ServerAction {
    let denied = tcp::PermissionDenied {
        r#type: Some(tcp::permission_denied::DenyType::TextTooLong as i32),
        session: Some(inbound.session),
        ..tcp::PermissionDenied::default()
    };
    to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

impl Serve for SessionLifecycleService {
    const NAME: &'static str = "session-lifecycle";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let fanout = Fanout::default();
        Ok(Arc::new(Self {
            connections: Connections::new(max_users(&ctx)),
            handshake: Handshake::new(Resolver::clone(&ctx.resolver), fanout.clone(), ctx.clone()),
            fanout,
            permit: Permit::new(ctx.resolver.clone()),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }

    /// Reap connections nothing has been heard from.
    ///
    /// [`Connections::timed_out`] existed, and the module header promised to
    /// "notice a timeout", but nothing ever called it — so a client that went
    /// away without its TCP connection noticing stayed in the tree for the life
    /// of the process. That is a laptop closing its lid, a phone losing signal,
    /// a cable pulled: the socket is not closed, it is *silent*, and no amount
    /// of handling close correctly at the gateway will ever reap it.
    ///
    /// The disconnect is asked for rather than applied locally, because the
    /// gateway owns the socket and everything else — the removal, telling the
    /// other services, the `UserRemove` other clients need — already hangs off
    /// the gateway noticing the connection end.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let timeout = timeout_ms(&ctx);
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(SWEEP_INTERVAL_MS));
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => return Ok(()),
                _ = tick.tick() => {}
            }

            let cutoff = now_ms().saturating_sub(timeout);
            for conn in self.connections.timed_out(cutoff) {
                let name = self
                    .connections
                    .get(conn)
                    .map(|pending| pending.name)
                    .unwrap_or_default();
                ctx.logger.log(
                    LogEvent::notice(Category::Session, "connection timed out")
                        .with("conn", conn)
                        .with("name", name)
                        .with("after_ms", timeout),
                );
                self.fanout.push(disconnect(conn, "timed out"));
            }
        }
    }
}

/// How often to look for connections that have gone quiet.
///
/// Well below the timeout itself, so the worst case is a ghost outliving its
/// deadline by one tick rather than by a whole timeout.
const SWEEP_INTERVAL_MS: u64 = 5_000;

/// The `UserStats` reply for `target` under murmur's two disclosure gates.
///
/// A free function so the rule can be tested without a running deployment —
/// and the rule is worth testing, because *which fields are present* is not a
/// cosmetic detail. The client decides whether to show each half of the dialog
/// by asking whether the fields that fill it arrived at all
/// (`UserInformation.cpp:154`), so an omission does not render a blank row, it
/// hides the entire box.
fn user_stats(target: &PendingConnection, details: bool, local: bool, now: u64) -> tcp::UserStats {
    tcp::UserStats {
        session: Some(target.session),
        onlinesecs: Some(seconds_since(target.connected_at_ms, now)),
        idlesecs: local.then(|| seconds_since(target.last_seen_ms, now)),
        strong_certificate: details.then_some(target.strong_cert),
        opus: details.then_some(target.opus),
        // Under `details` with the address and the client build: a
        // certificate identifies a person, so it goes to that person and to an
        // administrator, not to whoever right-clicks them.
        certificates: if details {
            target.certificates.clone()
        } else {
            Vec::new()
        },
        version: details.then(|| tcp::Version {
            version_v2: (target.mumble_version != 0).then_some(target.mumble_version),
            release: (!target.release.is_empty()).then(|| target.release.clone()),
            os: (!target.os.is_empty()).then(|| target.os.clone()),
            os_version: (!target.os_version.is_empty()).then(|| target.os_version.clone()),
            ..tcp::Version::default()
        }),
        // Absent, not empty: `optional bytes` distinguishes the two, and a
        // zero-length address is a value a client may try to render.
        address: details
            .then(|| address_bytes(&target.address))
            .filter(|address| !address.is_empty()),
        // The client's own measurements, repeated back. murmur does exactly
        // this (`Messages.cpp:2918` stores them, `:3277` echoes them): the
        // server is not in a position to time a client's round trips or count
        // what never reached it, so what it can offer is the last figures that
        // client reported.
        udp_packets: Some(target.reported.udp_packets),
        tcp_packets: Some(target.reported.tcp_packets),
        udp_ping_avg: Some(target.reported.udp_ping_avg),
        udp_ping_var: Some(target.reported.udp_ping_var),
        tcp_ping_avg: Some(target.reported.tcp_ping_avg),
        tcp_ping_var: Some(target.reported.tcp_ping_var),
        // `from_server` is what the client reports having received *from* the
        // server, so it is the client's figures. `from_client` is the mirror —
        // the server's own crypt counters for packets it received — and those
        // live in the voice service, which does not report them here yet. It is
        // sent zeroed rather than omitted because the client hides the whole
        // statistics box unless both halves are present.
        from_server: local.then_some(tcp::user_stats::Stats {
            good: Some(target.reported.good),
            late: Some(target.reported.late),
            lost: Some(target.reported.lost),
            resync: Some(target.reported.resync),
        }),
        from_client: local.then(tcp::user_stats::Stats::default),
        ..tcp::UserStats::default()
    }
}

/// Whether this `UserState` is a moderator's speak-state change.
///
/// Grouped exactly as murmur groups them (`Messages.cpp:1130`), because they
/// share one permission and one refusal — splitting them would mean four
/// chances to check three of them.
fn is_speak_state(state: &tcp::UserState) -> bool {
    state.mute.is_some()
        || state.deaf.is_some()
        || state.suppress.is_some()
        || state.priority_speaker.is_some()
}

/// Whether this `UserState` is about channel listeners.
///
/// All three fields together, because they are one feature and one handler: a
/// volume adjustment on its own is still a listener change, and routing it
/// anywhere else would leave the slider working only when the user happened to
/// toggle a channel in the same message.
fn is_listen_state(state: &tcp::UserState) -> bool {
    !state.listening_channel_add.is_empty()
        || !state.listening_channel_remove.is_empty()
        || !state.listening_volume_adjustment.is_empty()
}

/// Tell everyone what changed about a session's listeners.
///
/// Two shapes, decided by `broadcast_volume`:
///
/// * **on** — one message to everybody, gains included.
/// * **off** (the default) — the channels to everybody and the gains to their
///   owner alone, which takes two messages because one message cannot have two
///   audiences. murmur sends the same `UserState` twice, appending the
///   adjustments before the second send (`Messages.cpp:1599`).
fn announce_listeners(
    inbound: &Inbound,
    outcome: &starling_proto_fancy::metadata::ListenResult,
    broadcast_volume: bool,
) -> Actions {
    // Sorted, because the source is a `HashMap`: an unstable order would make
    // the same change produce different bytes each time, which is invisible in
    // production and turns any test that reads the message into a coin flip.
    let mut adjustments: Vec<tcp::user_state::VolumeAdjustment> = outcome
        .volume
        .iter()
        .map(|(channel, gain)| tcp::user_state::VolumeAdjustment {
            listening_channel: Some(*channel),
            volume_adjustment: Some(*gain),
        })
        .collect();
    adjustments.sort_by_key(|adjustment| adjustment.listening_channel);

    let mut echo = tcp::UserState {
        session: Some(inbound.session),
        actor: Some(inbound.session),
        listening_channel_add: outcome.added.clone(),
        listening_channel_remove: outcome.removed.clone(),
        ..tcp::UserState::default()
    };

    if broadcast_volume {
        echo.listening_volume_adjustment = adjustments;
        return vec![to_sessions(Vec::new(), USER_STATE, echo.encode_to_vec())];
    }

    let mut actions = Actions::new();
    if !echo.listening_channel_add.is_empty() || !echo.listening_channel_remove.is_empty() {
        actions.push(to_sessions(Vec::new(), USER_STATE, echo.encode_to_vec()));
    }
    if !adjustments.is_empty() {
        let mine = tcp::UserState {
            session: Some(inbound.session),
            actor: Some(inbound.session),
            listening_volume_adjustment: adjustments,
            ..tcp::UserState::default()
        };
        actions.push(to_conn(inbound.conn, USER_STATE, mine.encode_to_vec()));
    }
    actions
}

/// Tell the client which listener ceiling refused it.
///
/// `PERM_DENIED_FALLBACK` in murmur (`Messages.cpp:1179`): the typed refusal for
/// a client that knows the enum, and a sentence for one that does not. Both are
/// sent, because the two deny types post-date Mumble 1.4 and an older client
/// shows the text.
fn listener_limit_denied(
    inbound: &Inbound,
    refusal: &starling_proto_fancy::metadata::ListenRefusal,
) -> ServerAction {
    use starling_proto::proto::tcp::permission_denied::DenyType;
    use starling_proto_fancy::metadata::listen_refusal::Limit;

    let (kind, reason) = match refusal.limit() {
        Limit::ChannelFull => (
            DenyType::ChannelListenerLimit,
            "No more listeners allowed in this channel",
        ),
        Limit::UserFull => (
            DenyType::UserListenerLimit,
            "No more listeners allowed for this user",
        ),
    };
    refused_with(inbound, kind, refusal.channel, reason)
}

/// Whether this `UserState` carries a comment or an avatar.
///
/// Aimed at the sender it is a profile edit; aimed at anybody else it is a
/// reset, and the two are different permissions and different handlers.
fn is_user_content(state: &tcp::UserState) -> bool {
    state.comment.is_some() || state.texture.is_some()
}

/// Whether this `UserState` is an action a client may aim at somebody else.
///
/// The **one** list of them, because the cross-session refusal in
/// [`SessionLifecycleService::on_user_state`] is written as its negation: an
/// action missing from here is not refused loudly, it is dropped in silence, and
/// a dropped `UserState` looks exactly like a server that is working. That is
/// how moving another user (`docs/GAP-ANALYSIS.md` U2) came to be fully
/// implemented in [`SessionLifecycleService::on_move`], permission checks and
/// all, and unreachable — the dispatch above it dropped the message before the
/// handler was ever asked.
///
/// Every one of these is checked against a permission by the handler it reaches.
/// This decides only *which question gets asked*, never the answer.
fn moderates(state: &tcp::UserState) -> bool {
    // Mute, deafen, suppress, priority speaker — `MuteDeafen` on the target's
    // channel.
    is_speak_state(state)
        // A move — `Move` on the source, and `Move` on the destination or the
        // moved user's own `Enter`.
        || state.channel_id.is_some()
        // A reset — `ResetUserContent` on the root, and only ever to empty.
        || is_user_content(state)
}

/// Whether this `UserState` would take something away from the user it names.
///
/// The same group as [`is_speak_state`] minus `priority_speaker`, and the
/// distinction the SuperUser guard turns on: those three silence somebody,
/// while priority speaker grants them precedence. A message carrying both is
/// restrictive — otherwise attaching a grant to a mute would carry the mute
/// past the guard.
fn restricts(state: &tcp::UserState) -> bool {
    state.mute.is_some() || state.deaf.is_some() || state.suppress.is_some()
}

/// Whether a speak-state field belongs in the echo, and what it should say.
///
/// Present when the moderator asked for it, or when the server changed it on
/// its own through murmur's couplings — deafening also mutes, un-muting also
/// un-deafens. Absent when it was neither asked for nor touched, because a
/// client reads a *present* field as an event worth announcing: restating an
/// unchanged `false` is how a mute came to be logged as three separate actions.
const fn echoed(requested: Option<bool>, before: bool, after: bool) -> Option<bool> {
    if requested.is_some() || before != after {
        Some(after)
    } else {
        None
    }
}

/// The permission a registration takes (`Messages.cpp:1204`).
///
/// Two, not one, and the difference is the point: `SelfRegister` lets people
/// claim their own name, `Register` lets somebody name anyone. A server that
/// hands out the first has not handed out the second, so swapping these would
/// quietly promote every self-registering user into an account administrator.
const fn registration_permission(own: bool) -> Perm {
    if own {
        Perm::SELF_REGISTER
    } else {
        Perm::REGISTER
    }
}

/// A refusal carrying prose, for a failure that is not about permissions.
///
/// murmur's `DenyType::Text` — the client renders `reason` verbatim. Used where
/// the request was allowed but could not be carried out, which a permission
/// refusal would describe wrongly: the user would go looking for a missing
/// grant that nobody can give them.
fn refused(inbound: &Inbound, reason: &str) -> ServerAction {
    let denied = tcp::PermissionDenied {
        r#type: Some(tcp::permission_denied::DenyType::Text as i32),
        session: Some(inbound.session),
        reason: Some(reason.to_owned()),
        ..tcp::PermissionDenied::default()
    };
    to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

/// A `PermissionDenied` that names a reason other than a missing bit.
fn deny(inbound: &Inbound, kind: tcp::permission_denied::DenyType) -> ServerAction {
    let denied = tcp::PermissionDenied {
        r#type: Some(kind as i32),
        session: Some(inbound.session),
        ..tcp::PermissionDenied::default()
    };
    to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

/// Whole seconds between `then` and `now`, saturating.
///
/// Saturating rather than wrapping because the two timestamps come from
/// different moments of `now_ms()`, and a clock that steps backwards would
/// otherwise report a connection that has been online for half the age of the
/// universe.
fn seconds_since(then_ms: u64, now_ms: u64) -> u32 {
    u32::try_from(now_ms.saturating_sub(then_ms) / 1000).unwrap_or(u32::MAX)
}

/// A peer address as Mumble's wire form: sixteen raw bytes.
///
/// Not the `host:port` string it is stored as. Mumble's `HostAddress` is always
/// an IPv6 address — an IPv4 peer is carried as the v4-mapped `::ffff:a.b.c.d`
/// — and a client that is handed anything else renders the address field as
/// nonsense rather than failing visibly.
fn address_bytes(peer: &str) -> Vec<u8> {
    let host = match peer.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => peer.rsplit_once(':').map_or(peer, |(host, _)| host),
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.to_ipv6_mapped().octets().to_vec(),
        Ok(std::net::IpAddr::V6(v6)) => v6.octets().to_vec(),
        // Unparseable means the gateway reported something unexpected. Absent
        // is better than sixteen misleading bytes.
        Err(_) => Vec::new(),
    }
}

/// How many session ids to mint, from the deployment's own limit.
fn max_users(ctx: &ServiceContext) -> u32 {
    ctx.service().option::<u32>("max_users").unwrap_or(100)
}

/// How long a connection may go unheard from before it is reaped.
///
/// 30 seconds, which is murmur's default (`vendor/server/src/murmur/Meta.cpp:62`).
/// A Mumble client pings every few seconds, so this is many missed pings rather
/// than one unlucky one.
fn timeout_ms(ctx: &ServiceContext) -> u64 {
    ctx.service()
        .option::<u64>("timeout_ms")
        .unwrap_or(30_000)
        .max(SWEEP_INTERVAL_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_of_zero_means_no_limit() {
        // murmur reads 0 as "unlimited" throughout its configuration. Reading it
        // as "nothing is allowed" would make an operator who switched the limit
        // off find that avatars stopped working entirely.
        assert!(!over(10_000_000, 0));
        assert!(!over(0, 0));
    }

    #[test]
    fn content_is_refused_only_past_the_limit() {
        // Boundary either side: exactly at the limit is allowed, one past is not.
        assert!(!over(128, 128));
        assert!(over(129, 128));
        assert!(!over(0, 128));
    }

    #[test]
    fn a_comment_and_an_avatar_land_in_different_account_fields() {
        // The pair that got out of step: comments were stored and avatars were
        // decoded and dropped. Writing an avatar into `comment_hash` would be
        // the same class of bug wearing a different face.
        assert_eq!(UserContent::Comment.field(), "comment_hash");
        assert_eq!(UserContent::Texture.field(), "texture_hash");
        assert_ne!(UserContent::Comment, UserContent::Texture);
    }

    #[test]
    fn oversized_content_is_refused_as_too_long_not_as_forbidden() {
        // A client renders the two differently, and only one of them tells the
        // user something they can act on: shrink the picture.
        let refusal = too_long(&Inbound {
            conn: 1,
            session: 7,
            type_id: USER_STATE,
            payload: Vec::new(),
            gateway: String::new(),
            scope: 1,
        });
        let Some(server_action::Action::Send(send)) = refusal.action else {
            panic!("a refusal is a send");
        };
        assert_eq!(send.r#type, u32::from(PERMISSION_DENIED));
        let denied = tcp::PermissionDenied::decode(send.payload.as_slice()).expect("well-formed");
        assert_eq!(
            denied.r#type,
            Some(tcp::permission_denied::DenyType::TextTooLong as i32)
        );
        assert_eq!(denied.session, Some(7));
    }

    #[test]
    fn an_address_is_encoded_as_the_sixteen_bytes_mumble_expects() {
        // Mumble's `HostAddress` is always IPv6; a v4 peer travels v4-mapped.
        // Sending the `host:port` string instead — which is how it is stored —
        // makes a client render the address field as rubbish.
        let v4 = address_bytes("172.26.0.1:51454");
        assert_eq!(v4.len(), 16);
        assert_eq!(&v4[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(&v4[12..], &[172, 26, 0, 1]);
    }

    #[test]
    fn an_ipv6_peer_keeps_its_own_sixteen_bytes() {
        let v6 = address_bytes("[2001:db8::1]:64738");
        assert_eq!(v6.len(), 16);
        assert_eq!(v6[0], 0x20);
        assert_eq!(v6[1], 0x01);
        assert_eq!(v6[15], 1);
    }

    #[test]
    fn an_unparseable_address_is_absent_rather_than_invented() {
        assert!(address_bytes("not-an-address").is_empty());
        assert!(address_bytes("").is_empty());
    }

    #[test]
    fn a_clock_that_steps_backwards_does_not_report_an_absurd_uptime() {
        // The two timestamps come from different calls to `now_ms`.
        assert_eq!(seconds_since(9_000, 1_000), 0);
        assert_eq!(seconds_since(1_000, 9_000), 8);
    }

    fn somebody() -> PendingConnection {
        PendingConnection {
            session: 7,
            address: "10.0.0.4:51882".to_owned(),
            release: "Mumble 1.5.735".to_owned(),
            os: "Windows".to_owned(),
            os_version: "11".to_owned(),
            mumble_version: 0x0001_0005_0000,
            connected_at_ms: 1_000,
            last_seen_ms: 5_000,
            ..PendingConnection::default()
        }
    }

    /// The client shows the *Connection* box only if one of these arrived.
    fn connection_box_shown(stats: &tcp::UserStats) -> bool {
        !stats.certificates.is_empty() || stats.address.is_some() || stats.version.is_some()
    }

    /// …and the *UDP statistics* box only if both of these did.
    fn statistics_box_shown(stats: &tcp::UserStats) -> bool {
        stats.from_client.is_some() && stats.from_server.is_some()
    }

    #[test]
    fn asking_about_yourself_fills_both_halves_of_the_dialog() {
        let stats = user_stats(&somebody(), true, true, 9_000);
        assert!(connection_box_shown(&stats));
        assert!(statistics_box_shown(&stats));
        let version = stats.version.expect("the client build is the point of it");
        assert_eq!(version.release.as_deref(), Some("Mumble 1.5.735"));
        assert_eq!(stats.onlinesecs, Some(8));
        assert_eq!(stats.idlesecs, Some(4));
    }

    #[test]
    fn an_administrator_sees_another_users_details() {
        // murmur extends the full record to whoever holds Ban on the root
        // channel (`Messages.cpp:3206`). Without this the admin's window is
        // the empty one that started this.
        let stats = user_stats(&somebody(), true, true, 9_000);
        assert!(stats.address.is_some(), "an admin is shown the address");
        assert!(connection_box_shown(&stats));
    }

    #[test]
    fn an_ordinary_user_gets_a_dialog_with_something_in_it() {
        // No details for somebody else — murmur withholds those too — but the
        // statistics half must still arrive, or the window opens blank. This
        // is the exact regression: correct data, nothing rendered.
        let stats = user_stats(&somebody(), false, true, 9_000);
        assert!(
            !connection_box_shown(&stats),
            "another user's address and client build are not public"
        );
        assert!(
            statistics_box_shown(&stats),
            "the statistics box is what stops the dialog being empty"
        );
        assert_eq!(stats.onlinesecs, Some(8));
    }

    #[test]
    fn what_the_client_measured_is_reported_back() {
        // The ping panel used to read all zeros because the server tried to be
        // the source of numbers only the client can produce. These come from
        // the peer's own `Ping`.
        let mut peer = somebody();
        peer.reported = ReportedStats {
            good: 4_100,
            late: 7,
            lost: 3,
            resync: 1,
            udp_packets: 4_110,
            tcp_packets: 52,
            udp_ping_avg: 18.5,
            tcp_ping_avg: 21.25,
            ..ReportedStats::default()
        };
        let stats = user_stats(&peer, true, true, 9_000);

        assert_eq!(stats.tcp_packets, Some(52));
        assert_eq!(stats.udp_packets, Some(4_110));
        assert_eq!(stats.tcp_ping_avg, Some(21.25));
        assert_eq!(stats.udp_ping_avg, Some(18.5));

        // Direction matters and is easy to invert: what the *client* counted is
        // what it received from the server, so it belongs in `from_server`.
        // Swapping these compiles, renders, and is quietly wrong.
        let from_server = stats.from_server.expect("local");
        assert_eq!(from_server.good, Some(4_100));
        assert_eq!(from_server.lost, Some(3));
        // Present but empty: the server's own crypt counters live in voice and
        // are not reported here yet. What matters is that the message *exists*,
        // because the client hides the whole statistics box without it and
        // reads an unset counter as zero regardless.
        assert!(
            stats.from_client.is_some(),
            "omitting this hides the statistics box the other half fills"
        );
    }

    #[test]
    fn a_peer_that_has_reported_nothing_yet_reports_zeros_not_stale_figures() {
        // A connection that has not sent a `Ping` yet has nothing to repeat.
        // Zero is the honest answer here — unlike `bandwidth` below, these are
        // counters whose true value at this moment *is* zero, and the panel
        // that displays them is already visible.
        let stats = user_stats(&somebody(), true, true, 9_000);
        assert_eq!(stats.tcp_packets, Some(0));
        assert_eq!(stats.tcp_ping_avg, Some(0.0));
    }

    #[test]
    fn the_superuser_guard_covers_every_way_of_silencing_them() {
        // `MuteDeafen` in the root channel must not be enough to silence the one
        // account that can repair the ACL table which handed it out.
        for state in [
            tcp::UserState {
                mute: Some(true),
                ..tcp::UserState::default()
            },
            tcp::UserState {
                deaf: Some(true),
                ..tcp::UserState::default()
            },
            tcp::UserState {
                suppress: Some(true),
                ..tcp::UserState::default()
            },
        ] {
            assert!(restricts(&state), "{state:?} silences its target");
            assert!(is_speak_state(&state));
        }
    }

    #[test]
    fn making_the_superuser_a_priority_speaker_is_not_caught_by_the_guard() {
        // The deliberate divergence from murmur, which refuses this
        // (`Messages.cpp:1131` takes all four flags in one block) and so leaves
        // no account anywhere that can make the administrator a priority
        // speaker. Nothing is taken away here, which is what the guard is for.
        let state = tcp::UserState {
            priority_speaker: Some(true),
            ..tcp::UserState::default()
        };
        assert!(!restricts(&state), "a grant takes nothing away");
        assert!(
            is_speak_state(&state),
            "it still needs MuteDeafen on the target's channel"
        );
    }

    #[test]
    fn a_mute_riding_along_with_a_priority_flag_still_meets_the_guard() {
        // The bypass the split would otherwise open: one message carrying both,
        // so that attaching a grant to a mute walks the mute past the guard and
        // silences the administrator after all.
        let state = tcp::UserState {
            mute: Some(true),
            priority_speaker: Some(true),
            ..tcp::UserState::default()
        };
        assert!(restricts(&state));
    }

    #[test]
    fn muting_someone_announces_a_mute_and_nothing_else() {
        // The reported bug, exactly: muting logged "You gave priority speaker
        // status to X" and "You undeafened X" as well, because the echo carried
        // all three fields and a client logs one line per field *present*.
        // Nobody was given priority speaker and nobody was un-deafened.
        assert_eq!(echoed(Some(true), false, true), Some(true), "the mute");
        assert_eq!(
            echoed(None, false, false),
            None,
            "an untouched deafen must not appear at all"
        );
        assert_eq!(
            echoed(None, false, false),
            None,
            "nor an untouched priority speaker"
        );
    }

    #[test]
    fn a_coupling_the_server_forced_is_still_announced() {
        // The other half, and why the fix is not simply "echo what was asked".
        // Deafening also mutes (`Messages.cpp:1303`), and a client told only
        // about the deafen would render a user who is deaf but not muted.
        assert_eq!(
            echoed(None, false, true),
            Some(true),
            "a mute the server forced must be announced though nobody asked"
        );
        assert_eq!(
            echoed(None, true, false),
            Some(false),
            "and so must a deafen it cleared on un-mute"
        );
    }

    #[test]
    fn restating_a_field_at_the_value_it_already_held_still_counts_as_asking() {
        // Muting an already-muted user is a no-op in state but not in intent,
        // and murmur echoes what it was sent. The line is honest — somebody did
        // press mute — so this is deliberately not filtered out.
        assert_eq!(echoed(Some(true), true, true), Some(true));
    }

    #[test]
    fn claiming_your_own_name_and_naming_someone_else_are_different_permissions() {
        // Swapping these is invisible — registration still works, and every
        // user who may claim their own name may now register anybody.
        assert_eq!(registration_permission(true), Perm::SELF_REGISTER);
        assert_eq!(registration_permission(false), Perm::REGISTER);
        assert_ne!(Perm::SELF_REGISTER, Perm::REGISTER);
    }

    #[test]
    fn a_registration_is_routed_by_user_id_whoever_it_names() {
        // The field that decides it, and the reason the check sits ahead of the
        // cross-session refusal: registering somebody else names another
        // session, which is exactly what that refusal drops. This is the
        // regression that made the client's Register button do nothing.
        let registering = tcp::UserState {
            session: Some(9),
            user_id: Some(0),
            ..tcp::UserState::default()
        };
        assert!(registering.user_id.is_some());
        assert!(
            !is_speak_state(&registering),
            "a registration is not a speak-state change and must not be read as one"
        );
    }

    #[test]
    fn dragging_somebody_into_a_channel_reaches_its_handler() {
        // The U2 regression, and the shape of it is worth keeping: `on_move`
        // had the whole rule — `Move` on the source, `Move` or the target's own
        // `Enter` on the destination — and was unreachable for anyone but the
        // sender, because the cross-session refusal above it dropped the
        // message first. Nothing failed and nothing was logged; the user simply
        // did not move.
        let drag = tcp::UserState {
            session: Some(9),
            channel_id: Some(4),
            ..tcp::UserState::default()
        };
        assert!(
            moderates(&drag),
            "a move must survive the cross-session guard"
        );
        assert!(
            !is_speak_state(&drag),
            "and must not be mistaken for a mute, which checks a different permission"
        );
    }

    #[test]
    fn clearing_somebody_elses_profile_reaches_its_handler() {
        for state in [
            tcp::UserState {
                session: Some(9),
                comment: Some(String::new()),
                ..tcp::UserState::default()
            },
            tcp::UserState {
                session: Some(9),
                texture: Some(Vec::new()),
                ..tcp::UserState::default()
            },
        ] {
            assert!(is_user_content(&state));
            assert!(moderates(&state), "{state:?} is a ResetUserContent");
        }
    }

    #[test]
    fn a_bare_self_mute_is_not_moderation() {
        // The other direction: the guard still has to refuse a message that
        // names somebody else and carries only fields a user sets on themselves.
        // Letting those through would make self-mute a way to mute anybody.
        let selfish = tcp::UserState {
            session: Some(9),
            self_mute: Some(true),
            self_deaf: Some(true),
            ..tcp::UserState::default()
        };
        assert!(!moderates(&selfish));
        assert!(!is_user_content(&selfish));
    }

    #[test]
    fn a_failure_that_is_not_about_permissions_is_told_as_prose() {
        // A taken name is not a missing grant. Reporting it as one sends the
        // user looking for a permission nobody can give them.
        let refusal = refused(
            &Inbound {
                conn: 1,
                session: 7,
                type_id: USER_STATE,
                payload: Vec::new(),
                gateway: String::new(),
                scope: 1,
            },
            "the name \"sebastian\" is already registered",
        );
        let Some(server_action::Action::Send(send)) = refusal.action else {
            panic!("a refusal is a send");
        };
        let denied = tcp::PermissionDenied::decode(send.payload.as_slice()).expect("well-formed");
        assert_eq!(
            denied.r#type,
            Some(tcp::permission_denied::DenyType::Text as i32)
        );
        assert!(
            denied
                .reason
                .is_some_and(|reason| reason.contains("already")),
            "the client renders this string and it is all the user is told"
        );
    }

    #[test]
    fn bandwidth_stays_absent_because_nothing_measures_it() {
        // The one field with no source at all: it is neither measured here nor
        // reported by the client. Absent leaves the client's label blank, which
        // is true; a zero would claim the peer is sending nothing.
        let stats = user_stats(&somebody(), true, true, 9_000);
        assert_eq!(stats.bandwidth, None);
    }
}
