//! The handshake, in murmur's exact order.
//!
//! Verified against `vendor/server/src/murmur/Messages.cpp` and `Server.cpp`:
//!
//! ```text
//! Version (server-first, on TLS established, Server.cpp:1668)
//!   → client Version → client Authenticate
//!   → CryptSetup → CodecVersion
//!   → ChannelState × N (BFS from root)
//!   → own UserState → other UserStates
//!   → ServerSync → ServerConfig → SuggestConfig
//! ```
//!
//! The ordering is not cosmetic. `Messages.cpp:775` is explicit that listeners
//! must come *after* `ServerSync`, and a client that tolerates a different
//! order in development can hang against it in the wild (`PORTING-PLAN.md` R4).
//!
//! Every call out of here goes to the service that owns the answer: userdata
//! authenticates, voice mints the cipher, metadata supplies the tree,
//! server-config supplies the limits, and session-view is told the outcome.

use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::control::{ServerAction, SessionUp, server_action};
use starling_proto_fancy::fancy::session::{SessionEnvelope, session_envelope};
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::metadata::{EnterRequest, TreeRequest};
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::serverconfig::{GetRequest, Snapshot};
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::sessionview::{Announcement, Gone, Session, announcement};
use starling_proto_fancy::types::ServiceKind;
use starling_proto_fancy::userdata::user_data_client::UserDataClient;
use starling_proto_fancy::userdata::{AuthRequest, auth_result};
use starling_proto_fancy::voice::voice_client::VoiceClient;
use starling_proto_fancy::voice::MintRequest;
use starling_runtime::channel::Resolver;
use starling_runtime::ids::now_ms;
use starling_runtime::plane::{Actions, Fanout, Inbound, broadcast_except, to_conn};
use starling_runtime::serve::ServiceContext;

use crate::state::Connections;

/// The Mumble version Starling announces.
///
/// 1.6.0: the protobuf UDP format is available from 1.5.0, and announcing less
/// would pin every client to the legacy audio framing.
const MUMBLE_VERSION_V2: u64 = 0x0001_0006_0000;

/// Everything the handshake needs to reach.
#[derive(Debug, Clone)]
pub struct Handshake {
    resolver: Resolver,
    fanout: Fanout,
    ctx: ServiceContext,
}

/// The `Version` Starling sends first, before the client has said anything.
#[must_use]
pub fn server_version() -> tcp::Version {
    tcp::Version {
        version_v2: Some(MUMBLE_VERSION_V2),
        release: Some(format!("Starling {}", env!("CARGO_PKG_VERSION"))),
        os: Some(std::env::consts::OS.to_owned()),
        os_version: Some(std::env::consts::ARCH.to_owned()),
        ..tcp::Version::default()
    }
}

impl Handshake {
    /// A handshake over `resolver`.
    #[must_use]
    pub fn new(resolver: Resolver, fanout: Fanout, ctx: ServiceContext) -> Self {
        Self {
            resolver,
            fanout,
            ctx,
        }
    }

    /// The whole handshake, from `Authenticate` to `SuggestConfig`.
    pub async fn authenticate(&self, connections: &Connections, inbound: &Inbound) -> Actions {
        let Ok(request) = tcp::Authenticate::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        let Some(pending) = connections.get(inbound.conn) else {
            return Actions::new();
        };

        let config = self.config(inbound.scope).await;
        if !config.password.is_empty()
            && request.password.as_deref().unwrap_or_default() != config.password
        {
            return vec![reject(
                inbound.conn,
                tcp::reject::RejectType::WrongServerPw,
                "wrong server password",
            )];
        }

        let name = request.username.clone().unwrap_or_default();
        let outcome = self.identify(inbound.scope, &name, &request, &pending).await;
        let (account, name) = match outcome {
            Ok(identity) => identity,
            Err(action) => return vec![action],
        };

        let Some(session) = connections.allocate(inbound.conn, account, &name) else {
            return vec![reject(
                inbound.conn,
                tcp::reject::RejectType::ServerFull,
                "the server is full",
            )];
        };

        let mut actions = Vec::new();
        actions.push(self.crypt_setup(inbound, session, &pending).await);
        actions.push(to_conn(inbound.conn, 21, codec_version().encode_to_vec()));
        actions.extend(self.channel_flood(inbound).await);
        actions.extend(self.user_states(inbound, session, &name).await);
        actions.push(to_conn(
            inbound.conn,
            5,
            server_sync(session, &config).encode_to_vec(),
        ));
        actions.push(to_conn(
            inbound.conn,
            24,
            server_config(&config).encode_to_vec(),
        ));
        actions.push(to_conn(
            inbound.conn,
            25,
            tcp::SuggestConfig::default().encode_to_vec(),
        ));

        // The gateway learns the conn↔session mapping from this and nothing
        // else, so it is sent after the client's own view is complete.
        actions.push(ServerAction {
            action: Some(server_action::Action::SessionUp(SessionUp {
                conn: inbound.conn,
                session,
                account,
                name: name.clone(),
                channel: 0,
                fancy_version: pending.fancy_version,
            })),
        });

        // Legacy clients get no subscription and no resync on demand — the
        // flood is the only way they ever learn someone joined
        // (`docs/ARCHITECTURE.md` §6). Excluding the new session is not an
        // optimisation: it already received this exact `UserState` as its own
        // in `user_states`, in handshake order, and a second copy arriving
        // out of order would desync a client that keys off first-seen.
        let joined = tcp::UserState {
            session: Some(session),
            name: Some(name.clone()),
            channel_id: Some(0),
            ..tcp::UserState::default()
        };
        actions.push(broadcast_except(session, 9, joined.encode_to_vec()));

        self.announce_up(inbound, session, account, &name).await;
        self.enter_root(inbound.scope, session).await;
        actions
    }

    /// Who the peer is, or the rejection to send.
    async fn identify(
        &self,
        scope: u32,
        name: &str,
        request: &tcp::Authenticate,
        pending: &crate::state::PendingConnection,
    ) -> Result<(u64, String), ServerAction> {
        let Ok(channel) = self.resolver.channel("userdata").await else {
            // Userdata is essential: without it a login cannot be decided, and
            // guessing would either lock everyone out or let everyone in.
            return Err(reject(
                pending.conn,
                tcp::reject::RejectType::None,
                "the account service is unavailable",
            ));
        };
        let result = UserDataClient::new(channel)
            .authenticate(AuthRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
                name: name.to_owned(),
                password: request.password.clone().unwrap_or_default(),
                cert_hash: pending.cert_hash.clone(),
                strong_cert: pending.strong_cert,
                totp: String::new(),
            })
            .await;

        let Ok(result) = result else {
            return Err(reject(
                pending.conn,
                tcp::reject::RejectType::None,
                "the account service refused the request",
            ));
        };
        let result = result.into_inner();
        let outcome = auth_result::Outcome::try_from(result.outcome)
            .unwrap_or(auth_result::Outcome::UnknownAccount);

        match outcome {
            auth_result::Outcome::Ok => Ok((
                result.account.as_ref().map_or(0, |account| account.id),
                result
                    .account
                    .map_or_else(|| name.to_owned(), |account| account.name),
            )),
            auth_result::Outcome::WrongPassword => Err(reject(
                pending.conn,
                tcp::reject::RejectType::WrongUserPw,
                "wrong password",
            )),
            auth_result::Outcome::NameTaken => Err(reject(
                pending.conn,
                tcp::reject::RejectType::UsernameInUse,
                "that name is registered to another certificate",
            )),
            auth_result::Outcome::CertRequired => Err(reject(
                pending.conn,
                tcp::reject::RejectType::NoCertificate,
                "this server requires a certificate",
            )),
            auth_result::Outcome::InvalidName => Err(reject(
                pending.conn,
                tcp::reject::RejectType::InvalidUsername,
                "that name is not allowed",
            )),
            // The fork carries these two so a client can retry with a code
            // rather than guess why it was refused.
            auth_result::Outcome::TotpRequired => Err(reject(
                pending.conn,
                tcp::reject::RejectType::TotpRequired,
                "this account requires a one-time code",
            )),
            auth_result::Outcome::TotpInvalid => Err(reject(
                pending.conn,
                tcp::reject::RejectType::TotpInvalid,
                "that one-time code is wrong",
            )),
            auth_result::Outcome::UnknownAccount => Err(reject(
                pending.conn,
                tcp::reject::RejectType::AuthenticatorFail,
                "authentication failed",
            )),
        }
    }

    /// `CryptSetup`, minted by voice.
    ///
    /// The key seals UDP, so voice generates it and this service forwards a
    /// ready-made payload. Key material never crosses a service boundary in a
    /// form anything else could read (`docs/ARCHITECTURE.md` §4).
    async fn crypt_setup(
        &self,
        inbound: &Inbound,
        session: u32,
        pending: &crate::state::PendingConnection,
    ) -> ServerAction {
        let payload = match self.resolver.channel("voice").await {
            Ok(channel) => VoiceClient::new(channel)
                .mint(MintRequest {
                    scope: Some(starling_proto_fancy::common::Scope {
                        virtual_server: inbound.scope,
                    }),
                    session,
                    fancy_version: pending.fancy_version,
                    mumble_version: pending.mumble_version,
                    address: pending.address.clone(),
                })
                .await
                .map(|material| material.into_inner().crypt_setup)
                .unwrap_or_default(),
            // Voice down means no UDP audio, not no login: the client falls
            // back to tunnelling, which is exactly what that fallback is for.
            Err(_) => Vec::new(),
        };
        to_conn(inbound.conn, 15, payload)
    }

    /// Every channel, breadth-first from the root.
    async fn channel_flood(&self, inbound: &Inbound) -> Actions {
        let Ok(channel) = self.resolver.channel("metadata").await else {
            return Actions::new();
        };
        let Ok(tree) = MetadataClient::new(channel)
            .get_tree(TreeRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: inbound.scope,
                }),
            })
            .await
        else {
            return Actions::new();
        };

        let mut channels = tree.into_inner().channels;
        // Breadth-first: a client cannot render a channel before its parent
        // exists, and murmur sends them in this order for the same reason.
        channels.sort_by_key(|channel| (channel.parent.unwrap_or(0), channel.id));
        channels
            .into_iter()
            .map(|channel| {
                let state = tcp::ChannelState {
                    channel_id: Some(channel.id),
                    parent: channel.parent,
                    name: Some(channel.name),
                    description: Some(channel.description),
                    position: Some(channel.position),
                    max_users: Some(channel.max_users),
                    links: channel.links,
                    ..tcp::ChannelState::default()
                };
                to_conn(inbound.conn, 7, state.encode_to_vec())
            })
            .collect()
    }

    /// The client's own `UserState`, then everyone else's.
    async fn user_states(&self, inbound: &Inbound, session: u32, name: &str) -> Actions {
        let own = tcp::UserState {
            session: Some(session),
            name: Some(name.to_owned()),
            channel_id: Some(0),
            ..tcp::UserState::default()
        };
        let mut actions = vec![to_conn(inbound.conn, 9, own.encode_to_vec())];

        let Ok(channel) = self.resolver.channel("session-view").await else {
            return actions;
        };
        let Ok(sessions) = SessionViewClient::new(channel)
            .list(starling_proto_fancy::sessionview::SubscribeRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: inbound.scope,
                }),
                subscriber: "session-lifecycle".to_owned(),
            })
            .await
        else {
            return actions;
        };

        for other in sessions.into_inner().sessions {
            if other.session == session {
                continue;
            }
            let state = tcp::UserState {
                session: Some(other.session),
                name: Some(other.name),
                channel_id: Some(other.channel),
                self_mute: Some(other.self_mute),
                self_deaf: Some(other.self_deaf),
                ..tcp::UserState::default()
            };
            actions.push(to_conn(inbound.conn, 9, state.encode_to_vec()));
        }
        actions
    }

    /// Tell session-view a session exists.
    async fn announce_up(&self, inbound: &Inbound, session: u32, account: u64, name: &str) {
        let announcement = Announcement {
            scope: Some(starling_proto_fancy::common::Scope {
                virtual_server: inbound.scope,
            }),
            what: Some(announcement::What::Up(Session {
                session,
                conn: inbound.conn,
                gateway_id: inbound.gateway.clone(),
                account,
                name: name.to_owned(),
                channel: 0,
                connected_at_ms: now_ms(),
                ..Session::default()
            })),
        };
        self.announce(announcement).await;
    }

    /// Tell session-view a session has changed.
    pub async fn announce_changed(&self, connections: &Connections, conn: u64) {
        let Some(pending) = connections.get(conn) else {
            return;
        };
        self.announce(Announcement {
            scope: Some(starling_proto_fancy::common::Scope {
                virtual_server: pending.scope,
            }),
            what: Some(announcement::What::Changed(Session {
                session: pending.session,
                conn,
                gateway_id: pending.gateway,
                account: pending.account,
                name: pending.name,
                channel: pending.channel,
                self_mute: pending.self_mute,
                self_deaf: pending.self_deaf,
                ..Session::default()
            })),
        })
        .await;
    }

    /// Tell session-view a session has gone.
    pub async fn announce_down(&self, session: u32, reason: &str) {
        self.announce(Announcement {
            scope: Some(starling_proto_fancy::common::Scope { virtual_server: 1 }),
            what: Some(announcement::What::Down(Gone {
                session,
                reason: reason.to_owned(),
            })),
        })
        .await;
    }

    async fn announce(&self, announcement: Announcement) {
        let Ok(channel) = self.resolver.channel("session-view").await else {
            return;
        };
        if let Err(status) = SessionViewClient::new(channel).announce(announcement).await {
            tracing::warn!(%status, "session-view did not accept an announcement");
        }
    }

    /// Put a new session in the root channel.
    async fn enter_root(&self, scope: u32, session: u32) {
        let Ok(channel) = self.resolver.channel("metadata").await else {
            return;
        };
        let _ = MetadataClient::new(channel)
            .enter(EnterRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
                session,
                channel: 0,
            })
            .await;
    }

    /// The Fancy extensions: hello, resume, lazy subscription.
    pub async fn fancy(&self, connections: &Connections, inbound: &Inbound) -> Actions {
        let Ok(envelope) = SessionEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        match envelope.body {
            Some(session_envelope::Body::Hello(_)) => {
                connections.touch(inbound.conn);
                Actions::new()
            }
            Some(session_envelope::Body::Resume(resume)) => {
                // The replay itself is the gateway's: it owns the ring, and a
                // service cannot know what a pod already wrote to a socket.
                let reply = SessionEnvelope {
                    body: Some(session_envelope::Body::ResumeAck(
                        starling_proto_fancy::fancy::session::ResumeAck {
                            accepted: false,
                            from_seq: resume.last_seq,
                            full_resync_required: true,
                            session_token: resume.session_token,
                        },
                    )),
                };
                vec![to_conn(
                    inbound.conn,
                    ServiceKind::SessionLifecycle.outer_type(),
                    reply.encode_to_vec(),
                )]
            }
            _ => Actions::new(),
        }
    }

    /// The operational settings, or the shipped defaults if it is unreachable.
    async fn config(&self, scope: u32) -> Snapshot {
        let fallback = Snapshot {
            virtual_server: scope,
            max_users: 100,
            max_bandwidth: 72_000,
            ..Snapshot::default()
        };
        let Ok(channel) = self.resolver.channel("server-config").await else {
            return fallback;
        };
        ServerConfigClient::new(channel)
            .get(GetRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
            })
            .await
            .map(tonic::Response::into_inner)
            .unwrap_or(fallback)
    }

    /// The fan-out handle, for pushes that are not replies.
    #[must_use]
    pub fn fanout(&self) -> &Fanout {
        &self.fanout
    }

    /// The service context, for diagnostics.
    #[must_use]
    pub fn context(&self) -> &ServiceContext {
        &self.ctx
    }
}

/// A refusal the client can act on.
fn reject(conn: u64, kind: tcp::reject::RejectType, reason: &str) -> ServerAction {
    let payload = tcp::Reject {
        r#type: Some(kind as i32),
        reason: Some(reason.to_owned()),
    }
    .encode_to_vec();
    to_conn(conn, 4, payload)
}

/// The codecs Starling accepts.
///
/// Opus only: every Mumble client since 1.2.4 speaks it, and the server never
/// touches audio content, so there is nothing to gain by negotiating anything
/// older (`PORTING-PLAN.md` §1.2).
fn codec_version() -> tcp::CodecVersion {
    tcp::CodecVersion {
        alpha: -2_147_483_637,
        beta: 0,
        prefer_alpha: true,
        opus: Some(true),
    }
}

/// `ServerSync`: the message that ends the handshake.
fn server_sync(session: u32, config: &Snapshot) -> tcp::ServerSync {
    tcp::ServerSync {
        session: Some(session),
        max_bandwidth: Some(config.max_bandwidth),
        welcome_text: Some(config.welcome_text.clone()),
        // Permissions in the root channel, which the client uses to grey out
        // actions before it has asked about them.
        permissions: Some(u64::from(u32::MAX)),
    }
}

/// `ServerConfig`: the limits a client must respect.
fn server_config(config: &Snapshot) -> tcp::ServerConfig {
    tcp::ServerConfig {
        max_bandwidth: Some(config.max_bandwidth),
        welcome_text: Some(config.welcome_text.clone()),
        allow_html: Some(config.allow_html),
        message_length: Some(config.text_message_length),
        image_message_length: Some(config.image_message_length),
        max_users: Some(config.max_users),
        recording_allowed: Some(config.allow_recording),
        ..tcp::ServerConfig::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_announced_version_is_new_enough_for_protobuf_audio() {
        // Announcing less than 1.5.0 pins every client to the legacy UDP
        // framing, where the packet type is the codec and there is nowhere to
        // name a cipher.
        const { assert!(MUMBLE_VERSION_V2 >= 0x0001_0005_0000) };
        assert_eq!(server_version().version_v2, Some(MUMBLE_VERSION_V2));
    }

    #[test]
    fn the_codec_offer_is_opus() {
        assert_eq!(codec_version().opus, Some(true));
    }

    #[test]
    fn server_sync_carries_the_bandwidth_the_operator_configured() {
        // A client that is not told sends at its own idea of a sensible rate,
        // which is how a server's uplink disappears.
        let config = Snapshot {
            max_bandwidth: 96_000,
            welcome_text: "hello".to_owned(),
            ..Snapshot::default()
        };
        let sync = server_sync(7, &config);
        assert_eq!(sync.max_bandwidth, Some(96_000));
        assert_eq!(sync.welcome_text.as_deref(), Some("hello"));
    }
}
