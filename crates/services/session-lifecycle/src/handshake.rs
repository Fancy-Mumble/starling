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
use starling_proto_fancy::identity;
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::metadata::{EnterRequest, TreeRequest};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::serverconfig::{GetRequest, Snapshot};
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::sessionview::{Announcement, Gone, Session, announcement};
use starling_proto_fancy::types::ServiceKind;
use starling_proto_fancy::userdata::user_data_client::UserDataClient;
use starling_proto_fancy::userdata::{AuthRequest, auth_result};
use starling_proto_fancy::voice::MintRequest;
use starling_proto_fancy::voice::voice_client::VoiceClient;
use starling_runtime::channel::Resolver;
use starling_runtime::log::{Category, LogEvent};
use starling_runtime::plane::{Actions, Fanout, Inbound, broadcast_except, disconnect, to_conn};
use starling_runtime::serve::ServiceContext;

use crate::state::{Connections, Identity, PendingConnection};

/// The Mumble version Starling announces.
///
/// 1.6.0: the protobuf UDP format is available from 1.5.0, and announcing less
/// would pin every client to the legacy audio framing.
///
/// Encoded rather than written out. The literal this replaced was
/// `0x0001_0006_0000`, which is missing the sixteen-bit patch shift and decodes
/// to **0.1.6** — below every feature gate the number exists to pass, and
/// invisible because the handshake completes either way.
const MUMBLE_VERSION_V2: u64 = starling_proto::MUMBLE_VERSION.encode_v2();

/// Upstream `PermissionQuery`, pushed on channel entry as murmur does.
const PERMISSION_QUERY: u16 = 20;

/// The root channel, which is always id 0.
const ROOT_CHANNEL: u32 = 0;

/// `Channel.flags` bit for a hidden channel, from `metadata`'s `tree_actor.rs`.
///
/// Written out rather than imported: a service depending on another service's
/// crate is the coupling the gRPC boundary exists to prevent, and the layout is
/// documented on `Channel.flags` in `metadata.proto`.
const FLAG_HIDDEN: u32 = 1;

/// The Fancy wire epoch Starling speaks (`Mumble.proto`, `Version.fancy_protocol`).
///
/// Epoch 1: upstream 0–99 flat and frozen, every Fancy service behind one outer
/// type ≥ 1000. Starling has never spoken epoch 0's interleaved 100–999 layout,
/// and cannot — `docs/PROTOCOL-COMPATIBILITY.md` §2 explains why that range is
/// unroutable, and §3 is the scheme this number names.
const FANCY_PROTOCOL: u32 = 1;

/// Everything the handshake needs to reach.
#[derive(Debug, Clone)]
pub struct Handshake {
    resolver: Resolver,
    fanout: Fanout,
    ctx: ServiceContext,
}

/// The `Version` Starling sends first, before the client has said anything.
///
/// **`fancy_version` is deliberately absent.** It is a product version, and a
/// client reads it as "this server implements the Fancy features up to X" —
/// then sends those features on epoch 0's numbering, which Starling routes
/// nowhere. Claiming it would therefore *break* clients that work today: with
/// the field absent they fall back to `PluginDataTransmission`, which is
/// epoch-independent and which Starling relays correctly. The epoch below is
/// how a client learns there are Fancy extensions here at all.
#[must_use]
pub fn server_version() -> tcp::Version {
    tcp::Version {
        version_v2: Some(MUMBLE_VERSION_V2),
        fancy_protocol: Some(FANCY_PROTOCOL),
        release: Some(format!("Starling {}", env!("CARGO_PKG_VERSION"))),
        os: Some(std::env::consts::OS.to_owned()),
        os_version: Some(std::env::consts::ARCH.to_owned()),
        ..tcp::Version::default()
    }
}

/// The whole of what a connection is, in the shape `session-view` stores.
///
/// **`Upsert` replaces; it does not merge** (`session-view/src/lib.rs:181`).
/// session-view keeps exactly the `Session` it is handed, so a field omitted
/// here is not left alone — it is written as `false`, `0` or empty. Proto3
/// cannot tell "unset" from "false" for a `bool`, so there is no partial
/// update to send even in principle.
///
/// That is not a hypothetical. `announce_changed` used to rebuild the session
/// without `mute`, `deaf` or `suppress`, and `voice` reads a speaker's silence
/// **only** from session-view (`voice/src/view.rs:146`). So a moderator's mute
/// was applied to the connection record, broadcast to every client, rendered in
/// every user list — and then un-applied in the one place that decides whether
/// the packets are forwarded. The user showed as muted and stayed audible.
///
/// Written out field by field with no `..Session::default()`, which is what hid
/// the omission: a new field on the message should fail to compile here and
/// make somebody choose, rather than silently defaulting on every announcement.
fn session_record(pending: &PendingConnection) -> Session {
    let (account, registered) = identity::wire(pending.account);
    Session {
        session: pending.session,
        conn: pending.conn,
        gateway_id: pending.gateway.clone(),
        account,
        registered,
        name: pending.name.clone(),
        channel: pending.channel,
        self_mute: pending.self_mute,
        self_deaf: pending.self_deaf,
        // The moderator-owned flags. The reason this function exists.
        mute: pending.mute,
        deaf: pending.deaf,
        suppress: pending.suppress,
        priority_speaker: pending.priority_speaker,
        fancy_version: pending.fancy_version,
        address: pending.address.clone(),
        cert_hash: pending.cert_hash.clone(),
        // The account's profile, so that every client that builds its roster
        // from the view — which is every client that was already connected —
        // sees the avatar of someone who joined after it did.
        comment_hash: pending.comment_hash.clone(),
        texture_hash: pending.texture_hash.clone(),
        // From the record, not `now_ms()`: this is the moment the peer
        // connected, and recomputing it on every change would reset the uptime
        // the client shows each time somebody muted them.
        connected_at_ms: pending.connected_at_ms,
        // Nothing populates these yet, and saying so here is the point of
        // writing the fields out. `listening` waits on channel listeners
        // (GAP-ANALYSIS V5), `recording` on a client that reports it, and
        // `max_bandwidth` is a server-config value rather than a per-peer one.
        listening: Vec::new(),
        recording: false,
        max_bandwidth: 0,
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
            // Undecodable at the very first step: almost always a client
            // speaking a different protocol at a Mumble port.
            tracing::warn!(
                conn = inbound.conn,
                len = inbound.payload.len(),
                "undecodable Authenticate"
            );
            self.ctx.logger.log(
                LogEvent::notice(Category::Session, "malformed authentication")
                    .with("conn", inbound.conn),
            );
            return Actions::new();
        };
        let Some(pending) = connections.get(inbound.conn) else {
            tracing::warn!(
                conn = inbound.conn,
                "Authenticate for an unknown connection"
            );
            return Actions::new();
        };

        let name = request.username.clone().unwrap_or_default();
        // `Authenticate` is where a client announces Opus
        // (`vendor/server/src/murmur/Messages.cpp:538`), so it is recorded
        // before anything can refuse the login and lose it.
        connections.record_opus(inbound.conn, request.opus.unwrap_or(false));
        tracing::debug!(
            conn = inbound.conn,
            %name,
            fancy = pending.fancy_version,
            opus = request.opus.unwrap_or(false),
            "authenticating"
        );

        let config = self.config(inbound.scope).await;
        if !config.password.is_empty()
            && request.password.as_deref().unwrap_or_default() != config.password
        {
            return vec![self.refuse(
                inbound.conn,
                &name,
                tcp::reject::RejectType::WrongServerPw,
                "wrong server password",
            )];
        }

        let outcome = self
            .identify(inbound.scope, &name, &request, &pending)
            .await;
        let identity = match outcome {
            Ok(identity) => identity,
            Err(action) => return vec![action],
        };
        // Borrowed, not re-bound: `identity` owns the name from here on, and
        // the stored profile hashes travel with it into `welcome`.
        let account = identity.account;
        let name = identity.name.as_str();

        // Somebody is already here under this name or this account
        // (`vendor/server/src/murmur/Messages.cpp:418`). murmur never lets two
        // live sessions share a name: either this one is refused, or the older
        // one is a ghost and gets kicked. Doing neither is how a server ends up
        // with three of the same user in the tree.
        let ghost = connections.duplicate_of(inbound.conn, account, name);
        if let Some(ghost) = &ghost
            && !may_replace(&pending, ghost, account)
        {
            return vec![self.refuse(
                inbound.conn,
                name,
                tcp::reject::RejectType::UsernameInUse,
                "that name is already in use",
            )];
        }

        let Some(session) = connections.allocate(inbound.conn, &identity) else {
            return vec![self.refuse(
                inbound.conn,
                name,
                tcp::reject::RejectType::ServerFull,
                "the server is full",
            )];
        };

        // The line the operator asked for: somebody is now on the server.
        //
        // `registered` comes from the option itself rather than from `id != 0`.
        // That comparison read the administrator as a guest, because its account
        // id is 0.
        let (id, registered) = identity::wire(account);
        self.ctx.logger.log(
            LogEvent::info(Category::Session, "user authenticated")
                .with("conn", inbound.conn)
                .with("session", session)
                .with("name", name.to_owned())
                .with("account", id)
                .with("registered", registered)
                .with("address", pending.address.clone())
                .with("fancy", pending.fancy_version != 0),
        );

        let mut actions = self
            .welcome(inbound, session, &identity, &config, &pending)
            .await;

        self.announce_up(connections, inbound.conn).await;
        self.enter_root(inbound.scope, session).await;

        // Told, not asked. Sent after the announce so `permissions` can resolve
        // the session, and after entering root so the answer is about the
        // channel the client is actually in — the one its menus are drawn from.
        if let Some(pending) = connections.get(inbound.conn) {
            actions.extend(self.push_permissions(&pending, ROOT_CHANNEL).await);
        }

        // After the new session is up, as murmur does (`Messages.cpp:506`):
        // the replacement is complete before the old one goes, so the name is
        // never briefly absent from everyone's tree.
        if let Some(ghost) = ghost {
            self.kick_ghost(&ghost);
        }
        actions
    }

    /// Disconnect the older session a reconnecting user left behind.
    ///
    /// Pushed through the fan-out rather than returned with this connection's
    /// actions, because the ghost may be held by a different gateway pod
    /// entirely — the pod that does not have it ignores the frame, which is
    /// exactly the broadcast contract the plane already relies on.
    ///
    /// The `UserRemove` every other client needs is not sent here: closing the
    /// connection makes the gateway report it closed, and the ordinary
    /// disconnect path already broadcasts that. Sending one here too would
    /// remove the user twice.
    fn kick_ghost(&self, ghost: &PendingConnection) {
        tracing::info!(
            conn = ghost.conn,
            session = ghost.session,
            name = %ghost.name,
            "disconnecting a ghost: the same user connected again"
        );
        self.ctx.logger.log(
            LogEvent::notice(Category::Session, "ghost disconnected")
                .with("conn", ghost.conn)
                .with("session", ghost.session)
                .with("name", ghost.name.clone())
                .with("reason", "the same user connected from elsewhere"),
        );
        self.fanout.push(disconnect(
            ghost.conn,
            "You connected to the server from another device",
        ));
    }

    /// Everything the client is sent once it is admitted, in murmur's order.
    ///
    /// Split out of [`Self::authenticate`] because the two answer different
    /// questions: that one decides *whether* the peer may in, this one composes
    /// the world it is handed. The ordering constraints documented at the top of
    /// this module all live here.
    async fn welcome(
        &self,
        inbound: &Inbound,
        session: u32,
        identity: &Identity,
        config: &Snapshot,
        pending: &PendingConnection,
    ) -> Actions {
        let account = identity.account;
        let name = identity.name.as_str();

        let mut actions = Vec::new();
        actions.push(self.crypt_setup(inbound, session, pending).await);
        actions.push(to_conn(inbound.conn, 21, codec_version().encode_to_vec()));
        actions.extend(self.channel_flood(inbound).await);
        actions.extend(self.user_states(inbound, session, identity, pending).await);
        actions.push(to_conn(
            inbound.conn,
            5,
            server_sync(session, config).encode_to_vec(),
        ));
        actions.push(to_conn(
            inbound.conn,
            24,
            server_config(config).encode_to_vec(),
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
                // Flattened, and safe to flatten: the gateway routes and does not
                // authorize, so it never reads this field. Nothing downstream of
                // here makes a permission decision from it.
                account: identity::wire(account).0,
                name: name.to_owned(),
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
            name: Some(name.to_owned()),
            channel_id: Some(0),
            // Everyone else's user list is built from this one message, so it
            // needs the registration marker — and the certificate hash — just
            // as much as the client's own copy above does.
            user_id: account.map(|id| id as u32),
            hash: hex_hash(&pending.cert_hash),
            // And the stored profile, for the same reason: this is the only
            // message the already-connected clients get about the new arrival,
            // so an avatar left out here is one nobody but its owner ever sees.
            // The hashes, not the bodies — the client fetches those with
            // `RequestBlob` if it wants them, which is what keeps a 500 KiB
            // picture out of a broadcast to every session on the server.
            comment_hash: blob_hash(&identity.comment_hash),
            texture_hash: blob_hash(&identity.texture_hash),
            ..tcp::UserState::default()
        };
        actions.push(broadcast_except(session, 9, joined.encode_to_vec()));
        actions
    }

    /// Who the peer is, or the rejection to send.
    async fn identify(
        &self,
        scope: u32,
        name: &str,
        request: &tcp::Authenticate,
        pending: &PendingConnection,
    ) -> Result<Identity, ServerAction> {
        let Ok(channel) = self.resolver.channel("userdata") else {
            // Userdata is essential: without it a login cannot be decided, and
            // guessing would either lock everyone out or let everyone in.
            // Logged as an error, not a refusal: it is the server that is
            // broken here, not the credentials.
            tracing::error!(
                conn = pending.conn,
                "userdata is unreachable; refusing login"
            );
            self.ctx.logger.log(
                LogEvent::error(Category::Session, "the account service is unreachable")
                    .with("conn", pending.conn)
                    .with("name", name.to_owned()),
            );
            return Err(self.refuse(
                pending.conn,
                name,
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

        let result = match result {
            Ok(result) => result,
            Err(status) => {
                tracing::error!(
                    conn = pending.conn,
                    %status,
                    "userdata refused the authentication request"
                );
                self.ctx.logger.log(
                    LogEvent::error(Category::Session, "the account service refused the request")
                        .with("conn", pending.conn)
                        .with("name", name.to_owned())
                        .with("error", status.message().to_owned()),
                );
                return Err(self.refuse(
                    pending.conn,
                    name,
                    tcp::reject::RejectType::None,
                    "the account service refused the request",
                ));
            }
        };
        let result = result.into_inner();
        let outcome = auth_result::Outcome::try_from(result.outcome)
            .unwrap_or(auth_result::Outcome::UnknownAccount);

        if matches!(outcome, auth_result::Outcome::Ok) {
            // `Option<Account>`, kept as an option. Flattening an absent account
            // to 0 here is what made a guest indistinguishable from the
            // SuperUser, whose account id *is* 0 — see
            // `starling_proto_fancy::identity`.
            //
            // `guest` is authoritative when the two disagree: userdata sets it
            // for a name accepted without an account, and resolving the
            // contradiction towards "no account" is the direction that grants
            // nothing.
            let account = if result.guest {
                None
            } else {
                result.account.as_ref().map(|account| account.id)
            };
            let name = result
                .account
                .as_ref()
                .map_or_else(|| name.to_owned(), |account| account.name.clone());

            // The stored profile arrives on the same answer, so it is taken
            // here rather than looked up again in each of the three places that
            // build a `UserState` from it.
            //
            // Only when the session really holds the account: `guest` above can
            // strip an account id from a login that still carried an account
            // record, and an anonymous session must not wear the avatar of the
            // name it borrowed.
            let (comment_hash, texture_hash) = match (account, result.account) {
                (Some(_), Some(record)) => (record.comment_hash, record.texture_hash),
                _ => (Vec::new(), Vec::new()),
            };

            return Ok(Identity {
                account,
                name,
                comment_hash,
                texture_hash,
            });
        }
        let (kind, reason) = refusal_for(outcome);
        Err(self.refuse(pending.conn, name, kind, reason))
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
        pending: &PendingConnection,
    ) -> ServerAction {
        let payload = match self.resolver.channel("voice") {
            Ok(channel) => VoiceClient::new(channel)
                .mint(MintRequest {
                    scope: Some(starling_proto_fancy::common::Scope {
                        virtual_server: inbound.scope,
                    }),
                    session,
                    fancy_version: pending.fancy_version,
                    mumble_version: pending.mumble_version,
                    address: pending.address.clone(),
                    conn: inbound.conn,
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

    /// Tell a client what it may do in a channel, without being asked.
    ///
    /// murmur pushes this on every channel entry — the channel and its parent
    /// (`Server.cpp:2319`) — and a client builds its UI from it: an action it
    /// holds no permission for is not greyed out, it is *absent*. Starling only
    /// ever answered an explicit `PermissionQuery`, so a client that did not
    /// ask (or asked before the tree it wanted to ask about existed) rendered
    /// as though the user could do nothing at all. Every admin action was
    /// missing from the menus with nothing in any log to explain it.
    ///
    /// Best-effort: a client that never learns its permissions shows fewer
    /// actions than it holds, which is the safe direction, and every action it
    /// does attempt is authorised again on its own path.
    /// The identity is taken from the connection record, not asserted blank.
    /// `effective` trusts the `Subject` it is handed, and a default one is an
    /// unregistered guest — so asking with only a session id would report the
    /// administrator's own permissions as a stranger's and hide every action
    /// from them. This service is the authority on who just authenticated, so
    /// it is entitled to state it, through `identity` rather than by comparing
    /// `account` to zero.
    async fn push_permissions(&self, pending: &PendingConnection, channel: u32) -> Actions {
        use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
        use starling_proto_fancy::permissions::{EffectiveRequest, Subject};

        let Ok(transport) = self.resolver.channel("permissions") else {
            return Actions::new();
        };
        let (account, registered) = identity::wire(pending.account);
        let Ok(answer) = PermissionsClient::new(transport)
            .effective(EffectiveRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: pending.scope,
                }),
                subject: Some(Subject {
                    session: pending.session,
                    account,
                    registered,
                    name: pending.name.clone(),
                    cert_hash: pending.cert_hash.clone(),
                    tokens: Vec::new(),
                }),
                channel,
            })
            .await
        else {
            return Actions::new();
        };

        let granted = answer.into_inner().granted;
        tracing::debug!(
            session = pending.session,
            channel,
            granted = format!("{granted:#x}"),
            "pushing permissions"
        );
        let query = tcp::PermissionQuery {
            channel_id: Some(channel),
            permissions: Some(granted),
            flush: Some(false),
        };
        vec![to_conn(
            pending.conn,
            PERMISSION_QUERY,
            query.encode_to_vec(),
        )]
    }

    /// Whether this session may see a hidden channel.
    ///
    /// Asked of `permissions` through `CheckSession`, which resolves who the
    /// session is server-side — the identity is never the caller's to state.
    ///
    /// **Denies on any failure**, including `permissions` being unreachable.
    /// The alternative is that an outage reveals every private room on the
    /// server, and a channel briefly missing from a tree is recoverable where
    /// that is not.
    async fn may_see(&self, scope: u32, session: u32, channel: u32) -> bool {
        use starling_proto_fancy::permissions::SessionCheckRequest;
        use starling_proto_fancy::permissions::permissions_client::PermissionsClient;

        let Ok(transport) = self.resolver.channel("permissions") else {
            tracing::warn!(channel, "permissions is unreachable; hiding the channel");
            return false;
        };
        PermissionsClient::new(transport)
            .check_session(SessionCheckRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
                session,
                channel,
                permission: Perm::SEE_CHANNEL.bits(),
            })
            .await
            .is_ok_and(|decision| decision.into_inner().allowed)
    }

    /// Every channel the client may see, breadth-first from the root.
    async fn channel_flood(&self, inbound: &Inbound) -> Actions {
        let Ok(channel) = self.resolver.channel("metadata") else {
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

        // A hidden channel is only sent to a client that holds `SeeChannel` on
        // it. Without this the flag was decorative: `SEE_CHANNEL` was defined
        // and never read, so every private room — and, because the client
        // builds its tree from these messages, everyone sitting in one — was
        // announced to every user who connected.
        //
        // Only hidden channels cost a permission check. The common case is a
        // server with none, and a check per channel per login would put a
        // round trip on the handshake for a question whose answer is almost
        // always "it is not hidden".
        let mut visible = Vec::with_capacity(channels.len());
        for channel in channels {
            if channel.flags & FLAG_HIDDEN != 0
                && !self
                    .may_see(inbound.scope, inbound.session, channel.id)
                    .await
            {
                continue;
            }
            visible.push(channel);
        }

        visible
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
    async fn user_states(
        &self,
        inbound: &Inbound,
        session: u32,
        identity: &Identity,
        pending: &PendingConnection,
    ) -> Actions {
        let own = tcp::UserState {
            session: Some(session),
            name: Some(identity.name.clone()),
            channel_id: Some(0),
            // The certificate hash, hex-encoded as murmur sends it
            // (`Server.cpp:1686`). A client will not offer "Register" for a
            // user it believes has no certificate
            // (`vendor/server/src/mumble/MainWindow.cpp:1817`) — registration
            // binds an account to a certificate, so without one there is
            // nothing to bind. Omitting this greys the entry out for everybody,
            // including the administrator.
            hash: hex_hash(&pending.cert_hash),
            // `user_id` is the *only* thing that marks a user as registered to
            // a Mumble client: it is what draws the authenticated icon and what
            // "Registered Users" is keyed by. Leaving it unset — which every
            // `UserState` here used to do — renders the administrator as an
            // anonymous guest, however carefully the server authenticated them.
            //
            // Absent for a guest rather than 0, because 0 is the SuperUser's id.
            user_id: identity.account.map(|id| id as u32),
            // The profile stored on the account, which is how a picture set
            // anywhere other than this client — the web user manager, another
            // device, a previous session — is on the user the moment they
            // connect. Without these two the avatar existed on the account, in
            // the blob store and in nobody's user list.
            comment_hash: blob_hash(&identity.comment_hash),
            texture_hash: blob_hash(&identity.texture_hash),
            ..tcp::UserState::default()
        };
        let mut actions = vec![to_conn(inbound.conn, 9, own.encode_to_vec())];

        let Ok(channel) = self.resolver.channel("session-view") else {
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
                // Through `identity`, not `other.account` directly: the pair is
                // meaningless without the flag, and account 0 is the SuperUser
                // rather than "nobody".
                user_id: identity::account(other.registered, other.account).map(|id| id as u32),
                hash: hex_hash(&other.cert_hash),
                // Carried on the view for exactly this: the roster a client is
                // handed on connect is built here, so an avatar missing from
                // this loop is one that only appears for people who happened to
                // be connected when its owner joined.
                comment_hash: blob_hash(&other.comment_hash),
                texture_hash: blob_hash(&other.texture_hash),
                ..tcp::UserState::default()
            };
            actions.push(to_conn(inbound.conn, 9, state.encode_to_vec()));
        }
        actions
    }

    /// Tell session-view a session exists.
    ///
    /// Built from the connection record rather than from the arguments to hand,
    /// so that "up" and "changed" cannot describe the same session differently
    /// — the address, certificate and client version are on the record and were
    /// being dropped here.
    async fn announce_up(&self, connections: &Connections, conn: u64) {
        let Some(pending) = connections.get(conn) else {
            return;
        };
        self.announce(Announcement {
            scope: Some(starling_proto_fancy::common::Scope {
                virtual_server: pending.scope,
            }),
            what: Some(announcement::What::Up(session_record(&pending))),
        })
        .await;
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
            what: Some(announcement::What::Changed(session_record(&pending))),
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
        let Ok(channel) = self.resolver.channel("session-view") else {
            return;
        };
        if let Err(status) = SessionViewClient::new(channel).announce(announcement).await {
            tracing::warn!(%status, "session-view did not accept an announcement");
        }
    }

    /// Put a new session in the root channel.
    async fn enter_root(&self, scope: u32, session: u32) {
        let _ = self.enter(scope, session, 0).await;
    }

    /// Move `session` into `channel`, if metadata allows it.
    ///
    /// `None` when metadata could not be reached, which is different from a
    /// refusal: the caller tells the user nothing happened rather than telling
    /// them they lack a permission they may well hold.
    pub async fn enter(
        &self,
        scope: u32,
        session: u32,
        channel: u32,
    ) -> Option<starling_proto_fancy::metadata::EnterResult> {
        let transport = self.resolver.channel("metadata").ok()?;
        MetadataClient::new(transport)
            .enter(EnterRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
                session,
                channel,
            })
            .await
            .ok()
            .map(tonic::Response::into_inner)
    }

    /// The Fancy extensions: hello, resume, lazy subscription.
    pub fn fancy(&self, connections: &Connections, inbound: &Inbound) -> Actions {
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
    pub async fn config(&self, scope: u32) -> Snapshot {
        let fallback = Snapshot {
            virtual_server: scope,
            max_users: 100,
            max_bandwidth: 72_000,
            ..Snapshot::default()
        };
        let Ok(channel) = self.resolver.channel("server-config") else {
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

    /// How to reach other services, for the handlers outside this type.
    #[must_use]
    pub const fn resolver(&self) -> &Resolver {
        &self.resolver
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

    /// Refuse a login, and record why.
    ///
    /// Every refusal in the handshake goes through here, which is what makes
    /// "nobody can log in" answerable from the log alone — the client is told a
    /// `Reject` type it usually renders as one generic sentence, and without
    /// this the server's own reason existed only as the argument to a function
    /// that discarded it.
    fn refuse(
        &self,
        conn: u64,
        name: &str,
        kind: tcp::reject::RejectType,
        reason: &str,
    ) -> ServerAction {
        self.ctx.logger.log(
            LogEvent::warning(Category::Session, "login refused")
                .with("conn", conn)
                .with("name", name.to_owned())
                .with("reason", reason.to_owned())
                .with("reject", format!("{kind:?}")),
        );
        reject(conn, kind, reason)
    }
}

/// Whether `arriving` may take over from the `ghost` already using the name.
///
/// murmur's rule, transcribed from `Messages.cpp:429`. Three ways in:
///
/// * **A registered account.** The account has already been proved by password
///   or certificate, so the arriving peer *is* that user and the older session
///   is a leftover.
/// * **The same address.** This is murmur's "allow reuse of name from same IP",
///   and it is the case that matters in practice: a client whose connection
///   dropped reconnects before the server has noticed, and refusing would lock
///   somebody out of their own name until a timeout they cannot see.
/// * **The same certificate.** Identity without registration — proof enough
///   that this is the same person on a different network.
///
/// Anything else is a stranger taking a name that is in use, which is the case
/// `UsernameInUse` exists for.
fn may_replace(
    arriving: &PendingConnection,
    ghost: &PendingConnection,
    account: Option<u64>,
) -> bool {
    // A registered account is proof it is the same person. `is_some`, not
    // `!= 0`: the administrator holds account 0, and reading that as "no
    // account" sent it down the address-and-certificate path instead.
    if account.is_some() {
        return true;
    }
    if address_of(&arriving.address) == address_of(&ghost.address) {
        return true;
    }
    !arriving.cert_hash.is_empty() && arriving.cert_hash == ghost.cert_hash
}

/// The address without its port.
///
/// Compared without the port deliberately: a reconnect is a *new* TCP
/// connection and so always has a different source port, and comparing the
/// whole `host:port` string would mean the same-address rule never once
/// matched — turning every reconnect after a drop into `UsernameInUse`.
fn address_of(peer: &str) -> &str {
    // An IPv6 literal is bracketed, so its own colons are not the separator.
    match peer.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => peer.split(':').next().unwrap_or(peer),
    }
}

/// The `Reject` type and the sentence that go with an unsuccessful outcome.
///
/// A table rather than eight arms inline, because what this is *is* a mapping:
/// userdata decides the outcome, and the wire needs the murmur reject code and
/// something a human can read. `Ok` is absent on purpose — it is not a refusal,
/// and giving it a row here would mean inventing a reason for a success.
fn refusal_for(outcome: auth_result::Outcome) -> (tcp::reject::RejectType, &'static str) {
    use auth_result::Outcome;
    use tcp::reject::RejectType;
    match outcome {
        Outcome::WrongPassword => (RejectType::WrongUserPw, "wrong password"),
        // `WrongUserPw`, not `UsernameInUse`, and the difference is a security
        // property rather than a nicety. This outcome is murmur's `id == -1`:
        // the name belongs to a registered account and the peer proved nothing
        // (`Messages.cpp:381`, "Wrong certificate or password for existing
        // user"). `UsernameInUse` says something else entirely — that somebody
        // is *online* under the name — and a client told that reconnects under
        // a suffixed name, quietly turning a failed impersonation into a
        // successful login as a lookalike. It also leaks liveness: it answers
        // "is this person connected right now" to anyone who asks.
        //
        // A genuine live duplicate never reaches here; `duplicate_of` refuses
        // that case with `UsernameInUse` before authentication is consulted.
        Outcome::NameTaken => (
            RejectType::WrongUserPw,
            "that name is registered to another certificate",
        ),
        Outcome::CertRequired => (
            RejectType::NoCertificate,
            "this server requires a certificate",
        ),
        Outcome::InvalidName => (RejectType::InvalidUsername, "that name is not allowed"),
        // The fork carries these two so a client can retry with a code rather
        // than guess why it was refused.
        Outcome::TotpRequired => (
            RejectType::TotpRequired,
            "this account requires a one-time code",
        ),
        Outcome::TotpInvalid => (RejectType::TotpInvalid, "that one-time code is wrong"),
        // `Ok` cannot reach here — the caller returns before asking — and an
        // unknown account is the catch-all the enum's default already is.
        Outcome::UnknownAccount | Outcome::Ok => {
            (RejectType::AuthenticatorFail, "authentication failed")
        }
    }
}

/// A certificate hash as the wire carries it: lower-case hex, or absent.
///
/// Absent rather than empty for a peer with no certificate, because the client
/// tests emptiness to decide whether registration is even possible and an empty
/// string would answer that question the same way at more cost.
fn hex_hash(cert_hash: &[u8]) -> Option<String> {
    (!cert_hash.is_empty()).then(|| cert_hash.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A content hash as `UserState` carries it: the raw bytes, or absent.
///
/// Absent rather than empty, and the distinction is load-bearing in the client:
/// a *present but empty* `texture_hash` is how a picture is **cleared**
/// (`vendor/server/src/murmur/Messages.cpp:1517` sends one to do exactly that),
/// so sending an empty hash for a user who never had an avatar would order
/// every client to erase one it may already hold.
fn blob_hash(hash: &[u8]) -> Option<Vec<u8>> {
    (!hash.is_empty()).then(|| hash.to_vec())
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
    fn a_peer_with_a_certificate_has_its_hash_announced() {
        // A client will not offer "Register" for a user it believes has no
        // certificate (`vendor/server/src/mumble/MainWindow.cpp:1817`), because
        // registration binds an account to one. Omitting this greys the entry
        // out for everybody, administrator included — which is what it did.
        assert_eq!(
            hex_hash(&[0xaf, 0x08, 0xa1]),
            Some("af08a1".to_owned()),
            "lower-case hex, as murmur sends it"
        );
    }

    #[test]
    fn a_peer_without_one_announces_no_hash_at_all() {
        // Absent, not empty. The client tests emptiness to decide whether
        // registration is possible, so both answer the question the same way —
        // but only one of them costs a field on every `UserState`.
        assert_eq!(hex_hash(&[]), None);
    }

    #[test]
    fn the_wire_epoch_is_announced_and_the_product_version_is_not() {
        // Both halves matter and they pull in opposite directions.
        //
        // The epoch has to be present, or a client cannot tell Starling from a
        // plain Mumble server and never offers a Fancy feature at all.
        //
        // `fancy_version` has to be absent, and that is the counter-intuitive
        // one: it reads as "this server implements the Fancy features up to X",
        // and a client acting on it sends those features on epoch 0's
        // numbering, which this server routes nowhere. Claiming it would break
        // clients that work today, because with it absent they fall back to
        // `PluginDataTransmission` — epoch-independent, and relayed correctly.
        let version = server_version();
        assert_eq!(version.fancy_protocol, Some(FANCY_PROTOCOL));
        assert_eq!(
            version.fancy_version, None,
            "announcing a product version would make clients speak the numbering we do not"
        );
    }

    #[test]
    fn the_announced_version_is_new_enough_for_protobuf_audio() {
        // Announcing less than 1.5.0 pins every client to the legacy UDP
        // framing, where the packet type is the codec and there is nowhere to
        // name a cipher.
        const { assert!(MUMBLE_VERSION_V2 >= 0x0001_0005_0000) };
        assert_eq!(server_version().version_v2, Some(MUMBLE_VERSION_V2));
    }

    fn peer(address: &str, cert: &[u8]) -> PendingConnection {
        PendingConnection {
            address: address.to_owned(),
            cert_hash: cert.to_vec(),
            ..PendingConnection::default()
        }
    }

    #[test]
    fn a_moderators_mute_reaches_the_service_that_enforces_it() {
        // The bug this function exists for. `voice` decides whether to forward a
        // speaker's packets from the session-view record and nothing else
        // (`voice/src/view.rs:146`), and this announcement *replaces* that
        // record. Dropping `mute` here left the user muted in every client's
        // user list and audible to everyone in the channel.
        let muted = PendingConnection {
            session: 7,
            mute: true,
            deaf: true,
            suppress: true,
            priority_speaker: true,
            ..PendingConnection::default()
        };

        let announced = session_record(&muted);

        assert!(announced.mute, "a moderator mute must survive the trip");
        assert!(announced.deaf, "and so must a deafen");
        assert!(announced.suppress);
        assert!(announced.priority_speaker);
    }

    #[test]
    fn an_unrelated_change_does_not_silently_lift_a_mute() {
        // The shape of the original failure: a *different* edit — moving
        // channel, setting a comment — rebuilt the whole record, and every one
        // of those announcements un-muted the user in session-view. Anything
        // that rebuilds from the connection must carry the flags it did not set.
        let mut pending = PendingConnection {
            session: 7,
            mute: true,
            ..PendingConnection::default()
        };
        pending.channel = 4;

        assert!(
            session_record(&pending).mute,
            "a channel move must not lift a moderator's mute"
        );
    }

    #[test]
    fn the_connect_time_is_the_peers_own_not_the_moment_of_the_change() {
        // Recomputed here, every mute would reset the uptime the client shows.
        let pending = PendingConnection {
            connected_at_ms: 1_000,
            ..PendingConnection::default()
        };
        assert_eq!(session_record(&pending).connected_at_ms, 1_000);
    }

    #[test]
    fn a_stranger_may_not_take_a_name_that_is_in_use() {
        // The bug this rule exists for: without it the same name connects any
        // number of times and every client renders several of the same person.
        let ghost = peer("10.0.0.1:50000", &[]);
        let arriving = peer("10.0.0.2:50001", &[]);
        assert!(!may_replace(&arriving, &ghost, None));
    }

    #[test]
    fn reconnecting_from_the_same_address_replaces_your_own_ghost() {
        // murmur's "allow reuse of name from same IP" (`Messages.cpp:428`).
        // This is the case that actually happens: a dropped connection the
        // server has not noticed yet, and the same person coming back. The
        // ports differ because a reconnect is always a new TCP connection —
        // comparing them would make this rule dead.
        let ghost = peer("10.0.0.1:50000", &[]);
        let arriving = peer("10.0.0.1:61234", &[]);
        assert!(may_replace(&arriving, &ghost, None));
    }

    #[test]
    fn a_registered_account_always_replaces_its_own_ghost() {
        // The account has already been proved, so the arriving peer *is* that
        // user however their address changed.
        let ghost = peer("10.0.0.1:50000", &[]);
        let arriving = peer("198.51.100.7:50001", &[]);
        assert!(may_replace(&arriving, &ghost, Some(7)));
    }

    #[test]
    fn the_same_certificate_replaces_its_ghost_from_a_new_network() {
        let ghost = peer("10.0.0.1:50000", &[1, 2, 3]);
        let arriving = peer("198.51.100.7:50001", &[1, 2, 3]);
        assert!(may_replace(&arriving, &ghost, None));
    }

    #[test]
    fn an_absent_certificate_is_not_a_match_for_another_absent_one() {
        // Two clients with no certificate both carry an empty hash. Treating
        // that as "the same certificate" would let anyone displace anyone.
        let ghost = peer("10.0.0.1:50000", &[]);
        let arriving = peer("198.51.100.7:50001", &[]);
        assert!(!may_replace(&arriving, &ghost, None));
    }

    #[test]
    fn an_address_is_compared_without_its_port() {
        assert_eq!(address_of("10.0.0.1:50000"), "10.0.0.1");
        assert_eq!(address_of("[2001:db8::1]:50000"), "2001:db8::1");
        // Bare forms, in case a gateway ever reports one.
        assert_eq!(address_of("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn an_ipv6_peer_reconnecting_is_recognised_as_the_same_address() {
        // Splitting on the first colon would read the host as "[2001" for both
        // and match every IPv6 client to every other one.
        let ghost = peer("[2001:db8::1]:50000", &[]);
        let arriving = peer("[2001:db8::1]:61234", &[]);
        assert!(may_replace(&arriving, &ghost, None));

        let other = peer("[2001:db8::2]:61234", &[]);
        assert!(!may_replace(&other, &ghost, None));
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
