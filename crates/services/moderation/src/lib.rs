//! `moderation` — bans and kicks.
//!
//! A ban outlives the session it was issued against, which is why it is stored
//! here and not in `session-view`: that view is of *connected* users, and a ban
//! is most useful precisely when its subject is not.
//!
//! The gateway asks [`Moderation::check_ban`] on accept, before anything is
//! spent on a peer that is not allowed in.

// The async test harness, and nothing else in this crate, needs tokio.
#[cfg(test)]
use tokio as _;

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::identity;
use starling_proto_fancy::moderation::moderation_server::{Moderation, ModerationServer};
use starling_proto_fancy::moderation::{
    Ban, BanCheck, BanList, BanRequest, BanResult, BanVerdict, KickRequest, UnbanRequest,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::sessionview::Session;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent, Logger, describe_actor};
use starling_runtime::permit::{Permit, permission_denied};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, disconnect, to_conn, to_sessions,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use starling_runtime::trail::{self, Record, Trail};
use tonic::{Request, Response, Status};

/// Upstream `UserRemove`: a kick, or a kick with a ban flag.
const USER_REMOVE: u16 = 8;
/// The root channel, where the server-wide permissions live.
const ROOT_CHANNEL: u32 = 0;

/// Upstream `BanList`.
const BAN_LIST: u16 = 10;

/// The schema.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_ban",
    &[
        "CREATE TABLE IF NOT EXISTS ban (\
             server_id BIGINT NOT NULL, id BIGINT NOT NULL, \
             address BLOB NOT NULL, prefix_len INTEGER NOT NULL, \
             name VARCHAR(190) NOT NULL, cert_hash BLOB NULL, reason TEXT NOT NULL, \
             start_ms BIGINT NOT NULL, duration_s INTEGER NOT NULL, \
             PRIMARY KEY (server_id, id))",
        "CREATE INDEX IF NOT EXISTS ix_ban_cert ON ban(server_id, cert_hash)",
    ],
)];

/// The service.
#[derive(Debug)]
pub struct ModerationService {
    store: Store,
    fanout: Fanout,
    logger: Logger,
    /// Asks `permissions` before the ban list is handed to anyone.
    permit: Permit,
    /// Reaches `session-view` to find out who a session id refers to.
    ///
    /// A ban outlives the connection, so it has to be written against something
    /// durable — the address and the certificate hash — and the session id
    /// alone carries neither.
    resolver: Resolver,
    /// The operator-facing record of moderation actions.
    ///
    /// A ban or kick is the thing an operator is most often asked to justify
    /// months later, so it belongs in the queryable, hash-chained trail and not
    /// only in the server's own log.
    trail: Trail,
}

/// The client on `session`, as an audit actor.
fn session_actor(session: u32) -> starling_proto_fancy::common::Actor {
    starling_proto_fancy::common::Actor {
        who: Some(starling_proto_fancy::common::actor::Who::Session(session)),
    }
}

impl ModerationService {
    /// Store one ban.
    ///
    /// Shared by the operator RPC and by a kick that carries the ban flag, so
    /// the two cannot drift on which columns a ban needs to be findable by.
    async fn write_ban(&self, scope: u32, ban: &Ban) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO ban (server_id, id, address, prefix_len, name, cert_hash, reason,                  start_ms, duration_s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(ban.id as i64)
        .bind(ban.address.as_slice())
        .bind(i64::from(ban.prefix_len))
        .bind(&ban.name)
        .bind(ban.cert_hash.as_slice())
        .bind(&ban.reason)
        .bind(ban.start_ms as i64)
        .bind(i64::from(ban.duration_s))
        .execute(self.store.pool())
        .await
        .map(|_| ())
        .map_err(|error| {
            self.logger.log(
                LogEvent::error(Category::Admin, "ban could not be recorded")
                    .with("name", ban.name.clone())
                    .with("error", error.to_string()),
            );
            error.to_string()
        })
    }

    /// Every ban in `scope`, expired ones dropped.
    async fn bans(&self, scope: u32) -> Vec<Ban> {
        use sqlx::Row as _;
        let rows = sqlx::query(
            "SELECT id, address, prefix_len, name, cert_hash, reason, start_ms, duration_s \
             FROM ban WHERE server_id = ?",
        )
        .bind(i64::from(scope))
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default();

        rows.into_iter()
            .map(|row| Ban {
                id: row.try_get::<i64, _>("id").unwrap_or_default() as u64,
                address: row.try_get("address").unwrap_or_default(),
                prefix_len: row.try_get::<i64, _>("prefix_len").unwrap_or_default() as u32,
                name: row.try_get("name").unwrap_or_default(),
                cert_hash: row.try_get("cert_hash").unwrap_or_default(),
                reason: row.try_get("reason").unwrap_or_default(),
                start_ms: row.try_get::<i64, _>("start_ms").unwrap_or_default() as u64,
                duration_s: row.try_get::<i64, _>("duration_s").unwrap_or_default() as u32,
            })
            .filter(|ban| !expired(ban, now_ms()))
            .collect()
    }
}

/// A `PermissionDenied` saying the target is the administrator.
fn deny_superuser(inbound: &Inbound) -> starling_proto_fancy::control::ServerAction {
    let denied = starling_proto::proto::tcp::PermissionDenied {
        r#type: Some(starling_proto::proto::tcp::permission_denied::DenyType::SuperUser as i32),
        session: Some(inbound.session),
        ..starling_proto::proto::tcp::PermissionDenied::default()
    };
    to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

/// Upstream `PermissionDenied`.
const PERMISSION_DENIED: u16 = 12;

/// A stored address, as the ban table holds them.
///
/// The v6-mapped sixteen bytes, matching what a `/128` prefix is compared
/// against — see `covers` below, which walks the stored bytes directly.
fn address_bytes(peer: &str) -> Vec<u8> {
    let host = match peer.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => peer.rsplit_once(':').map_or(peer, |(host, _)| host),
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.to_ipv6_mapped().octets().to_vec(),
        Ok(std::net::IpAddr::V6(v6)) => v6.octets().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Whether a ban has run out.
///
/// `duration_s == 0` is permanent, as it is in murmur's `BanTable`.
#[must_use]
pub fn expired(ban: &Ban, now: u64) -> bool {
    ban.duration_s != 0 && now > ban.start_ms + u64::from(ban.duration_s) * 1000
}

/// Whether a ban covers this address, by prefix.
#[must_use]
pub fn covers(ban: &Ban, address: &[u8]) -> bool {
    if ban.address.is_empty() {
        return false;
    }
    let bits = ban.prefix_len as usize;
    let whole = bits / 8;
    let remainder = bits % 8;
    if address.len() < whole || ban.address.len() < whole {
        return false;
    }
    if ban.address.get(..whole) != address.get(..whole) {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    let mask = 0xff_u8 << (8 - remainder);
    let (Some(left), Some(right)) = (ban.address.get(whole), address.get(whole)) else {
        return false;
    };
    left & mask == right & mask
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct ModerationRpc(Arc<ModerationService>);

#[tonic::async_trait]
impl Moderation for ModerationRpc {
    async fn check_ban(&self, request: Request<BanCheck>) -> Result<Response<BanVerdict>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.virtual_server);
        let now = now_ms();
        for ban in self.0.bans(scope).await {
            let by_address = covers(&ban, &req.address);
            let by_cert = !ban.cert_hash.is_empty() && ban.cert_hash == req.cert_hash;
            if by_address || by_cert {
                return Ok(Response::new(BanVerdict {
                    banned: true,
                    reason: ban.reason.clone(),
                    expires_at_ms: if ban.duration_s == 0 {
                        0
                    } else {
                        ban.start_ms + u64::from(ban.duration_s) * 1000
                    },
                }));
            }
        }
        let _ = now;
        Ok(Response::new(BanVerdict::default()))
    }

    async fn ban(&self, request: Request<BanRequest>) -> Result<Response<BanResult>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.virtual_server);
        let Some(mut ban) = req.ban else {
            return Ok(Response::new(BanResult {
                applied: false,
                refused: "no ban was described".to_owned(),
                bans: Vec::new(),
            }));
        };
        ban.id = now_ms();
        ban.start_ms = now_ms();
        let result = sqlx::query(
            "INSERT INTO ban (server_id, id, address, prefix_len, name, cert_hash, reason, \
                 start_ms, duration_s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(ban.id as i64)
        .bind(ban.address.as_slice())
        .bind(i64::from(ban.prefix_len))
        .bind(&ban.name)
        .bind(ban.cert_hash.as_slice())
        .bind(&ban.reason)
        .bind(ban.start_ms as i64)
        .bind(i64::from(ban.duration_s))
        .execute(self.0.store.pool())
        .await;

        if let Err(error) = result {
            tracing::error!(%error, name = %ban.name, "could not record a ban");
            self.0.logger.log(
                LogEvent::error(Category::Admin, "ban could not be recorded")
                    .with("name", ban.name.clone())
                    .with("error", error.to_string()),
            );
            return Ok(Response::new(BanResult {
                applied: false,
                refused: error.to_string(),
                bans: Vec::new(),
            }));
        }

        // A ban outlives the session it was issued against, so it is the kind
        // of thing that has to be answerable months later — who, why, and for
        // how long.
        self.0.logger.log(
            LogEvent::notice(Category::Admin, "ban issued")
                .with("name", ban.name.clone())
                .with("session", req.session)
                .with("actor", describe_actor(req.actor.as_ref()))
                .with("reason", ban.reason.clone())
                .with("duration_s", ban.duration_s)
                .with("permanent", ban.duration_s == 0)
                .with("scope", scope),
        );
        self.0.trail.record(
            scope,
            Record::new(trail::category::BAN, "issued")
                .actor(req.actor.clone().unwrap_or_default(), ban.name.clone())
                .detail(if ban.duration_s == 0 {
                    format!("permanent: {}", ban.reason)
                } else {
                    format!("{}s: {}", ban.duration_s, ban.reason)
                }),
        );

        if req.session != 0 {
            self.0
                .fanout
                .push(disconnect(u64::from(req.session), "banned"));
        }
        Ok(Response::new(BanResult {
            applied: true,
            refused: String::new(),
            bans: self.0.bans(scope).await,
        }))
    }

    async fn unban(&self, request: Request<UnbanRequest>) -> Result<Response<BanResult>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.virtual_server);
        let _ = sqlx::query("DELETE FROM ban WHERE server_id = ? AND id = ?")
            .bind(i64::from(scope))
            .bind(req.id as i64)
            .execute(self.0.store.pool())
            .await;
        self.0.logger.log(
            LogEvent::notice(Category::Admin, "ban lifted")
                .with("ban", req.id)
                .with("scope", scope),
        );
        self.0.trail.record(
            scope,
            Record::new(trail::category::BAN, "lifted").detail(format!("ban {}", req.id)),
        );
        Ok(Response::new(BanResult {
            applied: true,
            refused: String::new(),
            bans: self.0.bans(scope).await,
        }))
    }

    async fn list_bans(
        &self,
        request: Request<starling_proto_fancy::common::Scope>,
    ) -> Result<Response<BanList>, Status> {
        let scope = request.into_inner().virtual_server;
        Ok(Response::new(BanList {
            bans: self.0.bans(scope).await,
        }))
    }

    async fn kick(&self, request: Request<KickRequest>) -> Result<Response<BanResult>, Status> {
        let req = request.into_inner();
        let actor = describe_actor(req.actor.as_ref());
        self.0.logger.log(
            LogEvent::notice(Category::Admin, "user kicked")
                .with("session", req.session)
                .with("actor", actor)
                .with("reason", req.reason.clone()),
        );
        self.0.trail.record(
            0,
            Record::new(trail::category::KICK, "kicked")
                .actor(req.actor.clone().unwrap_or_default(), String::new())
                .detail(req.reason.clone()),
        );
        // A kick is a disconnect and nothing else: the client reconnects, and
        // that is the difference between a kick and a ban.
        self.0
            .fanout
            .push(disconnect(u64::from(req.session), &req.reason));
        Ok(Response::new(BanResult {
            applied: true,
            refused: String::new(),
            bans: Vec::new(),
        }))
    }
}

impl ClientService for ModerationService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            BAN_LIST => self.on_ban_list(&inbound).await,
            USER_REMOVE => self.on_user_remove(&inbound).await,
            _ => Actions::new(),
        }
    }
}

impl ModerationService {
    /// A kick, or a kick that also leaves a ban behind.
    ///
    /// This was `Actions::new()` — accepted, discarded, and answered with
    /// nothing, so the moderator's client showed the user still present and no
    /// log said why.
    ///
    /// murmur's rule (`vendor/server/src/murmur/Messages.cpp:1607`): the
    /// permission is checked on the **root** channel, because kicking somebody
    /// removes them from the server rather than from a room. Banning needs
    /// `Ban`; kicking needs `Ban` *or* `Kick`.
    async fn on_user_remove(&self, inbound: &Inbound) -> Actions {
        let Ok(request) =
            starling_proto::proto::tcp::UserRemove::decode(inbound.payload.as_slice())
        else {
            tracing::debug!(conn = inbound.conn, "undecodable UserRemove");
            return Actions::new();
        };
        let banning = request.ban.unwrap_or(false);

        let Some(target) = self.session(inbound.scope, request.session).await else {
            tracing::debug!(session = request.session, "kick for an unknown session");
            return Actions::new();
        };

        // The administrator cannot be kicked or banned by anybody
        // (`Messages.cpp:1609`), or `Ban` in the root is enough to lock the
        // owner out of their own server.
        if identity::is_superuser(target.registered, target.account) {
            return vec![deny_superuser(inbound)];
        }

        if !self.may_remove(inbound, banning).await {
            tracing::info!(
                actor = inbound.session,
                session = request.session,
                banning,
                "kick refused"
            );
            let missing = if banning { Perm::BAN } else { Perm::KICK };
            return vec![permission_denied(inbound, missing, ROOT_CHANNEL)];
        }

        let reason = request.reason.clone().unwrap_or_default();
        if banning {
            self.record_ban(inbound.scope, &target, &request, &reason)
                .await;
        }

        self.logger.log(
            LogEvent::notice(
                Category::Admin,
                if banning {
                    "user banned"
                } else {
                    "user kicked"
                },
            )
            .with("actor", inbound.session)
            .with("session", request.session)
            .with("name", target.name.clone())
            .with("reason", reason.clone())
            .with("scope", inbound.scope),
        );
        self.trail.record(
            inbound.scope,
            Record::new(
                if banning {
                    trail::category::BAN
                } else {
                    trail::category::KICK
                },
                if banning { "banned" } else { "kicked" },
            )
            .actor(session_actor(inbound.session), String::new())
            .target_account(target.account)
            .detail(format!("{}: {reason}", target.name)),
        );

        // Everyone is told, with the actor filled in as murmur does
        // (`Messages.cpp:1602`) — a client renders "X was kicked by Y" from it.
        let announce = starling_proto::proto::tcp::UserRemove {
            session: request.session,
            actor: Some(inbound.session),
            reason: Some(reason.clone()),
            ban: Some(banning),
            ..starling_proto::proto::tcp::UserRemove::default()
        };
        vec![
            to_sessions(Vec::new(), USER_REMOVE, announce.encode_to_vec()),
            // And the connection actually goes. Announcing a removal without
            // closing the socket leaves the user connected and talking while
            // every other client has stopped rendering them.
            disconnect(target.conn, if banning { "banned" } else { "kicked" }),
        ]
    }

    /// Whether the actor may kick, or ban, at the root.
    ///
    /// Two separate questions rather than one two-bit request: `Permit::allows`
    /// requires *every* bit it is given, and murmur's kick rule is `Ban` **or**
    /// `Kick`. Asking for both at once would demand a moderator hold the ban
    /// power to perform a kick.
    async fn may_remove(&self, inbound: &Inbound, banning: bool) -> bool {
        if self
            .permit
            .allows(inbound, ROOT_CHANNEL, Perm::BAN.bits())
            .await
        {
            return true;
        }
        !banning
            && self
                .permit
                .allows(inbound, ROOT_CHANNEL, Perm::KICK.bits())
                .await
    }

    /// Who a session id refers to, from `session-view`.
    async fn session(&self, scope: u32, session: u32) -> Option<Session> {
        use starling_proto_fancy::sessionview::GetRequest;
        use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;

        let transport = self.resolver.channel("session-view").ok()?;
        let found = SessionViewClient::new(transport)
            .get(GetRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    virtual_server: scope,
                }),
                session,
            })
            .await
            .ok()?
            .into_inner();
        (found.session != 0).then_some(found)
    }

    /// Write the ban a kick left behind.
    ///
    /// By certificate *and* address unless the client asked for one or the
    /// other, which is murmur's default (`Messages.cpp:1617`). A certificate
    /// ban follows the person to a new address; an address ban catches the
    /// person who simply makes a new certificate. Neither alone is much of a
    /// ban, which is why the fallback is both.
    async fn record_ban(
        &self,
        scope: u32,
        target: &Session,
        request: &starling_proto::proto::tcp::UserRemove,
        reason: &str,
    ) {
        let by_certificate =
            request.ban_certificate.unwrap_or(true) && !target.cert_hash.is_empty();
        let by_address = request.ban_ip.unwrap_or(true);
        if !by_certificate && !by_address {
            // Nothing to key it on. murmur returns without writing rather than
            // storing a ban that matches everybody.
            tracing::info!(
                session = target.session,
                "ban names no method; nothing stored"
            );
            return;
        }

        let address = if by_address {
            address_bytes(&target.address)
        } else {
            Vec::new()
        };
        let ban = Ban {
            id: now_ms(),
            address,
            // A single host, not a range: `/128` over the v6-mapped form.
            prefix_len: if by_address { 128 } else { 0 },
            name: target.name.clone(),
            cert_hash: if by_certificate {
                target.cert_hash.clone()
            } else {
                Vec::new()
            },
            reason: reason.to_owned(),
            start_ms: now_ms(),
            // Permanent, as murmur's kick-ban is (`Messages.cpp:1639`). A timed
            // ban is issued through the operator API, which takes a duration.
            duration_s: 0,
        };
        let _ = self.write_ban(scope, &ban).await;
    }

    async fn on_ban_list(&self, inbound: &Inbound) -> Actions {
        let Ok(query) = starling_proto::proto::tcp::BanList::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        if !query.query.unwrap_or(false) {
            // A write from the client plane is refused: issuing a ban is an
            // operator action and takes an operator identity.
            return Actions::new();
        }

        // Reading the ban list takes `Ban` at the root, as murmur asks. It is a
        // list of names, addresses and certificate hashes of people who were
        // thrown off — handing it to any client who asks is a disclosure that
        // has nothing to do with using the server.
        if !self
            .permit
            .allows(inbound, ROOT_CHANNEL, Perm::BAN.bits())
            .await
        {
            return vec![permission_denied(inbound, Perm::BAN, ROOT_CHANNEL)];
        }

        let reply = starling_proto::proto::tcp::BanList {
            query: Some(false),
            bans: self
                .bans(inbound.scope)
                .await
                .into_iter()
                .map(|ban| starling_proto::proto::tcp::ban_list::BanEntry {
                    address: ban.address,
                    mask: ban.prefix_len,
                    name: Some(ban.name),
                    hash: Some(hex(&ban.cert_hash)),
                    reason: Some(ban.reason),
                    start: None,
                    duration: Some(ban.duration_s),
                })
                .collect(),
        };
        vec![to_conn(inbound.conn, BAN_LIST, reply.encode_to_vec())]
    }
}

/// Certificate hashes travel as hex on the wire, as they do in murmur.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Serve for ModerationService {
    const NAME: &'static str = "moderation";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            permit: Permit::new(ctx.resolver.clone()),
            resolver: ctx.resolver.clone(),
            trail: Trail::new(ctx.resolver.clone()),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(ModerationServer::new(ModerationRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

/// The outer type this service owns.
#[must_use]
pub const fn outer_type() -> u16 {
    ServiceKind::Moderation.outer_type()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kick_ban_stores_an_address_the_ban_check_can_match() {
        // The ban table is searched with `covers`, which walks the stored bytes
        // against the address a connecting peer presents. Storing the
        // `host:port` string instead would write a ban that never matches
        // anything and reports itself as applied.
        let stored = address_bytes("172.26.0.1:47498");
        assert_eq!(stored.len(), 16, "the v6-mapped form, as `covers` expects");
        assert!(covers(
            &Ban {
                address: stored.clone(),
                prefix_len: 128,
                ..Ban::default()
            },
            &stored
        ));
    }

    #[test]
    fn a_ban_on_one_address_does_not_catch_another() {
        let banned = address_bytes("172.26.0.1:47498");
        let someone_else = address_bytes("172.26.0.2:1234");
        assert!(!covers(
            &Ban {
                address: banned,
                prefix_len: 128,
                ..Ban::default()
            },
            &someone_else
        ));
    }

    #[test]
    fn an_unparseable_address_is_stored_as_nothing_rather_than_as_everything() {
        // `covers` returns false for an empty stored address, so an address it
        // could not read becomes a ban that matches nobody. The alternative —
        // storing a partial or zeroed value — is a ban that matches everybody.
        assert!(address_bytes("not-an-address").is_empty());
        assert!(!covers(
            &Ban {
                address: Vec::new(),
                prefix_len: 128,
                ..Ban::default()
            },
            &address_bytes("172.26.0.1:1")
        ));
    }

    fn ban(address: &[u8], prefix: u32) -> Ban {
        Ban {
            address: address.to_vec(),
            prefix_len: prefix,
            duration_s: 0,
            ..Ban::default()
        }
    }

    #[test]
    fn a_ban_on_a_subnet_covers_addresses_inside_it_and_no_others() {
        let subnet = ban(&[10, 0, 0, 0], 24);
        assert!(covers(&subnet, &[10, 0, 0, 7]));
        assert!(!covers(&subnet, &[10, 0, 1, 7]));
    }

    #[test]
    fn a_prefix_that_is_not_a_whole_byte_still_masks_correctly() {
        // /28 inside the last byte: the classic off-by-one in a hand-rolled
        // prefix check, and the one that silently bans a neighbour.
        let subnet = ban(&[192, 168, 1, 0], 28);
        assert!(covers(&subnet, &[192, 168, 1, 15]));
        assert!(!covers(&subnet, &[192, 168, 1, 16]));
    }

    #[test]
    fn a_zero_duration_ban_never_expires() {
        // murmur's convention; treating 0 as "already over" would quietly undo
        // every permanent ban on the first sweep.
        assert!(!expired(&ban(&[1, 2, 3, 4], 32), u64::MAX));
    }

    #[test]
    fn a_timed_ban_expires_when_its_duration_has_run() {
        let timed = Ban {
            start_ms: 1_000,
            duration_s: 60,
            ..ban(&[1, 2, 3, 4], 32)
        };
        assert!(!expired(&timed, 30_000));
        assert!(expired(&timed, 120_000));
    }
}
