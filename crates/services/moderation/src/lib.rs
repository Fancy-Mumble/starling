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

use async_trait::async_trait;
use prost::Message as _;
use starling_proto_fancy::moderation::moderation_server::{Moderation, ModerationServer};
use starling_proto_fancy::moderation::{
    Ban, BanCheck, BanList, BanRequest, BanResult, BanVerdict, KickRequest, UnbanRequest,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::now_ms;
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, disconnect, to_conn,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tonic::{Request, Response, Status};

/// Upstream `UserRemove`: a kick, or a kick with a ban flag.
const USER_REMOVE: u16 = 8;
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
}

impl ModerationService {
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
            return Ok(Response::new(BanResult {
                applied: false,
                refused: error.to_string(),
                bans: Vec::new(),
            }));
        }
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

#[async_trait]
impl ClientService for ModerationService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            BAN_LIST => self.on_ban_list(&inbound).await,
            USER_REMOVE => Actions::new(),
            _ => Actions::new(),
        }
    }
}

impl ModerationService {
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

#[async_trait]
impl Serve for ModerationService {
    const NAME: &'static str = "moderation";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
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
