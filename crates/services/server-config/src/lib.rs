//! `server-config` — the settings an operator changes while the server runs.
//!
//! murmur keeps deployment and operational settings in one `Config` table.
//! Starling splits them because they have different lifetimes: endpoints and
//! ports need a restart anyway and live in the TOML, while `bandwidth`,
//! `messagelimit`, `welcometext` and the rest are expected to change live
//! (`docs/CONFIGURATION.md`).
//!
//! It is **essential** for a specific reason: the gateway cannot rate-limit
//! without `messagelimit` and the handshake cannot complete without the config
//! the client is sent. A cold start with this down must reject logins rather
//! than quietly serve on defaults the operator never chose.
//!
//! One actor per virtual server, published as a snapshot readers cache — the
//! same pattern metadata uses for membership.

use std::collections::HashMap;
use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::Scope;
use starling_proto_fancy::fancy::domain::{
    ConfigValues, ServerConfigEnvelope, server_config_envelope,
};
use starling_proto_fancy::serverconfig::server_config_server::{
    ServerConfig as ServerConfigRpc, ServerConfigServer,
};
use starling_proto_fancy::serverconfig::{GetRequest, SetRequest, Snapshot};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::{RwLock, broadcast};
use tonic::{Request, Response, Status};

pub mod snapshot;

pub use snapshot::{apply_fields, defaults, redact};

/// The schema: one row per virtual server, typed columns, no EAV.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_server_config",
    &["CREATE TABLE IF NOT EXISTS server_config (\
         server_id BIGINT PRIMARY KEY, \
         version BIGINT NOT NULL, \
         settings BLOB NOT NULL)"],
)];

/// How many snapshots a lagging subscriber may fall behind. Bounded, because an
/// unbounded inbox turns one slow reader into an OOM.
const WATCH_BUFFER: usize = 32;

/// The service.
#[derive(Debug)]
pub struct ServerConfigService {
    snapshots: RwLock<HashMap<u32, Snapshot>>,
    updates: broadcast::Sender<Snapshot>,
    store: Option<Store>,
    fanout: Fanout,
}

impl ServerConfigService {
    /// The current snapshot for `scope`, or the shipped defaults.
    pub async fn snapshot(&self, scope: u32) -> Snapshot {
        self.snapshots
            .read()
            .await
            .get(&scope)
            .cloned()
            .unwrap_or_else(|| defaults(scope))
    }

    async fn publish(&self, snapshot: Snapshot) {
        let _ = self
            .snapshots
            .write()
            .await
            .insert(snapshot.virtual_server, snapshot.clone());
        if let Some(store) = &self.store
            && let Err(error) = persist(store, &snapshot).await
        {
            // Reported rather than swallowed: an operator whose change
            // vanishes must not learn about it from the next restart.
            tracing::error!(%error, "could not persist a configuration change");
        }
        let _ = self.updates.send(snapshot);
    }
}

async fn persist(store: &Store, snapshot: &Snapshot) -> Result<(), starling_runtime::StoreError> {
    let bytes = snapshot.encode_to_vec();
    sqlx::query(
        "INSERT INTO server_config (server_id, version, settings) VALUES (?, ?, ?) \
         ON CONFLICT (server_id) DO UPDATE SET version = excluded.version, settings = excluded.settings",
    )
    .bind(i64::from(snapshot.virtual_server))
    .bind(snapshot.version as i64)
    .bind(bytes)
    .execute(store.pool())
    .await
    .map(|_| ())
    .map_err(|error| starling_runtime::StoreError::Query(format!("server_config: {error}")))
}

async fn load(store: &Store, scope: u32) -> Option<Snapshot> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT settings FROM server_config WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_optional(store.pool())
        .await
        .ok()??;
    let bytes: Vec<u8> = row.try_get("settings").ok()?;
    Snapshot::decode(bytes.as_slice()).ok()
}

/// The gRPC surface, as a type this crate owns.
///
/// tonic's generated trait is foreign and `Arc` is foreign, so the service
/// cannot implement it through an `Arc` directly. A one-field wrapper is the
/// whole of the workaround, and it keeps the RPC methods visibly separate from
/// the service's own.
#[derive(Debug, Clone)]
pub struct ConfigRpc(Arc<ServerConfigService>);

#[tonic::async_trait]
impl ServerConfigRpc for ConfigRpc {
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<Snapshot>, Status> {
        let scope = scope_of(request.into_inner().scope);
        Ok(Response::new(self.0.snapshot(scope).await))
    }

    async fn set(&self, request: Request<SetRequest>) -> Result<Response<Snapshot>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let mut current = self.0.snapshot(scope).await;
        let Some(values) = req.values else {
            return Ok(Response::new(current));
        };
        // Only the named fields are written, so two operators editing different
        // settings do not overwrite each other.
        apply_fields(&mut current, &values, &req.fields);
        current.version += 1;
        self.0.publish(current.clone()).await;
        Ok(Response::new(current))
    }

    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<Snapshot, Status>>;

    async fn watch(
        &self,
        request: Request<GetRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let scope = scope_of(request.into_inner().scope);
        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_BUFFER);
        // Snapshot first, then deltas: a subscriber that connected after a
        // change must not have to ask for the state it missed.
        let _ = tx.send(Ok(self.0.snapshot(scope).await)).await;

        let mut updates = self.0.updates.subscribe();
        drop(tokio::spawn(async move {
            while let Ok(snapshot) = updates.recv().await {
                if snapshot.virtual_server != scope {
                    continue;
                }
                if tx.send(Ok(snapshot)).await.is_err() {
                    return;
                }
            }
        }));
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

impl ClientService for ServerConfigService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::ServerConfig.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = ServerConfigEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable ServerConfigEnvelope"
            );
            return Actions::new();
        };
        match envelope.body {
            Some(server_config_envelope::Body::Query(_)) => {
                let snapshot = self.snapshot(inbound.scope).await;
                let reply = ServerConfigEnvelope {
                    body: Some(server_config_envelope::Body::Values(ConfigValues {
                        settings: redact(&snapshot),
                        version: snapshot.version,
                    })),
                };
                vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
            }
            // An update from a client is refused rather than half-applied:
            // changing operational settings is an operator action, and the
            // operator plane carries an identity this one does not.
            _ => Actions::new(),
        }
    }
}

impl Serve for ServerConfigService {
    const NAME: &'static str = "server-config";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("settings loaded");
        let store = match ctx.storage().await {
            Ok(store) => {
                store.migrate(SCHEMA).await?;
                Some(store)
            }
            Err(error) => {
                // Persisting is optional; serving is not. A throwaway server
                // should not need a database to boot.
                tracing::warn!(%error, "running without persisted settings");
                None
            }
        };

        let mut snapshots = HashMap::new();
        for scope in ctx.virtual_servers() {
            let snapshot = match &store {
                Some(store) => load(store, scope).await.unwrap_or_else(|| defaults(scope)),
                None => defaults(scope),
            };
            let _ = snapshots.insert(scope, snapshot);
        }

        let (updates, _) = broadcast::channel(WATCH_BUFFER);
        ctx.health.ready("settings loaded");
        Ok(Arc::new(Self {
            snapshots: RwLock::new(snapshots),
            updates,
            store,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(ServerConfigServer::new(ConfigRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

/// The scope a request names, defaulting to the first virtual server.
#[must_use]
pub fn scope_of(scope: Option<Scope>) -> u32 {
    scope.map_or(1, |scope| scope.virtual_server)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Arc<ServerConfigService> {
        let (updates, _) = broadcast::channel(8);
        Arc::new(ServerConfigService {
            snapshots: RwLock::new(HashMap::new()),
            updates,
            store: None,
            fanout: Fanout::default(),
        })
    }

    #[tokio::test]
    async fn an_unset_virtual_server_reads_the_documented_defaults() {
        // The gateway sizes its buckets from this; a zero would mean no
        // messages at all rather than murmur's 1/s.
        let snapshot = service().snapshot(1).await;
        assert_eq!(snapshot.message_limit, 1);
        assert_eq!(snapshot.message_burst, 5);
        assert!(snapshot.max_users > 0);
    }

    #[tokio::test]
    async fn setting_one_field_leaves_the_others_alone() {
        // Two operators editing different settings must not overwrite each
        // other, which a whole-snapshot write would guarantee they do.
        let service = service();
        let mut values = defaults(1);
        values.welcome_text = "hello".to_owned();
        values.max_users = 1;

        let updated = ServerConfigRpc::set(
            &ConfigRpc(Arc::clone(&service)),
            Request::new(SetRequest {
                scope: Some(Scope { virtual_server: 1 }),
                actor: None,
                fields: vec!["welcome_text".to_owned()],
                values: Some(values),
            }),
        )
        .await
        .expect("set")
        .into_inner();

        assert_eq!(updated.welcome_text, "hello");
        assert_eq!(updated.max_users, defaults(1).max_users);
        assert_eq!(updated.version, 1);
    }

    #[tokio::test]
    async fn the_server_password_is_never_read_back() {
        // An operator sets it; nobody reads it. Handing it to a client would
        // make a chat window a credential store.
        let mut snapshot = defaults(1);
        snapshot.password = "hunter2".to_owned();
        let settings = redact(&snapshot);
        assert!(
            !settings.iter().any(|s| s.value.contains("hunter2")),
            "no readable field may carry the password"
        );
        let password = settings
            .iter()
            .find(|s| s.key == "password")
            .expect("the password is named even though it is withheld");
        assert!(password.secret, "it must say it is withheld");
        assert!(password.value.is_empty());
    }
}
