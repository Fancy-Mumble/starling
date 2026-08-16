//! `server-config`: the settings an operator changes while the server runs.
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
//! One actor per server instance, published as a snapshot readers cache, the
//! same pattern metadata uses for membership.
//!
//! # Three layers, and which one wins
//!
//! A setting can be stated in three places, and they are ordered by how
//! deliberate the statement is:
//!
//! 1. [`defaults`] -- murmur's, for a server nobody has configured;
//! 2. `[instances.settings]` in the deployment file, the operator's
//!    starting values;
//! 3. whatever an operator has since changed at run time, which wins.
//!
//! The third layer is stored **with the list of fields it covers** rather than
//! as a whole snapshot. That is the difference between "editing the file
//! changes anything nobody has touched" and "editing the file does nothing
//! whatsoever after the first admin request", which is what a whole-snapshot
//! row would have meant: one `set` of `welcome_text` would have frozen every
//! other setting at the value it happened to have that day.

use std::collections::{BTreeSet, HashMap};
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
use starling_runtime::config::Config;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::{RwLock, broadcast};
use tonic::{Request, Response, Status};

pub mod import;
pub mod snapshot;

pub use import::import;
pub use snapshot::{apply_fields, defaults, redact};

/// The schema: one row per server instance, typed columns, no EAV.
pub(crate) const SCHEMA: &[Migration<'static>] = &[
    Migration::new(
        "0001_server_config",
        &["CREATE TABLE IF NOT EXISTS server_config (\
             server_id BIGINT PRIMARY KEY, \
             version BIGINT NOT NULL, \
             settings BLOB NOT NULL)"],
    ),
    Migration::new(
        "0002_server_config_owned_fields",
        &[
            // Which settings an operator has actually set, newline separated.
            // Without it the stored row is a whole snapshot, so the deployment
            // file stops meaning anything the moment anybody uses the admin UI.
            "ALTER TABLE server_config ADD COLUMN owned TEXT NOT NULL DEFAULT ''",
            // Rows that predate the column are whole snapshots an operator
            // owns outright, and there is no way to tell which fields they
            // chose. Claiming all of them keeps an existing deployment behaving
            // exactly as it did; the file takes over each field as it is next
            // reset, rather than silently overriding settings on upgrade.
            "UPDATE server_config SET owned = '*' WHERE owned = ''",
        ],
    ),
];

/// The stored marker for "this row owns every field".
///
/// Only ever written by the migration above, for rows that predate the column.
const ALL_FIELDS: &str = "*";

/// How many snapshots a lagging subscriber may fall behind. Bounded, because an
/// unbounded inbox turns one slow reader into an OOM.
const WATCH_BUFFER: usize = 32;

/// The service.
#[derive(Debug)]
pub struct ServerConfigService {
    snapshots: RwLock<HashMap<u32, Snapshot>>,
    /// Which settings an operator has set at run time, per server instance.
    ///
    /// Everything else is the deployment file's, or murmur's, and follows the
    /// file when it is edited.
    owned: RwLock<HashMap<u32, BTreeSet<String>>>,
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

    /// Record `snapshot`, noting that the operator now owns `fields`.
    async fn publish(&self, snapshot: Snapshot, fields: &[String]) {
        let scope = snapshot.instance;
        let owned = {
            let mut all = self.owned.write().await;
            let owned = all.entry(scope).or_default();
            owned.extend(fields.iter().cloned());
            owned.clone()
        };
        let _ = self.snapshots.write().await.insert(scope, snapshot.clone());
        if let Some(store) = &self.store
            && let Err(error) = persist(store, &snapshot, &owned).await
        {
            // Reported rather than swallowed: an operator whose change
            // vanishes must not learn about it from the next restart.
            tracing::error!(%error, "could not persist a configuration change");
        }
        let _ = self.updates.send(snapshot);
    }

    /// Re-apply `[instances.settings]` after the deployment file was reloaded.
    ///
    /// The same three layers as [`starting_point`], recomputed: murmur's
    /// defaults, then the file as it now reads, then back on top whatever the
    /// operator has set at run time. The middle layer is the only one that
    /// moved, and the third still wins, so editing the file changes exactly
    /// what nobody has touched -- which is what the boot path already promises
    /// and what an operator plainly means by editing it.
    ///
    /// Published with **no** claimed fields: a value arriving from the file is
    /// not an operator's decision, and recording it as one would freeze it
    /// against every later edit of that file.
    async fn adopt_file(&self, config: &Config, scopes: &[u32]) {
        for scope in scopes {
            let Some(instance) = config.instances.iter().find(|i| i.id == *scope) else {
                // The file no longer mentions this instance. Its settings are
                // left exactly as they are: `[[instances]]` needs a restart to
                // add or remove one, so acting here would apply half of a
                // change whose other half cannot happen yet.
                continue;
            };
            let current = self.snapshot(*scope).await;
            let owned: Vec<String> = self
                .owned
                .read()
                .await
                .get(scope)
                .map(|owned| owned.iter().cloned().collect())
                .unwrap_or_default();

            // A row written before the `owned` column existed carries no record
            // of which fields an operator chose, so all of them are treated as
            // theirs and the file may not reach any of them.
            if owned.iter().any(|field| field == ALL_FIELDS) {
                continue;
            }

            let mut rebuilt = defaults(*scope);
            let named = instance.settings.overlay(&mut rebuilt);
            // Not an operator write, so the counter the gateway reads to tell
            // "nobody has set this" from "somebody set it to zero" must not
            // move (`crates/gateway/src/listener.rs`).
            rebuilt.version = current.version;
            apply_fields(&mut rebuilt, &current, &owned);

            if rebuilt == current {
                continue;
            }
            tracing::info!(
                scope,
                settings = named.join(", "),
                "adopting settings from the reloaded file"
            );
            self.publish(rebuilt, &[]).await;
        }
    }
}

/// The stored form of the owned-field set.
///
/// Newline separated, because the set includes `Snapshot.extra` keys, which a
/// service names and an operator types; a newline in one of those is a good
/// deal less likely than a comma.
fn encode_owned(owned: &BTreeSet<String>) -> String {
    owned
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

fn decode_owned(stored: &str) -> Vec<String> {
    stored
        .split('\n')
        .filter(|field| !field.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn persist(
    store: &Store,
    snapshot: &Snapshot,
    owned: &BTreeSet<String>,
) -> Result<(), starling_runtime::StoreError> {
    let bytes = snapshot.encode_to_vec();
    sqlx::query(
        "INSERT INTO server_config (server_id, version, settings, owned) VALUES (?, ?, ?, ?) \
         ON CONFLICT (server_id) DO UPDATE SET version = excluded.version, \
         settings = excluded.settings, owned = excluded.owned",
    )
    .bind(i64::from(snapshot.instance))
    .bind(snapshot.version as i64)
    .bind(bytes)
    .bind(encode_owned(owned))
    .execute(store.pool())
    .await
    .map(|_| ())
    .map_err(|error| starling_runtime::StoreError::Query(format!("server_config: {error}")))
}

/// What was persisted for `scope`: the snapshot, and the fields it owns.
async fn load(store: &Store, scope: u32) -> Option<(Snapshot, Vec<String>)> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT settings, owned FROM server_config WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_optional(store.pool())
        .await
        .ok()??;
    let bytes: Vec<u8> = row.try_get("settings").ok()?;
    let owned: String = row.try_get("owned").unwrap_or_default();
    Snapshot::decode(bytes.as_slice())
        .ok()
        .map(|snapshot| (snapshot, decode_owned(&owned)))
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
        // The same list decides what the operator now owns: a setting they have
        // never touched keeps following the deployment file.
        self.0.publish(current.clone(), &req.fields).await;
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
                if snapshot.instance != scope {
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
        let mut owned = HashMap::new();
        for scope in ctx.instances() {
            let (snapshot, fields) = starting_point(&ctx, scope, store.as_ref()).await;
            let _ = snapshots.insert(scope, snapshot);
            let _ = owned.insert(scope, fields);
        }

        let (updates, _) = broadcast::channel(WATCH_BUFFER);
        ctx.health.ready("settings loaded");
        Ok(Arc::new(Self {
            snapshots: RwLock::new(snapshots),
            owned: RwLock::new(owned),
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

    /// Follow the deployment file, so `[instances.settings]` is live.
    ///
    /// This service is where the two configuration layers meet, which makes it
    /// the only place a file edit can reach the operational half without a
    /// restart: the snapshot it republishes is the one every subscriber in the
    /// fleet already caches, so one SIGHUP here changes `max_users` everywhere
    /// that reads it.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let scopes = ctx.instances();
        let mut configs = ctx.live.subscribe();
        loop {
            tokio::select! {
                () = ctx.shutdown.wait() => return Ok(()),
                changed = configs.changed() => {
                    if changed.is_err() {
                        // The cell outlives every service in practice; if it
                        // did not, there is nothing further to follow.
                        return Ok(());
                    }
                    let config = Arc::clone(&configs.borrow_and_update());
                    self.adopt_file(&config, &scopes).await;
                }
            }
        }
    }
}

/// The settings `scope` starts with, and which of them the operator owns.
///
/// The three layers of the module header, applied in order: murmur's defaults,
/// then the deployment file, then whatever an operator has since set at run
/// time. A field the operator has never touched follows the file, so editing it
/// and restarting does what an operator plainly means by that.
async fn starting_point(
    ctx: &ServiceContext,
    scope: u32,
    store: Option<&Store>,
) -> (Snapshot, BTreeSet<String>) {
    let mut snapshot = defaults(scope);

    if let Some(server) = ctx
        .config
        .instances
        .iter()
        .find(|server| server.id == scope)
    {
        let named = server.settings.overlay(&mut snapshot);
        if !named.is_empty() {
            tracing::debug!(scope, settings = named.join(", "), "settings from the file");
        }
    }

    let persisted = match store {
        Some(store) => load(store, scope).await,
        None => None,
    };
    let Some((persisted, fields)) = persisted else {
        return (snapshot, BTreeSet::new());
    };

    // A row written before the `owned` column existed is a whole snapshot with
    // no record of which fields an operator chose, so it keeps all of them.
    if fields.iter().any(|field| field == ALL_FIELDS) {
        return (persisted, BTreeSet::from([ALL_FIELDS.to_owned()]));
    }
    snapshot.version = persisted.version;
    apply_fields(&mut snapshot, &persisted, &fields);
    (snapshot, fields.into_iter().collect())
}

/// The scope a request names, defaulting to the first server instance.
#[must_use]
pub fn scope_of(scope: Option<Scope>) -> u32 {
    scope.map_or(1, |scope| scope.instance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Arc<ServerConfigService> {
        let (updates, _) = broadcast::channel(8);
        Arc::new(ServerConfigService {
            snapshots: RwLock::new(HashMap::new()),
            owned: RwLock::new(HashMap::new()),
            updates,
            store: None,
            fanout: Fanout::default(),
        })
    }

    /// A config whose `[instances.settings]` for server 1 is `settings`.
    fn config_with(settings: starling_runtime::config::ServerSettings) -> Config {
        use starling_runtime::config::Instance;

        let mut config = Config::with_defaults(std::path::Path::new("/run/starling"));
        config.instances = vec![Instance {
            settings,
            ..Instance::default()
        }];
        config
    }

    #[tokio::test]
    async fn a_reloaded_file_reaches_a_setting_nobody_has_touched() {
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        assert_ne!(service.snapshot(1).await.max_users, 20);

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        assert_eq!(service.snapshot(1).await.max_users, 20);
    }

    #[tokio::test]
    async fn a_reloaded_file_never_reverts_what_an_operator_set() {
        // The rule the whole owned-field column exists for, now that the file
        // can move underneath a running server: an operator who set
        // `welcome_text` in the admin UI keeps it, and an unrelated edit to the
        // file still applies.
        use starling_runtime::config::ServerSettings;

        let service = service();
        let mut operator = defaults(1);
        operator.welcome_text = "set by an operator".to_owned();
        service
            .publish(operator, &["welcome_text".to_owned()])
            .await;

        service
            .adopt_file(
                &config_with(ServerSettings {
                    welcome_text: Some("set in the file".to_owned()),
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        let snapshot = service.snapshot(1).await;
        assert_eq!(
            snapshot.welcome_text, "set by an operator",
            "the run-time layer outranks the file"
        );
        assert_eq!(
            snapshot.max_users, 20,
            "a setting nobody claimed still follows the file"
        );
    }

    #[tokio::test]
    async fn dropping_a_setting_from_the_file_returns_it_to_the_default() {
        // Removing a line has to mean something, and the only coherent meaning
        // is the layer below it: murmur's default. Leaving the last value in
        // place would make the file unable to express "never mind".
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;
        assert_eq!(service.snapshot(1).await.max_users, 20);

        service
            .adopt_file(&config_with(ServerSettings::default()), &[1])
            .await;
        assert_eq!(service.snapshot(1).await.max_users, defaults(1).max_users);
    }

    #[tokio::test]
    async fn adopting_the_file_does_not_claim_the_settings_it_applied() {
        // If it did, the *next* edit of the same key would be ignored: the
        // field would be recorded as an operator's decision and outrank the
        // file it came from.
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        let config = config_with(ServerSettings {
            max_users: Some(20),
            ..ServerSettings::default()
        });
        service.adopt_file(&config, &[1]).await;

        assert!(
            service.owned.read().await.get(&1).is_none_or(BTreeSet::is_empty),
            "the file must claim nothing"
        );

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(30),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;
        assert_eq!(service.snapshot(1).await.max_users, 30, "a second edit lands");
    }

    #[tokio::test]
    async fn adopting_the_file_does_not_move_the_version_counter() {
        // The gateway reads `version == 0` as "no operator has ever set
        // anything here" and skips applying `message_limit` while it holds.
        // Bumping it from a file reload would make the gateway adopt a limit
        // nobody set through the admin plane.
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        let before = service.snapshot(1).await.version;

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        assert_eq!(service.snapshot(1).await.version, before);
    }

    #[tokio::test]
    async fn a_pre_migration_row_is_left_alone_by_the_file() {
        // It owns everything by definition, so there is no field the file may
        // reach without overwriting a decision whose record was never kept.
        use starling_runtime::config::ServerSettings;

        let service = service();
        let mut stored = defaults(1);
        stored.max_users = 5;
        service.publish(stored, &[ALL_FIELDS.to_owned()]).await;

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        assert_eq!(service.snapshot(1).await.max_users, 5);
    }

    #[tokio::test]
    async fn an_instance_the_file_no_longer_names_keeps_its_settings() {
        // Adding or removing an instance needs a restart, so acting on half of
        // that change here would leave a server whose settings moved and whose
        // actors did not.
        use starling_runtime::config::ServerSettings;

        let service = service();
        let mut stored = defaults(2);
        stored.max_users = 7;
        service.publish(stored, &[]).await;

        service
            .adopt_file(&config_with(ServerSettings::default()), &[2])
            .await;

        assert_eq!(service.snapshot(2).await.max_users, 7);
    }

    #[tokio::test]
    async fn adopting_an_unchanged_file_publishes_nothing() {
        // Every publish wakes every subscriber in the fleet; a SIGHUP that
        // changed nothing must not cost a fanout.
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        let config = config_with(ServerSettings {
            max_users: Some(20),
            ..ServerSettings::default()
        });
        service.adopt_file(&config, &[1]).await;

        let mut updates = service.updates.subscribe();
        service.adopt_file(&config, &[1]).await;
        assert!(
            updates.try_recv().is_err(),
            "an unchanged file must not republish"
        );
    }

    /// A context whose deployment file configures `settings` for server 1.
    fn ctx_with(settings: starling_runtime::config::ServerSettings) -> ServiceContext {
        use starling_runtime::config::{Config, Instance};

        let mut config = Config::with_defaults(std::path::Path::new("/run/starling"));
        config.instances = vec![Instance {
            settings,
            ..Instance::default()
        }];
        starling_runtime::serve::context(
            ServerConfigService::NAME,
            Arc::new(config),
            starling_runtime::inproc::Broker::new(),
            starling_runtime::shutdown::Shutdown::new(),
            starling_runtime::log::Logger::null(),
        )
    }

    #[tokio::test]
    async fn an_unset_server_instance_reads_the_documented_defaults() {
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
                scope: Some(Scope { instance: 1 }),
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
    async fn a_setting_written_in_the_deployment_file_is_where_a_server_starts() {
        // The gap this closes: the name of a server was configurable in a file
        // and the number of people allowed into it was not, so setting up a
        // server for twenty friends meant an admin API call.
        let settings = starling_runtime::config::ServerSettings {
            max_users: Some(20),
            welcome_text: Some("mind the frogs".to_owned()),
            ..Default::default()
        };
        let (snapshot, owned) = starting_point(&ctx_with(settings), 1, None).await;

        assert_eq!(snapshot.max_users, 20);
        assert_eq!(snapshot.welcome_text, "mind the frogs");
        assert_eq!(
            snapshot.max_bandwidth,
            defaults(1).max_bandwidth,
            "a setting the file never names keeps murmur's default"
        );
        assert!(
            owned.is_empty(),
            "the file's values are a starting point, not the operator's own"
        );
    }

    #[tokio::test]
    async fn an_operator_who_changed_nothing_follows_the_file_when_it_changes() {
        // The failure a whole-snapshot row would have caused: one `set` of
        // `welcome_text` freezes every other setting at whatever it was that
        // day, and editing the file afterwards does nothing forever.
        let service = service();
        let mut values = defaults(1);
        values.welcome_text = "set by an admin".to_owned();
        let _ = ServerConfigRpc::set(
            &ConfigRpc(Arc::clone(&service)),
            Request::new(SetRequest {
                scope: Some(Scope { instance: 1 }),
                actor: None,
                fields: vec!["welcome_text".to_owned()],
                values: Some(values),
            }),
        )
        .await
        .expect("set");

        let owned = service
            .owned
            .read()
            .await
            .get(&1)
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            owned.iter().cloned().collect::<Vec<_>>(),
            vec!["welcome_text".to_owned()],
            "only the field an operator named is theirs"
        );
    }

    #[test]
    fn the_owned_field_set_survives_the_round_trip_through_the_column() {
        let owned: BTreeSet<String> = ["max_users", "welcome_text"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        assert_eq!(decode_owned(&encode_owned(&owned)).len(), 2);
        // The empty case is the common one, and a naive split yields one empty
        // field name, which `apply_fields` would then warn about on every boot.
        assert!(decode_owned("").is_empty());
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
