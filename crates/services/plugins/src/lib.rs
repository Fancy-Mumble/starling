//! `plugins`: the host, and the storage capability plugins persist through.
//!
//! **Plugins are opaque to the server.** It shuttles opaque data and offers
//! generic callbacks (permissions, sessions, config, storage) and never learns
//! a plugin's name, message schema or feature semantics. That principle was
//! applied to the wire protocol; it applies equally to storage, which is why
//! the core schema contains no plugin-specific tables and a plugin gets a
//! namespace instead (`docs/STORAGE.md` L6).
//!
//! Storage is **ordered, namespaced key/value with atomic batches** (§5.4). The
//! namespace is implicit: the host knows which plugin is calling and scopes
//! every operation to it, so a plugin cannot name (or reach) another's data.
//!
//! # The host
//!
//! [`starling_plugin_host`] does the loading and the dispatching; this service
//! is what makes it a Starling service. It supplies the bridge the host reaches
//! the server through ([`bridge`]), the event feed it dispatches from
//! ([`events`]), and the wire plane plugin traffic arrives on.
//!
//! Every call into the host runs on the blocking pool. Plugin hooks are
//! synchronous by contract and a plugin may do anything inside one -- open a
//! socket, hit a disk, sleep -- so running them on a runtime worker would stall
//! tasks that have nothing to do with plugins. The precedent is `userdata`,
//! which puts Argon2 hashing on the same pool for the same reason.
//!
//! A panicking native plugin takes the process with it, because the release
//! profile is `panic = "abort"`. That is the same posture the C++ server ships
//! with rather than a regression, and it is why a native plugin is trusted
//! first-party code and anything installable should be WASM.

mod bridge;
mod events;

use std::sync::{Arc, Mutex, PoisonError};

use prost::Message as _;
use starling_plugin_host::{Host, PluginMessageInArgs};
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::feature::{
    AdminResult, PluginDescriptor, PluginsEnvelope, Registry, plugins_envelope,
};
use starling_proto_fancy::plugins::plugins_server::{Plugins, PluginsServer};
use starling_proto_fancy::plugins::{
    EnableRequest, InstallRequest, KvGetRequest, KvPage, KvPair, KvScanRequest, KvValue,
    KvWriteRequest, Plugin, PluginList, PluginMessage, PluginResult, UninstallRequest,
};
use starling_proto_fancy::sessionview::SubscribeRequest;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{KvOp, KvStore};
use tonic::{Request, Response, Status};

use crate::bridge::{HOST_NAMESPACE, StarlingBridge};
use crate::events::{Presence, Presences};

/// Upstream `PluginDataTransmission`: opaque client-to-client plugin data.
pub(crate) const PLUGIN_DATA: u16 = 26;

/// Readiness gate: membership is unknown until `session-view` answers.
const VIEW_GATE: &str = "session-view";

/// How long to wait before re-subscribing to `session-view`.
const RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// The host, and the rule that every call into it blocks somewhere safe.
///
/// One mutex around the whole host, exactly as the C++ integration had: every
/// inbound event and every admin operation is serialised. That was fast enough
/// for a server full of people and it is the arrangement that makes plugin
/// state need no locking of its own. Do not shard it before something measures
/// slow.
#[derive(Debug, Clone)]
struct HostHandle(Arc<Mutex<Host>>);

impl HostHandle {
    /// Run `work` against the host, on a thread where blocking is allowed.
    ///
    /// `None` means the work panicked. In release that cannot be observed --
    /// `panic = "abort"` has already taken the process -- so this is the debug
    /// and test path, where swallowing a plugin panic beats letting it end the
    /// task that was dispatching to it.
    async fn with<R, F>(&self, work: F) -> Option<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut Host) -> R + Send + 'static,
    {
        let host = Arc::clone(&self.0);
        let done = tokio::task::spawn_blocking(move || {
            // A poisoned lock means a plugin panicked while holding it. The
            // host is still structurally sound -- the panic was inside one
            // plugin's hook -- so recovering beats refusing every plugin
            // operation for the rest of the process's life.
            let mut host = host.lock().unwrap_or_else(PoisonError::into_inner);
            work(&mut host)
        })
        .await;
        match done {
            Ok(result) => Some(result),
            Err(error) => {
                tracing::error!(%error, "a plugin hook panicked");
                None
            }
        }
    }
}

/// The service.
#[derive(Debug)]
pub struct PluginsService {
    host: HostHandle,
    roster: Arc<Roster>,
    kv: KvStore,
    fanout: Fanout,
    logger: Logger,
    /// Which server instance this host serves.
    scope: u32,
}

impl PluginsService {
    /// Every plugin the host knows about, as the admin surface sees them.
    async fn list(&self) -> Vec<Plugin> {
        let listed = self.host.with(|host| host.list_plugins().0).await;
        listed
            .unwrap_or_default()
            .into_iter()
            .map(|info| Plugin {
                id: info.plugin_name.clone(),
                name: info.plugin_name,
                version: info.version,
                enabled: info.enabled,
                wasm: info.kind == "wasm",
                capabilities: Vec::new(),
            })
            .collect()
    }

    /// What a client is told is loaded.
    async fn registry(&self) -> Vec<PluginDescriptor> {
        self.host
            .with(|host| host.registry())
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|entry| PluginDescriptor {
                id: entry.plugin_name.clone(),
                name: entry.plugin_name,
                version: entry.version,
                enabled: true,
                info_json: entry.info_json,
            })
            .collect()
    }

    /// Re-send the registry to every connected client.
    ///
    /// Called whenever the loaded set changes. A client that asked once and was
    /// never told again would keep drawing a plugin that has gone.
    async fn broadcast_registry(&self) {
        let envelope = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Registry(Registry {
                plugins: self.registry().await,
            })),
        };
        self.fanout.push(to_sessions(
            Vec::new(),
            ServiceKind::Plugins.outer_type(),
            envelope.encode_to_vec(),
        ));
    }

    /// Keep the roster and the plugins in step with `session-view`, until the
    /// subscription ends.
    async fn follow_sessions(&self, ctx: &ServiceContext) {
        let Ok(transport) = ctx.resolver.channel("session-view") else {
            // Worth saying out loud: with no membership, a plugin is told about
            // nobody and every channel-addressed message reaches nobody, which
            // from the outside is indistinguishable from a quiet server.
            tracing::warn!("cannot reach session-view; plugins will see nobody");
            return;
        };
        let Ok(stream) = SessionViewClient::new(transport)
            .subscribe(SubscribeRequest {
                scope: Some(starling_proto_fancy::common::Scope {
                    instance: self.scope,
                }),
                subscriber: Self::NAME.to_owned(),
            })
            .await
        else {
            return;
        };

        let mut presences = Presences::new(self.scope);
        let mut events = stream.into_inner();
        while let Ok(Some(event)) = events.message().await {
            // The roster first: a plugin's `on_client_connected` may ask who is
            // in a channel, and the answer must already include the arrival it
            // is being told about.
            let _ = self.roster.apply(event.clone());
            for change in presences.apply(&event) {
                self.dispatch_presence(change).await;
            }
            ctx.health.ready(VIEW_GATE);
        }
        tracing::warn!("the session-view subscription ended; plugins now see stale membership");
    }

    /// Tell the plugins about one arrival or departure.
    async fn dispatch_presence(&self, change: Presence) {
        match change {
            Presence::Arrived(info) => {
                let _ = self
                    .host
                    .with(move |host| host.on_client_connected(info))
                    .await;
            }
            Presence::Left { server_id, session } => {
                let _ = self
                    .host
                    .with(move |host| host.on_client_disconnected(server_id, session))
                    .await;
            }
        }
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct PluginsRpc(Arc<PluginsService>);

#[tonic::async_trait]
impl Plugins for PluginsRpc {
    async fn list(
        &self,
        _request: Request<starling_proto_fancy::common::Scope>,
    ) -> Result<Response<PluginList>, Status> {
        Ok(Response::new(PluginList {
            plugins: self.0.list().await,
        }))
    }

    async fn enable(
        &self,
        request: Request<EnableRequest>,
    ) -> Result<Response<PluginResult>, Status> {
        let req = request.into_inner();
        let (id, enabled) = (req.id, req.enabled);
        let outcome = {
            let id = id.clone();
            self.0
                .host
                .with(move |host| host.set_enabled(&id, enabled))
                .await
        };
        let Some(outcome) = outcome else {
            return Err(Status::internal("the plugin host is unavailable"));
        };
        if let Err(refused) = outcome {
            return Ok(Response::new(PluginResult {
                applied: false,
                refused,
                plugin: None,
            }));
        }

        tracing::info!(%id, enabled, "plugin enablement changed");
        // Loading or unloading code is a notice-level fact whether or not
        // anybody is watching: "when did this start running" is unanswerable
        // afterwards.
        self.0.logger.log(
            LogEvent::notice(
                Category::Plugin,
                if enabled {
                    "plugin enabled"
                } else {
                    "plugin disabled"
                },
            )
            .with("plugin", id.clone()),
        );
        self.0.broadcast_registry().await;
        let plugin = self
            .0
            .list()
            .await
            .into_iter()
            .find(|plugin| plugin.id == id);
        Ok(Response::new(PluginResult {
            applied: true,
            refused: String::new(),
            plugin,
        }))
    }

    async fn install(
        &self,
        request: Request<InstallRequest>,
    ) -> Result<Response<PluginResult>, Status> {
        let req = request.into_inner();
        // The binary is fetched from the files service by key, never carried
        // inline: a plugin binary on the control plane would head-of-line block
        // every control message behind it.
        if req.source_key.is_empty() {
            return Ok(Response::new(PluginResult {
                applied: false,
                refused: "an install needs a source key".to_owned(),
                plugin: None,
            }));
        }
        // The host can install from bytes -- digest-checked, name-sanitised,
        // rolled back on a failed load -- but nothing here can *get* the bytes
        // yet: `files` exposes signed URLs and `Stat`, not a read, so fetching
        // one means an HTTP client this service does not have. Refused with the
        // reason rather than accepted and silently ignored, which is what the
        // previous version of this call did.
        tracing::warn!(
            id = %req.id,
            source = %req.source_key,
            "install refused: fetching a plugin binary from files is not wired up"
        );
        Ok(Response::new(PluginResult {
            applied: false,
            refused: "installing from a files key is not implemented yet; \
                      place the binary in the configured plugins_dir and enable it"
                .to_owned(),
            plugin: None,
        }))
    }

    async fn uninstall(
        &self,
        request: Request<UninstallRequest>,
    ) -> Result<Response<PluginResult>, Status> {
        let req = request.into_inner();
        let id = req.id;
        let outcome = {
            let id = id.clone();
            self.0
                .host
                .with(move |host| host.uninstall_plugin(&id))
                .await
        };
        let Some(outcome) = outcome else {
            return Err(Status::internal("the plugin host is unavailable"));
        };
        if let Err(refused) = outcome {
            return Ok(Response::new(PluginResult {
                applied: false,
                refused,
                plugin: None,
            }));
        }
        self.0
            .logger
            .log(LogEvent::notice(Category::Plugin, "plugin uninstalled").with("plugin", id));
        self.0.broadcast_registry().await;
        Ok(Response::new(PluginResult {
            applied: true,
            refused: String::new(),
            plugin: None,
        }))
    }

    async fn deliver(&self, request: Request<PluginMessage>) -> Result<Response<Ack>, Status> {
        let message = request.into_inner();
        let envelope = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Opaque(
                starling_proto_fancy::fancy::feature::Opaque {
                    plugin: message.plugin,
                    payload: message.payload,
                    recipients: message.recipients.clone(),
                    sender: message.session,
                    payload_type: message.payload_type,
                },
            )),
        };
        self.0.fanout.push(to_sessions(
            message.recipients,
            ServiceKind::Plugins.outer_type(),
            envelope.encode_to_vec(),
        ));
        Ok(Response::new(Ack {}))
    }

    async fn kv_get(&self, request: Request<KvGetRequest>) -> Result<Response<KvValue>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |scope| scope.instance);
        let plugin = plugin_namespace(&req.plugin)?;
        let value = self
            .0
            .kv
            .get(plugin, scope, &req.key)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(KvValue {
            found: value.is_some(),
            value: value.unwrap_or_default(),
        }))
    }

    async fn kv_scan(&self, request: Request<KvScanRequest>) -> Result<Response<KvPage>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |scope| scope.instance);
        let plugin = plugin_namespace(&req.plugin)?;
        let pairs = self
            .0
            .kv
            .scan(plugin, scope, &req.start, &req.end, req.limit, req.reverse)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(KvPage {
            pairs: pairs
                .into_iter()
                .map(|(key, value)| KvPair { key, value })
                .collect(),
        }))
    }

    async fn kv_write(&self, request: Request<KvWriteRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |scope| scope.instance);
        let plugin = plugin_namespace(&req.plugin)?;
        // The batch is applied atomically, which is what lets a plugin keep its
        // own secondary indexes consistent with its records.
        let ops: Vec<KvOp> = req
            .ops
            .into_iter()
            .map(|op| KvOp {
                key: op.key,
                value: op.value,
            })
            .collect();
        self.0
            .kv
            .write(plugin, scope, &ops)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(Ack {}))
    }
}

/// Refuse a caller naming the host's own settings namespace.
///
/// The isolation between two plugins is the namespace, and it holds because a
/// plugin never gets to choose one. This call does let a caller name it, so the
/// one name that is not a plugin's has to be excluded here or a plugin could
/// read and rewrite `plugin.<anything>.enabled` -- switching itself on, or
/// another plugin off.
fn plugin_namespace(requested: &str) -> Result<&str, Status> {
    if requested.is_empty() {
        return Err(Status::invalid_argument("a plugin namespace is required"));
    }
    if requested == HOST_NAMESPACE {
        return Err(Status::permission_denied(
            "that namespace belongs to the plugin host",
        ));
    }
    Ok(requested)
}

/// The largest `data` a plugin message may carry (`Messages.cpp:3409`).
const MAX_PLUGIN_DATA: usize = 8 * 1024 * 1024;
/// The largest `dataID` a plugin message may carry (`Messages.cpp:3414`).
const MAX_PLUGIN_DATA_ID: usize = 256;

impl PluginsService {
    /// Relay one `PluginDataTransmission`, and offer it to every loaded plugin.
    ///
    /// The payload stays opaque (the server never parses what a plugin sent)
    /// but the *envelope* is not opaque, and treating it as such was a bug in
    /// two directions (`vendor/server/src/murmur/Messages.cpp:3384`):
    ///
    /// **`senderSession` is overwritten, never trusted.** murmur is explicit
    /// that reading it from the message "would allow spoofing the sender's
    /// session". It is also what makes the field *useful*: a Fancy client
    /// relays its extension messages through here when the server has no native
    /// type for them, and the receiver reconstructs `actor` from
    /// `senderSession` (`mumble-protocol/src/fancy_codec.rs:236`). Relaying the
    /// message untouched left it unset, so a typing indicator arrived attributed
    /// to nobody and no client rendered it.
    ///
    /// **`receiverSessions` is a delivery list, not a hint.** Broadcasting to
    /// everyone sends a plugin's private message to the whole server. murmur
    /// delivers only to the sessions named, and strips the field on the way out
    /// because the receiver has no use for the guest list.
    ///
    /// Every field here is `deprecated` in the upstream proto, superseded by
    /// `PluginMessage`. Suppressed rather than avoided, exactly as murmur does
    /// with `MUMBLE_DEPRECATED_PUSH` around its own handler and for the same
    /// reason: the message is what shipped clients actually send, so the bridge
    /// has to keep relaying it. New code sends `PluginMessage`.
    #[allow(deprecated, reason = "the legacy bridge shipped clients still use")]
    async fn on_plugin_data(&self, inbound: &Inbound) -> Actions {
        let Ok(mut message) =
            starling_proto::proto::tcp::PluginDataTransmission::decode(inbound.payload.as_slice())
        else {
            tracing::debug!(conn = inbound.conn, "undecodable PluginDataTransmission");
            return Actions::new();
        };

        // A message with no data or no id cannot be acted on by any plugin, so
        // murmur drops it before it costs a fan-out.
        let (Some(data), Some(data_id)) = (message.data.clone(), message.data_id.clone()) else {
            return Actions::new();
        };
        if data.len() > MAX_PLUGIN_DATA || data_id.len() > MAX_PLUGIN_DATA_ID {
            tracing::info!(
                session = inbound.session,
                data = data.len(),
                id = data_id.len(),
                "dropping an oversized plugin message"
            );
            return Actions::new();
        }

        // Offered to every loaded plugin before it is relayed. Fan-out is the
        // only option: this envelope carries no plugin name, so the plugin it
        // was meant for can only find it by recognising its own `data_id`.
        let id_len = data_id.len();
        let (scope, session) = (inbound.scope, inbound.session);
        let _ = self
            .host
            .with(move |host| host.on_plugin_data(scope, session, &data_id, &data))
            .await;

        // Deduplicated, because a receiver named twice would be sent the
        // message twice, and order is preserved so a plugin that cares about
        // it sees what the sender wrote.
        let mut receivers: Vec<u32> = Vec::with_capacity(message.receiver_sessions.len());
        for session in &message.receiver_sessions {
            if !receivers.contains(session) {
                receivers.push(*session);
            }
        }
        if receivers.is_empty() {
            // Named nobody. Where this used to be the end of the road it is now
            // only the end of the *relay*: a client addressing a server-side
            // plugin names no receiver, and the dispatch above has already
            // happened. What is dropped here is a client-to-client message with
            // no client to send it to.
            tracing::debug!(
                session = inbound.session,
                id = id_len,
                "a plugin message named no receiver; nothing to relay"
            );
            return Actions::new();
        }

        message.sender_session = Some(inbound.session);
        message.receiver_sessions.clear();
        vec![to_sessions(receivers, PLUGIN_DATA, message.encode_to_vec())]
    }

    /// Hand an addressed plugin message to the plugin that owns the name, or
    /// relay it between clients when no plugin does.
    ///
    /// One envelope, two jobs, and which one it is depends entirely on whether
    /// a plugin is loaded under that name. That is the same envelope the C++
    /// server split across two wire types (200 server-side, 26 client-to-client);
    /// collapsing them means a client does not have to know which half of the
    /// feature is installed.
    async fn on_opaque(
        &self,
        inbound: &Inbound,
        opaque: starling_proto_fancy::fancy::feature::Opaque,
    ) -> Actions {
        let args = PluginMessageInArgs {
            server_id: inbound.scope,
            sender: inbound.session,
            // The name the sender is using, which the plugin would otherwise
            // have to keep its own table for.
            sender_name: self.roster.name_of(inbound.session).unwrap_or_default(),
            plugin_name: opaque.plugin.clone(),
            payload_type: opaque.payload_type.clone(),
            payload: opaque.payload.clone(),
            // Where the sender is standing, so a plugin can scope what it does
            // to that channel without a round trip.
            channel_id: self.roster.channel_of(inbound.session),
        };
        let taken = self
            .host
            .with(move |host| host.on_plugin_message(&args))
            .await
            .unwrap_or(false);
        if taken {
            // Addressed to a plugin on this server, and it has it. Relaying as
            // well would send the client's request on to every other client.
            return Actions::new();
        }

        let recipients = opaque.recipients.clone();
        if recipients.is_empty() {
            tracing::debug!(
                plugin = %opaque.plugin,
                "no plugin owns that name and the message named no recipient; dropped"
            );
            return Actions::new();
        }
        let relay = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Opaque(
                starling_proto_fancy::fancy::feature::Opaque {
                    sender: inbound.session,
                    recipients: Vec::new(),
                    ..opaque
                },
            )),
        };
        vec![to_sessions(
            recipients,
            ServiceKind::Plugins.outer_type(),
            relay.encode_to_vec(),
        )]
    }
}

impl ClientService for PluginsService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Plugins.outer_type();
        match inbound.type_id {
            PLUGIN_DATA => self.on_plugin_data(&inbound).await,
            id if id == outer => {
                let Ok(envelope) = PluginsEnvelope::decode(inbound.payload.as_slice()) else {
                    return Actions::new();
                };
                match envelope.body {
                    Some(plugins_envelope::Body::Query(_)) => {
                        let reply = PluginsEnvelope {
                            body: Some(plugins_envelope::Body::Registry(Registry {
                                plugins: self.registry().await,
                            })),
                        };
                        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
                    }
                    Some(plugins_envelope::Body::Opaque(opaque)) => {
                        self.on_opaque(&inbound, opaque).await
                    }
                    Some(plugins_envelope::Body::Admin(_)) => {
                        // Installing or enabling a plugin is an operator action
                        // and takes an operator identity, which the client plane
                        // does not carry.
                        let refusal = PluginsEnvelope {
                            body: Some(plugins_envelope::Body::AdminResult(AdminResult {
                                ok: false,
                                detail: "plugin administration is an operator action".to_owned(),
                            })),
                        };
                        vec![to_conn(inbound.conn, outer, refusal.encode_to_vec())]
                    }
                    _ => Actions::new(),
                }
            }
            _ => Actions::new(),
        }
    }
}

impl Serve for PluginsService {
    const NAME: &'static str = "plugins";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let kv = ctx.storage().await?.kv();
        kv.ensure_schema().await?;
        ctx.health.gate(VIEW_GATE);

        let fanout = Fanout::default();
        let roster = Arc::new(Roster::new());
        let scope = ctx.instances().first().copied().unwrap_or(1);
        let bridge = Arc::new(StarlingBridge::new(
            tokio::runtime::Handle::current(),
            ctx.resolver.clone(),
            Arc::clone(&roster),
            fanout.clone(),
            kv.clone(),
            scope,
            ctx.service().options,
        ));

        // On the blocking pool, because building the host runs every enabled
        // plugin's `on_load`, and that is arbitrary code: it opens sockets,
        // reads disks and blocks. It also calls straight back through the
        // bridge, which blocks on this runtime -- from a worker thread that
        // would deadlock rather than merely stall.
        let host = tokio::task::spawn_blocking(move || Host::new(bridge))
            .await
            .map_err(|error| {
                ServiceError::service(format!("a plugin panicked while loading: {error}"))
            })?;
        let loaded = host.loaded_count();
        ctx.logger.log(
            LogEvent::info(Category::Plugin, "plugin host started").with("loaded", loaded as u64),
        );

        Ok(Arc::new(Self {
            host: HostHandle(Arc::new(Mutex::new(host))),
            roster,
            kv,
            fanout,
            logger: ctx.logger.clone(),
            scope,
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(PluginsServer::new(PluginsRpc(Arc::clone(&self))))
            .add_service(plane)
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        // Started here rather than in `build` so a service that is only
        // constructed -- a test, a config check -- subscribes to nothing.
        let follower = {
            let service = Arc::clone(&self);
            let ctx = ctx.clone();
            tokio::spawn(async move {
                loop {
                    service.follow_sessions(&ctx).await;
                    tokio::time::sleep(RETRY).await;
                }
            })
        };
        ctx.shutdown.wait().await;
        follower.abort();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_runtime::storage::Store;

    async fn service() -> Arc<PluginsService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:plugins-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        let kv = store.kv();
        kv.ensure_schema().await.expect("schema");

        let fanout = Fanout::default();
        let roster = Arc::new(Roster::new());
        // No plugins directory, so the host finds nothing and loads nothing:
        // enough to exercise the wire plane and the registry without a plugin
        // binary on disk.
        let bridge = Arc::new(StarlingBridge::new(
            tokio::runtime::Handle::current(),
            starling_runtime::channel::Resolver::new(
                Arc::new(starling_runtime::config::Config::with_defaults(
                    std::path::Path::new("/run/starling"),
                )),
                starling_runtime::inproc::Broker::new(),
            ),
            Arc::clone(&roster),
            fanout.clone(),
            kv.clone(),
            1,
            std::collections::BTreeMap::new(),
        ));
        let host = tokio::task::spawn_blocking(move || Host::new(bridge))
            .await
            .expect("the host builds with no plugins");

        Arc::new(PluginsService {
            host: HostHandle(Arc::new(Mutex::new(host))),
            roster,
            kv,
            fanout,
            logger: Logger::null(),
            scope: 1,
        })
    }

    #[tokio::test]
    async fn an_install_without_a_source_key_is_refused() {
        // A plugin binary must arrive by key; inline bytes on the control plane
        // would block every control message behind them.
        let service = service().await;
        let result = PluginsRpc(Arc::clone(&service))
            .install(Request::new(InstallRequest {
                id: "audit".to_owned(),
                source_key: String::new(),
                ..InstallRequest::default()
            }))
            .await
            .expect("call")
            .into_inner();
        assert!(!result.applied);
    }

    #[tokio::test]
    async fn an_install_that_cannot_fetch_says_so_rather_than_reporting_success() {
        // This used to answer `applied: true` and record a row while doing
        // nothing at all, so an operator was told a plugin was installed and
        // then could not find it anywhere.
        let service = service().await;
        let result = PluginsRpc(Arc::clone(&service))
            .install(Request::new(InstallRequest {
                id: "audit".to_owned(),
                source_key: "blob/audit.so".to_owned(),
                ..InstallRequest::default()
            }))
            .await
            .expect("call")
            .into_inner();
        assert!(!result.applied);
        assert!(
            result.refused.contains("plugins_dir"),
            "the refusal has to say what to do instead: {}",
            result.refused
        );
    }

    #[tokio::test]
    async fn a_plugin_cannot_reach_another_plugins_data() {
        // The namespace is the isolation; the host scopes every operation to
        // the caller, and the caller never names it.
        let service = service().await;
        let rpc = PluginsRpc(Arc::clone(&service));
        let _ = rpc
            .kv_write(Request::new(KvWriteRequest {
                scope: None,
                plugin: "audit".to_owned(),
                ops: vec![starling_proto_fancy::plugins::KvOp {
                    key: b"k".to_vec(),
                    value: Some(b"v".to_vec()),
                }],
            }))
            .await
            .expect("write");

        let theirs = rpc
            .kv_get(Request::new(KvGetRequest {
                scope: None,
                plugin: "calendar".to_owned(),
                key: b"k".to_vec(),
            }))
            .await
            .expect("get")
            .into_inner();
        assert!(!theirs.found);
    }

    #[tokio::test]
    async fn a_plugin_cannot_reach_the_hosts_own_settings() {
        // The host keeps `plugin.<name>.enabled` in a namespace of its own. A
        // plugin that could name it could switch itself on, or a rival off.
        let service = service().await;
        let rpc = PluginsRpc(Arc::clone(&service));
        let refused = rpc
            .kv_write(Request::new(KvWriteRequest {
                scope: None,
                plugin: HOST_NAMESPACE.to_owned(),
                ops: vec![starling_proto_fancy::plugins::KvOp {
                    key: b"plugin.fancy-audit.enabled".to_vec(),
                    value: Some(b"false".to_vec()),
                }],
            }))
            .await;
        assert!(refused.is_err(), "the host namespace is not a plugin's");

        let read = rpc
            .kv_get(Request::new(KvGetRequest {
                scope: None,
                plugin: HOST_NAMESPACE.to_owned(),
                key: b"plugin.fancy-audit.enabled".to_vec(),
            }))
            .await;
        assert!(read.is_err(), "nor is it readable");
    }

    #[tokio::test]
    async fn plugin_administration_from_a_client_is_refused_with_a_reason() {
        let service = service().await;
        let envelope = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Admin(
                starling_proto_fancy::fancy::feature::Admin {
                    kind: starling_proto_fancy::fancy::feature::admin::Kind::Enable as i32,
                    id: "audit".to_owned(),
                    source_key: String::new(),
                },
            )),
        };
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: ServiceKind::Plugins.outer_type(),
                payload: envelope.encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;
        assert_eq!(actions.len(), 1, "the client is told, not ignored");
    }

    #[tokio::test]
    async fn a_registry_query_is_answered_from_the_host() {
        // With no plugins loaded the answer is an empty registry, which is a
        // different thing from no answer: a client that asked and heard nothing
        // waits forever.
        let service = service().await;
        let envelope = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Query(
                starling_proto_fancy::fancy::feature::RegistryQuery {},
            )),
        };
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: ServiceKind::Plugins.outer_type(),
                payload: envelope.encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;
        assert_eq!(actions.len(), 1);
    }

    #[tokio::test]
    async fn an_opaque_message_no_plugin_owns_is_relayed_between_clients() {
        // The fallback half of the envelope: with no server-side plugin under
        // that name, this is a client-to-client mesh message and dropping it
        // would break every Fancy extension that has no server half.
        let service = service().await;
        let envelope = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Opaque(
                starling_proto_fancy::fancy::feature::Opaque {
                    plugin: "nobody-loads-this".to_owned(),
                    payload: b"x".to_vec(),
                    recipients: vec![7, 9],
                    sender: 0,
                    payload_type: "typing".to_owned(),
                },
            )),
        };
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: ServiceKind::Plugins.outer_type(),
                payload: envelope.encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;
        assert_eq!(actions.len(), 1, "relayed to the recipients it named");
    }

    #[tokio::test]
    async fn an_opaque_message_addressed_at_nobody_is_not_broadcast() {
        // A `Send` naming no sessions reaches everyone, so this is the leak the
        // empty-recipient case has to close.
        let service = service().await;
        let envelope = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Opaque(
                starling_proto_fancy::fancy::feature::Opaque {
                    plugin: "nobody-loads-this".to_owned(),
                    payload: b"secret".to_vec(),
                    recipients: Vec::new(),
                    sender: 0,
                    payload_type: String::new(),
                },
            )),
        };
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: ServiceKind::Plugins.outer_type(),
                payload: envelope.encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;
        assert!(
            actions.is_empty(),
            "no recipients means nobody, not everybody"
        );
    }

    #[tokio::test]
    async fn enabling_a_plugin_that_is_not_there_is_refused_and_not_a_crash() {
        let service = service().await;
        let result = PluginsRpc(Arc::clone(&service))
            .enable(Request::new(EnableRequest {
                scope: None,
                actor: None,
                id: "not-installed".to_owned(),
                enabled: true,
            }))
            .await
            .expect("call")
            .into_inner();
        assert!(!result.applied);
        assert!(result.refused.contains("not found"), "{}", result.refused);
    }
}
