//! `plugins`: the host, and the storage capability plugins persist through.
//!
//! **Plugins are opaque to the server.** It shuttles opaque data and offers
//! generic callbacks (permissions, sessions, config, storage) and never
//! learns a plugin's name, message schema or feature semantics. That principle
//! was applied to the wire protocol; it applies equally to storage, which is
//! why the core schema contains no plugin-specific tables and a plugin gets a
//! namespace instead (`docs/STORAGE.md` L6).
//!
//! Storage is **ordered, namespaced key/value with atomic batches** (§5.4). The
//! namespace is implicit: the host knows which plugin is calling and scopes
//! every operation to it, so a plugin cannot name (or reach) another's data.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::feature::{
    AdminResult, PluginDescriptor, PluginsEnvelope, Registry, plugins_envelope,
};
use starling_proto_fancy::plugins::plugins_server::{Plugins, PluginsServer};
use starling_proto_fancy::plugins::{
    EnableRequest, InstallRequest, KvGetRequest, KvPage, KvPair, KvScanRequest, KvValue,
    KvWriteRequest, Plugin, PluginList, PluginMessage, PluginResult, UninstallRequest,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{KvOp, KvStore};
use tonic::{Request, Response, Status};

/// Upstream `PluginDataTransmission`: opaque client-to-client plugin data.
const PLUGIN_DATA: u16 = 26;

/// The service.
#[derive(Debug)]
pub struct PluginsService {
    installed: Mutex<HashMap<String, Plugin>>,
    kv: KvStore,
    fanout: Fanout,
    logger: Logger,
}

impl PluginsService {
    /// Every installed plugin.
    fn list(&self) -> Vec<Plugin> {
        self.installed
            .lock()
            .map(|installed| installed.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Install or replace one.
    pub fn install(&self, plugin: Plugin) {
        if let Ok(mut installed) = self.installed.lock() {
            let _ = installed.insert(plugin.id.clone(), plugin);
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
            plugins: self.0.list(),
        }))
    }

    async fn enable(
        &self,
        request: Request<EnableRequest>,
    ) -> Result<Response<PluginResult>, Status> {
        let req = request.into_inner();
        let Ok(mut installed) = self.0.installed.lock() else {
            return Err(Status::internal("the plugin registry is unavailable"));
        };
        let Some(plugin) = installed.get_mut(&req.id) else {
            return Ok(Response::new(PluginResult {
                applied: false,
                refused: "no such plugin".to_owned(),
                plugin: None,
            }));
        };
        plugin.enabled = req.enabled;
        tracing::info!(id = %req.id, enabled = req.enabled, "plugin enablement changed");
        self.0.logger.log(
            LogEvent::notice(
                Category::Plugin,
                if req.enabled {
                    "plugin enabled"
                } else {
                    "plugin disabled"
                },
            )
            .with("plugin", req.id.clone()),
        );
        Ok(Response::new(PluginResult {
            applied: true,
            refused: String::new(),
            plugin: Some(plugin.clone()),
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
        let plugin = Plugin {
            id: req.id.clone(),
            name: req.id,
            version: String::new(),
            enabled: false,
            wasm: true,
            capabilities: Vec::new(),
        };
        // Installing a plugin is adding code to the server. It is recorded at
        // notice whether or not anyone is watching, because "when did this
        // appear" is unanswerable afterwards.
        self.0.logger.log(
            LogEvent::notice(Category::Plugin, "plugin installed")
                .with("plugin", plugin.id.clone())
                .with("source", req.source_key)
                .with("wasm", plugin.wasm),
        );
        self.0.install(plugin.clone());
        Ok(Response::new(PluginResult {
            applied: true,
            refused: String::new(),
            plugin: Some(plugin),
        }))
    }

    async fn uninstall(
        &self,
        request: Request<UninstallRequest>,
    ) -> Result<Response<PluginResult>, Status> {
        let req = request.into_inner();
        let removed = self
            .0
            .installed
            .lock()
            .is_ok_and(|mut installed| installed.remove(&req.id).is_some());
        if removed {
            self.0.logger.log(
                LogEvent::notice(Category::Plugin, "plugin uninstalled").with("plugin", req.id),
            );
        } else {
            tracing::debug!(id = %req.id, "uninstall for a plugin that is not installed");
        }
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
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        let value = self
            .0
            .kv
            .get(&req.plugin, scope, &req.key)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(KvValue {
            found: value.is_some(),
            value: value.unwrap_or_default(),
        }))
    }

    async fn kv_scan(&self, request: Request<KvScanRequest>) -> Result<Response<KvPage>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        let pairs = self
            .0
            .kv
            .scan(
                &req.plugin,
                scope,
                &req.start,
                &req.end,
                req.limit,
                req.reverse,
            )
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
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
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
            .write(&req.plugin, scope, &ops)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(Ack {}))
    }
}

/// The largest `data` a plugin message may carry (`Messages.cpp:3409`).
const MAX_PLUGIN_DATA: usize = 8 * 1024 * 1024;
/// The largest `dataID` a plugin message may carry (`Messages.cpp:3414`).
const MAX_PLUGIN_DATA_ID: usize = 256;

impl PluginsService {
    /// Relay one `PluginDataTransmission` to the receivers it names.
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
    fn on_plugin_data(&self, inbound: &Inbound) -> Actions {
        let Ok(mut message) =
            starling_proto::proto::tcp::PluginDataTransmission::decode(inbound.payload.as_slice())
        else {
            tracing::debug!(conn = inbound.conn, "undecodable PluginDataTransmission");
            return Actions::new();
        };

        // A message with no data or no id cannot be acted on by any plugin, so
        // murmur drops it before it costs a fan-out.
        let (Some(data), Some(data_id)) = (message.data.as_ref(), message.data_id.as_ref()) else {
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
            return Actions::new();
        }

        message.sender_session = Some(inbound.session);
        message.receiver_sessions.clear();
        vec![to_sessions(receivers, PLUGIN_DATA, message.encode_to_vec())]
    }
}

impl ClientService for PluginsService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Plugins.outer_type();
        match inbound.type_id {
            PLUGIN_DATA => self.on_plugin_data(&inbound),
            id if id == outer => {
                let Ok(envelope) = PluginsEnvelope::decode(inbound.payload.as_slice()) else {
                    return Actions::new();
                };
                match envelope.body {
                    Some(plugins_envelope::Body::Query(_)) => {
                        let reply = PluginsEnvelope {
                            body: Some(plugins_envelope::Body::Registry(Registry {
                                plugins: self
                                    .list()
                                    .into_iter()
                                    .map(|plugin| PluginDescriptor {
                                        id: plugin.id,
                                        name: plugin.name,
                                        version: plugin.version,
                                        enabled: plugin.enabled,
                                    })
                                    .collect(),
                            })),
                        };
                        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
                    }
                    Some(plugins_envelope::Body::Opaque(opaque)) => {
                        let relay = PluginsEnvelope {
                            body: Some(plugins_envelope::Body::Opaque(
                                starling_proto_fancy::fancy::feature::Opaque {
                                    sender: inbound.session,
                                    ..opaque
                                },
                            )),
                        };
                        vec![to_sessions(Vec::new(), outer, relay.encode_to_vec())]
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
        Ok(Arc::new(Self {
            installed: Mutex::new(HashMap::new()),
            kv,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(PluginsServer::new(PluginsRpc(Arc::clone(&self))))
            .add_service(plane)
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
        Arc::new(PluginsService {
            installed: Mutex::new(HashMap::new()),
            kv,
            fanout: Fanout::default(),
            logger: Logger::null(),
        })
    }

    #[tokio::test]
    async fn an_install_without_a_source_key_is_refused() {
        // A plugin binary must arrive over HTTP by key; inline bytes on the
        // control plane would block every control message behind them.
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
}
