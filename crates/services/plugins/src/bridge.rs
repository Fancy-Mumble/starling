//! Starling, as the plugin host sees it.
//!
//! [`starling_plugin_host::HostBridge`] is a synchronous trait, because plugin
//! hooks are synchronous and a plugin calls back in from whatever thread it
//! likes. Everything behind it here is async. So every method blocks on a
//! runtime handle, and the whole arrangement rests on one rule:
//!
//! > **Nothing here may run on a runtime worker thread.**
//!
//! `Handle::block_on` panics if it is, and rightly. The callers are plugin-owned
//! threads and the blocking pool the service dispatches hooks through
//! (`lib.rs`), never a task. That is also why the host is not simply made async:
//! the plugin ABI is what it is, and the blocking has to happen somewhere; the
//! honest place is a thread whose job is blocking.
//!
//! # What a plugin can and cannot do through this
//!
//! Reading membership is local (the roster this service already folds from
//! `session-view`), so it costs nothing. Permission checks and channel
//! mutations are gRPC calls to the services that own them, which is deliberate:
//! the plugin host is not an authority on either, and a plugin that could
//! decide its own ACL answers would not need to ask.
//!
//! Absent on purpose, and the same set the C++ host withheld: kick, ban, mute,
//! deafen, move, and injecting a chat message. A plugin that needs them is
//! asking for moderation powers, which is a decision to make deliberately and
//! not by leaving a method on a trait.

use std::collections::BTreeMap;
use std::sync::Arc;

use prost::Message as _;
use starling_plugin_host::{HostBridge, NewChannel, OutboundMessage};
use starling_proto_fancy::common::{Actor, Internal, Scope, actor};
use starling_proto_fancy::control::ServerAction;
use starling_proto_fancy::fancy::feature::{Opaque, PluginsEnvelope, plugins_envelope};
use starling_proto_fancy::files::files_client::FilesClient;
use starling_proto_fancy::files::{
    ListNamesRequest, NameRequest, PutNameRequest, ReserveRequest, RevisionsRequest, SignRequest,
    sign_request,
};
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::metadata::{AccessRequest, Channel, CreateRequest};
use starling_proto_fancy::permissions::SessionCheckRequest;
use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::plane::{Fanout, to_conns, to_sessions};
use starling_runtime::roster::Roster;
use starling_runtime::storage::{KvOp, KvStore};

use crate::PLUGIN_DATA;

/// Namespace the host's own settings live in, inside the shared plugin KV.
///
/// Every `plugins_dir`, `builtin_plugins` and `plugin.<name>.*` key is a row
/// here rather than in the namespace of the plugin it is about, because these
/// are facts the *host* keeps: whether a plugin is switched on is not something
/// that plugin should be able to write.
///
/// The leading underscores keep it clear of any real plugin name; a plugin
/// binary calling itself `__host` would collide, which is why the name is
/// checked at install time (`lib.rs`).
pub(crate) const HOST_NAMESPACE: &str = "__host";

/// Everything a plugin reaches the server through.
#[derive(Debug)]
pub(crate) struct StarlingBridge {
    /// The runtime every method blocks on. Never held by a worker thread.
    runtime: tokio::runtime::Handle,
    resolver: Resolver,
    roster: Arc<Roster>,
    fanout: Fanout,
    kv: KvStore,
    /// Which server instance this host serves. Starling runs one host and keys
    /// plugin state by this, where the C++ server ran one host per instance.
    scope: u32,
    /// Configuration from the TOML block, read when the store has no answer.
    ///
    /// The seed, not the authority: an operator's file supplies the starting
    /// value and anything written at runtime wins from then on, which is what
    /// makes "disable this plugin" survive a restart without an edit to the
    /// file. The consequence is worth stating plainly, because it will surprise
    /// somebody: changing a key in the TOML has no effect once that key has
    /// been written through the admin surface.
    defaults: BTreeMap<String, String>,
}

impl StarlingBridge {
    /// Assemble one.
    pub(crate) fn new(
        runtime: tokio::runtime::Handle,
        resolver: Resolver,
        roster: Arc<Roster>,
        fanout: Fanout,
        kv: KvStore,
        scope: u32,
        defaults: BTreeMap<String, String>,
    ) -> Self {
        Self {
            runtime,
            resolver,
            roster,
            fanout,
            kv,
            scope,
            defaults,
        }
    }

    /// This server instance, as the services want it.
    fn scope(&self) -> Option<Scope> {
        Some(Scope {
            instance: self.scope,
        })
    }

    /// The host acting on its own behalf.
    ///
    /// Not a session: a plugin creating a channel is the *server* creating it,
    /// and attributing it to whichever client happened to ask would make the
    /// action subject to that client's permissions. Whether a plugin should
    /// have been allowed to ask is the plugin's judgement to make, using
    /// [`HostBridge::has_permission`] before it calls.
    fn actor(&self) -> Option<Actor> {
        Some(Actor {
            who: Some(actor::Who::Internal(Internal {
                service: "plugins".to_owned(),
            })),
        })
    }

    /// Address a plugin's frame at connections rather than sessions.
    ///
    /// Every write this bridge makes can be provoked by `on_client_connected`,
    /// which fires from the `session-view` stream. session-lifecycle awaits that
    /// announcement *before* it builds the `SessionUp` action the gateway binds
    /// the session id from, so at that instant the id addresses nothing and the
    /// gateway drops the frame in a `filter_map` with no log, no counter and no
    /// way to tell it apart from a delivery. That is what made a loaded live-doc
    /// plugin invisible to a client that was connected and working.
    ///
    /// A connection is bound from the accept, so addressing one is independent
    /// of that ordering. Sessions the roster cannot place fall back to being
    /// addressed as before: a cold roster knows nobody, while the gateway may
    /// well know the session, and the old behaviour is the better guess there.
    fn addressed(&self, sessions: Vec<u32>, type_id: u16, payload: Vec<u8>) -> Vec<ServerAction> {
        let mut conns = Vec::with_capacity(sessions.len());
        let mut unresolved = Vec::new();
        for session in sessions {
            match self.roster.conn_of(session) {
                Some(conn) => conns.push(conn),
                None => unresolved.push(session),
            }
        }
        let mut actions = Vec::with_capacity(2);
        if !conns.is_empty() {
            actions.push(to_conns(conns, type_id, payload.clone()));
        }
        if !unresolved.is_empty() {
            tracing::debug!(
                sessions = ?unresolved,
                type_id,
                "the roster cannot place these sessions; addressing them by session id"
            );
            actions.push(to_sessions(unresolved, type_id, payload));
        }
        actions
    }
}

impl HostBridge for StarlingBridge {
    fn get_config(&self, key: &str) -> Option<String> {
        let stored = self
            .runtime
            .block_on(self.kv.get(HOST_NAMESPACE, self.scope, key.as_bytes()));
        match stored {
            Ok(Some(bytes)) => return String::from_utf8(bytes).ok(),
            Ok(None) => {}
            Err(error) => {
                // Falling through to the file rather than failing: a settings
                // read that errors is indistinguishable to the caller from one
                // that found nothing, and the operator's configured value is a
                // better answer than neither.
                tracing::warn!(key, %error, "reading plugin configuration failed");
            }
        }
        self.defaults.get(key).cloned()
    }

    fn set_config(&self, key: &str, value: &str) -> Result<(), String> {
        let ops = [KvOp {
            key: key.as_bytes().to_vec(),
            value: Some(value.as_bytes().to_vec()),
        }];
        self.runtime
            .block_on(self.kv.write(HOST_NAMESPACE, self.scope, &ops))
            .map_err(|error| format!("cannot write {key}: {error}"))
    }

    fn delete_config_prefix(&self, prefix: &str) -> Result<(), String> {
        // The store is ordered, so everything under a prefix is one range: from
        // the prefix itself up to the smallest key that cannot start with it.
        let start = prefix.as_bytes().to_vec();
        let Some(end) = prefix_end(prefix.as_bytes()) else {
            // Only an empty prefix or one that is all 0xFF, neither of which
            // names a configuration key. Refused rather than treated as "every
            // key", which is what an unbounded scan would delete.
            return Err(format!("'{prefix}' is not a usable configuration prefix"));
        };
        let pairs = self
            .runtime
            .block_on(
                self.kv
                    .scan(HOST_NAMESPACE, self.scope, &start, &end, 0, false),
            )
            .map_err(|error| format!("cannot list {prefix}: {error}"))?;
        if pairs.is_empty() {
            return Ok(());
        }
        let ops: Vec<KvOp> = pairs
            .into_iter()
            .map(|(key, _)| KvOp { key, value: None })
            .collect();
        self.runtime
            .block_on(self.kv.write(HOST_NAMESPACE, self.scope, &ops))
            .map_err(|error| format!("cannot delete {prefix}: {error}"))
    }

    fn send_plugin_data(
        &self,
        _server_id: u32,
        target_session: u32,
        data_id: &str,
        data: &[u8],
    ) -> Result<(), String> {
        // The legacy envelope, and the one the plugin-info broadcast rides. The
        // sender is left unset: it is the server speaking, and stamping some
        // session onto it would attribute the server's message to a client.
        #[allow(
            deprecated,
            reason = "the legacy envelope shipped clients still read plugin info from"
        )]
        let message = starling_proto::proto::tcp::PluginDataTransmission {
            sender_session: None,
            receiver_sessions: Vec::new(),
            data: Some(data.to_vec()),
            data_id: Some(data_id.to_owned()),
        };
        for action in self.addressed(vec![target_session], PLUGIN_DATA, message.encode_to_vec()) {
            self.fanout.push(action);
        }
        Ok(())
    }

    fn send_plugin_message(&self, message: &OutboundMessage<'_>) -> Result<(), String> {
        let recipients: Vec<u32> = if message.target_sessions.is_empty() {
            match message.channel_id {
                // Everyone in the channel, the sender included: the host is the
                // sender here, so there is nobody to leave out.
                Some(channel) => self.roster.in_channel(channel, 0),
                // Addressed at nobody. Not an error -- a plugin that named no
                // recipient has said nothing -- but emphatically not a
                // broadcast, which is how a plugin's private message reaches
                // the whole server.
                None => return Ok(()),
            }
        } else {
            message.target_sessions.to_vec()
        };
        if recipients.is_empty() {
            return Ok(());
        }
        let envelope = PluginsEnvelope {
            body: Some(plugins_envelope::Body::Opaque(Opaque {
                plugin: message.plugin_name.to_owned(),
                payload: message.payload.to_vec(),
                recipients: Vec::new(),
                sender: 0,
                payload_type: message.payload_type.to_owned(),
            })),
        };
        for action in self.addressed(
            recipients,
            ServiceKind::Plugins.outer_type(),
            envelope.encode_to_vec(),
        ) {
            self.fanout.push(action);
        }
        Ok(())
    }

    fn is_session_active(&self, _server_id: u32, session: u32) -> bool {
        self.roster.channel_of(session).is_some()
    }

    fn user_has_channel_access(&self, server_id: u32, session: u32, channel: u32) -> bool {
        self.has_permission(
            server_id,
            session,
            channel,
            starling_proto_fancy::perm::Perm::ENTER.bits(),
        )
    }

    fn has_permission(&self, _server_id: u32, session: u32, channel: u32, flags: u32) -> bool {
        let Ok(transport) = self.resolver.channel("permissions") else {
            // Fails closed, the same way `Permit` does. An unreachable ACL
            // engine must never read as a grant.
            tracing::warn!("cannot reach permissions; the check is denied");
            return false;
        };
        // `CheckSession` and not `Check`: this names only the session, and lets
        // the permissions service resolve who that is. A caller that stated the
        // identity itself could state a better one.
        let request = SessionCheckRequest {
            scope: self.scope(),
            session,
            channel,
            permission: flags,
            temporary_tokens: Vec::new(),
        };
        self.runtime.block_on(async move {
            PermissionsClient::new(transport)
                .check_session(tonic::Request::new(request))
                .await
                .is_ok_and(|decision| decision.into_inner().allowed)
        })
    }

    fn current_channel(&self, _server_id: u32, session: u32) -> Option<u32> {
        self.roster.channel_of(session)
    }

    fn sessions_in_channel(&self, _server_id: u32, channel: u32) -> Vec<u32> {
        self.roster.in_channel(channel, 0)
    }

    fn all_sessions(&self, _server_id: u32) -> Vec<u32> {
        self.roster.sessions()
    }

    fn find_session_by_name(&self, _server_id: u32, name: &str) -> Option<u32> {
        self.roster.session_named(name)
    }

    fn create_channel(&self, _server_id: u32, spec: &NewChannel<'_>) -> Option<u32> {
        let Ok(transport) = self.resolver.channel("metadata") else {
            tracing::warn!("cannot reach metadata; no channel was created");
            return None;
        };
        let mut flags = 0_u32;
        if spec.hidden {
            flags |= starling_proto_fancy::channel::FLAG_HIDDEN;
        }
        if spec.detached {
            flags |= starling_proto_fancy::channel::FLAG_DETACHED;
        }
        let request = CreateRequest {
            scope: self.scope(),
            actor: self.actor(),
            channel: Some(Channel {
                // A detached channel is parentless by definition; sending the
                // nominal parent anyway would put a friend DM in the tree.
                parent: (!spec.detached).then_some(spec.parent),
                name: spec.name.to_owned(),
                flags,
                pchat_protocol: spec.pchat_protocol,
                expiry_mode: spec.expiry_mode,
                expiry_duration_s: spec.expiry_duration_secs,
                ..Channel::default()
            }),
            temporary: false,
            invitee_user_ids: spec.invitee_uids.to_vec(),
            // Find-or-create, which is what makes provisioning idempotent: two
            // clients opening the same friend chat at once must land in one
            // room, and the second attempt must not overwrite the first one's
            // ACL table.
            reuse_existing: true,
        };
        self.runtime.block_on(async move {
            let result = MetadataClient::new(transport)
                .create(tonic::Request::new(request))
                .await
                .ok()?
                .into_inner();
            if !result.applied {
                tracing::warn!(refused = %result.refused, "channel creation refused");
                return None;
            }
            result.channel.map(|channel| channel.id)
        })
    }

    fn grant_channel_access(&self, server_id: u32, channel: u32, user_id: u32) -> bool {
        self.access(server_id, channel, user_id, Access::Grant)
    }

    fn revoke_channel_access(&self, server_id: u32, channel: u32, user_id: u32) -> bool {
        self.access(server_id, channel, user_id, Access::Revoke)
    }

    fn kv_get(&self, plugin: &str, _server_id: u32, key: &[u8]) -> Option<Vec<u8>> {
        // `plugin` is the namespace, supplied by the host. A plugin naming a
        // key cannot reach past it, because it never names the namespace.
        match self.runtime.block_on(self.kv.get(plugin, self.scope, key)) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(plugin, %error, "a plugin's storage read failed");
                None
            }
        }
    }

    fn kv_scan(
        &self,
        plugin: &str,
        _server_id: u32,
        start: &[u8],
        end: &[u8],
        limit: u32,
        reverse: bool,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        match self
            .runtime
            .block_on(self.kv.scan(plugin, self.scope, start, end, limit, reverse))
        {
            Ok(pairs) => pairs,
            Err(error) => {
                tracing::warn!(plugin, %error, "a plugin's storage scan failed");
                Vec::new()
            }
        }
    }

    fn kv_write(
        &self,
        plugin: &str,
        _server_id: u32,
        ops: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<(), String> {
        let ops: Vec<KvOp> = ops
            .iter()
            .map(|(key, value)| KvOp {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();
        self.runtime
            .block_on(self.kv.write(plugin, self.scope, &ops))
            .map_err(|error| format!("cannot write plugin storage: {error}"))
    }

    fn object_reserve(
        &self,
        plugin: &str,
        _server_id: u32,
        filename: &str,
        content_type: &str,
        size: u64,
        public: bool,
    ) -> Option<(String, String, String, u64)> {
        let Ok(transport) = self.resolver.channel("files") else {
            tracing::warn!("cannot reach files; plugin storage is unavailable");
            return None;
        };
        let request = ReserveRequest {
            scope: self.scope(),
            ns: plugin_namespace(plugin),
            filename: filename.to_owned(),
            content_type: content_type.to_owned(),
            size,
            public,
        };
        let slot = self.runtime.block_on(async move {
            FilesClient::new(transport)
                .reserve(tonic::Request::new(request))
                .await
        });
        match slot {
            Ok(slot) => {
                let slot = slot.into_inner();
                Some((slot.key, slot.url, slot.method, slot.expires_at_ms))
            }
            Err(error) => {
                tracing::warn!(plugin, %error, "a plugin could not reserve an object");
                None
            }
        }
    }

    fn object_url(&self, plugin: &str, _server_id: u32, key: &str) -> Option<String> {
        // A plugin may only read its own objects. Checked here rather than in
        // `files`, because this is the layer that knows who is asking: the
        // service is told a key and would have to take the caller's word.
        if !key.starts_with(&format!("{}/", plugin_namespace(plugin))) {
            tracing::warn!(
                plugin,
                key,
                "a plugin asked for an object outside its namespace"
            );
            return None;
        }
        let Ok(transport) = self.resolver.channel("files") else {
            tracing::warn!("cannot reach files; plugin storage is unavailable");
            return None;
        };
        let request = SignRequest {
            scope: self.scope(),
            actor: self.actor(),
            op: sign_request::Op::Get as i32,
            key: key.to_owned(),
            content_type: String::new(),
            max_bytes: 0,
        };
        let signed = self.runtime.block_on(async move {
            FilesClient::new(transport)
                .sign(tonic::Request::new(request))
                .await
        });
        match signed {
            Ok(signed) => Some(signed.into_inner().url),
            Err(error) => {
                tracing::warn!(plugin, %error, "a plugin could not sign an object read");
                None
            }
        }
    }

    fn name_put(
        &self,
        plugin: &str,
        _server_id: u32,
        name: &str,
        key: &str,
        keep: u64,
    ) -> Result<u64, String> {
        let transport = self
            .resolver
            .channel("files")
            .map_err(|_| "cannot reach the file service".to_owned())?;
        let request = PutNameRequest {
            scope: self.scope(),
            ns: plugin_namespace(plugin),
            name: name.to_owned(),
            key: key.to_owned(),
            keep,
        };
        self.runtime
            .block_on(async move {
                FilesClient::new(transport)
                    .put_name(tonic::Request::new(request))
                    .await
            })
            .map(|answer| answer.into_inner().rev)
            .map_err(|error| format!("cannot store the name: {error}"))
    }

    fn name_latest(&self, plugin: &str, _server_id: u32, name: &str) -> Option<(u64, String, u64)> {
        let Ok(transport) = self.resolver.channel("files") else {
            tracing::warn!("cannot reach files; plugin storage is unavailable");
            return None;
        };
        let request = NameRequest {
            scope: self.scope(),
            ns: plugin_namespace(plugin),
            name: name.to_owned(),
        };
        let answer = self.runtime.block_on(async move {
            FilesClient::new(transport)
                .latest_name(tonic::Request::new(request))
                .await
        });
        match answer {
            Ok(answer) => {
                let revision = answer.into_inner();
                revision
                    .found
                    .then_some((revision.rev, revision.key, revision.created_at_ms))
            }
            Err(error) => {
                tracing::warn!(plugin, %error, "a plugin could not read a name");
                None
            }
        }
    }

    fn name_revisions(
        &self,
        plugin: &str,
        _server_id: u32,
        name: &str,
        limit: u32,
    ) -> Vec<(u64, String, u64)> {
        let Ok(transport) = self.resolver.channel("files") else {
            tracing::warn!("cannot reach files; plugin storage is unavailable");
            return Vec::new();
        };
        let request = RevisionsRequest {
            scope: self.scope(),
            ns: plugin_namespace(plugin),
            name: name.to_owned(),
            limit,
        };
        let answer = self.runtime.block_on(async move {
            FilesClient::new(transport)
                .list_revisions(tonic::Request::new(request))
                .await
        });
        match answer {
            Ok(answer) => answer
                .into_inner()
                .revisions
                .into_iter()
                .map(|revision| (revision.rev, revision.key, revision.created_at_ms))
                .collect(),
            Err(error) => {
                tracing::warn!(plugin, %error, "a plugin could not list revisions");
                Vec::new()
            }
        }
    }

    fn name_list(&self, plugin: &str, _server_id: u32) -> Vec<(String, u64, String, u64)> {
        let Ok(transport) = self.resolver.channel("files") else {
            tracing::warn!("cannot reach files; plugin storage is unavailable");
            return Vec::new();
        };
        let request = ListNamesRequest {
            scope: self.scope(),
            ns: plugin_namespace(plugin),
        };
        let answer = self.runtime.block_on(async move {
            FilesClient::new(transport)
                .list_names(tonic::Request::new(request))
                .await
        });
        match answer {
            Ok(answer) => answer
                .into_inner()
                .names
                .into_iter()
                .filter_map(|named| {
                    let latest = named.latest?;
                    Some((named.name, latest.rev, latest.key, latest.created_at_ms))
                })
                .collect(),
            Err(error) => {
                tracing::warn!(plugin, %error, "a plugin could not list names");
                Vec::new()
            }
        }
    }

    fn name_forget(&self, plugin: &str, _server_id: u32, name: &str) -> Result<(), String> {
        let transport = self
            .resolver
            .channel("files")
            .map_err(|_| "cannot reach the file service".to_owned())?;
        let request = NameRequest {
            scope: self.scope(),
            ns: plugin_namespace(plugin),
            name: name.to_owned(),
        };
        self.runtime
            .block_on(async move {
                FilesClient::new(transport)
                    .forget_name(tonic::Request::new(request))
                    .await
            })
            .map(|_| ())
            .map_err(|error| format!("cannot forget the name: {error}"))
    }
}

/// Which half of the invitee pair is being called.
#[derive(Debug, Clone, Copy)]
enum Access {
    Grant,
    Revoke,
}

impl StarlingBridge {
    /// Admit or drop one account on a private channel.
    fn access(&self, _server_id: u32, channel: u32, user_id: u32, which: Access) -> bool {
        let Ok(transport) = self.resolver.channel("metadata") else {
            tracing::warn!("cannot reach metadata; channel access is unchanged");
            return false;
        };
        let request = AccessRequest {
            scope: self.scope(),
            actor: self.actor(),
            channel,
            account: u64::from(user_id),
        };
        self.runtime.block_on(async move {
            let mut client = MetadataClient::new(transport);
            let call = match which {
                Access::Grant => client.grant_access(tonic::Request::new(request)).await,
                Access::Revoke => client.revoke_access(tonic::Request::new(request)).await,
            };
            call.is_ok_and(|result| result.into_inner().applied)
        })
    }
}

/// The object namespace one plugin owns, without a trailing separator.
///
/// `p/<name>`, matching `files`' own reading of a key's first component. The
/// plugin never supplies this - the host does - so a plugin cannot name
/// another's objects however it spells its request.
fn plugin_namespace(plugin: &str) -> String {
    format!("p/{plugin}")
}

fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_becomes_a_range_that_holds_exactly_its_own_keys() {
        // The trailing '.' (0x2E) becomes '/' (0x2F).
        let end = prefix_end(b"plugin.a.").expect("a usable range");
        assert_eq!(end, b"plugin.a/".to_vec());

        let inside = |key: &[u8]| key >= b"plugin.a.".as_slice() && key < end.as_slice();
        assert!(inside(b"plugin.a."));
        assert!(inside(b"plugin.a.enabled"));
        // The neighbours are what this range has to exclude: uninstalling
        // `plugin.a` must not take `plugin.ab`'s settings with it, and a
        // prefix scan that ran to the end of the namespace would.
        assert!(!inside(b"plugin.ab.enabled"));
        assert!(!inside(b"plugin.b.enabled"));
    }

    #[test]
    fn a_prefix_with_no_successor_is_refused_rather_than_treated_as_everything() {
        // An unbounded scan here would delete every setting in the namespace.
        assert_eq!(prefix_end(b""), None);
        assert_eq!(prefix_end(&[0xFF, 0xFF]), None);
    }
}
