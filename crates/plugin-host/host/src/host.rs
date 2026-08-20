//! The host: finds plugin binaries, loads them, and hands them events.
//!
//! Lifted from the C++ server's host with one substitution -- the C callback
//! table became [`HostBridge`] -- and two removals. The per-virtual-server
//! instancing is gone, because Starling runs one host and keys plugin state by
//! `server_id` instead; and so is the hard-coded live-doc/file-server config
//! bridge, which knew two plugins by name and is exactly what
//! `docs/STORAGE.md` L6 says the server must not do. Recording that here rather
//! than in a commit message because it is a deliberate behaviour difference,
//! not an oversight: live documents will not persist until something above the
//! host grants that capability generically.
//!
//! # Everything here is synchronous
//!
//! Every method blocks, because plugin hooks are synchronous. A caller on an
//! async runtime must not call these from a runtime worker; see
//! `starling-plugins`, which puts the whole host behind a blocking pool.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use abi_stable::std_types::{RArc, RNone, RSlice, RSome, RStr, RVec};
use mumble_plugin_api::{
    ChannelId, ClientInfo, PLUGIN_INFO_DATA_ID, PluginContext_TO, PluginMessageIn, ServerId,
    SessionId,
};
use serde::Serialize;

use crate::bridge::{HostBridge, OutboundMessage};
use crate::context::ScopedContext;
use crate::info::{PluginInfoRecord, encode};
use crate::install;
use crate::loader::{LoadedPlugin, discover_plugin_dirs, load_plugin, scan_dir};

/// Comma-separated plugin names that ship with the server and cannot be
/// uninstalled through the admin surface.
const CONFIG_KEY_BUILTIN_PLUGINS: &str = "builtin_plugins";

/// Where plugin binaries are found, and where installs are written.
const CONFIG_KEY_PLUGINS_DIR: &str = "plugins_dir";

/// Per-plugin key gating whether the plugin is loaded. The host reads it so
/// individual plugins never have to check it themselves.
const CONFIG_KEY_ENABLED: &str = "enabled";

/// Per-plugin key recording where an installed binary came from.
const CONFIG_KEY_SOURCE: &str = "source";

/// Per-plugin key recording when it was installed, in milliseconds since the
/// epoch. Written by the caller, which owns the clock.
const CONFIG_KEY_INSTALLED_AT: &str = "installed_at";

/// `payload_type` values broadcast when a plugin's loaded state changes at
/// runtime, so a connected client can drop or restore that plugin's UI rather
/// than leaving it on screen doing nothing. Plain strings on the wire: the
/// `payload_type` field is deliberately plugin-agnostic.
const PAYLOAD_TYPE_PLUGIN_ACTIVATED: &str = "PluginActivated";
const PAYLOAD_TYPE_PLUGIN_DEACTIVATED: &str = "PluginDeactivated";

/// Which backend a plugin loaded through.
///
/// Informational only. Dispatch goes through the same trait object either way,
/// which is what lets the rest of this file stay backend-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PluginKind {
    /// Native `abi_stable` cdylib.
    Native,
    /// WebAssembly component.
    Wasm,
}

impl PluginKind {
    fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some(e) if e.eq_ignore_ascii_case("wasm") => PluginKind::Wasm,
            _ => PluginKind::Native,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            PluginKind::Native => "native",
            PluginKind::Wasm => "wasm",
        }
    }
}

/// One plugin the host knows about, loaded or merely discovered.
struct Entry {
    name: String,
    version: String,
    /// Already-framed `fancy-plugin-info` envelope, or `None` when the plugin
    /// advertised something that was not valid JSON (logged once, at load).
    info_envelope: Option<Vec<u8>>,
    plugin: LoadedPlugin,
    /// The host's own handle on this plugin's context, populated when
    /// [`Entry::loaded`] flips true and cleared on unload. Every borrowed-
    /// reference callback passes a reference into this slot, so a plugin never
    /// has to have kept its own copy.
    ctx: Option<PluginContext_TO<RArc<()>>>,
    /// True once `on_load` has run. Dispatch skips entries where it is false.
    loaded: bool,
    source: Option<String>,
    installed_at: Option<u64>,
    /// The binary ships with the server rather than living in the writable
    /// install directory, so uninstall refuses it.
    builtin: bool,
    kind: PluginKind,
}

/// A plugin found on disk that could not be loaded.
///
/// Tracked rather than merely logged so the admin surface can list and delete a
/// broken file. A binary nobody can see is a binary nobody can remove, and it
/// is retried on every restart.
#[derive(Debug)]
struct FailedPlugin {
    /// For a binary-level failure this is the file stem, because the real name
    /// lives inside a plugin that would not load; for an `on_load` failure it
    /// is the name the plugin gave.
    name: String,
    path: PathBuf,
    error: String,
    builtin: bool,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("loaded", &self.loaded)
            .field(
                "info_envelope_len",
                &self.info_envelope.as_ref().map(Vec::len),
            )
            .field("path", &self.plugin.path)
            .finish()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        // The one unload path. Uninstall, a runtime toggle and full teardown
        // all funnel through here, so a plugin sees exactly one `on_unload` per
        // `on_load` however it was taken away.
        if self.loaded {
            if let Some(ctx) = self.ctx.as_ref()
                && let abi_stable::std_types::RResult::RErr(e) = self.plugin.plugin.on_unload(ctx)
            {
                tracing::warn!(plugin = %self.name, error = %e, "on_unload failed");
            }
            self.loaded = false;
            self.ctx = None;
        }
    }
}

/// One plugin as the admin surface sees it.
#[derive(Debug, Clone, Serialize)]
pub struct PluginAdminInfo {
    /// Stable plugin identifier.
    pub plugin_name: String,
    /// The plugin's own version string.
    pub version: String,
    /// Whether it is loaded right now.
    pub enabled: bool,
    /// Where its binary is.
    pub path: String,
    /// The plugin's advertised `PluginInfo`, as JSON.
    pub info_json: String,
    /// Where an installed binary came from.
    pub source: Option<String>,
    /// When it was installed, in milliseconds since the epoch.
    pub installed_at: Option<u64>,
    /// Ships with the server; uninstall refuses it.
    pub builtin: bool,
    /// `"native"` or `"wasm"`.
    pub kind: &'static str,
    /// Why it could not be loaded, when it could not be.
    pub load_error: Option<String>,
}

/// Everything the host owns.
#[derive(Debug)]
pub struct Host {
    bridge: Arc<dyn HostBridge>,
    plugins: Vec<Entry>,
    failed_plugins: Vec<FailedPlugin>,
    /// Where an install writes. The configured `plugins_dir` only, never the
    /// first search directory: the environment can put a read-only system
    /// directory ahead of it.
    install_dir: Option<PathBuf>,
    /// Sessions connected right now, so a runtime enable can re-announce a
    /// plugin to clients that connected before it was switched on, and a
    /// disable can tell them it went away. Mutated from `&self` callbacks,
    /// hence the interior mutability.
    sessions: Mutex<HashMap<(ServerId, SessionId), ClientInfo>>,
}

impl Host {
    /// Scan the configured directories, load what is there, and call `on_load`
    /// on everything enabled.
    ///
    /// Never fails as a whole: a plugin that will not load is recorded and the
    /// rest still start. One broken binary must not cost an operator every
    /// other plugin.
    #[must_use]
    pub fn new(bridge: Arc<dyn HostBridge>) -> Self {
        let dirs = discover_plugin_dirs(bridge.get_config(CONFIG_KEY_PLUGINS_DIR).as_deref());
        let install_dir = bridge
            .get_config(CONFIG_KEY_PLUGINS_DIR)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let builtin_names: Vec<String> = bridge
            .get_config(CONFIG_KEY_BUILTIN_PLUGINS)
            .map(|value| {
                value
                    .split(',')
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        tracing::info!(dir_count = dirs.len(), dirs = ?dirs, "plugin host initialising");

        let mut plugins = Vec::new();
        let mut failed_plugins: Vec<FailedPlugin> = Vec::new();
        for dir in &dirs {
            let candidates = scan_dir(dir);
            tracing::debug!(
                dir = %dir.display(),
                candidate_count = candidates.len(),
                "scanning plugin directory"
            );
            for path in candidates {
                match load_plugin(&path) {
                    Ok(loaded) => match build_entry(&bridge, loaded) {
                        Ok(mut entry) => {
                            entry.builtin = builtin_names.contains(&entry.name);
                            tracing::info!(
                                plugin = %entry.name,
                                version = %entry.version,
                                loaded = entry.loaded,
                                path = %entry.plugin.path.display(),
                                "plugin discovered"
                            );
                            plugins.push(entry);
                        }
                        Err(BuildEntryError::OnLoad { name, error }) => {
                            let builtin = builtin_names.contains(&name);
                            tracing::error!(
                                plugin = %name,
                                error = %error,
                                path = %path.display(),
                                "plugin failed to start"
                            );
                            failed_plugins.push(FailedPlugin {
                                name,
                                path,
                                error,
                                builtin,
                            });
                        }
                    },
                    Err(error) => {
                        let stem = path
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .unwrap_or("unknown")
                            .to_owned();
                        tracing::error!(
                            plugin = %stem,
                            error = %error,
                            path = %path.display(),
                            "plugin failed to load"
                        );
                        failed_plugins.push(FailedPlugin {
                            name: stem,
                            path,
                            error: error.to_string(),
                            builtin: false,
                        });
                    }
                }
            }
        }
        tracing::info!(
            discovered = plugins.len() + failed_plugins.len(),
            loaded = plugins.iter().filter(|entry| entry.loaded).count(),
            failed = failed_plugins.len(),
            "plugin host ready"
        );
        Self {
            bridge,
            plugins,
            failed_plugins,
            install_dir,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// How many plugins are loaded.
    #[must_use]
    pub fn loaded_count(&self) -> usize {
        self.plugins.iter().filter(|entry| entry.loaded).count()
    }

    /// Tell every loaded plugin a client arrived, then ship each one's
    /// `fancy-plugin-info` envelope to that session.
    pub fn on_client_connected(&self, info: ClientInfo) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.insert((info.server_id, info.session_id), info.clone());
        }
        for entry in self.plugins.iter().filter(|entry| entry.loaded) {
            let Some(ctx) = entry.ctx.as_ref() else {
                continue;
            };
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_client_connected(ctx, info.clone())
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_client_connected failed");
            }
            self.deliver_info(entry, &info);
        }
    }

    /// Tell every loaded plugin a client went away.
    pub fn on_client_disconnected(&self, server_id: ServerId, session: SessionId) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.remove(&(server_id, session));
        }
        for entry in self.plugins.iter().filter(|entry| entry.loaded) {
            let Some(ctx) = entry.ctx.as_ref() else {
                continue;
            };
            if let abi_stable::std_types::RResult::RErr(e) = entry
                .plugin
                .plugin
                .on_client_disconnected(ctx, server_id, session)
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_client_disconnected failed");
            }
        }
    }

    /// Hand a legacy `PluginDataTransmission` to **every** loaded plugin.
    ///
    /// Fan-out, unlike [`Self::on_plugin_message`]: the legacy envelope carries
    /// no plugin name, so the only way to reach the plugin it was meant for is
    /// to offer it to all of them and let each recognise its own `data_id`.
    pub fn on_plugin_data(
        &self,
        server_id: ServerId,
        sender: SessionId,
        data_id: &str,
        data: &[u8],
    ) {
        let id = RStr::from(data_id);
        let bytes = RSlice::from(data);
        for entry in self.plugins.iter().filter(|entry| entry.loaded) {
            let Some(ctx) = entry.ctx.as_ref() else {
                continue;
            };
            if let abi_stable::std_types::RResult::RErr(e) = entry
                .plugin
                .plugin
                .on_plugin_data(ctx, server_id, sender, id, bytes)
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_plugin_data failed");
            }
        }
    }

    /// Route one addressed plugin message to the single plugin that owns the
    /// name on it.
    ///
    /// Returns whether a plugin took it. `false` means the name matched nothing
    /// loaded, which the caller wants to know: in Starling that envelope is
    /// also a client-to-client relay, so an unclaimed name is forwarded to the
    /// other clients rather than dropped.
    pub fn on_plugin_message(&self, args: &PluginMessageInArgs) -> bool {
        let Some(entry) = self
            .plugins
            .iter()
            .find(|entry| entry.loaded && entry.name == args.plugin_name)
        else {
            tracing::debug!(
                plugin = %args.plugin_name,
                "no plugin loaded under that name"
            );
            return false;
        };
        let Some(ctx) = entry.ctx.as_ref() else {
            return false;
        };
        let msg = PluginMessageIn {
            server_id: args.server_id,
            sender_session: args.sender,
            sender_name: args.sender_name.clone().into(),
            plugin_name: args.plugin_name.clone().into(),
            payload_type: args.payload_type.clone().into(),
            payload: RVec::from(args.payload.clone()),
            channel_id: args.channel_id.map_or(RNone, RSome),
        };
        if let abi_stable::std_types::RResult::RErr(e) =
            entry.plugin.plugin.on_plugin_message(ctx, msg)
        {
            tracing::warn!(plugin = %args.plugin_name, error = %e, "on_plugin_message failed");
        }
        true
    }

    /// Every loaded plugin, in the order the registry lists them.
    #[must_use]
    pub fn registry(&self) -> Vec<RegistryEntry> {
        self.plugins
            .iter()
            .filter(|entry| entry.loaded)
            .enumerate()
            .map(|(slot, entry)| RegistryEntry {
                plugin_name: entry.name.clone(),
                version: entry.version.clone(),
                plugin_slot: u32::try_from(slot).unwrap_or(u32::MAX),
                info_json: entry.plugin.plugin.info_json().as_str().to_owned(),
            })
            .collect()
    }

    /// Every plugin the host knows about, loaded or broken, plus where an
    /// install would write.
    #[must_use]
    pub fn list_plugins(&self) -> (Vec<PluginAdminInfo>, Option<String>) {
        let mut out: Vec<PluginAdminInfo> = self
            .plugins
            .iter()
            .map(|entry| PluginAdminInfo {
                plugin_name: entry.name.clone(),
                version: entry.version.clone(),
                enabled: entry.loaded,
                path: entry.plugin.path.display().to_string(),
                info_json: entry.plugin.plugin.info_json().as_str().to_owned(),
                source: entry.source.clone(),
                installed_at: entry.installed_at,
                builtin: entry.builtin,
                kind: entry.kind.as_str(),
                load_error: None,
            })
            .collect();
        for failed in &self.failed_plugins {
            out.push(PluginAdminInfo {
                plugin_name: failed.name.clone(),
                version: String::new(),
                enabled: false,
                path: failed.path.display().to_string(),
                info_json: "{}".to_owned(),
                source: None,
                installed_at: None,
                builtin: failed.builtin,
                kind: PluginKind::from_path(&failed.path).as_str(),
                load_error: Some(failed.error.clone()),
            });
        }
        (
            out,
            self.install_dir
                .as_ref()
                .map(|dir| dir.display().to_string()),
        )
    }

    /// Turn a plugin on or off now, and persist the decision.
    ///
    /// # Errors
    ///
    /// The plugin is unknown, or its `on_load`/`on_unload` failed.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<(), String> {
        let idx = self
            .plugins
            .iter()
            .position(|entry| entry.name == name)
            .ok_or_else(|| format!("plugin '{name}' not found"))?;
        self.bridge.set_config(
            &format!("plugin.{name}.{CONFIG_KEY_ENABLED}"),
            if enabled { "true" } else { "false" },
        )?;

        let bridge = Arc::clone(&self.bridge);
        let entry = &mut self.plugins[idx];
        if enabled == entry.loaded {
            return Ok(());
        }
        if enabled {
            let (host_ctx, plugin_ctx) = contexts_for(&bridge, name);
            entry.ctx = Some(host_ctx);
            if let abi_stable::std_types::RResult::RErr(e) = entry.plugin.plugin.on_load(plugin_ctx)
            {
                entry.ctx = None;
                return Err(format!("on_load failed: {e}"));
            }
            entry.loaded = true;
        } else {
            let result = entry
                .ctx
                .as_ref()
                .map_or(abi_stable::std_types::RResult::ROk(()), |ctx| {
                    entry.plugin.plugin.on_unload(ctx)
                });
            entry.loaded = false;
            entry.ctx = None;
            if let abi_stable::std_types::RResult::RErr(e) = result {
                return Err(format!("on_unload failed: {e}"));
            }
        }

        // The borrow has ended. On enable, re-announce first so the plugin's
        // own per-session setup reaches clients that were already connected;
        // then tell everyone the plugin's UI came or went.
        if enabled {
            self.reannounce_plugin(idx);
        }
        self.broadcast_plugin_status(name, enabled);
        Ok(())
    }

    /// Write a plugin binary into the install directory and load it, disabled.
    ///
    /// The caller supplies the bytes; this host does not fetch anything. A
    /// failure at any point after the file lands removes it again, because a
    /// half-installed binary is rediscovered by the next startup scan and turns
    /// one bad install into a permanent one.
    ///
    /// Returns the name the plugin gave for itself, which is not necessarily
    /// the file name it arrived under.
    ///
    /// # Errors
    ///
    /// No install directory is configured, the artifact fails its digest or
    /// name checks, or the binary will not load.
    pub fn install_plugin(&mut self, request: &InstallRequest<'_>) -> Result<String, String> {
        let dest_dir = self
            .install_dir
            .clone()
            .ok_or_else(|| "no plugins_dir configured; cannot install".to_owned())?;
        let path =
            install::write_artifact(&dest_dir, request.file_name, request.bytes, request.sha256)
                .map_err(|error| error.to_string())?;

        let loaded = match load_plugin(&path) {
            Ok(loaded) => loaded,
            Err(error) => {
                remove_failed_install(&path);
                return Err(error.to_string());
            }
        };
        let name = loaded.plugin.name().as_str().to_owned();

        let written = (|| {
            self.bridge.set_config(
                &format!("plugin.{name}.{CONFIG_KEY_SOURCE}"),
                request.source,
            )?;
            self.bridge.set_config(
                &format!("plugin.{name}.{CONFIG_KEY_INSTALLED_AT}"),
                &request.installed_at_ms.to_string(),
            )?;
            // A new plugin starts switched off. Installing code and running it
            // are two decisions, and an operator who has only made the first
            // should not discover they made the second.
            self.bridge
                .set_config(&format!("plugin.{name}.{CONFIG_KEY_ENABLED}"), "false")
        })();
        if let Err(error) = written {
            remove_failed_install(&path);
            let _ = self.bridge.delete_config_prefix(&format!("plugin.{name}."));
            return Err(error);
        }

        // Replace any previous entry for this name; dropping it unloads it.
        if let Some(idx) = self.plugins.iter().position(|entry| entry.name == name) {
            let _ = self.plugins.swap_remove(idx);
        }
        // A reinstall of something that was broken clears the old complaint.
        self.failed_plugins.retain(|failed| failed.name != name);

        let mut entry = match build_entry(&self.bridge, loaded) {
            Ok(entry) => entry,
            Err(error) => {
                remove_failed_install(&path);
                let _ = self.bridge.delete_config_prefix(&format!("plugin.{name}."));
                return Err(error.to_string());
            }
        };
        entry.source = Some(request.source.to_owned());
        entry.installed_at = Some(request.installed_at_ms);
        let installed = entry.name.clone();
        self.plugins.push(entry);
        Ok(installed)
    }

    /// Unload a plugin, delete its binary, and strip its configuration.
    ///
    /// # Errors
    ///
    /// The plugin is unknown, ships with the server, or its file cannot be
    /// deleted.
    pub fn uninstall_plugin(&mut self, name: &str) -> Result<(), String> {
        if let Some(idx) = self.plugins.iter().position(|entry| entry.name == name) {
            if self.plugins[idx].builtin {
                return Err(format!("plugin '{name}' ships with the server"));
            }
            let path = self.plugins[idx].plugin.path.clone();
            let _ = self.plugins.swap_remove(idx);
            remove_binary(&path)?;
            self.bridge
                .delete_config_prefix(&format!("plugin.{name}."))?;
            self.broadcast_plugin_status(name, false);
            return Ok(());
        }
        if let Some(idx) = self
            .failed_plugins
            .iter()
            .position(|failed| failed.name == name)
        {
            if self.failed_plugins[idx].builtin {
                return Err(format!("plugin '{name}' ships with the server"));
            }
            let path = self.failed_plugins.swap_remove(idx).path;
            remove_binary(&path)?;
            // Best effort: for a binary-level failure the registered name is
            // the file stem, which may not be what the plugin calls itself, so
            // there may be nothing under this prefix at all.
            let _ = self.bridge.delete_config_prefix(&format!("plugin.{name}."));
            return Ok(());
        }
        Err(format!("plugin '{name}' not found"))
    }

    /// Ship one plugin's info envelope to one session.
    fn deliver_info(&self, entry: &Entry, info: &ClientInfo) {
        let Some(envelope) = &entry.info_envelope else {
            return;
        };
        if let Err(error) = self.bridge.send_plugin_data(
            info.server_id,
            info.session_id,
            PLUGIN_INFO_DATA_ID,
            envelope,
        ) {
            tracing::warn!(plugin = %entry.name, %error, "plugin-info delivery failed");
        }
    }

    /// Tell every connected session that a plugin came or went.
    fn broadcast_plugin_status(&self, name: &str, active: bool) {
        let payload_type = if active {
            PAYLOAD_TYPE_PLUGIN_ACTIVATED
        } else {
            PAYLOAD_TYPE_PLUGIN_DEACTIVATED
        };
        let mut by_server: HashMap<ServerId, Vec<SessionId>> = HashMap::new();
        let Ok(sessions) = self.sessions.lock() else {
            return;
        };
        for (server_id, session) in sessions.keys() {
            by_server.entry(*server_id).or_default().push(*session);
        }
        drop(sessions);

        for (server_id, targets) in by_server {
            let message = OutboundMessage {
                server_id,
                plugin_name: name,
                payload_type,
                payload: &[],
                target_sessions: &targets,
                channel_id: None,
            };
            if let Err(error) = self.bridge.send_plugin_message(&message) {
                tracing::warn!(plugin = %name, %error, "plugin-status broadcast failed");
            }
        }
    }

    /// Re-run one plugin's connect announcement for every session already here.
    ///
    /// A plugin switched on at runtime would otherwise only ever see clients
    /// that connect *after* the toggle, so everyone already on the server would
    /// be invisible to it until they reconnected.
    fn reannounce_plugin(&self, idx: usize) {
        let Ok(sessions) = self.sessions.lock() else {
            return;
        };
        let infos: Vec<ClientInfo> = sessions.values().cloned().collect();
        drop(sessions);

        let Some(entry) = self.plugins.get(idx) else {
            return;
        };
        if !entry.loaded {
            return;
        }
        let Some(ctx) = entry.ctx.as_ref() else {
            return;
        };
        for info in infos {
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_client_connected(ctx, info.clone())
            {
                tracing::warn!(plugin = %entry.name, error = %e, "re-announce failed");
            }
            self.deliver_info(entry, &info);
        }
    }
}

// `Drop for Host` is deliberately absent: `Vec<Entry>` drops each `Entry`, and
// `Drop for Entry` is the unload. One code path for every way a plugin goes
// away, rather than a second one here that could drift from it.

/// What an install needs to know, gathered so the call site reads.
#[derive(Debug, Clone, Copy)]
pub struct InstallRequest<'a> {
    /// The file name to write under. Reduced to a bare name before use.
    pub file_name: &'a str,
    /// The binary itself.
    pub bytes: &'a [u8],
    /// Expected SHA-256, hex. Checked when non-empty.
    pub sha256: Option<&'a str>,
    /// Where it came from, recorded against the plugin.
    pub source: &'a str,
    /// Install time in milliseconds since the epoch. Passed in because the host
    /// has no business reading a clock the caller can tell it about.
    pub installed_at_ms: u64,
}

/// One row of the plugin registry a client is told about.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Stable plugin identifier.
    pub plugin_name: String,
    /// The plugin's version string.
    pub version: String,
    /// Index among loaded plugins.
    ///
    /// Positional and therefore **not** stable across a reload: it is the
    /// enumeration order of what happens to be loaded, which changes when
    /// anything is enabled or disabled. Clients key on the name.
    pub plugin_slot: u32,
    /// The plugin's advertised `PluginInfo`, as JSON.
    pub info_json: String,
}

/// Owned parameters for [`Host::on_plugin_message`].
#[derive(Debug, Clone)]
pub struct PluginMessageInArgs {
    /// Server instance the message arrived on.
    pub server_id: ServerId,
    /// Who sent it.
    pub sender: SessionId,
    /// Their display name at the time.
    pub sender_name: String,
    /// The plugin the envelope is addressed to.
    pub plugin_name: String,
    /// Plugin-defined inner message type.
    pub payload_type: String,
    /// Opaque payload.
    pub payload: Vec<u8>,
    /// Channel hint, when the client chose one.
    pub channel_id: Option<ChannelId>,
}

/// Delete a binary left behind by a failed install.
///
/// Best effort, and warned about rather than propagated: the install has
/// already failed, and the caller's error is the one worth reporting. What the
/// operator needs from this line is that a file may be waiting to be retried.
fn remove_failed_install(path: &Path) {
    if let Err(error) = std::fs::remove_file(path) {
        tracing::warn!(
            binary = %path.display(),
            %error,
            "could not remove the binary after a failed install; \
             the next startup scan will try to load it again"
        );
    }
}

/// Delete a plugin binary, reporting what went wrong if it will not go.
fn remove_binary(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(path).map_err(|error| format!("cannot delete {}: {error}", path.display()))
}

/// The two context handles a loaded plugin needs.
///
/// Two independent trait objects over equivalent contexts, not one shared: the
/// first is handed to `on_load` **by value** so the plugin may keep it (clone
/// it into its own threads, hold it for the life of the plugin), and the second
/// stays with the host so every later `&ctx` callback and the final `on_unload`
/// can be dispatched whether or not the plugin kept its copy.
fn contexts_for(
    bridge: &Arc<dyn HostBridge>,
    name: &str,
) -> (PluginContext_TO<RArc<()>>, PluginContext_TO<RArc<()>>) {
    let prefix = format!("plugin.{name}");
    let make = || {
        PluginContext_TO::from_ptr(
            RArc::new(ScopedContext::new(Arc::clone(bridge), prefix.clone())),
            abi_stable::sabi_trait::TD_Opaque,
        )
    };
    (make(), make())
}

fn build_entry(
    bridge: &Arc<dyn HostBridge>,
    loaded: LoadedPlugin,
) -> Result<Entry, BuildEntryError> {
    let name = loaded.plugin.name().as_str().to_owned();
    let version = loaded.plugin.version().as_str().to_owned();
    let prefix = format!("plugin.{name}");
    let info_envelope = build_info_envelope(&name, &version, &loaded);
    let source = bridge.get_config(&format!("{prefix}.{CONFIG_KEY_SOURCE}"));
    let installed_at = bridge
        .get_config(&format!("{prefix}.{CONFIG_KEY_INSTALLED_AT}"))
        .and_then(|value| value.trim().parse().ok());
    let enabled = bridge
        .get_config(&format!("{prefix}.{CONFIG_KEY_ENABLED}"))
        .is_some_and(|value| is_truthy_enabled_value(&value));
    let kind = PluginKind::from_path(&loaded.path);

    let mut entry = Entry {
        name,
        version,
        info_envelope,
        plugin: loaded,
        ctx: None,
        loaded: false,
        source,
        installed_at,
        builtin: false,
        kind,
    };
    if !enabled {
        tracing::info!(
            plugin = %entry.name,
            "plugin discovered but not enabled; set plugin.{}.{CONFIG_KEY_ENABLED} = true to load it",
            entry.name
        );
        return Ok(entry);
    }

    let (host_ctx, plugin_ctx) = contexts_for(bridge, &entry.name);
    entry.ctx = Some(host_ctx);
    if let abi_stable::std_types::RResult::RErr(e) = entry.plugin.plugin.on_load(plugin_ctx) {
        return Err(BuildEntryError::OnLoad {
            name: entry.name.clone(),
            error: format!("on_load failed: {e}"),
        });
    }
    entry.loaded = true;
    Ok(entry)
}

/// Whether a configuration value reads as "on".
///
/// The same words `mumble-server.ini` accepts, so an operator moving a config
/// across does not discover that `yes` stopped meaning yes.
fn is_truthy_enabled_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

fn build_info_envelope(name: &str, version: &str, loaded: &LoadedPlugin) -> Option<Vec<u8>> {
    let raw = loaded.plugin.info_json();
    let parsed: serde_json::Value = match serde_json::from_str(raw.as_str()) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(plugin = %name, %error, "plugin info_json was not valid json");
            return None;
        }
    };
    match encode(&PluginInfoRecord {
        name,
        version,
        info: &parsed,
    }) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            tracing::warn!(plugin = %name, %error, "could not encode the plugin info envelope");
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum BuildEntryError {
    #[error("{error}")]
    OnLoad { name: String, error: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_reads_the_same_words_the_ini_always_accepted() {
        for value in ["true", "TRUE", "True", "1", "yes", "YES", "on", "  on  "] {
            assert!(is_truthy_enabled_value(value), "{value:?} should be on");
        }
        for value in ["", " ", "false", "0", "no", "off", "disabled", "maybe"] {
            assert!(!is_truthy_enabled_value(value), "{value:?} should be off");
        }
    }

    #[test]
    fn a_plugin_directory_that_does_not_exist_is_not_a_startup_failure() {
        // An operator who has not created the directory yet gets a server with
        // no plugins, not a server that will not start.
        #[derive(Debug)]
        struct NoPlugins;
        impl HostBridge for NoPlugins {
            fn get_config(&self, key: &str) -> Option<String> {
                (key == CONFIG_KEY_PLUGINS_DIR).then(|| {
                    std::env::temp_dir()
                        .join("starling-plugins-definitely-absent")
                        .display()
                        .to_string()
                })
            }
            fn set_config(&self, _key: &str, _value: &str) -> Result<(), String> {
                Ok(())
            }
            fn delete_config_prefix(&self, _prefix: &str) -> Result<(), String> {
                Ok(())
            }
            fn send_plugin_data(
                &self,
                _server_id: ServerId,
                _target_session: SessionId,
                _data_id: &str,
                _data: &[u8],
            ) -> Result<(), String> {
                Ok(())
            }
            fn send_plugin_message(&self, _message: &OutboundMessage<'_>) -> Result<(), String> {
                Ok(())
            }
            fn is_session_active(&self, _server_id: ServerId, _session: SessionId) -> bool {
                false
            }
            fn user_has_channel_access(
                &self,
                _server_id: ServerId,
                _session: SessionId,
                _channel: ChannelId,
            ) -> bool {
                false
            }
            fn has_permission(
                &self,
                _server_id: ServerId,
                _session: SessionId,
                _channel: ChannelId,
                _flags: u32,
            ) -> bool {
                false
            }
            fn current_channel(
                &self,
                _server_id: ServerId,
                _session: SessionId,
            ) -> Option<ChannelId> {
                None
            }
        }

        let host = Host::new(Arc::new(NoPlugins));
        assert_eq!(host.loaded_count(), 0);
        assert!(host.registry().is_empty());
        let (listed, _dir) = host.list_plugins();
        assert!(listed.is_empty());
    }
}
