//! Loading an actual plugin binary, end to end.
//!
//! Every other test in this crate stops at the edge of the loader, because the
//! interesting failures live past it: the ABI probe, the `abi_stable` vtable
//! cast, `on_load`, and whether a second plugin dispatches into the first one's
//! code. None of those can be reached without a real cdylib, and all of them
//! have bitten this code before.
//!
//! The binary used is `mumble-friends`, which is a workspace member, so
//! `cargo build` has already produced it next to this test. When it has not --
//! `cargo test -p starling-plugin-host` on its own does not build another
//! crate's cdylib -- the test says so and passes rather than failing for a
//! reason that is about the build and not the code.

// An integration test sees the library's dependencies as its own, and uses none
// of them directly: everything it needs is re-exported through the crate under
// test. Named here so `unused_crate_dependencies` stays on for the library,
// where it is worth having.
use abi_stable as _;
use mumble_plugin_api as _;
use serde as _;
use serde_json as _;
use sha2 as _;
use thiserror as _;
use tracing as _;
// Platform- and feature-gated, because these dependencies are. Naming them
// unconditionally fails to compile where they are not in the graph -- and not
// naming them fails `unused_crate_dependencies` where they are, which is how
// this arrived: `goblin` is Linux-only, so a Windows clippy run never sees it.
#[cfg(target_os = "linux")]
use goblin as _;
#[cfg(feature = "wasm-plugins")]
use wasmtime as _;
#[cfg(feature = "wasm-wasi")]
use wasmtime_wasi as _;
use zstd as _;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use starling_plugin_host::api::{ChannelId, ClientInfo, ServerId, SessionId};
use starling_plugin_host::{Host, HostBridge, NewChannel, OutboundMessage, PluginMessageInArgs};

/// The plugin this exercises, and the name it registers under.
const PLUGIN_FILE_STEM: &str = "mumble_friends";
const PLUGIN_NAME: &str = "fancy-friends";

/// A bridge that remembers what it was asked, and grants nothing.
#[derive(Debug, Default)]
struct Recorder {
    config: Mutex<HashMap<String, String>>,
    /// Every `(data_id, session)` the host asked to be delivered.
    data: Mutex<Vec<(String, SessionId)>>,
    /// Every outbound plugin message, as `(plugin, payload_type, recipients)`.
    messages: Mutex<Vec<(String, String, Vec<SessionId>)>>,
}

impl Recorder {
    fn with_config(pairs: &[(&str, &str)]) -> Self {
        let this = Self::default();
        if let Ok(mut config) = this.config.lock() {
            for (key, value) in pairs {
                let _ = config.insert((*key).to_owned(), (*value).to_owned());
            }
        }
        this
    }
}

impl HostBridge for Recorder {
    fn get_config(&self, key: &str) -> Option<String> {
        self.config.lock().ok()?.get(key).cloned()
    }
    fn set_config(&self, key: &str, value: &str) -> Result<(), String> {
        let mut config = self.config.lock().map_err(|_| "poisoned".to_owned())?;
        let _ = config.insert(key.to_owned(), value.to_owned());
        Ok(())
    }
    fn delete_config_prefix(&self, prefix: &str) -> Result<(), String> {
        let mut config = self.config.lock().map_err(|_| "poisoned".to_owned())?;
        config.retain(|key, _| !key.starts_with(prefix));
        Ok(())
    }
    fn send_plugin_data(
        &self,
        _server_id: ServerId,
        target_session: SessionId,
        data_id: &str,
        _data: &[u8],
    ) -> Result<(), String> {
        if let Ok(mut seen) = self.data.lock() {
            seen.push((data_id.to_owned(), target_session));
        }
        Ok(())
    }
    fn send_plugin_message(&self, message: &OutboundMessage<'_>) -> Result<(), String> {
        if let Ok(mut seen) = self.messages.lock() {
            seen.push((
                message.plugin_name.to_owned(),
                message.payload_type.to_owned(),
                message.target_sessions.to_vec(),
            ));
        }
        Ok(())
    }
    fn is_session_active(&self, _server_id: ServerId, _session: SessionId) -> bool {
        true
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
    fn current_channel(&self, _server_id: ServerId, _session: SessionId) -> Option<ChannelId> {
        None
    }
    fn create_channel(&self, _server_id: ServerId, spec: &NewChannel<'_>) -> Option<ChannelId> {
        // A stand-in for metadata: the id is derived from the name so the same
        // pair always resolves to the same channel, which is the find-or-create
        // behaviour the real one has.
        Some(spec.name.len() as u32 + 100)
    }
    fn grant_channel_access(
        &self,
        _server_id: ServerId,
        _channel: ChannelId,
        _user_id: u32,
    ) -> bool {
        true
    }
}

/// Where `cargo` left the plugin cdylib, if it built one.
fn built_plugin() -> Option<PathBuf> {
    // current_exe is `target/<profile>/deps/<test>-<hash>`; the cdylib is two
    // directories up, beside the other build artefacts.
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.parent()?;
    let name = format!(
        "{}{PLUGIN_FILE_STEM}{}",
        if cfg!(windows) { "" } else { "lib" },
        starling_plugin_host::cdylib_suffix()
    );
    let path = dir.join(name);
    path.is_file().then_some(path)
}

/// Copy the built plugin into a directory of its own, so the scan finds exactly
/// one thing and nothing else in `target/` is loaded by accident.
fn staged(dir: &Path) -> Option<()> {
    let source = built_plugin()?;
    std::fs::create_dir_all(dir).ok()?;
    let dest = dir.join(source.file_name()?);
    let _ = std::fs::copy(&source, &dest).ok()?;
    Some(())
}

/// A directory nothing else in this test binary shares.
fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("starling-plugin-host-{label}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn a_disabled_plugin_is_found_but_never_started() {
    let dir = scratch("disabled");
    let Some(()) = staged(&dir) else {
        eprintln!("skipped: no plugin cdylib built; run `cargo build --workspace` first");
        return;
    };
    // No `plugin.fancy-friends.enabled` key at all, which is the default an
    // operator who has merely dropped a binary in the directory has.
    let bridge = Arc::new(Recorder::with_config(&[(
        "plugins_dir",
        &dir.display().to_string(),
    )]));
    let host = Host::new(Arc::clone(&bridge) as Arc<dyn HostBridge>);

    assert_eq!(host.loaded_count(), 0, "installing is not running");
    let (listed, install_dir) = host.list_plugins();
    assert_eq!(listed.len(), 1, "it is still discovered, and listable");
    assert_eq!(listed[0].plugin_name, PLUGIN_NAME);
    assert!(
        listed[0].load_error.is_none(),
        "it loaded, it just did not start"
    );
    assert!(!listed[0].enabled);
    assert_eq!(
        install_dir.as_deref(),
        Some(dir.display().to_string().as_str())
    );
    assert!(host.registry().is_empty(), "a client is told about nothing");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_enabled_plugin_loads_registers_and_hears_about_a_client() {
    let dir = scratch("enabled");
    let Some(()) = staged(&dir) else {
        eprintln!("skipped: no plugin cdylib built; run `cargo build --workspace` first");
        return;
    };
    let bridge = Arc::new(Recorder::with_config(&[
        ("plugins_dir", &dir.display().to_string()),
        (&format!("plugin.{PLUGIN_NAME}.enabled"), "true"),
    ]));
    let host = Host::new(Arc::clone(&bridge) as Arc<dyn HostBridge>);

    // Loaded, named itself, and advertised something a client can render.
    assert_eq!(host.loaded_count(), 1);
    let registry = host.registry();
    assert_eq!(registry.len(), 1);
    assert_eq!(registry[0].plugin_name, PLUGIN_NAME);
    assert!(
        !registry[0].version.is_empty(),
        "a plugin states its version"
    );
    assert!(
        registry[0].info_json.contains("description"),
        "the registry carries what the client draws: {}",
        registry[0].info_json
    );

    // A client arriving reaches the plugin, and the plugin's info envelope is
    // shipped to that session. This is the whole connect path.
    host.on_client_connected(ClientInfo {
        server_id: 1,
        session_id: 42,
        username: "ada".into(),
        cert_hash: "aa".into(),
        user_id: 7,
    });
    let delivered = bridge.data.lock().expect("not poisoned").clone();
    assert_eq!(
        delivered,
        vec![("fancy-plugin-info".to_owned(), 42)],
        "the connecting session is told what plugins are here"
    );

    // ...and an addressed message reaches it, which is what proves the routing
    // and not merely the loading. `friends.open` for a registered user makes
    // the plugin provision a channel and answer on it.
    let taken = host.on_plugin_message(&PluginMessageInArgs {
        server_id: 1,
        sender: 42,
        sender_name: "ada".to_owned(),
        plugin_name: PLUGIN_NAME.to_owned(),
        payload_type: "friends.open".to_owned(),
        payload: br#"{"targetUserId":9}"#.to_vec(),
        channel_id: None,
    });
    assert!(taken, "the plugin owns its name");
    let replies = bridge.messages.lock().expect("not poisoned").clone();
    assert_eq!(replies.len(), 1, "the requester is answered: {replies:?}");
    assert_eq!(replies[0].0, PLUGIN_NAME);
    assert_eq!(replies[0].1, "friends.room");
    assert_eq!(replies[0].2, vec![42]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_message_for_a_plugin_that_is_not_loaded_is_not_taken() {
    // The caller relays it between clients instead, so "nobody took it" has to
    // be distinguishable from "it was handled".
    let dir = scratch("unowned");
    let Some(()) = staged(&dir) else {
        eprintln!("skipped: no plugin cdylib built; run `cargo build --workspace` first");
        return;
    };
    let bridge = Arc::new(Recorder::with_config(&[
        ("plugins_dir", &dir.display().to_string()),
        (&format!("plugin.{PLUGIN_NAME}.enabled"), "true"),
    ]));
    let host = Host::new(bridge as Arc<dyn HostBridge>);

    let taken = host.on_plugin_message(&PluginMessageInArgs {
        server_id: 1,
        sender: 1,
        sender_name: String::new(),
        plugin_name: "some-client-side-only-thing".to_owned(),
        payload_type: "typing".to_owned(),
        payload: Vec::new(),
        channel_id: None,
    });
    assert!(!taken);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_plugin_can_be_switched_off_and_on_at_runtime() {
    let dir = scratch("toggle");
    let Some(()) = staged(&dir) else {
        eprintln!("skipped: no plugin cdylib built; run `cargo build --workspace` first");
        return;
    };
    let bridge = Arc::new(Recorder::with_config(&[
        ("plugins_dir", &dir.display().to_string()),
        (&format!("plugin.{PLUGIN_NAME}.enabled"), "true"),
    ]));
    let mut host = Host::new(Arc::clone(&bridge) as Arc<dyn HostBridge>);
    assert_eq!(host.loaded_count(), 1);

    // Somebody is already connected when the toggle happens, which is the case
    // the re-announce exists for.
    host.on_client_connected(ClientInfo {
        server_id: 1,
        session_id: 5,
        username: "grace".into(),
        cert_hash: String::new().into(),
        user_id: -1,
    });

    host.set_enabled(PLUGIN_NAME, false).expect("switches off");
    assert_eq!(host.loaded_count(), 0);
    assert!(host.registry().is_empty());
    assert_eq!(
        bridge.get_config(&format!("plugin.{PLUGIN_NAME}.enabled")),
        Some("false".to_owned()),
        "the decision survives a restart"
    );
    // Connected clients are told, so they can drop the plugin's UI.
    let after_off = bridge.messages.lock().expect("not poisoned").clone();
    assert!(
        after_off
            .iter()
            .any(|(_, kind, targets)| kind == "PluginDeactivated" && targets.contains(&5)),
        "the client is told the plugin went: {after_off:?}"
    );

    host.set_enabled(PLUGIN_NAME, true)
        .expect("switches back on");
    assert_eq!(host.loaded_count(), 1);
    // Re-announced: the session that was already here is introduced to the
    // plugin again, or the plugin would only ever know about later arrivals.
    let delivered = bridge.data.lock().expect("not poisoned").clone();
    assert!(
        delivered
            .iter()
            .filter(|(_, session)| *session == 5)
            .count()
            >= 2,
        "the already-connected session is re-announced: {delivered:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(feature = "wasm-plugins")]
fn a_wasm_file_that_is_not_a_component_is_reported_rather_than_ignored() {
    // The WASM counterpart of the native decoy below, and a mistake that is
    // easy to make: `cargo build --target wasm32-unknown-unknown` produces a
    // *core module*, and only a *component* loads. Both are `.wasm`, so the
    // only thing standing between an operator and a silent nothing is that the
    // host says which it got.
    let dir = scratch("wasm-core-module");
    std::fs::create_dir_all(&dir).expect("scratch directory");
    // A well-formed core module header, which is exactly what the wrong build
    // step leaves behind.
    std::fs::write(dir.join("module.wasm"), b"\0asm\x01\0\0\0").expect("write a core module");

    let bridge = Arc::new(Recorder::with_config(&[(
        "plugins_dir",
        &dir.display().to_string(),
    )]));
    let host = Host::new(bridge as Arc<dyn HostBridge>);

    assert_eq!(host.loaded_count(), 0);
    let (listed, _) = host.list_plugins();
    assert_eq!(listed.len(), 1, "the file is seen, not skipped");
    assert!(
        listed[0].load_error.is_some(),
        "the operator is told why, not left to guess"
    );
    assert_eq!(listed[0].kind, "wasm", "and it is reported as what it is");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(not(feature = "wasm-plugins"))]
fn a_wasm_plugin_is_refused_with_the_reason_rather_than_skipped() {
    // With the WASM backend compiled out, an operator who drops a component in
    // the directory gets a server that does not run it. What they must not get
    // is silence: a file the scanner picks up and the loader ignores looks
    // identical to a plugin that loaded and does nothing, and the difference is
    // one build flag.
    let dir = scratch("wasm-off");
    std::fs::create_dir_all(&dir).expect("scratch directory");
    std::fs::write(dir.join("component.wasm"), b"\0asm\x01\0\0\0").expect("write a stub component");

    let bridge = Arc::new(Recorder::with_config(&[(
        "plugins_dir",
        &dir.display().to_string(),
    )]));
    let host = Host::new(bridge as Arc<dyn HostBridge>);

    let (listed, _) = host.list_plugins();
    assert_eq!(listed.len(), 1, "the file is seen, not skipped");
    let error = listed[0]
        .load_error
        .as_deref()
        .expect("a wasm file must be refused, not quietly dropped");
    assert!(
        error.contains("wasm-plugins"),
        "the refusal has to name the feature to turn on: {error}"
    );
    assert_eq!(listed[0].kind, "wasm", "and be reported as what it is");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_that_is_not_a_plugin_is_reported_rather_than_ignored() {
    // A binary nobody can see is a binary nobody can remove, and the startup
    // scan retries it every boot.
    let dir = scratch("broken");
    std::fs::create_dir_all(&dir).expect("scratch directory");
    std::fs::write(
        dir.join(format!(
            "notaplugin{}",
            starling_plugin_host::cdylib_suffix()
        )),
        b"this is not a shared library",
    )
    .expect("write the decoy");

    let bridge = Arc::new(Recorder::with_config(&[(
        "plugins_dir",
        &dir.display().to_string(),
    )]));
    let host = Host::new(bridge as Arc<dyn HostBridge>);

    assert_eq!(host.loaded_count(), 0);
    let (listed, _) = host.list_plugins();
    assert_eq!(listed.len(), 1);
    assert!(
        listed[0].load_error.is_some(),
        "the operator is told why, not left to guess"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
