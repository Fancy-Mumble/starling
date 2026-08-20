//! The published example plugins, loaded by this host.
//!
//! `loads_a_real_plugin.rs` proves the host can load a plugin. This proves
//! something narrower and more valuable: that it can load plugins **it did not
//! build**, compiled against the *other* copy of `mumble-plugin-api` -- the one
//! still in the C++ server's tree, which
//! [fancy-plugin-example](https://github.com/Fancy-Mumble/fancy-plugin-example)
//! depends on by path.
//!
//! That is the invariant `docs/PLUGIN-HOST-PLAN.md` §3 claims and nothing else
//! here checks: a plugin binary built against either tree loads in either
//! server. Two things have to hold for one of these files to load at all, and
//! both are exactly what would break if the lift had drifted:
//!
//! 1. the `__mumble_plugin_abi_version` the binary exports equals the
//!    `PLUGIN_ABI_VERSION` this host was built with, and
//! 2. `abi_stable`'s layout check passes on every type crossing the boundary --
//!    `MumblePlugin`'s vtable, `PluginContext`'s, `ClientInfo`, `PluginError`.
//!
//! A field reordered, a method added, a dependency at a different version: any
//! of them fails (2) with a vtable-layout error rather than loading and
//! misbehaving. So a green run here is a real statement about the ABI, not a
//! statement about this repository compiling.
//!
//! # Getting the artefacts
//!
//! The examples are a separate repository, checked out beside this one, which
//! is the layout its own README documents:
//!
//! ```text
//! <parent>/
//! ├── starling/                 # this repo
//! ├── fancy-plugin-example/     # the examples
//! └── mumble-server/            # what their api path dependency points at
//! ```
//!
//! ```sh
//! cd ../fancy-plugin-example
//! cargo build --release -p fancy-greeter -p fancy-gallery-showcase \
//!     -p fancy-info-card -p fancy-feedback-form -p fancy-chat-card \
//!     -p fancy-quick-poll
//! ```
//!
//! `fancy-greeter-wasm` is deliberately not in that list: it is a WebAssembly
//! component, needs `wasm-tools component new` after the build, and this host
//! ships with `wasm-plugins` off. Proving the WASM half is its own exercise.
//!
//! Without the artefacts every test here says so and passes. That is the right
//! behaviour for a check that depends on a second checkout -- it must not turn
//! `cargo test` red for somebody who has never heard of the examples -- but it
//! does mean a green run alone is not evidence. Read the skip line.

use abi_stable as _;
use mumble_plugin_api as _;
use serde as _;
use sha2 as _;
use thiserror as _;
use tracing as _;
use zstd as _;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use starling_plugin_host::api::{ChannelId, ClientInfo, ServerId, SessionId};
use starling_plugin_host::{Host, HostBridge, NewChannel, OutboundMessage};

/// What the six native examples call themselves.
///
/// Hard-coded rather than derived from the file names, because the point is
/// that the *plugin* says who it is: the host reads the name out of the loaded
/// binary, and a file called anything at all could claim any of these.
const EXPECTED: &[&str] = &[
    "fancy-chat-card",
    "fancy-feedback-form",
    "fancy-gallery-showcase",
    "fancy-greeter",
    "fancy-info-card",
    "fancy-quick-poll",
];

/// A bridge that records, grants nothing, and answers no configuration.
///
/// Deliberately bare: a plugin whose `on_load` needs something the host cannot
/// give must still load, and if one of these examples only works against a
/// generous bridge, that is worth finding out here.
#[derive(Debug, Default)]
struct Recorder {
    config: Mutex<HashMap<String, String>>,
    /// Every key anybody asked for, in order.
    reads: Mutex<Vec<String>>,
    /// `(data_id, session)` for everything delivered.
    data: Mutex<Vec<(String, SessionId)>>,
}

impl HostBridge for Recorder {
    fn get_config(&self, key: &str) -> Option<String> {
        if let Ok(mut reads) = self.reads.lock() {
            reads.push(key.to_owned());
        }
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
    fn send_plugin_message(&self, _message: &OutboundMessage<'_>) -> Result<(), String> {
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
    fn create_channel(&self, _server_id: ServerId, _spec: &NewChannel<'_>) -> Option<ChannelId> {
        None
    }
}

/// Where the sibling checkout leaves its release artefacts.
fn examples_release_dir() -> PathBuf {
    // `<repo>/crates/plugin-host/host` up four is the directory this repo sits
    // in, which is where the examples are checked out beside it.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../fancy-plugin-example/target/release")
}

/// Copy every example cdylib into a directory of its own.
///
/// A directory of its own, and not the build directory itself: `target/release`
/// also holds the dependencies' shared libraries and anything else cargo left
/// there, and the host loads *everything* with the platform suffix.
fn stage(label: &str) -> Option<(PathBuf, Vec<String>)> {
    let source = examples_release_dir();
    if !source.is_dir() {
        return None;
    }
    let dir = std::env::temp_dir().join(format!("starling-published-examples-{label}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;

    let suffix = starling_plugin_host::cdylib_suffix();
    let mut staged = Vec::new();
    for entry in std::fs::read_dir(&source).ok()?.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        // The examples are the `fancy_*` ones; a dependency that happens to
        // build a shared library is not under test here.
        if !name.ends_with(suffix) || !name.starts_with("fancy_") {
            continue;
        }
        let _ = std::fs::copy(&path, dir.join(name)).ok()?;
        staged.push(name.to_owned());
    }
    if staged.is_empty() {
        return None;
    }
    staged.sort();
    Some((dir, staged))
}

/// Say why nothing ran, so a green run is never mistaken for a proven one.
fn skip(reason: &str) {
    eprintln!(
        "SKIPPED: {reason}\n  \
         expected the example artefacts at {}\n  \
         build them with: cd ../fancy-plugin-example && cargo build --release \\\n    \
         -p fancy-greeter -p fancy-gallery-showcase -p fancy-info-card \\\n    \
         -p fancy-feedback-form -p fancy-chat-card -p fancy-quick-poll",
        examples_release_dir().display()
    );
}

/// A host with every staged example switched on.
fn host_with_everything(label: &str) -> Option<(Host, Arc<Recorder>, Vec<String>)> {
    let (dir, staged) = stage(label)?;
    let bridge = Arc::new(Recorder::default());
    bridge
        .set_config("plugins_dir", &dir.display().to_string())
        .ok()?;
    for name in EXPECTED {
        bridge
            .set_config(&format!("plugin.{name}.enabled"), "true")
            .ok()?;
    }
    let host = Host::new(Arc::clone(&bridge) as Arc<dyn HostBridge>);
    Some((host, bridge, staged))
}

#[test]
fn the_inventory_is_printed_so_a_green_run_can_be_read() {
    // Not an assertion so much as the evidence. Every other test here answers
    // yes or no; this one says *what* was loaded, from which file, at which
    // version, so somebody reading a CI log can see six plugins rather than
    // trusting that five checks passed over an empty directory.
    //
    // Run with `-- --nocapture` to see it.
    let Some((host, _bridge, staged)) = host_with_everything("inventory") else {
        skip("no example artefacts to inventory");
        return;
    };

    eprintln!(
        "\n  loaded {} of {} staged files, in a host built from this repository's\n  \
         copy of mumble-plugin-api; every binary below was compiled against the\n  \
         C++ server's copy:\n",
        host.loaded_count(),
        staged.len()
    );
    let (listed, dir) = host.list_plugins();
    for info in &listed {
        eprintln!(
            "    {:<24} {:<8} {:<7} {}",
            info.plugin_name,
            info.version,
            info.kind,
            info.load_error.as_deref().unwrap_or("ok")
        );
    }
    eprintln!("\n  from {}\n", dir.unwrap_or_default());
    // A reporter that stays green while every line above says "ABI version 3
    // but host expects 4" is worse than no reporter: the log looks fine and
    // the summary says passed.
    assert_eq!(
        host.loaded_count(),
        staged.len(),
        "the inventory above is a list of failures"
    );
}

#[test]
fn every_published_example_loads_in_this_host() {
    // The headline. Each of these was compiled against the C++ server's copy of
    // `mumble-plugin-api`; each is loaded here by the copy that moved into this
    // repository. Nothing rebuilt them in between.
    let Some((host, _bridge, staged)) = host_with_everything("load") else {
        skip("no example artefacts to load");
        return;
    };

    let (listed, _dir) = host.list_plugins();
    let broken: Vec<String> = listed
        .iter()
        .filter_map(|info| {
            info.load_error
                .as_ref()
                .map(|error| format!("{}: {error}", info.path))
        })
        .collect();
    assert!(
        broken.is_empty(),
        "every example must load; these did not:\n  {}",
        broken.join("\n  ")
    );
    assert_eq!(
        listed.len(),
        staged.len(),
        "every staged file must account for exactly one plugin"
    );

    let mut names: Vec<String> = listed.iter().map(|info| info.plugin_name.clone()).collect();
    names.sort();
    assert_eq!(
        names, EXPECTED,
        "each plugin names itself, and the host reads that name out of the binary"
    );
    assert_eq!(host.loaded_count(), EXPECTED.len(), "all of them started");
}

#[test]
fn each_one_advertises_something_a_client_could_draw() {
    // Loading is not enough: the `info_json` round trip crosses the boundary as
    // an `RString`, gets parsed here, and is re-encoded into the envelope a
    // client reads. A layout mismatch that somehow survived the vtable check
    // would surface as garbage in this string.
    let Some((host, _bridge, _staged)) = host_with_everything("info") else {
        skip("no example artefacts to inspect");
        return;
    };

    let registry = host.registry();
    // Without this the loop below is vacuously true over an empty registry,
    // which is exactly what a rejected-ABI run produces. Verified by bumping
    // `PLUGIN_ABI_VERSION` and watching this fail.
    assert_eq!(
        registry.len(),
        EXPECTED.len(),
        "nothing loaded, so there is nothing being checked here"
    );

    for entry in registry {
        assert!(
            !entry.version.is_empty(),
            "{} states no version",
            entry.plugin_name
        );
        let info: serde_json::Value =
            serde_json::from_str(&entry.info_json).unwrap_or_else(|error| {
                panic!("{}: info_json is not json: {error}", entry.plugin_name)
            });
        let description = info
            .get("description")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        assert!(
            !description.is_empty(),
            "{} describes itself as nothing",
            entry.plugin_name
        );
    }
}

#[test]
fn the_examples_that_declare_slash_commands_carry_them_across() {
    // The richest thing crossing the boundary: `client_manifest` is a nested
    // structure of commands, options and components, encoded by the plugin and
    // decoded here. If the two API copies disagreed about anything in it, this
    // is where it would show.
    let Some((host, _bridge, _staged)) = host_with_everything("manifest") else {
        skip("no example artefacts to inspect");
        return;
    };

    let mut with_commands = Vec::new();
    for entry in host.registry() {
        let Ok(info) = serde_json::from_str::<serde_json::Value>(&entry.info_json) else {
            continue;
        };
        let commands = info
            .get("client_manifest")
            .and_then(|manifest| manifest.get("slash_commands"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for command in commands {
            if let Some(name) = command.get("name").and_then(serde_json::Value::as_str) {
                with_commands.push(format!("{}:/{name}", entry.plugin_name));
            }
        }
    }
    with_commands.sort();
    assert!(
        !with_commands.is_empty(),
        "the examples exist to demonstrate slash commands; none survived the boundary"
    );
    // The four the repository's own README tabulates.
    for expected in [
        "fancy-feedback-form:/feedback",
        "fancy-greeter:/greet",
        "fancy-info-card:/info",
    ] {
        assert!(
            with_commands.iter().any(|found| found == expected),
            "{expected} did not come across; got {with_commands:?}"
        );
    }
}

#[test]
fn a_client_arriving_reaches_all_of_them() {
    // The dispatch path, over six plugins at once rather than one: every loaded
    // plugin gets the callback, and every one of them gets its own info
    // envelope shipped to that session.
    let Some((host, bridge, _staged)) = host_with_everything("connect") else {
        skip("no example artefacts to dispatch to");
        return;
    };

    host.on_client_connected(ClientInfo {
        server_id: 1,
        session_id: 77,
        username: "ada".into(),
        cert_hash: "aa".into(),
        user_id: 3,
    });

    let delivered = bridge.data.lock().expect("not poisoned").clone();
    let envelopes = delivered
        .iter()
        .filter(|(id, session)| id == "fancy-plugin-info" && *session == 77)
        .count();
    assert_eq!(
        envelopes,
        EXPECTED.len(),
        "one info envelope per loaded plugin reaches the connecting session: {delivered:?}"
    );
}

#[test]
fn each_plugin_is_looked_up_under_its_own_name_and_no_other() {
    // Six plugins loaded at once is the case where scoping either holds or is
    // found not to. Asserted from what the *host* asked the server for, which
    // is the only side that can see across namespaces: a plugin cannot even
    // name another's key, so asking the plugins would prove nothing.
    let Some((host, bridge, _staged)) = host_with_everything("config") else {
        skip("no example artefacts to configure");
        return;
    };
    assert_eq!(
        host.loaded_count(),
        EXPECTED.len(),
        "nothing loaded, so no namespace was ever consulted"
    );

    let reads = bridge.reads.lock().expect("not poisoned").clone();
    for name in EXPECTED {
        assert!(
            reads.contains(&format!("plugin.{name}.enabled")),
            "{name}'s own namespace was never read: {reads:?}"
        );
    }
    // Every plugin-scoped read names a plugin that is actually here. A key for
    // a name nothing loaded under would mean the host had invented a namespace
    // or crossed one plugin's reads into another's.
    for key in reads.iter().filter(|key| key.starts_with("plugin.")) {
        let named = key.trim_start_matches("plugin.");
        assert!(
            EXPECTED.iter().any(|name| named.starts_with(name)),
            "{key} belongs to no loaded plugin"
        );
    }
}
