# Plugin host port plan

How the Fancy plugin host moves from the C++ server into Starling. Written
2026-08-20 against `vendor/server` @ the current e2e pin and Starling main.
Companion to `docs/FANCY-PARITY.md` §1, which names this the single
highest-leverage piece of work left.

## 0. The good news: it is not a C++ port

The C++ server's plugin host is already Rust. `src/murmur/PluginHostManager.cpp`
is a ~800-line bridge; everything real lives in the Rust workspace at
`vendor/server/3rdparty/mumble-plugin-host/`:

- `host/` — discovery, `abi_stable` native loading (`loader.rs`), a wasmtime
  component backend (`wasm.rs`), marketplace install (`install.rs`), the
  `fancy-plugin-info` envelope (`info.rs`), and the `Host` state machine
  (`host.rs`).
- `api/` — the plugin-facing contract: `MumblePlugin` (the hook trait),
  `PluginContext` (what plugins call back into), permissions, client
  manifests. `PLUGIN_ABI_VERSION = 3`, `WASM_ABI_VERSION = 2`.
- `api-derive/`, `api-wasm/`, `wit/` — proc macros and the WASM guest SDK.
- Six shipped plugins: `audit`, `calendar`, `file-server`, `friends`,
  `link-preview`, `live-doc`.

Only two files in that workspace are C++-shaped and do not move:

- `host/src/ffi.rs` — the `extern "C"` surface for `PluginHostManager`. Dies.
- `host/src/context.rs` — `PluginHostCallbacks` (a C function-pointer table)
  plus `ScopedContext`. Replaced by a Starling-native `PluginContext` impl.

Everything the C++ side does beyond calling those entry points — event
subscription, wire-message handling for types 26/146–151/200/201, admin authz,
registry broadcast — Starling's `plugins` service either already does or has a
designated home for.

## 1. What Starling already has (terrain)

`crates/services/plugins/` (524 lines) owns:

- gRPC `PluginsRpc`: `List`, `Enable`, `Install`, `Uninstall`, `Deliver`,
  `KvGet/KvScan/KvWrite` (`plugins.proto`).
- Client plane: `PLUGIN_DATA` (26) relay with anti-spoof + caps, and outer
  type 1010 `PluginsEnvelope` (`Query`→`Registry`, `Opaque`→relay,
  `Admin`→refused as an operator action).
- Namespaced plugin storage: `runtime/src/storage/kv.rs` over the `plugin_kv`
  table, per `docs/STORAGE.md` §L5/L6.

What it lacks (verified: no `libloading`/`wasmtime`/`dlopen` anywhere under
`crates/`):

1. A loader. `Install` records a row; nothing is fetched, verified, or run.
2. Persistence — `installed: Mutex<HashMap>` forgets everything on restart.
3. A `Serve::run` task to own plugin lifetimes.
4. A lifecycle event feed — connect/disconnect/user-state never reach the
   plugins service (only `session-view` and operator-api's `EventHub` see
   them).
5. Operator routes — no `/v1/plugins`.
6. A `[services.plugins]` example config block.

## 2. Target architecture

The host lives **inside `PluginsService`**, in-process. No C ABI anywhere.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/plugin-host-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="diagrams/plugin-host.svg">
  <img alt="The plugin host inside the plugins service, coloured by provenance" src="diagrams/plugin-host.svg">
</picture>

Source: [`diagrams/plugin-host.puml`](diagrams/plugin-host.puml).

Key inversions relative to the C++ integration:

- **Per-server → per-service.** The C++ side creates one host per virtual
  server. Starling runs one `Host` in the plugins service and keys plugin
  state by `server_id`, which the host's session map
  (`HashMap<(ServerId, SessionId), ClientInfo>`) already supports. Plugins
  see the same `server_id` parameter they see today.
- **Wire admin → operator admin.** The C++ server accepts plugin admin over
  the client wire (types 146–151, root-channel Write). Starling has already
  decided otherwise — the 1010 `Admin` envelope is refused by design. Admin
  goes through operator-api routes calling `PluginsRpc`. The 146–151 wire
  messages are *not* ported.
- **Callback table → trait impl.** `PluginContext` stays the plugin-facing
  trait, byte-for-byte compatible; only its implementation changes from
  C-trampolines-into-Qt to gRPC-and-runtime calls.

### Sync/async bridge

Plugin hooks are synchronous and plugins own their own tokio runtimes
(`api/src/lib.rs:7-14`). Starling handlers are async. The bridge:

- Hooks are invoked via `tokio::task::spawn_blocking` (precedent:
  `userdata/src/lib.rs:181` for Argon2). Never call a hook on a runtime
  worker.
- `StarlingContext` methods are sync (the trait demands it); each captures a
  `tokio::runtime::Handle` plus cached tonic clients and uses
  `Handle::block_on`. Callers are plugin worker threads or the blocking
  pool — both are legal places to block on a foreign runtime.
- The whole `Host` stays behind one `Mutex`, exactly like the reference
  (`ffi.rs:61`). Serialized dispatch was good enough for the C++ server;
  don't parallelize until something measures slow.

### Context method mapping

| `PluginContext` method | C++ implementation | Starling implementation |
|---|---|---|
| `send_plugin_message` | direct proto emit | `Fanout::push` of a 1010 `Opaque` (or 26) to target sessions; channel targets resolved via `Roster` |
| `send_plugin_data` (deprecated) | ditto | ditto, type 26 |
| `is_session_active` / `all_sessions` / `sessions_in_channel` / `find_session_by_name` / `current_channel` | `qhUsers` under `qrwlVoiceThread` read lock | `Roster` + session-view snapshot cache held by the service |
| `user_has_channel_access` / `has_permission` | `ChanACL::` checks | `permissions` gRPC `Check`/`SessionCheck` |
| `get_config` / (host-only) `set_config` | per-server DB + ini fallback | plugin KV under a reserved `cfg/` prefix, seeded from `[services.plugins]` TOML `options`; `__host_*` virtual keys answered from constants as today |
| `create_channel` / `grant_channel_access` / `revoke_channel_access` | `QMetaObject::invokeMethod` onto server thread | `metadata` gRPC `CreateRequest` + `permissions` `SetAcl`/`TemporaryGroup` |
| `send_request_response` | C++ handler registry (`m_responseHandlers`) | Rust closure registry inside `PluginsService` (same request/response bridge, no FFI) |

Nothing in the trait needs kick/ban/move — the C++ host never exposed them
either. If plugins later need moderation verbs, `moderation` and
`SessionControlGrpc::set_state` are one gRPC call away, behind a new
versioned trait method.

### Event feed

The C++ host subscribes to exactly four distributor events. Their Starling
sources:

| Event | C++ source | Starling source |
|---|---|---|
| `on_client_connected` | `onUserConnected` | session-view broadcast: session appears |
| `on_client_disconnected` | `onUserDisconnected` | session-view broadcast: session gone |
| re-`connected` on registration (`user_id` change) | `onUserStateChanged` + `m_lastUserId` | session-view diff on `user_id`, same last-seen map |
| `on_plugin_data` / `on_plugin_message` | wire 26 / 200 | plane `frame()`: 26 fans out to all loaded plugins; 1010 `Opaque` naming a *loaded* plugin dispatches to exactly that one, otherwise relays to clients as today |

operator-api's `events.rs` already does the snapshot→event diffing with the
right vocabulary; extract that fold into `runtime` (or replicate the ~100
lines) so plugins and operator-api share it. `fancy-plugin-info` ships to
each session on its connected event, unchanged wire format
(`info.rs`: version byte, zstd bit, 64 KiB cap).

Note the semantics change worth accepting: session-view is eventually
consistent (broadcast snapshots), where the C++ distributor was synchronous
on the server thread. None of the four events is used for veto, so lag is
harmless; a cold roster just delays a greeter by milliseconds.

## 3. Moving the crates

Recommendation: **move the workspace into Starling** — `crates/plugin-host/`
holding `api`, `api-derive`, `api-wasm`, `host`, `wit`, and the six plugins
under `crates/plugin-host/plugins/`. Rationale: `vendor/server` is a frozen
parity reference; Starling is where this code will be maintained. The copy
left behind in the C++ tree keeps that server building but receives no new
work. (Alternative if both must track each other: split
`mumble-plugin-host` into its own repo and consume it as a submodule/path
dep from both. More moving parts; only worth it if the C++ server stays
alive longer than planned.)

Compatibility invariants to hold while moving:

- **Crate names and ABI constants unchanged** (`mumble-plugin-api`,
  `PLUGIN_ABI_VERSION = 3`, `WASM_ABI_VERSION = 2`, root module name
  `fancy_plugin`, both exported symbols). Existing built plugin binaries
  must load in either server unmodified.
- **Toolchain**: both workspaces already pin Rust 1.95.0 — keep them in
  lockstep; `abi_stable` layout checks fail loudly on drift, but matching
  compilers avoid the churn.
- Keep the loader's two hard-won gotchas: the layout-independent
  `__mumble_plugin_abi_version` probe *before* any `abi_stable` cast
  (`loader.rs:193-201`), and `lib_header_from_path` instead of
  `RootModule::load_from_file` (the per-type static cache returns the
  first-loaded module for every later path, `loader.rs:225-240`). Also keep
  the Linux ELF pre-validation via `goblin`.

Workspace friction to resolve up front:

- `unsafe_code = "deny"` workspace-wide (`Cargo.toml:192`). The reference
  workspace has the same lint relaxed to `allow` only in the `host` crate;
  Starling does the same, with a reason string
  (`allow_attributes_without_reason` is deny).
- `panic = "abort"` in release (`Cargo.toml:285`): the host's
  `catch_unwind` guards are moot in release — a panicking native plugin
  aborts the server. The reference host ships with the identical posture,
  so this is parity, not regression. Treat native plugins as trusted
  first-party code; untrusted/marketplace code should be WASM. (If that
  ever hurts, the standalone plugins-service binary can be built with a
  `panic = "unwind"` profile override — per-unit deployment makes the blast
  radius one service.)
- Starling denies `missing_docs`, `unwrap_used`, `too_many_lines`,
  `excessive_nesting` — the lifted crates carry the same lints already, but
  expect a small conformance pass (edition 2024 migration included).

## 4. Milestones

**M0 — Lift.** Move the crates as above; delete `ffi.rs`; stub `context.rs`
down to the `ScopedContext` config-prefixing logic worth keeping; make the
workspace build under Starling's lints. No behavior. Exit: `cargo clippy
--workspace --all-targets -D warnings` green with the new crates as members.

**M1 — Host in the service.** `PluginsService` gains `Serve::run`: build a
`Host` from `[services.plugins]` config (`plugins_dir`, `builtin_plugins`
as structured `ServiceConfig` fields or `options` keys), scan, load,
enable per the persisted registry. Registry moves from the in-memory map to
a table (host infrastructure, not plugin-specific — STORAGE.md L6 is about
plugin *feature* tables). `RegistryQuery` answers from the real host;
registry re-broadcast on change. Exit: `friends` (293 lines, the simplest
shipped plugin) loads at startup and appears in the 1010 `Registry`.

**M2 — StarlingContext.** Implement the mapping table above. `get_config`
seeded from TOML into KV on first load, never overwriting operator edits
(mirrors `provision_live_doc_bridge`'s never-clobber rule). Exit: `friends`
round-trips a plugin message end-to-end against a real client.

**M3 — Events + dispatch.** session-view subscription → connected /
disconnected / registration re-announce; `fancy-plugin-info` on connect;
26 fan-out and 1010 `Opaque` single-plugin dispatch into the host; the
request/response closure bridge. Exit: greeter-style behavior works; e2e
plugin suites that only need the server side go green.

**M4 — Admin.** operator-api `/v1/plugins` (GET list, POST
`{name}/enable|disable`, POST install, DELETE) → `PluginsRpc` → host
`set_enabled`/`install_plugin`/`uninstall_plugin`. Install fetches the
artifact from the `files` service by `source_key`, verifies `sha256`
(adapting `install.rs`; its HTTP marketplace path can stay for parity or
wait), writes to `plugins_dir`, lands disabled. Hot enable/disable with
re-announce + registry broadcast, matching the C++ toggle cycle. Exit:
operator can install/enable/disable/uninstall live.

**M5 — Hardening + parity sweep.** WASM epoch deadlines (the reference
configures none — a guest can spin forever; add them here), fix the
`install.rs` extraction path-sanitization gap (`cdylib_filename` from the
manifest is joined unsanitized), carry over the fuzz targets and
`cargo-deny` config, port the config-change → disable/enable reload cycle
into Starling's hot-reload table (`config/reload.rs`). Exit: shipped
plugins (`audit`? see open questions, `calendar`, `file-server`,
`link-preview`, `live-doc`) evaluated one by one against Starling.

Per FANCY-PARITY.md:168, the plugin layer is missing at both ends — M1–M4
alone won't green the client-visible e2e suites until the client side
exists too. `friends` + registry assertions are the honest server-side
exit tests.

## 5. Open questions (decisions wanted)

1. **Where the shipped plugins' feature bridges go.** The C++ server wires
   `link-preview` and `audit` through dedicated bridges
   (`LinkPreviewBridge`, `AuditLogBridge`) and hard-codes the
   live-doc↔file-server token handshake in the host
   (`provision_live_doc_bridge`). Starling already has an `audit` *service*
   and an opacity rule (STORAGE.md L6: the server must never know a
   plugin's name or semantics). Porting those bridges verbatim violates the
   rule. Options: (a) compat shims inside the plugins service, quarantined
   and documented as debt; (b) redesign as a generic capability grant
   plugins declare in their manifest. Recommendation: (a) for live-doc's
   token bridge to unblock parity, (b) as the stated end state; and decide
   whether Starling's `audit` service supersedes the `fancy-audit` plugin
   outright.
2. **Native backend: keep or WASM-only?** Recommendation: keep both — the
   shipped plugins are native `abi_stable` cdylibs and rewriting six of
   them as WASM components is a separate project. Policy: native =
   first-party/builtin, WASM = everything installable.
3. **Move vs. share the crates** (§3). Recommendation: move; the C++ tree
   keeps a frozen copy.
4. **`MUMBLE_PLUGIN_DIRS` / `MUMBLE_PLUGIN_LOG` env vars.** Keep for dev
   convenience or fold into TOML + Starling's tracing config? Cheap either
   way; default to TOML-first, keep `MUMBLE_PLUGIN_DIRS` honored.
5. **Client-manifest settings surface.** The C++ server exposes each
   enabled plugin's `client_manifest.config_schema` as editable server
   settings and bumps a settings revision on toggle. Starling's equivalent
   would hang off `server-config`. Defer past M4 unless a client suite
   needs it sooner.
