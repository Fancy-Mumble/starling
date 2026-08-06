# Starling, a 100% Rust port of the Fancy Mumble server

> **Codename rationale.** Starlings fly in *murmurations*. The name stays in the
> Mumble/Murmur family, describes exactly what the server does (coordinate a
> flock of voices into one motion), and (unlike `murmur`, `chorus` or `mumble`)
> is unique enough to grep for.

This document is the porting plan for replacing `vendor/server` (C++/Qt murmur,
Fancy fork) with a pure-Rust server. It is written against the actual source, not
against upstream Mumble: every scope number below was measured in this tree.

---

## 1. What we are actually porting

### 1.1 Measured scope

| Area | Path | Lines | Port difficulty |
|---|---|---:|---|
| Server core + handlers | `src/murmur/*.{cpp,h}` | 36 410 | High, the bulk of the work |
| ↳ of which message handlers | `src/murmur/Messages.cpp` | 5 304 | High, 90+ handlers |
| ↳ of which core/session/voice | `src/murmur/Server.cpp` | 3 813 | High, concurrency rewrite |
| ↳ of which Ice RPC | `src/murmur/MumbleServerIce.cpp` | 2 568 | **Replace, do not port** (§6) |
| ↳ of which DB wrapper | `src/murmur/DBWrapper.cpp` | 1 735 | Medium, mechanical |
| Generic DB layer | `src/database/` + `src/murmur/database/` | 14 323 | Medium, collapses hard under `sqlx` |
| Shared model/protocol | `src/{ACL,Channel,Group,User,Ban,MumbleProtocol,Version}.cpp`, `PacketDataStream.h` | ~3 100 | Medium, pure logic, very testable |
| Crypto | `src/crypto/` | 688 | Low, OCB2 already exists in Rust (§2.2) |

**~55 000 lines of C++ in scope.** Expected Rust equivalent: **18-25 kLOC**, because
`sqlx` deletes most of the 14 kLOC DB layer, prost deletes the serialisation
boilerplate, and the Ice subsystem is replaced rather than translated.

### 1.2 What we do **not** have to port

This is the part that makes the project tractable, and it is why this port is
worth doing *now* rather than in a year:

1. **The wire protocol is already implemented in Rust.**
   `vendor/client/crates/mumble-protocol` (12.8 kLOC) already contains the framing
   codec, the full `Mumble.proto` / `MumbleUDP.proto` bindings including all Fancy
   extensions, the OCB2-AES128 `CryptState`, and the legacy+protobuf UDP audio
   codec. It is written from the client's perspective, but the *wire* half is
   direction-agnostic.

2. **The plugin ecosystem is already Rust.**
   `vendor/server/3rdparty/mumble-plugin-host/` is a 9-crate Cargo workspace
   (`api`, `api-derive`, `api-wasm`, `host`, plus the `audit`, `calendar`,
   `file-server`, `friends`, `link-preview`, `live-doc` plugins) with both a native
   FFI loader and a WASM/WIT loader. In Starling we **delete `host/src/ffi.rs`**
   (the C ABI shim that exists purely to talk to C++) and link the host crate
   directly. Every existing plugin works on day one.

3. **The server never touches audio content.**
   Verified: `Server.cpp:1151` and `:1926` only *inspect* `audioData.usedCodec`;
   there is no decode, no mix, no resample anywhere in `src/murmur/`. The voice
   path is a header-rewrite-and-forward. **Starling needs no Opus dependency and
   no DSP.**

4. **The WebRTC SFU is already an out-of-process/dlopen'd component**
   (`3rdparty/webrtc-sfu`, loaded as `libwebrtc_sfu.so`). Its ABI is unchanged by
   the port; it is out of scope until the RPC surface lands.

---

## 2. Target architecture

### 2.1 Workspace layout

**Superseded.** This section planned eight crates named `starling-model`,
`starling-db`, `starling-server`, `starling-plugins` and `starling-rpc`. None of
them was ever built: the tree went to a gateway plus independent services
instead, and the layout that actually exists is `docs/ARCHITECTURE.md` §7.

The plan is kept for the one thing it still records, which is that the split was
chosen up front to keep pure logic away from I/O. That survived the rework; the
crate names did not.

### 2.2 Sharing the wire layer with the client

The `.proto` files are the contract and they already exist twice
(`vendor/server/src/Mumble.proto` and
`vendor/client/crates/mumble-protocol/proto/Mumble.proto`). Options considered:

| Option | Verdict |
|---|---|
| Cross-repo `path` dependency on `mumble-protocol` | **No.** The submodules are pinned independently; a path dep across them cannot be expressed in Cargo and would make the client's release cadence gate the server's. |
| Publish `mumble-protocol` to crates.io | **No.** It is `publish = false` by design and carries client-only concerns (audio pipeline, denoisers, work queue). |
| Split a `mumble-wire` crate out of the client and git-dep it from both | **Later.** Correct end state, but it is a refactor of a shipping client, not a prerequisite. |
| **Copy the `.proto` into `starling-proto`, generate independently, CI-enforce byte-identity** | **Yes, for now.** |

The `.proto` is copied from `vendor/server/src/` and `scripts/check-proto-drift.sh`
asserts all three copies are byte-identical. Note what `vendor/server` is not:
it is the Fancy fork, not upstream Mumble, and an earlier version of this
sentence called it "the upstream source of truth". Believing that is how the
field-numbering drift in `docs/PROTOCOL-COMPATIBILITY.md` §1 went unnoticed.
`scripts/check-proto-compat.py` is the check that actually looks at upstream.
Duplicating a *generated* artifact is cheap; duplicating the *contract* is what
must be prevented, and the drift check does exactly that.

Hand-written wire code (framing, message-id table, OCB2) is ported by reading the
client's implementation, not copy-pasted, the server's needs differ (it decodes
what the client encodes and vice versa, and it must be hostile-input-hardened in
a way a client never is).

### 2.3 Concurrency model

**Superseded.** This section specified a single `ServerCore` actor fed by an
`mpsc<Command>`, handlers shaped `fn(&mut ServerState, ..) -> Effects`, and an
`ArcSwap<RoutingTable>` for the voice path. None of `ServerCore`, `Command`,
`ServerState` or `Effects` exists in the tree.

Two of its conclusions did survive into `docs/ARCHITECTURE.md`, which is where
they are now written down: fan-out encodes once and clones a handle per
recipient, and a connection whose outbound queue is full is disconnected rather
than blocked on. The rest was replaced by the gateway (§1, §5 there).

### 2.4 Security: compatible by default, modern by negotiation

Mumble's transport security is dated in two specific ways, and the port is the
opportunity to fix both **without** costing backwards compatibility:

* **OCB2-AES128** (the UDP voice cipher) has a practical forgery attack
  (Inoue-Iwata-Minematsu-Poettering, CRYPTO 2019). Mumble's framing limits the
  exposure, but nobody would choose it today.
* murmur accepts **TLS 1.0 and later** (`Server.cpp:1671`).

Starling cannot simply raise the floor, the acceptance rule below requires the
shipped stock client to keep working. So security choices are negotiated
per peer by an **Abstract Factory** over what the peer announced:

```text
  PeerCapabilities ──► SecurityPolicy (Strategy) ──► SecuritySuite (product family)
                         ├── CompatibilityFirst        ├── tls_floor()
                         └── ModernOnly                └── voice_cipher()

  LegacySuite  TLS 1.2+, OCB2-AES128         ← every stock Mumble client
  FancySuite   TLS 1.3,  ChaCha20-Poly1305   ← clients announcing a Fancy version
```

A stock client behaves exactly as it does against murmur; a Fancy client is held
to modern primitives. Neither is a special case in a handler. `ModernOnly` is
available for deployments that control their client fleet and would rather
*refuse* a legacy client than carry OCB2, and it refuses explicitly, never by
silent downgrade.

Two things fall out for free: rustls implements **only** TLS 1.2 and 1.3, so
even Starling's most permissive floor beats murmur's; and `ChaCha20-Poly1305` is
already in the Fancy client's dependency graph (persistent chat), so the upgrade
adds no new cryptographic code to review.

Both suites are now negotiated, recorded, logged and implemented, with the TLS
floor enforced either way. The specifications (wire ids, key/nonce/tag sizes,
ordering) stay separate from the implementations in `crates/crypto`, so the
negotiation can be tested without standing up either cipher.

### 2.5 Handler shape

**Superseded**, along with §2.3. There is no `Handler` trait and no
`Effects` type; a service receives its own gRPC calls and answers with
`ServerAction`. See `docs/ARCHITECTURE.md` §5.

---

## 3. Compatibility contract

`SERVER-COVERAGE.md` in the e2e repo root is the acceptance spec and it is
already written. Restating the binding rule:

> The Rust server must pass the same tests with the same client binary and
> fixture matrix. Any intentional protocol difference needs a versioned schema
> decision and a test documenting the new contract; weakening an assertion is not
> an acceptable compatibility fix.

Three additional hard requirements this plan commits to:

1. **On-the-wire byte compatibility with the shipped client.** Not "compatible
   enough", the e2e suite drives the real packaged FancyMumble binary.
2. **Read the existing murmur SQLite/Postgres/MySQL schema in place.** The e2e
   fixture and any real deployment share `/data/mumble-server.sqlite`. Starling
   must open an existing murmur DB, run its migration chain, and preserve data.
   A greenfield schema + one-way importer is explicitly rejected: it makes
   rollback impossible, and rollback is the only thing that makes a rewrite of a
   live server safe.
3. **Storage: greenfield schema plus a migration tool** (decided 2026-07-25).
   Starling does *not* reuse murmur's schema. murmur's is EAV-based, nearly
   index-free, and stores the unbounded chat table's pagination cursor as an
   unindexed `TEXT` UUID, see `docs/STORAGE.md` for the measurements. Rollback
   safety comes instead from `starling migrate-db`, which reads murmur's database
   **non-destructively**, so the C++ server keeps working off the original file.
   Backends: SQLite (default), PostgreSQL, MySQL. Multi-tenancy (`server_id`) is
   retained. The event log stays behind `LogSink`, not in the relational schema.

4. **Config: TOML natively, `.ini` as a migration path.** Configuration is *not*
   part of the wire contract, so it is the one place the port deliberately
   modernises rather than reproduces. Starling's own format is `starling.toml`
   (typed, sectioned, comments, unknown keys rejected, see
   `starling.example.toml`). murmur `.ini` files still load, detected by
   extension, so the e2e fixture can drive either server from one file while the
   port is staged; `starling migrate-config <file.ini>` prints the equivalent
   TOML. The `.ini` reader is a migration aid with an expiry date, not a
   commitment.

---

## 4. The order of work

Each block below ends with a green subset of the real e2e suite. Nothing is
"done" because code exists; it is done when the shipped client passes. They are
listed roughly in dependency order rather than numbered, because the numbering
outlived its accuracy: voice and persistence were built concurrently, and the
last three overlap to this day.

### MVP
**Goal:** the smallest server the real client will complete a session against.

- TLS listener; self-signed cert auto-generated on first boot (`rcgen`).
- Handshake, in murmur's exact order (verified against `Messages.cpp`):
  `Version` (server-first, on TLS-established, `Server.cpp:1679`) → client
  `Version` → client `Authenticate` → `CryptSetup` → `CodecVersion` →
  `ChannelState`×N (BFS from root) → own `UserState` → other `UserState`s →
  `ServerSync` → `ServerConfig` → `SuggestConfig`.
- In-memory channel tree (root only), session allocation, TCP `Ping` echo with
  counters, `TextMessage` fan-out, `UserState` self-mute/deaf, `UserRemove` on
  disconnect.
- Permissions are an allow-all `Permissions` trait impl, the seam is real, the
  implementation is a stub.
- `.ini` parsing for the subset the MVP honours.

**Exit test:** `src/tests/smoke.connect.test.ts` (connect → chat view → text
round-trip) passes against Starling.

**Explicitly out:** UDP voice, database, ACL evaluation, registration, bans, and
every Fancy message.

### Voice
UDP socket + OCB2 `CryptState`, legacy and protobuf UDP framing, `UDPTunnel`
fallback, the `ArcSwap<RoutingTable>` routing snapshot, whisper/`VoiceTarget`,
channel listeners with volume adjustment, per-user bandwidth limiting,
`UserStats`.
**Exit:** `voice-state*`, `voice-state-sync`, `audio.resample`.

### Persistence and authority
`starling-db` (sqlx, SQLite first), murmur schema + migration chain, registered
users, `authenticate()` incl. certificate hash + PBKDF2 + legacy hashes, TOTP,
bans, channel/ACL/group persistence, textures and comments with blob hashing.
Full ACL evaluation and permission cache, the 24-bit `ChanACL::Perm` set
(`ACL.h:21`) including the Fancy additions (`SubscribePush`, `ShareFiles`,
`ShareFilesPublic`, `KeyOwner`, `ManageEmotes`, `ReadRegister`, `SeeChannel`).
**Exit:** `admin-create-role`, `hidden-channels`, `channels`,
`registered-name-impersonation`, `root-channel-visibility`, `channelviewer`.

### Plugin host
Link `mumble-plugin-host` directly (no FFI). Port `PluginHostManager` (797 lines)
and `ServerEventDistributor` (533 lines) to the `Effects` model. `PluginMessage`,
`PluginRegistry`, plugin admin list/enable/install/uninstall,
`PluginDataTransmission`.
**Exit:** `fileserver`, `forums`, `calendar*`, `link-preview`, `audit-log`.

### Persistent chat
`PersistentChatManager` + `PchatProtocolHandlers` + the 8 pchat DB tables. Note
the server is a *relay and store* for pchat, the E2E crypto lives in the client
(`mumble-protocol/src/persistent/`), so this phase is storage, fan-out, offline
queues, key-holder bookkeeping and rate limiting, **not** cryptography.
**Exit:** `pchat*`, `signal-pchat`, `reactions`, `friend-chat*`,
`scheduled-messages`, `meetings`.

### The remaining Fancy surface
Push notifications + FCM, read receipts, typing indicators, watch sync, draw
strokes, onboarding, polls, server/account settings, audit config/query.
**Exit:** `fancy-control-plane`, `server-compatibility`, remaining specs.

### SFU and RPC
WebRTC SFU: keep dlopen'ing the existing `libwebrtc_sfu.so` first; port to
`str0m` only after parity. Ship `starling-rpc` (§6) and the channelviewer shim.

---

## 5. Risk register

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | **Ice has no viable Rust implementation.** `MumbleServerIce.cpp` is 2 568 lines and `vendor/channelviewer` consumes it (`getDefaultConf`). | **High** | Do not port. Replace per §6 and ship a shim. Needs explicit sign-off before any of it is persisted; this is the one deliberate compatibility break. |
| R2 | Schema drift between Starling's migrations and murmur's. | High | Starling reads murmur's existing schema; migrations are additive only. CI runs a murmur-written DB through Starling and asserts data equality. |
| R3 | Hostile input. A client library trusts the peer; a server cannot. The ported framing must survive fuzzing. | High | `cargo-fuzz` target on the frame decoder from the first commit. `MAX_PAYLOAD_SIZE` and per-field limits enforced before allocation. |
| R4 | Subtle handshake ordering differences that the client tolerates in dev but not in the wild (e.g. `ServerSync` before listeners, `Messages.cpp:843` is explicit that listeners must come *after*). | Medium | Ordering is transcribed from source with line references and asserted by a raw-TCP harness (`SERVER-COVERAGE.md` fixture layer 2). |
| R5 | The `messagelimit`/`messageburst` leaky bucket **silently drops** messages (see `fixtures/mumble-server.ini`). Getting this subtly wrong breaks WebRTC signalling in ways that look like client bugs. | Medium | Port the token bucket first (`TokenBucketRateLimiter.cpp` is already isolated), unit-test it against the C++ behaviour, and log drops at `debug` rather than dropping silently. |
| R6 | Two servers to maintain during the transition. | Medium | Phases are gated on the *same* e2e suite, so both stay honest. Fixture picks the implementation via one env var. |
| R8 | **The gRPC hop cost has never been measured on the target platform.** The bus experiments it replaces were Windows-only on 24 unconstrained cores; the target is Linux containers, plausibly CPU-limited. A hop that is free on a workstation is not automatically free under a cgroup quota. | **High** | Measure gateway-to-service round-trip on Linux under quota, over both a Unix socket and TCP, before the first service ships. |
| R9 | **Audio bypassing the gateway is an assumption, not a measurement.** The design rests on voice binding its own UDP socket on the same port as the gateway's TCP socket, in a different process. murmur binds them separately (`Server.cpp:125` vs `:193`) so it should hold, but it has never been tried across process boundaries, and legacy clients cannot be redirected if it fails. | **High** | Prove two processes can hold TCP:64738 and UDP:64738 on every target OS before anything else is built. If it fails, voice becomes a gateway sidecar and the deployment story changes. |
| R11 | **A restarted service has cold caches and no way to say so.** Voice holds ciphers and membership; audio arriving before it re-subscribes is dropped silently. This is the failure mode with no log line. | **High** | `/readyz` gates on cache warm-up and is distinct from `/healthz`. An e2e test restarts voice mid-call and asserts audio resumes without loss beyond the drain window. |
| R10 | A blocking `call()` can **deadlock** on a cycle (A calls B, B calls A); `send` could not. No rule or mechanism exists. | Medium | Decide the rule before `call()` ships, either a documented acyclic port order or a depth/timeout guard. §4.2 B1. |
| R7 | Plugin host was built against the C++ FFI contract; removing `ffi.rs` may surface assumptions baked into `context.rs`. | Low | The plugin host work starts by running the existing host test suite against a Rust-native `HostFacade` impl before wiring any real server state. |

---

## 6. The Ice decision (needs sign-off)

Ice is the only subsystem that **cannot** be ported: there is no maintained Rust
ZeroC Ice implementation, and writing one is a larger project than the server.

Proposal:

- Ship `starling-rpc` as a **gRPC (tonic) admin API** mirroring the
  `MumbleServer.ice` interface; it is already an IDL-shaped, strongly-typed RPC
  surface, so the translation is mechanical.
- Ship a small **Ice↔gRPC shim** (or patch `vendor/channelviewer` to speak gRPC
  directly; it only needs `getDefaultConf` and the channel tree, per the fixture
  comment in `mumble-server.ini`).
- Keep `ice=` in the `.ini` accepted-but-ignored with a startup warning, so
  existing configs boot.

This is a versioned schema decision under the `SERVER-COVERAGE.md` acceptance
rule and must be recorded as such.

---

## 7. Why this is worth doing

Not "Rust good". Concretely, in this tree:

- **The handlers become testable.** `Messages.cpp` handlers reach into global
  server state, the DB and the Qt event loop; they can only be tested by running
  a server. `fn(&mut ServerState, msg) -> Effects` can be tested in microseconds.
- **The plugin ecosystem stops being second-class.** Today Rust plugins reach the
  C++ server through a hand-written 481-line C ABI shim. That shim disappears.
- **One toolchain.** Client, plugins, and server all build with `cargo` on the
  same pinned 1.95.0, no Qt6, no Ice, no CMake option matrix, no
  `Qt6::QMYSQLDriverPlugin` gymnastics.
- **The concurrency rewrite is the actual prize.** The single-actor + lock-free
  voice-routing design (§2.3) is not expressible cheaply in the current codebase;
  the port is the opportunity to fix it, and it is what makes the voice path
  immune to control-plane stalls.

---

## 8. The server event log

Operator-facing records, who connected, what was refused, what an administrator
changed, are a separate concern from `tracing`'s developer diagnostics, and live
in `starling-log`. Where they go is a Strategy:

```text
  Logger  ──(bounded queue)──►  writer thread  ──►  dyn LogSink
 (never blocks)                                       ├── ConsoleSink
                                                      ├── FileSink (size rotation)
                                                      ├── MemorySink (ring, for the admin API)
                                                      ├── FanoutSink ── [ ... ]   (Composite)
                                                      ├── FilterSink ── sink    (Decorator)
                                                      └── NullSink              (Null Object)
```

A database, syslog or HTTP destination is a new `LogSink` implementation and one
arm in `config/logging.rs`; nothing else in the server changes.

Two properties make it safe on a server, and both are tested:

* **`Logger::log` never blocks.** The writer is a dedicated OS thread, not an
  async task, logging must keep working while the runtime is saturated, which is
  exactly when the records matter most.
* **Overflow is counted and reported, never silent.** A log that quietly loses
  records is worse than no log, because it is trusted.

Handlers emit records as `Effect::Log`, so they stay pure and a test can assert
on what was logged without installing a sink.

## 9. Status

The tree now implements `docs/ARCHITECTURE.md`: a gateway in front, nineteen
independent gRPC services behind it, and media planes that bypass the gateway.
The list below tracks *what works*, which is not the same question as *how it is
arranged*.

- [x] MVP: handshake, channel tree, text fan-out, ping, disconnect
- [x] Voice: its own UDP socket, cipher minting per peer, routing core
- [x] Persistence and authority: per-service schemas, accounts, authentication,
      ACL evaluation with inheritance and deny-over-allow
- [~] Plugin host: the service, the opaque relay and the namespaced key/value
      capability exist; linking `mumble-plugin-host` itself does not
- [x] Persistent chat: relay and store, UUIDv7-keyed, retention swept
- [~] The remaining Fancy surface: push, audit, onboarding, social, link-preview
      and context-actions each have their service and envelope; several answer a
      subset of their envelope's messages
- [~] SFU and RPC: `operator-api` ships (REST + OpenAPI, pluggable auth,
      fail-closed audit); the SFU is signalling-only and the channelviewer Ice
      shim is not written

### What the architecture rework changed

The in-process microkernel is gone: no bus, no lanes, no envelopes, no
`starling-api` trait hub. What replaced it, and where to read about it:

| Was | Is | Why |
|---|---|---|
| one process, one actor | gateway + 19 services | §2, §4 |
| `Command` into `ServerCore` | gRPC, and a uniform client plane | §1 |
| in-process `Effects` | `ServerAction` over a bidirectional stream | §5 |
| one database | one schema per service | §4, `STORAGE.md` |
| `starling-api` | `starling-runtime`, which nothing calls *through* | §7 |

### Still open

* **The session store is in-memory.** The resume ring lives in the gateway
  process, so a resuming client must land on the pod it left. The interface
  does not change when it is externalised; that is why the decision it is
  waiting on (frames or events, §5) can still be made.
* **JWT and OIDC verification.** `operator-api` refuses every token in those
  modes rather than accepting one it has not verified. The static-token and
  mTLS modes work.
* **The plugin host is not linked.** The service, the opacity rule and the KV
  capability are built; loading a real plugin binary is not.
* **Audio routing is not wired to the socket.** The routing core, the ciphers,
  the packet codecs and the peer table are all present and tested; the UDP loop
  logs datagrams rather than routing them.

## 10. Lint suppressions

Per `DESIGN.md` §10, every `#[allow]`/`#[expect]` in the workspace is listed
here.

| Location | Kind | Lints | Why |
|---|---|---|---|
| `starling-proto/src/lib.rs` (×2, one per generated module) | `allow` | `missing_docs`, `missing_debug_implementations`, doc lints, `clippy::too_many_lines`, `clippy::allow_attributes_without_reason` | Generated by `prost-build`. `allow` rather than `expect` because which doc lints fire depends on how upstream wrapped its `.proto` comments. |
| `starling-proto-fancy/src/lib.rs` (one `generated!` macro, applied per module) | `allow` | as above, plus `unreachable_pub`, `unused_qualifications`, `unused_results`, `clippy::large_enum_variant` | Generated by `prost`/`tonic`; the list is the measured minimum. |
| `starling-metadata/src/serialize.rs::set_legacy_temporary` | `expect` | `deprecated` | `ChannelState.temporary` is proto-deprecated but is still the only temporary-channel signal a *stock* client understands; murmur writes it for the same reason (`Messages.cpp:189`). |
| `starling-metadata/src/serialize.rs` (one test) | `expect` | `deprecated` | Asserts on the field the client actually reads. |
| `starling-metadata/src/lib.rs::on_channel_state` | `allow` | `deprecated` | Reads the same frozen field on the way in. |
