# Hot reload plan

> **Status, 2026-08-16.** Part B is largely built and landed (uncommitted):
> classification, the reload pipeline, `SIGHUP`, and appliers for the whole of
> `[logging]` bar `queue`, the gateway's queue bounds / rate buckets / breakers
> / TLS certificate / routing table, `runtime.max_tree_message`,
> `[services.files]`'s URL keys, `[services.operator-api.auth]`, and
> `[instances.settings]`. `docs/CONFIGURATION.md#reloading` is the operator-
> facing description and the authority on what is live; the table in
> `crates/runtime/src/config/reload.rs` is the authority in code, with a test
> that fails on any unclassified key. **Part A is not started.**
>
> Three things found while building it, none of which were reload bugs, and all
> three are now fixed. `services.*.storage.max_connections` reaches
> `AnyPoolOptions` (`storage/backend.rs`); `operator-api`'s `audit.fail_closed`
> is read in `OperatorApi::record`, the one place that decides whether an
> unrecorded action refuses the request; and `gateway.default_deadline` bounds
> the `attach` dial in `gateway/src/attach.rs`, which previously had no timer
> under it at all, so a service that accepted the connection and then answered
> nothing parked the dial forever and never counted a breaker failure.

Two things an operator of a highly-available Starling wants to do without
clients noticing: **replace one component** (a patched `text` binary, a fixed
`pchat`) and **change configuration** in place. The second is now built (see the
status above); the first is not. This file says what exists, what is actually in
the way, and the order to build the rest.

The sections below were written before any of it existed, and §0 in particular
describes the tree as it was. Where it and the status block disagree, the status
block is current.

Nothing here is a Rust `dlopen` story. A Starling "component" is a process, and
hot-patching one means starting the new process and retiring the old one while
the gateway keeps every client socket. That is what the architecture was built
for (`ARCHITECTURE.md` §2), and it is closer than it looks; the gaps are in the
seams, not the shape.

---

## 0. What is true today

Findings from reading the tree at `3d90be4`; file:line so they can be re-checked.

**Config is read once and frozen.** `Config::load` runs at startup
(`crates/runtime/src/serve.rs:352`, `crates/starling/src/compose.rs:301`), is
handed out as `Arc<Config>` and never touched again. No `arc-swap`, no
`tokio::sync::watch` anywhere in the workspace. The only signal handled is
SIGTERM/ctrl-c → `Shutdown::drain()` (`crates/runtime/src/shutdown.rs:64-91`).
No SIGHUP, no file watcher, no `ExecReload=` in `packaging/starling.service`,
nothing in compose. Helm's answer is a `checksum/config` annotation on every
workload (`deploy/helm/starling/templates/workloads.yaml:50`), so a ConfigMap
edit **rolls every pod**, one at a time.

**Built once from that config, never rebuilt:** the gateway routing table
(`crates/gateway/src/router.rs:43-64`, plain field on `Gateway`), the TLS
acceptor (`crates/gateway/src/listener.rs:290-335`, called once at
`listener.rs:173`), the per-service attach set (`listener.rs:153-161`), the
`Resolver`'s `tonic::Channel` cache (`crates/runtime/src/channel.rs:126-136`,
never evicted), the per-route rate buckets, breaker thresholds, log format.

**The operational layer is already live, and it is the model to copy.**
`server-config` stores 33 fields per instance with the set of names an operator
has written (`crates/services/server-config/src/lib.rs:96-106`), publishes a
`Snapshot` on every `Set`, and `starling_runtime::Settings` follows the `Watch`
stream in every reader with a 2 s resubscribe loop
(`crates/runtime/src/settings.rs:226-281`). The gateway's `message_limit` even
re-tunes buckets on **open** connections (`crates/gateway/src/limiter.rs:128-165`).
Rough edges: only the `control` bucket follows; `operator-api` hardcodes
instance 1 (`crates/operator-api/src/routes.rs:2081`); the `version == 0` guard
at `listener.rs:252-282` has the documented residual bug.

**A service restart is already survivable for the gateway, badly.** The attach
loop re-dials forever (`crates/gateway/src/attach.rs:169-237`) and buffers up to
1024 events across the gap. But on re-attach it sends only `GatewayHello` and
**never replays `Opened` for the connections it holds** — a restarted service
learns of a client only from that client's next inbound frame. `session-view`
is in-memory, edge-triggered and declares no readiness gate
(`crates/services/session-view/src/lib.rs:235-242`), so after *its* restart the
composed view is empty for every connected session until something changes, and
every subscriber that reconnects `replace`s its roster with that emptiness
(`crates/runtime/src/roster.rs:121-155`).

**"HA" is one replica of everything.** All StatefulSets, `replicas: 1`
throughout, no `updateStrategy`, PDBs render for nothing by default. Readiness
probes are bare TCP connects because Kubernetes' `grpc:` probe speaks
`grpc.health.v1` and Starling's gate speaks `starling.health.v1`
(`deploy/helm/starling/templates/_helpers.tpl:145-171`), so "ready" means
"listening", not "caches warm". Gateway `replicas > 1` needs a shared cert and
`sessionAffinity: ClientIP` (`README.md:60-62`). The RESUME store is process
memory keyed by a **per-connection** token (`crates/gateway/src/resume.rs:88-96`,
`listener.rs:396-397`), so replay can never hit after a reconnect, let alone on
another gateway. Staggered drain and reconnect hints are doc comments
(`shutdown.rs:8-12`), not code; `Gateway::run` breaks the accept loop and returns.

**Plugins are not code.** `plugins` is a relay and a namespaced KV; nothing is
loaded, so nothing needs reloading (`crates/services/plugins/src/lib.rs:1-12`).
Its `installed` map is in-memory and lost on restart, which is a persistence
bug, not a reload problem.

**All-in-one has one `Shutdown` for everything** (`compose.rs:83-112`), and
`units::spawn` is a `match` that consumes the context (`crates/starling/src/units.rs:18-49`).
No per-unit lifecycle handle exists.

---

## 1. Part A — patching one component

Goal: `kubectl set image` on `text`, or `docker compose up -d text`, or
`systemctl restart starling-text`, and nobody in a channel notices. Then the
same for the gateway itself, which is the hard one.

### A1. Re-attach must resync (gateway ↔ service)

Add a `Resync` phase after `GatewayHello`: the gateway streams one `Opened` per
live connection in its `Registry` (it already holds `ctx.registry`,
`attach.rs:184-211`), then a `ResyncDone` marker. Services already handle
`Opened` (`crates/proto/fancy/proto/control.proto:38`); the marker is a new
`ClientEvent` variant so old services ignore it (additive, tolerates skew).
Until `ResyncDone` a service that keeps per-connection state treats itself as
warming. Cost: O(connections) frames per re-attach, once, on a lane that already
carries every control message.

Also: the event in `relay.send()` when the stream breaks is lost silently
(`attach.rs:222-224`). Push it back to the front of `events` or count it —
today it is neither.

### A2. `session-view` must rebuild, not wait

Its writers are the authorities (`session-lifecycle` for sessions, `metadata`
for channel state). Two options; pick the first:

* **Push on reconnect.** Each writer follows `session-view` health; when it sees
  a new incarnation (a `started_at`/`incarnation` field on `GatewayHello`-style
  hello, or simply a failed-then-succeeded announce), it re-announces everything
  it owns. `session-view` gates `Readiness` on "heard from lifecycle and
  metadata since start" with a bounded grace, so subscribers don't `replace`
  their rosters with an empty snapshot in the window.
* Persist the view. Wrong: it is a *view*, and a stale persisted view is the
  stale-grant bug from `ARCHITECTURE.md` §4.

Same rule generalised: **any service holding a cache of another's state must
be able to rebuild it from the authority on demand.** Voice and roster already
do (`Roster::follow`, `voice/src/service.rs:260-298`); session-view is the one
that doesn't.

### A3. Readiness the orchestrator can read

Serve `grpc.health.v1.Health` alongside `starling.health.v1` (tonic-health,
same gate) and an HTTP `/readyz` on the metrics port for compose healthchecks
and systemd `ExecStartPost`. Then a rolling update waits for **warm**, which is
the whole point of `ARCHITECTURE.md` §8 "restart semantics". Without this every
step below is racing cold caches.

### A4. Skew and rollback contract, made checkable

Already stated, not enforced: additive-only migrations (`storage/migrations.rs:1-9`),
additive protos. Add:

* `buf breaking` (or `prost-build` diff) in CI against the last tag for
  `crates/proto/**`.
* A `contract` field in `GatewayHello` and in the health reply: the
  proto-package version each side compiled. `health` already polls everyone
  (`crates/services/health/src/lib.rs`), so `GET /v1/health` can show
  version skew per service — the operator's view during a rollout.
* Migrations run at startup today; for a rolling replace that is fine **only**
  under additive-only. Add a `starling migrate --check` that fails on a
  destructive migration file, and run it in CI, not at boot.

### A5. Deployment mechanics per mode

| Mode | Component patch today | After A1-A3 |
|---|---|---|
| Helm | `checksum/config` rolls all; image bump rolls that StatefulSet, ordinal-descending, waits for TCP-ready | add `updateStrategy` per tier; probes on `grpc.health.v1`; PDB `maxUnavailable: 0` for essential once `replicas > 1` |
| compose | `up -d <service>` recreates the container; gateway buffers 1024 events, service comes back blind | same command, now transparent; `healthcheck` on `/readyz`; `depends_on: condition: service_healthy` |
| systemd | one process, `--all-in-one`; nothing to patch alone | ship per-service units (`starling@.service` template with `%i` as the service name) for the split deployment; all-in-one stays restart-only, see A7 |

`starling check-config` should run as an initContainer / `ExecStartPre` in all
three, so a bad file fails the *new* pod and the old one keeps serving. Today it
is a manual step (`README.md:235-248`).

### A6. The gateway itself — where HA actually lives

Everything above lets any *service* be replaced under a live gateway. Replacing
the gateway is different: it holds the sockets, and Mumble has no server-side
"go away, come back" for legacy clients. Order:

1. **Staggered drain.** On SIGTERM: stop accepting, mark ready=false, then close
   connections in batches with jitter over most of `terminationGracePeriodSeconds`,
   Fancy clients first with a `SessionEnvelope` reconnect hint (new variant:
   `Reconnect { retry_after_ms, host, port }` — the mirror of `VoiceEndpoint`),
   legacy last. The primitives exist (`connection.rs:327-334`); the loop doesn't.
2. **Two gateways behind one address.** Helm: `gateway.replicas: 2` +
   `existingSecret` (already required, `validate.yaml:12-14`). Bare metal:
   `SO_REUSEPORT` on `listen_tcp` (`socket2` is already a dep of `sfu`) so
   new-binary and old-binary gateways share `:64738`; old drains, new accepts.
   Voice: it must be reachable at the same address by legacy clients, so it is
   the gateway's sidecar (`values.yaml:153`) and **rolls with it** — voice
   restarts drop audio for the drain window; that is the legacy floor.
3. **Externalise RESUME**, so a Fancy client draining from gateway A resumes on
   gateway B. Fix the token first — key rings by `session_token`, not by
   `handle.token` (`resume.rs`, `attach.rs:292-346`) — because today it never
   hits even on the same pod. Store: the design's open question
   ("frames or events?", `ARCHITECTURE.md` §5). Start with frames in a small
   external KV with TTL (a Redis-compatible store, or Postgres `UNLOGGED`
   table); measure; only then consider events.

After 1–3, a gateway image bump is a rolling replace where Fancy clients resume
with no visible gap and legacy clients see one reconnect, spread over the drain
window. That is as good as the legacy protocol allows.

### A7. All-in-one: per-unit lifecycle, not hot code

Give `compose::all_in_one` a `Unit { name, shutdown: Shutdown, handle }` per
service with its **own** `Shutdown`, and a `restart(name)` that drains that
unit, re-`register`s on the `Broker` (already replaces, `inproc.rs:55-60`),
and re-enters `run::<S>` — this is what A1/A2 need for an in-process test, and
it makes `starling --all-in-one` able to restart a wedged unit from
`operator-api`. It is **not** a way to load new code: a patched all-in-one is a
new binary, and the path for that is A6 step 2 on one host (new process on
`SO_REUSEPORT`, old process drains). Say so in the docs rather than let anyone
expect a dylib.

---

## 2. Part B — live configuration

Goal: edit the file (or push through the API), and what *can* change without a
restart does, immediately and consistently; what cannot says so, by name.

### B1. Classify every key

The codebase has no data field for "restart required" — it is a sentence in
`CONFIGURATION.md:105`. Add one:

```rust
pub enum Reload { Live, NextConnection, Restart }
pub fn classify(path: &str) -> Reload   // "gateway.tls.cert" → Live, ...
```

with a test that walks `examples/reference.toml` and fails on any unclassified
key, and a `starling check-config --diff <old> <new>` that prints the class of
every changed key. That table is also what `CONFIGURATION.md` should render
from, so docs and code stop drifting (the routing table already went through
that, `CONFIGURATION.md:64-70`).

First-cut classification:

| `Live` (apply in place) | `NextConnection` (new connections only) | `Restart` |
|---|---|---|
| `gateway.tls.{cert,key}` | `gateway.control_queue`, `control_bytes`, `audio_queue` | `gateway.listen_tcp`, `services.*.{bind,endpoint,udp_listen,listen}` |
| `gateway.limits.*` (buckets re-tune like `message_limit` does) | `gateway.default_deadline` | `runtime.{all_in_one,data_dir}` |
| `gateway.breaker_*`, `gateway.resume.{ttl,ring}` | `runtime.max_tree_message` (per new attach) | `services.*.storage.url` |
| `services.*.{tier,limits,types}` — the routing table | `services.files.{url_ttl,max_upload,public_url}` | `services.*.enabled` (v1; `Live` in v2 via A7 units) |
| `services.*.enabled` for the **gateway's** view (attach/detach) | | `[instances]` `id`, `port` |
| `[instances.settings]` → republished by `server-config` | | `services.operator-api.{listen,auth.mode,webtransport}` |
| `telemetry.log_format`? no — level yes (`RUST_LOG` via `tracing_subscriber::reload`), format no | | `telemetry.{metrics,otlp_endpoint}` |
| `services.operator-api.auth.{oidc.map,mtls.map,token.tokens}` | | |

Endpoints are `Restart` on purpose in v1: repointing a service under a live
gateway is A5's problem (dual-run old and new), and a half-reloaded fleet where
`text` and the gateway disagree about where `metadata` is, is exactly what the
Helm checksum annotation exists to prevent (`workloads.yaml:47-49`).

### B2. The reload trigger and pipeline

Three triggers, one path:

* **SIGHUP** (unix) — `install_signal_handler` grows a `SignalKind::hangup` arm.
* **`POST /v1/reload`** on `operator-api`, scope `server-config:write`, which
  fans a `Reload` gRPC to every service (`health` already knows the roster);
  returns per-service `{applied: [..], deferred_until_restart: [..], rejected: ..}`.
* **File watch**, opt-in (`[runtime] watch_config = true`), debounced. Works
  under Kubernetes because ConfigMap mounts swap a symlink atomically; the
  `checksum/config` annotation becomes `values.rollOnConfigChange`, default
  **false** once B is in.

Pipeline in `starling_runtime`, shared by every service:

1. `Config::load` the same way as boot (includes, env, `deny_unknown_fields`,
   `validate`). Any error → log, keep the old config, **nothing applied**.
2. `diff(old, new)` → list of `(path, Reload)`. If any changed key is `Restart`,
   record it (health `Warning`: "config change pending restart: services.text.endpoint"),
   surface it in `GET /v1/health`, and continue with the rest.
3. Swap `Arc<Config>` in one step (`ArcSwap<Config>` on `ServiceContext`;
   readers on hot paths keep their own copies and subscribe, they do not
   `load()` per packet).
4. Notify appliers. One `tokio::sync::watch::Sender<Arc<Config>>` per process;
   each component that owns `Live` state (`Gateway`, `Limiter` templates,
   TLS resolver, `Router`, `Settings`, `Logger`) holds a `Receiver` and applies
   its slice. Appliers are infallible after step 1 — validation is where
   failure lives, so a reload can never leave a process half-applied.

### B3. The three appliers that need real work

* **TLS.** Replace `with_single_cert` with a `ResolvesServerCert` that reads an
  `ArcSwap<CertifiedKey>`; the applier reloads files via
  `starling_crypto::identity::load_or_generate` (which already refuses a
  half-pair). Note for operators: a **new key** changes the fingerprint clients
  pinned; rotation with the same key is transparent, rotation with a new key is
  a client-visible event whatever the server does. cert-manager renewals keep
  the key by default; say so in `CONFIGURATION.md`.
* **Router.** `Router` behind `ArcSwap`; on change: new services → `Attachments::spawn`;
  removed → detach and drop the link; changed `tier`/`limits` → replace the
  `Route`. Adding a service becomes the three TOML lines the docs promise
  ("no gateway release", `CONFIGURATION.md:348`) *without a gateway restart*.
* **`[instances.settings]` re-overlay.** `server-config` recomputes
  `starting_point` (`server-config/src/lib.rs:347-382`) for the fields the
  operator does **not** own and publishes if anything moved. Then the file is
  live for the operational layer too, and the three-layer rule in
  `CONFIGURATION.md:120-132` holds at runtime, not just at boot.

Also fold the existing rough edges in while there: `operator-api` takes
`instance` on `/v1/config`; every bucket follows `Settings`, not only `control`;
retire the `version == 0` guard by having `server-config` report per-field
ownership in the snapshot so the gateway can ask "did an operator set this?"
instead of guessing from a counter.

### B4. Consistency across a fleet

A reload is per process. Two things keep that honest:

* every process exposes `config_revision` (hash of the merged document) in its
  health reply; `GET /v1/health` shows the spread. A fleet mid-reload is
  visible, not inferred.
* `Live` is only assigned to keys where processes disagreeing for a few
  seconds is harmless. That is why endpoints and tiers-as-seen-by-services stay
  `Restart` in v1, and why the gateway's routing view is the one exception
  (only the gateway reads it).

### B5. `services.*.options.*` — one pattern, fourteen answers

**Open.** This is the one row in the classification table that is a *bag* rather
than a key, and it is classified `Restart` wholesale, which is wrong in both
directions: it withholds a reload from settings that would follow the file
trivially, and it would grant one to a bound socket if anybody flipped the row
without reading it.

`options` is `BTreeMap<String, String>` on every service block, read through
`ServiceConfig::option::<T>` (`crates/runtime/src/config/service.rs`). The
gateway never looks inside it; each service names its own keys, so there is no
central list and nothing that fails when a new one appears. That is what makes
one pattern tempting and one pattern wrong.

The fourteen keys in use today, and what each would actually take:

| Key | Read where | Feasible? |
|---|---|---|
| `directory.trust_store` | copied at build into `DirectoryService.trust_store`; the **file** is re-read per announcement (`directory/src/lib.rs`, `PublicList::new` in the hourly loop) | **Trivial.** Swap the `PathBuf`. The expensive half already follows a rotated bundle without a restart; only the *path* is frozen |
| `link-preview.preview_timeout_ms` | `Limits` → `Fetcher`, read per fetch | **Trivial** |
| `link-preview.preview_max_bytes` | as above | **Trivial** |
| `link-preview.preview_redirects` | as above | **Trivial** |
| `link-preview.preview_concurrency` | `Semaphore::new(limits.concurrency)` in `Fetcher::new` | **Awkward.** Raising it is `add_permits`. Lowering it means acquiring permits and forgetting them, which cannot complete until in-flight fetches return — so it is `NextConnection`-shaped at best, and honestly reported as such rather than called `Live` |
| `push.notify_text_message` | `Settings::notifies`, per notification | **Trivial** |
| `push.notify_reaction` | as above | **Trivial** |
| `push.notify_user_join` | as above | **Trivial** |
| `push.fcm_topic_prefix` | `Settings.topic_prefix`, per notification | **Trivial** |
| `push.fcm_credentials`, `push.fcm_project` | loaded once; construct the `Fcm` sender | **Moderate.** Rebuild the sender off the request path and swap it, exactly as `operator-api` rebuilds its auth strategy (§B3). Reading a credentials file can fail, so the previous sender stays in force on error |
| `screenshare.media_port` | `SfuConfig` → `SfuHandle::start`; the UDP socket is bound once | **No.** A bound socket, like every other listen address |
| `session-lifecycle.timeout_ms` | read once into a local at the top of `run()`, then used by the sweep loop | **Trivial.** Move the read inside the loop; the sweep already ticks every few seconds |
| `session-lifecycle.max_users` | `Connections::new` → `SessionAllocator::new`, which pre-fills a `VecDeque` with ids `1..max_users*2` | **Hard, and not worth it.** Growing means pushing ids onto the free queue; shrinking means removing ids that may be allocated to live sessions. Note this is *not* the operational `max_users` an operator changes in the admin UI — that one lives in `server-config` and is already live. This one sizes a pool |

So: nine trivial, two that need a client rebuilt, one awkward, two that must
stay `Restart` — and today all fourteen are `Restart` because they share one
wildcard.

**The fix is the pattern matcher, which already supports it.** A service name is
a literal segment, so the table can say:

```rust
("services.directory.options.trust_store", Reload::Live),
("services.link-preview.options.preview_concurrency", Reload::NextConnection),
("services.screenshare.options.media_port", Reload::Restart),
...
("services.*.options.*", Reload::Restart),   // the catch-all stays, last
```

First match wins, so specific rows shadow the catch-all and an option nobody has
classified keeps the answer that cannot mislead.

**Why it was not done with the rest.** Each `Live` row needs its service to grow
a follower, and that is five services rather than one change; and the
completeness test that protects the rest of the table cannot protect this part.
`option::<T>` reads a map by string, so a new option is invisible to a test that
walks the `Config` schema — nothing fails when somebody adds
`push.fcm_retry_ms` and never classifies it. Closing that needs the services to
*declare* their options (a `const OPTIONS: &[&str]` per service, or a typed
block instead of the map), which is the change that makes this row safe rather
than merely more granular. Worth doing before the row is split, not after.

---

## 3. Order

Each step is independently shippable and testable; none needs the ones after it.

| # | Step | Unlocks |
|---|---|---|
| 1 | A3 readiness (`grpc.health.v1`, `/readyz`) + `check-config` as pre-start | rolling updates that wait for warm |
| 2 | A1 `Resync` on re-attach; A2 session-view rebuild | replace any **service** under load |
| 3 | **done** — B1 classification + B2 pipeline with SIGHUP; appliers for `[logging]`, the gateway's queue bounds / buckets / breakers, `[instances.settings]` | most day-to-day config edits |
| 4 | **done** — B3 TLS resolver + Router swap | cert rotation, add-a-service without gateway restart |
| 4b | B5 services declare their options, then split `services.*.options.*` per service | `directory.trust_store`, `push`'s notification switches, `link-preview`'s fetch limits, `session-lifecycle.timeout_ms` |
| 5 | A6.1 staggered drain + `Reconnect` hint; A6.2 `SO_REUSEPORT` / replicas 2 | replace the **gateway** with one legacy reconnect |
| 6 | A6.3 external RESUME (token fix first) | Fancy clients see no gap at all |
| 7 | A4 CI gates (proto breaking, migrate --check), `contract` skew in health | safe mixed-version fleets |
| 8 | A7 per-unit lifecycle in all-in-one; `POST /v1/reload` fan-out; opt-in file watch | operator ergonomics |

Steps 3 and 4 are done. 4b is small but spread across five services, and wants
the options declared before it is split (§B5). 5–6 are the real work and the
only part that touches the client (`Reconnect` and a resume that actually
resumes — the client already sends `ResumeRequest`).

## 4. How it gets verified

In the e2e repo, alongside the existing suites:

* **service-restart**: two clients in a channel, `docker compose restart text`
  (later: `metadata`, `session-view`, `permissions`), assert both stay
  connected, a message sent during the restart arrives after, and the roster
  is intact. Today this fails on A1/A2 in ways that never mention a restart.
* **config-reload**: edit `message_limit` in the mounted TOML, SIGHUP, assert
  the new limit applies to the *open* connection; edit `listen_tcp`, assert the
  health warning names it and nothing else changed.
* **gateway-replace**: `replicas: 2` in compose (`SO_REUSEPORT`), stop the
  old one, assert a Fancy client resumes without a `ServerSync` re-flood and a
  legacy client reconnects exactly once within the drain window.

Unit level: a table test that every key in `reference.toml` has a `Reload`
class; an all-in-one test that restarts one unit (A7) and asserts the others'
attach loops recover — the in-process version of the first e2e above.
