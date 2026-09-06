# Reliability: what threatens years of uptime, and the plan to close it

Starling must never crash and must run for years unattended. Release builds use
`panic = "abort"`, so **any** panic on **any** task takes the whole process
down — and in `--all-in-one` (the systemd and `.deb` default) that is a total
outage. The decision recorded here is to *keep* abort and prove the reachable
panic set is empty, rather than catching unwinds.

This tree is disciplined. Production code has **zero `.unwrap()`, one
`.expect()`, and five explicit panics** — all five provably infallible crypto
arms, each with a comment justifying it. Queues are bounded, the drain path has
four independent bounded waits plus a regression test for the old SIGTERM
deadlock, and the frame decoder bounds before it allocates.

So the risk is not where a "never crash" audit usually finds it. The exposure is
in four places:

1. **Third-party parsers on unauthenticated input.** The SFU feeds raw UDP from
   anyone straight into `str0m` (STUN/DTLS/SRTP/RTP); every TLS accept parses an
   arbitrary DER chain; link-preview runs the `image` crate on bytes from a
   user-chosen URL. `unsafe_code = "deny"` on our own code buys nothing here.
2. **Detection.** Nothing distinguishes "serving" from "serving correctly".
   Health gates only ever move forward and the probes are TCP-only, so a process
   whose background tasks have all died still passes liveness.
3. **Admission.** No TLS handshake timeout, no per-IP cap, no accept cap.
4. **Longevity.** Nothing has ever run this server for more than one test
   scenario, and several maps grow without bound on a clear trigger.

---

## Part 1 — the defect register

Every item was read in the source and confirmed. Ordered by threat to uptime.
Update this table as each defect closes.

**Status.** Stages 0 to 5 and 8 are done. Stage 6 has its in-process half, the
one that owns the state assertions; the out-of-process driver (`scripts/soak.sh`
against the real `--all-in-one` binary) is **not written**, so the resident-memory
figures a soak reports are still a test binary's and not a server's, and the
`directory` exclusion below lives in the test rather than in the scenario. Stage
7 has its in-process restart half and Stage 9 its per-PR jobs. Defects 2, 3, 4,
7, 8, 10, 18 and 22 are
closed with regression tests, 6 is closed for visibility, and 16 and 19 are
partly closed. Restarting one service at a time then found two the audit had
not looked for, 23 and 24, both below.

Defect 7 turned out to have a second half the register missed --
`serve::run` discarded a panicking background task's `JoinError` before
`Deployment::stop` ever saw it, so fixing the harness alone would not have made
a service panic fail a test.

### P0 — will take the server down, or degrade it badly at scale

| # | Defect | Evidence |
|---|---|---|
| 1 | **`str0m` parses unauthenticated UDP inside an abort-on-panic process.** `route_udp_packet(source, &udp_buf[..len])` hands raw datagrams from any source to a third-party WebRTC stack. A panic anywhere in its STUN/DTLS/SRTP parsing aborts the whole server. Largest unowned attack surface in the tree. Fuzzing (Stage 1) finds these; it cannot prove their absence in code we do not own, and with `panic = "abort"` there is no `catch_unwind`. The SFU runs inside the `screenshare` unit, so per-service deployment already contains the blast radius to one pod; `--all-in-one` does not. Stage 2b records the decision. | `crates/sfu/src/session/runtime.rs:95`; `str0m = "0.21"` in `crates/sfu/Cargo.toml:11`; host `crates/services/screenshare/Cargo.toml:15` |
| 2 | **CLOSED.** *(handshake deadline, plus a server-wide and per-address ceiling on handshakes in flight; `crates/gateway/src/admission.rs`)* **No TLS handshake timeout.** `acceptor.accept(stream).await` is not wrapped in any `timeout`. A peer that completes TCP then trickles one byte holds a task, an fd and a rustls buffer forever. The 30 s idle reaper only sees connections registered *after* the handshake returns. No per-IP cap, no accept cap; `max_users` is checked only after TLS **and** auth. | `crates/gateway/src/listener.rs:526`; reaper `crates/services/session-lifecycle/src/lib.rs:1795`; `ServerFull` `handshake.rs:386` |
| 3 | **CLOSED.** *(the sweep is rate-limited to once per `ttl / 4`, and expiry is checked on the ring rather than left to the schedule)* **Resume ring is O(N^2) per broadcast.** `stamp()` takes a process-global `Mutex` and runs a full `retain` sweep over every session — called once *per recipient* inside the fan-out loop, for legacy clients too. One broadcast to 1 000 clients is ~10^6 `Instant` subtractions under one lock. | `crates/gateway/src/resume.rs:147`, `evict_expired` `:210`, call site `crates/gateway/src/attach.rs:632` |
| 4 | **CLOSED.** *(`ResumeStore::from_config`; `enabled = false` now keeps nothing and stops the gateway announcing sequencing)* **`gateway.resume.ttl` and `.enabled` are dead config.** `ResumeStore::new()` hardcodes `DEFAULT_TTL = 600s`; the config default is 120 s and is never passed (only `with_limits`, marked "for tests", takes it). `enabled = false` sets a health warning and nothing else, so an operator cannot turn off defect 3. | `resume.rs:49`, `:118`, `:132`; `listener.rs:154`, `:285`; default `crates/runtime/src/config/gateway.rs:215` |
| 5 | **Health gates are one-way, so nothing detects a wedge.** `Readiness::Warming` is written only by `gate()` at build time; nothing moves a gate backwards. A service whose background task died keeps reporting `Ready` while serving a frozen cache. The Kubernetes `livenessProbe` is `tcpSocket`, which a process with every task dead still passes. | `crates/runtime/src/health.rs:48`, `:60`; `crates/runtime/src/serve.rs:288`; `deploy/helm/starling/templates/all-in-one.yaml:103` |
| 6 | **CLOSED for visibility** *(every service handle is watched alongside the gateway and a service ending early is an error record naming it; supervision is still Stage 8)* **All-in-one awaits only the gateway.** A service task that dies at t=0 is unnoticed until shutdown, where it yields a "did not stop cleanly" warning. No restart, no alert, no exit. | `crates/starling/src/compose.rs:159` vs `:168` |
| 7 | **CLOSED.** *(drains and joins, reporting panics, service errors, stalled drains and unexpected error records; plus `serve::run`, which discarded the background task's panic upstream of it)* **`Deployment::stop()` discards panics.** It calls `handle.abort()` on every service without awaiting or inspecting the result, so all 66 whole-server tests silently swallow a service panic — it surfaces as an unrelated client timeout. | `crates/starling/src/e2e.rs:437` |

### P1 — unbounded growth, or an unowned parser

| # | Defect | Evidence |
|---|---|---|
| 8 | **CLOSED.** *(`ClientService::closed`, with the owning connection recorded per watch)* **`social` never cleans up on disconnect.** The one client-facing service that does not implement `ClientService::closed` (pchat, screenshare, voice and session-lifecycle all do). Its `watches` map is keyed by a **client-supplied** 64-byte string and only shrinks on an explicit `End`, so a client can mint unlimited entries that outlive it. | `crates/services/social/src/lib.rs:163`, `:365`, `:412`; the four impls at `pchat:595`, `screenshare:846`, `voice/service.rs:719`, `session-lifecycle:218` |
| 9 | **SFU viewers are never individually removed.** `outbound: BTreeMap<u32, Rtc>` is inserted on every viewer offer; the only removal is the whole session. Departed viewers' DTLS/SRTP state stays resident, is fed `Input::Timeout` each tick, and is linearly scanned per inbound packet. Its two `unbounded_channel`s are the only unbounded ones on a client-driven path, and the runtime `std::thread` is never joined. | `crates/sfu/src/session/broadcast.rs:31`, `:78`, `:129`, `:159`; sole removal `runtime.rs:226`; `mod.rs:143-144` |
| 10 | **CLOSED.** *(expiry filtered in SQL, and a five-minute sweep deletes)* **Expired bans are never deleted, and the whole table is scanned on every accept.** Expiry is a read-time filter; the only `DELETE FROM ban` is an explicit unban. `check_ban` `SELECT`s the entire history into a `Vec` per connection attempt — free amplification for whoever is being banned. | `crates/services/moderation/src/lib.rs:122`, `:144`, `:217`; delete `:321` |
| 11 | **Every TLS accept parses an arbitrary DER chain.** `AcceptAnyClientCertificate` is wired by design, so `PeerCertificate::from_chain` runs on unauthenticated input on every connection. | `crates/gateway/src/listener.rs:485`; `crates/crypto/src/peer_cert.rs:83`, `:124` |
| 12 | **link-preview decodes remote images with the `image` crate** — jpeg/png/gif/webp decoders on bytes from a URL a *user* chose. Third-party, remotely triggerable. | `crates/services/link-preview/src/thumbnail.rs`; `image.workspace = true` |
| 13 | **Outbound directory registration has no timeout at any hop and no response cap.** TCP connect, TLS connect, request and `collect()` of a third-party body are all unbounded. `link-preview` and `push/fcm` both get this right; this is the one path that does not. | `crates/services/directory/src/registrar.rs:165-193` |
| 14 | **OPEN.** **Blocking file I/O on the reactor, append-only forever.** `AuditLog::record` is a sync fn doing `std::fs` writes under a `std::sync::Mutex`, called from async handlers. No rotation, unlike the runtime log sink which rotates. | `crates/operator-api/src/audit.rs:52`; callers `routes.rs:186`, `webtransport.rs:175` |
| 15 | **WASM plugins have no resource ceiling.** No `consume_fuel`, no `epoch_interruption`, no `StoreLimits`, no call timeout, no memory cap. Hooks are synchronous by contract, so a guest that loops forever wedges the calling thread permanently. | `crates/plugin-host/host/src/wasm.rs:81`, store `:435` |

### P2 — latent, or a hazard rather than a live bug

| # | Defect | Evidence |
|---|---|---|
| 16 | **CLOSED for WAL and `busy_timeout`** *(both in the `after_connect` hook, on every pooled connection; reclaiming the freelist is still open)* **SQLite runs with no WAL, no `busy_timeout`, no `VACUUM`.** The only pragma set anywhere is `foreign_keys = ON`. Rollback-journal with `busy_timeout = 0` means a concurrent write fails *immediately* with `SQLITE_BUSY` across a pool of 8. The audit and pchat sweeps delete rows into a freelist that is never reclaimed. | `crates/runtime/src/storage/backend.rs:83-95`, `dialect/sqlite.rs:55`; zero hits for `journal_mode`/`busy_timeout`/`VACUUM` in the tree |
| 17 | **Postgres and MySQL ship completely untested.** Three dialect implementations exist; CI exercises one. This is a "the server does not start for an operator" bug waiting to happen. | `crates/runtime/src/storage/dialect/{sqlite,postgres,mysql}.rs`; `.github/workflows/ci.yml` |
| 18 | **CLOSED.** *(ids are handed out on demand, and `release` refuses an id nobody holds)* **Session-id pool is eagerly allocated from unvalidated config.** `(1..max_users.saturating_mul(2)).collect()` at boot; a fat-fingered `max_users` is a multi-GB allocation. `release()` also pushes with no membership check, so a double-release would hand out a duplicate id. | `crates/services/session-lifecycle/src/session/pool.rs:26`, `:37` |
| 19 | **PARTLY CLOSED** *(`DESIGN.md` and `.clippy.toml` now describe the lints that exist; landing the missing ones is Stage 3)* **The lint set does not match the documented one.** `docs/DESIGN.md:108` claims "`unwrap`/`expect`/indexing that can fail are denied by lint". `expect_used` is `warn` and **indexing is not linted at all**. Also absent: `clippy::panic`, `clippy::unreachable`, `integer_division`, `modulo_arithmetic`, `arithmetic_side_effects`, `cast_possible_truncation`. | `Cargo.toml:294`, `:300`, `:356-361`; `.clippy.toml` |
| 20 | **Six `plugin-host` crates do not inherit the workspace lints**, each hand-copying a subset; `api-wasm` has the thinnest table. `host` sets `unsafe_code = "allow"` — it is the crate that `dlopen`s third-party `.so`. A lint added to the workspace table silently misses all six. | `crates/plugin-host/{api,api-derive,host,api-wasm}/Cargo.toml` plus the two plugin crates |
| 21 | **No process limits in packaging.** `packaging/starling.service` sets no `LimitNOFILE`, `MemoryMax` or watchdog. Helm ships `resources: {}`. The compose healthcheck **latches on first success**, so it stops tracking liveness after start. | `packaging/starling.service`; `deploy/helm/starling/values.yaml:189`; `docker-compose.yml` |
| 22 | **CLOSED.** *(backoff on `EMFILE`/`ENFILE`, and the read buffer is returned to 8 KiB once drained)* **Accept loop hot-spins on `EMFILE`** — logged and `continue`d with no backoff. **Per-connection read buffer never shrinks**: one 8 MiB frame keeps 8 MiB resident for that connection's life. | `crates/gateway/src/listener.rs:322-330`, `:586`, `:615` |

### Found by Stage 7, not by the original audit

A restart is a fault the audit never injected, so nothing here was visible until
`crates/starling/tests/chaos.rs` stopped one service at a time. Both have a
named `#[ignore]`d reproduction in that file, and both pass the day the fix
lands.

| # | Defect | Evidence |
|---|---|---|
| 23 | **A drained service is still held by its callers' connections, so it can never be restarted.** `serve_routes` waits `DRAIN_GRACE` for its connections and returns anyway, but the per-connection tasks belong to hyper, spawned by `serve_with_incoming_shutdown` and detached; each holds the `Routes`, and so an `Arc` to the service. They end only when the caller closes the stream, and the caller is not the thing being restarted. `voice` is where it is fatal: its UDP port is still bound, the replacement fails to build with `Address already in use`, and `serve::run` does not retry a failed construction, so it never comes back. The quieter half is that every restart leaks the instance before it, database pool included, until the process exits. | `crates/runtime/src/listen.rs:84`, `:96`; `crates/services/voice/src/service.rs:894`; `serve::run` `crates/runtime/src/serve.rs:283`; repro `chaos.rs::voice_can_be_restarted` |
| 24 | **A restarted `session-view` forgets who is connected.** It holds the roster in memory and starts empty. It is fed by `announce(Up/Changed/Down)` as sessions change, and readers take a snapshot when they `subscribe`, so a new instance is refilled by whoever next announces or re-subscribes — and under defect 23 nobody does: the old instance's connections never die, so no subscriber's stream ends and none of them re-subscribe. Two clients who never disconnected can no longer hear each other twelve seconds later. **How much of this is 23 is unmeasured**; re-run the reproduction once 23 is fixed before writing a separate fix for it. What would remain is that `session-lifecycle` has no "a subscriber I have not seen before appeared" path, only per-change announcements. | `crates/services/session-view/src/lib.rs:126` (snapshot on subscribe), `:187` (announce); voice's re-subscribe `crates/services/voice/src/service.rs:59`; repro `chaos.rs::a_restarted_session_view_still_routes_a_message` |


### What the audit found to be clean

Recorded so it does not get re-litigated. Allocation from wire length fields is
bounded before reserving (`crates/proto/classic/src/codec.rs:69`, 8 MiB cap).
The 4 MiB blob-flood regression is fixed *structurally* by a byte-bounded
control lane that disconnects rather than drops (`connection.rs:246`). zstd goes
through a `LimitedWriter`, so there is no bomb (`compress.rs:97`). There are no
`duration_since(..).unwrap()` clock hazards, and `TokenBucket::refill` uses
`saturating_sub`, so an NTP step backwards stalls rather than underflows. The
OCB2 nonce wrap is documented and caught by a 256-entry replay table. The voice
router clears all six indexes on detach. Ticket stores, audit and pchat all
sweep.

---

## Part 2 — the plan

Ordering principle: **each stage must be able to turn up a real defect before
the next one starts.** Cheap detectors first, infrastructure last. Every stage
boundary is a place the work can stop and still be worth having.

### Stage 0 — make the 2 046 existing tests report crashes (~1 day)

Highest value per hour in the whole plan, and every later stage's signal flows
through it.

* **Fix `Deployment::stop()`** (`crates/starling/src/e2e.rs:437`, defect 7).
  Make it async: `shutdown.drain()`, then `timeout(grace, join_all(handles))`.
  Fail on any `JoinError::is_panic()` with the payload; fail naming any service
  that returned `Ok(Err(ServiceError))`; assert the "did not drain in time" list
  is empty. Also scan `records()` for `Severity::Error` outside a per-test
  allow-list. Add a `Drop` impl flagging a `Deployment` dropped without `stop()`,
  guarded by `std::thread::panicking()` so it never masks the real failure.
* **Make a dead service observable in `compose.rs`** (defect 6): poll the
  service handles in a `JoinSet` alongside the gateway and write a
  `Severity::Error` record naming the service the moment one finishes. Not a
  `select!`: that returns on the *first* completion, which would turn a finished
  service into a process exit, and whether to exit is Stage 8's decision. Stage 0
  only needs it visible.
* **Correct `docs/DESIGN.md:108` and the `.clippy.toml` header comment**
  (defect 19); both claim `panic!()` is denied by a lint that does not exist.

**Done when:** inserting `panic!()` into one service's `run()` fails a named e2e
test with that panic's message.

### Stage 1 — fuzz the surfaces an unauthenticated peer reaches (~5 days)

Where crashes actually get found. Priority is strictly "how many hops from an
unauthenticated packet".

**Restructure first.** One fuzz crate exists (`crates/proto/classic/fuzz`,
nested `[workspace]`, one target, **no committed corpus**). Fifteen such crates
would be unmaintainable. Create a single root `fuzz/` with its own workspace and
one `[[bin]]` per target; migrate `decode` in and delete the old directory.
Corpora live in `fuzz/corpus/<target>/`, committed, `cargo fuzz cmin`-minimised,
capped at ~200 files each, with `fuzz/dictionaries/*.dict` for protobuf tags and
Mumble type IDs.

**Tier 1, pre-authentication:**

| Target | Entry point |
|---|---|
| `sfu_input` | `str0m` `Rtc::handle_input` via `crates/sfu/src/session/broadcast.rs` (defect 1) |
| `voice_packet` | `AudioCodec::decode`, both impls — `crates/services/voice/src/packet.rs:239`, `:290`, `:393` |
| `voice_varint` | `crates/services/voice/src/varint.rs` — hand-rolled; `take(len)` with an attacker length |
| `peer_cert` | `PeerCertificate::from_chain` — `crates/crypto/src/peer_cert.rs:83` (defect 11) |
| `decode` | existing; give it a real corpus |

**Tier 2, post-handshake and pre-privilege:** `fancy_envelope`
(`crates/proto/fancy`); `unbatch` (`crates/gateway/src/compress.rs:97`, asserting
an output-size bound, not just no-panic); `ocb2` (`crates/crypto/src/ocb2/`,
plus a forgery property); `thumbnail`
(`crates/services/link-preview/src/thumbnail.rs`, defect 12).

**Tier 3, operator-controlled but still process-fatal:** `config_toml`;
`murmur_ini` (`crates/migrate/src/ini.rs`, 688 lines of hand parsing);
`murmur_db`; `acl_eval`; `operator_json`; `livery_json` / `greeting_binary`.

Two techniques worth more than "no panic":

* **A counting global allocator in the fuzz binaries** that aborts past N MB per
  iteration. Roughly 30 lines, and it turns a whole class of "not a panic but
  fatal" bugs into fuzzable ones — `config_toml` then catches defect 18
  mechanically, and `unbatch` catches decompression bombs.
* **Structured fuzzing with `arbitrary`**, only where the input is a type:
  `acl_eval` (a small tree/ACL/group model asserting determinism, monotonicity
  and agreement with a naive reference implementation written in the target —
  the differential test that finds real authorisation bugs) and
  `fancy_envelope`. Everything else stays `&[u8]`. Feature-gate any derive rather
  than adding `arbitrary` to 24 crates' graphs, which would trip
  `unused_crate_dependencies` and `cargo-deny bans`.

**Corpus seeding reuses what exists.** `scripts/canon-fixtures.json` already
holds complete framed messages with hex bodies, and
`crates/proto/fancy/tests/canon_fixtures.rs` already parses it — reuse that
reader to seed `decode` and `fancy_envelope`. `TestPeer` in
`crates/services/voice/src/testing.rs` produces genuine encrypted packets in both
`UdpFormat`s to seed `voice_packet`. For `sfu_input` and `peer_cert`, add an
env-gated tee in the SFU socket read path and in `serve_client`, run the existing
e2e suite once, `cmin`, commit.

**Per-PR versus nightly.** A committed corpus makes a timed run mostly a
*replay*, which is the right per-PR semantic. Gate on `-runs=0` (pure replay,
about 2 s, all targets) so a reintroduced crash fails in seconds, then 20 s of
search on the five Tier-1 targets. Nightly runs all targets 6 min each from the
committed corpus *plus* an accumulating `actions/cache` corpus. Weekly adds
`-fork=4` and MSan on the three pure-parsing targets; MSan needs `-Zbuild-std`,
which is why it is weekly.

**Done when:** every Tier-1 and Tier-2 target has at least 50 committed corpus
entries, `-runs=0` passes for all of them, and the nightly has been clean for a
week.

### Stage 2 — regression tests for the register (~2 days)

Written in the cheapest place that can see each defect, with deterministic
assertions rather than timings.

* **Defect 3** — instrument `evict_expired` with a counter of entries visited;
  populate 1 000 sessions, do 1 000 stamps, assert visits < 4x stamps. Catches
  the sweep without a wall-clock flake.
* **Defect 4** — a store built from a config with `ttl = 5s` has `ttl == 5s`, and
  `enabled = false` neither allocates a ring nor stamps.
* **Defect 2** — send one byte, never finish the handshake, assert closure within
  the timeout; then open `accept_max + 1` such connections and assert a
  legitimate client still gets through.
* **Defect 8** — register 100 watches, drop the clients, assert
  `watches.len() == 0`.
* **Defect 9** — add and remove 100 viewers, assert `outbound.is_empty()`.
* **Defect 16** — after `connect`, `PRAGMA journal_mode` is `wal` and
  `busy_timeout > 0` on **every** pooled connection. The existing `after_connect`
  hook (`backend.rs:91`) is the right place and already carries the comment
  explaining why every connection matters.
* **Defect 18** — `check-config` errors on an absurd `max_users`; the pool
  allocates lazily.
* **Defect 21** — a `helm template` and shell assertion in CI that `LimitNOFILE`,
  `MemoryMax`, `WatchdogSec` and `resources.limits` are present.

Several of these will fail on first write. That is the point.

### Stage 2b — close the register (~5 days)

Stage 2 writes tests that fail. This is where they start passing. One PR per
defect, each landing with its Stage 2 test. Not repeated here: defects 6 and 7
close in Stage 0, defects 19 and 20 in Stage 3, defect 17 in Stage 7's dialect
matrix, and defects 5 and 21 in Stage 8. Defect 11 stays open by design —
accepting any client certificate is the Mumble model, so its answer is the
`peer_cert` fuzz target, not a code change.

* **Defect 1** — a decision, not a patch. In per-service deployment a `str0m`
  panic already loses only `screenshare`. Under `--all-in-one` the only real
  defence is running `screenshare` as a child process over the existing local
  transport, which needs the Stage 8 supervisor to restart it. Record it now as
  a known limitation beside the native-plugin `abort()` case, and schedule the
  child-process split after Stage 8 rather than pretending fuzzing closes it.
* **Defect 2** — `timeout(handshake, acceptor.accept(stream))`, a `Semaphore`
  cap on connections mid-handshake, and a per-IP counter in the accept loop,
  all under `gateway.limits` with `check-config` validation.
* **Defect 3** — sweep at most once per `ttl / 4` from a `last_sweep: Instant`
  held beside the map, so a stamp is a lookup again.
* **Defect 4** — `ResumeStore::new(&config.gateway.resume)` takes the TTL;
  `enabled = false` builds a store that neither allocates a ring nor stamps.
* **Defect 8** — implement `ClientService::closed` in `social`, recording the
  owning connection on each watch so a disconnect removes everything it minted.
* **Defect 9** — an `SfuCommand::RemoveViewer` when a viewer leaves, removing
  its `Rtc` from `outbound`; bound the two channels; join the runtime thread on
  drop.
* **Defect 10** — delete expired rows in the existing sweep cadence, and make
  `check_ban` filter in SQL on the address and certificate hash instead of
  loading the table.
* **Defect 12** — cap the fetched byte count before decoding and set
  `image::Limits` (dimensions and allocation) on the reader.
* **Defect 13** — `timeout` on connect, TLS, request and body, and a body cap,
  copied from what `link-preview` already does.
* **Defect 14** — a dedicated writer task behind a bounded channel, with
  size-based rotation like the runtime log sink.
* **Defect 15** — `consume_fuel` plus `epoch_interruption` with a per-call
  deadline, and `StoreLimits` for memory.
* **Defect 16** — `journal_mode = WAL` and `busy_timeout` in the `after_connect`
  hook next to `foreign_keys`, and a periodic `wal_checkpoint(TRUNCATE)` in the
  sweeps that delete.
* **Defect 18** — a ceiling on `max_users` in `check-config`; a lazy allocator
  (a `next` counter plus a free list) with a membership check in `release`.
* **Defect 22** — sleep-then-retry on `EMFILE`; shrink the read buffer back to
  8 KiB once it is empty after a large frame.

**Done when:** every Stage 2 test passes and the external e2e suite is still
green against a release build.

### Stage 3 — static proof the remaining panic set is empty (~4 days)

Cheaper than it looks: `.clippy.toml` already sets `allow-unwrap-in-tests`,
`allow-expect-in-tests` and `allow-panic-in-tests`, so test bodies are exempt and
only production code is in scope. Land each lint as its own PR.

1. **`clippy::panic` and `clippy::unreachable` = deny.** Fallout: exactly the
   five audited crypto sites. Half a day. This is what makes the audit *stick* —
   every future explicit panic must be argued for at the site.
2. **`clippy::expect_used` warn -> deny.** Fallout: none. The only `.expect(`
   outside tests is inside a `//!` doc comment in
   `plugin-host/api/src/info_macros.rs`. One hour.
3. **`clippy::indexing_slicing` = deny**, with `allow-indexing-slicing-in-tests`
   in `.clippy.toml` so the count drops to the ~40 real production sites. Two to
   three days. Expect two or three genuine out-of-range possibilities in the
   varint, packet and ini parsers.
4. **Promote `clippy::string_slice` warn -> deny.** Byte-slicing a `str` panics
   on a char boundary, and `crates/migrate/src/ini.rs` and
   `crates/services/text/src/filter.rs` are where hostile UTF-8 meets byte
   offsets.
5. **`integer_division` and `modulo_arithmetic` = deny.** Division by a runtime
   zero is a panic no other lint here catches. Half a day.
6. **`arithmetic_side_effects` per-module, NOT tree-wide.** Workspace-wide it is
   thousands of diagnostics, and the fallout would be `saturating_add` sprayed
   over provably-fine arithmetic, which makes real overflow *harder* to see. Deny
   it with a module-level `#![deny(..., reason = "...")]` in
   `voice/src/varint.rs`, `voice/src/packet.rs`, `voice/src/bandwidth.rs`,
   `proto/classic/src/codec.rs`, `gateway/src/resume.rs` (`next_seq += 1` and
   `bytes += len` are exactly the shape), `gateway/src/compress.rs`,
   `gateway/src/limiter.rs`, `crypto/src/ocb2/`, `permissions/src/evaluate.rs`
   and `session-lifecycle/src/session/pool.rs`.
7. **Casts** — the same per-module list, plus `clippy::as_conversions = deny` in
   `crates/proto/*` and `crates/services/voice/` only, forcing `TryFrom` where
   the wire meets internal types.
8. **`missing_panics_doc = warn`** last, tree-wide. Documentation hygiene, not a
   safety lint; do not spend the deny budget on it.

**Use `#[expect]`, not `#[allow]`.** `expect` fails the build when the lint stops
firing, so an audited site refactored into safety loses its exemption instead of
accumulating a stale one. `allow_attributes_without_reason` is already `deny`, so
adopt a greppable house format —
`#[expect(clippy::indexing_slicing, reason = "AUDIT: len bounds-checked at :212")]`
— and add `scripts/check-panic-audit.sh`, mirroring the existing
`scripts/check-cpp-citations.py`, asserting every such reason starts `AUDIT:`.
That makes the audit reviewable as a diff.

**On `overflow-checks`.** It already defaults to `true` for `dev`, and `test`
inherits `dev`, so the 2 046 existing tests already run with trapping arithmetic.
The gap is release only. **Do not turn it on for `[profile.release]`** — with
`panic = "abort"` that converts every overflow, including benign ones in
dependencies, into a hard production abort, which is worse for a years-of-uptime
goal than a wrong number. Add instead:

```toml
[profile.soak]
inherits = "release"
overflow-checks = true
debug-assertions = true
debug = 1
strip = "none"
```

used by the nightly soak and the weekly chaos run. That gives release-shaped code
with trapping arithmetic under hours of load, which is where an overflow needing
2^32 frames actually appears.

**Lint inheritance (defect 20).** Add `lints.workspace = true` to all six
plugin-host manifests, overriding *only* the genuine exceptions per crate
(`unsafe_code = "allow"` in `host`, `api` and `api-wasm`, each keeping its
existing comment). Expect fallout in `api-wasm` and the two plugin crates from
lints they never had. Then extend `scripts/check-crate-layering.sh`, which
already walks the manifests, to assert every workspace member carries
`lints.workspace = true`, so this cannot regress.

**Done when:** clippy is green with the new lints, `check-panic-audit.sh` and the
layering check pass, and `docs/DESIGN.md:108` is true.

### Stage 4 — property and concurrency tests (~4 days)

Add `proptest` as a workspace dev-dependency; skip quickcheck. 256 cases per
property by default, `PROPTEST_CASES=10000` in the nightly.

* **Codec** — roundtrip; decode either consumes input or returns `Ok(None)` or
  `Err`; `encode` length is always `6 + payload.len()`. Lifting the existing
  inline fuzz assertion into a proptest gets it onto every PR.
* **Varint** — `count(write(n)) == n` for all `u64`; never reads past its slice.
* **Permission bitset** (`crates/proto/fancy/src/perm.rs`) — bitflags laws,
  `from_bits_truncate` never widens, the murmur mapping is a bijection.
* **ACL evaluation** — a random tree, ACL set and group graph: determinism; a
  deny is never overridden by a shallower inherited allow; a round-trip through
  `AclSet` agrees; an unrelated channel never changes a verdict. **This is where
  a real bug is most likely** — `group.rs:317` does
  `i64::try_from(home.len()) - 1`, exactly the shape that has off-by-ones.
* **Token bucket under clock jumps** — tokens never exceed burst; a *backwards*
  step never grants tokens; a `Duration::MAX` step never yields `inf` or `NaN`
  (the rate is `f64` and `float_cmp` is only `warn`). Needs a `Clock` injection,
  about half a day, which also unblocks Stage 7's clock-step chaos.
* **Resume ring invariants** — `bytes` equals the sum of payload lengths;
  `floor <= front.seq`; `next_seq` strictly increases; `resume(n >= floor)`
  returns a contiguous run; `len <= ring_size`;
  `bytes <= byte_budget || frames.is_empty()`.
* **Session pool** — no allocate/release sequence yields two live holders of one
  id, which is defect 18 as a property.
* **Channel tree** — breadth-first visits each node once; create, move and delete
  never orphan a node or create a cycle.

**loom on exactly three things.** It is worth it only for lock-free and atomic
state machines: `crates/runtime/src/pressure.rs` `Gauge` (mixes `fetch_add`,
`fetch_max`, `swap` and `fetch_update` on four atomics, all `Relaxed`, with a
documented single-reader high-water invariant that the whole soak harness will
trust); `crates/runtime/src/inflight.rs` (the RAII counter, same class); and
`crates/gateway/src/limits.rs` `Limits` (per-field `swap` against concurrent
`load`, where a torn combination disconnects a client). Do **not** loom the
`Mutex<BTreeMap>` registries — that just verifies `std`. Do **not** reach for
shuttle, turmoil or madsim: retrofitting a deterministic runtime across 23
units with real sockets, sqlx pools and a `std::thread` SFU runtime is a
multi-month project with a worse payoff than Stage 7.

### Stage 5 — expose the state the soak needs (~3 days; prerequisite for Stage 6)

You cannot assert on state you cannot read, and the plumbing is 80 % built.
**Do not build 23 per-unit `/metrics` listeners.**

`crates/runtime/src/serve.rs:246` constructs a fresh `Metrics` and `Pressure`
*per service*, so under all-in-one there are 23 unshared registries (the 22
services plus the gateway, per `units.rs`) and
`Metrics::render()` is genuinely dead code. But `Pressure` is already exported:
`health_rpc` wires a `HealthReporter` into every service's routes
(`serve.rs:317`), `ServiceHealth` already carries `repeated Load`, the `health`
service polls all 23 every 5 s keeping 720 samples, and operator-api serves the
aggregate at `/v1/health`. Collector, transport, aggregation and HTTP surface all
exist. What is missing is one field.

1. **Add counters to the health contract** — `CounterSample { name, value }` and
   `repeated CounterSample counters = 8` in
   `crates/proto/fancy/proto/health.proto`; field 8 is free. Run
   `check-proto-hygiene.py` and `check-proto-drift.sh`. Add `Metrics::sample()`
   beside `render()`, documenting that counters are cumulative so **many readers
   are fine** — the asymmetry with `Pressure` is exactly what gets miscopied.
   Fill it in `HealthReporter::snapshot()` and pass `&ctx.metrics` at
   `serve.rs:317`: **one call site for the whole tree.**
2. **`/metrics` on operator-api**, rendered from the collector's `Overview`
   rather than the local registry, so one scrape covers all 23 units in both
   topologies. **Critical:** `Pressure::sample()` *clears the peak* and permits
   exactly one reader, which is the `health` collector. `/metrics` must read the
   collector's last snapshot and never call `sample()` itself, or a Prometheus
   scrape and the dashboard will silently steal peaks from each other. The same
   rule binds the soak harness.
3. **Per-map gauges.** Only three exist tree-wide today. Add
   `pressure.gauge(name, cap).observe(map.len())` in each service's existing
   sweep for: gateway `connections`, `resume.sessions`, `resume.bytes` and
   `limiter.buckets`; `social.watches` (defect 8); the session-view store;
   `session-lifecycle` pool free and in-use (defect 18); `moderation` ban rows
   and expired (defect 10); metadata channels and description cache; the
   pchat, screenshare, voice and text subscriber maps; `sfu.sessions` and
   `outbound_per_session_max` (defect 9); plugins; files tickets and attempts;
   operator-api WebSocket subscribers and audit queue depth. Keep it honest with
   a `scripts/canon-gauges.json` contract test — the same "a human must edit this
   deliberately" pattern the tree already uses for `canon-fixtures.json` and
   `cpp-citations.json` — so a new map without a gauge is a conscious omission in
   a diff rather than an oversight.

**Done when:** `curl /metrics` on an all-in-one lists every counter and gauge
from all 23 units, the canon-gauges test passes, and `Deployment` gains an
`async fn overview()` helper going through the existing `self.resolver`.

### Stage 6 — the soak and longevity harness (~8 days; the centrepiece)

**Extract the harness first.** `Deployment`, `Client`, `TempDir`, the handshake
helpers and `TrustAnyCertificate` are all private inside `#[cfg(test)] mod e2e`
in a *binary* crate (`crates/starling/src/main.rs:31`), so nothing else can use
them and a second copy would drift. Move them to a new `crates/harness`; `e2e.rs`
becomes an importer and sheds roughly 1 200 lines. Not a pure move:
`Deployment` calls `crate::units::spawn`, `crate::units::names` and
`crate::compose::enabled` (`e2e.rs:173-197`), which are `pub(crate)` in the
binary, and `TestPeer` is a private `mod testing` in `voice`. Either `starling`
grows a `lib.rs` exposing `units` and `compose`, or those two move with the
harness. About two days, its own PR, no behaviour change so the 66 tests are the
proof. `ONE_AT_A_TIME` stays for e2e; the soak
gets its own target so it never contends.

**Two harnesses, not one.** In-process (`crates/starling/tests/soak.rs`,
`#[ignore]`d, `cargo test --profile soak`) reads `Overview` through the resolver
with no scrape latency, reads `Handle::metrics().num_alive_tasks()`, and holds
every `JoinHandle` for the teardown check — that is where the *state* assertions
live. Out-of-process (`scripts/soak.sh` plus a `soak-driver` bin against the real
`--all-in-one` binary) samples `/proc/<pid>/{status,fd,task}` and `/metrics` —
that is where the *resource* assertions live, because RSS measured inside a test
binary that also holds the client side and tempfiles is not the server's RSS.
Both share the scenario driver and the assertion module.

**The scenario** lives in `crates/harness/scenarios/*.toml` so a new one is a
config change: around 200 virtual clients, Poisson arrivals, lognormal session
length; 64 channels at depth 4 with churn; per client a channel join every 90 s,
chat at 1/min with 3 % near-max-size, 50 fps speech in 30 s bursts at 15 % duty
across both `UdpFormat`s (30 % legacy, 10 % over the UDPTunnel), 5 % starting a
screenshare with 3-10 viewers, 2 % reconnecting with resume and 2 % without, 1 %
presenting a malformed client certificate, 1 % disconnecting mid-frame. Plus an
operator polling `/v1/health` and a live WebSocket subscriber, and a background
bad actor doing a 50/s connection storm every 30 min with 20 slowloris
connections held throughout. Reuse `Client` for the TCP, TLS and handshake half,
and `TestPeer` for genuinely encrypted UDP.

**What to assert** — the part that matters. Sample every 30 s to a JSONL
artifact.

* **Memory, via slope not level.** Split warm-up from steady; fail if the
  least-squares RSS slope over the steady window exceeds about 2 MB/h with
  R^2 > 0.7 (a real leak is linear, noise is not), or if
  `max(RSS) > 3 x median(RSS_steady)`.
* **The quiesce phase — the single most informative assertion.** At T-10 min
  disconnect every client, stop all traffic, wait 5 min, sample again. Assert
  `RSS_quiesced < RSS_baseline x 1.15`. "Grew under load" is ambiguous; "did not
  come back down when idle" is not. This is also what makes a 90-second per-PR
  smoke test viable, because the quiesce assertion is a *level*, not a *slope*.
* **File descriptors** — `fd_quiesced <= fd_baseline + 8`; during the run,
  `fd <= baseline + 4 x live_connections + 64`.
* **Tasks and threads** — `tasks_quiesced <= baseline + 5`, and a thread count
  constant after startup, which is where the SFU's never-joined `std::thread`
  shows up.
* **Per-map gauges return to baseline.** From Stage 5. This is how defects 8, 9,
  3, 4 and 18 become failing tests rather than opinions. Report the top five
  gauges by `quiesced - baseline` on failure so the diagnosis is in the CI log.
* **Peaks against capacity** — `peak / capacity < 0.9` throughout. A soak that
  passes at 99 % occupancy will fail at 1.01x the load.
* **Counter deltas** — hard-zero on `starling_service_restarts` and any panic
  counter; budgeted on `*_dropped`, `*_refused` and `*_throttled`, and
  additionally assert the *rate* is not climbing. A drop rate that grows over six
  hours is a degradation the absolute count hides.
* **Latency non-degradation** — a probe client pinging every second; p99 in the
  last hour at most 1.5x p99 in the first steady hour. This is how defect 3 shows
  up as a measured symptom, complementing its deterministic unit test.
* **Log ring** — zero `Severity::Error` outside an allow-list, and a record count
  growing sub-linearly with connections.
* **Teardown** — the Stage 0 `stop()`: no panics, no failed drains.
* **Database** — `PRAGMA integrity_check` on every SQLite file afterwards, and an
  on-disk size bound. A WAL that never checkpoints is a disk-full in month six.

**Bounding the window.** Nightly `soak-short` is 45 min at 100 clients on a
hosted runner, which is enough for the map, fd, task and quiesce assertions since
those are population-independent. Weekly `soak-long` is 6 h at 200 clients and is
the only one that meaningfully tests the RSS slope and latency drift. Take
`--duration`, `--population` and `--seed` as flags with a **fixed seed printed at
startup** so a failure reproduces, emit `soak-report.json` every run, and add
`scripts/soak-compare.py` so the nightly can say "RSS slope went from 0.3 to
4.1 MB/h" rather than just "failed".

**Done when:** a 45-minute nightly is green three times running, and reverting the
`social::closed` fix makes it fail naming `social.watches`.

### Stage 7 — fault and chaos injection (~5 days)

**In-process** — 20x cheaper to run and debug, folded into the soak and run
nightly. `Deployment::restart(name)` looping over all 22 service names from
`units.rs` (every unit but the gateway, which owns the client sockets), one per
minute under churn: clients stay connected, gates go `Warming -> Ready`, no
unexpected disconnects. **This is the test that forces defect 6's fix, because
you cannot restart a service the runtime does not supervise.** Plus a background
task that returns `Err` (assert backoff restart and a `starling_service_restarts`
increment); clock steps forward 1 h, back 5 min and forward 30 days via the
Stage 4 `Clock` (note that `Instant::duration_since` on an earlier instant can
panic — `saturating_duration_since` is the fix, and the per-module
`arithmetic_side_effects` will surface it); packet loss, reorder, duplication and
corruption via a lossy `UdpSocket` wrapper with no kernel involvement (the OCB2
resync path already has an e2e test at `e2e.rs:2503`); mid-frame close with
`SO_LINGER 0`; slowloris; a 500-connection storm; oversized frames; a database
held under `BEGIN EXCLUSIVE` (assert the *retry* succeeds, which is what proves
the `busy_timeout` pragma landed); and hostile plugins in
`crates/plugin-host/plugins/`, dev-only, that loop forever, allocate unbounded,
panic on load, `abort()` on call and mismatch the ABI. One honest limitation to
document: **a native `.so` that calls `abort()` takes the process down and the
host cannot stop it.** The answer there is process isolation; assert all five
against the WASM backend.

**Out-of-process** — weekly, using the existing `docker-compose.yml`, already 20
containers with one `command` per service. Disk full via a 64 MB tmpfs data
volume, which also tests audit-log rotation and WAL growth; database corruption
by truncating a `.db` and flipping WAL bytes;
`docker compose kill -s SIGKILL voice` under load; a `tc netem` or `iptables`
partition between gateway and one service, asserting `crates/runtime/src/breaker.rs`
opens; `libfaketime` for a system-wide clock step; `mem_limit: 256m` on one
service, asserting the rest keep serving; and **the three-dialect matrix**
(defect 17), running the existing test suite against Postgres and MySQL. That
last one is cheap and covers three shipping code paths CI has never executed;
**promote it to nightly.**

### Stage 8 — detection in production (~4 days)

No test suite proves years; the server must notice its own wedge.

* **A real liveness gate** (defect 5). Add `Health::heartbeat(name, max_age)` and
  `Health::beat(name)` storing `(Instant, Duration)` beside the existing gates,
  with `is_live()` returning false on any stale heartbeat. The Stage 7 supervisor
  registers one per service and beats it each background cycle; the gateway beats
  on each accept-loop `select!` wakeup **including the timer arm**, so an idle
  server does not false-positive. Expose `/livez` (heartbeats) distinct from
  `/readyz` (warm-up gates), on operator-api *and* on a minimal always-on probe
  port for the per-service topology where operator-api is not deployed. Switch the
  Helm `livenessProbe` from `tcpSocket` to `httpGet /livez` and `readinessProbe`
  to `/readyz`, and add a `startupProbe` so slow cold starts are not killed.
* **Supervise rather than log** (defect 6). In `serve.rs:288`, a background task
  that returns `Err` or panics marks its heartbeat failed and restarts with
  backoff; after `max_restarts` the liveness gate fails. `compose.rs:159`
  `select!`s over all handles and exits non-zero when an essential-tier service
  dies, letting systemd or Kubernetes restart it.
* **systemd watchdog and limits** (defect 21). `Type=notify`, `WatchdogSec=60`,
  `LimitNOFILE=65536`, `MemoryMax`, `MemoryAccounting=yes`, `TasksMax=4096`, and
  `READY=1` after warm-up, which also fixes systemd currently considering the
  unit started before any service is warm. Ping `WATCHDOG=1` **only when
  `Health::is_live()`** — a plain timer ping proves the runtime is scheduling,
  which a wedged server also does; gating on `is_live()` is what makes systemd
  restart a server whose tasks died but whose socket still accepts. Implement
  `sd_notify` directly against `$NOTIFY_SOCKET` with `UnixDatagram`, a few dozen
  lines, rather than taking a dependency `cargo-deny` would have to vet. Mirror
  the limits into Helm and compose, and drop the compose healthcheck's
  first-success latch.
* **Panic hook.** With `panic = "abort"` the operator log's tail is lost because
  `log.finish()` never runs (`compose.rs:182`). Install `panic::set_hook` to
  write a structured record and flush before aborting. Also reconsider
  `strip = "symbols"`, or ship separate debuginfo — an abort with no backtrace is
  hard to act on.
* **Alerts**, ranked by how well they predict an outage: `starling_service_restarts`
  rate above zero, sustained; any gauge at `peak / capacity > 0.8` for 5 min; any
  `rejected` delta above zero; RSS slope above 1 %/day, which needs
  `process_resident_memory_bytes`, so add a small `/proc/self/statm` reader to
  the metrics route, Linux-only and feature-gated; fd count above 60 % of
  `LimitNOFILE`; a TLS-failure rate spike; **`/livez` failing while `/healthz`
  passes, which is the wedge signature and the highest-severity page**; WAL size
  over threshold; and a `Severity::Error` rate above baseline. Ship
  `deploy/prometheus-rules.yaml` and a Grafana dashboard so this is an artifact
  rather than advice.

### Stage 9 — CI wiring (~1 day)

**Per PR**, all parallel, targeting under 10 min wall: the existing jobs
unchanged, plus `layering` gaining the `lints.workspace = true` assertion; `test`
gaining the proptests at 256 cases and `check-panic-audit.sh`; the `fuzz` job
**replaced** by corpus replay (`-runs=0`, all targets, about 1 min) followed by
20 s of search on the five Tier-1 targets; and a new **`soak-smoke`** at 90
seconds and 20 clients, running all the quiesce assertions but no RSS slope. That
last job is the one worth fighting for: map, fd and task leaks are detectable in
60 s because quiesce is a level, and catching a leak in the PR that introduced it
beats catching it six weeks later.

**Nightly**, about 4 h with jobs parallel: `fuzz-long` (all targets, 6 min each,
accumulating cached corpus); `soak-short` (45 min, `--profile soak`);
`chaos-inproc`; `loom` on the three modules; `dialects` (Postgres and MySQL);
`sanitizers` (ASan then TSan on `runtime`, `gateway`, `sfu` and `voice` only —
TSan across 23 units and sqlx is noise); and `proptest-deep`.

**Weekly:** `soak-long` (6 h, 200 clients, needing a self-hosted runner or a
scheduled VM); `fuzz-deep` (`-fork=4` plus MSan on three targets);
`chaos-compose`; and an `upgrade` job that starts release N-1, populates,
upgrades in place, and asserts migrations and client reconnect.

**Reporting.** A red X nobody opens is not reporting. Every job emits a
machine-readable artifact; a final `report` job (`if: always()`) downloads the
last successful run's artifacts, diffs RSS slope, per-gauge quiesced deltas, p99
and counter budgets, and new fuzz crashes, and **opens or updates a single**
issue labelled `nightly-regression` with the diff table. Updating one issue
rather than opening N is what keeps it read. For a new fuzz crash, also run
`cargo fuzz tmin` and attach the minimised input with the exact reproduction
line. Commit `soak-baseline.json` on every green weekly so the slope comparison
has a stable reference rather than drifting against yesterday. This mirrors the
`nightly-state` branch pattern the e2e harness repo's nightly already uses.

---

## Effort and ordering

| Stage | Effort | Finds a real crash |
|---|---|---|
| 0 Teardown and supervisor visibility | ~1 d | **Immediately** — 66 tests stop swallowing panics |
| 1 Fuzz Tier 1 | ~3 d | **Days** — str0m and the hand-rolled varint are the likely two |
| 2 Regression tests for the register | ~2 d | Confirms known bugs; several fail on first write |
| 2b Close the register | ~5 d | Nothing new — turns Stage 2 from red to green |
| 1 Fuzz Tier 2 and 3, `arbitrary`, allocation cap | ~2 d | Days |
| 3 Lints, in order | ~4 d | Weeks — the ~40 indexing sites hold two or three real ones |
| 4 proptest and loom | ~4 d | ACL evaluation is the likeliest |
| 5 Counters, `/metrics`, per-map gauges | ~3 d | Nothing directly; unblocks Stage 6 |
| 6 Soak harness | ~8 d | Weeks — but the only thing that finds a *leak* |
| 7 Chaos | ~5 d | The restart-under-load loop finds defect 6's consequences fast |
| 8 Production detection | ~4 d | Nothing in test; it is the year-three insurance |
| 9 CI wiring | ~1 d | — |

About 42 engineer-days total. **Stages 0 to 2b are roughly 11 days and deliver
most of the crash-finding and every fix in the register**; the rest is the
machinery that keeps it true. Stages 5 to 7 wait for 2b: the soak's headline
assertions (quiesce, per-map gauges) are written to fail on today's code, and
fifteen days of red proving what the register already says is not a finding.

## Verification

* **Stage 0:** insert `panic!()` into a service's `run()`; a named e2e test fails
  with that message. Remove `stop()` from a test; it fails.
* **Stage 1:** `cargo fuzz run <t> -- -runs=0` green for every target from the
  committed corpus, and 30 min of search clean per target.
* **Stage 2:** the slowloris and DB-locked tests **fail on today's `main`** and
  pass after Stage 2b. That is the proof they test something.
* **Stage 3:** `cargo clippy --workspace --all-targets -- -D warnings` green;
  `scripts/check-panic-audit.sh` and the layering check pass.
* **Stage 4:** proptests run in the per-PR job under 60 s; `--cfg loom` green on
  the three modules; the session-pool property fails against a deliberately
  broken `release()`.
* **Stage 6:** a 45-minute soak green three times; reverting the
  `social::closed` fix makes it fail naming `social.watches`.
* **Stage 8:** kill a background task in a running all-in-one; `/livez` goes
  unready within k intervals and systemd restarts it.
* **Throughout:** the external e2e suite stays green, run against a **release**
  Starling as it requires.

## Notes

* **Stages 5 and 6 are coupled**: the soak assertions need the gauges and
  `/metrics` from Stage 5. Do the gauge work once.
* **The native-plugin `abort()` case is not solvable in-process** and should be
  documented as a known limitation rather than papered over. **A `str0m` panic
  under `--all-in-one` is the same class**: per-service deployment contains it to
  `screenshare`; all-in-one does not until that unit runs as a child process
  (Stage 2b, after the Stage 8 supervisor exists).
* **Disk.** The `soak`, ASan, TSan and fuzz builds are each a separate target
  directory. Budget around 40 GB on a self-hosted runner, and add a weekly
  `cargo clean` of the sanitizer trees.
