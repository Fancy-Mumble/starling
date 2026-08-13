# Fleet plan — e2e road to green

**Merged 2026-08-09** from four separate handovers (this file, `docs/E2E-HANDOVER.md`,
`docs/E2E-AGENT-HANDOFF.md`, `docs/WORK-IN-FLIGHT.md`) written by six parallel
sessions. **This is the single shared state.** Update it in place when you land
something; do not keep status only in chat, because sessions end and the next one
starts blind.

The e2e suite's *measurement* lives in the e2e repo's `E2E-STATUS.md`. This file
records what changed **since** that measurement and what it means for the next one.

---

# 1. Where the score stands

| Sweep | Result |
|---|---|
| Morning baseline | 40 pass / 81 tests in **31:33** |
| After harness work (12:38) | 67 pass / 8 fail / 86 tests in **14:57** |
| After D's client rebuild (14:15–14:28) | 85 tests, 48 suites, **69 pass, 2 fail**, 10 cancelled, 4 skipped |

Harness runtime work and the keymap fix are **committed** on the e2e repo's
`wip/audit-e2e` (`26aedd2`, `df3c234`, `c4ae3e6`). Everything else below is
uncommitted working-tree state — see §7.

The last sweep's "2 fail / 10 cancelled" is **one root cause each, not twelve
bugs**, confirmed by re-running every distinct failing suite standalone:

- `channels: hidden, expiring + meeting rooms` — **8/8 in isolation**. The sweep's
  red was a `StaleElementReferenceError` load flake (same class as
  `E2E-STATUS.md` §3.6). Not a regression.
- `persistent chat control messages` / read watermark — reproducible standalone;
  this is B's known, never-e2e-verified gap (§4).
- `screen share: delivery health`, `screenshare.multiclient`,
  `screenshare.performance`, `camera-share` — all four cascade from **one** cause:
  the client panics on launch under `capture-env.ts`'s forced `GDK_BACKEND=x11` /
  empty `WAYLAND_DISPLAY`, with `Failed to initialize GTK backend!` in
  `.tmp/tauri-driver-4445.log`. Every other suite in the same sweep launches fine
  under the ambient Wayland env. New information for §5, not a new bug.

**Conclusion: zero regressions from the client rebuild.**

---

# 2. State by workstream

| Stream | Tests | Status |
|---|---|---|
| **A — signal cross-client** | 3 | Root cause fixed (SKDM `sender_hash` self-identification, verified via client log `decrypted OK`) + a real forward-secrecy leak closed at 4 client call sites (`forward secrecy for late joiners` passed clean). 3/4 passed once, pre-rebuild. **Not re-verified against the current artifact.** |
| **B — archive pchat** | 2 | Root cause found and fixed (§4). Unit-verified everywhere; **never got a rig slot, so never e2e-verified.** |
| **C — media** | 5 suites | Four harness-side causes proven and fixed (§5), **none transport**. **No media suite has been observed green** — two rig slots were lost to the config mismatch. Do not score as passing. |
| **D — scheduled messages** | 1 (+3 cancelled) | **DONE — 3/3 twice** against the rebuilt artifact. Found and fixed one real bug: `ScheduledMessagesPanel`'s header button sat under `ResizableSplitPanel`'s close (×) overlay (`position:absolute; top/right:8px; z-index:25`) and intercepted its click — same class as C's reaction interception. Fixed with the `padding: 44px` right-inset convention `DownloadsPanel` already uses. **Confirmed on Windows too (2026-08-09): 3/3 twice.** The Windows red ("kebab never appears", reproducible standalone) was never the panel — it was a week-old `ui/dist` embedded in a fresh exe (§10); `npm run build` + cargo rebuild dissolved it. |
| **Server: murmur-settings parity** | — | **COMPLETE and green** (§6.1). |
| **Server: virtual_server → instance rename** | — | **DONE and landed** — committed (`daf58f7`), pinned by the e2e repo, and the harness now asks the binary which vocabulary it speaks, so the cutover no longer needs scheduling (§6.2). |
| **Server: `starling check-config`** | — | Complete, verified, **committed** (`edd7374`) (§6.3). |

**Correction to earlier doctrine (A and B agree):** nobody is blocked on
`FeaturePchatE2ee`. B's replace rule is unconditional on it; the flag only stops
the redundant placeholder being *inserted* alongside the real message — a cosmetic
ghost bubble, not a correctness issue. Go straight to verification after a rebuild.

---

# 3. What to do next

1. **Verify B and A against the current artifact.** Both signed off before the
   rebuild landed; their fixes are *in* it (same working tree) but neither was
   re-run. Run `pchat-control-plane` (2/2) and `pchat.multiclient` twice, and
   `signal-pchat.multiclient` 3/3 twice.
2. **Measure the media cluster** in this order (§5): `screen-share-health` →
   `screenshare.multiclient` on the ambient display — the freeze budget (≤2 in
   24 s) is the first assertion about the media path rather than the harness.
   Investigate the GTK-init panic from §1 first; it currently blocks all four.
3. **Highest-value experiment: `E2E_XVFB=1`** (`src/util/xvfb.ts`, wired, opt-in,
   **never yet run with a real client**). A private X server has a readable root,
   so it would un-gate entire-screen capture *and* stop media tests competing with
   five other sessions for one desktop — which is what cost two rig slots. Xvfb
   needs no window manager: `xcap` reads the window list with `ATOM_NONE`, so
   `xprop` can publish `_NET_CLIENT_LIST_STACKING` itself (verified).
4. **Build a Starling binary containing the `signal_v1` archive ban** — the tree
   is green, and a build needs no rig lock.
5. **Checkpoint sweep**: owners commit their vendor-tree work, rebuild client +
   starling from committed state, one full sweep, record it in `E2E-STATUS.md`
   with clean hashes. Iteration sweeps run `+dirty` and are navigation only;
   this one is the scoreboard. After any artifact swap, *everyone re-runs —
   greens included*.

---

# 4. Deep dive: archive-mode persistent chat (stream B)

**Status: code complete, unit-verified, NOT e2e-verified.**

## What was actually wrong

One server bug and three translation gaps. The server bug made a *correct*
ciphertext undecryptable by everybody, including its author.

A `fancy_v1_full_archive` message is sealed with

```
AAD = channel_id(4B) ‖ message_id(16B UUID) ‖ sent_at_ms(8B)
```

bound in both `encrypt` and `decrypt` (client `persistent/protocol/fancy_v1/aad.rs`,
`persistent/keys/crypto.rs`). `crates/services/pchat` minted its own uuid7 over
`message_id` and stamped `now_ms()` over `sent_at_ms` on the way into the archive.
The ciphertext crossed byte for byte, arrived intact, and the AEAD refused it — on
the other member's screen, and on the author's own after a reconnect. murmur never
had this problem: it stores what the sender sent (`PchatProtocolHandlers.cpp:58`,
which also dedups on that id).

It split a message's identity in two as well: the author's copy kept the id it
minted while everyone else held the server's, so a pin, a reaction or a read
watermark named a message the other end did not have. **That is the whole
read-watermark failure** — the receiver's watermark named an id the author's client
had never seen, and the store's `indexOf` returned −1.

## Changed in Starling

- **`crates/services/pchat`** — migration `0004_pchat_client_id`. The uuid7 stays
  the primary key and the cursor (it is what makes a page a backwards range scan,
  `STORAGE.md` L3); the wire identity is the sender's again. `sent_at_ms` is the
  sender's clock, falling back to `now_ms()` only when the sender named no time.
  Cursors resolve through the new column, so scroll-back pages by an id a client
  actually holds.
- **`crates/services/pchat`** — `signal_v1` is never archived and never served.
  Both halves on purpose: refusing to write only protects a database that has
  always run this build, while a deployment that upgraded into it still has older
  signal_v1 rows on disk, and the fetch/count filter keeps those unreadable without
  a data migration. Agreed with stream A, whose test asserts exactly this ("no
  server storage + forward secrecy"). The message is still relayed — this drops the
  row, not the message.
- **`crates/services/social`** — a relayed `ReadReceipt` now carries `actor_cert`
  (from the connection, like `Reaction.actor_cert`) and a server-stamped `at_ms`.
  Without the certificate the client discards every read state: its handler filters
  entries with an empty cert hash.
- **`crates/proto/.../social.proto`** — `ReadReceipt.actor_cert` field 5, mirrored
  into the client copy; `scripts/check-proto-drift.sh` passes.

## Changed in the client

- **`canon.rs`** — three gaps: `FancyReadReceipt` had **no canon form at all** and
  is `ServerOnly`, so the codec dropped every watermark with a debug line (a
  `query = true` receipt is deliberately still untranslated — the canon models a
  receipt as an event it relays, not state it stores); the canon `Receipt` had no
  inbound arm; the canon `FetchResponse` had **no inbound arm for any protocol**, so
  the server served history and the client discarded the frame as an unknown service
  message. That last one also sat in front of A's reconnect-resume.
- **`state/pchat/inbound.rs`** — the replace rule below.

## The trap the server fix exposed (read before trusting any pchat run)

A Fancy sender emits **both** halves of the dual path under **one** id: a plaintext
`TextMessage` (the `[Encrypted message]` placeholder — the real body only when
`enableDualPath` is on, which is not the default) and the encrypted `PchatMessage`
(`state/messaging/mod.rs`, one uuid minted and passed to both). Starling preserves
`message_id` on the text relay and now on the pchat relay too, so the two **collide**
where they previously did not.

The receiver resolved that badly. `text_message.rs` accepts the plaintext half as a
legacy message whenever the sender does not advertise `FeaturePchatE2ee` — and **no
shipped client sets it**; nothing in the client tree writes `client_features` at all,
it is only ever read (`state/types/ui.rs`). Then `insert_or_replace_message` was a
plain first-wins dedup, so if the plaintext landed first — the usual order — the
decrypted message was **dropped** and the peer rendered `[Encrypted message]` for
ever. In the other order you got two bubbles.

Fixed: a non-legacy message replaces a same-id legacy placeholder, one direction only
(a placeholder never overwrites a real message), carrying pin state across.

## Verified / not verified

| What | Result |
|---|---|
| `cargo test -p starling-pchat` | 20 passed |
| `cargo test -p starling-social` | 13 passed |
| `cargo test --workspace` (Starling) | 1350 passed, 0 failed |
| `cargo test -p mumble-protocol --lib` | 283 passed |
| `an_encrypted_message_reaches_the_other_member_of_its_channel` | passes; now asserts the sender's id crosses the relay untouched |

New tests worth knowing: `the_archive_gives_back_the_id_and_the_time_the_sender_
sealed_under`, `a_page_is_addressed_by_the_same_id_its_messages_carry`,
`a_signal_message_is_never_archived_and_never_served` (covers a legacy row inserted
behind the service's back), plus client-canon read-watermark and fetched-page round
trips.

**Not verified:** no e2e run ever happened (rig never free). The four tests appended
to `state/pchat/inbound.rs` are **uncompiled** — the *test* build pulls in
`cros-libva`, which does not compile against this host's libva 2.23 (`E0063` in
`buffer/vp9.rs`); run them under `scripts/build-client.sh`'s environment and treat
them as unproven until you have. No Starling binary yet contains the signal_v1 ban.

## Gaps deliberately left

- The archive does not dedup on the sender's id the way murmur does, so a client that
  retries a send writes two rows. Wants a unique index plus an ack reporting "already
  stored" rather than a failed insert.
- `FetchResponse` hardcodes `supersedes: String::new()`, so an edit's `replaces_id`
  never survives the archive, and `store_message` parses the client's `replaces_id`
  as a uuid7 (client ids are v4) before storing it. Edits do not round-trip through
  history. No suite covers this.
- The signal_v1 storage ban reads the protocol the *frame* declared. A client that
  mislabels its own message still gets it archived — a client lying about its own
  history rather than reading someone else's. The airtight form asks `metadata` for
  the channel's `pchat_protocol`, a cross-service call this path does not otherwise
  need.

---

# 5. Deep dive: media path (stream C)

**None of the media failures were the SFU, and none reached the transport.** All
five suites died during *source selection* or on a *DOM wait that could never match
on Linux*. `crates/sfu` is not implicated by any evidence gathered. Work is
**harness-side only**.

## The four causes, each verified rather than argued

1. **Wayland blinds source enumeration.** xcap's `wayland_detect()` keys off
   `XDG_SESSION_TYPE`/`WAYLAND_DISPLAY`; on Wayland `Window::all()` returns empty and
   the picker falls back to two synthetic "(system picker)" cards whose ids are
   advisory — a suite selecting a window *by title* can never match. Fix: media
   clients launch with an X11 identity on XWayland (`src/util/capture-env.ts`),
   including a deliberately dead `DBUS_SESSION_BUS_ADDRESS` so the portal fails
   inside its 5 s pre-dialog timeout instead of blocking forever on a compositor
   dialog WebDriver cannot answer.
2. **The checkerboard fixture was unenumerable by construction.**
   `fixtures/checkerboard.py` used `overrideredirect(True)`, which bypasses the WM —
   and unmanaged windows never enter `_NET_CLIENT_LIST_STACKING`, the property every
   enumerator reads. Measured across five window types (normal / override-redirect /
   splash / dock / utility): override-redirect is the **only** one absent. Now a
   splash-type window: undecorated, topmost, exact geometry, managed. Flip reporting
   and animation verified unchanged.
3. **On Linux the viewer is a `<canvas>`, and every harness wait named `<video>`.**
   WebKitGTK has no WebRTC, so the client decodes in Rust and paints into
   `stream-native-view`; `stream-viewer-video` never mounts — exactly the "own
   preview never appeared in 30 s" symptom against a stream that was in fact
   arriving. `src/pages/stream.page.ts` now accepts either surface, sizes via
   `videoWidth || width`, and counts decoded frames on canvas by tallying the paint
   path's `drawImage` calls (the stand-in for `getVideoPlaybackQuality`).
4. **The camera suite failed on a leaked modal.** With no cameras present, step 1
   skipped *while the picker was still open*, so step 2's toggle click hit the modal
   backdrop — `ElementClickInterceptedError` 4 ms in. `closePickerIfOpen()` now runs
   in `afterEach`.

## Entire-screen sharing is gated, not red

`XGetImage` on XWayland's root fails with `BadMatch` — confirmed twice independently
(ImageMagick `import`, PIL `ImageGrab`) — because that root is a bounding box no
compositor paints into. The portal alternative needs a human to answer a dialog.
`entireScreenCaptureUnavailable()` skips `screenshare.gpu` in ~0 ms with the fix
named, the same shape as `pluginMissing()`. Per-window capture works: verified
512×384, exactly two colours.

## Environment findings other streams will want

- **Portal mocking needs no root.** `org.gnome.Mutter.ScreenCast` (v4) is live on the
  session bus and non-interactive: `CreateSession` → `RecordMonitor` → `Start`
  returned PipeWire node 94 **with no dialog**, and an unrelated `gst-launch` pulled
  real 2560-wide BGRA frames over the ordinary PipeWire socket. A stub portal on a
  private `dbus-daemon` is viable, and is the only option that would restore coverage
  of the real PipeWire/DMA-BUF path — **no suite currently exercises it; we only ever
  hit the xcap CPU fallback.**
- **Mutter's screencast is damage-driven.** A static screen produces zero frames,
  which looks exactly like a broken pipeline. Any capture test must keep motion on
  screen.
- **Xvfb works and has a readable root** (verified: 2560×1440 grab, board pixels
  present) — see §3 item 3.
- Client logs used to die with the run: on Linux Tauri honours `XDG_DATA_HOME`, so
  logs land inside the per-instance data dir that `close()` deletes.
  `E2E_LOG_ARCHIVE=<dir>` now copies them out first.

---

# 6. Deep dive: server work in flight

## 6.1 Six murmur settings that had no Starling equivalent — COMPLETE

`cargo check --workspace --all-targets` and `cargo test --workspace` both green
(62 test binaries, 0 failures). Uncommitted. Implements `usersperchannel`,
`defaultchannel`, `rememberchannel`, `rememberchannelduration`, `channelname`,
`username`.

| Layer | Change |
|---|---|
| `proto/.../serverconfig.proto` | `Snapshot` fields 36-39, 41-42 (40 was already `extra`) |
| `proto/.../metadata.proto` | `EnterRequest.account`/`.bypass_full`, `LeaveRequest.account`, new `LastChannel` RPC |
| `runtime/src/settings.rs` | The six defaults (murmur's), `from_json` arms, `CHANNEL_NAME_PATTERN`/`USER_NAME_PATTERN` |
| `runtime/src/names.rs` | **New.** Anchored, cached name matching, shared by metadata and userdata |
| `runtime/src/config/server.rs` | Six `[instances.settings]` keys |
| `services/server-config/src/snapshot.rs` | `apply_fields` arms + six admin-UI schema rows |
| `services/metadata` | `TreeLimits.users_per_channel`; `is_full_for`; `last_channel` table (migration `0003`); channel-name check |
| `services/session-lifecycle` | Landing cascade at login; `Leave` on disconnect; `Write` bypass on move |
| `services/userdata` | `user_name_regex` at login, registration, both renames |
| `migrate/src/ini.rs` | All six migrate from a murmur `.ini` |

**Three behaviour changes the suite will see:**

1. **`metadata` is now told when a session ends.** `session-lifecycle::closed` calls
   `Leave`, which nothing had ever called. Memberships accumulated for every session
   that had ever connected, so occupancy counted the dead — invisible until an
   occupancy *limit* reads it, and then it is a room that says it is full and looks
   empty. The `qt6ui: disconnect leaves no ghost session` test should get **stronger**
   (before this it was passing on session-view's view, not metadata's).
2. **Login no longer always lands in the root.** `announce_up` moved ahead of
   `welcome` because choosing the landing channel asks `permissions` whether the user
   may enter each candidate, which resolves through `session-view`; asked earlier it
   answers "session could not be identified" and denies. **No client-visible message
   order changed** — everything `welcome` builds is emitted in the same sequence and
   the welcome text still rides `ServerSync`. ~3 extra local gRPC calls of latency.
   Defaults preserve "fresh clients land in root" (`default_channel` = 0; remember
   needs a registered account + stored channel + storage configured).
3. **A full root now rejects the login** as `ServerFull`, as murmur does
   (`Messages.cpp:552`), instead of admitting a session to no channel.

**Deliberate divergences from murmur:** a **broken** name pattern accepts every name
(loudly) rather than refusing every one — upstream's behaviour turns one typo into a
server nobody can log into. The **SuperUser is exempt** from `user_name_regex`, the
same carve-out `cert_required` has. `regex` is a **new direct dependency** of
`starling-runtime` (already in `Cargo.lock` transitively), chosen over a backtracking
engine deliberately: the pattern comes from a config file and is matched against names
a stranger picked. **`Cargo.toml`/`Cargo.lock` are touched** — relevant to anyone
diffing lockfiles for the rename cutover.

**Not done:** `docs/GAP-ANALYSIS.md` still lists C5 (no name validation) and A4 (no
last-channel memory) as open — both now closed, tables need updating. No e2e coverage
of the landing cascade. `LastChannel` has no operator-api surface. Migration `0003`'s
upgrade path is untested — the suite only ever migrates from zero, because
`StarlingServer.start()` mkdtemps a fresh data dir per run.

## 6.2 virtual_server → instance rename — LANDED

Committed as `daf58f7` on `main` and pinned by the e2e repo's submodule pointer
(`b220738`). At the user's request: a deliberate clean break, no back-compat
aliases, 336 occurrences across 66 files. Identifiers are
`instance`/`instances`/`Instance`; prose reads "server instance". `grep -ri
virtual_server` over the tree now returns hits in this file only.

| Surface | Before | After |
|---|---|---|
| TOML key | `[[virtual_servers]]` | `[[instances]]` |
| TOML key | `[virtual_servers.settings]` | `[instances.settings]` |
| proto field | `Scope.virtual_server` | `Scope.instance` |
| operator-API JSON | `AccountUpdate.virtual_server` | `instance` |
| audit log field | `"virtual_server"` | `"instance"` |
| env override | `STARLING_VIRTUAL_SERVERS_*` | `STARLING_INSTANCES_*` |
| helm values | `virtualServers` | `instances` |

The proto change keeps every field **number**, so it is wire-compatible; only the
generated field name moves. The TOML change is **not** compatible in either
direction. Left alone deliberately: murmur's `.ini` keys in `crates/migrate` are
external input; k8s "virtual ClusterIP", positional-audio "virtual world" and Cargo's
"virtual manifest" are unrelated. Verified: `cargo test --workspace` green (1116
tests at the time), fmt/clippy clean, `tsc --noEmit` clean, and a real boot against
the harness's generated config.

### The rollout hazard — resolved, see §8

The harness no longer has to be flipped in step with the binary: it reads the
binary it is about to spawn and writes whichever table name that binary knows.
An old binary and a new one both start.

## 6.3 `starling check-config` — complete, uncommitted

New `crates/starling/src/check.rs`, wired into `main.rs`:

```
starling check-config [--config <file>] [--strict]
```

Loads exactly what a boot would (same `--config` resolution, platform directory,
environment overrides) then asks the boot-time questions with nothing bound. Exit 1
on anything that would stop a start; `--strict` also fails on warnings. Catches the
class that otherwise shows up as one line among twenty-two at startup:

- Unix socket paths over `SUN_LEN` (107 Linux / 103 BSD) — **the one that paid for
  the command**: the path is *generated* from `runtime.data_dir`, so a deep data
  directory breaks twenty-two services at once and nothing in the file looks wrong.
  The report names `data_dir` rather than the sockets.
- Two listeners on one address per protocol (wildcard counts as colliding with
  specific). Voice sharing the gateway's number over UDP is the murmur convention and
  is *not* flagged.
- Duplicate instance ids (error) and ports (warning); half-stated TLS identity;
  unopenable certificates; endpoint strings no transport claims.

18 unit tests, including that the shipped defaults produce zero findings. **Useful
for the cutover:** a mismatched config gets `unknown field `virtual_servers`,
expected one of ..., `instances`` — a one-line diagnosis instead of a failed boot.

---

# 7. ⚠ Uncommitted work at risk

**Partly superseded as of 2026-08-09.** The Starling tree is now clean at `b220738`
— the rename (`daf58f7`), `check-config` (`edd7374`) and the six settings
(`777ff00`) are committed, and so is C's harness work in the e2e repo (`55898c0`
and earlier). Re-check `git status` in both trees before trusting the list below.

What the section was written about, and what may still be uncommitted elsewhere:
A's SKDM + forward-secrecy fixes, B's archive/canon/`inbound.rs` work, and D's
client UI — `vendor/client` is still dirty (regenerated proto modules) on a
detached HEAD.

**Do not `git checkout`, `stash`, or reset either vendor tree** — commit first, per
owner, or the day's diagnosis is lost. All of it is absent from `HEAD`, so
`git show HEAD:<file>` is the way to tell WIP from a real regression.

Remaining known-broken-in-tree items (neither blocks a normal build):

- `services/session-lifecycle/src/lib.rs` — `on_speak_state` is 115 lines against a
  `clippy::too_many_lines` deny at 100. Fails a strict clippy gate.
- `services/pchat/src/lib.rs` — not rustfmt-clean.

If you need a green build while something is mid-edit, build the crate you care about
(`cargo test -p starling-pchat`) rather than the workspace — do not stash or revert
someone's live editor buffer.

**Windows-tree addendum (2026-08-09 evening).** The scheduled-messages
investigation's speculative e2e edits (channel creation + SuperUser connect in
`scheduled-messages.multiclient.test.ts`, the `zz-probe-header` probe) are
reverted/deleted — neither was justified once the stale-dist trap (§10) was
found. Newly uncommitted and wanted: `src/config.ts` now falls back to
`.tools/msedgedriver.exe` when `E2E_NATIVE_DRIVER` is unset — the auto-use the
README always promised, which `run-local.ps1` had and `scripts/e2e.mts` lost;
without it tauri-driver exits before writing a single log line. The client's
`ui/dist` and `target/release/mumble-tauri.exe` were rebuilt from `0afc91d`.

---

# 8. Harness config ↔ server binary — decoupled

`src/util/starling.ts` in the e2e repo writes a config a specific binary must parse.
Config structs use `deny_unknown_fields`, so an unknown key is **fatal, not ignored**:

- pre-rename binary + `[[instances]]` → dies on unknown key
- post-rename binary + `[[virtual_servers]]` → dies on unknown key

This cost the rig two outages in one day, and once landed mid-run, where one agent
read the resulting timeouts as flakiness.

**This is fixed — the pair is no longer coupled.** The permanent fix landed as
`55898c0` in the e2e repo: `instancesTable()` in `src/util/starling.ts` scans
`E2E_STARLING_BIN` for the string `virtual_servers` and writes whichever table
name that binary knows, memoised per runner. The rename left no alias behind, so
the old name's *presence in the binary* is an exact discriminator; a binary too new
to contain it, or no binary at all, gets `[[instances]]`.

What that means in practice:

- **No scheduled cutover, no atomic swap, no announcement.** Replace the shared
  binary whenever you like — with a pre-rename or a post-rename build — and the
  next `StarlingServer.start()` writes a config it can parse.
- **Do not hand-edit the table name in `starling.ts`.** Both literals in that
  function are load-bearing; pinning either one re-creates the outage.
- **Mixed builds are fine.** Two agents on two binaries of different vintage each
  get a correct config, because the probe reads the binary rather than the tree.
- **Current rig binary:** `vendor/starling/target/debug/starling.exe` is from
  Aug 2 and is *pre*-rename, so the harness is writing `[[virtual_servers]]` today
  and the rig is green on it. Rebuilding from the pinned commit is now an ordinary
  rebuild, not an event.

---

# 9. Rig protocol (one machine, serial)

One e2e run at a time — the shared Starling owns 64738, tauri-driver 4445+, and all
client windows share one display.

- **Lock:** `mkdir <e2e-repo>/.tmp/rig.lock`. **Only the process whose `mkdir`
  succeeded writes `owner`, and it reads the file back to confirm ownership.** (The
  original instruction let anyone write `owner` without gating on the `mkdir`, so it
  could be overwritten — a coordinator error, fixed here. For the record the 13:48
  "double occupancy" was a FALSE ALARM: C acquired and released at 13:47:52 after
  failing in 0 s on the config mismatch, before A acquired at 13:48:23. The 12:56
  collision was real.) Put `role=` and your socket path in `owner`; release with
  `rm -rf`.
- **`pkill` is a rig operation** — pattern kills reach every agent. Take the lock
  first; prefer your own recorded PIDs. Stale `WebKitWebDriver` after a killed run
  causes `SessionNotCreatedError: Maximum number of active sessions` — reap with
  `pkill -9 -x WebKitWebDriver` under the lock.
- **No heavy builds during someone's media slot** — fps, freeze and latency floors
  are the most load-sensitive assertions in the suite.
- **Never leave a shared harness file half-finished.** An uncommitted
  `src/util/starling.ts` table rename broke every agent's server start twice.

---

# 10. Traps that have each cost hours

- **Keystrokes lie.** The compositor keymap types `-` as `ß`, focus-dependently.
  Every asserted-on value goes through `setReactInputValue`; `sendKeys` only where
  content is never asserted. This single cause was the whole "pchat never renders"
  cluster, the invitee-picker red, and the composer flake.
- **One WebDriver session, one command at a time.** Concurrent commands on a single
  session reset the connection (`ECONNRESET`). Parallelise across clients, serialise
  within one.
- **Canon has three outcomes, not two.** Canon entry → sent and stamped; no canon +
  `ServerOnly` → silently not sent; no canon + relayable → **sent but unstamped**, so
  fields the server would fill arrive empty. The SKDM bug was the third kind.
- **Build:** `/tmp` cleanups remove the pinned libva headers (`E0063` in
  `cros-libva`); `CROS_LIBVA_H_PATH=/tmp/libva-2.22/usr/include` only takes effect
  after `cargo clean -p cros-libva`, and is required every time from a clean
  `target/`. Nix-built binaries need
  `patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 --set-rpath '$ORIGIN'` —
  otherwise the build succeeds and the binary dies on `libgbm.so.1` inside
  `.tmp/tauri-driver-*.log`, where the harness blames a missing WebDriver. inotify
  exhausts at the default 128 with several sessions: use `E2E_BUILD_NO_CLI=1`, or
  persist `fs.inotify.max_user_instances=512`.
- **The exe's timestamp lies about the UI inside it.** `cargo build -p
  mumble-tauri` embeds `ui/dist` *as it finds it* — it never rebuilds the
  frontend. A week-old dist inside a minutes-old exe cost half a day on Windows:
  the scheduled-messages kebab was in `ChatHeader.tsx`, provably unconditional,
  and still absent at runtime, because the running UI predated it. The signature
  is a mounted component carrying every *old* testid and none of the *new* ones —
  when source archaeology says "this cannot be missing", check the dist's mtime
  (`ui/dist/index.html`) against the commit before anything else. `npm run build`
  in `crates/mumble-tauri/ui`, then cargo. (Grepping the exe for a testid proves
  nothing either way: release builds embed assets brotli-compressed.)
- **The harness config is a delta; a pre-`check-config` binary is not.** Current
  `starling.ts` writes a partial TOML and relies on `Config::load` overlaying it
  on the defaults. A binary older than that behavior (the Aug 2 debug builds)
  treats the file as the whole config and dies with `the routing table is empty`
  after every service logs `has no endpoint in the configuration`. The §8
  vocabulary probe does not cover this — it picks the right table name for a
  binary whose config semantics are still wrong. Windows note: the harness
  default is `target/debug/starling.exe`, which is exactly such a binary; point
  `E2E_STARLING_BIN` at a build of the pinned commit (`target/release` from
  Aug 9 works) or rebuild debug.
- **Re-measure before debugging.** Three separate "bugs" in one day were already
  fixed, or were the environment. Re-run before you dig.

---

# 11. Open items nobody owns

- The `E2E-STATUS.md` §3 rewrite after the checkpoint sweep.
- ~~The binary-vocabulary probe (§8), blocked on the rename landing.~~ **Done** —
  the rename landed (`daf58f7`) and the probe with it (`55898c0`).
- A stub screencast portal on a private D-Bus (§5) — the only route to covering the
  real PipeWire/DMA-BUF path.
- `docs/GAP-ANALYSIS.md` C5 and A4 are closed but still listed as open.
- Archive edits do not round-trip through history (§4, gaps).
