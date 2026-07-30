# What the Fancy fork has that Starling does not

Companion to `GAP-ANALYSIS.md`, and deliberately a separate file. That one
measures Starling against **upstream `mumble-voip/mumble` 1.6.x** — the protocol
as everyone else implements it. This one measures it against **`vendor/server`,
the Fancy fork**, which is the superset that gives this project its name. The
two answers are very different, and collapsing them into one number hides which
half of the work is left.

Verified against the code on **2026-07-31**, and against a full e2e sweep of the
41-file suite run on the same day. Every claim below was checked by reading the
handler or by reading a test's failure, not by remembering.

---

## 0. The short answer

Near-parity on vanilla murmur. Real but **enumerable** gaps in the Fancy
subsystems Starling implements natively. And **nothing at all** behind the
plugin layer, which is where most of what a user calls "Fancy Mumble" lives.

The e2e suite puts numbers on it: 46 passing, 54 failing, 12 of 41 files fully
green. That failure count overstates the server's part — §4 accounts for 18 of
those failures, none of which measure Starling.

---

## 1. The plugin host — the structural gap

**The Fancy features are not server code in the fork. They are plugins the
server hosts.** The client speaks to them over plugin-data channels, and a
census of the client source shows what they are:

```
fancy-greeter  fancy-live-doc  fancy-live-doc-config  fancy-poll
fancy-poll-vote  fancy-file-server  fancy-file-server-config
fancy-calendar  fancy-server-emotes  fancy-friends  fancy-plugin-info
```

`PluginHostManager` (`vendor/server/src/murmur/PluginHostManager.h`) is a real
host:

| It does | Where |
|---|---|
| loads a plugin **module** and holds a native handle | `isLoaded()`, `m_handle` |
| installs from a marketplace, pinned by digest | `installPlugin(marketplaceId, version, manifestUrl, expectedSha256)` |
| enables, disables and uninstalls at runtime | `setPluginEnabled`, `uninstallPlugin` |
| routes request/response pairs to a named plugin | `sendPluginRequest`, `registerResponseHandler` |
| feeds plugins the server's event stream | `onUserConnected`, `onUserStateChanged`, `onPluginMessage` |

Starling's `plugins` service opens with the words "`plugins` — the host", and it
is genuinely good at the half it implements: the registry, the opaque relay, and
namespaced per-plugin storage with atomic batches (`STORAGE.md` L6). What it
has **no** trace of is a loader. Nothing in `crates/services/plugins/src/`
spawns a process, opens a shared library, or installs anything — no
`Command::new`, no `libloading`, no `dlopen`/`LoadLibrary`, no install or
uninstall path.

So Starling can speak the plugin protocol fluently and has nothing to speak it
to. Every plugin-delivered feature has no server half.

**This is the single highest-leverage piece of work left.** It is one subsystem,
and it unblocks calendar, forums, live-doc, polls, the file server, the greeter
and server emotes at once. Nothing else on this page comes close.

---

## 2. The operator API against Ice

`GAP-ANALYSIS.md` S6 says `operator-api` replaces Ice but "not the whole Ice
surface", without saying which parts. Diffing the 92 operations in
`vendor/server/src/murmur/MumbleServer.ice` against the routes in
`operator-api/src/routes.rs` gives two tiers that need very different work.

### 2.1 The route is missing and the capability is not

Each of these is backed by an RPC that already works. They are small.

| Ice | Backing RPC | Route today |
|---|---|---|
| `kickUser` | `moderation.Kick` | none |
| `setBans` | `moderation.Ban`, `moderation.Unban` | `/v1/bans` is **GET only** |
| `hasPermission`, `effectivePermissions` | `permissions.Check`, `permissions.Effective` | none |
| `getLog`, `getLogLen` | `audit.Query`, `audit.Verify` | none |

The ban row is the one to notice: an operator can *list* bans and cannot *make*
one. `Ban`, `Unban` and `Kick` sit in `moderation.proto:13-16` with nothing
wired to them.

### 2.2 The capability is missing too

A route would not be enough; there is nothing behind it.

| Ice | Note |
|---|---|
| `setState` — move, mute, deafen, suppress, priority-speaker a **live session** | `/v1/sessions` is read-only, and no `Move`/`Mute`/`SetState` RPC exists in any `.proto`. Moderating a connected user is reachable only in-band from a Mumble client. For an external moderation bot — the thing this API exists for — that is the whole job |
| `startListening`, `getListeningUsers`, listener volume | channel listeners are unimplemented server-wide (`GAP-ANALYSIS.md` V5) |
| `verifyPassword`, `getCertificateList`, `updateCertificate` | no equivalent |
| `sendWelcomeMessage`, `redirectWhisperGroup` | no equivalent |
| `getChannelsForSession`, `getTreeForSession` | no per-session visibility view |
| `getAllServers`, `start`, `stop`, `newServer`, `getUptime`, `getVersion` | virtual servers are configuration here; there is no runtime lifecycle to drive |

### 2.3 Deliberately not coming back

Worth stating so nobody ports them out of completeness: `getSlice`,
`addCallback`/`removeCallback` (replaced by `/v1/events`), `setAuthenticator`,
and `get`/`setAssumedDatabaseState`.

---

## 3. Native Fancy subsystems

Starling implements natively what the fork implements natively — pchat with
reactions, audit, link previews, screen-share signalling, push, social, files,
context actions. The dividing line against §1 is exactly "was this a plugin in
the fork", which is a coherent place for a port to have got to.

They are not all *finished*, and the e2e sweep says which:

| Gap | Evidence |
|---|---|
| **Audit ingest fan-out is not wired.** Records are produced and never land | `audit-log` 1/9, whose own failure text is `server_audit has no rows - ingest fan-out not wired` |
| **pchat messages are not delivered.** The control plane answers; the message never arrives | `pchat` 0/1, `pchat-control-plane` 0/2, `signal-pchat` 3/4 |
| **Reactions never appear** on a message | `reactions` 0/1 |
| **Link previews are never produced** | `link-preview` 0/1 |
| **A channel cannot be deleted from the admin surface** | `admin-channel-delete` 0/1 |
| **Role creation half-works** | `admin-create-role` 2/4 |
| Screen-share **SFU** — signalling only, no `str0m` | `GAP-ANALYSIS.md` S2, fork's `WebRtcSfuManager.cpp` |

Six concrete defects. That is a list somebody can finish, which is why it is
worth separating from §1.

---

## 4. What is not Starling's to fix

**18 of the 54 e2e failures do not measure the server at all** — they wait on UI
the client does not render.

`forums` (0/10) waits for `chat-header-kebab`, which appears nowhere in the
client: it lives only in `ABSENT_FROM_CLIENT` in the harness's `src/selectors.ts`,
a list of 28 ids the suite references and the client never had. `meetings` (0/2)
and the four `calendar` files (0/6) fail the same way.

A further group is environmental rather than either: `channelviewer` needs its
own container and `camera-share` needs a camera. The three screen-share files
fail earlier than that, on a `screen-share-toggle` that never appears even
though the client does render one — a precondition, not a missing element, and
the one entry in this file whose cause is not yet established.

The honest consequence is that the plugin layer of §1 is missing at **both**
ends. A plugin host does not by itself make those tests pass.

---

## 5. What is built

Stated because a list of holes is not a description of a system, and because
this file is otherwise all holes.

Everything in `GAP-ANALYSIS.md` §8, plus: the Fancy wire epoch and its
negotiation (`PROTOCOL-COMPATIBILITY.md`), pchat's control plane and its
storage, context actions registered over the live channel, the operator API's
event stream with WebSocket and WebTransport transports, per-plugin namespaced
storage, push, social, the file service with signed URLs, link-preview
plumbing, screen-share signalling, and the account profile — comment and avatar
— now reaching every client that can see the user.

Against the fork's own e2e suite, 12 files are green end to end, including the
full signup path: register on the website, confirm by email, claim the Mumble
account, upload a picture, and have two live clients see it.

---

## Ordering, and why

1. **The plugin host** (§1). One subsystem, seven features, and the only item
   here that changes what the product *is*. Everything else is a defect.
2. **`setState` on a live session** (§2.2). An admin plane that can watch a user
   misbehave and do nothing about them is the gap an operator meets first.
3. **The four missing routes** (§2.1). Hours of work over RPCs that already
   work, and the ban one is a real hole in moderation today.
4. **The six native defects** (§3), cheapest first — audit fan-out names its own
   cause.
5. **Listeners** (`GAP-ANALYSIS.md` V5), which §2.2 also waits on.
