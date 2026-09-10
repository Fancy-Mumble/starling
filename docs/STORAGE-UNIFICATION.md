# Storage unification plan

One object store and one record store, and every kind of document — a chat
attachment, an emote, a live document and its revisions, a user's document
library, a calendar — expressed as a namespace over those two. Nothing here is a
new storage engine; the two primitives already exist in this tree and are
already portable across the three backends. What is missing is reach: the
consumers cannot get at them, so each grew its own store.

Companion to `STORAGE.md`, which this extends rather than replaces. Every
"today" claim below was read from the tree on 2026-09-09, not remembered.

**Status, 2026-09-09.** Phases 1, 2, 3 and 5 are built and green; §4 records
what each landed as, including the three places the plan was wrong. Phase 4 -
deleting the client's plugin transport - is deliberately not done: everything
above it *prefers* the server's own stores and falls back to the plugin, so a
server still running the plugin keeps working, which is what the "loadable for
one more release" line in phase 5 promises. Deleting the fallback is a
separate, reviewable change.

---

## 1. Where documents live today

Five stores, in three processes' worth of code, for what the user experiences as
one feature: "the server keeps my stuff".

| # | Store | Owner | Backing | Shape |
|---|---|---|---|---|
| 1 | `files` | Starling service | `object` table in `files.sqlite`; bytes under `data_dir/files/{channel}/{id}/{name}` (`services/files/src/lib.rs:872`) | channel-scoped objects, server-minted key, three visibilities, TTL, uploader, "my files", operator view, signed URLs, HTTP data plane (`http.rs:68-69`) |
| 2 | `userdata` | Starling service | `blob(hash, bytes, refs)` and `account_setting(server_id, account_id, k, v TEXT)` (`services/userdata/src/accounts.rs:65-71`) | content-addressed blobs keyed by the wire SHA-1 (`STORAGE.md` L4); a per-account string map, written whole by `Update` field `"settings"` (`accounts.rs:689`) |
| 3 | plugin KV | Starling runtime | `plugin_kv(plugin_id, server_id, k, v)` (`runtime/src/storage/kv.rs:24`) | ordered KV, atomic batch, per-plugin namespace — `STORAGE.md` §5.4 as designed |
| 4 | `fancy-file-server` | fork plugin, loaded as a cdylib | its own `storage_path`: `metadata.db` with `files`, `emotes`, `documents`, `document_revisions`, `document_acl`, `private_storage`; `blobs/`; `doc-revisions/`; `signing.key` | files with signed URLs and a pre-auth ticket, emotes with bytes in the row, revisioned documents behind an admin token, a per-user private KV at `/me/storage` |
| 5 | `fancy-audit` | fork plugin | its own SQLite | audit rows — the pattern `STORAGE.md` L5 calls "the file-server storage pattern" |

Two facts about this table decide the plan.

**Store 3 is unreachable.** The `plugins` service serves `kv_get` / `kv_scan` /
`kv_write` over gRPC to operators (`services/plugins/src/lib.rs:392-426`) and
uses the table itself for `plugin.<name>.*` config. A plugin cannot call it:
the native `HostBridge` offers `get_config` and nothing else storage-shaped, and
the WASM `host` interface (`plugin-host/wit/world.wit:70-115`) has no `kv-*`
at all. `STORAGE.md` §5.1's "Nothing" is still the truth for a plugin; §5.4 was
designed and its table was built, and the API between them was never wired.
That single gap is why store 4 exists — live-doc persists its documents by
HTTP-ing to a *sibling plugin* with a bearer token (`plugins/live-doc/src/persistence.rs:238-347`)
because the server it lives in gives it nowhere to write.

**Store 1 has one producer.** Its charter (`SERVICES.md` §6.3) lists shared
files, avatars, comments, plugin binaries, preview thumbnails and audit exports.
`grep FilesClient crates/services` finds no caller outside `files` itself. Only
the client's canon attachment path uses it. The service is finished and
under-used; everything else went to store 4 or nowhere.

### 1.1 Who reads and writes what

| Consumer | Today | Store | Reach |
|---|---|---|---|
| chat attachments, canon server | `starling_upload_file` … `starling_media_url` (`ui/src/core/features/chat/starlingFiles.ts`) | 1 | client, 1009 envelope |
| chat attachments, plugin server | `fileserver_*` + `download_file` (`mumble-tauri/src/state/file_server.rs`) | 4 | client, HTTP + JWT |
| custom emotes | `add_custom_emote` / `remove_custom_emote`, `GET /emotes` | 4 | client, HTTP; canon answers "Unknown · no answer yet" |
| live-doc snapshots + revisions + share list | `PUT/GET /admin/documents/{name}`, `/shared-with` | 4 | **plugin → sibling plugin**, admin token |
| document library index | `/me/storage/livedoc-sidebar` | 4 | client, JWT, registered only |
| master source list | `/me/storage/livedoc-sources-master` | 4 | client, same |
| calendar | `/me/storage/calendar` (`calendar/src/lib.rs:3`) | 4 | client, same |
| avatars, comments | `PutBlob` / `GetBlob` | 2 | internal gRPC |
| account settings | `Update` field `"settings"` | 2 | internal gRPC; the client's account-settings message carries name/email/password/TOTP, not keys |
| "my shared files", operator file view | canon branch and plugin branch, one behind the other | 1 or 4 | `fileServerKind` decides, in eleven files |
| audit rows | own SQLite | 5 | plugin, direct |

The client carries the cost of the split in plain sight: `fileServerKind`
branches in `useFileUpload.ts`, `FileShareDialog.tsx`, `MySharedFilesPanel.tsx`,
`MySharedFilesTable.tsx`, `fileServerMe.ts` (×3), `fileServerAdmin.ts` (×2),
`ChatView.tsx`, `NebulaClientApp.tsx`, and a synthesised `fileServerConfig`
(`starlingFiles.ts:236`) that reports `registered: false` for everybody because
nothing on a canon server was ever asked. The bug that opened this work — a
registered user told to register — was that line.

### 1.2 What each kind of document actually needs

Strip the consumers to their requirements and only two shapes remain.

| Need | Attachments | Emotes | Live-doc snapshots | Library / sources / calendar | Avatars |
|---|---|---|---|---|---|
| large, ranged, streamed | yes | no (≤ MB) | sometimes | no (≤ 1 MiB, the plugin's own cap) | no |
| reachable by a plain `<img>` / `<video>` | yes | **yes** | no | no | no |
| a name that can be overwritten | no | yes | **yes, with history** | yes | no |
| per-channel permission | yes | no (server-wide, `ManageEmotes`) | no (document ACL is the plugin's) | no | no |
| per-account private | no | no | no | **yes, registered only** | n/a |
| written by | client | client | **plugin** | client | client |
| atomic multi-key | no | no | no | no | no |

Two shapes:

* **Object** — bytes, possibly large, served over HTTP with a signature, under a
  key. Store 1 is this, and is good at it.
* **Record** — a small value under a name, overwritten in place, read back by
  name, optionally in an atomic batch. Stores 2 (`account_setting`) and 3
  (`plugin_kv`) are this, with the same `(scope, k, v)` primary key and the
  same range-scan access path.

Emotes and live-doc snapshots straddle: an emote is an *object* with a *name*;
a snapshot is an object with a name and a history. So the object store needs
names. Nothing needs a third primitive.

---

## 2. Design

### D1, Two primitives, one rule

Bytes go to `files`. Names go to a record store. A named object is a record
whose value is an object key.

| Primitive | Service | Table | Namespaces |
|---|---|---|---|
| objects | `files` | `object` (exists) | `{channel}/…` (exists, unchanged), `u/{account}/…`, `s/…`, `p/{plugin}/…` |
| records, per account | `userdata` | `account_setting` (exists) | one per account, registered only |
| records, per plugin | `plugins` | `plugin_kv` (exists) | one per plugin, implicit |
| names over objects | `files` | `name` (new, §2.3) | the same four |

The record stores are not merged into one table. `STORAGE.md` §4 decided each
service owns its schema and no service reads another's tables; `userdata`
answers for accounts and `plugins` for plugins, and the two never need a join.
What is unified is the *shape* and the client-facing contract, not the file on
disk.

### D2, Object namespaces are key prefixes, and the old keys are the channel namespace

Today's key is `{channel}/{id}/{name}` and `channel_of(key)` reads the first
component to know which channel's `Enter` to check (`lib.rs:118-133`). That
stays exactly as it is: every existing key remains valid and every existing
permission check unchanged.

New namespaces prefix with a letter, which no channel number starts with:

| Prefix | Namespace | Write needs | Read needs |
|---|---|---|---|
| `{channel}/` | channel attachment | `ShareFiles` in the channel (as today) | `Enter` in the channel (as today) |
| `u/{account}/` | per-account private | being that account | being that account; `ResetUserContent` on root for an operator |
| `srv/` | server-wide named | a permission named per sub-namespace — `srv/emotes/` needs `ManageEmotes` on root | public, for the sections that must be |
| `p/{plugin}/` | plugin-owned | that plugin, through the host facade only | that plugin only |

**`srv/` and not `s/`**, which is what this document first said. The data plane
has served public share links from `/s/{key}` since before namespaces existed,
so an object key beginning `s/` is routed to the share handler and answers
`405` to the upload meant to store it. Found by the emote test, which is the
only reason it is not a shipped bug.

`channel_of` becomes `namespace_of` returning an enum; the channel arm is the
existing parse. The data plane's `object_path` check (`http.rs:79`) already
refuses traversal; a letter prefix is one more path component.

### D3, Names are records that point at objects, and history is free

```sql
name(
  server_id  BIGINT      NOT NULL,
  ns         VARCHAR(190) NOT NULL,   -- 'u/42', 's/emotes', 'p/fancy-live-doc', or '{channel}'
  n          VARCHAR(190) NOT NULL,   -- the name inside the namespace
  rev        BIGINT      NOT NULL,    -- 1, 2, 3 … per (ns, n)
  k          VARCHAR(190) NOT NULL,   -- → object.k
  created_at_ms BIGINT   NOT NULL,
  PRIMARY KEY (server_id, ns, n, rev)
);
```

* **Put** = store an object, then insert `(ns, n, max(rev)+1, k)`. Two rows in
  one transaction, on one service's connection.
* **Get latest** = the highest `rev` for `(ns, n)`: a backwards range scan on
  the primary key, the same shape `STORAGE.md` L3 made fast.
* **Revisions** = the range. Live-doc's `documents` + `document_revisions`
  tables are exactly this pair and collapse into it.
* **Overwrite without history** (emotes, private records) = the same put, plus a
  retention rule per namespace: `s/emotes/` keeps one revision and forgets the
  object behind the old one; `p/…` keeps what the plugin asks for.

The `object` row is unchanged; a name is a second way to reach it. An object
with no name and no channel listing is the same orphan the collector already
sweeps (`collect_expired`).

### D4, Records reach the client through `userdata`, not through `files`

The library index, the master source list and the calendar are 2–1024 KiB of
JSON that a client wants to read on connect and write on every edit. Signing a
URL and moving them over HTTP is the plugin's design, and it is the wrong tool:
`account_setting` is already the per-account `(k, v)` map, already persisted
write-behind, already scoped by `(server_id, account_id)`.

Three arms on the `userdata` envelope (outer type 1003, `fancy/domain.proto`;
"adding an arm touches one file and no registry", `PROTOCOL-REDESIGN.md` §rules):

```proto
message RecordGet   { string request_id = 1; string key = 2; }
message RecordPut   { string request_id = 1; string key = 2; bytes value = 3; }
message RecordList  { string request_id = 1; string prefix = 2; }
message Record      { string request_id = 1; string key = 2; bytes value = 3;
                      bool found = 4; uint64 updated_at_ms = 5; }
message RecordKeys  { string request_id = 1; repeated string keys = 2; }
```

Rules, so this cannot become a second file store:

* The account is the caller's own, always. There is no `account_id` field to
  send; a guest gets `Refused` with the reason the client already knows how to
  show (`liveDoc.sidebar.guestHint`, now honestly).
* `value` is capped at 1 MiB, the plugin's `MAX_PRIVATE_BYTES`, so nothing that
  works today stops working and nothing that should be an object sneaks in.
* Keys are namespaced by the client feature (`livedoc/sidebar`,
  `livedoc/sources`, `calendar`), which is a convention, not a schema.
* `account_setting.v` is `TEXT`; on MySQL that is 64 KiB, so the migration for
  this phase makes it `MEDIUMTEXT` there. SQLite and PostgreSQL are unaffected.

### D5, Plugins reach both primitives through the host, and never through a sibling

`STORAGE.md` §5.4, delivered: `kv_get` / `kv_scan` / `kv_write` on the native
`HostBridge` and as `kv-*` imports in `world.wit`, forwarding to the same
`KvStore` the operator RPCs already use, with the plugin id supplied by the host.
This is the piece that was designed, built underneath, and never connected. It
is also the piece that makes a WASM plugin able to persist a byte, which
`STORAGE.md` §5.1 flags and which every plugin above the greeter needs.

Objects for plugins ride the pattern clients use, so there is one data plane:

```
object_grant(ns_name, method, size) -> Grant      // host mints a signed URL in p/{plugin}/
object_stat(name) -> option<ObjectInfo>
object_forget(name)
name_put(n, key) / name_latest(n) / name_revisions(n, limit)
```

The plugin moves bytes over HTTP to the `files` listener — loopback, same
process, the URL already signed for its own namespace. No admin token, no
`file_server_url` to configure, no second plugin to keep alive. `files` learns
nothing about what a live document is; it stores `p/fancy-live-doc/<DocKey>`
and answers for its name.

The document share list (`document_acl`) is live-doc semantics — who may open a
document is not a question `files` should be able to answer — so it moves to
live-doc's own `plugin_kv` namespace, under a key the plugin chooses. The host
stays opaque (`STORAGE.md` L6).

### D6, The client has one file implementation

With D2–D5 in place a canon server does everything the plugin did, and the
client's plugin path has no reason to exist. `fileServerKind` goes; the eleven
branches go; `state/file_server.rs` and `state/emotes.rs` go; `fancy-file-server-config`
plugin-data is no longer awaited, and `fileServerConfig` is derived from
`ServerConfig` plus the session's own registration — which is what the sidebar
fix already does for its one flag, and should be the rule for all of them.

Emotes on a canon server: a listing of `s/emotes/` names with their public
URLs, sent on connect and on change, replacing the `fancy-server-emotes`
broadcast. Emotes are stored `VISIBILITY_PUBLIC` because an `<img>` cannot sign
a request; a server that wants them private has the same choice it has today,
which is none.

---

## 3. What moves where

| Consumer | From | To | Phase |
|---|---|---|---|
| library index, master sources, calendar | plugin `/me/storage` | `userdata` records (D4) | 1 |
| plugin config, audit rows, anything a plugin persists | own SQLite / nowhere | `plugin_kv` via host (D5) | 2 |
| live-doc snapshots and revisions | plugin `/admin/documents` | `files` `p/fancy-live-doc/` + `name` (D3, D5) | 3 |
| live-doc share list | plugin `document_acl` | live-doc's `plugin_kv` | 3 |
| custom emotes | plugin `emotes` table | `files` `s/emotes/` + `name`, public | 3 |
| chat attachments on a plugin server | plugin `/files` | `files` `{channel}/` (exists) | 4 |
| "my files", operator file view | two branches | the canon branch (exists) | 4 |
| avatars, comments | `userdata.blob` | unchanged | — |
| plugin binaries, thumbnails, audit exports | not stored | `files` `s/…`, when each producer arrives | later |

---

## 4. Phases

Each phase ships on its own, leaves the tree green on all three backends, and
removes something. Order is by value over cost: phase 1 alone closes the bug
that opened this document.

### Phase 1 — Records for clients (`userdata`)

* `RecordGet` / `RecordPut` / `RecordList` on 1003; handler in `userdata`
  reading and writing `account_setting`; guest refused; 1 MiB cap; MySQL
  `MEDIUMTEXT` migration.
* Client: `sidebarStore`, `liveDocMasterSourcesStore`, `calendarSync` gain a
  records backend and prefer it whenever the server offers 1003 records; the
  plugin backend stays behind them until phase 4.
* Server info: "File sharing · built-in service" stops implying "no private
  storage".
* Tests: the `userdata` service tests for refusal, cap, overwrite and list;
  the client's `LiveDocSidebarStoreLoad.test.ts` shape, once more, against the
  records backend.

Removes: the last reason a registered user on a canon server sees a warning.

### Phase 2 — Records for plugins (`plugins`)

* `kv_get` / `kv_scan` / `kv_write` on `HostBridge`, forwarded to `KvStore`
  with the plugin id from the host; `kv-get` / `kv-scan` / `kv-write` in
  `world.wit`, mirrored in `wasm.rs`.
* `fancy-audit` moves off its own SQLite onto the KV — the worked example in
  `STORAGE.md` §5.6, with its five secondary indexes as key ranges.
* Tests: a plugin cannot read another's key; a batch is all-or-nothing; the
  same five queries against SQLite, PostgreSQL, MySQL.

Removes: `Connection::open` from every plugin, and the WASM persistence gap.

### Phase 3 — Named objects (`files`)

* `namespace_of`, the `u/`, `s/`, `p/` prefixes and their permission rows
  (D2); the `name` table and put/latest/revisions (D3); the object and name
  host-facade calls (D5); per-namespace retention.
* live-doc: `persistence.rs` rewritten against the facade; `file_server_url`
  and `file_server_admin_token` deleted from its config; share list to KV.
* Emotes: `s/emotes/` writes gated on `ManageEmotes`; a listing arm on 1009
  replacing `fancy-server-emotes`.
* Tests: a name resolves to its latest; revisions are ordered and bounded; a
  plugin cannot mint a grant outside `p/{itself}/`; an emote is fetchable with
  no signature and nothing else in `s/` is.

Removes: the plugin-to-plugin HTTP hop, the admin token, and the reason
live-doc documents vanish on a server without the file-server plugin.

### Phase 4 — One client *(not done, deliberately)*

Everything above prefers the server's own stores and keeps the plugin as a
fallback, so a server still running it keeps working. Deleting that fallback is
what this phase is, and it is a separate change somebody should be able to
review on its own rather than find inside a storage migration.

* Delete the plugin attachment path, the emote commands, `fileServerKind`
  and its branches; derive `fileServerConfig` from canon facts.
* The two e2e tests skipped as "client does not receive
  fancy-file-server-config" (`fileserver.multiclient.test.ts`,
  `friend-chat-file-upload.multiclient.test.ts`) come back against the canon
  path, which is the path they will run in production.

Removes: roughly the whole of `state/file_server.rs`, `state/emotes.rs`, and
the second implementation of every file surface in the UI.

### Phase 5 — Migration and retirement

* `starling migrate-fileserver --from <storage_path>`: reads the plugin's
  `metadata.db`, `blobs/` and `doc-revisions/`, writes objects, names, records
  and the live-doc share list. The five rules of `STORAGE.md` §4 apply
  unchanged: read-only on the source, `--verify` counts both sides,
  idempotent upserts, loud about the unmappable, per-tenant. The plugin's
  `private_storage` rows are keyed by a `<server_id>:<user_id>` scope string
  (in a column still called `cert_hash`), which maps straight onto
  `(server_id, account_id)`.
* `fancy-file-server` marked superseded in the marketplace, loadable for one
  more release for anyone mid-migration, then dropped from the plugin-host
  tree.

---

## 4.1 What was built, and where this plan was wrong

Three things the plan asserted turned out not to survive contact with the tree.
They are recorded here rather than quietly corrected, because each was found by
a test that would otherwise have been a shipped bug.

**`srv/` and not `s/`.** §2's namespace table said `s/`. The data plane has
served public share links from `/s/{key}` since long before namespaces, so an
object key beginning `s/` routes to the share handler and answers `405` to the
upload meant to store it. The emote test caught it.

**64 KiB records, not 1 MiB.** §D4 borrowed the plugin's ceiling. `TEXT` and
`BLOB` hold 64 KiB on MySQL, and the portable-SQL rule (`STORAGE.md` D3) rules
out the `MEDIUMBLOB` that would lift it — the existing `blob.bytes` column
already lives with that limit. A record past the ceiling is refused with the
number in the message rather than truncated.

**`account_setting` was never a store.** §1 listed it as one. It has existed
since the first migration and nothing has ever written a row to it: account
settings live in memory and are lost on restart. That is a separate latent bug,
untouched here; the record store deliberately does not repeat it, and has a
test that reopens the database to prove a record outlives the process.

What each phase landed as:

| Phase | Landed | Evidence |
|---|---|---|
| 1 | `RecordGet/Put/List` + `Record`/`RecordKeys` on 1003; `account_record`; client prefers records for the library, source list and calendar | 15 store tests, 8 envelope tests, 5 client codec tests, 12 sidebar tests |
| 2 | `kv_get`/`kv_scan`/`kv_write` on the native facade and in `world.wit`; `StarlingBridge` implements them over the existing `plugin_kv` | all 8 in-tree plugins and 6 published examples rebuilt and loading |
| 3 | `namespace.rs`, `names.rs`, `Reserve` + 5 name RPCs, emotes on 1009, live-doc off the sibling-plugin hop | plugin object round trip, 6 emote tests, 6 `host_store` tests |
| 5 | `starling migrate-fileserver`, carrying `private_storage` into `account_record` | run against a real plugin database: mapped, verified, and idempotent on a second run |

Both ABI versions moved, and both gates are tripwires that had to be edited by
hand: native `PLUGIN_ABI_VERSION` 3 → 4, WASM 2 → 3. Every compiled plugin must
be rebuilt against them, which is the cost the one-bump-for-two-phases ordering
was chosen to pay exactly once.

The migration carries private records only. Emotes, documents and shared files
are counted and named in its report rather than silently skipped: their bytes
are sealed under the plugin's own signing key, so carrying them means re-signing
what it stored, and a migration that silently dropped them would be worse than
one that says it did not try.

---

## 5. What this deliberately does not do

* **No shared table across services.** `STORAGE.md` §4's per-service ownership
  stands; the unification is of shape and contract.
* **No third primitive.** Everything above is an object or a record. A request
  for something else is a request to re-read §1.2.
* **No new encryption story.** Password shares are sealed as today
  (`files/src/crypto.rs`); records are plaintext server-side, as the plugin's
  were. End-to-end encryption of a user's library is a client concern and a
  different document.
* **No change to avatars.** `userdata.blob` is keyed by the wire SHA-1 for the
  reason L4 gives, and nothing here needs it to be anything else.

---

## 6. Open questions

1. **Does 1003 carry records, or does 1009?** D4 puts them on `userdata` because
   the table is there and the scope is the account. The counter-argument is
   that a client already thinks of "my stuff" as files. Either is one arm; the
   deciding fact is that `files` should never need to know what an account is
   beyond an uploader id, and records are entirely about the account.
2. **Emote visibility.** Public by necessity (`<img>`), which means an emote URL
   leaks past the server's membership. Same as today; worth saying out loud in
   the operator docs.
3. **Retention for `p/`.** A plugin that keeps every revision forever is a
   plugin that fills the disk. The host should impose a per-plugin ceiling
   from `[services.plugins.options]` and refuse a put past it with the number
   in the refusal, the way `files` refuses an upload past `max_upload`.
4. **`FANCY-PARITY.md` §1 is stale.** It says Starling has no plugin loader;
   it has had one since the cdylib host landed. A parity row for "plugin
   storage" should replace it, and this document is what that row points at.
