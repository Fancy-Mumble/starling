# Storage design

Decisions taken: **greenfield schema plus a migration tool**, SQLite + PostgreSQL
+ MySQL, multi-tenant retained, the event log stays behind `LogSink`, and
**speed is the top priority**.

This document records what we learned from murmur's schema, from the Fancy
plugin ecosystem, and from the client, and what the greenfield design does
differently because of it.

---

## 1. What the existing implementations taught us

Every item below was measured in this tree, not assumed.

### L1, Entity-attribute-value property tables

`UserPropertyTable` and `ChannelPropertyTable` are both
`(server_id, owner_id, key INTEGER, value TEXT)`.

`ChannelProperty.h` lists twelve keys: `Description, Position, MaxUsers,
PChatProtocol, PChatMaxHistory, PChatRetentionDays, PChatKeyCustodians, Hidden,
ExpiryMode, ExpiryDuration, CreatedAt, Structural`. Eight of those are integers
or booleans, stored as `TEXT` and re-parsed on every load.

Loading a 500-channel tree is therefore up to 6 000 row reads and 6 000 string
parses, to produce data that fits in a few hundred kilobytes.

**Greenfield:** typed columns. A channel is one row.

### L2, Almost no indexes

Index declarations across the whole schema:

| Table | Indexes |
|---|---|
| `UserTable` | 2 |
| `ACLTable` | 0 |
| `ChannelTable` | 0 |
| `ChannelPropertyTable` | 0 |
| `UserPropertyTable` | 0 |
| `PChatMessageTable` | **0** |
| `GroupMemberTable` | 0 |

**Greenfield:** every table carries the composite index its actual query shape
needs, and the query shapes are written down next to them.

### L3, The worst query in the system

`PchatFetch` (`Mumble.proto:840`) paginates with `before_id` / `after_id`, which
are **UUID strings**. `PChatMessageTable` stores `message_id` as `TEXT`, with no
index, in the only table that grows without bound.

Two query shapes hit this table, and murmur serves both with a full scan:

| Trigger | Request | What it needs | What murmur does |
|---|---|---|---|
| User opens a channel | `before_id=None, limit=50` | newest 50 in channel C | full scan + sort |
| User scrolls back | `before_id=<uuid>` | 50 before cursor X in channel C | scan to find X, then scan again |

The second is the worse one, an unindexed `TEXT` UUID lookup on the largest
table in the system, at exactly the moment that table is largest.

The client mitigates but does not avoid this. It caches per session
(`VolatileMessageProvider`, a `HashMap`; plus an `EncryptedFileProvider` that can
offload to disk) and guards with a `fetched_channels` set, so it fetches **once
per channel per connection**, but that set is per-connection state, so every
reconnect pays the initial fetch again for every channel the user visits.

**Greenfield:** UUIDv7 stored as `BLOB(16)`, primary key
`(server_id, channel_id, id)`. Because UUIDv7 is time-ordered, that key is
*physically* ordered by tenant → channel → time, so **both** shapes become one
index range scan, newest-50 is a backwards scan from the end of the channel's
range, and scroll-back is a backwards scan from the cursor. No sort, no secondary
lookup, and inserts append at the end of the index instead of scattering like
UUIDv4. 16 bytes instead of 36.

The wire type stays `string message_id`, so no protocol change.

### L4, Blobs are not content-addressed in storage

The protocol *is* content-addressed: `texture_hash` / `comment_hash` are sent,
and the client asks for the bytes with `RequestBlob` only when it lacks them.
Storage does not match, murmur hashes on the way in (`Server.cpp:2689`) but
keeps the bytes per user.

**Greenfield:** a `blob` table keyed by hash, with a refcount. Identical avatars
are stored once, and `RequestBlob` becomes a primary-key lookup.

### L5, The plugin ecosystem already solved this, better

`3rdparty/mumble-plugin-host/audit/src/store.rs` opens its own SQLite database
and creates:

```sql
CREATE TABLE server_audit ( id INTEGER PRIMARY KEY AUTOINCREMENT, server_id ...,
                            ts_ms INTEGER, ..., prev_hash BLOB, entry_hash BLOB );
CREATE INDEX idx_audit_server_ts       ON server_audit(server_id, ts_ms);
CREATE INDEX idx_audit_server_target   ON server_audit(server_id, target_user_id, ts_ms);
CREATE INDEX idx_audit_server_expiry   ON server_audit(server_id, expires_at_ms);
CREATE UNIQUE INDEX idx_audit_offset   ON server_audit(server_id, event_offset)
                                       WHERE event_offset IS NOT NULL;
```

Typed columns, composite indexes led by `server_id`, a retention column with an
index to sweep it, and a partial unique index for idempotency. This is the house
style the core never adopted, **so adopt it.**

The part to *not* copy: each plugin opens its own database file. That means N
connection pools, N `fsync` streams competing for the same disk, no transaction
spanning a plugin write and the server state it describes, and N things to back
up consistently.

**Greenfield:** one database, one pool. Plugins get a namespaced schema
(`plugin_<id>_*`) through an opaque storage capability, see L6.

### L6, Plugins must stay opaque, and that is a *schema* rule

From `HANDOVER-audit-opaque.md`: *"plugins must be fully opaque to the server,
the server may only shuttle opaque data and provide generic callbacks
(permissions, sessions, config), never know a plugin's name, message schema, or
feature semantics."*

That principle was applied to the wire protocol. It applies equally to storage:
**the core schema must contain no plugin-specific tables.** A plugin gets a
namespace and manages its own tables inside it; the server never names them.

### L7, The control plane is already RAM-resident

murmur loads the channel tree at boot (`initializeChannels`,
`initializeChannelDetails`, `initializeChannelLinks`, three passes) and keeps
ACLs in `AclSubsystem`'s in-memory cache, invalidated on change. The database is
never on a permission-check path.

That is correct, and Starling already works this way by construction
(`ChannelTree`, `Users` are in-memory). **Formalise it:** the database is a
durable record of the control plane, never a read path for it.

---

## 2. Design decisions

### D1, The database is write-behind, never in a request path

The core is a single actor; a synchronous query inside it stalls every session.
Writes leave as `Effect::Persist(DbOp)`, the shape `Effect::Log` already
proved, and a writer task batches them into one transaction per tick.

Consequences, stated plainly:

* Voice and chat never wait on `fsync`.
* Durability is bounded by the batch interval, not by the request. A crash loses
  at most one tick of control-plane changes, the same trade the log makes.
* The one read that cannot be deferred is authentication. Registered accounts are
  cached in memory at boot and maintained write-through, so `Authenticate` stays
  a pure, synchronous handler.

### D2, Boot loads the whole control plane in a fixed number of queries

Four, independent of channel count: channels, channel links, ACL entries +
groups, accounts. No per-entity property lookups, because there are no property
rows.

### D3, Portable SQL, verified not assumed

No vendor extensions, no `RETURNING`, no upsert syntax that differs across the
three. Transactions are retry-aware, because CockroachDB and TiDB hand back
retryable serialization errors under load. CI runs the compatibility suite
against SQLite, PostgreSQL and MySQL; a distributed engine is added to the matrix
before we claim it works.

### D4, Growth tables carry retention from day one

`pchat_message` and any plugin table that grows get an `expires_at_ms` column and
an index to sweep it, following the audit plugin's pattern. Retention is a schema
property, not an afterthought.

---

## 3. Schema sketch

Types shown as SQLite; the migration layer maps them per backend.

```sql
-- Tenancy ------------------------------------------------------------------
server(id INTEGER PRIMARY KEY, name TEXT, created_at_ms INTEGER)

-- Channel tree: one row per channel, typed ---------------------------------
channel(
  server_id INTEGER, id INTEGER, parent_id INTEGER NULL,
  name TEXT NOT NULL, description_hash BLOB NULL,     -- → blob(hash)
  position INTEGER NOT NULL, max_users INTEGER NOT NULL,
  flags INTEGER NOT NULL,                             -- hidden|temporary|detached|structural|inherit_acl
  expiry_mode INTEGER, expiry_duration_s INTEGER,
  created_at_ms INTEGER, last_active_ms INTEGER,
  PRIMARY KEY (server_id, id)
);
CREATE INDEX ix_channel_parent ON channel(server_id, parent_id);

channel_link(server_id, channel_id, linked_id, PRIMARY KEY (server_id, channel_id, linked_id));

-- Channel listeners: hearing a room without being in it ---------------------
-- Keyed by *account*, not session: the point of the table is that the listener
-- survives the visit. Guests therefore have none, and temporary channels are
-- never written here, the id is reused when the channel is collected, so a
-- restored row would subscribe the user to whatever room got the number next.
--
-- `enabled` rather than deleting the row, because the volume has to outlive
-- un-listening: a user who turns a room off and back on gets the level they
-- chose. No secondary index, the only query is "every listener of one account
-- on one server", and the primary key is a left prefix of exactly that.
channel_listener(
  server_id INTEGER, account_id INTEGER, channel_id INTEGER,
  volume_adjustment REAL NOT NULL,                    -- 1.0 is no adjustment
  enabled INTEGER NOT NULL,
  PRIMARY KEY (server_id, account_id, channel_id)
);

-- Accounts -----------------------------------------------------------------
account(
  server_id INTEGER, id INTEGER,
  name TEXT NOT NULL, email TEXT NULL,
  comment_hash BLOB NULL, texture_hash BLOB NULL,     -- → blob(hash)
  cert_hash BLOB NULL, password_hash BLOB NULL, kdf_iterations INTEGER,
  totp_secret TEXT NULL,                              -- never leaves the server
  created_at_ms INTEGER, last_active_ms INTEGER,
  PRIMARY KEY (server_id, id)
);
CREATE UNIQUE INDEX ux_account_name ON account(server_id, name);
CREATE INDEX        ix_account_cert ON account(server_id, cert_hash);   -- certificate auth

-- Content-addressed, deduplicated -----------------------------------------
blob(hash BLOB PRIMARY KEY, bytes BLOB NOT NULL, size INTEGER NOT NULL, refs INTEGER NOT NULL);

-- Authorisation ------------------------------------------------------------
acl(server_id, channel_id, priority, aff_account_id NULL, aff_group_id NULL,
    apply_here INTEGER, apply_sub INTEGER, granted INTEGER, revoked INTEGER,
    PRIMARY KEY (server_id, channel_id, priority));
group_(server_id, id, channel_id, name TEXT, inherit INTEGER, inheritable INTEGER,
    PRIMARY KEY (server_id, id));
CREATE INDEX ix_group_channel ON group_(server_id, channel_id);
group_member(server_id, group_id, account_id, is_add INTEGER,
    PRIMARY KEY (server_id, group_id, account_id));

ban(server_id, id, address BLOB, prefix_len INTEGER, reason TEXT,
    start_ms INTEGER, duration_s INTEGER, PRIMARY KEY (server_id, id));

-- Persistent chat: the only unbounded table --------------------------------
pchat_message(
  server_id INTEGER, channel_id INTEGER,
  id BLOB NOT NULL,                                   -- UUIDv7, 16 bytes, time-ordered
  sent_at_ms INTEGER NOT NULL, sender_hash BLOB, mode INTEGER,
  payload BLOB NOT NULL, payload_len INTEGER,
  supersedes BLOB NULL, superseded_by BLOB NULL,
  expires_at_ms INTEGER NULL,
  PRIMARY KEY (server_id, channel_id, id)             -- clustered by tenant→channel→time
);
CREATE INDEX ix_pchat_expiry ON pchat_message(server_id, expires_at_ms);

-- Plugin storage: namespaced, opaque to the core ---------------------------
-- Tables named plugin_<id>_*, created and owned by the plugin. The core never
-- names them (L6); it only grants a namespace and a connection.
```

`PRIMARY KEY (server_id, channel_id, id)` on `pchat_message` is the single most
important line in the schema, it turns the O(n) fetch of L3 into a range scan.

---

## 4. The migration tool

```sh
starling migrate-db --from sqlite:///data/mumble-server.sqlite \
                    --to   sqlite://starling-data/starling.db \
                    [--dry-run] [--server-id N] [--verify]
```

Requirements, in priority order:

1. **Non-destructive.** Reads murmur's database, never writes to it. The old
   server keeps working, which is what makes the greenfield choice safe.
2. **Verifying.** `--verify` re-reads both sides and compares row counts per
   entity plus a content sample. A migration you cannot check is a migration you
   cannot trust.
3. **Resumable and idempotent**, so a large pchat history can be migrated in
   passes and a failure does not mean starting over.
4. **Loud about what it could not map.** Every dropped or approximated value is
   reported, never silently discarded, the same rule the `.ini` reader follows.
5. **Per-tenant.** `--server-id` migrates one virtual server; omitted, it
   migrates all of them.

The interesting cases are EAV → typed columns (L1), where a malformed `TEXT`
value has no typed equivalent and must be reported, and TEXT-UUID → UUIDv7 BLOB
(L3), where existing UUIDv4 message ids are **not** time-sortable. For those, the
tool assigns UUIDv7 ids derived from the stored timestamp, preserving order, and
keeps a `legacy_id` mapping column so any client cursor still resolves.

---

## 5. Plugin storage

### 5.1 What exists today

Nothing. The plugin capability surface (`api/src/host_facade.rs`, and the WIT
`host` interface for WASM) offers sessions, channels, permissions, config and
messaging, **no storage of any kind**.

Native plugins work around it: `get_config("storage_path")` (audit
`lib.rs:528`), then `Connection::open(path)` with `rusqlite`. The audit plugin's
own comment calls this "the file-server storage pattern", so at least three
plugins do it.

WASM plugins cannot work around it. `host/src/wasm.rs:439` builds *"a
deliberately empty WASI context: no preopened directories"*, no filesystem, no
network, no environment. **A WASM plugin currently has no way to persist a single
byte.**

That gap becomes urgent the moment persistent chat becomes a plugin, because it
is the largest data owner in the system.

### 5.2 What plugin storage has to satisfy

| Requirement | Source |
|---|---|
| Host never learns a plugin's schema or semantics | L6 |
| Works for WASM plugins (no handles, no pointers, bytes across a WIT boundary) | `wasm.rs:439` |
| One database, one pool, one backup | L5 |
| Range scans fast enough for pchat's unbounded table | L3, "speed first" |
| Same behaviour on SQLite, PostgreSQL and MySQL | D3 |
| Multi-tenant scoping | decided |

### 5.3 Options

| | Own DB file (today) | **Ordered KV** | SQL passthrough | Declared schema |
|---|---|---|---|---|
| Works for WASM | no | yes | yes | yes |
| Host stays schema-blind | yes | yes | yes | partly, host sees columns |
| One database | no | yes | yes | yes |
| Fast range scans | yes | yes | yes | yes |
| Secondary indexes | free | **manual** | free | declared |
| Aggregates (`COUNT`) | free | **manual** | free | free |
| Backend-portability burden | host | **host** | **on the plugin author** | host |
| Sandboxing burden | n/a | none | high (`ATTACH`, `PRAGMA`, cross-namespace, DDL) | low |

**Recommendation: ordered, namespaced key/value with atomic batches.**

SQL passthrough is the tempting one; it is the most powerful, and executing
opaque SQL is philosophically identical to shuttling opaque messages. It loses on
two practical points: every plugin author would have to write SQL portable across
three dialects (or ship three variants), and the host would have to parse SQL to
enforce namespace isolation. Both taxes are permanent.

### 5.4 The API

```wit
// Added to the WIT `host` interface, and mirrored in the native facade.
kv-get:    func(scope: server-id, key: list<u8>) -> option<list<u8>>;
kv-scan:   func(scope: server-id, start: list<u8>, end: list<u8>,
                limit: u32, reverse: bool) -> list<tuple<list<u8>, list<u8>>>;
kv-write:  func(scope: server-id, ops: list<kv-op>) -> result<_, plugin-error>;
```

`kv-write` takes a **batch and applies it atomically**; that is what lets a
plugin keep its own secondary indexes consistent with its records, which is the
one thing KV genuinely costs it.

The plugin namespace is implicit: the host knows which plugin is calling and
scopes every operation to it. A plugin cannot name, or reach, another's data.

### 5.5 The backing table

One table, identical on all three backends:

```sql
plugin_kv(
  plugin_id  TEXT   NOT NULL,      -- supplied by the host, never by the plugin
  server_id  INTEGER NOT NULL,     -- multi-tenant scoping
  key        BLOB   NOT NULL,
  value      BLOB   NOT NULL,
  PRIMARY KEY (plugin_id, server_id, key)
);
```

A scan is `WHERE plugin_id = ? AND server_id = ? AND key >= ? AND key < ?
ORDER BY key [DESC] LIMIT ?`, an index range scan on the clustered primary key,
with no dialect-specific syntax.

### 5.6 Why this is not slower for pchat

The concern is obvious: pchat is the hot path, and KV sounds like a step down
from a dedicated table. It is not, because the winning access path was always
*"ordered range scan on a composite key"* (L3).

With key = `channel_id(8 bytes) ‖ uuidv7(16 bytes)`, the primary key
`(plugin_id, server_id, key)` is physically ordered plugin → tenant → channel →
time. That is the **same physical ordering** as the dedicated
`PRIMARY KEY (server_id, channel_id, id)` from §3, so both fetch shapes are the
same single range scan. The only overhead is the `plugin_id` prefix per row.

What KV genuinely costs, stated plainly:

* **Secondary indexes are manual.** The audit plugin has five (by time, target,
  actor, category, expiry). On KV those become additional key ranges the plugin
  writes itself (e.g. `\x01actor‖<actor_id>‖<uuidv7> → <primary key>`) kept
  consistent by the atomic batch. Standard KV practice, but it is real work and
  a real place to introduce bugs.
* **Aggregates are manual.** `PchatFetchResponse.total_stored` is a `COUNT`;
  on KV that is a maintained counter key, not a query.

Both are acceptable. Neither is free, and pretending otherwise would be the
wrong way to sell this.

### 5.7 The coupling to de-risk

Moving pchat to a plugin *and* putting plugin storage on KV are two bets landing
on the same feature at once. Before committing to both: implement pchat's exact
query shapes (newest-50, scroll-back, retention sweep, `total_stored`) against
the KV API and measure them against the §3 dedicated-table schema. If KV loses,
the fallback is to keep pchat core with its own table and give plugins KV
regardless, WASM plugins need it either way.

## 6. Open questions

1. **Persistent chat becomes a plugin** (decided 2026-07-25). The core schema
   therefore drops `pchat_message`, it moves to plugin storage (§5), subject to
   the measurement in §5.7. Core keeps config, tree, accounts, ACL, bans, blobs.
2. **How long is the write-behind batch interval?** It sets the durability window
   for control-plane changes. 100 ms is a reasonable default; it is a knob.
3. **Do we keep murmur's `Log` table at all?** The event log lives behind
   `LogSink`. A `DatabaseSink` can exist for parity, but it should not be the
   default.
