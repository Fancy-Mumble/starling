# Protocol compatibility

One rule, and it is the only hard one in this repo:

> **Never break a native Mumble client.** Everything else is negotiable.

"Native" means upstream `mumble-voip/mumble`, **not** `vendor/server`. The Fancy
fork's proto is 2137 lines against upstream's 639, and treating the fork as the
reference is how the drift below went unnoticed.

Anything outside the upstream surface may be renumbered, restructured or deleted.
Both ends of a Fancy conversation are ours.

---

## 1. Measured drift, fork against upstream

Compared against upstream `91fe75d5a` (Mumble 1.6.x, 2026-07-19), recovered from
the merge commit in `vendor/server` — there is no upstream remote configured.

**What is safe.** All 27 upstream messages are present; none removed. No upstream
field retyped or renumbered. And no `required` field was added to any upstream
message — all 15 new `required` fields live in new Fancy messages, where an
upstream client never looks. So the fork is wire-compatible with upstream *today*.

**What is not.** Seven of the nine extended upstream messages took upstream's
*immediate next* field numbers:

| message | upstream's max | Fancy took | |
|---|---|---|---|
| `TextMessage` | 5 | 6, 7, 8, 9, 10 | squats |
| `ACL` | 7 | 8, 9, 10, 11 | squats |
| `UserList` | 4 | 5, 6, 7 | squats |
| `ServerConfig` | 7 | 8, 9 | squats |
| `UserState` | 23 | 24 | squats |
| `RequestBlob` | 3 | 4 | squats |
| `Version` | 5 | 6 | squats |
| `Authenticate` | 6 | 100 | safe |
| `ChannelState` | 13 | 100–111 | safe |

Upstream's next `TextMessage` field *will be* 6. When that happens two different
meanings share one number, and proto2 resolves by number and type — so if both are
varint you get **silent misinterpretation**, not a parse error. That is the worst
failure class available: no log line, wrong data.

`ChannelState` and `Authenticate` show the discipline already exists. It was
applied inconsistently.

### The rule going forward

> **Upstream owns field numbers 1–99 in every upstream message. Fancy fields
> start at 100.**

Starling implements this from day one. `vendor/server` and `vendor/client` need
the seven messages above renumbered — a coordinated break affecting Fancy clients
only, which converts a permanent silent risk into one migration.

## 2. Message types: today's numbering cannot be routed

The TCP frame is `type: u16 ‖ len: u32 ‖ payload`. The wire allows 65 536 types.
Note that `vendor/server`'s `enum class TCPMessageType : byte`
(`MumbleProtocol.h:135`) caps the C++ at 255 and is already at 201 — about 54
left there, though Starling is Rust and unaffected.

The real problem is that the existing Fancy range is **interleaved, not blocked**:

```
100-119  pchat
120      WebRtcSignal        <-- wedged inside pchat's range
121      pchat
122-123  push
124      custom reactions
125      push
126-127  read receipts
128-130  pchat pins          <-- pchat again
131      typing
...
```

A range route such as `{ from = 100, to = 199 }` for pchat would capture
`WebRtcSignal`, push, reactions and typing along with it. Range-based routing
cannot be retrofitted onto this.

## 3. The scheme: one outer type per service

Upstream types stay flat and frozen. Every Fancy service gets **one** outer type,
and its payload is a service-owned envelope with its own `oneof`:

```protobuf
// proto-fancy/pchat.proto — owned entirely by the pchat service
message PchatEnvelope {
  oneof body {
    PchatMessage     message      = 1;
    PchatFetch       fetch        = 2;
    PchatKeyAnnounce key_announce = 3;
    // unbounded; adding one touches nothing outside this file
  }
}
```

| Range | Use |
|---|---|
| **0–99** | upstream Mumble, flat, **frozen** (0–26 in use) |
| **100–999** | **burned.** Shipped in released Fancy clients with the interleaved layout above. Never reused, so a stale client's message can never land on a new service |
| **1000+** | one outer type per service, nested envelope |

### Why nesting rather than blocks of 100

* **unbounded types per service** — no block size to guess wrong
* **one routing line per service**, so the gateway config stays trivial
* **no central registry.** With a flat space every new message type edits a shared
  enum, which is coordination between teams. Here a service's types are private
* **it costs nothing.** The gateway forwards verbatim either way, and the service
  was decoding protobuf regardless; the `oneof` tag is one extra varint

The cost is that a capture shows `type 1002`, not `PchatMessage`. The inner tag is
the payload's first field, so tooling recovers the name with one nested read.

### Assignments

| Type | Service |
|---|---|
| 1000 | session-lifecycle (Fancy extensions only; 0–26 stay flat) |
| — | session-view has **no** client-facing type: internal by construction |
| 1001 | permissions |
| 1002 | metadata |
| 1003 | userdata — including account settings |
| 1004 | voice |
| 1005 | text |
| 1006 | pchat |
| 1007 | moderation |
| 1008 | screenshare |
| 1009 | files / http |
| 1010 | plugins |
| 1011 | push |
| 1012 | audit |
| 1013 | server-config — runtime-mutable operational settings |
| 1014 | onboarding |
| 1015 | social |
| 1016 | link-preview |
| 1017 | context-actions |

New service: take the next number, add a TOML block, ship. No gateway release.

## 4. Enum and `oneof` hazards in proto2

`Mumble.proto` is `syntax = "proto2"`, which changes two things people expect from
proto3:

* **enums are closed.** An unrecognised value does not round-trip as the enum; it
  lands in unknown fields. Adding a value to an *upstream* enum (as the fork did
  with `CHANNEL_ATTRIBUTE_STRUCTURAL = 6`) is safe only because the field carrying
  it is itself a Fancy field at 110 that upstream ignores wholesale
* **`required` is permanent.** A `required` field added to an upstream message
  would make upstream clients fail to parse it outright. The fork has not done
  this; it must stay that way

## 5. Enforcement

`scripts/check-proto-drift.sh` currently asserts that Starling's proto matches
`vendor/server`'s, describing the fork as "upstream's source of truth". It is not
— it is the fork. That check has been verifying Fancy-consistency and saying
nothing about Mumble compatibility.

It needs to become two checks with two meanings:

1. **compatibility** — upstream messages, field numbers 1–99, against
   `mumble-voip/mumble`. A failure here is a released-client break
2. **consistency** — everything else, against `vendor/server` and
   `vendor/client`. A failure here is a coordination bug between our own trees

Plus a third that would have caught this class years earlier:

3. **no Fancy field below 100** in any upstream message
