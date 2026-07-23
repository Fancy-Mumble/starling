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
the merge commit in `vendor/server`; there is no upstream remote configured.

**What is safe.** All 27 upstream messages are present; none removed. No upstream
field retyped or renumbered. And no `required` field was added to any upstream
message, all 15 new `required` fields live in new Fancy messages, where an
upstream client never looks. So the fork is wire-compatible with upstream *today*.

**What was not.** Seven of the nine extended upstream messages took upstream's
*immediate next* field numbers. Upstream's next `TextMessage` field *will be* 6.
When that happens two meanings share one number, and proto2 resolves by number
and type, so if both are varint you get **silent misinterpretation**, not a
parse error. That is the worst failure class available: no log line, wrong data.

Fixed in this repo's copy (2026-07-29) by moving the Fancy fields clear of
upstream, and moved again (2026-08-02) from 100+ to 1000+ so the margin is one
nobody has to re-check. All three trees hold the same numbers:

| message | upstream's max | originally | now |
|---|---|---|---|
| `TextMessage` | 5 | 6, 7, 8, 9, 10 | 1000-1004 |
| `ACL.ChanGroup` | 7 | 8, 9, 10, 11 | 1000-1003 |
| `UserList.User` | 4 | 5, 6, 7 | 1000-1002 |
| `ServerConfig` | 7 | 8, 9 | 1000, 1001 |
| `UserState` | 23 | 24 | 1000 |
| `RequestBlob` | 3 | 4 | 1000 |
| `Version` | 5 | 6 (+7) | 6 **pinned**, epoch at 1000 |
| `Authenticate` | 6 | 100 | 1000 |
| `ChannelState` | 13 | 100-111 | 1000-1011 |

Four things to know about that move:

* **`Version.fancy_version = 6` stays where it is.** It is the field every
  shipped Fancy peer reads to decide whether extensions exist at all. Moving it
  would not break loudly; it would make this server look like plain Mumble to
  all of them. It keeps its squat, and `fancy_protocol` (1000) is what carries
  the numbering forward.
* **`Version.fancy_protocol` moved with everything else, and that is the one
  genuinely hard break here.** It is read *before* any epoch is known, so its
  location cannot be negotiated, a peer built against the 100+ layout looks at
  field 100, finds nothing, and concludes it is talking to plain Mumble. That is
  the correct outcome (it would not have understood the rest either) but it is
  silent, so all three trees have to move in one release. They did.
* **The vacated numbers are not `reserved`.** Reserving them would stop this
  file adopting the upstream field that eventually lands there, which is the
  entire point of vacating them. Upstream owns them now.
* **This is part of epoch 1, not a separate break.** Epoch 1 has never shipped,
  so redefining what it means costs nothing; §2a's number stays `1`. Bumping it
  to `2` would buy nothing anyone can read: a peer on the old layout cannot find
  `fancy_protocol` at its new number to *see* the `2`, so the field's location
  is already the discriminator.

### The rule going forward

> **Upstream owns field numbers 1-999 in every upstream message. Fancy fields
> start at 1000.**

1-99 would have been enough for any plausible upstream, `UserState`, the
tightest message, was at 24 against a ceiling of 99. The larger margin is not
about upstream running out; it is about never having to make this judgement
again, and it is free: protobuf spends two tag bytes on everything from field
16 to field 2047, so 100 and 1000 encode identically.

All three trees (`starling`, `vendor/server` and `vendor/client`) implement
this and hold identical numbers. `scripts/check-proto-drift.sh` is what keeps
them that way.

## 2. Message types: today's numbering cannot be routed

The TCP frame is `type: u16 ‖ len: u32 ‖ payload`. The wire allows 65 536 types.
Note that `vendor/server`'s `enum class TCPMessageType : byte`
(`MumbleProtocol.h:135`) caps the C++ at 255 and is already at 201, about 54
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

## 2a. Epochs: how a peer says *which* numbering it speaks

The numbering above is not something a peer can infer. `Version.fancy_version`
is a **product** version (it answers "which features exist") and there is no
way to express "I renumbered the wire" in it. A client that reads only that
field will happily send a type the peer routes nowhere, and the message
disappears with nothing in any log. That is precisely what happened here:
Starling kept the upstream types and moved every Fancy message to §3's scheme,
and a client reading `fancy_version` would have gone on speaking §2's layout.

So `Version.fancy_protocol` (field 7, `uint32`) names the numbering itself:

| Epoch | Numbering |
|---|---|
| absent / `0` | The interleaved 100-999 layout in §2. Every Fancy build shipped to date, including `vendor/server`. |
| `1` | §3: upstream 0-99 flat and frozen, every Fancy service behind one outer type ≥ 1000. What Starling speaks. |

Three rules make it work:

* **A peer speaks exactly one epoch**, and states it. `vendor/server` sets `0`
  explicitly rather than relying on the default, so that "an old Fancy server"
  is distinguishable from "a server that has not been taught about epochs".
* **The epoch is read before the version.** A version only means something once
  both sides agree what the numbers on the wire are.
* **No agreement means plain Mumble**, plus anything relayable through
  `PluginDataTransmission`: that path is epoch-independent and works through
  any Mumble server, so typing, watch-sync, WebRTC signalling and pchat key
  distribution survive a mismatch. Everything `ServerOnly` does not.

**Starling therefore announces `fancy_protocol = 1` and no `fancy_version` at
all.** Announcing a product version would be actively worse than silence: a
client would take it as licence to send epoch-0 natives. With it absent, clients
fall back to `PluginDataTransmission`, which Starling relays correctly.

The client keeps the mirror of this in `mumble-protocol/src/fancy_codec.rs`
(`FANCY_PROTOCOL_EPOCH`, `speaks_epoch`), and announces its own epoch in the
`Version` it sends, so the judgement is symmetric.

### What the client encodes at epoch 1, a correction

An earlier version of this section claimed the client "can only encode epoch 0
today, so against Starling it degrades to the `PluginData` path". **That is
false, and dangerously so.** The client announces `fancy_protocol = 1`
(`fancy_codec.rs`, `FANCY_PROTOCOL_EPOCH`), selects its `NativeCodec` the
moment Starling's `Version` arrives, and frames every Fancy message under its
service's outer type, `message.rs`, the `fancy_services!` mapping. There is
no degradation and no honest split.

What it frames is the problem: the *payloads* are the proto2 envelope shapes
from this file's `Mumble.proto`, while Starling decodes the proto3 sets in
`crates/proto-fancy/proto/fancy/`. Same epoch, same outer types, different
inner schemas, the silent break documented as D1 in `PROTOCOL-REDESIGN.md`
§0, fixed by its migration step M2c (the client codec moves to the canon).
Until M2c lands, Fancy traffic between the client and Starling corrupts or
vanishes per message, with nothing above debug level in any log.

## 3. The scheme: one outer type per service

Upstream types stay flat and frozen. Every Fancy service gets **one** outer type,
and its payload is a service-owned envelope with its own `oneof`:

```protobuf
// proto-fancy/pchat.proto, owned entirely by the pchat service
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
| **0-99** | upstream Mumble, flat, **frozen** (0-26 in use) |
| **100-999** | **burned.** Shipped in released Fancy clients with the interleaved layout above. Never reused, so a stale client's message can never land on a new service |
| **1000+** | one outer type per service, nested envelope |

### Why nesting rather than blocks of 100

* **unbounded types per service**, no block size to guess wrong
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
| 1000 | session-lifecycle (Fancy extensions only; 0-26 stay flat) |
| | session-view has **no** client-facing type: internal by construction |
| 1001 | permissions |
| 1002 | metadata |
| 1003 | userdata, including account settings |
| 1004 | voice |
| 1005 | text |
| 1006 | pchat |
| 1007 | moderation |
| 1008 | screenshare |
| 1009 | files / http |
| 1010 | plugins |
| 1011 | push |
| 1012 | audit |
| 1013 | server-config, runtime-mutable operational settings |
| 1014 | onboarding |
| 1015 | social |
| 1016 | link-preview |
| 1017 | context-actions |

New service: take the next number, add a TOML block, ship. No gateway release.

### The message mapping

All 61 epoch-0 types have exactly one epoch-1 home. The **inner message keeps its
epoch-0 shape**, `FancyOnboardingConfig` at inner tag 1 of 1014 is byte-for-byte
the `FancyOnboardingConfig` that used to be outer type 136. Epoch 1 changes the
*framing* only, so no feature has to be redesigned to cross the epoch, and the
three implementations share one set of definitions in `Mumble.proto`.

Ten services carry client-facing traffic; the other eight own messages Starling
introduced natively and have no epoch-0 ancestor.

| Outer | Service | Epoch-0 types folded in |
|---|---|---|
| 1006 | pchat | 100-116, 121, 128-130, message/fetch/deliver, the key ladder, deletes, offline drain, pins |
| 1015 | social | 117-119 (reactions), 124 (custom reactions), 126-127 (read receipts), 131 (typing), 134 (watch sync), 135 (draw stroke), 144-145 (polls) |
| 1011 | push | 122-123, 125 |
| 1008 | screenshare | 120 (`WebRtcSignal`, screen and camera share both ride it) |
| 1016 | link-preview | 132-133 |
| 1014 | onboarding | 136-140 |
| 1010 | plugins | 146-151, plus the generic plugin relay at 200-201 |
| 1013 | server-config | 152-153 |
| 1003 | userdata | 154-156 (account settings + ack) |
| 1012 | audit | 166-168, 170-171 |

Two consequences worth stating, because both were live bugs before:

* **Reactions and pins split from pchat.** `PchatReaction*` are named for pchat
  but are reactions, which is the social service's job; `PchatPin*` stay in pchat
  because a pin is a property of the stored message. The name is not the owner.
* **`WebRtcSignal` is one type for two features.** It is screenshare's by
  assignment; camera share shares the type rather than getting its own, exactly
  as it did at 120.

### What is dropped with epoch 0

Fancy-to-Fancy backwards compatibility only. Specifically: the per-message
`min_version` gate, which existed so a new client could talk to an older Fancy
server, in epoch 1 both ends ship together and a Fancy peer speaks all of it or
none of it.

**Compatibility with upstream Mumble is untouched.** `PluginDataTransmission`
relaying is epoch-independent, so a Fancy client keeps working against a vanilla
server exactly as before, and every message keeps its `FallbackPolicy`. An
epoch-0 Fancy server is simply not a peer any more: `speaks_epoch` already
returns false for it, which selects that same plain-Mumble path. No compatibility
code is written for it, the existing epoch check is the whole mechanism.

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
 it is the fork. That check has been verifying Fancy-consistency and saying
nothing about Mumble compatibility.

It needs to become two checks with two meanings:

1. **compatibility**, upstream messages, field numbers 1-99, against
   `mumble-voip/mumble`. A failure here is a released-client break
2. **consistency**, everything else, against `vendor/server` and
   `vendor/client`. A failure here is a coordination bug between our own trees

Plus a third that would have caught this class years earlier:

3. **no Fancy field below 100** in any upstream message
