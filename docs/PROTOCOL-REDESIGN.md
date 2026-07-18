# Protocol redesign

> **Thesis: one canon per message, four layers with a strict import law, bytes
> that are sliced and refcounted but never copied, and a wire that a stock
> Mumble 1.5 client cannot tell from murmur.**

This document is normative for every tree that speaks the protocol —
`starling`, `vendor/client`, `vendor/server`. It builds on
`PROTOCOL-COMPATIBILITY.md` (numbering law, epochs) and `ARCHITECTURE.md`
(planes, services, shard keys); where those describe mechanism, this document
decides canon and adds the zero-copy and scaling contracts.

---

## 0. What this resolves

Four discrepancies, found by diffing all copies and then by starting the
migration (2026-08-03). The first is the one that corrupts data.

**D1 — epoch 1 is defined twice, incompatibly.** `Mumble.proto` (identical in
all three trees) defines proto2 envelopes — `PchatEnvelope`, `SocialEnvelope`,
… — whose arms are the epoch-0 messages byte-for-byte. Starling's
`crates/proto-fancy/proto/fancy/` defines proto3 envelopes of the same names
with redesigned, minimal messages. **Both claim outer types 1000+ and epoch 1.**
The client's `NativeCodec` encodes the proto2 cut; Starling's pchat and social
services decode the proto3 cut. On a pchat message, inner field 3 is a
`timestamp` in one and a `sender` in the other; field 4 a `sender_hash` string
in one and `ciphertext` bytes in the other. Where the wire types happen to
agree — and varint/varint and string/bytes both do — this parses
"successfully" into garbage: the `timestamp` truncates into `sender`, the hash
becomes the ciphertext. Where they disagree, or non-UTF-8 ciphertext lands on
a proto3 `string` (field 6, `envelope` → `supersedes`), the decode errors and
the frame is dropped at debug level. Corrupt or vanish, per message — both
silent, which is the failure class `PROTOCOL-COMPATIBILITY.md` §1 exists to
prevent.

**And the split ran through Starling itself**, which the first pass missed:
`onboarding` decoded the *proto2* `OnboardingEnvelope` out of `Mumble.proto`
while every other service used its proto3 envelope, so outer type 1014 meant
one thing to one Starling service and another to the canon its neighbours
share. The canon `OnboardingEnvelope` was simultaneously unreachable code.
Fixed at M2a: onboarding is on the canon and no longer depends on
`starling-proto` at all. Every remaining `starling_proto::proto::tcp` import in
a service is an upstream L0 message — a `TextMessage` to hand a client — which
is what that crate is for.

**D2 — double ownership inside the new cut.** `fancy/pchat.proto` carried
`Reaction` (arm 10) and `Receipt` (arm 14); `fancy/social.proto` carries
`Reaction` (arm 1) and `ReadReceipt` (arm 3). One feature, two envelopes, two
shapes — a client had to guess which one a server honours. **Fixed:** social
owns both, pchat's arms are removed and their tags burned (§2).

**D4 — the canon is a redesign, not a reframing.** Found while starting M2, and
it is the reason M2 is now three steps rather than one.
`PROTOCOL-COMPATIBILITY.md` §3 says "the inner message keeps its epoch-0
shape", which was true of the *proto2* envelopes — they literally wrapped the
shipped messages. The proto3 sets do not: they are a green-field minimal
design, and for the feature-bearing services they are materially smaller than
what has shipped. §9's M2b lists the gaps. Moving the client onto the canon
as it stands would not reframe those features, it would delete them.

**D3 — cosmetic drift.** Comment and whitespace differences across the three
`Mumble.proto` copies, plus one semantic comment conflict
(`ChannelState.channel_info_password`: the client's copy says the server acts
on it, Starling's says it does not). Wire-neutral, but it hides real drift:
`scripts/check-proto-drift.sh` cannot tell these apart from D1.

## 1. Four layers, one import law

| # | Layer | File(s) | Syntax | Who compiles it |
|---|---|---|---|---|
| L0 | **Frozen Mumble surface** | `crates/proto/proto/Mumble.proto`, `MumbleUDP.proto` | proto2 | all three trees |
| L1 | **Mesh primitives** | `proto-fancy/proto/common.proto` (`starling.common.v1`) | proto3 | Starling only |
| L2 | **Client wire, epoch 1** | `proto-fancy/proto/fancy/*.proto` (`starling.fancy.*.v1`) | proto3 | Starling **and** the client |
| L3 | **Inter-service gRPC** | `proto-fancy/proto/*.proto` (`starling.*.v1`) | proto3 | Starling only |

The import law, which the crate split makes structural:

* **L0 imports nothing and is imported by nothing.** `starling-proto` is a
  separate crate precisely so no Fancy file can reach it. Where L2 needs an
  upstream message it embeds the *encoded frame* as `bytes` (§4, Z3) — never
  the type.
* **L1 is imported by L3 only.** `Scope` and `Actor` are mesh concepts; a
  client build must not compile them.
* **L2 files import `fancy/wire.proto` only** (`starling.fancy.wire.v1`, the
  wire plane's own primitives file — §7). Nothing else, in either direction.
* **L3 imports L1**, and may reference L2 payloads only as opaque `bytes`
  (`control.v1.Frame.payload`).

Layer 0 answers "is this Mumble". Layer 2 answers "what can a Fancy client
say". Layers 1 and 3 are invisible outside the mesh.

## 2. One canon per envelope

**The proto3 sets in `fancy/` are epoch 1.** The proto2 envelope block at the
tail of `Mumble.proto` is dead: tombstoned in place, deleted at M3 (§9). It
loses because epoch 1 has never shipped in a client — redefining it costs
nothing (`PROTOCOL-COMPATIBILITY.md` §1) — and because dragging the epoch-0
shapes forward would freeze their accumulated weight (21 pchat arms,
`sender_hash` strings where the server already knows the session, prose
`reason` strings where a client needs a machine-readable kind) into the wire
that is supposed to outlive them.

Ownership conflicts (D2) resolve by the rule already stated in the epoch-0
mapping — *the name is not the owner*:

* **social (1015) owns reactions and read receipts.** The pchat arms 10
  (`Reaction`) and 14 (`Receipt`) are removed and their tags `reserved`.
* **pchat (1006) owns pins**, because a pin is a property of the stored
  message.
* Everything else stands as assigned in `PROTOCOL-COMPATIBILITY.md` §3.

Envelope rules: one outer type per service, service-owned `oneof`, adding an arm
touches one file and no registry.

**Inner tags are permanent only after M4, and L2 carries no compatibility debt
before it.** This was got wrong once and is worth stating plainly, because the
mistake is an easy reflex: an earlier pass `reserved` every field number it
moved in `fancy/*.proto`, on the habit that a vacated tag must never be reused.
A reservation protects against a peer that still sends the old number. **Epoch 1
has never shipped in any client, so no such peer exists or can exist** — the
reservations protected nothing, and bought sparse numbering that made the files
harder to read for it. They are gone; the numbering is dense.

The compatibility obligations are exactly two, and neither is here:

* **`Mumble.proto` upstream messages** — a released Mumble client reads them.
  Field numbers there are upstream's, and the vacated ones are deliberately *not*
  reserved so upstream can grow into them (`PROTOCOL-COMPATIBILITY.md` §1).
* **Outer types 100–999** — burned, because released *Fancy* clients shipped
  messages under them. That is a range never reused, not a set of reservations.

After M4 the L2 tags join the first category and the reflex becomes correct.
Until then, a canon message may be renumbered freely, and should be: this is the
only window in which the wire can be made right rather than merely extended.

## 3. Backwards compatibility with Mumble 1.5

The hard rule stays the only hard rule: **never break a native Mumble
client.** What this design guarantees, mechanically:

* **Types 0–26 are flat and frozen.** Every upstream message, field number and
  wire type is exactly upstream's. No upstream message ever gains a `required`
  field or a Fancy field below 1000 (`Version.fancy_version = 6` is the single
  pinned exception, for discovery by already-shipped Fancy peers).
* **Upstream owns 1–999 in every upstream message; Fancy fields start at
  1000.** Tag encoding is two bytes either way; the margin costs nothing.
* **A stock 1.5 client negotiates nothing.** It never sends
  `Version.fancy_protocol`, so the gateway treats it as epoch-absent: it
  receives the full murmur flood (§5), flat types only, no seq prefix on
  frames (§5, S2), no zstd. Unknown Fancy fields inside upstream messages are
  skipped by protobuf as unknown fields, which is standard proto2 behaviour.
* **Voice is bit-compatible.** A legacy client sends UDP to the host:port it
  made TCP to, in the Mumble UDP format its version implies; `MumbleUDP.proto`
  is frozen alongside. Opus is forwarded, never transcoded.
* **Everything Fancy rides where upstream cannot look**: outer types ≥ 1000,
  fields ≥ 1000, or `PluginDataTransmission` when relaying through a foreign
  server. There is no third place.

Epoch negotiation is unchanged from `PROTOCOL-COMPATIBILITY.md` §2a:
`fancy_protocol` absent/0 = epoch 0, `1` = this design; no agreement means
plain Mumble plus the PluginData fallback.

## 4. Zero-copy

The rules, numbered so contracts can cite them. The unit of currency is a
refcounted slice (`bytes::Bytes` in prost — configure `bytes = ["."]`); "copy"
below means memcpy of payload bytes, not of a 24-byte handle.

**Z1 — the gateway routes on the framing and never parses a payload.** The
u16 type is in the frame header, so a client frame is sliced out of the socket
buffer once and travels to the owning service as that slice
(`control.v1.Frame.payload`). Outbound, `Send.payload` is written to N sockets
from one buffer. The gateway links no service's generated stubs; a new service
is a TOML route.

**Z2 — opaque at the edge stays opaque to the store.** Anything a service does
not itself interpret is declared `bytes` and stays the same bytes end-to-end:
pchat ciphertext, plugin payloads (`Opaque.payload` — "`bytes` and not a oneof
of plugin message types" is the opacity rule stated in the contract), minted
`CryptSetup` payloads, DER certificates, audio. A service that receives a
sealed blob stores the slice and replays the slice; decrypt/re-encrypt or
decode/re-encode on a relay path is a contract violation, not a style issue.

**Z3 — the submessage≡bytes law.** A length-delimited protobuf field encodes
identically whether declared `bytes` or a message type: `tag ‖ len ‖ payload`.
Three consequences the contracts exploit deliberately:

* A relay can *wrap* a received frame in an envelope arm — or *unwrap* one —
  by writing a tag and length around the existing slice. No parse, no
  re-encode.
* A store can persist the encoded frame it received and later emit it inside a
  response message verbatim (pchat fetch pages are the received `Message`
  frames, replayed).
* L2 can carry upstream messages without importing L0:
  `SyncDelta.user_states` is `repeated bytes` whose content is an encoded
  `MumbleProto.UserState` — the buffer encoded once for the legacy flood,
  embedded per subscriber without re-encoding (§5, S1).

**Z4 — encode once, fan out N.** A broadcast is one `encode()` and one
`Send{sessions:[…], payload}`; the gateway writes the same `Bytes` to every
socket. The audio invariant is the same rule on the realtime plane: payloads
are refcounted, never copied per listener — the real per-packet cost is N
*seals*, not N copies, and that number sizes the voice pod.

**Z5 — no request on a hot path.** Services subscribe to snapshot streams
(`session-view`, metadata `Watch`) and read their own copy; HTTP/2 flow
control is the only backpressure between gateway and service. A per-packet or
per-frame RPC anywhere on the audio or fan-out path is a design bug.

## 5. Scaling to tens of thousands of clients

The flood is the enemy. murmur broadcasts every `UserState` change to every
session: with N clients and state-change rate proportional to N, control
fan-out is Θ(N²) — at 10 000 clients and one presence change per client per
30 s, ~3.3 M frames/s before anyone speaks. Every mechanism here attacks that
or the reconnect herd.

**S1 — lazy subscription with `SyncDelta`.** Legacy clients keep the flood;
they cannot be told otherwise, and murmur-compatibility requires it. A Fancy
client declares what it is looking at (`LazySubscribe`, metadata `Subscribe`)
and receives `MetadataEnvelope.SyncDelta` batches: only entities inside its
subscription, bursts coalesced into one frame, contents being the
already-encoded upstream frames per Z3. Fan-out becomes Θ(events ×
subscribers-of-the-changed-entity) — a join is seen by the ~30 people whose
view contains that channel, not by 10 000.

**S2 — RESUME, with the sequence in the framing.** The gateway stamps a
per-session sequence so a reconnecting Fancy client replays the gap instead of
re-pulling the world. The sequence lives in the *framing*, not in any payload
— the gateway never parses payloads (Z1), so it cannot stamp a field inside
one. After a `Hello{resume:true}` is accepted, server→client frames carry an
8-byte big-endian sequence between `len` and `payload`:

```
legacy / un-negotiated:   type:u16 ‖ len:u32 ‖ payload
fancy, resume accepted:   type:u16 ‖ len:u32 ‖ seq:u64 ‖ payload
```

`len` covers `seq ‖ payload`, the client strips 8 bytes, and a stock client
never sees the layout because it never negotiates it. The replay ring outlives
the gateway pod (the session store, `ARCHITECTURE.md` §5); a gap longer than
the ring gets `full_resync_required` rather than a silent hole. Legacy clients
can never resume, so staggered drain and jittered reconnect hints exist
regardless.

**S3 — zstd on the Fancy control stream**, negotiated in `Hello`. The
reconnect flood and pchat history pages are the payloads that matter; audio is
Opus and incompressible.

**S4 — shard keys are part of the contract.** `voice` by channel (a channel's
members must share a pod; Fancy clients are handed the endpoint via
`VoiceEndpoint`, legacy scales vertically), `session-view` by session,
`metadata` and `server-config` by virtual server. These are decided now
because a shard key cannot be retrofitted.

**S5 — loss is bounded and honest.** Control overflow to a client:
disconnect that client, never stall the producer. Audio: drop oldest, count
it. Throttling: per route, and a Fancy client is *told* (`Throttled`) — the
silent murmur bucket ate SDP offers. Bounded mailboxes everywhere; identical
in-flight reads coalesce (permissions) instead of stampeding.

**S6 — ids are UUIDv7** for everything with history — time-sortable without a
sequencer process, index-local where UUIDv4 shreds locality.

## 6. Minimal message sets

One envelope per service; an arm exists only if a shipping feature reads it.
Current counts after the D2 fix, as the ceiling new work is measured against:

| Outer | Service | Envelope (L2 file) | Arms |
|---|---|---|---|
| 1000 | session-lifecycle | `fancy/session.proto` | 6 — hello, resume×2, throttled, voice-endpoint, subscribe |
| 1001 | permissions | `fancy/domain.proto` | 4 — tokens, invalidated, group query/list |
| 1002 | metadata | `fancy/domain.proto` | 4 — extras, structural, subscribe, **delta** |
| 1003 | userdata | `fancy/domain.proto` | 4 — account action/ack, settings, update |
| 1004 | voice | `fancy/feature.proto` | 4 — listen, volume, stats, cipher |
| 1005 | text | `fancy/feature.proto` | 4 — history req/page, edit, delete |
| 1006 | pchat | `fancy/pchat.proto` | 12 — message, fetch×2, ack, key ladder×5, pin×2, delete |
| 1007 | moderation | `fancy/feature.proto` | 4 — ban, bans, unban, refused |
| 1008 | screenshare | `fancy/screenshare.proto` | 6 — offer, answer, start, stop, viewers, health |
| 1009 | files | `fancy/files.proto` | 7 — upload, download, grant, share, listing, list, refused |
| 1010 | plugins | `fancy/feature.proto` | 5 — registry, query, opaque, admin, result |
| 1011 | push | `fancy/feature.proto` | 4 — register, unregister, subscribe, ack |
| 1012 | audit | `fancy/feature.proto` | 5 — query, page, config, update, event |
| 1013 | server-config | `fancy/domain.proto` | 3 — query, values, update |
| 1014 | onboarding | `fancy/feature.proto` | 4 — flow, query, response, update (`Response` serves both directions) |
| 1015 | social | `fancy/social.proto` | 10 — reaction, typing, receipt, poll×3, watch×2, stroke, clear |
| 1016 | link-preview | `fancy/feature.proto` | 3 — request, preview, error |
| 1017 | context-actions | `fancy/feature.proto` | 2 — action, menu |

`session-view` and `directory` keep no client-facing type at all — internal by
construction. For comparison, the dead proto2 cut needed 21 arms for pchat
alone; the discipline that got it to 12 (server-known facts like `sender_hash`
dropped, request/response pairs collapsed, challenge sub-protocol replaced by
the key ladder) is the discipline that keeps these numbers from regrowing.

On the mesh (L3), minimal means RPC count: each service exposes 3–7 methods
(metadata is the widest at 8, because it owns membership as well as the tree),
plus the uniform `ClientPlane.Attach` every client-facing service implements.
A contract and a process are not one-to-one: `sessioncontrol.v1` (the operator
plane's murmur `setState`) is served by session-lifecycle, because the fields
it changes are connection state and that is who owns a connection — while
`Kick` stays in moderation, which owns what outlives a session. Like
session-view, it has no client-facing type: internal by construction.

## 7. Shared primitives — one common per plane

Two files, because the planes have different compilers and different secrets:

**`common.proto` (`starling.common.v1`) — the mesh's.** `Scope` (virtual
server), `Actor` (session | operator | internal), `Ack`, `Decision`. Imported
by every L3 contract; never compiled into a client.

**`fancy/wire.proto` (`starling.fancy.wire.v1`) — the wire's.** `Cursor` and
`PageInfo` (keyset pagination — pchat, text, audit and files each hand-roll
this trio today), `MessageRef` (the (channel, message-id) coordinate every
message-scoped feature addresses), `Emoji` (unicode-or-shortcode, which a bare
string cannot express), `Refusal` (machine-readable kind + prose + retry-after
— moderation, files and the throttle notice each carry a fragment of it).

Deliberately *not* shared: `Scope`/`Actor` into L2 (the gateway stamps
identity; a client-supplied actor field is a spoofing surface, which is why L2
messages carry `actor` only in server→client direction where the server filled
it), and any L0 type into anything (the crate split is the compatibility
guarantee).

The adoption rule: **a new or changed arm MUST use the shared primitive where
one fits.** Existing arms adopted at M2a; the burned field numbers are marked
`reserved` in place. The bar for adding to either common file stays "two
contracts already carry the shape by hand" — a shared type is a coupling, and
one consumer is not a pattern.

One deliberate non-adoption, because the reasoning generalises: **the fan-out
services keep `channel` and `message_id` flat rather than folding them into
`MessageRef`.** prost renders a nested message as `Option<T>`, so a routing
read becomes an unwrap and an absent case appears in front of the field the
router cannot work without. `MessageRef` is used where the pair is read after
the body is understood (text's `Edit` and `Delete`, which carried no channel at
all before), and avoided on the paths that address traffic.

## 8. Where gRPC is used, and where it never will be

| Plane | Transport | gRPC? |
|---|---|---|
| mesh (service↔service, gateway↔service) | HTTP/2, tonic | **yes** — unary for commands, server-stream for `Watch`/snapshots, bidi for `ClientPlane.Attach` |
| client control | TCP 64738 + TLS, Mumble framing | **never** — the framing *is* the 1.5 compatibility |
| realtime | UDP 64738 / WebRTC | never — a 10 ms frame budget does not survive HTTP/2 |
| bulk | HTTPS, signed URLs | no — plain HTTP gets Ingress, CDN and resumable range requests for free |
| admin | HTTPS, REST + OpenAPI | no — `curl`-ability and IdP auth are the point; it calls the same gRPC methods internally |

gRPC earns its place on the mesh specifically: HTTP/2 flow control is the
backpressure story (Z5/S5), streams carry the snapshot+delta pattern, and
deadlines + `tier` drive the circuit breakers. Schema-skew tolerance across
independently deployed services is protobuf's native behaviour, which is what
lets twenty-four processes deploy on different days.

## 9. Migration

Moved to [`PROTOCOL-MIGRATION.md`](PROTOCOL-MIGRATION.md). The ordering rule it
turns on is worth restating here, because it constrains the design above: every
intermediate state has to be safe to ship, and the starting state was not. Both
ends already claim epoch 1 and corrupt each other (D1), so the sequence begins
with the step that makes the present honest rather than with the most valuable
change.

## 10. Requirements traceability

| Requirement | Where it is met |
|---|---|
| zero-copy between services | §4 Z1–Z5; `Frame`/`Send` as `Bytes`; Z3 embed-verbatim |
| tens of thousands of clients | §5 S1–S6; `SyncDelta`; framing seq; shard keys |
| minimal message set per service | §6 table; one envelope per service; D2 fix |
| shared common primitives | §7; `starling.common.v1` + `starling.fancy.wire.v1` |
| 100 % Mumble 1.5 compatibility | §3; L0 frozen; import law §1; checks `PROTOCOL-MIGRATION.md` M6 |
| gRPC where it fits | §8; mesh yes, client wire structurally never |
