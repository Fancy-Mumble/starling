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

Ordered so every intermediate state is safe to ship — **which the re-analysis
showed the starting state was not**: both ends already claim epoch 1 and
corrupt each other (D1), so the order now begins with the step that makes the
present honest. The L2 tags stay movable until M2c because no shipped peer
speaks the canon — the one client that claims epoch 1 speaks a dead dialect of
it — and after M4 they are frozen like everything else.

Remaining work runs in this order: **M2b → M2c → M3 → M4 → M5 → M6.** M2h and
M2p are done; M2c is the one that reverts M2h's degradation, and must not land
before M2b has given the client something worth encoding.

* **M1 — canon markers. Done.** Tombstone the proto2 envelope block in
  `Mumble.proto`; land `fancy/wire.proto` and `SyncDelta`; this document.
  Nothing on any wire changed.
* **M2a — the canon settles its own shape. Done.** The last window where L2
  tags may move freely, so everything that moves them happened at once:
  pchat's `Reaction` and `Receipt` arms removed and their tags `reserved`
  (D2); `Cursor`/`PageInfo` adopted by pchat, text and audit; `Emoji` by
  social; `Refusal` by moderation and files; `MessageRef` by text's `Edit` and
  `Delete`. `Cursor::page_size` fixes a bug all three paginated services
  shared — an unset `limit` is proto3-indistinguishable from 0, which every
  caller clamped up to 1, so a client that never set the field paged one entry
  at a time. **onboarding moved off the dead proto2 envelope** (the D1 instance
  inside Starling) and onto a canon that can carry what its answers grant.
  `Step.Choice` names the channels and ACL groups a choice confers, `Flow`
  carries `enabled` / `default_channels` / attribution, and `Response` batches
  a whole submission with the `flow_version` it answered — where the canon had
  a generic four-field wizard that could express none of it. Applying the
  grants is the remaining half, listed under M2b.
* **M2h — make the break honest. Done.** Three changes in `vendor/client`:
  the handshake stops announcing `fancy_protocol` (extracted to
  `client::version_announcement`, so the claim has one home a test can read),
  `select_codec` returns `LegacyCodec` for an epoch-1 peer, and — the part that
  outlives the hotfix — **an undecodable service frame is skipped instead of
  propagating**. That last one was a latent connection-killer: `codec::decode`
  used `?` on the envelope decode, so one frame from a peer whose envelope
  shapes differ tore down a working connection and turned a protocol skew into
  an unexplained reconnect loop. `fancy_version` still goes out: it is a
  product version and remains true, only the claim about the wire was false.

  The original statement of the problem, kept because the reasoning is what
  makes the ordering non-negotiable: today the
  client announces `fancy_protocol = 1`, selects `NativeCodec` against
  Starling, and the two ends corrupt each other in both directions. Until its
  codec encodes the canon, the client must be what it actually is — a peer
  that does not speak epoch 1: stop announcing `fancy_protocol`, and
  `select_codec` returns `LegacyCodec` unconditionally (one site,
  `fancy_codec.rs`, with the constant left at 1 for M2c). Starling then treats
  it as a plain-Mumble peer and relays `PluginData` — so every feature with
  that fallback (typing, watch-sync, WebRTC signalling, pchat key
  distribution) starts *working* again, and `ServerOnly` features go visibly
  off instead of silently wrong. This is strictly better than the present on
  both axes, which is why nothing may overtake it.

  Not the server side, deliberately: silencing Starling's announcement would
  fix the client's lie by adding a server lie, break the e2e stack's only
  epoch-1 speaker, and have to be un-shipped in lockstep with M2c across two
  trees. The client is the peer whose claim is false; the correction belongs
  where the falsehood lives.
* **M2p — the unset-limit rule, on every plane. Done.** `page::page_size` now
  states it once for a bare `u32`, `Cursor::page_size` delegates to it, and the
  three surviving `clamp(1, max)` sites (audit's L3 query, text's history,
  userdata's account list) call it. No `clamp(1,` remains in any service or in
  operator-api. The original finding:

  The re-analysis found the
  `clamp(1, max)` bug fixed for L2 in M2a alive on the mesh and REST planes:
  audit's L3 `query` clamps at `lib.rs:226`, text's L3 `History` RPC feeds the
  same clamp, and operator-api's new `GET /v1/log` passes a serde-default 0
  straight into it — **an operator querying the log without a limit gets
  exactly one entry.** The rule, stated once: *an unset limit means the
  default page, never one entry.* One shared helper (the semantics of
  `Cursor::page_size`, callable from a bare `u32` for L3 requests), applied at
  the service — not at operator-api, so every caller of the RPC is covered —
  plus a sweep for remaining `clamp(1,` sites in services.
* **M2b — complete the canon for the shipped features.** The D4 finding: the
  proto3 sets are a minimal green-field design, and several are smaller than
  what has shipped. Each of these must carry its feature's information before
  a client can move onto it, and none of it is a framing question:

  **First, a correction to how this list was drawn.** It originally measured
  each canon message against its epoch-0 counterpart and called every
  difference a gap. That is the wrong test twice over. A field is only missing
  if *this* plane still owes it — and for two of the six the service does not
  implement the feature at all, where designing a wire ahead of the code is
  how the minimal sets became wrong in the first place. Re-checked against
  what each service actually does:

  | Service | Status | Finding |
  |---|---|---|
  | server-config | **done** | Real, and blocking. `ConfigValues` now carries `repeated Setting` — key, kind, group, label, value, secret, help — plus the snapshot `version` a client drops stale replies by. The schema lives in one table in `snapshot.rs` where each row holds both its metadata *and* the accessor that reads it, because the value map and the `redacted` name list were two lists keyed by the same strings, and two such lists drift into a password on a settings screen. Keys from `Snapshot.extra` are offered as untyped strings rather than dropped, so the add-a-knob-without-a-proto-release mechanism keeps working |
  | audit | **done**, and it was worse than a missing field | `Query` gained `target_account`; `AuditRecord` gained `target_account` and `target_channel`, which the store had held all along while the record dropped them — so "banned" arrived without saying whom, and a reader had to parse the human-readable `detail` to find out. **The real bug was underneath:** `QueryRequest` already carried `until_ms`, `category`, `target_account` and `before`, and the statement bound *none* of them. An operator narrowing the log got the whole log back, looking narrowed. A filter that is accepted and ignored is worse than one that is refused, because whoever reads the result believes it. Now built with a `QueryBuilder` so each clause sits beside its own bind |
  | ~~onboarding~~ | done at M2a | the canon carries the grants; *applying* them is service work, below |
  | ~~plugins~~ | **not a gap on this plane** | The client-facing `Admin` arm is *refused by design* — "plugin administration is an operator action and takes an operator identity, which the client plane does not carry". `marketplace_id`, `installed_at`, `builtin` and `path` are an operator-surface concern, so they belong to operator-api's REST routes, not here. Epoch 0 put plugin admin on the client wire; Starling deliberately moved it |
  | ~~push~~ | **closed** | The canon had the semantics backwards — `Subscribe` was an *inclusion* list, and a user mutes two rooms out of forty rather than enumerating the other thirty-eight (and any channel created later would silently stop notifying). Now an exclusion list, which is the thing a person actually does. Closing it exposed that the feature was a **complete no-op**: `Subscribe` was never handled (it fell to `ok: false`), `Register` stored `channels: Vec::new()` and discarded the preference, every registration was filed under `account: 0` while every lookup asked for a real account, and `Notification` carried no channel — so delivery had nothing to compare a mute against. All four fixed; a muted channel no longer buzzes the phone, and there is a test saying so |
  | ~~link-preview~~ | **deferred, feature not built** | The service vets a URL and returns an empty `Preview`; it has no HTTP client at all. The rich embed — and the `preview_data`-versus-`image_key` question, which is a real design choice about whether thumbnails ride the control plane or the files service — gets decided with the fetcher that has to produce it |
  | ~~userdata~~ | **deferred, feature not built** | Worse than first measured, and in a way that reframes it: nothing decodes `UserdataEnvelope` at all. The account self-service surface (password, email, rename, TOTP enrol/verify/disable, unregister) does not exist in Starling. Its canon is also unsafe as drawn — `AccountAction.Kind` has no QUERY verb, so the proto3 default action is `SET_PASSWORD`, and a default-constructed message is a password change. Both get fixed with the implementation |

  The rule for closing a real gap is the one that produced the minimal sets in
  the first place: add what carries information the receiver cannot derive,
  and leave out what the server already knows (a `sender_hash` beside a
  session id) or what the epoch-0 shape carried only by habit. The rule for
  the deferred two is simpler: **design the wire with the implementation, not
  ahead of it.**

  Also outstanding here, and service work rather than protocol work: onboarding
  **applies** none of the grants its `Step.Choice` now carries.
* **M2c — the client moves to the canon. Vendoring done; the codec is the
  rest.** `vendor/client` now carries `proto/fancy/*.proto` mirrored from here
  and compiles all eight into `proto::fancy::*`, under the same two-pass
  `extern_path` dance `wire.proto` needs on this side. `check-proto-drift.sh`
  covers them in both directions — a file whose wire meaning differs, and a
  file the client has that Starling does not, which a loop over our own files
  would never look for. Nothing encodes them yet, and that is the point of
  doing it first: the canon is now *verified identical* on both ends before
  anything depends on it being so.

  **The pchat identity question is settled, and the canon was wrong.** The
  client's key ladder is keyed on TLS certificate hash throughout — peer keys,
  channel originators, key holders, even the consensus tie-break — while the
  canon modelled pchat identity as a session id alone. That is not a mismatch
  the client should adapt to: a session id is handed out per connection and
  reused, so an archive keyed on one attributes last week's messages to
  whoever holds that number today. `Roster` already says this in as many words
  about accounts; pchat's *store* was violating it, recording `sender BIGINT`
  for the longest-lived data this server keeps.

  So `Message` gained `sender_cert`, and the shape of it matters: **the server
  stamps it from the TLS connection**, beside the `sender` stamp it already
  did, rather than reading it off the wire. Client-filled would have been a
  claim; connection-stamped is an identity, and no client can write into
  somebody else's name. `Roster::cert_of` is the source, a nullable column
  holds it, and rows written before it existed read back empty rather than
  guessed at — a wrong attribution in an archive is worse than an absent one.

  The same treatment is still owed to the key-ladder arms (`KeyAnnounce`,
  `KeyRequest`, `KeyDeliver`, `HolderReport`), which address by session and so
  cannot express a durable key holder. Those are relayed verbatim rather than
  stored, so the crypto still verifies them end-to-end and nothing is being
  written wrong; `pchat_holder`'s `holder BIGINT` is the exception and is
  rebuildable from client reports.

  What remains is the codec: rewrite `NativeCodec` to encode the canon, drop
  the generated proto2 envelope types.
  The client's internal `ControlMessage` vocabulary stays its own: the codec is
  the boundary, and translating there is what keeps the app above it out of the
  migration. Starling's services already decode the canon; no server change.
  **The M2h degradation is reverted in this same change** — the epoch-1
  announcement and the codec that earns it ship in one commit, so the claim
  and the capability can never again be separated, which is precisely how D1
  happened.
* **M3 — the dead block is deleted. Done.** Gone from all three `Mumble.proto`
  copies, which are thereafter exactly: upstream surface + Fancy 1000+ fields +
  the epoch-0 legacy messages `vendor/server` still speaks. Deletion is also the
  guard — the onboarding service bound itself to the dead block and nobody
  noticed, because a tombstone comment stops readers and not compilers. The
  types no longer exist, so nothing can quietly speak them.

  It removed a live defect as well as dead text. The client's codec fell back to
  the proto2 envelopes whenever the canon did not recognise a payload, which
  meant **a canon frame at a service the canon does not cover** — server-config
  at 1013, say — was decoded as proto2, and where the wire types coincided it
  produced a message that looked valid and was not. That is D1 inbound, and the
  fallback was the only thing keeping it reachable. Now an unreadable
  service-typed frame is skipped, which is what the envelope design says may
  happen to any arm a build does not know.

  Outbound gained the matching rule: `encode` **refuses** a Fancy message with
  no canon form rather than framing it flat, because flat means its epoch-0 id
  in the burned 100–999 range, which routes nowhere on any peer. Those travel by
  relay, arranged a layer up; a raw one reaching the wire codec means somebody
  skipped that layer, and now they find out instead of the frame vanishing.
* **M4 — freeze, per set rather than per date. Mechanism done.** A blanket
  freeze would lock in whatever state the canon happened to be in on the day,
  and five services are still on the relay *because* their canon is incomplete
  — freezing those buys nothing (nothing encodes them) and makes finishing them
  expensive. So a set is frozen when both ends encode it and a build carrying it
  could ship, and `check-proto-hygiene.py` enforces that against a recorded
  manifest (`scripts/frozen-tags.json`): a frozen field that moves or vanishes
  fails the check by name. Frozen today: `pchat`, `social`, `wire` — the sets
  M2c's codec actually encodes. Everything else may still be renumbered, and
  should be, before it joins them.

  Verified the way the other gates were: by moving a frozen tag and watching it
  fail with the field named. `--update-frozen` re-records, which is the one
  command that may be run when a set legitimately joins.

  The epoch stays `1`: the
  layout a peer finds at `fancy_protocol` is already the discriminator, and no
  epoch-1 peer shipped before this point.
* **M5 — scale features behind capability bits. S1 landed; two features left.**
  The step reads like wiring and is not: none of the three existed.
  `SyncDelta` was defined and never constructed, `Resume` is a stub that always
  answers `full_resync_required`, and zstd and the framing sequence have no
  implementation at all.

  **S1, lazy subscription, is now real.** A connection records what it is
  looking at (`LazySubscribe`), and a `UserState` change splits its audience:
  peers that did not subscribe get exactly what murmur sends, peers that did and
  are looking at that channel get a `SyncDelta`, and **peers that did and are
  looking elsewhere get nothing at all**. That omission is the whole saving —
  the win is not a smaller message, it is no message, which is what turns
  Θ(events × clients) into Θ(events × subscribers of the changed entity).

  Three properties are load-bearing enough to have tests: an unsubscribed peer
  still gets everything (a stock client must not be quietly cut out of state it
  renders); a subscription from a peer that never announced `lazy_subscribe` is
  **ignored**, because honouring it would stop the flood for a client that
  cannot read what replaces it — a roster that silently stops updating; and
  `everything: true` is the flood *by choice*, which is distinct from a client
  that failed to subscribe.

  Z3 pays off here exactly as §4 claims: the `UserState` is encoded once and the
  same bytes go into both the flat frame and the `SyncDelta`, because a
  length-delimited field is identical whether declared `bytes` or a message.
  Nothing is re-encoded per recipient.

  Wired into the self-mute path first, deliberately: a push-to-talk binding
  emits two presence changes per utterance, so it is the highest-rate flood
  there is and the one most worth not sending to ten thousand people looking
  elsewhere. The remaining broadcast sites adopt the same helper.

  **S2 (resume) is done, and the Z4 collision dissolved rather than being
  traded away.** The apparent conflict was that a broadcast shares one
  refcounted frame across every recipient while a sequence number is per
  connection. It only conflicts if the header and the payload have to be *one
  buffer* — and they do not. The send queue now carries
  `Outbound { prefix, payload }`: the prefix is six bytes, or fourteen for a
  peer that negotiated resume, and is never shared; the payload is the same
  refcounted buffer for everyone. The writer emits the two in sequence rather
  than joining them, so nothing is copied per recipient. Z4 is not weakened —
  it is stronger, because the old path concatenated a header onto the payload
  and this one stops doing even that.

  `len` covers the sequence, so a reader takes `len` bytes after the header
  either way; the eight it skips first are the ones it asked for. A peer that
  never negotiated resume sees bytes identical to murmur's, which a test
  asserts directly against the joined form.

  The rest of the wiring, and one rule each:

  * **The gateway cannot see a `ResumeRequest`** — it is inside a payload, and
    the gateway never parses one (§1). So session-lifecycle reads it and
    *instructs* the gateway through two new `ServerAction` arms, `Sequence` and
    `Replay`. The gateway acts on a control-plane instruction rather than on
    client bytes, and Z1 holds.
  * **Replay is the gateway's** for a stronger reason than routing: only the
    pod holding the socket knows what it already wrote to it.
  * **Replayed frames keep their original sequence**, so a client that drops
    again mid-replay resumes from the right place rather than from a number
    that has since moved.
  * **A failed replay is not announced.** The gap in the numbers is the
    announcement — it covers every cause rather than the one the server
    happened to know about, and it spares the gateway from having to encode a
    service's message to explain itself. The client watches for a skip and
    re-syncs; a *repeat* is not a skip, because that is what a successful
    replay looks like.

  Before this, `Resume` answered `full_resync_required` unconditionally: the
  ring was filled on every outbound frame and never once read from.

  The original statement of the problem, kept because the reasoning is what
  made the shape obvious:

  * `ResumeStore::resume` is never called. The gateway owns the ring but must
    not parse payloads (Z1), so it cannot see a `ResumeRequest` — which arrives
    at outer type 1000 and routes to session-lifecycle, where the handler
    unconditionally answers `full_resync_required`. The fix is a new
    `ServerAction` arm (`Replay { conn, from_seq }`): the service reads the
    request and *instructs* the gateway, which keeps Z1 intact because the
    gateway acts on a control-plane instruction rather than on client bytes.
  * **The sequence has to reach the client, and putting it in the framing
    conflicts with encode-once fan-out.** §5's S2 says the seq sits between
    `len` and `payload`. But a broadcast builds *one* frame and shares it by
    refcount across every recipient (Z4), and a sequence is per recipient — so
    prefixing it means a distinct buffer per client, which is precisely the
    "1000 buffer writes for one logical event" the session-store note warns
    about. The two rules were written apart and have not been reconciled.

    The shape that keeps both: only connections that negotiated `resume` get a
    prefixed frame, so the shared path stays shared for everyone else — the
    same per-capability split S1 uses. That bounds the cost to the clients that
    asked for it, and is worth measuring before it is built rather than after.

  **S3 (zstd) is done, as a transport frame type.** The framing question was
  the real content of it, and the answer is `COMPRESSED_BATCH` (1900): a batch
  of whole frames, zstd'd, unwrapped before anything is routed.

  Stream-level compression was the alternative and is rejected because both
  ends must then switch at *exactly* the same byte — one frame written before
  the switch and read after it desynchronises the connection permanently, and
  the symptom appears at a layer with no idea compression exists. A frame type
  is self-describing, bounded by the framing that already exists, costs one
  batch rather than the connection when it fails, and is legible in a capture.

  **Not a service**, which is why it is numbered far from the service block
  rather than taking the next free slot: it is a property of the connection,
  not a destination on it, and what comes out of a batch is ordinary frames
  that route exactly as before. Numbering it 1018 would have made it look like
  the eighteenth service to every reader of the table and every capture.

  Three rules it follows, each with a test:

  * **Only to a peer that announced `zstd`.** Same rule as the sequence, same
    reason: a peer receiving a type it cannot parse cannot read its own
    connection, and a stock Mumble client announces nothing.
  * **A batch that does not shrink is not sent.** Sealed pchat ciphertext and
    avatars are effectively random, and zstd makes random data slightly larger
    — compressing them would cost bandwidth to save none. Nor is a single frame
    batched, or anything under 256 bytes.
  * **Expansion is bounded on the way in.** The expanded size is chosen by
    whoever sent the batch, so a few kilobytes can claim to be gigabytes. The
    decoder refuses mid-stream rather than after the fact, which is the same
    rule the frame length already follows.

  Level 1 rather than the default 3: this runs on the socket write path, where
  the budget is a 10 ms audio frame, and the alternative to compressing quickly
  is not compressing better — it is stalling the writer. Batching happens in
  the writer, which drains what is already queued, so a burst compresses and a
  quiet connection is untouched.

  The dependency was already declared in the workspace manifest and had no
  user; it has one now.

  What is done is the gate they will each need, and it fixed a real defect on
  the way: a client's `Hello` was received and **discarded**, so a peer
  announcing `zstd` had no way to learn whether anything heard it, and each
  feature would have arrived inventing its own way of asking. `Capabilities`
  now lives on the connection, recorded from the `Hello` and readable per
  connection.

  Its default is the load-bearing part. Every capability is something the
  server does *to* a client — compress its stream, replay a gap, send deltas
  instead of the flood — so a peer that never announced one must not receive
  it, or it cannot read its own connection. All-false is therefore both the
  default and what an unknown connection reads as, and a stock client lands
  there correctly by sending no `Hello` at all.
* **M6 — enforcement. Partly done; taken early because it guards the rest.**
  The three checks of `PROTOCOL-COMPATIBILITY.md` §5:

  * **consistency** — `check-proto-drift.sh`, which already compared L0's wire
    meaning across the three trees and passes. Its header called
    `vendor/server` "upstream's source of truth", which is the belief that let
    §1's numbering drift through, and its failure advice said to re-sync from
    that tree — so a deliberate change would be reverted by whoever ran the
    check next. Both corrected: no tree is the authority, and the diff has to
    be adjudicated rather than copied over. Extends to L2 when the client
    vendors those files at M2c.
  * **hygiene** — `check-proto-hygiene.py`, new. Two rules no compiler
    enforces and that the drift check is blind to *by construction*, because
    all three trees break them identically: **no field number in the burned
    100–999 range** (with `Version.fancy_version = 6` as the one pinned
    exception), and **no source outside the frozen crate may name a dead-block
    envelope type** — the canon shares those names, so the import *path* is
    what distinguishes them. Both were verified by reintroducing the original
    bug and watching the check fail with file and line: a Fancy field taking
    upstream's next number, and onboarding's dead-block import.
  * **compatibility** — upstream surface vs `mumble-voip/mumble`, still
    outstanding. It needs a remote, and none is configured here; a failure
    there is a released-client break, so it is the one that most wants doing.

  A fourth check landed with M4/M5: **outer-type agreement.** The client names
  outer types as its own constants because it does not link `proto-fancy`, so
  the table exists twice with nothing comparing the copies. A wrong one is not
  a compile error — the frame is well-formed and simply arrives at the wrong
  service, which does not recognise the envelope and skips it. A feature that
  silently does nothing, with plausible-looking numbers in both files. Verified
  by pointing the client's `PUSH` at the plugins service and watching the check
  name both values.

  Still outstanding: an **honesty check** on the epoch — the tree announcing
  `fancy_protocol = 1` must be the tree whose codec encodes the canon,
  asserted by the e2e suite round-tripping one Fancy message per service
  rather than by anyone's claim in a document. Both docs claimed states the
  code contradicted; only the round-trip is evidence. M2c has now made it
  writable, and the three structural checks above narrow what it has to cover:
  the protos are identical, the frozen tags cannot move, and the outer types
  agree — so what remains for it is the codecs themselves.

## 10. Requirements traceability

| Requirement | Where it is met |
|---|---|
| zero-copy between services | §4 Z1–Z5; `Frame`/`Send` as `Bytes`; Z3 embed-verbatim |
| tens of thousands of clients | §5 S1–S6; `SyncDelta`; framing seq; shard keys |
| minimal message set per service | §6 table; one envelope per service; D2 fix |
| shared common primitives | §7; `starling.common.v1` + `starling.fancy.wire.v1` |
| 100 % Mumble 1.5 compatibility | §3; L0 frozen; import law §1; checks §9 M6 |
| gRPC where it fits | §8; mesh yes, client wire structurally never |
