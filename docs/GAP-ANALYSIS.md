# What vanilla murmur has that Starling does not

Measured against **upstream `mumble-voip/mumble`, branch `1.6.x`**, HEAD `d1785ec`
(2026-07-21) — deliberately upstream rather than `vendor/server`, so the target is
the protocol as everyone else implements it and not the Fancy fork's superset.

Nothing here is started. This is the list, not the plan.

---

## 0. The baseline, stated honestly

Starling handles **7 of murmur's 27** inbound control messages:

```
Authenticate  PermissionQuery  Ping  QueryUsers  TextMessage  UserState  Version
```

It *sends* considerably more than it handles — `ServerSync`, `ServerConfig`,
`SuggestConfig`, `CodecVersion`, `ChannelState`, `UserRemove`, `Reject`,
`PermissionDenied` — because the handshake needs them outbound.

**7 of the 20 remaining are not gaps.** murmur's handlers for `Reject`,
`ServerSync`, `PermissionDenied`, `ContextActionModify`, `CodecVersion`,
`ServerConfig` and `SuggestConfig` have empty bodies: they are server-to-client
messages, and a client sending one is ignored. Starling ignoring them is correct
behaviour, not a missing feature.

So the real inbound gap is **13 handlers**, plus the subsystems below that no
handler count reflects.

---

## 1. Voice — nothing exists

The largest gap by far, and the only one that makes Starling unusable as a Mumble
server rather than merely incomplete. `sqlx` appears in 0 files; so does any UDP
socket.

| # | Missing | murmur reference |
|---|---|---|
| V1 | UDP socket, per-peer `CryptState` (OCB2-AES128) | `src/crypto/CryptStateOCB2.cpp` |
| V2 | `CryptSetup` (15) — key/nonce exchange | `Messages.cpp` |
| V3 | `UDPTunnel` (1) — voice over TCP when UDP is blocked | `Messages.cpp` |
| V4 | Audio routing: speak, whisper, shout, listener fan-out | `Server::processMsg`, `AudioReceiverBuffer.cpp` |
| V5 | `VoiceTarget` (19) — whisper/shout target registration | `Messages.cpp` |
| V6 | Codec negotiation, Opus threshold, `recheckCodecVersions` | `Server.cpp` |
| V7 | Channel listeners — hear a channel without joining | `ChannelListenerTable.cpp` |
| V8 | Voice-path enforcement of mute/deaf/suppress/priority-speaker | `Server::processMsg` |
| V9 | Positional-audio passthrough | `Server::processMsg` |

The bus experiments never carried real voice — the Realtime-lane measurement used
synthetic load. Those experiments are gone with the bus; the conclusions that
survived are in `ARCHITECTURE.md` §5.

## 2. Authority — the ACL subsystem

Starling's `Permissions` is `AllowAll`, a Null Object. Everything below is absent.

| # | Missing | murmur reference |
|---|---|---|
| A1 | Real ACL evaluation: inheritance, deny-over-allow, the `Cached` marker | `src/ACL.cpp` |
| A2 | `ACL` (13) — read and write a channel's ACLs and groups | `Messages.cpp` |
| A3 | Groups, membership, inheritance, `@all`/`@auth`/`@sub` | `src/Group.cpp`, `GroupTable.cpp`, `GroupMemberTable.cpp` |
| A4 | Access tokens | `Server.cpp` |
| A5 | Per-user permission cache and its invalidation | `Server::clearACLCache` |
| A6 | Channel nesting limit (`iChannelNestingLimit`) | `Meta.cpp` |

The `Permissions::effective` signature already carries a Phase 2 gate saying it
must stop taking bare ids before A1 lands
(`crates/domain/model/src/perm/policy.rs`).

## 3. Channel management

Starling serves a static tree built at startup and can push it. It cannot change
it.

| # | Missing | murmur reference |
|---|---|---|
| C1 | `ChannelState` (7) inbound — create, rename, move, describe, set limits | `Messages.cpp` |
| C2 | `ChannelRemove` (6) | `Messages.cpp` |
| C3 | Channel links, and permission propagation across them | `ChannelLinkTable.cpp` |
| C4 | Temporary channels, and sliding-window expiry | `Server.cpp` |
| C5 | Channel properties: position, max_users, description blobs | `ChannelPropertyTable.cpp` |

## 4. Users and moderation

| # | Missing | murmur reference |
|---|---|---|
| U1 | `UserRemove` (8) inbound — kick and ban | `Messages.cpp` |
| U2 | `UserState` admin paths — mute/deafen/move others, priority speaker | `Messages.cpp` |
| U3 | User registration, and `UserList` (18) — list, rename, delete accounts | `UserTable.cpp` |
| U4 | `UserStats` (22) — ping stats, cert chain, bandwidth, version | `Messages.cpp` |
| U5 | `RequestBlob` (23) — comments, avatars, descriptions on demand | `Messages.cpp` |
| U6 | `BanList` (10), plus ban enforcement at accept | `BanTable.cpp`, `src/Ban.cpp` |
| U7 | Certificate authentication: chain validation, strong-cert requirement | `Cert.cpp` |
| U8 | Comment and avatar storage with hash-based caching | `UserPropertyTable.cpp` |

## 5. Persistence — no database at all

`sqlx` appears in **0 files**. `STORAGE.md` has the design; none of it is built.

| # | Missing | murmur reference |
|---|---|---|
| P1 | ~20 tables: users, channels, ACLs, groups, bans, links, listeners, config, log | `src/murmur/database/` |
| P2 | Multiple virtual servers in one process | `ServerTable.cpp`, `Meta.cpp` |
| P3 | SQLite, MySQL and PostgreSQL back-ends | `ServerDatabase.cpp` |
| P4 | Schema migration and the murmur-compatibility read path | `DBWrapper.cpp` |
| P5 | Server log persistence with `logdays` retention | `LogTable.cpp` |

## 6. Operator surface

| # | Missing | murmur reference |
|---|---|---|
| O1 | Ice, or the gRPC replacement it is being swapped for | `MumbleServerIce.cpp` (2 460 lines), `RPC.cpp` |
| O2 | Public server-list registration | `Register.cpp` |
| O3 | Zeroconf/Bonjour advertisement | `Zeroconf.cpp` |
| O4 | The `messagelimit`/`messageburst` token bucket — **silently drops** when wrong | `Meta.cpp` |
| O5 | Separate plugin-message rate limit | `Meta.cpp` |
| O6 | Unix daemon behaviour: setuid, PID file, signal handling | `UnixMurmur.cpp` |
| O7 | Log obfuscation of client IPs (`obfuscate`) | `Meta.cpp` |
| O8 | The rest of murmur's ~30 `Meta.cpp` knobs | `Meta.cpp` |

O4 is called out in `PORTING-PLAN.md` R5 as the risk most likely to look like a
client bug.

## 7. Protocol tail

| # | Missing | murmur reference |
|---|---|---|
| T1 | `ContextAction` (17) and `ContextActionModify` (16) — server-defined menu items | `Messages.cpp` |
| T2 | `PluginDataTransmission` (26) — opaque client-to-client plugin data | `Messages.cpp` |

---

## Ordering, and why

The dependency structure is not the same as the priority order.

1. **Voice (§1)** — without it Starling is not a Mumble server. It also has no
   dependency on the database, so it can go first. V1–V6 are the usable subset;
   V7–V9 refine it.
2. **Persistence (§5)** — everything in §2–§4 needs somewhere to put state. P1
   and P3 unblock the rest.
3. **Authority (§2)** — needs P1 for ACL and group tables. Blocks all of §4's
   moderation paths, because "can this user kick" is an ACL question.
4. **Channels (§3)** and **moderation (§4)** — mostly independent of each other
   once §2 and §5 exist.
5. **Operator surface (§6)** — O4 should jump the queue: it is a *correctness*
   risk, not a feature, and getting it wrong looks like a client bug.
6. **Protocol tail (§7)** — genuinely last. Nothing depends on it.

## What this list is not

It is a comparison of **surface**, not of behaviour. A handler existing in both
does not mean they agree: `UserState` is 340 lines in murmur against Starling's
174, and the difference is the admin paths in §4 U2. Parity needs the e2e suite
pointed at Starling, which is its own outstanding task.

## §1 Voice — status

Implemented, and measured end to end by
`src/tests/starling-voice.multiclient.test.ts` in the e2e suite: a tone spoken
by one client has to come out of another's decoder.

| Item | State |
|---|---|
| V1 UDP socket, per-peer `CryptState` | done — `starling-net`'s `VoiceSocket`, `starling-crypto`'s `Ocb2` |
| V2 `CryptSetup` (15) | done — keys generated at authentication, resync handled |
| V3 `UDPTunnel` (1) | done — demultiplexed in the TCP reader onto the audio lane |
| V4 audio routing | done — `RoutingSnapshot`, published by the authority |
| V5 `VoiceTarget` (19) | done — slots 1–30, whisper and shout with links and children |
| V6 codec negotiation | done — legacy and protobuf framing, chosen per peer |
| V7 channel listeners | routing supports them; nothing creates one yet (C-series) |
| V8 mute / deaf / suppress | done — enforced before a recipient list is built |
| V9 positional audio | carried through both wire formats, unmodified |

### Deliberately not done

* **Channel links** (`AudienceView::links`) are always empty: nothing can create
  a link yet, which is C4. The routing code handles them, so the gap is one
  producer rather than a feature.
* **Whisper permission checks.** murmur verifies `ChanACL::Whisper` before
  accepting a `VoiceTarget`; there is no ACL evaluation yet (A1), so a target is
  accepted as written. Permissive, and recorded rather than silent.
* **`XChaCha20-Poly1305` is live for any Fancy client at 0.4.0 or later.** Both
  ends are implemented — `starling-crypto`'s `XChaCha20Voice` and the client's
  `mumble-protocol::transport::modern_crypt` — and pinned to each other by wire
  vectors in both directions, cross-verified between the two implementations
  rather than self-checked.

  The server chooses from the Fancy version the *client* announced; the client
  reads the choice from the shape of the key material. Nothing depends on the
  server announcing a Fancy version of its own, which is what previously made
  this wait on the unrelated Fancy message surface (T1/T2).

  Still on OCB2: every stock Mumble client, forever, and any Fancy client whose
  Mumble version forces legacy audio framing — the legacy packet type is the
  codec and has nowhere to name a cipher.
