# What vanilla murmur has that Starling does not

Measured against **upstream `mumble-voip/mumble`, branch `1.6.x`** — deliberately
upstream rather than `vendor/server`, so the target is the protocol as everyone
else implements it and not the Fancy fork's superset.

Re-verified against the code on **2026-07-27**. Every "missing" below was checked
by reading the handler, not by remembering — which is the only way this file
stays useful, because it drifts in the direction that flatters nobody: the last
pass found `UserRemove`(8), temporary-channel collection and positional audio all
listed as missing and all built, while the entries that *were* still missing were
missing exactly as described.

---

## 0. The baseline, stated honestly

Starling **handles 17** of murmur's 27 control messages, ignores 7 correctly, and
leaves 3 unanswered.

```
handled   Version(0) UDPTunnel(1) Authenticate(2) Ping(3) ChannelRemove(6)
          ChannelState(7) UserRemove(8) UserState(9) BanList(10) TextMessage(11)
          ACL(13) QueryUsers(14) ContextAction(17) PermissionQuery(20)
          UserStats(22) RequestBlob(23) PluginDataTransmission(26)
```

**Correctly ignored (7).** `Reject`(4), `ServerSync`(5), `PermissionDenied`(12),
`ContextActionModify`(16), `CodecVersion`(21), `ServerConfig`(24) and
`SuggestConfig`(25) travel server→client. murmur's handlers for these are empty
too; a client sending one is ignored, and that is correct behaviour rather than a
gap.

**Routed but unanswered (3)** — the gateway delivers these to a service that has
no arm for them, so the client is met with silence:

| Type | What the client wanted | Where it lands |
|---|---|---|
| `CryptSetup`(15) | **resync its voice cipher** | `session-lifecycle`, no arm |
| `UserList`(18) | the registered-users dialog | `userdata`, no arm |
| `VoiceTarget`(19) | register a whisper/shout target | `voice`, an arm that returns nothing |

**Handled is not the same as complete.** `ACL`(13) answers a *query* and refuses
a *write*, so the client's ACL editor reads correctly and saves nothing (G1
below). `VoiceTarget`(19) has an arm that returns nothing at all.

`CryptSetup`(15) is the one to notice. A client whose UDP nonce falls out of sync
asks for a resync and recovers; here it asks and is never answered, so it stays
broken for the rest of the session. It costs nothing to answer — `voice` already
mints the material — and it is three lines in a `match`.

---

## 1. Voice

**Channel speech now works, over both transports.** A peer joins the packet path
when its cipher is minted, membership comes from a `session-view` subscription
rather than a lookup per packet, and audio arrives either as a datagram on
voice's own socket or as `UDPTunnel` through the gateway. The two mix freely in
both directions — a client on UDP is heard by one that is tunnelled, and the
reverse — which is the state a real server is in constantly. A peer that starts
tunnelling has its proven UDP address dropped, as murmur does
(`Server.cpp:1911`), so a path that breaks mid-call recovers.

Covered end to end: `one_client_is_heard_by_another_over_the_tunnel` and
`a_datagram_on_the_voice_port_is_relayed_to_the_channel` in `crates/starling/src/e2e.rs`
drive two live clients through a real deployment.

**Also built:** the UDP socket, per-peer ciphers (OCB2-AES128 and
XChaCha20-Poly1305), `CryptSetup` minting, the legacy and protobuf packet codecs,
the routing core with its fan-out and per-listener sealing, cross-format
re-encoding, and the unauthenticated server-browser ping.

**Positional audio passes through**, which this file previously listed as
missing. Both codecs read the coordinates (`packet.rs:323` legacy, `:407`
protobuf) and both write them back (`:348`, `:435`); `route` rewrites `sender`
and `target` and leaves the field alone, so it survives re-encoding between the
two formats. Partial coordinates are discarded rather than zero-filled. Nothing
covers it with a test, which is the honest caveat.

| # | Missing | Evidence |
|---|---|---|
| V3 | `VoiceTarget`(19) is a stub — **no whisper, no shout**. The routing core already resolves targets, links and shout-into-children, and `TargetRegistry` is wired into it through `with_targets`; nothing ever fills a slot | `voice/src/service.rs` |
| V5 | Channel listeners: `UserState.listening_channel_add` appears nowhere, so nothing ever populates `with_listener` | `voice/src/view.rs:115` |
| V6 | No codec negotiation or `recheckCodecVersions`; `CodecVersion` is sent once and never revisited | `session-lifecycle` |
| V7 | No bandwidth enforcement. `max_bandwidth` is advertised in `ServerSync` and never applied | `handshake.rs` |

Two things found by wiring this up, both fixed, both worth recording because
neither had a symptom other than silence:

* **Tunnelled audio was charged to the `control` rate-limit bucket** — murmur's
  1 message per second. A client behind a UDP-blocking firewall was throttled
  off the air after its first few frames. Upstream does not rate-limit this path
  at all: `UDPTunnel` is handled and returned from at the top of
  `Server::message` (`Server.cpp:1905`), before the message-rate check. There is
  now an `audio` bucket, in the defaults *and* in both shipped TOMLs, with a
  test that the three agree.
* **A frame that decrypts but does not parse now says so.** It was counted and
  dropped in silence, which is the one failure with no other symptom: the peer
  is attributed, its cipher works, its packets are counted, and it is inaudible.
  The log names the peer's negotiated codec and the frame's leading byte,
  because it is nearly always the two sides disagreeing about the wire format.

## 2. Acting on another user

`on_user_state` refuses edits naming a session other than the sender's *unless* a
handler claims the request first. Two do: the speak-state flags and registration.
Everything else still falls to that refusal, which is safe by default and silent.
Kicking and banning do not come through here at all — they are `UserRemove`(8),
and `moderation` owns them.

| # | Missing | murmur permission |
|---|---|---|
| U2 | Move another user between channels | `Move` |
| U6 | Reset another user's comment or avatar | `ResetUserContent` |

**Built since this list was written:**

* **U1 and U3** — mute, deafen, un-mute and priority speaker, through
  `on_speak_state`, taking `MuteDeafen` on the *target's* channel. These were
  applied and broadcast but **not enforced** until `announce_changed` was fixed
  to carry them: session-view's `Upsert` replaces the whole record, the
  announcement omitted `mute`/`deaf`/`suppress`, and `voice` reads a speaker's
  silence from nowhere else — so a muted user was rendered as muted by every
  client and stayed audible to all of them. Worth recording as the shape of the
  failure: the moderation path, the broadcast and the user list all agreed, and
  the one service that had to act on it had been told the opposite.
* **U4 and U5** — kick and ban, through `moderation`'s `on_user_remove`. The
  permission is checked on the root channel because removal is from the server
  rather than from a room, and it is `Ban` **or** `Kick` for a kick and `Ban` for
  a ban — asked as two questions, since `Permit::allows` requires every bit it is
  given and one request for both would demand the ban power to perform a kick.
  The connection is closed as well as announced: announcing a removal without
  closing the socket leaves the user connected and talking while every other
  client has stopped rendering them.
* **U7** — register another user, or self-register, through `on_register`, which
  takes `Register` or `SelfRegister` on the root channel and requires the target
  to hold a certificate, as murmur does.

The SuperUser is guarded on each of these: it cannot be silenced
(`Messages.cpp:1131`) and it cannot be kicked or banned (`Messages.cpp:1609`),
both for the same reason — `Ban` or `MuteDeafen` in the root channel must not be
enough to lock the owner out of their own server. Registration needs no such
guard: the SuperUser is account 0 and already registered, so it is refused by the
already-registered branch.

`suppress` remains refused for every caller, and that is parity rather than a
gap: it is the server's own statement that a user lacks `Speak`, and murmur
refuses any client that sets it (`Messages.cpp:1135`).

**One deliberate divergence.** murmur refuses mute, deafen, suppress *and*
priority speaker against the SuperUser in a single block
(`Messages.cpp:1131`), so no account on a murmur server can make the
administrator a priority speaker. Starling narrows that guard to the three that
silence somebody: the rule exists so nothing can be taken away from the account
that repairs a broken ACL table, and priority speaker grants rather than takes.
Silencing the SuperUser is still refused.

Bans are now complete end to end: issued over gRPC *or* from a client's
right-click, recorded, checked on connect, and listed back to a client holding
`Ban`.

## 3. Channels

**Built:** create, rename, edit, remove, enter, the tree flood at login, and
permission checks on all of it. Temporary channels are modelled **and collected**
— `collect_temporary` runs when the last member leaves and when one moves away
(`tree_actor.rs:299` and `:314`), and the collection is announced, because a
client rendering a channel that has gone has no other way to find out.

| # | Missing | Notes |
|---|---|---|
| C1 | **Channel links.** `links_add`/`links_remove` appear nowhere; the `Link` RPC exists but nothing reaches it | `LinkChannel` is enforced nowhere because nothing links |
| C2 | `channel_nesting_limit` is never enforced — a client may nest arbitrarily | value exists in `server-config` |
| C3 | `channel_count_limit` is never enforced | value exists in `server-config` |
| C4 | **A channel's own user limit is modelled and never applied.** `Channel::is_full` handles murmur's `max_users == 0 means unlimited` correctly and is covered by tests, but nothing outside those tests calls it, so entry ignores it | `metadata/src/channel/entity.rs:56` |
| C5 | No name validation. murmur holds channel *and* user names to configurable regexes (`qrChannelName`, `qrUserName`, `Server.cpp:483`); Starling accepts any string | — |

## 4. Accounts

**Built:** registration over gRPC, `operator-api` and now from a client (see U7),
password (PBKDF2) and TOTP verification, certificate authentication, the
SuperUser account with a generated password announced once, comments and avatars
stored as content-addressed blobs.

| # | Missing | Notes |
|---|---|---|
| A1 | `UserList`(18) — the registered-users dialog is unanswered | routed to `userdata` |
| A3 | `cert_required` is never enforced; a certificate-less client is admitted regardless | value exists in `server-config` |
| A4 | **No last-channel memory.** murmur records a registered user's channel on leaving and puts them back there on their next login (`DBWrapper::setLastChannel`, `:1463`); Starling stores nothing and every login lands in the root | — |
| A5 | `SuggestConfig`(25) is sent **empty** — `tcp::SuggestConfig::default()`. murmur fills in the version, positional-audio and push-to-talk it wants clients to adopt; the settings do not exist here, so the message is a formality | `handshake.rs:322` |

A client registration stores no password, so the account is claimed by its
certificate from then on. That is murmur's model and it is why `on_register`
refuses a target with no certificate: `authenticate` rejects a password-less
account claimed by name alone (`accounts.rs:227`), so the row would be an
account nobody can use, holding a name nobody else can register either.

## 5. Settings that exist and are never applied

Each of these is in `server-config`, settable, and read by nothing. That is worse
than absent: an operator changes it, the change is accepted and persisted, and
nothing happens.

| Setting | State |
|---|---|
| `text_message_length` | applied to **comments** only, not to `TextMessage` itself |
| `channel_nesting_limit`, `channel_count_limit` | never read |
| `cert_required` | never read |
| `listeners_per_channel`, `listeners_per_user` | never read — there are no listeners |
| `log_days` | never read; the operator log has no retention |
| `obfuscate_ips` | never read; addresses are logged in full |
| `message_limit`, `message_burst` | read back by `operator-api` and applied nowhere. The gateway's buckets come from the **deployment TOML** instead, so murmur's runtime-tunable rate limit is not tunable at runtime |
| `allow_html`, `allow_recording` | advertised to the client in `ServerConfig`, never enforced |
| `max_bandwidth` | advertised in `ServerSync` and `ServerConfig`, and reported in the server-browser ping as `max_bandwidth_per_user`. Never enforced — nothing measures or caps a peer's rate |

`image_message_length` is the exception: it now bounds avatars.

## 6. ACL groups, tokens and writes

Found by the 2026-07-27 sweep; this file had not covered any of it, and §0 listing
`ACL`(13) as "handled" was true only for reads.

| # | Missing | Evidence |
|---|---|---|
| G1 | **A client cannot write an ACL.** `on_acl_query` refuses any `ACL`(13) whose `query` flag is false, so the client's ACL editor submits and silently changes nothing. Writes exist only over gRPC (`SetAcl`) and `operator-api` | `permissions/src/lib.rs:589` |
| G2 | **Access tokens do nothing.** `Subject.tokens` is in the proto, is written as `Vec::new()` at every call site, and `permissions` never reads it. So `#token` groups cannot match — **channel passwords do not work** | `session-lifecycle/src/lib.rs:337` |
| G3 | **Most of murmur's group grammar is absent.** `groups_of` recognises `all`, `auth` and named groups. Upstream (`src/Group.cpp:120-185`) also has `none`, `strong` (a verified certificate), `in`, `out` and `sub[,offset,min,max]`, plus four prefixes: `!` negate, `~` evaluate against the ACL's own channel, `#` access token, `$` certificate hash. `matches` compares the group name with `==`, so every one of these is read as an ordinary group name that nobody is in | `permissions/src/evaluate.rs:117`, `:213` |
| G4 | **An ACL entry naming account 0 also matches every guest.** `matches` compares `entry.account == subject.account` without consulting `registered`, and an unregistered guest is written as `account = 0, registered = false` — the same pair the SuperUser has. `identity::account` exists for exactly this and is used two lines away at `:182` | `permissions/src/evaluate.rs:210` |

G4 is the third appearance of one mistake: the file's own comments record fixing
it in `is_superuser` (the constant was 1, granting everything to the first
ordinary account) and in `@auth` (read as "connected" rather than "registered").
The pair must be interpreted through `identity`, never by comparing `account`.

G1 is the one an operator meets first. Reading an ACL takes `Write` and is
enforced; writing one is refused for everybody, including the SuperUser.

## 7. Absent subsystems

| # | Missing | murmur reference |
|---|---|---|
| S1 | Zeroconf/Bonjour advertisement | `Zeroconf.cpp` |
| S2 | The screen-share SFU — no `str0m` dependency exists; `screenshare` is signalling only | Fancy fork |
| S3 | `zstd` on the Fancy control stream — a workspace dependency no source file uses | Fancy fork |
| S4 | A session store that outlives a gateway pod. The resume ring is in-process, so RESUME cannot cross one | `ARCHITECTURE.md` §5 |
| S5 | Sharding. Every shard key in `scaling.puml` is a design decision; nothing is sharded | |
| S6 | Ice. Replaced by `operator-api`, which covers accounts, the ban list, config and the SuperUser password — not the whole Ice surface | `MumbleServerIce.cpp` |
| S7 | `--all-in-one` uses local sockets, not in-process pipes: a service cannot resolve its own endpoint through the broker before registering, so it falls back | `runtime/src/channel.rs` |

## 8. What is built

Stated because a list of holes is not a description of a system.

The gateway (TLS, framing, type-keyed routing, per-route rate limiting, circuit
breakers, the resume ring). All twenty services, serving gRPC. The full handshake,
end to end over a real socket, with an e2e test that drives it. Storage — `sqlx`
over SQLite, MySQL or PostgreSQL, one schema per service, twelve services using
it. ACL evaluation with murmur's default permission set, inheritance through the
channel tree, and durable ACL tables.

Permission **enforcement** on channel create, edit and remove, on channel entry,
on text messages, on ACL reads, on the ban list, on muting and deafening, on
kicking and banning, and on registering a user — with identity resolved
server-side so a caller cannot assert one. Bans, end to end. Text and its
history. Comments and avatars, size-bounded and content-addressed. The operator
log and `operator-api`. Public-list registration and the server-browser ping.

---

## Ordering, and why

1. **G1 — let a client write an ACL.** The permission model underneath is the
   most complete part of the server, and none of it is reachable from the tool
   every operator uses. `SetAcl` already exists; this is a handler that checks
   `Write` and calls it, and it makes §6 worth fixing at all.
2. **`CryptSetup`(15).** Three lines, and now that audio routes it is the thing
   most likely to break a working call: a client whose UDP nonce falls out of
   sync asks for a resync, is never answered, and stays silent for the rest of
   the session.
3. **`UserList`(18).** Registration works from a client now, which makes the
   unanswered registered-users dialog the next thing an operator meets: they
   register somebody successfully and the list they would check it in is empty.
   `userdata` already holds the data and already has a `List` RPC.
4. **G4, the guest/SuperUser account collision.** Small, and it is the one item
   on this list that grants permission rather than withholding it.
5. **U2, moving another user.** The last piece of moderation an operator reaches
   for, and the only one of murmur's `Move` semantics still missing: the mover
   needs `Move` on the destination *or* the moved user needs `Enter` on it.
6. **V3, whisper and shout.** The routing core already resolves targets, links
   and shout-into-children; only `VoiceTarget`(19) is missing, so this is the
   next-largest gap between effort and effect.
7. **G2 and G3, tokens and the group grammar.** Channel passwords are the
   feature users actually notice missing; `in`/`out`/`sub` and the prefixes are
   what an operator writing a real ACL table reaches for next.
8. **§5, the settings that do nothing.** Cheap individually, and each one is
   currently a lie told to an operator.
9. **C1 channel links**, then the limits in C2/C3/C4.

A3 (`cert_required`) is small and can ride along with §4. U6
(`ResetUserContent`) is small and can ride along with U2, since both are a
`UserState` naming another session. A4, A5 and C5 are cosmetic against the rest
of this list.
