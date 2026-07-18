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

Starling **handles all 20** of murmur's 27 control messages that travel
client→server, and ignores the other 7 correctly.

```
handled   Version(0) UDPTunnel(1) Authenticate(2) Ping(3) ChannelRemove(6)
          ChannelState(7) UserRemove(8) UserState(9) BanList(10) TextMessage(11)
          ACL(13) QueryUsers(14) CryptSetup(15) ContextAction(17)
          UserList(18) VoiceTarget(19) PermissionQuery(20) UserStats(22)
          RequestBlob(23) PluginDataTransmission(26)
```

**Correctly ignored (7).** `Reject`(4), `ServerSync`(5), `PermissionDenied`(12),
`ContextActionModify`(16), `CodecVersion`(21), `ServerConfig`(24) and
`SuggestConfig`(25) travel server→client. murmur's handlers for these are empty
too; a client sending one is ignored, and that is correct behaviour rather than a
gap.

**Routed but unanswered: none.** `UserList`(18) was the last of them and is now
answered by `userdata`, in both of its modes — the empty message reads the
directory, a non-empty one renames and unregisters (§4, A1).

**Handled is not the same as complete.** `ACL`(13) answers a *query* and refuses
a *write*, so the client's ACL editor reads correctly and saves nothing (G1
below).

`CryptSetup`(15) and `VoiceTarget`(19) **are now answered**, and the estimate
this file carried for the first one was wrong in a way worth recording, because
it was wrong in the direction that flatters: *"it is three lines in a `match`"*.
The dispatch arm is indeed small. What the arm needed on the other side was not
there:

* `ResyncRequest::classify` reduced a present `client_nonce` to an eight-byte
  counter, and **neither cipher Starling ships uses an eight-byte nonce** — OCB2
  sends sixteen and `XChaCha20` sixteen of salt. Every real resync therefore fell
  through the `AdoptTheirs` arm into `SendMine`. The unit test passed because it
  fed the classifier a `u64`.
* `voice`'s `Resync` RPC answered by re-minting the whole session. A client
  accepts that, but it discards a working key and drops the peer back to
  tunnelling for a peer that only needed telling where the counter had got to —
  and murmur does not do it.
* Nothing could reach a peer's nonce at all: `Ocb2` had `server_nonce` and
  `resync_to`, but the packet path holds `Box<dyn VoiceCipher>` and the trait
  exposed neither.

So the shape now is murmur's where the cipher allows it and a re-key where it
does not, which is a real difference between the two ciphers rather than a
simplification: `XChaCha20-Poly1305` folds its salt into a derived subkey and has
no IV to swap. `crates/starling/src/e2e.rs` drives the whole round trip against a
live deployment — a client deliberately desynchronised, asking, and hearing
again.

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

**Whisper and shout work**, and so does the resync that keeps a UDP session
alive. `VoiceTarget`(19) fills a slot, `CryptSetup`(15) inbound is answered, and
both are driven against a live deployment by
`a_whisper_reaches_the_person_it_names_and_not_the_room` and
`a_client_whose_nonce_drifted_asks_for_a_resync_and_is_answered`. Three things
had to be built that this file's V3 entry did not mention, because reading the
routing core is not enough to see them:

* **Nothing populated `links` or `parent_of`.** The core resolves
  `include_links` and `include_children` correctly and always had; the snapshot
  it resolved them against was composed from `session-view`, which publishes
  membership and says nothing about how channels relate. A shout with links
  ticked reached the base channel and stopped — indistinguishable from a shout
  that worked, because the speaker *is* heard by someone. `voice/src/tree.rs`
  now subscribes to `metadata`'s `Watch`.
* **`with_targets` had no caller and could not simply gain one.** The snapshot
  is rebuilt from scratch on every membership change, so a registry living
  inside it loses every slot the moment somebody joins. The registry is held by
  the service and composed in on each publish.
* **Every registered target was reported to the listener as a shout.** murmur
  splits `SpeechFlags::Whisper` from `SpeechFlags::Shout` per *recipient*, and
  one target can do both at once, so the context is decided per listener rather
  than per frame.

Two divergences worth stating rather than discovering. `Whisper` is checked when
the slot is registered and not per packet — nothing on the packet path may make a
request (`docs/ARCHITECTURE.md` §3) — so **a right revoked after registration is
not noticed until the client registers again**; murmur invalidates its whisper
cache on an ACL change and voice has no such signal yet. And a target scoped to
an **ACL group** is dropped rather than widened to the whole channel: voice
cannot resolve group membership, and widening would send audio meant for one
group to the room.

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
| V8 | A whisper permission revoked after the slot was registered is not noticed until the client registers again; murmur invalidates its cache on an ACL change | `voice/src/service.rs` |
| V9 | A `VoiceTarget` entry naming an ACL **group** reaches nobody. murmur narrows the shout to that group's members; voice cannot resolve membership on the packet path, and widening to the channel would be the unsafe way to be wrong | `voice/src/service.rs` |
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

Nothing in this section is missing any more. What is left of that refusal is the
list it is written as the negation of — `moderates` in `session-lifecycle` — and
the shape of the U2 bug is the argument for keeping it in one place: `on_move`
held murmur's whole rule, permission checks and all, and was **unreachable** for
anybody but the sender, because the refusal above it dropped the message first.
Nothing failed and nothing was logged. The user clicked and did not move.

**Built since this list was written:**

* **U2** — moving another user, through the same `on_move`, now reached. Three
  questions in two steps (`Messages.cpp:1075`, `:1080`): `Move` on the channel
  they are being taken *out* of, then `Move` on the destination **or** the moved
  user's own `Enter` there. The second is asked as two calls because
  `Permit::allows` requires every bit it is given, and one two-bit request would
  demand both — which is the difference between an operator being able to drag
  somebody into a private room and not.
* **U6** — clearing another user's comment or avatar, through
  `on_reset_content`, taking `ResetUserContent` on the **root**: it is a power
  over people rather than over a room. Both halves of murmur's rule are enforced
  (`Messages.cpp:1236`), and the second is the one worth naming: the value must
  be **empty**. It is a reset, not an edit. Without it an administrator could put
  words into somebody else's profile, under that person's name, on every client
  — so a non-empty value is refused as `TextTooLong`, which is upstream's answer
  and reads oddly until you notice what it says: the permitted length of another
  person's content is zero.
* Found while wiring U6: setting your **own** comment or avatar wrote the hash to
  the account row and to the echo, and never to the connection record — which is
  what `session-view` is built from. So a new avatar reached everyone who
  reconnected after it and nobody who was already there.

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
| C5 | No name validation. murmur holds channel *and* user names to configurable regexes (`qrChannelName`, `qrUserName`, `Server.cpp:483`); Starling accepts any string | — |

**C1 — channel links — is built.** `links_add`/`links_remove` are read off the
wire, `LinkChannel` is enforced on the channel being edited *and* on each
channel being linked to (murmur's rule, `Messages.cpp:2053`), and the edge is
written into **both** channels, because audio crossing a link is a property of
the pair and a one-sided edge is a link that works in one direction. Three
things the wire forced:

* **An unlink is announced as `links_remove`, never as full state.** A stock
  client treats a non-empty `links` as the complete set and *skips the field
  when it is empty* (`vendor/server/src/mumble/Messages.cpp:935`), so a removal
  sent as a whole record leaves the edge on its screen for ever.
* **Both ends are announced, as separate frames.** A client keys a
  `ChannelState` by `channel_id`, so one message can only describe one channel.
* **A removed channel takes the links pointing at it.** `links` is a complete
  statement, so a dangling id would be re-sent on every announcement afterwards.

The honest caveat, and it is narrower than it was: a link now **does** reach
`voice`, because V3 gave it a `metadata` tree subscription that reads
`Channel.links` — so a shout with `include_links` carries across one. What still
does not cross a link is **ordinary channel speech**: `Target::Normal` resolves
to `audience_of(channel)` and stops there (`routing.rs:202`), while murmur sends
normal speech into every linked channel the speaker holds `Speak` in
(`Server.cpp:1370`). Two people in linked rooms therefore see the link, and hear
each other only if one of them shouts. That is one arm in `recipients` plus the
per-channel `Speak` check it needs, and it belongs with V3's owner rather than
here.

**C2 and C3 are enforced** (see §5), on the client path only:
`operator-api` and gRPC pass no ceiling, because an operator building a tree
through the admin surface is the person who set the limit — which is where
murmur draws the same line, `canNest` and the count check living in
`msgChannelState`.

**C4 was half true and is now closed.** Entry *did* enforce `max_users`; what
the entry described was real all the same — the rule was written out twice, once
in the entity where it was tested and once in the tree that clients actually
enter. Two homes for one rule is a rule that is eventually enforced in one of
them, so both now call `channel::is_full`.

## 4. Accounts

**Built:** registration over gRPC, `operator-api` and now from a client (see U7),
password (PBKDF2) and TOTP verification, certificate authentication, the
SuperUser account with a generated password announced once, comments and avatars
stored as content-addressed blobs.

| # | Missing | Notes |
|---|---|---|
| A4 | **No last-channel memory.** murmur records a registered user's channel on leaving and puts them back there on their next login (`DBWrapper::setLastChannel`, `:1463`); Starling stores nothing and every login lands in the root | — |
| A5 | `SuggestConfig`(25) is sent **empty** — `tcp::SuggestConfig::default()`. murmur fills in the version, positional-audio and push-to-talk it wants clients to adopt; the settings do not exist here, so the message is a formality | `handshake.rs:322` |

**A1 is done.** `UserList`(18) is answered in both modes, and the read is two
answers rather than one (`Messages.cpp:3153`): `Register` manages the directory
and comes with the whole record, `ReadRegister` — held by every registered user
by default — gets a name and an avatar, enough to find somebody who is offline
and invite them and not enough to learn when they were last here. The SuperUser
is left out, as upstream leaves it out, because the dialog's other two buttons
are "rename" and "remove". Writing takes `Register` and nothing else: letting
`ReadRegister` delete an account would make every registered user an
administrator of everybody else's.

Two things it needed that the entry did not predict. A rename could not go
through `Accounts::update`, which demands the account's *current password* for a
name change — right for a user editing their own profile, impossible for an
administrator who does not know it; renaming somebody else rests on `Register`
instead, so it is its own method. And the answer is **bounded**: the frame codec
refuses anything past 8 MiB, and a directory of avatars is the one message here
that can reach it — an unsendable frame would be this exact bug wearing a
different face, the operator opening the dialog and finding it empty.

A4 is what stops `last_channel` being filled in on a directory row: a zero there
is not "unknown" to a client, it is the root channel.

A client registration stores no password, so the account is claimed by its
certificate from then on. That is murmur's model and it is why `on_register`
refuses a target with no certificate: `authenticate` rejects a password-less
account claimed by name alone (`accounts.rs:227`), so the row would be an
account nobody can use, holding a name nobody else can register either.

## 5. Settings that exist and are never applied

**Every entry in this table is now enforced.** It is kept, rather than deleted,
because the shape of the failure is worth remembering: each one was in
`server-config`, settable, persisted — and read by nothing. An operator changed
it, the change was accepted, and nothing happened. That is worse than the
setting being absent, because absent is visible.

| Setting | Where it now takes effect |
|---|---|
| `text_message_length` | `text`, on `TextMessage` itself as well as on comments. murmur's `isTextAllowed` order: the body is measured **after** markup is stripped, so a limit meant for words is not spent on tags |
| `allow_html` | `text`. Off **rewrites** rather than refusing — murmur strips the markup and delivers the words, because the alternative punishes a user for their client's default formatting |
| `channel_nesting_limit`, `channel_count_limit` | `metadata`, on the client path only (C2/C3). murmur's `canNest`, including the subtree *height* when a branch is re-parented |
| `cert_required` | `session-lifecycle`, in the handshake and **after the identity is known**, as upstream places it (`Messages.cpp:508`, guarding on `id != 0`). Refused as `NoCertificate`, the one rejection a Mumble client answers by offering to generate one. The SuperUser is exempt and that is the whole of the rule: the administrator account carries no certificate on purpose, so enforcing this against it means an operator ticking a checkbox and losing the only login that could untick it |
| `listeners_per_channel`, `listeners_per_user` | `metadata::listen`, per channel in the request rather than for the request as a whole — a client asking for five channels with room for three gets three and is told which two were refused, rather than losing the request entire |
| `log_days` | `audit`, hourly. The chain is deliberately **not** re-linked across a sweep: retention is a deletion, and an audit log that could delete its history and still verify clean would be one that can be edited without evidence |
| `obfuscate_ips` | the log writer, at the one point every operator-facing record passes through. murmur's `<<hash>>:port`, salted per process — a pseudonym rather than a redaction, because the question asked of an address is "is this the same one", not "what is it" |
| `message_limit`, `message_burst` | the gateway's `control` bucket, re-read on the frame path, so a change reaches a client that never reconnects. Unset leaves the deployment TOML's own numbers alone |
| `allow_recording` | `session-lifecycle`. murmur kicks (`Messages.cpp:1417`), and the severity is the point: the flag is a voluntary disclosure, so the only client this catches is an honest one |
| `max_bandwidth` | `voice`, per peer, charged `20 + 8 + 4 + payload` as murmur does and measured in bytes against a budget of one eighth of the setting |
| `broadcast_listener_volume_adjustments` | `session-lifecycle`, on both the handshake roster and every listener change. **Off by default**, as murmur has it: how loudly somebody listens to a room is their own business, so the channels go to everyone and the gains to their owner alone — two messages, because one message cannot have two audiences |

`image_message_length` was the exception before any of this: it already bounded
avatars, and now also bounds a message body when HTML is allowed.

**Three things this uncovered, all fixed, all of the same kind:**

* **The admin API could write two of them.** `POST /v1/config` understood
  `welcome_text` and `max_users`; `GET` read back seven fields. So the whole of
  this section could be enforced by the server and still be unreachable from the
  surface an operator uses — a setting nobody can set has not stopped being a
  lie, it has only moved which layer tells it. Both directions now go through
  one table beside the defaults.
* **There were two default tables.** `server-config` served one and every
  service that could not reach it would have needed its own. A second copy is a
  copy that eventually disagrees, and the symptom would be a limit that depends
  on which service restarted last. They live in `starling_runtime::settings` and
  `server-config` re-exports them.
* **Reading a setting per action is a round trip per action.** Services
  subscribe to `server-config`'s change stream once at boot and read a cached
  snapshot, which is also what makes a setting *live* rather than applied at
  connect time. The fallback order is documented and never zero: live snapshot,
  then last known, then murmur's defaults — `max_users = 0` reads as "nobody may
  connect" and `message_limit = 0` as "no messages at all", so the value meaning
  "I do not know" must never be the one meaning "forbid everything".

## 6. ACL groups, tokens and writes

Found by the 2026-07-27 sweep; this file had not covered any of it, and §0 listing
`ACL`(13) as "handled" was true only for reads.

**All four are now done.** Kept in full rather than deleted, because each says
what the symptom looked like from outside, and the three of them that are one
mistake are worth being able to point at.

| # | Was missing | Now |
|---|---|---|
| G1 | **A client cannot write an ACL.** `on_acl_query` refuses any `ACL`(13) whose `query` flag is false, so the client's ACL editor submits and silently changes nothing. Writes exist only over gRPC (`SetAcl`) and `operator-api` | Done. `on_acl_write` takes `Write` on the channel **or** on the root, replaces the table wholesale, persists write-through, invalidates before acknowledging, and answers with the stored set. `permissions/src/lib.rs` |
| G2 | **Access tokens do nothing.** `Subject.tokens` is in the proto, is written as `Vec::new()` at every call site, and `permissions` never reads it. So `#token` groups cannot match — **channel passwords do not work** | Done. `Authenticate.tokens` is recorded on the connection, carried on `Session` and read back into `Subject`; a second `Authenticate` replaces them mid-session; `UserState.temporary_access_tokens` rides on the one `Enter` check it was sent for, through `SessionCheckRequest.temporary_tokens` |
| G3 | **Most of murmur's group grammar is absent.** `groups_of` recognises `all`, `auth` and named groups. Upstream (`src/Group.cpp:120-185`) also has `none`, `strong` (a verified certificate), `in`, `out` and `sub[,offset,min,max]`, plus four prefixes: `!` negate, `~` evaluate against the ACL's own channel, `#` access token, `$` certificate hash. `matches` compares the group name with `==`, so every one of these is read as an ordinary group name that nobody is in | Done, whole grammar, in `permissions/src/group.rs`. Named groups are now *resolved* through the chain — `inherit` and `inheritable` were ignored before, so a group a parent declared as not inheritable was held in every child |
| G4 | **An ACL entry naming account 0 also matches every guest.** `matches` compares `entry.account == subject.account` without consulting `registered`, and an unregistered guest is written as `account = 0, registered = false` — the same pair the SuperUser has. `identity::account` exists for exactly this and is used two lines away at `:182` | Done, as a rider on G3: `matches` was being rewritten for the grammar, and it is the function the bug is in. Now `identity::account(...) == entry.account`, and an entry may name an account *and* a group as upstream allows |

G4 was the third appearance of one mistake: the file's own comments record
fixing it in `is_superuser` (the constant was 1, granting everything to the first
ordinary account) and in `@auth` (read as "connected" rather than "registered").
The pair must be interpreted through `identity`, never by comparing `account`.

**`@strong` is parsed and matches nobody.** The grammar accepts it, the
evaluator reads `subject.strong_cert`, and that field is only ever `false`:
`PeerCertificate::strong` has exactly one write in the tree
(`crypto/src/peer_cert.rs:90`), and no client CA is configurable for the control
plane — the one `client_ca` setting belongs to the operator API's own mTLS.
Nothing validates a chain, so nothing can set it.

It fails **closed**: an entry granting to `@strong` grants to nobody, and one
restricting to it excludes everybody. Recorded here rather than quietly left,
because a group an operator can write which silently matches nobody is the §5
failure wearing an ACL: the table reads as though a rule is in force. Closing it
means CA verification with a configured trust anchor — a design decision about
*whose* certificates a deployment trusts, not a missing line. Until then, do not
key a privilege off `@strong`.

The full reasoning, and four other findings on this path, are in
`SECURITY-AUDIT-identity.md`.

**`qsTemporary` — temporary group membership — is now built too.** Group
membership granted to a live *session* rather than to an account, and **no
client can create one**: the only writers upstream are Ice
(`MumbleServerIce.cpp:2307`, `:2338`) and `Server::setTempGroups`
(`RPC.cpp:235-247`). The `qsTemporary` uses in `ACLEditor.cpp` are the *client*
reusing that field to display `inherited_members`, and it never sends it back.

It is worth having despite being invisible from a client, because of what it is
*for*: an external authenticator granting a group to an **unregistered** user.
Permanent membership (`qsAdd`) is keyed on account id, so a guest can never be
in a named group by any other means. Starling reaches it through `operator-api`
rather than Ice (S6): `POST`/`DELETE /v1/channels/{id}/groups/{group}/members`,
naming either an `account` or a `session`.

Three properties, each of which is a silent failure if missed, and each covered
by a test:

* **It ends with the session.** Session ids are pooled and reissued —
  `Server.cpp:1904` re-queues them and Starling's allocator does the same — so a
  grant that outlived its holder would be inherited by the next arrival.
  `permissions` subscribes to `session-view` for departures, and clears every
  session-scoped grant outright if that stream ever drops, since a missed
  departure is exactly the case it cannot distinguish.
* **It survives an ACL save.** murmur stashes each group's temporary set before
  deleting the channel's groups and restores it while looping over the *new*
  ones (`Messages.cpp:2842`, `:2900`) — so a group the operator kept keeps its
  members and a group they deleted does not. Starling holds the memberships in
  their own table keyed by `(scope, channel, group)`, which makes preservation
  the default rather than a step every new write path has to remember; `set`
  drops only the names the new table no longer declares.
* **It is not durable**, exactly as upstream says of its own ("This state is not
  saved"). A session-scoped grant that survived a restart would name a session
  id belonging to somebody else.

Starling's storage deliberately does *not* copy upstream's encoding, which packs
accounts and sessions into one integer set by negating the session
(`Group.cpp:242`). That collides: an unregistered user's account id is `-1`,
which is also session 1 negated, so on a murmur server the first session to
connect is in every group any guest is in. `evaluate::Member` names the two
cases instead.

Still not here, deliberately: **the `ChannelState` resend after a token edit**
(`Messages.cpp:385`), which re-renders which channels a client may now enter.
The tree belongs to `metadata`; entry itself works without it, and the client
learns the door is open by walking through it.

## 7. Absent subsystems

| # | Missing | murmur reference |
|---|---|---|
| S1 | Zeroconf/Bonjour advertisement | `Zeroconf.cpp` |
| S2 | The screen-share SFU — no `str0m` dependency exists; `screenshare` is signalling only | Fancy fork |
| ~~S3~~ | ~~`zstd` on the Fancy control stream~~ **Done.** The gateway batches queued frames and compresses the batch, under outer type 1900, only for a peer that announced `zstd` in its `Hello` | Fancy fork |
| S4 | A session store that outlives a gateway pod. The resume ring is in-process, so RESUME cannot cross one | `ARCHITECTURE.md` §5 |
| S5 | Sharding. Every shard key in `scaling.puml` is a design decision; nothing is sharded | |
| S6 | Ice. Replaced by `operator-api`, which covers accounts, the ban list, config and the SuperUser password — not the whole Ice surface, which `FANCY-PARITY.md` §2 enumerates | `MumbleServerIce.cpp` |
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

1. ~~**G1 — let a client write an ACL.**~~ **Done.** The permission model
   underneath is the most complete part of the server, and none of it was
   reachable from the tool every operator uses.
2. ~~**`CryptSetup`(15).**~~ **Done**, and *not* three lines — the estimate is
   dissected in §0. The dispatch arm was small; what it needed underneath was a
   classifier shaped for a nonce width neither shipped cipher uses, an RPC that
   answered by discarding a working key, and a trait with no way to reach a
   peer's nonce at all.
3. ~~**`UserList`(18).**~~ **Done**, in both modes. The estimate — *"userdata
   already holds the data and already has a `List` RPC"* — was right about the
   read and missed the write: an administrator renaming somebody could not use
   the account update path at all, because it asks for a password only that
   account's owner knows. See §4.
4. ~~**G4, the guest/SuperUser account collision.**~~ **Done**, alongside G3 —
   it is a line in the function the grammar rewrote. It was the one item on this
   list that granted permission rather than withholding it.
5. ~~**U2, moving another user.**~~ **Done**, and it was not the rule that was
   missing — `on_move` already held both branches of it. What was missing was
   the dispatch: the cross-session refusal above it dropped the message before
   the handler was ever asked. See §2.
6. ~~**V3, whisper and shout.**~~ **Done.** `VoiceTarget`(19) was indeed the
   missing arm, but two of the three things it needed were not the arm: nothing
   populated the channel links the core resolves against, and the target
   registry could not live where the snapshot does. See §1. What remains is V8
   and V9, both narrow.
7. ~~**G2 and G3, tokens and the group grammar.**~~ **Done**, ahead of their
   place in this order because they were asked for together with G1. Channel
   passwords were the feature users actually noticed missing; `in`/`out`/`sub`
   and the prefixes are what an operator writing a real ACL table reaches for.
8. ~~**§5, the settings that do nothing.**~~ **Done**, all ten, and cheap
   individually as predicted — but the estimate missed what they had in common.
   Each was cheap to *enforce* and none of them was reachable: the admin API
   could write two of the ten, there was no shared way to read a setting, and
   the defaults would have needed a second copy in every service that enforced
   one. The settings are a third of the diff; the three things underneath them
   are the rest. See §5.
9. ~~**C1 channel links**, then the limits in C2/C3/C4.~~ **Done.** C4 was
   already enforced and the entry was still worth acting on — the rule had two
   homes. What remains of C1 is that ordinary speech does not cross a link,
   which is one arm in voice's `recipients`; see §3.

A3 (`cert_required`) and U6 (`ResetUserContent`) are **done**, both as riders as
predicted. A4, A5 and C5 are cosmetic against the rest of this list.
