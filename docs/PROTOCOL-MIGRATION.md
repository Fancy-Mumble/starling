# Protocol migration

The ordered steps that carry Starling and the Fancy client from the epoch-1
dialect they speak today to the canon in `PROTOCOL-REDESIGN.md`. That document
says what the protocol *is*; this one says how the two ends get there without a
window where they cannot talk.

Split out of `PROTOCOL-REDESIGN.md` §9, which it is still numbered against:
references to §1 through §8 and §10 mean sections of that document.

Ordered so every intermediate state is safe to ship, **which the re-analysis
showed the starting state was not**: both ends already claim epoch 1 and
corrupt each other (D1), so the order now begins with the step that makes the
present honest. The L2 tags stay movable until M2c because no shipped peer
speaks the canon, the one client that claims epoch 1 speaks a dead dialect of
it, and after M4 they are frozen like everything else.

**M1 through M6 have all landed.** They ran in the order M2h → M2p → M2a →
M2b → M2c → M3 → M4 → M5 → M6, each intermediate state shippable, and the
entries below are kept as the record of what each one changed and why — the
reasoning is the part that outlives the step.

What remains is not a milestone but a list: the services still relaying because
they have no canon (screenshare), and the fixture coverage that follows each
one as it gains a canon. **userdata and link-preview came off that list**:
both are built now, see M2b.

* **M1, canon markers. Done.** Tombstone the proto2 envelope block in
  `Mumble.proto`; land `fancy/wire.proto` and `SyncDelta`; this document.
  Nothing on any wire changed.
* **M2a, the canon settles its own shape. Done.** The last window where L2
  tags may move freely, so everything that moves them happened at once:
  pchat's `Reaction` and `Receipt` arms removed and their tags `reserved`
  (D2); `Cursor`/`PageInfo` adopted by pchat, text and audit; `Emoji` by
  social; `Refusal` by moderation and files; `MessageRef` by text's `Edit` and
  `Delete`. `Cursor::page_size` fixes a bug all three paginated services
  shared, an unset `limit` is proto3-indistinguishable from 0, which every
  caller clamped up to 1, so a client that never set the field paged one entry
  at a time. **onboarding moved off the dead proto2 envelope** (the D1 instance
  inside Starling) and onto a canon that can carry what its answers grant.
  `Step.Choice` names the channels and ACL groups a choice confers, `Flow`
  carries `enabled` / `default_channels` / attribution, and `Response` batches
  a whole submission with the `flow_version` it answered, where the canon had
  a generic four-field wizard that could express none of it. Applying the
  grants is the other half, done in M2b below.
* **M2h, make the break honest. Done.** Three changes in `vendor/client`:
  the handshake stops announcing `fancy_protocol` (extracted to
  `client::version_announcement`, so the claim has one home a test can read),
  `select_codec` returns `LegacyCodec` for an epoch-1 peer, and, the part that
  outlives the hotfix, **an undecodable service frame is skipped instead of
  propagating**. That last one was a latent connection-killer: `codec::decode`
  used `?` on the envelope decode, so one frame from a peer whose envelope
  shapes differ tore down a working connection and turned a protocol skew into
  an unexplained reconnect loop. `fancy_version` still goes out: it is a
  product version and remains true, only the claim about the wire was false.

  The original statement of the problem, kept because the reasoning is what
  makes the ordering non-negotiable: today the
  client announces `fancy_protocol = 1`, selects `NativeCodec` against
  Starling, and the two ends corrupt each other in both directions. Until its
  codec encodes the canon, the client must be what it actually is, a peer
  that does not speak epoch 1: stop announcing `fancy_protocol`, and
  `select_codec` returns `LegacyCodec` unconditionally (one site,
  `fancy_codec.rs`, with the constant left at 1 for M2c). Starling then treats
  it as a plain-Mumble peer and relays `PluginData`, so every feature with
  that fallback (typing, watch-sync, WebRTC signalling, pchat key
  distribution) starts *working* again, and `ServerOnly` features go visibly
  off instead of silently wrong. This is strictly better than the present on
  both axes, which is why nothing may overtake it.

  Not the server side, deliberately: silencing Starling's announcement would
  fix the client's lie by adding a server lie, break the e2e stack's only
  epoch-1 speaker, and have to be un-shipped in lockstep with M2c across two
  trees. The client is the peer whose claim is false; the correction belongs
  where the falsehood lives.
* **M2p, the unset-limit rule, on every plane. Done.** `page::page_size` now
  states it once for a bare `u32`, `Cursor::page_size` delegates to it, and the
  three surviving `clamp(1, max)` sites (audit's L3 query, text's history,
  userdata's account list) call it. No `clamp(1,` remains in any service or in
  operator-api. The original finding:

  The re-analysis found the
  `clamp(1, max)` bug fixed for L2 in M2a alive on the mesh and REST planes:
  audit's L3 `query` clamps at `lib.rs:226`, text's L3 `History` RPC feeds the
  same clamp, and operator-api's new `GET /v1/log` passes a serde-default 0
  straight into it, **an operator querying the log without a limit gets
  exactly one entry.** The rule, stated once: *an unset limit means the
  default page, never one entry.* One shared helper (the semantics of
  `Cursor::page_size`, callable from a bare `u32` for L3 requests), applied at
  the service (not at operator-api, so every caller of the RPC is covered)
  plus a sweep for remaining `clamp(1,` sites in services.
* **M2b, complete the canon for the shipped features.** The D4 finding: the
  proto3 sets are a minimal green-field design, and several are smaller than
  what has shipped. Each of these must carry its feature's information before
  a client can move onto it, and none of it is a framing question:

  **First, a correction to how this list was drawn.** It originally measured
  each canon message against its epoch-0 counterpart and called every
  difference a gap. That is the wrong test twice over. A field is only missing
  if *this* plane still owes it, and for two of the six the service does not
  implement the feature at all, where designing a wire ahead of the code is
  how the minimal sets became wrong in the first place. Re-checked against
  what each service actually does:

  | Service | Status | Finding |
  |---|---|---|
  | server-config | **done** | Real, and blocking. `ConfigValues` now carries `repeated Setting` (key, kind, group, label, value, secret, help) plus the snapshot `version` a client drops stale replies by. The schema lives in one table in `snapshot.rs` where each row holds both its metadata *and* the accessor that reads it, because the value map and the `redacted` name list were two lists keyed by the same strings, and two such lists drift into a password on a settings screen. Keys from `Snapshot.extra` are offered as untyped strings rather than dropped, so the add-a-knob-without-a-proto-release mechanism keeps working |
  | audit | **done**, and it was worse than a missing field | `Query` gained `target_account`; `AuditRecord` gained `target_account` and `target_channel`, which the store had held all along while the record dropped them, so "banned" arrived without saying whom, and a reader had to parse the human-readable `detail` to find out. **The real bug was underneath:** `QueryRequest` already carried `until_ms`, `category`, `target_account` and `before`, and the statement bound *none* of them. An operator narrowing the log got the whole log back, looking narrowed. A filter that is accepted and ignored is worse than one that is refused, because whoever reads the result believes it. Now built with a `QueryBuilder` so each clause sits beside its own bind |
  | ~~onboarding~~ | **done** | The canon carried the grants at M2a; applying them was service work, and is done below |
  | ~~plugins~~ | **not a gap on this plane** | The client-facing `Admin` arm is *refused by design*, "plugin administration is an operator action and takes an operator identity, which the client plane does not carry". `marketplace_id`, `installed_at`, `builtin` and `path` are an operator-surface concern, so they belong to operator-api's REST routes, not here. Epoch 0 put plugin admin on the client wire; Starling deliberately moved it |
  | ~~push~~ | **closed** | The canon had the semantics backwards, `Subscribe` was an *inclusion* list, and a user mutes two rooms out of forty rather than enumerating the other thirty-eight (and any channel created later would silently stop notifying). Now an exclusion list, which is the thing a person actually does. Closing it exposed that the feature was a **complete no-op**: `Subscribe` was never handled (it fell to `ok: false`), `Register` stored `channels: Vec::new()` and discarded the preference, every registration was filed under `account: 0` while every lookup asked for a real account, and `Notification` carried no channel, so delivery had nothing to compare a mute against. All four fixed; a muted channel no longer buzzes the phone, and there is a test saying so |
  | ~~link-preview~~ | **done, and the feature is built** | The service vetted a URL and returned an empty `Preview`; it had no HTTP client at all. It fetches now (`fetch.rs`, `parse.rs`). The `preview_data`-versus-`image_key` question is answered by leaving `image_key` **empty**: it names an object in the files service, nothing stores one yet, and putting the remote URL there would send every viewer to fetch it — the exact network probe that server-side previews exist to prevent. The guard is the interesting part. The textual check was never enough, because a name resolves to whatever its owner says, so the fetcher resolves the host itself, drops every address inside the deployment, and **connects to the address it checked** rather than to the name — connecting by name re-resolves, and the second answer need not match the first, which is DNS rebinding. Every hop of a redirect is re-checked, since a public URL that 302s to `169.254.169.254` is the attack. Everything is bounded: whole-fetch timeout, byte cap, redirect cap, and a concurrency cap, because sockets are the resource a client multiplies for free. Three real holes in the existing check surfaced while wiring it: `::ffff:127.0.0.1` (an IPv4-mapped v6 address bypassed the v4 ranges entirely), the v6 private ranges `fc00::/7` and `fe80::/10` (unchecked), and `198.18.0.0/15` read as a /16 (half of it fetchable). The client is told one vague reason for every network-shaped failure, deliberately: "does not resolve" versus "resolves inside" is a port scan with extra steps, and that distinction lives in the operator's log |
  | ~~userdata~~ | **done, and the feature is built** | It was worse than first measured: nothing decoded `UserdataEnvelope` at all, so the whole self-service surface silently did nothing. Now `selfservice.rs` handles outer type 1003 — password, email, rename, TOTP enrol/disable, unregister, and the settings map. Three decisions in it. **The account is never on the wire**: every verb applies to the account behind the session, resolved through `session-view`, so there is no id to get wrong. **The password is asked for again**, once, before dispatch, because a session is a connection someone authenticated and that is exactly what a hijacked session is too; it runs on the blocking pool, since 210 000 PBKDF2 rounds on a runtime worker is every other client queued behind one typo. **Enrolling a second factor takes two messages** — a secret is handed out and held *in memory*, and only a code derived from it writes anything, because the one-shot version locks out any user whose authenticator never got the secret, and logging in is what then needs the code. Underneath, `AccountAction.Kind` gained `UNSPECIFIED = 0` (the proto3 default was `SET_PASSWORD`, so a default-constructed message *was* a request to set an empty password), the envelope gained an explicit `SettingsQuery`, and `Accounts` gained `set_totp` — `"totp"` had been in `update`'s sensitive-field list with no arm to match it, so a caller asking to change it was answered `Ok` while nothing happened |

  The rule for closing a real gap is the one that produced the minimal sets in
  the first place: add what carries information the receiver cannot derive,
  and leave out what the server already knows (a `sender_hash` beside a
  session id) or what the epoch-0 shape carried only by habit. The rule for
  the deferred two is simpler: **design the wire with the implementation, not
  ahead of it.**

  **onboarding now applies its grants** (`services/onboarding/src/grants.rs`),
  which was the last of M2b and the only one that was service work rather than
  protocol work. Four decisions in it are worth keeping:

  * **The grants come out of the operator's `Flow`, never off the wire.** A
    `Response` carries step ids and choice ids and nothing else; every channel
    and group applied is looked up by those ids in the stored flow. An id
    matching nothing grants nothing. The alternative shape — a client that
    sends the grants it wants — is a client that sends itself `admin`.
  * **Recorded as group membership, not an ACL entry per user.** Each revealed
    channel gets one entry granting `@onboarded`, and onboarding adds accounts
    to that group: an integer per user rather than a row per user on every
    channel's ACL, which at ten thousand onboarded users is the difference
    between a table an operator can read and one the evaluator walks on every
    check.
  * **Applied on submission *and* on every query.** Idempotent, so a user who
    already holds everything causes no write and no invalidation, which is what
    makes it safe to re-apply — and re-applying is the only way an account whose
    grant failed (permissions down, group pruned) ever gets it back. Their
    answers are already stored, so there is nothing for the client to re-submit.
  * **It does not walk the tree, and it does not overrule a removal.** Reaching
    a channel needs `Traverse` on the path to it, but granting that would widen
    permissions on channels the flow never named; and an account an operator put
    in a group's `remove` list stays out, because a closer `remove` beats an
    `add` at evaluation, so re-adding would read as applied and do nothing. It
    logs instead.

  The tests go through the **real evaluator** from `permissions` (a
  dev-dependency, no runtime coupling), because the failure worth catching is
  not a mistyped field but an ACL shape the evaluator ignores: `apply_subs`
  where `apply_here` was meant, or a group left non-inheritable, both of which
  look correct in a debug print and grant nothing.
* **M2c, the client moves to the canon. Vendoring done; the codec is the
  rest.** `vendor/client` now carries `proto/fancy/*.proto` mirrored from here
  and compiles all eight into `proto::fancy::*`, under the same two-pass
  `extern_path` dance `wire.proto` needs on this side. `check-proto-drift.sh`
  covers them in both directions, a file whose wire meaning differs, and a
  file the client has that Starling does not, which a loop over our own files
  would never look for. Nothing encodes them yet, and that is the point of
  doing it first: the canon is now *verified identical* on both ends before
  anything depends on it being so.

  **The pchat identity question is settled, and the canon was wrong.** The
  client's key ladder is keyed on TLS certificate hash throughout, peer keys,
  channel originators, key holders, even the consensus tie-break, while the
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
  guessed at, a wrong attribution in an archive is worse than an absent one.

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
  **The M2h degradation is reverted in this same change**, the epoch-1
  announcement and the codec that earns it ship in one commit, so the claim
  and the capability can never again be separated, which is precisely how D1
  happened.
* **M3, the dead block is deleted. Done.** Gone from all three `Mumble.proto`
  copies, which are thereafter exactly: upstream surface + Fancy 1000+ fields +
  the epoch-0 legacy messages `vendor/server` still speaks. Deletion is also the
  guard, the onboarding service bound itself to the dead block and nobody
  noticed, because a tombstone comment stops readers and not compilers. The
  types no longer exist, so nothing can quietly speak them.

  It removed a live defect as well as dead text. The client's codec fell back to
  the proto2 envelopes whenever the canon did not recognise a payload, which
  meant **a canon frame at a service the canon does not cover**, server-config
  at 1013, say, was decoded as proto2, and where the wire types coincided it
  produced a message that looked valid and was not. That is D1 inbound, and the
  fallback was the only thing keeping it reachable. Now an unreadable
  service-typed frame is skipped, which is what the envelope design says may
  happen to any arm a build does not know.

  Outbound gained the matching rule: `encode` **refuses** a Fancy message with
  no canon form rather than framing it flat, because flat means its epoch-0 id
  in the burned 100-999 range, which routes nowhere on any peer. Those travel by
  relay, arranged a layer up; a raw one reaching the wire codec means somebody
  skipped that layer, and now they find out instead of the frame vanishing.
* **M4, freeze, per set rather than per date. Mechanism done.** A blanket
  freeze would lock in whatever state the canon happened to be in on the day,
  and five services are still on the relay *because* their canon is incomplete
 freezing those buys nothing (nothing encodes them) and makes finishing them
  expensive. So a set is frozen when both ends encode it and a build carrying it
  could ship, and `check-proto-hygiene.py` enforces that against a recorded
  manifest (`scripts/frozen-tags.json`): a frozen field that moves or vanishes
  fails the check by name. Frozen today: `pchat`, `social`, `wire`, the sets
  M2c's codec actually encodes. Everything else may still be renumbered, and
  should be, before it joins them.

  Verified the way the other gates were: by moving a frozen tag and watching it
  fail with the field named. `--update-frozen` re-records, which is the one
  command that may be run when a set legitimately joins.

  The epoch stays `1`: the
  layout a peer finds at `fancy_protocol` is already the discriminator, and no
  epoch-1 peer shipped before this point.
* **M5, scale features behind capability bits. S1 landed; two features left.**
  The step reads like wiring and is not: none of the three existed.
  `SyncDelta` was defined and never constructed, `Resume` is a stub that always
  answers `full_resync_required`, and zstd and the framing sequence have no
  implementation at all.

  **S1, lazy subscription, is now real.** A connection records what it is
  looking at (`LazySubscribe`), and a `UserState` change splits its audience:
  peers that did not subscribe get exactly what murmur sends, peers that did and
  are looking at that channel get a `SyncDelta`, and **peers that did and are
  looking elsewhere get nothing at all**. That omission is the whole saving,
  the win is not a smaller message, it is no message, which is what turns
  Θ(events × clients) into Θ(events × subscribers of the changed entity).

  Three properties are load-bearing enough to have tests: an unsubscribed peer
  still gets everything (a stock client must not be quietly cut out of state it
  renders); a subscription from a peer that never announced `lazy_subscribe` is
  **ignored**, because honouring it would stop the flood for a client that
  cannot read what replaces it, a roster that silently stops updating; and
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
  buffer*, and they do not. The send queue now carries
  `Outbound { prefix, payload }`: the prefix is six bytes, or fourteen for a
  peer that negotiated resume, and is never shared; the payload is the same
  refcounted buffer for everyone. The writer emits the two in sequence rather
  than joining them, so nothing is copied per recipient. Z4 is not weakened;
  it is stronger, because the old path concatenated a header onto the payload
  and this one stops doing even that.

  `len` covers the sequence, so a reader takes `len` bytes after the header
  either way; the eight it skips first are the ones it asked for. A peer that
  never negotiated resume sees bytes identical to murmur's, which a test
  asserts directly against the joined form.

  The rest of the wiring, and one rule each:

  * **The gateway cannot see a `ResumeRequest`**; it is inside a payload, and
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
    announcement, it covers every cause rather than the one the server
    happened to know about, and it spares the gateway from having to encode a
    service's message to explain itself. The client watches for a skip and
    re-syncs; a *repeat* is not a skip, because that is what a successful
    replay looks like.

  Before this, `Resume` answered `full_resync_required` unconditionally: the
  ring was filled on every outbound frame and never once read from.

  The original statement of the problem, kept because the reasoning is what
  made the shape obvious:

  * `ResumeStore::resume` is never called. The gateway owns the ring but must
    not parse payloads (Z1), so it cannot see a `ResumeRequest`, which arrives
    at outer type 1000 and routes to session-lifecycle, where the handler
    unconditionally answers `full_resync_required`. The fix is a new
    `ServerAction` arm (`Replay { conn, from_seq }`): the service reads the
    request and *instructs* the gateway, which keeps Z1 intact because the
    gateway acts on a control-plane instruction rather than on client bytes.
  * **The sequence has to reach the client, and putting it in the framing
    conflicts with encode-once fan-out.** §5's S2 says the seq sits between
    `len` and `payload`. But a broadcast builds *one* frame and shares it by
    refcount across every recipient (Z4), and a sequence is per recipient, so
    prefixing it means a distinct buffer per client, which is precisely the
    "1000 buffer writes for one logical event" the session-store note warns
    about. The two rules were written apart and have not been reconciled.

    The shape that keeps both: only connections that negotiated `resume` get a
    prefixed frame, so the shared path stays shared for everyone else, the
    same per-capability split S1 uses. That bounds the cost to the clients that
    asked for it, and is worth measuring before it is built rather than after.

  **S3 (zstd) is done, as a transport frame type.** The framing question was
  the real content of it, and the answer is `COMPRESSED_BATCH` (1900): a batch
  of whole frames, zstd'd, unwrapped before anything is routed.

  Stream-level compression was the alternative and is rejected because both
  ends must then switch at *exactly* the same byte, one frame written before
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
 compressing them would cost bandwidth to save none. Nor is a single frame
    batched, or anything under 256 bytes.
  * **Expansion is bounded on the way in.** The expanded size is chosen by
    whoever sent the batch, so a few kilobytes can claim to be gigabytes. The
    decoder refuses mid-stream rather than after the fact, which is the same
    rule the frame length already follows.

  Level 1 rather than the default 3: this runs on the socket write path, where
  the budget is a 10 ms audio frame, and the alternative to compressing quickly
  is not compressing better; it is stalling the writer. Batching happens in
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
  server does *to* a client, compress its stream, replay a gap, send deltas
  instead of the flood, so a peer that never announced one must not receive
  it, or it cannot read its own connection. All-false is therefore both the
  default and what an unknown connection reads as, and a stock client lands
  there correctly by sending no `Hello` at all.
* **M6, enforcement. Done; taken early because it guards the rest.**
  The three checks of `PROTOCOL-COMPATIBILITY.md` §5:

  * **consistency**, `check-proto-drift.sh`, which already compared L0's wire
    meaning across the three trees and passes. Its header called
    `vendor/server` "upstream's source of truth", which is the belief that let
    §1's numbering drift through, and its failure advice said to re-sync from
    that tree, so a deliberate change would be reverted by whoever ran the
    check next. Both corrected: no tree is the authority, and the diff has to
    be adjudicated rather than copied over. Extends to L2 when the client
    vendors those files at M2c.
  * **hygiene**, `check-proto-hygiene.py`, new. Two rules no compiler
    enforces and that the drift check is blind to *by construction*, because
    all three trees break them identically: **no field number in the burned
    100-999 range** (with `Version.fancy_version = 6` as the one pinned
    exception), and **no source outside the frozen crate may name a dead-block
    envelope type**, the canon shares those names, so the import *path* is
    what distinguishes them. Both were verified by reintroducing the original
    bug and watching the check fail with file and line: a Fancy field taking
    upstream's next number, and onboarding's dead-block import.
  * **compatibility**, `check-proto-compat.py`, new. Our upstream surface
    against `mumble-voip/mumble` itself, which the other two checks cannot
    speak to: they compare our trees with each other, and three trees agreeing
    on a break is still a break. No remote is configured, so it reads
    `upstream/1.6.x` out of `vendor/server`, where the merge history already
    carries it — the comparison was the missing part, not the bytes.

    It compares against **1.6.x, not 1.5.x**, and the difference is not
    cosmetic: run against 1.5 it reports three false alarms
    (`UserRemove.ban_certificate`, `UserRemove.ban_ip`, `UserStats`'s rolling
    stats), all of them real 1.6 fields. A check that cries wolf on day one is
    one people learn to skip.

    Verified the way the others were, by breaking it on purpose: a Fancy field
    squatting a number upstream already uses, and an upstream field widened
    under us. It names both. It also prints, every run, the one risk we chose
    to keep: `Version.fancy_version = 6` is pinned on upstream's next free
    number in `Version` (§1), so the day upstream uses it, this is the line
    that says so.

  A fourth check landed with M4/M5: **outer-type agreement.** The client names
  outer types as its own constants because it does not link `proto-fancy`, so
  the table exists twice with nothing comparing the copies. A wrong one is not
  a compile error, the frame is well-formed and simply arrives at the wrong
  service, which does not recognise the envelope and skips it. A feature that
  silently does nothing, with plausible-looking numbers in both files. Verified
  by pointing the client's `PUSH` at the plugins service and watching the check
  name both values.

  And the fifth, the one the other four cannot give: an **honesty check** on
  the epoch. The tree announcing `fancy_protocol = 1` must be the tree whose
  codec encodes the canon. Everything above is structural — it proves the
  `.proto` files match, the frozen tags have not moved and the outer types
  agree. None of that is evidence about the *encoders*, and D1 was two
  confident encoders, not two disagreeing schemas.

  It is **golden frames**, `scripts/canon-fixtures.json`: complete frames
  (`type ‖ len ‖ payload`) captured from the client's encoder and checked in as
  bytes. The client asserts it still produces them
  (`mumble-protocol/tests/canon_fixtures.rs`); Starling asserts it decodes them
  into the meaning the fixture names (`proto-fancy/tests/canon_fixtures.rs`) —
  the *meaning*, not merely that parsing succeeded, since a frame decoded into
  the wrong fields parses beautifully.

  Bytes rather than a helper both sides import, deliberately: such a helper
  agrees with itself while disagreeing with the wire, which is not a
  hypothetical failure mode, it is D1's. For the same reason the two copies of
  the fixture are compared to each other, because two copies with nothing
  comparing them is the outer-type table again — and that check caught a real
  divergence the first time it ran.

  Which leaves one honest gap: the fixtures cover social (typing, reaction).
  Extending them is one entry per message, and the services still on the relay
  (screenshare, link-preview, userdata) have no canon to capture yet.
