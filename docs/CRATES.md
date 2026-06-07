# Crate plan

The workspace the architecture implies, and how today's six crates get there.

The organising rule is one you can check rather than believe:

> Feature crates depend on `starling-api`. Services depend on `starling-api`.
> **Nothing below a feature ever depends on a feature.**

---

## 0. The kernel is the bus

`starling-bus` is the message bus: ports, lanes, envelopes, delivery. That is
all a microkernel is — IPC, and nothing else.

Everything else, including the thing that owns the channel tree, is a **service**
running on it:

| Crate | QNX analogue | Owns |
|---|---|---|
| `starling-bus` | the microkernel | message passing. **Knows nothing.** |
| `starling-state` | the process manager (`proc`) | state, permissions, effects — privileged, but a participant |
| `starling-feature-*` | resource managers / servers | one feature each |

This buys a property worth more than the naming, because it is mechanically
checkable:

> **`starling-bus` depends on nothing.** Not `starling-api`, not the domain
> crates, nothing but `bytes` for its payload type.

That is the strongest available statement of *"the kernel knows nothing"* — and
`cargo tree` enforces it, where a principle in a document would not.

**Features never address the bus.** A feature gets `StateQuery`,
`Capabilities`, and returns `Effects`. It never sees a `PortId` or a `Lane`,
because lane assignment is a capability the kernel controls and feature-to-feature
communication goes through events rather than direct addressing. Hence
`starling-api` does **not** depend on `starling-bus`.

---

## 1. Layout

Crates are grouped by namespace on disk. Package names stay short — the
directory is the namespace.

```
crates/
  kernel/
    bus/            starling-bus        the microkernel: IPC, nothing else
  domain/
    proto/          starling-proto      wire format
    model/          starling-model      channels, users, sessions, permissions
    crypto/         starling-crypto     ciphers, certificates, hashes
    log/            starling-log        records + the non-blocking emitter
  api/              starling-api        the feature contract, traits only
  services/
    state/          starling-state      the authority (see below)
    net/            starling-net        TLS + the one HTTP/WS surface
    voice/          starling-voice      UDP, routing snapshot
    db/             starling-db         sqlx store
  features/
    pchat/          starling-feature-pchat
    log/            starling-feature-log
    wasm/           starling-wasm       loader, not a feature itself
  edges/
    rpc/            starling-rpc
    migrate/        starling-migrate
    starling/       starling            the binary
```

> **Naming caveat:** the package in `crates/services/state` is still named
> `starling-server` on disk. Docs below use the target name `starling-state`;
> the rename is pending. `grep starling-state Cargo.toml` finds nothing today.

The move is done for the crates that exist: `crates/kernel/bus`,
`crates/domain/{proto,model,log}`, `crates/services/state`,
`crates/edges/starling`. All 408 tests pass unchanged.

---

### Status: nothing is wired to the bus yet

Worth stating plainly, because the diagrams imply otherwise. `starling-bus` is
**measured but unintegrated**: `bus.register()` is called only from
`crates/kernel/bus/examples/{isolation,realtime}.rs`, and no crate outside
`crates/kernel/bus` names `starling-bus` in its manifest.

`starling-server` today is a direct-call server — listener → dispatcher →
handlers → effects. The `.register()` calls inside it belong to two *other*
registries (the `Dispatcher`'s handler table and `Outbound`'s sink table) that
share a method name with the bus and nothing else.

Integrating the bus is Phase 1. The measurements in
`crates/kernel/bus/RESULTS.md` exist to justify the design before that work
starts, not to report on it.

### What never registers to the bus

Ports register. A **port** is a runtime participant with an inbox. The domain
crates — `starling-proto`, `starling-model`, `starling-log` — are none of those:
they are values, traits and pure functions with no runtime presence, so there is
nothing to register and no lane that would apply to them.

`scripts/check-crate-layering.sh` now enforces this: a domain crate that grows a
dependency on `starling-bus` (or on any service, contract or feature crate)
fails the build. Verified by injecting `starling-model -> starling-bus` and
confirming exit 1.

---

## 2. What `services/state` actually does

The first draft of this section listed five jobs. Reading the code, two of them
were not true and one was a defect. Corrected:

| Claimed | Reality |
|---|---|
| Owns authoritative state | **true** — channel tree, users, sessions, connections |
| Applies effects | **true** — `core/mod.rs::apply`, the only mutation point |
| Dispatches | **true**, but through a leaky signature — see below |
| Evaluates permissions | **false** — holds a `Box<dyn Permissions>` and delegates |
| Negotiates security | **false** — delegates to `security/`, which is a leaf |

So it owns state, routes to handlers, and applies what they return. Those are
three phrasings of **one** responsibility: it is the serialized writer. It has
one reason to change — how writes are serialized.

### Is it a god class?

The types say no. `ServerCore` is 238 impl lines, 5 fields, 3 command kinds, 3
effect kinds. `ServerState` is 207 lines and 6 fields. Neither is large.

The **trend** is the problem. Across one design conversation the answer to three
separate questions was "the state service": it serves permission queries, it
assembles the ACL context, it owns the memo cache. Nothing was wrong
individually. God classes are not built by one bad decision — they accrete
because one component is the default home for anything that needs consistent
state.

The distinction that stops it: **needing to read consistent state is not the
same as needing to own it.**

> **Admission test.** A responsibility belongs in the state service only if it
> must be **atomic with a state mutation.**

Applied to everything currently assigned to it:

| Responsibility | Atomic with a mutation? | Verdict |
|---|---|---|
| own tree / users / sessions / connections | it *is* the mutation | stays |
| apply effects | it *is* the mutation | stays |
| connection lifecycle | yes — who is connected is state | stays |
| serve permission questions | must see the tree the mutation saw | stays, as a **named collaborator** |
| ACL context assembly + memo cache | invalidated by tree changes | stays, as a **named collaborator** |
| dispatch inbound to handlers | no — routing | **can leave** |
| negotiate the security suite | no — per connection | **leaves** (422 lines, zero coupling) |
| persistence | no — write-behind is async by design | **already outside**: emitted as an effect, applied by the storage service |

Two notes on honesty. The permission work "stays" as *collaborators with names*
(`PermissionCache`, ACL-context assembly) — not as more fields on `ServerState`,
which is exactly how the accretion would continue. And this test is a **review
rule, not a CI rule**: "atomic with a mutation" is not mechanically checkable the
way `scripts/check-crate-layering.sh` checks crate edges. That asymmetry is worth
knowing — every other boundary in this design has a build failure behind it, and
this one has a sentence.

### The two that leave

`security/` (422 lines, 5 files) has **zero** `use crate::` imports pointing out
of itself. `connection.rs`, `listener.rs` and `state.rs` consume it. It is
already a crate, sitting in the wrong directory.

`Permissions` is already a trait in `starling-model`, injected as
`Box<dyn Permissions>`. Handler code calls `state.permissions().allows(..)` in
exactly one place. Nothing to extract.

### The defect: a concrete struct on a component boundary

```rust
fn handle(&self, state: &mut ServerState, conn: ConnId, msg: ControlMessage) -> Effects;
```

`DESIGN.md` says pass the trait, not the struct. This passes the struct — every
handler gets all 23 public methods of `ServerState`, and uses 11. A handler
registered for `Ping` can retune the channel tree.

The fix is the signature, not the location: handlers take a narrow capability
trait. Dispatch then has no reason to name `ServerState` at all.

### Why `apply` does not move

`apply` is 11 lines over 3 effect variants, and it is the reason the actor
exists: the single point where mutation is serialized. Moving it means something
else holds `&mut` on the state, which restores the multiple-writer problem the
design pays for. Small is the point — not evidence that it is misplaced.

### Which effects reach the state service

The admission test applies to effects too, and it splits them:

| Effect | Needs state to interpret? | Goes to |
|---|---|---|
| `Send { to: Recipients }` | yes — `Recipients` -> sessions needs the channel and user registries (`core/broadcast.rs::resolve`) | the state service, then the net port |
| `Disconnect { conn }` | yes — the connection registry | the state service |
| `Log(LogEvent)` | no | straight to the log port |
| `Persist` *(planned)* | no | straight to the storage port |
| `Publish` *(planned)* | no | straight to the subscribing ports |

Routing all five through the writer would make it a mail hub: it would be
handling persistence and fan-out that have nothing to do with the state it
guards. That is the accretion the admission test exists to catch, and the
message-flow diagram showed it before this correction.

### SOLID audit — findings and what was done

Each principle checked against the code rather than asserted.

| | Finding | Status |
|---|---|---|
| **SRP** | `services/state` held the TLS accept loop (225 lines) *and* the state authority. Measured: the authority half never names transport — the dependency is one-directional. | **partly fixed.** `security/` (421 lines) left for `starling-crypto`. Transport extraction is unblocked but not done. |
| **OCP** | Following the dataflow required opening implementations. | **fixed.** The state crate's `lib.rs` now carries a step-by-step table naming only the trait at each hop, so the flow reads at one level. |
| **LSP** | `Authority` was drafted as one 13-method trait — substitutable only as a whole. | **fixed.** Split into `Sessions` (7), `World` (4), `Settings` (1), with `Authority` as an empty supertrait and a blanket impl, so a substitute implements roles and never names `Authority`. |
| **ISP** | Handlers received `&mut ServerState` — 23 methods, 11 used, including `remove_connection`, `channels_mut` and `add_connection` in reach of `Ping`. | **fixed.** Handler impls no longer name `ServerState` at all; only test scaffolding does. |
| **DIP** | Two inversions: `Outbound::register` took a concrete `ConnectionSink`, and `ServerCore::new` constructed a `ConnectionRegistry` — the policy layer choosing a TCP detail. | **fixed.** `FrameSink` trait added, so `Outbound` registers a *destination*; `NoOutbound` (Null Object) is the default, so the core names no transport. |

The DIP fix has a visible consequence worth keeping: `ServerCore::new` now installs
`NoOutbound` and **discards** frames. Seven tests failed on that, because they had
been relying on the default being a recording transport. They now inject one
through `with_parts`, which is what that constructor documents itself for. A test
that needs a transport should say so.

### What is left for SRP

The transport extraction is now unblocked — nothing in the authority half names a
transport type outside test scaffolding, and the composition root already uses
`with_parts` rather than `new`. Moving `listener.rs` and `outbound/{registry,sink}.rs`
into `starling-net` is mechanical: the `Outbound` and `FrameSink` **traits** stay
with their consumer, the implementations go with the transport.

### The work queue — nothing here is started

Ordered by dependency. Steps 1 and 4 are mechanical; step 2 is load-bearing and
its shape is **not yet confirmed**.

| # | Step | Cost | Blocked on |
|---|---|---|---|
| 1 | ~~Extract `security/` into `starling-crypto`~~ | **done** — 421 lines moved | — |
| 2 | ~~`&mut ServerState` -> `&mut dyn Authority`~~ | **done** — split into `Sessions`/`World`/`Settings` | — |
| 2b | Extract transport into `starling-net` | 3 files; traits stay behind | nothing (unblocked) |
| 3 | Move `dispatch/` into `starling-api` | 157 lines move | step 2 |
| 4 | Rename package `starling-server` -> `starling-state` | manifest + doc references | nothing |
| 5 | `PermissionCache`, non-fetching `Permissions::effective` | new types | ACL storage (Phase 2) |

**Step 1** is free: `security/` has zero outbound `use crate::` and is consumed by
`connection.rs`, `listener.rs` and `state.rs`. `crates/domain/crypto/` is already
in the layout above.

**Step 2 — the open decision.** The surface handlers actually need is **11
methods plus 3 config reads** (`allow_recording`, `max_text_message_length`,
`password_matches`):

```
assign_session  channels     connection   connection_mut  is_authenticated
is_full         permissions  session_of   suite_for       users   users_mut
```

Left behind, and currently reachable by every handler including `Ping`:
`remove_connection` (evict a session), `channels_mut` (restructure the tree),
`add_connection` (fabricate one). The `new`/`with_*` builders take `self` by
value, so they are already out of reach through `&mut` — the leak is narrower
than "all 23", but it is the dangerous end of it.

*Proposed*: one trait, `Authority`. Interface segregation argues for role-shaped
traits (`Sessions`, `Users`, `Channels`), but `Handler` must stay object-safe for
`Box<dyn Handler>` in the dispatcher's registry, so a split needs a combining
supertrait — the same surface with more indirection. It also pairs with the bus
decision: `StateQuery` is the **feature** view (owned answers, crosses the bus),
`Authority` is the **in-process** view (borrows are fine, runs inside the
service). Not yet agreed.

**After steps 1-3**, `services/state` is 2 414 - 157 = **2 257 impl lines**:
own state, apply effects, connection lifecycle, serve reads. Every one atomic
with a mutation, so it passes its own admission test.

---

## 3. The crates

Sixteen, layered by **what a crate knows** — checkable, rather than a matter of
taste.

### Layer 0 — the kernel

| Crate | Role | Status |
|---|---|---|
| `starling-bus` | Ports, lanes, envelopes, overflow policy. Depends on nothing. | **built + measured** (1 168 lines) |

Lane isolation and the `Realtime` lane are both measured — see
[`RESULTS.md`](../crates/kernel/bus/RESULTS.md).

### Layer 1 — domain (concepts, no I/O)

| Crate | Role | Status |
|---|---|---|
| `starling-proto` | Wire format: prost types, TCP framing, version encodings | **built** (997 lines) |
| `starling-model` | Four independent concepts — `channel`, `user`, `session`, `perm` — each a trait plus an in-memory impl, all over the id newtypes in `ids`. No module references another. | **built** (844 impl lines) |
| `starling-crypto` | Voice ciphers (OCB2, `ChaCha20-Poly1305`), certificates, PBKDF2/legacy hashes, TOTP | new |
| `starling-log` | `LogEvent`, the non-blocking `Logger`, the `LogSink` trait, console fallback | **built** (2 363 lines), to be split — see §2 |

`starling-crypto` is separate because cryptographic code earns a small,
auditable blast radius, and because it is all pure functions with test vectors.

### Layer 2 — the contract

| Crate | Role | Status |
|---|---|---|
| `starling-api` | `StateQuery`, `Feature`, `EventSubscriber`, `Capabilities`, `DomainEvent`. No logic at all. | new |

Depends on layer 1 for the types in its signatures, and on **nothing above**. It
is small, it does nothing, and it is the crate that makes the feature boundary a
compile-time fact rather than a convention.

### Layer 3 — privileged services

| Crate | Role | Status |
|---|---|---|
| `starling-state` | State actor, effects, dispatcher, capability implementations, security negotiation | rename + slim of `starling-server` |
| `starling-net` | TLS listener, connection lifecycle, **the single HTTP/WS surface** | extract from `starling-server` |
| `starling-voice` | UDP socket, `ArcSwap` routing snapshot, audio forwarding | new |
| `starling-db` | `sqlx` store: greenfield schema, migrations, the `plugin_kv` table | new |

Privileged because they cannot be unloaded, not because they are part of the
kernel.

`starling-voice` is its own crate because it is the one path with a hard latency
budget and it **touches neither the bus nor the core** — it reads a published
snapshot. Isolating it makes that property structural rather than remembered.

`starling-net` closes the six-ports gap: features mount routes on one listener
instead of binding their own.

### Layer 4 — features

| Crate | Role | Status |
|---|---|---|
| `starling-wasm` | wasmtime loader; adapts sandboxed modules to `Feature`. Replaces `abi_stable`. | new |
| `starling-feature-pchat` | Persistent chat, moved out of the core | new |
| `starling-feature-log` | Where log records actually go: file, memory, filtering, fanout, and later a database or Cassandra | new — see §2 |

Third-party features live in their own repositories; that is the point. These
land here only because they are moving *out* of the core.

### Layer 5 — edges

| Crate | Role | Status |
|---|---|---|
| `starling-rpc` | gRPC admin API — the Ice replacement | new |
| `starling-migrate` | Reads murmur's 21-table schema, writes the greenfield one | new, optional |
| `starling` | The binary. Config, CLI, certificate bootstrap, **composition root** | **built** (2 183 lines) |

---

## 4. Logging splits, it does not simply move

Making logging a feature is right — the kernel should not know how to write a
file, and a Cassandra sink should be a plugin swap. But two properties of the
current design would be lost by moving it wholesale:

1. **Bootstrap.** What logs *"the log feature failed to load"*?
2. **It must never block.** `Logger::log` hands off to a dedicated OS thread
   precisely so logging keeps working while the runtime is saturated — which is
   when the records matter most. Route it over the bus onto the `Io` lane, whose
   policy is `BlockProducer`, and the guarantee inverts.

So the split follows the seam already in the crate:

| Part | Lives in | Why |
|---|---|---|
| `LogEvent`, `Logger` (non-blocking queue), `LogSink` trait, console fallback | `starling-log`, used by `starling-state` as a capability | bootstrap, and the never-blocks guarantee |
| `FileSink`, `MemorySink`, `FilterSink`, `FanoutSink`, future DB/Cassandra | `starling-feature-log` | swappable, third-party-able, gets `plugin_kv` |

`Logger` and `LogSink` are already separate types, so this is a move rather than
a redesign. **Emitting** stays a capability; **deciding where records go**
becomes a feature.

---

## 5. Where chat lives — two things, deliberately split

"Chat" is two features on the wire, and they land on opposite sides of the
feature boundary.

| | `TextMessage` | Persistent chat |
|---|---|---|
| Wire types | 1 (id 11) | **24** (ids 100–130) |
| Origin | stock Mumble protocol | Fancy extension |
| Storage | none — pure fan-out | unbounded history, offline queues |
| Crypto | none | end-to-end, keys negotiated between clients |
| Today | `services/state/handlers/text_message.rs`, 138 lines | in the C++ server's `murmur/pchat/` |
| Lands in | **stays in `services/state`** | **`features/pchat`** |

`TextMessage` stays because of a property worth protecting:

> **Unload every feature and you still have a working stock Mumble server** —
> voice, channels, and text chat. That is the baseline a stock client expects
> with no negotiation.

It is 138 lines of permission check, actor rewrite and fan-out, with no storage
and no state of its own. Making it a feature would move protocol plumbing across
a boundary and break the baseline.

Persistent chat is the opposite: an extension a stock client never asks for,
owning the largest table in the system. It is the same line drawn for opacity in
`ARCHITECTURE.md` — **is this the protocol contract, or an add-on?**

The honest wrinkle: a *user* does not experience these as two features. They see
"chat", and whether history survives a reconnect depends on a channel flag. That
is a UI concern, but it means the split has to be invisible in the client — and
it is worth checking that it is, when `features/pchat` is built.

---

## 6. The dependency rule, enforced

Diagram: [`diagrams/crates.puml`](diagrams/crates.puml) (render with
`plantuml -Playout=smetana`, see [`diagrams/README.md`](diagrams/README.md)).

```
                        starling  «binary»
                (the only crate that names both sides)
                   │                            │
      ┌────────────┘                            └────────────┐
      ▼                                                      ▼
  starling-state  ──────────► starling-api ◄────────  feature crates
  starling-net                (traits only)          starling-feature-*
  starling-voice                    │                starling-wasm
  starling-db                       ▼
                    -proto · -model · -crypto · -log
                                    │
                                    ▼
                            starling-bus
                     (depends on nothing; no feature
                          ever addresses it)
```

CI asserts the arrow that must not exist —
[`scripts/check-crate-layering.sh`](../scripts/check-crate-layering.sh), wired
into the `layering` job. It resolves the **full** graph with `cargo tree`, so a
transitive edge cannot slip through where a hand-audit of manifests would miss
it.

Verified both ways: it passes on the current workspace, and injecting a
`starling-feature-fake` dependency makes it fail with the offending crate named.

One bug found while writing it, worth recording because it is the classic shape:
the first version treated a failing `cargo tree` as "no violations found", so a
broken manifest produced a **green** layering check. It now fails loudly — *a
check that could not run is not a check that passed.*

This is the check that would have caught `AuditLogBridge`, where a principle
written in a handover document did not.

---

## 7. What changes from today

`starling-server` (5 655 lines) is the only crate that has to move. Its modules
split three ways:

| Today | Goes to | Why |
|---|---|---|
| `core/`, `state.rs`, `effects.rs`, `dispatch/` | `starling-state` | the actor and its effect pipeline |
| `connection.rs`, `listener.rs`, `outbound/` | `starling-net` | connection lifecycle and transport |
| `security/` | `starling-state` | negotiation is a core policy |
| `handlers/` | **split** — protocol handlers stay in the core; anything feature-shaped leaves | this is the microkernel line |
| `config.rs` | `starling-state` | resolved settings the core reads |

`starling-bus` already exists and is measured; wiring it in place of the
current single `mpsc` is a change inside `starling-state`, not a new crate.

---

## 8. Order of work

Crates arrive with the phase that needs them, so the tree never carries an empty
crate.

| Phase | Crates | Gate |
|---|---|---|
| 0 — MVP | kernel, proto, model, log, server, binary | **done** — handshake + chat against the real client |
| 1 — Voice | `starling-crypto`, `starling-voice`; core adopts the kernel bus | voice e2e specs |
| 2 — Persistence | `starling-db`, `starling-migrate` | admin/ACL/registration specs |
| 3 — Plugins | `starling-api`, `starling-wasm`, `starling-net`, `starling-feature-log` | fileserver/forums/calendar/audit specs |
| 4 — Pchat | `starling-feature-pchat` | pchat/signal-pchat specs |
| 5 — Fancy surface | (features only, no new crates) | control-plane specs |
| 6 — SFU + RPC | `starling-rpc` | channelviewer, screenshare |

`starling-feature-log` lands in Phase 3 rather than earlier: it needs the
`Feature` boundary and the storage capability to exist first, and until then the
binary composing sinks from config works fine.

---

## 9. Two judgement calls worth revisiting

* **`starling-net` versus keeping transport in `starling-state`.** Sixteen crates
  is a lot, and this is the split with the least forcing behind it. The argument
  for it is the HTTP/WS surface, which is genuinely its own subsystem; if that
  surface turns out small, fold it back.
* **`starling-feature-pchat` in this workspace.** It is here only because it is
  moving out of the core. Once the `Feature` boundary is real it could live in
  its own repository like every other feature — and if it cannot, that is
  evidence the boundary is not as clean as claimed.
