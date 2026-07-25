# Starling architecture

> **Thesis: look like a monolith from the outside, be a microkernel on the
> inside.**

The hard constraint is not throughput. It is that a user runs one container and
has a working server. Every pattern below is judged against that first.

---

## 1. What Starling already is

Worth naming before choosing anything new, because most of the answer is
"finish what is already there".

| Element | Status | Where |
|---|---|---|
| **Microkernel** — core owns sessions/channels/permissions/routing, features are plugins | ~80% | plugin host + `HANDOVER-audit-opaque.md`'s opacity rule |
| **Actor core** — one authoritative state owner, no locks | done | `ServerCore`, `PORTING-PLAN.md` §2.3 |
| **Command pattern** in | done | `Command` enum over one `mpsc` |
| **Effects** out — pure handlers, `fn(&mut State, msg) -> Effects` | done | `Effect::Send/Disconnect/Log`, `Persist` planned |
| **CQRS-shaped** — RAM read model, write-behind durable record | done, unnamed | `docs/STORAGE.md` D1/L7 |
| **Ports & adapters** — traits on every boundary | done | `Handler`, `Outbound`, `ChannelStore`, `LogSink`, `SecurityPolicy` |
| **Event-driven fan-out to plugins** | **missing** | see §4.1 |
| **Single deployment surface** | **missing** | see §4.2 |

So the architecture is not an open question. It is a **microkernel with an actor
core and an effect pipeline**, and two pieces are unfinished.

---

## 2. Verdicts on the named patterns

### Microkernel — **yes, this is the architecture**

Already ruled in by the maintainer's opacity principle: the server may provide
generic capabilities (sessions, permissions, config, messaging, storage) and
never know a plugin's name, schema or semantics. Persistent chat joining the
plugin side (decided 2026-07-25) leaves a genuinely small core: config, channel
tree, accounts, ACL, bans, blobs, routing.

The important qualifier: **plugins are in-process, not services.** Native (FFI)
or sandboxed (WASM), both loaded into the same binary. Microkernel is a *coupling*
pattern here, not a *deployment* pattern.

### Event-driven — **yes, in-process only**

The core should publish domain events (`session.established`, `channel.created`,
`user.moved`, `message.sent`) that plugins subscribe to by pattern. That is
exactly the "feature-agnostic server-event fan-out" the audit handover asks for,
and it is the missing half of the microkernel (§4.1).

What is explicitly *not* wanted: a broker, a queue product, or cross-process
events. The bus is a function call over a subscriber list, and it lives in the
same process as everything else.

### CQRS — **already true; do not add ceremony**

Reads are served from the RAM-resident model; writes go through the core and are
persisted write-behind. That is CQRS's essential shape and it is worth naming so
nobody "adds CQRS" later.

What must **not** follow: separate read/write databases, eventual consistency
between them, projection rebuild tooling. Those solve a scale problem this
workload does not have, and every one of them is a thing an operator has to
understand.

### Event sourcing — **no for the core; already used where it belongs**

Tempting because the audit plugin already hash-chains its events — but that is
event sourcing applied to the one domain that genuinely needs an immutable
ledger, and it lives in a plugin. Applying it to the core would mean snapshots,
projections and versioned event schemas to manage a channel tree that fits in a
few hundred kilobytes.

The single thing that would justify it is multi-node replication of one virtual
server. murmur has never done that, it is not on the roadmap, and it would be a
research project rather than an architecture choice. Revisit only if that
changes.

### Orchestrator / microservices — **no**

`ServerCore` is already the orchestrator, in-process. The distributed reading of
the pattern is directly opposed to the deployment constraint: it turns one
container into a compose file, a service mesh and a set of failure modes an
operator has to reason about, in exchange for scale-out that a voice server —
bounded by UDP fan-out at roughly a thousand users per instance — does not need.

Horizontal scale, when wanted, is *many virtual servers* (which the multi-tenant
schema already models) or *many independent instances*, not one server split into
services.

---

## 3. The deployment simplicity budget

A rule with a pass/fail test, because "keep it simple" is not enforceable:

> `docker run -p 64738:64738/tcp -p 64738:64738/udp starling` must yield a
> working server with chat, voice and every bundled plugin.

Which means:

| Budget | Limit | Today |
|---|---|---|
| Required config keys | **0** | 0 ✅ (Phase 0 runs with no `--config`) |
| Required external services | **0** | 0 ✅ (SQLite default) |
| Required exposed ports | **1** (+ its UDP twin) | **6** ❌ |
| Manual setup steps | **0** | 0 ✅ (self-signed cert auto-generated) |

Any architectural choice that adds a required port, a required external service,
or a required config key fails the budget and needs an explicit exception.

---

## 4. The two gaps

### 4.1 No event fan-out to plugins

The Rust plugin API offers `on_load`, `on_unload`, `on_client_connected`,
`on_client_disconnected`, `on_plugin_data`, `on_plugin_message` — and nothing
else. There is no way for a plugin to learn that a channel was created or a user
moved, which is why the audit feature needed a server-side bridge with hardcoded
knowledge of the audit plugin. That bridge is exactly what the handover ruled
wrong.

The C++ side grew `ServerEventDistributor` (`EventSubscriber`,
`registerSubscriber`) toward this, but it never reached the Rust plugin API.

**Design.** The core already produces `Effects`. Add one variant:

```rust
Effect::Publish(DomainEvent)     // alongside Send / Disconnect / Log / Persist
```

`DomainEvent` is a small, stable, **feature-agnostic** vocabulary — subject,
verb, ids, and an opaque detail payload. Plugins subscribe by pattern at load
time. The core never names a plugin; plugins never name each other.

This keeps handlers pure (they return the event, they do not dispatch it), and it
means adding an audit-like feature requires **no core change at all** — which is
the property the handover was actually asking for.

### 4.2 Six ports

| Port | Purpose | Fate |
|---|---|---|
| 64738/tcp | Mumble control | keep |
| 64738/udp | Voice | keep |
| 64739/tcp | file-server plugin HTTP | **fold into the core surface** |
| 64740/tcp | live-doc plugin WebSocket | **fold into the core surface** |
| 6502/tcp | ZeroC Ice admin | **replaced** by the admin API (`PORTING-PLAN.md` §6) |
| 10000/udp | WebRTC SFU media | keep — genuinely different traffic |

Plugins currently bind their own listeners, which leaks straight into every
operator's firewall rules, reverse proxy and compose file. Instead: **the core
owns one HTTP/WS listener and plugins mount routes on it** through a capability,
the same way they will get storage and events.

That takes the required-port count from six to two, and the admin API arrives
without adding a third.

---

## 5. The shape, end to end

```text
                        ┌──────────────── one process, one container ─────────────────┐
   Mumble clients ──TLS─┤                                                             │
   (TCP 64738)          │   read tasks ──► ServerCore (1 writer, serialises writes)   │
                        │                    │        ▲                               │
   Voice (UDP 64738) ───┤   ArcSwap routing ─┘        │ Commands                      │
                        │                             │                               │
                        │        Effects: Send │ Disconnect │ Log │ Persist │ Publish │
                        │                  │        │        │       │         │      │
                        │            write tasks    │     LogSink   DB      event bus │
                        │                           │        │       │         │      │
                        │                        (close)  sinks   sqlx      plugins   │
                        │                                                    │   │    │
                        │  HTTP/WS surface (one port) ◄── route capability ──┘   │    │
                        │  plugin_kv (one table)      ◄── storage capability ────┘    │
                        └─────────────────────────────────────────────────────────────┘
```

Five capabilities, one process: **messaging, permissions, events, storage,
routes.** A plugin uses those and nothing else; the core knows no plugin's name.

---

## 6. The kernel boundary

Diagrams (render with `plantuml -Playout=smetana`, see
[`diagrams/README.md`](diagrams/README.md)):

| Diagram | Question it answers |
|---|---|
| [`kernel-structure.puml`](diagrams/kernel-structure.puml) | Who may depend on whom? |
| [`kernel-internals.puml`](diagrams/kernel-internals.puml) | What may a feature touch? |
| [`kernel-message-flow.puml`](diagrams/kernel-message-flow.puml) | How does one message actually flow? |

> **Single writer is not a single owner.** `ServerCore` holds no domain data of
> its own. It holds `ServerState`, which holds `config`, `Connections` and four
> trait objects — `dyn ChannelStore`, `dyn UserRegistry`, `dyn Permissions`,
> `dyn SecurityPolicy` — each owning its own slice. `ServerState` cannot read a
> channel tree except by asking the store.
>
> What `ServerCore` guarantees is **ordering**: one mutation at a time, on one
> thread. Nothing in the system has full access to everything — not the bus,
> whose payload is opaque `Bytes`; not the domain crates, which hold values and
> no mechanism; and not the core. Describing the core as a god object made the
> design look like the thing it was built to avoid.

### 6.1 Everything is a message — two shapes of one mechanism

An earlier draft of this section said *"the mistake to avoid is making everything
a message"*, and gave reads a `&dyn StateQuery` that went straight to the state
service. That was a bus bypass, and it was wrong. Corrected: **nothing bypasses
the bus.**

The objection had been that a query-as-message costs "a round trip". That
conflates a message with a *queued asynchronous* message. QNX — the reference
this design keeps invoking — routes `read()`, `write()` and `open()` through
message passing and is still hard-realtime, because `MsgSend()` is not a queue
post:

| QNX | What it does | Here |
|---|---|---|
| `MsgSend()` | sender **blocks**; kernel hands the message directly to the server thread; server **inherits the sender's priority**; `MsgReply()` returns straight to the blocked sender | `call()` |
| `MsgSendPulse()` | non-blocking notification, no reply | `send()` |

A rendezvous is not a round trip through a buffer. It is a direct thread-to-thread
transfer costing roughly a function call plus a context switch — and the priority
inheritance is what stops a `Realtime` caller from being stalled behind a
`Feature`-lane server.

So the four directions become:

| Direction | Primitive | Shape |
|---|---|---|
| Feature **reads** authoritative state | `bus.call(..)` | blocks for a reply, cannot mutate |
| Feature **changes** anything | returns `Effects` | travel as a reply payload; applied by the state service |
| State service **notifies** features | `bus.send(..)` | fire-and-forget, no reply |
| Feature **uses** a service | `bus.call(..)` | same primitive, different port |

`StateQuery` and `Capabilities` survive as **client-side facades** over
`bus.call()` — they exist so a feature does not hand-assemble envelopes, not as a
way around the bus. Their implementations live on the feature side of the
boundary and hold nothing but a `PortId` and a `&dyn MessageBus`.

#### Two views of the same state, for two kinds of caller

`StateQuery` is the **feature** view: it crosses the bus, so every method returns
an owned answer. Handlers inside the state service are not features — they run in
the writer's own thread — so they get a second, in-process view where borrows are
fine:

| | `StateQuery` | `Authority` *(planned)* |
|---|---|---|
| caller | a feature, in another component | a handler, inside the service |
| reaches it by | `bus.call()` | direct `&mut` |
| returns | owned values only | borrows are fine |
| surface | questions answered | 11 methods + 3 config reads |

Both are narrow views onto the same `ServerState`. Neither is a bypass: the
feature's path is the bus, and the handler is already inside the component the
bus would deliver to. `Authority` does not exist yet — see the work queue in
`docs/CRATES.md` §2.

#### Blocking rendezvous or awaiting one? The reactor question

Asked as "would a reactor pattern be better suited". Two parts, and only the
second is a live decision.

**A reactor is not an alternative to the bus — it is already underneath it.**
Tokio *is* a reactor (epoll/IOCP) plus a work-stealing scheduler, and
`listener.rs` sits on it. `ServerCore::run` is itself reactor-shaped:
`while let Some(cmd) = rx.recv().await { self.handle(cmd) }` demultiplexes one
event source and dispatches by message type through `Dispatcher`, with handlers
that must not block. What a reactor does *not* provide is priority: `epoll`
returns ready handles in arbitrary order. The Realtime-lane result — 0% missed
frames against 99.8% (`RESULTS.md` §2) — came from priority queues. So lanes sit
*on* a reactor; they are not replaced by one.

**The live decision is whether `call()` blocks or awaits.** And here the
deployment budget settles it:

| | blocking rendezvous (QNX) | awaiting call (reactor discipline) |
|---|---|---|
| thread while waiting | parked | released |
| needs priority inheritance | **yes**, to be safe under contention | no |
| privilege required | **`CAP_SYS_NICE`** to raise a thread's priority | none |
| cold-path cost | 18.2 us, mostly wake-up (`RESULTS.md` §3.2) | no wake — the executor is already running |
| deadlock on a cycle | hangs *and* consumes a thread | hangs; a timeout is natural |

**QNX can inherit priority because it is the kernel.** We are an unprivileged
process in a container, and `RESULTS.md` line 92 already records that elevated
thread priority requires `CAP_SYS_NICE`, "which the deployment budget says must
never be required". Three files nonetheless advertised priority inheritance as a
bus feature. That was a requirement on a mechanism this design forbids itself.

So: **`call()` awaits, it does not block.** Priority stays where it can actually
be enforced — in the lane queues, which are ours — and not in the OS scheduler,
which we may not touch.

**What this does not fix.** Hold time. A handler spinning for 25 ms still owns
its executor thread, so `RESULTS.md` §3.3 stands unchanged — and cooperative
scheduling makes it *worse*, because there is no preemption at all. The
"no I/O or unbounded work" invariant is therefore **more** load-bearing under an
awaiting `call()`, not less. Nothing about a reactor rescues a handler that
refuses to yield.

**One unprivileged trick worth remembering.** Lowering a thread's priority is
free; only raising it is gated. So relative priority *is* available by starting
every thread at the default and nice-ing the `Feature` and `Io` workers *down*.
That buys static priority, not inheritance — and it does not address §3.3, where
the serving thread was already mid-request.

#### What the bus is missing

`MessageBus` today has `send` and `take` and no reply primitive, so a synchronous
query genuinely cannot go over it. `Lane::Feature`'s own doc comment already
promises "request/reply" — a promise the API does not keep. Two things have to be
added before the design above is real, and both need measuring the way the lane
design was measured:

1. **`fn call(&self, env: Envelope, timeout: Duration) -> Result<Envelope, CallError>`**
   — a blocking rendezvous. The reply must not be a normal lane post, or a busy
   lane would delay every reply on it.
2. **Priority inheritance for the duration of a call.** The serving port runs at
   the caller's lane priority, or a `Realtime` caller blocking on a `Feature`
   server is a priority inversion — precisely the failure
   `examples/realtime.rs` was written to expose.

Until those exist and are measured, the diagrams marked *DESIGN TARGET* are
describing a bus that cannot yet do what they show.

> This section is also a worked example of the length-of-justification rule: the
> bypass needed a paragraph to defend, and the paragraph was the tell.

### 6.2 The traits

> **Why not `KernelQuery`.** It was named that when `starling-state` was the
> kernel. The kernel is now the bus, and the bus knows nothing of users,
> channels or permissions. It queries the authoritative state, so it is
> `StateQuery`.
>
> **Who answers "may user X text in channel Y".** Three parties, and it is worth
> being exact because two rewrites of the diagrams blurred it:
>
> | | |
> |---|---|
> | **computes** the answer | `dyn Permissions` in `starling-model` — one implementation, unchanged |
> | **serves** the question | the state service, which owns the `Box<dyn Permissions>` |
> | **asks** | a feature, via `bus.call()` on the state service's port |
>
> Permissions did **not** move out of the domain. The state service asking its
> own `dyn Permissions` is a direct call, not a bus hop, and that is not a
> bypass: `dyn Permissions` is a pure function owned by the service, not a
> component with a port. It is the same reason the domain layer never sits on
> the bus (`scripts/check-crate-layering.sh`). The bus mediates *between*
> components, not inside one.
>
> **Is the in-process call to `dyn Permissions` a bypass?** Not today — `AllowAll`
> is stateless. But the trait's signature takes only `(UserId, ChannelId)`, and
> real evaluation needs the ancestor chain, per-channel ACLs and group membership
> (`src/ACL.cpp:104`). An implementation given only ids must **fetch**, and
> `ChannelStore` is SQL-backed from Phase 2 — so it would block inside the single
> writer. The signature invites exactly the bypass it looks innocent of.
>
> Two ways out, and the choice matters:
>
> | | |
> |---|---|
> | make it a **bus-mediated service** with its own port | needs its own copy of the channel tree — a second source of truth for the tree — plus a rendezvous on the hottest operation in the server |
> | keep it a **genuinely pure evaluator** | the state service assembles the data and passes it in; no fetch, no I/O, no port, no bypass |
>
> The second. The first reintroduces the duplicated-permission-state problem this
> design exists to avoid. Recorded as a Phase 2 gate on the trait itself, in
> `crates/domain/model/src/perm/policy.rs` — the signature must change before the
> real evaluator is written, and the memo cache belongs to the state service, not
> to the evaluator.

> This also retires the earlier "hand out the evaluator rather than wrap it"
> decision. The worry it addressed — two ways to ask the same question — is
> answered better here: there is one evaluator, behind one port. Handing out a
> reference was only ever possible while features were bypassing the bus.


```rust
// starling-api — traits only, no logic. Both sides depend on this; neither
// depends on the other.

/// Read-only view of kernel state. Handed to a feature for the duration of one
/// call. Cannot mutate — that is what makes features testable and the
/// single-owner invariant safe.
pub trait StateQuery {
    /// Answers the question. It cannot hand out `&dyn Permissions`: a borrow
    /// into the state service's memory does not fit in an envelope.
    fn allows(&self, user: Option<UserId>, ch: ChannelId, need: Perm) -> bool;

    /// Batched, because each call is a rendezvous rather than a pointer deref.
    /// One `TextMessage` is checked against every channel it targets, so the
    /// unbatched shape turns one client message into N round trips.
    fn allows_each(&self, user: Option<UserId>, chs: &[ChannelId], need: Perm)
        -> Vec<bool>;

    /// Owned snapshots, not borrows, for the same reason.
    fn channel(&self, id: ChannelId) -> Option<Channel>;
    fn user(&self, session: SessionId) -> Option<User>;
    fn sessions_in(&self, ch: ChannelId) -> Vec<SessionId>;
}

/// A feature. Statically linked or wasm-hosted — the kernel cannot tell.
pub trait Feature: Send + Sync {
    fn id(&self) -> &'static str;
    fn handles(&self) -> &[MessageKind];
    fn subscribes(&self) -> &[EventKind] { &[] }

    fn handle(&self, q: &dyn StateQuery, c: &dyn Capabilities,
              conn: ConnId, msg: Message) -> Effects;

    fn on_event(&self, _q: &dyn StateQuery, _e: &DomainEvent) -> Effects {
        Effects::none()
    }
}
```

`handle` and `on_event` have the same signature shape as the `Handler` trait
already shipping in Phase 0 — pure, no I/O, returns `Effects`. Feature crates get
the property the core already has: **testable in microseconds without a socket,
a runtime or a database.**

### 6.3 Why effects are queued, not applied recursively

An event subscriber returns effects, which may include another `Publish`. Applied
recursively that is unbounded stack growth and a re-entrancy hazard — precisely
what the single-actor design exists to avoid.

Instead the kernel keeps **one effect queue per command**. Subscriber effects are
appended with an incremented depth counter, and a depth ceiling turns a runaway
cascade into a logged error rather than a crash. The actor still processes one
command to completion before the next, so the transaction boundary survives.

### 6.4 The rule, and how it is enforced

> Feature crates depend on `starling-api`. The kernel depends on `starling-api`.
> **The kernel never depends on a feature crate.**

This is checkable rather than aspirational — a `cargo tree` assertion in CI
fails the build on any edge from `starling-state` to `starling-feature-*`. It
is the check that would have caught `AuditLogBridge` mechanically, where a stated
principle did not.

### 6.5 The lanes are measured, not assumed

`crates/kernel/bus/` implements the design and
[`RESULTS.md`](../crates/kernel/bus/RESULTS.md) records two experiments.

* **Lane separation protects the control plane:** ~900x better p99 (13 ms → 6 us
  median) with the feature lane saturated.
* **The `Realtime` lane is justified:** under a control storm, folding it into
  `Control` loses **99.8%** of routing-table publications — and the failure mode
  is *refusal at send*, not slowness, because `Control`'s overflow policy is
  `DisconnectPeer`.

The second result reverses the "start with three lanes" note this document
previously carried. It also produced a rule worth keeping: **a lane's overflow
policy is part of its latency profile**, and an experiment that measures only
delivered messages reports a flattering number computed over the survivors.

## 7. What this costs

Stated plainly, because the pattern list above is easy to read as free:

* **In-process plugins share a fate.** A native plugin that panics or corrupts
  memory takes the server with it. WASM plugins do not — which is the argument
  for making WASM the default loader and native the opt-in, and it is the main
  reason the WASM path deserves the storage capability it currently lacks.
* **One process is one scaling unit.** Fine for a voice server; a hard ceiling if
  Starling is ever wanted as a chat backend at a scale voice never reaches.
* **The event bus is a coupling surface.** Once plugins depend on
  `DomainEvent`'s vocabulary, changing it breaks them. It needs the same
  versioning discipline as the wire protocol, and it should start deliberately
  small.
