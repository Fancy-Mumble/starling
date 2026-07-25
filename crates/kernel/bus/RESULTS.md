# Bus measurements

Three experiments, all reproducible:

```sh
cargo run --release --example isolation   -p starling-bus
cargo run --release --example realtime    -p starling-bus
cargo run --release --example rendezvous  -p starling-bus
```

Measured on Windows 11, no elevated thread priority — deliberately the container
default, so the isolation comes from queue topology rather than `CAP_SYS_NICE`.

---

## 1. Does lane separation protect the control plane?

Four threads saturate the feature lane while control traffic is measured
end-to-end.

| Bus | control p50 | p99 | max | measured |
|---|---:|---:|---:|---:|
| `SharedQueueBus` (one queue, FIFO) | 13 001 us | 15 526 us | 16 405 us | 798/3000 (27%) |
| `LaneBus` (one queue per lane) | **6 us** | **17 us** | 213 us | 3000/3000 (100%) |

**~900x better p99.** Both configurations did the same feature work
(~12 600 envelopes), so the difference is topology, not throughput. The absolute
figures are the point: 13 ms versus 6 us median is a user-visible stall versus a
rounding error.

The coverage column is a second finding, not an artifact: **with one queue you
cannot dedicate a consumer to the control plane.** Envelopes go to whichever
worker grabs them, so most control traffic was handled by the feature worker.
That is the structural reason a separate lane is needed at all.

### Correction made during this experiment

The first run reported **6425x**. That was wrong: the shared queue had been given
64 Ki capacity "so the comparison measures ordering rather than overflow", which
quietly handed it 6.7x more buffering than the four lanes combined. Sized to the
**sum of lane capacities** (9 792) it fell to ~900x. The inflated number was an
artifact of the harness, not a property of the design.

---

## 2. Does the `Realtime` lane earn its keep?

`Realtime` carries routing-table publication. Audio frames never traverse the
bus — they read the published snapshot — so a late publication means voice is
routed to a **stale recipient set**.

That gives an absolute budget instead of a ratio: **one 10 ms audio frame.**

The A/B is one line: the same `LaneBus`, with the realtime port registered on a
different lane. Both configurations get the same number of consumer threads, and
every consumer records realtime envelopes, so coverage is 100% either way.

Load: 4 control-storm threads (a reconnect burst) + 2 feature flooders + one
publication every 5 ms.

| Config | delivered | refused | p50 | p99 | missed their frame |
|---|---:|---:|---:|---:|---:|
| 3 lanes (realtime rides `Control`) | 8/400 | **392** | 11 456 us | 11 794 us | **99.8%** |
| 4 lanes (realtime separate) | 400/400 | 0 | **8 us** | **20 us** | **0.0%** |

**The `Realtime` lane is justified.** Under a control storm, folding realtime
into `Control` loses essentially every routing update.

### The failure mode is refusal, not latency

The interesting part: only 8 of 400 publications were *slow*. **392 were refused
outright** — the `Control` lane was full and its policy is `DisconnectPeer`, so
the publication never entered the bus.

That is worse than a delay, and it was invisible in the first version of this
experiment because the harness discarded the `send` result with `let _ =`. The
lesson generalises: **a queue's overflow policy is part of its latency profile**,
and an experiment that only measures delivered messages will report a flattering
number computed over the survivors.

---

## Caveats for experiments 1 and 2

Experiment 3 has its own in §3.4; the design-wide gaps are in §4.

* `LockedQueue` is `Mutex<VecDeque>`. These measure **isolation**, not queue
  throughput — both configurations use the same queue underneath, so a lock-free
  MPMC would move both numbers and not the ratio.
* Feature and control work are synthetic spins (50 us / 20 us). Real handler cost
  varies; the shape of the result should not.
* No elevated thread priority. Adding it can only improve the lane figures, and
  requires `CAP_SYS_NICE` — which the deployment budget says must never be
  required.
* Experiment 2's 3-lane row is a percentile over 8 samples. The refusal count,
  not the percentile, is what carries that result.

---

## 3. What does "nothing bypasses the bus" cost?

`docs/ARCHITECTURE.md` §6.1 mandates that a feature asking *"may user X text in
channel Y?"* send a message rather than dereference a pointer. This measures the
price. 3 000 samples per case, 24 logical cores, Windows 11.

| Case | p50 | p99 | max | past frame budget |
|---|---:|---:|---:|---:|
| direct call, in-process (today) | **0.0004 us** | — | — | 0 |
| rendezvous, server hot (never parks) | **0.9 us** | 1.0 us | 28 us | 0 |
| rendezvous, server parked between calls | **17.8 us** | 47.9 us | 668 us | 0 |
| rendezvous, server holding 200 us | 14.8 us | 185 us | 237 us | 0 |
| rendezvous, server holding 25 ms | 14.5 us | **24 990 us** | 25 020 us | **111 (3.7%)** |

### 3.1 The mandate costs 2 250x, and it does not matter

A rendezvous is ~2 250x a pointer dereference when the serving thread is hot, and
~44 500x when it has parked. Both are the wrong way to read the number. The
absolute figures are 0.9 us and 17.8 us against a **10 ms** frame budget — three
orders of magnitude of headroom. The ceiling for a single serving port is
1 111 111 round-trips/second hot, 56 180/second cold.

The reason this is affordable is not the bus, it is where permission checks
actually sit. **murmur's `processMsg` — the per-packet voice path — makes zero
`hasPermission` calls.** It evaluates at channel entry and caches the answer in
`bSuppress` (`Server.cpp:2286`); 54 of its 71 call sites are in `Messages.cpp`,
the control handlers. So permission checks are Control-lane work at human pace,
not Realtime work at 50 packets/second/user.

**If that ever changes — if a query lands on the voice path — this measurement
must be re-run before the change ships.**

### 3.2 Hot beats cold by 20x, which inverts the usual intuition

A busy server answers *faster* per request (0.9 us) than an idle one (17.8 us),
because an idle server has parked and must be woken. The difference is thread
wake-up, not queueing.

Two consequences: a latency figure measured under load is not a worst case, and
benchmarks that hammer a server in a tight loop measure the *good* path. The
paced measurement is the honest one for a server at low load.

### 3.3 The budget is broken by hold time, not by the bus

The only case that misses the frame budget is the one where the serving thread is
already inside a 25 ms request: p99 = 24 990 us, and max = 25 020 us — the delay
is *exactly* the hold time. 3.7% of questions missed their frame. The same
experiment with a 200 us hold misses nothing.

Lane priority cannot fix this. The Control lane was correctly preferred in every
run; the question still waited, because a single serving thread already inside a
low-priority request cannot answer a high-priority one until it finishes. Only
two things fix it:

1. **Bounded hold time** — the invariant already recorded in `docs/CRATES.md` §2:
   *no command may perform I/O or unbounded work.* This experiment is what that
   invariant is buying.
2. **Preemption**, which cooperative async scheduling does not give us.

This is also the concrete argument for the Phase 2 gate on
`Permissions::effective` (`crates/domain/model/src/perm/policy.rs`): an evaluator
that fetches from a SQL-backed `ChannelStore` turns every permission check into
exactly the long hold measured here.

### 3.4 What this does not measure

- `MessageBus::call` does not exist. This builds the rendezvous over
  `send`/`take` plus a pre-registered reply slot. A real implementation should be
  no slower — the slot is already the direct hand-off — but it is not the same code.
- **No priority inheritance — and there never will be.** QNX runs the server at
  the caller's priority for the duration of a call. We cannot: raising a thread's
  priority needs `CAP_SYS_NICE`, which the deployment budget forbids requiring
  (line 92 of this file). So §3.3 measures an inversion whose QNX fix is
  unavailable, and `call()` will **await** rather than block
  (`docs/ARCHITECTURE.md` §6.1). Bounded hold time is the mitigation, not
  scheduling.
- One caller, one serving port. Contention between *many* callers on one port is
  unmeasured, and is the next thing to test.
- The evaluator is a bitmask, not real ACL evaluation. When the real one lands,
  re-measure: §3.3 says the hold time is what matters, and that is precisely what
  a real evaluator changes.

### 3.5 An earlier version of this experiment measured nothing

Recorded because the failure is easy to repeat: the first run had the caller
sending back-to-back with no pacing. The Control lane was therefore never empty,
the server never fell through to Feature work, and **4 feature requests were
served across 20 000 samples**. The inversion under test never happened, and the
run reported that contention was free.

The tell was in the output — a served-request counter that should have been in
the thousands. Any experiment claiming an effect is absent needs a counter
proving the cause was present.

---

## 4. Not yet covered

Everything above measures the bus in isolation on one machine. This is the rest
of the surface, ordered by whether it could change a conclusion already drawn.

### 4.1 Could invalidate §1-§3

| # | Gap | Why it bites |
|---|---|---|
| A1 | **Linux, and a CPU-limited container** | All three experiments ran on Windows 11, 24 unconstrained cores. Thread wake-up *is* the cold-path cost in §3 — 18 of the 18.2 us — and Windows scheduler granularity is not Linux futex behaviour. The deployment target is one container, plausibly under a cgroup quota. Every number in §3 and every derived ceiling could move. |
| A2 | **Real handler hold times** | §3.3 concludes hold time is the thing that breaks the budget. **No handler's hold time has ever been measured.** The longest one is the effective p99 floor for every other request, and it is currently unknown. |
| A3 | **Fan-out cost inside the state service** | `core/broadcast.rs::resolve` allocates twice per broadcast — `channel_members` -> `Vec<SessionId>`, then `conns_for` -> `Vec<ConnId>` — and `Recipients::All` allocates a vector of every session. O(members), on every broadcast, inside the single writer. That is exactly the hold time A2 asks about. |
| A4 | **Many callers on one port** | §3 used one caller and one serving port. Contention between callers, and the reply-storm when several unblock at once, are unmeasured. |
| A5 | **The `Bytes` refcount claim at fan-out scale** | A test asserts a clone shares the allocation. Nothing measures whether that holds up as a broadcast fans out to tens of recipients, which is the case it was chosen for. |

### 4.2 Liveness risks that `call()` introduces and nothing tests

`send` could not deadlock; a blocking `call()` can. These are correctness gaps,
not slow paths.

| # | Gap | Why it bites |
|---|---|---|
| B1 | **Cycles** | A `call()`s B while B `call()`s A blocks both forever. QNX has the same hazard and answers it with discipline, not mechanism; this design currently states no rule at all. |
| B2 | **Nested-call hold-time accumulation** | feature -> state -> storage: each level's hold time adds to the caller's wait. No depth limit and no budget decomposition exists. |
| B3 | **Timeout policy** | What a caller does when no reply arrives is unspecified, and it interacts with `Overflow::DisconnectPeer` on the Control lane. |
| B4 | **Reconnect storm x `DisconnectPeer`** | Already flagged as deserving its own experiment and still unmeasured: a full Control lane disconnects the peers that are trying to reconnect, which is a plausible feedback loop. |

### 4.3 Blocked on later phases

| # | Gap | Phase |
|---|---|---|
| C1 | SQL-backed `ChannelStore` latency — the change that would turn every permission check into A2's long hold | 2 |
| C2 | Write-behind queue depth under sustained load | 2 |
| C3 | The KV benchmark for persistent chat's four query shapes (`docs/STORAGE.md` §5.7) | 4 |
| C4 | Voice end-to-end: UDP -> bus -> routing snapshot -> N listeners. `realtime.rs` measured synthetic `send`/`take`, never voice. | 1 |
| C5 | WASM fuel/epoch-interruption overhead on a plugin call | 3 |

### 4.4 Scale and resource, wholly unmeasured

| # | Gap |
|---|---|
| D1 | Port count at scale — registration cost and `lane_of` lookup with hundreds of connections |
| D2 | **Memory.** No RAM figure exists for the bus at all: per port, per lane, per queue at capacity. |
| D3 | Envelope allocation churn — the PoC allocates a `Vec` per reply |
| D4 | The log path under load: `starling-log`'s 500 ms periodic flush against a saturated `Io` lane |
| D5 | TLS handshake cost, and a connection storm against `max_users` |

### 4.5 The blocking-versus-awaiting comparison is untested

§3 measured a *blocking* rendezvous: 0.9 us hot, 18.2 us cold, where the 17 us
difference is thread wake-up. The design has since chosen an **awaiting** `call()`
(`docs/ARCHITECTURE.md` §6.1), which should have no wake-up cost because the
executor thread is already running — but that is a prediction, not a measurement.

Re-running `rendezvous.rs` with an async caller on a live executor would test it,
and would also show whether releasing the thread changes the §3.3 hold-time
result. It should not: a handler that refuses to yield is worse under cooperative
scheduling, not better.

### 4.6 The honest summary

Three experiments justify **lane topology** (§1), **a separate Realtime lane**
(§2), and **the cost of the bus mandate** (§3). They do not yet say anything
about the server's throughput, its memory, its behaviour on the platform it
ships on, or whether a blocking `call()` can deadlock it. A1 and A2 are the two
worth closing before Phase 1, because §3's verdict rests on both.
