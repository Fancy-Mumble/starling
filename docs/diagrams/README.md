# Diagrams

| File | Shows |
|---|---|
| `components.puml` | **Start here.** The planned components and the traffic between them |
| `net-internals.puml` | The five parts of `starling-net`, and why only one of them faces the bus |
| `crates.puml` | The layers, and which of them may depend on which |
| `kernel-structure.puml` | Compile-time dependency direction — the rule the kernel/feature split rests on |
| `kernel-internals.puml` | What a feature may touch: read via `StateQuery`, use `Capabilities`, return `Effects` |
| `kernel-message-flow.puml` | Runtime: one pchat message end to end, including the audit fan-out |

Rendered PNGs are build output and are not committed — `*.png` here is ignored.

## `components.puml` — why each edge is what it is

This diagram is **the plan, not the build.** None of it is wired yet.

**Requests carry a deadline; events do not.** A request is addressed to one
subscriber and expects one reply, so it needs a deadline — otherwise a caller
waits on a reply that may never come. An event is published to whoever
subscribed and expects nothing back, so a deadline would be meaningless.

**Deadlines are absolute `Instant`s, not deltas.** A delta list has to subtract
elapsed time from every entry on every wake, and the sleep always overshoots
slightly, so a long timer drifts a little further out on each pass. Absolute
deadlines need no subtraction pass and cannot drift. `tokio_util::time::DelayQueue`
is already this, on a hierarchical timing wheel, with O(1) insert and removal.

**A dead peer is cancelled; a slow one is not.** `connection-manager` knows the
moment a peer is reaped, so it drops that peer's outstanding deadlines at once
and the caller hears "no such peer" immediately. A peer that is merely slow —
or a slow database — is left alone and expires on its own deadline, because
slowness is not death and the reply may still be coming.

**Peers are not bus endpoints: one address, N tasks.** `connection-manager` is
the only thing on the bus for connections; each peer is a task behind it with
its own mailbox and its own state. That buys three things at once. The pre-auth
handover from cman to peer needs no subscription transfer, so it cannot race or
double-deliver. The bus keeps a single registration mechanism — `inventory` by
message type — because there is no longer a dynamic, per-connection half for it
to express. And no parallelism is lost: the runtime spreads peer tasks across
every core, and a peer waiting on the store blocks only itself. The dispatcher
stays honest because all it does is look up a mailbox and send, which cannot
block.

**The connection id is a generational index, not a UUID.** A `slotmap` key is an
index plus a generation. The index *is* the protocol's `session` u32, so the two
id spaces that would otherwise need a mapping are the same number. The
generation makes reuse safe: slot 7 reissued to a new connection gets a new
generation, so a stale reference to the old peer 7 fails cleanly instead of
silently reaching whoever holds that slot now. A UUID would buy uniqueness
across processes and time; what is needed is uniqueness across live connections
in one process, and the wire format has only 32 bits for it regardless.

**cman owns the handshake, peer owns the flood.** cman handles `Version`,
`Authenticate`, cert validation and the ban and rate-limit verdict, then either
rejects or spawns a peer — it never touches the channel tree. The peer's first
act is `CryptSetup`, `CodecVersion`, the channel and user flood, and
`ServerSync`. Splitting it there keeps cman at "may you be here at all", which
is one responsibility, and puts "bring my client up to date" with the component
that owns that client's outbound side.

**A connection that never authenticates is reaped on a deadline.** TCP and TLS
complete, then nothing arrives. That is slowloris, admission is cman's job, and
the deadline scheduler already exists — so cman arms one at accept.

**Initial config is injected at construction; the bus carries only changes.**
Every component is created by something — the root creates the components, cman
creates the peers — so initial values arrive as a constructor argument and the
late-subscriber problem never exists. This project has already been bitten once
by assuming a published event reaches a listener that registered afterwards;
events are not replayed. A peer inherits a narrow *session policy* (message
limits, bandwidth, idle timeout, welcome text), never the whole config — it has
no business knowing the database URL.

**A late reply is a warning, not a silent drop.** If a reply arrives after its
deadline the subscription is already gone. Say so in the log: it is the only
signal that a deadline is set too tight.

**Nothing on the audio path may be a request.** Voice keeps a local user cache
fed by `channel-tree`'s membership events. At 50 packets per second per speaker,
asking who is in a channel would put a bus round trip and a deadline inside a
10 ms budget. Membership changes a few times a second; audio routes thousands of
frames in the same window. Cache the rare thing and never poll it.

**Voice publishes one frame plus a recipient set, not one message per
listener.** net does the fan-out, because only net knows which recipients have a
working UDP path and which have to be tunnelled over TCP. Voice decides *who*;
net decides *how*.

**It is `channel-tree`, not `world`.** A component named after everything
collects everything, and the name is the only thing standing between a design
and a god class. Named after one data structure, the wrong addition becomes
visibly absurd: nobody files a ban list under "channel tree". The component
label lists what it holds *and what it does not*, for the same reason.

**`starling-net` is five parts, and only one of them faces the bus** — see
`net-internals.puml`. Splitting them keeps "run the loop" separate from "speak
the wire format", which are the two jobs that otherwise fuse into one
unreviewable file.

**Only `starling-net` encrypts.** It owns the sockets and does the fan-out, so
one hop can encrypt for every listener. Behind one trait, so OCB2, XChaCha20 and
plaintext are indistinguishable to everyone else — no other component may know
or care which is in use.

**The cipher applies to UDP only.** Audio arriving over `UDPTunnel` is already
inside TLS and must be passed on plain. Sealing it a second time produces a
client that hears silence, with nothing in any log to say why — this has already
cost a debugging session once.

**Only `starling-store` touches the database.** A component that knew the schema
would have to change when a table did. Requests go over the bus instead.

**Ordering is per-stream, and it does not come from the bus.** A client needs
its own frames in order; there is no cross-client requirement, so global
ordering would be expensive and pointless. Order comes from three properties
instead. Sources are **single-writer** — `channel-tree` is one task and the only
thing that may mutate channel state, so the order it applies mutations *is* a
total order. The bus guarantees only **FIFO per sender-receiver pair**, which a
tokio mpsc gives for free. And **all control traffic for one connection rides
one lane**, because two messages to the same client on different lanes can
overtake each other. Audio is the exception and it is safe: it has its own lane
and may reorder, since Mumble audio frames carry their own sequence number for
the client's jitter buffer. Lane priority therefore cannot break an ordering
that is actually required.

**The flood needs a version, or it races the tree.** A peer sends every
`ChannelState` and `UserState` while the tree may be changing underneath it.
Snapshot-then-subscribe loses whatever happened in the gap; subscribe-then-
snapshot delivers it twice. So `channel-tree` keeps a monotonic version, bumped
on every mutation and stamped on both snapshots and deltas: the peer subscribes
first, takes a snapshot, and discards any delta at or below the snapshot's
version.

**A slow consumer never backpressures a shared producer.** If `channel-tree`
publishes to a thousand peers and one is on a bad connection, blocking would
head-of-line block every other client — one stalled socket stopping the whole
server. The slow peer is disconnected instead. Every rule below follows from
that one.

**Control overflow disconnects; audio overflow drops.** Dropping a control
message desyncs that client permanently and silently — it renders the wrong
world forever with nothing in any log — and queueing without a bound is a memory
DoS. Disconnecting is the only outcome that is both bounded and honest, and
reconnect already re-syncs from scratch. A late *audio* frame is worthless, so
the audio queue drops its oldest entry and counts it; a UDP socket that would
block drops rather than queues at all. Between components there is no queue rule
to invent, because the deadline scheduler already reports a slow peer as an
expiry.

**The flood awaits the socket rather than queueing** — which is a direct payoff
from giving each peer its own task. A peer that blocks on a slow client blocks
only itself, so bulk transfer can use real async backpressure. Without
task-per-peer the control queue would have to be sized for the largest
legitimate burst, `N channels + N users`; with it, that sizing question never
arises.

**Everything lost is counted.** Audio frames dropped, connections closed for
control overflow, requests expired. The design insists elsewhere that losses are
visible; these are the losses.

**Single-consumer crates go home.** `starling-crypto` and `starling-tls` have
exactly one caller once net owns the cipher, so they belong inside net;
`starling-config` belongs to the config component. `domain` keeps only what more
than one component genuinely shares — the wire types and the value types.

## Rendering

```sh
plantuml -Playout=smetana -tpng *.puml
```

`-Playout=smetana` uses PlantUML's built-in layout engine, so **GraphViz is not
required**. Without it, the component diagrams fail on a machine that has no
`dot` on PATH — which is most of them.

Verified rendering with PlantUML 1.2024.7.

Two things worth checking after an edit, because both fail silently:

```sh
# 1. Markup that leaked into the image instead of formatting it.
plantuml -tsvg *.puml && grep -o '\*\*[^<]*\|&lt;/*b&gt;' *.svg

# 2. Clipping. PlantUML caps output at 4096 px and truncates without a word;
#    if the unlimited render is larger, the normal one is silently cut.
java -DPLANTUML_LIMIT_SIZE=16384 -jar plantuml.jar -tpng *.puml
```

## Style notes, learned the hard way

* **One message per diagram.** The first version of `kernel-structure` tried to
  show packages, components, interfaces, wiring and two notes at once, and was
  unreadable. Each diagram now answers exactly one question.
* **No `skinparam linetype ortho`.** Right-angle routing makes crossings worse,
  not better, once there is more than a handful of edges.
* **Avoid `interface` in component diagrams.** It renders as a lollipop circle,
  so a long label sprawls away from a tiny glyph. Use `rectangle`.
* **Stick to ASCII arrows in labels.** `->`, not `→` — the default font has no
  glyph for it and renders tofu. `·` and `«»` are fine.
* **No markup may span a line break.** `<b>` opened on one line of a note and
  closed on the next prints a literal `</b>`; creole `**bold**` split the same
  way prints a literal `**`. Keep every pair on one line, however long that line
  gets. Relatedly, a note line *starting* with `*` is parsed as a bullet, so a
  wrapped `**bold**` also silently becomes a list item.
* **Prefer a labelled edge to an interface node.** `components.puml` first drew
  its ten seams as ten lollipops; every layout engine piled them onto one rank
  with the labels overlapping. As `A --> B : «Trait»` the same ten seams carry
  the same information — caller, implementor, trait — and lay out on their own.
