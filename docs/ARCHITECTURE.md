# Starling architecture

> **Thesis: a gateway in front, services behind it, and the realtime plane never
> touch the gateway at all.**

Starling is a set of independent processes speaking gRPC, fronted by one
**gateway** that owns the client's TCP connection. Audio and screen-share media
bypass the gateway entirely and reach their service directly. Bulk transfer goes
over plain HTTP.

Diagrams: `diagrams/services.puml` for the whole picture,
`diagrams/gateway-internals.puml` for the gateway, `diagrams/deployment.puml`
for the container topology.

This supersedes the microkernel / in-process-bus design entirely. There is no
bus, no lanes, no envelopes and no `starling-api` trait hub.

---

## 1. Why the gateway can route without understanding anything

The Mumble control frame is `type: u16 ‖ len: u32 ‖ payload`, and **the type is
in the framing, not in the protobuf** — `vendor/server/src/murmur/Server.cpp:2040`
writes it with `qToBigEndian(static_cast<quint16>(…))`.

So the gateway reads two bytes, looks up a route, and forwards the payload
**verbatim**. It never parses a protobuf field, never links a service's generated
stubs, and never recompiles when a service is added.

### One outer type per service, nested envelope inside

Upstream types (0–26) are flat and frozen forever. Every Fancy service instead
gets **one** outer type, and its payload is a service-owned envelope carrying its
own `oneof`:

```protobuf
// starling-proto-fancy/pchat.proto — owned entirely by the pchat service
message PchatEnvelope {
  oneof body {
    PchatMessage       message      = 1;
    PchatFetch         fetch        = 2;
    PchatKeyAnnounce   key_announce = 3;
    // ... unbounded, and adding one touches nothing outside this file
  }
}
```

This is strictly better than allocating blocks of the flat `u16` space:

* **message types per service are unbounded** — no block size to get wrong
* **the gateway's routing table is one line per service**, not one per message
* **adding a message type needs no config change and no coordination.** With a
  flat space, every new type edits a central registry that every service shares.
  Here a service's types are private to it
* **it costs nothing.** The gateway forwards verbatim either way, and the service
  was going to decode a protobuf regardless — the `oneof` tag is one extra varint

The trade-off is that a packet capture shows `type 1002` rather than
`PchatMessage`; the inner tag is the payload's first field, so tooling recovers
the name from one nested read.

### Type allocation

| Range | Use |
|---|---|
| **0–99** | upstream Mumble, flat, **frozen** (0–26 in use) |
| **100–999** | **burned.** The old interleaved Fancy flat types shipped in released clients; never reused, so a stale client's message can never be misread as a new service's |
| **1000+** | one outer type per service, nested envelope. 64 500 services available |

Why 100–999 is burned rather than reclaimed: today's Fancy numbering is
*interleaved*, not blocked — `WebRtcSignal` is 120, sitting between pchat's
100–119 and 121, and pchat's pins are at 128–130. Range routing cannot work on
it, and reusing those numbers risks a deployed client's message landing on the
wrong service. See `PROTOCOL-COMPATIBILITY.md`.

## 2. What only the gateway can do

**It is the single writer to each client socket.** It physically holds the TCP
connection, so per-client ordering is preserved by construction: a client cannot
receive the `UserState` naming a channel before the `ChannelState` creating it,
whatever order the services produced them in. The in-process design needed a lane
rule and a version counter for this. Here it is free.

**It owns rate limiting, per route.** murmur runs one shared leaky bucket per
user — 1 msg/s sustained, burst 5, **silent drop** (`RATELIMIT` in
`vendor/server/src/murmur/Messages.cpp`). Starting a screen share legitimately
emits several signalling messages back to back, and this silently ate the
loopback-viewer SDP offer in most runs: the client logged success, the server
logged nothing. So limits are per route, and **a throttled message is never
silently dropped** — Fancy clients are told; legacy clients keep the silence they
expect.

**It owns backpressure toward the client** — see §5.

## 3. Four planes

| Plane | Transport | Path |
|---|---|---|
| **control** | TCP 64738 + TLS | client → gateway → gRPC → service |
| **realtime** | UDP 64738, WebRTC/ICE | client → **service directly** |
| **bulk** | HTTPS | client → **http service directly**, signed URL |
| **admin** | HTTPS + REST | operator → **operator-api** → gRPC → service |

### Audio needs no hop

murmur already binds TCP and UDP as two independent sockets on one port number —
`Server.cpp:125` calls `listen()`, `Server.cpp:193` calls `::bind()`. Two
sockets, one port, and **they can live in different processes.**

The voice service binds UDP:64738 and clients send audio straight to it. The
kernel does the demux; no gateway hop, no serialisation, no fan-out
amplification. The only audio reaching the control plane is `UDPTunnel` (type 1),
the fallback for UDP-blocked clients, which is per-client not per-listener.

Screen share has the same shape — signalling through the gateway, media
client↔SFU. Two contract constraints, each of which cost a debugging session:

* the str0m SFU is **ICE-lite**: it ignores trickled candidates and its own rides
  in the SDP answer. Never trickle ICE through the control plane
* **SDP offers retry until answered**, because of the rate limit above

### Bulk must leave the control stream

Mumble has no file transfer; `RequestBlob` (23) moves avatars and comments over
the control connection. Anything large there head-of-line blocks every control
message behind it — and the control-overflow-disconnects rule would then kill
clients mid-upload.

So the http service gets its own listener. The gateway hands out a **short-lived
signed URL** over the control channel and bytes move over HTTP: shared files,
avatars, comments, plugin binaries, link-preview thumbnails, audit exports.

Being HTTP, it can sit behind a Kubernetes `Ingress` and get TLS termination and a
CDN for free. `operator-api` is the other HTTP surface, but wants the opposite
exposure — a private ingress, or none at all.

### The admin plane is HTTP, in its own process

The operator surface — the replacement for Ice — can create users, rewrite ACLs,
ban, and read the database. It is the highest-privilege surface in the system.

**It is plain HTTP with an OpenAPI description**, for two reasons. An admin client
becomes trivial to write in any language, including a browser panel and `curl`.
And authentication becomes **whatever the operator already runs** rather than
something we invent:

| Mode | Use |
|---|---|
| **`oidc`** | Keycloak, Authentik, Auth0, Entra — JWT validated against the issuer's JWKS |
| **`jwt`** | a bare token signed by a key you hold, for setups without an IdP |
| **`mtls`** | client certificates, when a PKI already exists |
| **`token`** | a static API token, for a script or a one-box install |

Token claims map to Starling scopes in the TOML, so an existing Keycloak role
becomes an authorisation without code. That is a Strategy per DESIGN.md §3: a new
mode is a new implementation, never a new arm in a `match`.

Against Ice, which is what this replaces:

| | Ice today | Starling |
|---|---|---|
| credential | `icesecret`, one static string in the config file | OIDC / JWT / mTLS / token, configured |
| identity | none — the secret *is* the identity | per operator, so actions attribute |
| scope | `icesecretread` / `icesecretwrite` | per service and per operation, from claims |
| rotation | edit the config, restart | issue and revoke at the IdP, no downtime |
| exposure | wherever the Ice endpoint was bound | **default off**, localhost unless configured |

**It is not a second policy implementation.** `operator-api` calls the same gRPC
methods the gateway does, carrying an operator identity and its scopes instead of
a session. The invariant is that no service accepts an unauthenticated call, and
that is enforced by inter-service auth (§8) — not by funnelling every plane
through one process.

**Why its own process rather than a listener on the gateway.** An OIDC client, a
JWKS cache, JSON and OpenAPI routing are a large dependency surface to load into
the process that holds every client's TCP socket; a bug in the admin stack must
not drop live calls. Admin traffic is tiny and bursty where client traffic is
steady, and in Kubernetes the two want opposite exposure — a private ingress
versus a public `LoadBalancer`. Co-locating them is still possible via
`--all-in-one` for a single-box install.

**Fail closed on audit.** Every operator action is recorded, and a request is
refused if it cannot be recorded. `audit` is an optional service (§4) and the
highest-privilege plane must not depend on one, so `operator-api` writes this
record itself.

`vendor/channelviewer` is an existing Ice consumer (`getDefaultConf`), so a shim
is required for it — see `PORTING-PLAN.md` R1 and §6.

## 4. Services and tiers

`tier` is not documentation — the gateway reads it and behaves accordingly.

| Tier | Services | Down means |
|---|---|---|
| **essential** | session-lifecycle, session-view, permissions, metadata, userdata, server-config | reject logins |
| **core** | voice, text, pchat, moderation | that feature is dead; server runs |
| **optional** | screenshare, files/http, plugins, push, audit, onboarding, social, link-preview, context-actions, **directory**, **operator-api** | nobody notices |

### The outward-facing plane is one service, and it is optional

`directory` is the replacement for murmur's `Register.cpp`: an hourly
announcement to the public Mumble server list. It has **no wire type, no gRPC
surface and no endpoint** — nothing dials it, it dials out — which makes it
internal by construction the way `session-view` is, for the opposite reason.

It is not part of `server-config`, which owns the settings it reads. That service
is **essential**, and a scheduled outbound HTTPS client with a TLS trust store
and an XML payload does not belong in the process a handshake cannot proceed
without. Being listed is the definition of optional: nobody notices for an hour,
which is the interval anyway.

Two couplings in it are worth stating, because both are easy to get subtly wrong:

* **the announced fingerprint must be the one clients are shown.** It is the
  SHA-1 of the *gateway's* certificate, so `directory` reads the same file by the
  same rule and never generates one — a second convention here would publish an
  identity nobody is ever presented with.
* **the user count must be the whole server's.** It comes from `session-view`,
  not from any one gateway or voice pod, each of which sees a fraction once there
  is more than one.

The unauthenticated UDP ping is the other half of the same story and lives
somewhere else, because it has to: `voice` owns the socket it arrives on. Both
are gated by one operational setting, `allow_ping` — and registration refuses to
run without it, since a listing the list cannot measure is a dead entry.

### Session is two services, because it is two responsibilities

**`session-lifecycle` owns a connection's existence.** Negotiate the version,
authenticate, hand over `CryptSetup`, answer `Ping`, notice a timeout, tear down.
It is a state machine per connection, and it is the only half a client ever talks
to.

**`session-view` owns the composed read model** the rest of the domain asks
questions of. It never talks to a client and **has no client-facing message
type**, which keeps it internal by construction rather than by convention.

Splitting them matters because they change for different reasons: the first
changes when the handshake changes, the second when a service needs a new fact.

### `session-view` is the edge of the domain

Every service in the control, core and realtime groups reads through `session-view`
and nowhere else. Without it each would depend on userdata, permissions, metadata
and server-config — N×4 edges, and four caches each to keep warm.

Two rules stop it becoming the god service:

**It forwards, but never decides.** Hot facts come from its composed view;
anything else it routes to the owning service untouched. It writes nothing, and
the four authorities stay authoritative. Note the distinction that makes a strict
edge workable: *forwarding* a cold query is routing, whereas *caching* the
`(user, channel)` ACL cross product would make it a second ACL engine. It does
the first and never the second.

**It is a subscription hub, not a proxy.** Services subscribe to a snapshot
stream and keep their own copy rather than calling per request, so the rule that
nothing on the audio path may make a request still holds. Voice subscribes *once*
instead of to three services.

The cost is one extra hop for the cold cases — an ACL query about a channel the
user is not in, or a lookup of an offline account. Neither is on a hot path:
whisper setup is not per-packet and moderation is not per-frame.

**A stale deny is safe; a stale grant is a security bug.** So a revocation
invalidates the composed view before it is acknowledged, while a grant may arrive
lazily.

**The admin plane is the one exception**, and it has to be: `session-view` is a
view of *connected* users, while an operator edits registered accounts, offline
bans and server config. `operator-api` therefore calls the authorities directly.

### Voice mints the ciphers, not session-lifecycle

`CryptSetup` (15) is a control message, so `session-lifecycle` delivers it — but
the key is used by voice to seal UDP. So **voice generates it** and
`session-lifecycle` asks for a ready-made payload to forward. Key material never
crosses a service boundary, and a client-requested resync takes the same path.

### There are two config layers, and only one of them is a service

murmur keeps both in one `Config` table. Starling splits them, because they have
different lifetimes:

**Deployment config lives in the TOML** — service endpoints, listen ports, TLS
paths, storage URLs, tiers and routes. Changing any of it needs a restart anyway,
so it is read once at startup and injected at construction. No late-subscriber
problem, no service to be down.

**Operational config lives in the `server-config` service** — everything murmur
lets an operator change live: `bandwidth`, `messagelimit`/`messageburst`, `users`,
`welcometext`, `allowhtml`, `channelnestinglimit`, `imagemessagelength`,
`listenersperchannel`, `certrequired`, `logdays`. One actor per virtual server,
published as a snapshot that readers cache — the same pattern as metadata's
membership.

That is why it is **essential**: the gateway cannot rate-limit without
`messagelimit` and the handshake cannot complete without the config the client is
sent. A cold start with it down must reject logins rather than quietly serve on
defaults the operator never chose. Once caches are warm a restart is survivable,
like every other service.

**Account settings are userdata**, not settings. They are per-user profile data
and belong with the profile.

A small server runs five processes; a large one runs twenty-four. "Don't run what
you don't want" beats murmur's compile-time flags.

**Each service owns its own schema.** No service reads another's tables. A shared
database service would keep the schema coupling *and* add a hop — the
anti-pattern this architecture exists to avoid. One migration tool, many schemas;
see `STORAGE.md`.

## 5. Ordering and backpressure

**Ordering is per-stream and comes from single-writer sources.** Metadata is one
actor and the sole writer of channel state, so the order it applies mutations is
a total order; the gateway is the sole writer to a client socket, so that order
survives to the wire. Nothing further is required.

**A slow consumer never backpressures a shared producer.** If metadata publishes
to a thousand clients and one has a bad connection, blocking would head-of-line
block all of them. That client is disconnected instead.

| Path | Full means |
|---|---|
| control to a client | **disconnect that client** |
| audio to a client | drop oldest, count it |
| UDP would block | drop, never queue |
| service to service | the gRPC deadline reports it |

Dropping a control message desyncs that client permanently and silently — it
renders the wrong world forever with nothing in any log — and unbounded queueing
is a memory DoS. Disconnecting is the only outcome both bounded and honest, and
reconnect already re-syncs from scratch. A late audio frame is worthless.

gRPC streams carry HTTP/2 flow control, so a service pushing faster than the
gateway can write is throttled by the transport rather than by hand-rolled queue
accounting.

**Everything lost is counted:** audio frames dropped, clients disconnected for
control overflow, requests expired.

### Shard keys are decided now, not at deployment

A shard key cannot be retrofitted — it changes every caller. `scaling.puml` has
the per-service table; three of them are load-bearing:

**`voice` shards by channel, never by client.** Audio routing is per channel, so
a channel's members must share a pod. Client affinity (`sessionAffinity: ClientIP`)
is actively wrong: it scatters a channel across pods, and there is no inter-pod
audio path. Discord assigns a voice *channel* to a voice server and tells the
client which one; Mumble has no such field, and **a legacy client sends UDP to the
port it made TCP to**, so it cannot be redirected. Legacy therefore scales
vertically only. Handing Fancy clients an explicit endpoint in `ServerSync` is the
one option that scales.

**`session-view` shards by session id.** It holds a composed view per connected
session and updates all of them on every change — unsharded, that is one actor
performing every domain read, which is Discord's guild-process bottleneck
relocated. It is also the hardest to fix later, because every service calls it.

**`metadata` and `server-config` shard by virtual server** — the guild-process
pattern, and simultaneously the answer to running several virtual servers.

### Reliability mechanisms that are not optional

**RESUME.** Restart a gateway holding 10 000 clients and every one reconnects and
pulls a full flood of every `ChannelState` and `UserState` at once — a
self-inflicted DDoS on `metadata` and `session-view`. With a sequence number per
session a client replays only the gap. That requires the sequence and its replay
buffer to **outlive the gateway pod**, so a resuming client can land on another
one. **zstd** on the Fancy control stream shrinks the same transfer.

**Legacy clients can never RESUME**, so staggered drain and jittered reconnect
hints are required regardless of whether the store exists. The store optimises a
path that must already survive without it.

#### The session store is not a service, and that is a gap in the tier model

`tier` decides one thing: what the gateway does when a dependency is down. For
the session store, both answers are wrong. **essential** would reject logins over
a lost *optimisation*. **optional** claims nobody notices — false, since its
absence bites at the worst possible moment, and the resulting reconnect herd can
saturate `metadata`, which *is* essential.

The resolution is that it is not a service. No client reaches it, it has no
message type or gRPC surface, and it is never scaled independently: it is the
gateway's own durable state, externalised so a pod can die. Closer to the
gateway's TLS keys than to `userdata`.

It therefore has no tier, and is reported in readiness as a **warning**, never as
unready. Worth recording the general shape, because a second component like this
will appear: **a dependency whose failure is deferred and amplifying does not fit
a taxonomy built around immediate behaviour.**

Two things about it are still undesigned, and both change the shape rather than
tune it:

* **frames or events?** Storing per-client *frames* lets the gateway replay
  verbatim, but one broadcast to 1000 clients becomes 1000 buffer writes for one
  logical event — roughly 200 MB for 10 000 clients × 100 frames. Storing the
  event stream once and re-deriving per client is far cheaper and much more
  complex.
* **it sits on the control hot path.** The gateway stamps the sequence, so a naive
  implementation writes to the store on every outbound frame. Buffer locally and
  flush asynchronously; a crash then loses the tail, which is harmless because the
  client simply resumes from further back.

**Circuit breakers, not just deadlines.** A saturated service otherwise makes
every caller wait its full deadline and *then* fail, burning gateway capacity
throughout. Trip the breaker and shed at the door, using the same `tier` the
readiness logic uses.

**Bounded mailboxes everywhere.** An unbounded inbox converts one slow consumer
into an OOM — the specific failure Discord hit with Erlang process mailboxes under
fanout. Every actor gets a bound and a shed policy.

**UUIDv7 for anything with history** — pchat messages, pins, reactions, offline
queues, text history, audit entries. Coordination-free and time-sortable, which is
what Discord's Snowflake buys them. A central sequence is a bottleneck; UUIDv4
destroys index locality.

### Two realtime invariants

**Opus is forwarded, never transcoded.** Starling is an SFU, not an MCU. A
transcode blows a 10 ms budget on the first frame, and it is the sort of thing
added for "server-side mixing" without anyone measuring.

**Audio payloads are refcounted, never copied per listener.** The real per-packet
cost is **N seals, not one** — each listener needs the frame under their own key,
and that number sizes the pod.

### The measured budget

Carried over from the bus experiments, which are gone with the bus:

* **one 10 ms audio frame is the budget** — an absolute figure, not a ratio
* 17.8 µs of overhead against that is three orders of magnitude clear, so
  per-message cost on the *control* plane is not where audio dies
* **the failure mode was refusal, not latency** — 392 of 400 slow publications
  were refused outright rather than delayed. Watch refusals, not percentiles

The surviving conclusion: a gRPC hop is affordable on the control plane and fatal
on audio fan-out. Hence §3.

## 6. What was taken from Discord

**Stateful gateway, state in separate processes.** Their gateway holds the socket
and fans out; guild state lives in separate processes rather than being read from
the database per event. That is the gateway + metadata split, and why voice caches
membership instead of querying it.

**One process per guild → one actor per virtual server.** Metadata runs one actor
per virtual server, sharded by server id — a better answer to multiple virtual
servers than either previous design had.

**Lazy subscriptions.** Discord clients declare what they are viewing and get
only that. Mumble broadcasts all channel and user state to everyone, which is
exactly the fanout Discord engineered away. Legacy clients need the full flood and
keep it; **Fancy clients subscribe.** Same protocol, opt-in scaling.

**Sequence numbers and resume.** Their gateway stamps each event with a sequence
number; a dropped client reconnects with its last seen value and replays the gap.
Here that makes the ordering guarantee observable and lets a Fancy client skip the
flood on reconnect.

**Request coalescing.** Their Rust data services collapse concurrent identical
reads into one query so a hot partition cannot be stampeded. The analogue is
**permissions**: ACL evaluation walks the channel tree and a busy channel produces
many identical in-flight queries. Coalescing beats a cache, because a cache needs
invalidation and coalescing does not.

## 7. Crates

```
crates/
  runtime/            starling-runtime       the one common standalone crate
  proto/              starling-proto         upstream Mumble.proto, FROZEN
  proto-fancy/        starling-proto-fancy   one envelope per service
  gateway/            starling-gateway
  services/
    session-lifecycle/  session-view/
    permissions/  metadata/  userdata/  server-config/
    voice/  text/  pchat/  moderation/
    screenshare/  files/  plugins/  push/  audit/
    onboarding/  social/  link-preview/  context-actions/
    directory/        starling-directory     the public server list, outbound only
  operator-api/       starling-operator-api  REST + OpenAPI, pluggable auth
```

Splitting the proto in two makes "never break native Mumble" structural rather
than a rule someone remembers.

### `starling-runtime`

Each service is a library crate plus a one-line binary:

```rust
fn main() -> anyhow::Result<()> { starling_runtime::serve::<TextService>() }
```

The runtime provides, once, what every service needs and Kubernetes requires:

* TOML config with env override, so a ConfigMap works without templating
* tonic bootstrap over TCP or a Unix socket
* `/healthz` and `/readyz`, **distinct** — readiness fails while caches warm
* **SIGTERM → graceful drain.** Non-negotiable; K8s kills you 30 s later anyway
* OTel tracing, request id threaded through every hop
* a metrics endpoint
* endpoint discovery from env, which K8s DNS fills in for free

It also provides `--all-in-one`: every service in one process, in-process calls.
Same code, two deployment modes — one binary for a VPS, twenty-four processes for
isolation or per-service scaling. It also exercises the boundaries both ways.

## 8. What separate processes cost

Things the in-process design got for free and now must be built:

* **request tracing** — or a hung permission check is unattributable
* **health and readiness** — the gateway must know what is up and degrade per §4
* **restart semantics** — a restarted service has cold caches. Voice must
  re-subscribe and refetch membership *before* routing, or it silently drops
  audio. Readiness gates on cache warm-up, not on the process being alive
* **inter-service auth** — Unix socket permissions locally, mTLS across hosts
* **schema skew** — twenty-four processes deploy at different times, so gRPC
  contracts must tolerate a version skew one process never had

## 9. Deployment

**One image, many deployments.** A single image whose entrypoint takes the
service name; K8s runs `args: ["text"]`. Twenty-four Dockerfiles is twenty-four
things to keep in sync, and it makes `--all-in-one` a matter of arguments rather
than a separate build.

Two things are genuinely awkward:

**The gateway cannot use a Kubernetes `Ingress`.** `Ingress` is HTTP-only and
Mumble is raw TCP+TLS, so it needs `Service type=LoadBalancer` or Gateway API
`TCPRoute`. This is also why the front component is the **gateway** and not
`ingress`: naming it after a resource it can never use is a trap.

**Voice under UDP load balancing.** A TCP connection pins a client to a gateway
pod; UDP has nothing to pin. Discord solves this by *telling* the client which
voice server to use. Mumble has no such field, and **a legacy client sends UDP to
the same host:port it made TCP to.** So:

* legacy clients need voice reachable at the gateway's address — a sidecar in the
  same pod, or a UDP load balancer with source-IP affinity
* Fancy clients can be handed an explicit voice endpoint in `ServerSync`, a
  protocol extension on the upgrade path already maintained
