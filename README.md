<img src=".github/images/starling.png" alt="Sterling, the Starling mascot" width="200" align="right">

# Starling

A pure-Rust Mumble server, the replacement for `vendor/server` (C++/Qt murmur,
Fancy fork).

Starlings fly in *murmurations*, which keeps the name in the Mumble/Murmur
family, and describes the job.

The bird is **Sterling** — one letter off the project, and by the usual
etymology "little star", after the star struck on early Norman pennies. It is
also what you call something dependable, which is the only promise a server
mascot should make.

**A gateway in front, independent gRPC services behind it, and media planes that
bypass the gateway entirely.** Architecture:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Wire compatibility:
[`docs/PROTOCOL-COMPATIBILITY.md`](docs/PROTOCOL-COMPATIBILITY.md). Config:
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md). Storage:
[`docs/STORAGE.md`](docs/STORAGE.md). Diagrams:
[`docs/diagrams/`](docs/diagrams/).

How far the port has got, measured against two different targets:
[`docs/GAP-ANALYSIS.md`](docs/GAP-ANALYSIS.md) against upstream murmur, and
[`docs/FANCY-PARITY.md`](docs/FANCY-PARITY.md) against the Fancy fork. A feature
can be done by one measure and missing by the other, so neither number alone
says whether a client will work.

## Quick start

```sh
# One process, every service, in-memory transports between them.
cargo run --bin starling -- --all-in-one

# One service, as Kubernetes runs it.
cargo run --bin starling -- text --config starling.toml

# Convert an existing murmur config.
cargo run --bin starling -- migrate-config /path/to/mumble-server.ini > starling.toml
```

With no `--config`, built-in defaults apply and a self-signed certificate is
generated in `starling-data/` on first boot. Mumble clients identify a server by
certificate fingerprint, so keeping that directory keeps the server's identity
stable across restarts.

**Linux, macOS and Windows.** Services on one host reach each other over the
platform's own local IPC — a Unix domain socket, or a named pipe on Windows —
and the built-in defaults pick whichever this build can serve, so the quick
start above needs no configuration file on any of the three. A hand-written
`unix:` endpoint is a startup error on Windows rather than a substitution: the
two are different permission boundaries and only one exists per build.
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md#endpoints) has the table.

## In containers

One image, one entrypoint, and `command` decides which service a container is.
[`docker-compose.yml`](docker-compose.yml) is the deployment of
`docs/ARCHITECTURE.md` — 22 containers by default, the 21 services plus the
gateway — configured by [`deploy/starling.toml`](deploy/starling.toml):

```sh
docker compose up -d --wait --build                  # build, start in tier order, block
docker compose --profile admin up -d --wait --build  # ... plus operator-api, on loopback
docker compose up -d --wait --build starling         # instead: one container, in-process
```

Keep the `--build`. Compose builds only when the image is *missing*, so a stale
`starling:local` is reused however far the source has moved. Every container
runs the same binary picked by `command`, so that failure surfaces as a service
exiting with `no service named "..."` — which says nothing about the image, and
is the reason this warning is here.

Then connect a Mumble client to `localhost:64738`. `--wait` returns once every
container is healthy, and health here is a TCP connect: this build has no HTTP
`/healthz` to probe, so it means the listener is up, not that the caches are
warm.

## The shape of it

```text
              ┌──────────┐   gRPC    ┌─────────────────────────────┐
 client ─TCP─►│ gateway  │──────────►│ 21 services, tiered         │
              │  TLS     │           │ essential · core · optional │
              │ framing  │           └─────────────────────────────┘
              │ limits   │
              └──────────┘
 client ─UDP──────────────────────► voice        (its own socket, no hop)
 client ─HTTPS────────────────────► files        (signed URL, out of band)
 operator ─HTTPS──────────────────► operator-api (REST + OpenAPI, off by default)
```

Two facts carry the rest of the gateway's design. It is the **single writer to
each client socket**, so per-client ordering holds by construction. And the wire
type is in the **framing, not the protobuf**, so routing is two bytes and a
lookup: it parses no payload, links no service's stubs, and never recompiles
when a service is added. A new service is a TOML block.

## Crates

| Crate                   | What it is                                                                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `starling-proto`        | Upstream `Mumble.proto`: framing, message ids, version encodings. Upstream's surface plus the Fancy 1000+ fields, headed for upstream's file verbatim |
| `starling-proto-fancy`  | One envelope per service (types 1000+), and the inter-service gRPC contracts                                                                          |
| `starling-gate`         | What a peer is allowed to be given, by announced Fancy version                                                                                        |
| `starling-crypto`       | Voice ciphers, TLS identity, suite negotiation                                                                                                        |
| `starling-runtime`      | The one common crate: config, serving, health, drain, telemetry, storage, the client plane                                                            |
| `starling-gateway`      | The only component that holds a client's socket                                                                                                       |
| `crates/services/*`     | Twenty-one services, tiered in `docs/ARCHITECTURE.md` §4 (`operator-api` has a tier too, but its own crate)                                            |
| `starling-directory`    | Outbound only: the hourly announcement to the public Mumble server list                                                                               |
| `starling-operator-api` | The admin plane: REST + OpenAPI, pluggable auth, fail-closed audit                                                                                    |
| `starling-migrate`      | murmur `.ini` → `starling.toml`                                                                                                                       |
| `starling`              | One image, one entrypoint: a service name, or `--all-in-one`                                                                                          |

## Services and tiers

`tier` is not documentation, the gateway reads it and behaves accordingly.

| Tier          | Services                                                                                                                     | Down means                            |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| **essential** | session-lifecycle, session-view, permissions, metadata, userdata, server-config                                              | reject logins                         |
| **core**      | voice, text, pchat, moderation                                                                                               | that feature is dead; the server runs |
| **optional**  | screenshare, files, plugins, push, audit, onboarding, social, link-preview, context-actions, directory, health, operator-api | nobody notices                        |

The gateway's own tier is `core`, which it would never consult: a tier says what
the gateway does while a service is unhealthy.

## Quality gates

Run after every logical task, not at the end of the day:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --doc
```

Before pushing:

```sh
cargo deny check advisories bans licenses sources
scripts/check-proto-drift.sh           # our trees agree with each other
python3 scripts/check-proto-hygiene.py # ...and none of them breaks its own rules
python3 scripts/check-proto-compat.py  # ...and we still match real upstream Mumble
```

Three checks because each is blind where the next one looks. The drift check
compares our trees, so it catches one that fell behind but never a rule all of
them break identically — both such rules did, see
[`docs/PROTOCOL-MIGRATION.md`](docs/PROTOCOL-MIGRATION.md) M6. Hygiene covers
those. Neither compares against Mumble itself, so neither can see a break with a
released client; compat reads `mumble-voip/mumble` from the `upstream` remote in
`vendor/server` and is the only one that can.

Lint configuration is deliberately mirrored from `vendor/client` and
`vendor/server/3rdparty/mumble-plugin-host`; keep the three in sync.
