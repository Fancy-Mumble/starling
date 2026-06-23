# Starling

A pure-Rust Mumble server — the replacement for `vendor/server` (C++/Qt murmur,
Fancy fork).

> Starlings fly in *murmurations*. The name stays in the Mumble/Murmur family,
> describes what the server does (coordinate a flock of voices into one motion),
> and is unique enough to grep for.

**A gateway in front, independent gRPC services behind it, and media planes that
bypass the gateway entirely.** Architecture:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Wire compatibility:
[`docs/PROTOCOL-COMPATIBILITY.md`](docs/PROTOCOL-COMPATIBILITY.md). Config:
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md). Storage:
[`docs/STORAGE.md`](docs/STORAGE.md). Diagrams:
[`docs/diagrams/`](docs/diagrams/).

## Quick start

```sh
# One process, every service, in-memory transports between them.
cargo run --bin starling -- --all-in-one

# One service, as Kubernetes runs it.
cargo run --bin starling -- text --config starling.toml

# Convert an existing murmur config.
cargo run --bin starling -- migrate-config /path/to/mumble-server.ini > starling.toml
```

With no `--config`, built-in defaults are used and a self-signed certificate is
generated in `starling-data/` on first boot — Mumble clients identify a server by
certificate fingerprint, so the pair is then stable across restarts.

**Linux, macOS and Windows.** Services on one host reach each other over the
platform's own local IPC — a Unix domain socket, or a named pipe on Windows — and
the built-in defaults pick whichever this build can serve, so the quick start
above needs no configuration file on any of the three. A hand-written `unix:`
endpoint is a startup error on Windows rather than a substitution, because the
two are different permission boundaries and only one of them exists per build;
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md#endpoints) has the table.

## In containers

One image, one entrypoint, and `command` decides which service a container is.
[`docker-compose.yml`](docker-compose.yml) is the twenty-container deployment of
`docs/ARCHITECTURE.md`, configured by [`deploy/starling.toml`](deploy/starling.toml):

```sh
docker compose up -d --wait --build                  # build, start in tier order, block
docker compose --profile admin up -d --wait --build  # ... plus operator-api, on loopback
docker compose up -d --wait --build starling         # instead: one container, in-process
```

Keep the `--build`. Compose builds only when the image is *missing*, so a stale
`starling:local` is reused however far the source has moved — and since every
container runs the same binary picked by `command`, that surfaces as a service
exiting with `no service named "…"` rather than as anything about the image.

Then connect a Mumble client to `localhost:64738`. `--wait` returns once every
container is healthy, which is a TCP connect — this build has no HTTP `/healthz`
to probe, so it means the listener is up rather than the caches are warm.

## The shape of it

```text
              ┌──────────┐   gRPC    ┌─────────────────────────────┐
 client ─TCP─►│ gateway  │──────────►│ 20 services, tiered         │
              │  TLS     │           │ essential · core · optional │
              │ framing  │           └─────────────────────────────┘
              │ limits   │
              └──────────┘
 client ─UDP──────────────────────► voice        (its own socket, no hop)
 client ─HTTPS────────────────────► files        (signed URL, out of band)
 operator ─HTTPS──────────────────► operator-api (REST + OpenAPI, off by default)
```

Two facts give the gateway everything else for free: it is the **single writer to
each client socket**, so per-client ordering is preserved by construction; and
the wire type is in the **framing, not the protobuf**, so routing is two bytes
and a lookup. It parses no payload, links no service's stubs, and never
recompiles when a service is added — a new service is a TOML block.

## Crates

| Crate | What it is |
|---|---|
| `starling-proto` | Upstream `Mumble.proto`, **frozen**: framing, message ids, version encodings |
| `starling-proto-fancy` | One envelope per service (types 1000+), and the inter-service gRPC contracts |
| `starling-gate` | What a peer is allowed to be given, by announced Fancy version |
| `starling-crypto` | Voice ciphers, TLS identity, suite negotiation |
| `starling-runtime` | The one common crate: config, serving, health, drain, telemetry, storage, the client plane |
| `starling-gateway` | The only component that holds a client's socket |
| `crates/services/*` | Twenty services, one per row of `docs/ARCHITECTURE.md` §4 |
| `starling-directory` | Outbound only: the hourly announcement to the public Mumble server list |
| `starling-operator-api` | The admin plane: REST + OpenAPI, pluggable auth, fail-closed audit |
| `starling-migrate` | murmur `.ini` → `starling.toml` |
| `starling` | One image, one entrypoint: a service name, or `--all-in-one` |

## Services and tiers

`tier` is not documentation — the gateway reads it and behaves accordingly.

| Tier | Services | Down means |
|---|---|---|
| **essential** | session-lifecycle, session-view, permissions, metadata, userdata, server-config | reject logins |
| **core** | voice, text, pchat, moderation | that feature is dead; the server runs |
| **optional** | screenshare, files, plugins, push, audit, onboarding, social, link-preview, context-actions, directory, operator-api | nobody notices |

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
scripts/check-proto-drift.sh
```

Lint configuration is deliberately mirrored from `vendor/client` and
`vendor/server/3rdparty/mumble-plugin-host`; keep the three in sync.
