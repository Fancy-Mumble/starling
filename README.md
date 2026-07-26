# Starling

A pure-Rust Mumble server — the replacement for `vendor/server` (C++/Qt murmur,
Fancy fork).

> Starlings fly in *murmurations*. The name stays in the Mumble/Murmur family,
> describes what the server does (coordinate a flock of voices into one motion),
> and is unique enough to grep for.

Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — a gateway in front,
independent gRPC services behind it, and media planes that bypass the gateway
entirely. Wire compatibility: [`docs/PROTOCOL-COMPATIBILITY.md`](docs/PROTOCOL-COMPATIBILITY.md).
Config: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).
Storage: [`docs/STORAGE.md`](docs/STORAGE.md).
Diagrams: [`docs/diagrams/`](docs/diagrams/).

> **The architecture in those documents is not what the code does.** The tree
> still holds the earlier in-process microkernel — `starling-bus`, `starling-api`
> and the `services/state` actor. Voice works there and is tested; everything
> else is being redesigned around the documents above.

**Status: Phase 0 (MVP).** Establishes sessions with the real FancyMumble
client, pushes the channel tree, and relays chat. No voice, no persistence, no
ACL evaluation yet. See [`PORTING-PLAN.md`](PORTING-PLAN.md) for the full plan
and phase gates, and [`DESIGN.md`](DESIGN.md) for the rules every change follows.

## Quick start

```sh
cargo run --bin starling -- --config starling.toml
```

With no `--config`, built-in defaults are used and a self-signed certificate is
generated in `starling-data/` on first boot. Copy
[`starling.example.toml`](starling.example.toml) to get started, or convert an
existing murmur config:

```sh
cargo run --bin starling -- migrate-config /path/to/mumble-server.ini > starling.toml
```

Legacy `.ini` files also load directly (`--config server.ini`), detected by
extension. Every key murmur honours that Starling does not implement yet is
reported at startup with the phase that will implement it — nothing is silently
dropped.

## Layout

| Crate | What it is |
|---|---|
| `starling-proto` | Wire only: prost types, TCP framing, version encodings. No I/O, no state. |
| `starling-log` | Server event log: structured records, pluggable sinks, non-blocking dispatch. |
| `starling-model` | Channel tree, users, permissions. Pure logic behind Repository traits. |
| `starling-server` | The server: state actor, dispatcher, handlers, TLS listener, security negotiation. |
| `starling` | The binary: config, CLI, certificate bootstrap. The only place concrete types are named. |

## Architecture in one picture

```text
  TCP conn 1 ──read task──┐                    ┌── write task ── socket
  TCP conn N ──read task──┤                    └── write task ── socket
                          ▼                          ▲
                   ┌──────────────┐                  │ Bytes (encoded once,
                   │  ServerCore  │──── Outbound ────┘  cloned per recipient)
                   │   (1 task)   │
                   │  ServerState │──── Dispatcher ──► Handler per message
                   └──────────────┘
```

One task serialises every mutation; connections reach it only by sending
`Command`s. No locks around server state means no lock ordering to get wrong and
no re-entrancy hazard — the failure mode that makes murmur's
`qrwlUsers`/`qrwlVoiceThread` pair delicate. Handlers are pure
`fn(&mut ServerState, …) -> Effects`, so they test in microseconds without a
socket, a runtime or a database.

## Security

Stock Mumble clients get exactly what murmur gives them. Clients that announce a
Fancy version are held to modern primitives, chosen per peer by an Abstract
Factory over what the peer announced:

| Suite | TLS | Voice cipher | Who gets it |
|---|---|---|---|
| `LegacySuite` | 1.2+ | OCB2-AES128 | every stock Mumble client |
| `FancySuite` | 1.3 | `ChaCha20-Poly1305` | clients announcing a Fancy version |

`ModernOnly` is available for deployments that control their client fleet and
would rather refuse a legacy client than carry OCB2 — and it refuses explicitly,
never by silent downgrade. See `starling_server::security` and
`PORTING-PLAN.md` §2.4.

## Logging

Operator-facing records — who connected, what was refused, what an administrator
changed — are separate from `tracing`'s developer diagnostics and live in
`starling-log`. Where they go is a strategy:

```text
  Logger  ──(bounded queue)──►  writer thread  ──►  dyn LogSink
 (never blocks)                                       ├── ConsoleSink
                                                      ├── FileSink (size rotation)
                                                      ├── MemorySink (ring, for the admin API)
                                                      ├── FanoutSink ── [ … ]   (Composite)
                                                      ├── FilterSink ── sink    (Decorator)
                                                      └── NullSink              (Null Object)
```

They compose, so "everything to a file, warnings also to the console" is two
config entries rather than a special mode — see `[logging]` in
[`starling.example.toml`](starling.example.toml). Sending the log somewhere new
(a database, syslog, an HTTP endpoint) is a new `LogSink` implementation; nothing
else in the server changes.

Two guarantees, both tested:

* **`Logger::log` never blocks.** The writer is a dedicated OS thread, not an
  async task — logging must keep working while the runtime is saturated, which is
  exactly when the records matter most.
* **Overflow is counted and reported, never silent.** A log that quietly loses
  records is worse than no log, because it is trusted. Buffers are also flushed
  periodically, so a `SIGKILL` costs at most half a second of records rather than
  everything since the last buffer fill.

Handlers emit records as `Effect::Log`, so they stay pure and a test can assert
on what was logged without installing a sink.

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

CI enforces all of the above plus Miri and a fuzz run of the frame decoder
(`.github/workflows/ci.yml`). Lint configuration is deliberately mirrored from
`vendor/client` and `vendor/server/3rdparty/mumble-plugin-host`; keep the three
in sync.
