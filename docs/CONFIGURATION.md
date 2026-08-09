# Configuration

Start from [`starling.example.toml`](../starling.example.toml). It is the file
somebody running a server for their friends actually edits: the name, the port,
how many people may join, the password, the chat and audio limits. Everything
below it is a knob you should not need, and lives in
[`examples/advanced/`](../examples/README.md).
[`examples/reference.toml`](../examples/reference.toml) lists every key that
exists, with its default and a sentence on what it does.

Configuration comes from three places, each overlaying the one before:

| | Where it lives | |
|---|---|---|
| Defaults | compiled into the binary | which is why `starling --all-in-one` with no file is a working server |
| A file | wherever `--config` points | may `include` others |
| Environment | `STARLING_*` | applied last, so it wins |

### The file `--all-in-one` finds on its own

Without `--config`, `--all-in-one` reads this platform's own configuration
directory, and writes a starter file there the first time it runs — along with
creating the SuperUser and printing its password, which is what makes a
downloaded `.deb` or `.exe` a server without a manual first.

| | |
|---|---|
| Linux, BSD | `$XDG_CONFIG_HOME/starling/starling.toml`, else `~/.config/starling/starling.toml` |
| macOS | `~/Library/Application Support/Starling/starling.toml` |
| Windows | `%APPDATA%\Starling\starling.toml` |

Three things that file is not. It is not written when `--config` was passed —
a path that names nothing is a typo, and reported as one. It is not written in a
directory that already holds a `starling-data/`, which keeps the built-in
defaults it has always had, so an existing deployment is never moved. And it is
never rewritten: from the moment it exists it is yours, and a later start reads
it and leaves it alone.

Only `--all-in-one` does this. A single service (`starling text`) is the
Kubernetes shape, which is always given a `--config`, and bringing a
configuration into existence as a side effect of starting one pod of twenty-one
would be a surprise in the worst possible place.

[`deploy/starling.toml`](../deploy/starling.toml) is not part of that chain for
anyone but `docker-compose.yml`, which mounts it into each container. It is not
shipped inside the executable, and it names endpoints because its services are
in separate containers where the built-in Unix sockets cannot be reached.

## A file names what it changes

A configuration file is an **overlay on the built-in defaults**, not a
replacement for them. What it does not mention keeps its built-in value, so this
is a complete, working server:

```toml
[[instances]]
name = "Frog Pond"
port = 64738

[instances.settings]
max_users = 20
password  = "hunter2"
```

The whole service map -- endpoints, tiers, routes, rate-limit buckets -- comes
from the defaults, which is where the routing table lives. It used to live in
code *and* in every shipped file, and the copies drifted: `UserState` moved to
`session-lifecycle` in code, the files went on naming `userdata`, and self-mute
worked under `--all-in-one` and did nothing in the container deployment.

Two consequences worth knowing:

* **A value replaces, it does not merge, arrays included.** A `types` list is
  the whole list; `[[instances]]` means *these* instances.
* **Omitting a service no longer switches it off.** Say `enabled = false`.
  (`operator-api` is the exception, and deliberately so: it has no built-in
  entry at all, so a file that never mentions the admin plane does not run it.)

Unknown keys are refused at startup, so a typo fails loudly instead of quietly
leaving a limit at its default.

## Splitting it across files

```toml
include = ["conf.d", "examples/advanced/logging.toml"]
```

A path is resolved against the directory of the file naming it; a directory
means every `*.toml` directly inside it, in name order. Includes are merged in
the order listed and **the including file is applied last**, so the file you are
editing wins over what it pulls in. Includes may nest; a file reached twice is
refused rather than merged twice, because the second visit is either a cycle or
an ambiguity about which copy wins.

## Two layers, and one file that writes to both

murmur keeps deployment and operational settings together in one `Config` table.
Starling splits them, because they have different lifetimes:

| | **Deployment** | **Operational (the `server-config` service)** |
|---|---|---|
| Examples | endpoints, listen ports, TLS paths, storage URLs, tiers, routes | `max_users`, `welcome_text`, `password`, `max_bandwidth`, `message_limit`, `allow_html`, `cert_required`, `allow_ping`, `registry_*` |
| Written in | the file, at any level | `[instances.settings]`, or the admin UI |
| Changed by | editing the file | an operator, at runtime, like murmur |
| Takes effect | on restart | immediately, republished to subscribers |
| Scope | the process | per server instance |

Anything that needs a restart anyway is read once at startup and injected at
construction: no late-subscriber problem and no service to be down. Anything an
operator expects to change live belongs to `server-config`, which is an
**essential** service for exactly that reason: the gateway cannot rate-limit
without `message_limit`, so a cold start without it rejects logins rather than
quietly serving on defaults nobody chose.

The file can still state what those settings *start* as, under
`[instances.settings]`, because the first question anybody setting up a
server asks is how to let twenty friends in and put a password on it, and that
had no answer that looked like configuration.

### Which wins

Three layers, in order of how deliberate the statement is:

1. murmur's defaults, for a server nobody has configured;
2. `[instances.settings]`, the operator's starting values;
3. whatever an operator has since changed at run time, which wins.

The third layer is stored **with the list of fields it covers**, not as a whole
snapshot, so a setting nobody has touched keeps following the file. Change
`welcome_text` in the admin UI, and editing `max_users` in the file still works.
A row written before this was recorded keeps all of its settings, so an upgrade
changes nothing.

## Environment variables

Every key has one, so a Kubernetes `ConfigMap` needs no templating and
`docker compose` needs no mount: `[services.text] endpoint` becomes
`STARLING_SERVICES_TEXT_ENDPOINT`, uppercase, dots and dashes to underscores,
`STARLING_` prefix. They are applied after the files, so they win.

---

## The gateway

```toml
[gateway]
listen_tcp       = "0.0.0.0:64738"   # control plane; TLS terminates here
control_queue    = 4096              # per client. Full -> disconnect that client
default_deadline = "5s"              # per gRPC call unless a route overrides it

[gateway.tls]
cert = "/etc/starling/tls/cert.pem"
key  = "/etc/starling/tls/key.pem"
# Omit both and a self-signed pair is generated on first boot.

[gateway.limits]
# Per route, never one shared bucket; a throttled message here is reported,
# never dropped in silence.
control   = { rate = "1/s",  burst = 5  }   # matches murmur for legacy clients
signalling = { rate = "10/s", burst = 20 }  # WebRTC bursts on share start
plugin    = { rate = "4/s",  burst = 15 }   # murmur's own plugin bucket
```

## The admin plane

`operator-api` is plain HTTP with an OpenAPI description, so an admin client is
trivial in any language and authentication is whatever you already run. Off unless
configured, and localhost-bound when it is.

```toml
[services.operator-api]
enabled = false                    # off by default, on purpose
listen  = "127.0.0.1:8081"         # never 0.0.0.0 without meaning it
tier    = "optional"
```

### Auth is a strategy, chosen here

```toml
[services.operator-api.auth]
mode = "oidc"                      # oidc | jwt | mtls | token
```

**`oidc`**, for Keycloak, Authentik, Auth0, Entra. The JWKS is discovered from
the issuer and cached, so key rotation needs no restart.

```toml
[services.operator-api.auth.oidc]
issuer      = "https://keycloak.example.org/realms/starling"
audience    = "starling-admin"
scope_claim = "roles"              # which claim carries authorisation

# An existing IdP role becomes a Starling authorisation, without code.
[services.operator-api.auth.oidc.map]
"starling-admin"   = ["*"]
"starling-auditor" = ["userdata:read", "audit:read"]
"backup-job"       = ["userdata:read", "metadata:read"]
```

**`jwt`**, a bare token you sign yourself, for setups with no IdP.

```toml
[services.operator-api.auth.jwt]
public_key  = "/etc/starling/operator/jwt.pub"
audience    = "starling-admin"
scope_claim = "scopes"
```

**`mtls`**, client certificates, when a PKI already exists. Scopes come from the
certificate subject.

```toml
[services.operator-api.auth.mtls]
client_ca = "/etc/starling/operator/ca.pem"
[services.operator-api.auth.mtls.map]
"CN=admin-console" = ["*"]
```

**`token`**, a static bearer token, for a script or a one-box install. The
weakest option: no identity, no expiry. It exists so nobody reinvents `icesecret`
badly, not because it is recommended.

```toml
[services.operator-api.auth.token]
tokens = [{ value_env = "STARLING_ADMIN_TOKEN", scopes = ["*"] }]
```

### The live channel

`GET /v1/events` is a WebSocket carrying what changed as it changes, users
connecting and moving, channels being created and edited, messages as they are
delivered, and context-menu entries being chosen. It needs no configuration and
works through any reverse proxy.

The same channel is available over **WebTransport (HTTP/3)**, and that one does
need configuring, because a reverse proxy generally *cannot* forward it,
WebTransport is Extended CONNECT over HTTP/3, and terminating it means
terminating QUIC.

```toml
[services.operator-api.webtransport]
enabled = false                    # off unless the deployment terminates QUIC
listen  = "0.0.0.0:8443"           # UDP, and a different socket from `listen`
cert    = "/etc/starling/wt/cert.pem"
key     = "/etc/starling/wt/key.pem"
```

**The certificate is not optional in practice.** Every other surface here can
sit behind a proxy holding the certificate; this listener is the one the proxy
is not terminating, so it presents its own. A self-signed pair is generated on
first boot if `cert` and `key` are absent, which a browser will refuse, that
default exists so a first boot starts, not so a deployment ships on it.

**One UDP port serves every endpoint, not every service.** A WebTransport
session is addressed by `:path`, so more endpoints here cost no more ports. Two
*independent* services each need their own UDP port, fronted by a QUIC-aware
proxy or advertised with `Alt-Svc`.

### Audit is fail-closed

```toml
[services.operator-api.audit]
path        = "/var/log/starling/operator-audit.log"
fail_closed = true                 # cannot record it -> it does not happen
```

`operator-api` writes this record itself rather than calling the `audit` service,
because audit is optional and the highest-privilege plane must not depend on a
service the operator may not be running.

## A service

You write a block only for a service you are changing; every service already has
one. They all take the same keys. `types` is the outer message type, one set per
service; a service's own message types live in its nested envelope, which the
gateway never looks inside.

```toml
[services.text]
endpoint = "http://text:50051"       # or "unix:/run/starling/text.sock"
tier     = "core"                    # essential | core | optional
types    = [1005]

[services.pchat]
endpoint = "unix:/run/starling/pchat.sock"
tier     = "core"
types    = [1006]

[services.voice]
endpoint   = "http://voice:50051"
tier       = "core"
types      = [1, 19, 1004]           # UDPTunnel, VoiceTarget, Fancy envelope
udp_listen = "0.0.0.0:64738"         # voice's OWN socket - audio skips the gateway

[services.screenshare]
endpoint = "http://screenshare:50051"
tier     = "optional"
types    = [1008]
limits   = "signalling"              # not the 1/s control bucket

[services.files]
endpoint   = "http://files:50051"
tier       = "optional"
types      = [1009]
listen     = "0.0.0.0:8080"          # its own HTTP listener
public_url = "https://files.example.org"   # what signed URLs point at
url_ttl    = "15m"
max_upload = "512MiB"
```

### Endpoints

`endpoint` says where a service is reached, and it is the only key that changes
between one VPS and twenty-four pods.

| Written | Means |
|---|---|
| `http://text:50051` | across hosts; Kubernetes DNS fills the name in |
| `unix:/run/starling/text.sock` | co-located, and file permissions are the auth |
| `pipe:starling/text` | the same on Windows, where the pipe's ACL is the auth |
| `inproc:text` | in-process, under `--all-in-one` |

A bare `host:port` is refused rather than assumed to be TCP: assuming it would
make `unix` a typo away from silently opening a TCP socket on a host that
expected a permission boundary.

The co-located form is the platform's own, and **only one of the two exists in a
given build**, a Unix socket cannot be served on Windows, and a named pipe
cannot be served anywhere else. An endpoint naming the other one is a startup
error rather than a substitution, so a configuration file carried between
platforms says so instead of quietly binding a different kind of boundary than
it asked for. A deployment meant to run on both should use `http://` for the
services it shares, or let `--all-in-one` and the built-in defaults pick.

With no `--config` file at all, every service is given the local form for
whichever platform it is running on, under the run directory, so a first boot
needs no port allocated for anything but the gateway.

> On Windows, `\\.\pipe\` is one flat namespace for the whole machine with no
> directories and no working directory, so the run directory is folded into each
> pipe's name to keep two servers apart. That name is capped at 256 characters
> by the OS; a very deeply nested data directory is reported at startup as the
> length problem it is, and the fix is a shorter one.

### Adding a service

Three lines, no gateway release:

```toml
[services.whiteboard]
endpoint = "http://whiteboard:50051"
tier     = "optional"
types    = [1018]
```

The gateway routes on the outer type and forwards the payload verbatim, so it
needs no generated stubs for the new service and no knowledge of its schema.

### The one service with no endpoint

`directory` announces this server to the public Mumble list. Nothing dials it, so
it has no `endpoint` and no gRPC surface, and the only line it needs here is
where to find a trust store:

```toml
[services.directory.options]
# The public list's certificate is verified against this bundle. A missing one
# fails the announcement rather than posting unverified, the payload carries a
# shared secret.
trust_store = "/etc/ssl/certs/ca-certificates.crt"
```

**Everything that decides *whether* it announces is operational**, because
murmur lets an operator change it while the server runs. Set it in the admin UI,
or state the starting value in `[instances.settings]`:

| Setting | murmur | Meaning |
|---|---|---|
| `registry_name` | `registerName` | the name to be listed under; empty means do not register |
| `registry_password` | `registerPassword` | the secret that authenticates later updates |
| `registry_url` | `registerUrl` | the web page the listing links to; required |
| `registry_hostname` | `registerHostname` | the DNS name to be reached at; empty means "whatever address this arrived from" |
| `registry_location` | `registerLocation` | free text, omitted when empty |
| `allow_ping` | `allowping` | answer unauthenticated UDP pings; **required to register** |

Two of those rules surprise people, and both are murmur's rather than ours: a
server with a `password` set is **never** listed, and `allow_ping = false` also
prevents registration, a listing the list cannot measure is a dead entry. When a
server is not being announced, the reason is logged once per interval, naming the
specific condition rather than "missing required fields".

## Storage, per service

Each service owns its own schema, no service reads another's tables.

```toml
[services.pchat.storage]
url             = "postgres://starling:@db/starling_pchat"
max_connections = 16

[services.userdata.storage]
url = "sqlite:///var/lib/starling/userdata.db"
```

In-memory SQLite is capped to one connection automatically: five connections to
`:memory:` are five different databases.

## Observability

```toml
[telemetry]
otlp_endpoint = "http://otel-collector:4317"
metrics       = "0.0.0.0:9090"
log_format    = "json"               # json | text
```

## All-in-one

```toml
[runtime]
all_in_one = true
```

Every service runs in one process with in-process calls instead of gRPC. Same
binary, same config file, `endpoint` values are ignored. This is the mode for a
single VPS; the multi-process mode is for isolation or per-service scaling.

## Server instances

```toml
[[instances]]
id   = 1
name = "Main"
port = 64738

[instances.settings]
max_users = 20
password  = "hunter2"

[[instances]]
id   = 2
name = "Staging"
port = 64739
```

Metadata runs one actor per server instance, sharded by id, the Discord
guild-process pattern. Port numbers follow murmur's convention of
`base_port + server_id`.

`settings` is the operational half, per server; see
[Two layers](#two-layers-and-one-file-that-writes-to-both) above.

### `port` is the port, singular

With **one** server instance, its `port` is what the gateway listens on and what
voice binds its UDP socket to, because to a client those are one port on two
protocols. It reached neither before: the gateway bound `[gateway] listen_tcp`
and voice bound its own `udp_listen`, so moving a server off 64738 in the
obvious place left it answering on 64738, and the two keys that would have moved
it are in blocks an operator otherwise never opens.

Saying either of those explicitly still wins, which is how you bind to loopback
or put the two on different ports. With **several** server instances nothing is
derived: they share one gateway listener, so picking one of their ports for it
would be arbitrary, and those deployments state `listen_tcp` themselves.
