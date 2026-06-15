# Configuration

## Two layers, and this file is only one of them

murmur keeps deployment and operational settings together in one `Config` table.
Starling splits them, because they have different lifetimes:

| | **Deployment — this file** | **Operational — the `server-config` service** |
|---|---|---|
| Examples | endpoints, listen ports, TLS paths, storage URLs, tiers, routes | `bandwidth`, `messagelimit`, `users`, `welcometext`, `allowhtml`, `channelnestinglimit`, `imagemessagelength`, `certrequired` |
| Changed by | editing this file | an operator, at runtime, like murmur |
| Takes effect | on restart | immediately, republished to subscribers |
| Scope | the process | per virtual server |

Anything that needs a restart anyway belongs here, so it is read once at startup
and injected at construction — no late-subscriber problem and no service to be
down. Anything an operator expects to change live belongs to `server-config`,
which is an **essential** service for exactly that reason: the gateway cannot
rate-limit without `messagelimit`, so a cold start without it rejects logins
rather than quietly serving on defaults nobody chose.

Every key below is overridable by environment variable, so a Kubernetes ConfigMap
works without templating and `docker compose` works without a mount. The rule:
`[services.text] endpoint` becomes `STARLING_SERVICES_TEXT_ENDPOINT` — uppercase,
dots and dashes to underscores, `STARLING_` prefix.

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
# Omit both and a self-signed pair is generated on first boot, as murmur does.

[gateway.limits]
# Per route, never one shared bucket. murmur's single 1 msg/s bucket silently
# ate SDP offers; a throttled message here is reported, never dropped in silence.
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

**`oidc`** — for Keycloak, Authentik, Auth0, Entra. The JWKS is discovered from
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

**`jwt`** — a bare token you sign yourself, for setups with no IdP.

```toml
[services.operator-api.auth.jwt]
public_key  = "/etc/starling/operator/jwt.pub"
audience    = "starling-admin"
scope_claim = "scopes"
```

**`mtls`** — client certificates, when a PKI already exists. Scopes come from the
certificate subject.

```toml
[services.operator-api.auth.mtls]
client_ca = "/etc/starling/operator/ca.pem"
[services.operator-api.auth.mtls.map]
"CN=admin-console" = ["*"]
```

**`token`** — a static bearer token, for a script or a one-box install. The
weakest option: no identity, no expiry. It exists so nobody reinvents `icesecret`
badly, not because it is recommended.

```toml
[services.operator-api.auth.token]
tokens = [{ value_env = "STARLING_ADMIN_TOKEN", scopes = ["*"] }]
```

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

Every service block takes the same keys. `types` is the outer message type from
`PROTOCOL-COMPATIBILITY.md` §3 — one number per service, because the service's own
message types live in its nested envelope and the gateway never looks inside.

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

## Storage, per service

Each service owns its own schema — no service reads another's tables.

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
binary, same config file — `endpoint` values are ignored. This is the mode for a
single VPS; the multi-process mode is for isolation or per-service scaling.

## Virtual servers

```toml
[[virtual_servers]]
id   = 1
name = "Main"
port = 64738

[[virtual_servers]]
id   = 2
name = "Staging"
port = 64739
```

Metadata runs one actor per virtual server, sharded by id — the Discord
guild-process pattern. Port numbers follow murmur's convention of
`base_port + server_id`.
