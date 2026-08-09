# Starling on Kubernetes

The shape `docs/ARCHITECTURE.md` §9 describes: one image whose entrypoint takes
a service name, a gateway in front, and the media planes bypassing it entirely.

```sh
helm install starling ./deploy/helm/starling
```

That gives you twenty StatefulSets, twenty-two Services, and one LoadBalancer
on 64738 carrying TCP to the gateway and UDP to voice. To try it on a laptop
cluster instead:

```sh
helm install starling ./deploy/helm/starling --set mode=all-in-one
```

which is one pod running every service over in-memory transports. Same image,
same routing table, one value between them.

## Two modes

| | `services` (default) | `all-in-one` |
|---|---|---|
| Pods | one per service, twenty of them | one |
| Calls between services | gRPC over TCP | in-process |
| Volumes | one per service | one |
| `endpoint` in the config | `http://<svc>.<ns>.svc:50051` | `inproc:<name>` |
| Scaling one service | yes | no |

The routing table in `values.yaml` is read by both. Moving between them changes
no service's configuration, only how the calls travel.

## What is awkward about this, and why

Three things do not follow from a normal chart. All three are properties of
Mumble or of the runtime, not choices this chart made freely.

### 1. The gateway cannot use an Ingress, and voice makes it worse

`Ingress` is HTTP-only; Mumble's control plane is raw TCP+TLS. So the gateway
needs `Service type=LoadBalancer` (or Gateway API `TCPRoute`). That is also why
the front component is called the gateway and not the ingress: naming it after
a resource it can never use is a trap.

Voice is harder. **A legacy Mumble client sends UDP to the same host:port it
made TCP to**, and the protocol has no field to tell it otherwise. So voice has
to answer at the gateway's address.

The chart's default is the sidecar option §9 names: `voice.colocateWithGateway`
puts voice in the gateway's pod, so one Service carries TCP 64738 to one
container and UDP 64738 to the other. Your load balancer must accept both
protocols on one Service - Kubernetes 1.24+, GA in 1.26.

Two consequences worth knowing before you scale:

* the colocated voice container binds gRPC on **50052**, not 50051. Containers
  in one pod share a network namespace, so it and the gateway cannot both have
  the usual port.
* `gateway.replicas > 1` needs `sessionAffinity: ClientIP` (the default here)
  so a client's UDP lands on the pod its TCP did. It also needs
  `gateway.tls.existingSecret`; see below.

Set `voice.colocateWithGateway=false` for voice's own workload and its own UDP
Service. Only Fancy clients can follow that, through
`services.voice.publicUrl`; every other client will tunnel audio over TCP.

### 2. `endpoint` is what a service binds, not just what others dial

`endpoint` answers both halves of the same question: where others dial a
service, and where it listens. That is one address per service, which is the
right default - a deployment cannot then say two things about where a service
is - and it does not survive contact with Kubernetes. `endpoint` has to name a
Service for anything to reach it, and a Service resolves to a ClusterIP, a
virtual address belonging to no interface. A pod that tried to bind it would
die at startup:

```
ERROR service failed  error=binding starling-text.default.svc:50051:
                            failed to lookup address information
```

`bind` is the other half of the pair, and each workload sets its own:

```yaml
env:
  - name: STARLING_SERVICES_TEXT_BIND
    value: "http://0.0.0.0:50051"
```

The name every *other* service dials is left alone, so nothing has to agree
with a value only one pod can see. This is generated for you; it is documented
here because it looks redundant in the manifests and is not.

The same fact is why `all-in-one` mode renders `inproc:` endpoints rather than
HTTP ones. A service resolves its own address before it has registered with the
in-process broker, so the short-circuit that makes a co-located call in-process
cannot apply to its own listener: `endpoint` is bound in all-in-one too, and
HTTP endpoints naming Services that mode never creates would take down every
service that has one.

### 3. Readiness means "listening", not "warm"

Every probe here is a TCP connect. That is weaker than it looks, and knowingly
so.

The runtime's real readiness is a per-service in-process gate that fails while
caches warm - exactly the distinction that matters, since a restarted voice
service is alive immediately but routes audio nowhere until it has re-subscribed
to `session-view`. It is served over gRPC, and it is `starling.health.v1.Health`.
Kubernetes' native `grpc:` probe speaks `grpc.health.v1.Health`, so **it cannot
read it**. Until the runtime also registers the standard service, a TCP connect
is the honest probe available from outside, and this chart does not pretend
otherwise.

Two exceptions:

* **the gateway** is probed on its gRPC port, never on 64738. A bare TCP
  connect to the client port is an unfinished TLS handshake, which the gateway
  records in the operator's security log - and a probe every few seconds
  forever would fill it with a peer the operator cannot identify and did not
  cause. `all-in-one` has no gRPC port to use instead, so it probes 64738
  rarely rather than often.
* **`directory`** has no probe at all. It has no listener: nothing dials it, it
  dials the public server list hourly. A TCP probe would fail forever.

## The certificate

Mumble clients identify a server by **certificate fingerprint**. Leave
`gateway.tls.existingSecret` empty and the gateway generates a self-signed pair
into its volume on first boot, as murmur does - fine for one replica, and the
reason the volume must survive a restart. A regenerated pair looks to every
client that has connected before exactly like a man-in-the-middle.

Two combinations the chart refuses to render rather than let you discover:

* **more than one gateway replica** without a shared certificate. Each pod
  would generate its own, so a client would get a different identity per
  connection.
* **`services.directory.enabled`** without one, in `services` mode. `directory`
  publishes the fingerprint of the certificate clients are shown and reads it
  from disk; in a different pod from the gateway, a self-signed pair generated
  into the gateway's own volume is not visible to it. The announcement would be
  skipped once an hour with a log line as the only sign.

```sh
kubectl create secret tls starling-tls --cert=cert.pem --key=key.pem
helm upgrade starling ./deploy/helm/starling --set gateway.tls.existingSecret=starling-tls
```

cert-manager produces the same shape.

## Storage

Every service writes a SQLite file named after itself under `runtime.dataDir`
and reads no other service's tables, so each workload gets **its own** volume
rather than sharing one - twenty small claims, not one RWX claim that most
clusters cannot provide anyway.

StatefulSets rather than Deployments for the same reason: a Deployment rolling
onto a ReadWriteOnce claim starts the replacement pod before the old one
releases the volume, and wedges.

Point an individual service at a real database when it outgrows a file:

```yaml
services:
  pchat:
    storage:
      url: postgres://starling:secret@db/starling_pchat
      maxConnections: 16
```

A service with a `storage.url` gets no volume.

## The admin plane

Off by default, and this chart will not give it a LoadBalancer: it wants the
opposite exposure to the gateway's.

```sh
kubectl create secret generic starling-admin --from-literal=token="$(openssl rand -hex 32)"
helm upgrade starling ./deploy/helm/starling \
  --set operatorApi.enabled=true \
  --set operatorApi.auth.token.existingSecret=starling-admin
```

Prefer `existingSecret` over `operatorApi.auth.token.value`: a value passed to
Helm is stored in the release and comes back out of `helm get values`, which is
not where the highest-privilege credential in the system should be readable
from.

`auth.mode` also takes `oidc`, `jwt` and `mtls`; those need their own config,
which goes in `extraToml` for now.

## Operational settings are not in here

`values.yaml` is the **deployment** layer only. Bandwidth, message limits, user
count, welcome text, `certrequired`, the public-list credentials - all of that
belongs to the `server-config` service, is changed by an operator at runtime,
and takes effect immediately. Putting it here would make a restart the way to
change it. See `docs/CONFIGURATION.md`.

## Adding a service

Three lines, no gateway release, no chart release:

```yaml
services:
  whiteboard:
    enabled: true
    tier: optional
    types: [1018]
```

You get a StatefulSet, a Service, its entry in the routing table and its bind
override. The gateway routes on the outer type and forwards the payload
verbatim, so it needs no stubs and no knowledge of the schema.

## Common values

| Value | Default | |
|---|---|---|
| `mode` | `services` | or `all-in-one` |
| `image.tag` | `.Chart.AppVersion` | pin to `sha-<short>` for immutability |
| `gateway.service.type` | `LoadBalancer` | `NodePort` and `ClusterIP` also work |
| `gateway.service.port` | `64738` | TCP and the UDP voice socket both follow it |
| `gateway.replicas` | `1` | >1 needs `gateway.tls.existingSecret` |
| `voice.colocateWithGateway` | `true` | false breaks legacy clients' UDP |
| `persistence.size` | `1Gi` | per service in `services` mode |
| `services.<n>.enabled` | `true` | `directory` is the one default-off |
| `operatorApi.enabled` | `false` | |
| `podDisruptionBudget.enabled` | `false` | only useful once a tier runs >1 replica |

## Checking it before installing

```sh
helm lint deploy/helm/starling
helm template starling deploy/helm/starling | kubeconform -strict -kubernetes-version 1.29.0

# The generated config, against the real parser - unknown keys are rejected at
# startup, so this catches a typo the templates cannot:
helm template starling deploy/helm/starling \
  | yq 'select(.kind == "ConfigMap") | .data["starling.toml"]' \
  > /tmp/starling.toml
STARLING_SERVICES_TEXT_BIND=http://0.0.0.0:50051 \
  starling text --config /tmp/starling.toml
```

This chart needs a build with `services.<name>.bind` wired up. It is declared
in older builds and read by none of them, so against an image predating that
every pod will try to bind its ClusterIP and fail to start.

## Not covered

* **Autoscaling.** No HPA. gRPC holds one long-lived HTTP/2 connection per
  caller, so a second replica of a service takes no share of existing traffic
  without a mesh or a proxy that load-balances requests rather than connections.
  Scaling the gateway works, because clients arrive as new connections.
* **A ServiceMonitor.** `telemetry.metrics` binds no listener in this build, so
  there is nothing to scrape yet.
* **NetworkPolicy.** Worth having - only the gateway and files need to be
  reachable from outside their namespace - and not written here.
* **Gateway API `TCPRoute`,** the other answer to the Ingress problem.
