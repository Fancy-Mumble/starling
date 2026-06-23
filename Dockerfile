# syntax=docker/dockerfile:1

# One image, one entrypoint (docs/ARCHITECTURE.md §9).
#
# The entrypoint takes a service name, so compose runs `command: ["text"]` and
# Kubernetes runs `args: ["text"]`. Twenty-one Dockerfiles would be twenty-one
# things to keep in sync, and it would make `--all-in-one` a separate build
# rather than a matter of arguments.

# Must match rust-toolchain.toml. It is an ARG rather than a literal so the pin
# is moved in one place when the toolchain moves.
ARG RUST_VERSION=1.95

FROM rust:${RUST_VERSION}-bookworm AS builder

# prost-build 0.14 shells out to `protoc` rather than bundling one — the same
# package .github/workflows/ci.yml installs for the Linux job.
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# `--locked`: the image is built from Cargo.lock, so an image rebuilt in six
# months is the dependency tree this one was reviewed against rather than
# whatever resolves that day.
#
# The release profile is lto = "thin" with codegen-units = 1, so the first
# build is slow. Both cache mounts survive it; a rebuild after a source change
# is minutes rather than the whole thing again. The binary is copied out of the
# target cache inside the same layer, because a cache mount is not part of the
# image.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin starling \
 && cp /src/target/release/starling /usr/local/bin/starling

FROM debian:bookworm-slim AS runtime

# ca-certificates: link-preview fetches URLs, and a container with no trust
# store fails that in a way that looks like the remote host being down.
#
# bash is already present (Debian Essential) and is load-bearing for the
# compose healthchecks: this build serves no HTTP /healthz to curl — health is
# an in-process readiness gate, not an endpoint — so the only honest liveness
# probe from outside is a TCP connect, which bash does with /dev/tcp and dash
# cannot do at all.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --home-dir /var/lib/starling starling

COPY --from=builder /usr/local/bin/starling /usr/local/bin/starling

# Generated certificates and the per-service SQLite files live here, and this
# is expected to be a volume. Mumble clients identify a server by certificate
# fingerprint, so losing the pair on every restart is a security warning for
# every client that has connected before.
USER starling
WORKDIR /var/lib/starling

# Documentation, not publication — compose decides what is actually reachable.
#   64738/tcp  gateway, control plane, TLS terminates there
#   64738/udp  voice, its own socket; audio never touches the gateway
#   50051/tcp  this service's gRPC surface, internal to the network
#   8080/tcp   the files service's HTTP listener
#   8081/tcp   operator-api's REST surface, off unless asked for
EXPOSE 64738/tcp 64738/udp 50051/tcp 8080/tcp 8081/tcp

ENTRYPOINT ["starling"]
# A container run with no arguments is the single-box deployment: every
# service in one process, over in-memory transports.
CMD ["--all-in-one"]
