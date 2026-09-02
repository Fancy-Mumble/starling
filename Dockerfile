# syntax=docker/dockerfile:1

# One image, one entrypoint. It takes a service name, so compose runs
# `command: ["text"]` and Kubernetes runs `args: ["text"]`, and `--all-in-one`
# is a matter of arguments rather than a separate build.

# Must match rust-toolchain.toml. It is an ARG rather than a literal so the pin
# is moved in one place when the toolchain moves.
ARG RUST_VERSION=1.95

FROM rust:${RUST_VERSION}-bookworm AS builder

# prost-build shells out to `protoc` rather than bundling one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# `--locked` builds from Cargo.lock, so a rebuild months later is the same
# dependency tree. The release profile is thin-LTO, so the first build is slow;
# the cache mounts make a rebuild after a source change minutes instead. The
# binary is copied out within the same layer, since a cache mount is not part of
# the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --bin starling \
        -p mumble-friends -p mumble-live-doc \
 && cp /src/target/release/starling /usr/local/bin/starling \
 && mkdir -p /usr/local/lib/starling/plugins \
 && cp /src/target/release/libmumble_friends.so \
       /src/target/release/libmumble_live_doc.so \
       /usr/local/lib/starling/plugins/

FROM debian:bookworm-slim AS runtime

# ca-certificates: link-preview fetches URLs, and no trust store makes that look
# like the remote host being down. bash (already present) is load-bearing for
# the compose healthchecks: there is no HTTP /healthz, so the only probe is a TCP
# connect via bash's /dev/tcp, which dash cannot do.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --home-dir /var/lib/starling starling

COPY --from=builder /usr/local/bin/starling /usr/local/bin/starling

# The Fancy plugins the host loads at startup. They are cdylibs opened with
# `dlopen` rather than part of the server binary, so they ship as files
# beside it, built from this workspace against the same `mumble-plugin-api` -
# a plugin whose ABI probe disagrees with the host's is refused at load.
#
# They used to be built by the C++ fork, which is EOL; that build now lives
# in this repository's CI.
COPY --from=builder /usr/local/lib/starling/plugins /usr/local/lib/starling/plugins

# Generated certificates and per-service SQLite files live here; expected to be a
# volume. Mumble clients trust a server by certificate fingerprint, so losing the
# pair on restart warns every client that connected before.
USER starling
WORKDIR /var/lib/starling

# `USER` does not set this, and the default is a directory `starling` cannot
# write. It matters because `--all-in-one` with no `--config` now writes a
# starter configuration where the platform keeps them, which under an unwritable
# HOME is a container that fails to start instead of one that just works.
#
# A container that already has a `starling-data/` here keeps it: an existing data
# directory beats this, so upgrading a deployment that ran with no `--config`
# changes nothing about where its databases and certificate live.
ENV HOME=/var/lib/starling

# Where the plugin host looks for cdylibs.
#
# The plugins are on by default: this image exists to be the whole server,
# and one that ships a plugin doing nothing until an operator finds the
# right key reads as a broken feature rather than an off one. Each is still
# one key away from off (`plugin.<name>.enabled = false`).
#
# Deliberately NOT set here: live-doc's `state_path`, which a deployment
# should put on its volume, and `file_server_url` with its admin token.
# Persistence needs a secret this image must not invent - a published
# default would be the same secret on every deployment - so until an
# operator supplies one, a document lives only as long as its room does.
ENV MUMBLE_PLUGIN_DIRS=/usr/local/lib/starling/plugins

# Documentation, not publication, compose decides what is actually reachable.
#   64738/tcp  gateway, control plane, TLS terminates there
#   64738/udp  voice, its own socket; audio never touches the gateway
#   50051/tcp  this service's gRPC surface, internal to the network
#   8080/tcp   the files service's HTTP listener
#   8081/tcp   operator-api's REST surface, off unless asked for
#   64740/tcp  live-doc's WebSocket endpoint, where documents are edited
EXPOSE 64738/tcp 64738/udp 50051/tcp 8080/tcp 8081/tcp 64740/tcp

ENTRYPOINT ["starling"]
# No arguments = the single-box deployment: every service in one process.
CMD ["--all-in-one"]
