# Releasing and versioning

## Two kinds of version

**The release version** is `version` under `[workspace.package]` in the root
`Cargo.toml`. The `starling` binary and the internal libraries (`runtime`,
`crypto`, `gate`, `sfu`, `migrate`, `operator-api`) inherit it. This is the
number a container image is tagged with, and it moves like Fancy Mumble's does:
a semver bump plus a matching `vX.Y.Z` git tag.

**Per-crate versions** belong to the crates a change is normally confined to:
the services (`crates/services/*`), the `gateway`, and the two `proto` crates.
Each carries its own `version`, so fixing one service does not force a version
bump on the other twenty. They start at `0.2.0` and diverge from there.

Nothing here is published to crates.io (`publish = false`); the versions are for
humans reading the tree and the image, not for a registry resolver. Internal
dependencies are path-only, so the two schemes never have to agree.

## Container images

Published to `ghcr.io/fancy-mumble/starling` by `.github/workflows/docker.yml`.
It is one image for every deployment (`docs/ARCHITECTURE.md` §9); the tag is the
only thing that changes.

| Trigger | Tags |
|---|---|
| `git tag vX.Y.Z` | `X.Y.Z`, `X.Y`, `latest` |
| push to `main` | `edge`, `<version>-<short>` (e.g. `0.2.0-e649422`) |

`latest` always points at the newest release; `edge` at the tip of `main`; a
`<version>-<short>` tag (e.g. `0.2.0-e649422`, a semver pre-release of `0.2.0`)
is the immutable pin for a specific commit.

## Cutting a release

1. Bump `[workspace.package].version` in the root `Cargo.toml` (and the
   `version` of any service / gateway / proto crate that changed).
2. Commit, and let CI go green on `main`.
3. Tag and push:

   ```sh
   git tag v0.3.0
   git push origin v0.3.0
   ```

   The `docker` workflow builds and publishes `:0.3.0`, `:0.3` and `:latest`,
   and cuts a matching GitHub release (auto-generated notes) for the tag.

## Running a published image

Both scenarios in `docker-compose.yml` take the image from `STARLING_IMAGE`,
which defaults to a locally built `starling:local`. Point it at GHCR to run a
published build instead — pin a version for reproducibility:

```sh
# The twenty-container split:
STARLING_IMAGE=ghcr.io/fancy-mumble/starling:0.2.0 docker compose up -d --wait

# The single-box, everything-in-one-process deployment:
STARLING_IMAGE=ghcr.io/fancy-mumble/starling:0.2.0 \
  docker compose up -d --wait starling
```

Use `:latest` for the newest release, `:edge` to track `main`, or a
`:<version>-<short>` (e.g. `:0.2.0-e649422`) for an exact commit.
