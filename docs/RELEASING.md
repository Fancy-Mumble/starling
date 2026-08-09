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

## Downloadable builds

Built and attached to the GitHub release by `.github/workflows/release.yml`.
Each one is the same all-in-one binary in whatever wrapper the platform
understands, on native runners, no cross-compilation.

| Platform | Files |
|---|---|
| Linux `x86_64`, `aarch64` | `.tar.gz`, `.deb`, `.rpm`, `.AppImage` |
| Windows `x86_64` | `.exe`, `.zip` |
| macOS Intel, Apple silicon | `.tar.gz`, `.dmg` |

Plus `SHA256SUMS.txt` over all of them.

Linux binaries are built on Ubuntu 22.04, so glibc 2.35 is the floor — Debian
12 and Ubuntu 22.04 upward. The macOS builds are unsigned and unnotarised;
`packaging/README-archive.txt`, which ships inside every archive, says what to
do about Gatekeeper. Signing needs a paid Apple developer identity.

**None of this runs on a pull request**, so a mistake in the package tables
would first appear in the release it broke. Two things to do about that:

* `workflow_dispatch` on `release.yml` builds and packages everything and
  publishes nothing. Run it after touching `packaging/` or either
  `[package.metadata.*]` table.
* Locally, for the two that need no runner:

  ```sh
  cargo build --release --bin starling
  cargo deb -p starling --no-build          # target/debian/
  cargo generate-rpm -p crates/starling     # target/generate-rpm/
  ```

The workflow refuses a tag whose version does not match
`[workspace.package].version`: both packaging tools take their version from
`Cargo.toml` regardless of the tag, so `v0.3.0` over a `0.2.0` workspace would
publish files named `0.2.0` under a release called `0.3.0`.

### What a downloaded build does on its first start

`--all-in-one` with no `--config`, on a machine with no configuration yet,
writes one, creates the SuperUser and prints both
(`crates/starling/src/firstrun.rs`). It happens once; a start that finds a
configuration reads it and stays quiet.

| | configuration | data |
|---|---|---|
| Linux, BSD | `~/.config/starling/starling.toml` | `~/.local/share/starling` |
| macOS | `~/Library/Application Support/Starling/starling.toml` | the same directory |
| Windows | `%APPDATA%\Starling\starling.toml` | `%LOCALAPPDATA%\Starling` |

Two things keep this out of the way of a deployment that already exists. A
`--config` that names a missing file is still an error rather than an invitation
to create one, and a working directory that already holds `starling-data/` still
gets the old behaviour — built-in defaults, rooted where they always were.
Containers therefore see no change at all: every `command:` in
`docker-compose.yml` passes `--config`.

The `.deb` and `.rpm` also install `/usr/lib/systemd/system/starling.service`,
which is **not** enabled by installing them. `systemctl enable --now starling`
starts it, under a systemd-allocated user, with its configuration and data under
`/var/lib/starling`; the first start's banner is in `journalctl -u starling`.

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

   The `docker` workflow builds and publishes `:0.3.0`, `:0.3` and `:latest`.
   The `release` workflow builds the downloadable packages and cuts the GitHub
   release for the tag, with auto-generated notes and every file attached.

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
