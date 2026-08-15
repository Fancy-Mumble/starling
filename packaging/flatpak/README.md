# Starling on Flathub

> **Not submittable as it stands - one step is missing, and it is not optional.**
>
> The manifest pins tag `v0.2.2`, but two things are true of that tag:
>
> 1. It does not contain this directory, so the build fails at
>    `install ... packaging/flatpak/...: No such file or directory`.
> 2. Its `Cargo.lock` differs from the working tree `cargo-sources.json` was
>    generated from, so the offline build would not match it anyway.
>
> Both are fixed by the same move: **cut a release that contains this
> directory** (0.2.3 is already the workspace version), point `tag:`/`commit:`
> at it, and re-run `generate-sources.sh`. Until then the packaging is verified
> but not shippable. See "Releasing a new version" below.

Starling is a server, so it is packaged as a Flathub **console application**:
no window, no menu entry, run from a terminal.

```
flatpak install flathub com.fancy_mumble.Starling
flatpak run com.fancy_mumble.Starling --all-in-one
```

The first start writes a configuration, creates the administrator account and
prints a SuperUser password once. Then point a Mumble client at
`localhost:64738`.

## Files

| File | What it is |
|---|---|
| `com.fancy_mumble.Starling.yml` | The flatpak-builder manifest |
| `com.fancy_mumble.Starling.metainfo.xml` | AppStream metadata (`console-application`) |
| `cargo-sources.json` | Generated. Every crate in `Cargo.lock`, with hashes |
| `generate-sources.sh` | Regenerates the above |

## Where things end up

Starling reads `$XDG_CONFIG_HOME` and `$XDG_DATA_HOME` straight from the
environment (`crates/starling/src/paths.rs`), and Flatpak already points those
at the per-app directories. So no code change and no filesystem permission was
needed:

```
~/.var/app/com.fancy_mumble.Starling/config/starling/starling.toml
~/.var/app/com.fancy_mumble.Starling/data/starling/
```

The data directory holds the account databases, the service sockets, and the
TLS certificate that is this server's identity. Back it up: replacing it looks,
to every client that has connected before, like a different server.

To use a configuration file from outside the sandbox, grant it per-install
rather than widening the manifest:

```
flatpak override --user --filesystem=/srv/starling com.fancy_mumble.Starling
flatpak run com.fancy_mumble.Starling --all-in-one --config /srv/starling/starling.toml
```

## What this package deliberately does not do

**No systemd unit.** `packaging/starling.service` is not installed. Nothing
outside the sandbox reads `/app/lib/systemd`, and `flatpak run` is not a service
manager. A server that should come up at boot wants the AUR package, the `.deb`
or the container image - not this. That is the main reason to keep the other
packaging targets alive rather than treating Flathub as a replacement.

**No `--filesystem=host`.** See the manifest for the reasoning.

## Releasing a new version

The manifest pins one exact commit and `cargo-sources.json` describes that
commit's `Cargo.lock`. They move together or the offline build fails:

1. Tag and push the release in this repository.
2. Update `tag:` and `commit:` in `com.fancy_mumble.Starling.yml`.
3. Run `./packaging/flatpak/generate-sources.sh` (needs network).
4. Add a `<release>` entry to `com.fancy_mumble.Starling.metainfo.xml`.
5. Commit all of it together, then open a PR against the Flathub repository
   `flathub/com.fancy_mumble.Starling`.

## Checking it locally

```
# The same linter Flathub CI runs
flatpak run --command=flatpak-builder-lint org.flatpak.Builder \
    manifest packaging/flatpak/com.fancy_mumble.Starling.yml

# A real build
flatpak run org.flatpak.Builder --user --install-deps-from=flathub \
    --force-clean --install builddir \
    packaging/flatpak/com.fancy_mumble.Starling.yml
```

## Before the first submission

- [ ] Serve the verification token at
      `https://fancy-mumble.com/.well-known/org.flathub.VerifiedApps.txt`.
      Flathub maps the app ID `com.fancy_mumble.Starling` back to the domain
      `fancy-mumble.com` (underscore for hyphen), which is what earns the
      verified badge.
- [ ] Decide which tag to ship. The manifest currently pins **v0.2.2**, the
      newest tag on GitHub, while the workspace version is already 0.2.3 - so
      cut and tag 0.2.3 first if that is what should go out.
- [ ] `LICENSE` says MIT and GitHub does not detect it. Worth checking the file
      is where GitHub looks, since Flathub reviewers read the same metadata.
