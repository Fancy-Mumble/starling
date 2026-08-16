# Starling on Flathub

> **Ready to submit.** The manifest pins `v0.2.4`, that tag contains this
> directory, and `cargo-sources.json` was regenerated from its `Cargo.lock`
> (verified identical). The one thing left is outside this repository: serve
> the token at `https://fancy-mumble.com/.well-known/org.flathub.VerifiedApps.txt`
> so Flathub can verify the app ID against the domain.

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
- [x] Tag to ship: **v0.2.4** (commit `9b7b3bd`), pinned in the manifest, with
      `cargo-sources.json` regenerated from that tag's `Cargo.lock`.
- [ ] `LICENSE` says MIT and GitHub does not detect it. Worth checking the file
      is where GitHub looks, since Flathub reviewers read the same metadata.
