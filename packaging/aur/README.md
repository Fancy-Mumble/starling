# AUR packaging

Two packages, both tracking the same upstream release:

| Directory      | Package        | What it does                                  |
| -------------- | -------------- | --------------------------------------------- |
| `starling/`    | `starling`     | Builds from the tagged source                  |
| `starling-bin/`| `starling-bin` | Repackages the published release tarball       |

They `provides`/`conflicts` each other, so a user picks one.

## Before the first submission

**Starling has no `LICENSE` file, and the AUR needs one.** `Cargo.toml` declares
`license = "MIT"`, but MIT is not one of the licences Arch keeps in
`/usr/share/licenses/common`, so a package that carries MIT code has to install
the licence text itself. There is nothing in the tree to install.

A `LICENSE` file has been added at the repository root for this. It is not in
`v0.2.2`, so **both PKGBUILDs work only from the first tag that contains it**:

1. Commit the new `LICENSE`.
2. Cut a release (`v0.2.3`, or whatever comes next) — see `docs/RELEASING.md`.
3. In both PKGBUILDs, bump `pkgver` and re-run `updpkgsums`; the `starling-bin`
   sums cover three files, one of which is the licence fetched from the tag.
4. Regenerate `.SRCINFO` (`makepkg --printsrcinfo > .SRCINFO`).

Until then the packages are complete but point at a release that will fail in
`package()` on the missing file.

Also check that neither name is taken before pushing — the AUR RPC is behind a
bot check, so use the web search at <https://aur.archlinux.org/packages>.

## Notes on the source package

- **`RUSTUP_TOOLCHAIN=stable`.** `rust-toolchain.toml` pins 1.95.0. Without the
  override a rustup-based builder downloads that exact toolchain during
  `build()`, which is network access a clean chroot does not have. The override
  is verified to take effect. It does mean the builder's stable has to be at or
  past the 1.95 floor `[workspace.package].rust-version` sets; Arch's `rust` is
  well past it.
- **`protobuf` is a real build dependency.** `starling-proto`'s `build.rs` shells
  out to `protoc` rather than bundling one, and every `.proto` here uses proto3
  `optional`, so it must be 3.15 or newer.
- **No `check()`.** The tests in `crates/starling/tests` bind real TCP and UDP
  sockets and drive a gateway handshake over them.
- **`options=('!lto')`** because the release profile already sets thin-LTO with
  `codegen-units=1`.

## Submitting

```sh
git clone ssh://aur@aur.archlinux.org/starling.git aur-starling
cp packaging/aur/starling/{PKGBUILD,.SRCINFO} aur-starling/
cd aur-starling && git add -A && git commit -m 'starling 0.2.3-1' && git push
```

Keep these directories the source of truth and copy outward, so the packaging
travels with the code that has to stay in step with it — the systemd unit and
`starling.example.toml` are installed from this tree.
