#!/usr/bin/env bash
# Regenerate the offline source manifest the Flatpak build needs.
#
# A Flathub builder has no network inside the build, so every crate in
# Cargo.lock has to be listed, with a hash, as a flatpak-builder source. That
# is what cargo-sources.json is.
#
# Run this whenever Cargo.lock changes AND whenever the tag in
# com.fancy_mumble.Starling.yml moves. The generated file describes one exact
# commit; a manifest pointing at v0.2.3 with v0.2.2's cargo-sources.json fails
# the offline build with a lockfile mismatch, usually a long way into it.
#
#   ./packaging/flatpak/generate-sources.sh
#
# Needs network (it resolves and hashes every dependency) and takes a couple of
# minutes. Commit the result.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

# Pinned so a regenerated file differs because Cargo.lock changed, not because
# upstream tooling drifted between two runs. Bump deliberately.
TOOLS_REF="${FLATPAK_BUILDER_TOOLS_REF:-master}"
TOOLS_URL="https://raw.githubusercontent.com/flatpak/flatpak-builder-tools/${TOOLS_REF}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

echo ">> setting up generator (python venv in ${workdir})"
python3 -m venv "${workdir}/venv"
"${workdir}/venv/bin/pip" --quiet install aiohttp toml tomlkit

curl -sSfL -o "${workdir}/flatpak-cargo-generator.py" \
    "${TOOLS_URL}/cargo/flatpak-cargo-generator.py"

cd "${repo}"

echo ">> cargo: the starling workspace"
"${workdir}/venv/bin/python" "${workdir}/flatpak-cargo-generator.py" \
    Cargo.lock -o packaging/flatpak/cargo-sources.json

echo
echo "done. Regenerated:"
ls -lh "${repo}/packaging/flatpak/cargo-sources.json"
