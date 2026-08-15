#!/usr/bin/env bash
# Download upstream Mumble's protobuf definitions for `check-proto-compat.py`.
#
#     scripts/fetch-upstream-proto.sh [ref] [dir]
#
# `ref` is any branch, tag or commit in mumble-voip/mumble; `dir` defaults to
# `target/upstream-proto`, which is gitignored.
#
# Why this exists rather than reading `vendor/server`'s `upstream` remote: that
# remote only exists in the superproject checkout. Starling has no submodules,
# so in this repo's CI the fork is not on disk at all and the git path skips.
#
# The default ref is a **tag**, not a branch. Upstream adding a field is a real
# finding, but it is not the finding of whoever opened the PR that happened to
# run next, and a check that goes red for reasons outside the diff gets ignored.
# `.github/workflows/upstream-proto.yml` compares against the branch head on a
# schedule, which is where that news belongs.
set -euo pipefail

REPO="mumble-voip/mumble"
REF="${1:-v1.6.870}"
DIR="${2:-target/upstream-proto}"

mkdir -p "$DIR"
for file in Mumble.proto MumbleUDP.proto; do
    # --fail so a bad ref exits nonzero instead of writing GitHub's 404 page to
    # the file, which parses as a proto with no messages and passes everything.
    curl --fail --silent --show-error --location --retry 3 \
        --output "$DIR/$file" \
        "https://raw.githubusercontent.com/$REPO/$REF/src/$file"
done

# Read back by the compatibility check, so its output names the upstream it
# actually compared against instead of a temp path.
printf '%s@%s\n' "$REPO" "$REF" > "$DIR/UPSTREAM_REF"

echo "fetched $REPO@$REF into $DIR"
