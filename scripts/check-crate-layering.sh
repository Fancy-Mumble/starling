#!/usr/bin/env bash
# Assert the layering the current architecture rests on. See docs/ARCHITECTURE.md.
#
#   1. The proto is split in two so that "never break native Mumble" is
#      structural, not a rule someone remembers (§7): the frozen upstream crate
#      `starling-proto` must never reach the Fancy one `starling-proto-fancy`.
#   2. The gateway routes by type id and forwards the payload verbatim; it never
#      parses a protobuf field and never links a service's stubs (§1), so adding
#      a service must never recompile it. It reaches no service, and not the
#      admin plane either.
#   3. `starling-runtime` is the one common standalone crate every service is
#      built on (§7). It sits below them all: it must never depend on a service,
#      the gateway or the admin plane.
#   4. Services speak gRPC to one another and never link each other (§4). That
#      boundary is what isolates a failure and lets a service deploy on its own,
#      and it is only real if the build enforces it.
#
# A principle in a design document did not stop the old `AuditLogBridge` from
# reaching across a boundary it should not have. A build failure will.
#
# Passes trivially while a layer is still empty, so it can be wired into CI
# before the crates it guards exist.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

status=0

# Every service crate, by package name (crates/services/*). The gateway and the
# admin plane must reach none of these, none of them may reach another, and the
# runtime sits below them all.
SERVICES=(
    starling-audit starling-context-actions starling-directory starling-files
    starling-health starling-link-preview starling-metadata starling-moderation
    starling-onboarding starling-pchat starling-permissions starling-plugins
    starling-push starling-screenshare starling-server-config
    starling-session-lifecycle starling-session-view starling-social
    starling-text starling-userdata starling-voice
)

have() { cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q "\"name\":\"$1\""; }

# Resolve a crate's shipping dependency graph, or fail loudly.
#
# A `cargo tree` that errors must NOT be treated as "no violations found": that
# turns a broken manifest into a green layering check, which is worse than no
# check at all. This function existing is the fix for that bug.
#
# Only edges that ship (`--edges normal`). A `[dev-dependencies]` entry is not
# part of the artifact: a service's tests may legitimately construct a neighbour
# to check a handler against, and that says nothing about what the service
# itself can reach at runtime.
resolve() {
    local crate="$1"
    if ! cargo tree -p "$crate" --edges normal --prefix none --no-dedupe 2>/tmp/cargo-tree-err.$$; then
        echo "ERROR: could not resolve the dependency graph for $crate." >&2
        echo "  The layering rule was NOT checked. Fix the manifest first:" >&2
        sed 's/^/    /' /tmp/cargo-tree-err.$$ >&2
        rm -f /tmp/cargo-tree-err.$$
        return 1
    fi
    rm -f /tmp/cargo-tree-err.$$
}

# Assert that $crate (described as $role) depends on none of $forbidden, an
# extended-regex alternation of package names. A crate that does not exist yet
# is skipped, not failed, so a layer can be guarded before it is filled.
forbid() {
    local crate="$1" role="$2" forbidden="$3"
    have "$crate" || return 0

    local deps
    if ! deps=$(resolve "$crate"); then
        status=1
        return 0
    fi

    local offenders
    offenders=$(echo "$deps" | grep -oE "$forbidden" | sort -u || true)
    if [[ -n "$offenders" ]]; then
        echo "LAYERING VIOLATION: $crate ($role) links a crate it must not:" >&2
        echo "$offenders" | sed 's/^/    /' >&2
        status=1
    else
        echo "ok:   $crate ($role) links nothing it must not"
    fi
}

# The service crates as one regex alternation. Package names hold only [a-z0-9-],
# so none carries a regex metacharacter.
services_re() { local IFS='|'; echo "${SERVICES[*]}"; }

# 1. The frozen upstream proto must not reach the Fancy proto.
forbid starling-proto "frozen upstream proto" "starling-proto-fancy"

# 2. The gateway routes blind: no service crate, and not the admin plane.
forbid starling-gateway "gateway" "$(services_re)|starling-operator-api"

# 3. The runtime sits below everything it serves.
forbid starling-runtime "runtime" "$(services_re)|starling-gateway|starling-operator-api"

# 4. No service links another service; they meet over gRPC.
for service in "${SERVICES[@]}"; do
    others=$(printf '%s\n' "${SERVICES[@]}" | grep -v "^${service}$" | paste -sd'|' -)
    forbid "$service" "service" "$others"
done

if [[ $status -ne 0 ]]; then
    echo >&2
    echo "See docs/ARCHITECTURE.md. Services reach each other over gRPC, the gateway" >&2
    echo "routes by type id without linking a service, and the frozen proto never" >&2
    echo "reaches the Fancy one. The build is what makes those structural." >&2
fi

exit $status
