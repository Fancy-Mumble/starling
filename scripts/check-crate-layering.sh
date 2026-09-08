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
    starling-push starling-render starling-screenshare starling-server-config
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

# 5. The loopback escape hatch never ships.
#
# `starling-outbound` refuses to connect to an address inside the deployment.
# Its `loopback` feature switches that off so that a consumer's own tests can
# fetch from a server on 127.0.0.1, and a `[dev-dependencies]` entry is the only
# place it may be turned on: a dev edge is absent from the artifact, a normal
# one is not.
#
# Resolved from **`starling`**, the binary every deployment runs, and not from
# `starling-outbound` itself. That distinction is the whole check: features
# unify across a graph, so the question "is loopback on" only has an answer
# relative to a root, and asking it at the crate's own root always answers no -
# which is a check that cannot fail. It was written that way first.
#
# `--edges normal` excludes dev edges, so link-preview's test-only entry is
# invisible here, exactly as intended.
if have starling && have starling-outbound; then
    shipped=$(cargo tree -p starling --edges normal --prefix none --format '{p} {f}' 2>/dev/null \
        | grep -F 'starling-outbound ' | sort -u || true)
    if echo "$shipped" | grep -qw 'loopback'; then
        echo "LAYERING VIOLATION: the starling binary links starling-outbound with \`loopback\` on." >&2
        echo "    That disables the SSRF guard's address check in the shipped server." >&2
        echo "    Move whichever dependency enables it into [dev-dependencies]:" >&2
        cargo tree -p starling --edges normal --invert starling-outbound --prefix depth 2>/dev/null | sed 's/^/    /' >&2
        status=1
    else
        echo "ok:   starling ships starling-outbound without the loopback escape hatch"
    fi
fi

# 6. Every workspace member inherits the workspace lint table.
#
# Six plugin-host crates each hand-copied a subset of it, so a lint added to the
# workspace silently missed all six -- and the crate with the thinnest table was
# the one that `dlopen`s third-party `.so` files. A crate that genuinely needs
# an exception states it in its own source with a reason, where the code that
# needs it is, rather than by opting out of the table wholesale.
#
# `[lints] workspace = true` and a per-crate override cannot coexist: cargo
# refuses the manifest. That is what makes this check a straight yes or no.
while IFS= read -r manifest; do
    # A member of *this* workspace: a manifest declaring its own `[workspace]`
    # (the fuzz crate does, so `cargo fuzz` can pick its own profile) inherits
    # from itself and is checked by its own build.
    grep -q '^\[package\]' "$manifest" || continue
    grep -q '^\[workspace\]' "$manifest" && continue
    if ! grep -qE '^\s*workspace\s*=\s*true' <(sed -n '/^\[lints\]/,/^\[/p' "$manifest"); then
        echo >&2 "$manifest does not inherit the workspace lints"
        echo >&2 "  add:  [lints]"
        echo >&2 "        workspace = true"
        status=1
    fi
done < <(find crates -name Cargo.toml -not -path '*/target/*' | sort)

if [[ $status -ne 0 ]]; then
    echo >&2
    echo "See docs/ARCHITECTURE.md. Services reach each other over gRPC, the gateway" >&2
    echo "routes by type id without linking a service, and the frozen proto never" >&2
    echo "reaches the Fancy one. The build is what makes those structural." >&2
fi

exit $status
