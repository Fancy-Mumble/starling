#!/usr/bin/env bash
# Assert the rule the microkernel rests on:
#
#   Feature crates depend on starling-api. The kernel depends on starling-api.
#   THE KERNEL NEVER DEPENDS ON A FEATURE CRATE.
#
# A principle in a design document did not stop `AuditLogBridge` from putting
# a plugin's name into the server's message handlers. A build failure will.
#
# Passes trivially while a layer is still empty, so it can be wired into CI
# before the crates it guards exist.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

status=0

# The kernel and the privileged services. None may depend on a feature.
KERNEL_CRATES=(starling-bus starling-state starling-server starling-net starling-tls starling-voice starling-db)
# Anything matching this prefix is a feature and is off-limits to the kernel.
FEATURE_PREFIX="starling-feature-"

have() { cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q "\"name\":\"$1\""; }

# Resolve a crate's full dependency graph, or fail loudly.
#
# A `cargo tree` that errors must NOT be treated as "no violations found", that
# turns a broken manifest into a green layering check, which is worse than no
# check at all. This function existing is the fix for that bug.
# Only edges that ship. A `[dev-dependencies]` entry is not part of the artifact:
# a feature's tests may construct a real `ServerState` to check the handler
# against, and that says nothing about what the feature itself can reach.
resolve() {
    local crate="$1"
    if ! cargo tree -p "$crate" --prefix none --no-dedupe --edges normal 2>/tmp/cargo-tree-err.$$; then
        echo "ERROR: could not resolve the dependency graph for $crate." >&2
        echo "  The layering rule was NOT checked. Fix the manifest first:" >&2
        sed 's/^/    /' /tmp/cargo-tree-err.$$ >&2
        rm -f /tmp/cargo-tree-err.$$
        return 1
    fi
    rm -f /tmp/cargo-tree-err.$$
}

for crate in "${KERNEL_CRATES[@]}"; do
    have "$crate" || continue

    # `cargo tree` resolves the real graph including transitive edges, which a
    # hand-audit of Cargo.toml files would miss.
    if ! deps=$(resolve "$crate"); then
        status=1
        continue
    fi

    offenders=$(echo "$deps" | grep -o "${FEATURE_PREFIX}[a-z0-9-]*" | sort -u || true)
    if [[ -n "$offenders" ]]; then
        echo "LAYERING VIOLATION: $crate depends on a feature crate:" >&2
        echo "$offenders" | sed 's/^/    /' >&2
        status=1
        continue
    fi
    echo "ok:   $crate depends on no feature crate"
done

# The domain is passive: data structures, traits and pure functions. It has no
# runtime presence, so it must not reach a mechanism, least of all the bus.
#
# `docs/diagrams/crates.puml` asserted a `domain -> kernel` edge for a while.
# Nothing implemented it, and nothing should: a domain type that needs the bus
# to exist cannot be unit-tested without one, and the arrow would point from the
# stable inner layer out to a mechanism.
DOMAIN_CRATES=(starling-proto starling-model starling-log starling-crypto starling-config)
DOMAIN_FORBIDDEN=(starling-bus starling-api starling-cli starling-state starling-server
                  starling-net starling-tls starling-voice starling-db "$FEATURE_PREFIX")

for crate in "${DOMAIN_CRATES[@]}"; do
    have "$crate" || continue

    if ! deps=$(resolve "$crate"); then
        status=1
        continue
    fi

    clean=1
    for forbidden in "${DOMAIN_FORBIDDEN[@]}"; do
        if echo "$deps" | grep -q "$forbidden"; then
            echo "LAYERING VIOLATION: $crate (domain) depends on $forbidden" >&2
            echo "  The domain layer holds values and traits; it reaches no mechanism." >&2
            status=1
            clean=0
        fi
    done
    [[ $clean -eq 1 ]] && echo "ok:   $crate reaches no mechanism"
done

# A feature reaches the server through `starling-api`'s traits, never by naming a
# service. Before `starling-api` existed a feature had to depend on
# `starling-server` to find `Handler`, which meant it could also see `ServerState`,
# `Listener` and everything else that crate exports.
FEATURE_CRATES=(starling-feature-permission-query starling-feature-query-users)
FEATURE_FORBIDDEN=(starling-server starling-state starling-net starling-tls starling-voice
                   starling-db starling-bus)

for crate in "${FEATURE_CRATES[@]}"; do
    have "$crate" || continue
    if ! deps=$(resolve "$crate"); then
        status=1
        continue
    fi
    clean=1
    for forbidden in "${FEATURE_FORBIDDEN[@]}"; do
        if echo "$deps" | grep -q "$forbidden"; then
            echo "LAYERING VIOLATION: $crate (feature) depends on $forbidden" >&2
            echo "  A feature depends on starling-api only. See docs/CRATES.md." >&2
            status=1
            clean=0
        fi
    done
    [[ $clean -eq 1 ]] && echo "ok:   $crate reaches only the contract"
done

# The contracts crate must stay free of everything above it.
if have starling-api; then
    if ! deps=$(resolve starling-api); then
        status=1
    else
        clean=1
        for forbidden in starling-state starling-server starling-net starling-tls starling-voice starling-db starling-cli "${FEATURE_PREFIX}"; do
            if echo "$deps" | grep -q "$forbidden"; then
                echo "LAYERING VIOLATION: starling-api depends on $forbidden" >&2
                echo "  starling-api must hold traits only, with nothing above it." >&2
                status=1
                clean=0
            fi
        done
        [[ $clean -eq 1 ]] && echo "ok:   starling-api depends on nothing above it"
    fi
fi

if [[ $status -ne 0 ]]; then
    echo >&2
    echo "See docs/CRATES.md §6 (the dependency rule). The kernel must reach features" >&2
    echo "starling-api's traits, never by naming them." >&2
fi

exit $status
