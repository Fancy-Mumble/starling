#!/usr/bin/env bash
# Assert that Starling's copy of the Mumble protobuf contract has not drifted
# from the C++ server's or the client's.
#
# **`vendor/server` is not upstream's source of truth** — it is the Fancy fork,
# whose proto is ~2100 lines against upstream's 639, and treating it as the
# reference is how the field-numbering drift in PROTOCOL-COMPATIBILITY.md §1
# went unnoticed. This check therefore proves *consistency between our trees*
# and says nothing about Mumble compatibility; that needs a comparison against
# `mumble-voip/mumble`, which has no remote configured here.
#
# It is also blind by construction to a rule all three trees break the same way.
# `check-proto-hygiene.py` next door covers the two that did.
#
# The three trees each carry their own copy of Mumble.proto / MumbleUDP.proto.
# Duplicating a *generated* artifact is cheap; duplicating the *contract* is what
# must be prevented. See PORTING-PLAN.md §2.2.
#
# The comparison is of **wire meaning**, not bytes: comments and whitespace
# legitimately differ between the trees (they document each side's perspective),
# and as of writing the server and client copies differ by 272 comment lines
# while being wire-identical. Requiring byte-identity would therefore fail on
# day one for no protocol reason, and teams learn to ignore a check that cries
# wolf.
#
# Usage:  scripts/check-proto-drift.sh [path-to-repo-root]

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Default layout: vendor/starling, vendor/server, vendor/client are siblings.
root="${1:-$(cd "$here/../.." && pwd)}"

ours="$here/crates/proto/proto"
server="$root/vendor/server/src"
client="$root/vendor/client/crates/mumble-protocol/proto"

# Reduce a .proto to the syntax that determines the wire format: strip both
# comment styles, collapse whitespace, normalise spacing around punctuation, and
# drop blank lines.
#
# Done in one perl pass because `/* … */` blocks span lines, which a line-based
# sed cannot see — the server's MumbleUDP.proto uses them and the client's does
# not.
#
# The punctuation pass matters too: the server writes `[deprecated = true]` and
# the client `[deprecated=true]`. Both compile to identical descriptors, so a
# check that flagged it would be crying wolf on day one — and a check people
# learn to ignore protects nothing.
normalise() {
    perl -0777 -pe '
        s{/\*.*?\*/}{}gs;      # block comments
        s{//[^\n]*}{}g;        # line comments
        s/[ \t\r]+/ /g;        # collapse intra-line whitespace
        s/ *([=,;{}]) */$1/g;  # spacing around punctuation
        s/\[ */[/g; s/ *\]/]/g;
        s/^ +//mg; s/ +$//mg;  # trim each line
        s/\n{2,}/\n/g;         # collapse blank lines
    ' "$1" | grep -v '^$'
}

status=0

check() {
    local file="$1" other="$2" label="$3"
    if [[ ! -f "$other" ]]; then
        echo "skip: $label copy not found at $other" >&2
        return 0
    fi
    if diff -u <(normalise "$ours/$file") <(normalise "$other") > /tmp/proto-drift.$$; then
        echo "ok:   $file matches the $label copy"
    else
        echo "DRIFT: $file differs from the $label copy ($other)" >&2
        cat /tmp/proto-drift.$$ >&2
        status=1
    fi
    rm -f /tmp/proto-drift.$$
}

check Mumble.proto    "$server/Mumble.proto"    "server"
check MumbleUDP.proto "$server/MumbleUDP.proto" "server"
check Mumble.proto    "$client/Mumble.proto"    "client"
check MumbleUDP.proto "$client/MumbleUDP.proto" "client"

# ---------------------------------------------------------------------------
# L2: the epoch-1 client wire.
#
# Starling owns `proto-fancy/proto/fancy/`; the client mirrors it so it can
# encode the canon. Both ends decode the same bytes, so a copy that drifts is
# the D1 failure exactly — two definitions of one outer type, resolving by
# field number into the wrong fields with nothing in any log.
#
# `vendor/server` is not checked: it speaks epoch 0 and has no L2 copy at all.
# ---------------------------------------------------------------------------
fancy_ours="$here/crates/proto-fancy/proto/fancy"
fancy_client="$client/fancy"

if [[ -d "$fancy_client" ]]; then
    for path in "$fancy_ours"/*.proto; do
        name="$(basename "$path")"
        # Compared against our own directory rather than `$ours`, so `check`'s
        # first argument is a path relative to the L2 root.
        ours="$fancy_ours" check "$name" "$fancy_client/$name" "client"
    done

    # A file the client has and we do not is drift in the other direction, and
    # a loop over *our* files cannot see it: it would simply never look.
    for path in "$fancy_client"/*.proto; do
        name="$(basename "$path")"
        if [[ ! -f "$fancy_ours/$name" ]]; then
            echo "DRIFT: the client carries fancy/$name and Starling does not" >&2
            status=1
        fi
    done
else
    echo "skip: the client has no L2 copy yet ($fancy_client)" >&2
fi

if [[ $status -ne 0 ]]; then
    echo >&2
    echo "The protobuf contract has drifted between our trees." >&2
    echo >&2
    echo "Decide which copy is right before copying anything: no tree is the" >&2
    echo "authority here, and blindly re-syncing from one is how a deliberate" >&2
    echo "change gets reverted by whoever ran this next. The diff above is of" >&2
    echo "wire meaning, so every line in it changes what the bytes say." >&2
    echo >&2
    echo "Once decided, all three copies move together:" >&2
    echo "    $ours/" >&2
    echo "    $server/" >&2
    echo "    $client/" >&2
fi

exit $status
