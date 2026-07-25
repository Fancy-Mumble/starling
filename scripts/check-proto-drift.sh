#!/usr/bin/env bash
# Assert that Starling's copy of the Mumble protobuf contract has not drifted
# from the C++ server's (upstream's source of truth) or the client's.
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

ours="$here/crates/starling-proto/proto"
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

if [[ $status -ne 0 ]]; then
    echo >&2
    echo "The protobuf contract has drifted. Re-sync from the server tree:" >&2
    echo "    cp $server/Mumble.proto    $ours/Mumble.proto" >&2
    echo "    cp $server/MumbleUDP.proto $ours/MumbleUDP.proto" >&2
    echo "...and make sure the client agrees before shipping either side." >&2
fi

exit $status
