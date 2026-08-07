#!/usr/bin/env bash
# Assert that Starling's copy of the Mumble protobuf contract has not drifted
# from the C++ server's or the client's.
#
# **`vendor/server` is not upstream's source of truth**; it is the Fancy fork,
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
# must be prevented. See docs/PORTING-PLAN.md §2.2.
#
# The comparison is of **wire meaning**, not bytes: comments and whitespace
# legitimately differ between the trees (they document each side's perspective),
# and as of writing the server and client copies differ by 272 comment lines
# while being wire-identical. Requiring byte-identity would therefore fail on
# day one for no protocol reason, and teams learn to ignore a check that cries
# wolf.
#
# **Mumble.proto is compared as a subset, not as a whole file.** Starling no
# longer carries the epoch-0 Fancy messages M3 left in place; its copy is for
# upstream's file verbatim, so that adopting an upstream release is a copy
# rather than a merge. The other two trees still carry the block. Whole-file
# identity would therefore report drift on every run for a difference that is
# the plan, which is the cry-wolf failure this file already argues against.
#
# So the invariant is now: **every type Starling declares must be declared
# identically by the other tree.** That is the half that can produce two
# definitions of one wire type; a type Starling does not declare cannot be
# decoded by Starling and so cannot disagree with anyone. A type Starling has
# and the other tree lacks is still drift, and still fails, because the
# projection below is keyed on *our* names.
#
# Ordering is normalised too (blocks are emitted sorted by name), because the
# subset is assembled from two files that declare the same types in different
# places, and a line diff would otherwise report a move as a change.
#
# Usage:  scripts/check-proto-drift.sh [path-to-repo-root]

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Default layout: vendor/starling, vendor/server, vendor/client are siblings.
root="${1:-$(cd "$here/../.." && pwd)}"

ours="$here/crates/proto/classic/proto"
server="$root/vendor/server/src"
client="$root/vendor/client/crates/mumble-protocol/proto"

# Reduce a .proto to the syntax that determines the wire format: strip both
# comment styles, collapse whitespace, normalise spacing around punctuation, and
# drop blank lines.
#
# Done in one perl pass because `/* ... */` blocks span lines, which a line-based
# sed cannot see, the server's MumbleUDP.proto uses them and the client's does
# not.
#
# The punctuation pass matters too: the server writes `[deprecated = true]` and
# the client `[deprecated=true]`. Both compile to identical descriptors, so a
# check that flagged it would be crying wolf on day one, and a check people
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

# Emit the top-level `message`/`enum` blocks of $1 whose names appear in $2,
# sorted by name, followed by the file-level declarations (`syntax`, `package`,
# `option`) which belong to no block and matter just as much.
#
# Brace-counted rather than regex-matched on the closing brace: every one of
# these files nests messages and enums inside messages, and `^}` would end the
# outer block at the first inner one, silently truncating everything after it.
project() {
    perl -0777 -e '
        sub blocks {
            open my $fh, "<", $_[0] or die "cannot read $_[0]: $!";
            local $/; my $t = <$fh>; close $fh;
            $t =~ s{/\*.*?\*/}{}gs;
            $t =~ s{//[^\n]*}{}g;
            my (%b, @top, $name, $depth, $buf);
            for my $line (split /\n/, $t) {
                if (!defined $name) {
                    if ($line =~ /^\s*(?:message|enum)\s+(\w+)/) {
                        $name = $1; $depth = 0; $buf = "";
                    } elsif ($line =~ /^\s*(?:syntax|package|option)\b/) {
                        push @top, $line;
                    }
                }
                next unless defined $name;
                $buf .= "$line\n";
                $depth += ($line =~ tr/{//) - ($line =~ tr/}//);
                if ($depth == 0 && $buf =~ /\{/) { $b{$name} = $buf; undef $name; }
            }
            return (\%b, \@top);
        }
        my ($src, $keys) = ($ARGV[0], $ARGV[1]);
        my ($sb, $stop) = blocks($src);
        my ($kb)        = blocks($keys);
        print $sb->{$_} for grep { exists $sb->{$_} } sort keys %$kb;
        print "$_\n" for sort @$stop;
    ' "$1" "$2"
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

# As `check`, but restricted to the types our copy declares. See the subset note
# in the header for why Mumble.proto and only Mumble.proto is compared this way.
check_subset() {
    local file="$1" other="$2" label="$3"
    if [[ ! -f "$other" ]]; then
        echo "skip: $label copy not found at $other" >&2
        return 0
    fi
    if diff -u \
        <(project "$ours/$file" "$ours/$file" | normalise /dev/stdin) \
        <(project "$other"      "$ours/$file" | normalise /dev/stdin) \
        > /tmp/proto-drift.$$; then
        echo "ok:   $file matches the $label copy (on the $(grep -cE '^(message|enum) ' <(project "$ours/$file" "$ours/$file")) types we declare)"
    else
        echo "DRIFT: $file differs from the $label copy ($other)" >&2
        cat /tmp/proto-drift.$$ >&2
        status=1
    fi
    rm -f /tmp/proto-drift.$$
}

check_subset Mumble.proto    "$server/Mumble.proto"    "server"
check        MumbleUDP.proto "$server/MumbleUDP.proto" "server"
check_subset Mumble.proto    "$client/Mumble.proto"    "client"
check        MumbleUDP.proto "$client/MumbleUDP.proto" "client"

# ---------------------------------------------------------------------------
# L2: the epoch-1 client wire.
#
# Starling owns `proto-fancy/proto/fancy/`; the client mirrors it so it can
# encode the canon. Both ends decode the same bytes, so a copy that drifts is
# the D1 failure exactly, two definitions of one outer type, resolving by
# field number into the wrong fields with nothing in any log.
#
# `vendor/server` is not checked: it speaks epoch 0 and has no L2 copy at all.
# ---------------------------------------------------------------------------
fancy_ours="$here/crates/proto/fancy/proto/fancy"
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
    echo "Once decided, the copies move together:" >&2
    echo "    $ours/" >&2
    echo "    $server/" >&2
    echo "    $client/" >&2
    echo >&2
    echo "For Mumble.proto the diff is a subset comparison, so a '-' line is a" >&2
    echo "type Starling declares and the other tree does not match or does not" >&2
    echo "have. Adding the epoch-0 Fancy messages back to Starling is never the" >&2
    echo "fix; they were deleted deliberately, see that file's header note." >&2
fi

exit $status
