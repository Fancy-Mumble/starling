#!/usr/bin/env python3
"""Compare our upstream Mumble surface against actual upstream Mumble.

The third of the three checks in `PROTOCOL-COMPATIBILITY.md` §5, and the only
one that can fail with a *released client* on the other end. The other two
compare our trees against each other, which proves we agree; it does not prove
we are right. A field that all three trees moved identically is invisible to
them and fatal here.

Upstream is read straight from the `upstream` remote in `vendor/server`
(`mumble-voip/mumble`), which the fork already tracks, so this needs no network
as long as the remote has been fetched. When it has not, the check *skips*
rather than passing: an unfetched remote must not read as agreement.

What it asserts, for every message upstream defines:

* **Every upstream field keeps upstream's number.** The failure this exists for
  is a Fancy field taking the number upstream will use next, proto resolves by
  number, so both ends decode happily and disagree about what they read.
* **Every upstream field keeps upstream's type and label.** `optional uint32`
  becoming `optional uint64` is silently wrong for values above 2^32, and
  `optional` becoming `repeated` changes the wire shape outright.
* **No upstream message disappears.** A stock client sends what it sends.

What it deliberately allows: fields we *add* at 1000+, messages we add, and
comment or ordering differences. Those are the extension mechanism working.

    python3 scripts/check-proto-compat.py [--branch upstream/1.5.x]
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

# 1.6.x, because that is what the fork tracks (`origin/HEAD -> origin/1.6.x`)
# and where fields like `UserRemove.ban_ip` and `UserStats.rolling_stats` come
# from. Comparing against 1.5 reports those as Fancy squatters, which is how
# this check first ran: three false alarms and one real finding.
DEFAULT_BRANCH = "upstream/1.6.x"
# Where the fork lives, and therefore where the upstream remote is configured.
FORK = "vendor/server"
UPSTREAM_PATH = "src/Mumble.proto"

# Ours, which must be a superset of upstream's surface.
OURS = "crates/proto/classic/proto/Mumble.proto"

# Everything at or above this is a Fancy addition and none of upstream's
# business (`PROTOCOL-COMPATIBILITY.md` §1).
FANCY_FIELD_MIN = 1000

# The one Fancy field below that line, and the standing risk it carries.
#
# `Version.fancy_version = 6` cannot move: it is what every shipped Fancy peer
# reads to decide whether extensions exist at all, so relocating it would not
# break loudly; it would make this server look like plain Mumble to all of
# them. But upstream's `Version` uses 1 to 5, which makes **6 the next number
# upstream will take**, and this is exactly the collision the rest of the rule
# exists to prevent.
#
# Reported every run rather than suppressed. An accepted risk that nobody is
# reminded of is indistinguishable from one nobody noticed, and the day
# upstream adds a sixth field is the day this line is the only warning anyone
# gets.
PINNED = {("Version", "fancy_version", 6)}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def fields(proto: str) -> dict[str, dict[str, tuple[int, str]]]:
    """`{message: {field: (number, "label type")}}`, nested names dotted."""
    out: dict[str, dict[str, tuple[int, str]]] = {}
    context: list[str] = []
    kinds: list[str] = []
    for line in strip_comments(proto).split("\n"):
        stripped = line.strip()
        opened = re.match(r"(message|enum|oneof)\s+(\w+)", stripped)
        if opened:
            kinds.append(opened.group(1))
            if opened.group(1) != "oneof":
                context.append(opened.group(2))
            continue
        if stripped.startswith("}"):
            if kinds and kinds.pop() != "oneof" and context:
                context.pop()
            continue
        if not context or (kinds and kinds[-1] == "enum"):
            continue
        # `optional uint32 session = 1;` / `repeated Foo bar = 2 [x = y];`
        field = re.match(
            r"(optional|required|repeated)?\s*([\w.]+)\s+(\w+)\s*=\s*(\d+)", stripped
        )
        if not field:
            continue
        label, kind, name, number = field.groups()
        out.setdefault(".".join(context), {})[name] = (
            int(number),
            f"{label or 'singular'} {kind}",
        )
    return out


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent.parent
    branch = DEFAULT_BRANCH
    positional = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
    if "--branch" in sys.argv:
        branch = sys.argv[sys.argv.index("--branch") + 1]
        positional = [arg for arg in positional if arg != branch]
    # The repo root may be named, and has to be when this runs out of a `git
    # worktree`: the sibling trees are then nowhere near this file, so deriving
    # the root from its own location finds no `vendor/server`, and the check
    # skips — which reads exactly like a check that passed.
    root = pathlib.Path(positional[0]).resolve() if positional else here.parent.parent

    fork = root / FORK
    try:
        upstream_text = subprocess.run(
            ["git", "-C", str(fork), "show", f"{branch}:{UPSTREAM_PATH}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Skipping, and saying so on stderr. An unfetched remote is not
        # agreement, and a check that silently passed here would be worse than
        # no check: it is the only one that can catch a released-client break.
        print(
            f"skip: {branch} is not available in {fork}; "
            f"run `git -C {fork} fetch upstream` to enable this check",
            file=sys.stderr,
        )
        return 0

    upstream = fields(upstream_text)
    ours = fields((here / OURS).read_text("utf-8"))

    problems: list[str] = []
    for message, upstream_fields in sorted(upstream.items()):
        mine = ours.get(message)
        if mine is None:
            problems.append(f"{message}: upstream defines it and we do not")
            continue
        for name, (number, kind) in sorted(upstream_fields.items()):
            got = mine.get(name)
            if got is None:
                problems.append(f"{message}.{name}: upstream field {number} is missing")
            elif got[0] != number:
                problems.append(
                    f"{message}.{name}: upstream numbers it {number}, we number it "
                    f"{got[0]}, a released client would read the wrong field"
                )
            elif got[1] != kind:
                problems.append(
                    f"{message}.{name}: upstream declares `{kind}`, we declare "
                    f"`{got[1]}`"
                )

    # And the other direction, which is the drift §1 was written about: a field
    # of *ours* squatting in upstream's range inside a message upstream owns.
    for message, upstream_fields in sorted(upstream.items()):
        taken = {number for number, _ in upstream_fields.values()}
        for name, (number, _) in sorted(ours.get(message, {}).items()):
            if name in upstream_fields or number >= FANCY_FIELD_MIN:
                continue
            if (message, name, number) in PINNED:
                print(
                    f"note: {message}.{name} = {number} is the pinned exception, "
                    f"and {number} is upstream's next free number in {message}, "
                    f"see PROTOCOL-COMPATIBILITY.md §1",
                    file=sys.stderr,
                )
                continue
            where = "already used by upstream" if number in taken else "upstream's to use"
            problems.append(
                f"{message}.{name} = {number}: a Fancy field below "
                f"{FANCY_FIELD_MIN} in an upstream message, and {number} is {where}"
            )

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print(f"ok:   the upstream surface matches {branch} ({len(upstream)} messages)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
