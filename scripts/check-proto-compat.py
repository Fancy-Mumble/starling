#!/usr/bin/env python3
"""Compare our upstream Mumble surface against actual upstream Mumble.

The third of the three checks in `PROTOCOL-COMPATIBILITY.md` §5, and the only
one that can fail with a *released client* on the other end. The other two
compare our trees against each other, which proves we agree; it does not prove
we are right. A field that all three trees moved identically is invisible to
them and fatal here.

Upstream's text comes from whichever of these is given:

* `--upstream-dir DIR`, holding `Mumble.proto` and `MumbleUDP.proto` as fetched
  from `mumble-voip/mumble`. `scripts/fetch-upstream-proto.sh` writes such a
  directory, and CI runs the check this way, because Starling has no submodules
  and the fork is therefore not on disk there.
* otherwise the `upstream` remote in `vendor/server`, which the fork already
  tracks, so a run in the superproject needs no network.

A missing file under `--upstream-dir` *fails*: the caller named that directory,
so an empty one is a broken fetch. An unfetched git remote *skips*, since a
remote nobody fetched is not a claim about upstream either way. Neither case
passes; this is the only check here that can catch a released-client break, and
one that silently reports success would be worse than not running.

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
    python3 scripts/check-proto-compat.py --upstream-dir target/upstream-proto
"""

from __future__ import annotations

import argparse
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
# Upstream keeps both files here; `fetch-upstream-proto.sh` flattens them.
UPSTREAM_DIR = "src"

# Upstream's file -> ours, which must be a superset of upstream's surface.
# MumbleUDP.proto carries the voice wire and is byte-identical to upstream
# today, but it is upstream's contract just as much and drifts just as fatally.
FILES = {
    "Mumble.proto": "crates/proto/classic/proto/Mumble.proto",
    "MumbleUDP.proto": "crates/proto/classic/proto/MumbleUDP.proto",
}

# Written by `fetch-upstream-proto.sh` so the result names the ref it compared
# against. Absent when the directory was assembled by hand, which is fine.
REF_STAMP = "UPSTREAM_REF"

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
#
# Keyed by file because both protos declare a `Ping` and a `Version`, and an
# exception granted in one must not silently apply in the other.
PINNED = {("Mumble.proto", "Version", "fancy_version", 6)}


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


def compare(file: str, upstream_text: str, ours_text: str) -> list[str]:
    """Problems with our copy of `file`, one line each, empty when compatible."""
    upstream = fields(upstream_text)
    ours = fields(ours_text)

    problems: list[str] = []
    for message, upstream_fields in sorted(upstream.items()):
        mine = ours.get(message)
        if mine is None:
            problems.append(f"{file}: {message}: upstream defines it and we do not")
            continue
        for name, (number, kind) in sorted(upstream_fields.items()):
            got = mine.get(name)
            if got is None:
                # The day upstream takes a pinned field's number is the day this
                # check exists for; reported as the collision it is, because
                # "field 26 is missing" reads like paperwork and this is not.
                collides = [
                    pinned
                    for pinned in PINNED
                    if pinned[0] == file and pinned[1] == message and pinned[3] == number
                ]
                if collides:
                    problems.append(
                        f"{file}: {message}.{name} = {number} COLLIDES with our "
                        f"pinned {message}.{collides[0][2]} = {number}; upstream "
                        f"has taken the number, see PROTOCOL-COMPATIBILITY.md §1"
                    )
                else:
                    problems.append(
                        f"{file}: {message}.{name}: upstream field {number} is missing"
                    )
            elif got[0] != number:
                problems.append(
                    f"{file}: {message}.{name}: upstream numbers it {number}, we "
                    f"number it {got[0]}, a released client would read the wrong field"
                )
            elif got[1] != kind:
                problems.append(
                    f"{file}: {message}.{name}: upstream declares `{kind}`, we "
                    f"declare `{got[1]}`"
                )

    # And the other direction, which is the drift §1 was written about: a field
    # of *ours* squatting in upstream's range inside a message upstream owns.
    for message, upstream_fields in sorted(upstream.items()):
        taken = {number for number, _ in upstream_fields.values()}
        for name, (number, _) in sorted(ours.get(message, {}).items()):
            if name in upstream_fields or number >= FANCY_FIELD_MIN:
                continue
            if (file, message, name, number) in PINNED:
                print(
                    f"note: {file}: {message}.{name} = {number} is the pinned "
                    f"exception, and {number} is upstream's next free number in "
                    f"{message}, see PROTOCOL-COMPATIBILITY.md §1",
                    file=sys.stderr,
                )
                continue
            where = "already used by upstream" if number in taken else "upstream's to use"
            problems.append(
                f"{file}: {message}.{name} = {number}: a Fancy field below "
                f"{FANCY_FIELD_MIN} in an upstream message, and {number} is {where}"
            )
    return problems


def from_fork(fork: pathlib.Path, branch: str, file: str) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(fork), "show", f"{branch}:{UPSTREAM_DIR}/{file}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare our upstream Mumble surface against upstream Mumble."
    )
    # The repo root may be named, and has to be when this runs out of a `git
    # worktree`: the sibling trees are then nowhere near this file, so deriving
    # the root from its own location finds no `vendor/server`, and the check
    # skips, which reads exactly like a check that passed.
    parser.add_argument(
        "root", nargs="?", help="superproject root holding vendor/server"
    )
    parser.add_argument(
        "--branch",
        default=DEFAULT_BRANCH,
        help=f"upstream ref inside the fork (default: {DEFAULT_BRANCH})",
    )
    parser.add_argument(
        "--upstream-dir",
        type=pathlib.Path,
        help="read upstream's protos from this directory instead of the fork; "
        "see scripts/fetch-upstream-proto.sh",
    )
    args = parser.parse_args()

    here = pathlib.Path(__file__).resolve().parent.parent
    root = pathlib.Path(args.root).resolve() if args.root else here.parent.parent
    fork = root / FORK

    # What the result should name as the thing we compared against.
    where = args.branch
    if args.upstream_dir is not None:
        stamp = args.upstream_dir / REF_STAMP
        where = (
            stamp.read_text("utf-8").strip()
            if stamp.is_file()
            else str(args.upstream_dir)
        )

    problems: list[str] = []
    for file, ours_path in FILES.items():
        if args.upstream_dir is not None:
            path = args.upstream_dir / file
            if not path.is_file():
                # Not a skip: this directory was asked for by name, so an
                # absent file is a fetch that failed, not an absent opinion.
                print(f"FAIL: {path} does not exist; the fetch did not run", file=sys.stderr)
                return 1
            upstream_text = path.read_text("utf-8")
        else:
            upstream_text = from_fork(fork, args.branch, file)
            if upstream_text is None:
                # Skipping, and saying so on stderr. An unfetched remote is not
                # agreement, and a check that silently passed here would be
                # worse than no check: it is the only one that can catch a
                # released-client break.
                print(
                    f"skip: {args.branch}:{UPSTREAM_DIR}/{file} is not available in "
                    f"{fork}; run `git -C {fork} fetch upstream`, or pass "
                    f"--upstream-dir after scripts/fetch-upstream-proto.sh",
                    file=sys.stderr,
                )
                return 0
        found = compare(file, upstream_text, (here / ours_path).read_text("utf-8"))
        if not found:
            print(f"ok:   {file} matches {where} ({len(fields(upstream_text))} messages)")
        problems += found

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
