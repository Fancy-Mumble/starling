#!/usr/bin/env python3
"""The rules no compiler enforces, and that the drift check cannot see.

`check-proto-drift.sh` next door compares the trees' copies of the contract
against each other, which catches a tree that fell behind. It is blind by
construction to a rule every tree breaks identically, and to anything that is
not a `.proto` file at all. Each check here exists because the thing it checks
broke once, silently:

**Numbering.** Upstream Mumble owns field numbers 1-999 in every upstream
message; Fancy fields start at 1000. Seven extended messages once took
upstream's *immediate next* number, so upstream's next release would have given
two meanings to one field, and proto resolves by number and type, so the
symptom is wrong data with nothing in any log.

**The dead block.** The proto2 envelopes that used to sit in `Mumble.proto`
were superseded by the proto3 canon and tombstoned with a comment, which stops
readers and not compilers, the onboarding service bound itself to them anyway,
so outer type 1014 meant one thing to it and another to every service beside
it. They are deleted now (M3) and this keeps them from coming back by import.

**Frozen tags.** A message set that both ends encode may no longer be
renumbered (M4). Per set rather than per date, because several are still
incomplete and freezing those would cost work for no gain.

**Outer types.** The client names them as its own constants, because it does
not link the proto crate. Two copies of one table, and nothing compared them:
getting one wrong is not a compile error but a well-formed frame arriving at
the wrong service, which skips it. A feature that silently does nothing.

All of it is structural, offline, and cheap. Run from anywhere:

    python3 scripts/check-proto-hygiene.py [path-to-repo-root]
    python3 scripts/check-proto-hygiene.py --update-frozen   # after freezing a set

Through the interpreter, not the shebang: Windows has `python` and no
`python3`, and there the shebang resolves to a Microsoft Store stub that
prints an install prompt and exits 49, a check that fails to *launch* looks
exactly like a check that failed, and is worse than not having one.

Exits non-zero on a violation, listing each with its file and line.
"""

from __future__ import annotations

import pathlib
import re
import sys

# Upstream owns everything below this; Fancy starts here. Two tag bytes either
# way, so the margin costs nothing on the wire.
FANCY_FIELD_MIN = 1000
# Numbers released Fancy clients used for the old interleaved layout. Burned:
# never reused, so a stale client's message can never land on a new service.
BURNED_RANGE = range(100, FANCY_FIELD_MIN)

# The one deliberate exception, and why it cannot move: every shipped Fancy peer
# reads this field to decide whether extensions exist at all. Relocating it
# would not break loudly; it would make this server look like plain Mumble to
# all of them.
PINNED = {("Version", 6)}


def strip_comments(text: str) -> str:
    """Remove both comment styles, keeping line numbering intact."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def check_numbering(proto: pathlib.Path) -> list[str]:
    """Every field number must be upstream's (<100) or Fancy's (>=1000).

    Enum *values* are deliberately not checked: they are not field numbers and
    an enum may legitimately use any value, `PermissionDenied.DenyType.H9K` is
    5 and always will be.
    """
    problems: list[str] = []
    context: list[tuple[str, str]] = []  # (kind, name)
    for number, line in enumerate(strip_comments(proto.read_text("utf-8")).split("\n"), 1):
        stripped = line.strip()
        opened = re.match(r"(message|enum|oneof)\s+(\w+)", stripped)
        if opened:
            context.append((opened.group(1), opened.group(2)))
        if stripped.startswith("}") and context:
            context.pop()
            continue
        if not context or context[-1][0] == "enum":
            continue
        field = re.search(r"=\s*(\d+)\s*[;\[]", stripped)
        if not field:
            continue
        tag = int(field.group(1))
        # The nearest enclosing *message* names the owner; a `oneof` sits inside
        # one and shares its number space.
        owner = next((name for kind, name in reversed(context) if kind == "message"), "?")
        if (owner, tag) in PINNED:
            continue
        if tag in BURNED_RANGE:
            problems.append(
                f"{proto}:{number}: {owner} field {tag} is in the burned "
                f"100-{FANCY_FIELD_MIN - 1} range, Fancy fields start at "
                f"{FANCY_FIELD_MIN} ({stripped})"
            )
    return problems


# A `use` of one of these out of the frozen crate means a service is speaking
# the dead proto2 envelopes. The canon types share these names but live in
# `starling_proto_fancy::fancy::*`, so the *path* is what distinguishes them.
DEAD_IMPORT = re.compile(r"starling_proto::proto::tcp::\{?[^;]*Envelope", re.S)


def check_dead_block(root: pathlib.Path) -> list[str]:
    """No code outside the frozen proto crate may name a dead envelope type."""
    problems: list[str] = []
    for source in sorted(root.glob("crates/**/*.rs")):
        parts = source.parts
        # The frozen crate is allowed to define them; it is what holds them.
        if "proto" in parts and "proto-fancy" not in parts:
            continue
        if "target" in parts:
            continue
        text = source.read_text("utf-8", errors="replace")
        for match in DEAD_IMPORT.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            problems.append(
                f"{source}:{line}: speaks a dead proto2 envelope from "
                f"Mumble.proto; the canon is starling_proto_fancy::fancy::* "
                f"(PROTOCOL-REDESIGN.md §2)"
            )
    return problems


# L2 message sets whose field numbers may no longer move (M4).
#
# **Per set, not per date.** A blanket freeze on a chosen day would lock in
# whatever state the canon happened to be in, and several services are still on
# the relay precisely because their canon is incomplete, freezing those would
# make finishing them expensive for no gain, since nothing encodes them.
#
# A set joins this list when both ends encode it and a build carrying it could
# ship. Until then it stays out and may be renumbered freely (§2).
FROZEN = {
    "fancy/pchat.proto",
    "fancy/social.proto",
    "fancy/wire.proto",
}

MANIFEST = "scripts/frozen-tags.json"


def field_tags(proto: pathlib.Path) -> dict[str, int]:
    """Every `Message.field` in `proto`, mapped to its number.

    Keyed by name because that is what survives a rename of the *file* and not
    of the field, and a field that vanishes is as much a break as one that
    moves, so both have to be visible to the comparison.
    """
    tags: dict[str, int] = {}
    context: list[tuple[str, str]] = []
    for line in strip_comments(proto.read_text("utf-8")).split("\n"):
        stripped = line.strip()
        opened = re.match(r"(message|enum|oneof)\s+(\w+)", stripped)
        if opened:
            context.append((opened.group(1), opened.group(2)))
            continue
        if stripped.startswith("}") and context:
            context.pop()
            continue
        if not context or context[-1][0] == "enum":
            continue
        field = re.search(r"(\w+)\s*=\s*(\d+)\s*[;\[]", stripped)
        if not field:
            continue
        owner = ".".join(name for kind, name in context if kind == "message")
        tags[f"{owner}.{field.group(1)}"] = int(field.group(2))
    return tags


def check_frozen(here: pathlib.Path, update: bool) -> list[str]:
    """A frozen set's field numbers must match the recorded manifest."""
    import json

    recorded_path = here / MANIFEST
    current = {
        name: field_tags(here / "crates/proto/fancy/proto" / name) for name in sorted(FROZEN)
    }
    if update:
        recorded_path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", "utf-8")
        print(f"ok:   recorded {sum(len(v) for v in current.values())} frozen tags")
        return []
    if not recorded_path.is_file():
        return [f"{MANIFEST} is missing; run with --update-frozen to record it"]

    recorded = json.loads(recorded_path.read_text("utf-8"))
    problems: list[str] = []
    for name, tags in current.items():
        was = recorded.get(name)
        if was is None:
            problems.append(f"{name} is frozen but absent from {MANIFEST}")
            continue
        for field, tag in was.items():
            if field not in tags:
                problems.append(f"{name}: frozen field {field} (tag {tag}) was removed")
            elif tags[field] != tag:
                problems.append(
                    f"{name}: frozen field {field} moved from tag {tag} to {tags[field]}"
                )
    if not problems:
        print(f"ok:   {len(FROZEN)} frozen message sets still hold their tags")
    return problems


# The client names outer types as its own constants, because it does not link
# this crate. Two copies of one table, and nothing compared them.
#
# Getting one wrong is a D1-shaped break rather than a compile error: the frame
# is well-formed, it simply arrives at the wrong service, which decodes an
# envelope it does not recognise and skips it. A feature that silently does
# nothing, with the numbers looking plausible in both files.
CLIENT_OUTER = "crates/mumble-protocol/src/canon.rs"


def check_outer_types(here: pathlib.Path, root: pathlib.Path) -> list[str]:
    """The client's outer-type constants must match `ServiceKind`."""
    table = here / "crates/proto/fancy/src/types.rs"
    client = root / "vendor/client" / CLIENT_OUTER
    if not client.is_file():
        print(f"skip: no client canon module at {client}", file=sys.stderr)
        return []

    base = re.search(r"SERVICE_BASE: u16 = (\d+)", table.read_text("utf-8"))
    offsets = re.search(
        r"const fn offset\(self\) -> u16 \{.*?match self \{(.*?)\n        \}",
        table.read_text("utf-8"),
        re.S,
    )
    if not base or not offsets:
        return [f"{table}: could not read the ServiceKind table"]
    authority = {
        name.lower(): int(base.group(1)) + int(offset)
        for name, offset in re.findall(r"Self::(\w+) => (\d+),", offsets.group(1))
    }

    problems: list[str] = []
    for name, value in re.findall(
        r"^const (\w+): u16 = (\d+);", client.read_text("utf-8"), re.M
    ):
        # Constants named after a service; anything else in the file is not a
        # claim about routing and is left alone.
        expected = authority.get(name.replace("_", "").lower())
        if expected is None:
            continue
        if int(value) != expected:
            problems.append(
                f"{client}: {name} is {value}, but ServiceKind says {expected}, "
                f"frames would arrive at the wrong service and be silently skipped"
            )
    if not problems:
        print("ok:   the client's outer types agree with ServiceKind")
    return problems


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent.parent
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = pathlib.Path(args[0]).resolve() if args else here.parent.parent

    problems: list[str] = []

    # Every tree's copy, not just ours: the rule is broken identically in all
    # three or not at all, which is precisely why the drift check cannot see it.
    copies = [
        here / "crates/proto/classic/proto/Mumble.proto",
        root / "vendor/server/src/Mumble.proto",
        root / "vendor/client/crates/mumble-protocol/proto/Mumble.proto",
    ]
    for proto in copies:
        if not proto.is_file():
            print(f"skip: no copy at {proto}", file=sys.stderr)
            continue
        found = check_numbering(proto)
        problems += found
        if not found:
            print(f"ok:   {proto.name} numbering ({proto.parent})")

    dead = check_dead_block(here)
    problems += dead
    if not dead:
        print("ok:   no service speaks a dead proto2 envelope")

    problems += check_frozen(here, update="--update-frozen" in sys.argv)
    problems += check_outer_types(here, root)

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
