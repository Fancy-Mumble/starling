#!/usr/bin/env python3
"""Assert that `File.cpp:NNN` citations still point at what they claim.

Starling's comments and docs cite murmur by line number, which is the only way
to point at code that has no stable symbol at the call site. Line numbers rot:
`vendor/server` moved on 2026-08-02 and took three citations with it, each of
which then pointed at real, plausible, unrelated code. That is worse than a
dangling reference, because a reader who follows it believes what they land on.

The pin is `scripts/cpp-citations.json`: one entry per citation, naming a symbol
that must appear within a few lines of the cited number. A citation whose symbol
has moved fails here rather than misleading somebody a year from now.

Unpinned citations are reported, not failed. Pinning all of them at once is not
the point; the point is that the ones that have been checked stay checked.

Usage:  python3 scripts/check-cpp-citations.py [--server <path>]
"""

import argparse
import json
import os
import re
import subprocess
import sys

CITATION = re.compile(r"\b([A-Za-z_][A-Za-z_0-9]*\.(?:cpp|h)):(\d+)")
WINDOW = 6

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PINS = os.path.join(HERE, "cpp-citations.json")


def tracked_files():
    out = subprocess.run(["git", "-C", ROOT, "ls-files"],
                         capture_output=True, text=True, check=True).stdout
    return [p for p in out.split("\n") if p and not p.startswith("target")]


def index_sources(server_root):
    """Basename -> the largest file with that name, which is the real one."""
    found = {}
    for base, _, names in os.walk(server_root):
        for n in names:
            if not n.endswith((".cpp", ".h")):
                continue
            path = os.path.join(base, n)
            if n not in found or os.path.getsize(path) > os.path.getsize(found[n]):
                found[n] = path
    return found


def collect_citations():
    seen = {}
    for rel in tracked_files():
        path = os.path.join(ROOT, rel)
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for m in CITATION.finditer(text):
            seen.setdefault((m.group(1), int(m.group(2))), set()).add(rel)
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=os.path.join(ROOT, "..", "server"),
                    help="path to the C++ server checkout")
    args = ap.parse_args()

    server_root = os.path.abspath(args.server)
    if not os.path.isdir(server_root):
        print(f"skipping: no C++ server checkout at {server_root}")
        return 0

    sources = index_sources(server_root)
    pins = json.load(open(PINS, encoding="utf-8")) if os.path.exists(PINS) else {}
    citations = collect_citations()

    dangling, moved, unpinned, ok = [], [], [], 0

    for (name, line), citers in sorted(citations.items()):
        src = sources.get(name)
        if src is None:
            dangling.append((name, line, sorted(citers), "no such file"))
            continue
        body = open(src, encoding="utf-8", errors="replace").read().split("\n")
        if line > len(body):
            dangling.append((name, line, sorted(citers),
                             f"file has only {len(body)} lines"))
            continue
        symbol = pins.get(f"{name}:{line}")
        if symbol is None:
            unpinned.append((name, line))
            continue
        window = "\n".join(body[max(0, line - 1 - WINDOW):line + WINDOW])
        if symbol in window:
            ok += 1
        else:
            actual = [i + 1 for i, l in enumerate(body) if symbol in l]
            moved.append((name, line, symbol, actual[:4], sorted(citers)))

    print(f"{len(citations)} distinct citations, {len(sources)} C++ files indexed")
    print(f"  pinned and verified : {ok}")
    print(f"  pinned but moved    : {len(moved)}")
    print(f"  dangling            : {len(dangling)}")
    print(f"  not yet pinned      : {len(unpinned)}")

    for name, line, citers, why in dangling:
        print(f"\nDANGLING {name}:{line} ({why})")
        for c in citers:
            print(f"    cited by {c}")
    for name, line, symbol, actual, citers in moved:
        where = f"now at {actual}" if actual else "no longer in the file"
        print(f"\nMOVED {name}:{line} should contain {symbol!r}, {where}")
        for c in citers:
            print(f"    cited by {c}")

    if unpinned:
        print("\nNot pinned (reported, not failed):")
        for name, line in unpinned[:20]:
            print(f"    {name}:{line}")
        if len(unpinned) > 20:
            print(f"    ... and {len(unpinned) - 20} more")

    return 1 if (dangling or moved) else 0


if __name__ == "__main__":
    sys.exit(main())
