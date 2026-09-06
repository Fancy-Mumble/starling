#!/usr/bin/env python3
"""Assert that every lint exemption for a panic is an argued one.

`docs/RELIABILITY.md` Stage 3 denies `panic!`, `unreachable!`, `expect` and
`unwrap` in production code, so the reachable panic set is empty by
construction rather than by inspection. What keeps that true is not the lint --
it is that the exemptions stay reviewable.

Two rules, both about production code only. Test bodies are exempt from the
lints themselves (`allow-unwrap-in-tests` and friends in `.clippy.toml`), so an
exemption inside a `#[cfg(test)]` module is not making a claim about the server
and is skipped here. So is anything under a `tests/` directory: an integration
test is its own crate, which is why clippy's in-test exemptions do not reach it
and why it needs an attribute at all. `crates/harness` is skipped for the same
reason -- it is the e2e scaffolding, a `publish = false` crate that never
reaches a shipping artifact, and it was a `#[cfg(test)] mod` until it had three
callers.

  1. Every exemption carries a reason beginning `AUDIT:`, so it reads as an
     argument in the diff that adds it rather than as a way past the lint.

  2. Exemptions use `#[expect]`, never `#[allow]`. `expect` fails the build once
     the lint stops firing, so a site refactored into safety loses its exemption
     instead of accumulating a stale one. An `allow` would sit there forever
     with nobody the wiser.

Usage:  python3 scripts/check-panic-audit.py
"""

import pathlib
import re
import sys

# The lints whose exemptions have to be argued.
LINTS = (
    "panic",
    "unreachable",
    "expect_used",
    "unwrap_used",
    "indexing_slicing",
    "string_slice",
)
LINT_RE = re.compile(rf"clippy::({'|'.join(LINTS)})\b")
ATTRIBUTE = re.compile(r"#!?\[(expect|allow)\(")
TEST_MODULE = re.compile(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{")


def balanced(source: str, opening: int, open_ch: str, close_ch: str) -> int:
    """The index of the delimiter closing the one at `opening`."""
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == open_ch:
            depth += 1
        elif source[index] == close_ch:
            depth -= 1
            if depth == 0:
                return index
    return len(source)


def test_spans(source: str) -> list[tuple[int, int]]:
    """Byte ranges covered by `#[cfg(test)] mod ... { }`."""
    spans = []
    for match in TEST_MODULE.finditer(source):
        brace = source.index("{", match.start())
        spans.append((match.start(), balanced(source, brace, "{", "}")))
    return spans


def check(path: pathlib.Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    if not LINT_RE.search(source):
        return []
    spans = test_spans(source)
    problems = []

    for match in ATTRIBUTE.finditer(source):
        start = match.start()
        if any(begin <= start < end for begin, end in spans):
            continue
        body = source[match.end() : balanced(source, match.end() - 1, "(", ")")]
        if not LINT_RE.search(body):
            continue

        line = source.count("\n", 0, start) + 1
        where = f"{path}:{line}"
        if match.group(1) == "allow":
            problems.append(f"{where}: allow() never expires; use expect()")
            continue

        reason = re.search(r'reason\s*=\s*"', body)
        if not reason:
            problems.append(f"{where}: no reason given")
            continue
        # Fold line continuations, so a wrapped reason is judged on what it
        # says rather than on how it is laid out.
        text = re.sub(r"\\\s*\n\s*", "", body[reason.end() :].lstrip())
        if not text.startswith("AUDIT:"):
            problems.append(f'{where}: reason does not begin "AUDIT:"')

    return problems


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    problems = []
    audited = 0
    for path in sorted((root / "crates").rglob("*.rs")):
        # Test code however clippy sees it: an integration test, or the e2e
        # harness that drives one.
        if "tests" in path.parts or "harness" in path.parts:
            continue
        found = check(path)
        problems.extend(found)
        if not found:
            audited += len(
                [
                    m
                    for m in ATTRIBUTE.finditer(path.read_text(encoding="utf-8"))
                    if LINT_RE.search(
                        path.read_text(encoding="utf-8")[m.end() : m.end() + 200]
                    )
                ]
            )

    if problems:
        for problem in problems:
            print(problem.replace(str(root) + "/", ""), file=sys.stderr)
        print(file=sys.stderr)
        print(
            "Every exemption from a panic lint must be argued at the site, as:",
            file=sys.stderr,
        )
        print(file=sys.stderr)
        print(
            '    #[expect(clippy::indexing_slicing, reason = "AUDIT: len checked at :212")]',
            file=sys.stderr,
        )
        print(file=sys.stderr)
        print("See docs/RELIABILITY.md, Stage 3.", file=sys.stderr)
        return 1

    print(f"panic-audit: every exemption in production code is argued")
    return 0


if __name__ == "__main__":
    sys.exit(main())
