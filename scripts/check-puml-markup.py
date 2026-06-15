"""Find bold markup that spans a line break in a .puml.

PlantUML's creole `**bold**` and HTML `<b>` do not survive a newline: the opener
is consumed and the closer prints literally. In a note that newline is a real
line; in a component label it is the `\n` escape. Both are checked here, because
both have leaked in this repo more than once and a read of the PNG missed them.
"""

import glob
import re
import sys

bad = 0
for path in sorted(glob.glob("*.puml")):
    lines = open(path, encoding="utf-8").read().splitlines()
    in_note = False
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.match(r"^note\b", stripped) or stripped.startswith("legend"):
            in_note = True
            continue
        if stripped in ("end note", "endlegend"):
            in_note = False
            continue

        # A note body line: bold must open and close on this same line.
        if in_note and stripped.count("**") % 2:
            print(f"{path}:{n}: note line has an unclosed ** -> {stripped[:70]}")
            bad += 1

        # Same rule for HTML tags, anywhere in the file including the header.
        if stripped.count("<b>") != stripped.count("</b>"):
            print(f"{path}:{n}: unbalanced <b> on this line -> {stripped[:70]}")
            bad += 1

        # A component label: every \n-separated segment must balance.
        for label in re.findall(r'"((?:[^"\\]|\\.)*)"', line):
            for seg in label.split("\\n"):
                if seg.count("**") % 2:
                    print(f"{path}:{n}: label segment has an unclosed ** -> {seg[:60]}")
                    bad += 1

sys.exit(1 if bad else 0)
