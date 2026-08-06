# Diagrams

| File | Shows |
|---|---|
| `shape.puml` | The top-level picture: four ways in, and only one through the gateway |
| `shape-dark.puml` | The same, on a dark canvas. Both are wrappers around `shape.iuml` |
| `services.puml` | **Start here.** Every service, the four planes, and how they talk |
| `scaling.puml` | The shard key per service, what scales out, what cannot, and why |
| `gateway-internals.puml` | The gateway's parts, and what it deliberately does not know |
| `deployment.puml` | Container topology, and the four exposure problems |

Each answers one question, and none repeats another's rationale, shard keys live
only in `scaling.puml`, gateway mechanics only in `gateway-internals.puml`.

Rendered PNGs are build output and are not committed, `*.png` here is ignored.

**One exception: `shape.svg` is committed.** The root README embeds it, and
GitHub renders no `.puml`, so a source-only rule there would mean no picture at
all on the page most people read first. It is the only render in the tree, and
it must be regenerated whenever `shape.puml` changes — see *The committed SVG*
below. Nothing regenerates it for you.

Prose lives in `../ARCHITECTURE.md`, `../PROTOCOL-COMPATIBILITY.md` and
`../CONFIGURATION.md`. Diagrams carry structure; rationale goes in the docs, so
neither has to repeat the other.

## What of this is built

These started as the plan. Much of it now exists, so the diagrams mark the
difference rather than claiming either extreme, a picture that overstates is
worse than one that admits a gap, because the gap is what a reader needs to know
before trusting the rest.

**Built and exercised end to end.** The gateway: TLS, framing, the type-keyed
routing table, the per-route limiter, the circuit breaker, the resume ring. All
twenty-one services exist and serve gRPC. The handshake carries a real client from
`Version` to `SuggestConfig`, and the `starling` binary's own e2e test drives it
over a real TCP+TLS socket. Storage is real, `sqlx` over SQLite, MySQL or
PostgreSQL, one schema per service. Permissions evaluates ACLs. Voice binds its
own UDP socket, mints the ciphers and answers the server-browser ping. `directory`
announces to the public server list. The operator log and `operator-api` are
running surfaces, not sketches.

**Drawn here but not built.** Marked `«not built»` in the diagrams:

| What | State |
|---|---|
| Audio routing | The router, codecs and fan-out are written and tested; nothing attaches a peer to it yet, so no audio flows |
| The screen-share SFU | No `str0m` dependency exists; `screenshare` is signalling only |
| A durable session store | The resume ring is in-process, so it does **not** outlive a gateway pod and RESUME cannot cross one |
| `zstd` on the Fancy stream | A workspace dependency no source file uses |
| Sharding | Every shard key below is a design decision. Nothing is sharded yet |

Rationale for each still lives in `../ARCHITECTURE.md`; this table is only about
what a reader can rely on today.

## The committed SVGs

`shape.svg` and `shape-dark.svg` are the only renders in the tree, because the
root README embeds them in a `<picture>` and GitHub picks by the reader's theme.
Regenerate **both** whenever `shape.iuml` changes:

```sh
java -jar plantuml.jar -Playout=smetana -tsvg shape.puml shape-dark.puml
python - <<'EOF'
import re
for f in ('shape.svg', 'shape-dark.svg'):
    s = open(f, encoding='utf-8').read()
    m = re.search(r'style="[^"]*background:(#[0-9A-Fa-f]{6})', s)
    assert m, f'no background colour in {f}'
    s, n = re.subn(r'(<defs/><g>)',
                   rf'\1<rect width="100%" height="100%" fill="{m.group(1)}"/>', s, count=1)
    assert n == 1, f'anchor not found in {f}'
    open(f, 'w', encoding='utf-8').write(s)
EOF
```

The second step is not optional and is why this is written down. PlantUML puts
the background in a **CSS `style` attribute on the root `<svg>`** and emits no
background element, so a viewer that drops that attribute gets the text on
whatever is behind it — an unreadable diagram in one theme or the other. The
injected `<rect>` is a painted element and survives. The colour is read back out
of the file rather than hard-coded, so the one snippet serves both variants.

### Why two wrappers and not one flag

`shape.iuml` holds the body; `shape.puml` and `shape-dark.puml` are wrappers
that differ only in the canvas and the colour of the text floating on it. Cards
keep their light fills and dark text in both, so the variants are one picture on
two pages rather than two pictures.

The obvious alternatives were tried and all fail, because `!theme plain` and the
explicit fills in the body are applied *after* them and win:

| Tried | Result |
|---|---|
| `-darkmode` | Output byte-identical to the light render |
| `-S<param>=<value>` | Same; the theme resets it |
| `%getenv` + `!if` | Returns empty under the default security profile |
| `-D<var>=<value>` | Sets a legacy `!define`, which `%getenv` does not read |

**Nothing that names the start or end marker may appear anywhere in
`shape.iuml`, including inside a comment.** PlantUML scans for those markers
lexically, so a comment mentioning one opens a second diagram inside the include
and the render fails reporting a line in neither file. Cost a bisect to find.

`check-puml-markup.py` globs `*.iuml` as well as `*.puml`, since every note in
this diagram lives in the body and a `*.puml`-only glob would walk straight past
the text it exists to check.

Note the output filename comes from the diagram name on the start line, not from
the input file name.

## Rendering

```sh
plantuml -Playout=smetana -tpng *.puml
```

`-Playout=smetana` uses PlantUML's built-in layout engine, so **GraphViz is not
required**, which is the case on most machines. Note the flag order: `java -jar
plantuml.jar -Playout=smetana`, since `-P...` before `-jar` is read as a JVM option
and fails.

Verified with PlantUML 1.2024.7 under both smetana and bundled `dot`.

Two things to check after an edit, because both fail **silently**:

```sh
# 1. Markup that spans a line break. Run from this directory.
python ../../scripts/check-puml-markup.py

# 2. Clipping. PlantUML caps output at 4096 px and truncates without a word,
#    so if the unlimited render is larger, the normal one is silently cut.
java -DPLANTUML_LIMIT_SIZE=16384 -jar plantuml.jar -tpng *.puml
```

`check-puml-markup.py` exists because this failure has been fixed by hand seven
times. It checks each note line and each `\n`-separated label segment for an
unclosed `**`, and each line for an unbalanced `<b>`. Grepping the rendered SVG
also works but only tells you *that* something leaked, not where.

## Style notes, learned the hard way

* **One message per diagram.** An early `components.puml` tried to show
  components, traffic types, two sets of internals and three open questions at
  once; it hit 4139 px and was silently truncated at 4096. Splitting it was the
  fix, not shrinking the fonts.
* **No markup may span a line break.** `<b>` opened on one line of a note and
  closed on the next prints a literal `</b>`; creole `**bold**` split the same
  way prints a literal `**`. This has now cost four separate fixes, use the SVG
  grep above rather than trusting a read of the PNG. Relatedly, a note line
  *starting* with `*` parses as a bullet.
* **Prefer a labelled edge to an interface node.** Lollipop `interface` glyphs
  pile onto one rank with their labels overlapping. `A --> B : «Trait»` carries
  the same information (caller, implementor, contract) and lays out.
* **No `skinparam linetype ortho`.** Right-angle routing makes crossings worse
  once there are more than a handful of edges.
* **Stick to ASCII arrows in labels.** `->`, not `→`; the default font renders
  tofu. `·` and `«»` are fine.
* **Encode the hard-won constraints in the picture.** The ICE-lite rule, the
  1 msg/s bucket, the two queue policies, each cost a debugging session, and a
  note on the edge is where the next person will actually look.
