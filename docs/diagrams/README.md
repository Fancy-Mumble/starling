# Diagrams

| File | Shows |
|---|---|
| `shape.puml` | The top-level picture: four ways in, and only one through the gateway |
| `shape-dark.puml` | The same, on a dark canvas. Both are wrappers around `shape.iuml` |
| `services.puml` | **Start here.** Every service, the four planes, and how they talk |
| `service-graph.puml` | Who calls whom: every internal edge, sorted into the four shapes an edge comes in |
| `login-sequence.puml` | One login end to end, across nine components, in murmur's order |
| `audio-timing.puml` | One 10 ms audio frame: what is inside the budget, and the two lanes kept flat |
| `scaling.puml` | The shard key per service, what scales out, what cannot, and why |
| `gateway-internals.puml` | The gateway's parts, and what it deliberately does not know |
| `deployment.puml` | Container topology, and the four exposure problems |
| `operator-api-request.puml` | The admin plane's request path: identify, authorise, record, act, and which status each failure produces |
| `operator-api-events.puml` | The live channel: four bridges, one hub, two transports, and when `started` may fire |
| `plugin-host.puml` | The plugin host inside the plugins service, coloured by what was lifted, what already existed, and what is new |
| `*-dark.puml` | The same diagram on a dark canvas. **Every diagram here is now a pair**, and both halves of a pair wrap one shared `.iuml` |

Each answers one question, and none repeats another's rationale, shard keys live
only in `scaling.puml`, gateway mechanics only in `gateway-internals.puml`,
admin-plane endpoints only in `../OPERATOR-API.md`.

Rendered PNGs are build output and are not committed, `*.png` here is ignored.

**The exception is the SVGs a document embeds**, because GitHub renders no
`.puml`, so a source-only rule would mean no picture at all on the pages people
actually read. Every diagram here is embedded somewhere, so every pair is
committed:

| Committed render | Embedded by |
|---|---|
| `shape.svg`, `shape-dark.svg` | the root `README.md`, *The shape of it* |
| `services.svg`, `services-dark.svg` | the root `README.md`, *Services and tiers* |
| `deployment.svg`, `deployment-dark.svg` | the root `README.md`, *In containers* |
| `gateway-internals.svg`, `gateway-internals-dark.svg` | `../ARCHITECTURE.md` §2 |
| `scaling.svg`, `scaling-dark.svg` | `../ARCHITECTURE.md` §5 |
| `operator-api-request.svg`, `operator-api-request-dark.svg` | `../OPERATOR-API.md` §3 |
| `operator-api-events.svg`, `operator-api-events-dark.svg` | `../OPERATOR-API.md` §6 |
| `service-graph.svg`, `service-graph-dark.svg` | `../SERVICES.md` §1 |
| `login-sequence.svg`, `login-sequence-dark.svg` | `../SERVICES.md` §3 |
| `audio-timing.svg`, `audio-timing-dark.svg` | `../SERVICES.md` §4 |
| `plugin-host.svg`, `plugin-host-dark.svg` | `../PLUGIN-HOST-PLAN.md` §2 |

Each pair shares one `.iuml` body, so **both halves of a pair must be
regenerated whenever that body changes**, and neither is regenerated for you.
See *The committed SVGs* below.

Prose lives in `../ARCHITECTURE.md`, `../SERVICES.md`,
`../PROTOCOL-COMPATIBILITY.md` and `../CONFIGURATION.md`. Diagrams carry
structure; rationale goes in the docs, so neither has to repeat the other. The
first draft of `service-graph.puml` carried five notes and was a hairball at
2191 px; moving every one of them into `../SERVICES.md` §2 is what made it
readable, which is this rule paying for itself rather than restating it.

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

Every `.puml` here is half of a pair. A `<picture>` embeds each pair and GitHub
picks by the reader's theme. Regenerate **both halves** whenever the shared
`.iuml` changes, and re-run both passes afterwards, the render overwrites the
file each time:

```sh
java -jar plantuml.jar -Playout=smetana -tsvg <name>.puml <name>-dark.puml
python - <<'EOF'
import re
NAME = '<name>'   # the same one, and only that pair: see below
FONT = ("Inter, system-ui, -apple-system, 'Segoe UI', "
        "Roboto, Helvetica, Arial, sans-serif")
for f in (NAME + '.svg', NAME + '-dark.svg'):
    s = open(f, encoding='utf-8').read()
    m = re.search(r'style="[^"]*background:(#[0-9A-Fa-f]{6})', s)
    assert m, f'no background colour in {f}'
    s, n = re.subn(r'(<defs/><g>)',
                   rf'\1<rect width="100%" height="100%" fill="{m.group(1)}"/>', s, count=1)
    assert n == 1, f'anchor not found in {f}'
    s, n = re.subn(r'font-family="Inter"', f'font-family="{FONT}"', s)
    assert n, f'no Inter font-family in {f}'
    open(f, 'w', encoding='utf-8').write(s)
EOF
```

Neither pass is optional, and that is why this is written down.

**Regenerate one pair, not the directory.** Two reasons, and both leave a mess
that looks like a real change. The patch pass is **not idempotent**: its anchor
survives the edit, so running it twice over a file injects a second background
rectangle. And a different PlantUML build lays text out a few pixels
differently, so `*.puml` rewrites every diagram in the tree, each as a
one-line diff in a file nobody can read. These SVGs were produced by more than
one version already; leave the ones you did not touch alone.

The **background** one: PlantUML puts the canvas colour in a CSS `style`
attribute on the root `<svg>` and emits no background element, so a viewer that
drops that attribute gets the text on whatever is behind it, an unreadable
diagram in one theme or the other. The injected `<rect>` is a painted element
and survives. The colour is read back out of the file rather than hard-coded, so
the one snippet serves every variant.

The **font** one: `skinparam defaultFontName Inter` emits a bare
`font-family="Inter"`, and almost no viewer, GitHub's included, has Inter. Left
alone it falls back to the browser default, which on a machine missing the named
font can be a monospace, which is what this replaces. Widening it to a stack ends
the fallback at `sans-serif`, so Inter if present and a proportional sans either
way.

### Why two wrappers and not one flag

`shape.iuml` holds the body and hard-codes no colour: every fill is a variable
the wrapper supplies. The dark render is dark throughout, canvas, cards and all,
with light text. Overriding only the canvas leaves white cards on a dark page,
which is worse than shipping no dark render, and was the first attempt.

The obvious alternatives were tried and all fail, because `!theme plain` and the
explicit fills in the body are applied *after* them and win:

| Tried | Result |
|---|---|
| `-darkmode` | Output byte-identical to the light render |
| `-S<param>=<value>` | Same; the theme resets it |
| `%getenv` + `!if` | Returns empty under the default security profile |
| `-D<var>=<value>` | Sets a legacy `!define`, which `%getenv` does not read |

**Five things the dark wrapper must colour that the obvious skinparam misses.**
Each showed up only by rendering the dark PNG and looking at it:

| Renders wrong | Fix |
|---|---|
| sequence `alt` / `opt` body, white | `skinparam sequenceGroupBodyBackgroundColor`, separate from the group *label* |
| sequence `==` divider rules, black | `<style> sequenceDiagram { LineColor ... } </style>`; there is no BorderColor skinparam |
| timing waveform and axis, black | `<style> timingDiagram { LineColor ... } </style>`; there is no TimingLineColor |
| timing `highlight`, light | pass the colour as a wrapper variable, `$c_frame` |
| timing packet markers, white on white | give each state an explicit fill, `$c_pkt` |

`grep -c 'stroke:#000000' <name>-dark.svg` catches the two line cases; the rest
need eyes. **Render the dark half and look at it** before committing a pair.

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

**`scaling` renders 4010 px wide, 86 px under the cap.** Widening it by one
column truncates it, silently. It was over the cap before `skinparam
defaultFontName Inter` narrowed the text; if it needs more, it needs splitting.

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
* **A caller that reaches *everything* belongs on its own diagram.** `health`
  and `operator-api` each fan out to all three tiers, which is ten long edges
  that say "everything" crossing every edge that says something. Leaving them
  out of `service-graph.puml` is what made the rest of it legible.
* **Four bits of documented timing-diagram syntax this build rejects**, each
  found by bisecting `audio-timing.iuml` against an error naming only a line
  number: `X has state, state` to declare a lane's states (they order by first
  appearance instead), `0 <-> 10 : label` duration constraints, a `line:` suffix
  on a `highlight` colour, and a `:` anywhere inside a lane label.
* **`skinparam ParticipantPadding` paints its own deprecation warning into the
  render**, which then ships inside the committed SVG. Check a new sequence
  diagram for a warning banner before committing it; PlantUML reports nothing on
  stderr.
