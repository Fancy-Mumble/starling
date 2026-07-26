# Diagrams

| File | Shows |
|---|---|
| `services.puml` | **Start here.** Every service, the four planes, and how they talk |
| `scaling.puml` | The shard key per service — what scales out, what cannot, and why |
| `gateway-internals.puml` | The gateway's parts, and what it deliberately does not know |
| `deployment.puml` | Container topology, and the four exposure problems |

Each answers one question, and none repeats another's rationale — shard keys live
only in `scaling.puml`, gateway mechanics only in `gateway-internals.puml`.

Rendered PNGs are build output and are not committed — `*.png` here is ignored.

Prose lives in `../ARCHITECTURE.md`, `../PROTOCOL-COMPATIBILITY.md` and
`../CONFIGURATION.md`. Diagrams carry structure; rationale goes in the docs, so
neither has to repeat the other.

**These are the plan, not the build.** Nothing here is implemented.

## Rendering

```sh
plantuml -Playout=smetana -tpng *.puml
```

`-Playout=smetana` uses PlantUML's built-in layout engine, so **GraphViz is not
required** — which is the case on most machines. Note the flag order: `java -jar
plantuml.jar -Playout=smetana`, since `-P…` before `-jar` is read as a JVM option
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
  way prints a literal `**`. This has now cost four separate fixes — use the SVG
  grep above rather than trusting a read of the PNG. Relatedly, a note line
  *starting* with `*` parses as a bullet.
* **Prefer a labelled edge to an interface node.** Lollipop `interface` glyphs
  pile onto one rank with their labels overlapping. `A --> B : «Trait»` carries
  the same information — caller, implementor, contract — and lays out.
* **No `skinparam linetype ortho`.** Right-angle routing makes crossings worse
  once there are more than a handful of edges.
* **Stick to ASCII arrows in labels.** `->`, not `→`; the default font renders
  tofu. `·` and `«»` are fine.
* **Encode the hard-won constraints in the picture.** The ICE-lite rule, the
  1 msg/s bucket, the two queue policies — each cost a debugging session, and a
  note on the edge is where the next person will actually look.
