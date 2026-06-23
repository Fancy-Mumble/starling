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

## What of this is built

These started as the plan. Much of it now exists, so the diagrams mark the
difference rather than claiming either extreme — a picture that overstates is
worse than one that admits a gap, because the gap is what a reader needs to know
before trusting the rest.

**Built and exercised end to end.** The gateway: TLS, framing, the type-keyed
routing table, the per-route limiter, the circuit breaker, the resume ring. All
twenty services exist and serve gRPC. The handshake carries a real client from
`Version` to `SuggestConfig`, and the `starling` binary's own e2e test drives it
over a real TCP+TLS socket. Storage is real — `sqlx` over SQLite, MySQL or
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
