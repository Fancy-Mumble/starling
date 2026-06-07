# Diagrams

| File | Shows |
|---|---|
| `kernel-structure.puml` | Compile-time dependency direction — the rule the kernel/feature split rests on |
| `kernel-internals.puml` | What a feature may touch: read via `StateQuery`, use `Capabilities`, return `Effects` |
| `kernel-message-flow.puml` | Runtime: one pchat message end to end, including the audit fan-out |

## Rendering

```sh
plantuml -Playout=smetana -tpng *.puml
```

`-Playout=smetana` uses PlantUML's built-in layout engine, so **GraphViz is not
required**. Without it, the component diagrams fail on a machine that has no
`dot` on PATH — which is most of them.

Verified rendering with PlantUML 1.2024.7.

## Style notes, learned the hard way

* **One message per diagram.** The first version of `kernel-structure` tried to
  show packages, components, interfaces, wiring and two notes at once, and was
  unreadable. Each diagram now answers exactly one question.
* **No `skinparam linetype ortho`.** Right-angle routing makes crossings worse,
  not better, once there is more than a handful of edges.
* **Avoid `interface` in component diagrams.** It renders as a lollipop circle,
  so a long label sprawls away from a tiny glyph. Use `rectangle`.
* **Stick to ASCII arrows in labels.** `->`, not `→` — the default font has no
  glyph for it and renders tofu. `·` and `«»` are fine.
