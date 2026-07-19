# Starling design rules

These are binding for every change in this workspace, including changes to
existing files. If a change would violate one of them, fix the surrounding code
instead of adding to the violation.

---

## 1. SOLID

### Single responsibility
One file, one concept. A file that needs a "and also" in its module doc is two
files. Target: **under ~250 lines of implementation** (tests may add more). When
a file grows past that, look for the seam before adding to it.

### Open/closed
New behaviour arrives as a **new implementation of an existing trait**, not as a
new arm in an existing `match`. The message dispatcher is the canonical example:
Phases 3–5 add ~70 Fancy handlers, and each must be a `register` call, not an
edit to a growing `match`.

### Liskov
Every implementation of a trait must satisfy the contract written in the trait's
doc comment, including the failure cases. If an implementation cannot, the trait
is wrong. Write the contract in the trait doc, then test *the trait* generically
where more than one implementation exists.

### Interface segregation
Small, role-shaped traits. A caller that only reads channels takes
`&dyn ChannelStore`, not `&ServerState`. Prefer several narrow traits over one
wide one; a trait nobody implements twice and nobody fakes in a test is probably
just a struct.

### Dependency inversion
**On every component boundary, depend on a trait, never on a concrete type.**
Concretely:

* `ServerCore` knows `Outbound`, not `HashMap<ConnId, mpsc::Sender<_>>`.
* Handlers know `ChannelStore` / `UserRegistry`, not `ChannelTree` / `Users`.
* Permission checks go through `Permissions`, never through an ACL table.
* The binary composes the concrete types; nothing below it names them.

The payoff is concrete, not theoretical: a database-backed store and a
different RPC surface each swap in without touching a handler.

## 2. Traits at boundaries

When passing a dependency, pass the **trait**:

```rust
// yes
fn handle(users: &dyn UserRegistry, ...)
fn apply(&self, out: &mut dyn Outbound, ...)

// no
fn handle(users: &Users, ...)
```

Use `&dyn Trait` for runtime-swapped collaborators and `impl Trait` /
generics for hot paths where dispatch cost matters (the voice path). Do not
introduce a trait with exactly one implementation and no test double: that is
ceremony, not design.

## 3. Patterns in use

Named so reviewers recognise them, and so new code reaches for the same shapes.
(References: <https://refactoring.guru/design-patterns>.)

| Pattern | Where | Why |
|---|---|---|
| **Command** | `ServerAction` back over `Attach` | A service says what it wants done without holding the socket it happens on |
| **Strategy** | `Permissions`, `CertificateSource`, `SecurityPolicy` | Swap policy without touching callers |
| **Adapter** | `Plane<S>` around `ClientService` | A service writes `async fn frame(..)`; the gRPC surface is generated around it |
| **Repository** | `ChannelStore` | A persistent implementation replaces the in-memory one, handlers unchanged |
| **Facade** | `Roster` | One place to ask who is connected, so no service keeps its own copy |
| **Builder** | `Actions` | Ordered, append-only action lists that read declaratively |
| **Null Object** | `AllowAll` | A working permission policy before the real evaluator exists |
| **Observer** | `Fanout` | Broadcast without the producer knowing its subscribers |

## 4. Effects, not side effects

A service handler answers `Actions`: it never touches a socket, never writes to
one directly, never logs-and-returns-nothing. The gateway applies what comes
back.

This is why a service's tests need no socket and no gateway, and it is the
single biggest testability gain over the C++ server. The handler is still
`async` because it may have to ask another service something first, which is
the one way this differs from the pure `fn(..) -> Effects` originally planned.

## 5. Testing

* Every behavioural rule gets a test **named after the rule**, not after the
  function (`a_wrong_server_password_is_rejected_and_disconnected`, not
  `test_authenticate`).
* Test the **contract**, including refusals: for anything a peer can ask for,
  there is a test that it is refused when it should be.
* Assert on `Effects`, not on internal state, wherever the effect is the
  observable behaviour.
* Never weaken an assertion to make a test pass, see the acceptance rule in
  `../../SERVER-COVERAGE.md`.

## 6. Hostile input

Everything that decodes bytes comes from an unauthenticated peer:

* bound before you allocate;
* never panic, `unwrap`/`expect`/indexing that can fail are denied by lint;
* a protocol error closes **that** connection and nothing else.

## 7. Quality gates

Run after **every logical task**, not at the end of the day:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo test --workspace --doc
```

Plus, before pushing:

```sh
cargo deny check advisories bans licenses sources
scripts/check-proto-drift.sh
```

CI enforces all of the above, plus Miri and a fuzz run of the frame decoder
(`.github/workflows/ci.yml`).

Lint configuration is shared with the client and plugin-host workspaces:
`unsafe_code = "deny"`, `missing_docs = "deny"`, `unwrap_used = "deny"`,
`too_many_lines = "deny"`, `excessive_nesting = "deny"`, see
`[workspace.lints]` in `Cargo.toml` and `.clippy.toml`.

## 8. Comments

Explain **why**, never what. A comment that restates the code is noise; a
comment that records a protocol constraint, a murmur line reference, or the
reason an obvious-looking alternative is wrong is the most valuable thing in the
file. Cite `vendor/server` source lines when transcribing behaviour, the next
person needs to check it.

## 9. Length of justification is a design smell

**If defending a choice takes a paragraph or more, the choice is probably bad.**
Refactor it into something that needs a sentence.

Note the distinction. Documenting an **external constraint**, a protocol
ordering, a wire-format quirk, a murmur line reference, is a domain fact, and it
can be as long as it needs to be. Arguing for **our own design** is what must stay
short. Long argument means the design is carrying weight it should not.

Architecture rationale that genuinely needs space goes in this file or
`PORTING-PLAN.md`, with a one-line pointer from the code. Prose in a source file
is prose nobody re-reads.

## 10. `#[allow]` is a last resort

Never reach for a lint suppression while another route exists. In order of
preference:

1. **Restructure** so the lint does not fire.
2. **`#[expect(...)]`**, it errors once the suppression stops being needed, so
   it deletes itself rather than rotting.
3. **`#[allow(...)]`**, only when neither of the above is possible.

Scope it to the smallest item that works (a three-line function, never a module),
always give a `reason`, and keep that reason to one line, by §9, a suppression
needing a paragraph is a suppression hiding a design problem.

Every surviving suppression is **reported explicitly when the work is handed
over**. A reviewer should never have to grep for them.

**Exemption: generated code.** `#[allow]` on a `prost`-generated module is fine
and needs no argument, the code is not ours to restructure. Use `allow` there
rather than `expect`: which lints fire depends on how upstream wrapped its
`.proto` comments, so an unfulfilled `expect` would break the build on someone
else's edit. Still narrow the list to the measured minimum rather than a guessed
one. Everywhere else, the rule above applies in full.

Current suppressions in this workspace: see the list in `PORTING-PLAN.md` §10.
