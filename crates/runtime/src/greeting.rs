//! The greeting graph: what an operator drew, what it is allowed to say, and
//! which greeting an arriving peer is shown.
//!
//! Everything here is pure. Facts are gathered elsewhere and handed in already
//! resolved, so choosing a greeting cannot fail, cannot block and cannot be
//! reached by a network error. That is the point: a welcome message must never
//! be able to stop somebody logging in, and the cheapest way to guarantee that
//! is to have nothing in the decision that can fail.
//!
//! The tri-state in [`Truth`] is what makes it hold. A condition whose fact the
//! server does not have - no geo-IP database, a guest with no account age -
//! answers *unknown* rather than false. Unknown propagates through the gates,
//! a greeting shows only on a definite yes, and a graph nobody can evaluate
//! falls through to the plain `welcome_text` the server always had.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use sha2::{Digest as _, Sha256};
use starling_proto_fancy::common::Scope;
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::serverconfig::{
    GetRequest, Greeting, GreetingEdge, GreetingNode, GreetingPort, greeting_node,
};

use crate::channel::Resolver;

/// How long to wait before resubscribing after the stream ends.
const RESUBSCRIBE_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Bytes of the SHA-256 that identify a version of the document.
pub const DIGEST_BYTES: usize = 8;

/// Nodes one graph may hold. Past this an operator is not drawing a rule.
pub const MAX_NODES: usize = 64;
/// Wires one graph may hold.
pub const MAX_EDGES: usize = 128;
/// Characters of markup in one greeting or snippet body.
///
/// Paid on every join, which is what the cap is about rather than storage.
pub const MAX_BODY: usize = 4096;
/// Characters in a snippet's name.
pub const MAX_NAME: usize = 48;
/// Countries one condition may name.
pub const MAX_COUNTRIES: usize = 32;

/// A refused greeting write, and what caused it.
///
/// The node is named because an operator acts on it: a canvas of forty nodes
/// and a message saying "invalid graph" tells them nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    /// The node id, or empty when the whole document is at fault.
    pub node: String,
    /// The rule it broke.
    pub reason: Reason,
}

/// What was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// More nodes or wires than a graph may hold.
    TooLarge(usize),
    /// Past the cap carried here, counted in characters.
    TooLong(usize),
    /// Two nodes, or two wires, share an id.
    DuplicateId,
    /// A wire names an end that is not in the graph.
    DanglingEdge,
    /// A wire lands somewhere its source cannot feed.
    BadPort,
    /// A condition was wired straight into a gate, which takes only
    /// settled answers. It has to pass through a filter first.
    UndecidedIntoGate,
    /// The wires close a loop, which no evaluation can walk.
    Cycle,
    /// A node carries no body at all.
    Empty,
    /// A country code that is not two letters.
    BadCountry,
}

/// What the server knows about the peer being greeted.
///
/// Every field is independently optional, and `None` means *not known* rather
/// than a default: a guest genuinely has no account age, and a server with no
/// geo-IP database genuinely has no country. Both must answer unknown, because a
/// zero here would silently satisfy "joined less than a month ago".
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// `Version.version_v2` as the peer announced it.
    pub client_version: Option<u64>,
    /// Normalised, never the raw `Version.os` string.
    pub os: Option<greeting_node::operating_system::Os>,
    /// Whether the peer holds a registered account.
    pub registered: Option<bool>,
    /// Whether their certificate chains to a configured CA.
    pub strong_cert: Option<bool>,
    /// Seconds since the account was created.
    pub account_age_s: Option<u64>,
    /// ACL groups at the root channel. `None` when nothing asked for them.
    pub groups: Option<Vec<String>>,
    /// ISO-3166-1 alpha-2, upper case.
    pub country: Option<String>,
}

/// Yes, no, or *the server cannot say*.
///
/// The third arm is the whole safety property. Without it every missing fact
/// would have to be a `false`, and "not from Germany" would silently include
/// everybody on a server whose operator never installed a geo-IP database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    /// The condition holds.
    Yes,
    /// The condition does not hold.
    No,
    /// The server has no fact to answer with.
    Unknown,
}

impl Truth {
    fn of(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }

    fn not(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unknown => Self::Unknown,
        }
    }

    /// `No` from either side settles an AND, even when the other is unknown.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Yes, Self::Yes) => Self::Yes,
            _ => Self::Unknown,
        }
    }

    /// `Yes` from either side settles an OR, for the same reason.
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            (Self::No, Self::No) => Self::No,
            _ => Self::Unknown,
        }
    }

    /// XOR needs both sides; there is no short circuit that could settle it.
    fn xor(self, other: Self) -> Self {
        match (self, other) {
            (Self::Yes, Self::No) | (Self::No, Self::Yes) => Self::Yes,
            (Self::Yes, Self::Yes) | (Self::No, Self::No) => Self::No,
            _ => Self::Unknown,
        }
    }
}

/* -- Reading the graph ----------------------------------------------------- */

fn node<'a>(graph: &'a Greeting, id: &str) -> Option<&'a GreetingNode> {
    graph.nodes.iter().find(|n| n.id == id)
}

/// The node wired into `port` of `id`, if any.
fn feeding<'a>(graph: &'a Greeting, id: &str, port: GreetingPort) -> Option<&'a GreetingNode> {
    let edge = graph
        .edges
        .iter()
        .find(|e| e.to == id && e.port == i32::from(port))?;
    node(graph, &edge.from)
}

/// Every snippet wired into `id`'s PLUS port, in the order they were wired.
pub fn snippets<'a>(graph: &'a Greeting, id: &str) -> Vec<&'a greeting_node::Snippet> {
    graph
        .edges
        .iter()
        .filter(|e| e.to == id && e.port == i32::from(GreetingPort::Plus))
        .filter_map(|e| node(graph, &e.from))
        .filter_map(|n| match n.body.as_ref() {
            Some(greeting_node::Body::Snippet(snippet)) => Some(snippet),
            _ => None,
        })
        .collect()
}

/* -- Evaluation ------------------------------------------------------------ */

/// Whether the condition ending at `id` holds for `facts`.
///
/// `seen` is not defence against an operator: [`validate`] refuses a cycle at
/// write time. It is defence against a *stored* document - one written before a
/// rule existed, or by something other than this server - because a walk that
/// trusted the graph would spin on the login path.
fn truth(graph: &Greeting, id: &str, facts: &Facts, seen: &mut HashSet<String>) -> Truth {
    if !seen.insert(id.to_owned()) {
        return Truth::Unknown;
    }
    let Some(n) = node(graph, id) else {
        return Truth::Unknown;
    };
    let verdict = match n.body.as_ref() {
        Some(greeting_node::Body::Gate(gate)) => {
            let a = feeding(graph, id, GreetingPort::A)
                .map_or(Truth::Unknown, |src| truth(graph, &src.id, facts, seen));
            match greeting_node::gate::Kind::try_from(gate.kind) {
                Ok(greeting_node::gate::Kind::Not) => a.not(),
                Ok(kind) => {
                    let b = feeding(graph, id, GreetingPort::B)
                        .map_or(Truth::Unknown, |src| truth(graph, &src.id, facts, seen));
                    match kind {
                        greeting_node::gate::Kind::And => a.and(b),
                        greeting_node::gate::Kind::Or => a.or(b),
                        greeting_node::gate::Kind::Xor => a.xor(b),
                        greeting_node::gate::Kind::Nand => a.and(b).not(),
                        greeting_node::gate::Kind::Nor => a.or(b).not(),
                        greeting_node::gate::Kind::Xnor => a.xor(b).not(),
                        greeting_node::gate::Kind::Not => a.not(),
                    }
                }
                Err(_) => Truth::Unknown,
            }
        }
        Some(greeting_node::Body::Filter(filter)) => {
            let inner = feeding(graph, id, GreetingPort::A)
                .map_or(Truth::Unknown, |src| truth(graph, &src.id, facts, seen));
            let fallback = match greeting_node::filter::Unknown::try_from(filter.unknown_becomes) {
                Ok(greeting_node::filter::Unknown::IsYes) => Truth::Yes,
                // An unreadable setting resolves the way the default
                // does. A filter that answered Unknown would be a
                // filter that filtered nothing, which is the one thing
                // this node must never do.
                _ => Truth::No,
            };
            match inner {
                Truth::Unknown => fallback,
                settled => settled,
            }
        }
        Some(body) => condition(body, facts),
        None => Truth::Unknown,
    };
    // Removed rather than left behind: a node feeding two gates is visited
    // twice on purpose, and only a walk that is *currently* inside it cycles.
    let _ = seen.remove(id);
    verdict
}

/// One condition against the facts. Anything the server cannot answer is
/// `Unknown`, and an unrecognised enum value is too - a document from a newer
/// server must go quiet rather than guess.
fn condition(body: &greeting_node::Body, facts: &Facts) -> Truth {
    use greeting_node::Body;
    match body {
        Body::Country(c) => match facts.country.as_deref() {
            None => Truth::Unknown,
            Some(here) => Truth::of(c.codes.iter().any(|code| code.eq_ignore_ascii_case(here))),
        },
        Body::Tenure(t) => match facts.account_age_s {
            None => Truth::Unknown,
            Some(age) => match greeting_node::tenure::Op::try_from(t.op) {
                Ok(greeting_node::tenure::Op::JoinedLessThan) => Truth::of(age < t.window_s),
                Ok(greeting_node::tenure::Op::JoinedMoreThan) => Truth::of(age > t.window_s),
                Err(_) => Truth::Unknown,
            },
        },
        Body::ClientVersion(v) => match facts.client_version {
            // Zero is what a peer that never sent a Version has, and it is not
            // a version - reading it as one makes every "older than" rule match
            // a client that said nothing at all.
            None | Some(0) => Truth::Unknown,
            Some(here) => match greeting_node::client_version::Op::try_from(v.op) {
                Ok(op) => Truth::of(match op {
                    greeting_node::client_version::Op::Lt => here < v.version,
                    greeting_node::client_version::Op::Le => here <= v.version,
                    greeting_node::client_version::Op::Eq => here == v.version,
                    greeting_node::client_version::Op::Ge => here >= v.version,
                    greeting_node::client_version::Op::Gt => here > v.version,
                }),
                Err(_) => Truth::Unknown,
            },
        },
        Body::Account(a) => match greeting_node::account_is::State::try_from(a.state) {
            Ok(greeting_node::account_is::State::Guest) => {
                facts.registered.map_or(Truth::Unknown, |r| Truth::of(!r))
            }
            Ok(greeting_node::account_is::State::Registered) => {
                facts.registered.map_or(Truth::Unknown, Truth::of)
            }
            Ok(greeting_node::account_is::State::StrongCert) => {
                facts.strong_cert.map_or(Truth::Unknown, Truth::of)
            }
            Err(_) => Truth::Unknown,
        },
        Body::Group(g) => match facts.groups.as_ref() {
            None => Truth::Unknown,
            Some(groups) => Truth::of(groups.iter().any(|held| held == &g.group)),
        },
        Body::Os(o) => match (
            facts.os,
            greeting_node::operating_system::Os::try_from(o.os),
        ) {
            (Some(here), Ok(want)) => Truth::of(here == want),
            _ => Truth::Unknown,
        },
        // A snippet is prose, not a truth value, and a greeting is the thing
        // being decided rather than part of the decision.
        Body::Snippet(_) | Body::Greet(_) | Body::Gate(_) | Body::Filter(_) => Truth::Unknown,
    }
}

/// The greeting this peer is shown, if any.
///
/// Greetings are considered in the order the operator left them and the first
/// definite match wins, which is the rule an operator can predict without
/// reading the whole canvas. A disabled graph shows nothing.
pub fn choose<'a>(graph: &'a Greeting, facts: &Facts) -> Option<&'a GreetingNode> {
    if !graph.enabled {
        return None;
    }
    graph.nodes.iter().find(|n| {
        if !matches!(n.body, Some(greeting_node::Body::Greet(_))) {
            return false;
        }
        // What decides is the condition wired into WHEN, never the greeting
        // node itself: a greeting is the thing being chosen, so asking it
        // whether it is true answers Unknown and shows nobody anything.
        feeding(graph, &n.id, GreetingPort::When).map_or(Truth::Unknown, |src| {
            truth(graph, &src.id, facts, &mut HashSet::new())
        }) == Truth::Yes
    })
}

/// The body of `greet` with its snippets appended, in the markup the server is
/// willing to send.
///
/// A server with `allow_html` off sends the plain form, because a client that
/// cannot render tags prints them, and a greeting full of `<p>` reads as a
/// broken server rather than as a welcome.
pub fn compose(graph: &Greeting, greet: &GreetingNode, allow_html: bool) -> String {
    let Some(greeting_node::Body::Greet(body)) = greet.body.as_ref() else {
        return String::new();
    };
    let pick = |html: &str, plain: &str| -> String {
        let chosen = if allow_html && !html.is_empty() {
            html
        } else {
            plain
        };
        chosen.trim().to_owned()
    };
    let mut parts = vec![pick(&body.html, &body.plain)];
    parts.extend(
        snippets(graph, &greet.id)
            .into_iter()
            .map(|s| pick(&s.html, &s.plain)),
    );
    parts.retain(|part| !part.is_empty());
    parts.join(if allow_html { "" } else { " " })
}

/// Whether this node's output can still be `Unknown`.
///
/// A *static* property of the drawing, not of any one arrival: it asks
/// whether there exists a peer for whom this wire is undecided, which is
/// what the editor draws so an operator can see the third state before it
/// costs them a greeting nobody received.
///
/// A condition can always be unknown - every fact behind one is optional. A
/// filter never can, which is its whole purpose. A gate can when an input
/// can, except that an AND or an OR with one settled side is settled - but
/// whether a side *is* settled depends on the peer, so the safe static
/// answer is that it can.
pub fn may_be_unknown(graph: &Greeting, id: &str) -> bool {
    fn walk(graph: &Greeting, id: &str, seen: &mut HashSet<String>) -> bool {
        if !seen.insert(id.to_owned()) {
            return true;
        }
        let Some(n) = node(graph, id) else {
            return true;
        };
        match n.body.as_ref() {
            Some(greeting_node::Body::Filter(_)) => false,
            Some(greeting_node::Body::Gate(gate)) => {
                let ports: &[GreetingPort] = match greeting_node::gate::Kind::try_from(gate.kind) {
                    Ok(greeting_node::gate::Kind::Not) => &[GreetingPort::A],
                    _ => &[GreetingPort::A, GreetingPort::B],
                };
                ports.iter().any(|port| {
                    feeding(graph, id, *port).is_none_or(|src| walk(graph, &src.id, seen))
                })
            }
            _ => true,
        }
    }
    walk(graph, id, &mut HashSet::new())
}

/// The operating system a peer's `Version.os` names, normalised.
///
/// The two clients spell it differently and neither spelling is wrong:
/// the Fancy client sends `std::env::consts::OS`, which is lower case
/// (`windows`, `macos`, `linux`), and stock Mumble sends its own, which
/// is capitalised and historically said `X11` for Linux. An operator who
/// matched on the raw string would pick one client and silently miss the
/// other, so the raw string never reaches a condition - this does.
///
/// `None` for anything unrecognised, which answers Unknown rather than
/// guessing: a client this server has never heard of is not Windows.
#[must_use]
pub fn normalise_os(raw: &str) -> Option<greeting_node::operating_system::Os> {
    use greeting_node::operating_system::Os;
    let name = raw.trim().to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    // Substring rather than equality: stock Mumble sends whole phrases
    // here ("Microsoft Windows 11", "Arch Linux"), not a bare token.
    let has = |needle: &str| name.contains(needle);
    if has("windows") || has("win32") || has("win64") {
        Some(Os::Windows)
    } else if has("macos") || has("mac os") || has("darwin") || has("osx") {
        Some(Os::Macos)
    } else if has("android") {
        // Before Linux: Android is a Linux, and an operator who picked
        // Android meant the phone.
        Some(Os::Android)
    } else if has("ios") || has("iphone") || has("ipad") {
        Some(Os::Ios)
    } else if has("linux") || has("x11") {
        Some(Os::Linux)
    } else if has("bsd") {
        Some(Os::Bsd)
    } else {
        None
    }
}

/* -- Validation ------------------------------------------------------------ */

/// Whether `node` answers a question about the peer, rather than combining
/// other answers or carrying prose.
fn is_condition(node: &GreetingNode) -> bool {
    !matches!(
        node.body,
        None | Some(
            greeting_node::Body::Gate(_)
                | greeting_node::Body::Filter(_)
                | greeting_node::Body::Snippet(_)
                | greeting_node::Body::Greet(_)
        )
    )
}

/// Whether a wire from `source` may land on `port` of `target`.
///
/// The interesting case is a gate. A gate takes only *settled* answers,
/// so its inputs must come from a filter or from another gate - and
/// since those are settled in turn, the rule is inductive: no maybe can
/// reach a gate at all. A condition has to pass through a filter first,
/// which is where the operator says what its maybe means.
fn port_accepts(source: &GreetingNode, target: &GreetingNode, port: GreetingPort) -> bool {
    let is_snippet = matches!(source.body, Some(greeting_node::Body::Snippet(_)));
    let is_greet = matches!(source.body, Some(greeting_node::Body::Greet(_)));
    if port == GreetingPort::Plus {
        // Prose, and only prose.
        return is_snippet;
    }
    // A truth value, and a greeting is not one.
    if is_snippet || is_greet {
        return false;
    }
    if matches!(target.body, Some(greeting_node::Body::Gate(_))) {
        return matches!(
            source.body,
            Some(greeting_node::Body::Gate(_) | greeting_node::Body::Filter(_))
        );
    }
    // WHEN and a filter's own input both take a maybe: WHEN has a
    // defined meaning for one - it shows on a definite yes and on
    // nothing else - and a filter exists precisely to be handed one.
    true
}

/// What is wrong with this document, if anything.
///
/// Refused at write time rather than tolerated at read time: an operator who
/// saved a graph and was told nothing will find out from a member that the
/// wrong greeting went out, which is the worst place to learn it.
pub fn validate(graph: &Greeting) -> Result<(), Vec<Invalid>> {
    let mut problems = Vec::new();
    let bad = |node: &str, reason: Reason| Invalid {
        node: node.to_owned(),
        reason,
    };

    if graph.nodes.len() > MAX_NODES {
        problems.push(bad("", Reason::TooLarge(graph.nodes.len())));
    }
    if graph.edges.len() > MAX_EDGES {
        problems.push(bad("", Reason::TooLarge(graph.edges.len())));
    }

    let mut ids = HashSet::new();
    for n in &graph.nodes {
        if !ids.insert(n.id.as_str()) {
            problems.push(bad(&n.id, Reason::DuplicateId));
        }
        match n.body.as_ref() {
            None => problems.push(bad(&n.id, Reason::Empty)),
            Some(greeting_node::Body::Country(c)) => {
                if c.codes.len() > MAX_COUNTRIES {
                    problems.push(bad(&n.id, Reason::TooLarge(c.codes.len())));
                }
                if c.codes
                    .iter()
                    .any(|code| code.len() != 2 || !code.chars().all(|ch| ch.is_ascii_alphabetic()))
                {
                    problems.push(bad(&n.id, Reason::BadCountry));
                }
            }
            Some(greeting_node::Body::Snippet(s)) => {
                if s.name.chars().count() > MAX_NAME {
                    problems.push(bad(&n.id, Reason::TooLong(s.name.chars().count())));
                }
                for body in [&s.html, &s.plain] {
                    if body.chars().count() > MAX_BODY {
                        problems.push(bad(&n.id, Reason::TooLong(body.chars().count())));
                    }
                }
            }
            Some(greeting_node::Body::Greet(g)) => {
                for body in [&g.html, &g.plain] {
                    if body.chars().count() > MAX_BODY {
                        problems.push(bad(&n.id, Reason::TooLong(body.chars().count())));
                    }
                }
            }
            Some(_) => {}
        }
    }

    let mut edge_ids = HashSet::new();
    for e in &graph.edges {
        if !edge_ids.insert(e.id.as_str()) {
            problems.push(bad(&e.id, Reason::DuplicateId));
        }
        let (Some(from), Some(to)) = (node(graph, &e.from), node(graph, &e.to)) else {
            problems.push(bad(&e.id, Reason::DanglingEdge));
            continue;
        };
        match GreetingPort::try_from(e.port) {
            Ok(port) if port_accepts(from, to, port) => {}
            // Named apart from a plain bad port, because the operator's
            // fix is a specific one: put a filter in between.
            Ok(port)
                if port != GreetingPort::Plus
                    && matches!(to.body, Some(greeting_node::Body::Gate(_)))
                    && is_condition(from) =>
            {
                problems.push(bad(&e.id, Reason::UndecidedIntoGate));
            }
            _ => problems.push(bad(&e.id, Reason::BadPort)),
        }
    }

    if graph.nodes.iter().any(|n| cycles(graph, &n.id)) {
        problems.push(bad("", Reason::Cycle));
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Whether following the wires backwards from `start` returns to it.
fn cycles(graph: &Greeting, start: &str) -> bool {
    fn walk(graph: &Greeting, id: &str, start: &str, seen: &mut HashSet<String>) -> bool {
        for edge in graph.edges.iter().filter(|e| e.to == id) {
            if edge.from == start {
                return true;
            }
            if seen.insert(edge.from.clone()) && walk(graph, &edge.from, start, seen) {
                return true;
            }
        }
        false
    }
    walk(graph, start, start, &mut HashSet::new())
}

/* -- Identity -------------------------------------------------------------- */

/// The document's canonical form: what the digest is taken over.
///
/// Layout is deliberately excluded. Moving a node changes the drawing and not
/// the rule, and a digest that moved with it would re-prompt every user on the
/// server because an operator tidied their canvas.
pub fn canonical(graph: &Greeting) -> String {
    let mut out = String::new();
    out.push_str(if graph.enabled { "on\n" } else { "off\n" });

    let mut nodes: Vec<&GreetingNode> = graph.nodes.iter().collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    for n in nodes {
        out.push_str(&n.id);
        out.push('\t');
        match n.body.as_ref() {
            Some(greeting_node::Body::Country(c)) => {
                let mut codes: Vec<String> = c.codes.iter().map(|s| s.to_uppercase()).collect();
                codes.sort();
                out.push_str(&format!("country={}", codes.join(",")));
            }
            Some(greeting_node::Body::Tenure(t)) => {
                out.push_str(&format!("tenure={}:{}", t.op, t.window_s));
            }
            Some(greeting_node::Body::ClientVersion(v)) => {
                out.push_str(&format!("version={}:{}", v.op, v.version));
            }
            Some(greeting_node::Body::Account(a)) => out.push_str(&format!("account={}", a.state)),
            Some(greeting_node::Body::Group(g)) => out.push_str(&format!("group={}", g.group)),
            Some(greeting_node::Body::Os(o)) => out.push_str(&format!("os={}", o.os)),
            Some(greeting_node::Body::Gate(g)) => out.push_str(&format!("gate={}", g.kind)),
            Some(greeting_node::Body::Filter(f)) => {
                out.push_str(&format!("filter={}", f.unknown_becomes));
            }
            Some(greeting_node::Body::Snippet(s)) => {
                out.push_str(&format!(
                    "snippet={}\u{1f}{}\u{1f}{}",
                    s.name, s.html, s.plain
                ));
            }
            Some(greeting_node::Body::Greet(g)) => {
                out.push_str(&format!(
                    "greet={}\u{1f}{}\u{1f}{}",
                    g.html, g.plain, g.once
                ));
            }
            None => out.push_str("empty"),
        }
        out.push('\n');
    }

    let mut edges: Vec<String> = graph
        .edges
        .iter()
        .map(|e| format!("{}>{}:{}", e.from, e.to, e.port))
        .collect();
    edges.sort();
    for edge in edges {
        out.push_str(&edge);
        out.push('\n');
    }
    out
}

/// Truncated SHA-256 over [`canonical`].
pub fn digest(graph: &Greeting) -> Vec<u8> {
    let hash = Sha256::digest(canonical(graph).as_bytes());
    hash[..DIGEST_BYTES].to_vec()
}

/// What a *single greeting* is dismissed against.
///
/// Per greeting rather than per document, and that is the whole of "show it
/// again only when it changed": an operator who fixes a typo in one greeting
/// must not re-prompt everybody who was shown a different one, and one who
/// rewires conditions without touching the words must not re-prompt anybody at
/// all. Snippets are folded in, because a greeting whose appended paragraph
/// changed is a greeting whose text changed.
pub fn greet_digest(graph: &Greeting, greet: &GreetingNode) -> Vec<u8> {
    let mut form = String::new();
    if let Some(greeting_node::Body::Greet(body)) = greet.body.as_ref() {
        form.push_str(&format!(
            "{}\u{1f}{}\u{1f}{}\n",
            body.html, body.plain, body.once
        ));
    }
    for snippet in snippets(graph, &greet.id) {
        form.push_str(&format!("{}\u{1f}{}\n", snippet.html, snippet.plain));
    }
    Sha256::digest(form.as_bytes())[..DIGEST_BYTES].to_vec()
}

/* -- JSON ------------------------------------------------------------------ */

/// The document's JSON form, as the operator API speaks it.
///
/// Shaped to match the editor's own model rather than the proto, so the client
/// sends what it already holds and the server does the translating. Three
/// places they differ, and each is deliberate:
///
/// * a version is the string an operator typed (`"1.5.0"`), never the packed
///   integer. Encoding it is exactly the mistake a hand-written literal makes -
///   `handshake.rs:53` records one that forgot the patch shift and decoded to
///   something else entirely - so it happens once, here, in Rust;
/// * a tenure window is seconds, because the editor's dropdown labels are
///   English and a server should not be parsing "1 month";
/// * a snippet or greeting carries one `body`, which becomes the plain form.
///   The markup half exists on the wire for servers with `allow_html` on, and
///   nothing authors it yet.
mod json {
    use super::{GreetingEdge, GreetingNode, GreetingPort, greeting_node};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub(super) struct Doc {
        #[serde(default)]
        pub(super) enabled: bool,
        #[serde(default)]
        pub(super) nodes: Vec<Node>,
        #[serde(default)]
        pub(super) edges: Vec<Edge>,
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct Node {
        pub(super) id: String,
        #[serde(default)]
        pub(super) x: i32,
        #[serde(default)]
        pub(super) y: i32,
        #[serde(flatten)]
        pub(super) body: Body,
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct Edge {
        pub(super) id: String,
        pub(super) from: String,
        pub(super) to: String,
        pub(super) port: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "kind")]
    pub(super) enum Body {
        #[serde(rename = "country")]
        Country { codes: Vec<String> },
        #[serde(rename = "tenure")]
        Tenure {
            op: String,
            #[serde(rename = "windowSeconds")]
            window_seconds: u64,
        },
        #[serde(rename = "clientVersion")]
        ClientVersion { op: String, version: String },
        #[serde(rename = "account")]
        Account { state: String },
        #[serde(rename = "group")]
        Group { group: String },
        #[serde(rename = "os")]
        Os { os: String },
        #[serde(rename = "gate")]
        Gate { gate: String },
        #[serde(rename = "filter")]
        Filter {
            #[serde(rename = "unknownAs")]
            unknown_as: String,
        },
        #[serde(rename = "text")]
        Text {
            name: String,
            body: String,
            /// The markup half, carried through untouched.
            ///
            /// Nothing authors it yet - the editor writes plain text - but a
            /// graph that has it must not lose it merely because somebody
            /// opened the canvas and pressed save.
            #[serde(default, skip_serializing_if = "String::is_empty")]
            html: String,
        },
        #[serde(rename = "greeting")]
        Greeting {
            body: String,
            once: bool,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            html: String,
        },
    }

    /// `major.minor.patch` in the packing `Version.version_v2` uses.
    pub(super) fn encode_version(text: &str) -> Option<u64> {
        let mut parts = text.trim().split('.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor: u64 = parts.next().unwrap_or("0").parse().ok()?;
        let patch: u64 = parts.next().unwrap_or("0").parse().ok()?;
        if parts.next().is_some() || major > 0xffff || minor > 0xffff || patch > 0xffff {
            return None;
        }
        Some((major << 48) | (minor << 32) | (patch << 16))
    }

    /// The inverse, so an operator reads back what they typed.
    pub(super) fn decode_version(packed: u64) -> String {
        let major = (packed >> 48) & 0xffff;
        let minor = (packed >> 32) & 0xffff;
        let patch = (packed >> 16) & 0xffff;
        format!("{major}.{minor}.{patch}")
    }

    pub(super) fn port_name(port: i32) -> &'static str {
        match GreetingPort::try_from(port) {
            Ok(GreetingPort::A) => "a",
            Ok(GreetingPort::B) => "b",
            Ok(GreetingPort::When) => "when",
            Ok(GreetingPort::Plus) => "plus",
            Err(_) => "a",
        }
    }

    pub(super) fn port_of(name: &str) -> Option<GreetingPort> {
        match name {
            "a" => Some(GreetingPort::A),
            "b" => Some(GreetingPort::B),
            "when" => Some(GreetingPort::When),
            "plus" => Some(GreetingPort::Plus),
            _ => None,
        }
    }

    pub(super) fn from_node(node: &GreetingNode) -> Option<Node> {
        use greeting_node::Body as P;
        let body = match node.body.as_ref()? {
            P::Country(c) => Body::Country {
                codes: c.codes.clone(),
            },
            P::Tenure(t) => Body::Tenure {
                op: match greeting_node::tenure::Op::try_from(t.op) {
                    Ok(greeting_node::tenure::Op::JoinedMoreThan) => "more".to_owned(),
                    _ => "less".to_owned(),
                },
                window_seconds: t.window_s,
            },
            P::ClientVersion(v) => Body::ClientVersion {
                op: match greeting_node::client_version::Op::try_from(v.op) {
                    Ok(greeting_node::client_version::Op::Le) => "<=".to_owned(),
                    Ok(greeting_node::client_version::Op::Eq) => "=".to_owned(),
                    Ok(greeting_node::client_version::Op::Ge) => ">=".to_owned(),
                    Ok(greeting_node::client_version::Op::Gt) => ">".to_owned(),
                    _ => "<".to_owned(),
                },
                version: decode_version(v.version),
            },
            P::Account(a) => Body::Account {
                state: match greeting_node::account_is::State::try_from(a.state) {
                    Ok(greeting_node::account_is::State::Registered) => "registered".to_owned(),
                    Ok(greeting_node::account_is::State::StrongCert) => {
                        "strong certificate".to_owned()
                    }
                    _ => "guest".to_owned(),
                },
            },
            P::Group(g) => Body::Group {
                group: g.group.clone(),
            },
            P::Os(o) => Body::Os {
                os: match greeting_node::operating_system::Os::try_from(o.os) {
                    Ok(greeting_node::operating_system::Os::Macos) => "macOS".to_owned(),
                    Ok(greeting_node::operating_system::Os::Linux) => "Linux".to_owned(),
                    Ok(greeting_node::operating_system::Os::Bsd) => "BSD".to_owned(),
                    Ok(greeting_node::operating_system::Os::Android) => "Android".to_owned(),
                    Ok(greeting_node::operating_system::Os::Ios) => "iOS".to_owned(),
                    _ => "Windows".to_owned(),
                },
            },
            P::Gate(g) => Body::Gate {
                gate: match greeting_node::gate::Kind::try_from(g.kind) {
                    Ok(greeting_node::gate::Kind::Or) => "or".to_owned(),
                    Ok(greeting_node::gate::Kind::Xor) => "xor".to_owned(),
                    Ok(greeting_node::gate::Kind::Nand) => "nand".to_owned(),
                    Ok(greeting_node::gate::Kind::Nor) => "nor".to_owned(),
                    Ok(greeting_node::gate::Kind::Xnor) => "xnor".to_owned(),
                    Ok(greeting_node::gate::Kind::Not) => "not".to_owned(),
                    _ => "and".to_owned(),
                },
            },
            P::Filter(f) => Body::Filter {
                unknown_as: match greeting_node::filter::Unknown::try_from(f.unknown_becomes) {
                    Ok(greeting_node::filter::Unknown::IsYes) => "yes".to_owned(),
                    _ => "no".to_owned(),
                },
            },
            P::Snippet(s) => Body::Text {
                name: s.name.clone(),
                body: s.plain.clone(),
                html: s.html.clone(),
            },
            P::Greet(g) => Body::Greeting {
                body: g.plain.clone(),
                once: g.once,
                html: g.html.clone(),
            },
        };
        Some(Node {
            id: node.id.clone(),
            x: node.x,
            y: node.y,
            body,
        })
    }

    pub(super) fn into_node(node: Node) -> Result<GreetingNode, String> {
        use greeting_node as p;
        let body = match node.body {
            Body::Country { codes } => p::Body::Country(p::CountryIn {
                codes: codes.iter().map(|c| c.to_uppercase()).collect(),
            }),
            Body::Tenure { op, window_seconds } => p::Body::Tenure(p::Tenure {
                op: if op == "more" {
                    p::tenure::Op::JoinedMoreThan as i32
                } else {
                    p::tenure::Op::JoinedLessThan as i32
                },
                window_s: window_seconds,
            }),
            Body::ClientVersion { op, version } => p::Body::ClientVersion(p::ClientVersion {
                op: match op.as_str() {
                    "<=" => p::client_version::Op::Le as i32,
                    "=" => p::client_version::Op::Eq as i32,
                    ">=" => p::client_version::Op::Ge as i32,
                    ">" => p::client_version::Op::Gt as i32,
                    _ => p::client_version::Op::Lt as i32,
                },
                version: encode_version(&version)
                    .ok_or_else(|| format!("{}: {version} is not a version", node.id))?,
            }),
            Body::Account { state } => p::Body::Account(p::AccountIs {
                state: match state.as_str() {
                    "registered" => p::account_is::State::Registered as i32,
                    "strong certificate" => p::account_is::State::StrongCert as i32,
                    _ => p::account_is::State::Guest as i32,
                },
            }),
            Body::Group { group } => p::Body::Group(p::GroupIs { group }),
            Body::Os { os } => p::Body::Os(p::OperatingSystem {
                os: match os.as_str() {
                    "macOS" => p::operating_system::Os::Macos as i32,
                    "Linux" => p::operating_system::Os::Linux as i32,
                    "BSD" => p::operating_system::Os::Bsd as i32,
                    "Android" => p::operating_system::Os::Android as i32,
                    "iOS" => p::operating_system::Os::Ios as i32,
                    _ => p::operating_system::Os::Windows as i32,
                },
            }),
            Body::Gate { gate } => p::Body::Gate(p::Gate {
                kind: match gate.as_str() {
                    "or" => p::gate::Kind::Or as i32,
                    "xor" => p::gate::Kind::Xor as i32,
                    "nand" => p::gate::Kind::Nand as i32,
                    "nor" => p::gate::Kind::Nor as i32,
                    "xnor" => p::gate::Kind::Xnor as i32,
                    "not" => p::gate::Kind::Not as i32,
                    _ => p::gate::Kind::And as i32,
                },
            }),
            Body::Filter { unknown_as } => p::Body::Filter(p::Filter {
                unknown_becomes: if unknown_as == "yes" {
                    p::filter::Unknown::IsYes as i32
                } else {
                    p::filter::Unknown::IsNo as i32
                },
            }),
            Body::Text { name, body, html } => p::Body::Snippet(p::Snippet {
                name,
                html,
                plain: body,
            }),
            Body::Greeting { body, once, html } => p::Body::Greet(p::Greet {
                html,
                plain: body,
                once,
            }),
        };
        Ok(GreetingNode {
            id: node.id,
            x: node.x,
            y: node.y,
            body: Some(body),
        })
    }

    pub(super) fn from_edge(edge: &GreetingEdge) -> Edge {
        Edge {
            id: edge.id.clone(),
            from: edge.from.clone(),
            to: edge.to.clone(),
            port: port_name(edge.port).to_owned(),
        }
    }

    pub(super) fn into_edge(edge: Edge) -> Result<GreetingEdge, String> {
        let port = port_of(&edge.port)
            .ok_or_else(|| format!("{}: {} is not a port", edge.id, edge.port))?;
        Ok(GreetingEdge {
            id: edge.id,
            from: edge.from,
            to: edge.to,
            port: i32::from(port),
        })
    }
}

/// The document as JSON, for the operator API.
#[must_use]
pub fn to_json(graph: &Greeting) -> serde_json::Value {
    let doc = json::Doc {
        enabled: graph.enabled,
        nodes: graph.nodes.iter().filter_map(json::from_node).collect(),
        edges: graph.edges.iter().map(json::from_edge).collect(),
    };
    serde_json::to_value(doc).unwrap_or(serde_json::Value::Null)
}

/// A document read back from JSON.
///
/// Shape errors only - a node that is not a node, a port that is not a port.
/// Whether the *graph* is legal is [`validate`]'s question and is asked after
/// this, because a wire cannot be checked against nodes that failed to parse.
pub fn from_json(value: &serde_json::Value) -> Result<Greeting, String> {
    let doc: json::Doc =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    let mut nodes = Vec::with_capacity(doc.nodes.len());
    for node in doc.nodes {
        nodes.push(json::into_node(node)?);
    }
    let mut edges = Vec::with_capacity(doc.edges.len());
    for edge in doc.edges {
        edges.push(json::into_edge(edge)?);
    }
    Ok(Greeting {
        enabled: doc.enabled,
        nodes,
        edges,
        ..Default::default()
    })
}

/* -- The live view --------------------------------------------------------- */

/// A service's live view of the greeting graph an operator has drawn.
///
/// Cheap to clone; every clone reads the same cache.
///
/// A subscription rather than a read per handshake, for the reason
/// `settings::Settings` gives about itself: the graph is consulted on every
/// single connect, and a `Get` per login would put `server-config` on the
/// critical path of the thing it is least allowed to slow down. It also makes
/// an edit take effect for everyone arriving next, rather than only for
/// whoever happens to log in after the cache would have expired.
#[derive(Debug, Clone)]
pub struct Greetings {
    resolver: Resolver,
    cache: Arc<RwLock<HashMap<u32, Greeting>>>,
}

impl Greetings {
    /// A view that reads through `resolver`.
    #[must_use]
    pub fn new(resolver: Resolver) -> Self {
        Self {
            resolver,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// A view backed only by `greeting`, for tests and for callers that already
    /// hold one. It never reaches the network.
    #[must_use]
    pub fn fixed(resolver: Resolver, greeting: Greeting) -> Self {
        let view = Self::new(resolver);
        view.store(greeting);
        view
    }

    /// The graph for `scope` right now.
    ///
    /// Never fails and never blocks. A caller that asks before the first
    /// document has arrived gets an empty graph, which greets nobody and falls
    /// through to the plain `welcome_text` - the same answer a server that has
    /// drawn no graph gives, and the right one to give while the answer is
    /// still unknown.
    #[must_use]
    pub fn get(&self, scope: u32) -> Greeting {
        self.cache
            .read()
            .ok()
            .and_then(|cache| cache.get(&scope).cloned())
            .unwrap_or_else(|| Greeting {
                instance: scope,
                ..Default::default()
            })
    }

    /// Fetch once, so the cache is warm as soon as this returns.
    pub async fn warm(&self, scope: u32) {
        if let Some(greeting) = self.fetch(scope).await {
            self.store(greeting);
        }
    }

    /// Spawn the subscription for every scope in `scopes`.
    pub fn watch(&self, scopes: &[u32]) -> Vec<tokio::task::JoinHandle<()>> {
        scopes
            .iter()
            .map(|scope| {
                let view = self.clone();
                let scope = *scope;
                tokio::spawn(async move { view.follow(scope).await })
            })
            .collect()
    }

    /// Fetch once, then follow the stream, forever.
    async fn follow(self, scope: u32) {
        loop {
            self.warm(scope).await;
            self.stream(scope).await;
            // Debug rather than warn, as the settings stream is: `server-config`
            // restarting is ordinary, and the graph in force did not change.
            tracing::debug!(scope, "the greeting subscription ended; retrying");
            tokio::time::sleep(RESUBSCRIBE_DELAY).await;
        }
    }

    async fn fetch(&self, scope: u32) -> Option<Greeting> {
        let transport = self.resolver.channel("server-config").ok()?;
        ServerConfigClient::new(transport)
            .get_greeting(GetRequest {
                scope: Some(Scope { instance: scope }),
            })
            .await
            .ok()
            .map(tonic::Response::into_inner)
    }

    async fn stream(&self, scope: u32) {
        let Ok(transport) = self.resolver.channel("server-config") else {
            return;
        };
        let request = GetRequest {
            scope: Some(Scope { instance: scope }),
        };
        let Ok(stream) = ServerConfigClient::new(transport)
            .watch_greeting(request)
            .await
        else {
            return;
        };
        let mut updates = stream.into_inner();
        while let Ok(Some(greeting)) = updates.message().await {
            tracing::debug!(
                scope,
                version = greeting.version,
                "the greeting graph changed underneath us"
            );
            self.store(greeting);
        }
    }

    fn store(&self, greeting: Greeting) {
        if let Ok(mut cache) = self.cache.write() {
            let _ = cache.insert(greeting.instance, greeting);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::serverconfig::GreetingEdge;
    use starling_proto_fancy::serverconfig::greeting_node::{
        AccountIs, Body, ClientVersion, CountryIn, Filter, Gate, Greet, Snippet, Tenure,
        account_is, client_version, filter, gate, tenure,
    };

    /// A version in the wire's own packing.
    ///
    /// A helper rather than a hex literal, because a literal is exactly how
    /// this goes wrong: `v(1, 5, 0)` reads like 1.5.0 and is not, and a
    /// fixture that packs one way while the wire packs another still compares
    /// equal to itself, so every test passes and the server matches nobody.
    const fn v(major: u64, minor: u64, patch: u64) -> u64 {
        (major << 48) | (minor << 32) | (patch << 16)
    }

    fn n(id: &str, body: Body) -> GreetingNode {
        GreetingNode {
            id: id.into(),
            x: 0,
            y: 0,
            body: Some(body),
        }
    }

    fn e(id: &str, from: &str, to: &str, port: GreetingPort) -> GreetingEdge {
        GreetingEdge {
            id: id.into(),
            from: from.into(),
            to: to.into(),
            port: i32::from(port),
        }
    }

    /// The canvas the operator drew in the mock: country in DE/AT/CH and joined
    /// less than a month ago, XOR version below 1.5.0 or account is guest.
    /// The conditions, each behind the filter that settles it.
    ///
    /// Split out because the fixture outgrew a screen once every condition
    /// needed a filter in front of it, which is itself worth noticing: the
    /// rule costs a node per condition, and that shows up in the drawing
    /// before it shows up here.
    fn conditions() -> Vec<GreetingNode> {
        let filter = |id: &str| {
            n(
                id,
                Body::Filter(Filter {
                    unknown_becomes: filter::Unknown::IsNo as i32,
                }),
            )
        };
        vec![
            n(
                "country",
                Body::Country(CountryIn {
                    codes: vec!["DE".into(), "AT".into(), "CH".into()],
                }),
            ),
            n(
                "tenure",
                Body::Tenure(Tenure {
                    op: tenure::Op::JoinedLessThan as i32,
                    window_s: 2_592_000,
                }),
            ),
            n(
                "version",
                Body::ClientVersion(ClientVersion {
                    op: client_version::Op::Lt as i32,
                    version: v(1, 5, 0),
                }),
            ),
            n(
                "account",
                Body::Account(AccountIs {
                    state: account_is::State::Guest as i32,
                }),
            ),
            filter("fc"),
            filter("ft"),
            filter("fv"),
            filter("fa"),
        ]
    }

    fn mock() -> Greeting {
        Greeting {
            instance: 0,
            version: 1,
            digest: Vec::new(),
            enabled: true,
            nodes: {
                let mut nodes = conditions();
                nodes.extend([
                    n(
                        "and",
                        Body::Gate(Gate {
                            kind: gate::Kind::And as i32,
                        }),
                    ),
                    n(
                        "or",
                        Body::Gate(Gate {
                            kind: gate::Kind::Or as i32,
                        }),
                    ),
                    n(
                        "xor",
                        Body::Gate(Gate {
                            kind: gate::Kind::Xor as i32,
                        }),
                    ),
                    n(
                        "rules",
                        Body::Snippet(Snippet {
                            name: "rules".into(),
                            html: "<p>House rules.</p>".into(),
                            plain: "House rules.".into(),
                        }),
                    ),
                    n(
                        "greet",
                        Body::Greet(Greet {
                            html: "<p>Willkommen!</p>".into(),
                            plain: "Willkommen!".into(),
                            once: true,
                        }),
                    ),
                ]);
                nodes
            },
            edges: vec![
                e("c1", "country", "fc", GreetingPort::A),
                e("c2", "tenure", "ft", GreetingPort::A),
                e("c3", "version", "fv", GreetingPort::A),
                e("c4", "account", "fa", GreetingPort::A),
                e("e1", "fc", "and", GreetingPort::A),
                e("e2", "ft", "and", GreetingPort::B),
                e("e3", "fv", "or", GreetingPort::A),
                e("e4", "fa", "or", GreetingPort::B),
                e("e5", "and", "xor", GreetingPort::A),
                e("e6", "or", "xor", GreetingPort::B),
                e("e7", "xor", "greet", GreetingPort::When),
                e("e8", "rules", "greet", GreetingPort::Plus),
            ],
            updated_by: String::new(),
            updated_at_ms: 0,
        }
    }

    /// A registered German newcomer on a current client: the left half of the
    /// XOR holds and the right half does not, so the XOR does.
    fn german_newcomer() -> Facts {
        Facts {
            client_version: Some(v(1, 5, 735)),
            registered: Some(true),
            strong_cert: Some(false),
            account_age_s: Some(60 * 60 * 24),
            country: Some("DE".into()),
            ..Facts::default()
        }
    }

    #[test]
    fn the_mock_graph_greets_the_person_it_was_drawn_for() {
        let graph = mock();
        let chosen = choose(&graph, &german_newcomer()).expect("a greeting");
        assert_eq!(chosen.id, "greet");
    }

    #[test]
    fn both_halves_true_is_an_xor_that_does_not_fire() {
        // A German newcomer who is *also* on an outdated client: xor cancels.
        let mut facts = german_newcomer();
        facts.client_version = Some(v(1, 4, 0));
        assert!(choose(&mock(), &facts).is_none());
    }

    #[test]
    fn a_disabled_graph_greets_nobody() {
        let graph = Greeting {
            enabled: false,
            ..mock()
        };
        assert!(choose(&graph, &german_newcomer()).is_none());
    }

    mod unknown_is_not_false {
        use super::*;

        #[test]
        fn a_missing_fact_withholds_the_greeting_rather_than_inventing_one() {
            // No geo-IP database. The AND cannot be settled and neither can the
            // XOR above it, so nothing is shown: the server falls through to
            // welcome_text rather than greeting a German who may not be one.
            let mut facts = german_newcomer();
            facts.country = None;
            assert!(choose(&mock(), &facts).is_none());
        }

        #[test]
        fn a_filtered_unknown_settles_the_expression_around_it() {
            // Country unknown, but they have been here two years: the AND is
            // false whatever the country was, so the XOR resolves on the right
            // half alone. This is the short circuit earning its keep.
            let mut facts = german_newcomer();
            facts.country = None;
            facts.account_age_s = Some(60 * 60 * 24 * 730);
            facts.client_version = Some(v(1, 4, 0));
            assert_eq!(
                choose(&mock(), &facts).map(|g| g.id.as_str()),
                Some("greet")
            );
        }

        #[test]
        fn a_peer_that_announced_no_version_is_not_an_old_client() {
            // Zero is what a peer that skipped Version has. Reading it as a
            // version makes every "older than" rule match a silent peer.
            let graph = Greeting {
                edges: vec![e("w", "version", "greet", GreetingPort::When)],
                ..mock()
            };
            let facts = Facts {
                client_version: Some(0),
                ..Facts::default()
            };
            assert!(choose(&graph, &facts).is_none());
        }

        #[test]
        fn a_guest_has_no_tenure() {
            let graph = Greeting {
                edges: vec![e("w", "tenure", "greet", GreetingPort::When)],
                ..mock()
            };
            let facts = Facts {
                registered: Some(false),
                ..Facts::default()
            };
            assert!(choose(&graph, &facts).is_none());
        }
    }

    #[test]
    fn a_stored_cycle_does_not_spin_the_login_path() {
        // validate() refuses this, so it can only arrive from storage - but the
        // walk still has to terminate, because it runs during a handshake.
        let mut graph = mock();
        graph.edges.push(e("loop", "xor", "and", GreetingPort::A));
        let _ = choose(&graph, &german_newcomer());
    }

    mod validation {
        use super::*;

        #[test]
        fn accepts_the_mock() {
            assert_eq!(validate(&mock()), Ok(()));
        }

        #[test]
        fn refuses_a_wire_to_a_node_that_is_not_there() {
            let mut graph = mock();
            graph.edges.push(e("x", "ghost", "and", GreetingPort::A));
            let problems = validate(&graph).expect_err("dangling");
            assert!(problems.iter().any(|p| p.reason == Reason::DanglingEdge));
        }

        #[test]
        fn keeps_prose_out_of_a_condition_and_conditions_out_of_plus() {
            let mut graph = mock();
            graph.edges.push(e("x", "rules", "and", GreetingPort::A));
            graph
                .edges
                .push(e("y", "country", "greet", GreetingPort::Plus));
            let problems = validate(&graph).expect_err("bad ports");
            assert_eq!(
                problems
                    .iter()
                    .filter(|p| p.reason == Reason::BadPort)
                    .count(),
                2
            );
        }

        #[test]
        fn refuses_a_loop() {
            let mut graph = mock();
            graph.edges.push(e("loop", "xor", "and", GreetingPort::A));
            let problems = validate(&graph).expect_err("cycle");
            assert!(problems.iter().any(|p| p.reason == Reason::Cycle));
        }

        #[test]
        fn refuses_a_body_nobody_should_be_sent_on_every_join() {
            let mut graph = mock();
            graph.nodes.push(n(
                "big",
                Body::Greet(Greet {
                    html: "x".repeat(MAX_BODY + 1),
                    plain: String::new(),
                    once: true,
                }),
            ));
            let problems = validate(&graph).expect_err("too long");
            assert!(
                problems
                    .iter()
                    .any(|p| matches!(p.reason, Reason::TooLong(_)))
            );
        }

        #[test]
        fn refuses_something_that_is_not_a_country_code() {
            let mut graph = mock();
            graph.nodes.push(n(
                "c2",
                Body::Country(CountryIn {
                    codes: vec!["Germany".into()],
                }),
            ));
            let problems = validate(&graph).expect_err("bad country");
            assert!(problems.iter().any(|p| p.reason == Reason::BadCountry));
        }
    }

    mod identity {
        use super::*;

        #[test]
        fn tidying_the_canvas_does_not_change_the_document() {
            let graph = mock();
            let mut moved = graph.clone();
            for node in &mut moved.nodes {
                node.x += 400;
                node.y -= 30;
            }
            assert_eq!(digest(&graph), digest(&moved));
        }

        #[test]
        fn changing_the_words_does_change_it() {
            let graph = mock();
            let mut edited = graph.clone();
            edited.nodes.retain(|node| node.id != "greet");
            edited.nodes.push(n(
                "greet",
                Body::Greet(Greet {
                    html: "<p>Hallo!</p>".into(),
                    plain: "Hallo!".into(),
                    once: true,
                }),
            ));
            assert_ne!(digest(&graph), digest(&edited));
        }

        #[test]
        fn a_greeting_is_dismissed_against_its_own_words_only() {
            let graph = mock();
            let greet = graph.nodes.iter().find(|node| node.id == "greet").unwrap();
            let before = greet_digest(&graph, greet);

            // Rewiring the conditions changes who is greeted, not what they
            // read, so nobody who already dismissed it is asked again.
            let mut rewired = graph.clone();
            rewired.edges.retain(|edge| edge.id != "e2");
            let same = greet_digest(
                &rewired,
                rewired.nodes.iter().find(|x| x.id == "greet").unwrap(),
            );
            assert_eq!(before, same);

            // Editing an appended snippet *is* a change to what they read.
            let mut resnipped = graph.clone();
            resnipped.nodes.retain(|node| node.id != "rules");
            resnipped.nodes.push(n(
                "rules",
                Body::Snippet(Snippet {
                    name: "rules".into(),
                    html: "<p>New.</p>".into(),
                    plain: "New.".into(),
                }),
            ));
            let differs = greet_digest(
                &resnipped,
                resnipped.nodes.iter().find(|x| x.id == "greet").unwrap(),
            );
            assert_ne!(before, differs);
        }
    }

    mod composing {
        use super::*;

        #[test]
        fn sends_plain_text_to_a_server_that_forbids_markup() {
            let graph = mock();
            let greet = graph.nodes.iter().find(|node| node.id == "greet").unwrap();
            let plain = compose(&graph, greet, false);
            assert_eq!(plain, "Willkommen! House rules.");
            assert!(!plain.contains('<'));
        }

        #[test]
        fn appends_the_snippets_to_the_body() {
            let graph = mock();
            let greet = graph.nodes.iter().find(|node| node.id == "greet").unwrap();
            assert_eq!(
                compose(&graph, greet, true),
                "<p>Willkommen!</p><p>House rules.</p>"
            );
        }
    }

    mod filtering {
        use super::*;
        fn filter_node(id: &str, unknown: filter::Unknown) -> GreetingNode {
            n(
                id,
                Body::Filter(Filter {
                    unknown_becomes: unknown as i32,
                }),
            )
        }

        /// Country alone into the greeting, through a filter.
        fn filtered_country(unknown: filter::Unknown) -> Greeting {
            let mut graph = mock();
            graph.nodes.push(filter_node("filter", unknown));
            graph.edges = vec![
                e("f1", "country", "filter", GreetingPort::A),
                e("f2", "filter", "greet", GreetingPort::When),
            ];
            graph
        }

        #[test]
        fn a_filter_turns_a_maybe_into_the_no_the_operator_asked_for() {
            // No geo-IP database, so the country cannot be answered. Without a
            // filter this greeting is silently withheld; with one the operator
            // has said what they want to happen.
            let facts = Facts {
                country: None,
                ..german_newcomer()
            };
            assert!(choose(&filtered_country(filter::Unknown::IsNo), &facts).is_none());
        }

        #[test]
        fn or_into_the_yes_the_operator_asked_for() {
            let facts = Facts {
                country: None,
                ..german_newcomer()
            };
            let graph = filtered_country(filter::Unknown::IsYes);
            assert_eq!(choose(&graph, &facts).map(|g| g.id.as_str()), Some("greet"));
        }

        #[test]
        fn a_settled_answer_passes_through_untouched() {
            // The filter decides nothing when the condition already has: a
            // Frenchman is not German however Unknown is resolved.
            let french = Facts {
                country: Some("FR".into()),
                ..german_newcomer()
            };
            for unknown in [filter::Unknown::IsNo, filter::Unknown::IsYes] {
                assert!(choose(&filtered_country(unknown), &french).is_none());
            }

            let german = german_newcomer();
            for unknown in [filter::Unknown::IsNo, filter::Unknown::IsYes] {
                assert_eq!(
                    choose(&filtered_country(unknown), &german).map(|g| g.id.as_str()),
                    Some("greet")
                );
            }
        }

        #[test]
        fn a_filtered_condition_is_settled_for_everything_downstream() {
            // The static answer the editor draws: a condition can be undecided,
            // and the same condition through a filter cannot.
            let graph = filtered_country(filter::Unknown::IsNo);
            assert!(may_be_unknown(&graph, "country"));
            assert!(!may_be_unknown(&graph, "filter"));
        }

        #[test]
        fn every_gate_in_a_legal_graph_is_settled() {
            // True by construction once the rule holds: a gate's inputs are
            // filters or gates, so nothing undecided can reach one.
            let graph = mock();
            for id in ["and", "or", "xor"] {
                assert!(!may_be_unknown(&graph, id));
            }
            // The condition itself is still undecidable - that is what the
            // filter below it is for.
            assert!(may_be_unknown(&graph, "country"));
        }

        #[test]
        fn a_condition_may_not_be_wired_straight_into_a_gate() {
            let mut graph = mock();
            graph.edges.push(e("raw", "country", "or", GreetingPort::A));
            let problems = validate(&graph).expect_err("undecided into a gate");
            assert!(
                problems
                    .iter()
                    .any(|p| p.reason == Reason::UndecidedIntoGate)
            );
        }

        #[test]
        fn prose_into_a_gate_is_still_just_a_bad_port() {
            // The fix here is to delete the wire, not to add a filter, so it
            // must not be reported as the undecided case.
            let mut graph = mock();
            graph.edges.push(e("bad", "rules", "or", GreetingPort::A));
            let problems = validate(&graph).expect_err("bad port");
            assert!(problems.iter().any(|p| p.reason == Reason::BadPort));
            assert!(
                !problems
                    .iter()
                    .any(|p| p.reason == Reason::UndecidedIntoGate)
            );
        }

        #[test]
        fn a_gate_reached_through_filters_is_settled_on_both_sides() {
            let mut graph = mock();
            graph.nodes.push(filter_node("fa", filter::Unknown::IsNo));
            graph.nodes.push(filter_node("fb", filter::Unknown::IsNo));
            graph.edges = vec![
                e("x1", "country", "fa", GreetingPort::A),
                e("x2", "fa", "and", GreetingPort::A),
                e("x3", "tenure", "and", GreetingPort::B),
            ];
            // One side filtered, the other not: still undecided.
            assert!(may_be_unknown(&graph, "and"));

            graph.edges.push(e("x4", "tenure", "fb", GreetingPort::A));
            graph.edges.retain(|edge| edge.id != "x3");
            graph.edges.push(e("x5", "fb", "and", GreetingPort::B));
            assert!(!may_be_unknown(&graph, "and"));
        }

        #[test]
        fn an_unwired_gate_input_counts_as_undecided() {
            let mut graph = mock();
            graph.edges.retain(|edge| edge.id != "e2");
            assert!(may_be_unknown(&graph, "and"));
        }

        #[test]
        fn how_unknown_resolves_is_part_of_the_document() {
            // Two graphs that differ only in what the filter does with Unknown
            // greet different people, so they must not share a digest.
            let no = filtered_country(filter::Unknown::IsNo);
            let yes = filtered_country(filter::Unknown::IsYes);
            assert_ne!(digest(&no), digest(&yes));
        }

        #[test]
        fn a_filter_is_wired_like_a_gate() {
            assert_eq!(validate(&filtered_country(filter::Unknown::IsNo)), Ok(()));

            // Prose is not a truth value, so it cannot be filtered.
            let mut graph = filtered_country(filter::Unknown::IsNo);
            graph
                .edges
                .push(e("bad", "rules", "filter", GreetingPort::A));
            let problems = validate(&graph).expect_err("bad port");
            assert!(problems.iter().any(|p| p.reason == Reason::BadPort));
        }
    }

    mod json_form {
        use super::*;

        #[test]
        fn a_graph_survives_the_round_trip_the_editor_makes() {
            // The operator API's whole contract: what the editor sends is what
            // comes back, so a save followed by a reload is not an edit.
            let before = mock();
            let after = from_json(&to_json(&before)).expect("valid");

            assert_eq!(after.enabled, before.enabled);
            assert_eq!(after.nodes.len(), before.nodes.len());
            assert_eq!(after.edges.len(), before.edges.len());
            // The digest is taken over meaning, not over layout or ids, so an
            // unchanged graph must hash the same after a trip through JSON.
            assert_eq!(digest(&after), digest(&before));
        }

        #[test]
        fn a_version_reads_back_as_the_operator_typed_it() {
            // Packing is where a hand-written literal goes wrong - one that
            // forgets the patch shift decodes to a different version and the
            // handshake completes either way - so it is done once, in Rust.
            let packed = json::encode_version("1.5.0").expect("a version");
            assert_eq!(packed, v(1, 5, 0));
            assert_eq!(json::decode_version(packed), "1.5.0");
            assert_eq!(json::encode_version("1.5.735"), Some(v(1, 5, 735)));
        }

        #[test]
        fn a_short_version_is_read_as_zeroed_rather_than_refused() {
            assert_eq!(json::encode_version("2"), Some(v(2, 0, 0)));
            assert_eq!(json::encode_version("1.4"), Some(v(1, 4, 0)));
        }

        #[test]
        fn something_that_is_not_a_version_is_refused_by_name() {
            // Named, because the operator has to know which node to fix.
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [{
                    "id": "v1", "x": 0, "y": 0,
                    "kind": "clientVersion", "op": "<", "version": "one point five"
                }],
                "edges": []
            });
            let error = from_json(&json).expect_err("refused");
            assert!(error.contains("v1"), "{error}");
        }

        #[test]
        fn a_wire_to_a_port_that_does_not_exist_is_refused() {
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [],
                "edges": [{ "id": "e9", "from": "a", "to": "b", "port": "sideways" }]
            });
            let error = from_json(&json).expect_err("refused");
            assert!(error.contains("e9"), "{error}");
        }

        #[test]
        fn country_codes_are_stored_upper_case_however_they_arrive() {
            // The evaluator compares case-insensitively, but the digest does
            // not, and two spellings of the same rule must not look like two
            // different documents.
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [{
                    "id": "c", "x": 0, "y": 0,
                    "kind": "country", "codes": ["de", "At"]
                }],
                "edges": []
            });
            let graph = from_json(&json).expect("valid");
            let Some(Body::Country(country)) = graph.nodes[0].body.as_ref() else {
                panic!("a country node");
            };
            assert_eq!(country.codes, vec!["DE".to_owned(), "AT".to_owned()]);
        }

        #[test]
        fn the_shape_the_editor_sends_is_the_shape_that_is_accepted() {
            // Written out rather than round-tripped, so this fails if the
            // field names drift away from the client's model.
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [
                    { "id": "t", "x": 30, "y": 34, "kind": "tenure",
                      "op": "less", "windowSeconds": 2592000 },
                    { "id": "f", "x": 268, "y": 34, "kind": "filter", "unknownAs": "no" },
                    { "id": "g", "x": 500, "y": 0, "kind": "greeting",
                      "body": "Welcome.", "once": true }
                ],
                "edges": [
                    { "id": "e1", "from": "t", "to": "f", "port": "a" },
                    { "id": "e2", "from": "f", "to": "g", "port": "when" }
                ]
            });
            let graph = from_json(&json).expect("valid");
            assert_eq!(validate(&graph), Ok(()));
            // And it greets somebody: a newcomer, since the filter settles the
            // tenure question either way.
            let facts = Facts {
                account_age_s: Some(60),
                ..Facts::default()
            };
            assert!(choose(&graph, &facts).is_some());
        }
    }
}
