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
    GetRequest, Greeting, GreetingAnnotation, GreetingDesign, GreetingEdge, GreetingNode,
    GreetingPort, design_part, greeting_annotation, greeting_node,
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
/// Bands one welcome screen may have. Past this it is not a screen.
pub const MAX_SECTIONS: usize = 24;
/// Cards in one row. Past four they are unreadable on any client's width.
pub const MAX_CARDS: usize = 6;
/// Characters in one line of a section - a title, a label, an eyebrow.
pub const MAX_LINE: usize = 160;
/// Inputs one design may declare. Past this a node is not a node.
pub const MAX_INPUTS: usize = 16;
/// Parts one compiled target may hold. Bounds the assembly at handshake.
pub const MAX_PARTS: usize = 128;
/// Characters of the editor's own block tree.
///
/// Never parsed here - it is what the editor reopens - but it is stored, and a
/// document nobody bounded is a document somebody eventually posts a megabyte
/// of.
pub const MAX_TREE: usize = 64_000;
/// Notes one canvas may carry. Past this an operator is not annotating a graph.
pub const MAX_ANNOTATIONS: usize = 64;
/// Characters in one note.
///
/// Shorter than a greeting body on purpose: this is read on the canvas by the
/// next operator, and it costs no join, so there is no reason for it to be
/// generous and every reason for a note to stay a note.
pub const MAX_ANNOTATION_TEXT: usize = 512;

/// What is wrong with one greeting's body, if anything.
///
/// Its own function rather than another arm of [`validate`]'s match: a
/// greeting carries three representations and a screen of bands, so checking
/// one is a page of its own and inlining it buried the other nine node kinds.
fn greet_problems(id: &str, greet: &greeting_node::Greet) -> Vec<Invalid> {
    let mut problems = Vec::new();
    let bad = |reason: Reason| Invalid {
        node: id.to_owned(),
        reason,
    };

    for body in [&greet.html, &greet.plain] {
        if body.chars().count() > MAX_BODY {
            problems.push(bad(Reason::TooLong(body.chars().count())));
        }
    }
    if greet.sections.len() > MAX_SECTIONS {
        problems.push(bad(Reason::TooLarge(greet.sections.len())));
    }
    for section in &greet.sections {
        problems.extend(section_problems(id, section));
    }
    if let Some(design) = greet.design.as_ref() {
        problems.extend(design_problems(id, design));
    }
    problems
}

/// What is wrong with one design.
fn design_problems(id: &str, design: &GreetingDesign) -> Vec<Invalid> {
    let mut problems = Vec::new();
    let bad = |reason: Reason| Invalid {
        node: id.to_owned(),
        reason,
    };

    if design.slots.len() + design.conditions.len() > MAX_INPUTS {
        problems.push(bad(Reason::TooLarge(
            design.slots.len() + design.conditions.len(),
        )));
    }
    if design.tree.chars().count() > MAX_TREE {
        problems.push(bad(Reason::TooLong(design.tree.chars().count())));
    }

    // A name is what a slot and a gate refer to, so two inputs sharing one is a
    // reference with two answers.
    let mut names = HashSet::new();
    for input in design.slots.iter().chain(design.conditions.iter()) {
        if !names.insert(input.name.as_str()) {
            problems.push(bad(Reason::DuplicateId));
        }
        if input.name.chars().count() > MAX_NAME {
            problems.push(bad(Reason::TooLong(input.name.chars().count())));
        }
    }

    for compiled in &design.compiled {
        if compiled.parts.len() > MAX_PARTS {
            problems.push(bad(Reason::TooLarge(compiled.parts.len())));
        }
        let total: usize = compiled
            .parts
            .iter()
            .map(|part| match part.body.as_ref() {
                Some(design_part::Body::Literal(text)) => text.chars().count(),
                _ => 0,
            })
            .sum();
        // The assembled greeting is what is paid for on every join, so the cap
        // is on the sum rather than on any one part.
        if total > MAX_BODY {
            problems.push(bad(Reason::TooLong(total)));
        }
        for part in &compiled.parts {
            // A part naming an input the design does not declare would be
            // dropped or substituted with nothing, silently, on every join.
            if !part.visible_if.is_empty() && !names.contains(part.visible_if.as_str()) {
                problems.push(bad(Reason::UnknownInput));
            }
            if let Some(design_part::Body::Slot(name)) = part.body.as_ref()
                && !names.contains(name.as_str())
            {
                problems.push(bad(Reason::UnknownInput));
            }
        }
    }
    problems
}

/// What is wrong with one band of a welcome screen.
fn section_problems(id: &str, section: &greeting_node::Section) -> Vec<Invalid> {
    let mut problems = Vec::new();
    let bad = |reason: Reason| Invalid {
        node: id.to_owned(),
        reason,
    };

    if section.cards.len() > MAX_CARDS {
        problems.push(bad(Reason::TooLarge(section.cards.len())));
    }
    if section.html.chars().count() > MAX_BODY {
        problems.push(bad(Reason::TooLong(section.html.chars().count())));
    }

    let lines = [&section.title, &section.subtitle, &section.glyph]
        .into_iter()
        .chain(
            section
                .cards
                .iter()
                .flat_map(|card| [&card.eyebrow, &card.label]),
        );
    problems.extend(
        lines
            .filter(|line| line.chars().count() > MAX_LINE)
            .map(|line| bad(Reason::TooLong(line.chars().count()))),
    );

    // Refused rather than stripped on the way out: a button pointing at
    // `javascript:` is a thing an operator has to be told about, and a client
    // that silently dropped it would leave a dead button on everybody's
    // welcome screen.
    problems.extend(
        [&section.url]
            .into_iter()
            .chain(section.cards.iter().map(|card| &card.url))
            .filter(|url| !url.is_empty() && !is_web_url(url))
            .map(|_| bad(Reason::BadUrl)),
    );
    problems
}

/// Whether a link is one a client will follow.
///
/// http(s) and nothing else, checked at write time. Every other scheme a URL
/// bar accepts - `javascript:`, `data:`, `file:` - is either an attack or a
/// button that does nothing on the platform it is read on.
fn is_web_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

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
    /// A link that is not `http://` or `https://`.
    BadUrl,
    /// A slot or a gate naming an input the design does not declare.
    UnknownInput,
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
    /// `Version.fancy_version` as the peer announced it. Zero is a stock
    /// Mumble client, which is a fact rather than an absence - see
    /// `GreetingNode.FancyVersion`.
    pub fancy_version: Option<u64>,
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
        Body::FancyVersion(v) => match facts.fancy_version {
            None => Truth::Unknown,
            // Zero is not a version here, it is *stock Mumble* - the same
            // reading `pending.fancy_version != 0` gets everywhere else in the
            // server. So it settles as a no, to every op: a client that is not
            // the fork's is not an older one either, and answering Unknown
            // would put every rule about the fork behind a filter that most
            // operators would resolve the wrong way round.
            Some(0) => Truth::No,
            Some(here) => match greeting_node::fancy_version::Op::try_from(v.op) {
                Ok(op) => Truth::of(match op {
                    greeting_node::fancy_version::Op::Lt => here < v.version,
                    greeting_node::fancy_version::Op::Le => here <= v.version,
                    greeting_node::fancy_version::Op::Eq => here == v.version,
                    greeting_node::fancy_version::Op::Ge => here >= v.version,
                    greeting_node::fancy_version::Op::Gt => here > v.version,
                    // Reached only past the zero above, so being here is
                    // already the answer: this peer runs the fork.
                    greeting_node::fancy_version::Op::Any => true,
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

/* -- Assembling a design --------------------------------------------------- */

/// The first Mumble whose markup is not the Qt subset.
///
/// `(major << 48) | (minor << 32) | (patch << 16)`, which is `version_v2`'s own
/// packing - the same one a `ClientVersion` condition compares in.
const QT_UNTIL: u64 = (1 << 48) | (6 << 32);

/// Which of a design's compiled targets this peer is sent.
///
/// The set of targets is the editor's; this is the only place the server picks
/// between them, and every rule here is a limit of the *reader* rather than a
/// preference:
///
/// * `plain` when the server forbids markup. A client with `allow_html` off
///   renders tags literally, which turns a greeting into what looks like a
///   broken server - the same reason [`compose`] has a plain half at all.
/// * `rich` for the fork, whose sanitiser drops any `<img>` that is not a data
///   URL, so a design's pictures cannot reach it as markup.
/// * `qt` for stock Mumble 1.5 and older, which draws a subset of HTML 4.
/// * `html` for anything newer.
///
/// A peer that announced no version is read as *old*, not as new: `qt` is the
/// narrower markup and it still renders in a client that understands more,
/// while the other way round leaves somebody reading tags.
#[must_use]
pub fn target_for(facts: &Facts, allow_html: bool) -> &'static str {
    if !allow_html {
        return "plain";
    }
    // Zero is stock Mumble rather than an absence, which is what it means
    // everywhere else the fork's version is read.
    if facts.fancy_version.is_some_and(|version| version != 0) {
        return "rich";
    }
    if facts
        .client_version
        .is_none_or(|version| version < QT_UNTIL)
    {
        return "qt";
    }
    "html"
}

/// What separates one part from the next.
///
/// `JOIN` in the editor's `compile.ts`, which is what generated the parts:
/// every markup part is a table row or a block that closes itself, so they need
/// nothing between them, and text has nothing to close so its separation has to
/// be real.
fn separator(target: &str) -> &'static str {
    if target == "plain" { "\n\n" } else { "" }
}

/// The node wired into `greet`'s design input named `name`.
///
/// By name rather than by position: a design's ports are its declared inputs,
/// and an index would re-point every wire the moment somebody reordered them.
fn wired<'a>(graph: &'a Greeting, greet: &str, name: &str) -> Option<&'a GreetingNode> {
    let edge = graph
        .edges
        .iter()
        .find(|e| e.to == greet && e.port == i32::from(GreetingPort::Input) && e.input == name)?;
    node(graph, &edge.from)
}

/// Whether the condition wired to the input named `name` holds.
fn input_truth(graph: &Greeting, greet: &str, name: &str, facts: &Facts) -> Truth {
    wired(graph, greet, name).map_or(Truth::Unknown, |src| {
        truth(graph, &src.id, facts, &mut HashSet::new())
    })
}

/// The snippet wired into a slot, in the form that target reads.
///
/// A snippet carries markup and text and nothing target-specific, so `qt` is
/// sent the markup: Qt keeps the words inside a tag it does not know, which is
/// what the editor's own `qtSafe` does to the preview. Doing better would cost
/// an HTML parser on the login path and a second copy of that sanitiser to keep
/// in step with it, to end at the same words.
///
/// The plain half is the fallback in every target, exactly as it is in
/// [`compose`]: a snippet written as text is still what the operator wants
/// said.
fn slot_body(graph: &Greeting, greet: &str, name: &str, target: &str) -> String {
    let Some(source) = wired(graph, greet, name) else {
        return String::new();
    };
    let Some(greeting_node::Body::Snippet(snippet)) = source.body.as_ref() else {
        return String::new();
    };
    if target != "plain" && !snippet.html.is_empty() {
        snippet.html.trim().to_owned()
    } else {
        snippet.plain.trim().to_owned()
    }
}

/// The greeting `greet` reads as for this peer.
///
/// [`compose`] is the greeting a peer got before designs existed and remains
/// the answer for every greeting that has no design; this is the walk over the
/// parts the editor compiled, which is where a design becomes one string.
///
/// The walk is a loop over a list on purpose. All the layout happened in the
/// editor at save time, and the only two things it could not know then are
/// resolved here: which gated parts are on for *this* peer, and what is wired
/// into each slot. Nothing here parses markup, and nothing here lays anything
/// out - which is the whole reason the compiled form is a list of parts rather
/// than a document.
#[must_use]
pub fn assemble(graph: &Greeting, greet: &GreetingNode, facts: &Facts, allow_html: bool) -> String {
    let Some(greeting_node::Body::Greet(body)) = greet.body.as_ref() else {
        return String::new();
    };
    let Some(design) = body.design.as_ref() else {
        return compose(graph, greet, allow_html);
    };
    let target = target_for(facts, allow_html);
    let Some(assembled) = assemble_target(graph, greet, facts, target) else {
        // A design with nothing compiled for this target has nothing to say to
        // this peer, and the greeting's own halves are what it said before the
        // design was drawn. Falling back is what makes a half-migrated document
        // safe to store.
        return compose(graph, greet, allow_html);
    };
    let _ = design;
    assembled
}

/// The same walk, for a target named outright rather than derived from a peer.
///
/// Split out because a Fancy client is sent a *different document* - markup
/// naming pictures, which no string target can carry - and choosing it is not
/// something [`target_for`] can do: that function answers "which string does
/// this peer read", and this one is asked after something else has already
/// decided the peer is getting bytes instead.
///
/// `None` where the design has nothing compiled under that name, which is what
/// makes a half-migrated document safe to store: the caller falls back to what
/// the greeting said before anybody drew a sheet.
#[must_use]
pub fn assemble_target(
    graph: &Greeting,
    greet: &GreetingNode,
    facts: &Facts,
    target: &str,
) -> Option<String> {
    let greeting_node::Body::Greet(body) = greet.body.as_ref()? else {
        return None;
    };
    let design = body.design.as_ref()?;
    let compiled = design.compiled.iter().find(|c| c.target == target)?;

    let mut pieces = Vec::new();
    // Bounded rather than trusted: [`validate`] refuses a longer list when it is
    // written, but this walks a *stored* document - one saved before a cap
    // existed, or by something other than this server - and it walks it on the
    // login path.
    for part in compiled.parts.iter().take(MAX_PARTS) {
        // A part gated on a condition the server cannot settle is dropped.
        // Validation already refuses an input fed by anything but a filter or a
        // gate, so reaching Unknown here means a document that predates that
        // rule - and a line shown for a reason nobody could establish is the
        // one failure a gate exists to prevent.
        if !part.visible_if.is_empty()
            && input_truth(graph, &greet.id, &part.visible_if, facts) != Truth::Yes
        {
            continue;
        }
        let piece = match part.body.as_ref() {
            Some(design_part::Body::Literal(text)) => text.clone(),
            Some(design_part::Body::Slot(name)) => slot_body(graph, &greet.id, name, target),
            None => String::new(),
        };
        if !piece.trim().is_empty() {
            pieces.push(piece);
        }
    }
    Some(pieces.join(separator(target)))
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
                problems.extend(greet_problems(&n.id, g));
            }
            Some(_) => {}
        }
    }

    if graph.annotations.len() > MAX_ANNOTATIONS {
        problems.push(bad("", Reason::TooLarge(graph.annotations.len())));
    }
    let mut annotation_ids = HashSet::new();
    for note in &graph.annotations {
        // The same id space as the nodes, because both are addressed by the
        // editor and a note that shared an id with a node would be a note the
        // canvas could delete by removing something else.
        if !annotation_ids.insert(note.id.as_str()) || ids.contains(note.id.as_str()) {
            problems.push(bad(&note.id, Reason::DuplicateId));
        }
        if note.text.chars().count() > MAX_ANNOTATION_TEXT {
            problems.push(bad(&note.id, Reason::TooLong(note.text.chars().count())));
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
            Some(greeting_node::Body::FancyVersion(v)) => {
                out.push_str(&format!("fancy={}:{}", v.op, v.version));
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
                    "greet={}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                    g.html,
                    g.plain,
                    g.once,
                    g.legacy,
                    format_args!(
                        "{}{}",
                        sections_form(&g.sections),
                        design_form(g.design.as_ref())
                    )
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

/// A screen's bands as one line, for the two digests.
///
/// Part of what is hashed, unlike layout: the bands *are* what somebody reads,
/// so a changed button is a changed greeting and "show it again" is exactly
/// what should happen.
fn sections_form(sections: &[greeting_node::Section]) -> String {
    sections
        .iter()
        .map(|section| {
            let cards = section
                .cards
                .iter()
                .map(|card| format!("{}~{}~{}", card.eyebrow, card.label, card.url))
                .collect::<Vec<_>>()
                .join("|");
            format!(
                "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{cards}",
                section.kind,
                section.title,
                section.subtitle,
                section.html,
                section.url,
                section.glyph,
                section.primary,
                section.align,
                section.tone,
                section.picture,
                section.compact,
            )
        })
        .collect::<Vec<_>>()
        .join("\u{1e}")
}

/// A design as one line, for the two digests.
///
/// The *compiled* parts, not the block tree: what somebody reads is the parts,
/// and a tree that moved a block two pixels without changing a word would
/// otherwise re-prompt everybody who had already dismissed the greeting.
fn design_form(design: Option<&GreetingDesign>) -> String {
    let Some(design) = design else {
        return String::new();
    };
    design
        .compiled
        .iter()
        .map(|target| {
            let parts = target
                .parts
                .iter()
                .map(|part| {
                    let body = match part.body.as_ref() {
                        Some(design_part::Body::Literal(text)) => format!("L{text}"),
                        Some(design_part::Body::Slot(name)) => format!("S{name}"),
                        None => String::new(),
                    };
                    format!("{}~{body}", part.visible_if)
                })
                .collect::<Vec<_>>()
                .join("|");
            format!("{}:{parts}", target.target)
        })
        .collect::<Vec<_>>()
        .join("\u{1d}")
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
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\n",
            body.html,
            body.plain,
            body.once,
            body.legacy,
            format_args!(
                "{}{}",
                sections_form(&body.sections),
                design_form(body.design.as_ref())
            )
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
    use super::{
        GreetingAnnotation, GreetingEdge, GreetingNode, GreetingPort, greeting_annotation,
        greeting_node,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub(super) struct Doc {
        #[serde(default)]
        pub(super) enabled: bool,
        #[serde(default)]
        pub(super) nodes: Vec<Node>,
        #[serde(default)]
        pub(super) edges: Vec<Edge>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub(super) annotations: Vec<Annotation>,
    }

    #[derive(Serialize, Deserialize)]
    pub(super) struct Node {
        pub(super) id: String,
        #[serde(default)]
        pub(super) x: i32,
        #[serde(default)]
        pub(super) y: i32,
        /// Zero, and so absent, means the editor's default for the kind.
        #[serde(default, skip_serializing_if = "is_zero")]
        pub(super) w: u32,
        #[serde(default, skip_serializing_if = "is_zero")]
        pub(super) h: u32,
        #[serde(flatten)]
        pub(super) body: Body,
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's skip_serializing_if hands the field by reference"
    )]
    fn is_zero(value: &u32) -> bool {
        *value == 0
    }

    /// A note on the canvas, in the editor's own shape.
    #[derive(Serialize, Deserialize)]
    pub(super) struct Annotation {
        pub(super) id: String,
        #[serde(default)]
        pub(super) x: i32,
        #[serde(default)]
        pub(super) y: i32,
        #[serde(default, skip_serializing_if = "is_zero")]
        pub(super) w: u32,
        #[serde(default, skip_serializing_if = "is_zero")]
        pub(super) h: u32,
        pub(super) kind: String,
        #[serde(default)]
        pub(super) text: String,
        #[serde(default)]
        pub(super) tone: String,
    }

    /// The four notes, as the editor spells them.
    pub(super) fn annotation_kind(name: &str) -> greeting_annotation::Kind {
        match name {
            "note" => greeting_annotation::Kind::Note,
            "frame" => greeting_annotation::Kind::Frame,
            "label" => greeting_annotation::Kind::Label,
            // A kind this build does not know becomes a title rather than
            // being dropped: the text is the part somebody wrote, and losing
            // it to keep the shape tidy is the wrong trade.
            _ => greeting_annotation::Kind::Title,
        }
    }

    pub(super) fn annotation_kind_name(kind: i32) -> &'static str {
        match greeting_annotation::Kind::try_from(kind) {
            Ok(greeting_annotation::Kind::Note) => "note",
            Ok(greeting_annotation::Kind::Frame) => "frame",
            Ok(greeting_annotation::Kind::Label) => "label",
            _ => "title",
        }
    }

    pub(super) fn tone(name: &str) -> greeting_annotation::Tone {
        match name {
            "accent" => greeting_annotation::Tone::Accent,
            "ok" => greeting_annotation::Tone::Ok,
            "warn" => greeting_annotation::Tone::Warn,
            _ => greeting_annotation::Tone::Muted,
        }
    }

    pub(super) fn tone_name(tone: i32) -> &'static str {
        match greeting_annotation::Tone::try_from(tone) {
            Ok(greeting_annotation::Tone::Accent) => "accent",
            Ok(greeting_annotation::Tone::Ok) => "ok",
            Ok(greeting_annotation::Tone::Warn) => "warn",
            _ => "muted",
        }
    }

    pub(super) fn from_annotation(note: &GreetingAnnotation) -> Annotation {
        Annotation {
            id: note.id.clone(),
            x: note.x,
            y: note.y,
            w: note.w,
            h: note.h,
            kind: annotation_kind_name(note.kind).to_owned(),
            text: note.text.clone(),
            tone: tone_name(note.tone).to_owned(),
        }
    }

    pub(super) fn into_annotation(note: Annotation) -> GreetingAnnotation {
        GreetingAnnotation {
            id: note.id,
            x: note.x,
            y: note.y,
            w: note.w,
            h: note.h,
            kind: i32::from(annotation_kind(&note.kind)),
            text: note.text,
            tone: i32::from(tone(&note.tone)),
        }
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
        #[serde(rename = "fancyVersion")]
        FancyVersion {
            op: String,
            /// Absent for `any`, which does not compare against anything.
            #[serde(default, skip_serializing_if = "String::is_empty")]
            version: String,
        },
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
            /// The welcome screen's bands, where the operator built one.
            ///
            /// Absent for a greeting written as prose, which is most of them,
            /// so a document that has none reads exactly as it did before
            /// screens existed.
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            sections: Vec<Section>,
            /// Whether the markup half is written for Qt's rich-text subset.
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            legacy: bool,
        },
    }

    /// One band of a welcome screen, in the editor's own shape.
    #[derive(Serialize, Deserialize, Default)]
    pub(super) struct Section {
        pub(super) kind: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) title: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) subtitle: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) html: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) url: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) glyph: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub(super) cards: Vec<Card>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        pub(super) primary: bool,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) align: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) tone: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) picture: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        pub(super) compact: bool,
    }

    /// How a band sits, as both ends spell it.
    fn align(name: &str) -> greeting_node::section::Align {
        match name {
            "left" => greeting_node::section::Align::Left,
            "center" => greeting_node::section::Align::Center,
            _ => greeting_node::section::Align::Default,
        }
    }

    fn align_name(value: i32) -> &'static str {
        match greeting_node::section::Align::try_from(value) {
            Ok(greeting_node::section::Align::Left) => "left",
            Ok(greeting_node::section::Align::Center) => "center",
            _ => "",
        }
    }

    fn band_tone(name: &str) -> greeting_node::section::Tone {
        match name {
            "accent" => greeting_node::section::Tone::Accent,
            "muted" => greeting_node::section::Tone::Muted,
            "warn" => greeting_node::section::Tone::Warn,
            "danger" => greeting_node::section::Tone::Danger,
            _ => greeting_node::section::Tone::None,
        }
    }

    fn band_tone_name(value: i32) -> &'static str {
        match greeting_node::section::Tone::try_from(value) {
            Ok(greeting_node::section::Tone::Accent) => "accent",
            Ok(greeting_node::section::Tone::Muted) => "muted",
            Ok(greeting_node::section::Tone::Warn) => "warn",
            Ok(greeting_node::section::Tone::Danger) => "danger",
            _ => "",
        }
    }

    fn picture(name: &str) -> greeting_node::section::Picture {
        match name {
            "icon" => greeting_node::section::Picture::Icon,
            "banner" => greeting_node::section::Picture::Banner,
            _ => greeting_node::section::Picture::None,
        }
    }

    fn picture_name(value: i32) -> &'static str {
        match greeting_node::section::Picture::try_from(value) {
            Ok(greeting_node::section::Picture::Icon) => "icon",
            Ok(greeting_node::section::Picture::Banner) => "banner",
            _ => "",
        }
    }

    #[derive(Serialize, Deserialize, Default)]
    pub(super) struct Card {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) eyebrow: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) label: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub(super) url: String,
    }

    /// The six bands, as both ends spell them.
    fn section_kind(name: &str) -> greeting_node::section::Kind {
        match name {
            "hero" => greeting_node::section::Kind::Hero,
            "image" => greeting_node::section::Kind::Image,
            "prose" => greeting_node::section::Kind::Prose,
            "action" => greeting_node::section::Kind::Action,
            "cards" => greeting_node::section::Kind::Cards,
            "divider" => greeting_node::section::Kind::Divider,
            _ => greeting_node::section::Kind::Header,
        }
    }

    fn section_kind_name(kind: i32) -> &'static str {
        match greeting_node::section::Kind::try_from(kind) {
            Ok(greeting_node::section::Kind::Hero) => "hero",
            Ok(greeting_node::section::Kind::Image) => "image",
            Ok(greeting_node::section::Kind::Prose) => "prose",
            Ok(greeting_node::section::Kind::Action) => "action",
            Ok(greeting_node::section::Kind::Cards) => "cards",
            Ok(greeting_node::section::Kind::Divider) => "divider",
            _ => "header",
        }
    }

    pub(super) fn from_section(section: &greeting_node::Section) -> Section {
        Section {
            kind: section_kind_name(section.kind).to_owned(),
            title: section.title.clone(),
            subtitle: section.subtitle.clone(),
            html: section.html.clone(),
            url: section.url.clone(),
            glyph: section.glyph.clone(),
            cards: section
                .cards
                .iter()
                .map(|card| Card {
                    eyebrow: card.eyebrow.clone(),
                    label: card.label.clone(),
                    url: card.url.clone(),
                })
                .collect(),
            primary: section.primary,
            align: align_name(section.align).to_owned(),
            tone: band_tone_name(section.tone).to_owned(),
            picture: picture_name(section.picture).to_owned(),
            compact: section.compact,
        }
    }

    pub(super) fn into_section(section: Section) -> greeting_node::Section {
        greeting_node::Section {
            kind: i32::from(section_kind(&section.kind)),
            title: section.title,
            subtitle: section.subtitle,
            html: section.html,
            url: section.url,
            glyph: section.glyph,
            cards: section
                .cards
                .into_iter()
                .map(|card| greeting_node::section::Card {
                    eyebrow: card.eyebrow,
                    label: card.label,
                    url: card.url,
                })
                .collect(),
            primary: section.primary,
            align: i32::from(align(&section.align)),
            tone: i32::from(band_tone(&section.tone)),
            picture: i32::from(picture(&section.picture)),
            compact: section.compact,
        }
    }

    /// The fork's version condition, as the editor spells it.
    ///
    /// Its own function because of `any`: that is the one op that carries no
    /// version, so this is the only condition here whose version field is
    /// conditionally required, and inlining the two branches took `into_node`
    /// past the length anybody reads in one go.
    fn fancy_version(
        id: &str,
        op: &str,
        version: &str,
    ) -> Result<greeting_node::FancyVersion, String> {
        use greeting_node::fancy_version::Op;
        let op = match op {
            "<=" => Op::Le,
            "=" => Op::Eq,
            ">=" => Op::Ge,
            ">" => Op::Gt,
            "any" => Op::Any,
            _ => Op::Lt,
        };
        Ok(greeting_node::FancyVersion {
            op: op as i32,
            // A missing version is still refused for every other op, because a
            // comparison against zero silently matches nobody.
            version: if op == Op::Any {
                0
            } else {
                encode_version(version)
                    .ok_or_else(|| format!("{id}: {version} is not a version"))?
            },
        })
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
            // Which input it is travels in `GreetingEdge.input`, beside this.
            Ok(GreetingPort::Input) => "input",
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
            P::FancyVersion(v) => {
                let op = greeting_node::fancy_version::Op::try_from(v.op);
                Body::FancyVersion {
                    op: match op {
                        Ok(greeting_node::fancy_version::Op::Le) => "<=".to_owned(),
                        Ok(greeting_node::fancy_version::Op::Eq) => "=".to_owned(),
                        Ok(greeting_node::fancy_version::Op::Ge) => ">=".to_owned(),
                        Ok(greeting_node::fancy_version::Op::Gt) => ">".to_owned(),
                        Ok(greeting_node::fancy_version::Op::Any) => "any".to_owned(),
                        _ => "<".to_owned(),
                    },
                    // Left out rather than sent as "0.0.0": a number beside
                    // `any` reads as one the node compares against, and the
                    // next operator to open the canvas would believe it.
                    version: match op {
                        Ok(greeting_node::fancy_version::Op::Any) => String::new(),
                        _ => decode_version(v.version),
                    },
                }
            }
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
                sections: g.sections.iter().map(from_section).collect(),
                legacy: g.legacy,
            },
        };
        Some(Node {
            id: node.id.clone(),
            x: node.x,
            y: node.y,
            w: node.w,
            h: node.h,
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
            Body::FancyVersion { op, version } => {
                p::Body::FancyVersion(fancy_version(&node.id, &op, &version)?)
            }
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
            Body::Greeting {
                body,
                once,
                html,
                sections,
                legacy,
            } => p::Body::Greet(p::Greet {
                html,
                plain: body,
                once,
                sections: sections.into_iter().map(into_section).collect(),
                legacy,
                design: None,
            }),
        };
        Ok(GreetingNode {
            id: node.id,
            x: node.x,
            y: node.y,
            w: node.w,
            h: node.h,
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
            input: String::new(),
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
        annotations: graph
            .annotations
            .iter()
            .map(json::from_annotation)
            .collect(),
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
        annotations: doc
            .annotations
            .into_iter()
            .map(json::into_annotation)
            .collect(),
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
        AccountIs, Body, ClientVersion, CountryIn, FancyVersion, Filter, Gate, Greet, Snippet,
        Tenure, account_is, client_version, fancy_version, filter, gate, tenure,
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
            // Zero size: the layout is the editor's, and no test here is
            // about it.
            w: 0,
            h: 0,
            body: Some(body),
        }
    }

    fn e(id: &str, from: &str, to: &str, port: GreetingPort) -> GreetingEdge {
        GreetingEdge {
            id: id.into(),
            from: from.into(),
            to: to.into(),
            port: i32::from(port),
            input: String::new(),
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

    /// A welcome screen with one of every band worth checking.
    fn screen() -> Vec<greeting_node::Section> {
        use greeting_node::section::{Card, Kind};
        vec![
            greeting_node::Section {
                kind: i32::from(Kind::Hero),
                title: "Welcome to Magical.Rocks".into(),
                subtitle: "The home of Fancy Mumble".into(),
                glyph: "\u{1f48e}".into(),
                ..Default::default()
            },
            greeting_node::Section {
                kind: i32::from(Kind::Action),
                title: "Register your account".into(),
                subtitle: "Takes about thirty seconds.".into(),
                url: "https://magical.rocks/register".into(),
                primary: true,
                ..Default::default()
            },
            greeting_node::Section {
                kind: i32::from(Kind::Cards),
                cards: vec![Card {
                    eyebrow: "BROWSE".into(),
                    label: "Channel Viewer".into(),
                    url: "https://magical.rocks/channels".into(),
                }],
                ..Default::default()
            },
        ]
    }

    fn with_screen(sections: &[greeting_node::Section]) -> Greeting {
        let mut graph = mock();
        for node in &mut graph.nodes {
            if let Some(Body::Greet(greet)) = node.body.as_mut() {
                greet.sections = sections.to_vec();
            }
        }
        graph
    }

    fn mock() -> Greeting {
        Greeting {
            instance: 0,
            version: 1,
            digest: Vec::new(),
            enabled: true,
            annotations: Vec::new(),
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
                            sections: Vec::new(),
                            legacy: false,
                            design: None,
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

    /// The fork's own version, which is not the Mumble one and does not
    /// answer the same way when it is missing.
    mod fancy_client {
        use super::*;

        /// A graph whose only rule is `fancy` wired straight into WHEN.
        fn asking(op: fancy_version::Op, version: u64) -> Greeting {
            Greeting {
                nodes: vec![
                    n(
                        "fancy",
                        Body::FancyVersion(FancyVersion {
                            op: op as i32,
                            version,
                        }),
                    ),
                    n(
                        "greet",
                        Body::Greet(Greet {
                            plain: "Welcome.".to_owned(),
                            ..Greet::default()
                        }),
                    ),
                ],
                edges: vec![e("w", "fancy", "greet", GreetingPort::When)],
                enabled: true,
                ..Greeting::default()
            }
        }

        fn on(fancy_version: u64) -> Facts {
            Facts {
                fancy_version: Some(fancy_version),
                ..Facts::default()
            }
        }

        #[test]
        fn any_greets_every_build_of_the_fork_and_only_the_fork() {
            let graph = asking(fancy_version::Op::Any, 0);
            assert!(choose(&graph, &on(v(0, 2, 12))).is_some());
            assert!(choose(&graph, &on(v(1, 0, 0))).is_some());
            // Stock Mumble announced none.
            assert!(choose(&graph, &on(0)).is_none());
        }

        #[test]
        fn a_stock_mumble_client_is_a_definite_no_rather_than_a_maybe() {
            // The distinction that matters: a no travels through a NOT and
            // comes back as the greeting for everyone *not* on the fork,
            // where a maybe would be swallowed and that greeting would go to
            // nobody. Asked directly, and not through choose(), because
            // choose() cannot tell the two apart - both withhold.
            let graph = asking(fancy_version::Op::Any, 0);
            let truth = |facts: &Facts| truth(&graph, "fancy", facts, &mut HashSet::new());
            assert_eq!(truth(&on(0)), Truth::No);
            assert_eq!(truth(&on(v(0, 4, 0))), Truth::Yes);
            // Nothing gathered the fact at all. That is the maybe.
            assert_eq!(truth(&Facts::default()), Truth::Unknown);
        }

        #[test]
        fn an_older_build_is_the_one_told_to_update() {
            let graph = asking(fancy_version::Op::Lt, v(0, 4, 0));
            assert!(choose(&graph, &on(v(0, 2, 12))).is_some());
            assert!(choose(&graph, &on(v(0, 4, 0))).is_none());
            // And a stock client is not an old fork client: it is not one at
            // all, so it must not be handed the fork's upgrade notice.
            assert!(choose(&graph, &on(0)).is_none());
        }

        #[test]
        fn it_is_numbered_apart_from_the_mumble_version() {
            // 0.4.0 of the fork against 1.5.0 of Mumble: the same peer answers
            // opposite ways depending on which node asked, which is the whole
            // reason there are two.
            let facts = Facts {
                client_version: Some(v(1, 5, 0)),
                fancy_version: Some(v(0, 4, 0)),
                ..Facts::default()
            };
            assert!(choose(&asking(fancy_version::Op::Ge, v(1, 0, 0)), &facts).is_none());
            assert!(choose(&asking(fancy_version::Op::Ge, v(0, 3, 0)), &facts).is_some());
        }

        #[test]
        fn an_op_from_a_newer_server_goes_quiet() {
            let mut graph = asking(fancy_version::Op::Any, 0);
            graph.nodes[0].body = Some(Body::FancyVersion(FancyVersion {
                op: 99,
                version: v(0, 4, 0),
            }));
            assert!(choose(&graph, &on(v(0, 4, 0))).is_none());
        }

        #[test]
        fn the_two_version_nodes_are_different_documents() {
            let fancy = asking(fancy_version::Op::Lt, v(1, 5, 0));
            let mut mumble = fancy.clone();
            mumble.nodes[0].body = Some(Body::ClientVersion(ClientVersion {
                op: client_version::Op::Lt as i32,
                version: v(1, 5, 0),
            }));
            assert_ne!(canonical(&fancy), canonical(&mumble));
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
        fn refuses_a_button_pointing_somewhere_a_client_will_not_go() {
            // Refused rather than stripped later: a `javascript:` button is a
            // thing an operator has to be told about, and one silently dropped
            // leaves a dead button on everybody's welcome screen.
            let mut graph = mock();
            for node in &mut graph.nodes {
                if let Some(Body::Greet(greet)) = node.body.as_mut() {
                    greet.sections = vec![greeting_node::Section {
                        kind: i32::from(greeting_node::section::Kind::Action),
                        title: "Click".into(),
                        url: "javascript:alert(1)".into(),
                        ..Default::default()
                    }];
                }
            }
            let problems = validate(&graph).expect_err("a refused link");
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.reason == Reason::BadUrl)
            );
        }

        #[test]
        fn a_changed_band_is_a_changed_greeting() {
            // Unlike layout: what somebody reads is exactly what "show it
            // again" is for, so the digests move with the bands.
            let plain = mock();
            let screened = with_screen(&screen());
            assert_ne!(digest(&screened), digest(&plain));

            let greet_of = |graph: &Greeting| {
                graph
                    .nodes
                    .iter()
                    .find(|node| node.id == "greet")
                    .map(|node| greet_digest(graph, node))
            };
            assert_ne!(greet_of(&screened), greet_of(&plain));
        }

        #[test]
        fn refuses_more_bands_than_a_screen_may_have() {
            let long: Vec<_> = (0..=MAX_SECTIONS)
                .map(|_| greeting_node::Section {
                    kind: i32::from(greeting_node::section::Kind::Divider),
                    ..Default::default()
                })
                .collect();
            assert!(validate(&with_screen(&long)).is_err());
        }

        #[test]
        fn refuses_more_notes_than_a_canvas_may_carry() {
            let mut graph = mock();
            graph.annotations = (0..=MAX_ANNOTATIONS)
                .map(|index| GreetingAnnotation {
                    id: format!("note{index}"),
                    text: "x".into(),
                    ..Default::default()
                })
                .collect();
            assert!(validate(&graph).is_err());
        }

        #[test]
        fn refuses_a_note_longer_than_a_note() {
            let mut graph = mock();
            graph.annotations = vec![GreetingAnnotation {
                id: "note1".into(),
                text: "x".repeat(MAX_ANNOTATION_TEXT + 1),
                ..Default::default()
            }];
            let problems = validate(&graph).expect_err("too long");
            assert!(problems.iter().any(|problem| problem.node == "note1"));
        }

        #[test]
        fn refuses_a_note_that_shares_an_id_with_a_node() {
            // One id space, because the editor addresses both: a note sharing
            // an id with a node is a note the canvas deletes by removing
            // something else.
            let mut graph = mock();
            let taken = graph.nodes[0].id.clone();
            graph.annotations = vec![GreetingAnnotation {
                id: taken.clone(),
                text: "clash".into(),
                ..Default::default()
            }];
            let problems = validate(&graph).expect_err("duplicate");
            assert!(problems.iter().any(|problem| problem.node == taken));
        }

        #[test]
        fn a_note_is_not_part_of_what_the_digest_is_taken_over() {
            // Same reason layout is not: documenting a canvas is not editing
            // the rule, and a digest that moved with a note would re-prompt
            // every user on the server because somebody wrote themselves a
            // reminder.
            let mut annotated = mock();
            annotated.annotations = vec![GreetingAnnotation {
                id: "note1".into(),
                text: "why this is here".into(),
                ..Default::default()
            }];
            assert_eq!(digest(&annotated), digest(&mock()));
        }

        #[test]
        fn a_size_is_not_part_of_what_the_digest_is_taken_over() {
            let mut resized = mock();
            resized.nodes[0].w = 480;
            assert_eq!(digest(&resized), digest(&mock()));
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
                    sections: Vec::new(),
                    legacy: false,
                    design: None,
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
                    sections: Vec::new(),
                    legacy: false,
                    design: None,
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

    mod assembling {
        use super::*;
        use starling_proto_fancy::serverconfig::{
            CompiledTarget, DesignInput, DesignPart, GreetingDesign, design_part,
        };

        fn input(name: &str) -> DesignInput {
            DesignInput {
                id: format!("in-{name}"),
                name: name.into(),
            }
        }

        fn literal(text: &str, gate: &str) -> DesignPart {
            DesignPart {
                body: Some(design_part::Body::Literal(text.into())),
                visible_if: gate.into(),
            }
        }

        fn slot(name: &str, gate: &str) -> DesignPart {
            DesignPart {
                body: Some(design_part::Body::Slot(name.into())),
                visible_if: gate.into(),
            }
        }

        /// A wire onto one of a design's declared inputs.
        fn into_input(id: &str, from: &str, to: &str, name: &str) -> GreetingEdge {
            GreetingEdge {
                input: name.into(),
                ..e(id, from, to, GreetingPort::Input)
            }
        }

        /// One line everybody reads, one behind a condition, and a slot - in
        /// three of the four targets. `rich` is left uncompiled on purpose:
        /// that is the fallback this fixture also has to exercise.
        fn design() -> GreetingDesign {
            GreetingDesign {
                sheet_w: 720,
                slots: vec![input("rules")],
                conditions: vec![input("closed")],
                // Never read here - it is what the editor reopens.
                tree: "{}".into(),
                assets: Vec::new(),
                compiled: vec![
                    CompiledTarget {
                        target: "html".into(),
                        parts: vec![
                            literal("<p>Welcome!</p>", ""),
                            literal("<p>Registration is closed.</p>", "closed"),
                            slot("rules", ""),
                        ],
                    },
                    CompiledTarget {
                        target: "qt".into(),
                        parts: vec![literal("<b>Welcome!</b>", ""), slot("rules", "")],
                    },
                    CompiledTarget {
                        target: "plain".into(),
                        parts: vec![literal("Welcome!", ""), slot("rules", "")],
                    },
                ],
            }
        }

        /// The design above, wired to a snippet and to a settled condition.
        fn designed() -> Greeting {
            Greeting {
                enabled: true,
                nodes: vec![
                    n(
                        "greet",
                        Body::Greet(Greet {
                            html: "<i>the old body</i>".into(),
                            plain: "the old body".into(),
                            design: Some(design()),
                            ..Default::default()
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
                        "guest",
                        Body::Account(AccountIs {
                            state: account_is::State::Guest as i32,
                        }),
                    ),
                    n(
                        "fg",
                        Body::Filter(Filter {
                            unknown_becomes: filter::Unknown::IsNo as i32,
                        }),
                    ),
                ],
                edges: vec![
                    e("w1", "guest", "fg", GreetingPort::A),
                    into_input("w2", "fg", "greet", "closed"),
                    into_input("w3", "rules", "greet", "rules"),
                ],
                ..Greeting::default()
            }
        }

        fn greet_of(graph: &Greeting) -> &GreetingNode {
            graph.nodes.iter().find(|node| node.id == "greet").unwrap()
        }

        /// A stock client of `version`, registered or not.
        fn stock(version: u64, registered: bool) -> Facts {
            Facts {
                client_version: Some(version),
                fancy_version: Some(0),
                registered: Some(registered),
                ..Default::default()
            }
        }

        #[test]
        fn a_server_that_forbids_markup_is_sent_the_plain_target() {
            // Ahead of every other rule: a client that cannot render tags
            // prints them, whatever it is.
            assert_eq!(target_for(&stock(v(1, 6, 0), true), false), "plain");
            let fork = Facts {
                fancy_version: Some(42),
                ..stock(v(1, 6, 0), true)
            };
            assert_eq!(target_for(&fork, false), "plain");
        }

        #[test]
        fn the_fork_is_sent_the_rich_subset() {
            let fork = Facts {
                fancy_version: Some(42),
                ..stock(v(1, 5, 0), true)
            };
            assert_eq!(target_for(&fork, true), "rich");
        }

        #[test]
        fn mumble_1_5_and_older_are_sent_the_qt_subset() {
            assert_eq!(target_for(&stock(v(1, 5, 735), true), true), "qt");
            assert_eq!(target_for(&stock(v(1, 3, 0), true), true), "qt");
            assert_eq!(target_for(&stock(v(1, 6, 0), true), true), "html");
        }

        #[test]
        fn a_peer_that_announced_no_version_is_read_as_old() {
            // Qt is the narrower markup and renders in a client that
            // understands more; the other way round leaves somebody reading
            // tags.
            let quiet = Facts {
                client_version: None,
                ..stock(0, true)
            };
            assert_eq!(target_for(&quiet, true), "qt");
            // 1.3, in the packing every version reaches here in - a client
            // that announced only `version_v1` was widened into it as its
            // `Version` was recorded, so there is no narrow number to handle.
            assert_eq!(target_for(&stock((1 << 48) | (3 << 32), true), true), "qt");
        }

        #[test]
        fn the_parts_of_the_chosen_target_are_joined() {
            let graph = designed();
            assert_eq!(
                assemble(&graph, greet_of(&graph), &stock(v(1, 6, 0), true), true),
                "<p>Welcome!</p><p>House rules.</p>"
            );
        }

        #[test]
        fn a_gated_part_is_sent_only_to_the_peers_its_condition_holds_for() {
            let graph = designed();
            let greet = greet_of(&graph);
            let guest = assemble(&graph, greet, &stock(v(1, 6, 0), false), true);
            let member = assemble(&graph, greet, &stock(v(1, 6, 0), true), true);
            assert!(guest.contains("Registration is closed."));
            assert!(!member.contains("Registration is closed."));
        }

        #[test]
        fn a_gate_the_server_cannot_settle_hides_its_part() {
            // The condition wired straight to the input, with no filter to
            // settle it, and no fact to answer it. `validate` refuses that at
            // write time; a document stored before the rule still has to be
            // safe to walk, and hiding is the quiet failure.
            let mut graph = designed();
            graph.nodes.push(n(
                "country",
                Body::Country(CountryIn {
                    codes: vec!["DE".into()],
                }),
            ));
            graph.edges.retain(|edge| edge.id != "w2");
            graph
                .edges
                .push(into_input("w4", "country", "greet", "closed"));
            let facts = stock(v(1, 6, 0), false);
            assert_eq!(
                input_truth(&graph, "greet", "closed", &facts),
                Truth::Unknown
            );
            assert!(!assemble(&graph, greet_of(&graph), &facts, true).contains("closed"));
        }

        #[test]
        fn a_slot_is_substituted_with_the_snippet_wired_to_it() {
            let graph = designed();
            assert!(
                assemble(&graph, greet_of(&graph), &stock(v(1, 5, 0), true), true)
                    .contains("<p>House rules.</p>")
            );
        }

        #[test]
        fn an_unwired_slot_leaves_nothing_behind() {
            // Not a hole in the markup and not the input's name: a slot with
            // nothing in it is a part that is not sent.
            let mut graph = designed();
            graph.edges.retain(|edge| edge.id != "w3");
            assert_eq!(
                assemble(&graph, greet_of(&graph), &stock(v(1, 6, 0), true), true),
                "<p>Welcome!</p>"
            );
        }

        #[test]
        fn plain_takes_the_snippets_text_half_and_separates_the_parts() {
            let graph = designed();
            let text = assemble(&graph, greet_of(&graph), &stock(v(1, 6, 0), true), false);
            assert_eq!(text, "Welcome!\n\nHouse rules.");
            assert!(!text.contains('<'));
        }

        #[test]
        fn a_target_the_design_never_compiled_falls_back_to_the_greetings_own_halves() {
            // `rich` has no compiled entry, and the fork is what asks for it.
            // What it gets is what a client that knows nothing about designs
            // gets, which is what those two halves are for.
            let graph = designed();
            let fork = Facts {
                fancy_version: Some(42),
                ..stock(v(1, 5, 0), true)
            };
            assert_eq!(
                assemble(&graph, greet_of(&graph), &fork, true),
                "<i>the old body</i>"
            );
        }

        #[test]
        fn a_greeting_with_no_design_composes_exactly_as_before() {
            let graph = mock();
            let greet = graph.nodes.iter().find(|node| node.id == "greet").unwrap();
            let facts = stock(v(1, 6, 0), true);
            assert_eq!(
                assemble(&graph, greet, &facts, true),
                compose(&graph, greet, true)
            );
            assert_eq!(
                assemble(&graph, greet, &facts, false),
                compose(&graph, greet, false)
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
        fn a_welcome_screen_survives_the_round_trip() {
            let before = with_screen(&screen());
            let after = from_json(&to_json(&before)).expect("valid");

            let Some(Body::Greet(greet)) = after
                .nodes
                .iter()
                .find_map(|node| node.body.as_ref().filter(|_| node.id == "greet"))
            else {
                panic!("the greeting is still a greeting");
            };
            assert_eq!(greet.sections.len(), 3);
            assert_eq!(greet.sections[0].title, "Welcome to Magical.Rocks");
            assert_eq!(greet.sections[0].glyph, "\u{1f48e}");
            assert!(greet.sections[1].primary);
            assert_eq!(greet.sections[2].cards[0].label, "Channel Viewer");
            // And the prose halves are untouched: a client that knows nothing
            // about bands still reads the greeting.
            assert!(!greet.html.is_empty());
        }

        #[test]
        fn a_greeting_written_as_prose_carries_no_bands_at_all() {
            // So a document that never used a screen reads exactly as it did
            // before screens existed.
            let json = to_json(&mock());
            let greet = json["nodes"]
                .as_array()
                .expect("nodes")
                .iter()
                .find(|node| node["kind"] == "greeting")
                .expect("a greeting");
            assert!(greet.get("sections").is_none());
        }

        #[test]
        fn a_band_this_build_does_not_know_is_read_as_a_header() {
            let json = serde_json::json!({
                "enabled": true,
                "edges": [],
                "nodes": [{
                    "id": "g", "x": 0, "y": 0, "kind": "greeting",
                    "body": "hi", "once": true,
                    "sections": [{ "kind": "carousel", "title": "kept" }],
                }],
            });
            let graph = from_json(&json).expect("valid");
            let Some(Body::Greet(greet)) = graph.nodes[0].body.as_ref() else {
                panic!("a greeting");
            };
            assert_eq!(greet.sections[0].title, "kept");
            assert_eq!(
                greet.sections[0].kind,
                i32::from(greeting_node::section::Kind::Header)
            );
        }

        #[test]
        fn a_node_keeps_the_size_the_operator_gave_it() {
            // The editor lets a node be resized, so the size travels with the
            // position. Absent means "the editor's default for this kind",
            // which is what every node stored before the field existed has.
            let mut graph = mock();
            graph.nodes[0].w = 420;
            graph.nodes[0].h = 260;

            let json = to_json(&graph);
            assert_eq!(json["nodes"][0]["w"], 420);
            let after = from_json(&json).expect("valid");
            assert_eq!(after.nodes[0].w, 420);
            assert_eq!(after.nodes[0].h, 260);

            // A node nobody resized carries no size at all rather than a
            // nominal one: the default belongs to the editor and differs per
            // kind, so writing one down here would freeze somebody else's
            // layout decision into the document.
            assert!(json["nodes"][1].get("w").is_none());
        }

        #[test]
        fn notes_on_the_canvas_survive_the_round_trip() {
            let mut graph = mock();
            graph.annotations = vec![
                GreetingAnnotation {
                    id: "note1".into(),
                    x: 40,
                    y: 12,
                    w: 300,
                    h: 120,
                    kind: i32::from(greeting_annotation::Kind::Frame),
                    text: "Everything in here decides the German greeting".into(),
                    tone: i32::from(greeting_annotation::Tone::Warn),
                },
                GreetingAnnotation {
                    id: "note2".into(),
                    x: 0,
                    y: 0,
                    w: 0,
                    h: 0,
                    kind: i32::from(greeting_annotation::Kind::Title),
                    text: "Conditions".into(),
                    tone: i32::from(greeting_annotation::Tone::Muted),
                },
            ];

            let after = from_json(&to_json(&graph)).expect("valid");
            assert_eq!(after.annotations.len(), 2);
            assert_eq!(after.annotations[0].text, graph.annotations[0].text);
            assert_eq!(after.annotations[0].kind, graph.annotations[0].kind);
            assert_eq!(after.annotations[0].tone, graph.annotations[0].tone);
            assert_eq!(after.annotations[0].w, 300);
            assert_eq!(after.annotations[1].kind, graph.annotations[1].kind);
            validate(&after).expect("notes are not a reason to refuse a graph");
        }

        #[test]
        fn a_graph_with_no_notes_sends_no_notes_field() {
            // So a client too old to know about them reads exactly the
            // document it read before.
            let json = to_json(&mock());
            assert!(json.get("annotations").is_none());
        }

        #[test]
        fn a_note_of_an_unknown_kind_keeps_its_words() {
            // From a newer editor. The text is the part somebody wrote, and
            // losing it to keep the shape tidy is the wrong trade - unlike a
            // *node*, which is dropped, because a condition drawn wrong is
            // worse than one missing.
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [],
                "edges": [],
                "annotations": [
                    { "id": "n1", "kind": "sticky", "text": "keep me", "tone": "chartreuse" }
                ],
            });
            let graph = from_json(&json).expect("valid");
            assert_eq!(graph.annotations[0].text, "keep me");
            assert_eq!(
                graph.annotations[0].kind,
                i32::from(greeting_annotation::Kind::Title)
            );
            assert_eq!(
                graph.annotations[0].tone,
                i32::from(greeting_annotation::Tone::Muted)
            );
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
        fn the_fork_version_reads_back_as_the_operator_typed_it() {
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [{
                    "id": "fv", "x": 0, "y": 0,
                    "kind": "fancyVersion", "op": ">=", "version": "0.4.0"
                }],
                "edges": []
            });
            let graph = from_json(&json).expect("valid");
            let Some(Body::FancyVersion(fancy)) = graph.nodes[0].body.as_ref() else {
                panic!("a fancy version node");
            };
            assert_eq!(fancy.version, v(0, 4, 0));
            assert_eq!(fancy.op, fancy_version::Op::Ge as i32);
            assert_eq!(to_json(&graph)["nodes"][0]["version"], "0.4.0");
        }

        #[test]
        fn any_carries_no_version_in_either_direction() {
            // A number beside `any` is a number the node does not compare
            // against, and an editor that drew one would be lying about the
            // rule. It is also the one op that may arrive without one.
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [{ "id": "fv", "x": 0, "y": 0, "kind": "fancyVersion", "op": "any" }],
                "edges": []
            });
            let graph = from_json(&json).expect("valid");
            let out = to_json(&graph);
            assert_eq!(out["nodes"][0]["op"], "any");
            assert!(out["nodes"][0].get("version").is_none(), "{out}");
        }

        #[test]
        fn a_fork_version_that_is_not_a_version_is_refused_by_name() {
            let json = serde_json::json!({
                "enabled": true,
                "nodes": [{
                    "id": "fv", "x": 0, "y": 0,
                    "kind": "fancyVersion", "op": "<", "version": ""
                }],
                "edges": []
            });
            let error = from_json(&json).expect_err("refused");
            assert!(error.contains("fv"), "{error}");
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
