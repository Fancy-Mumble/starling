//! Which configuration keys can change without a restart, and what changed.
//!
//! `docs/CONFIGURATION.md` has always said that the deployment layer takes
//! effect "on restart" and the operational layer "immediately". That was a
//! sentence in a document: nothing in the code knew which key was which, so
//! nothing could tell an operator that the value they just edited is not the
//! value the server is running on. This is that knowledge, as data.
//!
//! # The table is a statement about *this build*, not about the plan
//!
//! A key is [`Reload::Live`] only when something in this binary actually
//! follows it. Classifying a key as live before its applier exists would be
//! worse than saying nothing: the change would be reported as applied, no
//! restart warning would be raised, and the operator would be left to discover
//! from behaviour that it had not taken effect.
//!
//! So a key moves to `Live` in the same change that teaches something to
//! follow it, never before. `docs/HOT-RELOAD-PLAN.md` §B has the target table
//! and the order the rest arrives in; today's live set is small on purpose:
//!
//! * `[instances.settings]`, re-overlaid by `server-config` and republished to
//!   every subscriber, which is the whole operational layer;
//! * the whole of `[logging]` bar its queue depth, so an incident can be
//!   investigated at `debug`, or moved to a disk with room on it, without
//!   restarting the process holding the evidence;
//! * the gateway's per-client queue bounds, so a client being disconnected for
//!   control overflow can be given a wider lane without dropping every other
//!   client to do it.
//!
//! [`Reload::NextConnection`] is the third class, for a value a live process
//! adopts but cannot retrofit onto work already in flight. Its member is
//! `gateway.control_queue`: the per-client control lane is an `mpsc` whose
//! capacity is fixed when the channel is created, so a change reaches every
//! client that connects from now on and none of the ones already connected.
//! Saying that plainly is the point -- reporting it as `Live` would have an
//! operator watching a stuck client for a change that can never arrive there.
//!
//! # Completeness
//!
//! [`TABLE`] enumerates **leaves**, not subtrees. A `runtime.**` catch-all
//! would make [`lookup`] total and the test below vacuous, so that a field
//! added to [`Config`] next year would silently inherit a classification
//! nobody chose. Instead every leaf is listed, and
//! `every_configuration_key_is_classified` fails until a new one is added
//! here. The test is the reason the table is long.

use std::collections::BTreeMap;

use crate::config::Config;

/// When a change to a key takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reload {
    /// Applied by a running process, without a restart.
    Live,
    /// Adopted for work started from now on, and not retrofitted.
    ///
    /// A client already connected keeps the value it was accepted with, because
    /// the thing it sizes was allocated then and cannot be resized. Distinct
    /// from [`Self::Live`] so an operator is not left waiting for a change to
    /// reach a session it can never reach, and from [`Self::Restart`] because
    /// no restart is needed for it to take effect.
    NextConnection,
    /// Read once at construction. The file says one thing and the running
    /// server another until it is restarted.
    Restart,
}

impl Reload {
    /// The word an operator reads in a log line.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::NextConnection => "next connection",
            Self::Restart => "restart",
        }
    }
}

/// One key whose value differs between two configurations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The dotted path, as it would be written in the file.
    pub path: String,
    /// Whether this build can apply it without a restart.
    pub class: Reload,
    /// What it was. `None` means the key was absent.
    pub from: Option<String>,
    /// What it becomes. `None` means the key is now absent.
    pub to: Option<String>,
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let from = self.from.as_deref().unwrap_or("(unset)");
        let to = self.to.as_deref().unwrap_or("(unset)");
        write!(f, "{} {from} -> {to}", self.path)
    }
}

/// What [`lookup`] answers for a path nothing in [`TABLE`] matches.
///
/// [`Reload::Restart`], because an unknown key is one nothing follows, and a
/// wrong "live" is the answer that misleads. `lookup` still reports the miss so
/// the test can fail on it.
const UNCLASSIFIED: Reload = Reload::Restart;

/// Every leaf key, and when a change to it takes effect.
///
/// Matched in order, first match wins, so a specific pattern precedes the
/// general one it would otherwise be shadowed by. `*` matches exactly one
/// path segment: a service name, a limit bucket name, or an array index.
pub const TABLE: &[(&str, Reload)] = &[
    // -- Live -------------------------------------------------------------
    //
    // The operational layer. `server-config` re-overlays these onto the
    // settings no operator has claimed and republishes to every subscriber,
    // so editing the file changes a running server exactly as the admin API
    // would (`docs/CONFIGURATION.md`, "Which wins").
    ("instances.*.settings.*", Reload::Live),
    // The whole of `[logging]` bar `queue`, applied by
    // `crate::live::follow_logging`. Raising the level is what an operator does
    // *because* something is going wrong now, and the restart that would
    // otherwise be needed destroys the state being investigated.
    ("logging.level", Reload::Live),
    ("logging.categories.*", Reload::Live),
    ("logging.console.enabled", Reload::Live),
    ("logging.file.path", Reload::Live),
    ("logging.file.max_bytes", Reload::Live),
    ("logging.file.keep", Reload::Live),
    ("logging.memory.enabled", Reload::Live),
    ("logging.memory.records", Reload::Live),
    // -- Restart ----------------------------------------------------------
    ("include.*", Reload::Restart),
    ("runtime.all_in_one", Reload::Restart),
    ("runtime.data_dir", Reload::Restart),
    // Read per use by every reader of the channel tree, through the one
    // accessor on `Resolver` (`crates/runtime/src/channel.rs`). A tree that
    // overran this limit is refused whole -- clients complete the handshake and
    // see a server with no channels -- and that is discovered on a running
    // server, from a deployment imported out of murmur with megabytes of
    // channel artwork.
    ("runtime.max_tree_message", Reload::Live),
    // The per-client queue bounds, read on every enqueue by every connection
    // (`crates/gateway/src/limits.rs`). Live because the incident that makes an
    // operator reach for `control_bytes` -- clients being disconnected for
    // control overflow on a channel tree carrying artwork -- is one a restart
    // makes worse, since the restart drops every other client too.
    ("gateway.control_bytes", Reload::Live),
    ("gateway.audio_queue", Reload::Live),
    // The control lane is an `mpsc` sized when it is created, so this one is
    // adopted by connections accepted from now on and cannot be retrofitted.
    ("gateway.control_queue", Reload::NextConnection),
    ("gateway.listen_tcp", Reload::Restart),
    ("gateway.default_deadline", Reload::Restart),
    // Retuned on every attached service's breaker, keeping the failures already
    // counted: a breaker tripping too eagerly sheds traffic nobody meant it to,
    // and one that never trips leaves callers waiting out a full deadline.
    ("gateway.breaker_failures", Reload::Live),
    ("gateway.breaker_cooldown", Reload::Live),
    // The certificate is asked for at each handshake, not held by the acceptor
    // (`crates/gateway/src/certs.rs`), so a renewal reaches the next client.
    // Every reload re-reads the pair rather than only reacting to a changed
    // path, because cert-manager renews *in place*: the filenames stay and the
    // bytes change. A connection already established keeps the certificate it
    // negotiated with, which is what TLS means.
    ("gateway.tls.cert", Reload::Live),
    ("gateway.tls.key", Reload::Live),
    // Every bucket, not just `control`: the one that ate a screen share's SDP
    // offer was `signalling`, and the operator diagnosing that has a server
    // full of clients a restart would disconnect.
    ("gateway.limits.*.rate", Reload::Live),
    ("gateway.limits.*.burst", Reload::Live),
    ("gateway.resume.enabled", Reload::Restart),
    ("gateway.resume.ring", Reload::Restart),
    ("gateway.resume.ttl", Reload::Restart),
    ("telemetry.otlp_endpoint", Reload::Restart),
    ("telemetry.metrics", Reload::Restart),
    ("telemetry.log_format", Reload::Restart),
    // `logging.queue` is the writer thread's channel depth, fixed when that
    // thread was started. Everything else in the section is live, because
    // every part of it is something an operator finds out is wrong while the
    // server is running: a full disk, a mistyped path, a rotation size far too
    // small, a filter too coarse to diagnose with.
    ("logging.queue", Reload::Restart),
    // The routing table. The gateway swaps it and reconciles its attachments,
    // so adding a service to `[services]` is the three lines
    // `docs/CONFIGURATION.md` promises and no longer also a gateway restart.
    //
    // Live *for the gateway*, which is the only reader of the table. A service
    // process reads its own `enabled` at startup and cannot un-start itself, so
    // switching one off stops the gateway routing to it and leaves the process
    // running until it is stopped -- which is the behaviour a `[services]` edit
    // can honestly deliver, and better than routing to something nobody meant
    // to be reachable.
    ("services.*.enabled", Reload::Live),
    ("services.*.tier", Reload::Live),
    ("services.*.types.*", Reload::Live),
    ("services.*.limits", Reload::Live),
    // `endpoint` stays restart-only on purpose, and it is the one key here that
    // is technically reloadable and deliberately is not. The resolver caches a
    // channel per service and never evicts it, so a re-pointed endpoint would
    // be read and not dialled; and a fleet half-way through re-pointing a
    // service -- `text` and the gateway disagreeing about where `metadata` is
    // -- is exactly the disagreement the Helm checksum annotation exists to
    // prevent (`docs/HOT-RELOAD-PLAN.md` §B4).
    ("services.*.endpoint", Reload::Restart),
    ("services.*.bind", Reload::Restart),
    ("services.*.udp_listen", Reload::Restart),
    ("services.*.listen", Reload::Restart),
    // `files` mints a signed URL per grant from all three, and follows the
    // file (`crates/services/files/src/lib.rs`). A wrong `public_url` -- the
    // wrong scheme behind a new TLS terminator, a host that moved -- hands
    // every client a URL that does not resolve, and is always found afterwards.
    //
    // `screenshare` and `voice` also read `public_url`, and copy it at build;
    // for them this is still restart-only. Classified `Live` because the
    // service that owns these keys in the shipped configuration is `files`, and
    // the two media services are tracked in `docs/HOT-RELOAD-PLAN.md`.
    ("services.*.public_url", Reload::Live),
    ("services.*.url_ttl", Reload::Live),
    ("services.*.max_upload", Reload::Live),
    ("services.*.storage.url", Reload::Restart),
    ("services.*.storage.max_connections", Reload::Restart),
    // The admin plane's authentication, rebuilt by `operator-api` on every
    // reload. The credential that most needs this is the static `token`: it has
    // no expiry and no identity, so replacing it is the only way to revoke it,
    // and a leaked admin token must stop working now rather than at the next
    // restart of the highest-privilege surface in the system. The same argument
    // covers the scope maps -- an IdP role that should no longer map to `["*"]`
    // is an authorisation withdrawn, and withdrawal that waits is not
    // withdrawal.
    ("services.*.auth.mode", Reload::Live),
    ("services.*.auth.oidc.issuer", Reload::Live),
    ("services.*.auth.oidc.audience", Reload::Live),
    ("services.*.auth.oidc.scope_claim", Reload::Live),
    ("services.*.auth.oidc.map.*.*", Reload::Live),
    ("services.*.auth.jwt.public_key", Reload::Live),
    ("services.*.auth.jwt.audience", Reload::Live),
    ("services.*.auth.jwt.scope_claim", Reload::Live),
    ("services.*.auth.mtls.client_ca", Reload::Live),
    ("services.*.auth.mtls.map.*.*", Reload::Live),
    ("services.*.auth.token.tokens.*.value_env", Reload::Live),
    ("services.*.auth.token.tokens.*.scopes.*", Reload::Live),
    ("services.*.audit.path", Reload::Restart),
    ("services.*.audit.fail_closed", Reload::Restart),
    ("services.*.webtransport.enabled", Reload::Restart),
    ("services.*.webtransport.listen", Reload::Restart),
    ("services.*.webtransport.cert", Reload::Restart),
    ("services.*.webtransport.key", Reload::Restart),
    // The one row here that is a *bag* rather than a key, and the one place
    // this table is deliberately less accurate than it could be.
    //
    // `options` is a `BTreeMap<String, String>` each service names its own keys
    // in, so the fourteen in use today have fourteen different answers:
    // `directory`'s `trust_store` and `push`'s notification switches would
    // follow the file trivially, `screenshare`'s `media_port` is a bound
    // socket, and `session-lifecycle`'s `max_users` sizes a pre-filled id pool.
    // Splitting the row is mechanical -- a service name is a literal segment,
    // so `services.directory.options.trust_store` shadows this catch-all -- but
    // each `Live` row needs its service to grow a follower first.
    //
    // Restart until then, because it is the answer that cannot mislead, and
    // because the completeness test below cannot help here: `option::<T>` reads
    // a map by string, so an option added next year is invisible to a test that
    // walks the `Config` schema. `docs/HOT-RELOAD-PLAN.md` §B5 has the per-key
    // table and argues that the services should declare their options before
    // this row is split rather than after.
    ("services.*.options.*", Reload::Restart),
    ("instances.*.id", Reload::Restart),
    ("instances.*.name", Reload::Restart),
    ("instances.*.port", Reload::Restart),
];

/// Paths whose value is a secret and must never reach a log or an API reply.
///
/// A reload diff is written to the operator log and returned by the admin
/// plane, so the value is redacted at the point it is captured rather than at
/// each place it might be printed.
const SECRETS: &[&str] = &[
    "instances.*.settings.password",
    "instances.*.settings.registry_password",
    // A DSN carries its own password: `postgres://user:secret@host/db`.
    "services.*.storage.url",
];

/// What a redacted value reads as.
const REDACTED: &str = "(redacted)";

/// When a change to `path` takes effect, or `None` if nothing classifies it.
///
/// The `None` case is a gap in [`TABLE`], not a property of the key, and the
/// test in this module is what keeps it unreachable.
#[must_use]
pub fn lookup(path: &str) -> Option<Reload> {
    TABLE
        .iter()
        .find(|(pattern, _)| matches(pattern, path))
        .map(|(_, class)| *class)
}

/// When a change to `path` takes effect.
#[must_use]
pub fn classify(path: &str) -> Reload {
    lookup(path).unwrap_or(UNCLASSIFIED)
}

/// Whether `path` names a secret, and so must be redacted before it is shown.
#[must_use]
pub fn is_secret(path: &str) -> bool {
    SECRETS.iter().any(|pattern| matches(pattern, path))
}

/// Whether `path` matches `pattern`, where `*` stands for one whole segment.
fn matches(pattern: &str, path: &str) -> bool {
    let mut expected = pattern.split('.');
    let mut actual = path.split('.');
    loop {
        match (expected.next(), actual.next()) {
            (None, None) => return true,
            (Some(segment), Some(candidate)) if segment == "*" || segment == candidate => {}
            _ => return false,
        }
    }
}

/// Every key in `config`, as a dotted path with a printable value.
///
/// Absent `Option`s and empty tables produce no key at all, which is what makes
/// "the key was not there before" distinguishable from "it was there and empty".
#[must_use]
pub fn flatten(config: &Config) -> BTreeMap<String, String> {
    let mut flat = BTreeMap::new();
    match toml::Value::try_from(config) {
        Ok(value) => walk(&value, &mut String::new(), &mut flat),
        Err(error) => {
            // Only reachable if `Config` stops serialising, which is a bug in
            // Starling rather than in anybody's file. Reported rather than
            // silently producing an empty diff that reads as "nothing changed".
            tracing::error!(%error, "the configuration could not be flattened");
        }
    }
    flat
}

fn walk(value: &toml::Value, path: &mut String, flat: &mut BTreeMap<String, String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                let mark = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk(value, path, flat);
                path.truncate(mark);
            }
        }
        toml::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let mark = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(&index.to_string());
                walk(item, path, flat);
                path.truncate(mark);
            }
        }
        scalar => {
            let shown = if is_secret(path) {
                REDACTED.to_owned()
            } else {
                scalar.to_string()
            };
            let _ = flat.insert(path.clone(), shown);
        }
    }
}

/// Every key whose value differs between `old` and `new`, classified.
///
/// A key present in one and absent in the other is a change: dropping
/// `password` from the file is a decision, and one an operator wants reported
/// with the same weight as changing it.
#[must_use]
pub fn changes(old: &Config, new: &Config) -> Vec<Change> {
    let (old, new) = (flatten(old), flatten(new));
    let mut changes = Vec::new();
    for path in old.keys().chain(new.keys()).collect::<std::collections::BTreeSet<_>>() {
        let (before, after) = (old.get(path), new.get(path));
        if before == after {
            continue;
        }
        changes.push(Change {
            path: path.clone(),
            class: classify(path),
            from: before.cloned(),
            to: after.cloned(),
        });
    }
    changes
}

/// A short, stable identifier for the whole of `config`.
///
/// Two processes reporting the same revision are running the same configuration;
/// two reporting different ones are mid-reload, which is the point of publishing
/// it (`docs/HOT-RELOAD-PLAN.md` §B4). FNV-1a over the flattened form rather
/// than [`std::hash::DefaultHasher`], whose output is explicitly not stable
/// across Rust releases, so a fleet built from one source would still disagree
/// after a toolchain bump.
///
/// Not a security boundary: it detects difference, not tampering. Secrets are
/// redacted before they reach it, so two configurations differing only in a
/// password share a revision -- which is the right trade for a value that is
/// printed in logs and served over the admin plane.
#[must_use]
pub fn revision(config: &Config) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };
    for (path, value) in flatten(config) {
        eat(path.as_bytes());
        eat(b"=");
        eat(value.as_bytes());
        eat(b"\n");
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn defaults() -> Config {
        Config::with_defaults(Path::new("/run/starling"))
    }

    #[test]
    fn every_configuration_key_is_classified() {
        // The point of the table. A field added to `Config` without a decision
        // about when it takes effect would otherwise inherit one silently, and
        // an operator would be told "restart" or "live" by accident.
        let missing: Vec<_> = flatten(&defaults())
            .into_keys()
            .filter(|path| lookup(path).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "unclassified keys; add them to TABLE with a deliberate class: {missing:#?}"
        );
    }

    #[test]
    fn every_documented_key_is_classified() {
        // `examples/reference.toml` is the documented surface, and carries keys
        // the defaults leave absent because they are `Option::None` -- every
        // `[services.*.auth]` block, the whole of `[services.*.webtransport]`.
        // Without this the `Option` half of the schema would go unclassified.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/reference.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let config: Config = toml::from_str(&text)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));

        let missing: Vec<_> = flatten(&config)
            .into_keys()
            .filter(|path| lookup(path).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "documented but unclassified: {missing:#?}"
        );
    }

    #[test]
    fn a_pattern_segment_matches_exactly_one_segment() {
        assert!(matches("services.*.endpoint", "services.text.endpoint"));
        assert!(!matches("services.*.endpoint", "services.text.storage.url"));
        // Not a prefix match: `*` may not swallow the rest of the path, or
        // `services.*.limits` would also claim `services.text.limits.rate`.
        assert!(!matches("services.*", "services.text.endpoint"));
    }

    #[test]
    fn an_array_index_is_a_segment_like_any_other() {
        assert_eq!(
            lookup("instances.0.settings.max_users"),
            Some(Reload::Live),
            "the operational layer is live whichever instance it belongs to"
        );
        assert_eq!(lookup("instances.3.port"), Some(Reload::Restart));
    }

    #[test]
    fn the_first_matching_pattern_wins() {
        // `logging.level` is listed before the rest of `[logging]`; if the
        // order were reversed it would be classified as a restart, and raising
        // the level during an incident would silently do nothing.
        assert_eq!(lookup("logging.level"), Some(Reload::Live));
        assert_eq!(lookup("logging.queue"), Some(Reload::Restart));
    }

    #[test]
    fn an_unknown_key_is_a_restart_rather_than_a_live_claim() {
        // Unreachable through a file (`deny_unknown_fields`), but the default
        // still has to be the one that cannot mislead.
        assert_eq!(lookup("something.nobody.wrote"), None);
        assert_eq!(classify("something.nobody.wrote"), Reload::Restart);
    }

    #[test]
    fn changing_nothing_produces_no_changes() {
        assert!(changes(&defaults(), &defaults()).is_empty());
    }

    #[test]
    fn a_changed_key_is_reported_with_both_values_and_its_class() {
        let mut new = defaults();
        new.instances[0].settings.max_users = Some(20);
        let changes = changes(&defaults(), &new);
        let [change] = changes.as_slice() else {
            panic!("expected exactly one change, got {changes:#?}");
        };
        assert_eq!(change.path, "instances.0.settings.max_users");
        assert_eq!(change.class, Reload::Live);
        assert_eq!(change.from, None, "the default leaves it unset");
        assert_eq!(change.to.as_deref(), Some("20"));
    }

    #[test]
    fn removing_a_key_is_a_change_and_not_a_silence() {
        let mut old = defaults();
        old.instances[0].settings.welcome_text = Some("hello".to_owned());
        let changes = changes(&old, &defaults());
        let [change] = changes.as_slice() else {
            panic!("expected exactly one change, got {changes:#?}");
        };
        assert_eq!(change.from.as_deref(), Some("\"hello\""));
        assert_eq!(change.to, None);
    }

    #[test]
    fn a_secret_never_reaches_the_diff() {
        // The diff is written to the operator log and served over the admin
        // plane; a password that survived this far would be in both.
        let mut old = defaults();
        old.instances[0].settings.password = Some("hunter2".to_owned());
        let mut new = defaults();
        new.instances[0].settings.password = Some("correct horse".to_owned());

        let changes = changes(&old, &new);
        assert!(
            changes.is_empty(),
            "two redacted values are equal, so a password change reports nothing quotable: \
             {changes:#?}"
        );

        let flat = flatten(&old);
        let shown = flat
            .get("instances.0.settings.password")
            .expect("the key is still present");
        assert_eq!(shown, REDACTED);
        assert!(
            !flatten(&old).values().any(|value| value.contains("hunter2")),
            "the password reached the flattened form"
        );
    }

    #[test]
    fn a_storage_url_is_a_secret_because_a_dsn_carries_a_password() {
        let mut config = defaults();
        config
            .services
            .get_mut("pchat")
            .expect("pchat ships in the defaults")
            .storage = Some(crate::config::StorageConfig {
            url: "postgres://starling:hunter2@db/starling_pchat".to_owned(),
            max_connections: 16,
        });
        assert!(
            !flatten(&config)
                .values()
                .any(|value| value.contains("hunter2")),
            "a DSN password reached the flattened form"
        );
    }

    #[test]
    fn the_revision_changes_with_the_configuration_and_not_otherwise() {
        let baseline = revision(&defaults());
        assert_eq!(baseline, revision(&defaults()), "revision must be stable");
        assert_eq!(baseline.len(), 16, "a fixed-width hex digest");

        let mut changed = defaults();
        changed.gateway.control_queue += 1;
        assert_ne!(baseline, revision(&changed));
    }

    #[test]
    fn the_revision_ignores_a_secret_it_cannot_show() {
        // Stated as a test rather than left as a surprise: the revision is
        // computed over the redacted form, so it cannot be used to detect a
        // password change. Anything that needs to must ask `server-config`.
        let mut config = defaults();
        config.instances[0].settings.password = Some("hunter2".to_owned());
        let mut other = config.clone();
        other.instances[0].settings.password = Some("something else".to_owned());
        assert_eq!(revision(&config), revision(&other));
    }
}
