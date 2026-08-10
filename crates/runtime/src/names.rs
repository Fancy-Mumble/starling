//! What a channel name and a user name are allowed to look like.
//!
//! murmur holds both to an operator-supplied regular expression, `channelname`
//! and `username` (`vendor/server/src/murmur/Server.cpp:2607`). Two rules that
//! read the same way and are enforced in different services, `metadata` checks
//! channel names and `userdata` checks user names, so the rule lives here for
//! the reason [`crate::settings`] gives: a check written out twice is a check
//! that is eventually two different checks, and the one that drifted looks
//! exactly like the one that did not.
//!
//! # Anchored, and why that is not a detail
//!
//! murmur anchors the operator's pattern before matching it
//! (`Server.cpp:618`, `QRegularExpression::anchoredPattern`). Unanchored, every
//! pattern here is worthless: `[\w]+` would accept `hello; DROP` because it
//! matches the `hello` inside it, so a restriction an operator wrote would
//! admit exactly what they wrote it to keep out. The pattern is wrapped in
//! `\A(?:...)\z` rather than `^(?:...)$` so that a trailing newline cannot end
//! the match early either.
//!
//! # Which way a broken pattern fails
//!
//! **Open**, with a loud error, and this is the one place worth disagreeing
//! with murmur. An unparseable `QRegularExpression` there matches nothing, so a
//! typo in `username` refuses every login on the server, including the
//! administrator's, and the only way back in is to edit the file that broke it.
//! A setting is not a permission ([`crate::settings`] makes the same argument
//! about `server-config` being unreachable): the cost of being wrong in this
//! direction is a name somebody would rather not have, and in the other it is
//! an outage.
//!
//! An **empty** pattern is not an error, it is how an operator turns the rule
//! off, and it costs no compilation.

use std::sync::RwLock;

use regex::Regex;

/// Longest name of either kind, in characters.
///
/// murmur's, checked before the pattern is (`Server.cpp:2610`, `:2618`) and
/// worth keeping separate from it: an operator's `.+` is not an invitation to
/// store a megabyte of channel name, and a pattern that has to say so would be
/// a pattern nobody writes correctly.
pub const MAX_NAME_LEN: usize = 512;

/// A compiled name pattern, kept alongside the text it came from.
///
/// One entry rather than a map: the pattern changes when an operator changes
/// it, which is approximately never, while it is *read* on every channel
/// creation and every login. A one-slot cache turns that into a string
/// comparison, and a miss costs one compilation rather than one per name.
#[derive(Debug, Default)]
pub struct NameRule {
    cached: RwLock<Option<Compiled>>,
}

#[derive(Debug)]
struct Compiled {
    pattern: String,
    /// `None` when the pattern did not compile. Cached too, so a broken pattern
    /// is reported once rather than on every name it fails to check.
    regex: Option<Regex>,
}

impl NameRule {
    /// An empty rule, which accepts every name until a pattern is set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cached: RwLock::new(None),
        }
    }

    /// Whether `name` satisfies `pattern`.
    ///
    /// `what` names the rule in the log, so an operator reading "channel name
    /// pattern does not compile" does not have to guess which of the two it is.
    pub fn accepts(&self, pattern: &str, name: &str, what: &str) -> bool {
        if name.chars().count() > MAX_NAME_LEN {
            return false;
        }
        if pattern.is_empty() {
            return true;
        }
        if let Ok(cached) = self.cached.read()
            && let Some(compiled) = cached.as_ref()
            && compiled.pattern == pattern
        {
            return compiled.regex.as_ref().is_none_or(|re| re.is_match(name));
        }

        let regex = match Regex::new(&anchored(pattern)) {
            Ok(regex) => Some(regex),
            Err(error) => {
                tracing::error!(
                    %error,
                    pattern,
                    what,
                    "the name pattern does not compile; accepting every name until it is fixed"
                );
                None
            }
        };
        let accepted = regex.as_ref().is_none_or(|re| re.is_match(name));
        if let Ok(mut cached) = self.cached.write() {
            *cached = Some(Compiled {
                pattern: pattern.to_owned(),
                regex,
            });
        }
        accepted
    }
}

/// murmur's `anchoredPattern`: the whole name must match, not a piece of it.
fn anchored(pattern: &str) -> String {
    format!(r"\A(?:{pattern})\z")
}

/// Whether `name` is a usable user name under `pattern`.
///
/// Adds murmur's own precondition (`Server.cpp:2608`): the name must already be
/// trimmed. Upstream trims before calling, so a name with an edge space is a
/// caller that forgot, and accepting it would let ` alice` and `alice` be two
/// people whom every client draws identically.
#[must_use]
pub fn is_user_name(rule: &NameRule, pattern: &str, name: &str) -> bool {
    if name.trim() != name || name.is_empty() {
        return false;
    }
    rule.accepts(pattern, name, "user name")
}

/// Whether `name` is a usable channel name under `pattern`.
#[must_use]
pub fn is_channel_name(rule: &NameRule, pattern: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    rule.accepts(pattern, name, "channel name")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{CHANNEL_NAME_PATTERN, USER_NAME_PATTERN};

    #[test]
    fn murmurs_own_patterns_accept_ordinary_names() {
        let rule = NameRule::new();
        for name in ["Alice", "alice.smith", "Team (EU)", "user_1", "a b"] {
            assert!(
                is_user_name(&rule, USER_NAME_PATTERN, name),
                "{name} should be a valid user name"
            );
        }
        for name in ["Lobby", "#general", "Team (EU)", "Room [2]"] {
            assert!(
                is_channel_name(&rule, CHANNEL_NAME_PATTERN, name),
                "{name} should be a valid channel name"
            );
        }
    }

    #[test]
    fn a_pattern_is_matched_whole_and_not_anywhere_inside() {
        // The failure this rules out: an operator restricting names to word
        // characters, and every name containing one being accepted. Unanchored,
        // every assertion below passes.
        let rule = NameRule::new();
        assert!(rule.accepts(r"\w+", "alice", "test"));
        assert!(!rule.accepts(r"\w+", "alice;DROP TABLE", "test"));
        assert!(!rule.accepts(r"\w+", "hello world", "test"));
    }

    #[test]
    fn a_trailing_newline_does_not_end_the_match_early() {
        // `$` would accept this; `\z` is why the wrapper does not use it.
        let rule = NameRule::new();
        assert!(!rule.accepts(r"\w+", "alice\n", "test"));
    }

    #[test]
    fn an_empty_pattern_turns_the_rule_off() {
        let rule = NameRule::new();
        assert!(rule.accepts("", "anything at all !!!", "test"));
    }

    #[test]
    fn a_broken_pattern_accepts_rather_than_locking_everybody_out() {
        // murmur refuses every name here. That turns one typo in the config
        // file into a server nobody, administrator included, can log in to.
        let rule = NameRule::new();
        assert!(rule.accepts("[unclosed", "alice", "test"));
        // And it stays cached as broken rather than being recompiled per name.
        assert!(rule.accepts("[unclosed", "bob", "test"));
    }

    #[test]
    fn a_changed_pattern_replaces_the_cached_one() {
        // The one-slot cache would otherwise answer with the previous
        // operator's rule until the process restarted.
        let rule = NameRule::new();
        assert!(rule.accepts(r"\w+", "alice", "test"));
        assert!(!rule.accepts(r"[0-9]+", "alice", "test"));
        assert!(rule.accepts(r"[0-9]+", "42", "test"));
    }

    #[test]
    fn a_name_is_measured_in_characters_and_capped_before_the_pattern() {
        let rule = NameRule::new();
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(!rule.accepts(r".*", &long, "test"));
        assert!(rule.accepts(r".*", &"a".repeat(MAX_NAME_LEN), "test"));
    }

    #[test]
    fn an_untrimmed_user_name_is_refused_whatever_the_pattern_says() {
        // ` alice` and `alice` render identically in every client, so allowing
        // both is allowing impersonation.
        let rule = NameRule::new();
        assert!(!is_user_name(&rule, "", " alice"));
        assert!(!is_user_name(&rule, "", "alice "));
        assert!(!is_user_name(&rule, "", ""));
    }
}
