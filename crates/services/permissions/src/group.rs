//! The group specification grammar, transcribed from `vendor/server/src/Group.cpp:104`.
//!
//! An ACL entry does not name a group; it names a *specification*, and only the
//! plainest case of one is a group name. Upstream reads four prefixes and six
//! reserved words, and the difference is not cosmetic: `!~sub,0,1,1` is a
//! perfectly ordinary thing for an operator to write, and a server that compares
//! it to a group name with `==` reads it as a group nobody is in, so the entry
//! is silently inert, which is the failure mode this module exists to end
//! (`docs/GAP-ANALYSIS.md` G3).
//!
//! # The two channels
//!
//! Every predicate here is evaluated against a **context channel**, and the
//! whole grammar turns on which one that is:
//!
//! * [`Context::target`]: the channel permissions are being computed *for*.
//!   The default context.
//! * [`Context::acl_channel`]: the ancestor the entry was actually written on.
//!   Selected by the `~` prefix.
//!
//! They differ exactly when an entry is inherited. `in` on a parent's entry
//! therefore means "the user is in the channel we are asking about", while
//! `~in` means "the user is in the channel the rule was written on", which is
//! how upstream expresses "members of this room may do this in every room
//! below it".
//!
//! # What is deliberately not here
//!
//! murmur's `qsTemporary`, group membership granted to a live session rather
//! than to an account, by Ice or a plugin. There is no surface in Starling that
//! grants one, so implementing the lookup would be implementing a read of a
//! table nothing writes.

use starling_proto_fancy::identity;
use starling_proto_fancy::permissions::{Group, Subject};

use crate::evaluate::Acls;

/// Where a specification is being evaluated.
///
/// Borrowed rather than owned: this is built once per ACL entry inside the
/// evaluator's walk, which is the hot path of every permission check.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// Every channel's ACL set, for the named-group walk.
    pub acls: &'a Acls,
    /// The server instance.
    pub scope: u32,
    /// The channel being evaluated for, murmur's `currentChannel`.
    pub target: u32,
    /// The channel the entry is written on, murmur's `aclChannel`.
    ///
    /// The same as [`Self::target`] for an entry on the channel itself, and an
    /// ancestor of it for an inherited one.
    pub acl_channel: u32,
}

/// The arguments to `sub`, after its defaults are filled in.
///
/// Named fields rather than a `(i32, i32, i32)`, because the three are read in
/// a different order than they are written and two of them are bounds on the
/// same quantity, a tuple here is three chances to transpose a pair silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sub {
    /// How far from the context channel the required ancestor sits.
    offset: i64,
    /// The shallowest depth below it that still matches.
    min: i64,
    /// The deepest.
    max: i64,
}

impl Default for Sub {
    /// `sub` with no arguments: the context channel itself, one level down,
    /// and no practical ceiling (`Group.cpp:165`).
    fn default() -> Self {
        Self {
            offset: 0,
            min: 1,
            max: 1000,
        }
    }
}

/// What a specification resolves to once its prefixes are stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind<'a> {
    /// `#name`: an access token the client presented.
    Token(&'a str),
    /// `$hash`: the peer's certificate fingerprint.
    CertHash(&'a str),
    /// `none`: nobody, which is how an entry is disabled without deleting it.
    Nobody,
    /// `all`: everybody, including guests.
    Everybody,
    /// `auth`: a registered account.
    Registered,
    /// `strong`: a certificate that chained to a configured CA.
    Strong,
    /// `in`: standing in the context channel.
    In,
    /// `out`: standing anywhere else.
    Out,
    /// `sub[,offset[,min[,max]]]`: standing somewhere below the context channel.
    Sub(Sub),
    /// Anything else: an actual group name.
    Named(&'a str),
}

/// One parsed specification.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Spec<'a> {
    /// `!`: the result is negated.
    negate: bool,
    /// `~`: evaluate against the channel the entry was written on.
    at_acl_channel: bool,
    kind: Kind<'a>,
}

impl<'a> Spec<'a> {
    /// Read a specification, or `None` when there is nothing left to read.
    ///
    /// Prefixes are stripped in a loop and in any order, exactly as upstream
    /// does (`Group.cpp:112`), `!~name` and `~!name` are the same rule, and a
    /// parser that fixed an order would reject tables murmur accepts.
    ///
    /// A specification that is *only* prefixes is refused **without** applying
    /// the negation, which looks like an oversight upstream and is not: it is
    /// the difference between `!` meaning "nobody, inverted" (everybody) and
    /// meaning nothing at all. `Group.cpp:139` returns a bare `false`, and an
    /// entry reading `!` granting the whole server is not a bug worth
    /// reproducing faithfully in the other direction.
    fn parse(spec: &'a str) -> Option<Self> {
        let mut negate = false;
        let mut at_acl_channel = false;
        let mut token = false;
        let mut cert_hash = false;
        let mut rest = spec;

        while let Some((first, tail)) = rest.split_at_checked(1) {
            match first {
                "!" => negate = true,
                "~" => at_acl_channel = true,
                "#" => token = true,
                "$" => cert_hash = true,
                _ => break,
            }
            rest = tail;
        }

        if rest.is_empty() {
            return None;
        }

        // Checked ahead of the reserved words, as upstream does: `#all` is the
        // token "all" and not everybody, so an operator can use a word from the
        // grammar as a channel password without it silently meaning something
        // else.
        let kind = if token {
            Kind::Token(rest)
        } else if cert_hash {
            Kind::CertHash(rest)
        } else {
            match rest {
                "none" => Kind::Nobody,
                "all" => Kind::Everybody,
                "auth" => Kind::Registered,
                "strong" => Kind::Strong,
                "in" => Kind::In,
                "out" => Kind::Out,
                "sub" => Kind::Sub(Sub::default()),
                _ => rest
                    .strip_prefix("sub,")
                    .map_or(Kind::Named(rest), |args| Kind::Sub(parse_sub(args))),
            }
        };

        Some(Self {
            negate,
            at_acl_channel,
            kind,
        })
    }
}

/// `offset,min,max`, each optional and each defaulting on its own.
///
/// A field that will not parse is zero, which is `QString::toInt`'s answer for
/// the same input (`Group.cpp:172`). Worth keeping: an operator who typed
/// `sub,x` on murmur and moved the table here should get the same rule, not a
/// different one, and "different" here means a channel that opens or closes.
fn parse_sub(args: &str) -> Sub {
    let mut sub = Sub::default();
    let mut fields = args.split(',');
    for slot in [&mut sub.offset, &mut sub.min, &mut sub.max] {
        let Some(field) = fields.next() else {
            break;
        };
        if !field.is_empty() {
            *slot = field.parse().unwrap_or(0);
        }
    }
    sub
}

/// Whether `spec` addresses `subject` here.
///
/// The one entry point. An unparseable specification addresses nobody, which is
/// the safe direction: a typo in an ACL table withholds a permission rather
/// than handing one out.
#[must_use]
pub fn applies(spec: &str, subject: &Subject, context: &Context<'_>) -> bool {
    let Some(spec) = Spec::parse(spec) else {
        return false;
    };
    let channel = if spec.at_acl_channel {
        context.acl_channel
    } else {
        context.target
    };
    let matched = match &spec.kind {
        Kind::Token(name) => holds_token(subject, name),
        Kind::CertHash(hash) => is_cert(subject, hash),
        Kind::Nobody => false,
        Kind::Everybody => true,
        Kind::Registered => identity::is_authenticated(subject.registered),
        Kind::Strong => subject.strong_cert,
        Kind::In => subject.channel == channel,
        Kind::Out => subject.channel != channel,
        Kind::Sub(sub) => in_subtree(subject, context, channel, *sub),
        Kind::Named(name) => in_named_group(subject, context, channel, name),
    };
    matched != spec.negate
}

/// Whether the client presented this access token.
///
/// **Case-insensitive**, which is upstream's choice and not a relaxation of it
/// (`Group.cpp:16`). A channel password is typed by a human, and one that only
/// works in the capitalisation the operator happened to use is a support
/// ticket rather than a security property.
fn holds_token(subject: &Subject, name: &str) -> bool {
    subject
        .tokens
        .iter()
        .any(|held| held.eq_ignore_ascii_case(name))
}

/// Whether the peer's certificate is the one named.
///
/// Compared as hex rather than as bytes because that is the form an operator
/// writes into an ACL table, copied from the client's own certificate dialog.
/// The comparison ignores case: hex digits are case-insensitive by definition,
/// so this admits nobody a byte comparison would not.
fn is_cert(subject: &Subject, hash: &str) -> bool {
    if subject.cert_hash.is_empty() {
        return false;
    }
    let held: String = subject
        .cert_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    held.eq_ignore_ascii_case(hash)
}

/// `sub[,offset,min,max]`: whether the subject stands below the context channel.
///
/// Transcribed from `Group.cpp:162`, including the arithmetic, because every
/// part of it is load-bearing:
///
/// * `offset` moves the *required ancestor* along the target's own chain, so
///   `sub,-1` asks about the context channel's parent.
/// * The subject must actually be under that ancestor, otherwise no depth
///   counts.
/// * `min` and `max` bound how far under it they may be, measured from the
///   ancestor and not from the root.
///
/// Both hierarchies are rooted, so an index into one is the same index into the
/// other for any channel they share, which is what lets the depths be compared
/// as plain numbers.
fn in_subtree(subject: &Subject, context: &Context<'_>, channel: u32, sub: Sub) -> bool {
    let home = context.acls.ancestry(context.scope, subject.channel);
    let current = context.acls.ancestry(context.scope, context.target);

    // The context channel is on the target's chain by construction; it is
    // either the target itself or an ancestor whose entry we are applying. A
    // table that says otherwise is one whose parent links have not caught up
    // with a move, so this refuses rather than picking an arbitrary index.
    let Some(anchor) = current.iter().position(|id| *id == channel) else {
        return false;
    };

    let Ok(anchor) = i64::try_from(anchor) else {
        return false;
    };
    let required = anchor + sub.offset;
    let Ok(count) = i64::try_from(current.len()) else {
        return false;
    };
    if required >= count {
        return false;
    }
    // A negative offset that walks off the top clamps at the root rather than
    // failing, which is upstream's behaviour and the more useful one: `sub,-9`
    // written anywhere means "somewhere under the root".
    let required = usize::try_from(required.max(0)).unwrap_or(0);

    let Some(ancestor) = current.get(required) else {
        return false;
    };
    if !home.contains(ancestor) {
        return false;
    }

    let required = required as i64;
    let depth = i64::try_from(home.len()).unwrap_or(i64::MAX) - 1;
    depth >= required + sub.min && depth <= required + sub.max
}

/// Whether the subject is in the named group, as the group is seen from
/// `channel`.
///
/// This is murmur's group *resolution*, which is more than a membership list
/// (`Group.cpp:220`, and the same walk as `Group::members`). A group of a given
/// name may be declared on several channels in a chain, and two flags decide
/// which of those declarations are in play:
///
/// * `inherit`: this declaration ignores anything its ancestors said.
/// * `inheritable`: descendants may see this declaration at all.
///
/// The surviving declarations are then applied from the top down, so the
/// closest one wins: a parent that adds an account and a child that removes it
/// leave the account out of the group *in that child*.
///
/// **A guest can hold a temporary membership and nothing else.** Permanent
/// membership is recorded by account id, so a subject with no account is only
/// ever in a named group by way of a session-scoped grant, which is the whole
/// reason that mechanism exists upstream. The account, when there is one, is
/// read through `identity` rather than by trusting `account`, which is `0` for
/// a guest and `0` for the SuperUser alike.
fn in_named_group(subject: &Subject, context: &Context<'_>, channel: u32, name: &str) -> bool {
    let account = identity::account(subject.registered, subject.account);

    // Root first; the walk upstream does runs the other way, so this is read in
    // reverse and the collected levels are then applied in order.
    let chain = context.acls.ancestry(context.scope, channel);
    let mut levels: Vec<(u32, Option<Group>)> = Vec::new();
    for (depth, id) in chain.iter().enumerate().rev() {
        let declared = context
            .acls
            .get(context.scope, *id)
            .groups
            .into_iter()
            .find(|group| group.name == name);
        // A channel with temporary members but no declaration still takes part.
        // Upstream cannot tell the two apart, `addUserToGroup` constructs a
        // `Group` to hang them on, and the constructed one carries the same
        // defaults this treats a missing declaration as: inheriting, and
        // inheritable.
        let has_no_declaration = declared.is_none();
        let has_no_temporary_members = !context.acls.has_temporary(context.scope, *id, name);
        if has_no_declaration && has_no_temporary_members {
            continue;
        }
        let (inherit, inheritable) = declared
            .as_ref()
            .map_or((true, true), |group| (group.inherit, group.inheritable));
        if depth + 1 != chain.len() && !inheritable {
            break;
        }
        levels.push((*id, declared));
        if !inherit {
            break;
        }
    }

    let mut member = false;
    for (id, declared) in levels.iter().rev() {
        if let Some(account) = account
            && declared
                .as_ref()
                .is_some_and(|group| group.add.contains(&account))
        {
            member = true;
        }
        // Consulted at each level alongside `add`, exactly where upstream reads
        // it (`vendor/server/src/Group.cpp:242`), so a `remove` on a closer
        // channel overrides a temporary membership granted further up, and a
        // temporary membership granted closer overrides a `remove` above it.
        // Session 0 is "no session", an operator acting through `Check`, or a
        // connection mid-handshake. Asking about it would match a grant nobody
        // could have made, since no allocator issues 0.
        if subject.session != 0
            && context.acls.holds_temporary(
                context.scope,
                *id,
                name,
                crate::evaluate::Member::Session(subject.session),
            )
        {
            member = true;
        }
        if let Some(account) = account
            && context.acls.holds_temporary(
                context.scope,
                *id,
                name,
                crate::evaluate::Member::Account(account),
            )
        {
            member = true;
        }
        // After the adds at the same level, so a declaration naming an account
        // in both removes it.
        if let Some(account) = account
            && declared
                .as_ref()
                .is_some_and(|group| group.remove.contains(&account))
        {
            member = false;
        }
    }
    member
}

/// Every group name declared anywhere on `channel`'s chain.
///
/// murmur's `Group::groupNames` (`Group.cpp:78`): a name declared on a parent is
/// visible below it unless that declaration is not inheritable, in which case it
/// is taken back out of the set.
#[must_use]
pub fn declared_names(acls: &Acls, scope: u32, channel: u32) -> Vec<String> {
    let chain = acls.ancestry(scope, channel);
    let mut names: Vec<String> = Vec::new();
    for (depth, id) in chain.iter().enumerate() {
        let is_target = depth + 1 == chain.len();
        for group in acls.get(scope, *id).groups {
            let position = names.iter().position(|held| *held == group.name);
            if !is_target && !group.inheritable {
                if let Some(position) = position {
                    let _ = names.remove(position);
                }
            } else if position.is_none() {
                names.push(group.name);
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::permissions::AclSet;

    fn kind_of(spec: &str) -> Option<Kind<'_>> {
        Spec::parse(spec).map(|parsed| parsed.kind)
    }

    #[test]
    fn prefixes_are_read_in_any_order_and_any_number() {
        // `!~name` and `~!name` are the same rule upstream, because the prefix
        // loop restarts rather than expecting a fixed order. A parser that
        // insisted on one would refuse tables murmur accepts.
        let one = Spec::parse("!~admin").expect("a specification");
        let other = Spec::parse("~!admin").expect("a specification");
        assert_eq!(one, other);
        assert!(one.negate && one.at_acl_channel);
        assert_eq!(one.kind, Kind::Named("admin"));
    }

    #[test]
    fn a_specification_that_is_only_prefixes_addresses_nobody() {
        // And is *not* negated into addressing everybody, which is the whole
        // reason this is refused before the negation is applied.
        assert_eq!(kind_of("!"), None);
        assert_eq!(kind_of(""), None);
        assert!(!applies(
            "!",
            &Subject::default(),
            &Context {
                acls: &Acls::new(),
                scope: 1,
                target: 0,
                acl_channel: 0,
            }
        ));
    }

    #[test]
    fn a_token_named_after_a_reserved_word_is_still_a_token() {
        // `#all` is the password "all", not everybody. Reading the reserved
        // words first would make a perfectly ordinary channel password open the
        // channel for the entire server.
        assert_eq!(kind_of("#all"), Some(Kind::Token("all")));
        assert_eq!(kind_of("all"), Some(Kind::Everybody));
    }

    #[test]
    fn sub_arguments_default_field_by_field() {
        assert_eq!(kind_of("sub"), Some(Kind::Sub(Sub::default())));
        assert_eq!(
            kind_of("sub,1"),
            Some(Kind::Sub(Sub {
                offset: 1,
                ..Sub::default()
            }))
        );
        assert_eq!(
            kind_of("sub,,2"),
            Some(Kind::Sub(Sub {
                min: 2,
                ..Sub::default()
            }))
        );
        assert_eq!(
            kind_of("sub,1,2,3"),
            Some(Kind::Sub(Sub {
                offset: 1,
                min: 2,
                max: 3
            }))
        );
        // `QString::toInt` answers zero for a word, and an operator moving a
        // table across should get the rule they already had.
        assert_eq!(
            kind_of("sub,x"),
            Some(Kind::Sub(Sub {
                offset: 0,
                ..Sub::default()
            }))
        );
        // A group actually called "subs" is not a `sub` specification.
        assert_eq!(kind_of("subs"), Some(Kind::Named("subs")));
    }

    /// Root → 1 → 2 → 3, so `sub` has something to measure.
    fn nested() -> Acls {
        let acls = Acls::new();
        acls.set_parent(1, 1, 0);
        acls.set_parent(1, 2, 1);
        acls.set_parent(1, 3, 2);
        acls
    }

    fn context<'a>(acls: &'a Acls, target: u32, acl_channel: u32) -> Context<'a> {
        Context {
            acls,
            scope: 1,
            target,
            acl_channel,
        }
    }

    fn standing_in(channel: u32) -> Subject {
        Subject {
            session: 9,
            channel,
            ..Subject::default()
        }
    }

    #[test]
    fn in_and_out_are_about_where_the_user_is_standing() {
        let acls = nested();
        let context = context(&acls, 2, 2);
        assert!(applies("in", &standing_in(2), &context));
        assert!(!applies("in", &standing_in(1), &context));
        assert!(applies("out", &standing_in(1), &context));
        assert!(!applies("out", &standing_in(2), &context));
        // `!in` is `out`, which is what makes the prefixes worth having.
        assert!(applies("!in", &standing_in(1), &context));
    }

    #[test]
    fn the_tilde_prefix_moves_the_question_to_the_channel_the_rule_was_written_on() {
        // The reason both channels are carried. An entry written on channel 1
        // and inherited into channel 2 asks about 2 by default, and about 1
        // with `~`, which is how "members of this room, everywhere below it"
        // is expressed.
        let acls = nested();
        let inherited = context(&acls, 2, 1);
        assert!(applies("in", &standing_in(2), &inherited));
        assert!(!applies("in", &standing_in(1), &inherited));
        assert!(applies("~in", &standing_in(1), &inherited));
        assert!(!applies("~in", &standing_in(2), &inherited));
    }

    #[test]
    fn sub_matches_a_user_standing_below_the_context_channel() {
        let acls = nested();
        // Evaluated for channel 1, entry written on channel 1: the default
        // window is one level down, so a user in 2 matches and a user in 1 or 3
        // does not.
        let here = context(&acls, 1, 1);
        // Bare `sub` is *any* depth below, not one: upstream's ceiling is 1000
        // (`Group.cpp:167`). Reading it as a single level is the natural
        // misreading, and it would make the commonest form of the rule stop at
        // the first row of sub-channels.
        assert!(!applies("sub", &standing_in(1), &here));
        assert!(applies("sub", &standing_in(2), &here));
        assert!(applies("sub", &standing_in(3), &here));
        // The window is what narrows it to one level.
        assert!(!applies("sub,0,1,1", &standing_in(3), &here));
        assert!(applies("sub,0,1,1", &standing_in(2), &here));
        // Somebody outside the subtree entirely never matches, however wide.
        assert!(!applies("sub,0,0,1000", &standing_in(0), &here));
    }

    #[test]
    fn a_sub_offset_walks_the_targets_own_chain() {
        let acls = nested();
        // Evaluated for channel 2. `sub,-1` anchors on 2's parent, channel 1,
        // so a user standing in 2 is one level below the anchor and matches.
        let here = context(&acls, 2, 2);
        assert!(!applies("sub", &standing_in(2), &here));
        assert!(applies("sub,-1", &standing_in(2), &here));
        // An offset past the end of the chain matches nobody rather than
        // wrapping or panicking.
        assert!(!applies("sub,9", &standing_in(3), &here));
    }

    #[test]
    fn a_named_group_is_resolved_through_the_chain_not_looked_up_flat() {
        // A parent adds the account and a child removes it; the closest
        // declaration wins, so the account is in the group above and out of it
        // below. Comparing the specification to a name, which is what this
        // replaced, cannot express any of that.
        let acls = nested();
        acls.set(
            1,
            AclSet {
                channel: 1,
                inherit: true,
                acls: Vec::new(),
                groups: vec![Group {
                    name: "staff".to_owned(),
                    inherit: true,
                    inheritable: true,
                    add: vec![7],
                    ..Group::default()
                }],
            },
        );
        acls.set(
            1,
            AclSet {
                channel: 2,
                inherit: true,
                acls: Vec::new(),
                groups: vec![Group {
                    name: "staff".to_owned(),
                    inherit: true,
                    inheritable: true,
                    remove: vec![7],
                    ..Group::default()
                }],
            },
        );

        let member = Subject {
            account: 7,
            registered: true,
            ..Subject::default()
        };
        assert!(applies("staff", &member, &context(&acls, 1, 1)));
        assert!(!applies("staff", &member, &context(&acls, 2, 2)));
    }

    #[test]
    fn a_declaration_that_is_not_inheritable_is_invisible_below_it() {
        let acls = nested();
        acls.set(
            1,
            AclSet {
                channel: 1,
                inherit: true,
                acls: Vec::new(),
                groups: vec![Group {
                    name: "staff".to_owned(),
                    inherit: true,
                    inheritable: false,
                    add: vec![7],
                    ..Group::default()
                }],
            },
        );
        let member = Subject {
            account: 7,
            registered: true,
            ..Subject::default()
        };
        assert!(applies("staff", &member, &context(&acls, 1, 1)));
        assert!(!applies("staff", &member, &context(&acls, 2, 2)));
        assert_eq!(declared_names(&acls, 1, 1), vec!["staff".to_owned()]);
        assert!(declared_names(&acls, 1, 2).is_empty());
    }

    #[test]
    fn a_guest_is_in_no_named_group() {
        // Membership is by account id and a guest has none, but a guest is
        // written as `account = 0`, which is also the SuperUser's id, so a
        // group naming account 0 would otherwise contain every anonymous
        // visitor on the server.
        let acls = nested();
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: Vec::new(),
                groups: vec![Group {
                    name: "staff".to_owned(),
                    inherit: true,
                    inheritable: true,
                    add: vec![0],
                    ..Group::default()
                }],
            },
        );
        let guest = Subject {
            account: 0,
            registered: false,
            ..Subject::default()
        };
        assert!(!applies("staff", &guest, &context(&acls, 0, 0)));
    }

    #[test]
    fn an_access_token_matches_whatever_case_it_was_typed_in() {
        let holder = Subject {
            tokens: vec!["SeCrEt".to_owned()],
            ..Subject::default()
        };
        let acls = Acls::new();
        assert!(applies("#secret", &holder, &context(&acls, 0, 0)));
        assert!(applies("#SECRET", &holder, &context(&acls, 0, 0)));
        assert!(!applies("#other", &holder, &context(&acls, 0, 0)));
        // And nobody without it holds it, which is the point of the feature.
        assert!(!applies(
            "#secret",
            &Subject::default(),
            &context(&acls, 0, 0)
        ));
    }

    #[test]
    fn a_certificate_specification_names_the_hex_hash() {
        let acls = Acls::new();
        let peer = Subject {
            cert_hash: vec![0xa9, 0x99, 0x3e],
            ..Subject::default()
        };
        assert!(applies("$a9993e", &peer, &context(&acls, 0, 0)));
        assert!(applies("$A9993E", &peer, &context(&acls, 0, 0)));
        assert!(!applies("$deadbe", &peer, &context(&acls, 0, 0)));
        // A peer that presented no certificate matches no `$` entry, rather
        // than matching the empty one.
        assert!(!applies("$", &Subject::default(), &context(&acls, 0, 0)));
    }

    #[test]
    fn strong_is_an_assurance_and_not_merely_having_a_certificate() {
        let acls = Acls::new();
        let self_signed = Subject {
            cert_hash: vec![1, 2, 3],
            strong_cert: false,
            ..Subject::default()
        };
        assert!(!applies("strong", &self_signed, &context(&acls, 0, 0)));
        let chained = Subject {
            strong_cert: true,
            ..self_signed
        };
        assert!(applies("strong", &chained, &context(&acls, 0, 0)));
    }

    #[test]
    fn none_addresses_nobody_and_all_addresses_everybody() {
        let acls = Acls::new();
        let context = context(&acls, 0, 0);
        assert!(!applies("none", &Subject::default(), &context));
        assert!(applies("all", &Subject::default(), &context));
        // `!none` is how an entry is written to apply to everybody *including*
        // whoever a later entry excludes; it has to be everybody.
        assert!(applies("!none", &Subject::default(), &context));
    }

    #[test]
    fn auth_is_registration_and_not_connection() {
        let acls = Acls::new();
        let context = context(&acls, 0, 0);
        assert!(!applies("auth", &standing_in(0), &context));
        assert!(applies(
            "auth",
            &Subject {
                account: 7,
                registered: true,
                ..Subject::default()
            },
            &context
        ));
    }

    #[test]
    fn a_cycle_in_the_parent_table_cannot_hang_a_specification() {
        // The table is operator-editable and `sub` walks it twice.
        let acls = Acls::new();
        acls.set_parent(1, 1, 2);
        acls.set_parent(1, 2, 1);
        let _ = applies("sub,0,0,1000", &standing_in(1), &context(&acls, 2, 2));
    }
}
