//! ACL evaluation: the ancestor walk, deny over allow, and groups.
//!
//! Transcribed from murmur's `src/ACL.cpp:104`: walk the chain from the root to
//! the target channel, and at each level apply the entries that reach it,
//! `apply_here` on the channel itself, `apply_subs` on its descendants. Within
//! a level, **deny wins over allow**, and a channel with inheritance off starts
//! from nothing rather than from its parent's result.
//!
//! Evaluation is pure. Everything it needs is in [`Acls`], which is held in
//! memory: the database is a durable record of the control plane, never a read
//! path for it (`docs/STORAGE.md` L7).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use starling_proto::proto::tcp;
use starling_proto_fancy::identity;
use starling_proto_fancy::permissions::{AclEntry, AclSet, Group, Subject};

use crate::group::Context;
use crate::perm::Perm;

/// The root channel's id, which is zero on every Mumble server.
const ROOT_CHANNEL: u32 = 0;

/// Who holds a temporary group membership.
///
/// Two named cases rather than upstream's one integer set, where an account is
/// positive and a session is stored negated (`vendor/server/src/Group.cpp:242`).
/// That encoding collides: an unregistered user's account id is `-1`, which is
/// also session 1 negated, so on a murmur server the first session to connect
/// is in every group any guest is in. Naming the cases costs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    /// A registered account, held until removed or until the server restarts.
    Account(u64),
    /// A live session, the only way to put an *unregistered* user in a group,
    /// and dropped the moment that session goes.
    Session(u32),
}

/// Temporary group memberships, keyed by `(scope, channel, group name)`.
///
/// The group name is in the key rather than the value because that is how it is
/// looked up: the membership walk asks about one name on one channel, and a
/// map from channel to a map of names would be two lookups to answer it.
type Temporary = HashMap<(u32, u32, String), HashSet<Member>>;

/// Every channel's ACL set, by server instance.
#[derive(Debug, Clone, Default)]
pub struct Acls {
    inner: Arc<Mutex<HashMap<(u32, u32), AclSet>>>,
    parents: Arc<Mutex<HashMap<(u32, u32), u32>>>,
    /// Temporary group memberships, by `(scope, channel, group name)`.
    ///
    /// **Held apart from the ACL sets, and never persisted.** Upstream keeps
    /// them on the `Group` object and then has to stash and restore them by
    /// hand around every ACL rewrite (`Messages.cpp:2842` and `:2900`,
    /// duplicated again in `MumbleServerIce.cpp:1817`). Keeping them in their
    /// own table makes that preservation the default rather than a step
    /// somebody has to remember on each new write path.
    ///
    /// Not persisted because a session-scoped grant that outlived the process
    /// would be a grant attached to a session id belonging to somebody else.
    temporary: Arc<Mutex<Temporary>>,
}

impl Acls {
    /// No ACLs anywhere, which by the rules below grants nothing except to the
    /// superuser, so a server with no ACL tables at all still lets its owner
    /// in and nobody else.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace a channel's ACL set.
    ///
    /// **Temporary memberships for groups the new table still declares are
    /// kept; the rest go.** That is upstream's rule, and it is not obvious from
    /// either side: `Messages.cpp:2842` stashes every group's temporary set
    /// before deleting the old `Group` objects, and `:2900` restores it while
    /// looping over the *new* ones, so a group the operator deleted takes its
    /// temporary members with it, and a group they merely edited does not.
    ///
    /// Getting this wrong is silent in both directions. Dropping everything
    /// means an operator pressing Save in the ACL editor revokes every
    /// temporary membership in the channel; keeping everything means a group
    /// deleted from the table goes on admitting the people an external
    /// authority put in it.
    pub fn set(&self, scope: u32, acls: AclSet) {
        if let Ok(mut temporary) = self.temporary.lock() {
            temporary.retain(|(held_scope, channel, name), _| {
                *held_scope != scope
                    || *channel != acls.channel
                    || acls.groups.iter().any(|group| group.name == *name)
            });
        }
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.insert((scope, acls.channel), acls);
        }
    }

    /// Put `member` in `group` on `channel`, until it is removed or lost.
    ///
    /// Declares the group on the channel if it is not there already, which is
    /// what upstream does (`MumbleServerIce.cpp:2305` constructs a `Group` when
    /// the lookup misses). It matters: the membership walk only visits channels
    /// that declare the group, so a grant naming a group nobody has declared
    /// would otherwise be accepted and then never match anybody.
    ///
    /// The declaration is added in memory and **not** persisted, again as
    /// upstream: it exists to carry the temporary members, and writing it
    /// through would leave an empty group in the table after a restart that
    /// dropped the members.
    pub fn add_temporary(&self, scope: u32, channel: u32, group: &str, member: Member) {
        if let Ok(mut inner) = self.inner.lock() {
            let set = inner.entry((scope, channel)).or_insert_with(|| AclSet {
                channel,
                inherit: true,
                acls: Vec::new(),
                groups: Vec::new(),
            });
            if !set.groups.iter().any(|held| held.name == group) {
                set.groups.push(Group {
                    name: group.to_owned(),
                    inherited: false,
                    inherit: true,
                    inheritable: true,
                    add: Vec::new(),
                    remove: Vec::new(),
                    inherited_members: Vec::new(),
                });
            }
        }
        if let Ok(mut temporary) = self.temporary.lock() {
            let _ = temporary
                .entry((scope, channel, group.to_owned()))
                .or_default()
                .insert(member);
        }
    }

    /// Take a temporary membership away.
    pub fn remove_temporary(&self, scope: u32, channel: u32, group: &str, member: Member) {
        if let Ok(mut temporary) = self.temporary.lock() {
            let key = (scope, channel, group.to_owned());
            if let Some(held) = temporary.get_mut(&key) {
                let _ = held.remove(&member);
                if held.is_empty() {
                    let _ = temporary.remove(&key);
                }
            }
        }
    }

    /// Whether `member` holds a temporary membership of `group` on `channel`.
    #[must_use]
    pub fn holds_temporary(&self, scope: u32, channel: u32, group: &str, member: Member) -> bool {
        self.temporary
            .lock()
            .ok()
            .and_then(|temporary| {
                temporary
                    .get(&(scope, channel, group.to_owned()))
                    .map(|held| held.contains(&member))
            })
            .unwrap_or(false)
    }

    /// Whether `channel` carries any temporary membership of `group`.
    ///
    /// Used by the membership walk to decide whether a channel takes part at
    /// all: upstream always has a `Group` object where temporary members live,
    /// so a channel holding them is a channel that declares the group.
    #[must_use]
    pub fn has_temporary(&self, scope: u32, channel: u32, group: &str) -> bool {
        self.temporary
            .lock()
            .ok()
            .is_some_and(|temporary| temporary.contains_key(&(scope, channel, group.to_owned())))
    }

    /// Drop **every** session-scoped membership, keeping account-scoped ones.
    ///
    /// For the case where this service can no longer be sure it has seen every
    /// departure, a dropped `session-view` subscription. Account grants are
    /// unaffected because they are not tied to a connection and nothing about
    /// them has become uncertain.
    pub fn forget_every_session(&self) {
        let Ok(mut temporary) = self.temporary.lock() else {
            return;
        };
        temporary.retain(|_, held| {
            held.retain(|member| !matches!(member, Member::Session(_)));
            !held.is_empty()
        });
    }

    /// Drop every temporary membership one session holds, anywhere.
    ///
    /// Called when the session goes, and **required rather than tidy**: murmur
    /// re-queues a departing session's id for reuse
    /// (`vendor/server/src/murmur/Server.cpp:1904`) and Starling's allocator
    /// does the same, so a grant that outlived its holder would be inherited by
    /// whoever is issued that id next, silently, and carrying whatever the
    /// group was granted.
    ///
    /// A scan of the whole table rather than a reverse index. Temporary grants
    /// are made by an external authority a few at a time, not per frame, and
    /// upstream walks the channel tree for the same reason (`RPC.cpp:262`). An
    /// index here would be a second structure to keep consistent for a loop
    /// that is never hot.
    pub fn forget_session(&self, session: u32) {
        let Ok(mut temporary) = self.temporary.lock() else {
            return;
        };
        temporary.retain(|_, held| {
            let _ = held.remove(&Member::Session(session));
            !held.is_empty()
        });
    }

    /// A channel's ACL set, or an empty inheriting one.
    #[must_use]
    pub fn get(&self, scope: u32, channel: u32) -> AclSet {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.get(&(scope, channel)).cloned())
            .unwrap_or(AclSet {
                channel,
                inherit: true,
                acls: Vec::new(),
                groups: Vec::new(),
            })
    }

    /// Forget a channel that no longer exists.
    ///
    /// Both tables, because a leak here is unbounded: a server that creates and
    /// deletes temporary channels all day would otherwise accumulate one entry
    /// per channel for the life of the process. Worse than the memory, a later
    /// channel reusing the id would inherit the dead one's ACL set.
    pub fn forget(&self, scope: u32, channel: u32) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.remove(&(scope, channel));
        }
        if let Ok(mut parents) = self.parents.lock() {
            let _ = parents.remove(&(scope, channel));
        }
        // The third table, for the same reason as the first two: a later
        // channel reusing this id would otherwise inherit the dead one's
        // temporary members along with its ACL set.
        if let Ok(mut temporary) = self.temporary.lock() {
            temporary.retain(|(held_scope, held_channel, _), _| {
                *held_scope != scope || *held_channel != channel
            });
        }
    }

    /// Record the tree shape the walk needs.
    ///
    /// Permissions does not own the tree (metadata does) so it is told rather
    /// than asking per evaluation, which would put a network hop inside the hot
    /// path of every check.
    pub fn set_parent(&self, scope: u32, channel: u32, parent: u32) {
        if let Ok(mut parents) = self.parents.lock() {
            let _ = parents.insert((scope, channel), parent);
        }
    }

    /// The chain from the root down to `channel`.
    #[must_use]
    pub fn ancestry(&self, scope: u32, channel: u32) -> Vec<u32> {
        let mut chain = vec![channel];
        let Ok(parents) = self.parents.lock() else {
            return chain;
        };
        let mut current = channel;
        // Bounded by the nesting limit rather than by trust: a cycle in the
        // table would otherwise hang the evaluator, and this runs on data an
        // operator can edit.
        for _ in 0..64 {
            let Some(parent) = parents.get(&(scope, current)).copied() else {
                break;
            };
            if parent == current {
                break;
            }
            chain.push(parent);
            current = parent;
        }
        chain.reverse();
        chain
    }

    /// The groups a subject is in at `channel`, for a client to display.
    ///
    /// The *identity* groups only, the ones that describe who somebody is.
    /// `in`, `out` and `sub` are relations between two channels rather than
    /// memberships, so there is no honest way to list them here, and an entry
    /// naming one is still evaluated by [`crate::group::applies`] like any
    /// other.
    ///
    /// Each candidate is put through the same predicate the evaluator uses,
    /// rather than re-deriving membership. This used to scan the ancestry flat
    /// and read `add` directly, which ignored `inherit` and `inheritable`
    /// entirely: a group a parent declared as not inheritable was reported as
    /// held in every child, so a client displayed a membership the evaluator
    /// disagreed with.
    #[must_use]
    pub fn groups_of(&self, scope: u32, subject: &Subject, channel: u32) -> Vec<String> {
        let context = Context {
            acls: self,
            scope,
            target: channel,
            acl_channel: channel,
        };
        let mut groups = vec!["all".to_owned()];
        // `@auth` is `iId >= 0` upstream (`vendor/server/src/Group.cpp:154`),
        // *registered*, not "connected". Reading it as the latter puts every
        // anonymous guest in the group an operator granted to their members.
        if identity::is_authenticated(subject.registered) {
            groups.push("auth".to_owned());
        }
        if subject.strong_cert {
            groups.push("strong".to_owned());
        }
        for name in crate::group::declared_names(self, scope, channel) {
            if crate::group::applies(&name, subject, &context) && !groups.contains(&name) {
                groups.push(name);
            }
        }
        groups
    }
}

/// What `subject` may do in `channel`.
///
/// The superuser is granted everything before any walk happens, exactly as
/// murmur does: an ACL table that has locked its own administrator out is a
/// server nobody can repair.
///
/// The check goes through [`identity::is_superuser`] rather than comparing
/// `account` here, and that indirection is load-bearing in both directions. This
/// function used to hold `const SUPERUSER: u64 = 1`, which granted every
/// permission to the first ordinary registered account while leaving the real
/// administrator (account 0) subject to its own ACLs. Changing the constant to
/// 0 without also requiring registration would have been worse still, because an
/// unregistered guest is written as `account = 0`.
#[must_use]
pub fn evaluate(acls: &Acls, scope: u32, subject: &Subject, channel: u32) -> u32 {
    if identity::is_superuser(subject.registered, subject.account) {
        return Perm::SUPERUSER.bits();
    }

    let chain = acls.ancestry(scope, channel);
    // murmur seeds the walk with a default set rather than with nothing
    // (`vendor/server/src/ACL.cpp:130`). Starting from `NONE` made an
    // unconfigured server grant nobody anything at all, every client showing
    // every action greyed out, with no ACL entry anywhere to explain it.
    let mut granted = Perm::DEFAULT;

    for (depth, id) in chain.iter().enumerate() {
        let set = acls.get(scope, *id);
        let is_target = depth + 1 == chain.len();
        if !set.inherit {
            // Inheritance off resets to the *default* set, not to nothing
            // (`vendor/server/src/ACL.cpp:141` assigns `def` here, the same
            // value the walk started from). A detached channel is still a
            // channel people can enter and speak in; what it detaches from is
            // its parents' ACL entries, not from being usable at all.
            granted = Perm::DEFAULT;
        }

        // Registered users, not the SuperUser, which returned above, and not
        // guests, can read the account directory from the root by default, so
        // an offline user can be resolved and invited
        // (`vendor/server/src/ACL.cpp:147`). Seeded before this channel's own
        // entries, so a root ACL denying it can still take it away.
        let at_root = *id == ROOT_CHANNEL;
        let is_registered_user = identity::account(subject.registered, subject.account).is_some();
        if at_root && is_registered_user {
            granted |= Perm::READ_REGISTER;
        }
        // Which channel the entry was written on, which is not the channel
        // being evaluated once inheritance is in play. The group grammar reads
        // both: `~` chooses between them (`crate::group`).
        let context = Context {
            acls,
            scope,
            target: channel,
            acl_channel: *id,
        };
        for entry in &set.acls {
            let applies = if is_target {
                entry.apply_here
            } else {
                entry.apply_subs
            };
            if !applies || !matches(entry, subject, &context) {
                continue;
            }
            granted |= Perm::from_bits_truncate(entry.grant);
            // Deny wins: applied after the grant at the same level, so an entry
            // that both grants and denies denies.
            granted &= !Perm::from_bits_truncate(entry.deny);
        }
    }

    granted.bits()
}

/// Whether an entry addresses this subject.
///
/// An entry may name an account *and* a group, and upstream takes either
/// (`vendor/server/src/ACL.cpp:154`, `matchUser || matchGroup`) rather than
/// letting the account short-circuit the group. The client's editor writes one
/// or the other, so the difference only shows on a table written by hand or by
/// Ice, where preferring one would silently drop half of the rule.
///
/// The account is compared through [`identity::account`] and not by reading
/// `subject.account`. That is the third place this mistake has been made in
/// this file (`docs/GAP-ANALYSIS.md` G4): an unregistered guest goes on the
/// wire as `account = 0, registered = false`, and `0` is also the SuperUser's
/// id, so a comparison of the number alone means an entry granting something
/// to the administrator's account grants it to **every anonymous visitor on the
/// server**. The pair is only ever meaningful read together.
fn matches(entry: &AclEntry, subject: &Subject, context: &Context<'_>) -> bool {
    let by_account = entry.account.is_some_and(|account| {
        identity::account(subject.registered, subject.account) == Some(account)
    });
    let by_group = entry
        .group
        .as_deref()
        .is_some_and(|spec| crate::group::applies(spec, subject, context));
    by_account || by_group
}

/// Read a client's `ACL` message into the set this service stores.
///
/// The inverse of [`to_wire`], and deliberately **whole-set**: murmur clears a
/// channel's groups and entries and applies what the message carries
/// (`Messages.cpp:2735`), because the client's ACL editor sends the table it is
/// showing rather than a diff. Merging instead would resurrect an entry the
/// operator had just deleted.
///
/// `inherited` entries are dropped. They are what a *parent* contributes to the
/// view the client was sent, so storing them here would copy a parent's rule
/// into the child, where it would then survive the parent's rule being removed.
#[must_use]
pub fn from_wire(acl: &tcp::Acl) -> AclSet {
    AclSet {
        channel: acl.channel_id,
        inherit: acl.inherit_acls.unwrap_or(true),
        groups: acl
            .groups
            .iter()
            .filter(|group| !group.inherited.unwrap_or(false))
            .map(|group| Group {
                name: group.name.clone(),
                inherited: false,
                inherit: group.inherit.unwrap_or(true),
                inheritable: group.inheritable.unwrap_or(true),
                add: group.add.iter().map(|id| u64::from(*id)).collect(),
                remove: group.remove.iter().map(|id| u64::from(*id)).collect(),
                inherited_members: Vec::new(),
            })
            .collect(),
        acls: acl
            .acls
            .iter()
            .filter(|entry| !entry.inherited.unwrap_or(false))
            .map(|entry| AclEntry {
                apply_here: entry.apply_here.unwrap_or(true),
                apply_subs: entry.apply_subs.unwrap_or(true),
                inherited: false,
                account: entry.user_id.map(u64::from),
                group: entry.group.clone(),
                grant: entry.grant.unwrap_or_default(),
                deny: entry.deny.unwrap_or_default(),
            })
            .collect(),
    }
}

/// The upstream `ACL` message for a set, as a client reads it.
#[must_use]
pub fn to_wire(set: &AclSet) -> tcp::Acl {
    tcp::Acl {
        channel_id: set.channel,
        inherit_acls: Some(set.inherit),
        query: Some(false),
        groups: set
            .groups
            .iter()
            .map(|group| tcp::acl::ChanGroup {
                name: group.name.clone(),
                inherited: Some(group.inherited),
                inherit: Some(group.inherit),
                inheritable: Some(group.inheritable),
                add: group.add.iter().map(|id| *id as u32).collect(),
                remove: group.remove.iter().map(|id| *id as u32).collect(),
                inherited_members: group
                    .inherited_members
                    .iter()
                    .map(|id| *id as u32)
                    .collect(),
                // Fancy group presentation fields, which this service does not
                // own: they are set through the group's own surface, and
                // echoing a default here would blank whatever is stored.
                ..tcp::acl::ChanGroup::default()
            })
            .collect(),
        acls: set
            .acls
            .iter()
            .map(|entry| tcp::acl::ChanAcl {
                apply_here: Some(entry.apply_here),
                apply_subs: Some(entry.apply_subs),
                inherited: Some(entry.inherited),
                user_id: entry.account.map(|id| id as u32),
                group: entry.group.clone(),
                grant: Some(entry.grant),
                deny: Some(entry.deny),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::permissions::AclEntry;

    fn allow(group: &str, grant: Perm, subs: bool) -> AclEntry {
        AclEntry {
            apply_here: true,
            apply_subs: subs,
            group: Some(group.to_owned()),
            grant: grant.bits(),
            ..AclEntry::default()
        }
    }

    #[test]
    fn a_grant_on_a_parent_reaches_a_child_when_it_applies_to_subs() {
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![allow("all", Perm::ENTER.union(Perm::SPEAK), true)],
                groups: Vec::new(),
            },
        );
        let granted = evaluate(&acls, 1, &Subject::default(), 5);
        assert!(Perm::from_bits_truncate(granted).contains(Perm::SPEAK));
    }

    #[test]
    fn deny_beats_allow_at_the_same_level() {
        // The order murmur applies them in; the other order would make a deny
        // depend on where in the list it happened to sit.
        let acls = Acls::new();
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("all".to_owned()),
                    grant: Perm::SPEAK.bits(),
                    deny: Perm::SPEAK.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );
        let granted = Perm::from_bits_truncate(evaluate(&acls, 1, &Subject::default(), 0));
        assert!(!granted.contains(Perm::SPEAK), "deny must win over grant");
        // The rest of the default set survives: denying one permission takes
        // that one away, not everything.
        assert!(granted.contains(Perm::TEXT_MESSAGE));
    }

    #[test]
    fn a_channel_with_inheritance_off_starts_from_the_default_set() {
        // Not from nothing, which is what this asserted before and what murmur
        // does not do (`ACL.cpp:141` reassigns the same `def` the walk began
        // with). Detaching a channel drops its parents' *entries*; it does not
        // make the channel unusable.
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![allow("all", Perm::MAKE_CHANNEL, true)],
                groups: Vec::new(),
            },
        );
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: false,
                acls: Vec::new(),
                groups: Vec::new(),
            },
        );

        let granted = Perm::from_bits_truncate(evaluate(&acls, 1, &Subject::default(), 5));
        assert!(
            !granted.contains(Perm::MAKE_CHANNEL),
            "the parent's grant must not carry into a detached channel"
        );
        assert!(
            granted.contains(Perm::SPEAK) && granted.contains(Perm::ENTER),
            "but the default set is still there: {granted:?}"
        );
    }

    #[test]
    fn an_acl_on_a_parent_reaches_its_children() {
        // Inheritance, which needs the parent table to be populated. Until the
        // tree subscription existed nothing wrote it outside tests, so every
        // channel evaluated as a root and an entry on a parent reached nothing,
        // visibly present in the ACL editor, silently never consulted.
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![allow("all", Perm::MAKE_CHANNEL, true)],
                groups: Vec::new(),
            },
        );

        let granted = Perm::from_bits_truncate(evaluate(&acls, 1, &Subject::default(), 5));
        assert!(
            granted.contains(Perm::MAKE_CHANNEL),
            "a grant on the root must apply in a child channel: {granted:?}"
        );
    }

    #[test]
    fn a_removed_channel_leaves_nothing_behind() {
        // A leak here is unbounded on a server that churns temporary channels,
        // and worse than the memory: a later channel reusing the id would
        // inherit the dead one's ACL set.
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: false,
                acls: vec![allow("all", Perm::MAKE_CHANNEL, true)],
                groups: Vec::new(),
            },
        );
        assert!(
            Perm::from_bits_truncate(evaluate(&acls, 1, &Subject::default(), 5))
                .contains(Perm::MAKE_CHANNEL)
        );

        acls.forget(1, 5);

        assert_eq!(acls.ancestry(1, 5), vec![5], "the parent link must be gone");
        assert!(
            !Perm::from_bits_truncate(evaluate(&acls, 1, &Subject::default(), 5))
                .contains(Perm::MAKE_CHANNEL),
            "a new channel reusing the id must not inherit the old one's grants"
        );
    }

    #[test]
    fn an_unconfigured_server_lets_people_talk() {
        // The regression this exists for: starting the walk from `NONE` made a
        // server with no ACL table grant nobody anything, every action greyed
        // out in every client, with no entry anywhere to blame. murmur seeds
        // the walk with these six (`ACL.cpp:130`).
        let granted = Perm::from_bits_truncate(evaluate(&Acls::new(), 1, &Subject::default(), 0));
        for expected in [
            Perm::TRAVERSE,
            Perm::ENTER,
            Perm::SPEAK,
            Perm::WHISPER,
            Perm::TEXT_MESSAGE,
            Perm::LISTEN,
        ] {
            assert!(granted.contains(expected), "missing {expected:?}");
        }
        // And nothing administrative comes for free.
        assert!(!granted.contains(Perm::WRITE));
        assert!(!granted.contains(Perm::MAKE_CHANNEL));
        assert!(!granted.contains(Perm::KICK));
    }

    #[test]
    fn a_registered_user_can_read_the_account_directory_from_the_root() {
        // Seeded at the root for registered users so an offline account can be
        // resolved and invited (`ACL.cpp:147`). A guest does not get it.
        let registered = Subject {
            account: 7,
            registered: true,
            ..Subject::default()
        };
        let granted = Perm::from_bits_truncate(evaluate(&Acls::new(), 1, &registered, 0));
        assert!(granted.contains(Perm::READ_REGISTER));

        let guest = Perm::from_bits_truncate(evaluate(&Acls::new(), 1, &Subject::default(), 0));
        assert!(!guest.contains(Perm::READ_REGISTER));
    }

    /// An ACL table that denies everything to everyone, at the root.
    ///
    /// The table an administrator has to be able to survive.
    fn denies_everything() -> Acls {
        let acls = Acls::new();
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("all".to_owned()),
                    deny: Perm::ALL.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );
        acls
    }

    #[test]
    fn the_superuser_is_never_locked_out_by_an_acl_table() {
        // A server whose administrator cannot get in is a server nobody can
        // repair. Note `registered: true`, this test used to assert the same
        // thing about `account: 1`, which is why nothing caught the evaluator
        // and userdata disagreeing about which account this is.
        let superuser = Subject {
            account: identity::SUPERUSER,
            registered: true,
            ..Subject::default()
        };
        let granted = Perm::from_bits_truncate(evaluate(&denies_everything(), 1, &superuser, 0));

        // Everything administrative, through a table that denies all of it.
        for expected in [
            Perm::WRITE,
            Perm::MAKE_CHANNEL,
            Perm::KICK,
            Perm::BAN,
            Perm::REGISTER,
        ] {
            assert!(granted.contains(expected), "missing {expected:?}");
        }
        // But **not** speaking or whispering, murmur excludes exactly those
        // two (`ACL.cpp:106`), so an operator who logs in to fix something is
        // not silently transmitting into whatever channel they land in.
        assert!(!granted.contains(Perm::SPEAK));
        assert!(!granted.contains(Perm::WHISPER));
        assert_eq!(granted, Perm::SUPERUSER);
    }

    #[test]
    fn an_unregistered_subject_is_not_the_superuser() {
        // The hole this pair of tests exists for. An absent account goes on the
        // wire as 0 and 0 is the SuperUser's id, so a bypass that checks only
        // the number hands every anonymous guest the entire server.
        let guest = Subject {
            account: identity::SUPERUSER,
            registered: false,
            ..Subject::default()
        };
        assert_eq!(
            evaluate(&denies_everything(), 1, &guest, 0),
            0,
            "an unregistered subject must be subject to the ACL table"
        );
    }

    #[test]
    fn an_ordinary_registered_user_is_not_the_superuser() {
        // The other direction: account 1 held every permission on the server.
        let user = Subject {
            account: 1,
            registered: true,
            ..Subject::default()
        };
        assert_eq!(
            evaluate(&denies_everything(), 1, &user, 0),
            0,
            "only the SuperUser bypasses evaluation"
        );
    }

    #[test]
    fn only_a_registered_subject_is_in_the_auth_group() {
        // `@auth` is `iId >= 0` upstream, registered. It was read as "has a
        // session", which every connected client does, so anonymous guests were
        // getting whatever an operator granted to `@auth`.
        let acls = Acls::new();

        let guest = acls.groups_of(1, &Subject::default(), 0);
        assert!(guest.contains(&"all".to_owned()));
        assert!(
            !guest.contains(&"auth".to_owned()),
            "an unregistered guest must not be in @auth"
        );

        let registered = acls.groups_of(
            1,
            &Subject {
                account: 7,
                registered: true,
                ..Subject::default()
            },
            0,
        );
        assert!(registered.contains(&"auth".to_owned()));
    }

    #[test]
    fn an_entry_naming_the_superusers_account_does_not_match_every_guest() {
        // `docs/GAP-ANALYSIS.md` G4, and the third appearance of one mistake in
        // this file. An unregistered guest is written as
        // `account = 0, registered = false`, which is the same *number* the
        // SuperUser carries, so comparing `entry.account == subject.account`
        // handed every anonymous visitor whatever an operator granted to the
        // administrator's own account.
        let acls = Acls::new();
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    account: Some(identity::SUPERUSER),
                    grant: Perm::BAN.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );

        let guest = Subject {
            account: identity::SUPERUSER,
            registered: false,
            ..Subject::default()
        };
        assert!(
            !Perm::from_bits_truncate(evaluate(&acls, 1, &guest, 0)).contains(Perm::BAN),
            "an unregistered guest must not be read as account 0"
        );

        // An ordinary registered account still matches the entry that names it.
        let named = Subject {
            account: 4,
            registered: true,
            ..Subject::default()
        };
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    account: Some(4),
                    grant: Perm::BAN.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );
        assert!(Perm::from_bits_truncate(evaluate(&acls, 1, &named, 0)).contains(Perm::BAN));
    }

    #[test]
    fn a_channel_password_is_an_entry_granting_enter_to_a_token_group() {
        // What G2 and G3 add up to, and the shape an operator actually writes:
        // deny `Enter` to everybody on the channel, grant it back to whoever
        // presents the token. Before this, `#hunter2` was read as the name of a
        // group nobody was in, so the grant never fired and the channel was
        // shut to everyone including the people with the password.
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: true,
                acls: vec![
                    AclEntry {
                        apply_here: true,
                        apply_subs: true,
                        group: Some("all".to_owned()),
                        deny: Perm::ENTER.bits(),
                        ..AclEntry::default()
                    },
                    AclEntry {
                        apply_here: true,
                        apply_subs: true,
                        group: Some("#hunter2".to_owned()),
                        grant: Perm::ENTER.bits(),
                        ..AclEntry::default()
                    },
                ],
                groups: Vec::new(),
            },
        );

        let stranger = Subject::default();
        assert!(!Perm::from_bits_truncate(evaluate(&acls, 1, &stranger, 5)).contains(Perm::ENTER));

        let holder = Subject {
            tokens: vec!["hunter2".to_owned()],
            ..Subject::default()
        };
        assert!(
            Perm::from_bits_truncate(evaluate(&acls, 1, &holder, 5)).contains(Perm::ENTER),
            "the token must open the channel"
        );
    }

    #[test]
    fn a_rule_written_on_a_parent_can_ask_about_the_parent_rather_than_the_child() {
        // `~` through the whole evaluator, not just the parser: an entry on
        // channel 1 granting to `~in` reaches a user standing in 1 while it is
        // being evaluated for channel 2. That is how "people in this room may do
        // this in every room below it" is written, and every part of it depends
        // on the entry knowing which channel it was written on.
        let acls = Acls::new();
        acls.set_parent(1, 1, 0);
        acls.set_parent(1, 2, 1);
        acls.set(
            1,
            AclSet {
                channel: 1,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("~in".to_owned()),
                    grant: Perm::MUTE_DEAFEN.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );

        let standing_in_the_parent = Subject {
            channel: 1,
            ..Subject::default()
        };
        assert!(
            Perm::from_bits_truncate(evaluate(&acls, 1, &standing_in_the_parent, 2))
                .contains(Perm::MUTE_DEAFEN)
        );

        let standing_in_the_child = Subject {
            channel: 2,
            ..Subject::default()
        };
        assert!(
            !Perm::from_bits_truncate(evaluate(&acls, 1, &standing_in_the_child, 2))
                .contains(Perm::MUTE_DEAFEN)
        );
    }

    #[test]
    fn a_reported_group_list_agrees_with_what_the_evaluator_will_do() {
        // `groups_of` used to scan the ancestry flat and read `add` directly,
        // ignoring `inheritable`, so a client was shown a membership the
        // evaluator did not honour, which is a UI offering an action that is
        // then refused.
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 0,
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
        assert!(acls.groups_of(1, &member, 0).contains(&"staff".to_owned()));
        assert!(
            !acls.groups_of(1, &member, 5).contains(&"staff".to_owned()),
            "a declaration that is not inheritable is not held below it"
        );
    }

    /// A channel gated on a named group: `Enter` denied to everybody, granted
    /// back to `vip`. What an operator writes when an external authority is
    /// going to decide who gets in.
    fn gated_on_vip() -> Acls {
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: true,
                acls: vec![
                    AclEntry {
                        apply_here: true,
                        apply_subs: true,
                        group: Some("all".to_owned()),
                        deny: Perm::ENTER.bits(),
                        ..AclEntry::default()
                    },
                    AclEntry {
                        apply_here: true,
                        apply_subs: true,
                        group: Some("vip".to_owned()),
                        grant: Perm::ENTER.bits(),
                        ..AclEntry::default()
                    },
                ],
                groups: Vec::new(),
            },
        );
        acls
    }

    fn guest(session: u32) -> Subject {
        Subject {
            session,
            account: 0,
            registered: false,
            ..Subject::default()
        }
    }

    fn may_enter(acls: &Acls, subject: &Subject) -> bool {
        Perm::from_bits_truncate(evaluate(acls, 1, subject, 5)).contains(Perm::ENTER)
    }

    #[test]
    fn a_temporary_membership_is_the_only_way_to_put_a_guest_in_a_named_group() {
        // The reason this mechanism exists upstream. Permanent membership is
        // recorded by account id and an unregistered visitor has none, so no
        // amount of editing the ACL table can admit one to a named group.
        let acls = gated_on_vip();
        assert!(!may_enter(&acls, &guest(7)), "a guest starts outside");

        // Adding them to the group's `add` list cannot work: `add` is account
        // ids, and a guest's account is 0, which is the SuperUser's.
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: true,
                acls: acls.get(1, 5).acls,
                groups: vec![Group {
                    name: "vip".to_owned(),
                    inherit: true,
                    inheritable: true,
                    add: vec![0],
                    ..Group::default()
                }],
            },
        );
        assert!(
            !may_enter(&acls, &guest(7)),
            "a guest must not be admitted by an entry naming account 0"
        );

        acls.add_temporary(1, 5, "vip", Member::Session(7));
        assert!(
            may_enter(&acls, &guest(7)),
            "a session-scoped grant must admit the guest holding that session"
        );
        // And nobody else's session.
        assert!(!may_enter(&acls, &guest(8)));
    }

    #[test]
    fn a_temporary_membership_does_not_outlive_the_session_it_names() {
        // Not tidiness. Session ids are re-queued for reuse when a client
        // leaves (`Server.cpp:1904`), so a grant that survived its holder would
        // be handed to whoever is issued that id next.
        let acls = gated_on_vip();
        acls.add_temporary(1, 5, "vip", Member::Session(7));
        assert!(may_enter(&acls, &guest(7)));

        acls.forget_session(7);

        assert!(
            !may_enter(&acls, &guest(7)),
            "the next holder of session 7 must not inherit the grant"
        );
    }

    #[test]
    fn an_acl_rewrite_keeps_the_memberships_of_groups_it_still_declares() {
        // murmur stashes every group's temporary set before deleting the old
        // group objects and restores it while looping over the new ones
        // (`Messages.cpp:2842`, `:2900`). Both halves of that matter: an
        // operator pressing Save must not revoke a temporary membership, and a
        // group they *deleted* must not go on admitting people.
        let acls = gated_on_vip();
        acls.add_temporary(1, 5, "vip", Member::Session(7));
        acls.add_temporary(1, 5, "doomed", Member::Session(7));
        assert!(may_enter(&acls, &guest(7)));

        // A save that keeps `vip` and drops `doomed`.
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: true,
                acls: acls.get(1, 5).acls,
                groups: vec![Group {
                    name: "vip".to_owned(),
                    inherit: true,
                    inheritable: true,
                    ..Group::default()
                }],
            },
        );

        assert!(
            may_enter(&acls, &guest(7)),
            "editing the table must not revoke a temporary membership"
        );
        assert!(
            !acls.holds_temporary(1, 5, "doomed", Member::Session(7)),
            "a group deleted from the table takes its temporary members with it"
        );
    }

    #[test]
    fn a_remove_on_a_closer_channel_still_overrides_a_temporary_membership() {
        // Upstream reads `qsTemporary` inside the same per-level loop as `add`
        // and `remove` (`Group.cpp:242`), so the ordinary "closest declaration
        // wins" rule applies to it too. Reading temporary membership as an
        // override applied after the whole walk would quietly make it
        // unrevocable in a sub-channel.
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set_parent(1, 6, 5);
        // The permission is granted to `vip` on channel 5 and inherited down.
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("vip".to_owned()),
                    grant: Perm::MUTE_DEAFEN.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );
        // The child takes the account back out of the group.
        acls.set(
            1,
            AclSet {
                channel: 6,
                inherit: true,
                acls: Vec::new(),
                groups: vec![Group {
                    name: "vip".to_owned(),
                    inherit: true,
                    inheritable: true,
                    remove: vec![9],
                    ..Group::default()
                }],
            },
        );

        let registered = Subject {
            session: 3,
            account: 9,
            registered: true,
            ..Subject::default()
        };
        acls.add_temporary(1, 5, "vip", Member::Account(9));

        assert!(
            Perm::from_bits_truncate(evaluate(&acls, 1, &registered, 5))
                .contains(Perm::MUTE_DEAFEN),
            "the temporary membership holds on the channel it was granted on"
        );
        assert!(
            !Perm::from_bits_truncate(evaluate(&acls, 1, &registered, 6))
                .contains(Perm::MUTE_DEAFEN),
            "a remove on the closer channel must still win"
        );
    }

    #[test]
    fn a_channel_that_is_deleted_leaves_no_temporary_membership_behind() {
        // The same id-reuse hazard as the ACL set itself.
        let acls = gated_on_vip();
        acls.add_temporary(1, 5, "vip", Member::Session(7));
        acls.forget(1, 5);
        assert!(!acls.holds_temporary(1, 5, "vip", Member::Session(7)));
    }

    #[test]
    fn losing_the_session_stream_clears_session_grants_and_keeps_account_grants() {
        // A missed departure is a grant attached to an id that gets reissued,
        // so uncertainty is resolved by clearing. An account grant is not tied
        // to a connection, so nothing about it has become uncertain.
        let acls = gated_on_vip();
        acls.add_temporary(1, 5, "vip", Member::Session(7));
        acls.add_temporary(1, 5, "vip", Member::Account(9));

        acls.forget_every_session();

        assert!(!acls.holds_temporary(1, 5, "vip", Member::Session(7)));
        assert!(acls.holds_temporary(1, 5, "vip", Member::Account(9)));
    }

    #[test]
    fn a_cycle_in_the_parent_table_cannot_hang_the_evaluator() {
        // The table is operator-editable, so the walk is bounded rather than
        // trusting.
        let acls = Acls::new();
        acls.set_parent(1, 1, 2);
        acls.set_parent(1, 2, 1);
        assert!(acls.ancestry(1, 1).len() <= 65);
    }
}
