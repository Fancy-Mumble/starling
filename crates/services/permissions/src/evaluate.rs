//! ACL evaluation: the ancestor walk, deny over allow, and groups.
//!
//! Transcribed from murmur's `src/ACL.cpp:104`: walk the chain from the root to
//! the target channel, and at each level apply the entries that reach it —
//! `apply_here` on the channel itself, `apply_subs` on its descendants. Within
//! a level, **deny wins over allow**, and a channel with inheritance off starts
//! from nothing rather than from its parent's result.
//!
//! Evaluation is pure. Everything it needs is in [`Acls`], which is held in
//! memory: the database is a durable record of the control plane, never a read
//! path for it (`docs/STORAGE.md` L7).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto::proto::tcp;
use starling_proto_fancy::identity;
use starling_proto_fancy::permissions::{AclEntry, AclSet, Group, Subject};

use crate::perm::Perm;

/// The root channel's id, which is zero on every Mumble server.
const ROOT_CHANNEL: u32 = 0;

/// Every channel's ACL set, by virtual server.
#[derive(Debug, Clone, Default)]
pub struct Acls {
    inner: Arc<Mutex<HashMap<(u32, u32), AclSet>>>,
    parents: Arc<Mutex<HashMap<(u32, u32), u32>>>,
}

impl Acls {
    /// No ACLs anywhere, which by the rules below grants nothing except to the
    /// superuser — so a server with no ACL tables at all still lets its owner
    /// in and nobody else.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace a channel's ACL set.
    pub fn set(&self, scope: u32, acls: AclSet) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.insert((scope, acls.channel), acls);
        }
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
    }

    /// Record the tree shape the walk needs.
    ///
    /// Permissions does not own the tree — metadata does — so it is told rather
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

    /// The groups a subject is in at `channel`.
    #[must_use]
    pub fn groups_of(&self, scope: u32, subject: &Subject, channel: u32) -> Vec<String> {
        let mut groups = vec!["all".to_owned()];
        // `@auth` is `iId >= 0` upstream (`vendor/server/src/Group.cpp:154`) —
        // *registered*, not "connected". Reading it as the latter puts every
        // anonymous guest in the group an operator granted to their members.
        if identity::is_authenticated(subject.registered) {
            groups.push("auth".to_owned());
        }
        for id in self.ancestry(scope, channel) {
            for group in self.get(scope, id).groups {
                let member = group.add.contains(&subject.account)
                    || group.inherited_members.contains(&subject.account);
                let removed = group.remove.contains(&subject.account);
                if member && !removed && !groups.contains(&group.name) {
                    groups.push(group.name);
                }
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
/// administrator — account 0 — subject to its own ACLs. Changing the constant to
/// 0 without also requiring registration would have been worse still, because an
/// unregistered guest is written as `account = 0`.
#[must_use]
pub fn evaluate(acls: &Acls, scope: u32, subject: &Subject, channel: u32) -> u32 {
    if identity::is_superuser(subject.registered, subject.account) {
        return Perm::SUPERUSER.bits();
    }

    let groups = acls.groups_of(scope, subject, channel);
    let chain = acls.ancestry(scope, channel);
    // murmur seeds the walk with a default set rather than with nothing
    // (`vendor/server/src/ACL.cpp:130`). Starting from `NONE` made an
    // unconfigured server grant nobody anything at all — every client showing
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

        // Registered users — not the SuperUser, which returned above, and not
        // guests — can read the account directory from the root by default, so
        // an offline user can be resolved and invited
        // (`vendor/server/src/ACL.cpp:147`). Seeded before this channel's own
        // entries, so a root ACL denying it can still take it away.
        if *id == ROOT_CHANNEL && identity::account(subject.registered, subject.account).is_some() {
            granted |= Perm::READ_REGISTER;
        }
        for entry in &set.acls {
            let applies = if is_target {
                entry.apply_here
            } else {
                entry.apply_subs
            };
            if !applies || !matches(entry, subject, &groups) {
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
fn matches(entry: &AclEntry, subject: &Subject, groups: &[String]) -> bool {
    if let Some(account) = entry.account {
        return account == subject.account;
    }
    match &entry.group {
        Some(group) => groups.iter().any(|held| held == group),
        None => false,
    }
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
        // channel evaluated as a root and an entry on a parent reached nothing —
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
        // server with no ACL table grant nobody anything — every action greyed
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
        // repair. Note `registered: true` — this test used to assert the same
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
        // But **not** speaking or whispering — murmur excludes exactly those
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
        // `@auth` is `iId >= 0` upstream — registered. It was read as "has a
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
    fn a_cycle_in_the_parent_table_cannot_hang_the_evaluator() {
        // The table is operator-editable, so the walk is bounded rather than
        // trusting.
        let acls = Acls::new();
        acls.set_parent(1, 1, 2);
        acls.set_parent(1, 2, 1);
        assert!(acls.ancestry(1, 1).len() <= 65);
    }
}
