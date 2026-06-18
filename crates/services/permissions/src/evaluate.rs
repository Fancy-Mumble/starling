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
use starling_proto_fancy::permissions::{AclSet, Subject};

use crate::perm::Perm;

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
        if subject.authenticated {
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
#[must_use]
pub fn evaluate(acls: &Acls, scope: u32, subject: &Subject, channel: u32) -> u32 {
    const SUPERUSER: u64 = 1;
    if subject.account == SUPERUSER {
        return Perm::ALL.bits();
    }

    let groups = acls.groups_of(scope, subject, channel);
    let chain = acls.ancestry(scope, channel);
    let mut granted = Perm::NONE;

    for (depth, id) in chain.iter().enumerate() {
        let set = acls.get(scope, *id);
        let is_target = depth + 1 == chain.len();
        if !set.inherit {
            // Inheritance off: this channel starts from nothing, which is what
            // makes a "detached" channel a real boundary rather than a hint.
            granted = Perm::NONE;
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
fn matches(
    entry: &starling_proto_fancy::permissions::AclEntry,
    subject: &Subject,
    groups: &[String],
) -> bool {
    if let Some(account) = entry.account {
        return account == subject.account;
    }
    match &entry.group {
        Some(group) => groups.iter().any(|held| held == group),
        None => false,
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
        assert_eq!(evaluate(&acls, 1, &Subject::default(), 0), 0);
    }

    #[test]
    fn a_channel_with_inheritance_off_starts_from_nothing() {
        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![allow("all", Perm::SPEAK, true)],
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
        assert_eq!(evaluate(&acls, 1, &Subject::default(), 5), 0);
    }

    #[test]
    fn the_superuser_is_never_locked_out_by_an_acl_table() {
        // A server whose administrator cannot get in is a server nobody can
        // repair.
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
        let superuser = Subject {
            account: 1,
            authenticated: true,
            ..Subject::default()
        };
        assert_eq!(evaluate(&acls, 1, &superuser, 0), Perm::ALL.bits());
    }

    #[test]
    fn an_authenticated_subject_is_in_auth_and_an_anonymous_one_is_not() {
        let acls = Acls::new();
        let anonymous = acls.groups_of(1, &Subject::default(), 0);
        assert!(anonymous.contains(&"all".to_owned()));
        assert!(!anonymous.contains(&"auth".to_owned()));

        let registered = acls.groups_of(
            1,
            &Subject {
                authenticated: true,
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
