//! Turning an answered questionnaire into permissions that exist.
//!
//! Each `Step.Choice` names the channels it reveals and the ACL groups it joins
//! the user to; this is the half that makes those real. Without it the whole
//! flow is a survey whose results nobody reads, which is what it was.
//!
//! # The grants are the flow's, never the answer's
//!
//! A `Response` carries step ids and choice ids and *nothing else*. Every
//! channel and group applied here is read out of the operator's stored `Flow`,
//! looked up by those ids. That is deliberate and it is the security property
//! of this module: a client cannot ask to be let into a channel, it can only
//! pick an answer the operator wrote, and an id matching nothing grants
//! nothing. A shape where the client sent the grants would be a client that
//! sends itself `admin`.
//!
//! # Recorded as group membership, not as an entry per user
//!
//! Revealing a channel could be one `AclEntry` naming the account. It is not:
//! that puts a row per user on every channel's ACL, so ten thousand onboarded
//! users are ten thousand entries the evaluator walks on every permission check
//! in that channel, and an operator opening the ACL editor cannot read it any
//! more. Instead each revealed channel gets **one** entry granting
//! [`REVEALED`], and onboarding adds accounts to that group, an integer per
//! user in a list, and one line an operator can see and understand.
//!
//! # What it deliberately does not do
//!
//! **It does not touch ancestors.** Reaching a channel needs `Traverse` along
//! the path to it, so if an operator has hidden a parent, revealing the child
//! is not enough on its own. Onboarding grants exactly the channels the flow
//! names and no others: walking up the tree would mean widening permissions on
//! channels the operator never listed, which is not a thing a questionnaire
//! should be able to do quietly. The `Traverse` on the way down is the
//! operator's to grant.
//!
//! **It does not overrule a removal.** An account an operator has put in a
//! group's `remove` list stays out, a closer `remove` beats an `add` when the
//! group is resolved (`permissions::group`), so re-adding would look applied
//! and do nothing. It is logged instead, because a grant that cannot take
//! effect and says so is the opposite of the bug this module exists to fix.

use std::collections::BTreeSet;

use starling_proto_fancy::common::{Actor, Internal, Scope, actor};
use starling_proto_fancy::fancy::feature::{Flow, Response};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
use starling_proto_fancy::permissions::{AclEntry, AclRequest, AclSet, Group, SetAclRequest};
use starling_runtime::channel::Resolver;

/// The group a revealed channel's members are recorded in.
///
/// One name for every flow and every choice, because the grant it stands for is
/// always the same one: "onboarding let this account in here". Which *answer*
/// led to it is in `onboarding_answers`, where it can be re-read; duplicating it
/// into group names would put questionnaire wording into the ACL table, where
/// renaming a choice would strand a group nothing removes.
pub const REVEALED: &str = "onboarded";

/// Where a group named by a `Choice` is declared.
///
/// Groups from an answer are server-wide: the operator wrote "developers", not
/// "developers in this one room". A declaration at the root is inheritable and
/// therefore visible in every channel's ACL, which is what lets an operator
/// write `@developers` anywhere in the tree and have it mean these people.
const ROOT_CHANNEL: u32 = 0;

/// What a set of answers is worth, according to the flow they answered.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Wanted {
    /// Channels to reveal.
    pub channels: BTreeSet<u32>,
    /// Groups to join, by name.
    pub groups: BTreeSet<String>,
}

impl Wanted {
    /// Whether there is anything to do.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty() && self.groups.is_empty()
    }
}

/// What `flow` says `response` earns.
///
/// Sorted sets rather than vectors, so answering the same choice twice, or two
/// choices that reveal the same channel, is one grant, and so the log line is
/// stable enough to compare between two connections.
#[must_use]
pub fn wanted(flow: &Flow, response: &Response) -> Wanted {
    // Everyone who arrives gets these, whatever they answered, which is what
    // makes them worth having as a field rather than a choice every flow has to
    // remember to include.
    let mut found = Wanted {
        channels: flow.default_channels.iter().copied().collect(),
        groups: BTreeSet::new(),
    };

    for answer in &response.answers {
        let Some(step) = flow.steps.iter().find(|step| step.id == answer.step_id) else {
            // An answer to a question that no longer exists. Ordinary after an
            // operator edits the flow, and it grants nothing, which is the
            // point: the flow is the authority on what an id is worth.
            continue;
        };
        for id in &answer.choice_ids {
            let Some(choice) = step.choices.iter().find(|choice| &choice.id == id) else {
                continue;
            };
            found.channels.extend(choice.channels.iter().copied());
            found.groups.extend(choice.groups.iter().cloned());
        }
    }
    found
}

/// Applies grants by editing the ACL table through `permissions`.
#[derive(Debug, Clone)]
pub struct Grants {
    resolver: Resolver,
}

/// How a single grant attempt ended.
///
/// Distinguishes "already had it" from "granted it now", because they are the
/// same outcome and very different events: the first is every reconnect, the
/// second happens once and is worth a log line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Channels and groups that were written.
    pub changed: usize,
    /// Whether every intended grant was carried out.
    ///
    /// False means the permissions service refused or could not be reached, so
    /// the user is short of what they were promised. The caller does not fail
    /// the submission over it, the answers are stored and the grant is
    /// re-attempted on the next connection, but nothing may report success.
    pub complete: bool,
}

impl Grants {
    /// Grants applied through `resolver`.
    #[must_use]
    pub const fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }

    /// Make `wanted` true for `account`, and say what changed.
    ///
    /// Idempotent: a user who already holds every grant causes no write and no
    /// invalidation. That is what makes it safe to call on every connection,
    /// which is in turn what heals an account whose grant was lost, to a failed
    /// call here, or to an operator pruning a group.
    pub async fn apply(&self, scope: u32, account: u64, wanted: &Wanted) -> Applied {
        if wanted.is_empty() {
            return Applied {
                changed: 0,
                complete: true,
            };
        }
        let Ok(transport) = self.resolver.channel("permissions") else {
            tracing::warn!(
                account,
                "permissions is unreachable; onboarding grants not applied"
            );
            return Applied::default();
        };
        let mut client = PermissionsClient::new(transport);
        let mut applied = Applied {
            changed: 0,
            complete: true,
        };

        if !wanted.groups.is_empty() {
            let names: Vec<&str> = wanted.groups.iter().map(String::as_str).collect();
            edit(
                &mut client,
                &mut applied,
                &Edit {
                    scope,
                    channel: ROOT_CHANNEL,
                    account,
                    groups: &names,
                    reveal: false,
                },
            )
            .await;
        }
        for channel in &wanted.channels {
            edit(
                &mut client,
                &mut applied,
                &Edit {
                    scope,
                    channel: *channel,
                    account,
                    groups: &[REVEALED],
                    reveal: true,
                },
            )
            .await;
        }
        applied
    }
}

/// One channel's worth of grant: what to add, where, and for whom.
///
/// A struct because the alternative is eight positional arguments, and among
/// them are two `u32`s and a `bool`, `edit(scope, channel, ...)` transposed
/// would compile, run, and write the grant to the wrong channel of the wrong
/// virtual server. Named fields make that transposition impossible to write.
#[derive(Debug)]
struct Edit<'a> {
    scope: u32,
    channel: u32,
    account: u64,
    /// The groups to join on this channel.
    groups: &'a [&'a str],
    /// Whether this channel also needs the ACL entry that makes the group mean
    /// something. False for the root, where the groups are joined so an
    /// *operator's* entries can name them.
    reveal: bool,
}

/// Read one channel's ACL, add the memberships, write it back if it moved.
///
/// Read-modify-write rather than a dedicated "add member" call because the
/// permissions service has none that is durable: `AddTemporaryGroup` is
/// session-scoped by design and would evaporate on reconnect, which is the one
/// thing an onboarding grant must not do.
async fn edit(
    client: &mut PermissionsClient<tonic::transport::Channel>,
    applied: &mut Applied,
    grant: &Edit<'_>,
) {
    let Edit {
        scope,
        channel,
        account,
        groups,
        reveal,
    } = *grant;
    let current = client
        .get_acl(AclRequest {
            scope: Some(Scope {
                virtual_server: scope,
            }),
            channel,
        })
        .await;
    let mut set = match current {
        Ok(reply) => reply.into_inner(),
        Err(status) => {
            tracing::warn!(channel, account, %status, "could not read the acl; grant skipped");
            applied.complete = false;
            return;
        }
    };
    // The reply is this channel's own set; `channel` may still be unset on a
    // channel that has never had one written, and writing that back would
    // move every entry to channel 0.
    set.channel = channel;

    let mut moved = false;
    for group in groups {
        moved |= join(&mut set, account, group);
    }
    if reveal {
        moved |= reveal_to(&mut set, REVEALED);
    }
    if !moved {
        return;
    }

    let result = client
        .set_acl(SetAclRequest {
            scope: Some(Scope {
                virtual_server: scope,
            }),
            // The service acting on its own behalf. Not the submitting
            // session: the account asked a question, the *server* decided
            // what that was worth, and an audit line naming the user would
            // read as the user having edited the ACL themselves.
            actor: Some(Actor {
                who: Some(actor::Who::Internal(Internal {
                    service: "onboarding".to_owned(),
                })),
            }),
            acls: Some(set),
        })
        .await;
    match result {
        Ok(reply) if reply.get_ref().applied => applied.changed += 1,
        Ok(reply) => {
            tracing::warn!(
                channel,
                account,
                refused = %reply.get_ref().refused,
                "the acl edit was refused; onboarding grant not applied"
            );
            applied.complete = false;
        }
        Err(status) => {
            tracing::warn!(channel, account, %status, "the acl edit failed");
            applied.complete = false;
        }
    }
}

/// Put `account` in `group` on this channel's set. Returns whether it changed.
///
/// Pure, and separate from the call that persists it, because this is where the
/// interesting decisions are and a decision that can only be tested through a
/// gRPC round trip is one that ends up untested.
fn join(set: &mut AclSet, account: u64, group: &str) -> bool {
    if !set.groups.iter().any(|have| have.name == group) {
        set.groups.push(Group {
            name: group.to_owned(),
            // Inheriting and inheritable, which is what a group an operator
            // adds through the ACL editor gets, and what makes a group declared
            // at the root usable anywhere below it.
            inherit: true,
            inheritable: true,
            ..Group::default()
        });
    }
    // Found again rather than kept from the push, which costs one more walk of
    // a list that is a handful of entries long and removes the only branch in
    // here that could panic.
    let Some(declared) = set.groups.iter_mut().find(|have| have.name == group) else {
        return false;
    };

    if declared.remove.contains(&account) {
        // The operator's removal wins when the group is resolved, so adding
        // would be a grant that reads as applied and does nothing. Said out
        // loud instead.
        tracing::info!(
            account,
            group,
            channel = set.channel,
            "an onboarding grant is overruled by an operator's removal from the group"
        );
        return false;
    }
    if declared.add.contains(&account) {
        return false;
    }
    declared.add.push(account);
    true
}

/// Ensure this channel grants entry to `group`. Returns whether it changed.
///
/// `Traverse` as well as `Enter`, and both together: `Enter` alone lets someone
/// join a channel they cannot see listed, which every client renders as a
/// channel that is not there.
fn reveal_to(set: &mut AclSet, group: &str) -> bool {
    let wanted = Perm::TRAVERSE.union(Perm::ENTER).bits();
    let existing = set.acls.iter_mut().find(|entry| {
        entry.apply_here && entry.group.as_deref() == Some(group) && !entry.inherited
    });
    if let Some(entry) = existing {
        // An operator may have written this entry themselves, or narrowed ours.
        // Widening to include both bits is the grant; anything else they put on
        // it is theirs and is left alone.
        if entry.grant & wanted == wanted {
            return false;
        }
        entry.grant |= wanted;
        return true;
    }
    set.acls.push(AclEntry {
        apply_here: true,
        // The named channel only. A flow that reveals a room has said nothing
        // about the rooms under it, and inheriting the grant downward would
        // hand out every future sub-channel too.
        apply_subs: false,
        inherited: false,
        account: None,
        group: Some(group.to_owned()),
        grant: wanted,
        deny: 0,
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::fancy::feature::{Step, response, step};

    fn flow() -> Flow {
        Flow {
            flow_id: "welcome".to_owned(),
            default_channels: vec![1],
            steps: vec![Step {
                id: "interests".to_owned(),
                multi_select: true,
                choices: vec![
                    step::Choice {
                        id: "dev".to_owned(),
                        channels: vec![7, 9],
                        groups: vec!["developers".to_owned()],
                        ..step::Choice::default()
                    },
                    step::Choice {
                        id: "art".to_owned(),
                        channels: vec![9, 11],
                        ..step::Choice::default()
                    },
                ],
                ..Step::default()
            }],
            ..Flow::default()
        }
    }

    fn answered(step_id: &str, choices: &[&str]) -> Response {
        Response {
            answers: vec![response::Answer {
                step_id: step_id.to_owned(),
                choice_ids: choices.iter().map(|id| (*id).to_owned()).collect(),
                text: String::new(),
            }],
            ..Response::default()
        }
    }

    #[test]
    fn an_answer_earns_what_the_flow_says_it_earns() {
        let found = wanted(&flow(), &answered("interests", &["dev"]));
        assert_eq!(found.channels, BTreeSet::from([1, 7, 9]));
        assert_eq!(found.groups, BTreeSet::from(["developers".to_owned()]));
    }

    #[test]
    fn a_channel_two_answers_reveal_is_granted_once() {
        // Channel 9 is on both choices. Two grants of one channel would write
        // the account into the group twice and read as two grants in the log.
        let found = wanted(&flow(), &answered("interests", &["dev", "art"]));
        assert_eq!(found.channels, BTreeSet::from([1, 7, 9, 11]));
    }

    #[test]
    fn a_client_cannot_invent_a_grant() {
        // The property the module exists to hold. Ids that name nothing in the
        // flow are worth nothing, however many are sent, the only thing left
        // is what everybody gets.
        let found = wanted(
            &flow(),
            &answered("interests", &["dev-admin", "", "root", "9"]),
        );
        assert_eq!(found.channels, BTreeSet::from([1]));
        assert!(found.groups.is_empty());
    }

    #[test]
    fn an_answer_to_a_deleted_question_grants_nothing() {
        // Ordinary after an operator edits the flow, and the stored answers of
        // everyone who took the old one are re-read on their next connection.
        let found = wanted(&flow(), &answered("gone", &["dev"]));
        assert_eq!(found.channels, BTreeSet::from([1]));
    }

    #[test]
    fn everyone_who_arrives_gets_the_defaults_without_answering() {
        let found = wanted(&flow(), &Response::default());
        assert_eq!(found.channels, BTreeSet::from([1]));
    }

    #[test]
    fn joining_is_idempotent() {
        // What makes it safe to re-apply on every connection: the second call
        // writes nothing, so no ACL is persisted and no invalidation is
        // published to every connected client.
        let mut set = AclSet::default();
        assert!(join(&mut set, 42, "developers"));
        assert!(!join(&mut set, 42, "developers"));
        assert_eq!(set.groups.len(), 1);
        assert_eq!(set.groups[0].add, vec![42]);
    }

    #[test]
    fn joining_leaves_the_other_members_alone() {
        let mut set = AclSet {
            groups: vec![Group {
                name: "developers".to_owned(),
                add: vec![1, 2],
                inherit: true,
                inheritable: true,
                ..Group::default()
            }],
            ..AclSet::default()
        };
        assert!(join(&mut set, 3, "developers"));
        assert_eq!(set.groups[0].add, vec![1, 2, 3]);
    }

    #[test]
    fn an_operator_removal_is_not_overruled() {
        // A closer `remove` beats an `add` when the group is resolved, so
        // re-adding would be a grant that looks applied and is inert. Refusing
        // to write it keeps the ACL honest about who is in the group.
        let mut set = AclSet {
            groups: vec![Group {
                name: "developers".to_owned(),
                remove: vec![42],
                ..Group::default()
            }],
            ..AclSet::default()
        };
        assert!(!join(&mut set, 42, "developers"));
        assert!(set.groups[0].add.is_empty());
    }

    #[test]
    fn revealing_grants_both_traverse_and_enter() {
        // Enter without Traverse is a channel a user may join and cannot see,
        // which every client renders as no channel at all.
        let mut set = AclSet::default();
        assert!(reveal_to(&mut set, REVEALED));
        let entry = &set.acls[0];
        assert_eq!(entry.group.as_deref(), Some(REVEALED));
        assert!(entry.apply_here);
        assert!(!entry.apply_subs, "a revealed room is not its sub-rooms");
        assert_eq!(entry.grant, Perm::TRAVERSE.union(Perm::ENTER).bits());
        assert!(!reveal_to(&mut set, REVEALED), "and it is idempotent");
    }

    #[test]
    fn revealing_widens_an_existing_entry_without_taking_anything_away() {
        // An operator who granted Speak to the same group keeps it.
        let mut set = AclSet {
            acls: vec![AclEntry {
                apply_here: true,
                group: Some(REVEALED.to_owned()),
                grant: Perm::SPEAK.bits(),
                ..AclEntry::default()
            }],
            ..AclSet::default()
        };
        assert!(reveal_to(&mut set, REVEALED));
        let granted = Perm::from_bits_truncate(set.acls[0].grant);
        assert!(granted.contains(Perm::SPEAK));
        assert!(granted.contains(Perm::TRAVERSE.union(Perm::ENTER)));
        assert_eq!(set.acls.len(), 1, "widened, not duplicated");
    }

    /// The evaluator's answer for `account` in `channel`, given `set`.
    ///
    /// Through the real one from `permissions`, never a re-implementation: the
    /// question this module has to answer is not "did I write the fields I
    /// meant to" but "does the server that reads them let this person in".
    fn granted(set: AclSet, channel: u32, account: u64) -> Perm {
        use starling_permissions::evaluate::{Acls, evaluate};
        use starling_proto_fancy::permissions::Subject;

        let acls = Acls::new();
        acls.set_parent(1, channel, 0);
        acls.set(1, set);
        Perm::from_bits_truncate(evaluate(
            &acls,
            1,
            &Subject {
                account,
                registered: true,
                ..Subject::default()
            },
            channel,
        ))
    }

    /// A channel an operator has hidden: nobody enters unless named.
    fn hidden(channel: u32) -> AclSet {
        AclSet {
            channel,
            inherit: true,
            acls: vec![AclEntry {
                apply_here: true,
                group: Some("all".to_owned()),
                deny: Perm::TRAVERSE.union(Perm::ENTER).bits(),
                ..AclEntry::default()
            }],
            groups: Vec::new(),
        }
    }

    #[test]
    fn a_revealed_channel_is_one_the_evaluator_lets_the_account_into() {
        // The whole feature, end to end through the real ACL evaluator: the
        // channel is hidden from everyone, onboarding names one account, and
        // that account, and only that account, gets in.
        //
        // Worth this much ceremony because every part of it is a way to be
        // wrong that no unit assertion on the fields would catch: an entry
        // written with `apply_subs` instead of `apply_here` matches nothing
        // here, a group left `inheritable: false` disappears one level down,
        // and both look perfectly correct in a debug print.
        let entered = Perm::TRAVERSE.union(Perm::ENTER);
        assert!(
            !granted(hidden(7), 7, 42).intersects(entered),
            "the channel starts hidden, or the rest of this proves nothing"
        );

        let mut set = hidden(7);
        assert!(join(&mut set, 42, REVEALED));
        assert!(reveal_to(&mut set, REVEALED));

        assert!(
            granted(set.clone(), 7, 42).contains(entered),
            "the account onboarding named must be able to traverse and enter"
        );
        assert!(
            !granted(set, 7, 43).intersects(entered),
            "and nobody else may, or the grant is a public door"
        );
    }

    #[test]
    fn the_grant_beats_a_blanket_deny_that_was_already_there() {
        // Entries are applied in order, each one granting and then denying, so
        // an entry appended after the operator's `deny @all` wins and one
        // inserted before it is silently erased. That ordering is the reason
        // `reveal_to` pushes rather than inserts, and nothing else in the code
        // says so.
        let mut set = hidden(7);
        let _ = join(&mut set, 42, REVEALED);
        let _ = reveal_to(&mut set, REVEALED);
        assert_eq!(
            set.acls.last().and_then(|entry| entry.group.as_deref()),
            Some(REVEALED)
        );
        assert!(granted(set, 7, 42).contains(Perm::ENTER));
    }

    #[test]
    fn a_group_declared_at_the_root_is_a_group_everywhere() {
        // What makes `Choice.groups` server-wide: the declaration goes on the
        // root and an operator writes `@developers` on any channel in the tree.
        // If the group were declared without `inheritable`, that ACL entry
        // would match nobody one level down and the whole feature would be a
        // group nothing is ever in.
        use starling_permissions::evaluate::{Acls, evaluate};
        use starling_proto_fancy::permissions::Subject;

        let mut root = AclSet {
            channel: 0,
            inherit: true,
            ..AclSet::default()
        };
        assert!(join(&mut root, 42, "developers"));

        let acls = Acls::new();
        acls.set_parent(1, 5, 0);
        acls.set(1, root);
        acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    group: Some("developers".to_owned()),
                    grant: Perm::MUTE_DEAFEN.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );

        let of = |account| {
            Perm::from_bits_truncate(evaluate(
                &acls,
                1,
                &Subject {
                    account,
                    registered: true,
                    ..Subject::default()
                },
                5,
            ))
        };
        assert!(of(42).contains(Perm::MUTE_DEAFEN));
        assert!(!of(43).contains(Perm::MUTE_DEAFEN));
    }

    #[test]
    fn an_inherited_entry_is_not_edited_in_place() {
        // Inherited entries are a *view* of an ancestor's set; writing to one
        // here would either be discarded or, worse, copy an ancestor's rule
        // into this channel where it stops tracking the ancestor.
        let mut set = AclSet {
            acls: vec![AclEntry {
                apply_here: true,
                inherited: true,
                group: Some(REVEALED.to_owned()),
                grant: 0,
                ..AclEntry::default()
            }],
            ..AclSet::default()
        };
        assert!(reveal_to(&mut set, REVEALED));
        assert_eq!(set.acls.len(), 2);
        assert!(!set.acls[1].inherited);
    }
}
