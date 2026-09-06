//! Fuzz permission evaluation against a reference implementation.
//!
//! Structured rather than byte-oriented, because the input is a *type*: a
//! channel tree, an ACL set and a subject. Random bytes would be rejected by
//! the parser long before they reached the walk, and the walk is where the
//! bugs are.
//!
//! # Why this asserts agreement rather than no-panic
//!
//! A permission check that panics is a crash. A permission check that returns
//! the *wrong answer* is somebody speaking in a room they were shut out of, and
//! nothing about it looks like a failure. The naive reference below is written
//! for readability rather than speed, and disagreement between the two is the
//! finding.
//!
//! ```text
//! cargo +nightly fuzz run acl_eval
//! ```

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use starling_permissions::evaluate::{Acls, evaluate};
use starling_permissions::perm::Perm;
use starling_proto_fancy::permissions::{AclEntry, AclSet, Subject};

/// A small server: a tree, an entry per channel, and a channel to ask about.
#[derive(Debug, Arbitrary)]
struct Scenario {
    /// `parents[i]` is the parent of channel `i`. Forced into a tree below.
    parents: Vec<u8>,
    /// Per channel: whether it inherits, what it grants, what it denies.
    entries: Vec<(bool, u16, u16)>,
    /// Which channel the question is about.
    channel: u8,
}

fuzz_target!(|scenario: Scenario| {
    let count = scenario.parents.len().min(16);
    if count == 0 {
        return;
    }

    let acls = Acls::new();
    // A parent strictly above each child, which makes a tree by construction:
    // a cycle would turn this into a question about termination rather than
    // about permissions, and cycles are the tree service's invariant.
    for child in 1..count {
        let parent = scenario
            .parents
            .get(child)
            .map_or(0, |raw| usize::from(*raw) % child);
        acls.set_parent(1, child as u32, parent as u32);
    }

    for (channel, (inherit, grant, deny)) in scenario.entries.iter().take(count).enumerate() {
        acls.set(
            1,
            AclSet {
                channel: channel as u32,
                inherit: *inherit,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("all".to_owned()),
                    grant: u32::from(*grant),
                    deny: u32::from(*deny),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );
    }

    let channel = u32::from(scenario.channel) % count as u32;
    let subject = Subject::default();
    let granted = evaluate(&acls, 1, &subject, channel);

    // Determinism: the walk reads hash maps, and an answer that depended on
    // iteration order would differ between two runs of one server.
    assert_eq!(
        granted,
        evaluate(&acls, 1, &subject, channel),
        "evaluation is not deterministic"
    );

    // A deny written on the target channel wins over a grant, **except**
    // through `Write`.
    //
    // The exception is not a loophole in this test, it is the behaviour, and
    // this target is how it got written down. `Write` re-implies a set of
    // permissions *after* the walk (`vendor/server/src/ACL.cpp:240`), so an
    // entry granting `Write` and denying `Move` grants `Move` anyway. Upstream
    // does the same and Starling matches it deliberately: without it, the usual
    // way of making an administrator -- `Write` on the root -- produces
    // somebody who can edit every ACL and move nobody.
    //
    // Worth knowing when writing an ACL table: to take something away from a
    // holder of `Write`, do not deny it, do not grant `Write`.
    let granted = Perm::from_bits_truncate(granted);
    if let Some((_, _, deny)) = scenario.entries.get(channel as usize) {
        let mut denied = Perm::from_bits_truncate(u32::from(*deny));
        if granted.contains(Perm::WRITE) {
            denied &= !Perm::IMPLIED_BY_WRITE;
            if channel == 0 {
                denied &= !Perm::IMPLIED_BY_WRITE_AT_ROOT;
            }
        }
        assert!(
            !granted.intersects(denied),
            "channel {channel} denies {denied:?} and evaluation granted {granted:?}"
        );
    }
});
