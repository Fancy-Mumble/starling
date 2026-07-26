//! Every repository, exercised against a real database.
//!
//! In the crate rather than in `tests/` because clippy's
//! `allow-expect-in-tests` keys on `cfg(test)`, which an integration-test
//! crate does not set — so `tests/` would need an `#[allow]` that an in-crate
//! module does not.

#![cfg(test)]

use super::SqlStore;

use starling_api::{
    AclTarget, Store, StoredAcl, StoredBan, StoredChannel, StoredGroup, StoredGroupMember,
    StoredListener, StoredUser,
};
use starling_model::{ChannelId, UserId};

/// A fresh, empty store with the schema applied.
///
/// Each test gets its own in-memory database, so they cannot interfere and can
/// run in parallel.
async fn store() -> SqlStore {
    SqlStore::open("sqlite::memory:", 1)
        .await
        .expect("opening an in-memory store")
}

/// A store with a root channel, which most things need a foreign key to.
async fn with_root() -> SqlStore {
    let store = store().await;
    store
        .channels()
        .save(&StoredChannel::new(ChannelId(0), None, "Root"))
        .await
        .expect("saving the root channel");
    store
}

// ---------------------------------------------------------------- channels

#[tokio::test]
async fn a_channel_survives_a_round_trip_with_every_field() {
    let store = with_root().await;
    let channel = StoredChannel {
        id: ChannelId(1),
        parent: Some(ChannelId(0)),
        name: "Lobby".into(),
        inherit_acl: false,
        description: "<b>welcome</b>".into(),
        position: -3,
        max_users: 25,
    };
    store.channels().save(&channel).await.expect("save");

    let all = store.channels().all().await.expect("read");
    let found = all
        .iter()
        .find(|c| c.id == ChannelId(1))
        .expect("the channel was not stored");
    assert_eq!(found, &channel, "a field did not survive the round trip");
}

#[tokio::test]
async fn the_root_channel_has_no_parent() {
    // `NULL` rather than a sentinel id: a root pointing at itself would make
    // every tree walk a loop.
    let store = with_root().await;
    let all = store.channels().all().await.expect("read");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].parent, None);
}

#[tokio::test]
async fn saving_a_channel_twice_replaces_rather_than_duplicates() {
    let store = with_root().await;
    let mut channel = StoredChannel::new(ChannelId(1), Some(ChannelId(0)), "Before");
    store.channels().save(&channel).await.expect("first");
    channel.name = "After".into();
    store.channels().save(&channel).await.expect("second");

    let all = store.channels().all().await.expect("read");
    assert_eq!(all.len(), 2, "the channel was duplicated");
    assert!(all.iter().any(|c| c.name == "After"));
}

#[tokio::test]
async fn removing_a_channel_takes_its_children_and_acls() {
    // The cascade. murmur writes each of these deletes by hand at every call
    // site, and a forgotten one leaves rows pointing at nothing.
    let store = with_root().await;
    for (id, parent) in [(1, 0), (2, 1)] {
        store
            .channels()
            .save(&StoredChannel::new(
                ChannelId(id),
                Some(ChannelId(parent)),
                format!("c{id}"),
            ))
            .await
            .expect("save");
    }
    store
        .acls()
        .replace_channel(
            ChannelId(2),
            &[StoredAcl {
                channel: ChannelId(2),
                priority: 0,
                target: AclTarget::Group("all".into()),
                apply_in_current: true,
                apply_in_sub: true,
                granted: 1,
                revoked: 0,
            }],
        )
        .await
        .expect("acl");

    store.channels().remove(ChannelId(1)).await.expect("remove");

    let all = store.channels().all().await.expect("read");
    assert_eq!(all.len(), 1, "only the root should remain");
    assert!(
        store
            .acls()
            .for_channel(ChannelId(2))
            .await
            .expect("read")
            .is_empty(),
        "the grandchild's ACLs outlived it"
    );
}

#[tokio::test]
async fn removing_a_channel_that_is_not_there_is_not_an_error() {
    // The caller's intent is "make it absent", and it already is.
    let store = store().await;
    store
        .channels()
        .remove(ChannelId(99))
        .await
        .expect("remove");
}

#[tokio::test]
async fn links_are_symmetric_however_they_are_given() {
    let store = with_root().await;
    for id in [1, 2] {
        store
            .channels()
            .save(&StoredChannel::new(
                ChannelId(id),
                Some(ChannelId(0)),
                format!("c{id}"),
            ))
            .await
            .expect("save");
    }

    store
        .channels()
        .link(ChannelId(2), ChannelId(1))
        .await
        .expect("link in reverse order");
    assert_eq!(
        store.channels().links().await.expect("read"),
        vec![(ChannelId(1), ChannelId(2))],
        "the pair was not stored canonically"
    );

    // And unlinking in the other order must still find it — the bug that a
    // non-canonical store would hide.
    store
        .channels()
        .unlink(ChannelId(1), ChannelId(2))
        .await
        .expect("unlink");
    assert!(store.channels().links().await.expect("read").is_empty());
}

#[tokio::test]
async fn linking_the_same_pair_twice_is_not_an_error() {
    let store = with_root().await;
    for id in [1, 2] {
        store
            .channels()
            .save(&StoredChannel::new(ChannelId(id), Some(ChannelId(0)), "c"))
            .await
            .expect("save");
    }
    store
        .channels()
        .link(ChannelId(1), ChannelId(2))
        .await
        .expect("first");
    store
        .channels()
        .link(ChannelId(1), ChannelId(2))
        .await
        .expect("second");
    assert_eq!(store.channels().links().await.expect("read").len(), 1);
}

#[tokio::test]
async fn a_listener_round_trips_and_can_be_removed() {
    let store = with_root().await;
    store
        .users()
        .save(&StoredUser::new(UserId(1), "alice"))
        .await
        .expect("user");

    let listener = StoredListener {
        user: UserId(1),
        channel: ChannelId(0),
        volume_adjustment: -50,
    };
    store.channels().add_listener(listener).await.expect("add");
    assert_eq!(
        store.channels().listeners().await.expect("read"),
        vec![listener]
    );

    store
        .channels()
        .remove_listener(UserId(1), ChannelId(0))
        .await
        .expect("remove");
    assert!(store.channels().listeners().await.expect("read").is_empty());
}

// ------------------------------------------------------------------- users

#[tokio::test]
async fn an_account_survives_a_round_trip_with_every_field() {
    let store = with_root().await;
    let user = StoredUser {
        id: UserId(7),
        name: "alice".into(),
        password_hash: Some("hash".into()),
        salt: Some("salt".into()),
        kdf_iterations: Some(100_000),
        cert_hash: Some("aa:bb".into()),
        last_channel: Some(ChannelId(0)),
        last_active: Some(1_700_000_000),
        last_disconnect: Some(1_700_000_100),
    };
    store.users().save(&user).await.expect("save");

    assert_eq!(
        store.users().by_id(UserId(7)).await.expect("read"),
        Some(user.clone())
    );
    assert_eq!(
        store.users().by_name("alice").await.expect("read"),
        Some(user.clone())
    );
    assert_eq!(
        store.users().by_cert_hash("aa:bb").await.expect("read"),
        Some(user)
    );
}

#[tokio::test]
async fn account_names_are_case_sensitive() {
    // murmur treats these as different registrations. Matching loosely would
    // let one account authenticate as another.
    let store = store().await;
    store
        .users()
        .save(&StoredUser::new(UserId(1), "Alice"))
        .await
        .expect("save");
    assert!(
        store
            .users()
            .by_name("Alice")
            .await
            .expect("read")
            .is_some()
    );
    assert!(
        store
            .users()
            .by_name("alice")
            .await
            .expect("read")
            .is_none(),
        "a lowercase lookup matched a capitalised account"
    );
}

#[tokio::test]
async fn two_accounts_cannot_share_a_name() {
    let store = store().await;
    store
        .users()
        .save(&StoredUser::new(UserId(1), "alice"))
        .await
        .expect("first");
    assert!(
        store
            .users()
            .save(&StoredUser::new(UserId(2), "alice"))
            .await
            .is_err(),
        "a duplicate account name was accepted"
    );
}

#[tokio::test]
async fn an_absent_account_reads_as_none_not_an_error() {
    let store = store().await;
    assert_eq!(store.users().by_id(UserId(9)).await.expect("read"), None);
    assert_eq!(store.users().by_name("nobody").await.expect("read"), None);
}

#[tokio::test]
async fn ids_are_allocated_above_the_highest_in_use() {
    // SuperUser is 0 and must never be handed out again.
    let store = store().await;
    assert_eq!(store.users().next_id().await.expect("id"), UserId(1));

    store
        .users()
        .save(&StoredUser::new(UserId(41), "alice"))
        .await
        .expect("save");
    assert_eq!(store.users().next_id().await.expect("id"), UserId(42));
}

#[tokio::test]
async fn account_properties_round_trip_and_replace() {
    let store = store().await;
    store
        .users()
        .save(&StoredUser::new(UserId(1), "alice"))
        .await
        .expect("save");

    store
        .users()
        .set_property(UserId(1), "comment", "hello")
        .await
        .expect("set");
    store
        .users()
        .set_property(UserId(1), "comment", "goodbye")
        .await
        .expect("replace");
    store
        .users()
        .set_property(UserId(1), "texture", "png")
        .await
        .expect("set");

    let mut properties = store.users().properties(UserId(1)).await.expect("read");
    properties.sort();
    assert_eq!(
        properties,
        vec![
            ("comment".to_owned(), "goodbye".to_owned()),
            ("texture".to_owned(), "png".to_owned()),
        ]
    );
}

#[tokio::test]
async fn removing_an_account_takes_its_properties() {
    let store = store().await;
    store
        .users()
        .save(&StoredUser::new(UserId(1), "alice"))
        .await
        .expect("save");
    store
        .users()
        .set_property(UserId(1), "comment", "hi")
        .await
        .expect("set");

    store.users().remove(UserId(1)).await.expect("remove");
    assert!(
        store
            .users()
            .properties(UserId(1))
            .await
            .expect("read")
            .is_empty()
    );
}

// -------------------------------------------------------------------- acls

#[tokio::test]
async fn acl_entries_round_trip_in_priority_order() {
    // The order is the semantics: later entries override earlier ones.
    let store = with_root().await;
    let entry = |priority, target| StoredAcl {
        channel: ChannelId(0),
        priority,
        target,
        apply_in_current: true,
        apply_in_sub: false,
        granted: 0x1F,
        revoked: 0x20,
    };
    store
        .acls()
        .replace_channel(
            ChannelId(0),
            &[
                entry(10, AclTarget::Group("admin".into())),
                entry(1, AclTarget::User(UserId(3))),
            ],
        )
        .await
        .expect("replace");

    let read = store.acls().for_channel(ChannelId(0)).await.expect("read");
    assert_eq!(read.len(), 2);
    assert_eq!(
        read[0].priority, 1,
        "entries came back out of priority order"
    );
    assert_eq!(read[0].target, AclTarget::User(UserId(3)));
    assert_eq!(read[1].target, AclTarget::Group("admin".into()));
    assert_eq!(read[0].granted, 0x1F);
    assert_eq!(read[0].revoked, 0x20);
    assert!(!read[0].apply_in_sub);
}

#[tokio::test]
async fn replacing_acls_removes_what_was_there() {
    let store = with_root().await;
    let entry = StoredAcl {
        channel: ChannelId(0),
        priority: 0,
        target: AclTarget::Group("all".into()),
        apply_in_current: true,
        apply_in_sub: true,
        granted: 1,
        revoked: 0,
    };
    store
        .acls()
        .replace_channel(ChannelId(0), &[entry])
        .await
        .expect("first");
    store
        .acls()
        .replace_channel(ChannelId(0), &[])
        .await
        .expect("clear");
    assert!(
        store
            .acls()
            .for_channel(ChannelId(0))
            .await
            .expect("read")
            .is_empty()
    );
}

#[tokio::test]
async fn a_group_round_trips_and_gets_an_id() {
    let store = with_root().await;
    let id = store
        .acls()
        .save_group(&StoredGroup {
            id: 0,
            channel: ChannelId(0),
            name: "admin".into(),
            inherit: false,
            inheritable: true,
        })
        .await
        .expect("save");
    assert!(id > 0, "the database did not assign an id");

    let groups = store.acls().groups(ChannelId(0)).await.expect("read");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "admin");
    assert!(!groups[0].inherit);
    assert!(groups[0].inheritable);
}

#[tokio::test]
async fn group_members_distinguish_adding_from_removing() {
    // The distinction that lets a sub-channel override its parent: a membership
    // row can mean "add" or "take away what inheritance would have granted".
    let store = with_root().await;
    let group = store
        .acls()
        .save_group(&StoredGroup {
            id: 0,
            channel: ChannelId(0),
            name: "admin".into(),
            inherit: true,
            inheritable: true,
        })
        .await
        .expect("group");
    for id in [1, 2] {
        store
            .users()
            .save(&StoredUser::new(UserId(id), format!("u{id}")))
            .await
            .expect("user");
    }

    store
        .acls()
        .replace_members(
            group,
            &[
                StoredGroupMember {
                    group,
                    user: UserId(1),
                    add: true,
                },
                StoredGroupMember {
                    group,
                    user: UserId(2),
                    add: false,
                },
            ],
        )
        .await
        .expect("members");

    let members = store.acls().members(group).await.expect("read");
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|m| m.user == UserId(1) && m.add));
    assert!(members.iter().any(|m| m.user == UserId(2) && !m.add));
}

#[tokio::test]
async fn removing_a_group_takes_its_members() {
    let store = with_root().await;
    let group = store
        .acls()
        .save_group(&StoredGroup {
            id: 0,
            channel: ChannelId(0),
            name: "admin".into(),
            inherit: true,
            inheritable: true,
        })
        .await
        .expect("group");
    store
        .users()
        .save(&StoredUser::new(UserId(1), "alice"))
        .await
        .expect("user");
    store
        .acls()
        .replace_members(
            group,
            &[StoredGroupMember {
                group,
                user: UserId(1),
                add: true,
            }],
        )
        .await
        .expect("members");

    store.acls().remove_group(group).await.expect("remove");
    assert!(store.acls().members(group).await.expect("read").is_empty());
    assert!(
        store
            .acls()
            .groups(ChannelId(0))
            .await
            .expect("read")
            .is_empty()
    );
}

// -------------------------------------------------------------------- bans

#[tokio::test]
async fn bans_round_trip_including_permanent_ones() {
    let store = store().await;
    let permanent = StoredBan {
        address: "2001:db8::1".into(),
        prefix_length: 128,
        name: Some("troll".into()),
        cert_hash: None,
        reason: Some("repeatedly".into()),
        start: 1_000,
        expires_at: None,
    };
    let temporary = StoredBan {
        address: "::ffff:192.0.2.1".into(),
        prefix_length: 120,
        name: None,
        cert_hash: Some("aa:bb".into()),
        reason: None,
        start: 2_000,
        expires_at: Some(3_000),
    };
    store
        .bans()
        .replace_all(&[permanent.clone(), temporary.clone()])
        .await
        .expect("replace");

    let read = store.bans().all().await.expect("read");
    assert_eq!(read, vec![permanent, temporary]);
    assert_eq!(read[0].expires_at, None, "a permanent ban gained an expiry");
}

#[tokio::test]
async fn pruning_removes_lapsed_bans_and_keeps_permanent_ones() {
    // The reason `expires_at` is nullable rather than murmur's `duration = 0`:
    // a permanent ban must survive every prune, and `0` compares as expired.
    let store = store().await;
    store
        .bans()
        .replace_all(&[
            StoredBan {
                address: "::1".into(),
                prefix_length: 128,
                name: None,
                cert_hash: None,
                reason: None,
                start: 0,
                expires_at: None,
            },
            StoredBan {
                address: "::2".into(),
                prefix_length: 128,
                name: None,
                cert_hash: None,
                reason: None,
                start: 0,
                expires_at: Some(500),
            },
        ])
        .await
        .expect("replace");

    let removed = store.bans().prune_expired(1_000).await.expect("prune");
    assert_eq!(removed, 1);

    let remaining = store.bans().all().await.expect("read");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].address, "::1", "the permanent ban was pruned");
}

// ------------------------------------------------------------------ config

#[tokio::test]
async fn settings_round_trip_and_replace() {
    let store = store().await;
    store
        .config()
        .set("welcometext", "hello")
        .await
        .expect("set");
    store
        .config()
        .set("welcometext", "hi")
        .await
        .expect("replace");
    store.config().set("port", "64738").await.expect("set");

    assert_eq!(
        store.config().get("welcometext").await.expect("read"),
        Some("hi".to_owned())
    );
    assert_eq!(store.config().all().await.expect("read").len(), 2);

    store.config().clear("port").await.expect("clear");
    assert_eq!(store.config().get("port").await.expect("read"), None);
}

#[tokio::test]
async fn an_unset_setting_reads_as_none() {
    let store = store().await;
    assert_eq!(store.config().get("nothing").await.expect("read"), None);
}

// --------------------------------------------------------------------- log

#[tokio::test]
async fn log_entries_come_back_newest_first() {
    let store = store().await;
    for (at, message) in [(100, "first"), (200, "second"), (300, "third")] {
        store.log().append(at, message).await.expect("append");
    }

    let recent = store.log().recent(2).await.expect("read");
    assert_eq!(recent.len(), 2, "the limit was not applied");
    assert_eq!(recent[0].1, "third");
    assert_eq!(recent[1].1, "second");
}

#[tokio::test]
async fn entries_sharing_a_timestamp_have_a_stable_order() {
    // Without the tiebreak, paging through the log could show one entry twice
    // and skip another.
    let store = store().await;
    for message in ["a", "b", "c"] {
        store.log().append(100, message).await.expect("append");
    }
    let first = store.log().recent(10).await.expect("read");
    let second = store.log().recent(10).await.expect("read");
    assert_eq!(first, second, "the order of equal timestamps is unstable");
}

#[tokio::test]
async fn pruning_the_log_removes_only_what_is_older() {
    let store = store().await;
    for at in [100, 200, 300] {
        store.log().append(at, "entry").await.expect("append");
    }

    let removed = store.log().prune(250).await.expect("prune");
    assert_eq!(removed, 2);
    assert_eq!(store.log().recent(10).await.expect("read").len(), 1);
}

// ----------------------------------------------------------------- scoping

#[tokio::test]
async fn two_virtual_servers_do_not_see_each_others_data() {
    // Every table carries a `server_id` and every query filters on it. A missing
    // filter would leak one server's users, channels and bans into another's —
    // which is why the id is on the store rather than on each call.
    let backend = crate::Backend::connect("sqlite:file:scoping?mode=memory&cache=shared")
        .await
        .expect("connect");
    crate::schema::migrate(&backend).await.expect("migrate");

    let first = SqlStore::with_backend(backend.clone(), 1);
    let second = SqlStore::with_backend(backend, 2);

    first
        .users()
        .save(&StoredUser::new(UserId(1), "alice"))
        .await
        .expect("save");
    first
        .config()
        .set("welcometext", "first server")
        .await
        .expect("set");

    assert!(second.users().all().await.expect("read").is_empty());
    assert_eq!(
        second.config().get("welcometext").await.expect("read"),
        None
    );
    assert_eq!(first.users().all().await.expect("read").len(), 1);

    // And the same name is free on the other server, because the uniqueness
    // constraint is per server rather than global.
    second
        .users()
        .save(&StoredUser::new(UserId(1), "alice"))
        .await
        .expect("the same name must be available on another server");
}
