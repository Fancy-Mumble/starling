//! Invite links, end to end: minted over a Fancy connection, redeemed by a
//! stock one through its access tokens, against a server with a password.
//!
//! Apart from `e2e.rs` because the feature crosses three services - `invites`
//! mints, `session-lifecycle` redeems, `server-config` decides who may - and
//! only a whole deployment shows the three agreeing.

#![allow(
    unused_crate_dependencies,
    reason = "the manifest's dependencies are shared across targets"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failed assumption is the test result"
)]
#![allow(clippy::too_many_lines, reason = "an e2e scenario is a long script")]

use std::time::Duration;

use prost::Message as _;
use starling_harness::{
    CLIENT_FANCY_PROTOCOL, Client, Deployment, FRAME_TIMEOUT, MUMBLE_VERSION_V2, TempDir,
    handshake_as,
};
use starling_proto::proto::tcp;
use starling_proto_fancy::fancy::invites::{
    Invite, InviteCreate, InviteListQuery, InviteRevoke, InviteSupport, InviteSupportQuery,
    InvitesEnvelope, invite_refused, invites_envelope,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::{AclEntry, AclSet};
use starling_proto_fancy::types::ServiceKind;
use tokio::time::timeout;

const PASSWORD: &str = "correct horse";

/// A deployment with a server password, where everybody may administer the
/// root - so the first user in can mint invites without a registration dance.
async fn private_server(tag: &str) -> (TempDir, Deployment) {
    let data_dir = TempDir::new(tag);
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        config.instances[0].settings.password = Some(PASSWORD.to_owned());
    })
    .await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![AclEntry {
                apply_here: true,
                apply_subs: true,
                group: Some("all".to_owned()),
                grant: (Perm::WRITE | Perm::ENTER | Perm::TRAVERSE).bits(),
                deny: 0,
                ..AclEntry::default()
            }],
            groups: Vec::new(),
        })
        .await;
    (data_dir, deployment)
}

/// The epoch-1 handshake with the `Authenticate` spelled out, so a Fancy
/// client can present a password. Returns the session.
async fn fancy_login(client: &mut Client, authenticate: tcp::Authenticate) -> u32 {
    let (greeting, _) = client.recv().await;
    assert_eq!(greeting, 0, "the server speaks Version first");
    client
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                fancy_protocol: Some(CLIENT_FANCY_PROTOCOL),
                ..tcp::Version::default()
            },
        )
        .await;
    client.send(2, &authenticate).await;
    let (_, sync) = client.recv_until(5).await;
    tcp::ServerSync::decode(sync.as_slice())
        .expect("a well-formed ServerSync")
        .session
        .expect("ServerSync carries the session id")
}

/// Log in as a Fancy client that knows the password.
async fn member(deployment: &Deployment, name: &str) -> (Client, u32) {
    let mut client = Client::connect(deployment.port).await;
    let session = fancy_login(
        &mut client,
        tcp::Authenticate {
            username: Some(name.to_owned()),
            password: Some(PASSWORD.to_owned()),
            opus: Some(true),
            ..tcp::Authenticate::default()
        },
    )
    .await;
    (client, session)
}

/// Log in as a Fancy guest on a server without a password.
async fn fancy_guest(deployment: &Deployment, name: &str) -> Client {
    let mut client = Client::connect(deployment.port).await;
    let _ = fancy_login(
        &mut client,
        tcp::Authenticate {
            username: Some(name.to_owned()),
            opus: Some(true),
            ..tcp::Authenticate::default()
        },
    )
    .await;
    client
}

/// Log in as a stock client that knows no password, presenting `tokens`.
async fn guest(deployment: &Deployment, name: &str, tokens: Vec<String>) -> (Client, u32) {
    let mut client = Client::connect(deployment.port).await;
    let session = handshake_as(
        &mut client,
        tcp::Authenticate {
            username: Some(name.to_owned()),
            tokens,
            opus: Some(true),
            ..tcp::Authenticate::default()
        },
        None,
    )
    .await;
    (client, session)
}

/// Try to log in without the password, and return the refusal's type.
async fn refused(deployment: &Deployment, name: &str, tokens: Vec<String>) -> Option<i32> {
    let mut client = Client::connect(deployment.port).await;
    let (greeting, _) = client.recv().await;
    assert_eq!(greeting, 0, "the server speaks Version first");
    client
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                ..tcp::Version::default()
            },
        )
        .await;
    client
        .send(
            2,
            &tcp::Authenticate {
                username: Some(name.to_owned()),
                tokens,
                ..tcp::Authenticate::default()
            },
        )
        .await;
    let (seen, payload) = client.recv_until(4).await;
    assert!(
        !seen.contains(&7),
        "a refused login must never be sent ServerSync; saw {seen:?}"
    );
    tcp::Reject::decode(payload.as_slice())
        .expect("a well-formed Reject")
        .r#type
}

/// Send one envelope body and wait for the service's answer.
async fn ask(client: &mut Client, body: invites_envelope::Body) -> invites_envelope::Body {
    let outer = ServiceKind::Invites.outer_type();
    client
        .send(outer, &InvitesEnvelope { body: Some(body) })
        .await;
    timeout(FRAME_TIMEOUT, async {
        loop {
            let (type_id, payload) = client.recv().await;
            if type_id != outer {
                continue;
            }
            let envelope = InvitesEnvelope::decode(payload.as_slice()).expect("an envelope");
            if let Some(body) = envelope.body {
                return body;
            }
        }
    })
    .await
    .expect("the invites service never answered")
}

async fn support(client: &mut Client) -> InviteSupport {
    match ask(
        client,
        invites_envelope::Body::SupportQuery(InviteSupportQuery {
            request_id: "s".to_owned(),
        }),
    )
    .await
    {
        invites_envelope::Body::Support(support) => support,
        other => panic!("expected InviteSupport, got {other:?}"),
    }
}

async fn create(client: &mut Client, channel_id: u32, max_uses: u32) -> Invite {
    match ask(
        client,
        invites_envelope::Body::Create(InviteCreate {
            request_id: "c".to_owned(),
            channel_id,
            max_age_s: 3600,
            max_uses,
        }),
    )
    .await
    {
        invites_envelope::Body::Created(created) => {
            assert_eq!(created.request_id, "c", "the answer echoes the request");
            created.invite.expect("the invite")
        }
        other => panic!("expected InviteCreated, got {other:?}"),
    }
}

fn token(invite: &Invite) -> Vec<String> {
    vec![format!("invite:{}", invite.code)]
}

#[tokio::test]
async fn an_invite_lets_a_stranger_past_the_password_and_into_its_channel() {
    let (_dir, deployment) = private_server("invite-admits").await;
    let lounge = deployment.create_channel("Lounge").await;

    let (mut alice, alice_session) = member(&deployment, "alice").await;
    deployment
        .wait_until_permitted(alice_session, 0, Perm::WRITE.bits())
        .await;

    let terms = support(&mut alice).await;
    assert!(terms.available, "invites are on for admins by default");
    assert!(
        terms.may_create && terms.may_manage,
        "alice holds Write on the root"
    );
    assert!(terms.skips_password, "invites skip the password by default");
    assert_eq!(terms.max_age_s, 168 * 3600, "the default week");

    let invite = create(&mut alice, lounge, 0).await;
    assert_eq!(invite.channel_id, lounge);
    assert!(invite.mine, "alice made it");
    assert_eq!(invite.creator, "alice");
    assert!(
        invite.expires_ms > invite.created_ms,
        "an hour was asked for"
    );

    // Bob has a stock client and no password; the invite is in his token box.
    let (_bob, bob_session) = guest(&deployment, "bob", token(&invite)).await;
    let landed = timeout(FRAME_TIMEOUT, async {
        loop {
            if alice.next_channel_of(bob_session).await == lounge {
                return;
            }
        }
    })
    .await;
    assert!(landed.is_ok(), "the invite must land bob in its channel");

    // Without the invite the password is still the door.
    assert_eq!(
        refused(&deployment, "carol", Vec::new()).await,
        Some(tcp::reject::RejectType::WrongServerPw as i32)
    );
    // And a code nobody minted is no invite: the same answer, so a login
    // cannot be used to learn which codes exist.
    assert_eq!(
        refused(&deployment, "dave", vec!["invite:aaaaaaaaaaaa".to_owned()]).await,
        Some(tcp::reject::RejectType::WrongServerPw as i32)
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_use_is_a_person_and_a_revoked_invite_admits_nobody() {
    let (_dir, deployment) = private_server("invite-uses").await;
    let (mut alice, alice_session) = member(&deployment, "alice").await;
    deployment
        .wait_until_permitted(alice_session, 0, Perm::WRITE.bits())
        .await;

    let invite = create(&mut alice, 0, 1).await;
    assert_eq!(invite.max_uses, 1);

    let (bob, _) = guest(&deployment, "bob", token(&invite)).await;
    bob.close().await;
    // Bob again: the same person, so not a second use.
    let (bob, _) = guest(&deployment, "bob", token(&invite)).await;
    bob.close().await;
    // Carol is a second person, and there was only one use.
    assert_eq!(
        refused(&deployment, "carol", token(&invite)).await,
        Some(tcp::reject::RejectType::WrongServerPw as i32)
    );

    let listed = match ask(
        &mut alice,
        invites_envelope::Body::ListQuery(InviteListQuery {
            request_id: "l".to_owned(),
            everyone: true,
        }),
    )
    .await
    {
        invites_envelope::Body::List(list) => list.invites,
        other => panic!("expected InviteList, got {other:?}"),
    };
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].uses, 1, "bob twice is one use");

    match ask(
        &mut alice,
        invites_envelope::Body::Revoke(InviteRevoke {
            request_id: "r".to_owned(),
            code: invite.code.clone(),
        }),
    )
    .await
    {
        invites_envelope::Body::Revoked(revoked) => assert_eq!(revoked.code, invite.code),
        other => panic!("expected InviteRevoked, got {other:?}"),
    }
    assert_eq!(
        refused(&deployment, "bob", token(&invite)).await,
        Some(tcp::reject::RejectType::WrongServerPw as i32),
        "a revoked invite re-admits nobody, not even the people it let in"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn only_the_people_the_operator_names_may_mint_invites() {
    // The default ACL and the default `invites = "admins"`: a guest is not an
    // administrator, so they are told up front and refused if they try anyway.
    let data_dir = TempDir::new("invite-policy");
    let deployment = Deployment::start(data_dir.path()).await;
    let mut alice = fancy_guest(&deployment, "alice").await;

    let terms = support(&mut alice).await;
    assert!(terms.available, "invites are on by default");
    assert!(
        !terms.may_create && !terms.may_manage,
        "a guest is no administrator"
    );
    match ask(
        &mut alice,
        invites_envelope::Body::Create(InviteCreate {
            request_id: "c".to_owned(),
            ..InviteCreate::default()
        }),
    )
    .await
    {
        invites_envelope::Body::Refused(refusal) => {
            assert_eq!(refusal.request_id, "c");
            assert_eq!(refusal.reason, invite_refused::Reason::Permission as i32);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    deployment.stop().await;

    // Switched off: nobody is offered anything.
    let data_dir = TempDir::new("invite-off");
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        config.instances[0].settings.invites = Some("off".to_owned());
    })
    .await;
    let mut alice = fancy_guest(&deployment, "alice").await;
    // The settings reach `invites` through a watch; give it a moment rather
    // than race the first snapshot.
    let off = timeout(Duration::from_secs(10), async {
        loop {
            if !support(&mut alice).await.available {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(off.is_ok(), "invites = \"off\" must say so");
    deployment.stop().await;
}
