//! What becomes of a comment or an avatar once nobody shows it.
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
use sha1::{Digest as _, Sha1};
use starling_harness::{Client, Deployment, FRAME_TIMEOUT, TempDir, handshake};
use starling_proto::proto::tcp;
use starling_proto_fancy::common::Scope;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::{AclEntry, AclSet};
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::serverconfig::{Livery, SetLiveryRequest};
use starling_proto_fancy::userdata::user_data_client::UserDataClient;
use starling_proto_fancy::userdata::{Blob, BlobRequest};

/// Whether the blob store still holds `bytes`, waiting for it to settle on
/// `expected`: releases travel as their own calls after the frame.
async fn settles(deployment: &Deployment, bytes: &[u8], expected: bool) -> bool {
    let hash = Sha1::digest(bytes).to_vec();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let transport = deployment.resolver.channel("userdata").expect("dial");
        let held = UserDataClient::new(transport)
            .get_blob(BlobRequest {
                scope: None,
                hash: hash.clone(),
            })
            .await
            .is_ok();
        if held == expected || tokio::time::Instant::now() > deadline {
            return held == expected;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Set this guest's avatar, paced past the control bucket.
async fn wear(client: &mut Client, avatar: &[u8]) {
    tokio::time::sleep(Duration::from_millis(1100)).await;
    client
        .send(
            9,
            &tcp::UserState {
                texture: Some(avatar.to_vec()),
                ..tcp::UserState::default()
            },
        )
        .await;
}

#[tokio::test]
async fn a_guests_avatar_is_let_go_when_nobody_wears_it_any_more() {
    // Nothing ever released a blob: every avatar a guest set stayed stored
    // after they replaced it and after they left.
    let data = TempDir::new("content-guest");
    let deployment = Deployment::start(data.path()).await;
    let mut ann = Client::connect(deployment.port).await;
    let _ = handshake(&mut ann, "ann").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    wear(&mut ann, b"a shared face").await;
    wear(&mut bob, b"a shared face").await;
    assert!(settles(&deployment, b"a shared face", true).await, "stored");

    ann.close().await;
    assert!(
        settles(&deployment, b"a shared face", true).await,
        "bob still wears it"
    );

    wear(&mut bob, b"bob's own face").await;
    assert!(
        settles(&deployment, b"a shared face", false).await,
        "nobody wears it now"
    );
    assert!(settles(&deployment, b"bob's own face", true).await);

    bob.close().await;
    assert!(
        settles(&deployment, b"bob's own face", false).await,
        "a guest who left holds nothing"
    );
    deployment.stop().await;
}

/// Register the sender, and wait for the server to say so.
async fn register(client: &mut Client, session: u32) {
    tokio::time::sleep(Duration::from_millis(1100)).await;
    client
        .send(
            9,
            &tcp::UserState {
                session: Some(session),
                user_id: Some(0),
                ..tcp::UserState::default()
            },
        )
        .await;
    loop {
        let (kind, payload) = client
            .next_frame(FRAME_TIMEOUT)
            .await
            .expect("the registration is announced");
        let state = (kind == 9)
            .then(|| tcp::UserState::decode(payload.as_slice()).ok())
            .flatten();
        if state.is_some_and(|state| state.session == Some(session) && state.user_id.is_some()) {
            return;
        }
    }
}

#[tokio::test]
async fn a_guest_who_registers_hands_their_avatar_to_the_account() {
    // The account a guest registered as started out holding nothing, and the
    // connection stopped holding anything once it had an account: the avatar
    // put as a guest was held by nobody and stayed stored for good.
    let data = TempDir::new("content-register");
    let deployment = Deployment::start(data.path()).await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![AclEntry {
                apply_here: true,
                apply_subs: true,
                group: Some("all".to_owned()),
                grant: Perm::SELF_REGISTER.bits(),
                ..AclEntry::default()
            }],
            groups: Vec::new(),
        })
        .await;
    let mut ann = Client::connect_with_certificate(deployment.port, data.path()).await;
    let session = handshake(&mut ann, "ann").await;
    deployment
        .wait_until_permitted(session, 0, Perm::SELF_REGISTER.bits())
        .await;

    wear(&mut ann, b"a guest's face").await;
    assert!(
        settles(&deployment, b"a guest's face", true).await,
        "stored"
    );
    register(&mut ann, session).await;
    assert!(
        settles(&deployment, b"a guest's face", true).await,
        "the account wears it now"
    );

    wear(&mut ann, b"an account's face").await;
    assert!(
        settles(&deployment, b"a guest's face", false).await,
        "the account let go of what it replaced"
    );
    ann.close().await;
    assert!(
        settles(&deployment, b"an account's face", true).await,
        "an account keeps its avatar after leaving"
    );
    deployment.stop().await;
}

/// Point the livery's banner at `bytes`, as `PUT /v1/livery/banner` does:
/// the upload takes a reference, then the document names it. Nothing clears
/// it, as `DELETE` does.
async fn show_banner(deployment: &Deployment, bytes: &[u8]) {
    let key = if bytes.is_empty() {
        String::new()
    } else {
        let transport = deployment.resolver.channel("userdata").expect("dial");
        let stored = UserDataClient::new(transport)
            .put_blob(Blob {
                scope: Some(Scope { instance: 1 }),
                hash: Vec::new(),
                bytes: bytes.to_vec(),
            })
            .await
            .expect("stored")
            .into_inner();
        stored
            .hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    };
    let transport = deployment.resolver.channel("server-config").expect("dial");
    let _ = ServerConfigClient::new(transport)
        .set_livery(SetLiveryRequest {
            scope: Some(Scope { instance: 1 }),
            actor: None,
            fields: vec!["banner_key".to_owned()],
            values: Some(Livery {
                banner_key: key,
                ..Livery::default()
            }),
        })
        .await
        .expect("written");
}

#[tokio::test]
async fn livery_art_is_let_go_when_the_operator_replaces_or_clears_it() {
    // The document pointed at each new upload and nothing released the old
    // one: every banner and icon an operator ever set stayed stored.
    let data = TempDir::new("content-livery");
    let deployment = Deployment::start(data.path()).await;

    show_banner(&deployment, b"the first banner").await;
    show_banner(&deployment, b"the second banner").await;
    assert!(
        settles(&deployment, b"the first banner", false).await,
        "replaced"
    );
    assert!(
        settles(&deployment, b"the second banner", true).await,
        "shown"
    );

    show_banner(&deployment, b"the second banner").await;
    assert!(
        settles(&deployment, b"the second banner", true).await,
        "the same picture uploaded again is still shown"
    );

    show_banner(&deployment, b"").await;
    assert!(
        settles(&deployment, b"the second banner", false).await,
        "cleared"
    );
    deployment.stop().await;
}
