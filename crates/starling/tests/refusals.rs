//! What a refusal may say: never where somebody else is, never whether
//! somebody or something exists, to a caller with no right to know.
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
use starling_harness::{Client, Deployment, TempDir, handshake};
use starling_proto::proto::tcp;
use starling_proto_fancy::common::Scope;

/// The next `PermissionDenied` within a moment, or `None`.
async fn denial(client: &mut Client) -> Option<tcp::PermissionDenied> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (kind, payload) = client.next_frame(left).await?;
        if kind == 12 {
            return Some(tcp::PermissionDenied::decode(payload.as_slice()).expect("a denial"));
        }
    }
}

/// Send a `UserState`, paced: the gateway charges each to murmur's control
/// bucket (1/s, a burst of five), and a throttled frame is not a refusal.
async fn state(client: &mut Client, state: &tcp::UserState) {
    tokio::time::sleep(Duration::from_millis(1100)).await;
    client.send(9, state).await;
}

/// A hidden room with `session` standing in it.
async fn hidden_with(deployment: &Deployment, session: u32) -> u32 {
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest};
    use starling_proto_fancy::sessioncontrol::SetStateRequest;
    use starling_proto_fancy::sessioncontrol::session_control_client::SessionControlClient;

    let transport = deployment.resolver.channel("metadata").expect("dial");
    let hidden = MetadataClient::new(transport)
        .create(CreateRequest {
            scope: Some(Scope { instance: 1 }),
            channel: Some(Channel {
                name: "back room".to_owned(),
                parent: Some(0),
                flags: 1,
                ..Channel::default()
            }),
            ..CreateRequest::default()
        })
        .await
        .expect("created")
        .into_inner()
        .channel
        .expect("the channel")
        .id;
    let transport = deployment
        .resolver
        .channel("session-lifecycle")
        .expect("dial");
    let moved = SessionControlClient::new(transport)
        .set_state(SetStateRequest {
            session,
            channel: Some(hidden),
            ..SetStateRequest::default()
        })
        .await
        .expect("answered")
        .into_inner();
    assert!(moved.applied, "{}", moved.refused);
    hidden
}

#[tokio::test]
async fn a_refusal_about_somebody_never_says_where_they_are_or_whether_they_are_here() {
    let data = TempDir::new("refusals-where");
    let deployment = Deployment::start(data.path()).await;
    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    let hidden = hidden_with(&deployment, bob_session).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Muting bob, who is in a room alice cannot see, and somebody not here.
    let mute = |session: u32| tcp::UserState {
        session: Some(session),
        mute: Some(true),
        ..tcp::UserState::default()
    };
    state(&mut alice, &mute(bob_session)).await;
    let on_bob = denial(&mut alice).await.expect("refused");
    state(&mut alice, &mute(9999)).await;
    let on_nobody = denial(&mut alice).await.expect("refused alike");
    assert_eq!(on_bob.channel_id, Some(0), "alice's own room, not {hidden}");
    assert_eq!(on_bob, on_nobody);

    // Moving bob into the room he is already in, elsewhere, and nobody.
    let drag = |session: u32, channel: u32| tcp::UserState {
        session: Some(session),
        channel_id: Some(channel),
        ..tcp::UserState::default()
    };
    state(&mut alice, &drag(bob_session, hidden)).await;
    let into_his_room = denial(&mut alice).await.expect("refused, not silent");
    state(&mut alice, &drag(bob_session, 0)).await;
    let elsewhere = denial(&mut alice).await.expect("refused");
    state(&mut alice, &drag(9999, 0)).await;
    let nobody = denial(&mut alice).await.expect("refused alike");
    assert_eq!(into_his_room.channel_id, Some(0));
    assert_eq!(into_his_room, elsewhere);
    assert_eq!(into_his_room, nobody);

    // Kicking bob, and somebody not here: one answer.
    let kick = |session: u32| tcp::UserRemove {
        session,
        reason: Some("x".to_owned()),
        ..tcp::UserRemove::default()
    };
    alice.send(8, &kick(bob_session)).await;
    let kick_bob = denial(&mut alice).await.expect("refused");
    alice.send(8, &kick(9999)).await;
    let kick_nobody = denial(&mut alice).await.expect("refused alike");
    assert_eq!(kick_bob, kick_nobody);

    let _ = alice_session;
    deployment.stop().await;
}
