//! What a connection may do before it has logged in, and who a ban keeps out.
//!
//! Each test here was a hole on a running server: a connection that never sent
//! `Authenticate` could message anybody, become session 0 in the view for
//! good, look accounts up and mint invites; a stored ban turned nobody away.
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
    CLIENT_FANCY_PROTOCOL, Client, Deployment, FRAME_TIMEOUT, MUMBLE_VERSION_V2, TempDir, handshake,
};
use starling_proto::proto::tcp;
use starling_proto_fancy::common::Scope;
use starling_proto_fancy::moderation::moderation_client::ModerationClient;
use starling_proto_fancy::moderation::{Ban, BanRequest};
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::sessionview::{Session, SubscribeRequest};

/// Long enough for any answer on a loopback deployment, short enough to wait
/// for the absence of one many times over.
const QUIET: Duration = Duration::from_millis(1500);

/// A connection that has said `Version` (our epoch) and nothing else, and has
/// been answered with the server's announcement, the one thing it is owed.
async fn stranger(deployment: &Deployment) -> Client {
    let mut client = Client::connect(deployment.port).await;
    let (kind, _) = client.recv().await;
    assert_eq!(kind, 0, "the server speaks Version first");
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
    let (kind, _) = client.recv().await;
    assert_eq!(kind, 0, "a peer on our epoch is told the feature version");
    client
}

/// Every frame type that arrives within `within`. `next_frame` asserts the
/// socket stays open, so this is also "still connected".
async fn heard(client: &mut Client, within: Duration) -> Vec<u16> {
    let deadline = tokio::time::Instant::now() + within;
    let mut kinds = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return kinds;
        }
        match client.next_frame(left).await {
            Some((kind, _)) => kinds.push(kind),
            None => return kinds,
        }
    }
}

/// Everyone `session-view` holds.
async fn sessions(deployment: &Deployment) -> Vec<Session> {
    let transport = deployment.resolver.channel("session-view").expect("dial");
    SessionViewClient::new(transport)
        .list(SubscribeRequest {
            scope: Some(Scope { instance: 1 }),
            subscriber: "test".to_owned(),
        })
        .await
        .expect("list")
        .into_inner()
        .sessions
}

#[tokio::test]
async fn a_connection_that_never_logged_in_cannot_message_anybody() {
    let data = TempDir::new("before-login-dm");
    let deployment = Deployment::start(data.path()).await;
    let mut victim = Client::connect(deployment.port).await;
    let session = handshake(&mut victim, "victim").await;

    let mut nobody = stranger(&deployment).await;
    nobody
        .send(
            11,
            &tcp::TextMessage {
                session: vec![session],
                message: "hello from nobody".to_owned(),
                ..tcp::TextMessage::default()
            },
        )
        .await;

    assert!(
        !heard(&mut victim, QUIET).await.contains(&11),
        "a message from a connection that never logged in was delivered"
    );
    assert!(heard(&mut nobody, QUIET).await.is_empty());
    deployment.stop().await;
}

#[tokio::test]
async fn a_connection_that_never_logged_in_never_becomes_a_session() {
    // A `UserState` that only set a listening volume made session-lifecycle
    // announce the connection as session 0, a user in the root to every
    // service, and nothing ever took it down.
    let data = TempDir::new("before-login-phantom");
    let deployment = Deployment::start(data.path()).await;
    let mut victim = Client::connect(deployment.port).await;
    let _ = handshake(&mut victim, "victim").await;

    let mut nobody = stranger(&deployment).await;
    nobody
        .send(
            9,
            &tcp::UserState {
                listening_volume_adjustment: vec![tcp::user_state::VolumeAdjustment {
                    listening_channel: Some(0),
                    volume_adjustment: Some(0.5),
                }],
                ..tcp::UserState::default()
            },
        )
        .await;
    let _ = heard(&mut nobody, QUIET).await;
    let held: Vec<u32> = sessions(&deployment)
        .await
        .iter()
        .map(|s| s.session)
        .collect();
    assert!(!held.contains(&0), "session 0 is in the view: {held:?}");
    assert_eq!(held.len(), 1);

    nobody.close().await;
    tokio::time::sleep(QUIET).await;
    let held: Vec<u32> = sessions(&deployment)
        .await
        .iter()
        .map(|s| s.session)
        .collect();
    assert!(
        !held.contains(&0),
        "session 0 outlived its connection: {held:?}"
    );
    deployment.stop().await;
}

#[tokio::test]
async fn nothing_about_accounts_users_or_rooms_is_answered_before_login() {
    let data = TempDir::new("before-login-lookups");
    let deployment = Deployment::start(data.path()).await;
    let mut victim = Client::connect(deployment.port).await;
    let session = handshake(&mut victim, "victim").await;

    let mut nobody = stranger(&deployment).await;
    nobody
        .send(
            14,
            &tcp::QueryUsers {
                names: vec!["SuperUser".to_owned(), "victim".to_owned()],
                ..tcp::QueryUsers::default()
            },
        )
        .await;
    nobody
        .send(
            20,
            &tcp::PermissionQuery {
                channel_id: Some(0),
                ..tcp::PermissionQuery::default()
            },
        )
        .await;
    nobody
        .send(
            23,
            &tcp::RequestBlob {
                channel_description: vec![0],
                session_comment: vec![session],
                ..tcp::RequestBlob::default()
            },
        )
        .await;
    nobody
        .send(
            22,
            &tcp::UserStats {
                session: Some(session),
                ..tcp::UserStats::default()
            },
        )
        .await;

    let kinds = heard(&mut nobody, QUIET).await;
    assert!(kinds.is_empty(), "answered before login: {kinds:?}");
    deployment.stop().await;
}

#[tokio::test]
async fn an_invite_cannot_be_minted_before_login() {
    use starling_proto_fancy::fancy::invites::{InviteCreate, InvitesEnvelope, invites_envelope};
    use starling_proto_fancy::invites::ListRequest;
    use starling_proto_fancy::invites::invites_client::InvitesClient;

    let data = TempDir::new("before-login-invite");
    let deployment = Deployment::start_with(data.path(), |config| {
        config.instances[0].settings.invites = Some("everyone".to_owned());
    })
    .await;
    let mut nobody = stranger(&deployment).await;
    nobody
        .send(
            starling_proto_fancy::types::ServiceKind::Invites.outer_type(),
            &InvitesEnvelope {
                body: Some(invites_envelope::Body::Create(InviteCreate {
                    request_id: "r1".to_owned(),
                    ..InviteCreate::default()
                })),
            },
        )
        .await;
    let _ = heard(&mut nobody, QUIET).await;

    let transport = deployment.resolver.channel("invites").expect("dial");
    let listed = InvitesClient::new(transport)
        .list(ListRequest {
            scope: Some(Scope { instance: 1 }),
        })
        .await
        .expect("list")
        .into_inner();
    assert!(listed.invites.is_empty(), "minted: {:?}", listed.invites);
    deployment.stop().await;
}

#[tokio::test]
async fn a_hidden_rooms_description_goes_only_to_who_may_see_the_room() {
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest};

    let data = TempDir::new("before-login-hidden");
    let deployment = Deployment::start(data.path()).await;
    let shown = deployment
        .create_described_channel("lobby", "the lobby".to_owned())
        .await;
    let transport = deployment.resolver.channel("metadata").expect("dial");
    let hidden = MetadataClient::new(transport)
        .create(CreateRequest {
            scope: Some(Scope { instance: 1 }),
            channel: Some(Channel {
                name: "back room".to_owned(),
                parent: Some(0),
                description: "the plans".to_owned(),
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

    let mut guest = Client::connect(deployment.port).await;
    let _ = handshake(&mut guest, "guest").await;
    guest
        .send(
            23,
            &tcp::RequestBlob {
                channel_description: vec![hidden, shown],
                ..tcp::RequestBlob::default()
            },
        )
        .await;
    let mut described = Vec::new();
    let deadline = tokio::time::Instant::now() + QUIET;
    while let Some((kind, payload)) = guest
        .next_frame(deadline.saturating_duration_since(tokio::time::Instant::now()))
        .await
    {
        if kind == 7 {
            let state = tcp::ChannelState::decode(payload.as_slice()).expect("a ChannelState");
            if state.description.is_some() {
                described.push(state.channel_id.unwrap_or_default());
            }
        }
    }
    assert!(described.contains(&shown), "the visible room is described");
    assert!(
        !described.contains(&hidden),
        "a hidden room's description reached somebody who may not see it"
    );
    deployment.stop().await;
}

#[tokio::test]
async fn a_clients_own_deafen_sent_beside_authenticate_still_applies() {
    // The Fancy client deafens itself right after `Authenticate`, before it
    // has a session; that one `UserState` must survive the guard.
    let data = TempDir::new("before-login-deafen");
    let deployment = Deployment::start(data.path()).await;
    let mut client = stranger(&deployment).await;
    client
        .send(
            9,
            &tcp::UserState {
                self_deaf: Some(true),
                self_mute: Some(true),
                ..tcp::UserState::default()
            },
        )
        .await;
    client
        .send(
            2,
            &tcp::Authenticate {
                username: Some("quiet".to_owned()),
                opus: Some(true),
                ..tcp::Authenticate::default()
            },
        )
        .await;
    let session = loop {
        let (kind, payload) = client.recv().await;
        if kind == 5 {
            let sync = tcp::ServerSync::decode(payload.as_slice()).expect("a ServerSync");
            break sync.session.expect("a session");
        }
    };
    // In the view, which is what voice reads silence from.
    let held = sessions(&deployment).await;
    assert!(
        held.iter()
            .any(|s| s.session == session && s.self_deaf && s.self_mute),
        "{held:?}"
    );
    deployment.stop().await;
}

// ---------------------------------------------------------------------------
// Bans

/// 127.0.0.1 as a ban stores it: sixteen v6-mapped bytes, one address /128.
fn loopback() -> Vec<u8> {
    std::net::Ipv4Addr::LOCALHOST
        .to_ipv6_mapped()
        .octets()
        .to_vec()
}

async fn ban(deployment: &Deployment, ban: Ban) {
    let transport = deployment.resolver.channel("moderation").expect("dial");
    let result = ModerationClient::new(transport)
        .ban(BanRequest {
            scope: Some(Scope { instance: 1 }),
            ban: Some(ban),
            ..BanRequest::default()
        })
        .await
        .expect("ban")
        .into_inner();
    assert!(result.applied, "{}", result.refused);
}

/// Log in as `name`: the session, or the `Reject` and that the socket closed.
async fn log_in(client: &mut Client, name: &str) -> Result<u32, (tcp::Reject, bool)> {
    let (kind, _) = client.recv().await;
    assert_eq!(kind, 0, "the server speaks Version first");
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
                opus: Some(true),
                ..tcp::Authenticate::default()
            },
        )
        .await;
    loop {
        let (kind, payload) = client.recv().await;
        match kind {
            4 => {
                let reject = tcp::Reject::decode(payload.as_slice()).expect("a Reject");
                return Err((reject, client.closed_by_server(FRAME_TIMEOUT).await));
            }
            5 => {
                let sync = tcp::ServerSync::decode(payload.as_slice()).expect("a ServerSync");
                return Ok(sync.session.expect("a session"));
            }
            _ => {}
        }
    }
}

fn assert_banned(answer: Result<u32, (tcp::Reject, bool)>, reason: &str) {
    let (reject, closed) = answer.expect_err("a banned login must be refused");
    assert_eq!(
        reject.r#type,
        Some(tcp::reject::RejectType::None as i32),
        "typed, and not as a password a client would then ask for"
    );
    let words = reject.reason.unwrap_or_default();
    assert!(words.contains("banned"), "{words}");
    assert!(words.contains(reason), "{words}");
    assert!(closed, "and disconnected");
}

#[tokio::test]
async fn a_banned_address_is_refused_at_login_and_told_why() {
    let data = TempDir::new("ban-address");
    let deployment = Deployment::start(data.path()).await;
    ban(
        &deployment,
        Ban {
            address: loopback(),
            prefix_len: 128,
            reason: "flooding".to_owned(),
            ..Ban::default()
        },
    )
    .await;

    let mut client = Client::connect(deployment.port).await;
    assert_banned(log_in(&mut client, "anybody").await, "flooding");
    deployment.stop().await;
}

#[tokio::test]
async fn a_banned_certificate_is_refused_and_another_is_not() {
    let data = TempDir::new("ban-cert");
    let certs = TempDir::new("ban-cert-client");
    let deployment = Deployment::start(data.path()).await;

    let mut first = Client::connect_with_certificate(deployment.port, certs.path()).await;
    let session = log_in(&mut first, "carol").await.expect("admitted");
    let cert_hash = sessions(&deployment)
        .await
        .into_iter()
        .find(|held| held.session == session)
        .expect("listed")
        .cert_hash;
    assert!(!cert_hash.is_empty(), "the client presented a certificate");
    first.close().await;

    ban(
        &deployment,
        Ban {
            cert_hash,
            reason: "impersonation".to_owned(),
            ..Ban::default()
        },
    )
    .await;

    let mut again = Client::connect_with_certificate(deployment.port, certs.path()).await;
    assert_banned(log_in(&mut again, "carol").await, "impersonation");
    let mut other = Client::connect(deployment.port).await;
    assert!(
        log_in(&mut other, "dave").await.is_ok(),
        "only that certificate"
    );
    deployment.stop().await;
}

#[tokio::test]
async fn a_ban_naming_only_a_name_refuses_that_name_and_no_other() {
    let data = TempDir::new("ban-name");
    let deployment = Deployment::start(data.path()).await;
    ban(
        &deployment,
        Ban {
            name: "Mallory".to_owned(),
            reason: "known troll".to_owned(),
            ..Ban::default()
        },
    )
    .await;

    let mut mallory = Client::connect(deployment.port).await;
    assert_banned(log_in(&mut mallory, "mallory").await, "known troll");
    let mut alice = Client::connect(deployment.port).await;
    assert!(log_in(&mut alice, "alice").await.is_ok(), "only that name");
    deployment.stop().await;
}

#[tokio::test]
async fn a_ban_that_has_run_out_lets_its_subject_back_in() {
    let data = TempDir::new("ban-expiry");
    let deployment = Deployment::start(data.path()).await;
    ban(
        &deployment,
        Ban {
            address: loopback(),
            prefix_len: 128,
            reason: "cool off".to_owned(),
            duration_s: 2,
            ..Ban::default()
        },
    )
    .await;

    let mut early = Client::connect(deployment.port).await;
    let (reject, _) = log_in(&mut early, "eve").await.expect_err("still banned");
    assert!(
        reject.reason.unwrap_or_default().contains("until"),
        "a timed ban says until when"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut later = Client::connect(deployment.port).await;
    assert!(log_in(&mut later, "eve").await.is_ok(), "the ban ran out");
    deployment.stop().await;
}

#[tokio::test]
async fn a_ban_written_while_its_subject_is_here_turns_them_away() {
    let data = TempDir::new("ban-present");
    let deployment = Deployment::start(data.path()).await;
    let mut here = Client::connect(deployment.port).await;
    let _ = log_in(&mut here, "frank").await.expect("admitted");

    ban(
        &deployment,
        Ban {
            address: loopback(),
            prefix_len: 128,
            reason: "now".to_owned(),
            ..Ban::default()
        },
    )
    .await;
    assert!(
        here.closed_by_server(FRAME_TIMEOUT).await,
        "a ban covering somebody connected must disconnect them"
    );
    deployment.stop().await;
}
