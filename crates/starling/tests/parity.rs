//! What a client bringing a feature to parity found missing on the server, each
//! shown from outside, over the wire, the way the client met it.
//!
//! Its own binary rather than more of `e2e.rs`: these are a picture, a ban
//! editor, pins, a whiteboard, a profile and a channel password, as a client
//! uses them, and each was a feature that worked against murmur and did
//! nothing here.

// A test binary. See `crates/starling/tests/e2e.rs`.
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
    Client, Deployment, FRAME_TIMEOUT, PCHAT_OUTER_TYPE, TempDir, handshake, handshake_epoch1,
};
use starling_proto::proto::tcp;
use starling_proto_fancy::fancy::pchat::{self, pchat_envelope};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::{AclEntry, AclSet};
use tokio::time::timeout;

/// Upstream `PermissionDenied`.
const PERMISSION_DENIED: u16 = 12;
/// Upstream `BanList`.
const BAN_LIST: u16 = 10;

/// One ACL entry for `group`, here and below.
fn entry(group: &str, grant: Perm, deny: Perm) -> AclEntry {
    AclEntry {
        apply_here: true,
        apply_subs: true,
        group: Some(group.to_owned()),
        grant: grant.bits(),
        deny: deny.bits(),
        ..AclEntry::default()
    }
}

/// The next frame of `type_id`, skipping everything else, or `None` within
/// `within`.
async fn next_of(client: &mut Client, type_id: u16, within: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (kind, payload) = client.next_frame(remaining).await?;
        if kind == type_id {
            return Some(payload);
        }
    }
}

// -- 1. A guest's picture and comment ------------------------------------------

#[tokio::test]
async fn a_guests_picture_and_long_comment_are_served_to_whoever_asks() {
    // A guest's hashes are put on their session record and announced to
    // everyone; `RequestBlob` answered only through an account, so for a guest
    // it said nothing and the picture was never drawn by anybody else. The
    // comment is long enough to travel by hash in murmur as well (128 bytes).
    const PICTURE: &[u8] = b"\x89PNG not really, but bytes all the same";
    let comment = "a guest's comment, ".repeat(10);

    let data_dir = TempDir::new("guest-picture");
    let deployment = Deployment::start(data_dir.path()).await;
    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    alice
        .send(
            9,
            &tcp::UserState {
                texture: Some(PICTURE.to_vec()),
                comment: Some(comment.clone()),
                ..tcp::UserState::default()
            },
        )
        .await;
    let announced = timeout(
        FRAME_TIMEOUT,
        bob.next_state_of(alice_session, |state| {
            state.texture_hash.as_ref().map(|_| true)
        }),
    )
    .await
    .expect("bob is told alice's hashes");
    assert!(
        announced.comment_hash.is_some(),
        "both, in one announcement"
    );

    bob.send(
        23,
        &tcp::RequestBlob {
            session_texture: vec![alice_session],
            session_comment: vec![alice_session],
            ..tcp::RequestBlob::default()
        },
    )
    .await;
    let picture = timeout(
        Duration::from_secs(3),
        bob.next_state_of(alice_session, |state| state.texture.as_ref().map(|_| true)),
    )
    .await
    .expect("the announced picture is served");
    assert_eq!(picture.texture.as_deref(), Some(PICTURE));
    let said = timeout(
        FRAME_TIMEOUT,
        bob.next_state_of(alice_session, |state| state.comment.as_ref().map(|_| true)),
    )
    .await
    .expect("the announced comment is served");
    assert_eq!(said.comment.as_deref(), Some(comment.as_str()));

    deployment.stop().await;
}

// -- 2. A ban list written by a client -----------------------------------------

/// A v4-mapped address, as every address travels in a `BanList`.
fn mapped(v4: [u8; 4]) -> Vec<u8> {
    std::net::Ipv4Addr::from(v4)
        .to_ipv6_mapped()
        .octets()
        .to_vec()
}

/// One entry of a ban list, by address.
fn ban_entry(address: Vec<u8>, mask: u32, name: &str) -> tcp::ban_list::BanEntry {
    tcp::ban_list::BanEntry {
        address,
        mask,
        name: Some(name.to_owned()),
        hash: Some(String::new()),
        reason: Some("by hand".to_owned()),
        start: None,
        duration: Some(0),
    }
}

/// Ask for the list and return it.
async fn read_bans(client: &mut Client) -> Vec<tcp::ban_list::BanEntry> {
    client
        .send(
            BAN_LIST,
            &tcp::BanList {
                query: Some(true),
                ..tcp::BanList::default()
            },
        )
        .await;
    let payload = next_of(client, BAN_LIST, FRAME_TIMEOUT)
        .await
        .expect("the list is answered");
    tcp::BanList::decode(payload.as_slice())
        .expect("a well-formed BanList")
        .bans
}

/// A deployment where `ops` holds `Ban` at the root, and one session in it.
async fn with_a_moderator(tag: &str) -> (TempDir, Deployment, Client, u32) {
    let data_dir = TempDir::new(tag);
    let deployment = Deployment::start(data_dir.path()).await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("ops", Perm::BAN, Perm::empty())],
            groups: Vec::new(),
        })
        .await;
    let mut moderator = Client::connect(deployment.port).await;
    let session = handshake(&mut moderator, "moderator").await;
    deployment.add_temporary_group(0, "ops", session).await;
    deployment
        .wait_until_permitted(session, 0, Perm::BAN.bits())
        .await;
    (data_dir, deployment, moderator, session)
}

#[tokio::test]
async fn a_ban_list_written_by_a_moderator_replaces_the_list_and_says_when_each_began() {
    // murmur's ban editor: the whole list is sent back with `query` unset, and
    // that is how a ban is added, changed or lifted. It was dropped without a
    // word, so both Fancy clients' editors did nothing here.
    let (_dir, deployment, mut moderator, _) = with_a_moderator("ban-write").await;

    moderator
        .send(
            BAN_LIST,
            &tcp::BanList {
                query: Some(false),
                bans: vec![ban_entry(mapped([203, 0, 113, 7]), 128, "Nobody")],
            },
        )
        .await;
    let held = read_bans(&mut moderator).await;
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].address, mapped([203, 0, 113, 7]));
    assert_eq!(held[0].mask, 128);
    assert_eq!(held[0].name.as_deref(), Some("Nobody"));
    assert!(
        held[0]
            .start
            .as_deref()
            .is_some_and(|start| start.len() >= 19),
        "a ban says when it began: {:?}",
        held[0].start
    );

    // Lifting it is writing the list without it.
    moderator
        .send(
            BAN_LIST,
            &tcp::BanList {
                query: Some(false),
                bans: Vec::new(),
            },
        )
        .await;
    assert!(read_bans(&mut moderator).await.is_empty());

    deployment.stop().await;
}

#[tokio::test]
async fn a_ban_list_written_without_ban_is_refused_out_loud() {
    let data_dir = TempDir::new("ban-write-refused");
    let deployment = Deployment::start(data_dir.path()).await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    bob.send(
        BAN_LIST,
        &tcp::BanList {
            query: Some(false),
            bans: vec![ban_entry(mapped([203, 0, 113, 7]), 128, "Nobody")],
        },
    )
    .await;
    let payload = next_of(&mut bob, PERMISSION_DENIED, FRAME_TIMEOUT)
        .await
        .expect("a write without Ban is answered, not dropped");
    let denied = tcp::PermissionDenied::decode(payload.as_slice()).expect("well-formed");
    assert_eq!(denied.permission, Some(Perm::BAN.bits()));
    assert_eq!(denied.channel_id, Some(0));

    deployment.stop().await;
}

#[tokio::test]
async fn a_ban_that_would_cover_every_ipv4_address_is_refused_with_a_reason() {
    // The web client starts a new ban with a mask of 32 and sends it as it is.
    // Counted over the sixteen bytes every address travels in, that is the
    // first 32 bits of `::ffff:a.b.c.d`, which are zero for every IPv4 client:
    // a ban on everybody (`mumble-ban-mask-wire-contract`).
    let (_dir, deployment, mut moderator, _) = with_a_moderator("ban-short-mask").await;
    moderator
        .send(
            BAN_LIST,
            &tcp::BanList {
                query: Some(false),
                bans: vec![ban_entry(mapped([203, 0, 113, 7]), 128, "Kept")],
            },
        )
        .await;
    assert_eq!(read_bans(&mut moderator).await.len(), 1);

    moderator
        .send(
            BAN_LIST,
            &tcp::BanList {
                query: Some(false),
                bans: vec![ban_entry(mapped([203, 0, 113, 7]), 32, "Everybody")],
            },
        )
        .await;
    let payload = next_of(&mut moderator, PERMISSION_DENIED, FRAME_TIMEOUT)
        .await
        .expect("the refusal is said, not silent");
    let denied = tcp::PermissionDenied::decode(payload.as_slice()).expect("well-formed");
    assert_eq!(
        denied.r#type,
        Some(tcp::permission_denied::DenyType::Text as i32)
    );
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| !reason.is_empty()),
        "the client is told why"
    );
    let held = read_bans(&mut moderator).await;
    assert_eq!(held.len(), 1, "nothing of a refused list is applied");
    assert_eq!(held[0].name.as_deref(), Some("Kept"));

    deployment.stop().await;
}

// -- 3. Pins ------------------------------------------------------------------

/// A channel that keeps its messages, made as an operator would.
async fn kept_channel(deployment: &Deployment, name: &str) -> u32 {
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest};

    let transport = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    let created = MetadataClient::new(transport)
        .create(CreateRequest {
            scope: None,
            actor: None,
            channel: Some(Channel {
                name: name.to_owned(),
                parent: Some(0),
                pchat_protocol: pchat::Protocol::FancyV1FullArchive as u32,
                ..Channel::default()
            }),
            temporary: false,
            invitee_user_ids: Vec::new(),
            reuse_existing: false,
        })
        .await
        .expect("the channel is created")
        .into_inner();
    // pchat learns a channel's mode from metadata's stream, a moment later.
    tokio::time::sleep(Duration::from_millis(500)).await;
    created.channel.expect("a channel").id
}

async fn send_pchat(client: &mut Client, body: pchat_envelope::Body) {
    let envelope = pchat::PchatEnvelope { body: Some(body) };
    client
        .send_raw(PCHAT_OUTER_TYPE, &envelope.encode_to_vec())
        .await;
}

/// The next pchat body that `wanted` picks, skipping the rest.
async fn next_pchat<T>(
    client: &mut Client,
    wanted: impl Fn(pchat_envelope::Body) -> Option<T>,
) -> Option<T> {
    let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let payload = next_of(client, PCHAT_OUTER_TYPE, remaining).await?;
        let envelope = pchat::PchatEnvelope::decode(payload.as_slice()).expect("an envelope");
        if let Some(found) = envelope.body.and_then(&wanted) {
            return Some(found);
        }
    }
}

#[tokio::test]
async fn a_pin_in_a_channel_that_keeps_its_messages_is_told_to_who_comes_later() {
    // A pin was relayed to who was there and kept nowhere, so somebody who
    // came later, or reconnected, never learned of it.
    const KEPT: &str = "01234567-89ab-7def-8123-456789abcdef";
    let data_dir = TempDir::new("pin-kept");
    let deployment = Deployment::start(data_dir.path()).await;
    let channel = kept_channel(&deployment, "Kept").await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake_epoch1(&mut alice, "alice").await;
    send_pchat(
        &mut alice,
        pchat_envelope::Body::Message(pchat::Message {
            message_id: KEPT.to_owned(),
            channel,
            ciphertext: b"sealed".to_vec(),
            protocol: pchat::Protocol::FancyV1FullArchive as i32,
            ..pchat::Message::default()
        }),
    )
    .await;
    let _ = next_pchat(&mut alice, |body| match body {
        pchat_envelope::Body::Ack(ack) => Some(ack),
        _ => None,
    })
    .await
    .expect("the message is acknowledged");
    send_pchat(
        &mut alice,
        pchat_envelope::Body::Pin(pchat::Pin {
            message_id: KEPT.to_owned(),
            channel,
            unpin: false,
            ..pchat::Pin::default()
        }),
    )
    .await;
    let _ = next_pchat(&mut alice, |body| match body {
        pchat_envelope::Body::Pin(pin) => Some(pin),
        _ => None,
    })
    .await
    .expect("the pinner is told the pin took");

    let mut late = Client::connect(deployment.port).await;
    let _ = handshake_epoch1(&mut late, "late").await;
    send_pchat(
        &mut late,
        pchat_envelope::Body::Fetch(pchat::Fetch {
            channel,
            page: None,
        }),
    )
    .await;
    let listed = next_pchat(&mut late, |body| match body {
        pchat_envelope::Body::PinList(list) => Some(list),
        _ => None,
    })
    .await
    .expect("whoever fetches the history is told what is pinned in it");
    assert_eq!(listed.channel, channel);
    let ids: Vec<&str> = listed
        .pinned
        .iter()
        .map(|message| message.message_id.as_str())
        .collect();
    assert_eq!(ids, vec![KEPT]);
    assert_eq!(listed.pins.len(), 1);
    assert_eq!(listed.pins[0].message_id, KEPT);
    assert_eq!(
        listed.pins[0].pinner_name, "alice",
        "who pinned it, by the server"
    );
    assert!(listed.pins[0].pinned_at_ms > 0, "and when, by its clock");

    deployment.stop().await;
}

// -- 4. A stroke on a shared screen ----------------------------------------------

#[tokio::test]
async fn a_stroke_and_a_clear_reach_the_others_as_they_were_drawn() {
    use starling_proto_fancy::fancy::social::{
        DrawClear, DrawStroke, SocialEnvelope, social_envelope,
    };
    use starling_proto_fancy::types::ServiceKind;

    let outer = ServiceKind::Social.outer_type();
    let data_dir = TempDir::new("stroke");
    let deployment = Deployment::start(data_dir.path()).await;
    let mut alice = Client::connect(deployment.port).await;
    let (alice_session, _) = handshake_epoch1(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake_epoch1(&mut bob, "bob").await;

    let drawn = DrawStroke {
        channel: 0,
        colour: "#0088ff".to_owned(),
        width: 0.01,
        points: vec![0.25, 0.5, 0.75, 0.5],
        stroke_id: "s-1".to_owned(),
        end: true,
        width_px: 6.0,
        alpha: 0x80,
        ..DrawStroke::default()
    };
    for body in [
        social_envelope::Body::Stroke(drawn.clone()),
        social_envelope::Body::Clear(DrawClear {
            channel: 0,
            actor: 0,
            all: true,
        }),
    ] {
        let envelope = SocialEnvelope { body: Some(body) };
        alice.send_raw(outer, &envelope.encode_to_vec()).await;
    }

    let mut heard = Vec::new();
    while heard.len() < 2 {
        let payload = next_of(&mut bob, outer, FRAME_TIMEOUT)
            .await
            .expect("bob is sent both");
        if let Some(body) = SocialEnvelope::decode(payload.as_slice())
            .expect("an envelope")
            .body
        {
            heard.push(body);
        }
    }
    assert_eq!(
        heard[0],
        social_envelope::Body::Stroke(DrawStroke {
            actor: alice_session,
            ..drawn
        }),
        "field for field"
    );
    assert_eq!(
        heard[1],
        social_envelope::Body::Clear(DrawClear {
            channel: 0,
            actor: alice_session,
            all: true,
        })
    );

    deployment.stop().await;
}

// -- 5. The comment limit -------------------------------------------------------

/// Whether a comment is taken: its hash comes back, or it is refused.
async fn comment_taken(client: &mut Client, session: u32, comment: String) -> bool {
    client
        .send(
            9,
            &tcp::UserState {
                comment: Some(comment),
                ..tcp::UserState::default()
            },
        )
        .await;
    let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (kind, payload) = client
            .next_frame(remaining)
            .await
            .expect("the comment is answered");
        match kind {
            PERMISSION_DENIED => return false,
            9 => {
                let state = tcp::UserState::decode(payload.as_slice()).expect("a UserState");
                if state.session == Some(session) && state.comment_hash.is_some() {
                    return true;
                }
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn a_profiles_mark_does_not_spend_the_comment_limit_and_the_whole_is_still_bounded() {
    // A Fancy profile rides in front of the comment as `<!--FANCY:{json}-->`,
    // and with a banner and a few thumbnails it is longer than the 5000
    // characters `text_message_length` allows while the words are a line.
    // murmur leaves embedded picture data out of that count and bounds the
    // whole by `image_message_length`; this counts the same way.
    let data_dir = TempDir::new("comment-limit");
    let deployment = Deployment::start(data_dir.path()).await;
    let mut alice = Client::connect(deployment.port).await;
    let session = handshake(&mut alice, "alice").await;

    let profile = format!(
        "<!--FANCY:{{\"banner\":\"#123456\",\"thumbs\":\"{}\"}}-->",
        "A".repeat(6_000)
    );
    assert!(
        comment_taken(&mut alice, session, format!("{profile}a few words")).await,
        "a profile with a short text fits"
    );
    assert!(
        !comment_taken(&mut alice, session, "w".repeat(5_001)).await,
        "the words themselves are still held to text_message_length"
    );
    assert!(
        !comment_taken(
            &mut alice,
            session,
            format!("<!--FANCY:{{\"x\":\"{}\"}}-->hi", "A".repeat(140_000))
        )
        .await,
        "and the whole to image_message_length"
    );

    deployment.stop().await;
}

// -- 7. A channel's password given when it is made ------------------------------

#[tokio::test]
async fn a_channel_made_with_a_password_admits_only_who_presents_it() {
    // The web client's channel form sends the password in
    // `ChannelState.channel_info_password`; nothing acted on it, so a channel
    // made with a password was open to everybody. In Mumble a channel password
    // is an ACL: Enter denied to `all` and granted to `#<password>`.
    let data_dir = TempDir::new("channel-password");
    let deployment = Deployment::start(data_dir.path()).await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("all", Perm::MAKE_CHANNEL, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    // With a certificate: a guest's grant as a channel's maker is by
    // certificate, as murmur's is, and a guest with none has nothing to hold it.
    let mut alice = Client::connect_with_certificate(deployment.port, data_dir.path()).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .wait_until_permitted(alice_session, 0, Perm::MAKE_CHANNEL.bits())
        .await;
    alice
        .send(
            7,
            &tcp::ChannelState {
                parent: Some(0),
                name: Some("Vault".to_owned()),
                channel_info_password: Some("hunter2".to_owned()),
                ..tcp::ChannelState::default()
            },
        )
        .await;
    let vault = loop {
        let payload = next_of(&mut alice, 7, FRAME_TIMEOUT)
            .await
            .expect("the channel is made");
        let state = tcp::ChannelState::decode(payload.as_slice()).expect("a ChannelState");
        if state.name.as_deref() == Some("Vault") {
            assert_eq!(
                state.channel_info_password, None,
                "a password is never told to anybody"
            );
            break state.channel_id.expect("an id");
        }
    };
    // The ACL is written beside the channel, a moment after it.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    let refused = bob
        .enter(bob_session, vault, "bob is answered")
        .await
        .expect_err("without the password bob is turned away");
    assert_eq!(refused.permission, Some(Perm::ENTER.bits()));

    bob.send(
        9,
        &tcp::UserState {
            session: Some(bob_session),
            channel_id: Some(vault),
            temporary_access_tokens: vec!["hunter2".to_owned()],
            ..tcp::UserState::default()
        },
    )
    .await;
    let admitted = timeout(FRAME_TIMEOUT, bob.next_entry_answer(bob_session))
        .await
        .expect("bob is answered the second time");
    assert_eq!(admitted, Ok(vault), "with it he gets in");

    // Whoever made it is granted `Write` there, as murmur grants it, and so is
    // not locked out of their own room.
    let entered = alice.enter(alice_session, vault, "alice is answered").await;
    assert_eq!(entered, Ok(vault), "the maker gets in without the password");

    deployment.stop().await;
}

// -- Onboarding ---------------------------------------------------------------

#[tokio::test]
async fn questions_saved_by_an_administrator_are_asked_answered_and_kept() {
    // Both Fancy clients sent onboarding on the plugin relay, which this
    // server does not read, so no question was ever saved or asked. This is
    // the canon conversation they now hold: an administrator saves, a member
    // is told, answers, and asks again for what is kept.
    use starling_harness::handshake_epoch1_as;
    use starling_proto_fancy::fancy::feature::{
        Flow, FlowQuery, FlowUpdate, OnboardingEnvelope, Response, Step, onboarding_envelope,
        response, step,
    };
    use starling_proto_fancy::types::ServiceKind;
    use starling_proto_fancy::userdata::user_data_client::UserDataClient;
    use starling_proto_fancy::userdata::{Account, RegisterRequest};

    let outer = ServiceKind::Onboarding.outer_type();
    let say =
        |body: onboarding_envelope::Body| OnboardingEnvelope { body: Some(body) }.encode_to_vec();
    let heard = |payload: Vec<u8>| {
        OnboardingEnvelope::decode(payload.as_slice())
            .expect("an envelope")
            .body
            .expect("a body")
    };

    let data_dir = TempDir::new("onboarding");
    let deployment = Deployment::start(data_dir.path()).await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("ops", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;
    let _ = UserDataClient::new(deployment.resolver.channel("userdata").expect("userdata"))
        .register(RegisterRequest {
            scope: None,
            actor: None,
            account: Some(Account {
                name: "member".to_owned(),
                ..Account::default()
            }),
            password: "pw".to_owned(),
        })
        .await
        .expect("registered");

    let mut admin = Client::connect(deployment.port).await;
    let (admin_session, _) = handshake_epoch1(&mut admin, "admin").await;
    deployment
        .add_temporary_group(0, "ops", admin_session)
        .await;
    deployment
        .wait_until_permitted(admin_session, 0, Perm::WRITE.bits())
        .await;
    let mut member = Client::connect(deployment.port).await;
    let _ = handshake_epoch1_as(
        &mut member,
        tcp::Authenticate {
            username: Some("member".to_owned()),
            password: Some("pw".to_owned()),
            opus: Some(true),
            ..tcp::Authenticate::default()
        },
    )
    .await;

    // Somebody without Write is told no, and nothing changes.
    member
        .send_raw(
            outer,
            &say(onboarding_envelope::Body::Update(FlowUpdate {
                flow: Some(Flow::default()),
            })),
        )
        .await;
    assert!(
        next_of(&mut member, PERMISSION_DENIED, FRAME_TIMEOUT)
            .await
            .is_some(),
        "a refused edit is said"
    );

    admin
        .send_raw(
            outer,
            &say(onboarding_envelope::Body::Update(FlowUpdate {
                flow: Some(Flow {
                    enabled: true,
                    steps: vec![Step {
                        id: "why".to_owned(),
                        title: "What brings you here?".to_owned(),
                        kind: step::Kind::Choice as i32,
                        choices: vec![step::Choice {
                            id: "testing".to_owned(),
                            groups: vec!["testers".to_owned()],
                            ..step::Choice::default()
                        }],
                        ..Step::default()
                    }],
                    ..Flow::default()
                }),
            })),
        )
        .await;
    let onboarding_envelope::Body::Flow(told) = heard(
        next_of(&mut member, outer, FRAME_TIMEOUT)
            .await
            .expect("the member is told"),
    ) else {
        panic!("expected the questions");
    };
    assert!(told.enabled && told.version >= 1);
    assert_eq!(told.steps[0].choices[0].id, "testing");

    member
        .send_raw(
            outer,
            &say(onboarding_envelope::Body::Response(Response {
                answers: vec![response::Answer {
                    step_id: "why".to_owned(),
                    choice_ids: vec!["testing".to_owned()],
                    text: String::new(),
                }],
                ..Response::default()
            })),
        )
        .await;
    let onboarding_envelope::Body::Response(echo) = heard(
        next_of(&mut member, outer, FRAME_TIMEOUT)
            .await
            .expect("the answer is echoed"),
    ) else {
        panic!("expected the answers");
    };
    assert!(echo.submitted_at_ms > 0);

    // Asked again, as a client does on arriving: the questions and the answers.
    member
        .send_raw(
            outer,
            &say(onboarding_envelope::Body::Query(FlowQuery {
                include_answers: true,
            })),
        )
        .await;
    let mut bodies = Vec::new();
    while bodies.len() < 2 {
        bodies.push(heard(
            next_of(&mut member, outer, FRAME_TIMEOUT)
                .await
                .expect("both answered"),
        ));
    }
    // The answers first, so a client does not see unanswered questions and
    // ask for the answers again.
    let onboarding_envelope::Body::Response(kept) = &bodies[0] else {
        panic!("expected the answers kept first");
    };
    assert!(
        matches!(&bodies[1], onboarding_envelope::Body::Flow(flow) if flow.version == told.version)
    );
    assert_eq!(kept.flow_version, told.version);
    assert_eq!(kept.answers[0].choice_ids, ["testing"]);

    deployment.stop().await;
}
