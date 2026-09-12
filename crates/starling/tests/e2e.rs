//! The one test that starts every service plus the gateway and speaks the
//! wire protocol from outside, the way a real client does.
//!
//! The scaffolding lives in `starling-harness`; this file is the assertions.
//! Every other test in the workspace exercises one crate. This is the only
//! place that proves the composition in `compose::all_in_one` actually wires
//! a client through the real handshake
//! (`crates/services/session-lifecycle/src/handshake.rs`) end to end, over a
//! real TCP+TLS socket, not an in-memory `Inbound`.

// A test binary, not production code. `expect` here names the assumption that
// failed, which is what a failing e2e run needs to say; the panic audit in
// `scripts/check-panic-audit.py` skips `tests/` for the same reason.
// The manifest's dependencies are shared by the lib, the bin and this test;
// `unused_crate_dependencies` is per-target and cannot see that.
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use prost::Message as _;
use starling_crypto::VoiceCipher as _;
use starling_crypto::ocb2::{Block, Ocb2};
use starling_harness::{
    AUDIO_ATTEMPT, AUDIO_TIMEOUT, Client, Deployment, FRAME_TIMEOUT, LIVE_START_TIMEOUT,
    MUMBLE_VERSION_V2, PCHAT_OUTER_TYPE, REGULAR_SPEECH, SERVER_LOOPBACK, TempDir, UDP_TUNNEL,
    audio_frame, free_port, handshake, handshake_as, handshake_epoch1, handshake_fancy,
    handshake_with_tokens, heard,
};
use starling_proto::proto::tcp;
use starling_proto::proto::udp;
use starling_proto_fancy::fancy;
use starling_runtime::log::{Category, FieldValue};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// An admin changing the livery over the connection they already have.
///
/// The whole point of the client-channel path: no operator token is typed,
/// no second surface is exposed, and the identity is the session the frame
/// arrived on. This proves the authorised half; the refusal is next door.
#[tokio::test]
async fn an_admin_changes_the_livery_over_the_connection_they_already_have() {
    use starling_proto_fancy::fancy::domain::{
        LiveryDoc, LiveryQuery, LiveryUpdate, ServerConfigEnvelope, server_config_envelope,
    };
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;
    use starling_proto_fancy::types::ServiceKind;

    let data_dir = TempDir::new("livery-write");
    let deployment = Deployment::start(data_dir.path()).await;

    // Livery is a property of the server, so the permission is `Write` on the
    // root channel - murmur's rule for every administrative write.
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("all", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let session = handshake_fancy(&mut alice, "alice").await;
    deployment
        .wait_until_permitted(session, 0, Perm::WRITE.bits())
        .await;

    let outer = ServiceKind::ServerConfig.outer_type();
    alice
        .send(
            outer,
            &ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::LiveryUpdate(LiveryUpdate {
                    fields: vec!["tagline".to_owned(), "display_name".to_owned()],
                    values: Some(LiveryDoc {
                        tagline: "cozy corner".to_owned(),
                        display_name: "magical.rocks".to_owned(),
                        ..Default::default()
                    }),
                })),
            },
        )
        .await;

    // Read it back the way the connect screen does, which also proves the two
    // halves of 1013 agree about the document.
    alice
        .send(
            outer,
            &ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::LiveryQuery(LiveryQuery {
                    have_keys: Vec::new(),
                })),
            },
        )
        .await;

    let document = loop {
        let (type_id, payload) = alice.recv().await;
        if type_id != outer {
            continue;
        }
        let envelope = ServerConfigEnvelope::decode(payload.as_slice()).expect("an envelope");
        if let Some(server_config_envelope::Body::Livery(doc)) = envelope.body
            && !doc.tagline.is_empty()
        {
            break doc;
        }
    };

    assert_eq!(document.tagline, "cozy corner");
    assert_eq!(document.display_name, "magical.rocks");
    assert!(document.version >= 1, "the write did not bump the version");
    assert!(
        !document.digest.is_empty(),
        "a livery with content has a digest"
    );

    deployment.stop().await;
}

/// The same write from somebody who may not make it.
///
/// Refused *out loud*. A write accepted and dropped shows the admin their
/// change on screen and leaves nothing in any log, which is the failure
/// `moderation::on_user_remove` records having shipped once.
#[tokio::test]
async fn a_client_without_write_is_told_the_livery_change_was_refused() {
    use starling_proto_fancy::fancy::domain::{
        LiveryDoc, LiveryUpdate, ServerConfigEnvelope, server_config_envelope,
    };
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::types::ServiceKind;

    let data_dir = TempDir::new("livery-refused");
    let deployment = Deployment::start(data_dir.path()).await;

    // No grant: the default ACL gives `all` no Write at the root.
    let mut mallory = Client::connect(deployment.port).await;
    let _ = handshake(&mut mallory, "mallory").await;

    mallory
        .send(
            ServiceKind::ServerConfig.outer_type(),
            &ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::LiveryUpdate(LiveryUpdate {
                    fields: vec!["tagline".to_owned()],
                    values: Some(LiveryDoc {
                        tagline: "not allowed".to_owned(),
                        ..Default::default()
                    }),
                })),
            },
        )
        .await;

    // Wire type 12 is upstream's PermissionDenied.
    let denied = loop {
        let (type_id, payload) = mallory.recv().await;
        if type_id == 12 {
            break tcp::PermissionDenied::decode(payload.as_slice())
                .expect("a well-formed PermissionDenied");
        }
    };
    assert_eq!(
        denied.permission,
        Some(Perm::WRITE.bits()),
        "the client has to be told which permission it lacked"
    );

    deployment.stop().await;
}

/// An admin reading and changing the settings over the connection they have.
///
/// The other half of 1013, and for a long time the half that did nothing: the
/// server answered a query nobody sent and refused every write, so the client's
/// settings screen showed "this server may not support runtime settings" to an
/// admin of a server that supports them.
#[tokio::test]
async fn an_admin_reads_and_changes_the_server_settings_over_their_connection() {
    use starling_proto_fancy::fancy::domain::{
        ConfigQuery, ConfigUpdate, ConfigValues, ServerConfigEnvelope, Setting,
        server_config_envelope, setting,
    };
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;
    use starling_proto_fancy::types::ServiceKind;

    /// The next settings snapshot to arrive, ignoring everything else.
    async fn values(alice: &mut Client, outer: u16) -> ConfigValues {
        loop {
            let (type_id, payload) = alice.recv().await;
            if type_id != outer {
                continue;
            }
            let envelope = ServerConfigEnvelope::decode(payload.as_slice()).expect("an envelope");
            if let Some(server_config_envelope::Body::Values(values)) = envelope.body {
                return values;
            }
        }
    }

    /// What one setting reads as on the wire.
    fn read(settings: &[Setting], key: &str) -> String {
        settings
            .iter()
            .find(|setting| setting.key == key)
            .map(|setting| setting.value.clone())
            .unwrap_or_default()
    }

    let data_dir = TempDir::new("settings-write");
    let deployment = Deployment::start(data_dir.path()).await;

    // A property of the server, so the gate is `Write` on the root channel -
    // murmur's rule for every administrative write, and the same one livery
    // is held to next door.
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("all", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let session = handshake_fancy(&mut alice, "alice").await;
    deployment
        .wait_until_permitted(session, 0, Perm::WRITE.bits())
        .await;

    let outer = ServiceKind::ServerConfig.outer_type();
    alice
        .send(
            outer,
            &ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::Query(ConfigQuery {})),
            },
        )
        .await;
    let before = values(&mut alice, outer).await;
    assert!(
        before.settings.iter().any(|s| s.key == "welcome_text"),
        "the schema a client builds its form from has to come with the values"
    );
    assert!(
        before
            .settings
            .iter()
            .any(|s| s.key == "password" && s.secret && s.value.is_empty()),
        "a secret is named so a client can tell 'not set' from 'withheld'"
    );
    // The kind reaches the client too, and this one decides whether an operator
    // is handed a formatting toolbar or a box of raw tags.
    assert_eq!(
        before
            .settings
            .iter()
            .find(|s| s.key == "welcome_text")
            .map(Setting::kind),
        Some(setting::Kind::Html),
        "the welcome text has to arrive declared as the markup it is"
    );

    alice
        .send(
            outer,
            &ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::Update(ConfigUpdate {
                    values: [
                        ("welcome_text".to_owned(), "cozy corner".to_owned()),
                        ("max_users".to_owned(), "42".to_owned()),
                    ]
                    .into_iter()
                    .collect(),
                })),
            },
        )
        .await;

    // The save is answered with the stamped snapshot, so the screen shows what
    // the server holds rather than what was typed at it.
    let after = values(&mut alice, outer).await;
    assert_eq!(read(&after.settings, "welcome_text"), "cozy corner");
    assert_eq!(read(&after.settings, "max_users"), "42");
    assert!(
        after.version > before.version,
        "a write that changed something has to move the version"
    );

    deployment.stop().await;
}

/// The same read from somebody who may not make it.
///
/// Silence rather than a refusal, the way `audit` answers an unauthorised
/// query: the settings are what this server may be talked into doing, and the
/// list of them is an inventory of what to try.
#[tokio::test]
async fn a_client_without_write_is_not_sent_the_server_settings() {
    use starling_proto_fancy::fancy::domain::{
        ConfigQuery, LiveryQuery, ServerConfigEnvelope, server_config_envelope,
    };
    use starling_proto_fancy::types::ServiceKind;

    let data_dir = TempDir::new("settings-refused");
    let deployment = Deployment::start(data_dir.path()).await;

    // No grant: the default ACL gives `all` no Write at the root.
    let mut mallory = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut mallory, "mallory").await;

    let outer = ServiceKind::ServerConfig.outer_type();
    mallory
        .send(
            outer,
            &ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::Query(ConfigQuery {})),
            },
        )
        .await;
    // Chased by something this session *may* have, so the test proves an
    // ordering rather than waiting out a timeout: the livery comes back and
    // the settings never do.
    mallory
        .send(
            outer,
            &ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::LiveryQuery(LiveryQuery {
                    have_keys: Vec::new(),
                })),
            },
        )
        .await;

    loop {
        let (type_id, payload) = mallory.recv().await;
        if type_id != outer {
            continue;
        }
        let envelope = ServerConfigEnvelope::decode(payload.as_slice()).expect("an envelope");
        match envelope.body {
            Some(server_config_envelope::Body::Livery(_)) => break,
            other => panic!("the settings were sent to a client without Write: {other:?}"),
        }
    }

    deployment.stop().await;
}

#[tokio::test]
async fn a_client_on_our_epoch_is_told_which_fancy_features_exist() {
    // The gap that made every encrypted channel carry nothing. Starling
    // announced the wire epoch and withheld the product version, so the client
    // knew *how* to speak but not *what exists* -- and it gates on the latter.
    // With it absent `mumble-tauri` leaves `message_id` unset, its
    // encrypted-message path is keyed on that id, and it therefore builds no
    // ciphertext at all. The channel is correctly signal_v1 at both ends and no
    // message ever crosses it.
    let data_dir = TempDir::new("epoch1-version");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let (_, announced) = handshake_epoch1(&mut alice, "alice").await;

    let announced = announced.expect("an epoch-1 peer must be told the feature version");
    assert!(
        announced >= starling_gate::FancyVersion::new(0, 2, 12).to_wire(),
        "below 0.2.12 a client tunnels everything instead of speaking natively"
    );

    deployment.stop().await;
}

/// A Fancy version from before the renumbering, wire-encoded.
///
/// `major << 48 | minor << 32 | patch << 16`, so this is 0.3.0 -- a real
/// released client, and the one the report came from.
const PRE_EPOCH_FANCY_VERSION: u64 = 3 << 32;

#[tokio::test]
async fn a_fancy_client_from_before_the_renumbering_is_told_to_update() {
    // The other half of withholding. The gateway is right to keep service
    // frames away from this peer, but on its own that is a silent downgrade:
    // chat and reactions stop working and the user has nothing to read about
    // why. `TextMessage` is upstream and frozen, so it is the one channel that
    // reaches a peer of any epoch.
    let data_dir = TempDir::new("outdated-notice");
    let deployment = Deployment::start(data_dir.path()).await;

    // `fancy_version` set and no `fancy_protocol`: exactly a 0.3.0 client.
    let mut legacy = Client::connect(deployment.port).await;
    let _ = handshake_as(
        &mut legacy,
        tcp::Authenticate {
            username: Some("legacy".to_owned()),
            ..tcp::Authenticate::default()
        },
        Some(PRE_EPOCH_FANCY_VERSION),
    )
    .await;

    let mut notice = None;
    while let Some((type_id, payload)) = legacy.next_frame(Duration::from_secs(2)).await {
        if type_id == 11 {
            notice = tcp::TextMessage::decode(payload.as_slice()).ok();
            break;
        }
    }

    let notice = notice.expect("a client on the older epoch is told why things do not work");
    assert!(
        notice.message.contains("out of date"),
        "the notice has to say what is wrong: {}",
        notice.message
    );
    assert_eq!(
        notice.actor, None,
        "actorless, so it renders as a server notice rather than a whisper"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_stock_mumble_client_is_not_told_its_client_is_out_of_date() {
    // It is epoch 0 too, and it is using this server exactly as it should. On a
    // public server it is also most of the room, so a warning aimed at the
    // wrong population is worse than none at all.
    let data_dir = TempDir::new("stock-no-notice");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut stock = Client::connect(deployment.port).await;
    let _ = handshake(&mut stock, "stock").await;

    while let Some((type_id, payload)) = stock.next_frame(Duration::from_secs(2)).await {
        if type_id == 11 {
            let text = tcp::TextMessage::decode(payload.as_slice()).unwrap_or_default();
            assert!(
                !text.message.contains("out of date"),
                "a stock client has no Fancy build to update: {}",
                text.message
            );
        }
    }

    deployment.stop().await;
}

#[tokio::test]
async fn a_client_on_the_older_epoch_is_never_handed_a_service_frame() {
    // The delivery half of the epoch rule, and the half that was missing. The
    // handshake correctly withheld the feature version from an epoch-0 peer
    // (the test below), but nothing gated the *fan-out*: a service addresses an
    // audience it never enumerates, so one epoch-1 client's pchat traffic was
    // relayed to every member of the channel at outer type 1006 -- including
    // peers whose decoder cannot map that id.
    //
    // For those peers it is not a dropped feature. `mumble-protocol`'s codec
    // turns an unknown type into `Error::UnknownMessageType` and the read loop
    // treats it as fatal, so the frame cost a 0.3.0 client its connection: it
    // was dropped whenever a develop client spoke, and could not get back in
    // while one was connected, because its own arrival was what prompted the
    // other client to send.
    let data_dir = TempDir::new("epoch-gate");
    let deployment = Deployment::start(data_dir.path()).await;

    // The shipped client: it announces no epoch, because it was built before
    // there was one to announce.
    let mut legacy = Client::connect(deployment.port).await;
    let _ = handshake(&mut legacy, "legacy").await;

    let mut modern = Client::connect(deployment.port).await;
    let (_, _) = handshake_epoch1(&mut modern, "modern").await;

    let envelope = fancy::pchat::PchatEnvelope {
        body: Some(fancy::pchat::pchat_envelope::Body::Message(
            fancy::pchat::Message {
                message_id: "01234567-89ab-7def-8123-456789abcdef".to_owned(),
                channel: 0,
                ciphertext: b"not plaintext".to_vec(),
                epoch: 1,
                protocol: fancy::pchat::Protocol::SignalV1 as i32,
                ..fancy::pchat::Message::default()
            },
        )),
    };
    modern
        .send_raw(PCHAT_OUTER_TYPE, &envelope.encode_to_vec())
        .await;

    // Everything the legacy peer is handed while that crosses the server.
    let mut seen = Vec::new();
    while let Some((type_id, _)) = legacy.next_frame(Duration::from_secs(2)).await {
        seen.push(type_id);
    }

    assert!(
        seen.iter()
            .all(|&type_id| type_id < starling_proto_fancy::types::SERVICE_BASE),
        "an epoch-0 peer was handed a service outer type it cannot decode: {seen:?}"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_stock_client_is_never_told_a_feature_version() {
    // The other half, and the reason the announcement is conditional rather
    // than unconditional: to a peer that never named an epoch, a product
    // version reads as licence to send the 100-999 layout, which this server
    // routes nowhere. Silence keeps it on `PluginDataTransmission`, which is
    // relayed correctly. `handshake` sends no `fancy_protocol`, so this is the
    // stock shape.
    let data_dir = TempDir::new("stock-version");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;
    assert_eq!(
        alice.announced_fancy_version, None,
        "a stock client must not be given a product version"
    );

    deployment.stop().await;
}

/// Drive the handshake to `ServerConfig` and return it decoded.
///
/// Not `handshake`: that helper asserts order and throws the frame away, and
/// these tests are about what the frame says.
async fn server_config_of(client: &mut Client, username: &str) -> tcp::ServerConfig {
    let (greeting_type, _) = client.recv().await;
    assert_eq!(greeting_type, 0, "the server speaks Version first");
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
                username: Some(username.to_owned()),
                ..tcp::Authenticate::default()
            },
        )
        .await;
    let (_, payload) = client.recv_until(24).await;
    tcp::ServerConfig::decode(payload.as_slice()).expect("a well-formed ServerConfig")
}

#[tokio::test]
async fn a_configured_media_plane_is_advertised_in_the_handshake() {
    // The client warns on every share that the server has no relay unless
    // `ServerConfig` says otherwise, so an SFU that starts but is never
    // advertised looks exactly like no SFU at all.
    let data_dir = TempDir::new("sfu-advertised");
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        if let Some(service) = config.services.get_mut("screenshare") {
            // A literal IP, the media-plane precondition; port 0 keeps the
            // SFU's real UDP socket ephemeral under parallel tests.
            service.public_url = Some("127.0.0.1:0".to_owned());
        }
    })
    .await;

    let mut alice = Client::connect(deployment.port).await;
    let config = server_config_of(&mut alice, "alice").await;
    assert_eq!(
        config.webrtc_sfu_available,
        Some(true),
        "a deployment with a media plane must say so in the handshake"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_server_without_a_media_plane_does_not_claim_one() {
    // Absent, not `Some(false)`, matching murmur: the client defaults the
    // field and a claimed relay that does not exist would have every share
    // negotiate against nothing instead of warning up front.
    let data_dir = TempDir::new("sfu-absent");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let config = server_config_of(&mut alice, "alice").await;
    assert_eq!(config.webrtc_sfu_available, None);

    deployment.stop().await;
}

/// Channels in the tree this test builds, and bytes of artwork in each.
///
/// 128 KiB is murmur's own `image_message_length`, which is the size of image
/// its clients were allowed to paste into a description in the first place; the
/// count is the smallest that clears 4 MiB with room to spare. The server that
/// found the bug carried more (5.75 MiB over 47 channels) and the test used to
/// match it, which cost a slow runner more than it bought: every byte over the
/// limit proves the same thing, and all of them are encoded, permission-checked
/// and written by a debug build before the assertion can run.
const ARTWORK_CHANNELS: usize = 36;
/// Bytes of "image" in one channel description.
const ARTWORK_BYTES: usize = 128 * 1024;

/// How long the whole channel flood may take to arrive.
///
/// Not [`FRAME_TIMEOUT`], which bounds *one* frame on a server with nothing to
/// do. The handshake computes its entire reply before sending any of it, so the
/// gap this covers contains a multi-MiB tree being decoded, turned into one
/// `ChannelState` per channel and permission-checked, in an unoptimised build.
/// Ten seconds is comfortable on a developer's machine and not on a
/// two-core runner, which is where this first came apart.
const FLOOD_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn a_channel_tree_too_large_for_the_grpc_default_still_reaches_a_client() {
    // The whole tree crosses between services as **one** gRPC message, and gRPC
    // caps what a client will decode at 4 MiB unless it says otherwise. Nothing
    // about that is gradual: past the limit the reply is refused whole, so the
    // handshake completes and admits the client to a server with no channels in
    // it, which is not a failure anybody reads as "a message was too large".
    //
    // A fresh server never approaches it. A server imported from murmur can
    // arrive over it on day one, because descriptions are HTML and murmur has
    // always allowed an image inside one, stored inline as base64.
    let data_dir = TempDir::new("large-tree");
    let deployment = Deployment::start(data_dir.path()).await;

    let artwork = format!(
        "<img src=\"data:image/png;base64,{}\">",
        "A".repeat(ARTWORK_BYTES)
    );
    for index in 0..ARTWORK_CHANNELS {
        let _ = deployment
            .create_described_channel(&format!("Gallery {index}"), artwork.clone())
            .await;
    }

    let mut viewer = Client::connect(deployment.port).await;
    let announced = channels_announced(&mut viewer, "viewer").await;
    assert_eq!(
        announced,
        ARTWORK_CHANNELS + 1,
        "every channel and the root must be announced; a client that is told \
         about fewer has been admitted to a server it cannot see"
    );

    deployment.stop().await;
}

/// Log in and count the channels announced before `ServerSync`.
///
/// Its own handshake rather than [`handshake`]: that one asserts *that* the
/// tree arrived before the sync, and the question here is how much of it did.
async fn channels_announced(client: &mut Client, username: &str) -> usize {
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
                username: Some(username.to_owned()),
                ..tcp::Authenticate::default()
            },
        )
        .await;

    let mut announced = 0;
    loop {
        // The count goes into the panic, because "a frame did not arrive" says
        // nothing about whether the flood never started or stopped halfway, and
        // those have different causes.
        let (type_id, payload) = client
            .next_frame(FLOOD_TIMEOUT)
            .await
            .unwrap_or_else(|| panic!("the flood stalled after {announced} channels"));
        match type_id {
            // `ChannelState`. Decoded rather than counted blind, so a frame
            // that arrived truncated is a failure here and not a mystery later.
            7 => {
                let _ = tcp::ChannelState::decode(payload.as_slice()).expect("a well-formed frame");
                announced += 1;
            }
            // `ServerSync`: the tree is complete by contract once this lands.
            5 => return announced,
            _ => {}
        }
    }
}

/// Bytes of artwork that force the lazy path: well over murmur's 128-byte inline
/// threshold, small enough to stay quick in a debug build.
const LAZY_DESCRIPTION_BYTES: usize = 200 * 1024;

/// Log in, and hand back the flood's `ChannelState` for one channel id.
///
/// Its own handshake rather than [`handshake`]: this one keeps a channel's
/// state to look inside it, where that one asserts the ordering and moves on.
async fn flood_channel_state(client: &mut Client, username: &str, id: u32) -> tcp::ChannelState {
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
                username: Some(username.to_owned()),
                ..tcp::Authenticate::default()
            },
        )
        .await;

    let mut found = None;
    loop {
        let (type_id, payload) = client.recv().await;
        match type_id {
            7 => {
                let state = tcp::ChannelState::decode(payload.as_slice())
                    .expect("a well-formed ChannelState");
                if state.channel_id == Some(id) {
                    found = Some(state);
                }
            }
            5 => return found.expect("the channel was announced before ServerSync"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn a_large_channel_description_is_flooded_as_a_hash_and_fetched_on_demand() {
    // The regression this guards. A channel description rode inline in the login
    // flood, and murmur stores an image inside a description as base64, so a
    // themed server's flood could pass the gateway's per-connection control
    // budget; the tail of the handshake -- ServerSync and the user list -- was
    // then dropped with no log, and the client connected to a tree it could not
    // see.
    //
    // `a_channel_tree_too_large_for_the_grpc_default_still_reaches_a_client`
    // did not catch it and could not: it runs in-process, where the OS socket
    // buffer swallows a multi-MiB flood so the byte budget (which bounds
    // *un-drained* queue occupancy, not total bytes) is never reached, and it
    // asserted only that every channel was announced, never that a description
    // stays out of the flood.
    //
    // The fix, asserted directly: a description at or over the threshold travels
    // as its SHA-1 (`ChannelState.description_hash`), the body is fetched with
    // `RequestBlob.channel_description`, and the flood carries a few dozen bytes
    // per channel however much artwork it holds.
    let data_dir = TempDir::new("lazy-description");
    let deployment = Deployment::start(data_dir.path()).await;

    let artwork = "A".repeat(LAZY_DESCRIPTION_BYTES);
    let id = deployment
        .create_described_channel("Gallery", artwork.clone())
        .await;

    let mut client = Client::connect(deployment.port).await;
    let flooded = flood_channel_state(&mut client, "viewer", id).await;
    assert!(
        flooded
            .description
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "a large description must not ride inline in the flood"
    );
    assert_eq!(
        flooded.description_hash.as_ref().map(Vec::len),
        Some(20),
        "it travels as its 20-byte SHA-1 instead"
    );

    // Redeem it the way a client renders a channel it has clicked into.
    client
        .send(
            23,
            &tcp::RequestBlob {
                channel_description: vec![id],
                ..tcp::RequestBlob::default()
            },
        )
        .await;
    let redeemed = loop {
        let (type_id, payload) = client.recv().await;
        if type_id == 7 {
            let state =
                tcp::ChannelState::decode(payload.as_slice()).expect("a well-formed ChannelState");
            if state.channel_id == Some(id) {
                break state;
            }
        }
    };
    assert_eq!(
        redeemed.description.as_deref(),
        Some(artwork.as_str()),
        "RequestBlob.channel_description returns the full body"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_login_flood_over_the_control_budget_still_completes() {
    // The outage itself, made deterministic. On the deployed server the flood
    // passed the gateway's 4 MiB control budget and the handshake was truncated:
    // the client authenticated, then received neither ServerSync nor the tree,
    // with nothing in the log. In-process the OS buffer hides a 4 MiB flood, so
    // the budget is set small here and one oversized description reaches it in a
    // single frame -- inlined it overflows and the login never completes; hashed
    // it stays tiny and the handshake runs to `SuggestConfig`, which is what
    // [`handshake`] returning at all asserts.
    let data_dir = TempDir::new("flood-over-budget");
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        config.gateway.control_bytes = 256 * 1024;
    })
    .await;

    // Inlined, this one channel's `ChannelState` alone exceeds the budget.
    let _ = deployment
        .create_described_channel("Gallery", "A".repeat(512 * 1024))
        .await;

    let mut client = Client::connect(deployment.port).await;
    let _session = handshake(&mut client, "viewer").await;

    deployment.stop().await;
}

#[tokio::test]
async fn a_request_for_every_description_is_answered_within_the_control_budget() {
    // The outage's second half. Hashing the descriptions moved the megabytes
    // out of the flood, but a Fancy client redeems them by asking for the whole
    // tree in one `RequestBlob` at `ServerSync` -- and the answer to that went
    // out as one burst, past the same budget, killing the client a few hundred
    // milliseconds after it had connected. Against the deployed server: 36
    // channels, 5.75 MiB of descriptions, 4 MiB budget, reset every time.
    //
    // So the reply is capped, and the contract is what this asserts: one
    // request is answered with what fits and no more, the rest keep their
    // hashes, and asking again redeems them -- the whole tree arrives, over
    // several rounds, without the connection ever being at risk.
    let data_dir = TempDir::new("blob-within-budget");
    const BUDGET: usize = 256 * 1024;
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        config.gateway.control_bytes = BUDGET;
    })
    .await;
    // Half the budget is the cap; each of these is comfortably under it, so
    // nothing here is unanswerable -- only more than one reply can carry.
    let ceiling = BUDGET / 2;
    let each = 48 * 1024;
    let mut ids = Vec::new();
    for n in 0..8 {
        ids.push(
            deployment
                .create_described_channel(&format!("Gallery {n}"), "A".repeat(each))
                .await,
        );
    }

    let mut client = Client::connect(deployment.port).await;
    let _session = handshake(&mut client, "viewer").await;

    /// The gap between frames once a round's burst is already flowing, not
    /// the wait for its first one: short enough to spend eight of these in
    /// one test, long enough that back-to-back frames from the same reply
    /// never trip it.
    const QUIET: Duration = Duration::from_millis(500);
    let mut redeemed: Vec<u32> = Vec::new();
    let mut rounds = 0;
    while redeemed.len() < ids.len() {
        rounds += 1;
        assert!(
            rounds <= ids.len(),
            "each round must redeem at least one description; \
             {} of {} after {rounds} rounds",
            redeemed.len(),
            ids.len()
        );
        let missing: Vec<u32> = ids
            .iter()
            .copied()
            .filter(|id| !redeemed.contains(id))
            .collect();
        client
            .send(
                23,
                &tcp::RequestBlob {
                    channel_description: missing,
                    ..tcp::RequestBlob::default()
                },
            )
            .await;

        let mut answered = 0usize;
        // The wait for this round's *first* `ChannelState` is [`FRAME_TIMEOUT`],
        // same as every other "did the server answer at all" in this file: a
        // busy runner can starve the gateway's task for a while without it
        // making any less progress than an idle one, and that starving is
        // exactly what [`QUIET`] was mistaken for before, one round in five
        // failing under load with a 500ms deadline that measured scheduler
        // noise instead of the reply.
        //
        // The connection carries more than this round's answer -- a
        // `PermissionQuery` the server sends on its own schedule showed up
        // here too, in the same slot a real reply would have -- so only a
        // frame that *is* one, type 7, is allowed to tighten the deadline to
        // QUIET. Anything else is read and ignored without changing `wait`,
        // exactly as a client waiting on this round would treat it.
        let mut wait = FRAME_TIMEOUT;
        while let Some((type_id, payload)) = client.next_frame(wait).await {
            if type_id != 7 {
                continue;
            }
            wait = QUIET;
            let state =
                tcp::ChannelState::decode(payload.as_slice()).expect("a well-formed ChannelState");
            let (Some(id), Some(description)) = (state.channel_id, state.description) else {
                continue;
            };
            if description.is_empty() || !ids.contains(&id) {
                continue;
            }
            assert_eq!(description.len(), each, "a redeemed description is whole");
            answered += description.len();
            redeemed.push(id);
        }
        assert!(
            answered <= ceiling,
            "one request must not be answered with more than the cap: \
             {answered} bytes against a {ceiling}-byte ceiling"
        );
        assert!(
            answered > 0,
            "a request must make progress: no reply within {FRAME_TIMEOUT:?} of asking"
        );
    }
    assert!(
        rounds > 1,
        "the point is a reply too large for one round; it took {rounds}"
    );

    // Still connected, and still being served: the reply that used to be a
    // disconnect is now just a reply.
    client
        .send(
            3,
            &tcp::Ping {
                timestamp: Some(1),
                ..tcp::Ping::default()
            },
        )
        .await;
    let (kind, _) = client.recv().await;
    assert_eq!(kind, 3, "the server answers a ping on a live connection");

    deployment.stop().await;
}

#[tokio::test]
async fn the_server_announces_its_release_version_not_a_service_crate_s() {
    // The opening `Version.release` is the server's version, from the workspace,
    // and must not be a component crate's own number. It was built from
    // `session-lifecycle`'s `CARGO_PKG_VERSION` -- 0.2.0, that service's pinned
    // version -- so every client read "Starling 0.2.0" whatever the release.
    let data_dir = TempDir::new("release-version");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut client = Client::connect(deployment.port).await;
    let (greeting_type, payload) = client.recv().await;
    assert_eq!(greeting_type, 0, "the server speaks Version first");
    let greeting = tcp::Version::decode(payload.as_slice()).expect("a well-formed Version");
    assert_eq!(
        greeting.release.as_deref(),
        Some(format!("Starling {}", starling_runtime::VERSION).as_str()),
        "the advertised release must be the server's version, not a service's"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn an_encrypted_message_reaches_the_other_member_of_its_channel() {
    // Persistent chat, end to end over the real wire: the server stores an
    // opaque ciphertext and relays it to the rest of the channel. Asserted on
    // the bytes, because the one transformation this service must never make is
    // to the payload -- a re-encoded ciphertext is a message the recipient
    // cannot decrypt, and it would fail identically to not arriving at all.
    let data_dir = TempDir::new("pchat-relay");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let (alice_session, _) = handshake_epoch1(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let (_, _) = handshake_epoch1(&mut bob, "bob").await;

    const CIPHERTEXT: &[u8] = b"\x00\xffnot plaintext\x00";
    let envelope = fancy::pchat::PchatEnvelope {
        body: Some(fancy::pchat::pchat_envelope::Body::Message(
            fancy::pchat::Message {
                message_id: "01234567-89ab-7def-8123-456789abcdef".to_owned(),
                channel: 0,
                ciphertext: CIPHERTEXT.to_vec(),
                epoch: 1,
                protocol: fancy::pchat::Protocol::SignalV1 as i32,
                ..fancy::pchat::Message::default()
            },
        )),
    };
    alice
        .send_raw(PCHAT_OUTER_TYPE, &envelope.encode_to_vec())
        .await;

    let (_, delivered) = bob.recv_until(PCHAT_OUTER_TYPE).await;
    let Some(fancy::pchat::pchat_envelope::Body::Message(message)) =
        fancy::pchat::PchatEnvelope::decode(delivered.as_slice())
            .expect("a well-formed PchatEnvelope")
            .body
    else {
        panic!("expected a pchat message");
    };

    assert_eq!(
        message.ciphertext, CIPHERTEXT,
        "the ciphertext must cross byte for byte"
    );
    assert_eq!(
        message.sender, alice_session,
        "the server stamps the live sender rather than trusting the wire"
    );
    assert_eq!(
        message.protocol,
        fancy::pchat::Protocol::SignalV1 as i32,
        "the recipient has to know which scheme sealed it"
    );
    assert_eq!(
        message.message_id, "01234567-89ab-7def-8123-456789abcdef",
        "the sender's id must cross untouched: an archive message is sealed \
         against it (AAD = channel ‖ message_id ‖ sent_at_ms), so a server that \
         re-mints it delivers a ciphertext nobody can open"
    );

    deployment.stop().await;
}

/// The wire number of the mode where this server holds the key.
const PCHAT_SERVER_MANAGED: u32 = 3;

/// Create a channel under the root running `protocol`.
async fn create_pchat_channel(deployment: &Deployment, name: &str, protocol: u32) -> u32 {
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest};

    let transport = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    MetadataClient::new(transport)
        .create(CreateRequest {
            scope: None,
            actor: None,
            channel: Some(Channel {
                name: name.to_owned(),
                parent: Some(0),
                pchat_protocol: protocol,
                ..Channel::default()
            }),
            temporary: false,
            invitee_user_ids: Vec::new(),
            reuse_existing: true,
        })
        .await
        .expect("the channel is created")
        .into_inner()
        .channel
        .expect("a created channel is described")
        .id
}

/// Send one server-managed message, retrying until the mode cache has caught up.
///
/// `pchat` learns a channel's mode from a `metadata` subscription, so a channel
/// created a moment ago may not be in that table yet, and a message claiming
/// this mode is refused until it is. That is the write-side fail-closed working
/// as designed rather than a fault, so the test waits for it the way a client
/// would have to.
async fn send_server_managed(
    client: &mut Client,
    channel: u32,
    message_id: &str,
    body: &[u8],
) -> fancy::pchat::Ack {
    let mut last = None;
    for _ in 0..40 {
        let envelope = fancy::pchat::PchatEnvelope {
            body: Some(fancy::pchat::pchat_envelope::Body::Message(
                fancy::pchat::Message {
                    message_id: message_id.to_owned(),
                    channel,
                    ciphertext: body.to_vec(),
                    protocol: fancy::pchat::Protocol::ServerManaged as i32,
                    ..fancy::pchat::Message::default()
                },
            )),
        };
        client
            .send_raw(PCHAT_OUTER_TYPE, &envelope.encode_to_vec())
            .await;

        let (_, answered) = client.recv_until(PCHAT_OUTER_TYPE).await;
        let Some(fancy::pchat::pchat_envelope::Body::Ack(ack)) =
            fancy::pchat::PchatEnvelope::decode(answered.as_slice())
                .expect("a well-formed PchatEnvelope")
                .body
        else {
            panic!("a message is answered by an ack");
        };
        if ack.status != fancy::pchat::ack::Status::Refused as i32 {
            return ack;
        }
        last = Some(ack);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    last.expect("the loop runs at least once")
}

#[tokio::test]
async fn a_server_managed_archive_reaches_a_late_joiner_and_not_the_disk() {
    use starling_proto_fancy::perm::Perm;

    // The two claims the mode makes, against one deployment.
    //
    // The first is the reason it exists: every other persistent mode is
    // end-to-end, so somebody arriving after the conversation needs a key from
    // a member who was already there. Here the server holds it, so the archive
    // is readable as soon as they can enter. Asserted through a client that was
    // not connected when the message was sent, because a sender reading its own
    // message proves nothing.
    //
    // The second is what "sealed at rest" has to mean to be worth saying: the
    // plaintext appears in none of the files the deployment wrote.
    //
    // One deployment rather than two on purpose. The suite's Windows flake is
    // suspected to be `free_port` racing when several deployments start at
    // once, so a new test that needs no second server should not start one.
    let data_dir = TempDir::new("pchat-server-managed");
    let deployment = Deployment::start(data_dir.path()).await;
    let channel = create_pchat_channel(&deployment, "minutes", PCHAT_SERVER_MANAGED).await;

    const SAID: &[u8] = b"the server can read this, and that is the point";
    let mut alice = Client::connect(deployment.port).await;
    let (alice_session, _) = handshake_epoch1(&mut alice, "alice").await;
    deployment
        .wait_until_permitted(alice_session, channel, Perm::TEXT_MESSAGE.bits())
        .await;

    let ack = send_server_managed(
        &mut alice,
        channel,
        "01234567-89ab-7def-8123-000000000001",
        SAID,
    )
    .await;
    assert_eq!(
        ack.status,
        fancy::pchat::ack::Status::Stored as i32,
        "a server-managed message in a server-managed channel is kept: {}",
        ack.detail
    );
    alice.close().await;

    // Connected only now, so nothing it holds could have come from the relay.
    let mut bob = Client::connect(deployment.port).await;
    let (bob_session, _) = handshake_epoch1(&mut bob, "bob").await;
    deployment
        .wait_until_permitted(bob_session, channel, Perm::ENTER.bits())
        .await;

    let fetch = fancy::pchat::PchatEnvelope {
        body: Some(fancy::pchat::pchat_envelope::Body::Fetch(
            fancy::pchat::Fetch {
                channel,
                page: Some(fancy::wire::Cursor {
                    limit: 50,
                    ..fancy::wire::Cursor::default()
                }),
            },
        )),
    };
    bob.send_raw(PCHAT_OUTER_TYPE, &fetch.encode_to_vec()).await;

    let (_, served) = bob.recv_until(PCHAT_OUTER_TYPE).await;
    let Some(fancy::pchat::pchat_envelope::Body::FetchResponse(page)) =
        fancy::pchat::PchatEnvelope::decode(served.as_slice())
            .expect("a well-formed PchatEnvelope")
            .body
    else {
        panic!("a fetch is answered by a page");
    };

    assert_eq!(page.messages.len(), 1, "the archive holds what was said");
    assert_eq!(
        page.messages[0].ciphertext, SAID,
        "sealed on the way in and opened on the way out, so a reader who was \
         never handed a key still reads it"
    );
    assert_eq!(page.total_stored, 1, "the first page carries the count");

    deployment.stop().await;

    // Every byte the server left behind, whatever it called the files.
    let mut looked_at = 0_usize;
    let mut stack = vec![data_dir.path().to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                looked_at += 1;
                assert!(
                    !bytes.windows(SAID.len()).any(|window| window == SAID),
                    "{} holds the plaintext; a stolen backup would read it",
                    path.display()
                );
            }
        }
    }
    assert!(
        looked_at > 0,
        "the deployment wrote something to look through"
    );
}

#[tokio::test]
async fn a_pin_reaches_the_channel_including_whoever_set_it() {
    // A pin is channel state rather than a message, and the client holds no
    // optimistic copy of it: it learns the pin took by being sent it. The relay
    // skips the sender by default, which made the one person who saw nothing
    // happen the person who clicked Pin.
    //
    // Both halves are asserted here because either alone is a working feature
    // for somebody: bob proves the relay, alice proves the echo.
    let data_dir = TempDir::new("pchat-pin");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let (_, _) = handshake_epoch1(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let (_, _) = handshake_epoch1(&mut bob, "bob").await;

    const PINNED: &str = "01234567-89ab-7def-8123-456789abcdef";
    let envelope = fancy::pchat::PchatEnvelope {
        body: Some(fancy::pchat::pchat_envelope::Body::Pin(fancy::pchat::Pin {
            message_id: PINNED.to_owned(),
            channel: 0,
            unpin: false,
        })),
    };
    alice
        .send_raw(PCHAT_OUTER_TYPE, &envelope.encode_to_vec())
        .await;

    for (who, client) in [("bob", &mut bob), ("alice", &mut alice)] {
        let (_, delivered) = client.recv_until(PCHAT_OUTER_TYPE).await;
        let Some(fancy::pchat::pchat_envelope::Body::Pin(pin)) =
            fancy::pchat::PchatEnvelope::decode(delivered.as_slice())
                .expect("a well-formed PchatEnvelope")
                .body
        else {
            panic!("{who} expected a pin");
        };
        assert_eq!(
            pin.message_id, PINNED,
            "{who} was told about the wrong message"
        );
        assert!(!pin.unpin, "{who} saw a pin arrive as an unpin");
        assert_eq!(pin.channel, 0);
    }

    deployment.stop().await;
}

#[tokio::test]
async fn a_sender_key_distribution_reaches_the_member_it_names() {
    // How Signal sender keys actually travel. The client has no canon form for
    // `PchatSenderKeyDistribution`, so it relays it the epoch-independent way:
    // wrapped in `PluginDataTransmission` (upstream type 26) with a
    // `fancy-native:121` id, addressed at the channel's current members. Nothing
    // decrypts cross-client until this leg works, and it fails invisibly --
    // messages arrive and simply cannot be read.
    //
    // Asserted from outside because the two halves are owned by different
    // processes: the client fills the receiver list, the server stamps the
    // sender and strips the list.
    #[allow(deprecated, reason = "the legacy bridge shipped clients still use")]
    {
        let data_dir = TempDir::new("skdm-relay");
        let deployment = Deployment::start(data_dir.path()).await;

        let mut alice = Client::connect(deployment.port).await;
        let alice_session = handshake(&mut alice, "alice").await;
        let mut bob = Client::connect(deployment.port).await;
        let bob_session = handshake(&mut bob, "bob").await;

        const SKDM: &[u8] = b"\x33opaque sender key distribution";
        alice
            .send(
                26,
                &tcp::PluginDataTransmission {
                    // Deliberately wrong, and the point: murmur overwrites this
                    // rather than trusting it, or a peer could distribute a key
                    // in somebody else's name.
                    sender_session: Some(99999),
                    receiver_sessions: vec![bob_session],
                    data: Some(SKDM.to_vec()),
                    data_id: Some("fancy-native:121".to_owned()),
                },
            )
            .await;

        let (_, delivered) = bob.recv_until(26).await;
        let relayed = tcp::PluginDataTransmission::decode(delivered.as_slice())
            .expect("a well-formed PluginDataTransmission");

        assert_eq!(
            relayed.data.as_deref(),
            Some(SKDM),
            "the key material must cross untouched"
        );
        assert_eq!(
            relayed.data_id.as_deref(),
            Some("fancy-native:121"),
            "the id is how the receiving client knows which message this wraps"
        );
        assert_eq!(
            relayed.sender_session,
            Some(alice_session),
            "the server stamps the real sender; the receiver keys the sender key on it"
        );

        deployment.stop().await;
    }
}

#[tokio::test]
async fn a_relayed_text_message_carries_a_clock_whether_or_not_its_sender_sent_one() {
    // The finding: a message from a client that sends no `timestamp` reached
    // every reader without one, and nothing downstream can invent it - so the
    // reader drew the message at no particular moment, while the sender's own
    // copy, stamped locally on the way out, showed a time. The server is the
    // one party that knows when it arrived.
    let data_dir = TempDir::new("text-clock");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    // A sender that stamped its message keeps its stamp: its own copy is
    // already on screen reading that.
    alice
        .send(
            11,
            &tcp::TextMessage {
                actor: Some(alice_session),
                channel_id: vec![0],
                message: "stamped".to_owned(),
                timestamp: Some(1_700_000_000_000),
                ..tcp::TextMessage::default()
            },
        )
        .await;
    let (_, payload) = bob.recv_until(11).await;
    let received = tcp::TextMessage::decode(payload.as_slice()).expect("a TextMessage");
    assert_eq!(received.message, "stamped");
    assert_eq!(received.timestamp, Some(1_700_000_000_000));

    // A sender that stamped nothing gets the server's clock.
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64;
    alice
        .send(
            11,
            &tcp::TextMessage {
                actor: Some(alice_session),
                channel_id: vec![0],
                message: "unstamped".to_owned(),
                ..tcp::TextMessage::default()
            },
        )
        .await;
    let (_, payload) = bob.recv_until(11).await;
    let received = tcp::TextMessage::decode(payload.as_slice()).expect("a TextMessage");
    assert_eq!(received.message, "unstamped");
    let stamped = received
        .timestamp
        .expect("the relay stamps a message that arrived with no clock");
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64;
    assert!(
        (before..=after).contains(&stamped),
        "stamped {stamped} outside [{before}, {after}]"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn two_clients_complete_the_handshake_and_exchange_text() {
    let data_dir = TempDir::new("text");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;

    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    assert_ne!(alice_session, bob_session);

    alice
        .send(
            11,
            &tcp::TextMessage {
                actor: Some(alice_session),
                channel_id: vec![0],
                message: "hello from alice".to_owned(),
                ..tcp::TextMessage::default()
            },
        )
        .await;

    // Not `recv`: the handshake is followed by a pushed `PermissionQuery` for
    // the channel the client landed in, as murmur sends one on every entry
    // (`Server.cpp:2319`). It is a server-initiated frame with no request
    // behind it, so it can be the first thing waiting here, asserting on the
    // *next* frame made this test fail for a message it was not about.
    let (before_text, bob_payload) = bob.recv_until(11).await;
    assert!(
        before_text.iter().all(|&kind| kind == 20),
        "only the pushed PermissionQuery may precede alice's text, saw {before_text:?}"
    );
    let received =
        tcp::TextMessage::decode(bob_payload.as_slice()).expect("a well-formed TextMessage");
    assert_eq!(received.message, "hello from alice");
    assert_eq!(received.actor, Some(alice_session));

    // Mumble never echoes a message back to its own sender. Alice may still
    // see bob's join broadcast (UserState, 9) land before her pong; that is
    // a real, unrelated notification racing the reply, not an echo, so scan
    // past anything but a TextMessage rather than requiring the very next
    // frame to be the pong.
    alice
        .send(
            3,
            &tcp::Ping {
                timestamp: Some(7),
                ..tcp::Ping::default()
            },
        )
        .await;
    let (before_pong, alice_payload) = alice.recv_until(3).await;
    assert!(
        !before_pong.contains(&11),
        "alice's text message must not echo back to her"
    );
    let pong = tcp::Ping::decode(alice_payload.as_slice()).expect("a well-formed Ping");
    assert_eq!(pong.timestamp, Some(7));

    deployment.stop().await;
}

#[tokio::test]
async fn one_client_is_heard_by_another_over_the_tunnel() {
    // Audio over TCP: what a client behind a UDP-blocking firewall depends on,
    // and the path *every* connection uses until one of its datagrams
    // authenticates. Asserted end to end because nothing else can: the routing
    // core is covered by unit tests, but whether the gateway hands type 1 to
    // voice, whether voice's membership subscription warms in a real
    // deployment, and whether the fan-out reaches another socket are all
    // properties of the wiring rather than of the router.
    let data_dir = TempDir::new("tunnel-audio");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    // Re-sent until it lands, as a real client transmitting fifty frames a
    // second effectively does. Voice subscribes to `session-view` on start-up
    // and retries a second later if that service was not up yet, so *when* the
    // first routable frame is accepted is a start-up race, and one dropped
    // frame at start-up is not the failure this test is looking for.
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let received = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"hello"))
            .await;

        if let Some(payload) = bob.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };

    let payload = received.expect("bob never heard alice");
    let (speaker, opus) = heard(&payload);
    assert_eq!(opus, b"hello", "the audio was altered on the way through");
    assert_eq!(
        speaker, alice_session,
        "the listener must be told who spoke, or nobody's talking indicator works"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_datagram_on_the_voice_port_is_relayed_to_the_channel() {
    // Audio over UDP, which is how every client that can reach the port sends
    // it. Three separate things have to hold and none is visible from a unit
    // test: the socket is bound where the deployment said, a datagram is
    // *attributed* to a session by decrypting under that session's key, and the
    // frame is re-encoded for a listener on a different transport.
    //
    // Bob is tunnelled; he has sent no datagram, so the server has no proven
    // address for him, which makes this the mixed case a real server is in
    // constantly: UDP in, TCP out.
    let data_dir = TempDir::new("udp-audio");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    let mut cipher = alice.voice_cipher();
    let voice = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), deployment.voice_port));
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port is always available");

    // The connectivity probe a real client sends before trusting UDP with
    // anything: the server echoes target 31 back to the speaker alone. It also
    // proves the return direction, which nothing else here does, bob receives
    // over TCP.
    let echo = loop_back(&socket, voice, &mut cipher).await;
    assert_eq!(echo, b"probe", "voice did not echo the loopback target");

    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let received = loop {
        let sealed = cipher
            .seal(&audio_frame(REGULAR_SPEECH, b"over udp"), &[])
            .expect("the client seals its own audio");
        let _ = socket.send_to(&sealed, voice).await;

        if let Some(payload) = bob.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };

    let payload = received.expect("a datagram from alice never reached bob");
    let (speaker, opus) = heard(&payload);
    assert_eq!(opus, b"over udp");
    assert_eq!(speaker, alice_session);

    deployment.stop().await;
}

#[tokio::test]
async fn a_client_whose_nonce_drifted_asks_for_a_resync_and_is_answered() {
    // `CryptSetup`(15) inbound, which is the whole of the recovery a Mumble
    // client has when its UDP cipher falls out of step. It asks once every five
    // seconds while its audio is failing (`ServerHandler::message`) and does
    // nothing else: it does not reconnect and it does not fall back to the
    // tunnel. Unanswered, the client is deaf for the rest of its session with
    // every counter at both ends looking healthy.
    //
    // Driven end to end because the failure this covers is entirely in the
    // wiring. The classifier and the cipher's two halves are unit-tested; what
    // nothing below this level can show is whether the gateway hands type 15 to
    // session-lifecycle, whether that service asks voice, and whether what comes
    // back is a message this client can act on.
    let data_dir = TempDir::new("crypt-resync");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;

    let mut cipher = alice.voice_cipher();
    let voice = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), deployment.voice_port));
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port is always available");

    // A working UDP path first, or the rest of this proves nothing: a client
    // that was never able to hear the server cannot demonstrate recovering.
    assert_eq!(
        loop_back(&socket, voice, &mut cipher).await,
        b"probe",
        "voice did not echo the loopback target"
    );

    // Now break exactly what packet loss breaks, this client's idea of where
    // the server's counter has got to. Its *sending* half is untouched, which is
    // what makes this the real failure rather than a dead connection: the server
    // still hears alice perfectly while alice hears nothing.
    cipher.resync_to(Block([0xAB; 16]));
    assert!(
        try_loop_back(&socket, voice, &mut cipher).await.is_none(),
        "the client should now be unable to open the server's echo"
    );

    // The request, byte for byte what a Mumble client sends: a `CryptSetup` with
    // nothing in it. The absence of `client_nonce` is the entire message.
    alice.send(15, &tcp::CryptSetup::default()).await;
    let (_, payload) = alice.recv_until(15).await;
    let answer = tcp::CryptSetup::decode(payload.as_slice()).expect("a well-formed CryptSetup");

    assert_eq!(
        answer.key, None,
        "a key here reads as a whole new session to a client that asked only where the counter was"
    );
    assert_eq!(answer.client_nonce, None);
    let nonce = answer
        .server_nonce
        .expect("the answer is the nonce the server seals under");
    assert_eq!(nonce.len(), 16, "an AES block, which is what OCB2 installs");

    // And it is usable. This is the assertion the whole test exists for: an
    // answer the client cannot act on is indistinguishable from no answer.
    assert!(cipher.adopt_recv_nonce(&nonce));
    assert_eq!(
        loop_back(&socket, voice, &mut cipher).await,
        b"probe",
        "the resync was answered and the client is still deaf"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_refused_login_is_told_why_and_then_hung_up_on() {
    // The reported bug, both halves of it.
    //
    // Starling sent the `Reject` and left the socket open. murmur sends it and
    // calls `disconnectSocket()` immediately (`Messages.cpp:568`). What the
    // difference looked like to a user: "Server connection rejected: Wrong
    // certificate or password", then a client still sitting there rendering
    // the root channel, still pinging, still switching to TCP when its UDP
    // probe failed thirty seconds later. A session that is half present,
    // no audio, no roster, nothing it can do, and no disconnect either.
    //
    // The idle sweep never rescued it: a connection that keeps pinging is
    // never timed out, so the refused peer held its slot for as long as it
    // felt like.
    let data_dir = TempDir::new("refused-login");
    let deployment = Deployment::start(data_dir.path()).await;

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

    // SuperUser is registered on every deployment and has a password, so
    // getting it wrong is a refusal that needs no set-up to arrange, and it
    // is exactly the refusal in the report.
    client
        .send(
            2,
            &tcp::Authenticate {
                username: Some("SuperUser".to_owned()),
                password: Some("not-the-password".to_owned()),
                ..tcp::Authenticate::default()
            },
        )
        .await;

    let (_, payload) = client.recv_until(4).await;
    let refusal = tcp::Reject::decode(payload.as_slice()).expect("a well-formed Reject");
    assert_eq!(
        refusal.r#type,
        Some(tcp::reject::RejectType::WrongUserPw as i32),
        "the client renders this as the reason; a generic refusal sends the user hunting"
    );

    // The half that was missing. Generous, because it must not be a race:
    // the gateway flushes the queued `Reject` before closing, and this is
    // asserting the close still arrives promptly afterwards.
    assert!(
        client.closed_by_server(Duration::from_secs(5)).await,
        "the server refused the login and left the connection open; the client stays half \
         connected, keeps pinging, and is never reaped"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_self_muted_speaker_stops_being_relayed() {
    // Mute has to reach the *packet path*, not just the user list. A server that
    // renders alice as muted while still forwarding her audio is the worst
    // version of this bug: every client's UI says she is not being heard.
    //
    // Driven end to end because the enforcement and the fact are three services
    // apart, session-lifecycle records the flag, session-view publishes it, and
    // voice reads it off a subscription, and each of the three can be right on
    // its own while the chain does nothing.
    let data_dir = TempDir::new("self-mute");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    // Audible first, or a silent second half proves nothing: a test that only
    // checks bob hears nothing after the mute passes on a server that never
    // routed anything at all.
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let heard_before = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"before"))
            .await;
        if bob.next_audio(AUDIO_ATTEMPT).await.is_some() {
            break true;
        }
        if tokio::time::Instant::now() >= deadline {
            break false;
        }
    };
    assert!(
        heard_before,
        "bob never heard alice, so the mute proves nothing"
    );

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                self_mute: Some(true),
                ..tcp::UserState::default()
            },
        )
        .await;
    // The echo every client is sent, which is also the point the server has
    // finished applying it. Waiting on a timer instead would race the
    // announcement to session-view and voice's subscription behind it.
    let muted = bob
        .next_state_of(alice_session, |state| state.self_mute)
        .await;
    assert_eq!(muted.self_mute, Some(true));

    // Anything still in flight lands, then a clean window.
    let _ = bob.next_audio(AUDIO_ATTEMPT).await;
    for _ in 0..10 {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"after"))
            .await;
    }
    assert!(
        bob.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "a self-muted speaker was still relayed; mute is in the user list and not on the packet path"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_whisper_reaches_the_person_it_names_and_not_the_room() {
    // `VoiceTarget`(19), which is what fills in one of the thirty slots Mumble's
    // five-bit target field addresses. Without it a client can register a
    // whisper, see no error, press the key, and reach nobody, the routing core
    // resolves slots correctly and no slot was ever filled.
    //
    // Bob is the control. He shares alice's channel, so nothing but the target
    // itself can keep him out of a frame she sends; carol is named personally,
    // so nothing but the target can carry one to her.
    let data_dir = TempDir::new("whisper");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;
    let mut carol = Client::connect(deployment.port).await;
    let carol_session = handshake(&mut carol, "carol").await;

    // Slot 3 means "carol", and nothing else. Whispering takes `Whisper` in the
    // target's channel, which the default ACL grants, so this is the ordinary
    // case rather than one propped up by an ACL the test installed.
    alice
        .send(
            19,
            &tcp::VoiceTarget {
                id: Some(3),
                targets: vec![tcp::voice_target::Target {
                    session: vec![carol_session],
                    ..tcp::voice_target::Target::default()
                }],
            },
        )
        .await;

    // Re-sent until it lands, as a real client transmitting fifty frames a
    // second effectively does: the registration and the first frame travel on
    // one connection but are handled by a service that awaits a permission check
    // between them, so *which* frame is the first routable one is a race and not
    // the behaviour under test.
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let received = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(3, b"only for carol"))
            .await;
        if let Some(payload) = carol.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };

    let payload = received.expect("carol never heard the whisper aimed at her");
    let audio = udp::Audio::decode(&payload[1..]).expect("a well-formed audio frame");
    assert_eq!(audio.opus_data, b"only for carol");
    assert_eq!(
        audio.header,
        Some(udp::audio::Header::Context(2)),
        "somebody named personally must be told it is a whisper, not a shout"
    );

    // The other half, and the one that matters for privacy: bob is in the same
    // channel and was not named, so a whisper that reached him would be a
    // private conversation leaking into the room it was aimed away from.
    assert!(
        bob.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "a whisper reached somebody it did not name"
    );

    deployment.stop().await;
}

/// Send a loopback frame until the server echoes it, and return what came back.
///
/// Also what binds this client's address server-side: an address is only
/// believed once a packet from it has authenticated, so until this succeeds the
/// server has no UDP path for this peer at all.
/// One loopback attempt, tolerating a reply this client cannot open.
///
/// The fallible half of [`loop_back`], for the one caller that is *asserting*
/// the client has gone deaf. `loop_back` panics on a reply it cannot decrypt,
/// which is right for every other use and useless for proving a cipher is out
/// of step.
///
/// Deliberately short: a negative assertion should not cost fifteen seconds, and
/// a client whose nonce has drifted fails on the first packet, not the
/// fiftieth.
async fn try_loop_back(
    socket: &UdpSocket,
    voice: SocketAddr,
    cipher: &mut Ocb2,
) -> Option<Vec<u8>> {
    let mut scratch = [0_u8; 2048];
    let sealed = cipher
        .seal(&audio_frame(SERVER_LOOPBACK, b"probe"), &[])
        .expect("the client seals its own audio");
    let _ = socket.send_to(&sealed, voice).await;

    let (read, _) = timeout(AUDIO_ATTEMPT, socket.recv_from(&mut scratch))
        .await
        .ok()?
        .ok()?;
    let plain = cipher.open(&scratch[..read], &[]).ok()?;
    Some(heard(&plain).1)
}

async fn loop_back(socket: &UdpSocket, voice: SocketAddr, cipher: &mut Ocb2) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let mut scratch = [0_u8; 2048];
    loop {
        let sealed = cipher
            .seal(&audio_frame(SERVER_LOOPBACK, b"probe"), &[])
            .expect("the client seals its own audio");
        let _ = socket.send_to(&sealed, voice).await;

        if let Ok(Ok((read, _))) = timeout(AUDIO_ATTEMPT, socket.recv_from(&mut scratch)).await {
            let plain = cipher
                .open(&scratch[..read], &[])
                .expect("the echo is sealed under this session's key");
            return heard(&plain).1;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "voice never answered on its UDP port"
        );
    }
}

#[tokio::test]
async fn a_client_can_switch_channels_and_everyone_is_told() {
    // Reported as "I can't switch channels". The request is a `UserState`
    // carrying `channel_id`, and nothing read that field, so the server parsed
    // it, ignored it, and replied with the self-mute echo, which looks like a
    // successful answer and moves nobody.
    //
    // Asserted from *both* clients on purpose: a client builds its user tree
    // from these broadcasts, so a move only the mover hears about leaves the
    // same person rendered in two channels everywhere else.
    let data_dir = TempDir::new("switch");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Testing").await;
    assert_ne!(target, 0, "the new channel must not be the root");

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;

    // Both are told, and both are told the same thing.
    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let moved = timeout(FRAME_TIMEOUT, client.next_channel_of(alice_session)).await;
        assert_eq!(
            moved.ok(),
            Some(target),
            "{who} was never told alice moved to {target}"
        );
    }

    deployment.stop().await;
}

#[tokio::test]
async fn an_operator_can_moderate_a_live_session_from_outside() {
    // murmur's `setState`, which Starling had no equivalent of at all: every
    // moderation path went through a Mumble client holding a connection, so an
    // external bot could watch somebody misbehave and do nothing about them.
    //
    // Driven over gRPC and asserted on the *socket*, because the two halves fail
    // separately, a change that lands in the connection table and is never
    // broadcast leaves every other client rendering the old state, which is the
    // same class of bug as the missing `actor` above.
    use starling_proto_fancy::sessioncontrol::SetStateRequest;
    use starling_proto_fancy::sessioncontrol::session_control_client::SessionControlClient;

    let data_dir = TempDir::new("operator-moderation");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Naughty Step").await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    let transport = deployment
        .resolver
        .channel("session-lifecycle")
        .expect("session-lifecycle resolves");
    let applied = SessionControlClient::new(transport)
        .set_state(SetStateRequest {
            scope: None,
            actor: None,
            session: alice_session,
            channel: Some(target),
            // Deafen without muting, to prove the coupling is applied on this
            // path too: murmur's deafen implies mute, and an operator told only
            // what they asked for would render a user deaf but not muted.
            deaf: Some(true),
            ..SetStateRequest::default()
        })
        .await
        .expect("the operator plane answers")
        .into_inner();

    assert!(applied.applied, "refused: {}", applied.refused);
    assert_eq!(applied.channel, target, "the move was not applied");
    assert!(applied.deaf, "the deafen was not applied");
    assert!(
        applied.mute,
        "deafening must imply muting, as it does in murmur"
    );

    // And everyone is told, the mover included. Asserted from bob as well
    // because a client builds its user list from these: a moderation action only
    // the subject hears about leaves everybody else rendering them unmuted and
    // in the wrong channel.
    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let moved = timeout(FRAME_TIMEOUT, client.next_move_of(alice_session))
            .await
            .unwrap_or_else(|_| panic!("{who} was never told alice was moved"));
        assert_eq!(
            moved.channel_id,
            Some(target),
            "{who} saw the wrong channel"
        );
        assert_eq!(moved.deaf, Some(true), "{who} was not told alice is deaf");
    }

    deployment.stop().await;
}

#[tokio::test]
async fn a_move_names_who_made_it_and_not_the_server() {
    // Reported as the client logging "You were moved to X by the server." for an
    // ordinary channel click, where murmur produces "You joined X."
    //
    // The difference is one field. `actor` names who caused the change, murmur
    // sets it on every `UserState` it rebroadcasts
    // (`vendor/server/src/murmur/Messages.cpp:1052`), and Starling set it on
    // none, so a client had nobody to attribute the move to and fell back to
    // blaming the server. Every voluntary move then read as an administrator
    // dragging the user around, which is alarming rather than merely wrong.
    let data_dir = TempDir::new("attribution");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Beginner Lobby").await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;

    // Asserted from both clients: alice needs the attribution to know she moved
    // herself, and bob needs it to render who moved whom. A server that set it
    // only in the echo to the mover would leave everyone else with the same
    // "by the server" line about somebody who walked in on their own.
    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let moved = timeout(FRAME_TIMEOUT, client.next_move_of(alice_session))
            .await
            .unwrap_or_else(|_| panic!("{who} was never told alice moved"));
        assert_eq!(
            moved.channel_id,
            Some(target),
            "{who} saw the wrong channel"
        );
        assert_eq!(
            moved.actor,
            Some(alice_session),
            "{who} was not told who moved alice, and an unset actor reads as the server"
        );
    }

    deployment.stop().await;
}

/// An ACL entry addressing `group`, applying here and to everything below.
fn entry(
    group: &str,
    grant: starling_proto_fancy::perm::Perm,
    deny: starling_proto_fancy::perm::Perm,
) -> starling_proto_fancy::permissions::AclEntry {
    starling_proto_fancy::permissions::AclEntry {
        apply_here: true,
        apply_subs: true,
        group: Some(group.to_owned()),
        grant: grant.bits(),
        deny: deny.bits(),
        ..starling_proto_fancy::permissions::AclEntry::default()
    }
}

#[tokio::test]
async fn a_client_holding_write_can_save_an_acl_table_and_read_it_back() {
    // `docs/GAP-ANALYSIS.md` G1, end to end and from outside. The ACL editor in
    // every Mumble client is built on this one message: `ACL`(13) with `query`
    // unset is a save. Starling refused every one of them for everybody,
    // including the SuperUser, and said nothing, so a role was created in the
    // editor, appeared to stick, and was gone on the next read.
    //
    // Asserted through a *second* read rather than only through the reply,
    // because the reply is generated on the write path: a handler that echoed
    // its input without storing it would satisfy the first assertion and fail
    // the users of this feature in exactly the way it already had.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("acl-write");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Moderated").await;

    // What an operator does once so the editor is usable at all. Reading an ACL
    // takes `Write` too, so without this the client cannot even open the dialog.
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("all", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;

    let submitted = tcp::Acl {
        channel_id: target,
        inherit_acls: Some(true),
        query: Some(false),
        groups: vec![tcp::acl::ChanGroup {
            name: "moderators".to_owned(),
            add: vec![4],
            ..tcp::acl::ChanGroup::default()
        }],
        acls: vec![tcp::acl::ChanAcl {
            apply_here: Some(true),
            apply_subs: Some(true),
            group: Some("moderators".to_owned()),
            grant: Some(Perm::MUTE_DEAFEN.bits()),
            ..tcp::acl::ChanAcl::default()
        }],
    };
    alice.send(13, &submitted).await;

    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(13))
        .await
        .expect("the save was never answered");
    let saved = tcp::Acl::decode(payload.as_slice()).expect("a well-formed ACL");
    assert_eq!(saved.channel_id, target);
    assert_eq!(saved.acls.len(), 1, "the entry was not kept: {saved:?}");
    assert_eq!(saved.acls[0].grant, Some(Perm::MUTE_DEAFEN.bits()));
    assert_eq!(saved.groups.len(), 1);
    assert_eq!(saved.groups[0].name, "moderators");

    // The read the editor performs when it is next opened. This is the one that
    // used to come back empty.
    alice
        .send(
            13,
            &tcp::Acl {
                channel_id: target,
                query: Some(true),
                ..tcp::Acl::default()
            },
        )
        .await;
    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(13))
        .await
        .expect("the read was never answered");
    let reread = tcp::Acl::decode(payload.as_slice()).expect("a well-formed ACL");
    assert_eq!(
        reread.acls.len(),
        1,
        "the saved table did not survive to the next read: {reread:?}"
    );
    assert_eq!(reread.groups[0].add, vec![4]);

    deployment.stop().await;
}

#[tokio::test]
async fn an_acl_reply_carries_the_names_of_the_accounts_it_mentions() {
    // What the classic client's ACL editor has no other way to learn. It seeds
    // its name cache from the users that are *connected* and never asks about
    // an id, so an offline group member rendered as `#27`: a members list of
    // numbers, unreadable and uneditable. Murmur sends an unsolicited
    // `QueryUsers`(14) after every `ACL`(13) reply; Starling sent only the ACL.
    //
    // Both halves of the table are asserted, group membership and an ACL row,
    // because they are gathered from different fields and one without the other
    // leaves the same symptom on the other tab.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::{AclEntry, AclSet, Group};

    let data_dir = TempDir::new("acl-names");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Moderated").await;

    // Registered and never connected, which is the case that was broken.
    let zewi = register_with_password(&deployment, "zewi", "hunter2").await;
    let sebi = register_with_password(&deployment, "sebi", "hunter2").await;

    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("all", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;
    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![AclEntry {
                apply_here: true,
                account: Some(sebi),
                grant: Perm::MUTE_DEAFEN.bits(),
                ..AclEntry::default()
            }],
            groups: vec![Group {
                name: "salz".to_owned(),
                add: vec![zewi],
                ..Group::default()
            }],
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;
    alice
        .send(
            13,
            &tcp::Acl {
                channel_id: target,
                query: Some(true),
                ..tcp::Acl::default()
            },
        )
        .await;

    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(13))
        .await
        .expect("the read was never answered");
    let table = tcp::Acl::decode(payload.as_slice()).expect("a well-formed ACL");
    assert_eq!(table.groups[0].add, vec![zewi as u32]);

    // After the ACL, never before it: the editor that absorbs these names is
    // constructed from the ACL frame, and a `QueryUsers` that arrives first is
    // handed to a dialog that does not exist yet.
    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(14))
        .await
        .expect("the ACL reply carried no names");
    let names = tcp::QueryUsers::decode(payload.as_slice()).expect("a well-formed QueryUsers");
    let resolved: Vec<(u32, &str)> = names
        .ids
        .iter()
        .zip(names.names.iter())
        .map(|(id, name)| (*id, name.as_str()))
        .collect();
    assert!(
        resolved.contains(&(zewi as u32, "zewi")),
        "the group member was left unnamed: {resolved:?}"
    );
    assert!(
        resolved.contains(&(sebi as u32, "sebi")),
        "the account named by an ACL row was left unnamed: {resolved:?}"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_channel_password_admits_whoever_presents_it_and_nobody_else() {
    // G2 and G3 together, which is how a user meets them: a channel password is
    // an `Enter` denied to `all` and granted back to `#token`, and it needs the
    // grammar to parse `#hunter2` as a token *and* the token itself to reach the
    // evaluator. Either half missing leaves the same symptom, a channel nobody
    // can enter, including the people who were given the password.
    //
    // Both ways a client can present one are covered, because they are different
    // paths: stored and sent at login, and typed into the dialog and sent with
    // the request it authorises.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("acl-token");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Private").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                // Deny first and grant second is not the reason this works,
                // deny wins at the same level regardless of order. What admits
                // the holder is that the second entry does not match anybody
                // else at all.
                entry("#hunter2", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session =
        handshake_with_tokens(&mut alice, "alice", vec!["hunter2".to_owned()]).await;
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;
    let admitted = timeout(FRAME_TIMEOUT, alice.next_entry_answer(alice_session))
        .await
        .expect("alice was never answered");
    assert_eq!(
        admitted,
        Ok(target),
        "the token presented at login must open the channel"
    );

    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    bob.send(
        9,
        &tcp::UserState {
            session: Some(bob_session),
            channel_id: Some(target),
            ..tcp::UserState::default()
        },
    )
    .await;
    let refusal = timeout(FRAME_TIMEOUT, bob.next_entry_answer(bob_session))
        .await
        .expect("bob was never answered");
    let refusal = refusal.expect_err("a channel with no token must not admit bob");
    assert_eq!(refusal.channel_id, Some(target));
    assert_eq!(refusal.permission, Some(Perm::ENTER.bits()));

    // Now bob types the password into the dialog. The client sends it *with*
    // the request rather than storing it, and it must authorise this entry and
    // leave nothing behind.
    bob.send(
        9,
        &tcp::UserState {
            session: Some(bob_session),
            channel_id: Some(target),
            temporary_access_tokens: vec!["HUNTER2".to_owned()],
            ..tcp::UserState::default()
        },
    )
    .await;
    let admitted = timeout(FRAME_TIMEOUT, bob.next_entry_answer(bob_session))
        .await
        .expect("bob was never answered the second time");
    assert_eq!(
        admitted,
        Ok(target),
        "a token sent with the request must open the channel, in any case"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_second_authenticate_replaces_the_access_tokens_without_a_second_login() {
    // How a stock Mumble client actually submits a password it has just been
    // given: it re-sends `Authenticate` on the same connection with its whole
    // token list (`vendor/server/src/murmur/Messages.cpp:367`). Starling read
    // that as a fresh login, which would allocate a second session for one
    // connection and announce the same user twice.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("acl-retoken");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("Private").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("#hunter2", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;

    alice
        .send(
            2,
            &tcp::Authenticate {
                username: Some("alice".to_owned()),
                tokens: vec!["hunter2".to_owned()],
                ..tcp::Authenticate::default()
            },
        )
        .await;

    // The edit is acknowledged with a fresh `PermissionQuery`, which is also
    // what tells the client its menus have changed.
    let (_, _) = timeout(FRAME_TIMEOUT, alice.recv_until(20))
        .await
        .expect("the token edit was never acknowledged");

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;
    let admitted = timeout(FRAME_TIMEOUT, alice.next_entry_answer(alice_session))
        .await
        .expect("alice was never answered");
    assert_eq!(
        admitted,
        Ok(target),
        "a token added mid-session must take effect"
    );

    // And she is still one user. A second `Authenticate` read as a login would
    // have allocated another session and announced her again.
    assert_eq!(
        deployment
            .records()
            .iter()
            .filter(|event| event.message == "user authenticated")
            .count(),
        1,
        "a token edit must not log in a second time"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn an_external_authority_can_admit_a_guest_to_a_group_gated_channel() {
    // Temporary group membership, end to end, and the case it exists for.
    //
    // A channel gated on a named group is shut to every unregistered visitor
    // and cannot be opened to one by editing the ACL table: membership is
    // recorded by *account* id, and a guest has no account, they go on the
    // wire as account 0, which is the SuperUser's. A session-scoped grant is
    // the only mechanism upstream has for it (`Group.cpp:242`, reading
    // `qsTemporary` for `-session`), and it is what an external authenticator
    // uses to map something the server cannot know (a game lobby, a rota)
    // onto somebody who never registered.
    //
    // Asserted from outside because every part of this is wiring: the grant is
    // made over gRPC, the subject is resolved through `session-view`, and the
    // answer comes back as a `UserState` or a `PermissionDenied` on a socket.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("temp-groups");
    let deployment = Deployment::start(data_dir.path()).await;
    let target = deployment.create_channel("VIP").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("vip", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;

    // Shut, as it is to everybody, before the grant.
    let refusal = alice
        .enter(alice_session, target, "alice was never answered")
        .await
        .expect_err("a channel gated on a group must not admit a guest");
    assert_eq!(refusal.permission, Some(Perm::ENTER.bits()));

    deployment
        .add_temporary_group(target, "vip", alice_session)
        .await;

    let admitted = alice
        .enter(
            alice_session,
            target,
            "alice was never answered after the grant",
        )
        .await;
    assert_eq!(
        admitted,
        Ok(target),
        "a session-scoped grant must admit an unregistered user"
    );

    // Revoked, and the door shuts again. Asserted here rather than in its own
    // test because it needs a subject already inside the group, and because a
    // grant that cannot be taken back is the more dangerous half of the pair.
    assert!(
        deployment
            .temporary_group(target, "vip", alice_session, false)
            .await
            .applied
    );
    let _ = alice
        .enter(alice_session, 0, "alice was never moved back to the root")
        .await;
    let after_revoke = alice
        .enter(
            alice_session,
            target,
            "alice was never answered after the revocation",
        )
        .await;
    assert!(
        after_revoke.is_err(),
        "a revoked membership must stop admitting"
    );

    // And it belongs to that session alone. Bob is the same kind of visitor and
    // was granted nothing.
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;
    let refusal = bob
        .enter(bob_session, target, "bob was never answered")
        .await
        .expect_err("the grant must not admit anybody else");
    assert_eq!(refusal.channel_id, Some(target));

    deployment.stop().await;
}

#[tokio::test]
async fn a_session_scoped_grant_does_not_pass_to_the_next_holder_of_that_session() {
    // The hazard that makes clearing this on disconnect a requirement rather
    // than tidiness: session ids are pooled and reissued, murmur re-queues
    // them at `Server.cpp:1904` and Starling's allocator does the same, so a
    // grant that outlived its holder would silently admit whoever is handed
    // that id next.
    //
    // Driven by connecting, granting, disconnecting, and connecting again until
    // the same id comes back round, because asserting on the id directly is the
    // only way to know the reuse actually happened.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("temp-groups-reuse");
    // A pool of exactly one id, so the reuse this is about happens on the very
    // next connection instead of after two hundred. The pool is `max_users * 2`
    // and FIFO, sized and ordered to *delay* reuse, which is the right default
    // and the reason a test cannot wait for it.
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        if let Some(service) = config.services.get_mut("session-lifecycle") {
            let _ = service
                .options
                .insert("max_users".to_owned(), "1".to_owned());
        }
    })
    .await;
    let target = deployment.create_channel("VIP").await;

    deployment
        .set_acl(AclSet {
            channel: target,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("vip", Perm::ENTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let granted_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(target, "vip", granted_session)
        .await;
    alice.close().await;

    // Granting to an id that has already gone is refused, which is murmur's
    // rule (`InvalidSessionException`, and the reason this test exists at all):
    // a departure is what clears these grants, so one made *after* the
    // departure has missed its only cleanup and would wait in the table for
    // whoever is issued that id next.
    let refused = deployment
        .temporary_group(target, "vip", granted_session, true)
        .await;
    assert!(
        !refused.applied,
        "a grant naming a departed session must be refused, not recorded"
    );

    let mut mallory = Client::connect(deployment.port).await;
    let reissued = handshake(&mut mallory, "mallory").await;
    assert_eq!(
        reissued, granted_session,
        "the pool was meant to hand the same id straight back, so nothing is being proven"
    );

    mallory
        .send(
            9,
            &tcp::UserState {
                session: Some(granted_session),
                channel_id: Some(target),
                ..tcp::UserState::default()
            },
        )
        .await;
    let answer = timeout(FRAME_TIMEOUT, mallory.next_entry_answer(granted_session))
        .await
        .expect("mallory was never answered");
    assert!(
        answer.is_err(),
        "the new holder of session {granted_session} inherited a stranger's group membership"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn the_same_name_twice_replaces_the_first_rather_than_joining_it() {
    // Reported from a live deployment: the same user connected three times and
    // the server held three sessions, so every client rendered three copies of
    // one person. murmur never allows that (`Messages.cpp:418`), the second
    // connection is the same user coming back from the same address, so it is
    // admitted and the first is disconnected as a ghost.
    let data_dir = TempDir::new("dupe");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut first = Client::connect(deployment.port).await;
    let first_session = handshake(&mut first, "alice").await;

    let mut second = Client::connect(deployment.port).await;
    let second_session = handshake(&mut second, "alice").await;
    assert_ne!(first_session, second_session);

    // The ghost is disconnected, which is what was not happening: the older
    // connection has to actually end, not merely be forgotten.
    let ended = timeout(FRAME_TIMEOUT, async {
        loop {
            if deployment.records().iter().any(|event| {
                event.message == "user left"
                    && event.field("session") == Some(&FieldValue::Uint(first_session.into()))
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the first session must be disconnected when the same user reconnects"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn the_ghost_is_told_why_its_connection_ended() {
    // The other half of the eviction above, and the half the user actually
    // sees. The ghost is gone from the registry before the ordinary disconnect
    // path builds its `UserRemove`, so it was the one peer never told anything:
    // its socket simply closed, which is what a flaky network looks like too.
    // The client reported a lost link and, with auto-reconnect on, dialled
    // back in - evicting the device the user had just moved to, which evicted
    // this one, indefinitely. A `UserRemove` naming the ghost's own session is
    // how every Mumble client is told "you were kicked, and here is why".
    let data_dir = TempDir::new("ghost-reason");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut first = Client::connect(deployment.port).await;
    let first_session = handshake(&mut first, "alice").await;

    let mut second = Client::connect(deployment.port).await;
    let second_session = handshake(&mut second, "alice").await;
    assert_ne!(first_session, second_session);

    let removal = timeout(
        FRAME_TIMEOUT,
        first.next_removal_of(first_session, FRAME_TIMEOUT),
    )
    .await
    .expect("the ghost was still waiting when the test gave up");
    let removal = removal.expect("the ghost was hung up on without being told why");
    let reason = removal.reason.unwrap_or_default();
    assert!(
        reason.contains("another device"),
        "the ghost has to be told it was replaced, not left to guess; got {reason:?}"
    );

    // And then the socket actually goes: the frame explains the disconnect, it
    // does not replace it.
    assert!(
        first.closed_by_server(FRAME_TIMEOUT).await,
        "the ghost's connection must still end after it is told why"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_login_and_a_refusal_both_reach_the_operator_log() {
    // The whole point of the operator log: reading it afterwards answers who
    // connected and who was turned away. Asserted end to end, because every
    // piece of this, the config section, the runtime, the logger on the
    // context, the call in the handshake, can be present and still not
    // produce a record if one of them is not wired to the next.
    let data_dir = TempDir::new("operator-log");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let session = handshake(&mut alice, "alice").await;

    let records = deployment.records();
    let login = records
        .iter()
        .find(|event| event.message == "user authenticated")
        .expect("a completed handshake must be recorded");
    assert_eq!(login.category, Category::Session);
    assert_eq!(
        login.field("name"),
        Some(&FieldValue::Text("alice".to_owned()))
    );
    assert_eq!(
        login.field("session"),
        Some(&FieldValue::Uint(session.into()))
    );

    assert!(
        records
            .iter()
            .any(|event| event.message == "client connected"),
        "the gateway must record the connection itself, before any handshake"
    );

    // An empty username, which userdata refuses as `InvalidName`. The client
    // is sent a `Reject`; this asserts the server also keeps its own reason,
    // which the client is never told in that detail.
    let mut nobody = Client::connect(deployment.port).await;
    let _ = nobody.recv().await; // the server's unprompted Version
    nobody
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                ..tcp::Version::default()
            },
        )
        .await;
    nobody
        .send(
            2,
            &tcp::Authenticate {
                username: Some(String::new()),
                ..tcp::Authenticate::default()
            },
        )
        .await;
    let refused = timeout(FRAME_TIMEOUT, async {
        loop {
            if deployment
                .records()
                .iter()
                .any(|event| event.message == "login refused")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(refused.is_ok(), "a refused login must be recorded");

    deployment.stop().await;
}

#[cfg(test)]
mod example_config {
    use starling_runtime::config::Config;

    fn shipped(name: &str) -> Config {
        // `deny_unknown_fields` means a stale file is a startup failure for
        // whoever copies it, and they find out at deploy time.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(name);
        let config =
            Config::load(&path).unwrap_or_else(|error| panic!("{name} must load: {error}"));
        config
            .validate()
            .unwrap_or_else(|error| panic!("{name} must be a valid routing table: {error}"));
        config
    }

    #[test]
    fn the_shipped_example_configuration_loads() {
        let _ = shipped("starling.example.toml");
    }

    #[test]
    fn a_shipped_file_routes_every_type_where_the_defaults_do() {
        // The routing table exists twice, once as the built-in defaults, once
        // per shipped file, and nothing made them agree. They drifted, and the
        // drift was invisible: `UserState` and `UserStats` were moved to
        // session-lifecycle in code, both files went on naming userdata, and so
        // the fix worked under `--all-in-one` and did nothing whatsoever in the
        // Docker deployment, where a file is what is actually loaded.
        //
        // Compared by *type*, not by whole service block, because a file
        // is entitled to differ on endpoints, tiers and limits. Where a client's
        // frame is delivered is not that kind of choice.
        let defaults = Config::with_defaults(std::path::Path::new("/run/starling"));
        for name in ["starling.example.toml", "deploy/starling.toml"] {
            let shipped = shipped(name);
            for service in defaults.services.values() {
                for type_id in &service.types {
                    let expected = defaults.route(*type_id).map(|(service, _)| service);
                    let actual = shipped.route(*type_id).map(|(service, _)| service);
                    assert_eq!(
                        actual, expected,
                        "{name} routes type {type_id} to {actual:?}, the defaults to {expected:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_shipped_file_charges_every_service_to_the_bucket_the_defaults_do() {
        // The same drift as the test above, on the axis that silences people
        // rather than misrouting them. Voice was charged to `control`,
        // murmur's 1 message per second, and tunnelled audio is a hundred
        // frames a second, so a client behind a UDP-blocking firewall was cut
        // off after its first few frames with no error anywhere.
        //
        // A bucket named in a service block but missing from `[gateway.limits]`
        // is not an error either: the limiter allows what it has no bucket for,
        // so the mistake shows up as *no* limit rather than as a failure.
        let defaults = Config::with_defaults(std::path::Path::new("/run/starling"));
        for name in ["starling.example.toml", "deploy/starling.toml"] {
            let shipped = shipped(name);
            for (service, expected) in &defaults.services {
                let actual = shipped
                    .services
                    .get(service)
                    .and_then(|service| service.limits.as_deref());
                assert_eq!(
                    actual,
                    expected.limits.as_deref(),
                    "{name} charges {service} to {actual:?}, the defaults to {:?}",
                    expected.limits
                );
                if let Some(bucket) = actual {
                    assert!(
                        shipped.gateway.limits.contains_key(bucket),
                        "{name} charges {service} to a bucket \"{bucket}\" it never defines, \
                         so that traffic is not limited at all"
                    );
                }
            }
        }
    }

    #[test]
    fn the_compose_configuration_loads_and_is_reachable_over_tcp() {
        // docker-compose.yml puts every service in its own container, so the
        // Unix sockets the example ships are unreachable there. A `unix:`
        // endpoint surviving into this file would bind a socket inside one
        // container that no other container can dial, a stack that comes up
        // healthy and answers nothing.
        let config = shipped("deploy/starling.toml");
        for (name, service) in &config.services {
            let Some(endpoint) = service.endpoint.as_deref() else {
                // `directory` is the one service nothing dials: it has no gRPC
                // surface, so an endpoint would be a socket with no purpose.
                // Any *other* service without one is a container the rest of
                // the stack cannot reach.
                assert_eq!(
                    name, "directory",
                    "{name} has no endpoint, so nothing can reach it"
                );
                continue;
            };
            assert!(
                endpoint.starts_with("http://"),
                "{name} is at {endpoint}, which no other container can reach"
            );
        }
        assert!(
            !config.runtime.all_in_one,
            "the file is the multi-container deployment; --all-in-one is a flag, not a second file"
        );
    }

    #[test]
    fn the_all_in_one_profile_overrides_every_endpoint_it_would_otherwise_bind() {
        // `--all-in-one` is a flag rather than a second file, and that is only
        // half of what the single-box deployment needs. `endpoint` is what a
        // service *binds*, in every mode - a service resolves its own address
        // before it has registered with the broker, so the in-process
        // short-circuit cannot apply to its own listener - and the file above
        // points every service at a container name. Run one process with it and
        // all twenty-one die on "failed to lookup address information", the
        // gateway included, because those containers are exactly what this
        // profile replaces.
        //
        // So the profile overrides each endpoint to `inproc:`. This test exists
        // because that block is a list nobody would think to extend: adding a
        // service to the routing table would leave the single-box deployment
        // broken in a way only a full `up --wait` shows.
        let compose = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("docker-compose.yml"),
        )
        .expect("docker-compose.yml must be readable");

        let config = shipped("deploy/starling.toml");
        for (name, service) in &config.services {
            if service.endpoint.is_none() {
                continue;
            }
            let expected = format!(
                "STARLING_SERVICES_{}_ENDPOINT: inproc:{name}",
                name.replace('-', "_").to_uppercase()
            );
            assert!(
                compose.contains(&expected),
                "the all-in-one profile never overrides {name}, so it would try to bind \
                 {:?} - a container that profile does not start. Add:\n      {expected}",
                service.endpoint.as_deref().unwrap_or_default()
            );
        }
    }
}

// ── The live channel ────────────────────────────────────────────────────────
//
// Every test below runs on a **multi-threaded** runtime, and that is load
// bearing, not tidiness.
//
// `#[tokio::test]` gives a current-thread runtime, and these tests start a whole
// deployment (twenty-one services plus the gateway) on it. A real Starling
// process runs multi-threaded, so a single-threaded one is not a smaller
// deployment, it is a different one.
//
// It bites here in particular because the event bridges are background tasks
// nothing else awaits. On one thread they are scheduled only when everything
// else yields, and during a cold start they lose that race often enough to be
// flaky, the subscriber attaches, no bridge has run, and a task that never
// executed writes no log. The symptom is silence, which is exactly why it first
// read as a transport fault.

/// The token the live-channel tests authenticate with.
///
/// Named, not inlined, because the configuration holds the *variable's
/// name* and never the secret, so the test has to set the same variable the
/// deployment reads.
const LIVE_TOKEN_VAR: &str = "STARLING_E2E_LIVE_TOKEN";
const LIVE_TOKEN: &str = "e2e-live-channel-token";

/// A deployment with the admin plane switched on, and the port it listens on.
///
/// `operator-api` ships disabled, so a plain [`Deployment::start`] does not run
/// it, which is correct, and means a test that wants it has to configure it
/// the way an operator would.
#[expect(
    unsafe_code,
    reason = "edition 2024 has no safe way to set an environment variable, and               token auth deliberately names a variable rather than holding a               secret, so a test of it has to set one"
)]
async fn deployment_with_operator_api(data_dir: &Path) -> (Deployment, u16) {
    use starling_runtime::config::{
        AuthMode, OperatorAudit, OperatorAuth, ServiceConfig, StaticToken, TokenAuth,
    };

    // SAFETY: setting an environment variable is only unsound alongside a
    // concurrent read from another thread. These tests are serialised by
    // `ONE_AT_A_TIME`, and this runs before the deployment that reads it exists.
    unsafe { std::env::set_var(LIVE_TOKEN_VAR, LIVE_TOKEN) };

    let port = free_port();
    let data_dir_for_endpoint = data_dir.to_path_buf();
    let deployment = Deployment::start_with(data_dir, move |config| {
        // Inserted rather than adjusted: `operator-api` is not a `ServiceKind`
        // (it owns no wire type and the gateway never routes to it) so
        // `Config::with_defaults` creates no entry for it, and an absent entry
        // is exactly what `compose::enabled` reads as "off" for this one
        // service.
        let service = config
            .services
            .entry("operator-api".to_owned())
            .or_insert_with(|| {
                ServiceConfig::new(
                    // The deployment's own directory, never a fixed path: on
                    // Windows the local endpoint is a named pipe whose name is
                    // derived from it, so a hard-coded root would give every
                    // deployment in this process the same pipe, and the second
                    // one to start would find it busy.
                    &starling_runtime::transport::local_endpoint(
                        &data_dir_for_endpoint,
                        "operator-api",
                    ),
                    starling_runtime::tier::Tier::Optional,
                    &[],
                )
            });
        service.enabled = true;
        service.listen = Some(format!("127.0.0.1:{port}"));
        service.auth = Some(OperatorAuth {
            mode: AuthMode::Token,
            token: Some(TokenAuth {
                tokens: vec![StaticToken {
                    value_env: LIVE_TOKEN_VAR.to_owned(),
                    scopes: vec!["*".to_owned()],
                }],
            }),
            ..OperatorAuth::default()
        });
        // The deployment's own directory, never the `/var/log/starling` default:
        // audit is fail-closed, so the very first operator action, of which
        // opening this channel is one, is refused with a 503 when the record
        // cannot be written, and a test must not depend on a writable system
        // path. Same reasoning as the endpoint above.
        service.audit = Some(OperatorAudit {
            path: data_dir_for_endpoint.join("operator-audit.log"),
            fail_closed: true,
            ..OperatorAudit::default()
        });
    })
    .await;

    (deployment, port)
}

/// The live channel's socket type, spelled once.
type LiveSocket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

/// Open the live channel, presenting the bearer token.
async fn open_live_channel(port: u16) -> LiveSocket {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    // Retried because the API's listener is spawned alongside the rest of the
    // deployment: the port can be a moment behind everything else being up.
    let deadline = std::time::Instant::now() + FRAME_TIMEOUT;
    loop {
        let mut request = format!("ws://127.0.0.1:{port}/v1/events")
            .into_client_request()
            .expect("a valid websocket URL");
        let _ = request.headers_mut().insert(
            "authorization",
            format!("Bearer {LIVE_TOKEN}")
                .parse()
                .expect("a valid header value"),
        );

        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => return socket,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the live channel never accepted a subscriber: {error}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Read events until one satisfies `wanted`.
///
/// Reads until it finds one, instead of inspecting only the next frame: the
/// channel carries everything that happens on the server, so a test asserting
/// on one event has to skip the others and cannot demand its own arrive
/// first.
async fn next_event(
    socket: &mut LiveSocket,
    wanted: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    next_event_within(socket, wanted, FRAME_TIMEOUT).await
}

/// Wait for the bridge's opening `started`.
///
/// Longer than [`FRAME_TIMEOUT`], because it is not waiting for a frame; it is
/// waiting for twenty services to finish coming up. `started` is sent to a
/// joining subscriber only once the state below the bridge is readable
/// (`operator-api/src/live.rs:86`), so a subscriber that attaches during
/// start-up waits for the deployment, not for the channel. On a loaded machine
/// that is well past ten seconds: the gateway is still logging "All pipe
/// instances are busy" retries at that point, and the test failed for a server
/// that was merely slow.
async fn started(socket: &mut LiveSocket) {
    let _ = next_event_within(socket, |event| is(event, "started"), LIVE_START_TIMEOUT).await;
}

/// [`next_event`], with the caller choosing how long to wait.
async fn next_event_within(
    socket: &mut LiveSocket,
    wanted: impl Fn(&serde_json::Value) -> bool,
    within: Duration,
) -> serde_json::Value {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let deadline = tokio::time::Instant::now() + within;
    let mut seen: Vec<String> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let message = timeout(remaining, socket.next())
            .await
            .unwrap_or_else(|_| panic!("no matching event arrived; saw {seen:?}"))
            .expect("the live channel closed")
            .expect("a readable frame");

        if let Message::Text(text) = message {
            let event: serde_json::Value =
                serde_json::from_str(&text).expect("every frame on this channel is JSON");
            if wanted(&event) {
                return event;
            }
            seen.push(event["event"].as_str().unwrap_or("?").to_owned());
        }
    }
}

/// Whether an event is of the named kind.
fn is(event: &serde_json::Value, kind: &str) -> bool {
    event["event"].as_str() == Some(kind)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_change_reaches_a_live_subscriber_as_the_right_kind_of_event() {
    // The whole path in one test: `metadata` publishes a tree change, the
    // bridge turns it into an event, and a real WebSocket client is handed it.
    // Every unit test around this can pass while the wiring between them does
    // not, which is the gap this closes.
    let data_dir = TempDir::new("live-channel");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    let mut socket = open_live_channel(port).await;

    // The bridge announces itself once the state below it is readable.
    started(&mut socket).await;

    // Created over the same gRPC surface the REST route calls, so this asserts
    // the bridge observed a real change rather than one the test published into
    // the hub itself.
    use starling_proto_fancy::common::Scope;
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest, UpdateRequest};

    let grpc = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    let created = MetadataClient::new(grpc)
        .create(CreateRequest {
            scope: Some(Scope { instance: 1 }),
            actor: None,
            channel: Some(Channel {
                parent: Some(0),
                name: "Observed".to_owned(),
                ..Channel::default()
            }),
            temporary: false,
            invitee_user_ids: Vec::new(),
            reuse_existing: false,
        })
        .await
        .expect("the channel is created")
        .into_inner();
    assert!(created.applied, "refused: {}", created.refused);
    let id = created.channel.expect("a created channel").id;

    let event = next_event(&mut socket, |event| is(event, "channelCreated")).await;
    assert_eq!(event["channel"]["name"].as_str(), Some("Observed"));
    assert_eq!(
        event["channel"]["parent"].as_u64(),
        Some(0),
        "a channel under the root reports parent 0"
    );

    // And an edit arrives as a *change*, not a second creation. This is the
    // distinction the bridge exists to reconstruct: `metadata` publishes one
    // upsert for both, and a consumer cannot recover it from that alone.
    let grpc = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    let renamed = MetadataClient::new(grpc)
        .update(UpdateRequest {
            scope: Some(Scope { instance: 1 }),
            actor: None,
            channel: id,
            fields: vec!["name".to_owned()],
            values: Some(Channel {
                name: "Renamed".to_owned(),
                ..Channel::default()
            }),
        })
        .await
        .expect("the channel is renamed")
        .into_inner();
    assert!(renamed.applied, "refused: {}", renamed.refused);

    let event = next_event(&mut socket, |event| is(event, "channelStateChanged")).await;
    assert_eq!(event["channel"]["name"].as_str(), Some("Renamed"));
    assert_eq!(event["channel"]["id"].as_u64(), Some(u64::from(id)));

    deployment.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connecting_client_is_reported_to_a_live_subscriber() {
    // `session-view` publishes an upsert for an arrival and for a change alike.
    // This asserts the first one a session produces is reported as a connect.
    let data_dir = TempDir::new("live-users");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    let mut socket = open_live_channel(port).await;
    started(&mut socket).await;

    let mut client = Client::connect(deployment.port).await;
    let session = handshake(&mut client, "observed-user").await;

    let event = next_event(&mut socket, |event| is(event, "userConnected")).await;
    assert_eq!(event["user"]["name"].as_str(), Some("observed-user"));
    assert_eq!(event["user"]["session"].as_u64(), Some(u64::from(session)));
    // An unregistered guest carries no account. Account 0 is the SuperUser, so
    // a guest reported as 0 would read as the administrator.
    assert!(
        event["user"]["user_id"].is_null(),
        "an unregistered guest must not carry an account: {event}"
    );

    deployment.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_live_channel_answers_a_command_and_refuses_an_unknown_one() {
    // The channel is bidirectional, and a command that goes unanswered is
    // indistinguishable from one the server chose not to honour.
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let data_dir = TempDir::new("live-commands");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    let mut socket = open_live_channel(port).await;

    socket
        .send(Message::Text(r#"{"command":"ping"}"#.into()))
        .await
        .expect("the command is sent");
    let _ = next_event(&mut socket, |event| is(event, "pong")).await;

    socket
        .send(Message::Text(r#"{"command":"detonate"}"#.into()))
        .await
        .expect("the command is sent");
    let event = next_event(&mut socket, |event| is(event, "error")).await;
    assert!(
        event["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "a refusal must say why: {event}"
    );

    deployment.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_live_channel_refuses_a_subscriber_without_a_credential() {
    // The highest-privilege surface in the system. The refusal happens before
    // the upgrade, because a socket that opens and then closes is, to most
    // clients, indistinguishable from a network fault.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let data_dir = TempDir::new("live-unauthorised");
    let (deployment, port) = deployment_with_operator_api(data_dir.path()).await;
    // One authorised connection first, so a refusal below cannot be the
    // listener simply not being up yet.
    drop(open_live_channel(port).await);

    let request = format!("ws://127.0.0.1:{port}/v1/events")
        .into_client_request()
        .expect("a valid websocket URL");
    assert!(
        tokio_tungstenite::connect_async(request).await.is_err(),
        "the live channel accepted a subscriber with no credential"
    );

    deployment.stop().await;
}

// -- Meeting rooms: out-of-tree channels, the invitee flow, and deleting one

/// The `Channel.flags` bits `metadata` packs, for building a room to provision.
const FLAG_HIDDEN: u32 = 1;
const FLAG_DETACHED: u32 = 4;
/// `signal_v1`, the Signal sender-key group protocol a meeting room runs.
const PCHAT_SIGNAL_V1: u32 = 4;
/// A Fancy client build, i.e. one that understands an out-of-tree channel.
const FANCY_CLIENT: u64 = 1;
/// How long to wait before concluding a frame is *not* coming.
///
/// Short, and it has to be: this is asserting an absence, so every millisecond
/// of it is spent on every run. Everything that would produce the frame is
/// in-process and has already happened by the time it is called - the grant it
/// follows was acknowledged over gRPC - so a frame still in flight after this
/// is not a slow one, it is one the server decided not to send.
const NOT_COMING: Duration = Duration::from_millis(750);

/// Register an account that logs in with a password rather than a certificate.
///
/// The harness dials `with_no_client_auth`, so an account bound to a
/// certificate can never be *logged into* here: `authenticate` finds the record
/// by name, sees a certificate hash it cannot match, and refuses with
/// `NameTaken`. A password is the proof a test client can actually present, and
/// the invitee flow needs a live session that carries a real account.
async fn register_with_password(deployment: &Deployment, name: &str, password: &str) -> u64 {
    use starling_proto_fancy::userdata::user_data_client::UserDataClient;
    use starling_proto_fancy::userdata::{Account, RegisterRequest};

    let transport = deployment
        .resolver
        .channel("userdata")
        .expect("userdata is reachable");
    UserDataClient::new(transport)
        .register(RegisterRequest {
            scope: None,
            actor: None,
            account: Some(Account {
                name: name.to_owned(),
                ..Account::default()
            }),
            password: password.to_owned(),
        })
        .await
        .expect("the account is registered")
        .into_inner()
        .id
}

/// Log in as a registered account from a Fancy or a stock client.
async fn login(client: &mut Client, name: &str, password: &str, fancy: Option<u64>) -> u32 {
    handshake_as(
        client,
        tcp::Authenticate {
            username: Some(name.to_owned()),
            password: Some(password.to_owned()),
            ..tcp::Authenticate::default()
        },
        fancy,
    )
    .await
}

/// Provision a meeting room the way the calendar does.
///
/// One call: out of the tree, hidden, end-to-end encrypted, on an absolute
/// deadline, and private to `invitees`. `reuse_existing` is what makes it safe
/// to run twice, which the real caller does - a room is provisioned by
/// whichever of the meeting starting and somebody asking to join happens first.
async fn provision_room(
    deployment: &Deployment,
    name: &str,
    invitees: &[u64],
) -> starling_proto_fancy::metadata::ChannelResult {
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest};

    let transport = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    MetadataClient::new(transport)
        .create(CreateRequest {
            scope: None,
            actor: None,
            channel: Some(Channel {
                name: name.to_owned(),
                // Named and ignored, as murmur's own host callback passes the
                // root here: a detached channel is parentless whatever is sent.
                parent: Some(0),
                flags: FLAG_DETACHED | FLAG_HIDDEN,
                pchat_protocol: PCHAT_SIGNAL_V1,
                expiry_mode: 1,
                expiry_duration_s: 7 * 24 * 60 * 60,
                ..Channel::default()
            }),
            temporary: false,
            invitee_user_ids: invitees.iter().map(|id| *id as u32).collect(),
            reuse_existing: true,
        })
        .await
        .expect("the room is provisioned")
        .into_inner()
}

/// Admit or drop one account, over the surface a plugin would call.
async fn set_access(deployment: &Deployment, channel: u32, account: u64, admit: bool) {
    use starling_proto_fancy::metadata::AccessRequest;
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;

    let transport = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    let mut client = MetadataClient::new(transport);
    let request = AccessRequest {
        scope: None,
        actor: None,
        channel,
        account,
    };
    let result = if admit {
        client.grant_access(request).await
    } else {
        client.revoke_access(request).await
    };
    let result = result.expect("the access change is answered").into_inner();
    assert!(result.applied, "refused: {}", result.refused);
}

#[tokio::test]
async fn a_meeting_room_is_provisioned_out_of_tree_and_told_only_to_its_invitees() {
    // The server half of a scheduled meeting: the calendar asks for a room and
    // gets a parentless, hidden, end-to-end-encrypted channel that exists only
    // for the people invited to it.
    //
    // Three clients, because the room has to be withheld for two *different*
    // reasons and a test that checked one would pass while the other leaked:
    //
    //   * dave holds no invitation - the ACL keeps it from him;
    //   * carol holds one but runs a stock client - it is kept from her anyway,
    //     because a client that does not understand a parentless channel hangs
    //     it under the root, and then every meeting on the server is in her
    //     channel list (`vendor/server/src/murmur/ServerUser.h`).
    let data_dir = TempDir::new("meeting-room");
    let deployment = Deployment::start(data_dir.path()).await;
    let bob = register_with_password(&deployment, "bob", "hunter2").await;
    let carol = register_with_password(&deployment, "carol", "hunter3").await;

    let mut bob_client = Client::connect(deployment.port).await;
    let _ = login(&mut bob_client, "bob", "hunter2", Some(FANCY_CLIENT)).await;
    let mut carol_client = Client::connect(deployment.port).await;
    let _ = login(&mut carol_client, "carol", "hunter3", None).await;
    let mut dave = Client::connect(deployment.port).await;
    let _ = handshake_as(
        &mut dave,
        tcp::Authenticate {
            username: Some("dave".to_owned()),
            ..tcp::Authenticate::default()
        },
        Some(FANCY_CLIENT),
    )
    .await;

    let provisioned = provision_room(&deployment, "Standup [ab12cd34]", &[bob]).await;
    assert!(provisioned.applied, "refused: {}", provisioned.refused);
    assert!(provisioned.created, "the first call makes the room");
    let room = provisioned.channel.expect("a provisioned room");
    assert_eq!(room.parent, None, "a meeting room is out of the tree");

    let state = timeout(
        FRAME_TIMEOUT,
        bob_client.next_channel_state(room.id, FRAME_TIMEOUT),
    )
    .await
    .expect("bob was never told about the room he was invited to")
    .expect("bob was never told about the room he was invited to");
    assert_eq!(state.parent, None, "the room has no place in bob's tree");
    assert!(
        state
            .attributes
            .contains(&(tcp::ChannelAttribute::Detached as i32)),
        "without the attribute bob's client hangs it under the root"
    );
    assert_eq!(state.hidden, Some(true));
    assert_eq!(
        state.pchat_protocol,
        Some(tcp::PchatProtocol::SignalV1 as i32),
        "the only thing that puts the client into end-to-end mode"
    );
    assert!(
        state.expires_at.is_some(),
        "a room that self-destructs has to say when"
    );

    assert!(
        dave.next_channel_state(room.id, NOT_COMING).await.is_none(),
        "an uninvited client must not be told a private room exists"
    );

    // Carol is invited *now*, and still hears nothing: her client could not
    // render the room.
    set_access(&deployment, room.id, carol, true).await;
    assert!(
        carol_client
            .next_channel_state(room.id, NOT_COMING)
            .await
            .is_none(),
        "a stock client must never be sent an out-of-tree channel"
    );

    // Provisioning again finds the same room rather than minting a second one,
    // which is what lets the two triggers for a meeting both fire.
    let again = provision_room(&deployment, "Standup [ab12cd34]", &[bob]).await;
    assert!(again.applied && !again.created, "the second call reuses it");
    assert_eq!(again.channel.map(|c| c.id), Some(room.id));

    deployment.stop().await;
}

#[tokio::test]
async fn leaving_a_meeting_room_takes_it_off_the_leavers_client_and_deleting_it_leaves_the_server_up()
 {
    // The rest of a room's life. Two things, in one deployment because the
    // second depends on the first having put somebody inside a parentless
    // channel:
    //
    //   * revoking access moves the leaver out and tells *them* the room is
    //     gone, without touching anybody else's copy of it
    //     (`Server::revokeChannelAccess`, `Server.cpp:3713`);
    //   * deleting the room afterwards does not take the server down. That is
    //     the C++ crash this guards: `removeChannel` took the parent as the
    //     destination for displaced users and dereferenced it, so deleting a
    //     meeting room or a friend DM killed the process
    //     (`Server.cpp:2161`).
    use starling_proto_fancy::metadata::RemoveRequest;
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;

    let data_dir = TempDir::new("meeting-leave");
    let deployment = Deployment::start(data_dir.path()).await;
    let bob = register_with_password(&deployment, "bob", "hunter2").await;
    let alice = register_with_password(&deployment, "alice", "hunter4").await;

    let mut bob_client = Client::connect(deployment.port).await;
    let bob_session = login(&mut bob_client, "bob", "hunter2", Some(FANCY_CLIENT)).await;
    let mut alice_client = Client::connect(deployment.port).await;
    let alice_session = login(&mut alice_client, "alice", "hunter4", Some(FANCY_CLIENT)).await;

    let room = provision_room(&deployment, "Standup [ab12cd34]", &[bob, alice])
        .await
        .channel
        .expect("a provisioned room")
        .id;
    for client in [&mut bob_client, &mut alice_client] {
        assert!(
            client
                .next_channel_state(room, FRAME_TIMEOUT)
                .await
                .is_some(),
            "both invitees are told about the room"
        );
    }

    assert_eq!(
        bob_client
            .enter(bob_session, room, "bob joins the meeting")
            .await,
        Ok(room),
        "an invitee may enter the room they were admitted to"
    );

    set_access(&deployment, room, bob, false).await;
    assert_eq!(
        timeout(FRAME_TIMEOUT, bob_client.next_channel_of(bob_session))
            .await
            .expect("bob was left sitting in a channel he may no longer see"),
        0,
        "the move comes first: a client cannot leave a channel it has been \
         told does not exist"
    );
    assert!(
        bob_client.told_channel_gone(room, FRAME_TIMEOUT).await,
        "a room somebody may no longer see must leave their channel list"
    );
    assert!(
        !alice_client.told_channel_gone(room, NOT_COMING).await,
        "one invitee leaving must not take the room off everybody else's client"
    );

    // Alice is still in the room when it is deleted, which is the case that
    // crashed: her destination is the parent a detached channel does not have.
    assert_eq!(
        alice_client
            .enter(alice_session, room, "alice joins the meeting")
            .await,
        Ok(room)
    );
    let transport = deployment
        .resolver
        .channel("metadata")
        .expect("metadata is reachable");
    let removed = MetadataClient::new(transport)
        .remove(RemoveRequest {
            scope: None,
            actor: None,
            channel: room,
        })
        .await
        .expect("the room is removed")
        .into_inner();
    assert!(removed.applied, "refused: {}", removed.refused);

    assert_eq!(
        timeout(FRAME_TIMEOUT, alice_client.next_channel_of(alice_session))
            .await
            .expect("alice was never relocated out of the deleted room"),
        0,
        "an occupant of a parentless channel goes to the root, not nowhere"
    );
    assert!(alice_client.told_channel_gone(room, FRAME_TIMEOUT).await);

    // The definitive no-crash check: the server is still answering.
    let mut late = Client::connect(deployment.port).await;
    let _ = handshake(&mut late, "late").await;

    deployment.stop().await;
}

// -- The registered-user directory, moving somebody, and clearing their profile

/// Register an account the way an operator does, over userdata's own gRPC.
///
/// Deployment set-up, not the behaviour under test, on the same grounds
/// as [`Deployment::create_channel`], and for one more: registering *from a
/// client* requires the target to have presented a certificate, and this
/// harness dials with `with_no_client_auth`. What the tests below assert is
/// what a client can then see and do about the accounts this put there.
async fn register_account(deployment: &Deployment, name: &str) -> u64 {
    use starling_proto_fancy::userdata::user_data_client::UserDataClient;
    use starling_proto_fancy::userdata::{Account, RegisterRequest};

    let transport = deployment
        .resolver
        .channel("userdata")
        .expect("userdata is reachable");
    UserDataClient::new(transport)
        .register(RegisterRequest {
            scope: None,
            actor: None,
            account: Some(Account {
                name: name.to_owned(),
                cert_hash: name.as_bytes().to_vec(),
                ..Account::default()
            }),
            password: String::new(),
        })
        .await
        .expect("the account is registered")
        .into_inner()
        .id
}

/// The `UserList` the server sends back, or the refusal it sends instead.
///
/// Both are legitimate answers, and a test asserting one has to be able to see
/// the other: a directory that is refused and a directory that is never
/// answered are the same timeout otherwise, and the second was the bug.
async fn next_directory(client: &mut Client) -> Result<tcp::UserList, tcp::PermissionDenied> {
    loop {
        let (type_id, payload) = client.recv().await;
        match type_id {
            18 => {
                return Ok(
                    tcp::UserList::decode(payload.as_slice()).expect("a well-formed UserList")
                );
            }
            12 => {
                return Err(tcp::PermissionDenied::decode(payload.as_slice())
                    .expect("a well-formed PermissionDenied"));
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn the_registered_user_directory_shows_an_operator_more_than_a_guest() {
    // `docs/GAP-ANALYSIS.md` UserList(18)/A1. The message was routed to
    // `userdata`, which had no arm for it, so an operator registered somebody
    // successfully and found the dialog they would check it in empty, with
    // nothing logged, because dropping an unhandled frame is normal and silent.
    //
    // Both views are asserted from one deployment because the *difference* is
    // the rule (`Messages.cpp:3153`), and a server that answered everybody with
    // the administrator's view would pass any test that looked at only one of
    // them. `Register` manages the directory and comes with the whole record;
    // `ReadRegister` is a lookup permission, enough to find somebody who is
    // offline and invite them, not enough to learn when they were last here.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("user-list");
    let deployment = Deployment::start(data_dir.path()).await;
    let fred = register_account(&deployment, "offline-fred").await;

    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![
                // Everybody may look somebody up...
                entry("all", Perm::READ_REGISTER, Perm::empty()),
                // ...and the operators may manage the directory.
                entry("ops", Perm::REGISTER, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(0, "ops", alice_session)
        .await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    for client in [&mut alice, &mut bob] {
        client.send(18, &tcp::UserList::default()).await;
    }

    let operator = next_directory(&mut alice)
        .await
        .expect("an operator holding Register may read the directory");
    let listed = operator
        .users
        .iter()
        .find(|user| u64::from(user.user_id) == fred)
        .expect("the account that was just registered is in the directory");
    assert_eq!(listed.name.as_deref(), Some("offline-fred"));
    assert!(
        listed.last_seen.is_some(),
        "an operator is shown when the account was last active"
    );
    assert!(
        operator.users.iter().all(|user| user.user_id != 0),
        "the SuperUser is not somebody to be renamed or unregistered, and murmur \
         leaves it out of the dialog that offers both"
    );

    let guest = next_directory(&mut bob)
        .await
        .expect("ReadRegister is enough to look somebody up");
    let seen = guest
        .users
        .iter()
        .find(|user| u64::from(user.user_id) == fred)
        .expect("the reduced view still names the account");
    assert_eq!(seen.name.as_deref(), Some("offline-fred"));
    assert_eq!(
        seen.last_seen, None,
        "presence is not part of a lookup: ReadRegister must not report when \
         somebody was last on the server"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_guest_with_no_grant_at_all_is_refused_the_directory() {
    // The other direction, and the one that matters: the account list of
    // everyone who has ever been on this server is not public. Refused *out
    // loud*, because a silent drop here is indistinguishable from the bug the
    // handler was written to fix.
    let data_dir = TempDir::new("user-list-refused");
    let deployment = Deployment::start(data_dir.path()).await;
    let _ = register_account(&deployment, "offline-fred").await;

    // No ACL table at all. The default set grants `ReadRegister` to registered
    // users only (`permissions/src/evaluate.rs:182`), and this client is a guest.
    let mut mallory = Client::connect(deployment.port).await;
    let _ = handshake(&mut mallory, "mallory").await;
    mallory.send(18, &tcp::UserList::default()).await;

    let refusal = next_directory(&mut mallory)
        .await
        .expect_err("a guest must not be handed the account directory");
    assert_eq!(
        refusal.permission,
        Some(starling_proto_fancy::perm::Perm::READ_REGISTER.bits()),
        "the refusal names the permission that was missing, or it is a support ticket"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_moderator_moves_another_user_by_either_half_of_murmurs_rule() {
    // `docs/GAP-ANALYSIS.md` U2, and the shape of the gap is worth recording:
    // `on_move` already held the whole rule, `Move` on the channel the user is
    // being taken out of, then `Move` on the destination **or** the moved
    // user's own `Enter`, and was unreachable for anybody but the sender,
    // because the cross-session refusal above it dropped the message first.
    // Nothing failed and nothing was logged; the user simply did not move.
    //
    // Both halves of the *or* are exercised, because implementing one of them
    // is indistinguishable from implementing both until the day an operator
    // drags somebody into a room that person cannot enter alone, which is the
    // entire point of a `Move` permission.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::{AclEntry, AclSet};

    let data_dir = TempDir::new("move-another");
    let deployment = Deployment::start(data_dir.path()).await;
    let lobby = deployment.create_channel("Lobby").await;
    let vault = deployment.create_channel("Vault").await;

    // `apply_subs` off, so this grants Move in the **root only**: alice may take
    // people out of the room they start in and nowhere else. Left on, the grant
    // would inherit into every channel below and the destination half of the
    // rule would pass for the wrong reason.
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![AclEntry {
                apply_here: true,
                apply_subs: false,
                group: Some("ops".to_owned()),
                grant: Perm::MOVE.bits(),
                ..AclEntry::default()
            }],
            groups: Vec::new(),
        })
        .await;
    // A room nobody may walk into and an operator may still put people in.
    deployment
        .set_acl(AclSet {
            channel: vault,
            inherit: true,
            acls: vec![
                entry("all", Perm::empty(), Perm::ENTER),
                entry("ops", Perm::MOVE, Perm::empty()),
            ],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(0, "ops", alice_session)
        .await;
    deployment
        .add_temporary_group(vault, "ops", alice_session)
        .await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;

    // Bob cannot get into the Vault on his own, which is what makes the first
    // move below a real exercise of alice's `Move` rather than of bob's `Enter`.
    bob.send(
        9,
        &tcp::UserState {
            session: Some(bob_session),
            channel_id: Some(vault),
            ..tcp::UserState::default()
        },
    )
    .await;
    let refusal = bob
        .next_entry_answer(bob_session)
        .await
        .expect_err("Enter is denied to everyone in the Vault");
    assert_eq!(refusal.permission, Some(Perm::ENTER.bits()));

    // Half one: the **mover's** `Move` on the destination, into a room the moved
    // user was just refused. This is the case an operator reaches for, and the
    // one a server implementing only the `Enter` branch would refuse.
    //
    // Bob starts in the root, where alice's grant applies, so the *source* half
    // of the rule is satisfied and what is under test is the destination.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                channel_id: Some(vault),
                ..tcp::UserState::default()
            },
        )
        .await;
    let dragged = timeout(FRAME_TIMEOUT, bob.next_move_of(bob_session))
        .await
        .expect("an operator holding Move on the destination may put somebody there");
    assert_eq!(
        dragged.channel_id,
        Some(vault),
        "the mover's Move on the destination has to be enough on its own"
    );
    assert_eq!(
        dragged.actor,
        Some(alice_session),
        "a move done *to* somebody has to name who did it, or the client reports \
         it as the server acting on its own"
    );

    // Half two: the **moved user's** own `Enter`. Alice holds `Move` in the
    // Vault, so she may take bob out of it, and holds none in the Lobby, so
    // putting him *there* can only be allowed by bob's own default `Enter`.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                channel_id: Some(lobby),
                ..tcp::UserState::default()
            },
        )
        .await;
    let moved = timeout(FRAME_TIMEOUT, bob.next_move_of(bob_session))
        .await
        .expect("bob was never told he had been moved");
    assert_eq!(
        moved.channel_id,
        Some(lobby),
        "the moved user's own Enter has to be enough, with no Move on the mover"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn an_administrator_holding_only_write_on_the_root_can_move_people() {
    // The way every Mumble server's administrators are made: `Write` for the
    // `admin` group on the root, handed down, and nothing else spelled out.
    // murmur makes that enough because `Write` implies `Move` and the rest
    // of the channel after the walk (`vendor/server/src/ACL.cpp:240`).
    // Starling transcribed the walk and not the line after it, so such an
    // administrator could rewrite every ACL on the server and was refused
    // every move, with a `PermissionDenied` naming a permission they were
    // certain they held.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("move-by-write");
    let deployment = Deployment::start(data_dir.path()).await;
    let vault = deployment.create_channel("Vault").await;

    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("admin", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;
    // A room nobody may walk into, so the move below is carried by the
    // administrator's implied `Move` on both ends and not by bob's `Enter`.
    deployment
        .set_acl(AclSet {
            channel: vault,
            inherit: true,
            acls: vec![entry("all", Perm::empty(), Perm::ENTER)],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(0, "admin", alice_session)
        .await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;

    // The destination half of the move is alice's *inherited* `Move` in the
    // Vault, which `permissions` can only see once it has learned from
    // `metadata` that the Vault hangs off the root. Wait for that rather than
    // for luck: what is under test is the implication, not the boot order.
    deployment
        .wait_until_permitted(alice_session, vault, Perm::MOVE.bits())
        .await;

    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                channel_id: Some(vault),
                ..tcp::UserState::default()
            },
        )
        .await;
    let dragged = timeout(FRAME_TIMEOUT, bob.next_move_of(bob_session))
        .await
        .expect("Write on the root has to be enough to move somebody");
    assert_eq!(dragged.channel_id, Some(vault));
    assert_eq!(dragged.actor, Some(alice_session));

    deployment.stop().await;
}

#[tokio::test]
async fn moving_a_channel_takes_make_channel_on_where_it_is_going() {
    // murmur's rule for a re-parent is two questions (`Messages.cpp:2025`,
    // `:2032`): `Write` on the channel being moved, then `MakeChannel` on the
    // new parent, because putting a channel somewhere is the same power as
    // creating one there. Starling asked the first and not the second, so
    // anybody who owned a room could hang it under any channel on the server,
    // including ones they could not create in.
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("move-channel");
    let deployment = Deployment::start(data_dir.path()).await;
    let attic = deployment.create_channel("Attic").await;
    let wing = deployment.create_channel("Locked Wing").await;

    // Alice owns the Attic and nothing else.
    deployment
        .set_acl(AclSet {
            channel: attic,
            inherit: true,
            acls: vec![entry("ops", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(attic, "ops", alice_session)
        .await;

    // The move she may not make: her own room, into a wing she cannot create
    // in. The refusal names the permission and the channel it was missing on,
    // so the client can say which of the two rooms is the problem.
    alice
        .send(
            7,
            &tcp::ChannelState {
                channel_id: Some(attic),
                parent: Some(wing),
                ..tcp::ChannelState::default()
            },
        )
        .await;
    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(12))
        .await
        .expect("the move is refused out loud, not dropped");
    let refusal = tcp::PermissionDenied::decode(payload.as_slice()).expect("well-formed");
    assert_eq!(refusal.permission, Some(Perm::MAKE_CHANNEL.bits()));
    assert_eq!(refusal.channel_id, Some(wing));

    // Given `MakeChannel` in the wing, the same move goes through.
    deployment
        .set_acl(AclSet {
            channel: wing,
            inherit: true,
            acls: vec![entry("ops", Perm::MAKE_CHANNEL, Perm::empty())],
            groups: Vec::new(),
        })
        .await;
    deployment
        .add_temporary_group(wing, "ops", alice_session)
        .await;
    alice
        .send(
            7,
            &tcp::ChannelState {
                channel_id: Some(attic),
                parent: Some(wing),
                ..tcp::ChannelState::default()
            },
        )
        .await;
    let (_, payload) = timeout(FRAME_TIMEOUT, alice.recv_until(7))
        .await
        .expect("the move is announced");
    let moved = tcp::ChannelState::decode(payload.as_slice()).expect("well-formed");
    assert_eq!(moved.channel_id, Some(attic));
    assert_eq!(moved.parent, Some(wing));

    deployment.stop().await;
}

#[tokio::test]
async fn an_operator_clears_another_users_comment_but_cannot_write_one() {
    // `docs/GAP-ANALYSIS.md` U6. Both halves are the feature: murmur's rule is
    // `ResetUserContent` on the root **and** an empty value
    // (`Messages.cpp:1236`), so a moderator can take down a comment nobody
    // should have to read and cannot replace it with one of their own choosing.
    // Enforcing only the permission would let an administrator put words into
    // somebody else's profile, under that person's name, on every client.
    use sha1::Digest as _;
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;

    let data_dir = TempDir::new("reset-content");
    let deployment = Deployment::start(data_dir.path()).await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("ops", Perm::RESET_USER_CONTENT, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    deployment
        .add_temporary_group(0, "ops", alice_session)
        .await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake(&mut bob, "bob").await;

    // Bob's own comment, which needs no permission at all.
    bob.send(
        9,
        &tcp::UserState {
            comment: Some("something regrettable".to_owned()),
            ..tcp::UserState::default()
        },
    )
    .await;
    let posted = timeout(
        FRAME_TIMEOUT,
        alice.next_state_of(bob_session, |state| {
            state.comment_hash.as_ref().map(|_| true)
        }),
    )
    .await
    .expect("everyone is told bob set a comment");
    // SHA-1 of the body, not merely "some hash": a Mumble client recomputes this
    // digest from the comment it is handed (`UserModel.cpp:1188`) and keys its
    // "comment already seen" table by the result, so a hash produced any other
    // way makes every reconnect look like a brand-new comment and paints the
    // yellow flag on a user whose comment has not changed in months.
    assert_eq!(
        posted.comment_hash.as_deref(),
        Some(sha1::Sha1::digest(b"something regrettable").as_slice()),
        "the announced hash is the one the client computes for itself"
    );

    // Bob may not be *given* a comment by somebody else, however privileged.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                comment: Some("words alice put in bob's mouth".to_owned()),
                ..tcp::UserState::default()
            },
        )
        .await;
    let (type_id, payload) = timeout(FRAME_TIMEOUT, alice.recv())
        .await
        .expect("the write is answered rather than dropped");
    assert_eq!(
        type_id, 12,
        "writing another user's comment must be refused"
    );
    let refusal = tcp::PermissionDenied::decode(payload.as_slice()).expect("well-formed");
    assert_eq!(
        refusal.r#type,
        Some(tcp::permission_denied::DenyType::TextTooLong as i32),
        "the permitted length of somebody else's comment is zero, and murmur says \
         so with TextTooLong rather than with a permission the operator does hold"
    );

    // Clearing it is exactly what the permission is for.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(bob_session),
                comment: Some(String::new()),
                ..tcp::UserState::default()
            },
        )
        .await;
    let cleared = timeout(
        FRAME_TIMEOUT,
        bob.next_state_of(bob_session, |state| state.comment.as_ref().map(|_| true)),
    )
    .await
    .expect("bob is told his comment was cleared");
    assert_eq!(
        cleared.comment.as_deref(),
        Some(""),
        "an empty body, not an empty hash: a client reads the first as blank and \
         the second as something to go and fetch"
    );
    assert_eq!(
        cleared.actor,
        Some(alice_session),
        "a reset done to somebody names who did it"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_peer_that_never_authenticated_reaches_nobody() {
    // Defence in depth: asserted, not assumed.
    //
    // The gateway has **no authentication gate**: `dispatch` routes any frame
    // whose type has a route, and an unauthenticated connection simply carries
    // `session = 0`. What actually stops it is the layer below, `Permit`
    // refuses session 0 without even asking `permissions`, so the safety of
    // the whole front door rests on every service failing closed.
    //
    // That is a real property and worth a test, because it is invisible: it
    // holds by everything downstream being careful, not by anything at the
    // door saying no. A service that grew a path acting on `conn` rather than
    // `session` would open a hole with nothing to catch it.
    //
    // Companion to `a_refused_login_is_told_why_and_then_hung_up_on`, which
    // covers the peer that *tried* and failed; this one never tries at all,
    // so no `Reject` and no disconnect is due to it.
    let data_dir = TempDir::new("unauthenticated");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake(&mut bob, "bob").await;

    // Completes TLS and `Version`, then skips `Authenticate` entirely and
    // starts talking, which a stock client cannot do and a hostile one can.
    let mut intruder = Client::connect(deployment.port).await;
    let _ = intruder.recv().await;
    intruder
        .send(
            0,
            &tcp::Version {
                version_v2: Some(MUMBLE_VERSION_V2),
                ..tcp::Version::default()
            },
        )
        .await;
    intruder
        .send(
            11,
            &tcp::TextMessage {
                // Claiming somebody else's session, because a peer with none
                // of its own has nothing to lose by trying.
                actor: Some(1),
                channel_id: vec![0],
                message: "INTRUDER".to_owned(),
                ..tcp::TextMessage::default()
            },
        )
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let Some((type_id, payload)) = bob.next_frame(Duration::from_millis(500)).await else {
            continue;
        };
        if type_id != 11 {
            continue;
        }
        let message = tcp::TextMessage::decode(payload.as_slice()).expect("a well-formed message");
        assert!(
            !message.message.contains("INTRUDER"),
            "a peer that never authenticated had its text delivered to a real user"
        );
    }

    deployment.stop().await;
}

/// Stage 5: the soak's window onto the deployment, end to end.
#[tokio::test]
async fn every_service_reports_its_counters_and_gauges_through_one_call() {
    // The plumbing the soak harness depends on: counters and per-map gauges
    // from every unit in one round trip, without a per-service `/metrics`
    // listener and without anyone but the collector calling `Pressure::sample`.
    let data_dir = TempDir::new("overview-counters");
    let deployment = Deployment::start(data_dir.path()).await;

    // Traffic, so there is something to have counted.
    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake(&mut alice, "alice").await;

    // The collector polls on a fixed interval, so the first overview may
    // predate the connection.
    let found = timeout(FRAME_TIMEOUT, async {
        loop {
            let overview = deployment.overview().await;
            let gateway = overview
                .services
                .iter()
                .find(|service| service.service == "gateway");
            if let Some(gateway) = gateway
                && gateway.counters.iter().any(|c| c.value > 0)
                && gateway.load.iter().any(|l| l.name == "connections")
            {
                return overview;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the gateway must report counters and gauges");

    let gateway = found
        .services
        .iter()
        .find(|service| service.service == "gateway")
        .expect("the gateway is in the overview");

    assert!(
        gateway
            .counters
            .iter()
            .any(|counter| counter.name == "starling_gateway_connections"),
        "a counter the gateway increments must reach the collector: {:?}",
        gateway.counters.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
    assert!(
        gateway
            .load
            .iter()
            .any(|load| load.name == "resume.sessions"),
        "the per-map gauges must reach it too: {:?}",
        gateway.load.iter().map(|l| &l.name).collect::<Vec<_>>()
    );

    // Every unit answers, not just the ones that happen to be busy: a service
    // missing from this is one the soak cannot assert anything about.
    assert!(
        found.services.len() >= 20,
        "expected every unit in the overview, got {}",
        found.services.len()
    );

    deployment.stop().await;
}

#[tokio::test]
async fn the_health_collector_reports_every_service_in_a_live_deployment() {
    // The whole feature, against a real deployment. Each half is easy to get
    // right on its own and worthless alone: a service reporting its own gates
    // that nothing collects, or a collector that reaches nobody.
    //
    // What only this level can show is that the runtime's injected health RPC
    // is actually *served* by every service; it is added in `serve`, so a
    // service that composes its routes unusually could silently lack it, and
    // the collector would report the healthiest service on the server as
    // unreachable.
    use starling_proto_fancy::health::health_overview_client::HealthOverviewClient;
    use starling_proto_fancy::health::{OverviewRequest, State};

    let data_dir = TempDir::new("health-overview");
    let deployment = Deployment::start(data_dir.path()).await;

    // The first sweep runs the moment the collector starts, which is while
    // the other services are still opening their databases and binding. A
    // callee that takes longer than the dial's retry window to bind (a cold
    // Windows runner does) is honestly reported unreachable in that sweep,
    // and honestly reported so for a whole `POLL_INTERVAL`, because that is
    // the warming picture the collector exists to show. What this asserts is
    // the settled one, so a sweep with anything unreachable is waited out
    // rather than judged. The deadline is what turns "still unreachable"
    // into the failure; how long a whole deployment takes to come up is not
    // what this asserts.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let overview = loop {
        let attempt = async {
            let channel = deployment.resolver.channel("health").ok()?;
            let overview = HealthOverviewClient::new(channel)
                .get(OverviewRequest { scope: None })
                .await
                .ok()?
                .into_inner();
            let settled = !overview.services.is_empty()
                && overview
                    .services
                    .iter()
                    .all(|service| service.state != i32::from(State::Unreachable));
            settled.then_some(overview)
        }
        .await;
        if let Some(overview) = attempt {
            break overview;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the health collector never produced a sweep with every service reachable"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };

    // Every enabled service is in the sweep, including the ones with no wire
    // type. A collector that only knew the client-facing services would miss
    // session-view, which everything else reads through. Reachability was
    // the loop's condition; presence is this one's.
    for expected in [
        "voice",
        "metadata",
        "userdata",
        "session-view",
        "permissions",
    ] {
        assert!(
            overview
                .services
                .iter()
                .any(|service| service.service == expected),
            "{expected} is missing from the sweep"
        );
    }

    // The gates themselves survive, which is the difference between a
    // dashboard that says "something is wrong" and one that says what.
    let voice = overview
        .services
        .iter()
        .find(|service| service.service == "voice")
        .expect("voice is in the sweep");
    assert!(
        voice.gates.iter().any(|gate| gate.name == "session view"),
        "voice's own readiness gates did not reach the collector: {:?}",
        voice.gates
    );

    // And the snapshot says when it was taken, so a dashboard can show a
    // stale picture as stale rather than as current.
    assert!(overview.observed_at_ms > 0);

    deployment.stop().await;
}

#[tokio::test]
async fn a_channel_listener_hears_a_room_without_being_in_it() {
    // `docs/GAP-ANALYSIS.md` V5. The routing core could already fan out to a
    // listener and the tree could already hold one, but `UserState`'s
    // `listening_channel_add` was never read, so a user clicked "listen" in
    // their client, the server parsed the message, ignored it, and answered
    // nothing. Every piece worked and the feature did not exist.
    //
    // Driven end to end because that is exactly the shape of the bug: the wire
    // handler, metadata's tree, the session view and voice's subscription are
    // four services, and each was right on its own.
    //
    // Bob is the control. He is in the lobby with alice and must keep hearing
    // her; carol never leaves the lobby either, but listens to the annex.
    let data_dir = TempDir::new("channel-listener");
    let deployment = Deployment::start(data_dir.path()).await;
    let annex = deployment.create_channel("Annex").await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut carol = Client::connect(deployment.port).await;
    let carol_session = handshake(&mut carol, "carol").await;

    // Alice moves to the annex, so that anything carol hears from her can only
    // have arrived through the listener.
    alice
        .send(
            9,
            &tcp::UserState {
                session: Some(alice_session),
                channel_id: Some(annex),
                ..tcp::UserState::default()
            },
        )
        .await;
    assert_eq!(carol.next_channel_of(alice_session).await, annex);

    // Silent first, or the second half proves nothing: a test that only checks
    // carol hears alice after the listener passes on a server that routes every
    // frame to everybody.
    for _ in 0..10 {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"unheard"))
            .await;
    }
    assert!(
        carol.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "carol heard another channel before she listened to it; the annex is not isolated, \
         so nothing below can be attributed to the listener"
    );

    carol
        .send(
            9,
            &tcp::UserState {
                session: Some(carol_session),
                listening_channel_add: vec![annex],
                ..tcp::UserState::default()
            },
        )
        .await;

    // The echo, which is also the point the server has finished applying it.
    // Waiting on a timer would race the announcement to session-view and
    // voice's subscription behind it.
    let listening = carol
        .next_state_of(carol_session, |state| {
            (!state.listening_channel_add.is_empty()).then_some(true)
        })
        .await;
    assert_eq!(
        listening.listening_channel_add,
        vec![annex],
        "the client is told which listener was registered, or its own UI never lights up"
    );

    let deadline = tokio::time::Instant::now() + AUDIO_TIMEOUT;
    let reached = loop {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"heard"))
            .await;
        if let Some(payload) = carol.next_audio(AUDIO_ATTEMPT).await {
            break Some(payload);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
    };
    let payload = reached.expect(
        "carol registered a listener on the annex and never heard it; the wire handler, the \
         tree, the session view and voice's snapshot are four places this can stop",
    );
    let (speaker, opus) = heard(&payload);
    assert_eq!(speaker, alice_session);
    assert_eq!(opus, b"heard");

    // Context 3, and it is not cosmetic: a client renders a listener frame
    // differently from someone in the room, and reporting it as normal speech
    // tells carol that alice has joined her channel.
    assert_eq!(
        listener_context(&payload),
        3,
        "a frame reached through a channel listener must say so"
    );

    // And it stops when she says so, the half that a server which only ever
    // adds listeners passes without implementing.
    carol
        .send(
            9,
            &tcp::UserState {
                session: Some(carol_session),
                listening_channel_remove: vec![annex],
                ..tcp::UserState::default()
            },
        )
        .await;
    let _ = carol
        .next_state_of(carol_session, |state| {
            (!state.listening_channel_remove.is_empty()).then_some(true)
        })
        .await;

    let _ = carol.next_audio(AUDIO_ATTEMPT).await;
    for _ in 0..10 {
        alice
            .send_raw(UDP_TUNNEL, &audio_frame(REGULAR_SPEECH, b"after"))
            .await;
    }
    assert!(
        carol.next_audio(AUDIO_ATTEMPT).await.is_none(),
        "carol stopped listening and still heard the annex; a listener that cannot be \
         cancelled is a subscription the user is stuck with"
    );

    deployment.stop().await;
}

/// The `context` the server put on a frame, 0 normal, 1 shout, 2 whisper,
/// 3 through a channel listener.
fn listener_context(payload: &[u8]) -> u32 {
    assert_eq!(payload.first(), Some(&0), "not an audio packet");
    let audio = udp::Audio::decode(&payload[1..]).expect("a well-formed audio frame");
    match audio.header {
        Some(udp::audio::Header::Context(context)) => context,
        // Outbound frames carry `context`; `target` is the inbound spelling of
        // the same oneof, and the two are not interchangeable.
        other => panic!("the server sent a frame with no context: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Social and scheduled messages
//
// Both were features that answered on the wire and did nothing on screen, so
// the assertions here are deliberately about *who* a frame names and *who* it
// reaches, not merely that one arrived.
// ---------------------------------------------------------------------------

/// The social service's outer type.
const SOCIAL: u16 = 1015;
/// The text service's outer type.
const TEXT: u16 = 1005;

/// One `SocialEnvelope`, ready to send.
fn social(body: fancy::social::social_envelope::Body) -> fancy::social::SocialEnvelope {
    fancy::social::SocialEnvelope { body: Some(body) }
}

/// The next social body a client is given.
async fn next_social(client: &mut Client) -> fancy::social::social_envelope::Body {
    let (_, payload) = client.recv_until(SOCIAL).await;
    fancy::social::SocialEnvelope::decode(payload.as_slice())
        .expect("a well-formed SocialEnvelope")
        .body
        .expect("an envelope with a body in it")
}

#[tokio::test]
async fn a_reaction_reaches_the_channel_including_the_person_who_sent_it() {
    // Two failures at once, and each made the feature do nothing rather than
    // do it wrongly. The relay excluded the sender, and the client has no
    // optimistic update, so a reactor never saw their own pill. And the actor
    // was whatever the peer wrote, which is nothing.
    let data_dir = TempDir::new("reaction");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake_fancy(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut bob, "bob").await;

    alice
        .send(
            SOCIAL,
            &social(fancy::social::social_envelope::Body::Reaction(
                fancy::social::Reaction {
                    channel: 0,
                    message_id: "m-1".to_owned(),
                    emoji: Some(fancy::wire::Emoji {
                        kind: Some(fancy::wire::emoji::Kind::Unicode("\u{1f44d}".to_owned())),
                    }),
                    ..fancy::social::Reaction::default()
                },
            )),
        )
        .await;

    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let fancy::social::social_envelope::Body::Reaction(reaction) = next_social(client).await
        else {
            panic!("{who} was sent something other than the reaction");
        };
        assert_eq!(reaction.message_id, "m-1", "{who}");
        assert_eq!(
            reaction.actor, alice_session,
            "{who} must be told who reacted; the peer never says"
        );
    }

    deployment.stop().await;
}

#[tokio::test]
async fn a_typing_indicator_names_the_typist_and_is_not_echoed_to_them() {
    let data_dir = TempDir::new("typing");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake_fancy(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut bob, "bob").await;

    alice
        .send(
            SOCIAL,
            &social(fancy::social::social_envelope::Body::Typing(
                fancy::social::Typing {
                    channel: 0,
                    actor: 0,
                    typing: true,
                },
            )),
        )
        .await;

    let fancy::social::social_envelope::Body::Typing(typing) = next_social(&mut bob).await else {
        panic!("bob was sent something other than the typing indicator");
    };
    assert_eq!(
        typing.actor, alice_session,
        "a client drops an indicator whose actor is 0, which is what it sends"
    );

    // And alice is not told about her own keystrokes. Scanning for a *social*
    // frame rather than any frame: a `UserState` from bob's join is unrelated
    // traffic that would otherwise read as an echo.
    let echo = timeout(Duration::from_millis(750), async {
        loop {
            let (type_id, _) = alice.recv().await;
            if type_id == SOCIAL {
                return;
            }
        }
    })
    .await;
    assert!(echo.is_err(), "alice was told that she is typing");

    deployment.stop().await;
}

/// The screenshare service's outer type.
const SCREENSHARE: u16 = 1008;

/// The next screenshare body a client is given.
async fn next_screenshare(client: &mut Client) -> fancy::screenshare::screenshare_envelope::Body {
    let (_, payload) = client.recv_until(SCREENSHARE).await;
    fancy::screenshare::ScreenshareEnvelope::decode(payload.as_slice())
        .expect("a well-formed ScreenshareEnvelope")
        .body
        .expect("an envelope with a body in it")
}

/// One `WebRtcSignal`, as a client sends it.
fn webrtc(
    target: u32,
    kind: fancy::screenshare::web_rtc_signal::SignalType,
    payload: &str,
) -> fancy::screenshare::ScreenshareEnvelope {
    fancy::screenshare::ScreenshareEnvelope {
        body: Some(fancy::screenshare::screenshare_envelope::Body::Signal(
            fancy::screenshare::WebRtcSignal {
                target_session: target,
                // What a client claims. The assertion below is that it does
                // not survive: on this path a sender field a client fills is a
                // client signalling as somebody else, which means hijacking
                // their broadcast.
                sender_session: 4_242,
                signal_type: kind.into(),
                payload: payload.to_owned(),
            },
        )),
    }
}

#[tokio::test]
async fn a_screen_share_announcement_reaches_the_channel_and_names_the_real_presenter() {
    // The signalling the shipped client speaks, over a real socket: it proves
    // the routing as much as the handler. Outer type 1008 has to reach the
    // screenshare service, and it has to arrive on the `signalling` bucket -
    // on murmur's single 1/s control bucket this silently ate the SDP offer
    // that follows, and a dropped offer looks exactly like a client bug.
    let data_dir = TempDir::new("webrtc-start");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake_fancy(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut bob, "bob").await;

    alice
        .send(
            SCREENSHARE,
            &webrtc(
                0,
                fancy::screenshare::web_rtc_signal::SignalType::Start,
                "tracks",
            ),
        )
        .await;

    let fancy::screenshare::screenshare_envelope::Body::Signal(signal) =
        next_screenshare(&mut bob).await
    else {
        panic!("bob was sent something other than the announcement");
    };
    assert_eq!(
        signal.signal_type(),
        fancy::screenshare::web_rtc_signal::SignalType::Start
    );
    assert_eq!(
        signal.sender_session, alice_session,
        "stamped by the server, over the 4242 alice claimed"
    );
    assert_eq!(
        signal.payload, "tracks",
        "the track metadata every viewer re-parses, relayed verbatim"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_screen_share_offer_is_relayed_to_the_one_session_it_names() {
    // The mesh half, which is what a deployment with no public media address
    // runs: the server addresses the signalling and the clients negotiate
    // between themselves. murmur's directed relay, including that it is
    // directed - a broadcast here would show one viewer's SDP to the channel.
    let data_dir = TempDir::new("webrtc-offer");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake_fancy(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake_fancy(&mut bob, "bob").await;
    let mut carol = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut carol, "carol").await;

    alice
        .send(
            SCREENSHARE,
            &webrtc(
                0,
                fancy::screenshare::web_rtc_signal::SignalType::Start,
                "tracks",
            ),
        )
        .await;
    // Both viewers are told, which is what makes the next assertion about the
    // offer being *directed* rather than about nothing arriving at all.
    let _ = next_screenshare(&mut bob).await;
    let _ = next_screenshare(&mut carol).await;

    bob.send(
        SCREENSHARE,
        &webrtc(
            alice_session,
            fancy::screenshare::web_rtc_signal::SignalType::SdpOffer,
            "v=0 bob",
        ),
    )
    .await;

    let fancy::screenshare::screenshare_envelope::Body::Signal(offer) =
        next_screenshare(&mut alice).await
    else {
        panic!("alice was sent something other than the offer");
    };
    assert_eq!(offer.sender_session, bob_session);
    assert_eq!(offer.payload, "v=0 bob");

    // And carol is not shown bob's SDP. Scanning for a *screenshare* frame
    // rather than any frame: unrelated handshake traffic would read as one.
    let leaked = timeout(Duration::from_millis(750), async {
        loop {
            let (type_id, _) = carol.recv().await;
            if type_id == SCREENSHARE {
                return;
            }
        }
    })
    .await;
    assert!(leaked.is_err(), "a directed offer went to the channel");

    deployment.stop().await;
}

#[tokio::test]
async fn a_presenter_who_drops_ends_their_screen_share_for_everyone_else() {
    // murmur tracked no shares at all, so a presenter closing their laptop
    // left every viewer watching a stream that had stopped, with no event to
    // tell them: it could only be cleared by the presenter reconnecting and
    // stopping it by hand.
    let data_dir = TempDir::new("webrtc-drop");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut bob, "bob").await;

    alice
        .send(
            SCREENSHARE,
            &webrtc(
                0,
                fancy::screenshare::web_rtc_signal::SignalType::Start,
                "tracks",
            ),
        )
        .await;
    let _ = next_screenshare(&mut bob).await;

    drop(alice);

    let fancy::screenshare::screenshare_envelope::Body::Signal(stopped) =
        next_screenshare(&mut bob).await
    else {
        panic!("bob was sent something other than the stop");
    };
    assert_eq!(
        stopped.signal_type(),
        fancy::screenshare::web_rtc_signal::SignalType::Stop,
        "in the dialect the broadcast was announced in"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_poll_and_its_vote_carry_the_identity_and_the_channel_the_server_resolved() {
    // The vote is the half that was invisible: the canon vote carries no
    // channel, and a client drops a vote it cannot route to a poll card, so
    // the tally never moved however correctly the server counted.
    let data_dir = TempDir::new("poll");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake_fancy(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = handshake_fancy(&mut bob, "bob").await;

    alice
        .send(
            SOCIAL,
            &social(fancy::social::social_envelope::Body::Poll(
                fancy::social::Poll {
                    poll_id: "p-1".to_owned(),
                    channel: 0,
                    question: "lunch?".to_owned(),
                    options: vec!["yes".to_owned(), "no".to_owned()],
                    ..fancy::social::Poll::default()
                },
            )),
        )
        .await;

    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let fancy::social::social_envelope::Body::Poll(poll) = next_social(client).await else {
            panic!("{who} was sent something other than the poll itself");
        };
        assert_eq!(poll.question, "lunch?", "{who}");
        assert_eq!(poll.creator, alice_session, "{who} must be told whose poll");
    }

    bob.send(
        SOCIAL,
        &social(fancy::social::social_envelope::Body::Vote(
            fancy::social::PollVote {
                poll_id: "p-1".to_owned(),
                options: vec![1],
                ..fancy::social::PollVote::default()
            },
        )),
    )
    .await;

    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let fancy::social::social_envelope::Body::Vote(vote) = next_social(client).await else {
            panic!("{who} was sent something other than the vote");
        };
        assert_eq!(vote.voter, bob_session, "{who} must be told who voted");
        assert_eq!(vote.options, vec![1], "{who}");
        assert_eq!(
            vote.channel, 0,
            "{who} needs the poll's channel to find the card the vote belongs to"
        );
    }

    deployment.stop().await;
}

#[tokio::test]
async fn a_scheduled_message_is_stored_timed_and_delivered_to_the_channel() {
    // The whole path the `scheduled-messages` suite drives, minus the panel:
    // an ack that says it was accepted, the timer, and the message arriving as
    // ordinary channel text for everybody who is there when it is due.
    let data_dir = TempDir::new("scheduled");
    let deployment = Deployment::start(data_dir.path()).await;

    // With a client certificate: the owner of a message due later has to
    // outlive the connection that scheduled it, and only a certificate does.
    let mut alice = Client::connect_with_certificate(deployment.port, data_dir.path()).await;
    let _ = handshake_fancy(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _ = handshake_fancy(&mut bob, "bob").await;

    let due_at = starling_runtime::ids::now_ms() + 2_000;
    alice
        .send(
            TEXT,
            &fancy::feature::TextEnvelope {
                body: Some(fancy::feature::text_envelope::Body::Schedule(
                    fancy::feature::Scheduled {
                        channels: vec![0],
                        body: "from the past".to_owned(),
                        deliver_at_ms: due_at,
                        ..fancy::feature::Scheduled::default()
                    },
                )),
            },
        )
        .await;

    let (_, payload) = alice.recv_until(TEXT).await;
    let Some(fancy::feature::text_envelope::Body::Ack(ack)) =
        fancy::feature::TextEnvelope::decode(payload.as_slice())
            .expect("a well-formed TextEnvelope")
            .body
    else {
        panic!("scheduling was not acknowledged");
    };
    assert_eq!(
        ack.status,
        fancy::feature::ScheduleStatus::SchedulePending as i32,
        "refused: {}",
        ack.reason
    );
    assert!(!ack.schedule_id.is_empty(), "an ack names the message");

    // Both clients get it as ordinary channel text when it comes due, which is
    // the point: a scheduled message is a message, not a notification.
    for (who, client) in [("alice", &mut alice), ("bob", &mut bob)] {
        let (_, payload) = client.recv_until(11).await;
        let message = tcp::TextMessage::decode(payload.as_slice()).expect("a TextMessage");
        assert_eq!(message.message, "from the past", "{who}");
    }

    // And it has left the pending list, so a panel re-fetching after delivery
    // shows nothing.
    alice
        .send(
            TEXT,
            &fancy::feature::TextEnvelope {
                body: Some(fancy::feature::text_envelope::Body::Query(
                    fancy::feature::ScheduleQuery {
                        include_finished: false,
                    },
                )),
            },
        )
        .await;
    let (_, payload) = alice.recv_until(TEXT).await;
    let Some(fancy::feature::text_envelope::Body::List(list)) =
        fancy::feature::TextEnvelope::decode(payload.as_slice())
            .expect("a well-formed TextEnvelope")
            .body
    else {
        panic!("the query was not answered with a list");
    };
    assert!(
        list.messages.is_empty(),
        "a delivered message is not still pending"
    );

    deployment.stop().await;
}

#[tokio::test]
async fn a_scheduled_message_can_be_cancelled_and_then_never_arrives() {
    let data_dir = TempDir::new("scheduled-cancel");
    let deployment = Deployment::start(data_dir.path()).await;

    let mut alice = Client::connect_with_certificate(deployment.port, data_dir.path()).await;
    let _ = handshake_fancy(&mut alice, "alice").await;

    alice
        .send(
            TEXT,
            &fancy::feature::TextEnvelope {
                body: Some(fancy::feature::text_envelope::Body::Schedule(
                    fancy::feature::Scheduled {
                        channels: vec![0],
                        body: "never mind".to_owned(),
                        deliver_at_ms: starling_runtime::ids::now_ms() + 1_500,
                        ..fancy::feature::Scheduled::default()
                    },
                )),
            },
        )
        .await;
    let (_, payload) = alice.recv_until(TEXT).await;
    let Some(fancy::feature::text_envelope::Body::Ack(ack)) =
        fancy::feature::TextEnvelope::decode(payload.as_slice())
            .expect("a well-formed TextEnvelope")
            .body
    else {
        panic!("scheduling was not acknowledged");
    };
    assert_eq!(
        ack.status,
        fancy::feature::ScheduleStatus::SchedulePending as i32,
        "refused: {}",
        ack.reason
    );

    alice
        .send(
            TEXT,
            &fancy::feature::TextEnvelope {
                body: Some(fancy::feature::text_envelope::Body::Cancel(
                    fancy::feature::ScheduleCancel {
                        schedule_id: ack.schedule_id.clone(),
                    },
                )),
            },
        )
        .await;
    let (_, payload) = alice.recv_until(TEXT).await;
    let Some(fancy::feature::text_envelope::Body::Ack(cancelled)) =
        fancy::feature::TextEnvelope::decode(payload.as_slice())
            .expect("a well-formed TextEnvelope")
            .body
    else {
        panic!("the cancel was not acknowledged");
    };
    assert_eq!(
        cancelled.status,
        fancy::feature::ScheduleStatus::ScheduleCancelled as i32,
        "refused: {}",
        cancelled.reason
    );

    // Past the due time, with room for the timer's own granularity.
    let arrived = timeout(Duration::from_millis(3_000), async {
        loop {
            let (type_id, payload) = alice.recv().await;
            if type_id == 11
                && tcp::TextMessage::decode(payload.as_slice())
                    .is_ok_and(|message| message.message == "never mind")
            {
                return;
            }
        }
    })
    .await;
    assert!(arrived.is_err(), "a cancelled message was delivered anyway");

    deployment.stop().await;
}

/// A profile change is kept, for an admin to look back at.
///
/// The whole path: the user's own `UserState` through `session-lifecycle`, the
/// trail into `audit`, the copy kept beside the chain and trimmed to
/// `profile_history`, and an admin reading it back over the client channel.
#[tokio::test]
async fn an_admin_reads_back_a_comment_the_profile_history_kept() {
    use starling_proto_fancy::fancy::feature::{
        AuditEnvelope, Query, SnapshotQuery, Verify, audit_envelope,
    };
    use starling_proto_fancy::perm::Perm;
    use starling_proto_fancy::permissions::AclSet;
    use starling_proto_fancy::types::ServiceKind;

    let data_dir = TempDir::new("profile-history");
    let deployment = Deployment::start_with(data_dir.path(), |config| {
        assert!(
            !config.instances.is_empty(),
            "a deployment serves an instance"
        );
        for instance in &mut config.instances {
            instance.settings.profile_history = Some(2);
        }
    })
    .await;
    deployment
        .set_acl(AclSet {
            channel: 0,
            inherit: true,
            acls: vec![entry("all", Perm::WRITE, Perm::empty())],
            groups: Vec::new(),
        })
        .await;

    let mut alice = Client::connect(deployment.port).await;
    let session = handshake_fancy(&mut alice, "alice").await;
    deployment
        .wait_until_permitted(session, 0, Perm::WRITE.bits())
        .await;

    for comment in ["first", "second", "third"] {
        alice
            .send(
                9,
                &tcp::UserState {
                    comment: Some(format!("<b>{comment}</b>")),
                    ..tcp::UserState::default()
                },
            )
            .await;
        // The trail is spawned, so two changes sent back to back may reach
        // `audit` out of order; spacing them keeps "newest" meaning "last sent".
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let outer = ServiceKind::Audit.outer_type();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let records = loop {
        alice
            .send(
                outer,
                &AuditEnvelope {
                    body: Some(audit_envelope::Body::Query(Query {
                        category: "audit.profile".to_owned(),
                        query_id: "profile".to_owned(),
                        ..Query::default()
                    })),
                },
            )
            .await;
        let page = loop {
            let (type_id, payload) = alice.recv().await;
            if type_id != outer {
                continue;
            }
            if let Some(audit_envelope::Body::Page(page)) =
                AuditEnvelope::decode(payload.as_slice())
                    .expect("an envelope")
                    .body
            {
                break page;
            }
        };
        if page.records.len() >= 3 {
            break page.records;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the comment changes never reached the audit log: {:?}",
            page.records
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    assert_eq!(records.len(), 3, "{records:?}");
    assert!(records.iter().all(|r| r.action == "comment changed"));
    assert_eq!(
        records.iter().map(|r| r.has_snapshot).collect::<Vec<_>>(),
        vec![true, true, false],
        "two copies kept, the oldest trimmed: {records:?}"
    );
    assert!(records[0].detail.contains("snapshot sha256:"));

    let mut snapshot_of = async |id: &str| {
        alice
            .send(
                outer,
                &AuditEnvelope {
                    body: Some(audit_envelope::Body::SnapshotQuery(SnapshotQuery {
                        entry_id: id.to_owned(),
                        query_id: id.to_owned(),
                    })),
                },
            )
            .await;
        loop {
            let (type_id, payload) = alice.recv().await;
            if type_id != outer {
                continue;
            }
            if let Some(audit_envelope::Body::Snapshot(snapshot)) =
                AuditEnvelope::decode(payload.as_slice())
                    .expect("an envelope")
                    .body
                && snapshot.query_id == id
            {
                break snapshot;
            }
        }
    };
    let newest = snapshot_of(&records[0].id).await;
    assert!(newest.found);
    assert_eq!(newest.kind, "comment");
    assert_eq!(newest.body, b"<b>third</b>");
    let oldest = snapshot_of(&records[2].id).await;
    assert!(!oldest.found, "a trimmed copy is reported gone, not served");

    alice
        .send(
            outer,
            &AuditEnvelope {
                body: Some(audit_envelope::Body::Verify(Verify {
                    query_id: "verify".to_owned(),
                })),
            },
        )
        .await;
    let verified = loop {
        let (type_id, payload) = alice.recv().await;
        if type_id != outer {
            continue;
        }
        if let Some(audit_envelope::Body::VerifyResult(result)) =
            AuditEnvelope::decode(payload.as_slice())
                .expect("an envelope")
                .body
        {
            break result;
        }
    };
    assert!(verified.intact, "kept copies must verify: {verified:?}");

    deployment.stop().await;
}
