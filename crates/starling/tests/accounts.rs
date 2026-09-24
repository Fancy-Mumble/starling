//! Accounts from the outside: logging in to one, and what its owner can do to
//! it from their own client.
//!
//! Its own binary rather than more of `e2e.rs`, which is about the wire and the
//! composition. These are about a person and their account, and they grow
//! together: a second factor, and the devices an account is used from.

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

use prost::Message as _;
use starling_harness::{
    Client, Deployment, FRAME_TIMEOUT, MUMBLE_VERSION_V2, TempDir, handshake_as,
    handshake_epoch1_as,
};
use starling_proto::proto::tcp;
use starling_proto_fancy::fancy::domain::{
    AccountAck, AccountAction, AccountQuery, AccountState, UserdataEnvelope, account_action,
    userdata_envelope,
};
use tokio::time::timeout;

/// Register an account that logs in with a password.
///
/// The harness's default client presents no certificate, so a password is the
/// proof it can actually offer. See `e2e.rs`, which has the same helper.
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

/// `Authenticate` for `name` with `password`, and nothing else.
fn credentials(name: &str, password: &str) -> tcp::Authenticate {
    tcp::Authenticate {
        username: Some(name.to_owned()),
        password: Some(password.to_owned()),
        opus: Some(true),
        ..tcp::Authenticate::default()
    }
}

/// Send one frame on the self-service envelope.
async fn send_userdata(client: &mut Client, body: userdata_envelope::Body) {
    let envelope = UserdataEnvelope { body: Some(body) };
    client
        .send_raw(starling_userdata::outer_type(), &envelope.encode_to_vec())
        .await;
}

/// The next self-service frame, skipping the rest of what the server says.
async fn next_userdata(client: &mut Client) -> userdata_envelope::Body {
    timeout(FRAME_TIMEOUT, async {
        loop {
            let (type_id, payload) = client.recv().await;
            if type_id != starling_userdata::outer_type() {
                continue;
            }
            let envelope =
                UserdataEnvelope::decode(payload.as_slice()).expect("a well-formed envelope");
            if let Some(body) = envelope.body {
                return body;
            }
        }
    })
    .await
    .expect("the self-service envelope answered")
}

/// The next acknowledgement, skipping the account snapshots sent beside it.
async fn next_ack(client: &mut Client) -> AccountAck {
    loop {
        if let userdata_envelope::Body::Ack(ack) = next_userdata(client).await {
            return ack;
        }
    }
}

/// The code an authenticator shows for `secret` right now.
fn current_code(secret: &[u8]) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past 1970")
        .as_secs();
    format!("{:06}", starling_userdata::secret::totp(secret, now / 30))
}

/// Send `Version` and `Authenticate`, and return the `Reject` the server
/// answers with.
async fn refused(client: &mut Client, authenticate: tcp::Authenticate) -> tcp::Reject {
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
    client.send(2, &authenticate).await;
    let (_, payload) = client.recv_until(4).await;
    tcp::Reject::decode(payload.as_slice()).expect("a well-formed Reject")
}

#[tokio::test]
async fn an_account_with_a_second_factor_can_still_log_in_with_its_code() {
    // The code travels in `Authenticate.totp_code`, the fork's field 1000, and
    // the handshake used to send userdata an empty string in its place. Every
    // account that turned a second factor on was answered "a code is required"
    // on every login, including the ones that had just typed it, and had no way
    // back in: turning it off again is a self-service action, which needs a
    // session.
    let data_dir = TempDir::new("totp-login");
    let deployment = Deployment::start(data_dir.path()).await;
    let _ = register_with_password(&deployment, "alice", "pw").await;

    // Enrol through the owner's own client, the way a user does: ask for a
    // secret, then prove the authenticator has it.
    let mut owner = Client::connect(deployment.port).await;
    let _ = handshake_epoch1_as(&mut owner, credentials("alice", "pw")).await;
    send_userdata(
        &mut owner,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::EnableTotp as i32,
            current_password: "pw".to_owned(),
            ..AccountAction::default()
        }),
    )
    .await;
    let issued = next_ack(&mut owner).await;
    assert!(issued.ok, "enrolment refused: {}", issued.detail);
    let secret =
        starling_userdata::secret::from_base32(&issued.totp_secret).expect("a base32 secret");
    send_userdata(
        &mut owner,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::EnableTotp as i32,
            current_password: "pw".to_owned(),
            totp: current_code(&secret),
            ..AccountAction::default()
        }),
    )
    .await;
    let confirmed = next_ack(&mut owner).await;
    assert!(confirmed.ok, "confirmation refused: {}", confirmed.detail);

    // Without the code: refused, and told what is missing.
    let mut forgetful = Client::connect(deployment.port).await;
    let reject = refused(&mut forgetful, credentials("alice", "pw")).await;
    assert_eq!(
        reject.r#type,
        Some(tcp::reject::RejectType::TotpRequired as i32),
        "a login without the code has to be asked for it"
    );

    // With it: in. The bug was that this was refused exactly like the above.
    let mut returning = Client::connect(deployment.port).await;
    let session = handshake_as(
        &mut returning,
        tcp::Authenticate {
            totp_code: Some(current_code(&secret)),
            ..credentials("alice", "pw")
        },
        None,
    )
    .await;
    assert_ne!(session, 0);

    deployment.stop().await;
}

/// `Authenticate` for `name` from the install called `device`.
fn from_device(name: &str, password: &str, device: &str) -> tcp::Authenticate {
    tcp::Authenticate {
        device_id: Some(device.to_owned()),
        device_secret: Some(format!("{device}-secret-0123456789abcdef0123456789")),
        device_name: Some(device.to_owned()),
        ..credentials(name, password)
    }
}

/// What the server holds about the caller's own account, asked for now.
async fn account_state(client: &mut Client) -> AccountState {
    send_userdata(
        client,
        userdata_envelope::Body::AccountQuery(AccountQuery {}),
    )
    .await;
    loop {
        if let userdata_envelope::Body::Account(state) = next_userdata(client).await {
            return state;
        }
    }
}

/// The account's devices as `(id, online)`, in id order.
fn listed(state: &AccountState) -> Vec<(String, bool)> {
    let mut devices: Vec<(String, bool)> = state
        .devices
        .iter()
        .map(|device| (device.id.clone(), device.online))
        .collect();
    devices.sort();
    devices
}

/// How long a session is watched for an eviction that must not come.
const NO_EVICTION: std::time::Duration = std::time::Duration::from_secs(2);

#[tokio::test]
async fn one_account_is_online_from_two_devices_at_once() {
    // The reason devices exist. A second login of one account used to be read
    // as the first one reconnecting, so the laptop was evicted as a ghost the
    // moment the phone connected, and the phone the moment the laptop
    // reconnected, and so on for as long as both were on.
    let data_dir = TempDir::new("two-devices");
    let deployment = Deployment::start(data_dir.path()).await;
    let _ = register_with_password(&deployment, "alice", "pw").await;

    let mut laptop = Client::connect(deployment.port).await;
    let (laptop_session, _) =
        handshake_epoch1_as(&mut laptop, from_device("alice", "pw", "laptop")).await;
    let mut phone = Client::connect(deployment.port).await;
    let (phone_session, _) =
        handshake_epoch1_as(&mut phone, from_device("alice", "pw", "phone")).await;
    assert_ne!(laptop_session, phone_session);

    assert!(
        laptop
            .next_removal_of(laptop_session, NO_EVICTION)
            .await
            .is_none(),
        "the laptop was evicted as a ghost of the phone"
    );

    // Both are the owner's, both are online, and each knows which it is.
    let seen_from_laptop = account_state(&mut laptop).await;
    assert_eq!(seen_from_laptop.this_device, "laptop");
    assert_eq!(
        listed(&seen_from_laptop),
        vec![("laptop".to_owned(), true), ("phone".to_owned(), true)]
    );

    // The same device coming back is still a reconnect, and still replaces its
    // own ghost: that rule is untouched, it just no longer fires across
    // devices.
    let mut laptop_again = Client::connect(deployment.port).await;
    let _ = handshake_epoch1_as(&mut laptop_again, from_device("alice", "pw", "laptop")).await;
    let removal = laptop
        .next_removal_of(laptop_session, FRAME_TIMEOUT)
        .await
        .expect("the laptop's ghost is told it was replaced");
    assert!(
        removal
            .reason
            .unwrap_or_default()
            .contains("another device"),
        "a ghost is told why"
    );
    assert_eq!(account_state(&mut phone).await.this_device, "phone");

    deployment.stop().await;
}

#[tokio::test]
async fn a_device_signed_out_from_another_is_disconnected_and_kept_out() {
    let data_dir = TempDir::new("sign-out-device");
    let deployment = Deployment::start(data_dir.path()).await;
    let _ = register_with_password(&deployment, "alice", "pw").await;

    let mut laptop = Client::connect(deployment.port).await;
    let _ = handshake_epoch1_as(&mut laptop, from_device("alice", "pw", "laptop")).await;
    let mut phone = Client::connect(deployment.port).await;
    let (phone_session, _) =
        handshake_epoch1_as(&mut phone, from_device("alice", "pw", "phone")).await;

    // Taking something away needs the password, like every other change that
    // could lock the owner out.
    send_userdata(
        &mut laptop,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::RemoveDevice as i32,
            current_password: "not it".to_owned(),
            device_id: "phone".to_owned(),
            ..AccountAction::default()
        }),
    )
    .await;
    assert!(!next_ack(&mut laptop).await.ok);

    send_userdata(
        &mut laptop,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::RemoveDevice as i32,
            current_password: "pw".to_owned(),
            device_id: "phone".to_owned(),
            ..AccountAction::default()
        }),
    )
    .await;
    let ack = next_ack(&mut laptop).await;
    assert!(ack.ok, "sign-out refused: {}", ack.detail);

    // The phone is told why and then goes, rather than seeing its link drop
    // and dialling straight back in.
    let removal = phone
        .next_removal_of(phone_session, FRAME_TIMEOUT)
        .await
        .expect("the signed-out device is told why");
    assert_eq!(
        removal.reason.as_deref(),
        Some(starling_userdata::selfservice::SIGNED_OUT_REASON)
    );
    assert!(phone.closed_by_server(FRAME_TIMEOUT).await);

    // It still has the password, and it is still refused: by id.
    let mut back = Client::connect(deployment.port).await;
    let reject = refused(&mut back, from_device("alice", "pw", "phone")).await;
    assert_eq!(
        reject.r#type,
        Some(tcp::reject::RejectType::DeviceNotTrusted as i32)
    );

    let state = account_state(&mut laptop).await;
    assert_eq!(listed(&state), vec![("laptop".to_owned(), true)]);
    assert!(state.devices_locked);

    // A device cannot sign itself out; that is what disconnecting is.
    send_userdata(
        &mut laptop,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::RemoveDevice as i32,
            current_password: "pw".to_owned(),
            device_id: "laptop".to_owned(),
            ..AccountAction::default()
        }),
    )
    .await;
    assert!(!next_ack(&mut laptop).await.ok);

    deployment.stop().await;
}

/// The next `TextMessage`, skipping everything else.
async fn next_text(client: &mut Client) -> tcp::TextMessage {
    timeout(FRAME_TIMEOUT, async {
        loop {
            let (type_id, payload) = client.recv().await;
            if type_id == 11 {
                return tcp::TextMessage::decode(payload.as_slice())
                    .expect("a well-formed TextMessage");
            }
        }
    })
    .await
    .expect("a text message arrived")
}

#[tokio::test]
async fn a_direct_message_reaches_every_device_on_both_ends() {
    // A direct message names a *session*, and a person on two devices is two
    // sessions. Delivered to the one named, it reached whichever device the
    // sender happened to pick and never the one its recipient was holding;
    // and the sender's other device never learned what they had said.
    let data_dir = TempDir::new("dm-devices");
    let deployment = Deployment::start(data_dir.path()).await;
    let _ = register_with_password(&deployment, "alice", "pw").await;

    let mut laptop = Client::connect(deployment.port).await;
    let (laptop_session, _) =
        handshake_epoch1_as(&mut laptop, from_device("alice", "pw", "laptop")).await;
    let mut phone = Client::connect(deployment.port).await;
    let _ = handshake_epoch1_as(&mut phone, from_device("alice", "pw", "phone")).await;
    let mut bob = Client::connect(deployment.port).await;
    let bob_session = starling_harness::handshake(&mut bob, "bob").await;

    // Bob writes to the laptop's session; the phone has it too.
    bob.send(
        11,
        &tcp::TextMessage {
            session: vec![laptop_session],
            message: "to alice".to_owned(),
            ..tcp::TextMessage::default()
        },
    )
    .await;
    assert_eq!(next_text(&mut laptop).await.message, "to alice");
    let on_phone = next_text(&mut phone).await;
    assert_eq!(on_phone.message, "to alice");
    assert_eq!(on_phone.actor, Some(bob_session));

    // Alice answers from the laptop; Bob has it, and so does her phone.
    laptop
        .send(
            11,
            &tcp::TextMessage {
                session: vec![bob_session],
                message: "from alice".to_owned(),
                ..tcp::TextMessage::default()
            },
        )
        .await;
    assert_eq!(next_text(&mut bob).await.message, "from alice");
    let copy = next_text(&mut phone).await;
    assert_eq!(copy.message, "from alice");
    assert_eq!(copy.actor, Some(laptop_session));
    assert_eq!(
        copy.session,
        vec![bob_session],
        "the copy still says who it was to, which is how the phone files it"
    );

    deployment.stop().await;
}

/// The next record answer, skipping everything else on the envelope.
async fn next_record(client: &mut Client) -> starling_proto_fancy::fancy::domain::Record {
    loop {
        if let userdata_envelope::Body::Record(record) = next_userdata(client).await {
            return record;
        }
    }
}

#[tokio::test]
async fn a_linked_device_logs_in_once_on_its_code_and_then_like_the_account() {
    // Linking: the laptop registers the phone ahead and leaves it a sealed
    // parcel in the account's records. The phone has no certificate and no
    // password yet, so its first login rests on the code alone - and only its
    // first: after that it is a device of a password account like any other.
    let data_dir = TempDir::new("link-device");
    let deployment = Deployment::start(data_dir.path()).await;
    let _ = register_with_password(&deployment, "alice", "pw").await;

    let mut laptop = Client::connect(deployment.port).await;
    let _ = handshake_epoch1_as(&mut laptop, from_device("alice", "pw", "laptop")).await;
    let phone_creds = from_device("alice", "", "phone");
    send_userdata(
        &mut laptop,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::AddDevice as i32,
            value: "New device".to_owned(),
            device_id: "phone".to_owned(),
            device_secret: phone_creds.device_secret.clone().unwrap_or_default(),
            ..AccountAction::default()
        }),
    )
    .await;
    let ack = next_ack(&mut laptop).await;
    assert!(ack.ok, "registering ahead refused: {}", ack.detail);
    send_userdata(
        &mut laptop,
        userdata_envelope::Body::RecordPut(starling_proto_fancy::fancy::domain::RecordPut {
            request_id: "1".to_owned(),
            key: "link/phone".to_owned(),
            value: b"sealed".to_vec(),
            remove: false,
        }),
    )
    .await;
    assert!(next_record(&mut laptop).await.found);

    // The phone: no password, no certificate, only what the code gave it.
    let mut phone = Client::connect(deployment.port).await;
    let _ = handshake_epoch1_as(
        &mut phone,
        tcp::Authenticate {
            password: None,
            ..phone_creds.clone()
        },
    )
    .await;
    send_userdata(
        &mut phone,
        userdata_envelope::Body::RecordGet(starling_proto_fancy::fancy::domain::RecordGet {
            request_id: "2".to_owned(),
            key: "link/phone".to_owned(),
        }),
    )
    .await;
    assert_eq!(next_record(&mut phone).await.value, b"sealed");
    let state = account_state(&mut phone).await;
    assert_eq!(state.this_device, "phone");
    assert!(
        state
            .devices
            .iter()
            .any(|device| device.id == "phone" && device.name == "phone"),
        "the phone names itself on its first login"
    );

    // Once only. From now on the phone logs in the way the account does.
    let mut again = Client::connect(deployment.port).await;
    let reject = refused(
        &mut again,
        tcp::Authenticate {
            password: None,
            ..phone_creds
        },
    )
    .await;
    assert_eq!(
        reject.r#type,
        Some(tcp::reject::RejectType::WrongUserPw as i32)
    );

    // A link nobody completed is withdrawn without the password, and does not
    // lock the account the way signing a device out does.
    send_userdata(
        &mut laptop,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::AddDevice as i32,
            value: "New device".to_owned(),
            device_id: "tablet".to_owned(),
            device_secret: "tablet-secret-0123456789abcdef0123456789".to_owned(),
            ..AccountAction::default()
        }),
    )
    .await;
    assert!(next_ack(&mut laptop).await.ok);
    send_userdata(
        &mut laptop,
        userdata_envelope::Body::Action(AccountAction {
            kind: account_action::Kind::RemoveDevice as i32,
            device_id: "tablet".to_owned(),
            ..AccountAction::default()
        }),
    )
    .await;
    let withdrawn = next_ack(&mut laptop).await;
    assert!(withdrawn.ok, "withdrawing refused: {}", withdrawn.detail);
    let state = account_state(&mut laptop).await;
    assert!(!state.devices_locked);
    assert!(state.devices.iter().all(|device| device.id != "tablet"));

    deployment.stop().await;
}
