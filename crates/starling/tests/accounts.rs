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
    AccountAck, AccountAction, UserdataEnvelope, account_action, userdata_envelope,
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
