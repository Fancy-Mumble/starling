//! Fault injection: what a deployment does when one of its parts stops.
//!
//! Stage 7 of `docs/RELIABILITY.md`, the in-process half. The soak next door
//! asks whether a healthy server stays healthy; this asks whether a damaged one
//! comes back. The two share the harness and nothing else.
//!
//! The fault modelled here is a service that *went away and came back*, which
//! is what a supervisor does to one it has decided is unhealthy.
//! [`Deployment::restart`] drains it rather than aborting the task, and not
//! because draining is gentler: aborting does not work. A service's `run`
//! spawns tasks of its own, `tokio::spawn` detaches them, and cancelling `run`
//! leaves every one of them holding what the service had bound. Draining is
//! the only way to stop one service, which is why each has a drain of its own.

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

use std::time::Duration;

use prost::Message as _;
use starling_harness::{Client, Deployment, TempDir, handshake};
use starling_proto::proto::tcp;

/// How long to wait for a close that must not come.
///
/// Short on purpose. This is paid once per service and it is asserting the
/// *absence* of an event, so the only thing a longer wait buys is a slower
/// suite; a disconnect caused by the kill arrives immediately or not at all.
const NOT_CLOSED: Duration = Duration::from_millis(200);

/// How long a message may take to cross a server whose parts are restarting.
///
/// Longer than the same wait in `e2e.rs`, because the transport between two
/// services dials lazily and the first request after a kill pays a reconnect.
const RELAY: Duration = Duration::from_secs(5);

/// How long the server may take to notice a service came back empty.
///
/// Four of `session-lifecycle`'s five-second sweeps, which is what re-announces
/// the roster a restarted `session-view` is missing.
const REPAIR: Duration = Duration::from_secs(20);

/// How long the health collector may take to describe the deployment again.
///
/// Three of its own five-second sweeps. A restarted collector knows nothing
/// until it has polled, and this is a chaos run: the machine is busy.
const SWEEP: Duration = Duration::from_secs(15);

/// Whether `client` receives a text message carrying `needle` within `within`.
///
/// Drains rather than reading one frame: a restart makes the server push
/// unrelated state, and asserting on the very next frame would fail for a
/// notification the test is not about.
async fn heard_text(client: &mut Client, needle: &str, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
        && let Some((kind, payload)) = client.next_frame(remaining).await
    {
        if kind == 11
            && let Ok(text) = tcp::TextMessage::decode(payload.as_slice())
            && text.message.contains(needle)
        {
            return true;
        }
    }
    false
}

/// The service with something a second instance cannot share.
///
/// `voice` is the one that binds more than a socket whose path the harness can
/// unlink: it owns a UDP port, so a restart that leaves the old instance alive
/// anywhere fails here and nowhere else. It is the reproduction for defect 23,
/// and the reason that defect was found at all.
///
/// It used to fail with `Address already in use`. A drained service waited
/// `listen::DRAIN_GRACE` for its connections and returned anyway, but under
/// `serve_with_incoming_shutdown` the per-connection tasks were hyper's,
/// spawned and detached; each held the `Routes`, and so an `Arc` to the
/// service, and so its socket. They ended when the *caller* closed the stream,
/// and the caller was the gateway, which is not the thing being restarted.
/// `listen::serve_routes` now runs its own accept loop and can close them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voice_can_be_restarted() {
    let dir = TempDir::new("chaos-voice");
    let mut deployment = Deployment::start(dir.path()).await;
    deployment.restart("voice").await;
    deployment.stop().await;
}

/// Restarting one service, and a message that no longer crosses the server.
///
/// The narrow reproduction of what the sweep below found. Two clients who never
/// disconnected, and who could hear each other a moment earlier, cannot once
/// `session-view` has come back: it holds who is connected in memory, starts
/// empty, and nothing re-publishes the sessions that already exist, so the
/// server routes their messages to a roster of nobody. The sweep sees it as
/// every later restart failing too, because it never recovers.
///
/// Not defect 23, which was the obvious suspect: a new `session-view` is
/// refilled by whoever next announces or re-subscribes, and while the old
/// instance's connections outlived it nobody did either. Measured after 23 was
/// fixed and `voice_can_be_restarted` went green, this still fails, so the two
/// are separate. What is left is that `session-lifecycle` has no path for a
/// subscriber it has not seen before, only announcements as sessions change.
///
/// Recorded in `docs/RELIABILITY.md` as defect 24. Twelve seconds, and it is
/// the reproduction, so it is ignored rather than deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_session_view_still_routes_a_message() {
    let dir = TempDir::new("chaos-view");
    let mut deployment = Deployment::start(dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _bob_session = handshake(&mut bob, "bob").await;

    // Once before, so the failure below cannot be "these two never could".
    assert!(
        relayed(&mut alice, alice_session, &mut bob, "before").await,
        "the two clients must be able to hear each other to begin with"
    );

    deployment.restart("session-view").await;

    // Retried, because the repair is on `session-lifecycle`'s sweep and the
    // restart lands at an arbitrary point in it. What is being asserted is that
    // the server heals, not how many milliseconds it takes; a single attempt
    // here would be a test of where in the tick the restart happened to fall.
    let deadline = tokio::time::Instant::now() + REPAIR;
    let mut after = false;
    while !after && tokio::time::Instant::now() < deadline {
        after = relayed(&mut alice, alice_session, &mut bob, "after").await;
    }

    deployment.stop().await;
    assert!(
        after,
        "a message no longer crossed the server after `session-view` restarted"
    );
}

/// Send from `from` and wait for `to` to hear it.
async fn relayed(from: &mut Client, sender: u32, to: &mut Client, tag: &str) -> bool {
    from.send(
        11,
        &tcp::TextMessage {
            actor: Some(sender),
            channel_id: vec![0],
            message: tag.to_owned(),
            ..tcp::TextMessage::default()
        },
    )
    .await;
    heard_text(to, tag, RELAY).await
}

/// Restart every service in turn, with two clients connected throughout.
///
/// One at a time, and after each: the service bound its endpoint again, the
/// deployment describes itself again, and neither client was disconnected.
/// Twenty services stopped and started under a live connection, and nobody is
/// hung up on.
///
/// **Not asserted here: that the server still routes between them.** It does
/// not, from `session-view` onwards, and
/// [`a_restarted_session_view_still_routes_a_message`] is that failure on its
/// own in twelve seconds rather than as nineteen entries in a list. Asserting
/// it twice would mean this test fails for a defect it is not about, and every
/// other thing it checks would stop being run.
///
/// The gateway is excluded. It owns the client sockets, so stopping it
/// disconnects everyone by construction; that it does is not a finding, and
/// what *should* happen afterwards is a resume test rather than this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_service_can_be_restarted_without_dropping_a_client() {
    let dir = TempDir::new("chaos-restart");
    let mut deployment = Deployment::start(dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let _alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _bob_session = handshake(&mut bob, "bob").await;

    let services: Vec<&'static str> = deployment
        .services()
        .into_iter()
        .filter(|name| *name != "gateway")
        .collect();
    assert!(
        services.len() > 10,
        "a deployment with {} services is not the one this test is about",
        services.len()
    );

    // Collected rather than asserted in the loop, so one run names every
    // service that failed instead of stopping at the first.
    let mut dropped_a_client = Vec::new();

    for name in &services {
        deployment.restart(name).await;

        // The collector polls every service, so this is the cheapest
        // whole-server liveness there is.
        //
        // Given a sweep to answer, not asked once. A restarted collector starts
        // with an empty view and fills it on its own five-second timer, so
        // asserting on the first reply after restarting `health` itself failed
        // for a server that was perfectly well -- the collector had simply not
        // looked yet.
        let described = tokio::time::Instant::now() + SWEEP;
        while deployment.overview().await.services.is_empty() {
            assert!(
                tokio::time::Instant::now() < described,
                "the health collector still described nothing {SWEEP:?} after {name} restarted"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        if alice.closed_by_server(NOT_CLOSED).await || bob.closed_by_server(NOT_CLOSED).await {
            dropped_a_client.push(*name);
        }
    }

    // Stopped before the assertion, so a chaos run that also panicked a service
    // reports the panic rather than only its symptom.
    deployment.stop().await;

    assert!(
        dropped_a_client.is_empty(),
        "restarting these disconnected a client that was already connected: \
         {dropped_a_client:?}"
    );
}
