//! Fault injection: what a deployment does when one of its parts stops.
//!
//! Stage 7 of `docs/RELIABILITY.md`, the in-process half. The soak next door
//! asks whether a healthy server stays healthy; this asks whether a damaged one
//! comes back. The two share the harness and nothing else.
//!
//! The fault modelled here is a service that *stopped* -- panicked, was
//! OOM-killed, lost its runtime -- not one that was asked to leave.
//! [`Deployment::restart`] aborts the task rather than draining it, because a
//! service given the chance to finish its work is a different, easier fault.

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

/// The service that cannot be restarted, and why.
///
/// `voice` drains, `run` returns, and its UDP port is **still bound**, so the
/// replacement fails to build with `Address already in use` and never comes
/// back -- `serve::run` does not retry a construction that failed, and a
/// service that cannot construct has nothing to supervise.
///
/// What holds it is not `voice`. A drained service waits `listen::DRAIN_GRACE`
/// for its connections and then returns anyway, but the per-connection tasks
/// under `serve_with_incoming_shutdown` are hyper's, spawned and detached; each
/// one holds the `Routes`, which hold the `Arc<VoiceService>`, which holds the
/// socket. They end when the *caller* closes the stream, and the caller here is
/// the gateway, which is not the thing being restarted. Measured: the service is
/// dropped, but only when the whole deployment drains.
///
/// So this is not `voice`'s bug and not a missing `abort` anywhere. It is that
/// nothing owns a service's inbound connections, and the fix is for
/// `listen::serve_routes` to hold them itself -- an accept loop over a
/// `JoinSet` it can cut off at the deadline it already logs about. Two
/// consequences, this one and a quieter one: every restart leaks the instance
/// before it, with its database pool, until the process exits.
///
/// Recorded in `docs/RELIABILITY.md` as defect 23. Ignored rather than deleted,
/// because it is the reproduction, and it passes the day that lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "defect 23: a drained service is still held by its callers' connections"]
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
/// A service that can be restarted but forgets the deployment's state is not
/// restartable in any sense a supervisor cares about. The answer is for
/// `session-lifecycle` to re-publish on a subscriber it has not seen before,
/// which is the same reconnect the gateway already does for its own streams.
///
/// Recorded in `docs/RELIABILITY.md` as defect 24. Twelve seconds, and it is
/// the reproduction, so it is ignored rather than deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "defect 24: a restarted session-view starts empty and nobody refills it"]
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
    let after = relayed(&mut alice, alice_session, &mut bob, "after").await;

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
/// Two units are excluded. The gateway owns the client sockets, so stopping it
/// disconnects everyone by construction; that it does is not a finding, and
/// what *should* happen afterwards is a resume test rather than this one.
/// `voice` is excluded because it cannot be restarted at all yet -- see
/// [`voice_can_be_restarted`], which is that defect's reproduction. Every other
/// service comes back, because the only thing they bind is a socket whose path
/// the harness unlinks; `voice` also owns a UDP port, which is what makes it
/// the one that shows the problem.
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
        .filter(|name| *name != "gateway" && *name != "voice")
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
