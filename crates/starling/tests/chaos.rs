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

    let after = relayed_within(&mut alice, alice_session, &mut bob, "after").await;

    deployment.stop().await;
    assert!(
        after,
        "a message no longer crossed the server after `session-view` restarted"
    );
}

/// Tell the server both clients are still there.
///
/// `session-lifecycle` disconnects a connection it has heard nothing from for
/// thirty seconds, and a chat message is not heard from: `TextMessage` is
/// routed to `text`, so the frame never reaches the service holding the
/// deadline. A test that keeps a client past thirty seconds must therefore ping
/// even while it is talking, which `soak/drive.rs` documents and does for the
/// same reason.
///
/// This is not incidental to the sweep, it is what makes it honest. Restarting
/// `session-lifecycle` empties the map the reaper reads, so the *unpinged*
/// version of this test survived by being forgotten -- the clients lived
/// because the service that would have reaped them no longer knew they existed.
/// Pinging is what lets the sweep hold `session-lifecycle` out, keep a working
/// reaper, and still run for a minute.
///
/// Exempt from the rate limiter, so it costs the relay's allowance nothing.
async fn keepalive(clients: [&mut Client; 2]) {
    for client in clients {
        client.send(3, &tcp::Ping::default()).await;
    }
}

/// [`relayed`], retried until it works or [`REPAIR`] runs out.
///
/// A service that comes back empty is repaired on `session-lifecycle`'s sweep,
/// and a restart lands at an arbitrary point in one. Asking once would assert
/// where in the tick the restart happened to fall; asking until the deadline
/// asserts that the server heals, which is the property. It costs nothing when
/// nothing is broken, because the first attempt answers in milliseconds.
async fn relayed_within(from: &mut Client, sender: u32, to: &mut Client, tag: &str) -> bool {
    let deadline = tokio::time::Instant::now() + REPAIR;
    loop {
        if relayed(from, sender, to, tag).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
    }
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

/// A restarted `session-lifecycle` cannot repair a `session-view` restarted after it.
///
/// `Connections` is a `HashMap` in this service's memory and there is no store
/// behind it, so an instance that has just started holds nobody. On its own
/// that is survivable: the view still has the roster, and this probe measures
/// that the relay does still cross straight after.
///
/// What is not survivable is the pair. [`Handshake::reconcile_view`] repairs a
/// restarted view by re-announcing what *this* service is holding, and it is
/// the only path that can, so once this service is the empty one the repair is
/// a no-op and the next `session-view` restart takes routing down for good.
/// The sweep found it that way round: `session-lifecycle` is the first unit in
/// `units.rs`, so it restarted first, and every service after `session-view`
/// then failed too.
///
/// Neither of these two is authoritative about who is connected -- the gateway
/// owns the sockets -- so refilling this service from the view would copy a
/// cache back into the thing that feeds it, and a client the gateway has since
/// dropped would become a ghost re-announced forever. The fix belongs on the
/// gateway, which knows.
///
/// Recorded in `docs/RELIABILITY.md` as defect 25. Thirty seconds, and it is
/// the reproduction, so it is ignored rather than deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "defect 25: a restarted session-lifecycle can no longer repair the view"]
async fn a_restarted_session_lifecycle_can_still_repair_a_restarted_view() {
    let dir = TempDir::new("chaos-lifecycle");
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

    // Survivable alone, and asserted rather than assumed: it is what makes the
    // failure below specific to the pair rather than to this restart.
    deployment.restart("session-lifecycle").await;
    assert!(
        relayed_within(&mut alice, alice_session, &mut bob, "after-lifecycle").await,
        "restarting `session-lifecycle` alone must not stop the server routing"
    );

    deployment.restart("session-view").await;
    keepalive([&mut alice, &mut bob]).await;
    let after = relayed_within(&mut alice, alice_session, &mut bob, "after-view").await;

    deployment.stop().await;
    assert!(
        after,
        "a message no longer crossed the server after `session-view` restarted \
         behind a `session-lifecycle` that had restarted first"
    );
}

/// Services this sweep does not restart, and why each one is out.
///
/// `gateway` owns the client sockets, so stopping it disconnects everyone by
/// construction. `session-lifecycle` is defect 25: it holds the only copy of
/// who is connected, an instance that has just started holds nobody, and after
/// that it can no longer repair a restarted `session-view` -- so leaving it in
/// makes every later service in the list fail for one defect that is not
/// theirs, which is the whole reason this list exists.
/// [`a_restarted_session_lifecycle_can_still_repair_a_restarted_view`] is that
/// failure on its own in thirty seconds instead.
const EXCLUDED: [&str; 2] = ["gateway", "session-lifecycle"];

/// Restart every service in turn, with two clients connected throughout.
///
/// One at a time, and after each: the service bound its endpoint again, the
/// deployment describes itself again, and a message still crosses from one
/// client to the other. Twenty services stopped and started under two live
/// connections, with the server still doing its job between each.
///
/// The relay is the assertion worth having, and it subsumes the weaker one this
/// started with. It goes through the gateway, `session-view`'s roster,
/// `permissions`, `text` and the fan-out, so a client that was hung up on and a
/// server that forgot how to route both fail it, and neither can pass by
/// accident. It also avoids `Client::closed_by_server`, which reads raw bytes
/// and would leave these clients mid-frame for the next iteration.
///
/// Two services are held out, for the reasons on [`EXCLUDED`]. For the gateway
/// that is by construction: it owns the client sockets, so stopping it
/// disconnects everyone; that it does is not a finding, and
/// what *should* happen afterwards is a resume test rather than this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_service_can_be_restarted_without_dropping_a_client() {
    let dir = TempDir::new("chaos-restart");
    let mut deployment = Deployment::start(dir.path()).await;

    let mut alice = Client::connect(deployment.port).await;
    let alice_session = handshake(&mut alice, "alice").await;
    let mut bob = Client::connect(deployment.port).await;
    let _bob_session = handshake(&mut bob, "bob").await;

    let services: Vec<&'static str> = deployment
        .services()
        .into_iter()
        .filter(|name| !EXCLUDED.contains(name))
        .collect();
    assert!(
        services.len() > 10,
        "a deployment with {} services is not the one this test is about",
        services.len()
    );

    // Collected rather than asserted in the loop, so one run names every
    // service that failed instead of stopping at the first.
    let mut lost_the_relay = Vec::new();

    for (round, name) in services.iter().enumerate() {
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

        keepalive([&mut alice, &mut bob]).await;

        // The real assertion. A message from one client reaching the other goes
        // through the gateway, `session-view`'s roster, `permissions`, `text`
        // and the fan-out, so it covers both halves at once: that neither
        // client was hung up on, and that the server still knows how to route
        // between two it never disconnected.
        let needle = format!("after-{round}-{name}");
        if !relayed_within(&mut alice, alice_session, &mut bob, &needle).await {
            lost_the_relay.push(*name);
        }
    }

    // Stopped before the assertion, so a chaos run that also panicked a service
    // reports the panic rather than only its symptom.
    deployment.stop().await;

    assert!(
        lost_the_relay.is_empty(),
        "after restarting these, a message no longer crossed the server between \
         two clients that were never disconnected: {lost_the_relay:?}"
    );
}
