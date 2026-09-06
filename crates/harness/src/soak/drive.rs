//! Running a [`Scenario`] against a live deployment.
//!
//! One task per virtual client, each on its own loop with its own stream from
//! the seeded generator, plus a sampler on the main task. Clients never share a
//! generator: that would make the run depend on task scheduling order and the
//! printed seed would stop reproducing anything.
//!
//! Deliberately tolerant of a client failing. A soak's verdict comes from the
//! sampler, and a virtual client that loses its connection because the server
//! refused it is a *measurement*, counted and reported, not a panic that ends
//! the run twenty minutes before its most informative sample.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use starling_proto::proto::tcp;

use super::assess::{Failure, Report, assess};
use super::sample::Phase;
use super::scenario::{Rng, Scenario};
use super::{Sampler, sample};
use crate::{Client, Deployment, handshake};

/// How often a virtual client pings.
///
/// Five seconds, as a real Mumble client does, against a server that reaps at
/// thirty. The margin is what keeps a scheduling hiccup on a loaded runner from
/// reading as a disconnect.
const KEEPALIVE: Duration = Duration::from_secs(5);

/// How many clients are connected right now, and what went wrong so far.
///
/// Shared between every client task and the sampler, so a sample's `clients`
/// is the count at the instant of the read rather than the population the
/// scenario asked for. The two differ during warm-up and during a reconnect,
/// which is exactly when the descriptor bound is tightest.
#[derive(Debug, Default)]
pub struct Live {
    connected: AtomicU64,
    /// Clients that failed to connect or were disconnected unexpectedly.
    ///
    /// Reported rather than asserted here: whether a refusal is a fault depends
    /// on the scenario, and a hostile one expects many.
    lost: AtomicU64,
    stopping: AtomicBool,
}

impl Live {
    /// How many virtual clients are connected.
    #[must_use]
    pub fn connected(&self) -> u64 {
        self.connected.load(Ordering::Relaxed)
    }

    /// How many lost their connection unexpectedly.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.lost.load(Ordering::Relaxed)
    }

    /// Whether the run has asked its clients to leave.
    #[must_use]
    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }
}

/// One virtual client's whole life: connect, act, leave.
///
/// Returns rather than panicking. See the module note: a lost client is a
/// number in the report, not the end of the run.
async fn live_one(port: u16, id: u64, channels: Arc<[u32]>, mut rng: Rng, live: Arc<Live>) {
    // Arrivals spread over the warm-up rather than all at once: a thundering
    // herd measures admission control, which is a different test.
    tokio::time::sleep(rng.delay(Duration::from_millis(200 * (id % 64 + 1)))).await;
    if live.stopping() {
        return;
    }

    let mut client = Client::connect(port).await;
    let session = handshake(&mut client, &format!("soak-{id}")).await;
    let _was = live.connected.fetch_add(1, Ordering::Relaxed);

    let mut next_join = Instant::now();
    let mut next_chat = Instant::now();
    let mut next_ping = Instant::now();

    while !live.stopping() {
        let now = Instant::now();

        // The keepalive a real client sends, and the reason this loop cannot
        // be driven by its Poisson timers alone: those average ninety and sixty
        // seconds, and `session-lifecycle` disconnects a connection that has
        // said nothing for thirty. Without this the whole population is reaped
        // during the steady window and the run measures a server tearing down
        // twelve idle clients rather than serving them.
        //
        // Not charged to the rate limiter (`is_rate_limited` exempts `Ping`),
        // so it costs the allowance a client's real messages need nothing.
        if now >= next_ping {
            client.send(3, &tcp::Ping::default()).await;
            next_ping = now + KEEPALIVE;
        }

        if now >= next_join && !channels.is_empty() {
            let target = channels[(rng.below(channels.len() as u64)) as usize];
            client
                .send(
                    9,
                    &tcp::UserState {
                        session: Some(session),
                        channel_id: Some(target),
                        ..tcp::UserState::default()
                    },
                )
                .await;
            next_join = now + rng.delay(Duration::from_secs(90));
        }

        if now >= next_chat {
            // Three per cent near the maximum: a size distribution with no tail
            // never reaches the branch that fragments, and that branch is where
            // the interesting allocation lives.
            let length = if rng.chance(3) { 4096 } else { 32 };
            client
                .send(
                    11,
                    &tcp::TextMessage {
                        message: "s".repeat(length),
                        channel_id: vec![channels.first().copied().unwrap_or(0)],
                        ..tcp::TextMessage::default()
                    },
                )
                .await;
            next_chat = now + rng.delay(Duration::from_secs(60));
        }

        // Drain whatever the server sent, so a client that never reads is not
        // silently exercising the gateway's backpressure instead of its
        // routing. A quiet 50 ms is the whole point of the timeout.
        while client.next_frame(Duration::from_millis(50)).await.is_some() {
            if live.stopping() {
                break;
            }
        }
    }

    let _was = live.connected.fetch_sub(1, Ordering::Relaxed);
    client.close().await;
}

/// Run `scenario` against `deployment` and assess what happened.
///
/// The phases, in order, and why each exists:
///
/// 1. **Baseline.** One sample of a started, idle server. Every level assertion
///    is against this, so it must be taken before a single client connects.
/// 2. **Warm-up.** Clients arrive. Sampled and never asserted on: a cold
///    process filling caches has a slope that says nothing about hour six.
/// 3. **Steady.** The window every trend is fitted over.
/// 4. **Draining.** Clients leave. Sampled so a report can show the shape of
///    the descent, which is where a slow drain is visible.
/// 5. **Quiesced.** One settled sample. The most informative one in the run.
///
/// # Panics
///
/// If `scenario.check()` fails. A scenario whose steady window holds no samples
/// asserts nothing, and running it to green would be worse than refusing it.
#[expect(
    clippy::too_many_lines,
    reason = "one run of the soak, start to report: warm-up, the steady window, \
              the drain and the assessment. Splitting it would put the phases in \
              separate functions threading the same eight locals between them, \
              which is harder to read against the scenario than the sequence is"
)]
pub async fn run(deployment: &Deployment, scenario: &Scenario, seed: u64) -> Report {
    scenario.check().unwrap_or_else(|error| panic!("{error}"));

    // Printed, not just recorded: a failing nightly's first line has to be the
    // thing that reproduces it.
    println!(
        "soak: scenario {:?}, population {}, duration {}s, seed {seed}",
        scenario.name, scenario.population, scenario.duration_s,
    );

    let sampler = Sampler::new();
    let mut samples = Vec::new();
    let mut lost = 0_u64;

    settle(deployment).await;
    samples.push(sampler.sample(deployment, Phase::Baseline, 0, 0).await);

    let mut channels = Vec::new();
    for i in 0..scenario.channels {
        channels.push(deployment.create_channel(&format!("soak-{i}")).await);
    }
    let channels: Arc<[u32]> = channels.into();

    let interval = Duration::from_secs(scenario.sample_every_s);
    let mut why: Vec<String> = Vec::new();

    for cycle in 1..=scenario.cycles {
        let live = Arc::new(Live::default());
        let mut clients = Vec::new();
        for id in 0..scenario.population {
            // One stream per client, derived from the run's seed and the
            // client. Splitting it this way rather than sharing one generator
            // keeps the run reproducible under a different task schedule.
            //
            // Mixed with the cycle as well, so the second cycle is not a replay
            // of the first, which would test the caches rather than the server.
            //
            // This was briefly the suspect for the two descriptors and four
            // tasks that appear once, mid-run: vary the work per cycle and a
            // cycle can be the first to take some path, whose one-time cost
            // then looks exactly like a leak. Measured, it was not the cause --
            // the step survived making every cycle identical. It is
            // `directory`'s first announcement, on a 60-180s timer from boot,
            // and `crates/starling/tests/soak.rs` excludes that service.
            let rng = Rng::new(
                seed ^ id.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ cycle.wrapping_mul(0x1234_5678),
            );
            clients.push(tokio::spawn(live_one(
                deployment.port,
                cycle * scenario.population + id,
                Arc::clone(&channels),
                rng,
                Arc::clone(&live),
            )));
        }

        sample_for(
            &sampler,
            deployment,
            &live,
            &mut samples,
            Phase::Warmup,
            cycle,
            Duration::from_secs(scenario.warmup_s),
            interval,
        )
        .await;
        sample_for(
            &sampler,
            deployment,
            &live,
            &mut samples,
            Phase::Steady,
            cycle,
            scenario.steady(),
            interval,
        )
        .await;

        live.stopping.store(true, Ordering::Relaxed);
        for client in clients {
            // A client that wedged is abandoned rather than waited on: the
            // quiesce sample is the point of the run and must not be lost to
            // one stuck task. It shows up as a live connection the descriptor
            // check then catches, which is the right way for it to be reported.
            match tokio::time::timeout(Duration::from_secs(30), client).await {
                Ok(Ok(())) => {}
                // The panic's own message, not just a count. "A client failed"
                // is not actionable and "the server closed the connection
                // mid-frame" is, and a soak that hides it costs a whole run to
                // rediscover.
                Ok(Err(error)) => {
                    let _was = live.lost.fetch_add(1, Ordering::Relaxed);
                    why.push(crate::panic_message(error));
                }
                Err(_) => {
                    let _was = live.lost.fetch_add(1, Ordering::Relaxed);
                    why.push("would not stop within the drain grace".to_owned());
                }
            }
        }
        lost += live.lost();

        sample_for(
            &sampler,
            deployment,
            &live,
            &mut samples,
            Phase::Draining,
            cycle,
            Duration::from_secs(scenario.quiesce_s),
            interval,
        )
        .await;
        samples.push(
            sampler
                .sample(deployment, Phase::Quiesced, cycle, live.connected())
                .await,
        );
    }

    let mut report = assess(&samples, scenario.budget, 0);
    report.seed = seed;

    // A virtual client that panicked or would not stop is a finding, not
    // background noise: it means the server did something this harness does not
    // know how to answer, and the run's own numbers were taken while that was
    // happening.
    if lost > 0 {
        report.failures.push(Failure {
            check: "clients.lost".to_owned(),
            detail: {
                why.sort_unstable();
                why.dedup();
                format!(
                    "{lost} of {} virtual clients did not finish: {}",
                    scenario.population.saturating_mul(scenario.cycles),
                    why.join("; "),
                )
            },
        });
    }
    report
}

/// Wait until the collector has completed a sweep, before the baseline.
///
/// Gauges are created on first use, and the collector polls each service on its
/// own five-second timer. A baseline taken the instant a deployment starts sees
/// a partial set -- most gauges do not exist yet -- and every one that appears
/// later then reads as growth from zero. The worst of these is the per-service
/// "requests in flight": the collector's own sweep *is* one of those requests,
/// so it reads one in every sample except a cold baseline, and the quiesce
/// check would then report twenty-three leaked requests on a healthy server.
///
/// Two consecutive reads with the same set of keys, rather than a sleep: it
/// waits exactly as long as the collector takes and no longer, and on a loaded
/// runner where a sweep takes longer than its own interval a fixed sleep would
/// simply be wrong.
async fn settle(deployment: &Deployment) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut previous: Vec<String> = Vec::new();
    while Instant::now() < deadline {
        let overview = deployment.overview().await;
        let mut keys: Vec<String> = overview
            .services
            .iter()
            .flat_map(|service| {
                service
                    .load
                    .iter()
                    .map(|load| sample::key(&service.service, &load.name))
            })
            .collect();
        keys.sort_unstable();
        if !keys.is_empty() && keys == previous {
            return;
        }
        previous = keys;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Not a panic. A collector that never settles is itself a finding, and the
    // run's own assertions describe it better than a timeout here would.
    println!("soak: the collector did not settle within 30s; the baseline is cold");
}

/// Sample every `interval` for `duration`, tagging each sample `phase`.
#[expect(
    clippy::too_many_arguments,
    reason = "every one names a coordinate of the sample being taken"
)]
async fn sample_for(
    sampler: &Sampler,
    deployment: &Deployment,
    live: &Live,
    samples: &mut Vec<sample::Sample>,
    phase: Phase,
    cycle: u64,
    duration: Duration,
    interval: Duration,
) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        tokio::time::sleep(interval.min(deadline.saturating_duration_since(Instant::now()))).await;
        samples.push(
            sampler
                .sample(deployment, phase, cycle, live.connected())
                .await,
        );
    }
}
