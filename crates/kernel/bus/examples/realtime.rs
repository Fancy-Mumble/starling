//! Does the `Realtime` lane earn its keep, or is `Control` enough?
//!
//! `Realtime` carries what audio correctness depends on — routing-table
//! publication, crypt setup. Audio frames never traverse the bus; they read the
//! published snapshot. So a delayed publication means voice is routed with a
//! **stale recipient set** until it lands.
//!
//! That gives an absolute budget rather than a ratio: a Mumble audio frame is
//! **10 ms**. A publication delayed beyond that misroutes at least one frame.
//!
//! The A/B is a one-line difference — the same [`LaneBus`], with the realtime
//! port registered on a different lane:
//!
//! * **3 lanes** — realtime traffic rides `Lane::Control`.
//! * **4 lanes** — realtime traffic gets `Lane::Realtime`.
//!
//! The experiment is built to be able to say *no*. If three lanes already keep
//! p99 inside the frame budget, the fourth lane is unjustified complexity.
//!
//! ```text
//! cargo run --release --example realtime -p starling-bus
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use starling_bus::{Envelope, Lane, LaneBus, MessageBus, PortId};

// Reached only through `impl Into<Bytes>`; named for the unused-deps lint.
use bytes as _;

/// One Mumble audio frame. The budget a publication must land inside.
const FRAME_BUDGET: Duration = Duration::from_millis(10);

/// A reconnect storm: clients re-authenticating all at once, each needing a
/// channel-tree and user-list push. This is when the control lane is busiest.
const CONTROL_STORM_THREADS: usize = 4;
/// Work the core does per control message. Bounded by design — the core
/// mutates state and emits effects, it never performs I/O.
const CONTROL_WORK: Duration = Duration::from_micros(20);

/// Feature lane saturated at the same time, as in `isolation.rs`.
const FEATURE_FLOODERS: usize = 2;
const FEATURE_WORK: Duration = Duration::from_micros(50);

/// Routing-table publications: one per 5 ms, as users move between channels.
const PUBLISH_PERIOD: Duration = Duration::from_millis(5);
const PUBLISH_SAMPLES: usize = 400;

const REALTIME_PORT: PortId = PortId(1);
const CONTROL_PORT: PortId = PortId(2);
const FEATURE_PORT: PortId = PortId(3);

const REALTIME_MARK: u8 = 9;

fn main() {
    println!("Does the Realtime lane earn its keep?\n");
    println!("  budget:  {FRAME_BUDGET:?} — one audio frame; past this, voice misroutes");
    println!("  realtime: {PUBLISH_SAMPLES} publications, one per {PUBLISH_PERIOD:?}");
    println!("  control:  {CONTROL_STORM_THREADS} storm threads, {CONTROL_WORK:?} each");
    println!("  feature:  {FEATURE_FLOODERS} flooders, {FEATURE_WORK:?} each\n");

    let folded = run("3 lanes (realtime rides Control)", Lane::Control);
    let separate = run("4 lanes (realtime has its own)", Lane::Realtime);

    println!("\n{:-<80}", "");
    report("3 lanes", &folded);
    report("4 lanes", &separate);

    let budget_us = FRAME_BUDGET.as_secs_f64() * 1e6;
    println!("\n  frame budget: {budget_us:.0}us");

    // Judge on both failure modes: a publication refused at the door missed its
    // frame just as surely as one delivered late.
    let folded_ok = folded.p99 < budget_us && missed(&folded) < 0.01;
    let ratio = folded.p99 / separate.p99.max(0.001);

    println!(
        "  routing updates that missed their frame:  3 lanes {:.1}%   4 lanes {:.1}%",
        missed(&folded) * 100.0,
        missed(&separate) * 100.0
    );

    println!("\n  verdict:");
    if folded_ok {
        println!("    3 lanes already holds p99 inside the frame budget.");
        println!("    The Realtime lane is NOT justified by this workload — ship 3 lanes.");
    } else if ratio >= 2.0 {
        println!(
            "    3 lanes misses {:.0}% of routing updates (refused or past budget);",
            missed(&folded) * 100.0
        );
        println!(
            "    a separate Realtime lane brings it to {:.0}us ({ratio:.0}x better).",
            separate.p99
        );
        println!("    The Realtime lane IS justified.");
    } else {
        println!("    3 lanes blows the budget, but a separate lane does not meaningfully");
        println!(
            "    fix it ({ratio:.1}x). The bottleneck is elsewhere — investigate before adding a lane."
        );
    }
}

struct Stats {
    p50: f64,
    p99: f64,
    max: f64,
    samples: usize,
    over_budget: usize,
    /// Publications the bus refused outright — the routing table never updated.
    refused: usize,
}

/// Fraction of routing updates that missed their frame — refused at the door,
/// or delivered too late. Both mean the snapshot did not update in time.
fn missed(s: &Stats) -> f64 {
    (s.refused + s.over_budget) as f64 / PUBLISH_SAMPLES as f64
}

fn report(name: &str, s: &Stats) {
    println!(
        "  {name:<9} delivered={:>3}/{PUBLISH_SAMPLES}  refused={:>3}  \
         p50={:>8.1}us  p99={:>9.1}us  max={:>9.1}us  over-budget={:>3}  \
         => {:>5.1}% missed their frame",
        s.samples,
        s.refused,
        s.p50,
        s.p99,
        s.max,
        s.over_budget,
        missed(s) * 100.0
    );
}

/// Same bus, same load — only the lane the realtime port is registered on
/// differs.
fn run(name: &str, realtime_lane: Lane) -> Stats {
    let bus = Arc::new(LaneBus::new());
    bus.register(REALTIME_PORT, realtime_lane);
    bus.register(CONTROL_PORT, Lane::Control);
    bus.register(FEATURE_PORT, Lane::Feature);

    let running = Arc::new(AtomicBool::new(true));
    let samples = Arc::new(Mutex::new(Vec::with_capacity(PUBLISH_SAMPLES)));
    let mut workers = Vec::new();

    // Background load: a control storm and a saturated feature lane.
    spawn_flooders(
        &mut workers,
        &bus,
        &running,
        CONTROL_STORM_THREADS,
        CONTROL_PORT,
    );
    spawn_flooders(&mut workers, &bus, &running, FEATURE_FLOODERS, FEATURE_PORT);
    spawn_consumer(
        &mut workers,
        &bus,
        &running,
        Lane::Feature,
        FEATURE_WORK,
        &samples,
    );

    // Both configurations get the **same number of consumer threads**, so the
    // only difference measured is whether realtime has its own queue — not
    // whether it has its own thread.
    //
    // 3 lanes: two consumers share Lane::Control, and realtime rides with them.
    // 4 lanes: one consumer on Control, one on Realtime.
    //
    // Every consumer records realtime envelopes it happens to receive, so
    // coverage is 100% either way and no publication goes unmeasured.
    let consumer_lanes = if realtime_lane == Lane::Control {
        vec![(Lane::Control, CONTROL_WORK), (Lane::Control, CONTROL_WORK)]
    } else {
        vec![
            (Lane::Control, CONTROL_WORK),
            (Lane::Realtime, Duration::ZERO),
        ]
    };
    for (lane, work) in consumer_lanes {
        spawn_consumer(&mut workers, &bus, &running, lane, work, &samples);
    }

    // Count send outcomes. A publication refused at the door never updates the
    // routing table at all — which is worse than a slow one, and invisible if
    // the result is discarded.
    let mut refused = 0usize;
    for _ in 0..PUBLISH_SAMPLES {
        if bus
            .send(Envelope::new(REALTIME_PORT, vec![REALTIME_MARK]))
            .is_err()
        {
            refused += 1;
        }
        spin(PUBLISH_PERIOD);
    }
    thread::sleep(Duration::from_millis(50));
    running.store(false, Ordering::Relaxed);
    bus.close();
    for w in workers {
        let _ = w.join();
    }

    let mut measured = samples.lock().map(|s| s.clone()).unwrap_or_default();
    measured.sort_by(f64::total_cmp);

    let budget_us = FRAME_BUDGET.as_secs_f64() * 1e6;
    println!(
        "  {name}: {} delivered, {refused} refused at send",
        measured.len()
    );

    Stats {
        p50: percentile(&measured, 0.50),
        p99: percentile(&measured, 0.99),
        max: measured.last().copied().unwrap_or(0.0),
        over_budget: measured.iter().filter(|us| **us > budget_us).count(),
        samples: measured.len(),
        refused,
    }
}

fn spawn_flooders(
    workers: &mut Vec<thread::JoinHandle<()>>,
    bus: &Arc<LaneBus>,
    running: &Arc<AtomicBool>,
    count: usize,
    port: PortId,
) {
    for _ in 0..count {
        let bus = Arc::clone(bus);
        let running = Arc::clone(running);
        workers.push(thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                let _ = bus.send(Envelope::new(port, vec![0u8; 64]));
            }
        }));
    }
}

/// A consumer that does `work` per envelope and times any realtime publication
/// it receives — so a publication is measured whichever consumer picks it up.
fn spawn_consumer(
    workers: &mut Vec<thread::JoinHandle<()>>,
    bus: &Arc<LaneBus>,
    running: &Arc<AtomicBool>,
    lane: Lane,
    work: Duration,
    samples: &Arc<Mutex<Vec<f64>>>,
) {
    let bus = Arc::clone(bus);
    let running = Arc::clone(running);
    let samples = Arc::clone(samples);
    workers.push(thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            if let Some(env) = bus.take(lane, Duration::from_millis(5)) {
                record_if_realtime(&env, &samples);
                spin(work);
            }
        }
    }));
}

/// Time a publication, ignoring the storm traffic sharing its lane under the
/// 3-lane configuration.
fn record_if_realtime(env: &Envelope, samples: &Mutex<Vec<f64>>) {
    if env.payload.first() != Some(&REALTIME_MARK) {
        return;
    }
    let micros = env.enqueued_at.elapsed().as_secs_f64() * 1e6;
    if let Ok(mut s) = samples.lock() {
        s.push(micros);
    }
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

/// Busy-wait: `thread::sleep` is millisecond-granular on Windows, far too
/// coarse for a 20-50us budget.
fn spin(d: Duration) {
    let until = Instant::now() + d;
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}
