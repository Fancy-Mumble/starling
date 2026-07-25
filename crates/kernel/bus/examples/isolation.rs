//! Does lane separation actually protect control latency?
//!
//! The hypothesis the whole priority design rests on:
//!
//! > When a feature saturates the bus, control-plane latency stays low.
//!
//! The experiment runs the *same* workload through two [`MessageBus`]
//! implementations and compares control-envelope latency:
//!
//! * [`LaneBus`] — one queue per lane, each drained by its own thread.
//! * [`SharedQueueBus`] — one queue for everything, drained FIFO. The control.
//!
//! What is being measured is **isolation**, not raw queue throughput. Both
//! configurations use the same `LockedQueue` underneath, so the difference
//! between them is the lane topology and nothing else.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --example isolation -p starling-bus
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use starling_bus::{Envelope, Lane, LaneBus, MessageBus, PortId, SharedQueueBus};

// Reached only through `impl Into<Bytes>`; named so the workspace's
// unused-crate-dependencies lint sees it on this target.
use bytes as _;

/// Control traffic: one envelope every `CONTROL_PERIOD`, like client protocol.
const CONTROL_PERIOD: Duration = Duration::from_micros(200);
/// How many control envelopes each run measures.
const CONTROL_SAMPLES: usize = 3_000;
/// How many threads flood the feature lane.
const FEATURE_FLOODERS: usize = 4;
/// Simulated work per feature envelope — a plugin doing something real.
const FEATURE_WORK: Duration = Duration::from_micros(50);

const CONTROL_PORT: PortId = PortId(1);
const FEATURE_PORT: PortId = PortId(2);

fn main() {
    println!("Bus isolation — does a saturated feature lane delay the control plane?\n");
    println!("  control: {CONTROL_SAMPLES} envelopes, one per {CONTROL_PERIOD:?}");
    println!(
        "  feature: {FEATURE_FLOODERS} flooding threads, {FEATURE_WORK:?} of work per envelope\n"
    );

    let baseline = run("SharedQueueBus (one queue, FIFO)", || {
        Arc::new(SharedQueueBus::new())
    });
    let lanes = run("LaneBus       (one queue per lane)", || {
        Arc::new(LaneBus::new())
    });

    println!("\n{:-<78}", "");
    report("SharedQueueBus", &baseline);
    report("LaneBus", &lanes);

    let improvement = baseline.p99 / lanes.p99.max(0.001);
    println!("\n  p99 improvement from lane separation: {improvement:.0}x");
    println!(
        "  verdict: {}",
        if improvement >= 2.0 {
            "lane separation measurably protects the control plane"
        } else {
            "NO MEANINGFUL ISOLATION - the design does not pay for itself here"
        }
    );

    println!(
        "\n  Note the coverage column. With one shared queue you cannot dedicate a\n  \
         consumer to the control plane - envelopes go to whichever worker grabs\n  \
         them first, so most control traffic is handled by the feature worker and\n  \
         never measured here. That is not a flaw in the experiment; it is the\n  \
         structural reason a separate lane is needed at all."
    );
}

/// Latency percentiles for one run, in microseconds.
struct Stats {
    p50: f64,
    p99: f64,
    max: f64,
    samples: usize,
    feature_handled: usize,
}

fn report(name: &str, s: &Stats) {
    let coverage = s.samples as f64 / CONTROL_SAMPLES as f64 * 100.0;
    println!(
        "  {name:<16} p50={:>8.1}us  p99={:>9.1}us  max={:>10.1}us  \
         measured={:>4}/{CONTROL_SAMPLES} ({coverage:>3.0}%)  feature_done={}",
        s.p50, s.p99, s.max, s.samples, s.feature_handled
    );
}

/// Run the same workload against a bus implementation and measure control
/// latency: the time from `send` to the control consumer receiving it.
fn run<B: MessageBus + 'static>(name: &str, make: impl Fn() -> Arc<B>) -> Stats {
    let bus = make();
    bus.register(CONTROL_PORT, Lane::Control);
    bus.register(FEATURE_PORT, Lane::Feature);

    let running = Arc::new(AtomicBool::new(true));
    let samples = Arc::new(Mutex::new(Vec::with_capacity(CONTROL_SAMPLES)));
    let feature_handled = Arc::new(Mutex::new(0usize));

    // --- feature lane: flooders + a consumer that does real work -----------
    let mut workers = Vec::new();
    for _ in 0..FEATURE_FLOODERS {
        let bus = Arc::clone(&bus);
        let running = Arc::clone(&running);
        workers.push(thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                // Rejections are expected once the lane fills — that IS the
                // backpressure policy working.
                let _ = bus.send(Envelope::new(FEATURE_PORT, vec![0u8; 64]));
            }
        }));
    }

    {
        let bus = Arc::clone(&bus);
        let running = Arc::clone(&running);
        let handled = Arc::clone(&feature_handled);
        workers.push(thread::spawn(move || {
            let mut n = 0usize;
            while running.load(Ordering::Relaxed) {
                if bus.take(Lane::Feature, Duration::from_millis(5)).is_some() {
                    spin(FEATURE_WORK);
                    n += 1;
                }
            }
            if let Ok(mut slot) = handled.lock() {
                *slot = n;
            }
        }));
    }

    // --- control lane: a consumer that records end-to-end latency ----------
    {
        let bus = Arc::clone(&bus);
        let running = Arc::clone(&running);
        let samples = Arc::clone(&samples);
        workers.push(thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                let Some(env) = bus.take(Lane::Control, Duration::from_millis(5)) else {
                    continue;
                };
                // The shared-queue bus hands this consumer feature traffic too;
                // only control envelopes are timed.
                record_if_control(&env, &samples);
            }
        }));
    }

    // --- the measured producer --------------------------------------------
    let started = Instant::now();
    for _ in 0..CONTROL_SAMPLES {
        let _ = bus.send(Envelope::new(CONTROL_PORT, vec![CONTROL_MARK]));
        spin(CONTROL_PERIOD);
    }
    // Let the tail drain before stopping.
    thread::sleep(Duration::from_millis(50));
    running.store(false, Ordering::Relaxed);
    bus.close();
    for w in workers {
        let _ = w.join();
    }

    let handled_total = feature_handled.lock().map(|h| *h).unwrap_or(0);
    let mut measured = samples.lock().map(|s| s.clone()).unwrap_or_default();
    measured.sort_by(f64::total_cmp);
    println!(
        "  {name}: {} control samples in {:?}",
        measured.len(),
        started.elapsed()
    );

    Stats {
        samples: measured.len(),
        p50: percentile(&measured, 0.50),
        p99: percentile(&measured, 0.99),
        max: measured.last().copied().unwrap_or(0.0),
        feature_handled: handled_total,
    }
}

/// Marker byte identifying a control envelope.
const CONTROL_MARK: u8 = 1;

/// Time a control envelope, ignoring feature traffic that reached the same
/// consumer (which only happens on the shared-queue bus).
fn record_if_control(env: &Envelope, samples: &Mutex<Vec<f64>>) {
    if env.payload.first() != Some(&CONTROL_MARK) {
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
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx]
}

/// Busy-wait. `thread::sleep` has millisecond granularity on Windows, which is
/// far too coarse for a 50–200us budget and would dominate the measurement.
fn spin(d: Duration) {
    let until = Instant::now() + d;
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}
