//! What does "nothing bypasses the bus" cost?
//!
//! The design mandates that a feature asking "may user X text in channel Y?"
//! sends a message instead of dereferencing a pointer (`docs/ARCHITECTURE.md`
//! §6.1). This measures the difference, and whether the answer still fits the
//! budgets the server actually has.
//!
//! Three cases:
//!
//! 1. **The floor** — a direct in-process call, what a handler inside the state
//!    service does today. Timed in batches, because a single call is below the
//!    resolution of `Instant::now`.
//! 2. **A rendezvous to an idle server** — the best the mandate can do.
//! 3. **A rendezvous to a server that is mid-way through slower work.** This is
//!    the priority inversion: the question is not whether the *lane* is
//!    prioritised, but that a serving thread already inside a long request
//!    cannot answer until it finishes. The delay is bounded by that request's
//!    hold time, which is why bounded hold time is the invariant that matters
//!    (`docs/CRATES.md` §2).
//!
//! `call()` does not exist on `MessageBus` yet. This builds the rendezvous over
//! `send`/`take` plus a pre-registered reply slot per caller — the reply goes
//! straight to the blocked thread rather than through a correlation-id hash map,
//! which is the shape a real implementation should have and avoids measuring a
//! `HashMap` we would not ship.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use starling_bus::{Envelope, Lane, LaneBus, MessageBus, PortId};

const STATE_PORT: PortId = PortId(1);
const FEATURE_PORT: PortId = PortId(2);

const SAMPLES: usize = 3_000;
/// The caller paces itself. A back-to-back loop keeps the Control lane
/// permanently non-empty, so the server never falls through to Feature work and
/// the inversion under test never happens — an earlier run of this experiment
/// served 4 feature requests in 20 000 samples and measured almost nothing.
const CALL_PERIOD: Duration = Duration::from_micros(500);
/// Batch size for the direct case: one call is below timer resolution.
const DIRECT_BATCH: usize = 1_000;
/// Batches for the direct case — cheap, so take a real sample.
const DIRECT_BATCHES: usize = 200;
/// One audio frame. Nothing on the voice path may exceed this.
const FRAME_BUDGET: Duration = Duration::from_millis(10);

/// How long the serving thread is busy per feature request. Two values: one
/// comfortably inside the frame budget, one deliberately past it.
const HOLD_SHORT: Duration = Duration::from_micros(200);
const HOLD_LONG: Duration = Duration::from_millis(25);

fn main() {
    println!("What does routing a permission check through the bus cost?\n");
    println!("  samples:      {SAMPLES} per case");
    println!("  frame budget: {FRAME_BUDGET:?}");
    println!(
        "  cores:        {}\n",
        thread::available_parallelism().map_or(0, std::num::NonZero::get)
    );
    println!("{:-<92}", "");

    let direct = measure_direct();
    report("direct call, in-process (today)", &direct);

    let hot = measure_rendezvous(None, None);
    report("bus rendezvous, server hot (never parks)", &hot);

    let idle = measure_rendezvous(None, Some(CALL_PERIOD));
    report("bus rendezvous, server parked between calls", &idle);

    let short = measure_rendezvous(Some(HOLD_SHORT), Some(CALL_PERIOD));
    report(
        &format!("bus rendezvous, server holding {HOLD_SHORT:?}"),
        &short,
    );

    let long = measure_rendezvous(Some(HOLD_LONG), Some(CALL_PERIOD));
    report(
        &format!("bus rendezvous, server holding {HOLD_LONG:?}"),
        &long,
    );

    println!("{:-<92}", "");
    verdict(&direct, &hot, &idle, &short, &long);
}

// ---------------------------------------------------------------- the floor

fn measure_direct() -> Stats {
    let policy = AllowAll;
    let mut samples = Vec::with_capacity(DIRECT_BATCHES);

    for b in 0..DIRECT_BATCHES {
        let start = Instant::now();
        for i in 0..DIRECT_BATCH {
            let answer = policy.allows((b * DIRECT_BATCH + i) as u32 % 64, i as u32 % 16);
            let _ = std::hint::black_box(answer);
        }
        let per_call = start.elapsed().as_secs_f64() * 1e6 / DIRECT_BATCH as f64;
        samples.push(per_call);
    }
    Stats::from(samples)
}

/// Stands in for `dyn Permissions`; the point is the indirection, not the ACL.
#[derive(Debug)]
struct AllowAll;

trait Policy {
    fn allows(&self, user: u32, channel: u32) -> bool;
}

impl Policy for AllowAll {
    fn allows(&self, user: u32, channel: u32) -> bool {
        !std::hint::black_box(user ^ channel).is_multiple_of(97)
    }
}

// ----------------------------------------------------------- the rendezvous

type Slots = Arc<Mutex<Vec<SyncSender<Bytes>>>>;

/// Take one permission question, answer it, reply straight into the caller's
/// slot. Returns whether there was one to serve.
fn serve_question(bus: &LaneBus, slots: &Slots) -> bool {
    let Some(env) = bus.take(Lane::Control, Duration::from_micros(50)) else {
        return false;
    };
    let Some((id, user, chan)) = parse_question(&env.payload) else {
        return true;
    };
    let answer = AllowAll.allows(user, chan);
    let slot = slots.lock().ok().and_then(|s| s.get(id as usize).cloned());
    if let Some(slot) = slot {
        let _ = slot.send(Bytes::from(vec![u8::from(answer)]));
    }
    true
}

fn parse_question(payload: &[u8]) -> Option<(u32, u32, u32)> {
    let id = u32::from_le_bytes(payload.get(0..4)?.try_into().ok()?);
    let user = u32::from_le_bytes(payload.get(4..8)?.try_into().ok()?);
    let chan = u32::from_le_bytes(payload.get(8..12)?.try_into().ok()?);
    Some((id, user, chan))
}

/// Occupy the serving thread for `hold`, the way a slow request would.
fn serve_feature(bus: &LaneBus, hold: Option<Duration>, served: &AtomicU64) {
    let Some(work) = hold else { return };
    if bus.take(Lane::Feature, Duration::from_micros(50)).is_none() {
        return;
    }
    let spin = Instant::now();
    while spin.elapsed() < work {
        let _ = std::hint::black_box(spin.elapsed());
    }
    let _ = served.fetch_add(1, Ordering::Relaxed);
}

/// `hold` = how long the serving thread is busy per feature request, or `None`
/// for a server with nothing else to do.
fn measure_rendezvous(hold: Option<Duration>, pace: Option<Duration>) -> Stats {
    let bus = Arc::new(LaneBus::new());
    bus.register(STATE_PORT, Lane::Control);
    bus.register(FEATURE_PORT, Lane::Feature);

    let running = Arc::new(AtomicBool::new(true));
    let slots: Slots = Arc::new(Mutex::new(Vec::new()));
    let served_feature = Arc::new(AtomicU64::new(0));

    let (tx, rx): (SyncSender<Bytes>, Receiver<Bytes>) = sync_channel(1);
    let caller_id = slots.lock().map_or(0, |mut s| {
        s.push(tx);
        (s.len() - 1) as u32
    });

    // ONE serving thread, exactly as a single-writer service is. It prefers
    // Control, but a Feature request already in progress must finish first —
    // that is the inversion this measures.
    let server = {
        let bus = Arc::clone(&bus);
        let slots = Arc::clone(&slots);
        let running = Arc::clone(&running);
        let served_feature = Arc::clone(&served_feature);
        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if serve_question(bus.as_ref(), &slots) {
                    continue;
                }
                serve_feature(bus.as_ref(), hold, &served_feature);
            }
        })
    };

    // Keep the Feature lane occupied so the server is genuinely mid-request
    // when questions arrive.
    let mut floods = Vec::new();
    if hold.is_some() {
        let bus = Arc::clone(&bus);
        let running = Arc::clone(&running);
        floods.push(thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                let _ = bus.send(Envelope::new(FEATURE_PORT, vec![0u8; 12]));
                thread::sleep(Duration::from_micros(100));
            }
        }));
    }

    thread::sleep(Duration::from_millis(50));

    let mut samples = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let mut payload = Vec::with_capacity(12);
        payload.extend_from_slice(&caller_id.to_le_bytes());
        payload.extend_from_slice(&(i as u32 % 64).to_le_bytes());
        payload.extend_from_slice(&(i as u32 % 16).to_le_bytes());

        if let Some(gap) = pace {
            thread::sleep(gap);
        }

        let start = Instant::now();
        if bus.send(Envelope::new(STATE_PORT, payload)).is_err() {
            continue;
        }
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(reply) => {
                samples.push(start.elapsed().as_secs_f64() * 1e6);
                let _ = std::hint::black_box(reply);
            }
            Err(_) => break,
        }
    }

    running.store(false, Ordering::Relaxed);
    bus.close();
    let _ = server.join();
    for f in floods {
        let _ = f.join();
    }

    let mut s = Stats::from(samples);
    s.feature_served = served_feature.load(Ordering::Relaxed);
    s
}

// -------------------------------------------------------------- reporting

struct Stats {
    n: usize,
    p50: f64,
    p99: f64,
    max: f64,
    over_budget: usize,
    feature_served: u64,
}

impl Stats {
    fn from(mut samples: Vec<f64>) -> Self {
        samples.sort_by(f64::total_cmp);
        let budget_us = FRAME_BUDGET.as_secs_f64() * 1e6;
        Self {
            n: samples.len(),
            p50: percentile(&samples, 0.50),
            p99: percentile(&samples, 0.99),
            max: samples.last().copied().unwrap_or(0.0),
            over_budget: samples.iter().filter(|s| **s > budget_us).count(),
            feature_served: 0,
        }
    }
}

fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx]
}

fn report(name: &str, s: &Stats) {
    println!(
        "  {name:<44} n={:<5} p50={:>8.4}us p99={:>9.1}us max={:>9.1}us over-budget={}",
        s.n, s.p50, s.p99, s.max, s.over_budget
    );
}

fn verdict(direct: &Stats, hot: &Stats, idle: &Stats, short: &Stats, long: &Stats) {
    println!("\n  cost of the mandate (p50):");
    println!("    direct call:      {:>9.4}us", direct.p50);
    println!(
        "    rendezvous, hot:  {:>9.4}us   = {:>7.0}x",
        hot.p50,
        hot.p50 / direct.p50.max(1e-9)
    );
    println!(
        "    rendezvous, cold: {:>9.4}us   = {:>7.0}x   (the extra is thread wake-up)",
        idle.p50,
        idle.p50 / direct.p50.max(1e-9)
    );

    println!("\n  ceiling for one serving port (round-trips/second):");
    println!("    hot server:       {:>9.0}/s", 1e6 / hot.p50.max(1e-9));
    println!("    cold server:      {:>9.0}/s", 1e6 / idle.p50.max(1e-9));
    println!(
        "    holding {HOLD_SHORT:?}:   {:>9.0}/s   ({} feature requests served)",
        1e6 / short.p50.max(1e-9),
        short.feature_served
    );

    println!("\n  priority inversion — a question behind an in-progress request:");
    println!(
        "    hold {HOLD_SHORT:?}: p99 {:>8.1}us  ({:.2}% past the frame budget)",
        short.p99,
        short.over_budget as f64 / short.n.max(1) as f64 * 100.0
    );
    println!(
        "    hold {HOLD_LONG:?}:  p99 {:>8.1}us  ({:.2}% past the frame budget)",
        long.p99,
        long.over_budget as f64 / long.n.max(1) as f64 * 100.0
    );

    println!("\n  verdict:");
    if long.over_budget > 0 && short.over_budget == 0 {
        println!("    The rendezvous itself is cheap. What breaks the budget is the serving");
        println!("    thread's HOLD TIME, not the bus: a {HOLD_LONG:?} request pushes p99 past");
        println!("    one audio frame, a {HOLD_SHORT:?} one does not.");
        println!();
        println!("    So the invariant to enforce is 'no handler performs I/O or unbounded");
        println!("    work' (docs/CRATES.md §2). Lane priority cannot rescue a question that");
        println!("    arrives while the only serving thread is already busy — only bounded");
        println!("    hold time, or preemption, can.");
    } else {
        println!("    Inconclusive: re-check the hold-time constants against this machine.");
    }
}
