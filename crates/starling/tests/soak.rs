//! The in-process soak: state assertions against a deployment in this process.
//!
//! `#[ignore]`d, because it takes minutes at the shortest and hours at the
//! longest. Run it deliberately:
//!
//! ```text
//! cargo test --profile soak -p starling --test soak -- --ignored --nocapture
//! E2E_SOAK_SCENARIO=nightly cargo test --profile soak ... -- --ignored
//! ```
//!
//! The `soak` profile is release-shaped with `overflow-checks` and
//! `debug-assertions` back on. A wrong number that never panics is exactly the
//! class of bug a long run exists to find, and `panic = "abort"` in plain
//! release is why those checks are not simply on everywhere.
//!
//! **This half owns the state assertions**, not the resource ones. Resident
//! memory measured inside a test binary that also holds two hundred clients and
//! their TLS buffers is not the server's resident memory; `scripts/soak.sh`
//! measures that from outside, against the real `--all-in-one` binary, and
//! shares this file's assessment module so the two disagree about scale and
//! about nothing else.

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

use starling_harness::soak::{Scenario, render, run, to_jsonl};
use starling_harness::{Deployment, TempDir};

/// Which scenario to drive, from `crates/harness/scenarios/`.
///
/// A name rather than a path, so a CI job says `nightly` and cannot point the
/// run at a file that is not in the repository.
fn scenario() -> Scenario {
    let name = std::env::var("E2E_SOAK_SCENARIO").unwrap_or_else(|_| "smoke".to_owned());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../harness/scenarios")
        .join(format!("{name}.toml"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let mut scenario =
        Scenario::parse(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));

    // Population and duration are overridable without editing a file, because
    // the first question about any quiesce finding is whether it scales with
    // the number of clients. A leak does and a pool warming does not, and
    // running the same scenario at two populations is how you tell them apart.
    if let Some(population) = number("E2E_SOAK_POPULATION") {
        scenario.population = population;
    }
    if let Some(duration) = number("E2E_SOAK_DURATION") {
        scenario.duration_s = duration;
    }
    // The other half of the same question: a cost that recurs every cycle is a
    // leak, and one that plateaus after the second is a pool reaching its bound.
    if let Some(cycles) = number("E2E_SOAK_CYCLES") {
        scenario.cycles = cycles;
    }
    scenario
}

/// A `u64` from the environment, or `None` when unset or unparseable.
fn number(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.parse().ok()
}

/// The seed, from the environment or from the clock.
///
/// Printed either way by the driver, which is the whole contract: a failing
/// nightly's first line is the thing that reproduces it.
fn seed() -> u64 {
    std::env::var("E2E_SOAK_SEED")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |since| since.as_nanos() as u64)
        })
}

/// Where to leave the samples, so a failure is diagnosable after the fact.
fn artifact(name: &str, body: &str) {
    let dir = std::env::var("E2E_SOAK_ARTIFACTS").unwrap_or_else(|_| "target/soak".to_owned());
    if std::fs::create_dir_all(&dir).is_ok() {
        let path = std::path::Path::new(&dir).join(name);
        if std::fs::write(&path, body).is_ok() {
            println!("soak: wrote {}", path.display());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "minutes at the shortest; run it deliberately"]
async fn a_deployment_under_load_comes_back_to_where_it_started() {
    let scenario = scenario();
    let seed = seed();

    let data_dir = TempDir::new("soak");
    let deployment = Deployment::start(data_dir.path()).await;

    let report = run(&deployment, &scenario, seed).await;

    artifact(
        &format!("{}-samples.jsonl", scenario.name),
        &to_jsonl(&report.samples),
    );
    artifact(
        &format!("{}-report.json", scenario.name),
        &serde_json::to_string_pretty(&report).unwrap_or_default(),
    );

    let rendered = render(&report);
    println!("{rendered}");

    // The server's own account of who left and why, which is the first thing
    // to read when the report says clients were lost. Notice and above only:
    // a run at Info is tens of thousands of lines of routed frames.
    for record in deployment.records() {
        if record.severity >= starling_runtime::log::Severity::Notice
            || record.message.contains("disconnected")
        {
            println!(
                "  [{:?}] {} {:?}",
                record.severity, record.message, record.fields
            );
        }
    }

    // Stopped before the assertion, so a failing soak still reports a service
    // that panicked. `stop` is the Stage 0 teardown check and it has caught
    // more than the assertions below have.
    deployment.stop().await;

    assert!(
        report.failures.is_empty(),
        "the deployment did not come back to where it started:\n{rendered}"
    );
}
