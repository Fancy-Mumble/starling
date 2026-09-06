//! The gauge contract: a map a client can grow must report its size.
//!
//! `scripts/canon-gauges.json` names every such map and the gauge that reports
//! it, plus the ones deliberately left without one and why. This test asserts
//! the file and the tree still agree.
//!
//! # Why a checked-in list rather than a lint
//!
//! Nothing in the type system distinguishes "a map bounded by the source" from
//! "a map a client can add to", and that is the whole distinction. The failure
//! this prevents is not a wrong gauge; it is a *new* map with no gauge, found
//! six weeks later by a soak run that says memory grew and cannot say where.
//! With the list, adding one is a line in a diff a reviewer sees.
//!
//! The same pattern as `scripts/canon-fixtures.json` and
//! `scripts/cpp-citations.json`: a human must edit it deliberately.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "an integration test is its own crate, so clippy's in-test \
              exemptions do not reach it. A contract this test cannot read is a \
              test that must fail loudly, naming the file"
)]
// This test reads two files and compares strings; the crate's twenty other
// dependencies belong to the library, and `unused_crate_dependencies` is
// per-target, so it cannot see that.
#![allow(
    unused_crate_dependencies,
    reason = "the manifest's dependencies belong to the lib target"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every gauge name the contract declares.
fn declared() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(root().join("scripts/canon-gauges.json"))
        .expect("scripts/canon-gauges.json must be readable");
    let parsed: serde_json::Value =
        serde_json::from_str(&text).expect("canon-gauges.json must be valid JSON");
    parsed["gauges"]
        .as_array()
        .expect("`gauges` must be an array")
        .iter()
        .map(|entry| {
            (
                entry["service"]
                    .as_str()
                    .expect("every gauge names its service")
                    .to_owned(),
                entry["gauge"]
                    .as_str()
                    .expect("every gauge has a name")
                    .to_owned(),
            )
        })
        .collect()
}

/// The gauge names one file registers.
///
/// `gauge("name", ..)`, taking what sits between the quotes. A string literal
/// rather than a parse: the alternative is a syn dependency in a test whose
/// whole job is to be obviously right.
fn names_in(source: &str) -> impl Iterator<Item = String> + '_ {
    source.split(".gauge(").skip(1).filter_map(|hit| {
        let rest = hit.trim_start().strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(rest.get(..end)?.to_owned())
    })
}

/// Every `.rs` file under `crates`, skipping build output.
fn sources() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root().join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.file_name().is_none_or(|name| name != "target") {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found
}

/// Every `pressure.gauge("name", ..)` in the tree, by the name it registers.
fn registered() -> BTreeSet<String> {
    sources()
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|source| names_in(&source).collect::<Vec<_>>())
        .collect()
}

#[test]
fn every_declared_gauge_is_registered_somewhere() {
    let registered = registered();
    let missing: Vec<String> = declared()
        .into_iter()
        .filter(|(_, gauge)| !registered.contains(gauge))
        .map(|(service, gauge)| format!("{service}: {gauge}"))
        .collect();

    assert!(
        missing.is_empty(),
        "scripts/canon-gauges.json declares gauges nothing registers: {missing:#?}\n\
         Either wire `pressure.gauge(..)` for it, or move the entry to `omitted` \
         with the reason."
    );
}

#[test]
fn the_contract_explains_every_entry() {
    // A list of names with no reasons is a list nobody can review. Each entry
    // has to say what the map is and why it is worth watching, because that is
    // what a future reader needs in order to decide whether a new map belongs.
    let text = std::fs::read_to_string(root().join("scripts/canon-gauges.json")).expect("readable");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    for entry in parsed["gauges"].as_array().expect("an array") {
        let name = entry["gauge"].as_str().unwrap_or("<unnamed>");
        assert!(
            entry["map"].as_str().is_some_and(|m| !m.is_empty()),
            "{name} does not say which map it reports"
        );
        assert!(
            entry["why"].as_str().is_some_and(|w| w.len() > 20),
            "{name} does not say why it is worth watching"
        );
    }
    for entry in parsed["omitted"].as_array().expect("an array") {
        assert!(
            entry["why"].as_str().is_some_and(|w| w.len() > 20),
            "an omission without a reason is an oversight with a JSON entry"
        );
    }
}
