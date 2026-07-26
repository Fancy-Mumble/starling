//! Generate the inter-service gRPC stubs and the Fancy envelope types.
//!
//! Splitting the proto in two crates makes "never break native Mumble"
//! structural rather than a rule someone remembers: `starling-proto` carries
//! the frozen upstream `Mumble.proto`, and nothing here can reach it.

use std::io::Result;
use std::path::PathBuf;

/// Contracts with a `service` block: these need client and server stubs.
const SERVICES: &[&str] = &[
    "control.proto",
    "sessionview.proto",
    "serverconfig.proto",
    "metadata.proto",
    "permissions.proto",
    "userdata.proto",
    "voice.proto",
    "moderation.proto",
    "text.proto",
    "audit.proto",
    "files.proto",
    "push.proto",
    "plugins.proto",
];

/// Client-facing envelopes: message types only, never an RPC surface.
const ENVELOPES: &[&str] = &[
    "fancy/session.proto",
    "fancy/domain.proto",
    "fancy/feature.proto",
    "fancy/pchat.proto",
    "fancy/social.proto",
    "fancy/screenshare.proto",
    "fancy/files.proto",
];

fn main() -> Result<()> {
    let root = PathBuf::from("proto");
    let includes = [root.clone()];

    let mut files: Vec<PathBuf> = SERVICES
        .iter()
        .chain(ENVELOPES.iter())
        .map(|f| root.join(f))
        .collect();
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    let common = root.join("common.proto");
    println!("cargo:rerun-if-changed={}", common.display());

    // Two passes, because the generated modules are `include!`d flat rather
    // than nested. Without `extern_path` prost emits `super::super::common`,
    // a module depth that does not exist here; *with* it prost treats common
    // as somebody else's crate and generates nothing for it. So it is compiled
    // once on its own, and once declared external for everything that imports
    // it.
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(false)
        .compile_protos(&[common], &includes)?;

    files.sort();
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .extern_path(".starling.common.v1", "crate::common")
        .compile_protos(&files, &includes)
}
