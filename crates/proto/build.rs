//! Build script for `starling-proto`.
//!
//! Compiles the Mumble protobuf definitions with `prost-build`. Unlike the
//! client's `mumble-protocol`, the generated sources go to `OUT_DIR` and are
//! `include!`d rather than checked in — there is no reason to review generated
//! code in review, and it keeps the tree honest about what is hand-written.
//!
//! The `.proto` files are copied from `vendor/server/src/` (upstream's source of
//! truth). `scripts/check-proto-drift.sh` asserts they stay wire-identical to
//! the server's and the client's copies.
use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=proto/Mumble.proto");
    println!("cargo:rerun-if-changed=proto/MumbleUDP.proto");

    prost_build::Config::new().compile_protos(
        &["proto/Mumble.proto", "proto/MumbleUDP.proto"],
        &["proto/"],
    )
}
