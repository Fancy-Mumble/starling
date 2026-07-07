//! Build script for `starling-proto`.
//!
//! Compiles the Mumble protobuf definitions with `prost-build`. Unlike the
//! client's `mumble-protocol`, the generated sources go to `OUT_DIR` and are
//! `include!`d rather than checked in — there is no reason to review generated
//! code in review, and it keeps the tree honest about what is hand-written.
//!
//! The `.proto` files here, in `vendor/server/src/` and in the client are three
//! copies of one contract. **None of them is upstream** — `vendor/server` is the
//! Fancy fork, and taking it for upstream's source of truth is how the field
//! numbering in `docs/PROTOCOL-COMPATIBILITY.md` §1 drifted unnoticed. A change
//! is adjudicated and then applied to all three; `scripts/check-proto-drift.sh`
//! asserts they stay wire-identical, and `check-proto-hygiene.py` asserts the
//! rules that hold identically in all three and so are invisible to a diff.
use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=proto/Mumble.proto");
    println!("cargo:rerun-if-changed=proto/MumbleUDP.proto");

    prost_build::Config::new().compile_protos(
        &["proto/Mumble.proto", "proto/MumbleUDP.proto"],
        &["proto/"],
    )
}
