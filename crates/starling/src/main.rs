//! The binary: argument dispatch and an exit code.
//!
//! Everything else is in the library beside it, so the e2e harness in
//! `crates/harness` can start services the same way this entrypoint does
//! rather than keeping a second copy of `units::spawn` that drifts.

// Every service, the gateway and the migration tools are dependencies of the
// library beside this file, not of these twenty lines. `unused_crate_dependencies`
// is per-target and cannot see that.
#![allow(
    unused_crate_dependencies,
    reason = "the manifest's dependencies belong to the lib target"
)]

use std::io::{self, Write as _};
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match starling::run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Ignored rather than reported: this *is* the reporting path, and
            // there is nowhere left to report a stderr that will not take it.
            let _ = writeln!(io::stderr().lock(), "starling: {message}");
            ExitCode::FAILURE
        }
    }
}
