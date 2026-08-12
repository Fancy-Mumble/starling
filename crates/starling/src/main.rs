//! `starling`: one image, one entrypoint.
//!
//! **One image, many deployments.** A single binary whose entrypoint takes the
//! service name, so Kubernetes runs `args: ["text"]` and a VPS runs
//! `--all-in-one`. Twenty-four Dockerfiles would be twenty-four things to keep
//! in sync, and it would make all-in-one a separate build rather than a matter
//! of arguments (`docs/ARCHITECTURE.md` §9).
//!
//! ```text
//! starling gateway                 one component
//! starling text --config c.toml    one service
//! starling --all-in-one            every service, in-process transports
//! starling migrate-config s.ini    print the equivalent TOML
//! starling migrate-db --from ...   move a murmur database into this one
//! ```
//!
//! **And one download.** `--all-in-one` with no `--config` on a machine that has
//! never run Starling writes a configuration where this platform keeps them,
//! creates the administrator, and prints both; see [`firstrun`]. That is what
//! makes the `.deb`, the `.AppImage`, the `.dmg` and the `.exe` in `docs/
//! RELEASING.md` something a person can double-click.

mod check;
mod compose;
mod firstrun;
mod migrate_db;
mod paths;
mod superuser;
mod units;

#[cfg(test)]
mod e2e;

use std::io::{self, Write as _};
use std::process::ExitCode;

/// Write `text` to stdout, reporting a failed write instead of dying on it.
///
/// The `print!` family panics when stdout is gone, and `starling --help | head`
/// is enough to make that happen: `head` exits, the pipe closes, and a usage
/// message turns into a panic and a non-zero exit. Writing through the handle
/// makes a broken pipe the ordinary error it is.
pub(crate) fn out(text: &str) -> Result<(), String> {
    io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(|error| format!("writing to stdout: {error}"))
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Ignored rather than reported: this *is* the reporting path, and
            // there is nowhere left to report a stderr that will not take it.
            let _ = writeln!(io::stderr().lock(), "starling: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch on the first argument.
fn run(arguments: &[String]) -> Result<(), String> {
    let first = arguments.first().map(String::as_str);
    match first {
        None | Some("--help" | "-h") => out(&format!("{}\n", usage())),
        Some("--version" | "-V") => out(&format!("starling {}\n", env!("CARGO_PKG_VERSION"))),
        Some("migrate-config") => {
            let path = arguments
                .get(1)
                .ok_or("migrate-config needs a path to a mumble-server.ini")?;
            let contents =
                std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
            // Every key murmur honours that has no home yet is reported rather
            // than dropped, so a migration is reviewable. `migrate` reports them
            // through `tracing`, which goes nowhere at all unless a subscriber
            // is installed first, so one is, on stderr, leaving stdout to carry
            // the TOML alone for `starling migrate-config x.ini > starling.toml`.
            let _ = tracing_subscriber::fmt()
                .with_writer(io::stderr)
                .without_time()
                .with_target(false)
                .try_init();
            let toml = starling_migrate::Ini::parse(&contents)
                .migrate()
                .map_err(|error| error.to_string())?;
            out(&toml)
        }
        Some("migrate-db") => {
            // As `migrate-config` does, and for the same reason: the reader
            // reports what it could not carry through `tracing`, which goes
            // nowhere at all unless a subscriber is installed first.
            let _ = tracing_subscriber::fmt()
                .with_writer(io::stderr)
                .without_time()
                .with_target(false)
                .try_init();
            migrate_db::migrate_db(arguments)
        }
        Some("check-config") => check::check_config(arguments),
        Some("set-superuser-password") => superuser::set_password(arguments),
        Some("--all-in-one") => compose::all_in_one(arguments).map_err(|error| error.to_string()),
        Some(name) if !name.starts_with('-') => {
            compose::one(name, arguments).map_err(|error| error.to_string())
        }
        Some(other) => Err(format!("unknown argument {other:?}\n\n{}", usage())),
    }
}

/// What this binary accepts.
fn usage() -> String {
    let mut lines = String::from(
        "usage: starling <component> [--config <file>]\n\
         \x20      starling --all-in-one [--config <file>]\n\
         \x20      starling check-config [--config <file>] [--strict]\n\
         \x20      starling migrate-config <mumble-server.ini>\n\
         \x20      starling migrate-db --from <url> [--server-id <id>] [--dry-run] [--verify]\n\
         \x20      starling set-superuser-password <password> [--server <id>] [--config <file>]\n\n\
         With no --config, `--all-in-one` uses this platform's own configuration\n\
         directory, and writes a starter file there the first time it is run.\n\n\
         `check-config` loads exactly what a start would, environment included,\n\
         and reports what would fail without binding anything. `--strict` makes\n\
         warnings non-zero too, for CI.\n\n\
         `migrate-config` carries a murmur `.ini`; `migrate-db` carries the rest\n\
         of a murmur server -- channels, accounts, ACLs, bans -- reading its\n\
         database without writing to it. Try `--dry-run` first.\n\n\
         components:\n\x20 gateway\n",
    );
    for name in units::names() {
        lines.push_str(&format!("\x20 {name}\n"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_service_is_reachable_by_name_from_the_command_line() {
        // A service that cannot be named cannot be deployed, and the operator
        // finds out at rollout rather than at review.
        let listed = usage();
        for name in units::names() {
            assert!(listed.contains(name), "{name} is not in the usage");
        }
        assert!(listed.contains("gateway"));
    }

    #[test]
    fn an_unknown_component_is_refused_with_the_list_rather_than_a_bare_error() {
        let err = run(&["whiteboard".to_owned()]).expect_err("no such service");
        assert!(err.contains("whiteboard"));
    }
}
