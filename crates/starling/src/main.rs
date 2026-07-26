//! `starling` — one image, one entrypoint.
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
//! ```

mod compose;
mod units;

#[cfg(test)]
mod e2e;

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("starling: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch on the first argument.
fn run(arguments: &[String]) -> Result<(), String> {
    let first = arguments.first().map(String::as_str);
    match first {
        None | Some("--help" | "-h") => {
            println!("{}", usage());
            Ok(())
        }
        Some("--version" | "-V") => {
            println!("starling {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("migrate-config") => {
            let path = arguments
                .get(1)
                .ok_or("migrate-config needs a path to a mumble-server.ini")?;
            let contents = std::fs::read_to_string(path)
                .map_err(|error| format!("{path}: {error}"))?;
            // Every key murmur honours that has no home yet is reported on
            // stderr rather than dropped, so a migration is reviewable.
            let toml = starling_migrate::Ini::parse(&contents)
                .migrate()
                .map_err(|error| error.to_string())?;
            print!("{toml}");
            Ok(())
        }
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
         \x20      starling migrate-config <mumble-server.ini>\n\n\
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
