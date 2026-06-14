// A plugin crate that is a dependency but missing from `plugins.rs` would be
// dropped from the build, and the server would start without it. The workspace
// lints that as a warning; here it is an error, because "the feature is silently
// absent" is not a warning-grade outcome.
#![deny(unused_crate_dependencies)]

//! Starling — a pure-Rust Mumble server.
//!
//! ```text
//! starling [--config <path>] [--cert <path>] [--key <path>] [--port <n>]
//! starling migrate-config <murmur.ini>
//! ```
//!
//! This file is the **composition root**, and nothing more: parse the command
//! line, resolve settings, hand them to [`Server`]. Wiring lives in
//! [`server`] and the failure vocabulary in [`mod@error`]. Logging — including
//! its setup — belongs to `starling-log`; this crate only translates the config
//! file into that crate's vocabulary. Everything below works against traits
//! (`DESIGN.md` §1).
//!
//! See `PORTING-PLAN.md` for scope. This is the Phase 0 MVP: it establishes
//! sessions with the real FancyMumble client and relays chat, but has no voice,
//! no database and no ACL evaluation.

mod error;
mod plugins;
mod server;

use std::process::ExitCode;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::error::StartupError;
use crate::server::Server;
use starling_cli::{ConfigFile, ConfigSource, Settings};
use starling_cli::{Invocation, USAGE};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            error!("{failure}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), StartupError> {
    let command = starling_cli::args::parse().map_err(|e| {
        StartupError::Usage(format!(
            "{e}

{USAGE}"
        ))
    })?;
    match command {
        Invocation::Help => {
            print!("{USAGE}");
            Ok(())
        }

        Invocation::Serve(args) => Server::new(load_settings(&args)?)?.run().await,
        Invocation::Sub { name, args } => run_subcommand(&name, &args),
    }
}

/// Resolve settings from every layer: defaults, then the config file, then CLI.
fn load_settings(args: &starling_cli::ServeArgs) -> Result<Settings, StartupError> {
    let file = match &args.config {
        None => {
            info!("no --config given; using built-in defaults");
            None
        }
        Some(path) => {
            let file = ConfigFile::load(path)?;
            info!(path = %path.display(), format = file.name(), "loaded configuration");
            Some(file)
        }
    };

    let mut sources: Vec<&dyn ConfigSource> = Vec::new();
    if let Some(file) = &file {
        sources.push(file);
    }
    sources.push(&args.overrides);
    Ok(starling_cli::resolve(&sources))
}

/// Run a registered subcommand.
///
/// The binary does not know which subcommands exist. `starling-migrate` provides
/// `migrate-config`; anything else linked in appears here without this file
/// changing.
fn run_subcommand(name: &str, args: &[String]) -> Result<(), StartupError> {
    let Some(command) = starling_cli::command::lookup(name) else {
        return Err(StartupError::Usage(format!(
            "unknown command {name:?}

{USAGE}"
        )));
    };
    command.run(args).map_err(StartupError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn serve_args(config: Option<PathBuf>, port: Option<u16>) -> starling_cli::ServeArgs {
        starling_cli::ServeArgs {
            config,
            overrides: starling_cli::CliOverrides {
                port,
                ..Default::default()
            },
        }
    }

    #[test]
    fn no_config_file_yields_the_defaults() {
        let settings = load_settings(&serve_args(None, None)).expect("defaults should load");
        assert_eq!(
            settings.server.port,
            starling_api::ServerConfig::default().port
        );
    }

    #[test]
    fn a_port_override_wins_over_the_config_file() {
        let settings = load_settings(&serve_args(None, Some(9999))).expect("defaults should load");
        assert_eq!(settings.server.port, 9999);
    }

    #[test]
    fn a_missing_config_file_is_an_error_rather_than_a_silent_default() {
        let args = serve_args(Some(PathBuf::from("definitely-not-here.toml")), None);
        assert!(load_settings(&args).is_err());
    }
}
