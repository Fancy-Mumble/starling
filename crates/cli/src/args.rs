//! Command-line parsing.
//!
//! Hand-rolled rather than `clap`: the surface is four flags and one
//! subcommand, and a server that terminates TLS for untrusted peers is a place
//! to keep the dependency graph small. Revisit if the surface grows.

use std::path::PathBuf;

use crate::CliOverrides;

/// Usage text, also printed on a parse error so the mistake and the remedy
/// appear together.
pub const USAGE: &str = "\
Starling - a pure-Rust Mumble server

USAGE:
    starling [OPTIONS]
    starling migrate-config <FILE>

OPTIONS:
    --config <PATH>  configuration file. `.toml` (native) or `.ini` (legacy
                     murmur, read for migration). Defaults to built-in values.
    --cert <PATH>    TLS certificate PEM   [default: starling-data/cert.pem]
    --key <PATH>     TLS private key PEM   [default: starling-data/key.pem]
    --port <PORT>    override the configured port
    -h, --help       print this help

COMMANDS:
    migrate-config <FILE>
                     print <FILE> (a murmur .ini) as the equivalent
                     starling.toml on stdout, then exit

Logging is controlled by RUST_LOG (default: info).
";

/// Arguments for the default (serve) mode.
#[derive(Debug, Default)]
pub struct ServeArgs {
    /// `--config`
    pub config: Option<PathBuf>,
    /// Everything that overrides the config file.
    pub overrides: CliOverrides,
}

/// What the user asked for.
#[derive(Debug)]
pub enum Command {
    /// Print usage and exit.
    Help,
    /// A registered subcommand and its unparsed arguments.
    ///
    /// This parser does not know which subcommands exist — it recognises the
    /// *shape* (a leading word that is not a flag) and hands the rest over. A
    /// command owns its own argument grammar, so adding one changes nothing here.
    Sub {
        /// The word the operator typed.
        name: String,
        /// Everything after it, untouched.
        args: Vec<String>,
    },
    /// Run the server.
    Serve(ServeArgs),
}

/// Parse `std::env::args`.
pub fn parse() -> Result<Command, String> {
    parse_from(std::env::args().skip(1))
}

/// Parse an explicit argument list, so the rules are testable.
fn parse_from(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut args = args.into_iter().peekable();

    // A leading word that is not a flag is a subcommand. Resolving it against the
    // registry is the caller's job; this only decides that it *is* one.
    if args.peek().is_some_and(|a| !a.starts_with('-')) {
        let name = args.next().unwrap_or_default();
        return Ok(Command::Sub {
            name,
            args: args.collect(),
        });
    }

    let mut serve = ServeArgs::default();
    while let Some(flag) = args.next() {
        // Bound in the loop so the error message can name the flag.
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--config" => serve.config = Some(PathBuf::from(value()?)),
            "--cert" => serve.overrides.certificate = Some(PathBuf::from(value()?)),
            "--key" => serve.overrides.key = Some(PathBuf::from(value()?)),
            "--port" => {
                let raw = value()?;
                serve.overrides.port =
                    Some(raw.parse().map_err(|_| format!("invalid port: {raw}"))?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Command::Serve(serve))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_from(args.iter().map(|s| (*s).to_owned()))
    }

    fn serve(args: &[&str]) -> ServeArgs {
        match parse(args).expect("should parse") {
            Command::Serve(s) => s,
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn no_arguments_serves_with_defaults() {
        let args = serve(&[]);
        assert!(args.config.is_none());
        assert!(args.overrides.port.is_none());
    }

    #[test]
    fn both_help_spellings_work() {
        for flag in ["-h", "--help"] {
            assert!(matches!(parse(&[flag]), Ok(Command::Help)), "{flag}");
        }
    }

    #[test]
    fn every_option_is_captured() {
        let args = serve(&[
            "--config",
            "starling.toml",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
            "--port",
            "1234",
        ]);
        assert_eq!(args.config, Some(PathBuf::from("starling.toml")));
        assert_eq!(args.overrides.certificate, Some(PathBuf::from("c.pem")));
        assert_eq!(args.overrides.key, Some(PathBuf::from("k.pem")));
        assert_eq!(args.overrides.port, Some(1234));
    }

    #[test]
    fn a_leading_word_is_handed_over_as_a_subcommand() {
        // The parser recognises the shape, not the name: resolving it against the
        // registry is the binary's job, so adding a command changes nothing here.
        match parse(&["migrate-config", "server.ini"]) {
            Ok(Command::Sub { name, args }) => {
                assert_eq!(name, "migrate-config");
                assert_eq!(args, vec!["server.ini".to_owned()]);
            }
            other => panic!("expected a subcommand, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_subcommand_still_parses_and_is_rejected_later() {
        // A typo must reach the registry so the error can list what exists,
        // rather than being mistaken for a flag here.
        match parse(&["migrate-cofnig"]) {
            Ok(Command::Sub { name, .. }) => assert_eq!(name, "migrate-cofnig"),
            other => panic!("expected a subcommand, got {other:?}"),
        }
    }

    #[test]
    fn a_subcommand_receives_its_arguments_untouched() {
        match parse(&["whatever", "--its-own", "flags", "-x"]) {
            Ok(Command::Sub { args, .. }) => {
                assert_eq!(args, vec!["--its-own", "flags", "-x"]);
            }
            other => panic!("expected a subcommand, got {other:?}"),
        }
    }

    #[test]
    fn the_subcommand_is_only_recognised_first() {
        // Otherwise `--config migrate-config` would be misread as a command.
        assert!(parse(&["--config", "migrate-config"]).is_ok());
    }

    #[test]
    fn a_flag_without_its_value_names_the_flag_in_the_error() {
        let err = parse(&["--port"]).expect_err("should fail");
        assert!(err.contains("--port"), "{err}");
    }

    #[test]
    fn an_unparseable_port_is_an_error_rather_than_a_silent_default() {
        // A typo'd port must not quietly start the server somewhere else.
        let err = parse(&["--port", "not-a-number"]).expect_err("should fail");
        assert!(err.contains("not-a-number"), "{err}");
    }

    #[test]
    fn an_unknown_argument_is_rejected() {
        assert!(parse(&["--nonsense"]).is_err());
    }

    #[test]
    fn help_wins_even_when_other_flags_precede_it() {
        assert!(matches!(
            parse(&["--port", "1234", "--help"]),
            Ok(Command::Help)
        ));
    }
}
