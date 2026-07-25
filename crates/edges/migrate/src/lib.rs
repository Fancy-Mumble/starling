//! `starling-migrate` — murmur compatibility.
//!
//! Two halves of one job, kept together because they exist for the same reason:
//!
//! * [`Ini`] reads a `mumble-server.ini`, quirks included, as a
//!   [`ConfigSource`];
//! * [`MigrateConfig`] is the `migrate-config` subcommand that prints one as the
//!   equivalent `starling.toml`.
//!
//! Neither belongs in the binary. Reading murmur's format is not something the
//! server does — it is something an operator coming *from* murmur does once — and
//! the binary should not carry a parser for a format it hopes never to see again.
//!
//! The command registers itself, so nothing outside this crate names it.

mod ini;

pub use ini::Ini;

use std::path::PathBuf;

use starling_cli::{resolve, Command, CommandError, ConfigFormat, ConfigSource, NativeConfig};

/// `migrate-config <FILE>` — print a murmur `.ini` as `starling.toml`.
#[derive(Debug, Default)]
pub struct MigrateConfig;

impl Command for MigrateConfig {
    fn name(&self) -> &'static str {
        "migrate-config"
    }

    fn usage(&self) -> &'static str {
        "<FILE>       print FILE (a murmur .ini) as the equivalent starling.toml"
    }

    fn run(&self, args: &[String]) -> Result<(), CommandError> {
        let [path] = args else {
            return Err(CommandError::Usage(
                "migrate-config takes exactly one argument: the .ini to read".to_owned(),
            ));
        };
        let path = PathBuf::from(path);
        let contents = std::fs::read_to_string(&path).map_err(|e| CommandError::at(&path, e))?;

        // Printed, never written: a migration an operator can read before
        // adopting is a migration they can disagree with.
        let settings = resolve(&[&Ini::parse(&contents)]);
        print!("{}", NativeConfig::render(&settings));
        Ok(())
    }
}

starling_cli::register_command!(MigrateConfig);

/// murmur's `mumble-server.ini`, as a config format the server can read directly.
///
/// Registered at priority 0 so it is tried before `starling-cli`'s TOML fallback.
/// Reading one warns: it works, but the operator is running on a format that
/// exists for migration.
#[derive(Debug, Default)]
pub struct MurmurIni;

impl ConfigFormat for MurmurIni {
    fn name(&self) -> &'static str {
        "murmur .ini"
    }

    fn claims(&self, path: &std::path::Path) -> bool {
        path.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ini"))
    }

    fn parse(
        &self,
        path: &std::path::Path,
        contents: &str,
    ) -> Result<Box<dyn ConfigSource>, starling_cli::ConfigError> {
        tracing::warn!(
            path = %path.display(),
            "reading a legacy murmur .ini; run `starling migrate-config` to convert it to TOML"
        );
        Ok(Box::new(Ini::parse(contents)))
    }
}

starling_cli::register_config_format!(MurmurIni, 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_answers_to_the_name_an_operator_types() {
        assert_eq!(MigrateConfig.name(), "migrate-config");
    }

    #[test]
    fn no_argument_is_a_usage_error_not_a_panic() {
        let e = MigrateConfig
            .run(&[])
            .expect_err("one argument is required");
        assert!(matches!(e, CommandError::Usage(_)));
    }

    #[test]
    fn two_arguments_are_a_usage_error() {
        let args = ["a.ini".to_owned(), "b.ini".to_owned()];
        assert!(matches!(
            MigrateConfig.run(&args),
            Err(CommandError::Usage(_))
        ));
    }

    #[test]
    fn a_missing_file_names_the_path_it_could_not_read() {
        let args = ["definitely-not-here.ini".to_owned()];
        let e = MigrateConfig
            .run(&args)
            .expect_err("the file does not exist");
        assert!(
            e.to_string().contains("definitely-not-here.ini"),
            "the error must say which file: {e}"
        );
    }
}
