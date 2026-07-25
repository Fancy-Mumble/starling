//! Subcommands, registered rather than listed.
//!
//! `starling migrate-config foo.ini` is not a variant in this crate's `match`.
//! It is a [`Command`] that `starling-migrate` announces with
//! [`register_command!`](crate::register_command), and this crate finds it by
//! asking [`registered`].
//!
//! # Why
//!
//! The alternative is an enum with a variant per subcommand, a `match` arm per
//! variant, and a usage string listing them — three places that must agree, all
//! in the crate least qualified to know. Every new subcommand then edits the same
//! file, and the crate that hosts them accumulates dependencies on every crate
//! that implements one. That is how the binary became large enough to notice.
//!
//! Same mechanism and same caveat as features: a command crate needs a reference
//! in the binary or rustc will not link it. See
//! `starling_api::register_plugin!`.

use std::path::Path;

/// A subcommand the binary can run instead of serving.
///
/// Implementations are constructed by the host, so they take no arguments:
/// everything a command needs arrives in [`Self::run`].
pub trait Command: std::fmt::Debug + Send + Sync {
    /// The word an operator types, e.g. `migrate-config`.
    fn name(&self) -> &'static str;

    /// One line for the usage text, without the command name.
    ///
    /// Example: `"<FILE>  print FILE (a murmur .ini) as starling.toml"`.
    fn usage(&self) -> &'static str;

    /// Run it.
    ///
    /// `args` is everything after the command name, unparsed: a command owns its
    /// own argument grammar, so adding one cannot change this crate's parser.
    ///
    /// # Errors
    ///
    /// [`CommandError`] if the arguments are wrong or the command fails.
    fn run(&self, args: &[String]) -> Result<(), CommandError>;
}

/// Why a subcommand did not complete.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    /// The arguments were wrong. Carries a message for the operator.
    #[error("{0}")]
    Usage(String),

    /// The command ran and failed.
    #[error("{0}")]
    Failed(String),
}

impl CommandError {
    /// A failure with a path in it, which is the common case.
    #[must_use]
    pub fn at(path: &Path, cause: impl std::fmt::Display) -> Self {
        Self::Failed(format!("{}: {cause}", path.display()))
    }
}

/// One command's entry in the link-time registry.
#[derive(Debug)]
pub struct Registration {
    /// The command's name, available without constructing it.
    pub name: &'static str,
    /// Constructs the command.
    pub make: fn() -> Box<dyn Command>,
}

inventory::collect!(Registration);

/// Every subcommand linked into this build, sorted by name so `--help` is stable.
#[must_use]
pub fn registered() -> Vec<Box<dyn Command>> {
    let mut commands: Vec<_> = inventory::iter::<Registration>
        .into_iter()
        .map(|entry| (entry.make)())
        .collect();
    commands.sort_by_key(|c| c.name());
    commands
}

/// Find a command by the word an operator typed.
#[must_use]
pub fn lookup(name: &str) -> Option<Box<dyn Command>> {
    registered().into_iter().find(|c| c.name() == name)
}

/// Announce a [`Command`] to the binary.
///
/// ```ignore
/// starling_cli::register_command!(MigrateConfig);
/// ```
///
/// The type must implement [`Command`] and [`Default`].
#[macro_export]
macro_rules! register_command {
    ($ty:ty) => {
        $crate::inventory::submit! {
            $crate::command::Registration {
                name: ::core::stringify!($ty),
                make: || ::std::boxed::Box::new(<$ty as ::core::default::Default>::default()),
            }
        }
    };
}
