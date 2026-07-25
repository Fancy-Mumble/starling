//! Config file formats, registered rather than enumerated.
//!
//! [`ConfigFile::load`](crate::ConfigFile::load) used to `match` on the file
//! extension and name every format it knew. That made this crate depend on the
//! crate that reads murmur `.ini` — a compatibility shim the server hopes never
//! to need — just to have a variant for it.
//!
//! A format now announces itself, so `starling-migrate` owns the `.ini` reader
//! *and* the fact that `.ini` is a thing.

use std::path::Path;

use crate::{ConfigError, ConfigSource};

/// A configuration file format.
pub trait ConfigFormat: std::fmt::Debug + Send + Sync {
    /// Short name for logs and diagnostics, e.g. `"TOML"`.
    fn name(&self) -> &'static str;

    /// Whether this format will read `path`, normally judged by extension.
    ///
    /// The first registered format to claim a path wins, so a format should only
    /// claim what it is confident about. [`Toml`] deliberately claims everything
    /// *last* by being the fallback rather than by claiming eagerly.
    fn claims(&self, path: &Path) -> bool;

    /// Parse the file's contents into a settings layer.
    ///
    /// # Errors
    ///
    /// The format's own parse failure, as a [`ConfigError`].
    fn parse(&self, path: &Path, contents: &str) -> Result<Box<dyn ConfigSource>, ConfigError>;
}

/// One format's entry in the link-time registry.
#[derive(Debug)]
pub struct Registration {
    /// Ordering hint. Lower runs first; the TOML fallback sits at `i16::MAX`.
    pub priority: i16,
    /// Constructs the format.
    pub make: fn() -> Box<dyn ConfigFormat>,
}

inventory::collect!(Registration);

/// Every format linked into this build, most specific first.
#[must_use]
pub fn registered() -> Vec<Box<dyn ConfigFormat>> {
    let mut entries: Vec<_> = inventory::iter::<Registration>.into_iter().collect();
    entries.sort_by_key(|e| e.priority);
    entries.into_iter().map(|e| (e.make)()).collect()
}

/// Announce a [`ConfigFormat`].
///
/// `priority` orders detection: a format that claims a specific extension should
/// use a low number, a catch-all a high one.
#[macro_export]
macro_rules! register_config_format {
    ($ty:ty, $priority:expr_2021) => {
        $crate::inventory::submit! {
            $crate::formats::Registration {
                priority: $priority,
                make: || ::std::boxed::Box::new(<$ty as ::core::default::Default>::default()),
            }
        }
    };
}

/// Starling's native TOML, and the fallback when nothing else claims a file.
///
/// Claims last on purpose: a mis-detected TOML file produces a precise parse
/// error, whereas a permissive format would silently accept almost anything and
/// start with surprising defaults.
#[derive(Debug, Default)]
pub struct Toml;

impl ConfigFormat for Toml {
    fn name(&self) -> &'static str {
        "TOML"
    }

    fn claims(&self, _path: &Path) -> bool {
        true
    }

    fn parse(&self, path: &Path, contents: &str) -> Result<Box<dyn ConfigSource>, ConfigError> {
        crate::NativeConfig::parse(contents)
            .map(|c| Box::new(c) as Box<dyn ConfigSource>)
            .map_err(|source| ConfigError::Toml {
                path: path.to_path_buf(),
                source,
            })
    }
}

register_config_format!(Toml, i16::MAX);
