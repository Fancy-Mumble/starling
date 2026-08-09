//! Where a downloaded Starling keeps its configuration and its data.
//!
//! A container is handed both by its deployment (`--config`, a mounted volume),
//! so this exists for the other way of getting a server: the `.deb`, the
//! `.AppImage`, the `.dmg`, the `starling.exe` out of a zip. Someone who
//! downloads one of those has not been told where to put anything, and a server
//! that scatters databases into whatever directory the shell happened to be in
//! is a server they cannot find again.
//!
//! Each platform already has an answer, and this is it and nothing else:
//!
//! | | configuration | data |
//! |---|---|---|
//! | Linux, BSD | `$XDG_CONFIG_HOME/starling` | `$XDG_DATA_HOME/starling` |
//! | macOS | `~/Library/Application Support/Starling` | the same directory |
//! | Windows | `%APPDATA%\Starling` | `%LOCALAPPDATA%\Starling` |
//!
//! Read from the environment rather than through a platform API, which is what
//! makes [`from_environment`] a pure function of its arguments and every rule
//! above a test rather than a claim. It also keeps the dependency list where it
//! is: the Windows API for this needs `unsafe`, which this workspace denies.

use std::path::{Path, PathBuf};

/// The name of the file [`Locations::config_file`] points at.
pub(crate) const CONFIG_FILE: &str = "starling.toml";

/// Where configuration and data belong on this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Locations {
    /// The directory holding `starling.toml` and anything it includes.
    pub(crate) config: PathBuf,
    /// Databases, the generated certificate, and the local service sockets.
    pub(crate) data: PathBuf,
}

impl Locations {
    /// The configuration file itself.
    pub(crate) fn config_file(&self) -> PathBuf {
        self.config.join(CONFIG_FILE)
    }
}

/// Which set of conventions to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform {
    /// The XDG base directory specification: Linux, the BSDs, everything else.
    Xdg,
    /// macOS, where an application owns one directory and puts both in it.
    Macos,
    /// Windows, where roaming and local state are deliberately separate.
    Windows,
}

impl Platform {
    /// The conventions this build was compiled for.
    pub(crate) const HOST: Self = if cfg!(windows) {
        Self::Windows
    } else if cfg!(target_os = "macos") {
        Self::Macos
    } else {
        Self::Xdg
    };
}

/// This platform's directories, read from the process environment.
///
/// [`None`] when the environment does not say where the user's home is, which
/// is a service account or a stripped container rather than a person; the
/// caller falls back to the working directory, the behaviour every release
/// before these packages had.
pub(crate) fn locations() -> Option<Locations> {
    from_environment(&|name| std::env::var(name).ok(), Platform::HOST)
}

/// [`locations`], against a given environment and platform.
fn from_environment(var: &dyn Fn(&str) -> Option<String>, platform: Platform) -> Option<Locations> {
    // A variable that is set but empty says nothing, and joining onto it would
    // silently produce a relative path rooted in the working directory -- the
    // exact accident this module exists to avoid.
    let read = |name: &str| {
        var(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    // The XDG specification says a relative value must be ignored rather than
    // resolved, for the same reason.
    let absolute = |name: &str| read(name).filter(|path| path.is_absolute());
    let home = |suffix: &str| read("HOME").map(|home| home.join(suffix));

    match platform {
        Platform::Windows => {
            let roaming = read("APPDATA")?;
            // Falling back to roaming rather than failing: a profile without
            // LOCALAPPDATA is unusual, and a server that will not start is a
            // worse answer than one whose databases roam.
            let local = read("LOCALAPPDATA").unwrap_or_else(|| roaming.clone());
            Some(Locations {
                config: roaming.join("Starling"),
                data: local.join("Starling"),
            })
        }
        Platform::Macos => {
            let base = home("Library/Application Support")?.join("Starling");
            Some(Locations {
                config: base.clone(),
                data: base,
            })
        }
        Platform::Xdg => Some(Locations {
            config: absolute("XDG_CONFIG_HOME")
                .or_else(|| home(".config"))?
                .join("starling"),
            data: absolute("XDG_DATA_HOME")
                .or_else(|| home(".local/share"))?
                .join("starling"),
        }),
    }
}

/// Whether `path` looks like a directory Starling has already used.
///
/// The compatibility hinge. Every release before the downloadable packages ran
/// `starling --all-in-one` with no `--config` against `./starling-data`, and
/// moving that out from under a running deployment would lose its databases and
/// its certificate -- which, since Mumble clients trust a server by certificate
/// fingerprint, every client that ever connected would report as a new server.
/// So an existing one wins over anything this module would choose.
pub(crate) fn in_use(path: &Path) -> bool {
    path.is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment built from pairs, for [`from_environment`].
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name: &str| {
            owned
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn linux_follows_the_xdg_base_directory_specification() {
        let found = from_environment(&env(&[("HOME", "/home/ada")]), Platform::Xdg)
            .expect("a home directory is enough");
        assert_eq!(found.config, PathBuf::from("/home/ada/.config/starling"));
        assert_eq!(found.data, PathBuf::from("/home/ada/.local/share/starling"));
        assert_eq!(
            found.config_file(),
            PathBuf::from("/home/ada/.config/starling/starling.toml")
        );
    }

    #[test]
    fn the_xdg_variables_win_over_the_home_directory_when_they_are_absolute() {
        let found = from_environment(
            &env(&[
                ("HOME", "/home/ada"),
                ("XDG_CONFIG_HOME", "/etc/xdg-user"),
                ("XDG_DATA_HOME", "/srv/state"),
            ]),
            Platform::Xdg,
        )
        .expect("the variables are enough");
        assert_eq!(found.config, PathBuf::from("/etc/xdg-user/starling"));
        assert_eq!(found.data, PathBuf::from("/srv/state/starling"));
    }

    #[test]
    fn a_relative_or_empty_xdg_variable_is_ignored_rather_than_resolved() {
        // Both are what the specification requires, and both are the same bug
        // if they are not: a data directory that moves with the shell's working
        // directory, so a restart from elsewhere finds an empty server.
        for value in ["", "relative/path"] {
            let found = from_environment(
                &env(&[("HOME", "/home/ada"), ("XDG_DATA_HOME", value)]),
                Platform::Xdg,
            )
            .expect("HOME still answers");
            assert_eq!(
                found.data,
                PathBuf::from("/home/ada/.local/share/starling"),
                "XDG_DATA_HOME={value:?} must not be used"
            );
        }
    }

    #[test]
    fn macos_puts_both_under_application_support() {
        let found = from_environment(&env(&[("HOME", "/Users/ada")]), Platform::Macos)
            .expect("a home directory is enough");
        assert_eq!(
            found.config,
            PathBuf::from("/Users/ada/Library/Application Support/Starling")
        );
        assert_eq!(found.data, found.config);
    }

    #[test]
    fn windows_separates_roaming_configuration_from_local_data() {
        // The distinction is the point: a roaming profile follows the user to
        // another machine, and a SQLite database that follows them there is a
        // database being written from two hosts at once.
        let found = from_environment(
            &env(&[
                ("APPDATA", r"C:\Users\Ada\AppData\Roaming"),
                ("LOCALAPPDATA", r"C:\Users\Ada\AppData\Local"),
            ]),
            Platform::Windows,
        )
        .expect("both variables are set");
        // Joined rather than spelled out: the separator `join` inserts is the
        // host's, and this test has to say the same thing when it runs on Linux
        // (where that is `/`) as when it runs on the platform it is about.
        assert_eq!(
            found.config,
            PathBuf::from(r"C:\Users\Ada\AppData\Roaming").join("Starling")
        );
        assert_eq!(
            found.data,
            PathBuf::from(r"C:\Users\Ada\AppData\Local").join("Starling")
        );
    }

    #[test]
    fn windows_without_a_local_directory_roams_rather_than_failing() {
        let found = from_environment(
            &env(&[("APPDATA", r"C:\Users\Ada\AppData\Roaming")]),
            Platform::Windows,
        )
        .expect("APPDATA alone is enough");
        assert_eq!(found.data, found.config);
    }

    #[test]
    fn an_environment_that_names_no_home_has_no_answer() {
        // A service account or a stripped container. Guessing `/root` or `/`
        // here would write a server's databases somewhere nobody backs up.
        assert!(from_environment(&env(&[]), Platform::Xdg).is_none());
        assert!(from_environment(&env(&[]), Platform::Macos).is_none());
        assert!(from_environment(&env(&[]), Platform::Windows).is_none());
        assert!(from_environment(&env(&[("HOME", "")]), Platform::Xdg).is_none());
    }
}
