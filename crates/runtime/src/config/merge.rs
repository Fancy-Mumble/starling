//! Splitting a configuration across files, and laying one over the defaults.
//!
//! # Why a file merges rather than replaces
//!
//! `--config` used to *replace* [`Config::with_defaults`], so a file was
//! obliged to spell out every service's endpoint, tier and wire types before it
//! could change a port. A service the file forgot was a service silently
//! switched off, and the routing table existed twice -- once in code, once per
//! shipped file -- with nothing keeping the copies in step. They drifted, and
//! the drift was invisible: `UserState` moved to session-lifecycle in code, the
//! files went on naming userdata, and self-mute worked under `--all-in-one` and
//! did nothing in the container deployment.
//!
//! So a file is now an **overlay**. It names what it changes, and everything it
//! is silent about keeps the built-in value. The routing table has one home
//! again, and an operator's file can be six lines long.
//!
//! # `include`
//!
//! ```toml
//! include = ["conf.d"]
//! ```
//!
//! A path is resolved against the directory of the file naming it; a directory
//! is expanded to the `*.toml` files directly inside it, in name order. Includes
//! are merged in the order they are listed, and then **the including file's own
//! keys are applied last**, so the file you are editing always wins over what it
//! pulls in.
//!
//! A file reached twice is refused rather than merged twice: with `include`
//! being a tree, the second visit is either a cycle or an ambiguity about which
//! copy wins, and both are better said out loud than resolved by a coin toss.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use toml::Value;

use crate::config::{Config, ConfigError};

/// Read `path` and everything it includes, as one table.
///
/// The result is still only the operator's side of the merge; laying it over
/// the defaults is [`Config::load`]'s job.
pub(crate) fn document(path: &Path) -> Result<toml::Table, ConfigError> {
    read(path, &mut BTreeSet::new())
}

/// Lay `patch` over `base`, table by table.
///
/// Tables merge key-wise and everything else replaces, arrays included: a file
/// listing `[[instances]]` means *these* instances, not "these as well as
/// the built-in one", and a `types` list that appended to the default would be
/// a routing table nobody wrote.
pub(crate) fn overlay(base: &mut toml::Table, patch: toml::Table) {
    for (key, value) in patch {
        match (base.get_mut(&key), value) {
            (Some(Value::Table(existing)), Value::Table(patch)) => overlay(existing, patch),
            (_, value) => {
                let _ = base.insert(key, value);
            }
        }
    }
}

fn read(path: &Path, seen: &mut BTreeSet<PathBuf>) -> Result<toml::Table, ConfigError> {
    // Canonical, so `./conf.d/a.toml` and `conf.d/a.toml` are one file. A path
    // that cannot be canonicalised does not exist, and the read below says so
    // with the operator's own spelling of it.
    if !seen.insert(path.canonicalize().unwrap_or_else(|_| path.to_path_buf())) {
        return Err(ConfigError::Include {
            path: path.to_path_buf(),
            reason: "included twice; an include tree may not revisit a file".to_owned(),
        });
    }

    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    // Parsed as a `Config` first, and the result thrown away. It is the *error*
    // that is wanted: a typo caught after the merge is reported against a
    // document that exists only in memory, with a line number in no file
    // anybody can open. This says `conf.d/limits.toml:14`.
    let _: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let own: toml::Table = toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    let mut merged = toml::Table::new();
    for include in includes(&own, path)? {
        overlay(&mut merged, read(&include, seen)?);
    }
    // The including file last: whoever wrote `include` is stating a base, and a
    // base that overrode the file naming it would be a very surprising base.
    overlay(&mut merged, own);
    Ok(merged)
}

/// The files `table`'s `include` names, resolved against `path`'s directory.
fn includes(table: &toml::Table, path: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let Some(value) = table.get("include") else {
        return Ok(Vec::new());
    };
    let Some(entries) = value.as_array() else {
        return Err(ConfigError::Include {
            path: path.to_path_buf(),
            reason: "`include` is a list of paths".to_owned(),
        });
    };

    let base = path.parent().unwrap_or(Path::new("."));
    let mut resolved = Vec::new();
    for entry in entries {
        let Some(entry) = entry.as_str() else {
            return Err(ConfigError::Include {
                path: path.to_path_buf(),
                reason: format!("`include` holds {entry}, which is not a path"),
            });
        };
        let candidate = base.join(entry);
        if candidate.is_dir() {
            // Sorted, because "whatever order the filesystem hands them back"
            // is a merge whose result depends on the machine it ran on.
            let mut children: Vec<PathBuf> = std::fs::read_dir(&candidate)
                .map_err(|source| ConfigError::Io {
                    path: candidate.clone(),
                    source,
                })?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|child| child.extension().is_some_and(|ext| ext == "toml"))
                .collect();
            children.sort();
            resolved.extend(children);
        } else {
            resolved.push(candidate);
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("a test directory");
        }
        std::fs::write(&path, text).expect("a test file");
        path
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("starling-include-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn a_table_merges_key_wise_and_everything_else_replaces() {
        // The two halves of the rule in one assertion: an operator raising one
        // bucket's burst must not lose the other buckets, and one listing
        // `types` must get exactly that list rather than an append.
        let mut base: toml::Table =
            toml::from_str("[a]\nx = 1\ny = 2\n[b]\nlist = [1, 2, 3]\n").expect("base");
        let patch: toml::Table = toml::from_str("[a]\ny = 9\n[b]\nlist = [7]\n").expect("patch");
        overlay(&mut base, patch);

        assert_eq!(
            base["a"]["x"].as_integer(),
            Some(1),
            "untouched keys survive"
        );
        assert_eq!(base["a"]["y"].as_integer(), Some(9));
        assert_eq!(
            base["b"]["list"].as_array().map(Vec::len),
            Some(1),
            "an array replaces rather than appends"
        );
    }

    #[test]
    fn an_included_file_is_the_base_and_the_including_file_wins() {
        let dir = scratch("precedence");
        let _ = write(
            &dir,
            "conf.d/limits.toml",
            "[gateway]\ncontrol_queue = 111\n",
        );
        let main = write(
            &dir,
            "starling.toml",
            "include = [\"conf.d\"]\n[gateway]\ncontrol_queue = 222\n",
        );

        let merged = document(&main).expect("the tree loads");
        assert_eq!(merged["gateway"]["control_queue"].as_integer(), Some(222));
    }

    #[test]
    fn a_directory_include_takes_every_toml_in_name_order() {
        let dir = scratch("directory");
        let _ = write(&dir, "conf.d/10-a.toml", "[gateway]\naudio_queue = 1\n");
        let _ = write(&dir, "conf.d/20-b.toml", "[gateway]\naudio_queue = 2\n");
        // Not a `.toml`, so not configuration: a README beside the fragments is
        // a normal thing to have and a parse error is not a normal thing to get.
        let _ = write(&dir, "conf.d/README.md", "# not configuration\n");
        let main = write(&dir, "starling.toml", "include = [\"conf.d\"]\n");

        let merged = document(&main).expect("the tree loads");
        assert_eq!(
            merged["gateway"]["audio_queue"].as_integer(),
            Some(2),
            "later files in name order win"
        );
    }

    #[test]
    fn a_cycle_is_refused_rather_than_followed() {
        let dir = scratch("cycle");
        let _ = write(&dir, "a.toml", "include = [\"b.toml\"]\n");
        let _ = write(&dir, "b.toml", "include = [\"a.toml\"]\n");
        let err = document(&dir.join("a.toml")).expect_err("a cycle must not load");
        assert!(matches!(err, ConfigError::Include { .. }));
    }

    #[test]
    fn a_typo_is_reported_against_the_file_that_holds_it() {
        // The reason each file is parsed as a `Config` on its own: reported
        // against the merged document, this would name no file at all.
        let dir = scratch("typo");
        let _ = write(&dir, "conf.d/oops.toml", "[gateway]\ncontrol_qeue = 4096\n");
        let main = write(&dir, "starling.toml", "include = [\"conf.d\"]\n");

        let err = document(&main).expect_err("an unknown key must be refused");
        let ConfigError::Parse { path, .. } = &err else {
            panic!("expected a parse error, got {err}");
        };
        assert!(
            path.ends_with("oops.toml"),
            "the error must name the file with the typo, not {}",
            path.display()
        );
    }
}
