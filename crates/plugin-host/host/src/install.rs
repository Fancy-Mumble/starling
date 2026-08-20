//! Putting a plugin binary on disk, once something else has fetched it.
//!
//! The C++ server's host did the fetching itself: a marketplace manifest over
//! blocking HTTP, an artifact picked by `(os, arch)`, a zip or tar.gz unpacked
//! in process. None of that belongs here. Starling already has a service whose
//! job is holding bytes somebody uploaded (`files`), and a control plane that
//! refuses to carry a binary inline, so the host is handed the bytes and asked
//! only to check them and write them down.
//!
//! What survives from the original is the part that was load-bearing: the
//! digest check, and refusing to let the *name* of an artifact decide where it
//! lands.

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

/// Largest plugin binary accepted.
///
/// The same 32 MiB the marketplace flow allowed. A plugin is a shared library,
/// not a media file; anything past this is a mistake or an attack, and either
/// way the answer is the same.
pub const MAX_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;

/// Why a plugin binary was not installed.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The artifact was larger than [`MAX_ARTIFACT_BYTES`].
    #[error("plugin binary is {size} B, over the {limit} B limit")]
    TooLarge {
        /// Size of the rejected artifact.
        size: usize,
        /// [`MAX_ARTIFACT_BYTES`].
        limit: usize,
    },

    /// The bytes did not hash to what the caller said they would.
    #[error("plugin binary digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// What the caller asked for.
        expected: String,
        /// What the bytes actually are.
        actual: String,
    },

    /// The requested file name was not one this host will write.
    #[error("'{0}' is not a usable plugin file name")]
    BadName(String),

    /// Writing to the plugin directory failed.
    #[error("cannot write plugin binary: {0}")]
    Io(#[from] std::io::Error),
}

/// Reduce a caller-supplied name to a bare file name this host will write.
///
/// **This is a security boundary, not tidiness.** The original took the name
/// straight out of an attacker-writable manifest and did `dest_dir.join(name)`,
/// so a name of `../../etc/whatever` -- or, on Windows, `C:\...` -- escaped the
/// plugin directory entirely. `Path::file_name` drops every directory component
/// and both `.` and `..`, which is what makes the join below safe; the
/// extension check then keeps the directory to files the scanner would pick up
/// anyway.
fn safe_file_name(requested: &str) -> Result<String, InstallError> {
    let bad = || InstallError::BadName(requested.to_owned());
    let name = Path::new(requested)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(bad)?;
    if name.is_empty() || name.starts_with('.') {
        return Err(bad());
    }
    let suffix_ok = name.ends_with(crate::loader::cdylib_suffix())
        || name.ends_with(crate::loader::wasm_suffix());
    if !suffix_ok {
        return Err(bad());
    }
    Ok(name.to_owned())
}

/// Lowercase hex of the SHA-256 of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut hex = String::with_capacity(out.len() * 2);
    for byte in out {
        use std::fmt::Write as _;
        // Writing hex into a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Check `bytes` and write them into `dest_dir` as `requested_name`.
///
/// `expected_sha256` is compared case-insensitively when the caller supplies
/// one. Returns the path written.
///
/// # Errors
///
/// [`InstallError`] when the artifact is oversized, fails its digest check,
/// names a file this host will not write, or cannot be written.
pub(crate) fn write_artifact(
    dest_dir: &Path,
    requested_name: &str,
    bytes: &[u8],
    expected_sha256: Option<&str>,
) -> Result<PathBuf, InstallError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(InstallError::TooLarge {
            size: bytes.len(),
            limit: MAX_ARTIFACT_BYTES,
        });
    }
    let actual = digest(bytes);
    if let Some(expected) = expected_sha256.filter(|value| !value.is_empty())
        && !expected.eq_ignore_ascii_case(&actual)
    {
        return Err(InstallError::DigestMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }

    let name = safe_file_name(requested_name)?;
    std::fs::create_dir_all(dest_dir)?;
    let path = dest_dir.join(name);
    std::fs::write(&path, bytes)?;

    // A plugin binary the server cannot execute is a plugin that will not load.
    // Windows has no equivalent bit, so this is Unix-only rather than
    // conditional on anything about the file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_name_cannot_climb_out_of_the_plugin_directory() {
        // The bug this function exists for: the C++ host joined the requested
        // name onto the destination unsanitised, so an artifact could be
        // written anywhere the server could write.
        let suffix = crate::loader::cdylib_suffix();
        for attempt in [
            format!("../evil{suffix}"),
            format!("../../evil{suffix}"),
            format!("sub/dir/evil{suffix}"),
        ] {
            let name = safe_file_name(&attempt).expect("the stem itself is fine");
            assert_eq!(
                name,
                format!("evil{suffix}"),
                "{attempt} must collapse to a bare file name"
            );
            assert!(!name.contains(['/', '\\']), "{attempt} kept a separator");
        }
    }

    #[test]
    fn only_something_the_scanner_would_load_is_written() {
        // Writing a file the directory scan then ignores leaves litter that
        // looks like a successful install, so it is refused up front.
        assert!(safe_file_name("notes.txt").is_err());
        assert!(safe_file_name("").is_err());
        assert!(safe_file_name(".hidden.so").is_err());
        assert!(safe_file_name("plugin.wasm").is_ok());
    }

    #[test]
    fn bytes_that_do_not_match_their_digest_are_refused() {
        let dir = std::env::temp_dir().join("starling-plugin-install-test");
        let err = write_artifact(
            &dir,
            &format!("p{}", crate::loader::wasm_suffix()),
            b"hello",
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        )
        .expect_err("a mismatched digest must not install");
        assert!(matches!(err, InstallError::DigestMismatch { .. }));
    }

    #[test]
    fn a_matching_digest_installs_and_is_readable_again() {
        let dir = std::env::temp_dir().join("starling-plugin-install-ok");
        let _ = std::fs::remove_dir_all(&dir);
        let bytes = b"a plugin, notionally".as_slice();
        let name = format!("p{}", crate::loader::wasm_suffix());
        let path = write_artifact(&dir, &name, bytes, Some(&digest(bytes))).expect("install");
        assert_eq!(std::fs::read(&path).expect("read back"), bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
