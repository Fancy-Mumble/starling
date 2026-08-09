//! First start: write a configuration, create the administrator, say so.
//!
//! What turns a downloaded file into a running server. Someone who unpacked a
//! `.zip`, installed a `.deb` or double-clicked a `.dmg` has been given no
//! configuration, no administrator password and no idea where either would go,
//! and every one of those is a question this can answer without asking.
//!
//! It happens exactly once, and only when [`crate::compose::Source::Fresh`] says
//! there is no configuration at the place this platform keeps one. A second
//! start finds the file it wrote and does nothing: the sample is the operator's
//! from the moment it exists, so nothing here ever rewrites it.
//!
//! The administrator is created *before* the services start rather than by
//! `userdata` on its way up, which is what lets the password appear in the
//! banner instead of somewhere in the scrollback. `Accounts::ensure_superuser`
//! is the same call `userdata` makes and is create-once, so `userdata` then
//! finds the account already there and stays quiet -- the credential is still
//! announced exactly once.

use std::path::Path;

use starling_runtime::config::Config;
use starling_runtime::log::{Category, LogEvent};
use starling_runtime::serve::{ServiceContext, ServiceError};
use starling_userdata::Accounts;

/// The configuration Starling ships, and the one a first start is given.
///
/// The shipped file rather than a second one written for this purpose: two
/// starter configurations drift, and the one an operator is told to read in the
/// README would not be the one on their disk.
const EXAMPLE: &str = include_str!("../../../starling.example.toml");

/// The line in [`EXAMPLE`] that says where data goes.
const DATA_DIR_KEY: &str = "data_dir = ";

/// Write the starter configuration to `path`, pointed at `data_dir`.
///
/// # Errors
///
/// A message when the directory or the file cannot be created. Refusing to
/// start is deliberate: the alternative is a server that runs from defaults and
/// loses whatever the operator later writes into a file it never reads.
pub(crate) fn write_config(path: &Path, data_dir: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    std::fs::write(path, sample(data_dir)?).map_err(|error| format!("{}: {error}", path.display()))
}

/// Create the data directory, restricted to its owner where that is a concept.
///
/// It holds every account database and the server's private key, and a default
/// umask leaves both world-readable. Created here rather than left to the first
/// service that needs it, because the permissions have to be right *before*
/// anything is written into it, not after.
///
/// # Errors
///
/// A message when the directory cannot be created. Its mode failing to apply is
/// not an error: a filesystem without Unix permissions is not a reason to
/// refuse to start.
pub(crate) fn prepare_data_dir(data_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|error| format!("{}: {error}", data_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// [`EXAMPLE`], with the data directory pointed at `data_dir`.
///
/// # Errors
///
/// A message when the shipped example no longer carries the key this rewrites,
/// which would otherwise ship a first start whose data directory silently
/// landed in the working directory.
fn sample(data_dir: &Path) -> Result<String, String> {
    // Through `toml::Value` rather than by quoting: on Windows this path is
    // full of backslashes, every one of which is an escape in a TOML basic
    // string, so `data_dir = "C:\Users\Ada\..."` is both wrong and, at `\U`, a
    // parse error on a file the operator never typed.
    let value = toml::Value::from(data_dir.display().to_string());
    let mut written = false;
    let mut out = String::with_capacity(EXAMPLE.len() + 256);
    out.push_str(HEADER);
    for line in EXAMPLE.lines() {
        if !written && line.starts_with(DATA_DIR_KEY) {
            out.push_str(&format!("{DATA_DIR_KEY}{value}"));
            written = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if written {
        Ok(out)
    } else {
        Err(format!(
            "starling.example.toml no longer has a `{DATA_DIR_KEY}` line to point at {}",
            data_dir.display()
        ))
    }
}

/// What a written configuration says about itself, above the shipped comments.
const HEADER: &str = "\
# Written by Starling on its first start, because there was no configuration
# here yet. It is yours now: edit it freely, nothing rewrites it, and a start
# that finds it leaves it exactly as it is.
#
# `starling --all-in-one` reads this file without being told to. Any other file
# takes `--config <path>`.

";

/// Create each server instance's administrator, and return the passwords.
///
/// Returns one entry per server instance that did not have a SuperUser, which on
/// a genuine first start is all of them and on a restored database may be none.
///
/// # Errors
///
/// [`ServiceError`] when userdata's database cannot be opened or written, which
/// is a server nobody could administer.
pub(crate) async fn create_administrator(
    ctx: &ServiceContext,
) -> Result<Vec<(u32, String)>, ServiceError> {
    let accounts = Accounts::open(ctx.storage().await?).await?;
    let mut created = Vec::new();
    for scope in ctx.instances() {
        let Some(password) = accounts.ensure_superuser(scope).await else {
            continue;
        };
        // The same record `userdata` writes when it is the one that generates
        // the account, so an operator who scrolled past the banner still has
        // the credential wherever their logs go. The banner is the console
        // copy; this is the durable one.
        ctx.logger.log(
            LogEvent::notice(
                Category::Server,
                "superuser account created; this password is shown once and cannot be recovered",
            )
            .with("instance", scope)
            .with("user", "SuperUser")
            .with("password", password.clone()),
        );
        created.push((scope, password));
    }
    Ok(created)
}

/// The width of the banner's rules, in columns.
const WIDTH: usize = 78;

/// What a first start prints, once.
///
/// ASCII only, and no colour. This is the one message that has to survive being
/// read over `docker logs`, in a `journalctl` pager, and in a Windows console
/// still on a legacy code page, where box-drawing characters arrive as mojibake
/// and an escape sequence arrives as literal `←[0m`.
pub(crate) fn banner(config: &Config, config_file: &Path, created: &[(u32, String)]) -> String {
    let rule = "=".repeat(WIDTH);
    let mut text = format!(
        "\n{rule}\n  STARLING {}   |   FIRST START\n{rule}\n\n  \
         There was no configuration here, so one has been written and this\n  \
         server is ready to use. You will not see this message again.\n",
        env!("CARGO_PKG_VERSION")
    );
    text.push_str(&administrator(created));
    text.push_str(&format!(
        "\n  Files\n    \
         configuration   {}\n    \
         data            {}\n\n    \
         The data directory holds the account databases and the certificate\n    \
         that is this server's identity to every client that has connected.\n    \
         Back it up; losing it looks to a client like a different server.\n",
        config_file.display(),
        config.runtime.data_dir.display()
    ));
    text.push_str(&connect(config));
    text.push_str(&format!("\n{rule}\n\n"));
    text
}

/// The banner's administrator block.
fn administrator(created: &[(u32, String)]) -> String {
    if created.is_empty() {
        // A database restored from a backup that already had the account. Its
        // password is whatever it was, and saying nothing here is better than
        // implying this start changed it.
        return "\n  Administrator\n    \
                The SuperUser account was already in the database, so its\n    \
                password is unchanged. Forgotten it?\n      \
                starling set-superuser-password <new password>\n"
            .to_owned();
    }
    let mut text = String::from("\n  Administrator\n");
    for (scope, password) in created {
        // The id only when there is more than one to tell apart: on the
        // single-server deployment this ships with, "server instance 1" is a
        // number the reader has no use for.
        if created.len() > 1 {
            text.push_str(&format!("    server instance  {scope}\n"));
        }
        text.push_str(&format!(
            "    user            SuperUser\n    password        {password}\n"
        ));
    }
    text.push_str(
        "\n    Stored only as a hash, so it cannot be shown again: write it\n    \
         down now. To choose a different one at any time:\n      \
         starling set-superuser-password <new password>\n",
    );
    text
}

/// The banner's connection block.
fn connect(config: &Config) -> String {
    let port = config.instances.first().map_or(64738, |server| server.port);
    let name = config
        .instances
        .first()
        .map_or("Starling", |server| server.name.as_str());
    format!(
        "\n  Connect\n    \
         Point a Mumble client at   localhost:{port}\n    \
         and log in as SuperUser with the password above. The server is\n    \
         called {name:?}; rename it in the configuration file.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_written_sample_points_at_the_data_directory_it_was_given() {
        let rendered = sample(Path::new("/srv/starling")).expect("the example has the key");
        assert!(
            rendered.contains("data_dir = \"/srv/starling\""),
            "the data directory was not written:\n{rendered}"
        );
        assert!(
            !rendered.contains("data_dir = \"starling-data\""),
            "the shipped default survived the rewrite:\n{rendered}"
        );
    }

    #[test]
    fn a_windows_path_is_escaped_rather_than_pasted() {
        // `"C:\Users\Ada"` is not the path it looks like: `\U` is a TOML escape
        // and rejects the file outright, so a Windows first start would write a
        // configuration its own next start refuses to parse.
        let windows = PathBuf::from(r"C:\Users\Ada\AppData\Local\Starling");
        let rendered = sample(&windows).expect("the example has the key");
        let parsed: toml::Table = rendered
            .parse()
            .unwrap_or_else(|error| panic!("what was written must parse: {error}\n{rendered}"));
        assert_eq!(
            parsed["runtime"]["data_dir"].as_str(),
            Some(r"C:\Users\Ada\AppData\Local\Starling")
        );
    }

    #[test]
    fn what_a_first_start_writes_is_a_configuration_starling_accepts() {
        // The whole point of writing a file is that the next start reads it.
        // Through the real loader, which rejects unknown keys, so a sample that
        // drifted from the structs fails here rather than on somebody's box.
        let directory = std::env::temp_dir().join(format!(
            "starling-firstrun-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = directory.join("starling.toml");
        let data = directory.join("data");
        write_config(&path, &data).expect("the sample is written");
        let config = Config::load(&path).expect("the sample loads");
        assert_eq!(config.runtime.data_dir, data);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_banner_carries_the_password_the_paths_and_the_port() {
        // Everything somebody needs to reach the server they just started. A
        // banner missing any one of them sends them to the documentation.
        let config = Config::load(Path::new("../../starling.example.toml")).expect("loads");
        let text = banner(
            &config,
            Path::new("/home/ada/.config/starling/starling.toml"),
            &[(1, "swordfish".to_owned())],
        );
        assert!(text.contains("swordfish"), "{text}");
        assert!(text.contains("SuperUser"), "{text}");
        assert!(
            text.contains("/home/ada/.config/starling/starling.toml"),
            "{text}"
        );
        assert!(text.contains("64738"), "{text}");
        assert!(text.contains("set-superuser-password"), "{text}");
    }

    #[test]
    fn the_banner_is_ascii_so_every_console_renders_it() {
        // A Windows console on a legacy code page turns box drawing into
        // mojibake, and the one message a first-time operator must be able to
        // read is this one.
        let config = Config::default();
        let text = banner(&config, Path::new("/tmp/starling.toml"), &[]);
        assert!(text.is_ascii(), "{text}");
    }

    #[test]
    fn a_database_that_already_had_an_administrator_is_not_claimed_to_have_a_new_password() {
        // Restored from a backup. Printing "password: none" or an empty line
        // would read as the account being broken.
        let config = Config::default();
        let text = banner(&config, Path::new("/tmp/starling.toml"), &[]);
        assert!(text.contains("password is unchanged"), "{text}");
        assert!(text.contains("set-superuser-password"), "{text}");
    }
}
