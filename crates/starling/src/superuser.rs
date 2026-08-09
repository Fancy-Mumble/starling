//! `starling set-superuser-password`: murmur's `--set-su-pw`.
//!
//! # Why this exists next to the operator API
//!
//! `operator-api` can set the same password over HTTP, and for routine rotation
//! that is the better route: it is authenticated, scoped and audited. But it is
//! **off by default and behind a bearer token**, which makes it exactly the wrong
//! tool for the two occasions this credential is usually needed:
//!
//! * a fresh deployment where nobody has read the announcement yet, and
//! * a recovery where the password is lost and the admin plane was never enabled.
//!
//! Both are the case murmur's flag covers, so this covers it too. It writes
//! straight to userdata's own database rather than asking a service, because in
//! both situations the point is not needing the rest of the server to be running.
//!
//! It reads userdata's storage through the same [`starling_runtime::ServiceContext::storage`] the
//! service uses, so the file it writes is by construction the file the service
//! reads. Deriving the path a second way here is how a tool ends up quietly
//! editing a database nobody loads.

use std::sync::Arc;

use starling_runtime::inproc::Broker;
use starling_runtime::log::{Category, LogEvent, LogRuntime};
use starling_runtime::serve::{ServiceError, context};
use starling_runtime::shutdown::Shutdown;
use starling_userdata::Accounts;

/// Set the SuperUser password from the command line.
///
/// # Errors
///
/// A message when the arguments are unusable or userdata's database cannot be
/// opened or written.
pub(crate) fn set_password(arguments: &[String]) -> Result<(), String> {
    let password = positional(arguments)
        .ok_or("set-superuser-password needs a password\n\nusage: starling set-superuser-password <password> [--server <id>] [--config <file>]")?;
    // Refused rather than stored. murmur refuses the same thing, "empty" reads
    // as "disable the account", which is a different operation, and storing it
    // would leave an administrator login that any password opens.
    if password.trim().is_empty() {
        return Err("the superuser password cannot be empty".to_owned());
    }
    let scope = flag(arguments, "--server")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| format!("--server needs a server instance id, not {value:?}"))
        })
        .transpose()?;

    let config = crate::compose::load(arguments).map_err(|error| error.to_string())?;
    let scope = scope.unwrap_or_else(|| config.instances.first().map_or(1, |server| server.id));

    // The configured logger, not `Logger::null()`. This command resets the
    // administrator credential while deliberately bypassing the operator API,
    // the route this module's own documentation calls "authenticated, scoped
    // and audited". Leaving it unlogged means the one path that skips the audit
    // trail is also the one that leaves no trace, which is precisely backwards:
    // recovery and compromise look identical from the command line.
    let log = LogRuntime::start_from(&config.logging);
    let logger = log.logger().clone();

    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime
        .block_on(async move {
            let ctx = context(
                "userdata",
                Arc::new(config),
                Broker::new(),
                Shutdown::new(),
                logger.clone(),
            );
            let store = ctx.storage().await.map_err(ServiceError::from)?;
            let accounts = Accounts::open(store).await.map_err(ServiceError::from)?;
            accounts.set_superuser_password(scope, &password).await;
            // After the write, so this records what happened rather than what
            // was attempted. The password is not a field: the record says the
            // credential changed, never what it changed to.
            logger.log(
                LogEvent::notice(Category::Admin, "superuser password set")
                    .with("instance", scope)
                    .with("source", "command line"),
            );
            Ok::<_, ServiceError>(())
        })
        .map_err(|error| error.to_string())?;

    // Drained before returning, or the process exits with the record still in
    // the writer's queue and the log this just wrote never reaches its sink.
    log.finish();

    // Stdout as well as the log: this is a command that was asked for and
    // answered, and the answer is what the caller is waiting for. The password
    // itself is deliberately not echoed, whoever ran this typed it.
    crate::out(&format!(
        "superuser password set on server instance {scope}\n"
    ))
}

/// The first argument that is not a flag or a flag's value.
fn positional(arguments: &[String]) -> Option<String> {
    let mut rest = arguments.iter().skip(1);
    while let Some(argument) = rest.next() {
        if argument.starts_with("--") {
            // Every flag this command takes has a value, so skip both.
            let _ = rest.next();
            continue;
        }
        return Some(argument.clone());
    }
    None
}

/// The value of `name`, if it was given.
fn flag(arguments: &[String], name: &str) -> Option<String> {
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if argument == name {
            return rest.next().cloned();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn the_password_is_the_first_positional_argument() {
        assert_eq!(
            positional(&args(&["set-superuser-password", "hunter2"])),
            Some("hunter2".to_owned())
        );
    }

    #[test]
    fn a_flags_value_is_never_mistaken_for_the_password() {
        // The bug this guards: `--config starling.toml hunter2` setting the
        // password to "starling.toml" and reporting success.
        assert_eq!(
            positional(&args(&[
                "set-superuser-password",
                "--config",
                "starling.toml",
                "hunter2"
            ])),
            Some("hunter2".to_owned())
        );
        assert_eq!(
            positional(&args(&[
                "set-superuser-password",
                "--server",
                "2",
                "hunter2"
            ])),
            Some("hunter2".to_owned())
        );
    }

    #[test]
    fn a_missing_password_is_an_error_rather_than_an_empty_one() {
        assert!(positional(&args(&["set-superuser-password"])).is_none());
        assert!(
            set_password(&args(&["set-superuser-password"])).is_err(),
            "no password must not silently set an empty one"
        );
    }

    #[test]
    fn an_empty_password_is_refused() {
        // Storing it would leave an administrator login that any password opens.
        assert!(set_password(&args(&["set-superuser-password", "   "])).is_err());
    }

    #[test]
    fn a_non_numeric_server_id_is_reported_rather_than_defaulted() {
        // Defaulting would set the password on server instance 1 while the
        // operator believes they set it on another.
        let error = set_password(&args(&["set-superuser-password", "pw", "--server", "main"]))
            .expect_err("a non-numeric id must be refused");
        assert!(error.contains("--server"), "{error}");
    }

    #[test]
    fn the_flag_reader_finds_a_value_and_reports_its_absence() {
        assert_eq!(
            flag(&args(&["x", "--server", "7"]), "--server"),
            Some("7".to_owned())
        );
        assert_eq!(flag(&args(&["x", "--server"]), "--server"), None);
        assert_eq!(flag(&args(&["x"]), "--server"), None);
    }
}
