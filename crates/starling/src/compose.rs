//! Composition: one service, or every service in one process.
//!
//! `--all-in-one` is not a second code path. Every service is built and served
//! exactly as it is in a twenty-four-pod deployment; the only difference is
//! that the transport underneath is an in-memory pipe rather than a socket, and
//! that difference lives entirely in `starling-runtime`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use starling_runtime::config::Config;
use starling_runtime::inproc::Broker;
use starling_runtime::log::{Category, LogEvent, LogRuntime, Logger};
use starling_runtime::serve::{ServiceError, context};
use starling_runtime::shutdown::Shutdown;
use starling_runtime::telemetry;

use crate::{firstrun, paths, units};

/// Run one component.
pub(crate) fn one(name: &str, arguments: &[String]) -> Result<(), ServiceError> {
    let config = load(arguments)?;
    telemetry::install(&config.telemetry);
    let log = LogRuntime::start_from(&config.logging);
    log.logger().log(
        LogEvent::info(Category::Server, "starling starting")
            .with("component", name.to_owned())
            .with("version", env!("CARGO_PKG_VERSION")),
    );
    let logger = log.logger().clone();
    let runtime = tokio::runtime::Runtime::new()?;

    let result = runtime.block_on(async move {
        let shutdown = Shutdown::new();
        shutdown.install_signal_handler();
        let ctx = context(name, Arc::new(config), Broker::new(), shutdown, logger);
        let Some(handle) = units::spawn(name, ctx) else {
            return Err(ServiceError::service(format!("no service named {name:?}")));
        };
        match handle.await {
            Ok(result) => result,
            Err(error) => Err(ServiceError::service(format!("{name} stopped: {error}"))),
        }
    });

    log.logger().log(
        LogEvent::info(Category::Server, "starling stopped").with("component", name.to_owned()),
    );
    log.finish();
    result
}

/// Run every service, plus the gateway, in one process.
pub(crate) fn all_in_one(arguments: &[String]) -> Result<(), ServiceError> {
    // A first start writes its configuration before anything reads one, so that
    // what runs now is the file the next start will find rather than defaults
    // that happen to resemble it. Resolved a second time below for exactly that
    // reason: the file exists by then, and `load` reads it.
    let first_start = match source(arguments) {
        Source::Fresh { config, data } => {
            firstrun::prepare_data_dir(&data).map_err(ServiceError::service)?;
            firstrun::write_config(&config, &data).map_err(ServiceError::service)?;
            Some(config)
        }
        _ => None,
    };
    let mut config = load(arguments)?;
    config.runtime.all_in_one = true;
    telemetry::install(&config.telemetry);
    let log = LogRuntime::start_from(&config.logging);
    log.logger().log(
        LogEvent::info(Category::Server, "starling starting")
            .with("component", "all-in-one")
            .with("version", env!("CARGO_PKG_VERSION"))
            .with("data_dir", config.runtime.data_dir.display().to_string()),
    );
    let logger = log.logger().clone();
    let config = Arc::new(config);
    let runtime = tokio::runtime::Runtime::new()?;

    let result = runtime.block_on(async move {
        let shutdown = Shutdown::new();
        shutdown.install_signal_handler();
        let broker = Broker::new();

        // Before the services rather than during them. `userdata` creates the
        // administrator on its way up and announces the password there, which
        // puts the one credential nobody can recover somewhere in the middle of
        // twenty-one startup records. Doing it here puts it in the banner
        // instead, and leaves `userdata` finding the account already made.
        if let Some(path) = &first_start {
            announce_first_start(&config, &broker, &shutdown, &logger, path).await?;
        }

        // Services first, gateway last: the gateway attaches to whatever it
        // finds, and starting it first would mean a reconnect for every one of
        // them. Not a correctness problem (attachments retry) but a second of
        // log noise on every boot is a second of log noise nobody reads after.
        let mut handles = Vec::new();
        let mut skipped = Vec::new();
        for name in units::names() {
            if !enabled(&config, name) {
                skipped.push(*name);
                continue;
            }
            let ctx = context(
                name,
                Arc::clone(&config),
                broker.clone(),
                shutdown.clone(),
                logger.clone(),
            );
            if let Some(handle) = units::spawn(name, ctx) {
                handles.push((*name, handle));
            }
        }

        // Which services are *not* running is the question behind most "why is
        // this feature dead" reports, and it is unanswerable from a log that
        // only records what started.
        if !skipped.is_empty() {
            logger.log(
                LogEvent::notice(Category::Server, "services disabled by configuration")
                    .with("services", skipped.join(", ")),
            );
        }

        let gateway_ctx = context(
            "gateway",
            Arc::clone(&config),
            broker.clone(),
            shutdown.clone(),
            logger.clone(),
        );
        let Some(gateway) = units::spawn("gateway", gateway_ctx) else {
            return Err(ServiceError::service("the gateway could not be started"));
        };

        tracing::info!(services = handles.len(), "all-in-one");
        logger.log(
            LogEvent::info(Category::Server, "all services started")
                .with("services", handles.len()),
        );
        let result = match gateway.await {
            Ok(result) => result,
            Err(error) => Err(ServiceError::service(format!("gateway stopped: {error}"))),
        };

        // Draining the gateway drains everything: a service outliving the
        // socket that feeds it is a process that will not exit.
        logger.log(LogEvent::info(Category::Server, "draining"));
        shutdown.drain();
        for (name, handle) in handles {
            if let Err(error) = handle.await {
                logger.log(
                    LogEvent::warning(Category::Server, "service did not stop cleanly")
                        .with("service", name)
                        .with("error", error.to_string()),
                );
            }
        }
        result
    });

    log.logger()
        .log(LogEvent::info(Category::Server, "starling stopped").with("component", "all-in-one"));
    log.finish();
    result
}

/// Whether a service should run in this process.
pub(crate) fn enabled(config: &Config, name: &str) -> bool {
    config
        .services
        .get(name)
        .map_or(name != "operator-api", |service| service.enabled)
}

/// Create the administrator and print the first-start banner.
///
/// Split out of [`all_in_one`] rather than inlined: the context it needs is
/// four values that only exist inside the runtime, and building them there is
/// what keeps the difference between a first start and every other one to the
/// three lines that call this.
async fn announce_first_start(
    config: &Arc<Config>,
    broker: &Broker,
    shutdown: &Shutdown,
    logger: &Logger,
    config_file: &Path,
) -> Result<(), ServiceError> {
    // `userdata`'s own context, because this opens `userdata`'s database. Any
    // other name here would resolve a different storage URL and quietly create
    // an administrator in a file the service never reads.
    let ctx = context(
        "userdata",
        Arc::clone(config),
        broker.clone(),
        shutdown.clone(),
        logger.clone(),
    );
    let created = firstrun::create_administrator(&ctx).await?;
    crate::out(&firstrun::banner(config, config_file, &created)).map_err(ServiceError::service)
}

/// Where this run's configuration comes from.
///
/// Named rather than resolved inline because the answer decides more than which
/// file to read: a [`Source::Fresh`] is the one case that writes anything, and
/// the one case that prints a banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    /// `--config <path>`. A file that is not there is an error, not an
    /// invitation to create one: the operator named it, so a missing file is a
    /// typo, and writing a fresh server over the path they meant to load would
    /// be the worst possible reading of it.
    Given(PathBuf),
    /// This platform's own location, with a configuration already in it.
    Found(PathBuf),
    /// This platform's own location, with nothing in it yet. A first start.
    Fresh {
        /// The file to write, and then read.
        config: PathBuf,
        /// The data directory that file will name.
        data: PathBuf,
    },
    /// The built-in defaults, rooted at the working directory.
    ///
    /// What every release before the downloadable packages did with no
    /// `--config`, kept for the two cases where it is still the right answer:
    /// a directory that is already a Starling deployment, and an environment
    /// with no home directory to put anything in.
    Builtin,
}

/// Work out where this run's configuration comes from.
pub(crate) fn source(arguments: &[String]) -> Source {
    let locations = paths::locations();
    resolve(
        explicit(arguments),
        locations.as_ref(),
        locations
            .as_ref()
            .is_some_and(|locations| locations.config_file().is_file()),
        paths::in_use(&Config::default().runtime.data_dir),
    )
}

/// The `--config` argument, if there is one.
///
/// An empty path stands for `--config` with nothing after it, which [`load`]
/// reports rather than guesses at.
fn explicit(arguments: &[String]) -> Option<PathBuf> {
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if argument == "--config" {
            return Some(rest.next().map(PathBuf::from).unwrap_or_default());
        }
    }
    None
}

/// [`source`], with the two filesystem questions already answered.
///
/// Taken as answers rather than asked here so that the precedence below is a
/// test rather than a claim: asking the real filesystem would make these rules
/// depend on the home directory of whoever is running the suite.
fn resolve(
    explicit: Option<PathBuf>,
    locations: Option<&paths::Locations>,
    config_exists: bool,
    deployment_here: bool,
) -> Source {
    if let Some(path) = explicit {
        return Source::Given(path);
    }
    // An existing configuration wins over everything below it, the
    // working-directory check included: a server that was set up once must keep
    // starting the same way from whatever directory it is started in.
    if let (Some(locations), true) = (locations, config_exists) {
        return Source::Found(locations.config_file());
    }
    // Before choosing a new home. A directory already holding a deployment's
    // databases and certificate *is* that deployment, and moving it would look
    // to every client that ever connected like a different server.
    if deployment_here {
        return Source::Builtin;
    }
    locations.map_or(Source::Builtin, |locations| Source::Fresh {
        config: locations.config_file(),
        data: locations.data.clone(),
    })
}

/// The configuration this run should use.
///
/// Reads a file when there is one to read, and never writes: creating a first
/// start is [`all_in_one`]'s decision, so that `set-superuser-password` and a
/// single-service run resolve the same paths without bringing a server into
/// existence as a side effect of asking where one is.
pub(crate) fn load(arguments: &[String]) -> Result<Config, ServiceError> {
    match source(arguments) {
        Source::Given(path) if path.as_os_str().is_empty() => {
            Err(ServiceError::service("--config needs a path"))
        }
        Source::Given(path) | Source::Found(path) => Ok(Config::load(&path)?),
        // Not yet written, so there is nothing to read: the defaults it would
        // have been rendered from, under the same data directory it will name.
        Source::Fresh { data, .. } => defaults(&data),
        Source::Builtin => defaults(&Config::default().runtime.data_dir),
    }
}

/// The built-in defaults, rooted at `data_dir`, with the environment applied.
fn defaults(data_dir: &Path) -> Result<Config, ServiceError> {
    let mut config = Config::with_defaults(&data_dir.join("run"));
    config.runtime.data_dir = data_dir.to_path_buf();
    starling_runtime::config::apply_environment(
        &mut config,
        &std::env::vars().collect::<Vec<_>>(),
    )?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admin_plane_is_off_unless_it_is_configured() {
        // The highest-privilege surface must not appear because somebody ran
        // the binary with no file.
        let config = Config::with_defaults(Path::new("/run/starling"));
        let mut bare = config;
        bare.services.clear();
        assert!(!enabled(&bare, "operator-api"));
        assert!(enabled(&bare, "text"));
    }

    /// A platform's directories, for [`resolve`].
    fn locations() -> paths::Locations {
        paths::Locations {
            config: PathBuf::from("/home/ada/.config/starling"),
            data: PathBuf::from("/home/ada/.local/share/starling"),
        }
    }

    #[test]
    fn an_explicit_config_is_taken_exactly_as_given() {
        // Including one that does not exist: `load` must report the typo rather
        // than write a fresh server over the path the operator meant.
        let named = ["--all-in-one", "--config", "a.toml"].map(str::to_owned);
        assert_eq!(source(&named), Source::Given(PathBuf::from("a.toml")));
        assert!(load(&["--config".to_owned(), "no-such-file.toml".to_owned()]).is_err());
        assert!(
            load(&["--config".to_owned()]).is_err(),
            "--config with no path is an error, not the defaults"
        );
    }

    #[test]
    fn a_working_directory_that_is_already_a_deployment_keeps_its_own_layout() {
        // The compatibility hinge. `starling --all-in-one` with no `--config`
        // has always meant `./starling-data`, and adopting this platform's
        // directories out from under such a directory would lose its databases
        // and, with the certificate, its identity to every client that ever
        // connected.
        assert_eq!(
            resolve(None, Some(&locations()), false, true),
            Source::Builtin
        );
        // And `Builtin` still resolves to exactly what it always did.
        let config = defaults(Path::new("starling-data")).expect("the defaults");
        assert_eq!(config.runtime.data_dir, PathBuf::from("starling-data"));
    }

    #[test]
    fn a_configuration_that_exists_wins_over_a_directory_that_looks_like_a_deployment() {
        // Otherwise a server configured once starts differently depending on
        // which directory its launcher happened to be in.
        assert_eq!(
            resolve(None, Some(&locations()), true, true),
            Source::Found(PathBuf::from("/home/ada/.config/starling/starling.toml"))
        );
    }

    #[test]
    fn a_machine_that_has_never_run_starling_gets_a_first_start() {
        assert_eq!(
            resolve(None, Some(&locations()), false, false),
            Source::Fresh {
                config: PathBuf::from("/home/ada/.config/starling/starling.toml"),
                data: PathBuf::from("/home/ada/.local/share/starling"),
            }
        );
    }

    #[test]
    fn an_environment_with_nowhere_to_put_anything_falls_back_rather_than_failing() {
        // A service account or a stripped container: no home directory, so no
        // platform location. The working directory is still a working answer,
        // and it is the one every release before this shipped.
        assert_eq!(resolve(None, None, false, false), Source::Builtin);
    }

    #[test]
    fn a_disabled_service_is_not_started() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        if let Some(pchat) = config.services.get_mut("pchat") {
            pchat.enabled = false;
        }
        assert!(!enabled(&config, "pchat"));
    }
}
