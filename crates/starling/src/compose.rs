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
use starling_runtime::live::ConfigCell;
use starling_runtime::log::{Category, LogEvent, LogHandles, LogRuntime, Logger, Severity};
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
    // Before anything can panic. In a release build a panic aborts, so this is
    // the only chance to write down why.
    install_panic_hook(logger.clone());
    let handles = log.handles();
    let source = source_path(arguments);
    let runtime = tokio::runtime::Runtime::new()?;

    let result = runtime.block_on(async move {
        let shutdown = Shutdown::new();
        shutdown.install_signal_handler();
        let config = Arc::new(config);
        let cell = cell_for(&config, source, &logger, handles);

        let ctx = context(name, config, Broker::new(), shutdown, logger).following(cell);
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
    // Before anything can panic. In a release build a panic aborts, taking the
    // whole all-in-one process with it, so this is the only chance to write
    // down which task it was and where.
    install_panic_hook(logger.clone());
    let handles = log.handles();
    // After the first-start write above, so a fresh deployment reloads the file
    // it just created rather than reporting that it has none.
    let source = source_path(arguments);
    let config = Arc::new(config);
    let runtime = tokio::runtime::Runtime::new()?;

    let result = runtime.block_on(async move {
        let shutdown = Shutdown::new();
        shutdown.install_signal_handler();
        let broker = Broker::new();
        // One cell for the whole process, so a single SIGHUP is one read of the
        // file and one consistent view of it across all twenty-two units. A
        // cell each would mean twenty-two reads racing an operator's editor.
        let cell = cell_for(&config, source, &logger, handles);

        // One for the whole process, because every service below shares it and
        // a restart is a process-wide event: a dead sweep in `voice` is this
        // process's problem however healthy `pchat` is.
        // See `ServiceContext::sharing_health`.
        let health = starling_runtime::health::Health::new();

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
            )
            .following(cell.clone())
            .sharing_health(health.clone());
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
        )
        .following(cell.clone())
        .sharing_health(health.clone());
        let Some(gateway) = units::spawn("gateway", gateway_ctx) else {
            return Err(ServiceError::service("the gateway could not be started"));
        };

        // Watched while the gateway runs, not only after it stops. A service
        // task that ended at t=0 used to be noticed at shutdown, as a "did not
        // stop cleanly" warning however many hours later, with everything that
        // depended on it failing in between and nothing saying why.
        //
        // Watched, deliberately, rather than supervised: nothing here restarts
        // a service or brings the process down. Which of those is right is a
        // per-service decision and this is not where it is made. What this does
        // is stop the event being invisible.
        let mut watch = ServiceWatch::new();
        for (name, handle) in handles {
            let _ = watch.spawn(async move { (name, handle.await) });
        }

        tracing::info!(services = watch.len(), "all-in-one");
        logger.log(
            LogEvent::info(Category::Server, "all services started").with("services", watch.len()),
        );

        let watchdog = start_watchdog(&health, &shutdown);
        let result = run_until_gateway_stops(gateway, &mut watch, &logger).await;
        if let Some(watchdog) = watchdog {
            watchdog.abort();
        }

        // Draining the gateway drains everything: a service outliving the
        // socket that feeds it is a process that will not exit.
        logger.log(LogEvent::info(Category::Server, "draining"));
        shutdown.drain();
        while let Some(Ok((name, outcome))) = watch.join_next().await {
            note_service_end(&logger, true, name, outcome);
        }
        result
    });

    log.logger()
        .log(LogEvent::info(Category::Server, "starling stopped").with("component", "all-in-one"));
    log.finish();
    result
}

/// Write a record for a panic before the process aborts on it.
///
/// Release builds set `panic = "abort"`, so a panic ends the process without
/// unwinding: `log.finish()` never runs and the operator log's tail -- the part
/// describing what led to the crash -- is lost in whatever buffer held it. The
/// hook writes the panic itself and flushes, so the last line in the file is
/// the reason there are no more.
///
/// Installed once, from the process entry point rather than per service: there
/// is one process and one hook.
pub(crate) fn install_panic_hook(logger: Logger) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map_or_else(String::new, |at| format!("{}:{}", at.file(), at.line()));
        logger.log(
            LogEvent::new(Severity::Critical, Category::Server, "panic")
                .with("message", info.to_string())
                .with("location", location)
                .with(
                    "thread",
                    std::thread::current()
                        .name()
                        .unwrap_or("unnamed")
                        .to_owned(),
                ),
        );
        // Waited on, not merely requested: `request_flush` returns before the
        // write lands, and the next instruction after this hook is the abort.
        // Bounded, so a writer already wedged on a full disk turns a panic into
        // a lost record rather than a hang.
        let _ = logger.flush_blocking(std::time::Duration::from_secs(2));
        // The default hook still runs, so the backtrace reaches stderr the way
        // a developer expects.
        previous(info);
    }));
}

/// Tell systemd the server is up, and keep telling it while it works.
///
/// Called once every service has started and the gateway is accepting. Before
/// this, the unit was `Type=exec`, so systemd considered it started as soon as
/// the process existed and `systemctl start` returned while nothing could yet
/// answer a login.
///
/// The returned handle pings for as long as the process is live. `None` when
/// there is no systemd to tell, which is every deployment that is not a
/// `Type=notify` unit.
fn start_watchdog(
    health: &starling_runtime::health::Health,
    shutdown: &Shutdown,
) -> Option<tokio::task::JoinHandle<()>> {
    starling_runtime::notify::ready();
    let interval = starling_runtime::notify::interval_from_env()?;
    Some(tokio::spawn(starling_runtime::notify::watchdog(
        health.clone(),
        shutdown.clone(),
        interval,
    )))
}

/// Serve until the gateway stops, reporting any service that stops first.
///
/// The gateway is the one whose result is the process's, so it is what the
/// wait is *for*; the services are watched alongside it only so that one dying
/// early is a record at the time rather than a puzzle at shutdown.
async fn run_until_gateway_stops(
    gateway: tokio::task::JoinHandle<Result<(), ServiceError>>,
    watch: &mut ServiceWatch,
    logger: &Logger,
) -> Result<(), ServiceError> {
    let mut gateway = gateway;
    loop {
        tokio::select! {
            // Biased so that when the gateway and a service end together,
            // which is what a drain looks like, the gateway's own result is
            // reported rather than whichever of the two the runtime polled
            // first.
            biased;
            joined = &mut gateway => {
                return match joined {
                    Ok(result) => result,
                    Err(error) => Err(ServiceError::service(format!("gateway stopped: {error}"))),
                };
            }
            Some(Ok((name, outcome))) = watch.join_next() => {
                note_service_end(logger, false, name, outcome);
            }
        }
    }
}

/// Every service task, named, so one ending can be reported as itself.
type ServiceWatch = tokio::task::JoinSet<(
    &'static str,
    Result<Result<(), ServiceError>, tokio::task::JoinError>,
)>;

/// Record how one service task ended, and whether that was asked for.
///
/// Before the drain, a service returning *at all* is the event: nothing asked
/// it to stop, and everything depending on it is about to start failing. After
/// the drain, returning is exactly what was asked for and only a failure is
/// worth a record.
fn note_service_end(
    logger: &Logger,
    draining: bool,
    name: &str,
    outcome: Result<Result<(), ServiceError>, tokio::task::JoinError>,
) {
    let (severity, message, detail) = match outcome {
        Ok(Ok(())) if draining => return,
        Ok(Ok(())) => (
            Severity::Error,
            "service stopped early",
            "it returned before anything asked it to drain".to_owned(),
        ),
        Ok(Err(error)) => (Severity::Error, "service failed", error.to_string()),
        // `JoinError` renders the panic payload, so the record carries the
        // message the panic itself was written with.
        Err(error) if error.is_panic() => {
            (Severity::Critical, "service panicked", error.to_string())
        }
        Err(error) => (
            Severity::Warning,
            "service did not stop cleanly",
            error.to_string(),
        ),
    };
    logger.log(
        LogEvent::new(severity, Category::Server, message)
            .with("service", name.to_owned())
            .with("error", detail),
    );
}

/// Whether a service should run in this process.
pub fn enabled(config: &Config, name: &str) -> bool {
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
/// The process's configuration cell, with SIGHUP and the log-level applier
/// already wired to it.
///
/// One function because the two entry points must agree: a reload that worked
/// under `--all-in-one` and did nothing for a single service would be the
/// worst kind of difference between the two deployment modes, and exactly the
/// kind the routing table drifted into once already.
fn cell_for(
    config: &Arc<Config>,
    source: Option<PathBuf>,
    logger: &Logger,
    handles: LogHandles,
) -> ConfigCell {
    let cell = match source {
        Some(path) => ConfigCell::watching(Arc::clone(config), path),
        None => ConfigCell::fixed(Arc::clone(config)),
    };
    // Re-decided on every reload, because it is a decision this entry point
    // made rather than something the file said: `all_in_one` forces the flag
    // after loading, and a reload that re-read the file without it reported the
    // flag as a change needing a restart, every single time.
    let all_in_one = config.runtime.all_in_one;
    let cell = cell.adjusting(move |config| config.runtime.all_in_one = all_in_one);
    cell.install_signal_handler(logger);
    starling_runtime::live::follow_logging(&cell, handles, logger.clone());
    cell
}

/// The file this run reads, when there is one.
///
/// `None` for a run on the built-in defaults, which has no file to re-read and
/// so cannot be reloaded. Resolved from the same [`source`] as [`load`], so the
/// two can never disagree about which file is in play -- and called *after* a
/// first start has written its configuration, which is what turns a `Fresh`
/// resolution into the `Found` one below.
pub(crate) fn source_path(arguments: &[String]) -> Option<PathBuf> {
    match source(arguments) {
        Source::Given(path) if path.as_os_str().is_empty() => None,
        Source::Given(path) | Source::Found(path) => Some(path),
        Source::Fresh { .. } | Source::Builtin => None,
    }
}

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
