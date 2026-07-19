//! Composition: one service, or every service in one process.
//!
//! `--all-in-one` is not a second code path. Every service is built and served
//! exactly as it is in a twenty-four-pod deployment; the only difference is
//! that the transport underneath is an in-memory pipe rather than a socket, and
//! that difference lives entirely in `starling-runtime`.

use std::path::Path;
use std::sync::Arc;

use starling_runtime::config::Config;
use starling_runtime::inproc::Broker;
use starling_runtime::log::{Category, LogEvent, LogRuntime};
use starling_runtime::serve::{ServiceError, context};
use starling_runtime::shutdown::Shutdown;
use starling_runtime::telemetry;

use crate::units;

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

/// `--config <path>`, or the built-in defaults.
pub(crate) fn load(arguments: &[String]) -> Result<Config, ServiceError> {
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--config" {
            let path = arguments
                .next()
                .ok_or_else(|| ServiceError::service("--config needs a path"))?;
            return Ok(Config::load(Path::new(path))?);
        }
    }
    let mut config = Config::with_defaults(Path::new("starling-data/run"));
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

    #[test]
    fn a_disabled_service_is_not_started() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        if let Some(pchat) = config.services.get_mut("pchat") {
            pchat.enabled = false;
        }
        assert!(!enabled(&config, "pchat"));
    }
}
