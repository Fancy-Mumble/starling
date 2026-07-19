//! Endpoint discovery: a service name in, a gRPC channel out.
//!
//! A caller names the service it wants and never learns which transport it got
//! that is the whole point of [`Transport`], and it is what makes
//! `--all-in-one` a configuration choice rather than a code path. Nothing here
//! knows what the transports are: dialling is [`Transport::connect`], and the
//! only thing this module decides is *which* transport a name resolves to.
//!
//! Channels are cached per service. tonic's `Channel` is a cheap handle over a
//! connection pool and is designed to be cloned, so building a second one per
//! call would throw away the pool and reconnect on every request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tonic::transport::Channel;

use crate::config::Config;
use crate::inproc::{Broker, BrokerError};
use crate::transport::{self, Transport};

/// Resolves service names to channels, and remembers the result.
#[derive(Debug, Clone)]
pub struct Resolver {
    config: Arc<Config>,
    broker: Broker,
    all_in_one: bool,
    cache: Arc<Mutex<HashMap<String, Channel>>>,
}

/// Why a service could not be reached.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// Nothing in the configuration says where this service is.
    #[error("service {0:?} has no endpoint in the configuration")]
    Unconfigured(String),
    /// The endpoint string was not claimed by any transport.
    #[error(transparent)]
    Malformed(#[from] transport::MalformedEndpoint),
    /// The transport refused.
    #[error("connecting to {service}: {source}")]
    Transport {
        /// Which service.
        service: String,
        /// What went wrong.
        #[source]
        source: tonic::transport::Error,
    },
    /// The in-process switchboard refused.
    #[error(transparent)]
    InProcess(#[from] BrokerError),
    /// The cache lock was poisoned by a panic elsewhere.
    #[error("the channel cache is poisoned")]
    Poisoned,
}

impl Resolver {
    /// A resolver over `config`, using `broker` for in-process services.
    #[must_use]
    pub fn new(config: Arc<Config>, broker: Broker) -> Self {
        let all_in_one = config.runtime.all_in_one;
        Self {
            config,
            broker,
            all_in_one,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// How `service` is reached, after the all-in-one override.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Unconfigured`] when no endpoint is configured, and
    /// [`ChannelError::Malformed`] when one is but cannot be parsed.
    pub fn transport(&self, service: &str) -> Result<Arc<dyn Transport>, ChannelError> {
        // In all-in-one the configured endpoints are ignored on purpose: the
        // file is the same one a multi-process deployment uses, and rewriting
        // it for a single box is exactly the friction this mode removes.
        if self.all_in_one && self.broker.has(service) {
            return Ok(transport::in_process(service));
        }
        let configured = self
            .config
            .services
            .get(service)
            .and_then(|s| s.endpoint.as_deref())
            .ok_or_else(|| ChannelError::Unconfigured(service.to_owned()))?;
        Ok(transport::parse(configured)?)
    }

    /// A channel to `service`, connecting lazily and caching the handle.
    ///
    /// # Errors
    ///
    /// [`ChannelError`] when the service is unconfigured, unreachable, or not
    /// part of an all-in-one set that claims to hold it.
    pub fn channel(&self, service: &str) -> Result<Channel, ChannelError> {
        if let Some(channel) = self.cached(service)? {
            return Ok(channel);
        }
        let channel = self.transport(service)?.connect(service, &self.broker)?;
        {
            let mut cache = self.cache.lock().map_err(|_| ChannelError::Poisoned)?;
            let _ = cache.insert(service.to_owned(), channel.clone());
        }
        Ok(channel)
    }

    fn cached(&self, service: &str) -> Result<Option<Channel>, ChannelError> {
        let cache = self.cache.lock().map_err(|_| ChannelError::Poisoned)?;
        Ok(cache.get(service).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn resolver(all_in_one: bool, broker: Broker) -> Resolver {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        config.runtime.all_in_one = all_in_one;
        Resolver::new(Arc::new(config), broker)
    }

    #[test]
    fn all_in_one_overrides_the_configured_endpoint_rather_than_needing_a_second_file() {
        let broker = Broker::new();
        let _incoming = broker.register("text").expect("register");
        let resolved = resolver(true, broker).transport("text").expect("resolve");
        // `dyn Transport` is not `Eq`, so the description stands in for the
        // value, which is the string an operator would have written anyway.
        assert_eq!(resolved.describe(), "inproc:text");
    }

    #[test]
    fn a_service_outside_the_all_in_one_set_still_resolves_to_its_endpoint() {
        // Mixed deployments are legitimate: one box running most services and a
        // shared voice pod elsewhere.
        let broker = Broker::new();
        let resolved = resolver(true, broker).transport("voice").expect("resolve");
        // Whichever local scheme this platform serves, and not the in-process
        // one: that is the distinction the test is about.
        assert_eq!(
            resolved.describe(),
            transport::local_endpoint(Path::new("/run/starling"), "voice"),
            "voice resolved to {}",
            resolved.describe()
        );
    }

    #[test]
    fn a_service_with_no_endpoint_is_named_in_the_error() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        let _ = config.services.remove("audit");
        let resolver = Resolver::new(Arc::new(config), Broker::new());
        let err = resolver.transport("audit").expect_err("no endpoint");
        assert!(matches!(err, ChannelError::Unconfigured(name) if name == "audit"));
    }
}
