//! Endpoint discovery: a service name in, a gRPC channel out.
//!
//! A caller names the service it wants and never learns which transport it got
//! — that is the whole point of the three [`Endpoint`] forms, and it is what
//! makes `--all-in-one` a configuration choice rather than a code path.
//!
//! Channels are cached per service. tonic's `Channel` is a cheap handle over a
//! connection pool and is designed to be cloned, so building a second one per
//! call would throw away the pool and reconnect on every request.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Uri};
use tower::service_fn;

use crate::config::Config;
use crate::endpoint::Endpoint;
use crate::inproc::{Broker, BrokerError};

/// How long a fresh dial keeps retrying a peer that is not listening yet.
///
/// Services spawn concurrently, so a caller can win the race and dial before
/// the callee has created its socket. That is a startup ordering fact, not an
/// outage — `ENOENT`/`ECONNREFUSED` get a short retry window before the error
/// is allowed through, matching the gateway's own attach loop
/// (`starling-gateway/src/attach.rs`).
const DIAL_RETRY_WINDOW: Duration = Duration::from_secs(2);
/// Delay between dial attempts within the retry window.
const DIAL_RETRY_INTERVAL: Duration = Duration::from_millis(25);

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
    /// The endpoint string was not one of the three forms.
    #[error(transparent)]
    Malformed(#[from] crate::endpoint::MalformedEndpoint),
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

    /// Where `service` is, after the all-in-one override.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Unconfigured`] when no endpoint is configured, and
    /// [`ChannelError::Malformed`] when one is but cannot be parsed.
    pub fn endpoint(&self, service: &str) -> Result<Endpoint, ChannelError> {
        // In all-in-one the configured endpoints are ignored on purpose: the
        // file is the same one a multi-process deployment uses, and rewriting
        // it for a single box is exactly the friction this mode removes.
        if self.all_in_one && self.broker.has(service) {
            return Ok(Endpoint::in_process(service));
        }
        let configured = self
            .config
            .services
            .get(service)
            .and_then(|s| s.endpoint.as_deref())
            .ok_or_else(|| ChannelError::Unconfigured(service.to_owned()))?;
        Ok(configured.parse()?)
    }

    /// A channel to `service`, connecting lazily and caching the handle.
    ///
    /// # Errors
    ///
    /// [`ChannelError`] when the service is unconfigured, unreachable, or not
    /// part of an all-in-one set that claims to hold it.
    pub async fn channel(&self, service: &str) -> Result<Channel, ChannelError> {
        if let Some(channel) = self.cached(service)? {
            return Ok(channel);
        }
        let channel = self.connect(service).await?;
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

    async fn connect(&self, service: &str) -> Result<Channel, ChannelError> {
        match self.endpoint(service)? {
            Endpoint::Http(uri) => self.connect_http(service, &uri).await,
            Endpoint::Unix(path) => self.connect_unix(service, path).await,
            Endpoint::InProcess(name) => self.connect_in_process(service, name).await,
        }
    }

    async fn connect_http(&self, service: &str, uri: &str) -> Result<Channel, ChannelError> {
        // `connect_lazy` rather than `connect`: a service that is not up yet is
        // a startup ordering fact, not an error. Readiness, not construction,
        // is where "is it there" is answered.
        let endpoint = tonic::transport::Endpoint::from_shared(uri.to_owned()).map_err(|source| {
            ChannelError::Transport {
                service: service.to_owned(),
                source,
            }
        })?;
        Ok(endpoint.connect_lazy())
    }

    async fn connect_unix(
        &self,
        service: &str,
        path: std::path::PathBuf,
    ) -> Result<Channel, ChannelError> {
        // The URI is required by HTTP/2 and ignored by the connector: the
        // socket path decides where the bytes go.
        let endpoint = tonic::transport::Endpoint::try_from("http://[::]:50051")
            .map_err(|source| ChannelError::Transport {
                service: service.to_owned(),
                source,
            })?;
        let channel = endpoint
            .connect_with_connector_lazy(service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream = retry_dial(|| tokio::net::UnixStream::connect(&path)).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }));
        Ok(channel)
    }

    async fn connect_in_process(
        &self,
        service: &str,
        name: String,
    ) -> Result<Channel, ChannelError> {
        let broker = self.broker.clone();
        let endpoint = tonic::transport::Endpoint::try_from("http://[::]:50051")
            .map_err(|source| ChannelError::Transport {
                service: service.to_owned(),
                source,
            })?;
        let channel = endpoint.connect_with_connector_lazy(service_fn(move |_: Uri| {
            let broker = broker.clone();
            let name = name.clone();
            async move {
                let stream = retry_dial(|| async {
                    broker
                        .dial(&name)
                        .await
                        .map_err(|err| std::io::Error::other(err.to_string()))
                })
                .await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }));
        Ok(channel)
    }
}

/// Retry `dial` for [`DIAL_RETRY_WINDOW`] before returning its last error.
///
/// The callee's listener is created asynchronously relative to this call, so
/// the first attempt failing is expected under concurrent startup rather than
/// exceptional; only a dial that is still failing once the window elapses is
/// treated as the peer actually being unreachable.
async fn retry_dial<F, Fut, T>(mut dial: F) -> std::io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    let deadline = tokio::time::Instant::now() + DIAL_RETRY_WINDOW;
    loop {
        match dial().await {
            Ok(value) => return Ok(value),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(DIAL_RETRY_INTERVAL).await;
            }
            Err(error) => return Err(error),
        }
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
        let resolved = resolver(true, broker).endpoint("text").expect("resolve");
        assert_eq!(resolved, Endpoint::in_process("text"));
    }

    #[test]
    fn a_service_outside_the_all_in_one_set_still_resolves_to_its_endpoint() {
        // Mixed deployments are legitimate: one box running most services and a
        // shared voice pod elsewhere.
        let broker = Broker::new();
        let resolved = resolver(true, broker).endpoint("voice").expect("resolve");
        assert!(matches!(resolved, Endpoint::Unix(_)));
    }

    #[test]
    fn a_service_with_no_endpoint_is_named_in_the_error() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        let _ = config.services.remove("audit");
        let resolver = Resolver::new(Arc::new(config), Broker::new());
        let err = resolver.endpoint("audit").expect_err("no endpoint");
        assert!(matches!(err, ChannelError::Unconfigured(name) if name == "audit"));
    }
}
