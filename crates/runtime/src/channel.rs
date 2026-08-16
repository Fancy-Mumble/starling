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
use crate::live::ConfigCell;
use crate::transport::{self, Transport};

/// Resolves service names to channels, and remembers the result.
#[derive(Debug, Clone)]
pub struct Resolver {
    /// The configuration this resolver was built with.
    ///
    /// Endpoints are read from here and **not** from [`Self::live`], on
    /// purpose: the channel cache below is never invalidated, so a re-pointed
    /// endpoint would be read but not dialled. Reading it live would make a
    /// restart-only key look as though it had taken effect, which is exactly
    /// the failure the classification table exists to prevent.
    config: Arc<Config>,
    /// The configuration as it now reads, for the deployment-wide sizes.
    live: ConfigCell,
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
            live: ConfigCell::fixed(Arc::clone(&config)),
            config,
            broker,
            all_in_one,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Read the deployment-wide sizes from `cell` rather than from the
    /// configuration this resolver was built with.
    ///
    /// Only the sizes: see the note on [`Self::config`] for why endpoints stay
    /// where they are.
    #[must_use]
    pub fn following(mut self, cell: ConfigCell) -> Self {
        self.live = cell;
        self
    }

    /// How `service` is **dialled**, after the all-in-one short-circuit.
    ///
    /// A callee already serving in this process is reached in-process whatever
    /// the file says, because rewriting endpoints for a single box is exactly
    /// the friction that mode removes. That only applies once the callee has
    /// registered, which is why it cannot answer the serving question:
    /// see [`Self::listener`].
    ///
    /// # Errors
    ///
    /// [`ChannelError::Unconfigured`] when no endpoint is configured, and
    /// [`ChannelError::Malformed`] when one is but cannot be parsed.
    pub fn transport(&self, service: &str) -> Result<Arc<dyn Transport>, ChannelError> {
        let served_in_this_process = self.all_in_one && self.broker.has(service);
        if served_in_this_process {
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

    /// How `service` **serves**, which is not always where it is dialled.
    ///
    /// `bind` wins over `endpoint` when it is set, and that is the only
    /// difference from [`Self::transport`]. The two are separate methods rather
    /// than one with a flag because they answer to different sides of the same
    /// name, and the all-in-one short-circuit belongs to only one of them: a
    /// service asks this *before* it has registered with the broker, so
    /// `broker.has` is false here by construction and consulting it would
    /// silently mean "never".
    ///
    /// # Errors
    ///
    /// [`ChannelError::Unconfigured`] when neither address is configured, and
    /// [`ChannelError::Malformed`] when one is but cannot be parsed.
    pub fn listener(&self, service: &str) -> Result<Arc<dyn Transport>, ChannelError> {
        let configured = self
            .config
            .services
            .get(service)
            .and_then(|s| s.bind.as_deref().or(s.endpoint.as_deref()))
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

    /// The decode limit a client reading `metadata`'s tree is given.
    ///
    /// On the resolver because every reader of the tree already holds one to
    /// dial `metadata` with, and because the limit belongs to *the deployment*
    /// rather than to any one service: it comes from `[runtime]
    /// max_tree_message`, and readers that disagree about it are readers that
    /// disagree about how large a server may be.
    #[must_use]
    pub fn max_tree_message(&self) -> usize {
        // Saturating rather than refusing: a 32-bit build handed a file that
        // asks for 8 GiB gets the largest message it can address, which is
        // already more than it can allocate. Nothing is served by failing the
        // dial over the arithmetic.
        usize::try_from(self.live.current().runtime.max_tree_message.get()).unwrap_or(usize::MAX)
    }

    /// The gateway's per-client control budget, for services that answer a
    /// request with many frames at once.
    ///
    /// A service cannot see a client's queue, so a reply it builds in one go is
    /// the one thing it *can* keep from overflowing that queue by itself. Here
    /// for the same reason [`Self::max_tree_message`] is: it is the
    /// deployment's number, and a service that guessed a different one would
    /// disagree with the gateway about when a client dies.
    #[must_use]
    pub fn control_bytes(&self) -> usize {
        self.live.current().gateway.control_bytes
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
    fn a_service_serves_where_bind_says_and_is_dialled_where_endpoint_says() {
        // The Kubernetes case: `endpoint` names a Service, whose ClusterIP
        // belongs to no interface, so binding it would fail to start. Without
        // the split there is nowhere to say so.
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        let text = config.services.get_mut("text").expect("text is configured");
        text.endpoint = Some("http://text.default.svc:50051".to_owned());
        text.bind = Some("http://0.0.0.0:50051".to_owned());
        let resolver = Resolver::new(Arc::new(config), Broker::new());

        assert_eq!(
            resolver.listener("text").expect("serve").describe(),
            "http://0.0.0.0:50051"
        );
        assert_eq!(
            resolver.transport("text").expect("dial").describe(),
            "http://text.default.svc:50051"
        );
    }

    #[test]
    fn one_address_is_still_the_normal_case() {
        // Absent `bind` must mean `endpoint` rather than nothing, or every
        // deployment that has never heard of the split stops serving.
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        config
            .services
            .get_mut("text")
            .expect("text is configured")
            .endpoint = Some("http://text:50051".to_owned());
        let resolver = Resolver::new(Arc::new(config), Broker::new());
        assert_eq!(
            resolver.listener("text").expect("serve").describe(),
            "http://text:50051"
        );
    }

    #[test]
    fn a_service_serves_its_configured_endpoint_even_under_all_in_one() {
        // The property `crates/starling/src/e2e.rs` waits on: under
        // `--all-in-one` a service still binds what it was configured with, so
        // there is a socket to watch for. Registration happens inside the bind,
        // so the broker cannot be consulted here - it would answer "no" every
        // time and make this depend on a race it always loses.
        let broker = Broker::new();
        let resolved = resolver(true, broker).listener("text").expect("resolve");
        assert_eq!(
            resolved.describe(),
            transport::local_endpoint(Path::new("/run/starling"), "text")
        );
    }

    #[test]
    fn the_tree_limit_readers_are_given_is_the_one_the_file_names() {
        // Every reader of the tree takes it from here, so an operator raising
        // the key raises it for the handshake, the admin API and the event
        // bridge at once; a reader that read its own number would be the one
        // that still refuses the tree everyone else can see.
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        config.runtime.max_tree_message = crate::config::ByteSize(9 * 1024 * 1024);
        let resolver = Resolver::new(Arc::new(config), Broker::new());
        assert_eq!(resolver.max_tree_message(), 9 * 1024 * 1024);
    }

    #[test]
    fn the_default_tree_limit_clears_the_one_grpc_would_have_imposed() {
        // 4 MiB is gRPC's own default for what a client will decode, and a
        // murmur import lands over it on day one: 5.75 MiB of channel artwork
        // across 47 channels is the server this default was measured against.
        // A default that did not clear it would leave the shipped server
        // broken for exactly the deployments that migrate to it.
        let resolver = resolver(false, Broker::new());
        assert!(
            resolver.max_tree_message() > 4 * 1024 * 1024,
            "the default is {} bytes, which gRPC would have refused anyway",
            resolver.max_tree_message()
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
