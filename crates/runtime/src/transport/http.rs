//! TCP, for services that are not on the same host.
//!
//! This is the transport a Kubernetes deployment uses, and the name in the URI
//! is the one cluster DNS resolves.

use std::sync::Arc;

use async_trait::async_trait;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;

use super::{Incoming, LocalStream, Transport};
use crate::channel::ChannelError;
use crate::inproc::Broker;
use crate::listen::ListenError;

/// A TCP endpoint, held as the URI it was configured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http {
    uri: String,
}

impl Http {
    /// The transport for `uri`, which carries an `http` or `https` scheme.
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self { uri: uri.into() }
    }
}

/// Claim `text` if it names a TCP endpoint.
pub(super) fn parse(text: &str) -> Option<Arc<dyn Transport>> {
    if text.starts_with("http://") || text.starts_with("https://") {
        return Some(Arc::new(Http::new(text)));
    }
    None
}

#[async_trait]
impl Transport for Http {
    async fn bind(&self, _broker: &Broker) -> Result<Incoming, ListenError> {
        let address = tcp_address(&self.uri)?;
        let listener = tokio::net::TcpListener::bind(&address)
            .await
            .map_err(|source| ListenError::Bind {
                what: address.clone(),
                source,
            })?;
        let stream = TcpListenerStream::new(listener)
            .map(|conn| conn.map(|conn| LocalStream::new(conn).erase()));
        Ok(Box::pin(stream))
    }

    fn connect(&self, service: &str, _broker: &Broker) -> Result<Channel, ChannelError> {
        // `connect_lazy` rather than `connect`: a service that is not up yet is
        // a startup ordering fact, not an error. Readiness, not construction,
        // is where "is it there" is answered.
        let endpoint =
            tonic::transport::Endpoint::from_shared(self.uri.clone()).map_err(|source| {
                ChannelError::Transport {
                    service: service.to_owned(),
                    source,
                }
            })?;
        Ok(endpoint.connect_lazy())
    }

    fn describe(&self) -> String {
        self.uri.clone()
    }
}

/// The `host:port` inside an `http://` endpoint.
fn tcp_address(uri: &str) -> Result<String, ListenError> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
        .ok_or_else(|| ListenError::Address(format!("{uri:?} is not an http endpoint")))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.contains(':') {
        Ok(authority.to_owned())
    } else {
        Err(ListenError::Address(format!(
            "{uri:?} has no port; a service must be told which one to bind"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_http_endpoint_yields_the_authority_to_bind() {
        assert_eq!(
            tcp_address("http://0.0.0.0:50051").ok(),
            Some("0.0.0.0:50051".to_owned())
        );
        assert_eq!(
            tcp_address("http://text:50051/").ok(),
            Some("text:50051".to_owned())
        );
    }

    #[test]
    fn an_endpoint_without_a_port_is_refused_rather_than_defaulted() {
        // Defaulting would bind a port the operator never chose, and two
        // services would then fight over it.
        assert!(tcp_address("http://text").is_err());
    }

    #[test]
    fn only_an_http_scheme_is_claimed() {
        assert!(parse("http://text:50051").is_some());
        assert!(parse("https://text:50051").is_some());
        assert!(parse("unix:/run/t.sock").is_none());
        assert!(parse("text:50051").is_none());
    }
}
