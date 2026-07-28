//! An in-memory pipe, for `--all-in-one`.
//!
//! The services still speak gRPC to each other, still serialise, and still see
//! deadlines and streaming semantics. Only the socket is gone — see
//! [`crate::inproc`] for why that matters more than saving a syscall.

use std::sync::Arc;

use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Uri};
use tower::service_fn;

use super::{Incoming, Transport};
use crate::channel::ChannelError;
use crate::inproc::Broker;
use crate::listen::ListenError;

/// A service served in this process, held as the name it registered under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InProcess {
    name: String,
}

impl InProcess {
    /// The transport for the service registered as `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Claim `text` if it names a service in this process.
pub(super) fn parse(text: &str) -> Option<Arc<dyn Transport>> {
    let name = text.strip_prefix("inproc:")?;
    if name.is_empty() {
        return None;
    }
    Some(Arc::new(InProcess::new(name)))
}

#[async_trait]
impl Transport for InProcess {
    async fn bind(&self, broker: &Broker) -> Result<Incoming, ListenError> {
        let incoming = broker.register(&self.name)?;
        let stream =
            ReceiverStream::new(incoming).map(|conn| Ok::<_, std::io::Error>(conn.erase()));
        Ok(Box::pin(stream))
    }

    fn connect(&self, service: &str, broker: &Broker) -> Result<Channel, ChannelError> {
        let broker = broker.clone();
        let name = self.name.clone();
        let channel = super::connector_uri(service)?.connect_with_connector_lazy(service_fn(
            move |_: Uri| {
                let broker = broker.clone();
                let name = name.clone();
                async move {
                    let stream = super::retry_dial(|| async {
                        broker
                            .dial(&name)
                            .await
                            .map_err(|err| std::io::Error::other(err.to_string()))
                    })
                    .await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            },
        ));
        Ok(channel)
    }

    fn describe(&self) -> String {
        format!("inproc:{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scheme_with_no_name_is_not_claimed() {
        assert!(parse("inproc:").is_none());
        assert!(parse("inproc:text").is_some());
    }

    #[tokio::test]
    async fn binding_registers_the_name_a_caller_will_dial() {
        // The two halves have to agree about the name; if they drifted,
        // --all-in-one would fail only at the first cross-service call.
        let broker = Broker::new();
        let transport = InProcess::new("text");
        let _incoming = transport.bind(&broker).await.expect("bind");
        assert!(broker.has("text"));
    }
}
