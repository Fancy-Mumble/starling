//! `--all-in-one`: every service in one process, over in-memory pipes.
//!
//! One image, two deployment modes — one process for a VPS, twenty-four for
//! isolation or per-service scaling. The point is that it is the *same* code:
//! the services still speak gRPC to each other, still serialise, still see
//! deadlines and streaming semantics. Only the socket is gone.
//!
//! That matters more than saving a syscall. A second, direct-call code path
//! would be the one nobody tests until a small deployment hits a bug the large
//! one cannot reproduce. Here `--all-in-one` exercises the boundaries in both
//! directions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::transport::{IN_PROCESS_BUFFER, InProcessStream, LocalStream};

/// The in-process switchboard: which service is served where.
///
/// Cloning is cheap and shares the registry, so the binary builds one and hands
/// it to every service it starts.
#[derive(Debug, Clone, Default)]
pub struct Broker {
    services: Arc<Mutex<HashMap<String, mpsc::Sender<InProcessStream>>>>,
}

/// Why an in-process dial failed.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    /// No service registered under that name in this process.
    #[error("no in-process service named {0:?}; is it in the all-in-one set?")]
    Unknown(String),
    /// The service was registered but has stopped accepting connections.
    #[error("in-process service {0:?} has shut down")]
    Gone(String),
    /// The registry lock was poisoned by a panic elsewhere.
    #[error("the in-process registry is poisoned")]
    Poisoned,
}

impl Broker {
    /// A registry with nothing in it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `name`, returning the stream of connections to serve.
    ///
    /// The receiver is what a service hands to `Server::serve_with_incoming`.
    /// Registering the same name twice replaces the first, which is what makes
    /// a restarted service under test observable rather than silently ignored.
    pub fn register(&self, name: &str) -> Result<mpsc::Receiver<InProcessStream>, BrokerError> {
        let (tx, rx) = mpsc::channel(16);
        let mut services = self.services.lock().map_err(|_| BrokerError::Poisoned)?;
        let _ = services.insert(name.to_owned(), tx);
        Ok(rx)
    }

    /// Whether `name` is served in this process.
    pub fn has(&self, name: &str) -> bool {
        self.services
            .lock()
            .map(|services| services.contains_key(name))
            .unwrap_or(false)
    }

    /// Open a connection to `name`, returning this side of the pipe.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Unknown`] when the service is not in the all-in-one set,
    /// and [`BrokerError::Gone`] when it has shut down. Both are startup or
    /// drain conditions rather than transient, so neither is retried here.
    pub async fn dial(&self, name: &str) -> Result<tokio::io::DuplexStream, BrokerError> {
        let sender = {
            let services = self.services.lock().map_err(|_| BrokerError::Poisoned)?;
            services
                .get(name)
                .cloned()
                .ok_or_else(|| BrokerError::Unknown(name.to_owned()))?
        };
        let (client, server) = tokio::io::duplex(IN_PROCESS_BUFFER);
        sender
            .send(LocalStream::new(server))
            .await
            .map_err(|_| BrokerError::Gone(name.to_owned()))?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_dial_reaches_the_service_that_registered_the_name() {
        let broker = Broker::new();
        let mut incoming = broker.register("text").expect("register");

        let mut client = broker.dial("text").await.expect("dial");
        let mut served = incoming.recv().await.expect("the connection arrives");

        client.write_all(b"hi").await.expect("write");
        let mut buf = [0_u8; 2];
        let _ = served.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hi");
    }

    #[tokio::test]
    async fn dialling_a_service_this_process_does_not_run_names_it() {
        // Under --all-in-one a missing service is a composition bug, and an
        // error that does not name it sends the operator to the wrong file.
        let broker = Broker::new();
        let err = broker.dial("pchat").await.expect_err("nothing registered");
        assert!(matches!(err, BrokerError::Unknown(name) if name == "pchat"));
    }

    #[tokio::test]
    async fn a_stopped_service_reports_gone_rather_than_hanging() {
        let broker = Broker::new();
        let incoming = broker.register("audit").expect("register");
        drop(incoming);
        let err = broker.dial("audit").await.expect_err("receiver is gone");
        assert!(matches!(err, BrokerError::Gone(name) if name == "audit"));
    }
}
