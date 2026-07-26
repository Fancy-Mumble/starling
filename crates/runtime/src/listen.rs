//! Serving a service's gRPC routes over whichever transport it was given.
//!
//! One function, three transports, and the service never learns which — the
//! same asymmetry [`crate::channel`] provides on the calling side. Every one of
//! them stops accepting on drain and finishes what it is holding, because
//! Kubernetes sends `SIGTERM` and then `SIGKILL` thirty seconds later whatever
//! the process thinks about it.

use std::path::Path;

use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tokio_stream::StreamExt as _;
use tonic::service::Routes;
use tonic::transport::Server;

use crate::endpoint::Endpoint;
use crate::inproc::Broker;
use crate::shutdown::Shutdown;
use crate::transport::LocalStream;

/// Why a service could not be served.
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    /// The socket could not be bound.
    #[error("binding {what}: {source}")]
    Bind {
        /// What was being bound.
        what: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The endpoint could not be turned into an address to bind.
    #[error("{0}")]
    Address(String),
    /// The server stopped with an error.
    #[error(transparent)]
    Serve(#[from] tonic::transport::Error),
    /// The in-process registry refused.
    #[error(transparent)]
    Broker(#[from] crate::inproc::BrokerError),
}

/// Serve `routes` at `endpoint` until `shutdown` drains.
///
/// # Errors
///
/// [`ListenError`] if the transport cannot be bound, or if serving fails.
pub async fn serve_routes(
    name: &str,
    endpoint: &Endpoint,
    broker: &Broker,
    routes: Routes,
    shutdown: Shutdown,
) -> Result<(), ListenError> {
    let signal = {
        let shutdown = shutdown.clone();
        async move { shutdown.wait().await }
    };
    tracing::info!(service = name, endpoint = %endpoint.describe(), "serving");

    match endpoint {
        Endpoint::InProcess(registered) => {
            let incoming = broker.register(registered)?;
            let stream = ReceiverStream::new(incoming).map(Ok::<_, std::io::Error>);
            Server::builder()
                .add_routes(routes)
                .serve_with_incoming_shutdown(stream, signal)
                .await?;
        }
        Endpoint::Unix(path) => {
            prepare_socket_path(path)?;
            let listener = tokio::net::UnixListener::bind(path).map_err(|source| ListenError::Bind {
                what: format!("unix:{}", path.display()),
                source,
            })?;
            let stream = UnixListenerStream::new(listener).map(|conn| conn.map(LocalStream::new));
            Server::builder()
                .add_routes(routes)
                .serve_with_incoming_shutdown(stream, signal)
                .await?;
        }
        Endpoint::Http(uri) => {
            let address = tcp_address(uri)?;
            let listener = tokio::net::TcpListener::bind(&address)
                .await
                .map_err(|source| ListenError::Bind {
                    what: address.clone(),
                    source,
                })?;
            let stream = TcpListenerStream::new(listener).map(|conn| conn.map(LocalStream::new));
            Server::builder()
                .add_routes(routes)
                .serve_with_incoming_shutdown(stream, signal)
                .await?;
        }
    }

    tracing::info!(service = name, "drained");
    Ok(())
}

/// Make a Unix socket bindable: create the directory, remove a stale file.
///
/// A stale socket after an unclean exit is the normal case, not an exception —
/// refusing to start because a previous process died badly would turn a crash
/// into an outage that needs a human.
fn prepare_socket_path(path: &Path) -> Result<(), ListenError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ListenError::Bind {
            what: parent.display().to_string(),
            source,
        })?;
    }
    if path.exists() {
        std::fs::remove_file(path).map_err(|source| ListenError::Bind {
            what: path.display().to_string(),
            source,
        })?;
    }
    Ok(())
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
        assert_eq!(tcp_address("http://0.0.0.0:50051").ok(), Some("0.0.0.0:50051".to_owned()));
        assert_eq!(tcp_address("http://text:50051/").ok(), Some("text:50051".to_owned()));
    }

    #[test]
    fn an_endpoint_without_a_port_is_refused_rather_than_defaulted() {
        // Defaulting would bind a port the operator never chose, and two
        // services would then fight over it.
        assert!(tcp_address("http://text").is_err());
    }

    #[tokio::test]
    async fn a_stale_socket_file_does_not_stop_a_restart() {
        let dir = std::env::temp_dir().join(format!("starling-listen-{}", std::process::id()));
        let path = dir.join("text.sock");
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(&path, b"stale").expect("stale socket");

        prepare_socket_path(&path).expect("a stale file must be cleared");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
