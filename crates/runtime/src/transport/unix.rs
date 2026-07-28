//! A Unix domain socket, for services co-located on one host.
//!
//! File permissions are the authentication here, which is why the path is
//! never guessed and a bare `host:port` is never treated as one of these.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Uri};
use tower::service_fn;

use super::{Incoming, LocalStream, Transport};
use crate::channel::ChannelError;
use crate::inproc::Broker;
use crate::listen::ListenError;

/// A Unix domain socket, held as the path it lives at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unix {
    path: PathBuf,
}

impl Unix {
    /// The transport for the socket at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

/// Claim `text` if it names a Unix socket.
pub(super) fn parse(text: &str) -> Option<Arc<dyn Transport>> {
    let path = text.strip_prefix("unix:")?;
    if path.is_empty() {
        return None;
    }
    Some(Arc::new(Unix::new(path)))
}

#[async_trait]
impl Transport for Unix {
    async fn bind(&self, _broker: &Broker) -> Result<Incoming, ListenError> {
        prepare_socket_path(&self.path)?;
        let listener =
            tokio::net::UnixListener::bind(&self.path).map_err(|source| ListenError::Bind {
                what: format!("unix:{}", self.path.display()),
                source,
            })?;
        let stream = UnixListenerStream::new(listener)
            .map(|conn| conn.map(|conn| LocalStream::new(conn).erase()));
        Ok(Box::pin(stream))
    }

    fn connect(&self, service: &str, _broker: &Broker) -> Result<Channel, ChannelError> {
        let path = self.path.clone();
        let channel = super::connector_uri(service)?.connect_with_connector_lazy(service_fn(
            move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream =
                        super::retry_dial(|| tokio::net::UnixStream::connect(&path)).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            },
        ));
        Ok(channel)
    }

    fn describe(&self) -> String {
        format!("unix:{}", self.path.display())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_scheme_with_no_path_is_not_claimed() {
        // Falling through to the next parser is what turns this into the
        // "not an endpoint" error, rather than a socket at the empty path.
        assert!(parse("unix:").is_none());
        assert!(parse("unix:/run/starling/text.sock").is_some());
    }
}
