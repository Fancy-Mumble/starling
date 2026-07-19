//! A Windows named pipe, for services co-located on one host.
//!
//! The counterpart of [`super::unix`], and there for the same reason: a
//! deployment whose services share a box should not be reachable from off it.
//! A pipe's ACL is the boundary a Unix socket's file permissions are, and the
//! default one (the creating account, and administrators) is what a service
//! gets here; nothing in this file widens it.
//!
//! # Why the name still looks like a path
//!
//! `\\.\pipe\` is one flat namespace for the whole machine, with no directories
//! and no working directory. The run directory that keeps one deployment's
//! sockets away from another's therefore has to live *inside* the name, which is
//! what [`super::local_endpoint`] puts there. Windows allows every character but
//! `\` in a pipe name, so a path goes in very nearly verbatim.

use std::sync::Arc;

use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Uri};
use tower::service_fn;

use super::{Incoming, LocalStream, Transport};
use crate::channel::ChannelError;
use crate::inproc::Broker;
use crate::listen::ListenError;

/// The namespace every named pipe on this machine lives in.
const PREFIX: &str = r"\\.\pipe\";

/// The longest a pipe path may be, [`PREFIX`] included.
///
/// Checked before binding so an over-long run directory is reported as the
/// length problem it is, rather than as `ERROR_INVALID_NAME`.
const MAX_PATH: usize = 256;

/// How many accepted connections wait to be served before accepting pauses.
///
/// The analogue of a listen backlog: a connection here is already established,
/// so this bounds how far ahead of `tonic` the accept loop may run.
const ACCEPT_BACKLOG: usize = 16;

/// A named pipe, held as the name it lives at under `\\.\pipe\`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipe {
    name: String,
}

impl Pipe {
    /// The transport for the pipe called `name`.
    ///
    /// `name` is normalised, so the bare name and the full `\\.\pipe\...` path
    /// name the same pipe.
    #[must_use]
    pub fn new(name: impl AsRef<str>) -> Self {
        Self {
            name: normalize(name.as_ref()),
        }
    }

    /// The path the OS is asked for.
    fn path(&self) -> String {
        format!("{PREFIX}{}", self.name)
    }
}

/// Claim `text` if it names a pipe.
pub(super) fn parse(text: &str) -> Option<Arc<dyn Transport>> {
    let pipe = Pipe::new(text.strip_prefix("pipe:")?);
    if pipe.name.is_empty() {
        return None;
    }
    Some(Arc::new(pipe))
}

/// A pipe name in the one form that round-trips: no prefix, `/` for separators.
///
/// Both forms get pasted into configuration, the bare name, and the full path
/// that tools which list pipes print, and `\` is the one character a pipe name
/// may not contain. Folding them together here means [`Transport::describe`]
/// has a single form to emit, so a description copied back out of a log parses
/// to the pipe it came from.
fn normalize(name: &str) -> String {
    let slashed = name.replace('\\', "/");
    slashed
        .strip_prefix("//./pipe/")
        .unwrap_or(&slashed)
        .to_owned()
}

#[async_trait]
impl Transport for Pipe {
    async fn bind(&self, _broker: &Broker) -> Result<Incoming, ListenError> {
        let path = self.path();
        if path.len() > MAX_PATH {
            return Err(ListenError::Address(format!(
                "{} is {} characters including the {PREFIX:?} prefix; \
                 a pipe name may be at most {MAX_PATH}",
                self.describe(),
                path.len()
            )));
        }
        // `first_pipe_instance` is this transport's "address already in use".
        // Without it, a second deployment that derived the same name would
        // quietly start answering half of the first one's connections.
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .map_err(|source| ListenError::Bind {
                what: self.describe(),
                source,
            })?;

        let (connections, incoming) = mpsc::channel(ACCEPT_BACKLOG);
        drop(tokio::spawn(accept(path, server, connections)));
        let stream = ReceiverStream::new(incoming)
            .map(|conn| conn.map(|conn| LocalStream::new(conn).erase()));
        Ok(Box::pin(stream))
    }

    fn connect(&self, service: &str, _broker: &Broker) -> Result<Channel, ChannelError> {
        let path = self.path();
        let channel = super::connector_uri(service)?.connect_with_connector_lazy(service_fn(
            move |_: Uri| {
                let path = path.clone();
                async move {
                    // The retry covers `ERROR_PIPE_BUSY` as well as a callee
                    // that has not bound yet: every free instance being taken
                    // is the documented way a named pipe says "try again", and
                    // the accept loop replaces one within microseconds.
                    let stream =
                        super::retry_dial(|| async { ClientOptions::new().open(&path) }).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            },
        ));
        Ok(channel)
    }

    fn describe(&self) -> String {
        format!("pipe:{}", self.name)
    }
}

/// Hand each connected instance on, having created its replacement first.
///
/// A named pipe server is one instance per connection, the instance a client
/// connects to *is* the connection, so unlike a socket there is no listener
/// that outlives the accept. The replacement therefore has to exist before the
/// connected one is handed over: a client that dials in the gap gets
/// `ERROR_FILE_NOT_FOUND`, which reads as "the service is not running" and
/// would make a busy deployment look like an intermittently missing one.
async fn accept(
    path: String,
    mut server: NamedPipeServer,
    connections: mpsc::Sender<std::io::Result<NamedPipeServer>>,
) {
    loop {
        if let Err(error) = server.connect().await {
            let _ = connections.send(Err(error)).await;
            return;
        }
        let next = match ServerOptions::new().create(&path) {
            Ok(next) => next,
            Err(error) => {
                let _ = connections.send(Err(error)).await;
                return;
            }
        };
        if connections
            .send(Ok(std::mem::replace(&mut server, next)))
            .await
            .is_err()
        {
            // Nothing is serving these any more, so the pipe this task still
            // holds is dropped with it, which is how the name is released.
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pipe name no other test and no other run will pick.
    fn unique(tag: &str) -> String {
        format!("starling-test/{}/{tag}", std::process::id())
    }

    #[test]
    fn a_scheme_with_no_name_is_not_claimed() {
        // Falling through to the next parser is what turns this into the
        // "not an endpoint" error, rather than a pipe with no name.
        assert!(parse("pipe:").is_none());
        assert!(parse("pipe:starling/text").is_some());
    }

    #[test]
    fn the_bare_name_and_the_full_path_are_the_same_pipe() {
        // Both get pasted into configuration, and a description that did not
        // settle would mean a log an operator cannot copy back.
        let bare = Pipe::new("starling/text");
        assert_eq!(Pipe::new(r"\\.\pipe\starling\text"), bare);
        assert_eq!(bare.describe(), "pipe:starling/text");
        assert_eq!(bare.path(), r"\\.\pipe\starling/text");
    }

    #[tokio::test]
    async fn a_name_too_long_to_bind_says_so_rather_than_failing_obscurely() {
        let long = Pipe::new("x".repeat(MAX_PATH));
        // `err()` rather than `expect_err`: a bound transport is a stream of
        // trait objects, which has no `Debug` to print.
        let error = long
            .bind(&Broker::new())
            .await
            .err()
            .expect("the name is over the limit");
        assert!(
            matches!(&error, ListenError::Address(message) if message.contains("at most")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn two_deployments_cannot_share_one_name() {
        // The whole isolation story rests on this: `\\.\pipe\` is machine-wide,
        // so a name collision that bound successfully would have one server
        // answering the other's calls.
        let broker = Broker::new();
        let pipe = Pipe::new(unique("exclusive"));
        let _first = pipe.bind(&broker).await.expect("the first bind succeeds");
        let error = pipe
            .bind(&broker)
            .await
            .err()
            .expect("the second must be refused");
        assert!(matches!(error, ListenError::Bind { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_dial_reaches_the_bound_pipe_and_carries_bytes() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let pipe = Pipe::new(unique("bytes"));
        let mut incoming = pipe.bind(&Broker::new()).await.expect("bind");

        let mut client = ClientOptions::new().open(pipe.path()).expect("dial");
        let mut served = incoming
            .next()
            .await
            .expect("a connection arrives")
            .expect("it is not an error");

        client.write_all(b"ping").await.expect("write");
        let mut buf = [0_u8; 4];
        let _ = served.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn a_second_client_is_accepted_while_the_first_is_still_connected() {
        // One instance per connection is the trap: an accept loop that did not
        // create the replacement would serve exactly one caller and then look
        // like a service that had stopped.
        let pipe = Pipe::new(unique("concurrent"));
        let mut incoming = pipe.bind(&Broker::new()).await.expect("bind");

        let _first = ClientOptions::new().open(pipe.path()).expect("first dial");
        let _served = incoming.next().await.expect("the first arrives");
        let _second = ClientOptions::new().open(pipe.path()).expect("second dial");
        let served = incoming.next().await.expect("the second arrives");
        assert!(served.is_ok(), "{:?}", served.err());
    }
}
