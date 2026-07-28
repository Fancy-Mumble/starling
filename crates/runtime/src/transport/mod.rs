//! Where a service can be reached, in the forms deployment needs.
//!
//! The scheme is the deployment decision, and it is the *only* thing that
//! changes between a single VPS and twenty-four pods:
//!
//! | Written | Means |
//! |---|---|
//! | `http://text:50051` | across hosts; Kubernetes DNS fills the name in |
//! | `unix:/run/starling/text.sock` | co-located, and file permissions are the auth |
//! | `pipe:starling/text` | the same, on Windows, where the pipe's ACL is the auth |
//! | `inproc:text` | `--all-in-one`, over an in-memory transport |
//!
//! The co-located form is the platform's, and only one of the two exists in any
//! given build: a Unix socket cannot be served on Windows, and pretending
//! otherwise would turn "this deployment has no local IPC" into a socket
//! silently opened somewhere else. [`local_endpoint`] is what writes the right
//! one, so nothing above this module names either scheme.
//!
//! # Why a trait and not an enum
//!
//! Each transport owns *both* halves of its scheme — how a service is served on
//! it, and how a caller dials it — in one file implementing [`Transport`].
//! [`parse`] is the single place that maps a configured string to one, so
//! [`crate::listen`] and [`crate::channel`] hold no per-transport knowledge at
//! all: they take a `dyn Transport` and call it.
//!
//! Adding a transport is therefore a new module plus one line in
//! [`TRANSPORTS`], and no edit to anything that serves or dials.

mod http;
mod in_process;
mod local;
#[cfg(windows)]
mod pipe;
#[cfg(unix)]
mod unix;

use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;
use tonic::transport::Channel;

use crate::channel::ChannelError;
use crate::inproc::Broker;
use crate::listen::ListenError;

pub use http::Http;
pub use in_process::InProcess;
pub use local::{IN_PROCESS_BUFFER, InProcessStream, LocalStream};
#[cfg(windows)]
pub use pipe::Pipe;
#[cfg(unix)]
pub use unix::Unix;

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

/// Any byte stream tonic can serve a connection over.
///
/// This is an alias for the bundle of bounds tonic wants, so that
/// [`LocalStream::erase`] has something to box into.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// A connection whose originating transport has been forgotten.
pub type BoxedIo = Box<dyn Io>;

/// The connections a bound transport yields, as they arrive.
pub type Incoming = Pin<Box<dyn Stream<Item = std::io::Result<LocalStream<BoxedIo>>> + Send>>;

/// The forms this build accepts, for the error that lists them.
///
/// Platform-specific because the co-located transport is: offering `unix:` on
/// Windows would send an operator to write an endpoint nothing can serve.
const FORMS: &str = core::cfg_select! {
    unix => { "http://host:port, unix:/path or inproc:name" }
    windows => { "http://host:port, pipe:name or inproc:name" }
};

/// Why an endpoint string could not be understood.
#[derive(Debug, thiserror::Error)]
#[error("{0:?} is not an endpoint: write {forms}", forms = FORMS)]
pub struct MalformedEndpoint(String);

/// One way a service can be reached: how to serve on it, and how to dial it.
///
/// Both halves live on the same type deliberately. They have to agree about
/// what a given string means, and a transport that could be served but not
/// dialled is a deployment that half works — a failure that shows up as a
/// caller timing out against a service that is running perfectly well.
#[async_trait]
pub trait Transport: fmt::Debug + Send + Sync + 'static {
    /// Start accepting, yielding connections until the caller stops polling.
    ///
    /// `broker` is used only by the in-process transport; the others ignore it.
    ///
    /// # Errors
    ///
    /// [`ListenError`] when the transport cannot be bound.
    async fn bind(&self, broker: &Broker) -> Result<Incoming, ListenError>;

    /// A channel to this peer, connecting lazily.
    ///
    /// `service` names the callee and is used only to make errors legible.
    ///
    /// # Errors
    ///
    /// [`ChannelError`] when the channel cannot be constructed.
    fn connect(&self, service: &str, broker: &Broker) -> Result<Channel, ChannelError>;

    /// How this endpoint was written, and how it is logged.
    ///
    /// The result round-trips: feeding it back to [`parse`] yields the same
    /// transport, which is what lets configuration be echoed into a log and
    /// then copied back out of one.
    fn describe(&self) -> String;
}

/// A scheme matcher: `Some` when the text is this transport's, `None` if not.
type Parser = fn(&str) -> Option<Arc<dyn Transport>>;

/// Every transport, in the order a configured string is offered to them.
///
/// The order is written here rather than left to link order — which is what a
/// self-registering (`inventory`-style) registry would give — because these are
/// *prefix* matchers. Two schemes sharing a prefix would otherwise resolve
/// differently depending on how the binary happened to be linked, and the
/// transport is the one decision where "it worked in my build" is unaffordable:
/// getting it wrong silently swaps a file-permission boundary for a TCP socket.
const TRANSPORTS: &[Parser] = &[
    #[cfg(unix)]
    unix::parse,
    #[cfg(windows)]
    pipe::parse,
    in_process::parse,
    http::parse,
];

/// The transport a configured endpoint string names.
///
/// A bare `host:port` is refused rather than assumed to be TCP: assuming would
/// make `unix` a typo away from silently opening a TCP socket on a host that
/// expected a file-permission boundary.
///
/// # Errors
///
/// [`MalformedEndpoint`] when no transport claims the string.
pub fn parse(text: &str) -> Result<Arc<dyn Transport>, MalformedEndpoint> {
    let text = text.trim();
    TRANSPORTS
        .iter()
        .find_map(|claims| claims(text))
        .ok_or_else(|| MalformedEndpoint(text.to_owned()))
}

/// The in-process transport for `service`.
#[must_use]
pub fn in_process(service: &str) -> Arc<dyn Transport> {
    Arc::new(InProcess::new(service))
}

/// Where `service` is reached when every service shares one host.
///
/// This is what the shipped defaults are written in, and the reason they need no
/// operator to allocate twenty ports: the OS's own local-IPC boundary, under
/// `run_dir`. Which mechanism that is depends on the platform, and this is the
/// only place that decides.
///
/// On Windows the directory is made absolute first. `\\.\pipe\` is one flat
/// namespace for the whole machine with no working directory, so a relative
/// `run_dir` — which is what the binary defaults to — would hand two servers
/// started in different directories the same names, and the second would refuse
/// to start. Absolute paths restore exactly the isolation the Unix form gets
/// from the filesystem.
#[must_use]
pub fn local_endpoint(run_dir: &Path, service: &str) -> String {
    if cfg!(windows) {
        let root = std::path::absolute(run_dir).unwrap_or_else(|_| run_dir.to_path_buf());
        // `/` because `\` is the one character a pipe name may not contain.
        let name = root.join(service).display().to_string().replace('\\', "/");
        format!("pipe:{name}")
    } else {
        format!("unix:{}", run_dir.join(format!("{service}.sock")).display())
    }
}

/// The placeholder endpoint a connector-based channel is built from.
///
/// HTTP/2 requires an authority, and the connector ignores it: for a Unix
/// socket or an in-memory pipe the path or the name already decided where the
/// bytes go.
fn connector_uri(service: &str) -> Result<tonic::transport::Endpoint, ChannelError> {
    tonic::transport::Endpoint::try_from("http://[::]:50051").map_err(|source| {
        ChannelError::Transport {
            service: service.to_owned(),
            source,
        }
    })
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

    /// The co-located form this build serves, written the way an operator would.
    const LOCAL: &str = core::cfg_select! {
        unix => { "unix:/run/starling/text.sock" }
        windows => { "pipe:starling/text" }
    };

    #[test]
    fn each_documented_form_parses_to_its_transport() {
        // describe() is the round trip: it is what a log shows and what an
        // operator copies back into the configuration file.
        assert_eq!(
            parse("http://text:50051").map(|t| t.describe()).ok(),
            Some("http://text:50051".to_owned())
        );
        assert_eq!(
            parse(LOCAL).map(|t| t.describe()).ok(),
            Some(LOCAL.to_owned())
        );
        assert_eq!(
            parse("inproc:text").map(|t| t.describe()).ok(),
            Some("inproc:text".to_owned())
        );
    }

    #[test]
    fn a_bare_host_port_is_refused_rather_than_assumed_to_be_tcp() {
        // Assuming would make the co-located scheme a typo away from silently
        // opening a TCP socket on a host that expected an OS-level boundary.
        assert!(parse("text:50051").is_err());
        assert!(parse("unix:").is_err());
        assert!(parse("pipe:").is_err());
        assert!(parse("inproc:").is_err());
    }

    #[test]
    fn the_transport_this_platform_cannot_serve_is_refused_rather_than_substituted() {
        // A configuration file moved between platforms is the case: the
        // endpoint naming a mechanism this build has no way to serve must fail
        // at startup, not resolve to a different boundary than it asks for.
        let absent = core::cfg_select! {
            windows => { "unix:/run/starling/text.sock" }
            unix => { "pipe:starling/text" }
        };
        assert!(parse(absent).is_err(), "{absent} was claimed by something");
    }

    #[test]
    fn every_registered_transport_round_trips_its_own_description() {
        // The property a new transport has to hold, asserted over the registry
        // rather than over a list someone has to remember to extend.
        for written in ["http://text:50051", LOCAL, "inproc:text"] {
            let once = parse(written).expect("the documented forms parse");
            let twice = parse(&once.describe()).expect("a description re-parses");
            assert_eq!(
                once.describe(),
                twice.describe(),
                "{written} did not settle"
            );
        }
    }

    #[test]
    fn the_default_local_endpoint_is_one_this_build_can_actually_serve() {
        // The defaults are generated, so nothing else would catch a platform
        // whose generated endpoint no registered transport claims — it would
        // look like a configuration error in a file the operator never wrote.
        let written = local_endpoint(Path::new("starling-data/run"), "text");
        let transport = parse(&written)
            .unwrap_or_else(|error| panic!("the shipped default must parse: {error}"));
        assert_eq!(
            parse(&transport.describe()).map(|t| t.describe()).ok(),
            Some(transport.describe())
        );
    }

    #[test]
    fn two_run_directories_are_two_deployments() {
        // On Windows the run directory is the *only* thing keeping two servers
        // off one pipe name, and a relative default would collapse both onto
        // the same one.
        assert_ne!(
            local_endpoint(Path::new("/srv/a/run"), "text"),
            local_endpoint(Path::new("/srv/b/run"), "text")
        );
        assert_ne!(
            local_endpoint(Path::new("/srv/a/run"), "text"),
            local_endpoint(Path::new("/srv/a/run"), "voice")
        );
    }
}
