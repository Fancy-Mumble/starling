//! A server on loopback to fetch from, for the tests of whatever is fetching.
//!
//! Every test of this crate and of its consumers needs the same thing: a real
//! HTTP server, on a real socket, answering whatever the test says. Nothing
//! here is a stub - real sockets, real HTTP/1.1, real redirects - because the
//! part worth testing is the exchange, and an exchange against a fake is a test
//! of the fake.
//!
//! It lives beside [`Fetcher::against_loopback`] and behind the same
//! `loopback` feature, for the same reason: a consumer that needs the fetcher
//! to talk to 127.0.0.1 needs something there to talk to, and having each of
//! them stand up its own hyper server is how the scaffolding drifts and how
//! `hyper` ends up in the dependencies of a crate that does not otherwise
//! make HTTP requests.
//!
//! [`Fetcher::against_loopback`]: crate::Fetcher::against_loopback

// `allow-expect-in-tests` covers a `#[cfg(test)]` module and cannot see this
// one: with the `loopback` feature on, this compiles as ordinary library code
// even though every caller is a test. The panics are the point - a scaffolding
// that cannot bind a port and returns a URL nothing is listening on turns one
// broken machine into a suite of confusing fetch failures - so the exemption is
// stated here rather than the panics being smuggled past the lint as silent
// fallbacks.
#![expect(
    clippy::expect_used,
    reason = "AUDIT: test scaffolding, gated behind `loopback` and never shipped               (scripts/check-crate-layering.sh); failing loudly is the contract"
)]

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, body::Incoming};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// A response, as a test writes one.
pub type Answer = Response<Full<Bytes>>;

/// Serve `answer` for each request path, and hand back the URL to fetch.
///
/// The port is whatever the OS gives us, because a fixed one makes the suite
/// fail whenever a developer happens to be running something on it.
pub async fn serving<F>(answer: F) -> String
where
    F: Fn(&str) -> Answer + Send + Sync + Clone + 'static,
{
    serving_requests(move |request| answer(request.uri().path())).await
}

/// The same, for a test that cares what the *request* said rather than only
/// where it was aimed.
pub async fn serving_requests<F>(answer: F) -> String
where
    F: Fn(&Request<Incoming>) -> Answer + Send + Sync + Clone + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("bound").port();
    drop(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            drop(tokio::spawn(answering(stream, answer.clone())));
        }
    }));
    format!("http://127.0.0.1:{port}")
}

/// One connection, answered by `answer` until the peer goes away.
async fn answering<F>(stream: TcpStream, answer: F)
where
    F: Fn(&Request<Incoming>) -> Answer + Send + Sync + Clone + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let answer = answer.clone();
        async move { Ok::<_, Infallible>(answer(&request)) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// An HTML page.
#[must_use]
pub fn html(body: &str) -> Answer {
    Response::builder()
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("a response")
}

/// A response carrying `bytes` as `kind`.
#[must_use]
pub fn asset(kind: &'static str, bytes: Vec<u8>) -> Answer {
    Response::builder()
        .header("content-type", kind)
        .body(Full::new(Bytes::from(bytes)))
        .expect("a response")
}

/// A `302` to `to`.
#[must_use]
pub fn redirect(to: &str) -> Answer {
    Response::builder()
        .status(302)
        .header("location", to)
        .body(Full::new(Bytes::new()))
        .expect("a response")
}

/// A bare status with no body, for the failure paths.
#[must_use]
pub fn status(code: u16) -> Answer {
    Response::builder()
        .status(code)
        .body(Full::new(Bytes::new()))
        .expect("a response")
}
