//! How many requests a service is handling at once, measured for every service
//! without any service measuring anything.
//!
//! [`Pressure`](crate::pressure::Pressure) can describe any bounded thing, but
//! a registry only holds what somebody remembered to put in it, and the
//! service nobody instrumented is reliably the service that falls over. The
//! gateway's control lane got a gauge because somebody had already been bitten
//! by it; nineteen other services had none, and their queue depth was not zero,
//! it was unknown.
//!
//! So concurrency is measured where every service already passes through: the
//! tower stack the runtime wraps around each service's routes. A service opts
//! into nothing, and cannot forget.
//!
//! # Why in-flight is the useful number here
//!
//! Starling's services are RPC servers with no concurrency limit, so nothing
//! queues in a channel a depth could be read from. What backs up instead is the
//! caller: requests arrive faster than they complete and the count of
//! outstanding ones climbs. That count *is* the queue, and its peak over an
//! interval is the backpressure signal, see `pressure`'s note on why the peak
//! matters more than the instant.

use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::pressure::{Gauge, Pressure};

/// What the per-service concurrency gauge is called.
///
/// A constant because three places name it, the layer that fills it, the
/// dashboard that draws it, and the test that asserts it exists, and a gauge
/// renamed in two of the three is a chart that silently goes flat.
pub const IN_FLIGHT: &str = "requests in flight";

/// Wraps a service so its outstanding requests are counted.
#[derive(Debug, Clone)]
pub struct InFlightLayer {
    gauge: Gauge,
}

impl InFlightLayer {
    /// A layer filling `IN_FLIGHT` in `pressure`.
    ///
    /// Capacity zero: nothing limits concurrency, so there is no denominator
    /// and a dashboard must show the count rather than a percentage.
    #[must_use]
    pub fn new(pressure: &Pressure) -> Self {
        Self {
            gauge: pressure.gauge(IN_FLIGHT, 0),
        }
    }
}

impl<S> Layer<S> for InFlightLayer {
    type Service = InFlight<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InFlight {
            inner,
            gauge: self.gauge.clone(),
        }
    }
}

/// A service counting the requests it has not finished.
#[derive(Debug, Clone)]
pub struct InFlight<S> {
    inner: S,
    gauge: Gauge,
}

impl<S, R> Service<R> for InFlight<S>
where
    S: Service<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Counted<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        self.gauge.add(1);
        Counted {
            inner: self.inner.call(request),
            // Held by the future rather than released here: `call` returns
            // immediately and the work happens while the future is polled, so
            // decrementing here would count every request as instantaneous and
            // the gauge would read zero under any load at all.
            _busy: Busy(self.gauge.clone()),
        }
    }
}

/// Releases one unit of occupancy when dropped.
///
/// A guard rather than a decrement at the end of the future, because a request
/// can end without finishing: a cancelled call, a client that hung up, a
/// panicking handler. Each of those drops the future, and none of them reaches
/// a line at the bottom of it, which would leak occupancy upward forever and
/// make a healthy service look permanently saturated.
#[derive(Debug)]
struct Busy(Gauge);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.release(1);
    }
}

pin_project! {
    /// A response future that counts as occupancy until it resolves.
    #[derive(Debug)]
    pub struct Counted<F> {
        #[pin]
        inner: F,
        _busy: Busy,
    }
}

impl<F: Future> Future for Counted<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Waker;
    use tower::ServiceExt;

    /// A service that answers only once `finish` is set.
    #[derive(Clone)]
    struct Held(Arc<AtomicBool>);

    impl Service<()> for Held {
        type Response = ();
        type Error = std::convert::Infallible;
        type Future = HeldFuture;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, (): ()) -> Self::Future {
            HeldFuture(Arc::clone(&self.0))
        }
    }

    struct HeldFuture(Arc<AtomicBool>);

    impl Future for HeldFuture {
        type Output = Result<(), std::convert::Infallible>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.0.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[tokio::test]
    async fn a_request_counts_while_it_is_running_and_not_after() {
        let pressure = Pressure::new();
        let finish = Arc::new(AtomicBool::new(false));
        let mut service = InFlightLayer::new(&pressure).layer(Held(Arc::clone(&finish)));

        let call = service.ready().await.expect("ready").call(());
        tokio::task::yield_now().await;
        assert_eq!(
            pressure.gauge(IN_FLIGHT, 0).used(),
            1,
            "a request that has not answered is not in flight"
        );

        finish.store(true, Ordering::SeqCst);
        let _ = call.await;
        assert_eq!(
            pressure.gauge(IN_FLIGHT, 0).used(),
            0,
            "occupancy outlived the request"
        );
    }

    #[tokio::test]
    async fn a_dropped_request_releases_its_occupancy() {
        // A cancelled call or a client that hung up drops the future without
        // ever resolving it. Counting that as still in flight would make a
        // healthy service look permanently saturated, and the number would
        // only ever climb.
        let pressure = Pressure::new();
        let finish = Arc::new(AtomicBool::new(false));
        let mut service = InFlightLayer::new(&pressure).layer(Held(finish));

        let call = service.ready().await.expect("ready").call(());
        assert_eq!(pressure.gauge(IN_FLIGHT, 0).used(), 1);
        drop(call);
        assert_eq!(pressure.gauge(IN_FLIGHT, 0).used(), 0);
    }

    #[tokio::test]
    async fn concurrent_requests_raise_the_peak() {
        // The number an operator is actually looking for: not how many are
        // running at the moment of the poll, but how many piled up.
        let pressure = Pressure::new();
        let finish = Arc::new(AtomicBool::new(false));
        let mut service = InFlightLayer::new(&pressure).layer(Held(Arc::clone(&finish)));

        let calls: Vec<_> = (0..5)
            .map(|_| {
                let _ = Waker::noop();
                service.call(())
            })
            .collect();
        assert_eq!(pressure.gauge(IN_FLIGHT, 0).used(), 5);

        finish.store(true, Ordering::SeqCst);
        for call in calls {
            let _ = call.await;
        }

        let sample = pressure
            .sample()
            .into_iter()
            .find(|load| load.name == IN_FLIGHT)
            .expect("the layer registered its gauge");
        assert_eq!(sample.used, 0, "everything finished");
        assert_eq!(sample.peak, 5, "the pile-up was not recorded");
        // Nothing limits concurrency, so there is no percentage to show.
        assert_eq!(sample.utilisation(), None);
    }
}
