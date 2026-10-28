use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use tokio::time::{Instant, Sleep};

const WINDOW: Duration = Duration::from_secs(10);

/// The `min_body_rate` put on every request by the server; proxies wrap the
/// body they forward in [`MinBodyRate`] with it.
#[derive(Debug, Clone, Copy)]
pub struct BodyRate(pub u64);

/// The body arrived slower than `min_body_rate`.
#[derive(Debug)]
pub struct TooSlow;

impl fmt::Display for TooSlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request body slower than l4.min_body_rate")
    }
}

impl Error for TooSlow {}

/// Whether `e` or one of its sources is [`TooSlow`].
pub fn is_too_slow(e: &(dyn Error + 'static)) -> bool {
    let mut cur = Some(e);
    while let Some(e) = cur {
        if e.is::<TooSlow>() {
            return true;
        }
        // io::Error's source skips the error it wraps
        cur = match e.downcast_ref::<io::Error>() {
            Some(io) => io.get_ref().map(|i| i as &(dyn Error + 'static)),
            None => e.source(),
        };
    }
    false
}

/// A request body cut with [`TooSlow`] when fewer than `rate * 10` bytes
/// arrive in a 10 s window; rate 0 passes everything through.
pub struct MinBodyRate<B> {
    inner: B,
    /// bytes a window needs; 0 off
    need: u64,
    seen: u64,
    /// end of the current window, from the first poll
    window: Option<Pin<Box<Sleep>>>,
}

impl<B> MinBodyRate<B> {
    pub fn new(inner: B, rate: u64) -> Self {
        Self {
            inner,
            need: rate.saturating_mul(WINDOW.as_secs()),
            seen: 0,
            window: None,
        }
    }
}

impl<B> Body for MinBodyRate<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        if let Poll::Ready(f) = Pin::new(&mut this.inner).poll_frame(cx) {
            if let Some(d) = f.as_ref().and_then(|f| f.as_ref().ok()?.data_ref()) {
                this.seen += d.len() as u64;
            }
            return Poll::Ready(f.map(|f| f.map_err(Into::into)));
        }
        if this.need == 0 {
            return Poll::Pending;
        }
        let window = this
            .window
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(WINDOW)));
        while window.as_mut().poll(cx).is_ready() {
            if this.seen < this.need {
                metrics::counter!("dvarapala_l4_timeouts_total", "kind" => "body").increment(1);
                return Poll::Ready(Some(Err(Box::new(TooSlow))));
            }
            this.seen = 0;
            window.as_mut().reset(Instant::now() + WINDOW);
        }
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http_body_util::BodyExt;

    use super::*;

    /// `left` chunks of `size` bytes, one every `every`.
    struct Trickle {
        left: usize,
        size: usize,
        every: Duration,
        sleep: Pin<Box<Sleep>>,
    }

    fn trickle(left: usize, size: usize, every: Duration) -> Trickle {
        let sleep = Box::pin(tokio::time::sleep(every));
        Trickle {
            left,
            size,
            every,
            sleep,
        }
    }

    impl Body for Trickle {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            if self.left == 0 {
                return Poll::Ready(None);
            }
            std::task::ready!(self.sleep.as_mut().poll(cx));
            let next = tokio::time::Instant::now() + self.every;
            self.sleep.as_mut().reset(next);
            self.left -= 1;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; self.size])))))
        }
    }

    /// RFC 0009 case 11, at the body: 10 bytes a second against 1000
    #[tokio::test(start_paused = true)]
    async fn slow_body_is_cut() {
        let body = MinBodyRate::new(trickle(100, 10, Duration::from_secs(1)), 1000);
        let e = body.collect().await.expect_err("cut");
        assert!(is_too_slow(&*e));
    }

    #[tokio::test(start_paused = true)]
    async fn fast_or_unlimited_body_passes() {
        let fast = MinBodyRate::new(trickle(30, 20_000, Duration::from_secs(1)), 1000);
        assert_eq!(fast.collect().await.unwrap().to_bytes().len(), 600_000);
        let off = MinBodyRate::new(trickle(30, 10, Duration::from_secs(1)), 0);
        assert_eq!(off.collect().await.unwrap().to_bytes().len(), 300);
    }

    #[test]
    fn too_slow_is_found_in_the_chain() {
        let boxed: Box<dyn Error + Send + Sync> = Box::new(TooSlow);
        assert!(is_too_slow(&*boxed));
        assert!(!is_too_slow(&std::io::Error::other("x")));
        assert!(is_too_slow(&std::io::Error::other(TooSlow)));
    }
}
