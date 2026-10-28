use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::limits::Guard;

/// Bytes and requests on one connection, for the idle timeout.
pub struct Activity {
    base: Instant,
    /// nanoseconds after `base` of the last byte or request end
    last: AtomicU64,
    in_flight: AtomicUsize,
}

/// A request in flight on a connection; dropping it ends the request.
pub struct InFlight(Arc<Activity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Activity {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
        }
    }

    fn touch(&self) {
        let at = self.base.elapsed().as_nanos() as u64;
        self.last.fetch_max(at, Ordering::Relaxed);
    }

    /// Counts a request until the guard drops.
    pub fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        InFlight(self.clone())
    }

    /// Resolves once nothing was read or written and no request was in
    /// flight for `timeout`.
    pub async fn idle(&self, timeout: Duration) {
        loop {
            // ponytail: rechecks every `timeout` while a request runs, a
            // Notify if requests ever outlast many timeouts in bulk
            if self.in_flight.load(Ordering::Acquire) > 0 {
                tokio::time::sleep(timeout).await;
                continue;
            }
            let last = self.base + Duration::from_nanos(self.last.load(Ordering::Relaxed));
            let deadline = last + timeout;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// An accepted connection: holds its place against the limits until it is
/// dropped (also under an upgraded tunnel), and records activity.
pub struct Conn {
    io: TcpStream,
    _guard: Option<Guard>,
    activity: Arc<Activity>,
}

impl Conn {
    pub(crate) fn new(io: TcpStream, guard: Option<Guard>) -> Self {
        Self {
            io,
            _guard: guard,
            activity: Arc::new(Activity::new()),
        }
    }

    pub fn activity(&self) -> Arc<Activity> {
        self.activity.clone()
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity.touch();
        }
        r
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r
            && n > 0
        {
            self.activity.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair() -> (Conn, TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (server, _) = l.accept().await.unwrap();
        (Conn::new(server, None), client)
    }

    /// RFC 0009 case 10, at the connection
    #[tokio::test(start_paused = true)]
    async fn idle_waits_for_quiet_and_no_request() {
        let (conn, _client) = pair().await;
        let act = conn.activity();
        let start = tokio::time::Instant::now();
        let req = act.begin();
        let idle = act.idle(Duration::from_secs(1));
        tokio::pin!(idle);
        // a request in flight keeps it busy however long it takes
        assert!(
            tokio::time::timeout(Duration::from_secs(5), &mut idle)
                .await
                .is_err()
        );
        drop(req);
        idle.await;
        let took = start.elapsed();
        assert!(
            took >= Duration::from_secs(6) && took < Duration::from_secs(7),
            "{took:?}"
        );
        drop(conn);
    }
}
