use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::tunnels::Slot;

/// HTTP/1.1 upgrades passed through to the upstream (RFC 0005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeConfig {
    /// `Upgrade` tokens passed to the upstream, lowercase; empty turns
    /// upgrades off.
    pub protocols: Vec<String>,
    /// Open tunnels at once; over it, `503`.
    pub max_tunnels: usize,
    /// No bytes in either direction for this long closes a tunnel.
    pub idle_timeout: Duration,
    /// Closes any tunnel after this long; `None` off.
    pub max_lifetime: Option<Duration>,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            protocols: vec!["websocket".to_owned()],
            max_tunnels: 10_000,
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Some(Duration::from_secs(24 * 3600)),
        }
    }
}

/// Put on every request by the server: signalled when shutdown starts, and
/// the server waits until every clone is dropped (RFC 0005).
#[derive(Clone)]
pub(crate) struct Drain(pub(crate) watch::Receiver<()>);

/// Waits for both sides to finish the `101`, then copies bytes both ways
/// until one side ends, the tunnel idles or outlives its limit, or `drain`
/// fires. `slot` is held until then.
pub(crate) fn spawn(
    client: OnUpgrade,
    upstream: OnUpgrade,
    protocol: String,
    slot: Slot,
    drain: Option<Drain>,
) {
    tokio::spawn(async move {
        let (client, upstream) = match tokio::join!(client, upstream) {
            (Ok(c), Ok(u)) => (c, u),
            (Err(e), _) | (_, Err(e)) => {
                tracing::debug!(error = %e, "upgrade failed");
                return;
            }
        };
        tunnel(client, TokioIo::new(upstream), protocol, &slot, drain).await;
    });
}

/// Like [`spawn`] for a `CONNECT` tunnel (RFC 0007) to an open `upstream`
/// connection; `held` is dropped when the tunnel ends.
pub(crate) fn spawn_connect<T: Send + 'static>(
    client: OnUpgrade,
    upstream: TcpStream,
    slot: Slot,
    drain: Option<Drain>,
    held: T,
) {
    tokio::spawn(async move {
        match client.await {
            Ok(c) => tunnel(c, upstream, "connect".to_owned(), &slot, drain).await,
            Err(e) => tracing::debug!(error = %e, "upgrade failed"),
        }
        drop(held);
    });
}

async fn tunnel<U: AsyncRead + AsyncWrite>(
    client: Upgraded,
    upstream: U,
    protocol: String,
    slot: &Slot,
    drain: Option<Drain>,
) {
    let open = metrics::gauge!("dvarapala_tunnels_open", "protocol" => protocol.clone());
    open.increment(1.0);
    let end = copy(TokioIo::new(client), upstream, &slot.0.config, drain).await;
    open.decrement(1.0);
    metrics::counter!("dvarapala_tunnels_total", "protocol" => protocol, "end" => end).increment(1);
}

/// Shared by both sides of one tunnel.
struct Activity {
    start: Instant,
    /// milliseconds from `start` to the last read
    last: AtomicU64,
}

/// Returns the `end` label.
async fn copy<C, U>(
    client: C,
    upstream: U,
    config: &UpgradeConfig,
    drain: Option<Drain>,
) -> &'static str
where
    C: AsyncRead + AsyncWrite,
    U: AsyncRead + AsyncWrite,
{
    let act = Activity {
        start: Instant::now(),
        last: AtomicU64::new(0),
    };
    let (cr, mut cw) = tokio::io::split(client);
    let (ur, mut uw) = tokio::io::split(upstream);
    let (mut cr, mut ur) = (Side::new(cr, &act), Side::new(ur, &act));
    let end = {
        // 8 KB buffer each way. The first direction to end closes the
        // tunnel: no half-close, a WebSocket never needs one.
        // ponytail: a write error is labelled as the reading side's end
        let up = tokio::io::copy(&mut cr, &mut uw);
        let down = tokio::io::copy(&mut ur, &mut cw);
        let lifetime = async {
            match config.max_lifetime {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        };
        let drain = async {
            match drain {
                // an error means the server is gone: shut down too
                Some(mut d) => drop(d.0.changed().await),
                None => std::future::pending().await,
            }
        };
        tokio::pin!(up, down, lifetime, drain);
        let idle_at = || {
            let last = Duration::from_millis(act.last.load(Ordering::Relaxed));
            act.start + last + config.idle_timeout
        };
        loop {
            tokio::select! {
                _ = &mut up => break "client",
                _ = &mut down => break "upstream",
                // a read while the timer ran moved `idle_at`: go round
                () = tokio::time::sleep_until(idle_at()) => {
                    if Instant::now() >= idle_at() {
                        break "idle";
                    }
                }
                () = &mut lifetime => break "lifetime",
                () = &mut drain => break "shutdown",
            }
        }
    };
    metrics::counter!("dvarapala_tunnel_bytes_total", "direction" => "in").increment(cr.bytes);
    metrics::counter!("dvarapala_tunnel_bytes_total", "direction" => "out").increment(ur.bytes);
    end
}

/// The read half of one side: counts its bytes and records each read in
/// the shared [`Activity`].
struct Side<'a, T> {
    io: T,
    act: &'a Activity,
    bytes: u64,
}

impl<'a, T> Side<'a, T> {
    fn new(io: T, act: &'a Activity) -> Self {
        Self { io, act, bytes: 0 }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Side<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = ready!(Pin::new(&mut self.io).poll_read(cx, buf));
        let n = buf.filled().len() - before;
        if n > 0 {
            self.bytes += n as u64;
            let ms = self.act.start.elapsed().as_millis() as u64;
            self.act.last.store(ms, Ordering::Relaxed);
        }
        Poll::Ready(r)
    }
}
