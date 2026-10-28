use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::limits::Guard;

/// Bytes and requests on one connection, for the idle timeout.
pub struct Activity {
    _todo: (),
}

/// A request in flight on a connection; dropping it ends the request.
#[allow(dead_code)]
pub struct InFlight(Arc<Activity>);

impl Activity {
    /// Counts a request until the guard drops.
    pub fn begin(self: &Arc<Self>) -> InFlight {
        InFlight(self.clone())
    }

    /// Resolves once nothing was read or written and no request was in
    /// flight for `timeout`.
    pub async fn idle(&self, timeout: Duration) {
        let _ = timeout;
        todo!("rfc 0009")
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
    #[allow(dead_code)]
    pub(crate) fn new(io: TcpStream, guard: Option<Guard>) -> Self {
        let _ = (&io, &guard);
        todo!("rfc 0009")
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
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
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
    #[ignore = "rfc 0009"]
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
