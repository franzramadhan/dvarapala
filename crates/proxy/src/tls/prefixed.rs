use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream that gives back bytes already read off it (the ClientHello
/// read for JA4, RFC 0012) before reading on.
pub(crate) struct Prefixed<IO> {
    seen: Vec<u8>,
    pos: usize,
    io: IO,
}

impl<IO> Prefixed<IO> {
    pub(crate) fn new(seen: Vec<u8>, io: IO) -> Self {
        Self { seen, pos: 0, io }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Prefixed<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if me.pos < me.seen.len() {
            let n = buf.remaining().min(me.seen.len() - me.pos);
            buf.put_slice(&me.seen[me.pos..me.pos + n]);
            me.pos += n;
            if me.pos == me.seen.len() {
                me.seen = Vec::new();
                me.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefixed<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, b)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, b)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
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
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn replays_then_reads_on() {
        let mut s = Prefixed::new(b"abc".to_vec(), &b"def"[..]);
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "abcdef");
    }

    #[tokio::test]
    async fn writes_go_straight_through() {
        use tokio::io::AsyncWriteExt;
        let mut s = Prefixed::new(b"hello".to_vec(), Vec::new());
        assert_eq!(s.is_write_vectored(), Vec::<u8>::new().is_write_vectored());
        s.write_all(b"one ").await.unwrap();
        s.write_vectored(&[io::IoSlice::new(b"two")]).await.unwrap();
        s.flush().await.unwrap();
        s.shutdown().await.unwrap();
        assert_eq!(s.io, b"one two");
    }
}
