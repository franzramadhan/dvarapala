#![allow(unused_variables, unused_imports, unused_mut, dead_code)]
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
        todo!("rfc 0012")
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Prefixed<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        todo!("rfc 0012")
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefixed<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        todo!("rfc 0012")
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        todo!("rfc 0012")
    }

    fn is_write_vectored(&self) -> bool {
        todo!("rfc 0012")
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("rfc 0012")
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!("rfc 0012")
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    #[ignore = "rfc 0012"]
    async fn replays_then_reads_on() {
        let mut s = Prefixed::new(b"abc".to_vec(), &b"def"[..]);
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "abcdef");
    }
}
