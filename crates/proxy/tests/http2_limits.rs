//! RFC 0004 cases 15 to 18: HTTP/2 listener limits. A compliant client
//! never breaks them, so these tests write raw frames.

mod h2;

use std::net::SocketAddr;
use std::time::Duration;

use dvarapala_proxy::{Http2Limits, UpstreamProtocol};
use h2::{proxy, upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const GOAWAY: u8 = 7;
const CONTINUATION: u8 = 9;
const END_STREAM: u8 = 1;
const ACK: u8 = 1;
const END_HEADERS: u8 = 4;
const CANCEL: u32 = 8;
const REFUSED_STREAM: u32 = 7;
const ENHANCE_YOUR_CALM: u32 = 0xb;

struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    f.extend([ty, flags]);
    f.extend(stream.to_be_bytes());
    f.extend(payload);
    f
}

/// HPACK for `:method POST`, `:scheme http`, `:path /version` and
/// `:authority 127.0.0.1`, from the static table and literals.
fn post_block() -> Vec<u8> {
    let mut b = vec![0x83, 0x86, 0x44, 8];
    b.extend(b"/version");
    b.extend([0x41, 9]);
    b.extend(b"127.0.0.1");
    b
}

async fn read_frame(s: &mut TcpStream) -> Option<Frame> {
    let mut head = [0u8; 9];
    s.read_exact(&mut head).await.ok()?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0; len];
    s.read_exact(&mut payload).await.ok()?;
    Some(Frame {
        ty: head[3],
        flags: head[4],
        stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
        payload,
    })
}

/// Preface and SETTINGS, then ACKs the server's SETTINGS so its limits
/// apply before the first stream.
async fn connect(addr: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&[PREFACE, &frame(SETTINGS, 0, 0, &[])].concat())
        .await
        .unwrap();
    loop {
        let f = read_frame(&mut s).await.expect("closed during handshake");
        if f.ty == SETTINGS && f.flags & ACK == 0 {
            s.write_all(&frame(SETTINGS, ACK, 0, &[])).await.unwrap();
            return s;
        }
    }
}

/// Reads frames until `pick` returns `Some`, the connection closes (`None`)
/// or 5 seconds pass (panic).
async fn until<T>(s: &mut TcpStream, mut pick: impl FnMut(&Frame) -> Option<T>) -> Option<T> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(f) = read_frame(s).await {
            if let Some(t) = pick(&f) {
                return Some(t);
            }
        }
        None
    })
    .await
    .expect("no matching frame within 5s")
}

fn code(f: &Frame, at: usize) -> u32 {
    u32::from_be_bytes(f.payload[at..at + 4].try_into().unwrap())
}

async fn start(h2: Http2Limits) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let up = upstream().await;
    proxy(&format!("http://{up}"), UpstreamProtocol::Http1, h2).await
}

/// RFC 0004 case 15
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn third_stream_is_refused() {
    let (addr, _stop) = start(Http2Limits {
        max_concurrent_streams: 2,
        ..Http2Limits::default()
    })
    .await;
    let mut s = connect(addr).await;
    // no END_STREAM: the upstream waits for the body, the streams stay open
    for id in [1, 3, 5] {
        s.write_all(&frame(HEADERS, END_HEADERS, id, &post_block()))
            .await
            .unwrap();
    }
    let refused = until(&mut s, |f| {
        (f.ty == RST_STREAM).then(|| (f.stream, code(f, 0)))
    })
    .await;
    assert_eq!(refused, Some((5, REFUSED_STREAM)));
}

/// RFC 0004 case 16
#[tokio::test(flavor = "multi_thread")]
async fn rapid_reset_gets_goaway() {
    let (addr, _stop) = start(Http2Limits::default()).await;
    let mut s = connect(addr).await;
    let mut burst = Vec::new();
    for i in 0..500u32 {
        let id = 2 * i + 1;
        burst.extend(frame(HEADERS, END_HEADERS | END_STREAM, id, &post_block()));
        burst.extend(frame(RST_STREAM, 0, id, &CANCEL.to_be_bytes()));
    }
    // the server may close before reading it all
    let _ = s.write_all(&burst).await;
    let goaway = until(&mut s, |f| (f.ty == GOAWAY).then(|| code(f, 4))).await;
    assert_eq!(goaway, Some(ENHANCE_YOUR_CALM));
}

/// RFC 0004 case 17: 64 KB of headers in CONTINUATION frames
#[tokio::test(flavor = "multi_thread")]
async fn oversized_header_list_is_rejected() {
    let (addr, _stop) = start(Http2Limits::default()).await;
    let mut s = connect(addr).await;
    let mut out = frame(HEADERS, END_STREAM, 1, &post_block());
    let value = [b'a'; 100];
    let mut block = Vec::new();
    for i in 0..600u32 {
        // literal without indexing, new name
        let name = format!("x-h{i}");
        block.extend([0x00, name.len() as u8]);
        block.extend(name.as_bytes());
        block.push(value.len() as u8);
        block.extend(value);
    }
    let chunks: Vec<&[u8]> = block.chunks(4096).collect();
    for (i, c) in chunks.iter().enumerate() {
        let last = i + 1 == chunks.len();
        out.extend(frame(
            CONTINUATION,
            if last { END_HEADERS } else { 0 },
            1,
            c,
        ));
    }
    let _ = s.write_all(&out).await;
    // a response that starts with 0x88 is `:status 200`: the upstream got it
    let answer = until(&mut s, |f| match f.ty {
        GOAWAY => Some("goaway"),
        RST_STREAM if f.stream == 1 => Some("reset"),
        HEADERS if f.stream == 1 && f.payload.first() == Some(&0x88) => Some("forwarded"),
        HEADERS if f.stream == 1 => Some("rejected"),
        _ => None,
    })
    .await;
    assert_ne!(answer, Some("forwarded"));
}

/// RFC 0004 case 18
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn unanswered_ping_closes_the_connection() {
    let (addr, _stop) = start(Http2Limits {
        keepalive_interval: Some(Duration::from_millis(200)),
        keepalive_timeout: Duration::from_millis(200),
        ..Http2Limits::default()
    })
    .await;
    let mut s = connect(addr).await;
    // never answer PING: a GOAWAY or the close must come before `until`
    // gives up after 5 s
    until(&mut s, |f| (f.ty == GOAWAY).then_some(())).await;
}
