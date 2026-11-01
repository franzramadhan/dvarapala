//! `dvarapala replay` (RFC 0016): the protection layer over an access log
//! on a virtual clock, then the protection metrics.

use std::convert::Infallible;
use std::error::Error;
use std::fs::File;
use std::future::{Ready, poll_fn, ready};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_l7::{Line, MAX_LINE, RateLimitLayer};
use http::{Request, Response, StatusCode};
use http_body_util::{Empty, Full};
use tower_layer::Layer;
use tower_service::Service;
use tracing_subscriber::EnvFilter;

use crate::{config, layer, metrics, model, waf};

const USAGE: &str = "dvarapala replay --config <file> [--out <file>] <log | ->";

/// Series in the report, by name prefix.
const REPORT: [&str; 6] = [
    "dvarapala_requests_total",
    "dvarapala_challenges_total",
    "dvarapala_fingerprint_matches_total",
    "dvarapala_route_requests_total",
    "dvarapala_detection_",
    "dvarapala_waf_",
];

/// Skip reasons kept for the report.
const MAX_REASONS: usize = 10;

static BASE: OnceLock<Instant> = OnceLock::new();
/// Nanoseconds since the first line's `ts`.
static NANOS: AtomicU64 = AtomicU64::new(0);

/// The layer's clock: the `ts` of the line being replayed.
fn now() -> Instant {
    *BASE.get_or_init(Instant::now) + Duration::from_nanos(NANOS.load(Ordering::Relaxed))
}

/// The upstream: `200` without any I/O.
#[derive(Clone)]
struct Answer;

impl<B> Service<Request<B>> for Answer {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request<B>) -> Self::Future {
        ready(Ok(Response::new(Full::default())))
    }
}

struct Args {
    config: PathBuf,
    out: Option<PathBuf>,
    log: String,
}

fn args(mut a: impl Iterator<Item = String>) -> Option<Args> {
    let (mut config, mut out, mut log) = (None, None, None);
    while let Some(x) = a.next() {
        match x.as_str() {
            "--config" => config = Some(PathBuf::from(a.next()?)),
            "--out" => out = Some(PathBuf::from(a.next()?)),
            _ if log.is_none() && (x == "-" || !x.starts_with('-')) => log = Some(x),
            _ => return None,
        }
    }
    Some(Args {
        config: config?,
        out,
        log: log?,
    })
}

/// Exit status 2 on bad arguments, a bad config or an unreadable log.
pub fn main(a: impl Iterator<Item = String>) -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();
    let Some(a) = args(a) else {
        eprintln!("usage: {USAGE}");
        return ExitCode::from(2);
    };
    match run(a) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dvarapala replay: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(a: Args) -> Result<(), Box<dyn Error>> {
    let cfg = config::load(Some(&a.config))?;
    if cfg.mode != config::ProxyMode::Reverse || !cfg.rate_limit.enabled {
        return Err("replay runs the reverse proxy's rate limiter: mode = \"reverse\" and rate_limit.enabled".into());
    }
    let ignored: Vec<&str> = [
        ("upstream", cfg.upstream.is_some()),
        ("[pool]", cfg.pool != Default::default()),
        ("[tls]", cfg.tls != Default::default()),
        ("[quic]", cfg.quic != Default::default()),
        ("[l4]", cfg.l4 != Default::default()),
        ("[store]", cfg.store != Default::default()),
        ("[xdp]", cfg.xdp != Default::default()),
        ("[admin]", cfg.admin != Default::default()),
    ]
    .into_iter()
    .filter_map(|(k, set)| set.then_some(k))
    .collect();
    if !ignored.is_empty() {
        tracing::warn!(msg = "replay ignores", keys = ?ignored, "no network in a replay");
    }
    let handle = metrics::install()?;
    // RFC 0017: the agent sees the request line and headers, no body
    let waf = waf::Layer::new(waf::config(&cfg)?);
    let model = cfg
        .ml
        .model
        .as_deref()
        .map(|p| model::load(p, None))
        .transpose()?;
    let mut svc =
        RateLimitLayer::new(layer::config(&cfg, now, model.as_ref())?)?.layer(waf.layer(Answer));
    let input: Box<dyn Read> = match a.log.as_str() {
        "-" => Box::new(io::stdin()),
        p => Box::new(File::open(p).map_err(|e| format!("{p}: {e}"))?),
    };
    let mut input = BufReader::new(input);
    let mut out = match &a.out {
        Some(p) => Some(BufWriter::new(
            File::create(p).map_err(|e| format!("{}: {e}", p.display()))?,
        )),
        None => None,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (mut n, mut replayed, mut reasons) = (0u64, 0u64, Vec::new());
    let (mut first, mut clock) = (None::<f64>, 0f64);
    let mut buf = Vec::new();
    while let Some(fits) = next_line(&mut input, &mut buf)? {
        n += 1;
        let line = if fits {
            std::str::from_utf8(&buf)
                .map_err(|_| "not UTF-8".to_owned())
                .and_then(Line::parse)
        } else {
            Err(format!("line over {MAX_LINE} bytes"))
        };
        let line = match line {
            Ok(l) => l,
            Err(why) => {
                if reasons.len() < MAX_REASONS {
                    tracing::warn!(msg = "line skipped", line = n, %why);
                    reasons.push(format!("line {n}: {why}"));
                }
                continue;
            }
        };
        // the clock never goes back
        clock = clock.max(line.ts - *first.get_or_insert(line.ts));
        NANOS.store((clock * 1e9) as u64, Ordering::Relaxed);
        let status = rt.block_on(async {
            poll_fn(|cx| Service::<Request<Empty<Bytes>>>::poll_ready(&mut svc, cx)).await?;
            svc.call(line.request.map(|()| Empty::<Bytes>::new()))
                .await
                .map(|r| r.status())
        });
        let status = status.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        replayed += 1;
        if let Some(o) = &mut out {
            writeln!(o, r#"{{"line":{n},"status":{}}}"#, status.as_u16())?;
        }
    }
    if let Some(mut o) = out {
        o.flush()?;
    }
    let mut report = io::stdout().lock();
    writeln!(
        report,
        "lines {n}, replayed {replayed}, skipped {}, span {clock:.3} s",
        n - replayed
    )?;
    for r in &reasons {
        writeln!(report, "skipped {r}")?;
    }
    for l in handle.render().lines() {
        if REPORT.iter().any(|p| l.starts_with(p)) {
            writeln!(report, "{l}")?;
        }
    }
    Ok(())
}

/// Reads the next line into `buf` without its newline. `Some(false)` for
/// a line over [`MAX_LINE`], whose rest is dropped unread into `buf`;
/// `None` at the end.
fn next_line(r: &mut impl BufRead, buf: &mut Vec<u8>) -> io::Result<Option<bool>> {
    buf.clear();
    let n = r
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        return Ok(Some(true));
    }
    if buf.len() <= MAX_LINE {
        return Ok(Some(true));
    }
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => {
                r.consume(i + 1);
                break;
            }
            None => {
                let len = chunk.len();
                r.consume(len);
            }
        }
    }
    Ok(Some(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lines_are_cut_and_skipped() {
        let long = "a".repeat(MAX_LINE + 10);
        let data = format!("one\r\n{long}\nthree");
        let mut r = BufReader::with_capacity(16, data.as_bytes());
        let mut buf = Vec::new();
        let mut got = Vec::new();
        while let Some(fits) = next_line(&mut r, &mut buf).unwrap() {
            got.push((
                fits,
                String::from_utf8_lossy(&buf[..buf.len().min(5)]).into_owned(),
            ));
        }
        assert_eq!(
            got,
            [
                (true, "one".to_owned()),
                (false, "aaaaa".to_owned()),
                (true, "three".to_owned())
            ]
        );
    }

    #[test]
    fn long_last_line_without_a_newline() {
        let data = "a".repeat(MAX_LINE + 100);
        let mut r = BufReader::with_capacity(16, data.as_bytes());
        let mut buf = Vec::new();
        assert_eq!(next_line(&mut r, &mut buf).unwrap(), Some(false));
        assert_eq!(next_line(&mut r, &mut buf).unwrap(), None);
    }

    #[test]
    fn arguments() {
        let a = |v: &[&str]| args(v.iter().map(|s| (*s).to_owned()));
        let ok = a(&["--config", "c.toml", "--out", "o.json", "-"]).unwrap();
        assert_eq!(ok.config, PathBuf::from("c.toml"));
        assert_eq!(ok.out, Some(PathBuf::from("o.json")));
        assert_eq!(ok.log, "-");
        for bad in [
            &["--config", "c.toml"][..],
            &["log"],
            &["--config", "c.toml", "log", "again"],
            &["--config", "c.toml", "--verbose", "log"],
            &["--config"],
            &["--config", "c.toml", "log", "--out"],
        ] {
            assert!(a(bad).is_none(), "{bad:?}");
        }
    }
}
