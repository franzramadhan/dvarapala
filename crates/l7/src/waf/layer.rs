//! RFC 0017: the WAF stage. Buffers the body up to `max_body`, asks the
//! agent, then forwards, answers its status or fails closed.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{TrustedProxies, client_ip};
use http::header::CONNECTION;
use http::request::Parts;
use http::{HeaderValue, Request, Response, StatusCode, Version};
use http_body::Body;
use http_body_util::BodyExt;
use tower_layer::Layer;
use tower_service::Service;

use super::agent::{Answer, Endpoint, Failure, Pool};
use super::body::WafBody;
use super::frame::Value;
use crate::rate_limit::forwarded_for;
use crate::{GrpcStatus, NoWaf, PeerAddr, grpc_response, is_grpc};

/// The message `coraza-spoa` reads.
const MESSAGE: &str = "coraza-req";
/// Room for the request line and headers in a frame, on top of the body.
pub const HEADROOM: usize = 16 * 1024;
/// Rule IDs kept as metric labels; the rest count as `other`.
const MAX_RULE_LABELS: usize = 256;

#[derive(Debug, Clone)]
pub struct WafConfig {
    /// `false` observes: the agent's verdict is logged and counted only.
    pub enforce: bool,
    pub endpoint: Endpoint,
    /// The `app` argument: the agent's rule set.
    pub app: String,
    /// Waiting for a connection plus the round trip.
    pub timeout: Duration,
    /// `true` forwards when the agent fails, in `enforce` too.
    pub fail_open: bool,
    /// Body bytes sent at most; `0` sends headers only.
    pub max_body: usize,
    /// Over `max_body` in `enforce`: `413`, or `false` to send without
    /// the body.
    pub reject_over_limit: bool,
    pub max_concurrent: usize,
    pub trusted: TrustedProxies,
    /// `dst-ip` and `dst-port`.
    pub listen: SocketAddr,
}

struct Live {
    cfg: WafConfig,
    pool: Arc<Pool>,
}

type Shared = Arc<RwLock<Option<Arc<Live>>>>;

/// The WAF in front of a service. Clones share the config and the pool.
#[derive(Clone, Default)]
pub struct WafLayer {
    shared: Shared,
}

impl WafLayer {
    /// `None` passes every request on untouched.
    pub fn new(cfg: Option<WafConfig>) -> Self {
        let l = Self::default();
        l.reload(cfg);
        l
    }

    /// Applies new keys; the pool and its connections stay when the
    /// endpoint, frame size and connection count do.
    pub fn reload(&self, cfg: Option<WafConfig>) {
        let mut cur = self.shared.write().unwrap_or_else(|e| e.into_inner());
        *cur = cfg.map(|cfg| {
            let pool = match &*cur {
                Some(old)
                    if old.cfg.endpoint == cfg.endpoint
                        && old.cfg.max_body == cfg.max_body
                        && old.cfg.max_concurrent == cfg.max_concurrent =>
                {
                    old.pool.clone()
                }
                _ => Arc::new(Pool::new(
                    cfg.endpoint.clone(),
                    (cfg.max_body + HEADROOM).try_into().unwrap_or(u32::MAX),
                    cfg.max_concurrent,
                )),
            };
            Arc::new(Live { cfg, pool })
        });
    }

    fn live(&self) -> Option<Arc<Live>> {
        self.shared
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl<S> Layer<S> for WafLayer {
    type Service = Waf<S>;

    fn layer(&self, inner: S) -> Waf<S> {
        Waf {
            inner,
            layer: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Waf<S> {
    inner: S,
    layer: WafLayer,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S, B, R> Service<Request<B>> for Waf<S>
where
    S: Service<Request<WafBody<B>>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send,
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    R: Default + Send + 'static,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Response<R>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let Some(live) = self.layer.live() else {
            return Box::pin(self.inner.call(req.map(WafBody::new)));
        };
        if req.extensions().get::<NoWaf>().is_some() {
            count("skipped");
            return Box::pin(self.inner.call(req.map(WafBody::new)));
        }
        // the clone that was made ready answers this call
        let ready = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, ready);
        Box::pin(inspect(live, inner, req))
    }
}

async fn inspect<S, B, R>(
    live: Arc<Live>,
    mut inner: S,
    req: Request<B>,
) -> Result<Response<R>, S::Error>
where
    S: Service<Request<WafBody<B>>, Response = Response<R>>,
    B: Body<Data = Bytes> + Unpin,
    R: Default,
{
    let cfg = &live.cfg;
    let (parts, body) = req.into_parts();
    let grpc = is_grpc(&parts.headers);
    let (mut head, mut data, mut rest) = (VecDeque::new(), Vec::new(), Some(body));
    let mut over = false;
    // gRPC streams may never end: headers only
    if let Some(b) = rest
        .as_mut()
        .filter(|b| cfg.max_body > 0 && !grpc && !b.is_end_stream())
    {
        over = b.size_hint().lower() > cfg.max_body as u64;
        while !over {
            match b.frame().await {
                None => {
                    rest = None;
                    break;
                }
                Some(Err(_)) => return Ok(local(StatusCode::BAD_REQUEST, grpc)),
                Some(Ok(f)) => {
                    if let Some(d) = f.data_ref() {
                        data.extend_from_slice(d);
                    }
                    head.push_back(f);
                    over = data.len() > cfg.max_body;
                }
            }
        }
    }
    if over {
        count("body_over_limit");
        // observe always forwards
        if cfg.reject_over_limit && cfg.enforce {
            return Ok(local(StatusCode::PAYLOAD_TOO_LARGE, grpc));
        }
        data.clear();
    }
    let client = client(cfg, &parts);
    let block = match ask(&live, &parts, client, &data).await {
        Ok(a) if a.action.is_some() => {
            log_match(&parts, client.0, &a, cfg.enforce);
            if let Some(r) = a.rule {
                count_rule(r);
            }
            count(if cfg.enforce { "block" } else { "would_block" });
            cfg.enforce.then(|| status(a.status))
        }
        Ok(_) => {
            count("pass");
            None
        }
        Err(f) => {
            metrics::counter!("dvarapala_waf_errors_total", "reason" => f.label()).increment(1);
            count("error");
            (cfg.enforce && !cfg.fail_open).then_some(StatusCode::SERVICE_UNAVAILABLE)
        }
    };
    if let Some(code) = block {
        return Ok(local(code, grpc));
    }
    inner
        .call(Request::from_parts(parts, WafBody::buffered(head, rest)))
        .await
}

/// The client address and port, `X-Forwarded-For` read from trusted
/// proxies only.
fn client(cfg: &WafConfig, p: &Parts) -> (IpAddr, u16) {
    let peer = p.extensions.get::<PeerAddr>().map(|a| a.0);
    let ip = peer.map_or(IpAddr::from([0, 0, 0, 0]), |a| {
        client_ip(a.ip(), forwarded_for(&p.headers).as_deref(), &cfg.trusted)
    });
    // the port belongs to the peer, not to a client behind it
    let port = peer.filter(|a| a.ip() == ip).map_or(0, |a| a.port());
    (ip.to_canonical(), port)
}

/// The `coraza-req` message for the request, bounded by `timeout`.
async fn ask(
    live: &Live,
    p: &Parts,
    (src, port): (IpAddr, u16),
    body: &[u8],
) -> Result<Answer, Failure> {
    let cfg = &live.cfg;
    let mut headers = Vec::with_capacity(1024);
    for (k, v) in &p.headers {
        headers.extend_from_slice(k.as_str().as_bytes());
        headers.extend_from_slice(b": ");
        headers.extend_from_slice(v.as_bytes());
        headers.extend_from_slice(b"\r\n");
    }
    let version = match p.version {
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "1.1",
    };
    let args = [
        ("app", Value::Str(cfg.app.as_bytes())),
        ("src-ip", Value::Ip(src)),
        ("src-port", Value::Uint32(port.into())),
        ("dst-ip", Value::Ip(cfg.listen.ip())),
        ("dst-port", Value::Uint32(cfg.listen.port().into())),
        ("method", Value::Str(p.method.as_str().as_bytes())),
        ("path", Value::Bin(p.uri.path().as_bytes())),
        ("query", Value::Bin(p.uri.query().unwrap_or("").as_bytes())),
        ("version", Value::Str(version.as_bytes())),
        ("headers", Value::Bin(&headers)),
        ("body", Value::Bin(body)),
        ("exportRuleIDs", Value::Bool(true)),
    ];
    let start = Instant::now();
    let out = tokio::time::timeout(cfg.timeout, live.pool.ask(MESSAGE, &args)).await;
    metrics::histogram!("dvarapala_waf_inspect_seconds").record(start.elapsed().as_secs_f64());
    out.unwrap_or(Err(Failure::Timeout))
}

/// The agent's status when it is an error status, `403` otherwise.
fn status(s: Option<i64>) -> StatusCode {
    s.and_then(|s| u16::try_from(s).ok())
        .and_then(|s| StatusCode::from_u16(s).ok())
        .filter(|s| s.is_client_error() || s.is_server_error())
        .unwrap_or(StatusCode::FORBIDDEN)
}

fn local<R: Default>(code: StatusCode, grpc: bool) -> Response<R> {
    if grpc {
        let g = if code == StatusCode::SERVICE_UNAVAILABLE {
            GrpcStatus::Unavailable
        } else {
            GrpcStatus::PermissionDenied
        };
        return grpc_response(g, None);
    }
    let mut res = Response::new(R::default());
    *res.status_mut() = code;
    if code == StatusCode::FORBIDDEN {
        res.headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    res
}

fn count(verdict: &'static str) {
    metrics::counter!("dvarapala_waf_requests_total", "verdict" => verdict).increment(1);
}

/// `dvarapala_waf_rule_matches_total{rule}`, the label set bounded.
fn count_rule(rule: i64) {
    static SEEN: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());
    let label = {
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(&rule) {
            rule.to_string()
        } else if seen.len() < MAX_RULE_LABELS {
            seen.push(rule);
            rule.to_string()
        } else {
            "other".to_owned()
        }
    };
    metrics::counter!("dvarapala_waf_rule_matches_total", "rule" => label).increment(1);
}

/// `msg="waf match"`, at most one line per client per second.
fn log_match(p: &Parts, client: IpAddr, a: &Answer, enforce: bool) {
    static LAST: std::sync::Mutex<(u64, Vec<IpAddr>)> = std::sync::Mutex::new((0, Vec::new()));
    let now = crate::unix_now();
    {
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        if last.0 != now {
            *last = (now, Vec::new());
        }
        // ponytail: linear scan, cleared every second; bounded so a
        // scanner on many addresses cannot grow it
        if last.1.contains(&client) || last.1.len() >= 1024 {
            return;
        }
        last.1.push(client);
    }
    tracing::warn!(
        msg = "waf match",
        rule = a.rule,
        rule_ids = a.rule_ids.as_deref().unwrap_or(""),
        anomaly_score = a.anomaly_score,
        id = a.id.as_deref().unwrap_or(""),
        %client,
        method = %p.method,
        path = p.uri.path(),
        mode = if enforce { "enforce" } else { "observe" },
    );
}
