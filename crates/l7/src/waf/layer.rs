//! RFC 0017: the WAF stage. Buffers the body up to `max_body`, asks the
//! agent, then forwards, answers its status or fails closed.
#![allow(unused_variables, unused_imports, dead_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::TrustedProxies;
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
        todo!("rfc 0017")
    }

    /// Applies new keys; the pool and its connections stay when the
    /// endpoint, frame size and connection count do.
    pub fn reload(&self, cfg: Option<WafConfig>) {
        todo!("rfc 0017")
    }

    fn live(&self) -> Option<Arc<Live>> {
        todo!("rfc 0017")
    }
}

impl<S> Layer<S> for WafLayer {
    type Service = Waf<S>;

    fn layer(&self, inner: S) -> Waf<S> {
        todo!("rfc 0017")
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
        todo!("rfc 0017")
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        todo!("rfc 0017")
    }
}

async fn inspect<S, B, R>(
    live: Arc<Live>,
    inner: S,
    req: Request<B>,
) -> Result<Response<R>, S::Error>
where
    S: Service<Request<WafBody<B>>, Response = Response<R>>,
    B: Body<Data = Bytes> + Unpin,
    R: Default,
{
    todo!("rfc 0017")
}

/// The client address and port, `X-Forwarded-For` read from trusted
/// proxies only.
fn client(cfg: &WafConfig, p: &Parts) -> (IpAddr, u16) {
    todo!("rfc 0017")
}

/// The `coraza-req` message for the request, bounded by `timeout`.
async fn ask(
    live: &Live,
    p: &Parts,
    (src, port): (IpAddr, u16),
    body: &[u8],
) -> Result<Answer, Failure> {
    todo!("rfc 0017")
}

/// The agent's status when it is an error status, `403` otherwise.
fn status(s: Option<i64>) -> StatusCode {
    todo!("rfc 0017")
}

fn local<R: Default>(code: StatusCode, grpc: bool) -> Response<R> {
    todo!("rfc 0017")
}

fn count(verdict: &'static str) {
    todo!("rfc 0017")
}

/// `dvarapala_waf_rule_matches_total{rule}`, the label set bounded.
fn count_rule(rule: i64) {
    todo!("rfc 0017")
}

/// `msg="waf match"`, at most one line per client per second.
fn log_match(p: &Parts, client: IpAddr, a: &Answer, enforce: bool) {
    todo!("rfc 0017")
}
