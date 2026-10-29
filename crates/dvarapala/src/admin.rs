//! The RFC 0014 admin API on its own listener: JSON over HTTP/1.1, every
//! call behind the bearer token.
#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]

use std::convert::Infallible;
use std::fmt::Write;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dvarapala_l7::{Call, RateLimitLayer, authorized, parse_admin};
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, WWW_AUTHENTICATE};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::config::parse_duration;
use crate::reload::{Outcome, Reloader};

/// Open admin connections at most; one request each.
const MAX_CONNS: usize = 16;

pub struct Admin {
    pub token: String,
    pub max_block_ttl: Duration,
    /// `None` when the reverse proxy's rate limiter is off.
    pub layer: Option<RateLimitLayer>,
    pub reloader: Arc<Reloader>,
    /// `reverse` or `forward`
    pub mode: &'static str,
}

/// Binds `addr` and serves the admin API until the process exits.
pub async fn serve(addr: SocketAddr, admin: Admin) -> io::Result<()> {
    todo!("rfc 0014")
}

impl Admin {
    fn answer<B>(&self, req: &Request<B>) -> Response<Full<Bytes>> {
        todo!("rfc 0014")
    }

    fn call(&self, call: Call) -> Response<Full<Bytes>> {
        todo!("rfc 0014")
    }

    fn status(&self, l: Option<&RateLimitLayer>) -> String {
        todo!("rfc 0014")
    }
}

fn outcome(o: &Outcome) -> String {
    todo!("rfc 0014")
}

fn error(msg: &str) -> String {
    todo!("rfc 0014")
}

/// `s` as a JSON string.
fn string(s: &str) -> String {
    todo!("rfc 0014")
}

fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    todo!("rfc 0014")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "rfc 0014"]
    fn json_strings() {
        assert_eq!(string("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }
}
