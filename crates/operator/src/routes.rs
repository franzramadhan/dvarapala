//! Route rewrite: the backend Services of an `Ingress`, `HTTPRoute` or
//! `GRPCRoute`, pointed at their gateways or back at the originals. Pure,
//! on the route as JSON, so it reads attacker-shaped input without a panic.
#![allow(unused_variables, unused_imports, dead_code)]

use serde_json::{Map, Value};

use crate::gateway;

/// On a route: gateway Service name to original backend name.
pub const BACKENDS: &str = "dvarapala.franzramadhan.dev/backends";
/// The opt-in label, on a route or a namespace.
pub const LABEL: &str = "dvarapala.franzramadhan.dev/policy";
/// The label value that opts a route out.
pub const NONE: &str = "none";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ingress,
    HttpRoute,
    GrpcRoute,
}

impl Kind {
    pub fn from_kind(kind: &str) -> Option<Self> {
        todo!("rfc 0019")
    }
}

/// A backend Service and the port the route names, a number or a name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Backend {
    pub service: String,
    pub port: String,
}

/// The policy a route uses: its own label, else its namespace's; `none`
/// opts out.
pub fn policy<'a>(route: Option<&'a str>, namespace: Option<&'a str>) -> Option<&'a str> {
    todo!("rfc 0019")
}

/// The original backends of `route`, through the `backends` annotation.
pub fn backends(kind: Kind, route: &Value, ns: &str) -> Vec<Backend> {
    todo!("rfc 0019")
}

/// `route` with each backend pointed at its gateway under `policy` when
/// `exists` says that gateway's Service is there, else at the original.
/// Idempotent: a rewritten route gives itself back.
pub fn rewrite(
    kind: Kind,
    route: &Value,
    ns: &str,
    policy: Option<&str>,
    exists: &dyn Fn(&str) -> bool,
) -> Value {
    todo!("rfc 0019")
}

/// The `backends` annotation, or an empty map.
fn recorded(route: &Value) -> Map<String, Value> {
    todo!("rfc 0019")
}

fn record(route: &mut Value, used: Map<String, Value>) {
    todo!("rfc 0019")
}

/// Calls `f` with every backend reference of a Service in `ns` and its port.
fn visit(
    kind: Kind,
    route: &mut Value,
    ns: &str,
    f: &mut dyn FnMut(&mut Map<String, Value>, String),
) {
    todo!("rfc 0019")
}

fn ingress_ref(s: &mut Value, f: &mut dyn FnMut(&mut Map<String, Value>, String)) {
    todo!("rfc 0019")
}

#[cfg(test)]
#[path = "routes_tests.rs"]
mod tests;
