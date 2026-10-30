//! Route rewrite: the backend Services of an `Ingress`, `HTTPRoute` or
//! `GRPCRoute`, pointed at their gateways or back at the originals. Pure,
//! on the route as JSON, so it reads attacker-shaped input without a panic.

use serde_json::{Map, Value};

use crate::gateway;

/// On a route: gateway Service name to original backend name.
pub const BACKENDS: &str = "dvarapala.franzramadhan.dev/backends";
/// The opt-in label, on a route or a namespace.
pub const LABEL: &str = "dvarapala.franzramadhan.dev/policy";
/// The label value that opts a route out.
pub const NONE: &str = "none";
/// RFC 0025: on a route, the rules that opt in: rule names of an
/// `HTTPRoute` or `GRPCRoute`, path values of an `Ingress`, comma separated.
pub const RULES: &str = "dvarapala.franzramadhan.dev/rules";
/// Entries of [`RULES`] read at most, each at most [`MAX_RULE`] bytes.
pub const MAX_RULES: usize = 64;
pub const MAX_RULE: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ingress,
    HttpRoute,
    GrpcRoute,
}

impl Kind {
    pub fn from_kind(kind: &str) -> Option<Self> {
        match kind {
            "Ingress" => Some(Self::Ingress),
            "HTTPRoute" => Some(Self::HttpRoute),
            "GRPCRoute" => Some(Self::GrpcRoute),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Ingress => "Ingress",
            Self::HttpRoute => "HTTPRoute",
            Self::GrpcRoute => "GRPCRoute",
        }
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
    route.or(namespace).filter(|p| *p != NONE && !p.is_empty())
}

/// The original backends of `route`, through the `backends` annotation.
pub fn backends(kind: Kind, route: &Value, ns: &str) -> Vec<Backend> {
    let originals = recorded(route);
    let mut out = Vec::new();
    let mut r = route.clone();
    visit(kind, &mut r, ns, &mut |m, port, selected| {
        if !selected {
            return;
        }
        let name = m.get("name").and_then(Value::as_str).unwrap_or_default();
        let service = originals.get(name).and_then(Value::as_str).unwrap_or(name);
        out.push(Backend {
            service: service.into(),
            port,
        });
    });
    out.sort();
    out.dedup();
    out
}

/// `route` with each backend pointed at its gateway under `policy` when
/// `exists` says that gateway's Service is there, else at the original.
/// With [`RULES`], backends of other rules point at the originals.
/// Idempotent: a rewritten route gives itself back.
pub fn rewrite(
    kind: Kind,
    route: &Value,
    ns: &str,
    policy: Option<&str>,
    exists: &dyn Fn(&str) -> bool,
) -> Value {
    let originals = recorded(route);
    let mut used = Map::new();
    let mut out = route.clone();
    visit(kind, &mut out, ns, &mut |m, port, selected| {
        let name = m.get("name").and_then(Value::as_str).unwrap_or_default();
        let service = originals
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_owned();
        let target = policy
            .filter(|_| selected)
            .map(|p| gateway::name(&service, &port, p))
            .filter(|g| exists(g));
        let target = match target {
            Some(g) => {
                used.insert(g.clone(), service.into());
                g
            }
            None => service,
        };
        m.insert("name".into(), target.into());
    });
    record(&mut out, used);
    out
}

/// The entries of [`RULES`] that name no rule of `route`.
pub fn unknown_rules(kind: Kind, route: &Value) -> Vec<String> {
    let Some(wanted) = wanted(route) else {
        return Vec::new();
    };
    let have: Vec<&str> = match kind {
        Kind::Ingress => route
            .pointer("/spec/rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| r.pointer("/http/paths").and_then(Value::as_array))
            .flatten()
            .filter_map(|p| p.get("path").and_then(Value::as_str))
            .collect(),
        Kind::HttpRoute | Kind::GrpcRoute => route
            .pointer("/spec/rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| r.get("name").and_then(Value::as_str))
            .collect(),
    };
    wanted
        .into_iter()
        .filter(|w| !have.contains(&w.as_str()))
        .collect()
}

/// The [`RULES`] entries, `None` without the annotation (all rules).
fn wanted(route: &Value) -> Option<Vec<String>> {
    let s = route
        .pointer("/metadata/annotations")?
        .get(RULES)?
        .as_str()?;
    Some(
        s.split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty() && e.len() <= MAX_RULE)
            .take(MAX_RULES)
            .map(str::to_owned)
            .collect(),
    )
}

/// The `backends` annotation, or an empty map.
fn recorded(route: &Value) -> Map<String, Value> {
    route
        .pointer("/metadata/annotations")
        .and_then(|a| a.get(BACKENDS))
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

fn record(route: &mut Value, used: Map<String, Value>) {
    let Some(meta) = route.get_mut("metadata").and_then(Value::as_object_mut) else {
        return;
    };
    let annotations = meta
        .entry("annotations")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(a) = annotations.as_object_mut() else {
        return;
    };
    if used.is_empty() {
        a.remove(BACKENDS);
    } else {
        a.insert(BACKENDS.into(), Value::Object(used).to_string().into());
    }
    if a.is_empty() {
        meta.remove("annotations");
    }
}

/// What `visit` calls: a backend reference, its port, and whether its
/// rule opts in.
type Visit<'a> = dyn FnMut(&mut Map<String, Value>, String, bool) + 'a;

/// Calls `f` with every backend reference of a Service in `ns` and its port.
fn visit(kind: Kind, route: &mut Value, ns: &str, f: &mut Visit) {
    let wanted = wanted(route);
    let picked = |v: Option<&Value>| {
        wanted.as_ref().is_none_or(|w| {
            v.and_then(Value::as_str)
                .is_some_and(|s| w.iter().any(|x| x == s))
        })
    };
    let Some(spec) = route.get_mut("spec") else {
        return;
    };
    match kind {
        Kind::Ingress => {
            let all = wanted.is_none();
            if let Some(s) = spec.pointer_mut("/defaultBackend/service") {
                ingress_ref(s, all, f);
            }
            for rule in array(spec.get_mut("rules")) {
                for path in array(rule.pointer_mut("/http/paths")) {
                    let selected = picked(path.get("path"));
                    if let Some(s) = path.pointer_mut("/backend/service") {
                        ingress_ref(s, selected, f);
                    }
                }
            }
        }
        Kind::HttpRoute | Kind::GrpcRoute => {
            for rule in array(spec.get_mut("rules")) {
                let selected = picked(rule.get("name"));
                for r in array(rule.get_mut("backendRefs")) {
                    let Some(m) = r.as_object_mut() else { continue };
                    let is = |k: &str, ok: &[&str]| {
                        m.get(k)
                            .is_none_or(|v| v.as_str().is_some_and(|s| ok.contains(&s)))
                    };
                    let ours =
                        is("group", &[""]) && is("kind", &["Service"]) && is("namespace", &[ns]);
                    let port = m.get("port").and_then(Value::as_i64);
                    let named = m.get("name").is_some_and(Value::is_string);
                    if let (true, true, Some(port)) = (ours, named, port) {
                        f(m, port.to_string(), selected);
                    }
                }
            }
        }
    }
}

fn ingress_ref(s: &mut Value, selected: bool, f: &mut Visit) {
    let Some(m) = s.as_object_mut() else { return };
    let port = m.get("port").and_then(|p| {
        p.get("number")
            .and_then(Value::as_i64)
            .map(|n| n.to_string())
            .or_else(|| p.get("name").and_then(Value::as_str).map(str::to_owned))
    });
    let named = m.get("name").is_some_and(Value::is_string);
    if let (Some(port), true) = (port, named) {
        f(m, port, selected);
    }
}

fn array(v: Option<&mut Value>) -> impl Iterator<Item = &mut Value> {
    v.and_then(Value::as_array_mut).into_iter().flatten()
}

#[cfg(test)]
#[path = "routes_tests.rs"]
mod tests;
