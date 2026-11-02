//! An in-memory Kubernetes API for the tests: objects by path, every
//! request recorded, errors injected per method and path. Enough of the
//! API for what the operator calls: get, list with a label selector,
//! create, replace, delete, and patch (apply, merge, JSON patch, status).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use kube::Client;
use serde_json::{Value, json};

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Value>,
    errors: BTreeMap<(Method, String), u16>,
    log: Vec<String>,
}

#[derive(Clone, Default)]
pub struct Fake(Arc<Mutex<State>>);

impl Fake {
    pub fn client(&self) -> Client {
        let me = self.clone();
        let svc = tower::service_fn(move |req: Request<kube::client::Body>| {
            let me = me.clone();
            async move { Ok::<_, Infallible>(me.handle(req).await) }
        });
        Client::new(svc, "default")
    }

    pub fn put(&self, path: &str, obj: Value) {
        self.0.lock().unwrap().objects.insert(path.into(), obj);
    }

    pub fn get(&self, path: &str) -> Option<Value> {
        self.0.lock().unwrap().objects.get(path).cloned()
    }

    /// Answers `code` to every `method` request on `path` (no query).
    pub fn fail(&self, method: Method, path: &str, code: u16) {
        let mut s = self.0.lock().unwrap();
        s.errors.insert((method, path.into()), code);
    }

    /// Every request but the reads, as `METHOD path`.
    pub fn writes(&self) -> Vec<String> {
        let s = self.0.lock().unwrap();
        s.log
            .iter()
            .filter(|l| !l.starts_with("GET "))
            .cloned()
            .collect()
    }

    async fn handle(&self, req: Request<kube::client::Body>) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let query = req.uri().query().unwrap_or_default().to_owned();
        let ct = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = req.into_body().collect().await.map(|b| b.to_bytes());
        let input: Value = body
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let mut s = self.0.lock().unwrap();
        s.log.push(format!("{method} {path}"));
        if let Some(code) = s.errors.get(&(method.clone(), path.clone())) {
            return status(*code);
        }
        // the status subresource writes into its object
        let key = path.strip_suffix("/status").unwrap_or(&path).to_owned();
        match method {
            Method::GET => match s.objects.get(&path) {
                Some(o) => reply(StatusCode::OK, o),
                None if collection(&path) => {
                    let wanted = selector(&query);
                    let items: Vec<&Value> = s
                        .objects
                        .iter()
                        .filter(|(k, o)| {
                            k.rsplit_once('/').is_some_and(|(p, _)| p == path)
                                && wanted.iter().all(|(l, v)| {
                                    o.pointer(&format!("/metadata/labels/{}", l.replace('/', "~1")))
                                        .and_then(Value::as_str)
                                        == Some(v)
                                })
                        })
                        .map(|(_, o)| o)
                        .collect();
                    reply(
                        StatusCode::OK,
                        &json!({"apiVersion": "v1", "kind": "List", "metadata": {}, "items": items}),
                    )
                }
                None => status(404),
            },
            Method::POST => {
                let name = input["metadata"]["name"].as_str().unwrap_or_default();
                let k = format!("{path}/{name}");
                if s.objects.contains_key(&k) {
                    return status(409);
                }
                s.objects.insert(k, input.clone());
                reply(StatusCode::CREATED, &input)
            }
            Method::PUT => {
                if !s.objects.contains_key(&key) {
                    return status(404);
                }
                s.objects.insert(key, input.clone());
                reply(StatusCode::OK, &input)
            }
            Method::PATCH => {
                let apply = ct.contains("apply-patch");
                let Some(mut cur) = s.objects.get(&key).cloned().or(apply.then(|| json!({})))
                else {
                    return status(404);
                };
                if ct.contains("json-patch") {
                    let ops: json_patch::Patch = serde_json::from_value(input).unwrap();
                    if json_patch::patch(&mut cur, &ops.0).is_err() {
                        return status(422);
                    }
                } else {
                    json_patch::merge(&mut cur, &input);
                }
                s.objects.insert(key, cur.clone());
                reply(StatusCode::OK, &cur)
            }
            Method::DELETE => match s.objects.remove(&key) {
                Some(o) => reply(StatusCode::OK, &o),
                None => status(404),
            },
            _ => status(405),
        }
    }
}

/// Whether `path` names a collection: `/api/v1/<rest>` or
/// `/apis/<group>/<version>/<rest>`, `<rest>` being `<resource>` or
/// `namespaces/<ns>/<resource>`.
fn collection(path: &str) -> bool {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let rest = match parts.first() {
        Some(&"api") => &parts[2.min(parts.len())..],
        Some(&"apis") => &parts[3.min(parts.len())..],
        _ => return false,
    };
    match rest {
        ["namespaces", _, _] => true,
        [_] => true,
        _ => false,
    }
}

/// The `labelSelector` of `query` as `key=value` pairs.
fn selector(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|kv| kv.strip_prefix("labelSelector="))
        .flat_map(|v| decode(v).split(',').map(str::to_owned).collect::<Vec<_>>())
        .filter_map(|p| p.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect()
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn reply(code: StatusCode, v: &Value) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(v.to_string())));
    *r.status_mut() = code;
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    r
}

fn status(code: u16) -> Response<Full<Bytes>> {
    // kube matches on the reason, as the API server sends it
    let reason = match code {
        403 => "Forbidden",
        404 => "NotFound",
        409 => "AlreadyExists",
        _ => "InternalError",
    };
    let body = json!({
        "apiVersion": "v1", "kind": "Status", "metadata": {},
        "status": "Failure", "message": format!("fake {code}"), "code": code,
        "reason": reason
    });
    reply(StatusCode::from_u16(code).unwrap(), &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collections_and_selectors() {
        assert!(collection("/api/v1/namespaces"));
        assert!(!collection("/api/v1/namespaces/shop"));
        assert!(collection("/api/v1/namespaces/shop/services"));
        assert!(!collection("/api/v1/namespaces/shop/services/web"));
        assert!(collection("/apis/apps/v1/namespaces/shop/deployments"));
        assert!(!collection("/healthz"));
        assert_eq!(
            selector("labelSelector=app.kubernetes.io%2Fmanaged-by%3Ddvarapala-operator&x=1"),
            [(
                "app.kubernetes.io/managed-by".to_owned(),
                "dvarapala-operator".to_owned()
            )]
        );
    }
}
