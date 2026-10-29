//! RFC 0017 case 13: the client's overhead against a fake agent that
//! answers at once, for a GET with 10 headers and a 16 KiB form POST.
//! With `DVARAPALA_TEST_CORAZA` (`host:port`), the same end to end
//! through `coraza-spoa` and its CRS.

#[path = "../tests/fake_agent/mod.rs"]
#[allow(dead_code)]
mod fake_agent;

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use dvarapala_engine::TrustedProxies;
use dvarapala_l7::{Endpoint, PeerAddr, WafBody, WafConfig, WafLayer};
use fake_agent::{Behavior, Reply};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, ServiceExt, service_fn};

fn request(method: &str, body: Bytes) -> Request<Full<Bytes>> {
    let mut r = Request::builder()
        .method(method)
        .uri("/search?q=shoes&page=2")
        .header("host", "app.example");
    for i in 0..9 {
        r = r.header(format!("x-h{i}"), "value-of-a-typical-length");
    }
    if !body.is_empty() {
        r = r
            .header("content-type", "application/x-www-form-urlencoded")
            .header("content-length", body.len());
    }
    let mut r = r.body(Full::new(body)).unwrap();
    r.extensions_mut()
        .insert(PeerAddr("192.0.2.7:50000".parse().unwrap()));
    r
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (agent, seen) = rt.block_on(fake_agent::spawn(Behavior::reply(Reply::Pass)));
    let mut agents = vec![("waf", agent.to_string())];
    if let Ok(a) = std::env::var("DVARAPALA_TEST_CORAZA") {
        agents.push(("coraza", a));
    }
    // 16 KiB of short fields, as a form sends them
    let mut form = String::new();
    for i in 0.. {
        let f = format!("field{i}=some+typed+text+{i}&");
        if form.len() + f.len() > 16 * 1024 {
            break;
        }
        form.push_str(&f);
    }
    let form = Bytes::from(form);
    for (agent, endpoint) in agents {
        let layer = WafLayer::new(Some(WafConfig {
            enforce: true,
            endpoint: Endpoint::Tcp(endpoint),
            app: "default".into(),
            timeout: Duration::from_secs(5),
            fail_open: false,
            max_body: 16 * 1024,
            reject_over_limit: true,
            max_concurrent: 4,
            trusted: TrustedProxies::default(),
            listen: "192.0.2.1:443".parse().unwrap(),
        }));
        let svc = layer.layer(service_fn(|_: Request<WafBody<Full<Bytes>>>| async {
            Ok::<_, Infallible>(Response::new(Full::<Bytes>::default()))
        }));
        for (name, method, body) in [
            ("get_10_headers", "GET", Bytes::new()),
            ("post_16k_form", "POST", form.clone()),
        ] {
            c.bench_function(&format!("{agent}_{name}"), |b| {
                b.iter_batched(
                    // the fake agent keeps every message: drop them untimed
                    || seen.messages.lock().unwrap().clear(),
                    |()| {
                        let r = rt.block_on(svc.clone().oneshot(request(method, body.clone())));
                        assert_eq!(r.unwrap().status(), StatusCode::OK, "{agent}_{name}");
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
