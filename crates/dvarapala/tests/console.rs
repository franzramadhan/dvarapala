//! RFC 0018 cases 8 to 15 and 17 against the running binary, with a mock
//! OIDC issuer on loopback.
#![cfg(all(unix, feature = "ui"))]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
mod stop;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

struct Proxy {
    child: Child,
    listen: u16,
    admin: u16,
    config: PathBuf,
    log: Arc<Mutex<String>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        stop::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.config);
    }
}

impl Proxy {
    /// Waits until the log has a line with every one of `parts`.
    fn logged(&self, parts: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let log = self.log.lock().unwrap().clone();
            if log.lines().any(|l| parts.iter().all(|p| l.contains(p))) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no line with {parts:?} in\n{log}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(name: &str, admin_extra: &str) -> Proxy {
    let (listen, admin) = (port(), port());
    let toml = format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         [metrics]\nlisten = \"\"\n[rate_limit]\nrate = 1000\nburst = 1000\n\
         [admin]\nlisten = \"127.0.0.1:{admin}\"\ntoken = \"{TOKEN}\"\n{}\n",
        admin_extra.replace("{admin}", &admin.to_string())
    );
    let config =
        std::env::temp_dir().join(format!("dvarapala-ui-{name}-{}.toml", std::process::id()));
    std::fs::write(&config, toml).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_dvarapala"))
        .args(["serve", "--config"])
        .arg(&config)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    let (out, l) = (child.stdout.take().unwrap(), log.clone());
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            l.lock().unwrap().push_str(&(line + "\n"));
        }
    });
    let p = Proxy {
        child,
        listen,
        admin,
        config,
        log,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", p.admin)).is_err() {
        assert!(Instant::now() < deadline, "admin listener did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    p
}

struct Answer {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

/// One request on a new connection; `headers` as `name: value` lines.
fn call(port: u16, method: &str, target: &str, headers: &[String]) -> Answer {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    write!(c, "{method} {target} HTTP/1.1\r\nHost: x\r\n{extra}\r\n").unwrap();
    let mut r = BufReader::new(c);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut headers = HashMap::new();
    loop {
        line.clear();
        r.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        let (k, v) = line.split_once(':').unwrap();
        headers.insert(k.to_ascii_lowercase(), v.trim().to_owned());
    }
    let len = headers
        .get("content-length")
        .map_or(0, |l| l.parse().unwrap());
    let mut body = vec![0; len];
    r.read_exact(&mut body).unwrap();
    Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn bearer() -> String {
    format!("Authorization: Bearer {TOKEN}")
}

/// The `name=value` part of a `Set-Cookie`.
fn session(a: &Answer) -> String {
    let c = &a.headers["set-cookie"];
    format!("Cookie: {}", c.split(';').next().unwrap())
}

/// A JSON string field, the simple way.
fn field(body: &str, name: &str) -> String {
    let at = body.find(&format!("\"{name}\":\"")).unwrap() + name.len() + 4;
    body[at..].split('"').next().unwrap().to_owned()
}

const UI: &str = "ui_enabled = true";

// case 8
#[test]
fn console_off_by_default() {
    let p = start("off", "");
    assert_eq!(call(p.admin, "GET", "/ui/", &[bearer()]).status, 404);
    assert_eq!(call(p.admin, "POST", "/session", &[bearer()]).status, 404);
    assert_eq!(call(p.admin, "GET", "/status", &[bearer()]).status, 200);
}

// case 9
#[test]
fn bundle_served_with_headers() {
    let p = start("bundle", UI);
    for path in ["/ui/", "/ui/blocks"] {
        let a = call(p.admin, "GET", path, &[]);
        assert_eq!(a.status, 200);
        assert!(a.headers["content-type"].starts_with("text/html"));
        assert_eq!(a.headers["content-encoding"], "gzip");
        assert!(a.headers["content-security-policy"].contains("frame-ancestors 'none'"));
    }
    let js = call(p.admin, "GET", "/ui/app.js", &[]);
    assert!(js.headers["content-type"].starts_with("text/javascript"));
    assert!(js.headers.contains_key("etag"));
    let methods = call(p.admin, "GET", "/session/methods", &[]);
    assert_eq!(methods.body, "{\"token\":true,\"oidc\":null}");
}

// cases 10, 11, 12
#[test]
fn token_session_csrf_and_logout() {
    let p = start("token", UI);
    let wrong = format!("Authorization: Bearer {}", "f".repeat(TOKEN.len()));
    let a = call(p.admin, "POST", "/session", &[wrong]);
    assert_eq!(a.status, 401);
    assert!(!a.headers.contains_key("set-cookie"));
    let a = call(p.admin, "POST", "/session", &[bearer()]);
    assert_eq!(a.status, 204);
    let set = &a.headers["set-cookie"];
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Lax"),
        "{set}"
    );
    assert!(!set.contains("Secure"), "plain http public_url: {set}");
    p.logged(&["admin login", "method=\"token\"", "result=\"ok\""]);
    let cookie = session(&a);
    assert_eq!(
        call(p.admin, "GET", "/status", std::slice::from_ref(&cookie)).status,
        200
    );
    let me = call(p.admin, "GET", "/session", std::slice::from_ref(&cookie));
    assert_eq!(field(&me.body, "method"), "token");
    let csrf = field(&me.body, "csrf");
    let block = "/blocks?cidr=192.0.2.0/24&ttl=10m";
    assert_eq!(
        call(p.admin, "POST", block, std::slice::from_ref(&cookie)).status,
        403
    );
    let bad = format!("X-Dvarapala-Csrf: {}", "0".repeat(64));
    assert_eq!(
        call(p.admin, "POST", block, &[cookie.clone(), bad]).status,
        403
    );
    let good = format!("X-Dvarapala-Csrf: {csrf}");
    assert_eq!(
        call(p.admin, "POST", block, &[cookie.clone(), good.clone()]).status,
        200
    );
    p.logged(&["admin action", "actor=\"token\"", "192.0.2.0"]);
    assert_eq!(
        call(p.admin, "DELETE", "/session", &[cookie.clone(), good]).status,
        204
    );
    assert_eq!(call(p.admin, "GET", "/status", &[cookie]).status, 401);
}

// case 17
#[test]
fn status_counts_requests() {
    let p = start("totals", "");
    let allowed = |p: &Proxy| {
        let body = call(p.admin, "GET", "/status", &[bearer()]).body;
        let at = body.find("\"allow\":").unwrap() + 8;
        body[at..]
            .split([',', '}'])
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    let before = allowed(&p);
    for _ in 0..3 {
        assert_eq!(call(p.listen, "GET", "/", &[]).status, 502);
    }
    assert_eq!(allowed(&p), before + 3);
}

/// A mock issuer: discovery, and a token endpoint answering an ID token
/// for the email and nonce the test sets.
struct Issuer {
    port: u16,
    claims: Arc<Mutex<(String, String)>>,
}

fn issuer() -> Issuer {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let claims = Arc::new(Mutex::new((String::new(), String::new())));
    let c = claims.clone();
    std::thread::spawn(move || {
        for s in l.incoming().map_while(Result::ok) {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let mut len = 0;
            let mut h = String::new();
            while r.read_line(&mut h).unwrap() > 2 {
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                h.clear();
            }
            let mut form = vec![0; len];
            r.read_exact(&mut form).unwrap();
            let iss = format!("http://127.0.0.1:{port}");
            let body = if line.starts_with("GET /.well-known/openid-configuration") {
                format!(
                    "{{\"issuer\":\"{iss}\",\"authorization_endpoint\":\"{iss}/auth\",\"token_endpoint\":\"{iss}/token\"}}"
                )
            } else {
                let form = String::from_utf8(form).unwrap();
                assert!(
                    form.contains("grant_type=authorization_code&code=the-code&"),
                    "{form}"
                );
                assert!(form.contains("code_verifier="), "{form}");
                let (email, nonce) = c.lock().unwrap().clone();
                let claims = format!(
                    "{{\"iss\":\"{iss}\",\"aud\":\"dvarapala\",\"exp\":4000000000,\"sub\":\"7\",\"email\":\"{email}\",\"email_verified\":true,\"nonce\":\"{nonce}\"}}"
                );
                format!("{{\"id_token\":\"e30.{}.sig\"}}", b64url(claims.as_bytes()))
            };
            let mut s = s;
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    Issuer { port, claims }
}

fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, x)| n | u32::from(*x) << (16 - 8 * i));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

fn oidc(i: &Issuer) -> String {
    format!(
        "{UI}\npublic_url = \"http://127.0.0.1:{{admin}}\"\n[admin.oidc]\nissuer = \"http://127.0.0.1:{}\"\n\
         client_id = \"dvarapala\"\nclient_secret = \"<secret>\"\nallow_emails = [\"ops@example.com\"]\nlabel = \"Dex\"\n",
        i.port
    )
}

/// Runs the flow for `email`; the callback's answer.
fn sign_in(p: &Proxy, i: &Issuer, email: &str) -> Answer {
    let start = call(p.admin, "GET", "/session/oidc", &[]);
    assert_eq!(start.status, 302, "{}", start.body);
    let url = &start.headers["location"];
    assert!(
        url.starts_with(&format!("http://127.0.0.1:{}/auth?", i.port)),
        "{url}"
    );
    let q: HashMap<_, _> = url
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();
    assert_eq!(q["code_challenge_method"], "S256");
    *i.claims.lock().unwrap() = (email.into(), q["nonce"].into());
    let back = format!("/session/oidc/callback?code=the-code&state={}", q["state"]);
    call(p.admin, "GET", &back, &[])
}

// cases 13, 15
#[test]
fn oidc_login_opens_a_session() {
    let i = issuer();
    let p = start("oidc", &oidc(&i));
    let m = call(p.admin, "GET", "/session/methods", &[]);
    assert_eq!(m.body, "{\"token\":true,\"oidc\":{\"label\":\"Dex\"}}");
    let a = sign_in(&p, &i, "ops@example.com");
    assert_eq!(a.status, 302);
    assert_eq!(a.headers["location"], "/ui/");
    p.logged(&[
        "admin login",
        "method=\"oidc\"",
        "ops@example.com",
        "result=\"ok\"",
    ]);
    let cookie = session(&a);
    let me = call(p.admin, "GET", "/session", std::slice::from_ref(&cookie));
    assert_eq!(field(&me.body, "subject"), "ops@example.com");
    let csrf = format!("X-Dvarapala-Csrf: {}", field(&me.body, "csrf"));
    let block = "/blocks?cidr=192.0.2.0/24";
    assert_eq!(call(p.admin, "POST", block, &[cookie, csrf]).status, 200);
    p.logged(&["admin action", "actor=\"ops@example.com\"", "POST /blocks"]);
}

// cases 6, 14
#[test]
fn oidc_denied_and_replayed() {
    let i = issuer();
    let p = start("denied", &oidc(&i));
    let a = sign_in(&p, &i, "intruder@example.com");
    assert_eq!(a.status, 303);
    assert!(
        a.headers["location"].starts_with("/ui/login?error="),
        "{:?}",
        a.headers
    );
    assert!(!a.headers.contains_key("set-cookie"));
    p.logged(&["admin login", "intruder@example.com", "result=\"denied\""]);
    let unknown = call(
        p.admin,
        "GET",
        "/session/oidc/callback?code=the-code&state=nope",
        &[],
    );
    assert_eq!(unknown.status, 303);
    assert!(!unknown.headers.contains_key("set-cookie"));
}
