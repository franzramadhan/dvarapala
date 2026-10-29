use super::*;

const ISS: &str = "https://idp.example";

fn cfg() -> OidcConfig {
    OidcConfig {
        issuer: ISS.into(),
        client_id: "dvarapala".into(),
        client_secret: "<secret>".into(),
        redirect_uri: "https://admin.example/session/oidc/callback".into(),
        scopes: vec!["openid".into(), "email".into()],
        allow_emails: vec!["ops@example.com".into()],
        allow_groups: vec![],
        groups_claim: "groups".into(),
        trust_email: false,
    }
}

fn jwt(claims: &str) -> String {
    format!("eyJhbGciOiJSUzI1NiJ9.{}.c2ln", b64url(claims.as_bytes()))
}

fn query(url: &str) -> HashMap<String, String> {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .map(|kv| kv.split_once('=').unwrap())
        .map(|(k, _)| (k.to_owned(), param(q, k).unwrap().unwrap()))
        .collect()
}

// RFC 0018 case 3
#[test]
fn authorization_url_with_pkce() {
    let p = Provider {
        authorization_endpoint: format!("{ISS}/auth"),
        token_endpoint: format!("{ISS}/token"),
    };
    let logins = Logins::default();
    let now = Instant::now();
    let a = query(&logins.begin(&cfg(), &p, now));
    let b = query(&logins.begin(&cfg(), &p, now));
    assert_eq!(a["response_type"], "code");
    assert_eq!(a["code_challenge_method"], "S256");
    assert_eq!(a["client_id"], "dvarapala");
    assert_eq!(a["scope"], "openid email");
    assert_eq!(a["redirect_uri"], cfg().redirect_uri);
    assert_ne!(a["state"], b["state"]);
    assert_ne!(a["nonce"], b["nonce"]);
    let pending = logins.take(&a["state"], now).unwrap();
    assert_eq!(pending.nonce, a["nonce"]);
    let challenge = b64url(digest(&SHA256, pending.verifier.as_bytes()).as_ref());
    assert_eq!(a["code_challenge"], challenge);
    assert_eq!(pending.verifier.len(), 43);
}

// RFC 0018 case 4
#[test]
fn claims_are_checked() {
    let ok = r#"{"iss":"https://idp.example","aud":"dvarapala","exp":2000,"nonce":"n","sub":"1","email":"Ops@example.com","email_verified":true}"#;
    assert_eq!(
        check(&cfg(), &jwt(ok), "n", 1000),
        Ok("Ops@example.com".into())
    );
    let with = |from: &str, to: &str| jwt(&ok.replace(from, to));
    let reason = |t: String, now| match check(&cfg(), &t, "n", now) {
        Err(Denied::Invalid(r)) => r,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        reason(with("idp.example", "evil.example"), 1000),
        "iss mismatch"
    );
    assert_eq!(
        reason(with(r#""aud":"dvarapala""#, r#""aud":"other""#), 1000),
        "aud mismatch"
    );
    assert_eq!(reason(jwt(ok), 2000), "expired");
    assert_eq!(
        reason(with(r#""nonce":"n""#, r#""nonce":"m""#), 1000),
        "nonce mismatch"
    );
    assert_eq!(
        check(&cfg(), &with("true", "false"), "n", 1000),
        Err(Denied::NotAllowed("Ops@example.com".into()))
    );
    let aud_list = with(r#""aud":"dvarapala""#, r#""aud":["x","dvarapala"]"#);
    assert!(check(&cfg(), &aud_list, "n", 1000).is_ok());
    assert_eq!(reason("a.b".into(), 1000), "id_token is not a JWT");
    assert_eq!(
        reason("a.!!.c".into(), 1000),
        "id_token payload is not base64url"
    );
}

// RFC 0018 case 5
#[test]
fn groups_rule() {
    let c = OidcConfig {
        allow_emails: vec![],
        allow_groups: vec!["sre".into()],
        groups_claim: "roles".into(),
        ..cfg()
    };
    let t = |roles: &str| {
        jwt(&format!(
            r#"{{"iss":"{ISS}","aud":"dvarapala","exp":2000,"nonce":"n","sub":"42"{roles}}}"#
        ))
    };
    assert_eq!(
        check(&c, &t(r#","roles":["sre"]"#), "n", 1),
        Ok("42".into())
    );
    assert_eq!(check(&c, &t(r#","roles":"sre""#), "n", 1), Ok("42".into()));
    let denied = Err(Denied::NotAllowed("42".into()));
    assert_eq!(check(&c, &t(r#","roles":["dev"]"#), "n", 1), denied);
    assert_eq!(check(&c, &t(""), "n", 1), denied);
}

// RFC 0018 case 6
#[test]
fn state_is_single_use_and_expires() {
    let p = Provider {
        authorization_endpoint: format!("{ISS}/auth?x=1"),
        token_endpoint: format!("{ISS}/token"),
    };
    let logins = Logins::default();
    let now = Instant::now();
    let url = logins.begin(&cfg(), &p, now);
    assert!(url.starts_with("https://idp.example/auth?x=1&response_type=code"));
    let state = query(&url)["state"].clone();
    assert_eq!(logins.take("unknown", now), None);
    assert!(logins.take(&state, now).is_some());
    assert_eq!(logins.take(&state, now), None, "used twice");
    let old = query(&logins.begin(&cfg(), &p, now))["state"].clone();
    assert_eq!(logins.take(&old, now + PENDING_TTL), None, "too old");
    for _ in 0..MAX_PENDING + 5 {
        logins.begin(&cfg(), &p, now);
    }
    assert_eq!(logins.lock().len(), MAX_PENDING);
}

#[test]
fn callback_and_token_answer() {
    assert_eq!(
        callback(Some("code=a%2Fb&state=s")),
        Ok(("a/b".into(), "s".into()))
    );
    assert!(matches!(callback(Some("state=s")), Err(Denied::Invalid(_))));
    assert_eq!(
        callback(Some("error=access_denied&error_description=no%20way")),
        Err(Denied::Invalid("issuer: access_denied: no way".into()))
    );
    assert_eq!(id_token(br#"{"id_token":"x.y.z"}"#), Ok("x.y.z".into()));
    assert!(id_token(b"{}").is_err());
    let body = token_request(&cfg(), "c&d", "v");
    assert!(body.contains("code=c%26d&"));
    assert!(body.contains("client_secret=%3Csecret%3E"));
    assert!(body.ends_with("code_verifier=v"));
}

#[test]
fn discovery_and_urls() {
    let doc = br#"{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/a","token_endpoint":"https://idp.example/t"}"#;
    assert_eq!(
        provider(doc, ISS).unwrap().token_endpoint,
        "https://idp.example/t"
    );
    assert!(provider(doc, "https://other.example").is_err());
    let plain =
        String::from_utf8_lossy(doc).replace("https://idp.example/t", "http://idp.example/t");
    assert!(provider(plain.as_bytes(), ISS).is_err());
    assert_eq!(
        discovery_url("https://idp.example/"),
        "https://idp.example/.well-known/openid-configuration"
    );
    for ok in [
        "https://x",
        "http://localhost:8080/cb",
        "http://127.0.0.1",
        "http://[::1]:9/",
    ] {
        assert!(secure_url(ok), "{ok}");
    }
    for no in [
        "http://example.com",
        "http://127.0.0.1:1@evil.example/",
        "ftp://localhost",
        "http://localhost.evil",
    ] {
        assert!(!secure_url(no), "{no}");
    }
    for s in [&b""[..], b"f", b"fo", b"foo", b"foob", b"\xff\x00"] {
        assert_eq!(b64url_decode(&b64url(s)).unwrap(), s);
    }
    assert_eq!(b64url(b"\xfb\xff"), "-_8");
}

// RFC 0020 cases 1 to 5
#[test]
fn trusted_email_without_the_claim() {
    let base = r#"{"iss":"https://idp.example","aud":"dvarapala","exp":2000,"nonce":"n","sub":"1","email":"Ops@example.com""#;
    let token = |extra: &str| jwt(&format!("{base}{extra}}}"));
    let trusting = OidcConfig {
        trust_email: true,
        ..cfg()
    };
    assert_eq!(
        check(&trusting, &token(""), "n", 1000),
        Ok("Ops@example.com".into())
    );
    for extra in [r#","email_verified":false"#, r#","email_verified":"false""#] {
        assert_eq!(
            check(&trusting, &token(extra), "n", 1000),
            Err(Denied::NotAllowed("Ops@example.com".into())),
            "{extra}"
        );
    }
    assert_eq!(
        check(&cfg(), &token(""), "n", 1000),
        Err(Denied::NotAllowed("Ops@example.com".into()))
    );
    let other = OidcConfig {
        allow_emails: vec!["dev@example.com".into()],
        ..trusting
    };
    assert_eq!(
        check(&other, &token(""), "n", 1000),
        Err(Denied::NotAllowed("Ops@example.com".into()))
    );
}
