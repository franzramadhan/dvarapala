//! RFC 0030 case 11: behind one balancer, the rate limiter keys on the
//! client each PROXY protocol header carries.
#![cfg(unix)]

#[allow(dead_code)]
mod proc;
mod stop;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use proc::{port, serve, wait_port};

/// One request from `client`, through a v1 header: the status code.
fn get_as(listen: u16, client: &str) -> u16 {
    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!(
        "PROXY TCP4 {client} 198.51.100.1 4000 443\r\nGET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut res = String::new();
    let _ = s.read_to_string(&mut res);
    res.get(9..12)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status: {res:?}"))
}

#[test]
#[ignore = "rfc 0030"]
fn rate_limit_keys_on_the_carried_client() {
    let listen = port();
    let toml = format!(
        "listen = \"127.0.0.1:{listen}\"\nupstream = \"http://127.0.0.1:1\"\n\
         [metrics]\nlisten = \"\"\n\
         [rate_limit]\nrate = 1\nburst = 1\n\
         [l4]\nproxy_protocol = \"v1\"\nproxy_protocol_from = [\"127.0.0.0/8\"]\n"
    );
    let p = serve("proxy-protocol", Some(&toml), &[]);
    p.logged(&["proxy listening"]);
    wait_port(listen);
    // the upstream refuses connections: 502 means the limiter let it by
    assert_eq!(get_as(listen, "192.0.2.10"), 502);
    assert_eq!(get_as(listen, "192.0.2.10"), 429);
    assert_eq!(get_as(listen, "192.0.2.11"), 502);
}
