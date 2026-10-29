//! Readiness of a spawned binary's listener. A bare `connect` is not
//! enough: on Linux a connect to a free ephemeral port can connect the
//! socket to itself before the binary binds it.

use std::io::{Read, Write};
use std::net::TcpStream;

/// `port` answers an HTTP request (any status).
pub fn answers(port: u16) -> bool {
    let probe = || -> std::io::Result<bool> {
        let mut c = TcpStream::connect(("127.0.0.1", port))?;
        c.write_all(b"GET /ready HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")?;
        let mut head = [0; 9];
        c.read_exact(&mut head)?;
        Ok(&head == b"HTTP/1.1 ")
    };
    probe().unwrap_or(false)
}
