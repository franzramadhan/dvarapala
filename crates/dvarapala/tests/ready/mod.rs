//! Ports and readiness for a spawned binary's listeners.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

/// A free port, never the same one twice in this process: tests run in
/// parallel, and the kernel hands a port just released by `bind` to the
/// next `bind`, so two proxies could be told the same port.
pub fn port() -> u16 {
    static USED: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    loop {
        let p = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut used = USED.lock().unwrap();
        if !used.contains(&p) {
            used.push(p);
            return p;
        }
    }
}

/// `port` answers an HTTP request (any status). A bare `connect` is not
/// enough: on Linux a connect to a free ephemeral port can connect the
/// socket to itself before the binary binds it.
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
