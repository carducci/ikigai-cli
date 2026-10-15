//! What the socket-level tests of this crate share: start a door on an ephemeral port, send
//! raw bytes, and read the whole answer.
#![allow(dead_code)] // each test binary uses its own subset

use ikigai_core::Kernel;
use ikigai_web::{CapFn, EdgeConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Serve `kernel` under `config` and `cap_fn`; the address it answers on. The listener is
/// bound here, port 0, and handed to the server, so no port is picked and released.
pub async fn start(kernel: Arc<Kernel>, config: EdgeConfig, cap_fn: CapFn) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = ikigai_web::serve_with_listener(kernel, cap_fn, listener, config).await;
    });
    addr
}

/// Send `raw` and read to EOF.
pub async fn send(addr: SocketAddr, raw: &[u8]) -> String {
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

/// A response split into its head lines and its body.
pub fn split(resp: &str) -> (Vec<&str>, &str) {
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((resp, ""));
    (head.split("\r\n").collect(), body)
}

/// Every value of the header `name` (case-insensitive) in `resp`.
pub fn headers<'a>(resp: &'a str, name: &str) -> Vec<&'a str> {
    split(resp)
        .0
        .into_iter()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect()
}

/// The one value of the header `name`, or `None`; panics when it appears twice.
pub fn header<'a>(resp: &'a str, name: &str) -> Option<&'a str> {
    let all = headers(resp, name);
    assert!(
        all.len() <= 1,
        "`{name}` appears {} times: {resp}",
        all.len()
    );
    all.first().copied()
}
