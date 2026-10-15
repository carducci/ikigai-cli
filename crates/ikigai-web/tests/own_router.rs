//! A door with its own router writes with `write_response` (ledger #1593): every header it
//! sets passes the checks an endpoint's do (ledger #117), the framing headers stay the
//! writer's, and a HEAD is answered with the head alone.

use ikigai_web::{write_answer, write_response, EdgeConfig, HeaderRefusal, Response};
use tokio::io::AsyncReadExt;

/// Write `response` the way `write` does and read back everything that reached the client.
async fn written<F, Fut>(write: F) -> (std::io::Result<()>, String)
where
    F: FnOnce(tokio::io::DuplexStream) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let result = write(server).await;
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    (result, String::from_utf8_lossy(&out).into_owned())
}

async fn write_one(response: Response) -> (std::io::Result<()>, String) {
    written(|mut server| async move {
        write_response(&mut server, response, &EdgeConfig::default()).await
    })
    .await
}

/// The refusal an `Err` from the writer carries.
fn refusal(result: std::io::Result<()>) -> HeaderRefusal {
    let err = result.expect_err("the writer must refuse");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
    err.into_inner()
        .expect("an inner error")
        .downcast::<HeaderRefusal>()
        .map(|b| *b)
        .expect("the inner error is the HeaderRefusal")
}

#[tokio::test]
async fn a_header_value_that_would_start_a_header_of_its_own_is_refused_and_nothing_is_written() {
    for value in [
        "a=b\r\nSet-Cookie: stolen=1",
        "a=b\nLocation: /evil",
        "a=b\rX: y",
        "nul\0byte",
    ] {
        let response =
            Response::new(200, "text/plain", b"hi".to_vec()).with_header("X-Note", value);
        assert!(response.check().is_err(), "{value:?}");
        let (result, wire) = write_one(response).await;
        assert_eq!(refusal(result).header, "X-Note", "{value:?}");
        assert!(wire.is_empty(), "nothing reaches the client: {wire:?}");
    }
    // The content type is a header value too.
    let (result, wire) = write_one(Response::new(
        200,
        "text/plain\r\nSet-Cookie: stolen=1",
        b"hi".to_vec(),
    ))
    .await;
    assert_eq!(refusal(result).header, "Content-Type");
    assert!(wire.is_empty(), "{wire:?}");
    // So is a value past the bound an endpoint's is held to.
    let long = "x".repeat(ikigai_web::MAX_HEADER_VALUE + 1);
    let (result, _) =
        write_one(Response::new(200, "text/plain", Vec::new()).with_header("X-Long", &long)).await;
    assert_eq!(refusal(result).header, "X-Long");
}

#[tokio::test]
async fn a_malformed_header_name_is_refused() {
    for name in ["", "Bad Name", "X:Y", "X\r\nY", "Caf\u{e9}"] {
        let response = Response::new(200, "text/plain", Vec::new()).with_header(name, "v");
        let (result, wire) = write_one(response).await;
        assert_eq!(refusal(result).header, name, "{name:?}");
        assert!(wire.is_empty(), "{wire:?}");
    }
}

#[tokio::test]
async fn the_framing_headers_are_the_writers_and_refused_from_the_caller() {
    for name in [
        "Content-Length",
        "content-length",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
        "Proxy-Connection",
        "TE",
        "Trailer",
        "Upgrade",
        "Content-Type",
    ] {
        let response = Response::new(200, "text/plain", b"hi".to_vec()).with_header(name, "x");
        let (result, wire) = write_one(response).await;
        assert_eq!(refusal(result).header, name, "{name}");
        assert!(wire.is_empty(), "{name}: {wire:?}");
    }
}

#[tokio::test]
async fn a_doors_own_headers_are_written_as_given() {
    let response = Response::new(405, "application/json", b"{}".to_vec())
        .with_header("Allow", "GET, HEAD")
        .with_header("WWW-Authenticate", "Bearer realm=\"layers\"")
        .with_header("Cache-Control", "no-store");
    assert_eq!(response.check(), Ok(()));
    let (result, wire) = write_one(response).await;
    result.unwrap();
    assert!(
        wire.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
        "{wire}"
    );
    assert!(wire.contains("\r\nAllow: GET, HEAD\r\n"), "{wire}");
    assert!(
        wire.contains("\r\nWWW-Authenticate: Bearer realm=\"layers\"\r\n"),
        "{wire}"
    );
    assert!(wire.contains("\r\nContent-Length: 2\r\n"), "{wire}");
    assert!(wire.ends_with("\r\n\r\n{}"), "{wire}");
}

#[tokio::test]
async fn an_answer_to_head_is_the_head_alone_with_gets_length() {
    let answer = || Response::new(200, "application/json", br#"{"ok":true}"#.to_vec());
    let (result, get) = written(|mut server| async move {
        write_answer(&mut server, "GET", answer(), &EdgeConfig::default()).await
    })
    .await;
    result.unwrap();
    let (result, head) = written(|mut server| async move {
        write_answer(&mut server, "HEAD", answer(), &EdgeConfig::default()).await
    })
    .await;
    result.unwrap();
    assert!(get.ends_with(r#"{"ok":true}"#), "{get}");
    assert!(
        head.ends_with("\r\n\r\n"),
        "no content after the head: {head:?}"
    );
    assert!(
        head.contains("\r\nContent-Length: 11\r\n"),
        "GET's length: {head}"
    );
    assert_eq!(
        head,
        get.strip_suffix(r#"{"ok":true}"#).unwrap(),
        "HEAD is GET's head, byte for byte"
    );
    // A refusal to HEAD carries no content either.
    let (result, refused) = written(|mut server| async move {
        let refusal = Response::new(401, "application/json", br#"{"kind":"denied"}"#.to_vec());
        write_answer(&mut server, "HEAD", refusal, &EdgeConfig::default()).await
    })
    .await;
    result.unwrap();
    assert!(refused.starts_with("HTTP/1.1 401 "), "{refused}");
    assert!(refused.ends_with("\r\n\r\n"), "{refused:?}");
    // And the header checks hold on this path too.
    let (result, wire) = written(|mut server| async move {
        let bad = Response::new(200, "text/plain", Vec::new()).with_header("X", "a\r\nB: c");
        write_answer(&mut server, "HEAD", bad, &EdgeConfig::default()).await
    })
    .await;
    assert_eq!(refusal(result).header, "X");
    assert!(wire.is_empty(), "{wire:?}");
}
