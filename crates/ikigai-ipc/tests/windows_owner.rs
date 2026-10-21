//! The Windows owner channel, end to end.
//!
//! `the_owner_reaches_the_door` is the same-account round trip. The refusal of a DIFFERENT
//! account cannot be shown by one account alone, so `another_account_is_refused_live` is an
//! `#[ignore]` test two accounts run together (its doc comment says how); the decision itself
//! (SID compare, the refusal naming the account) and the socket file's DACL are unit-tested in
//! `src/windows.rs` with injected SIDs.
#![cfg(windows)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ikigai_core::{builtins, ArgRef, EndpointSpace, Exact, Iri, Kernel, Request, Verb};
use ikigai_resolve::Resolver;

fn kernel() -> Kernel {
    Kernel::new(Arc::new(
        EndpointSpace::new().bind(Exact::new("urn:test:upper"), builtins::to_upper()),
    ))
}

fn upper(text: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:test:upper").unwrap())
        .with_arg("in", ArgRef::Inline(text.as_bytes().to_vec()))
}

/// Scenario 1: a client in the same account connects through the Windows channel and a
/// request round-trips.
#[test]
fn the_owner_reaches_the_door() {
    let dir = std::env::temp_dir().join(format!("ikigai-ipc-owner-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("owner.sock");
    let listener = ikigai_ipc::bind(&path).expect("bind");
    std::thread::spawn(move || ikigai_ipc::serve_shared_on(Arc::new(kernel()), listener));

    let client = ikigai_ipc::connect(&path).expect("the owner connects");
    let (representation, _) = client
        .issue(upper("hello"))
        .expect("the request round-trips");
    assert_eq!(representation.bytes, b"HELLO");
}

/// The live refusal, for a SECOND Windows account to see. Not run by default.
///
/// Needs two accounts on one machine, A and B, and a directory both can traverse (the default,
/// `C:\Users\Public`, does). From a checkout both can build and run (or run the same
/// prebuilt test binary as each):
///
/// 1. As A, in one console:
///    `set IKIGAI_IPC_LIVE_ROLE=serve` then
///    `cargo test -p ikigai-ipc --test windows_owner -- --ignored --nocapture another_account`.
///    A binds `C:\Users\Public\ikigai-ipc-live.sock` (override: `IKIGAI_IPC_LIVE_SOCKET`),
///    then DELIBERATELY widens the socket file's ACL to Everyone, so B gets past the file
///    boundary and only the second layer, the process-token check, stands between B and the
///    hub. A serves for 120 s (`IKIGAI_IPC_LIVE_SECS`).
/// 2. As B, with `IKIGAI_IPC_LIVE_ROLE=connect`, the same command.
///
/// Expected: B's test passes (the socket-level connect SUCCEEDS, which rules out a missing
/// socket and an ACL denial, and the hub then closes the connection without a byte, which is the
/// token-check refusal), and A's
/// console shows `ikigai-ipc: refused a connection from <MACHINE>\<B> (S-1-5-21-...): not the
/// owner of this socket, <MACHINE>\<A>`. Without `IKIGAI_IPC_LIVE_ROLE` the test does nothing,
/// so `--ignored` on one account cannot pass by accident.
#[test]
#[ignore = "needs a second Windows account; see the doc comment"]
fn another_account_is_refused_live() {
    let path = PathBuf::from(
        std::env::var_os("IKIGAI_IPC_LIVE_SOCKET")
            .unwrap_or_else(|| r"C:\Users\Public\ikigai-ipc-live.sock".into()),
    );
    match std::env::var("IKIGAI_IPC_LIVE_ROLE").as_deref() {
        Ok("serve") => {
            let listener = ikigai_ipc::bind(&path).expect("bind");
            let status = std::process::Command::new("icacls")
                .arg(&path)
                .args(["/grant", "*S-1-1-0:(R,W)"])
                .status()
                .expect("icacls runs");
            assert!(status.success(), "could not widen the ACL for the demo");
            let secs = std::env::var("IKIGAI_IPC_LIVE_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(120);
            eprintln!(
                "serving {} for {secs}s; run the connect role as another account",
                path.display()
            );
            std::thread::spawn(move || ikigai_ipc::serve_shared_on(Arc::new(kernel()), listener));
            std::thread::sleep(Duration::from_secs(secs));
        }
        Ok("connect") => {
            use std::io::{Read, Write};
            // Socket level first: NotFound (no hub) or PermissionDenied (the ACL) must fail
            // this test, so only the token check can be what turns B away.
            let mut raw = uds_windows::UnixStream::connect(&path).expect(
                "the socket-level connect must succeed (is A serving? is the ACL widened?)",
            );
            raw.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let _ = raw.write_all(b"\0");
            let mut byte = [0u8; 1];
            match raw.read(&mut byte) {
                Ok(0) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) => {}
                other => panic!("the hub must hang up on a different account, got {other:?}"),
            }
            assert!(
                ikigai_ipc::connect(&path).is_err(),
                "a different account must not be served by the owner's hub"
            );
            eprintln!("refused as expected: the server closed the connection");
        }
        _ => eprintln!("set IKIGAI_IPC_LIVE_ROLE=serve (account A) or connect (account B)"),
    }
}
