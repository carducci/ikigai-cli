//! The HTTP door's per-client rate limits through the REAL binary (ledger #1717): the limits are
//! on with nothing configured, the config home changes them, a refused client is answered `429`
//! with `Retry-After`, and a line the door cannot read stops it from starting.
//!
//! The library behavior (windows, the bounded table, the forged `X-Forwarded-For`, the page and
//! the JSON body) is pinned in `ikigai-web`; this file pins the wiring: that `serve --http`
//! reads `http.rate_limit*` and `passkey.max_challenges` from the config home and acts on them.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `host_posture.rs` is: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(all(feature = "embedded", feature = "web", unix))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner or exit. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A child process that is killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home whose config home's `config.toml` is `config`, and an owner-only workspace.
fn scratch(case: &str, config: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-rl-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&home).expect("scratch config home");
    std::fs::write(home.join("config.toml"), config).expect("scratch config.toml");
    let files = dir.join("files");
    std::fs::create_dir_all(&files).expect("scratch workspace");
    std::fs::set_permissions(&files, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("an owner-only workspace");
    dir
}

/// Start `serve --http 0` against `home` and report how it ENDED: `Ok((door, banner))` once it
/// printed `serving HTTP on`, `Err((code, stderr))` when it exited first.
fn start(home: &Path) -> Result<(Door, String), (i32, String)> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        // The ceiling grants the passkey challenge, as the edge's does: the endpoint declares
        // `urn:cap:passkey:challenge`, and a door without it refuses before any limit is counted.
        .args(["serve", "--http", "0", "--cap", "urn:cap:passkey:challenge"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut served = false;
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving HTTP on") {
                served = true;
                break;
            }
        }
        let _ = tx.send((served, seen));
        lines.for_each(drop);
    });
    let (served, seen) = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("the door neither served nor exited: {e}"));
    if served {
        return Ok((Door(child), seen));
    }
    // stderr reached EOF: the process is exiting. `wait`, never `try_wait` (field guide 9h).
    let status = child.wait().expect("the door's exit status");
    Err((status.code().unwrap_or(-1), seen))
}

/// The port the door bound, off its banner (`serving HTTP on 127.0.0.1:<port>`).
fn bound_port(banner: &str) -> u16 {
    banner
        .lines()
        .find_map(|line| line.split("serving HTTP on ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
        .map(|addr| addr.port())
        .unwrap_or_else(|| panic!("no bound address on the banner: {banner}"))
}

/// `GET path`, returning the whole raw response.
fn get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("nothing accepted on {port}: {e}"));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("the request is written");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("the response is read");
    raw
}

#[test]
fn with_nothing_configured_the_door_limits_the_intake_and_the_challenge() {
    let home = scratch("defaults", "");
    let (_door, banner) = start(&home).unwrap_or_else(|(code, err)| panic!("{code}: {err}"));
    assert!(
        banner.contains(
            "rate limits per client: urn:booking:submit 10/3600s, urn:contact:submit 10/3600s, \
             urn:passkey:challenge 30/120s"
        ),
        "the banner names the limits in force: {banner}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_configured_limit_answers_429_with_retry_after_past_it() {
    let home = scratch(
        "configured",
        "http.rate_limit = \"urn:passkey:challenge 2/3600\"\n",
    );
    let (_door, banner) = start(&home).unwrap_or_else(|(code, err)| panic!("{code}: {err}"));
    assert!(
        banner.contains("urn:passkey:challenge 2/3600s"),
        "the config home's rule replaced the default: {banner}"
    );
    let port = bound_port(&banner);
    for n in 0..2 {
        let ok = get(port, "/passkey/challenge");
        assert!(
            ok.starts_with("HTTP/1.1 200 "),
            "read {n} is in budget: {ok}"
        );
        assert!(ok.contains("\"challenge\""), "{ok}");
    }
    let refused = get(port, "/passkey/challenge");
    assert!(
        refused.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
        "{refused}"
    );
    let wait: u64 = refused
        .lines()
        .find_map(|l| l.strip_prefix("Retry-After: "))
        .unwrap_or_else(|| panic!("a Retry-After header: {refused}"))
        .trim()
        .parse()
        .unwrap();
    assert!((3500..=3600).contains(&wait), "about an hour: {refused}");
    assert!(
        refused.contains("rate-limited: `urn:passkey:challenge`"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_rate_limit_line_the_door_cannot_read_stops_it_from_starting() {
    for (case, config, says) in [
        (
            "bad-rule",
            "http.rate_limit = \"urn:contact:submit ten/3600\"\n",
            "is not a whole number",
        ),
        (
            "bad-key",
            "http.rate_limits = \"urn:contact:submit 1/1\"\n",
            "is not an HTTP rate-limit setting",
        ),
        (
            "bad-bound",
            "passkey.max_challenges = 0\n",
            "passkey.max_challenges = 0",
        ),
    ] {
        let home = scratch(case, config);
        match start(&home) {
            Ok((_door, banner)) => panic!("`{config}` must stop the door, and it served: {banner}"),
            Err((code, stderr)) => {
                assert_eq!(code, 2, "{stderr}");
                assert!(stderr.contains(says), "`{config}`: {stderr}");
                assert!(
                    stderr.contains("config.toml"),
                    "the file is named: {stderr}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}
