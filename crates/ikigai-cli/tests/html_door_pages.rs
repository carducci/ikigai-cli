//! The embedded host's HTML pages under an HTML door's CSP, through the REAL binary (ledger
//! #1834): served with `ikigai_web::HTML_DOOR_CSP` (`style-src 'self'`, `script-src 'self'`) on
//! their routes, a page carries no inline style, no inline script and no event-handler
//! attribute, and every stylesheet and script it names is a same-origin path the door serves
//! with the right type. That is what a browser needs to render the page as written under that
//! policy.
//!
//! The route file here is the one change an edge makes to adopt the preset on its HTML routes:
//! a `csp` on each route, and one route for the stylesheet.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `http_rate_limits.rs` is: `HOME`, `XDG_CONFIG_HOME`
//! and `IKIGAI_FILES` are set on the spawned process only, and the door binds port 0 and names
//! its port on its banner (field guide 9h).
#![cfg(all(feature = "embedded", feature = "web", unix))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use ikigai_web::HTML_DOOR_CSP;

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

/// A scratch home with an empty config home and an owner-only workspace holding `routes.json`.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-hd-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("config").join("ikigai");
    std::fs::create_dir_all(&home).expect("scratch config home");
    std::fs::write(home.join("config.toml"), "").expect("scratch config.toml");
    let files = dir.join("files");
    std::fs::create_dir_all(&files).expect("scratch workspace");
    std::fs::set_permissions(&files, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("an owner-only workspace");
    let route = |id: &str, path: &str, target: &str| serde_json::json!({"id": id, "match": path, "target": target, "csp": HTML_DOOR_CSP});
    let routes = serde_json::json!({ "routes": [
        route("passkey-register", "/passkey/register", "urn:passkey:register"),
        route("passkey-js", "/passkey/app.js", "urn:passkey:js"),
        route("decide-css", "/decide/css", "urn:decide:css"),
    ]});
    std::fs::write(files.join("routes.json"), routes.to_string()).expect("the route file");
    dir
}

/// Open an enrollment window in `home`'s workspace, as the person at the box does, so the register
/// page shows its whole body: the code field, the button and the ceremony script.
fn open_enrollment_window(home: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(["--quiet", "-c", "sink urn:passkey:enroll-open"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdin(Stdio::null())
        .output()
        .expect("the binary under test runs");
    assert!(
        out.status.success(),
        "enroll-open: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Start `serve --http 0 --routes-only` against `home`; `(door, banner)` once it is serving.
fn start(home: &Path) -> (Door, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args([
            "serve",
            "--http",
            "0",
            "--routes",
            "urn:file:routes.json",
            "--routes-only",
            "--passkey-rp-id",
            "edge.test",
            "--cap",
            "urn:cap:passkey:register",
        ])
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
    if !served {
        // stderr reached EOF: the process is exiting. `wait`, never `try_wait` (field guide 9h).
        let status = child.wait().expect("the door's exit status");
        panic!("the door exited ({status}): {seen}");
    }
    (Door(child), seen)
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

/// `GET path`: the status line, the header lines, and the body.
fn get(port: u16, path: &str) -> (String, Vec<String>, String) {
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
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end: {raw}"));
    let mut lines = head.split("\r\n").map(str::to_string);
    let status = lines.next().unwrap_or_default();
    (status, lines.collect(), body.to_string())
}

/// The value of header `name` (case-insensitive), if sent.
fn header<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Every value of attribute `attr` (`href` or `src`) in `html`, quoted or not.
fn attribute_values(html: &str, attr: &str) -> Vec<String> {
    let needle = format!(" {attr}=");
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find(&needle) {
        let value = &rest[at + needle.len()..];
        let (v, after) = match value.strip_prefix('"') {
            Some(quoted) => {
                let end = quoted.find('"').expect("a closing quote");
                (&quoted[..end], &quoted[end..])
            }
            None => {
                let end = value
                    .find(|c: char| c.is_whitespace() || c == '>')
                    .unwrap_or(value.len());
                (&value[..end], &value[end..])
            }
        };
        out.push(v.to_string());
        rest = after;
    }
    out
}

#[test]
fn a_page_on_an_html_door_route_uses_only_what_its_csp_admits() {
    let home = scratch("pages");
    open_enrollment_window(&home);
    let (_door, banner) = start(&home);
    let port = bound_port(&banner);

    let (status, headers, html) = get(port, "/passkey/register");
    assert!(status.starts_with("HTTP/1.1 200 "), "{status}\n{html}");
    assert!(
        html.contains("Register a passkey"),
        "the whole page: {html}"
    );
    assert_eq!(
        header(&headers, "Content-Security-Policy"),
        Some(HTML_DOOR_CSP),
        "{headers:?}"
    );
    assert_eq!(
        header(&headers, "X-Content-Type-Options"),
        Some("nosniff"),
        "{headers:?}"
    );
    assert!(
        header(&headers, "Content-Type").is_some_and(|t| t.starts_with("text/html")),
        "{headers:?}"
    );

    // `style-src 'self'` refuses a `style=` attribute and a `<style>` element.
    let lower = html.to_ascii_lowercase();
    assert!(
        !lower.contains("style="),
        "an inline style attribute: {html}"
    );
    assert!(!lower.contains("<style"), "an inline style element: {html}");
    // `script-src 'self'` refuses an inline script and an event-handler attribute.
    for (at, _) in lower.match_indices("<script") {
        let tag = &lower[at..at + lower[at..].find('>').expect("a closed tag")];
        assert!(tag.contains(" src="), "an inline script: {html}");
    }
    for handler in [" onclick=", " onload=", " onsubmit=", " onerror="] {
        assert!(!lower.contains(handler), "{handler} in {html}");
    }

    // The stylesheet the shell links is same-origin and served as CSS.
    let sheets = attribute_values(&html, "href");
    assert_eq!(sheets, ["/decide/css"], "{html}");
    let (status, headers, css) = get(port, "/decide/css");
    assert!(status.starts_with("HTTP/1.1 200 "), "{status}\n{css}");
    assert_eq!(
        header(&headers, "Content-Type"),
        Some("text/css;charset=utf-8"),
        "{headers:?}"
    );
    assert!(css.contains("max-width:32rem"), "{css}");

    // And every script it names is same-origin and served as JavaScript.
    let scripts = attribute_values(&html, "src");
    assert_eq!(scripts, ["/passkey/app.js"], "{html}");
    for src in scripts {
        assert!(src.starts_with('/') && !src.starts_with("//"), "{src}");
        let (status, headers, _) = get(port, &src);
        assert!(status.starts_with("HTTP/1.1 200 "), "{src}: {status}");
        assert!(
            header(&headers, "Content-Type")
                .is_some_and(|t| t.starts_with("application/javascript")),
            "{src}: {headers:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}
