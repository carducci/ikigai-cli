//! `serve quic://` names every client it serves, through the REAL binary (ledger #1179).
//!
//! Before this, the door's minter set `principal: None` on all three of its postures
//! (per-identity grants, a shared `--cap` ceiling, per-client workspaces), so nothing behind
//! the door could tell one certificate from another, even when their grants differed. Now
//! each connection is named by its `clients.json` entry's `principal`, else by the convention
//! `urn:iki:host:{name}:client:<fingerprint>`. `urn:host:identity` reports it, which is how
//! these tests see it from outside the process.
//!
//! The airlock shape is pinned too: the edge's QUIC door runs exactly
//! `serve quic://… --cap urn:cap:space:read --cap urn:cap:space:take --cap urn:cap:space:out`
//! with no enrolment, and bug drains it (peek, deliver, take). That door must behave as it
//! did, now with a name on each connection.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as `host_posture.rs` is: `HOME`,
//! `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set on each spawned process only.
#![cfg(all(feature = "embedded", feature = "quic", unix))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a door gets to print its banner. A watchdog, not a performance assertion.
const PATIENCE: Duration = Duration::from_secs(90);

/// A child killed when the test ends, whatever the test does.
struct Door(Child);

impl Drop for Door {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch home unique to this case and process, with an empty config home.
fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-qp-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(config_home(&dir)).expect("scratch config home");
    dir
}

fn config_home(home: &Path) -> PathBuf {
    home.join("config").join("ikigai")
}

fn spawn(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        // The test harness may run with the developer's own overrides set; these would
        // point the child at real enrolment files.
        .env_remove("IKIGAI_CLIENTS")
        .env_remove("IKIGAI_GRANTS");
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    spawn(home, args).output().expect("the binary runs")
}

fn ok(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// A certificate set: the server pair, the base client, and `extra` added clients.
fn certs(home: &Path, extra: &[&str]) -> PathBuf {
    let dir = home.join("certs");
    let d = dir.to_str().unwrap();
    ok(
        run(home, &["cert", "generate", "--dir", d]),
        "cert generate",
    );
    for name in extra {
        ok(
            run(home, &["cert", "add-client", name, "--cert-dir", d]),
            "cert add-client",
        );
    }
    dir
}

/// The fingerprint a door keys a client by: lowercase hex SHA-256 of its certificate DER.
fn fingerprint(cert: &Path) -> String {
    let pem = std::fs::read_to_string(cert).expect("the client certificate");
    ikigai_quic::fingerprint_of_pem(&pem).expect("a certificate")
}

/// A UDP port nothing holds: bound, read back, released.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free UDP port")
        .port()
}

/// Start `serve quic://127.0.0.1:<port>` with `extra` flags; returns the door, its address
/// and its stderr up to the banner.
fn serve(home: &Path, certs: &Path, extra: &[&str]) -> (Door, String, String) {
    let target = format!("quic://127.0.0.1:{}", free_port());
    let mut args = vec![
        "serve",
        target.as_str(),
        "--cert-dir",
        certs.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let mut child = spawn(home, &args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the door starts");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    // ⚠ The reader keeps DRAINING after the banner rather than dropping the pipe: the door
    // logs a line per enrolled connection, and a write to a closed stderr panics the
    // connection's task, which a client sees as `connection lost`.
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
        for line in lines.by_ref() {
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("serving on") {
                break;
            }
        }
        let _ = tx.send(seen);
        lines.for_each(drop);
    });
    let door = Door(child);
    let seen = rx
        .recv_timeout(PATIENCE)
        .unwrap_or_else(|e| panic!("`{args:?}` never printed its banner: {e}"));
    (door, target, seen)
}

/// Ask the door `command` as the client whose certificate is `cert` (the base client when
/// `None`). The banner prints before the socket binds, so a refused first dial is retried.
fn ask_as(home: &Path, certs: &Path, cert: Option<&str>, target: &str, command: &str) -> Output {
    let dir = certs.to_str().unwrap().to_string();
    let mut args = vec!["--cert-dir".to_string(), dir.clone()];
    if let Some(name) = cert {
        args.extend([
            "--client-cert".to_string(),
            format!("{dir}/clients/{name}.crt"),
            "--client-key".to_string(),
            format!("{dir}/clients/{name}.key"),
        ]);
    }
    args.extend(
        ["--connect", target, "--plain", "-c", command]
            .iter()
            .map(|s| s.to_string()),
    );
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut last = None;
    for _ in 0..40 {
        let out = run(home, &argv);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !stderr.contains("connect") {
            return out;
        }
        last = Some(out);
        std::thread::sleep(Duration::from_millis(100));
    }
    last.expect("at least one attempt")
}

/// The `principal` line `urn:host:identity` reports, if any.
fn principal_of(identity: &str) -> Option<String> {
    identity
        .lines()
        .find_map(|line| line.strip_prefix("principal "))
        .map(str::to_string)
}

/// Two certificates with two grants arrive as two principals: one named by its enrolment's
/// `principal`, the other by the default convention under this door's `--name`. And an
/// enrolment edit refuses the removed one on its next connection.
#[test]
fn two_enrolled_certificates_arrive_as_two_principals() {
    let home = scratch("two");
    let certs = certs(&home, &["alice", "bob"]);
    let alice = fingerprint(&certs.join("clients/alice.crt"));
    let bob = fingerprint(&certs.join("clients/bob.crt"));
    let enrol = |clients: &str| {
        std::fs::write(config_home(&home).join("clients.json"), clients).unwrap();
    };
    std::fs::write(
        config_home(&home).join("grants.json"),
        r#"{"reader": ["urn:cap:space:read"], "taker": ["urn:cap:space:read", "urn:cap:space:take"]}"#,
    )
    .unwrap();
    enrol(&format!(
        r#"{{"clients": {{
            "{alice}": {{"grant": "reader", "label": "alice", "principal": "urn:collab:participant:alice"}},
            "{bob}": {{"grant": "taker", "label": "bob"}}
        }}}}"#
    ));
    let (_door, target, _banner) = serve(&home, &certs, &["--name", "layers"]);

    let seen_by_alice = ok(
        ask_as(
            &home,
            &certs,
            Some("alice"),
            &target,
            "source urn:host:identity",
        ),
        "alice's identity",
    );
    let seen_by_bob = ok(
        ask_as(
            &home,
            &certs,
            Some("bob"),
            &target,
            "source urn:host:identity",
        ),
        "bob's identity",
    );
    assert_eq!(
        principal_of(&seen_by_alice).as_deref(),
        Some("urn:collab:participant:alice"),
        "the enrolment's own principal: {seen_by_alice}"
    );
    assert_eq!(
        principal_of(&seen_by_bob),
        Some(format!("urn:iki:host:layers:client:{bob}")),
        "the default form, exactly: {seen_by_bob}"
    );

    // Revoke bob by editing the file: his next connection is refused.
    enrol(&format!(
        r#"{{"clients": {{"{alice}": {{"grant": "reader", "principal": "urn:collab:participant:alice"}}}}}}"#
    ));
    let refused = ask_as(
        &home,
        &certs,
        Some("bob"),
        &target,
        "source urn:host:identity",
    );
    assert!(
        !refused.status.success()
            || principal_of(&String::from_utf8_lossy(&refused.stdout)).is_none(),
        "a revoked certificate must not be served: {}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The airlock's exact shape — a shared `--cap` ceiling of the three bare space tokens, no
/// enrolment, no `--name` — still drops, peeks and takes as bug's drain does, and now names
/// each connection `urn:iki:host:serve:client:<fingerprint>`.
#[test]
fn the_airlock_shape_drains_as_before_and_names_its_client() {
    let home = scratch("airlock");
    let certs = certs(&home, &[]);
    let base = fingerprint(&certs.join("client.crt"));
    let (_door, target, _banner) = serve(
        &home,
        &certs,
        &[
            "--cap",
            "urn:cap:space:read",
            "--cap",
            "urn:cap:space:take",
            "--cap",
            "urn:cap:space:out",
        ],
    );
    let ask = |command: &str| ok(ask_as(&home, &certs, None, &target, command), command);

    assert_eq!(
        principal_of(&ask("source urn:host:identity")),
        Some(format!("urn:iki:host:serve:client:{base}"))
    );
    // drain.scm's cycle against two spaces: drop, peek (list + read), then take by id.
    for space in ["bookings", "decisions"] {
        let id = ask(&format!("sink urn:space:{space} a-{space}-tuple"))
            .trim()
            .to_string();
        assert_eq!(id.len(), 64, "a tuple id: {id}");
        assert!(ask(&format!("source urn:space:{space}")).contains(&id));
        assert_eq!(
            ask(&format!("source urn:space:{space} tuple={id}")).trim(),
            format!("a-{space}-tuple")
        );
        assert_eq!(
            ask(&format!("delete urn:space:{space} {id}")).trim(),
            format!("a-{space}-tuple")
        );
        assert!(
            !ask(&format!("source urn:space:{space}")).contains(&id),
            "a take still removes the tuple"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// An unusable `quic.max_connection_age` stops the door rather than quietly serving under
/// the default: a revocation bound nobody chose is not a bound.
#[test]
fn an_unusable_connection_age_stops_the_door() {
    let home = scratch("age");
    let certs = certs(&home, &[]);
    std::fs::write(
        config_home(&home).join("config.toml"),
        "quic.max_connection_age = \"0\"\n",
    )
    .unwrap();
    let target = format!("quic://127.0.0.1:{}", free_port());
    let out = run(
        &home,
        &["serve", &target, "--cert-dir", certs.to_str().unwrap()],
    );
    assert!(!out.status.success(), "the door must not start");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("quic.max_connection_age"), "{stderr}");
    let _ = std::fs::remove_dir_all(&home);
}
