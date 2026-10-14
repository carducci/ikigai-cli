//! The spam filter in the local root, through the REAL binary (ledger #1512): `--bayes-state` +
//! `--bayes-model` (else the config home's `bayes.*` keys) open `ikigai-bayes` over a state
//! directory and bind `urn:bayes:{model}:*`; a pipe fills `content` for a score and a train; the
//! doors' capabilities are enforced for a narrowed caller; a second process on the same state
//! directory is refused at startup, naming the holder's pid; and with no setting nothing is bound.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT: `HOME` and `XDG_CONFIG_HOME` point into a scratch tree,
//! `--files` roots the file module there, and `--no-config-mounts` keeps any topology out.
#![cfg(all(feature = "embedded", unix))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const SPAM: &str = "buy cheap pills now at https://pills.example.com/deal";
const HAM: &str = "can we meet on tuesday to review the draft";

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-bayes-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("ws")).expect("scratch file root");
    dir
}

fn command(home: &Path, flags: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(["--no-config-mounts", "--files"])
        .arg(home.join("ws"))
        .args(flags)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env_remove("IKIGAI_FILES");
    command
}

/// `ikigai <flags> -c <cmd>…`, with `input` on stdin (or an empty stdin).
fn run(home: &Path, flags: &[&str], commands: &[&str], input: Option<&str>) -> Output {
    let mut command = command(home, flags);
    for c in commands {
        command.args(["-c", c]);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    match input {
        None => command
            .stdin(Stdio::null())
            .output()
            .expect("the binary runs"),
        Some(text) => {
            let mut child = command.stdin(Stdio::piped()).spawn().expect("spawns");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("writes stdin");
            child.wait_with_output().expect("the binary runs")
        }
    }
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn state_flags(state: &Path) -> Vec<String> {
    vec![
        "--bayes-state".to_string(),
        state.to_str().unwrap().to_string(),
        "--bayes-model".to_string(),
        "contact".to_string(),
    ]
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

#[test]
fn the_flags_bind_the_model_and_a_pipe_scores_and_trains() {
    let home = scratch("pipe");
    let state = home.join("bayes");
    let flags = state_flags(&state);
    let flags = strs(&flags);

    let models = ok(&run(&home, &flags, &["source urn:bayes:models"], None));
    assert!(models.starts_with("contact\n"), "{models}");

    // A train through a pipe: the piped value lands in `content`.
    let trained = ok(&run(
        &home,
        &flags,
        &["sink urn:bayes:contact:train label=spam"],
        Some(SPAM),
    ));
    assert!(trained.contains("as spam"), "{trained}");
    let trained = ok(&run(
        &home,
        &flags,
        &["sink urn:bayes:contact:train label=ham"],
        Some(HAM),
    ));
    assert!(trained.contains("messages spam 1 ham 1"), "{trained}");

    // A score through a pipe, the brief's exact form: the model persisted across processes.
    let score = ok(&run(
        &home,
        &flags,
        &["source urn:bayes:contact:score"],
        Some("cheap pills now at https://pills.example.com/today"),
    ));
    assert!(score.starts_with("spam "), "{score}");

    // The state directory was created at 0700, and holds the model.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "a missing state directory is created private");
    assert!(state.join("contact.json").is_file());

    // The startup line, on an interactive-style (non -c) start: one line naming the counts.
    let out = command(&home, &flags)
        .arg("--plain")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    let line = format!(
        "ikigai: bayes: contact (2 messages: 1 spam, 1 ham) — state in {} (flag)",
        state.display()
    );
    assert!(stderr(&out).contains(&line), "{}", stderr(&out));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn the_config_home_binds_it_for_the_instance_it_names() {
    let home = scratch("config");
    std::fs::write(
        home.join("config/ikigai/config.toml"),
        "repl.bayes.state = \"bayes\"\nrepl.bayes.models = \"contact, other\"\n",
    )
    .unwrap();
    let models = ok(&run(&home, &[], &["source urn:bayes:models"], None));
    assert_eq!(
        models.lines().take(2).collect::<Vec<_>>(),
        ["contact", "other"]
    );
    assert!(
        home.join("config/ikigai/bayes/contact.json").is_file(),
        "relative to the config home"
    );
    // Another instance reads neither scoped key: nothing bound, startup unchanged.
    let out = run(
        &home,
        &["--name", "other"],
        &["source urn:bayes:models"],
        None,
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no endpoint resolved"),
        "{}",
        stderr(&out)
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_narrowed_caller_needs_the_models_own_grants() {
    let home = scratch("caps");
    let flags = state_flags(&home.join("bayes"));
    let flags = strs(&flags);

    // Another model's read grant does not reach this one.
    let out = run(
        &home,
        &flags,
        &[
            "cap urn:cap:bayes:read:other",
            "source urn:bayes:contact:score hello",
        ],
        None,
    );
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("denied") && err.contains("urn:cap:bayes:read:contact"),
        "{err}"
    );

    // The read grant scores, and does not train.
    let scored = ok(&run(
        &home,
        &flags,
        &[
            "cap urn:cap:bayes:read:contact",
            "source urn:bayes:contact:score hello",
        ],
        None,
    ));
    assert!(scored.contains("unsure 0.500000"), "{scored}");
    let out = run(
        &home,
        &flags,
        &[
            "cap urn:cap:bayes:read:contact",
            "sink urn:bayes:contact:train label=spam",
        ],
        Some(SPAM),
    );
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("denied") && err.contains("urn:cap:bayes:train:contact"),
        "{err}"
    );

    // The train grant trains.
    let trained = ok(&run(
        &home,
        &flags,
        &[
            "cap urn:cap:bayes:train:contact",
            "sink urn:bayes:contact:train label=spam",
        ],
        Some(SPAM),
    ));
    assert!(trained.contains("as spam"), "{trained}");
    let _ = std::fs::remove_dir_all(&home);
}

/// Kills the daemon on drop, by its PID, whatever the test did.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_second_process_on_the_state_directory_is_refused_naming_the_holder() {
    let home = scratch("lock");
    let state = home.join("bayes");
    let flags = state_flags(&state);
    let mut daemon = command(&home, &strs(&flags))
        .args(["--daemon", "--name", "bayes-holder"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon starts");
    let pid = daemon.id();
    let lines = BufReader::new(daemon.stderr.take().expect("stderr"));
    let mut daemon = Daemon(daemon);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in lines.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(120)) {
            Ok(line) if line.starts_with("ikigai: bayes: contact") => break,
            Ok(line) => seen.push(line),
            Err(_) => panic!(
                "the daemon never said it opened the model (exit {:?}); stderr so far:\n{}",
                daemon.0.try_wait(),
                seen.join("\n")
            ),
        }
    }

    let out = run(&home, &strs(&flags), &["source urn:bayes:models"], None);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(&format!("pid {pid}")) && err.contains(state.to_str().unwrap()),
        "the refusal names the holder and the directory: {err}"
    );
    assert!(
        out.stdout.is_empty(),
        "nothing ran: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    drop(daemon);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn with_no_setting_nothing_is_bound_and_startup_is_unchanged() {
    let home = scratch("none");
    let out = run(&home, &[], &["source urn:bayes:models"], None);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no endpoint resolved"),
        "{}",
        stderr(&out)
    );
    let out = command(&home, &[])
        .arg("--plain")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("bayes"),
        "no bayes line: {}",
        stderr(&out)
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn half_a_setting_and_a_served_door_are_refused_by_name() {
    let home = scratch("half");
    let state = home.join("bayes");
    let out = run(
        &home,
        &["--bayes-state", state.to_str().unwrap()],
        &["source urn:host:identity"],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--bayes-model"), "{}", stderr(&out));
    assert!(!state.exists(), "nothing was opened or created");

    let out = run(
        &home,
        &["--bayes-model", "contact"],
        &["source urn:host:identity"],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--bayes-state"), "{}", stderr(&out));

    let flags = state_flags(&state);
    // The mode word comes first, so this one is built by hand.
    let out = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args(["serve", "--http", "0", "--no-config-mounts"])
        .args(strs(&flags))
        .current_dir(&home)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("`serve --http`") && stderr(&out).contains("--bayes-state"),
        "{}",
        stderr(&out)
    );
    assert!(!state.exists(), "the HTTP door never opens the model");
    let _ = std::fs::remove_dir_all(&home);
}
