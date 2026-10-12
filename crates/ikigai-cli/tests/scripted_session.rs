//! A scripted session through the REAL binary: what a `-c` batch caches when its stdin holds
//! nothing (ledger #1305), and the `--quiet` REPL a replay drives instead (ledger #1310).
//!
//! Ledger #1305: since cli 0.1.48 a `-c` batch whose stdin is not a terminal routes stdin to
//! a `source` stage's one required argument (ledger #1166), so it fetched the contract of every
//! bare `source` in case stdin should fill it, and the kernel cached that contract. A harness
//! hands a child `/dev/null` and so does an agent's shell, so a scripted run listed cache rows
//! an interactive session never makes (the ikigai Book's replay saw 5 where a reader sees 3,
//! ikigai-rs/ikigai-tutorial PR 109). Now a stdin already at its end with nothing is told apart
//! without reading it, and nothing is fetched for its sake.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT, as in `sink_stdin.rs`: `HOME`, `XDG_CONFIG_HOME` and
//! `IKIGAI_FILES` are set on the spawned process only.
#![cfg(all(feature = "embedded", unix))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-sc-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    std::fs::create_dir_all(dir.join("files")).expect("scratch workspace");
    dir
}

fn ikigai(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("IKIGAI_FILES", home.join("files"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Spawn, write `input` to a piped stdin (then close it), and reap with `wait` (never
/// `try_wait`: see the field guide on stderr EOF).
fn piped(mut command: Command, input: &[u8]) -> Output {
    let mut child = command.stdin(Stdio::piped()).spawn().expect("spawn ikigai");
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(input).expect("write stdin");
    drop(stdin);
    child.wait_with_output().expect("reap ikigai")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The batch every case runs: a bare `source` (no arguments, so only stdin could have made
/// it fetch a contract), then the cache listing.
const BATCH: [&str; 4] = [
    "-c",
    "source urn:kernel:scheduler",
    "-c",
    "source urn:kernel:cache",
];

/// The cache listing's own `entries N` line.
fn entries(listing: &str) -> &str {
    listing
        .lines()
        .find(|line| line.trim_start().starts_with("entries"))
        .unwrap_or_else(|| panic!("no `entries` line in:\n{listing}"))
        .trim()
}

/// `/dev/null`, a closed empty pipe and an empty file each hold nothing: the batch caches
/// nothing, exactly as the same two lines typed at a prompt do.
#[test]
fn a_batch_on_an_empty_stdin_caches_what_it_asked_for_and_nothing_else() {
    let home = scratch("empty");

    let null = ikigai(&home, &BATCH)
        .stdin(Stdio::null())
        .output()
        .expect("run ikigai");
    let pipe = piped(ikigai(&home, &BATCH), b"");
    let file = home.join("empty.txt");
    std::fs::write(&file, b"").expect("empty file");
    let from_file = ikigai(&home, &BATCH)
        .stdin(std::fs::File::open(&file).expect("open"))
        .output()
        .expect("run ikigai");

    for (case, output) in [
        ("/dev/null", &null),
        ("closed empty pipe", &pipe),
        ("empty file", &from_file),
    ] {
        assert!(output.status.success(), "{case}: {output:?}");
        let listing = stdout(output);
        assert!(
            entries(&listing).starts_with("entries  0 /"),
            "{case}: a contract was fetched for an empty stdin's sake:\n{listing}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// The control: a stdin WITH bytes is still the one required argument's value, so the
/// contract is fetched (it routes the value) and the answer is the piped one.
#[test]
fn a_batch_stdin_with_bytes_still_fills_the_required_argument() {
    let home = scratch("bytes");
    let output = piped(
        ikigai(&home, &["-c", "source urn:iki:fn:toUpper"]),
        b"piped",
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output).trim_end(), "PIPED");
    let _ = std::fs::remove_dir_all(&home);
}

/// Ledger #1310: `--quiet` on a piped stdin prints the answers and nothing else. No version
/// banner, no topology lines, no prompts, and no blank line at EOF, so the session can be
/// compared line for line with what was typed. And it is a REPL, not a batch: the bare
/// `source` fetched no contract, so the cache holds only what `toUpper` asked for.
#[test]
fn a_quiet_repl_on_a_pipe_prints_only_its_answers() {
    let home = scratch("quiet");
    let lines =
        "source urn:iki:fn:toUpper hi\nsource urn:kernel:scheduler\nsource urn:kernel:cache\n";

    let quiet = piped(ikigai(&home, &["--quiet"]), lines.as_bytes());
    assert!(quiet.status.success(), "{quiet:?}");
    let out = stdout(&quiet);
    let err = String::from_utf8_lossy(&quiet.stderr);
    assert!(
        out.starts_with("HI\n"),
        "the first answer comes first:\n{out}"
    );
    assert!(
        !out.contains("ikigai>"),
        "no prompt on a piped stdin:\n{out}"
    );
    assert!(!out.contains("REPL"), "no banner:\n{out}");
    assert!(!err.contains("ikigai: "), "no topology lines:\n{err}");
    assert!(!out.ends_with("\n\n\n"), "no extra line at EOF:\n{out:?}");
    assert!(
        entries(&out).starts_with("entries  2 /"),
        "only toUpper's contract and answer are cached:\n{out}"
    );

    // Without `--quiet` the same session greets and prompts, as before.
    let plain = piped(ikigai(&home, &["--plain"]), lines.as_bytes());
    let out = stdout(&plain);
    assert!(out.starts_with("ikigai "), "the banner:\n{out}");
    assert!(out.contains("ikigai> HI\n"), "the prompt:\n{out}");
    let _ = std::fs::remove_dir_all(&home);
}
