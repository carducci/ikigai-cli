//! Where the local file module is rooted, through the REAL binary (ledger #1285): `--files
//! <dir>`, else the config home's `<instance>.files` / `files`, else `IKIGAI_FILES`, else
//! `~/.ikigai/workspace`. Before, the variable was the only channel, so a unit serving a
//! file root (the edge's layer door) had to carry an environment.
//!
//! Each case places one file in each candidate root, each saying which root it is in, and
//! reads `urn:file:which.txt`: the answer names the root that won.
//!
//! ★ HERMETIC BY THE CHILD'S ENVIRONMENT: `HOME`, `XDG_CONFIG_HOME` and `IKIGAI_FILES` are set
//! (or removed) on the spawned process only, and `--no-config-mounts` keeps any topology out.
#![cfg(all(feature = "embedded", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch(case: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iki-fr-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("config").join("ikigai")).expect("scratch config home");
    for root in [
        "flag",
        "config/ikigai/scoped",
        "config/ikigai/plain",
        "env",
        ".ikigai/workspace",
    ] {
        let at = dir.join(root);
        std::fs::create_dir_all(&at).expect("a candidate root");
        std::fs::write(at.join("which.txt"), root).expect("its marker");
    }
    dir
}

fn config(home: &Path, text: &str) {
    std::fs::write(home.join("config/ikigai/config.toml"), text).expect("config.toml");
}

/// `ikigai [flags] -c 'source urn:file:which.txt'`, with `IKIGAI_FILES` set or not.
fn which(home: &Path, flags: &[&str], env: bool) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ikigai"));
    command
        .args(flags)
        .args(["--no-config-mounts", "-c", "source urn:file:which.txt"])
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .stdin(Stdio::null());
    if env {
        command.env("IKIGAI_FILES", home.join("env"));
    } else {
        command.env_remove("IKIGAI_FILES");
    }
    let out: Output = command.output().expect("the binary runs");
    assert!(
        out.status.success(),
        "{flags:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn the_flag_then_the_config_home_then_the_variable_then_the_default() {
    let home = scratch("order");
    let flag = home.join("flag");
    let flag = flag.to_str().unwrap();

    config(&home, "repl.files = \"scoped\"\nfiles = \"plain\"\n");
    assert_eq!(
        which(&home, &["--files", flag], true),
        "flag",
        "the flag wins"
    );
    assert_eq!(
        which(&home, &["--files=flag"], true),
        "flag",
        "relative to the working directory"
    );
    assert_eq!(
        which(&home, &[], true),
        "config/ikigai/scoped",
        "then the instance-scoped key, relative to the config home"
    );
    assert_eq!(
        which(&home, &["--name", "other"], true),
        "config/ikigai/plain",
        "an instance the scoped key does not name reads the plain key"
    );
    config(&home, "");
    assert_eq!(
        which(&home, &[], true),
        "env",
        "then IKIGAI_FILES, kept as the fallback"
    );
    assert_eq!(
        which(&home, &[], false),
        ".ikigai/workspace",
        "then the default under the data home"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn files_beside_connect_is_refused() {
    let home = scratch("connect");
    let out = Command::new(env!("CARGO_BIN_EXE_ikigai"))
        .args([
            "--files",
            "/tmp",
            "--connect",
            "/tmp/nothing.sock",
            "-c",
            "list",
        ])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("--files") && stderr.contains("--connect"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
