//! Ledger #1548: a reactor that cannot write a tuple's `.err` (or `.out`) note says so on
//! stderr, naming the space, the tuple and the error, instead of dropping it with `let _`.
//!
//! The note is made unwritable HERMETICALLY: a DIRECTORY already stands at the note's path, so
//! the write fails while the tuple's own move into the stage succeeds. A permission bit would
//! not do: the move and the write both create an entry in the same directory, and a CI runner
//! as root ignores permissions anyway. The error's wording is the platform's ("Is a directory"
//! on Unix, "Access is denied" on Windows), so the child reports the error a write to that
//! path gives and the parent looks for exactly that text.
//!
//! What is asserted is stderr, and libtest captures a test's stderr, so each case runs ITSELF
//! in a child process (`--exact <case> --nocapture`) with [`CHILD`] set and reads the child's
//! stderr. Without the fix the child prints nothing and the assertion names that.

mod common;

use common::{drop_tuple, scratch, Counting};
use ikigai_core::{Capability, Error, Kernel, Representation, Request, SpaceEntry};
use ikigai_intray::{space, SpaceReactor, CAP_OUT};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

/// Set in the child: run the scenario instead of spawning it.
const CHILD: &str = "IKIGAI_INTRAY_NOTE_FAILURE_CHILD";

/// A handler that always fails, with a reason the dead-letter note should have carried.
struct Failing;

impl ikigai_resolve::Resolver for Failing {
    fn issue(
        &self,
        request: Request,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        self.issue_as(request, &Capability::root())
    }
    fn issue_as(
        &self,
        _: Request,
        _: &Capability,
    ) -> Result<(Representation, ikigai_resolve::CacheStatus), Error> {
        Err(Error::Endpoint("calendar unreachable".into()))
    }
    fn is_cached(&self, _: &Request, _: &Capability) -> bool {
        false
    }
    fn entries(&self) -> Option<Vec<SpaceEntry>> {
        None
    }
}

/// Drop one tuple into a reactive `jobs` space under `root`, stand a directory where its note
/// in `stage` would go (`ext` is `err` or `out`), drain it through `handler`, and print the
/// tuple id and the error a write to the note's path gives on this platform, for the parent.
fn settle_with_a_blocked_note(
    root: &Path,
    handler: Arc<dyn ikigai_resolve::Resolver>,
    stage: &str,
    ext: &str,
) {
    std::fs::create_dir_all(root.join("jobs")).unwrap();
    std::fs::write(root.join("jobs").join("handler"), "urn:test:handler").unwrap();
    let kernel = Kernel::new(Arc::new(space(root.to_path_buf())));
    let id = drop_tuple(
        &kernel,
        &Capability::scoped([CAP_OUT]),
        "urn:space:jobs",
        b"book me",
    )
    .unwrap();
    let note = root.join("jobs").join(stage).join(format!("{id}.{ext}"));
    std::fs::create_dir_all(&note).unwrap();
    let reactor = SpaceReactor::new(
        root.to_path_buf(),
        handler,
        Capability::scoped(["urn:cap:demo"]),
    );
    reactor.drain("jobs");
    assert!(
        root.join("jobs")
            .join(stage)
            .join(format!("{id}.tuple"))
            .exists(),
        "the tuple itself still reaches `{stage}/`: only its note is lost"
    );
    let error = std::fs::write(&note, b"probe").expect_err("the note's path is a directory");
    println!("tuple-id {id}");
    println!("write-error {error}");
}

/// Run `case` in a child process with [`CHILD`] set and return (its stderr, the tuple id and
/// the write error it printed on stdout).
fn child_run(case: &str) -> (String, String, String) {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", case, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .expect("the test binary re-runs itself");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "the child case failed: {stdout}{stderr}"
    );
    let id = stdout
        .lines()
        // Not a line prefix: libtest prints `test <case> ... ` on the same line first.
        .find_map(|line| line.split("tuple-id ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("the child printed no tuple id: {stdout}"))
        .to_string();
    let error = stdout
        .lines()
        .find_map(|line| line.strip_prefix("write-error "))
        .unwrap_or_else(|| panic!("the child printed no write error: {stdout}"))
        .to_string();
    (stderr, id, error)
}

#[test]
fn an_unwritable_dead_letter_note_is_reported_on_stderr() {
    if std::env::var_os(CHILD).is_some() {
        settle_with_a_blocked_note(
            &scratch("err-note-blocked"),
            Arc::new(Failing),
            "error",
            "err",
        );
        return;
    }
    let (stderr, id, error) = child_run("an_unwritable_dead_letter_note_is_reported_on_stderr");
    let line = stderr
        .lines()
        .find(|line| line.contains(".err note"))
        .unwrap_or_else(|| panic!("no stderr line reports the lost .err note: {stderr:?}"));
    assert!(line.contains("space `jobs`"), "names the space: {line}");
    assert!(line.contains(&id), "names the tuple: {line}");
    assert!(line.contains(&error), "names the error ({error}): {line}");
    assert!(
        line.contains("calendar unreachable"),
        "carries the reason the note would have: {line}"
    );
}

#[test]
fn an_unwritable_answer_note_is_reported_on_stderr() {
    if std::env::var_os(CHILD).is_some() {
        let handler = Counting::new();
        handler.answers.lock().unwrap().push("booked");
        settle_with_a_blocked_note(
            &scratch("out-note-blocked"),
            Arc::new(handler),
            "outbox",
            "out",
        );
        return;
    }
    let (stderr, id, error) = child_run("an_unwritable_answer_note_is_reported_on_stderr");
    let line = stderr
        .lines()
        .find(|line| line.contains(".out note"))
        .unwrap_or_else(|| panic!("no stderr line reports the lost .out note: {stderr:?}"));
    assert!(line.contains("space `jobs`"), "names the space: {line}");
    assert!(line.contains(&id), "names the tuple: {line}");
    assert!(line.contains(&error), "names the error ({error}): {line}");
}
