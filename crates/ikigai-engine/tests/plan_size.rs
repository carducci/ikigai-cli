//! A plan too large to read or validate is refused before it costs the host a process or a
//! worker, at every door that reads one: `urn:plan:validate`, `urn:plan:eval` and
//! `urn:plan:requires` (ledger #1733).
//!
//! Two claims, both structural, so no Turtle nesting scan sees them (ledger #992 bounded the
//! nesting; these are plans of perfectly flat Turtle):
//!
//! * The reader's dependency walk (`Plan::visit`, behind the cycle check and the run order)
//!   recursed once per dependency, so a plain piped chain of 5,000 steps (about 600 KB)
//!   overflowed a 2 MiB thread, the size of a tokio worker's, and Rust aborted the whole
//!   process. Now the walk is iterative (pinned by a unit test in `plan.rs` on a chain far past
//!   the bound below), AND a plan past `MAX_PLAN_TRIPLES` triples is refused before it is read.
//! * `urn:plan:validate` (and so `urn:plan:eval`) handed the whole plan to SHACL, whose
//!   shapes are superlinear in the plan's size (`edge-cycle` follows every step's upstream
//!   chain to its head) and run under no time budget: a 20,000-step plan was still validating
//!   after eight minutes. Now the plan's triples are counted in the syntax pass and a plan
//!   past the bound is refused before the sub-request.
//!
//! Every reproduction runs in a CHILD PROCESS (this test binary re-executed with one probe
//! named in its environment) on a 2 MiB thread. The parent asserts on the child's exit: an
//! abort kills the child, never this binary, and reads as a failure with the signal named.
//! (The harness `plan_nesting.rs` uses.)
#![cfg(feature = "plan-reader")]

use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};

use ikigai_engine::plan_space::MAX_PLAN_TRIPLES;

const PROBE: &str = "IKIGAI_ENGINE_PLAN_SIZE_PROBE";

/// A plan of `n` steps, each piping from the one before: the longest dependency chain a
/// plan of that size can hold, and the shape every reader walks deepest. It holds `5n + 1`
/// triples: the process's type, `n` `ik:step` and its `ik:result`, and each step's type, verb,
/// target and (all but the first) `ik:pipeFrom`.
fn chain(n: usize) -> String {
    padded_chain(n, 0)
}

/// [`chain`], with `comments` more triples on the process (`rdfs:comment`, which no reader
/// or shape constrains), to land a plan on an exact triple count.
fn padded_chain(n: usize, comments: usize) -> String {
    let mut out = String::from(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\
         @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\n\
         <urn:plan:long> a ik:Process ;\n",
    );
    for i in 1..=comments {
        out.push_str(&format!("    rdfs:comment \"padding {i}\" ;\n"));
    }
    let steps: Vec<String> = (1..=n)
        .map(|i| format!("<urn:plan:long:step:{i}>"))
        .collect();
    out.push_str(&format!(
        "    ik:step {} ;\n    ik:result <urn:plan:long:step:{n}> .\n",
        steps.join(" , ")
    ));
    for i in 1..=n {
        out.push_str(&format!(
            "\n<urn:plan:long:step:{i}> a ik:Step ;\n    ik:verb \"Source\" ;\n    \
             ik:resolves <urn:echo>"
        ));
        if i > 1 {
            out.push_str(&format!(
                " ;\n    ik:pipeFrom <urn:plan:long:step:{}>",
                i - 1
            ));
        }
        out.push_str(" .\n");
    }
    out
}

/// One step carrying `n` arguments by value: the most triples one node can hold.
fn wide(n: usize) -> String {
    let mut out = String::from(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\n<urn:plan:wide> a ik:Process ;\n    \
         ik:step <urn:plan:wide:step:1> ;\n    ik:result <urn:plan:wide:step:1> .\n\n\
         <urn:plan:wide:step:1> a ik:Step ;\n    ik:verb \"Source\" ;\n    ik:resolves <urn:echo>",
    );
    let args: Vec<String> = (1..=n)
        .map(|i| format!("<urn:plan:wide:step:1:arg:a{i}>"))
        .collect();
    out.push_str(&format!(" ;\n    ik:argument {} .\n", args.join(" , ")));
    for i in 1..=n {
        out.push_str(&format!(
            "\n<urn:plan:wide:step:1:arg:a{i}> a ik:Argument ;\n    ik:inputName \"a{i}\" ;\n    \
             ik:value \"v\" .\n"
        ));
    }
    out
}

/// One fork joining `n` branches, none fed: the most nodes one fork can hold.
fn forked(n: usize) -> String {
    let mut out = String::from(
        "@prefix ik: <https://ikigai-rs.dev/ns#> .\n\n<urn:plan:fan> a ik:Process ;\n",
    );
    let steps: Vec<String> = (1..=n)
        .map(|i| format!("<urn:plan:fan:step:{i}>"))
        .collect();
    out.push_str(&format!(
        "    ik:step {} ;\n    ik:result <urn:plan:fan:fork:1> .\n\n\
         <urn:plan:fan:fork:1> a ik:Fork ;\n    ik:join \"newline\" .\n",
        steps.join(" , ")
    ));
    for i in 1..=n {
        out.push_str(&format!(
            "\n<urn:plan:fan:step:{i}> a ik:Step ;\n    ik:verb \"Source\" ;\n    \
             ik:resolves <urn:echo> ;\n    ik:forkOf <urn:plan:fan:fork:1> ;\n    \
             ik:order {i} .\n"
        ));
    }
    out
}

/// The number of steps in a [`chain`] holding exactly [`MAX_PLAN_TRIPLES`] triples.
const AT_THE_BOUND: usize = (MAX_PLAN_TRIPLES - 1) / 5;

/// A plan of shape `shape` and size `n`: `chain`, `wide`, `forked`, or `chain+1`, a chain
/// with one triple more.
fn plan(shape: &str, n: usize) -> String {
    match shape {
        "chain" => chain(n),
        "chain+1" => padded_chain(n, 1),
        "wide" => wide(n),
        "forked" => forked(n),
        other => panic!("no plan shape `{other}`"),
    }
}

/// One request to `door` with a plan of `shape` and size `n`.
fn issue_shape(door: &str, shape: &str, n: usize) -> Result<String, ikigai_core::Error> {
    let kernel = Kernel::new(Arc::new(ikigai_core::Fallback::new(vec![
        Arc::new(ikigai_shacl::space()) as Arc<dyn ikigai_core::Space>,
        Arc::new(ikigai_engine::plan_space::space()),
    ])));
    let request = Request::new(
        Verb::Source,
        Iri::parse(format!("urn:plan:{door}")).expect("IRI"),
    )
    .with_arg("in", ArgRef::Inline(plan(shape, n).into_bytes()));
    block_on(kernel.issue(request, &Capability::root()))
        .map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
}

/// The child's half: inert unless a parent named a probe. Runs it on a 2 MiB thread, prints
/// the outcome and how long it took, and exits before the harness can.
#[test]
fn probe_child() {
    let Ok(spec) = std::env::var(PROBE) else {
        return;
    };
    let mut parts = spec.splitn(3, ':');
    let (door, shape, n) = (
        parts.next().expect("door").to_string(),
        parts.next().expect("shape").to_string(),
        parts.next().expect("n").parse::<usize>().expect("n"),
    );
    let outcome = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            #[allow(
                clippy::disallowed_methods,
                reason = "a native-only test timing a child's request; it never builds for wasm"
            )]
            let start = Instant::now();
            let outcome = match issue_shape(&door, &shape, n) {
                Ok(text) => format!("ok {}", text.replace('\n', " ")),
                Err(e) => format!("err {}", e.to_string().replace('\n', " ")),
            };
            format!("{}ms {outcome}", start.elapsed().as_millis())
        })
        .expect("spawn")
        .join()
        .expect("join");
    println!("\nOUTCOME {outcome}");
    std::process::exit(0);
}

/// The parent's half: run one probe in a child and return (milliseconds, what it said), or
/// fail naming how it died (an abort is the defect).
fn probe(door: &str, n: usize) -> (u128, String) {
    probe_shape(door, "chain", n)
}

/// [`probe`] for a plan of `shape`.
fn probe_shape(door: &str, shape: &str, n: usize) -> (u128, String) {
    let out = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", "probe_child", "--nocapture", "--test-threads=1"])
        .env(PROBE, format!("{door}:{shape}:{n}"))
        .output()
        .expect("child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "urn:plan:{door} with a {shape} plan of {n} did not survive a 2 MiB thread: {} - {}",
        out.status,
        stderr
            .lines()
            .find(|l| l.contains("overflow"))
            .unwrap_or(&stderr)
    );
    let at = stdout
        .find("\nOUTCOME ")
        .unwrap_or_else(|| panic!("urn:plan:{door} at {n} reported nothing: {stdout}"));
    let line = stdout[at + "\nOUTCOME ".len()..]
        .lines()
        .next()
        .unwrap_or("");
    let (ms, outcome) = line.split_once("ms ").expect("{ms}ms {outcome}");
    (ms.parse().expect("ms"), outcome.to_string())
}

#[test]
fn a_five_thousand_step_chain_is_refused_at_every_door_and_aborts_nothing() {
    // Before: `urn:plan:requires` SIGABRTed on a 2 MiB thread (stack overflow in the walk).
    for door in ["requires", "validate", "eval"] {
        let (_, outcome) = probe(door, 5000);
        assert!(
            outcome.starts_with("err invalid argument `in`")
                && outcome.contains("MAX_PLAN_TRIPLES"),
            "urn:plan:{door}: {outcome}"
        );
    }
}

#[test]
fn a_twenty_thousand_step_plan_is_refused_by_validate_within_seconds() {
    // Before: still inside SHACL validation after eight minutes. The refusal comes from the
    // count in the syntax pass, so it costs a parse of the bound's worth of text; ten
    // seconds is a debug build's generous ceiling for that, not the measurement.
    for door in ["validate", "eval"] {
        let (ms, outcome) = probe(door, 20_000);
        assert!(
            outcome.starts_with("err invalid argument `in`")
                && outcome.contains("MAX_PLAN_TRIPLES"),
            "urn:plan:{door}: {outcome}"
        );
        assert!(ms < 10_000, "urn:plan:{door} took {ms} ms to refuse");
    }
}

#[test]
fn a_plan_at_the_bound_is_read_and_one_triple_past_it_is_refused() {
    assert_eq!(
        5 * AT_THE_BOUND + 1,
        MAX_PLAN_TRIPLES,
        "the chain lands on the bound"
    );
    // At the bound the chain is a plan like any other: `requires` walks it (every target is
    // unbound here, so it is reported incomplete) and validation answers that it conforms.
    let (_, at) = probe("requires", AT_THE_BOUND);
    assert!(
        at.starts_with("ok <urn:plan:long> requires AT LEAST nothing"),
        "{at}"
    );
    let (_, at) = probe("validate", AT_THE_BOUND);
    assert!(at.starts_with("ok <urn:plan:long> conforms"), "{at}");
    // One triple more is refused for its size, by name, at every door.
    for door in ["requires", "validate", "eval"] {
        let (_, past) = probe_shape(door, "chain+1", AT_THE_BOUND);
        assert!(
            past.starts_with("err invalid argument `in`") && past.contains("MAX_PLAN_TRIPLES"),
            "urn:plan:{door}: {past}"
        );
    }
}

/// The measurement behind the bound, not a check: how long `urn:plan:validate` takes on a
/// chain of each size. Run with `--ignored --nocapture`.
#[test]
#[ignore = "a measurement; run by hand"]
fn measure_validate() {
    let sizes: Vec<usize> = std::env::var("PLAN_SIZES")
        .ok()
        .map(|s| s.split(',').map(|n| n.trim().parse().expect("n")).collect())
        .unwrap_or_else(|| vec![128, 256, 512, 1024]);
    let shapes = std::env::var("PLAN_SHAPES").unwrap_or_else(|_| "chain".to_string());
    let doors = std::env::var("PLAN_DOORS").unwrap_or_else(|_| "validate,requires".to_string());
    for shape in shapes.split(',') {
        for n in &sizes {
            for door in doors.split(',') {
                let (ms, outcome) = probe_shape(door, shape, *n);
                let short: String = outcome.chars().take(100).collect();
                println!("{door} {shape} {n}: {ms} ms: {short}");
            }
        }
    }
}
