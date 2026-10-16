//! A plan whose Turtle nests RDF 1.2 triple terms past the bound is refused before it is
//! parsed, at every door that reads one: `urn:plan:validate`, `urn:plan:eval` and
//! `urn:plan:requires` (ledger #992).
//!
//! The claim: a plan is caller Turtle, and in a build with RDF 1.2 on (`oxrdf/rdf-12`, which
//! this workspace gets by feature unification through rudof) oxttl builds a nested triple
//! term, and oxrdf copies and drops it, RECURSIVELY, once per level. A stack overflow is not an
//! error a caller gets back: Rust aborts the whole process. The plan doors parsed the plan
//! inline on the request's thread, so a plan a few thousand levels deep took down the host.
//!
//! Every reproduction runs in a CHILD PROCESS (this test binary re-executed with one probe
//! named in its environment) on a 2 MiB thread, the size of a tokio worker's. The parent
//! asserts on the child's exit: an abort kills the child, never this binary, and reads as a
//! failure with the signal named. (The harness `ikigai-intray`'s `match_stack.rs` uses.)
#![cfg(feature = "plan-reader")]

use std::process::Command;
use std::sync::Arc;

use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Iri, Kernel, Request, Verb};

const PROBE: &str = "IKIGAI_ENGINE_PLAN_NESTING_PROBE";
/// `ikigai_store::depth::MAX_RDF_NESTING`, restated so a change upstream is noticed here.
const BOUND: usize = 64;

/// A one-triple document whose object nests `n` triple terms.
fn nested(n: usize) -> String {
    format!(
        "<urn:s> <urn:p> {}<urn:o>{} .\n",
        "<<( <urn:s> <urn:p> ".repeat(n),
        " )>>".repeat(n)
    )
}

/// One request to `door` (`validate`, `eval` or `requires`) with a plan nesting `n` deep.
fn issue(door: &str, n: usize) -> Result<String, ikigai_core::Error> {
    let kernel = Kernel::new(Arc::new(ikigai_core::Fallback::new(vec![
        Arc::new(ikigai_shacl::space()) as Arc<dyn ikigai_core::Space>,
        Arc::new(ikigai_engine::plan_space::space()),
    ])));
    let request = Request::new(
        Verb::Source,
        Iri::parse(format!("urn:plan:{door}")).expect("IRI"),
    )
    .with_arg("in", ArgRef::Inline(nested(n).into_bytes()));
    block_on(kernel.issue(request, &Capability::root()))
        .map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
}

/// The child's half: inert unless a parent named a probe. Runs it on a 2 MiB thread, prints
/// the outcome, and exits before the harness can.
#[test]
fn probe_child() {
    let Ok(spec) = std::env::var(PROBE) else {
        return;
    };
    let (door, n) = spec.split_once(':').expect("door:n");
    let (door, n) = (door.to_string(), n.parse::<usize>().expect("n"));
    let outcome = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || match issue(&door, n) {
            Ok(text) => format!("ok {}", text.replace('\n', " ")),
            Err(e) => format!("err {}", e.to_string().replace('\n', " ")),
        })
        .expect("spawn")
        .join()
        .expect("join");
    println!("\nOUTCOME {outcome}");
    std::process::exit(0);
}

/// The parent's half: run one probe in a child and return what it said, or fail naming how
/// it died (an abort is the defect).
fn probe(door: &str, n: usize) -> String {
    let out = Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", "probe_child", "--nocapture", "--test-threads=1"])
        .env(PROBE, format!("{door}:{n}"))
        .output()
        .expect("child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "urn:plan:{door} with a plan nested {n} deep did not survive a 2 MiB thread: {} - {}",
        out.status,
        stderr
            .lines()
            .find(|l| l.contains("overflow"))
            .unwrap_or(&stderr)
    );
    let at = stdout
        .find("\nOUTCOME ")
        .unwrap_or_else(|| panic!("urn:plan:{door} at {n} reported nothing: {stdout}"));
    stdout[at + "\nOUTCOME ".len()..]
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[test]
fn a_plan_nested_three_thousand_deep_is_refused_at_every_door_and_aborts_nothing() {
    for door in ["validate", "eval", "requires"] {
        let outcome = probe(door, 3000);
        assert!(
            outcome.starts_with("err invalid argument `in`")
                && outcome.contains(&format!("deeper than {BOUND}")),
            "urn:plan:{door}: {outcome}"
        );
    }
}

#[test]
fn a_plan_at_the_bound_is_read_and_one_past_it_is_refused() {
    // At the bound the document parses, and is then refused for what it is (no plan), not
    // for its depth: the guard costs nothing a real plan could carry.
    for door in ["validate", "requires"] {
        let at = issue(door, BOUND);
        if let Err(e) = &at {
            assert!(
                !e.to_string().contains("MAX_RDF_NESTING"),
                "urn:plan:{door} refused a document AT the bound for its depth: {e}"
            );
        }
        let past = issue(door, BOUND + 1)
            .expect_err("one past the bound")
            .to_string();
        assert!(
            past.contains("`in`") && past.contains("MAX_RDF_NESTING"),
            "urn:plan:{door}: {past}"
        );
    }
}
