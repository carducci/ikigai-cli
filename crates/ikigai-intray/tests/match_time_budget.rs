//! A `match=` template runs within a TIME budget, on both doors that take one (ledger #1327).
//!
//! The claim (the ikigai-layers audit, ikigai-rs/ikigai-layers PR 10): `match=` is caller
//! SPARQL, bounded by size (1 MiB), nesting (64) and a sized stack, never by time, so a
//! ~300-byte template holds a thread for minutes per pending tuple, and anyone holding read on
//! a space can send one.
//!
//! Reproduced on cli main fa74229 (ikigai-store 0.2.15, debug build), one 7-triple tuple, the
//! audit's shape ([`template`]), through `rd match=`:
//!
//! | k | bytes | answer | time |
//! | --- | --- | --- | --- |
//! | 4 | 208 | `Ok`, no hits | 13 ms |
//! | 5 | 252 | `Ok`, no hits | 89 ms |
//! | 6 | 296 | `Ok`, no hits | 0.74 s |
//! | 7 | 340 | `Ok`, no hits | 9.0 s |
//!
//! Nothing refused it; each pattern multiplied the cost by about 10. The fix runs every match
//! inside `ikigai_store::EvaluationBudget::run` (one per mounted space, cloned): the caller is
//! answered with a typed `Timeout` at the budget, the evaluation gets the cancellation token,
//! what still runs is counted and capped, and the store's algebra bounds apply first.

mod common;

use common::{drop_tuple, iri, scratch};
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Error, Kernel, Request, Verb};
use ikigai_intray::{space, space_with_budget, CAP_OUT, CAP_READ, CAP_TAKE};
use ikigai_store::budget::{cap_budget, EvaluationBudget, TimeBudget};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A tuple of 7 triples, the size the audit measured on.
fn tuple_turtle() -> Vec<u8> {
    (0..7)
        .map(|i| format!("<urn:t:s> <urn:t:p{i}> \"v{i}\" .\n"))
        .collect::<String>()
        .into_bytes()
}

/// The audit's shape: `k` unconstrained triple patterns (a cross product, |tuple|^k rows) and
/// one FILTER over every variable, so nothing is pushed into a pattern and the ASK can never
/// stop early. `ikigai-store`'s `tests/match_time_budget.rs` measures the same template.
fn template(k: usize) -> String {
    let patterns: String = (0..k).map(|i| format!("?s{i} ?p{i} ?o{i} . ")).collect();
    let all: Vec<String> = (0..k)
        .map(|i| format!("STR(?s{i}), STR(?p{i}), STR(?o{i})"))
        .collect();
    format!(
        "ASK {{ {patterns}FILTER(CONCAT({}) = \"never\") }}",
        all.join(", ")
    )
}

/// Wall time, for measuring how long a caller waited. Native-only: this test binary never
/// builds for wasm, and a budget is measured in real time, not a kernel `Clock`'s.
#[allow(clippy::disallowed_methods)]
fn now() -> Instant {
    Instant::now()
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A kernel over a fresh space `urn:space:q` holding the 7-triple tuple, its matches within
/// `budget`. Returns the kernel and the tuple's id.
fn seeded(sub: &str, budget: EvaluationBudget) -> (Kernel, String) {
    let k = Kernel::new(Arc::new(space_with_budget(scratch(sub), budget)));
    let id = drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:q",
        &tuple_turtle(),
    )
    .expect("dropping the tuple");
    (k, id)
}

/// One `match=` request: `rd` (Source, read) or `take` (Delete, take).
fn matching(k: &Kernel, door: &str, cap: &[String], text: &str) -> Result<String, Error> {
    let verb = match door {
        "rd" => Verb::Source,
        "take" => Verb::Delete,
        other => panic!("unknown door {other}"),
    };
    block_on(
        k.issue(
            Request::new(verb, iri("urn:space:q"))
                .with_arg("match", ArgRef::Inline(text.as_bytes().to_vec())),
            &Capability::scoped(cap.to_vec()),
        ),
    )
    .map(|r| String::from_utf8_lossy(&r.bytes).into_owned())
}

fn reader() -> Vec<String> {
    vec![CAP_READ.to_string()]
}

fn taker() -> Vec<String> {
    vec![CAP_TAKE.to_string()]
}

fn assert_timeout(result: Result<String, Error>, budget_ms: u64) {
    match result {
        Err(Error::Timeout(message)) => assert!(
            message.contains(&format!("{budget_ms} ms")),
            "the refusal names the budget: {message}"
        ),
        other => panic!("expected a Timeout naming {budget_ms} ms, got {other:?}"),
    }
}

/// Wait (bounded) until no evaluation is overdue, and say how long that took.
fn settles(budget: &EvaluationBudget) -> Duration {
    let start = now();
    while budget.overdue_evaluations() != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "an overdue evaluation was still running after 120 s"
        );
        std::thread::sleep(ms(20));
    }
    start.elapsed()
}

/// The ids still pending in `urn:space:q`.
fn pending(k: &Kernel) -> String {
    let listed = block_on(k.issue(
        Request::new(Verb::Source, iri("urn:space:q")),
        &Capability::scoped([CAP_READ]),
    ))
    .expect("listing the space");
    String::from_utf8(listed.bytes).unwrap()
}

#[test]
fn rd_match_is_answered_at_its_budget_and_the_worker_is_counted_until_it_ends() {
    let budget = EvaluationBudget::new(TimeBudget::new(ms(50)));
    let (k, _) = seeded("budget-rd", budget.clone());
    let start = now();
    assert_timeout(matching(&k, "rd", &reader(), &template(6)), 50);
    let answered = start.elapsed();
    // Before: 0.74 s at k=6 and 9 s at k=7, answered `Ok` whatever it cost.
    assert!(answered < ms(1_050), "answered after {answered:?}");
    // The budget the space was mounted with is the one the request ran under: its count saw
    // the abandoned worker (or the worker already stopped at the token).
    let ended = settles(&budget);
    eprintln!("rd: answered after {answered:?}; the worker ended {ended:?} later");
}

#[test]
fn take_match_is_answered_at_its_budget_and_consumes_nothing() {
    let budget = EvaluationBudget::new(TimeBudget::new(ms(50)));
    let (k, id) = seeded("budget-take", budget.clone());
    let start = now();
    assert_timeout(matching(&k, "take", &taker(), &template(6)), 50);
    assert!(
        start.elapsed() < ms(1_050),
        "answered after {:?}",
        start.elapsed()
    );
    // The scan decides which tuple matches; the claim is made only after the budget answered.
    // So a take its caller was told timed out takes nothing, then or after the worker ends.
    settles(&budget);
    assert_eq!(pending(&k), id, "the tuple is still pending");
}

#[test]
fn at_the_overdue_cap_a_new_match_is_refused_at_once_until_one_ends() {
    let budget = EvaluationBudget::new(TimeBudget::new(ms(50)).with_max_overdue(1));
    let (k, _) = seeded("budget-cap", budget.clone());
    assert_timeout(matching(&k, "rd", &reader(), &template(7)), 50);
    // The worker outlived its caller: oxigraph checks the token only where it touches the
    // dataset, and k=7 spends its time in a cross product already in memory (the store
    // measured it stopping ~0.9 s after a 50 ms token, debug).
    assert_eq!(
        budget.overdue_evaluations(),
        1,
        "the abandoned worker is counted"
    );
    let start = now();
    match matching(&k, "rd", &reader(), &template(2)) {
        Err(Error::Unavailable(message)) => assert!(
            message.contains("the most it allows is 1"),
            "the refusal says why: {message}"
        ),
        other => panic!("expected Unavailable at the cap, got {other:?}"),
    }
    assert!(start.elapsed() < ms(50), "refused at once");
    let ended = settles(&budget);
    eprintln!("cap: the overdue k=7 worker ended {ended:?} after the refusal");
    assert_eq!(
        matching(&k, "rd", &reader(), &template(2)),
        Ok(String::new())
    );
}

#[test]
fn a_budget_grant_raises_the_base_and_a_legitimate_match_still_answers() {
    let budget = EvaluationBudget::new(TimeBudget::new(ms(1)));
    let (k, id) = seeded("budget-grant", budget.clone());
    // 1 ms is too little for a k=5 cross product (~90 ms, debug) …
    assert_timeout(matching(&k, "rd", &reader(), &template(5)), 1);
    // … and a `urn:cap:store:budget:<ms>` grant raises it, as at the store's own doors.
    let granted = vec![CAP_READ.to_string(), cap_budget(30_000)];
    let matches = "ASK { ?s <urn:t:p3> \"v3\" }";
    assert_eq!(matching(&k, "rd", &granted, matches), Ok(id.clone()));
    assert_eq!(
        matching(&k, "rd", &granted, "ASK { ?s <urn:t:p3> \"no\" }"),
        Ok(String::new())
    );
    let granted_taker = vec![CAP_TAKE.to_string(), cap_budget(30_000)];
    let taken = matching(&k, "take", &granted_taker, matches).expect("taking by template");
    assert_eq!(taken.into_bytes(), tuple_turtle());
    assert_eq!(pending(&k), "", "the take consumed it");
    settles(&budget);
}

#[test]
fn the_default_mount_answers_a_legitimate_match_on_both_doors() {
    let k = Kernel::new(Arc::new(space(scratch("budget-default"))));
    let id = drop_tuple(
        &k,
        &Capability::scoped([CAP_OUT]),
        "urn:space:q",
        &tuple_turtle(),
    )
    .unwrap();
    let matches = "ASK { ?s <urn:t:p3> \"v3\" }";
    assert_eq!(matching(&k, "rd", &reader(), matches), Ok(id));
    assert_eq!(
        matching(&k, "rd", &reader(), &template(3)),
        Ok(String::new())
    );
    assert!(matches!(
        matching(&k, "take", &taker(), &template(3)),
        Err(Error::NotFound(_))
    ));
    let taken = matching(&k, "take", &taker(), matches).expect("taking by template");
    assert_eq!(taken.into_bytes(), tuple_turtle());
}

#[test]
fn the_algebra_bounds_refuse_before_anything_runs_on_both_doors() {
    // 33 operands in one join: the planner's cost, which no token reaches, so it is refused
    // as `InvalidArgument` on `match` rather than timed out.
    let wide: String = (0..33).map(|i| format!("?s <urn:p{i}> ?o{i} . ")).collect();
    let text = format!("ASK {{ {wide}}}");
    let (k, id) = seeded("budget-algebra", EvaluationBudget::default());
    for (door, cap) in [("rd", reader()), ("take", taker())] {
        match matching(&k, door, &cap, &text) {
            Err(Error::InvalidArgument { name, detail }) => {
                assert_eq!(name, "match", "{door}: {detail}")
            }
            other => panic!("{door}: expected InvalidArgument on match, got {other:?}"),
        }
    }
    assert_eq!(pending(&k), id);
}
