//! Post/Redirect/Get for the emailed decision pages (ledger #1879).
//!
//! A decision page (`/calendar-request/{action}`, `/contact-block`, `/contact-label`) is a GET
//! that shows what a signed link would do and a form that POSTs it back. The POST used to answer
//! with the result page itself, so a phone that restored the tab later restored a POST, and the
//! browser asked to send it again. Now every decision POST answers `303 See Other` to a GET of
//! the same page with `?outcome=<word>`, and that GET renders the outcome. Two rules hold it:
//!
//! - **No personal data in the URL.** The redirect carries one word from a closed set (and the
//!   path the door routed the POST to, which the browser already had); never the address, the
//!   decision's token, or an enquiry id. A browser shows, keeps and may sync that URL. The
//!   outcome page is therefore generic: it says what happened, not to whom.
//! - **A decision acts once.** The same signed link POSTed twice (a double tap, a "post again"
//!   on an older browser, a replayed request) records its intent once; the second answers
//!   `?outcome=already`. What is remembered is the link's token, which is a signature only the
//!   minting host can make, so only links that host minted ever enter the memory, and each is
//!   forgotten when its link expires (seven days at most).
//!
//! ⚠ The memory is this PROCESS's: a restart forgets it, and a link POSTed again after one acts
//! again. Downstream that is harmless for a booking (the Mac's `confirm` takes the pending tuple,
//! so a second decision finds nothing) and for a block (the blocklist is a set); a label is
//! trained a second time, which the opposite click or an `untrain` undoes.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use ikigai_core::{Error, ReprType, Representation, Result};

/// The media type of an ikigai-web entity envelope (`ikigai_web::HTTP_ENTITY`): header lines,
/// an empty line, then the content. Written by hand because this crate does not link the door;
/// the envelope is a documented byte format any language writes, and
/// `crates/ikigai-cli/tests/decision_prg.rs` drives it through the real door.
pub(crate) const HTTP_ENTITY: &str = "application/vnd.ikigai.http-entity";

/// The query name the outcome rides in.
pub(crate) const OUTCOME: &str = "outcome";

/// The outcome word for a POST that found its decision already made.
pub(crate) const ALREADY: &str = "already";

/// The most decisions remembered at once. Only links the minting host signed can enter, and
/// each leaves when it expires, so this is far past any real week of email; it exists so the
/// memory has a stated bound. Past it a decision is REFUSED (`503`, try again later), never
/// acted on unremembered, which would let a replay act twice.
const MAX_REMEMBERED: usize = 4096;

/// The decisions already acted on, each with its link's expiry (unix seconds), keyed by the
/// endpoint, the verifying key its links are checked against, and the link's token. The key
/// file is part of the name because a token means something only under the key that verifies
/// it: two endpoints over two keys (as tests build) never share a memory.
fn acted() -> &'static Mutex<HashMap<String, i64>> {
    static ACTED: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    ACTED.get_or_init(Default::default)
}

/// Claim the decision `token` (a link valid until `exp`, verified against the key at `key`) at
/// the endpoint `scope` for acting on now: `Ok(true)`
/// the first time, `Ok(false)` when it was claimed before. The claim is taken BEFORE the action
/// so two POSTs racing each other cannot both act; [`release`] gives it back when the action
/// fails, so a failed attempt can be retried.
pub(crate) fn claim(scope: &str, key: &Path, token: &str, exp: i64, now: i64) -> Result<bool> {
    let mut acted = acted().lock().unwrap_or_else(|e| e.into_inner());
    acted.retain(|_, until| *until > now);
    let key = name(scope, key, token);
    if acted.contains_key(&key) {
        return Ok(false);
    }
    if acted.len() >= MAX_REMEMBERED {
        return Err(Error::Unavailable(format!(
            "{MAX_REMEMBERED} decisions are remembered and none has expired; try again later"
        )));
    }
    acted.insert(key, exp);
    Ok(true)
}

/// Give back a claim whose action failed (see [`claim`]).
pub(crate) fn release(scope: &str, key: &Path, token: &str) {
    let mut acted = acted().lock().unwrap_or_else(|e| e.into_inner());
    acted.remove(&name(scope, key, token));
}

/// What a decision is remembered by (see [`acted`]).
fn name(scope: &str, key: &Path, token: &str) -> String {
    format!("{scope}|{}|{token}", key.display())
}

/// The answer to a decision POST: `303 See Other` to this same page with `?outcome=<word>`, with
/// `page` as the body for a client that does not follow it. `word` is one of the endpoint's own
/// literals, so the Location is fixed text: no value from the request reaches it.
pub(crate) fn see_other(word: &'static str, page: Representation) -> Representation {
    debug_assert!(word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
    let mut bytes = format!(
        "Content-Type: {}\r\nLocation: ?{OUTCOME}={word}\r\n\r\n",
        page.repr_type
    )
    .into_bytes();
    bytes.extend_from_slice(&page.bytes);
    Representation::new(ReprType::new(HTTP_ENTITY), bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decision_is_claimed_once_until_its_link_expires() {
        let (token, key) = ("prg-test-token-once", Path::new("/k/once.pub"));
        assert!(claim("t", key, token, 200, 100).unwrap());
        assert!(
            !claim("t", key, token, 200, 150).unwrap(),
            "the replay finds it"
        );
        assert!(
            claim("other", key, token, 200, 150).unwrap(),
            "scoped by endpoint"
        );
        assert!(
            claim("t", Path::new("/k/other.pub"), token, 200, 150).unwrap(),
            "scoped by verifying key"
        );
        assert!(
            claim("t", key, token, 300, 250).unwrap(),
            "forgotten once expired"
        );
    }

    #[test]
    fn a_released_claim_can_be_taken_again() {
        let (token, key) = ("prg-test-token-release", Path::new("/k/release.pub"));
        assert!(claim("t", key, token, i64::MAX, 0).unwrap());
        release("t", key, token);
        assert!(claim("t", key, token, i64::MAX, 0).unwrap());
    }

    #[test]
    fn see_other_wraps_the_page_with_a_fixed_location() {
        let page = Representation::new(
            ReprType::new("text/html").with_param("charset", "utf-8"),
            b"<p>x</p>".to_vec(),
        );
        let answer = see_other("recorded", page);
        assert_eq!(answer.repr_type.to_string(), HTTP_ENTITY);
        assert_eq!(
            answer.bytes,
            b"Content-Type: text/html;charset=utf-8\r\nLocation: ?outcome=recorded\r\n\r\n<p>x</p>"
        );
    }
}
