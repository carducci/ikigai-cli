//! The HTTP door's per-source rate limits, read from the config home (ledger #1717).
//!
//! `ikigai serve --http` limits how often ONE client may reach the resources whose every request
//! costs something real: the public intake (each contact or booking submission is an email to a
//! person) and the passkey challenge (each read holds a place in a bounded store). The limits are
//! on by default; `config.toml` changes them:
//!
//! ```toml
//! # <IRI prefix> <requests>/<seconds> — one line per rule; it replaces the default for that prefix
//! http.rate_limit = "urn:contact:submit 5/3600"
//! # `off` drops the rule for that prefix, default or not
//! http.rate_limit = "urn:passkey:challenge off"
//! # how many client windows the door tracks at once (default 4096)
//! http.rate_limit_sources = 8192
//! ```
//!
//! A line that does not parse stops the door at start-up, naming the line; it is never ignored.
use ikigai_web::{SourceLimits, SourceRate, DEFAULT_MAX_SOURCES};
use std::time::Duration;

/// The rule key; it repeats, one line per rule.
pub const RULE_KEY: &str = "http.rate_limit";
/// The table-size key.
pub const SOURCES_KEY: &str = "http.rate_limit_sources";

/// The rules a door runs with when the config home names none, as `(prefix, max, seconds)`.
///
/// - Contact and booking submit: 10 an hour from one client. An honest person submits a form
///   once, perhaps again after a typo or a slot that was taken; ten leaves room for several people
///   behind one address (an office, a carrier's NAT), and still bounds one client to ten emails an
///   hour.
/// - The passkey challenge: 30 per two minutes (its TTL) from one client. One person taps one
///   challenge per decision; 30 is a busy run of decisions. It keeps a single client from filling
///   the challenge store's bound (4096) on its own: that takes over a hundred clients.
pub const DEFAULTS: &[(&str, u32, u64)] = &[
    ("urn:contact:submit", 10, 3600),
    ("urn:booking:submit", 10, 3600),
    ("urn:passkey:challenge", 30, 120),
];

/// Build the door's limits from the `http.rate_limit*` lines of the config home (as
/// `(key, value)`, in file order) over [`DEFAULTS`]. `Ok(None)` when every rule is `off`.
pub fn limits_from(entries: &[(String, String)]) -> Result<Option<SourceLimits>, String> {
    let mut rules: Vec<(String, Option<(u32, u64)>)> = DEFAULTS
        .iter()
        .map(|(prefix, max, secs)| (prefix.to_string(), Some((*max, *secs))))
        .collect();
    let mut named: Vec<String> = Vec::new();
    let mut sources = DEFAULT_MAX_SOURCES;
    let mut sources_seen = false;
    for (key, value) in entries {
        match key.as_str() {
            RULE_KEY => {
                let (prefix, rule) = parse_rule(value)?;
                if named.contains(&prefix) {
                    return Err(format!(
                        "`{RULE_KEY}` names `{prefix}` twice; give each prefix one line"
                    ));
                }
                named.push(prefix.clone());
                match rules.iter_mut().find(|(p, _)| *p == prefix) {
                    Some(slot) => slot.1 = rule,
                    None => rules.push((prefix, rule)),
                }
            }
            SOURCES_KEY => {
                if sources_seen {
                    return Err(format!("`{SOURCES_KEY}` is set twice; set it once"));
                }
                sources_seen = true;
                sources = whole_number(SOURCES_KEY, value)? as usize;
            }
            other => {
                return Err(format!(
                    "`{other}` is not an HTTP rate-limit setting; the keys are `{RULE_KEY}` \
                     and `{SOURCES_KEY}`"
                ))
            }
        }
    }
    let rules: Vec<SourceRate> = rules
        .into_iter()
        .filter_map(|(prefix, rule)| {
            rule.map(|(max, secs)| SourceRate::new(prefix, max, Duration::from_secs(secs)))
        })
        .collect();
    if rules.is_empty() {
        return Ok(None);
    }
    Ok(Some(SourceLimits::new(rules).max_sources(sources)))
}

/// One `http.rate_limit` value: `<prefix> <max>/<seconds>`, or `<prefix> off`.
fn parse_rule(value: &str) -> Result<(String, Option<(u32, u64)>), String> {
    let shape = || {
        format!(
            "`{RULE_KEY} = \"{value}\"` is not `<IRI prefix> <requests>/<seconds>` (or \
             `<IRI prefix> off`), e.g. `urn:contact:submit 10/3600`"
        )
    };
    let mut words = value.split_whitespace();
    let (Some(prefix), Some(rate), None) = (words.next(), words.next(), words.next()) else {
        return Err(shape());
    };
    if !prefix.contains(':') {
        return Err(shape());
    }
    if rate == "off" {
        return Ok((prefix.to_string(), None));
    }
    let (max, secs) = rate.split_once('/').ok_or_else(shape)?;
    let max = whole_number(RULE_KEY, max)?;
    let max =
        u32::try_from(max).map_err(|_| format!("`{RULE_KEY}`: {max} requests is too many"))?;
    let secs = whole_number(RULE_KEY, secs)?;
    Ok((prefix.to_string(), Some((max, secs))))
}

/// A whole number of at least 1, with TOML's `_` separators allowed.
fn whole_number(key: &str, value: &str) -> Result<u64, String> {
    let digits: String = value.chars().filter(|c| *c != '_').collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("`{key}`: `{value}` is not a whole number"));
    }
    match digits.parse::<u64>() {
        Ok(0) => Err(format!(
            "`{key}`: `{value}`: the least it can be is 1 (use `off` to drop a rule)"
        )),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("`{key}`: `{value}` is too large")),
    }
}

/// The banner's words for `limits`: each rule as `<prefix> <max>/<seconds>s`.
pub fn describe(limits: Option<&SourceLimits>) -> String {
    match limits {
        None => "no rate limits".to_string(),
        Some(limits) => {
            let mut rules: Vec<String> = limits
                .rules()
                .iter()
                .map(|r| format!("{} {}/{}s", r.prefix, r.max, r.window.as_secs()))
                .collect();
            rules.sort();
            format!("rate limits per client: {}", rules.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn rules(limits: &SourceLimits) -> Vec<(String, u32, u64)> {
        let mut out: Vec<_> = limits
            .rules()
            .iter()
            .map(|r| (r.prefix.clone(), r.max, r.window.as_secs()))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn with_nothing_configured_the_intake_and_the_challenge_are_limited() {
        let limits = limits_from(&[]).unwrap().expect("on by default");
        assert_eq!(
            rules(&limits),
            vec![
                ("urn:booking:submit".to_string(), 10, 3600),
                ("urn:contact:submit".to_string(), 10, 3600),
                ("urn:passkey:challenge".to_string(), 30, 120),
            ]
        );
        assert_eq!(
            describe(Some(&limits)),
            "rate limits per client: urn:booking:submit 10/3600s, urn:contact:submit 10/3600s, \
             urn:passkey:challenge 30/120s"
        );
    }

    #[test]
    fn a_line_replaces_its_prefixs_default_adds_a_rule_or_turns_one_off() {
        let limits = limits_from(&entries(&[
            ("http.rate_limit", "urn:contact:submit 5/600"),
            ("http.rate_limit", "urn:passkey:challenge off"),
            ("http.rate_limit", "urn:calendar-request: 20/60"),
            ("http.rate_limit_sources", "8_192"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(
            rules(&limits),
            vec![
                ("urn:booking:submit".to_string(), 10, 3600),
                ("urn:calendar-request:".to_string(), 20, 60),
                ("urn:contact:submit".to_string(), 5, 600),
            ]
        );
    }

    #[test]
    fn every_rule_off_is_no_limits() {
        let off = limits_from(&entries(&[
            ("http.rate_limit", "urn:contact:submit off"),
            ("http.rate_limit", "urn:booking:submit off"),
            ("http.rate_limit", "urn:passkey:challenge off"),
        ]))
        .unwrap();
        assert!(off.is_none());
        assert_eq!(describe(None), "no rate limits");
    }

    #[test]
    fn a_line_that_does_not_parse_is_refused_naming_it() {
        for (key, value, says) in [
            (
                "http.rate_limit",
                "urn:contact:submit",
                "is not `<IRI prefix>",
            ),
            (
                "http.rate_limit",
                "urn:contact:submit 10",
                "is not `<IRI prefix>",
            ),
            (
                "http.rate_limit",
                "urn:contact:submit 10/3600 extra",
                "is not `<IRI prefix>",
            ),
            ("http.rate_limit", "contact 10/3600", "is not `<IRI prefix>"),
            (
                "http.rate_limit",
                "urn:contact:submit 0/3600",
                "the least it can be is 1",
            ),
            (
                "http.rate_limit",
                "urn:contact:submit 10/0",
                "the least it can be is 1",
            ),
            (
                "http.rate_limit",
                "urn:contact:submit ten/3600",
                "is not a whole number",
            ),
            ("http.rate_limit_sources", "0", "the least it can be is 1"),
            (
                "http.rate_limits",
                "urn:x 1/1",
                "is not an HTTP rate-limit setting",
            ),
        ] {
            let err = limits_from(&entries(&[(key, value)]))
                .err()
                .unwrap_or_else(|| panic!("`{key} = {value}` must be refused"));
            assert!(err.contains(says), "`{key} = {value}`: {err}");
        }
        let twice = limits_from(&entries(&[
            ("http.rate_limit", "urn:contact:submit 1/1"),
            ("http.rate_limit", "urn:contact:submit 2/2"),
        ]))
        .err()
        .unwrap();
        assert!(twice.contains("twice"), "{twice}");
    }
}
