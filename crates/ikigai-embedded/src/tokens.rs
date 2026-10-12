//! Bearer tokens for the layer host's HTTPS front: a token is bound to ONE enrolled participant.
//!
//! A participant that speaks only HTTP (no QUIC, no client certificate it can present) takes
//! part in layers through the front `serve quic://… --layers-https <addr>` opens beside the
//! QUIC door. It authenticates with `Authorization: Bearer <token>`, and the token names
//! nothing by itself: it is bound to one ENROLLED client, the `clients.json` key (a
//! certificate fingerprint) the participant is enrolled under, and the front mints that
//! client's authority exactly as the QUIC door mints it for the certificate. Same grant, same
//! principal, same ceiling; a token is a second way to present an enrollment, never a second
//! authority.
//!
//! The binding lives in `layer-tokens.json`, beside `clients.json` in the config home:
//!
//! ```json
//! {
//!   "tokens": {
//!     "<lowercase hex SHA-256 of the token>": {
//!       "client": "<the clients.json key it is bound to>",
//!       "label": "relay host",
//!       "created": "2026-10-12T20:00:00Z"
//!     }
//!   }
//! }
//! ```
//!
//! Three properties are load-bearing, and each is the same as `clients.json`'s:
//!
//! - **Stored hashed.** The file holds SHA-256 of each token, never the token: reading the
//!   file does not let anyone present one. The token is printed once, when it is minted.
//! - **Live.** The front reads the file on EVERY request, so removing an entry (or
//!   `ikigai layers-token revoke`) refuses the token's next request; removing the client's
//!   `clients.json` entry refuses it too, because the front mints through the same
//!   enrollment the QUIC door reads.
//! - **Fail closed.** A file that exists and does not parse refuses every token; an absent
//!   file is no tokens at all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The token file's name, in the config home beside `clients.json`.
pub const FILE: &str = "layer-tokens.json";

/// Every token starts with this, so one pasted into a log or a chat is recognizable for
/// what it is, and so a secret scanner can find it.
pub const PREFIX: &str = "iklt_";

/// `<config home>/layer-tokens.json`.
pub fn tokens_path() -> Option<PathBuf> {
    crate::config::config_home().map(|dir| dir.join(FILE))
}

/// One token's binding, as the file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The token's id: the first 12 hex digits of its hash, what `list` shows and `revoke`
    /// takes. Not a secret: it cannot be presented.
    pub id: String,
    /// The `clients.json` key the token is bound to.
    pub client: String,
    /// For humans reading the file and the front's log.
    pub label: String,
    /// When it was minted (RFC 3339, UTC).
    pub created: String,
}

/// The parsed token file: token hash → binding.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tokens {
    by_hash: BTreeMap<String, Binding>,
}

/// How many hex digits of the hash name a token in `list` and `revoke`.
const ID_LEN: usize = 12;

/// Lowercase hex SHA-256 of `token`: what the file keys a token by.
///
/// ```
/// use ikigai_embedded::tokens::hash;
///
/// // SHA-256 of "abc" (FIPS 180-2's first example), as lowercase hex.
/// assert_eq!(hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
/// assert_ne!(hash("iklt_example"), hash("iklt_Example"));
/// ```
pub fn hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Now, as RFC 3339 UTC to the second: what a binding's `created` holds.
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A fresh token: [`PREFIX`] and 32 random bytes as 64 lowercase hex digits.
pub fn generate() -> Result<String, String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| format!("no randomness for a token: {e}"))?;
    Ok(format!(
        "{PREFIX}{}",
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

impl Tokens {
    /// The binding a presented token resolves to, if the file holds its hash.
    pub fn binding_for(&self, token: &str) -> Option<&Binding> {
        self.by_hash.get(&hash(token.trim()))
    }

    /// Every binding, ordered by id.
    pub fn bindings(&self) -> Vec<&Binding> {
        let mut all: Vec<&Binding> = self.by_hash.values().collect();
        all.sort_by(|a, b| a.id.cmp(&b.id));
        all
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Bind `token` to `client`. Refuses a token already in the file (a collision of 32
    /// random bytes is not going to happen, but a re-run of a scripted mint should not
    /// silently rebind one).
    pub fn insert(
        &mut self,
        token: &str,
        client: &str,
        label: &str,
        created: &str,
    ) -> Result<Binding, String> {
        let key = hash(token);
        if self.by_hash.contains_key(&key) {
            return Err("that token is already bound".to_string());
        }
        let binding = Binding {
            id: key[..ID_LEN].to_string(),
            client: client.to_string(),
            label: label.to_string(),
            created: created.to_string(),
        };
        self.by_hash.insert(key, binding.clone());
        Ok(binding)
    }

    /// Remove the token whose id is `id` (or starts with it, at least 8 hex digits, when that
    /// names exactly one). Returns what was removed.
    pub fn revoke(&mut self, id: &str) -> Result<Binding, String> {
        let id = id.trim().to_ascii_lowercase();
        if id.len() < 8 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "`{id}` is not a token id (at least 8 hex digits, as `list` prints them)"
            ));
        }
        let matching: Vec<String> = self
            .by_hash
            .keys()
            .filter(|key| key.starts_with(&id))
            .cloned()
            .collect();
        match matching.as_slice() {
            [one] => Ok(self.by_hash.remove(one).expect("a key just read")),
            [] => Err(format!("no token has the id `{id}`")),
            _ => Err(format!(
                "`{id}` names {} tokens: give more of the id",
                matching.len()
            )),
        }
    }

    /// The file's JSON, pretty-printed and ending in a newline.
    pub fn to_json(&self) -> String {
        let tokens: serde_json::Map<String, serde_json::Value> = self
            .by_hash
            .iter()
            .map(|(key, b)| {
                (
                    key.clone(),
                    serde_json::json!({
                        "client": b.client,
                        "label": b.label,
                        "created": b.created,
                    }),
                )
            })
            .collect();
        let mut text = serde_json::to_string_pretty(&serde_json::json!({ "tokens": tokens }))
            .expect("a JSON object serializes");
        text.push('\n');
        text
    }
}

/// Parse the token file's text. Every unusable entry is an ERROR, never skipped: a binding
/// silently dropped would refuse a participant for a reason nobody can see, and one silently
/// kept with a wrong shape could bind it to something its operator never wrote.
pub fn parse(text: &str) -> Result<Tokens, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let mut by_hash = BTreeMap::new();
    if let Some(map) = v.get("tokens") {
        let map = map
            .as_object()
            .ok_or("`tokens` must be an object of token hash → binding")?;
        for (key, entry) in map {
            let key = key.to_ascii_lowercase();
            if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "`{key}` is not a token hash (64 hex digits): the file holds hashes, never \
                     tokens"
                ));
            }
            let field = |name: &str| entry.get(name).and_then(|v| v.as_str());
            let client = field("client")
                .filter(|c| !c.trim().is_empty())
                .ok_or_else(|| format!("token `{}` names no `client`", &key[..ID_LEN]))?;
            by_hash.insert(
                key.clone(),
                Binding {
                    id: key[..ID_LEN].to_string(),
                    client: client.trim().to_string(),
                    label: field("label").unwrap_or_default().to_string(),
                    created: field("created").unwrap_or_default().to_string(),
                },
            );
        }
    }
    Ok(Tokens { by_hash })
}

/// Read the token file at `path`. Absent is no tokens; present and unusable is an error.
pub fn load_from(path: &Path) -> Result<Tokens, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Tokens::default()),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Write `tokens` to `path`, owner read-write only, replacing the file whole (written beside
/// it and renamed, so a reader never sees half a file).
pub fn save_to(path: &Path, tokens: &Tokens) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let partial = path.with_extension("json.partial");
    std::fs::write(&partial, tokens.to_json())
        .map_err(|e| format!("write {}: {e}", partial.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("restrict {}: {e}", partial.display()))?;
    }
    std::fs::rename(&partial, path).map_err(|e| format!("replace {}: {e}", path.display()))
}

/// The `clients.json` key a mint binds to, from what the operator typed: a key the
/// enrollment holds (a fingerprint, colons and case as `openssl` prints them accepted), or a
/// participant's IRI that exactly ONE enrolled entry names as its `principal`.
pub fn resolve_client(
    enrolment: &crate::clients::Enrolment,
    named: &str,
) -> Result<String, String> {
    if let Some(key) = enrolment.key_for(named) {
        return Ok(key);
    }
    let keys = enrolment.keys_with_principal(named.trim());
    match keys.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!(
            "`{named}` is neither an enrolled fingerprint nor the principal of one: enroll the \
             participant first (`ikigai-layers grants` writes clients.json from enrollment.toml)"
        )),
        _ => Err(format!(
            "`{named}` is the principal of {} enrolled certificates: name the fingerprint the \
             token should present",
            keys.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "6f1c00000000000000000000000000000000000000000000000000000000abcd";

    #[test]
    fn a_token_is_stored_hashed_and_resolves_to_its_binding() {
        let token = generate().unwrap();
        assert!(token.starts_with(PREFIX) && token.len() == PREFIX.len() + 64);
        let mut tokens = Tokens::default();
        let bound = tokens
            .insert(&token, FP, "relay", "2026-10-12T00:00:00Z")
            .unwrap();
        let text = tokens.to_json();
        assert!(!text.contains(&token), "the file never holds the token");
        assert!(text.contains(&hash(&token)));
        let read = parse(&text).unwrap();
        assert_eq!(read.binding_for(&token), Some(&bound));
        assert_eq!(read.binding_for(&generate().unwrap()), None);
        assert!(tokens.insert(&token, FP, "again", "x").is_err());
    }

    #[test]
    fn revoking_by_id_removes_exactly_one() {
        let (a, b) = (generate().unwrap(), generate().unwrap());
        let mut tokens = Tokens::default();
        let first = tokens.insert(&a, FP, "a", "t").unwrap();
        tokens.insert(&b, FP, "b", "t").unwrap();
        assert!(tokens.revoke("abc").is_err(), "too short to be an id");
        assert!(tokens.revoke("not-hex!").is_err());
        assert_eq!(tokens.revoke(&first.id.to_uppercase()).unwrap(), first);
        assert_eq!(tokens.binding_for(&a), None);
        assert!(tokens.binding_for(&b).is_some());
        assert!(tokens.revoke(&first.id).is_err(), "already gone");
    }

    #[test]
    fn an_unusable_file_is_an_error_not_an_empty_one() {
        assert!(parse("{ not json").is_err());
        assert!(parse(r#"{"tokens": []}"#).is_err());
        assert!(
            parse(r#"{"tokens": {"iklt_raw": {"client": "x"}}}"#).is_err(),
            "a raw token in the file is refused: it holds hashes"
        );
        let key = "a".repeat(64);
        assert!(parse(&format!(r#"{{"tokens": {{"{key}": {{"label": "x"}}}}}}"#)).is_err());
        assert!(parse("{}").unwrap().is_empty());
    }

    #[test]
    fn a_mint_binds_by_fingerprint_or_by_a_unique_principal() {
        let other = "b".repeat(64);
        let twice = "c".repeat(64);
        let enrolment = crate::clients::parse(&format!(
            r#"{{"clients": {{
                "{FP}": {{"grant": "relay", "principal": "urn:collab:participant:relay"}},
                "{other}": {{"grant": "bob", "principal": "urn:collab:participant:bob"}},
                "{twice}": {{"grant": "bob", "principal": "urn:collab:participant:bob"}}
            }}}}"#
        ))
        .unwrap();
        assert_eq!(resolve_client(&enrolment, FP).unwrap(), FP);
        let openssl = FP
            .to_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(resolve_client(&enrolment, &openssl).unwrap(), FP);
        assert_eq!(
            resolve_client(&enrolment, "urn:collab:participant:relay").unwrap(),
            FP
        );
        let ambiguous = resolve_client(&enrolment, "urn:collab:participant:bob").unwrap_err();
        assert!(ambiguous.contains("2 enrolled"), "{ambiguous}");
        assert!(resolve_client(&enrolment, "urn:collab:participant:eve").is_err());
    }

    #[test]
    fn save_then_load_round_trips_owner_only() {
        let dir = std::env::temp_dir().join(format!("iki-tokens-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(FILE);
        assert!(load_from(&path).unwrap().is_empty(), "absent is no tokens");
        let mut tokens = Tokens::default();
        tokens
            .insert(&generate().unwrap(), FP, "relay", "t")
            .unwrap();
        save_to(&path, &tokens).unwrap();
        assert_eq!(load_from(&path).unwrap(), tokens);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
