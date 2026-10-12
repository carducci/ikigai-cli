//! A leading `~` in a path a person typed: the one expansion rule for the workspace.
//!
//! A config file is hand-written, and `~` is what a person types, so every config-home key
//! that names a path (a `mount` line's socket and certificate directory, `files`,
//! `layers.state`, `arrangement`, `browse.root`, `browse.store`) and the directory flags
//! (`--config-home`, `--files`) expand it the same way. Before ledger #1379 there were seven
//! copies of this rule, each a little different, and the `mount` line's socket had none at
//! all: `mount = "prefer urn:x:=~/x.sock"` dialed the literal path `~/x.sock`.

use std::path::{is_separator, Path, PathBuf};

/// `value` with a leading `~` expanded against `home`, the current user's home directory.
///
/// - `~` alone is `home`;
/// - `~/rest` is `home/rest` (on Windows `~\rest` too: a separator of the platform);
/// - anything that does not begin with `~` is returned unchanged.
///
/// Two spellings are REFUSED rather than passed through, because either one would otherwise
/// name a path nobody meant, and the failure would surface later and somewhere else (a dial
/// of the literal `~/x.sock`, a directory created under the working directory):
///
/// - `~name/…`, another user's home: only the current user's home is expanded, so write the
///   path out in full;
/// - a leading `~` when `home` is `None` or empty: there is no home to expand it against.
///
/// The home is a parameter rather than a `$HOME` read: the environment is process-global,
/// and a test that redirects it races every other test that reads it. The caller reads it
/// once, at the top of its call chain.
///
/// ```
/// use std::path::{Path, PathBuf};
/// use ikigai_resolve::expand_home;
///
/// let home = Some(Path::new("/home/b"));
/// assert_eq!(expand_home("~", home), Ok(PathBuf::from("/home/b")));
/// assert_eq!(expand_home("~/x.sock", home), Ok(PathBuf::from("/home/b/x.sock")));
/// assert_eq!(expand_home("/srv/x.sock", home), Ok(PathBuf::from("/srv/x.sock")));
/// assert_eq!(expand_home("quic://plasma:4433", home), Ok(PathBuf::from("quic://plasma:4433")));
/// assert!(expand_home("~bob/x.sock", home).unwrap_err().contains("another user's home"));
/// assert!(expand_home("~/x.sock", None).unwrap_err().contains("HOME is not set"));
/// ```
pub fn expand_home(value: &str, home: Option<&Path>) -> Result<PathBuf, String> {
    let Some(rest) = value.strip_prefix('~') else {
        return Ok(PathBuf::from(value));
    };
    if !rest.is_empty() && !rest.starts_with(is_separator) {
        let user = rest.split(is_separator).next().unwrap_or(rest);
        return Err(format!(
            "`{value}` names another user's home (`~{user}`); only `~` and `~/…`, the current \
             user's home, are expanded, so write the path out in full"
        ));
    }
    let home = home
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "`{value}` begins with `~` and HOME is not set, so there is no home to expand it \
             against: set HOME or write the path out in full"
            )
        })?;
    // Every leading separator goes: `home.join("/x")` would REPLACE the home with `/x`, so
    // `~//x` must mean `~/x`, not `/x`.
    let rest = rest.trim_start_matches(is_separator);
    Ok(if rest.is_empty() {
        home.to_path_buf()
    } else {
        home.join(rest)
    })
}

/// [`expand_home`] for a value that must stay a `String` (a mount target, which is also
/// shown back to the operator). A home that is not valid UTF-8 is refused by name rather
/// than replaced lossily, since the lossy spelling names a different path.
pub fn expand_home_str(value: &str, home: Option<&Path>) -> Result<String, String> {
    let expanded = expand_home(value, home)?;
    expanded.into_os_string().into_string().map_err(|path| {
        format!(
            "`{value}` expands to `{}`, which is not valid UTF-8; write the path out in full",
            Path::new(&path).display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/b";

    fn home() -> Option<&'static Path> {
        Some(Path::new(HOME))
    }

    #[test]
    fn a_bare_tilde_is_the_home() {
        assert_eq!(expand_home("~", home()), Ok(PathBuf::from(HOME)));
        assert_eq!(expand_home("~/", home()), Ok(PathBuf::from(HOME)));
    }

    #[test]
    fn a_tilde_slash_path_lands_under_the_home() {
        assert_eq!(
            expand_home("~/.ikigai/gonk.sock", home()),
            Ok(PathBuf::from("/home/b/.ikigai/gonk.sock"))
        );
    }

    #[test]
    fn repeated_separators_never_replace_the_home() {
        assert_eq!(
            expand_home("~//x.sock", home()),
            Ok(PathBuf::from("/home/b/x.sock"))
        );
    }

    #[test]
    fn a_value_without_a_leading_tilde_is_unchanged() {
        for value in [
            "/srv/x.sock",
            "relative/dir",
            "quic://bug.local:4433",
            "peer:plasma",
            "a~b",
            "./~",
            "",
        ] {
            assert_eq!(
                expand_home(value, home()),
                Ok(PathBuf::from(value)),
                "{value}"
            );
            assert_eq!(
                expand_home(value, None),
                Ok(PathBuf::from(value)),
                "{value}"
            );
        }
    }

    #[test]
    fn another_users_home_is_refused_by_name() {
        let err = expand_home("~bob/x.sock", home()).unwrap_err();
        assert!(err.contains("`~bob`"), "{err}");
        assert!(err.contains("another user's home"), "{err}");
        let err = expand_home("~bob", home()).unwrap_err();
        assert!(err.contains("`~bob`"), "{err}");
    }

    #[test]
    fn no_home_refuses_rather_than_passing_the_tilde_through() {
        for home in [None, Some(Path::new(""))] {
            for value in ["~", "~/x.sock"] {
                let err = expand_home(value, home).unwrap_err();
                assert!(err.contains("HOME is not set"), "{value}: {err}");
                assert!(err.contains(value), "{value}: {err}");
            }
        }
    }

    #[test]
    fn the_string_form_matches_the_path_form() {
        let expected = Path::new(HOME).join("x.sock");
        assert_eq!(
            expand_home_str("~/x.sock", home()),
            Ok(expected.to_str().unwrap().to_string())
        );
        assert!(expand_home_str("~bob", home()).is_err());
    }

    /// A separator of the PLATFORM ends the `~`: `~\x` is the home on Windows, where a
    /// person types it, and on Unix, where `\` is an ordinary byte, it names a user.
    #[test]
    fn a_backslash_after_the_tilde_follows_the_platform() {
        let expanded = expand_home(r"~\x.sock", home());
        if cfg!(windows) {
            assert_eq!(expanded, Ok(Path::new(HOME).join("x.sock")));
        } else {
            assert!(expanded.unwrap_err().contains("another user's home"));
        }
    }
}
