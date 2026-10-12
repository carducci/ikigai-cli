//! Is a name, taken from a request, safe to join under a directory?
//!
//! A host builds file paths from names it did not choose: an IRI segment
//! (`urn:codekey:{file}`), an argument (a tuple id), a name a peer announced on the LAN.
//! Each of those is joined under a directory the host does choose, and the join is only
//! safe if the name stays ONE entry of that directory. Refusing `/` and `..` is enough on
//! Unix and not enough on Windows, where `Path::join` with a name that carries a drive
//! prefix (`C:x`) REPLACES the base instead of extending it, and where the file system
//! quietly rewrites some names into others (ledger #1307). So the rule here is the
//! Windows rule, applied on every platform: a name that is one entry on macOS and a
//! different path on Windows is not a name to build a path from.

use std::path::{Component, Path};

/// Whether `name` is exactly ONE ordinary directory entry on every platform, so
/// `dir.join(name)` names a file inside `dir` and nothing else. Refused:
///
/// - the empty name, `.` and `..`;
/// - any `/`, `\`, `:` or NUL: a separator on some platform, or (`:`) a drive prefix
///   (`C:x`, which `Path::join` on Windows lets replace the base) or an NTFS stream name;
///   so the verbatim and UNC spellings (`\\?\C:\x`, `\\server\share`) are refused too;
/// - a trailing `.` or space, which Windows strips, so `key.` would open `key` and
///   `.. ` would mean `..`;
/// - a Windows reserved device name (`CON`, `NUL`, `COM1`, `LPT1.txt`, any case): on
///   Windows those name a device, not a file in the directory;
/// - anything whose [`Path::components`] on this platform is not exactly one
///   [`Component::Normal`] equal to the name itself.
///
/// It refuses rather than normalizes: a normalized name is a DIFFERENT name, and the
/// caller asked for this one.
///
/// ```
/// use ikigai_resolve::is_plain_file_name;
///
/// assert!(is_plain_file_name("ed25519.pub"));
/// assert!(is_plain_file_name("quic-plasma"));
/// for escape in ["C:x", r"C:\x", r"\\?\C:\x", r"\\server\share", "../x", "a/b", ".."] {
///     assert!(!is_plain_file_name(escape), "{escape}");
/// }
/// assert!(!is_plain_file_name("CON"));
/// assert!(!is_plain_file_name("key."));
/// ```
pub fn is_plain_file_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.contains(['/', '\\', ':', '\0']) {
        return false;
    }
    if name.ends_with(['.', ' ']) {
        return false;
    }
    if is_windows_device_name(name) {
        return false;
    }
    let mut components = Path::new(name).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(only)), None) if only == name
    )
}

/// Whether Windows reads `name` as a DOS device rather than a file: the part before the
/// first `.`, with trailing spaces dropped, is one of the reserved names in any case
/// (`nul`, `Com1.log`, `LPT¹`). `CONIN$` and `CONOUT$` are included, as current Windows
/// treats them the same way.
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => ["COM", "LPT"].iter().any(|port| {
            upper.strip_prefix(port).is_some_and(|n| {
                matches!(
                    n,
                    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names that would leave the directory on Windows, refused on EVERY platform:
    /// this is the test that runs on macOS and Linux, where none of them would escape.
    #[test]
    fn names_that_escape_on_windows_are_refused_everywhere() {
        for name in [
            "C:x",
            "C:",
            r"C:\x",
            "C:/x",
            r"\\?\C:\x",
            r"\\server\share",
            r"\x",
            "/x",
            "..",
            ".",
            "../x",
            r"..\x",
            "a/b",
            r"a\b",
            "",
            "a\0b",
            "key:stream",
            ".. ",
            "...",
            "key.",
            "key ",
        ] {
            assert!(!is_plain_file_name(name), "{name:?} must be refused");
        }
    }

    #[test]
    fn reserved_device_names_are_refused_in_any_case_and_with_an_extension() {
        for name in [
            "CON", "con", "Nul", "nul.txt", "PRN", "AUX", "COM1", "com9.log", "LPT1", "lpt¹",
            "COM0", "CONIN$", "conout$", "NUL .txt",
        ] {
            assert!(!is_plain_file_name(name), "{name:?} must be refused");
        }
    }

    #[test]
    fn ordinary_names_are_plain() {
        for name in [
            "ed25519.pub",
            "quic-plasma",
            "jobs",
            "a..b",
            ".hidden",
            "console",
            "COM10",
            "LPT",
            "nullable.txt",
            "3f2a.tuple",
        ] {
            assert!(is_plain_file_name(name), "{name:?} is one plain entry");
        }
    }

    /// The premise of ledger #1307, observed where it holds: on Windows a drive-prefixed
    /// name REPLACES the base when joined, so the result is not inside the directory.
    /// Runs only on a Windows runner (ci.yml's `windows` job); elsewhere `C:x` is an
    /// ordinary file name and the join stays put.
    #[cfg(windows)]
    #[test]
    fn on_windows_a_drive_prefix_replaces_the_base() {
        let base = Path::new(r"D:\keys");
        for name in ["C:x", r"C:\x", r"\\?\C:\x", r"\\server\share\x"] {
            let joined = base.join(name);
            assert!(
                !joined.starts_with(base),
                "{name:?} joined to {} stayed inside it: {}",
                base.display(),
                joined.display()
            );
            assert!(!is_plain_file_name(name), "{name:?} must be refused");
        }
    }

    /// The other half, on Unix: the same names do NOT escape there, which is exactly why
    /// a Unix-only check (`/` and `..`) passed every test this repo ran.
    #[cfg(unix)]
    #[test]
    fn on_unix_a_drive_prefix_is_an_ordinary_name() {
        let base = Path::new("/keys");
        assert!(base.join("C:x").starts_with(base));
    }
}
