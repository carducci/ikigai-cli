//! What an accept error means for the loop that saw it (ledger #720).
//!
//! The door used to `accept().await?`, so ANY accept error — one `EMFILE` under a 256-descriptor
//! launchd limit — returned from the serve loop and took the host down with it. Accept errors
//! are not one thing, and only one kind of them says the listener is finished:
//!
//! - **Per-connection** ([`Fault::Skip`]): the failure belongs to one would-be connection — it
//!   was aborted or reset before we took it, or Linux handed us a network error that was
//!   pending on it (`accept(2)`: "treat them like EAGAIN by retrying"). Take the next one at
//!   once. Not logged: a client can cause these at will, so logging each one is a log-flooding
//!   lever handed to anyone who can reach the port.
//! - **Exhaustion** ([`Fault::BackOff`]): the process or the system is out of something
//!   (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`). The connection is still in the backlog and
//!   retrying immediately fails again, so wait — bounded, doubling from 10ms to 1s — and
//!   retry. Anything this table does not recognize is treated the same way: a door that keeps
//!   trying, and says so, beats a door that exits on an errno nobody anticipated.
//! - **Fatal** ([`Fault::Fatal`]): the listener itself is unusable (`EBADF`, `ENOTSOCK`,
//!   `EINVAL` — not listening, `EFAULT`). Retrying would back off forever against a dead
//!   socket and hide that the door is gone, so these alone end `serve`.
//!
//! The reference is axum's `serve` (`axum/src/serve/listener.rs`): connection
//! refused/aborted/reset are skipped silently; every other error is logged and followed by a
//! flat one-second sleep, and nothing ends the loop. This matches its skip set and its
//! one-second ceiling, and differs on purpose in three places: the backoff starts at 10ms so a
//! brief spike costs milliseconds rather than a second; an episode is logged once at its start
//! and once at its end rather than once per retry; and a dead listener ends the loop instead
//! of sleeping on it forever.
//!
//! ⚠ `ikigai-ipc` carries a twin of this table for the socket door (a synchronous loop, so the
//! wait is a thread sleep there). Change both or neither.

use std::io;
use std::time::Duration;

/// Write one diagnostic line to stderr, and DROP it if stderr cannot take it (ledger #1217).
///
/// The twin of `ikigai-cli`'s in-service `diagnose` (ledger #1208). `eprintln!` PANICS when
/// the write fails, and a door's stderr is whatever its supervisor handed it: under a harness
/// that stopped reading, a pipe whose read end has closed (EPIPE; Rust ignores SIGPIPE, so the
/// write returns the error). These lines are written by the accept loop itself, so the panic
/// would end the serve loop and with it the whole HTTP door, for a log line nobody was
/// reading. A diagnostic that cannot be written is lost; the door is not.
fn diagnose(line: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(io::stderr().lock(), "{line}");
}

/// The first wait after an exhaustion error.
pub(crate) const BACKOFF_FLOOR: Duration = Duration::from_millis(10);
/// The longest wait between retries during one exhaustion episode.
pub(crate) const BACKOFF_CEILING: Duration = Duration::from_secs(1);

/// What the accept loop does about one error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// One connection's problem: take the next connection at once.
    Skip,
    /// Out of a resource, or unrecognized: wait, then retry.
    BackOff,
    /// The listener cannot accept again: end the loop with this error.
    Fatal,
}

/// Classify one accept error. See the module docs for the table and why.
pub(crate) fn classify(e: &io::Error) -> Fault {
    #[cfg(unix)]
    if let Some(code) = e.raw_os_error() {
        return match code {
            libc::EBADF | libc::ENOTSOCK | libc::EINVAL | libc::EFAULT => Fault::Fatal,
            libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM => Fault::BackOff,
            libc::ECONNABORTED
            | libc::ECONNRESET
            | libc::ECONNREFUSED
            | libc::EINTR
            | libc::EAGAIN
            | libc::EPROTO
            | libc::EPERM
            | libc::ETIMEDOUT
            | libc::ENETDOWN
            | libc::ENETUNREACH
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::ENOPROTOOPT
            | libc::EOPNOTSUPP => Fault::Skip,
            _ => Fault::BackOff,
        };
    }
    match e.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => Fault::Skip,
        _ => Fault::BackOff,
    }
}

/// One exhaustion episode's state: the next wait, and what to say when it ends.
///
/// An episode starts at the first [`Fault::BackOff`] after a success and ends at the next
/// successful accept. It logs exactly twice — at its start and at its end — however many
/// retries it takes, so the log says THAT the door struggled and for how long, not every
/// attempt.
#[derive(Debug, Default)]
pub(crate) struct Backoff {
    /// The next wait; `None` outside an episode.
    next: Option<Duration>,
    /// Failed accepts in this episode.
    failures: u32,
    /// Total time waited in this episode (summed waits, not a clock reading).
    waited: Duration,
}

impl Backoff {
    /// Record an exhaustion error and return how long to wait before retrying.
    pub(crate) fn failed(&mut self, e: &io::Error) -> Duration {
        let wait = match self.next {
            None => {
                diagnose(format_args!(
                    "ikigai-web: accept failing ({e}); backing off up to {}ms and retrying",
                    BACKOFF_CEILING.as_millis()
                ));
                BACKOFF_FLOOR
            }
            Some(wait) => wait,
        };
        self.next = Some((wait * 2).min(BACKOFF_CEILING));
        self.failures += 1;
        self.waited += wait;
        wait
    }

    /// Record a successful accept, closing the episode if one was open.
    pub(crate) fn succeeded(&mut self) {
        if self.next.take().is_some() {
            diagnose(format_args!(
                "ikigai-web: accept recovered after {} failed attempts (~{}ms backed off)",
                self.failures,
                self.waited.as_millis()
            ));
            self.failures = 0;
            self.waited = Duration::ZERO;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn exhaustion_backs_off_a_dead_listener_is_fatal_one_connection_is_skipped() {
        let os = io::Error::from_raw_os_error;
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(classify(&os(code)), Fault::BackOff, "errno {code}");
        }
        for code in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EFAULT] {
            assert_eq!(classify(&os(code)), Fault::Fatal, "errno {code}");
        }
        for code in [
            libc::ECONNABORTED,
            libc::ECONNRESET,
            libc::EPROTO,
            libc::EINTR,
            libc::ENETUNREACH,
        ] {
            assert_eq!(classify(&os(code)), Fault::Skip, "errno {code}");
        }
        // An errno nobody listed keeps the door trying rather than ending it.
        assert_eq!(classify(&os(libc::EIO)), Fault::BackOff);
    }

    #[test]
    fn an_error_without_an_errno_is_classified_by_kind() {
        let kind = |k| io::Error::new(k, "synthetic");
        assert_eq!(
            classify(&kind(io::ErrorKind::ConnectionAborted)),
            Fault::Skip
        );
        assert_eq!(classify(&kind(io::ErrorKind::Other)), Fault::BackOff);
    }

    #[test]
    fn the_backoff_doubles_from_the_floor_to_the_ceiling_and_resets_on_success() {
        let e = io::Error::other("exhausted");
        let mut backoff = Backoff::default();
        let waits: Vec<u128> = (0..10).map(|_| backoff.failed(&e).as_millis()).collect();
        assert_eq!(waits, [10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000]);
        backoff.succeeded();
        assert_eq!(
            backoff.failed(&e),
            BACKOFF_FLOOR,
            "a new episode starts at the floor"
        );
    }

    /// Set in the child [`an_exhaustion_episode_survives_a_closed_stderr`] spawns.
    const CLOSED_STDERR_CHILD: &str = "IKIGAI_WEB_TEST_CLOSED_STDERR_CHILD";
    /// What the child prints once both episode lines were written, so a child that ran no
    /// test (a filter that matched nothing) cannot pass for one that survived.
    const SURVIVED: &str = "ikigai-web-accept-survived";

    /// ledger #1217: an exhaustion episode's two log lines go to stderr, and the accept loop
    /// writes them itself, so a panic there ends the serve loop: the whole HTTP door, not one
    /// connection. Reproduced with this test binary re-run as a child whose stderr is a pipe
    /// with its read end CLOSED before the child writes (EPIPE; Rust ignores SIGPIPE, so the
    /// write returns the error and `eprintln!` panics on it).
    #[test]
    fn an_exhaustion_episode_survives_a_closed_stderr() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};

        if std::env::var_os(CLOSED_STDERR_CHILD).is_some() {
            // Wait until the parent has closed our stderr's read end, so the writes below
            // are known to hit a closed pipe rather than racing the close.
            let _ = io::stdin().read(&mut [0u8; 1]);
            let mut backoff = Backoff::default();
            backoff.failed(&io::Error::other("exhausted"));
            backoff.succeeded();
            println!("{SURVIVED}");
            return;
        }
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "accept::tests::an_exhaustion_episode_survives_a_closed_stderr",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CLOSED_STDERR_CHILD, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the test binary as a child");
        drop(child.stderr.take());
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(b"x")
            .expect("release the child");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .read_to_string(&mut out)
            .expect("read the child's stdout");
        let status = child.wait().expect("reap the child");
        assert!(
            status.success() && out.contains(SURVIVED),
            "the accept loop's log lines must not panic on a closed stderr: {status}\n{out}"
        );
    }
}
