# A native Windows build: what breaks (ledger #1162)

This is a **probe**, measured on GitHub's `windows-latest` runner (MSVC toolchain, stable Rust)
by the non-gating `windows-probe` job in `.github/workflows/ci.yml`. It records what fails, why,
and what a fix would take. It fixes nothing beyond what was trivial and obviously right. The
job reports every step's outcome in its summary and as a warning annotation; ledger #1162 is the
item that turns it into a gate.

WSL2 is the supported Windows path today (it is Linux). This page is about the native build.

## The short answer

| question | answer on `windows-latest` |
| --- | --- |
| does `cargo build -p ikigai-cli --features quic,web` build? | **yes**, after one cfg fix in this PR (W1). Cold build ~18 min, cached ~1.5 min |
| does `ikigai --version` run? | **yes**: `ikigai 0.1.59`, from PowerShell with `HOME` unset |
| does a local `ikigai -c` run? | **yes**: `source urn:host:identity` answers `identity root (full authority)` with `HOME` unset |
| does `ikigai serve quic://` start? | **yes**: `serving on quic://127.0.0.1:60355 (per-client workspaces; surface: host + fs; …)` |
| does `ikigai -c` reach a QUIC door? | **yes**: through `--override urn:host:=quic://127.0.0.1:<port> --cert-dir <certs>`, the door minted `principal urn:iki:host:win:client:<fingerprint>` |
| does `cargo test --workspace` pass? | **no**: 24 tests fail in 6 test targets (28 before this PR's four test fixes); 14 of them are one cause, W6 |
| is the binary's behavior on Windows TESTED? | **barely**: 19 of the 20 cli integration test files are `cfg(unix)` (W12). The smoke steps above are the only run of the binary |

So the remote path a collaborator would use (a client on Windows, a QUIC door anywhere) works
today. What does not work is everything that touches the local filesystem through `urn:file:*`
(W6), and the local transport (W3).

## The map

Ordered by what blocks `ikigai --version`, then `ikigai -c` against a QUIC server, then
`ikigai serve`. "Size" is a rough guess at the fix, not a measurement.

### Blocks `ikigai --version`

**W1. The socket-mount dial named an empty crate.** FIXED in this PR.
- crate: `ikigai-cli` (bin `ikigai`); first error, verbatim:
  ```
  error[E0433]: cannot find `HelloMode` in `ikigai_ipc`
      --> crates\ikigai-cli\src\main.rs:2695:58
  ```
  (plus `connect_as` and `DEFAULT_DESCRIBE_TIMEOUT`, and in the test build two
  `std::os::unix::net::UnixStream` uses and two `ikigai_ipc::serve` calls).
- cause: `ikigai-ipc` is `#![cfg(unix)]`, so on Windows the default `ipc` feature names an empty
  crate. `connect_mount_ipc` and two `mount_cert_tests` were gated on `feature = "ipc"` alone,
  while every other ipc site already required `unix` too.
- cfg-gated already: no (that was the defect).
- remedy: gate on `all(feature = "ipc", unix)`, with the fallback refusing a socket mount the way
  `serve_ipc` and `connect_ipc` already did. Done. **This was the only thing stopping the build.**
- size: trivial. It changes shipped code (a cfg and a message), so it rides the next cli release.

**Native dependencies: not a blocker on the runner.** `ring` 0.17.14 and `oxrocksdb-sys`
0.5.11 (RocksDB, through `oxigraph`'s `rocksdb` feature, which `ikigai-embedded` turns on
unconditionally) both compiled. `oxrocksdb-sys` runs `bindgen`, so it needs **libclang**, which
the runner image ships; a person building on their own machine needs the Visual Studio C++ build
tools AND an LLVM install (`LIBCLANG_PATH` if it is not found). `aws-lc-sys` is in the lockfile but
not in this build's graph. The `store` feature (`ikigai-store` persistent) was not built.

### Blocks or degrades `ikigai -c` against a QUIC server

Nothing here blocked the smoke run. These are what a person would hit next.

**W2. Home resolution reads only `HOME`.**
- crates: `ikigai-cli`, `ikigai-embedded`, `ikigai-engine`; no compile error (runtime only).
- cause: the config home (`XDG_CONFIG_HOME`, else `$HOME/.config/ikigai`), the data home
  (`~/.ikigai`), the file root default (`~/.ikigai/workspace`), and the `~` rule's home all read
  `HOME`. Git Bash sets it; **cmd and PowerShell do not** (they set `USERPROFILE`). The smoke run
  shows the consequence is quiet rather than fatal: with `HOME` unset there is no config home, so
  `config.toml`, its `mount` lines, `grants.json` and `clients.json` are simply not read, and a `~`
  in a mount flag is refused with "HOME is not set".
- cfg-gated already: no.
- remedy: one home function that falls back to `USERPROFILE` on Windows (recent Rust's
  `std::env::home_dir` answers the profile directory there; check it against the MSRV before
  relying on it), used by the config-home TWINS
  (`ikigai_embedded::config::config_home` and `ikigai_engine::config::path`, kept in step by hand)
  and by `ikigai-resolve`'s `~` rule. A design choice, because whether a Windows config home is
  `%USERPROFILE%\.config\ikigai` or `%APPDATA%\ikigai` is a decision. Today `--config-home <dir>`
  is the workaround, and it works in every mode.
- size: small to medium (about 20 call sites, one decision).

**W3. No local transport: `ikigai-ipc` is Unix sockets only.**
- crates: `ikigai-ipc` (empty on Windows), `ikigai-cli` (`serve <socket>`, `--connect <socket>`,
  `--mount <p>=<socket>`), and gonk's socket mount (`urn:gk:=~/.ikigai/gonk.sock`, in
  ikigai-gonk). No compile error since W1.
- cause: `std::os::unix::net`, `0600`/`0700` modes, and a kernel-verified peer UID
  (`SO_PEERCRED`/`getpeereid`) as the only authentication.
- cfg-gated already: yes, and every entry point refuses with "needs the `ipc` feature on a Unix
  platform".
- remedy: a design choice, out of scope for the probe. Either **named pipes** (tokio has them; the
  peer check becomes `GetNamedPipeClientProcessId` plus a token SID comparison, and the pipe's
  security descriptor replaces the `0700` directory) or **AF_UNIX on Windows 10 1803+** (a crate
  such as `uds_windows`; Windows AF_UNIX has no `SO_PEERCRED`, so the peer check still needs a
  Windows answer). Either way the authentication is the hard half, not the bytes. A Windows client
  of gonk needs a QUIC door on gonk's host instead, which is not this repo.
- size: medium to large.

**W4. Key and certificate files are not restricted on Windows.**
- crates: `ikigai-cli` (`quic.rs` `restrict`, a no-op on non-Unix: "rely on the user-private
  config directory's ACLs"), `ikigai-embedded` (`passkey.rs`, `tokens.rs`, `lib.rs`: every `0600`
  and `0700` is `cfg(unix)`). Runtime only.
- cause: Unix permission bits have no Windows meaning; nothing sets an ACL instead.
- cfg-gated already: yes, by design. The passkey file's permission JUDGE (`judge_permissions`,
  `judge_directory`) is compiled on Windows and never called (two dead-code warnings, W11).
- remedy: decide whether profile ACLs are enough (they usually are under `%USERPROFILE%`, not
  under a shared directory a `--config-home` could name), or set an owner-only DACL through
  `windows-sys`. A security decision, so not done here.
- size: medium.

**W5. The quinn tripwire's control sees a different error on Windows.** Test only.
- crate: `ikigai-quic` (test `quinn_recv_errors`); verbatim:
  ```
  assertion `left == right` failed: Os { code: 10054, kind: ConnectionReset, message: "An existing connection was forcibly closed by the remote host." }
    left: ConnectionReset
   right: ConnectionRefused
  ```
- cause: Windows reports an ICMP port-unreachable on a UDP socket as `WSAECONNRESET`, where Linux
  and macOS report `ECONNREFUSED`. That matters beyond the assertion: quinn's driver survives
  exactly `ECONNRESET`, so on Windows the error this test provokes is the one quinn exempts, and the
  tripwire beside it (which passed) proves less there than it does on Unix.
- cfg-gated already: no.
- remedy: decide what the tripwire must prove on Windows (provoke a different receive error, or
  record that it is vacuous there) before making the control's assertion per-platform.
- size: small.

### Blocks or degrades `ikigai serve` (and the embedded kernel generally)

**W6. `urn:file:*` refuses every request: `ikigai-fs` has no confined backend on Windows.**
- crate: `ikigai-fs` (sibling repo; seen here through `ikigai-embedded`, `ikigai-engine` and the
  cli's unit tests); verbatim:
  ```
  endpoint error: `urn:file:note.txt`: ikigai-fs has no confined backend on this platform (it needs openat); refused rather than served unconfined
  ```
- cause: the jail is a handle-relative, no-follow walk (`openat` through `rustix`). Off Unix the
  backend is a deliberate fail-closed stub, which is the right behavior and is why nothing leaks.
- cfg-gated already: yes (`cfg(not(any(unix, target_family = "wasm")))`).
- what it takes down: 14 of the 24 failing tests. The file root and per-client workspaces (the QUIC
  door's banner says `surface: host + fs`, and the fs half answers nothing), the FOAF faces (their
  stylesheets and context are `urn:file:` resources), `--arrangement` read through the kernel, the
  file watcher, `--routes` from a `urn:file:` resource, and every engine `sink`/`source` of a file.
- remedy: a Windows backend in ikigai-fs: open each segment relative to its parent handle
  (`NtCreateFile` with `RootDirectory`, refusing reparse points with `FILE_FLAG_OPEN_REPARSE_POINT`
  plus an attribute check), or adopt `cap-std`, which already implements that walk on Windows.
  ikigai-fs also has the Windows name rules to keep (ledger #1320).
- size: large, and it is ikigai-fs's arc, not this repo's.

**W7. Tenant scopes assume Unix paths.**
- crate: `ikigai-embedded` (`tenant.rs`); verbatim, two of the six:
  ```
  left: ["urn:cap:fs:read:/home/u/.ikigai/workspace\\0123456789abcdef\\notes"]
  right: ["urn:cap:fs:read:/home/u/.ikigai/workspace/0123456789abcdef/notes"]
  ```
  ```
  a path outside the jail cannot authorize anything inside it
  ```
- cause: `root_fs_scope` joins scopes with `Path::join`, so a cap IRI carries `\`; and the tests'
  "absolute" fixtures (`/Users/brian/notes`) are not absolute on Windows (no drive), so the jail
  logic classifies them differently and four tests see a different set of grants.
- cfg-gated already: no.
- remedy: decide how a Windows path is spelled inside an fs capability IRI (and how ikigai-fs's ACL
  matches it), then give the tests per-platform absolute fixtures. Ledger #1320 already asks for a
  Windows review of `tenant::root_fs_scope`. Two more tenant tests fail on W6.
- size: medium (one decision shared with ikigai-fs).

**W8. `--config-home` test fixtures are Unix-absolute.** Test only.
- crate: `ikigai-cli` (`config_home_flag_tests::a_missing_or_doubled_directory_is_refused`);
  verbatim: ``--config-home was given twice, as `\a` and `\b`; a process has one config home``.
- cause: `/a` is not absolute on Windows, so it is resolved against the working directory and
  normalized to `\a`; the test then looks for `/a`.
- cfg-gated already: no.
- remedy: per-platform absolute fixtures (`C:\a` on Windows). Left alone here because it touches
  how the flag's absolutizing is specified on Windows, not only a separator.
- size: small.

**W9. The HTTP edge never stops on a dead listener on Windows.**
- crate: `ikigai-web` (`accept.rs`); compile warning, verbatim: ``warning: variant `Fatal` is never
  constructed``.
- cause: the accept-error table is `cfg(unix)` errno values; on Windows only `io::ErrorKind` is
  consulted, which never yields `Fatal`, so a listener that can no longer accept backs off and
  retries forever instead of ending the loop with an error.
- cfg-gated already: yes, which is the gap.
- remedy: a `cfg(windows)` arm mapping the WinSock codes (`WSAENOTSOCK` 10038, `WSAEBADF` 10009,
  `WSAEINVAL` 10022 to `Fatal`; `WSAEMFILE` 10024, `WSAENOBUFS` 10055 to `BackOff`) and its
  test. `ikigai-web/tests/accept_errors.rs` is `cfg(unix)` too.
- size: small.

**W10. The space's take is not a compare-and-swap on Windows.**
- crate: `ikigai-intray`; verbatim:
  ```
  679 takes failed after claiming (474 delivered); first: Some("endpoint error: space `tc`: take read: The system cannot find the file specified. (os error 2)")
  ```
- cause (probable, not proven): a take claims a tuple by renaming it out of the inbox, and relies
  on "exactly one rename finds the source present" (POSIX). On Windows, std's `rename` opens the
  source and renames it BY HANDLE, so two takers that both opened the source can both "succeed",
  the second moving the first's staged file away; the first then fails its read. The tests saw no
  lost tuple and no double delivery: the loser gets an error where it should get `Gone`.
- cfg-gated already: no.
- remedy: on Windows, read a vanished staged file as a lost race (`Gone`), or claim with an
  exclusive create (`create_new` marker) rather than a rename. Needs the mechanism confirmed first.
  Reaches `--daemon` and `--react` spaces, not the QUIC client path.
- size: medium.

### Cross-cutting

**W11. Windows-only warnings would fail a `clippy -D warnings` gate.** `ikigai-embedded`
(`Permission`, `judge_permissions`, `judge_directory`: pure judges tested on every platform but
called only under `cfg(unix)`), `ikigai-web` (`Fault::Fatal`, W9), and one unused test helper
(`public_registration_succeeds`). Small; it is the first thing a Windows clippy job would need.

**W12. Coverage: the binary is almost untested on Windows.** 19 of the 20 integration test files
in `crates/ikigai-cli/tests/` are `#![cfg(… unix)]` (only `lockstep_pins.rs` runs), as are
`ikigai-ipc`'s and `ikigai-web`'s `accept_errors.rs` and `ikigai-embedded`'s `workspace_mode.rs`.
Many use `unix` only for a socket host or for `HOME`; the QUIC ones (`quic_redial`,
`quic_principals`, `call_deadline`, `describe_deadline`, `layers_serve`, `layers_https`) would need
a host that is not a socket door. And the probe's `cargo test --workspace` uses default features,
so the `quic`, `web`, `store` and `p2p` test code was not compiled at all. Medium, and the
precondition for turning this job into a gate.

**W13. Supervision.** This repo has no launchd or systemd code; `--daemon` is documented "for
launchd" and the plists live in devtools. A Windows service or scheduled task, accounts, ACLs and
power settings are ledger #1162's part 3, out of scope here.

## Test failures, by cause

| target | failed | causes |
| --- | --- | --- |
| `ikigai-cli` (bin unit tests) | 3 | W6 ×2, W8 ×1 (four separator tests fixed in this PR) |
| `ikigai-embedded` (lib) | 16 | W6 ×10 (arrangement, FOAF ×6, tenant ×2, watcher), W7 ×6 |
| `ikigai-engine` (lib) | 2 | W6 ×2 |
| `ikigai-intray` (lib) | 1 | W10 |
| `ikigai-intray` (`tests/staging.rs`) | 1 | W10 |
| `ikigai-quic` (`tests/quinn_recv_errors.rs`) | 1 | W5 |

## What this PR changed in code

- `crates/ikigai-cli/src/main.rs`: `connect_mount_ipc` and two socket tests gated on
  `all(feature = "ipc", unix)` (W1); four mount tests that asserted `home + "/" + rest` now build
  the expectation with `Path::join`, as the code does.
- `.github/workflows/ci.yml`: the `windows-probe` job: the build, a PowerShell smoke with `HOME`
  unset, a QUIC door and client smoke, `cargo test --workspace`, and the summary.
