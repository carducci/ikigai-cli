//! The Windows owner channel's transport: a named pipe served through tokio.
//!
//! The same blocking, thread-per-connection shape as the Unix door; the stream and listener
//! types here stand in for `UnixStream` and `UnixListener`. Tokio's native named-pipe support
//! (`tokio::net::windows::named_pipe`) does the I/O; a small private runtime drives it and the
//! synchronous reads and writes block on it, each under the stream's read or write timeout.
//!
//! **Two layers keep other accounts out**, as on Unix (the `0700` directory and the UID check):
//!
//! - **The pipe's DACL** ([`OwnerOnlyDescriptor`]): every instance is created with a
//!   protected DACL holding ONE entry, full access for the server's own user SID. No Everyone,
//!   no Administrators, no SYSTEM, nothing inherited. The pipe's owner is set to that SID as
//!   well (an elevated token would otherwise make the Administrators group the owner, and an
//!   owner can rewrite the DACL). Instances also refuse remote clients
//!   (`PIPE_REJECT_REMOTE_CLIENTS`), and the first instance is created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`, so another process cannot squat the name ahead of us, and
//!   a second server on a live name is refused rather than joining it.
//! - **The per-connection owner check** ([`crate::winowner`]): the client's user SID, compared
//!   with the server's. The DACL decides who may open the pipe; this decides who is served.
//!
//! The pipe name is derived from the path the caller passes, as a Unix socket's address is
//! the path ([`pipe_name`]); [`default_socket_path`] is per-user.

use std::ffi::{c_void, OsString};
use std::future::Future;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};
use tokio::runtime::{Builder, Runtime};
use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use crate::winowner::OwnerSid;

/// `ERROR_PIPE_BUSY`: every instance of the pipe is in use. A client waits and retries.
const ERROR_PIPE_BUSY: i32 = 231;
/// `ERROR_BROKEN_PIPE`: the other end closed. On a read this is end-of-stream.
const ERROR_BROKEN_PIPE: i32 = 109;

/// `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`: the client lets the server learn who it is
/// (impersonate at the identification level) and nothing more, so the owner check's fallback can
/// name a client but cannot act as it.
const IDENTIFY_ONLY: u32 = 0x0010_0000 | 0x0001_0000;

/// How long [`PipeStream::connect`] waits out `ERROR_PIPE_BUSY` before giving up.
const BUSY_WAIT: Duration = Duration::from_secs(5);

/// How long the impersonation fallback waits for the client's first bytes.
const PRIME_WAIT: Duration = Duration::from_secs(2);

/// The private runtime that drives every pipe. One worker thread: it only moves bytes.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("ikigai-ipc-pipe")
            .enable_all()
            .build()
            .expect("the named-pipe runtime starts")
    })
}

/// Run `fut` to completion from a plain thread, failing with `TimedOut` at `deadline`.
fn block_until<T>(
    deadline: Option<Instant>,
    fut: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    runtime().block_on(async {
        match deadline {
            None => fut.await,
            Some(at) => match tokio::time::timeout_at(at.into(), fut).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe deadline elapsed",
                )),
            },
        }
    })
}

/// The pipe name for a caller's `path`.
///
/// A path that is already a pipe name (`\\.\pipe\...`) is used as it is. Any other path is
/// hashed (FNV-1a over its lowercased text, since Windows paths ignore case) into
/// `\\.\pipe\ikigai-<16 hex digits>`, so the identity of the door is still "the path you gave",
/// as a Unix socket's is, and the API keeps its shape: the CLI's `--serve <path>` and
/// `--connect <path>` meet at the same pipe from the same text. Pipe names live in one global
/// namespace with no directories to hide in, which is why the per-user protection is the DACL
/// and the owner check, not the name.
pub(crate) fn pipe_name(path: &Path) -> OsString {
    let text = path.as_os_str();
    let lower = text.to_string_lossy().to_lowercase();
    if lower.starts_with(r"\\.\pipe\") {
        return text.to_owned();
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in lower.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    OsString::from(format!(r"\\.\pipe\ikigai-{hash:016x}"))
}

/// The default per-user door: `\\.\pipe\ikigai-<the user's SID>`. The Unix default is a
/// per-user directory (`$XDG_RUNTIME_DIR` or `/tmp/ikigai-<uid>`); the SID is this platform's
/// uid. `None` if the account's SID cannot be read.
pub fn default_socket_path() -> Option<PathBuf> {
    let sid = OwnerSid::current().ok()?.to_sid_string();
    Some(PathBuf::from(format!(r"\\.\pipe\ikigai-{sid}")))
}

/// A security descriptor allocated by `ConvertStringSecurityDescriptorToSecurityDescriptor`.
struct OwnerOnlyDescriptor(*mut c_void);

// SAFETY: the descriptor is immutable after creation and freed once, on drop.
unsafe impl Send for OwnerOnlyDescriptor {}
unsafe impl Sync for OwnerOnlyDescriptor {}

impl OwnerOnlyDescriptor {
    /// Owner `owner`, and a protected DACL of `entries` (SDDL ACEs).
    fn new(owner: &OwnerSid, entries: &str) -> io::Result<Self> {
        let sddl: Vec<u16> = format!("O:{0}D:P{entries}", owner.to_sid_string())
            .encode_utf16()
            .chain([0])
            .collect();
        let mut sd: *mut c_void = null_mut();
        // SAFETY: `sddl` is NUL-terminated; `sd` is allocated by the call and freed on drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnerOnlyDescriptor(sd))
    }
}

impl Drop for OwnerOnlyDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated with LocalAlloc by the conversion call.
        unsafe { LocalFree(self.0) };
    }
}

/// The server end: a stream of pipe instances, each created owner-only.
pub struct PipeListener {
    name: OsString,
    descriptor: OwnerOnlyDescriptor,
    /// The instance waiting for the next client. Always refilled before one is handed out, so
    /// a client that arrives right behind another finds an instance.
    waiting: Mutex<Option<NamedPipeServer>>,
}

/// Bind the server pipe for `path` (see [`pipe_name`]) for the owning account only. The
/// first instance is created exclusively: a live server on the name is refused
/// ([`AddrInUse`](io::ErrorKind::AddrInUse)), and nobody can squat the name before us. There
/// is no stale pipe to replace: a pipe vanishes with its last handle. The listener is ready
/// when this returns; a client that opens it now waits for [`PipeListener::accept`].
pub fn bind(path: &Path) -> io::Result<PipeListener> {
    let owner = OwnerSid::current()?;
    let descriptor =
        OwnerOnlyDescriptor::new(&owner, &format!("(A;;GA;;;{})", owner.to_sid_string()))?;
    PipeListener::create(path, descriptor)
}

/// [`bind`] with the DACL deliberately widened so Everyone may OPEN the pipe, leaving the
/// per-connection owner check as the only layer. This exists for ONE purpose: the live test
/// `another_account_is_refused_live`, which needs a second account to get past the DACL so the
/// hub can log the owner check's refusal naming that account. Never use it to serve.
#[doc(hidden)]
pub fn bind_open_to_everyone_for_the_refusal_demo(path: &Path) -> io::Result<PipeListener> {
    let owner = OwnerSid::current()?;
    let descriptor = OwnerOnlyDescriptor::new(
        &owner,
        &format!("(A;;GA;;;{})(A;;GRGW;;;WD)", owner.to_sid_string()),
    )?;
    PipeListener::create(path, descriptor)
}

impl PipeListener {
    fn create(path: &Path, descriptor: OwnerOnlyDescriptor) -> io::Result<PipeListener> {
        let name = pipe_name(path);
        let first = create_instance(&name, &descriptor, true).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                // FILE_FLAG_FIRST_PIPE_INSTANCE fails with ACCESS_DENIED when the name exists.
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "a kernel server is already listening on {}; stop it, or serve on \
                         another path ({e})",
                        path.display()
                    ),
                )
            } else {
                e
            }
        })?;
        Ok(PipeListener {
            name,
            descriptor,
            waiting: Mutex::new(Some(first)),
        })
    }

    /// Wait for a client to open the pipe. The instance it opened is returned, and a fresh
    /// one is already waiting for the next client (should that creation fail, this client is
    /// still served, the failure is logged, and the next `accept` tries again and reports it).
    pub fn accept(&self) -> io::Result<(PipeStream, ())> {
        let taken = self.waiting.lock().expect("pipe listener lock").take();
        let server = match taken {
            Some(server) => server,
            None => create_instance(&self.name, &self.descriptor, false)?,
        };
        block_until(None, server.connect())?;
        match create_instance(&self.name, &self.descriptor, false) {
            Ok(next) => *self.waiting.lock().expect("pipe listener lock") = Some(next),
            Err(e) => crate::accept::diagnose(format_args!(
                "ikigai-ipc: could not create the next pipe instance ({e}); retrying at the next accept"
            )),
        }
        Ok((PipeStream::new(Pipe::Server(server)), ()))
    }

    /// The instance waiting for a client, as a stream that nobody has connected to.
    #[cfg(test)]
    pub(crate) fn take_unconnected(&self) -> PipeStream {
        let server = self.waiting.lock().expect("pipe listener lock").take();
        PipeStream::new(Pipe::Server(server.expect("an instance is waiting")))
    }

    /// The handle of the instance waiting for a client, for reading its security back.
    #[cfg(test)]
    pub(crate) fn waiting_handle(&self) -> HANDLE {
        let guard = self.waiting.lock().expect("pipe listener lock");
        guard
            .as_ref()
            .expect("an instance is waiting")
            .as_raw_handle() as HANDLE
    }
}

/// Create one pipe instance with the owner-only descriptor, byte mode, remote clients rejected.
fn create_instance(
    name: &OsString,
    descriptor: &OwnerOnlyDescriptor,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let _enter = runtime().enter();
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte);
    // SAFETY: `attributes` and the descriptor it points at outlive the call; the handle is
    // not inheritable.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

/// Either end of a pipe.
enum Pipe {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

macro_rules! either {
    ($pipe:expr, $p:ident => $body:expr) => {
        match $pipe {
            Pipe::Server($p) => $body,
            Pipe::Client($p) => $body,
        }
    };
}

/// One connected pipe, read and written synchronously, with `UnixStream`'s timeout surface.
pub struct PipeStream {
    pipe: Pipe,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    /// One byte read ahead by [`PipeStream::prime_for_impersonation`], owed to the next read.
    read_ahead: Mutex<Option<u8>>,
}

impl PipeStream {
    fn new(pipe: Pipe) -> PipeStream {
        PipeStream {
            pipe,
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            read_ahead: Mutex::new(None),
        }
    }

    /// Open the pipe for `path` (see [`pipe_name`]). A busy pipe (every instance in use) is
    /// waited out for a few seconds; a missing one is `NotFound`; one the DACL does not admit
    /// is `PermissionDenied`.
    pub fn connect(path: &Path) -> io::Result<PipeStream> {
        let name = pipe_name(path);
        let give_up = crate::now() + BUSY_WAIT;
        loop {
            let opened = {
                let _enter = runtime().enter();
                ClientOptions::new()
                    .security_qos_flags(IDENTIFY_ONLY)
                    .open(&name)
            };
            match opened {
                Ok(client) => return Ok(PipeStream::new(Pipe::Client(client))),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && crate::now() < give_up => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *self.read_timeout.lock().expect("timeout lock") = timeout;
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *self.write_timeout.lock().expect("timeout lock") = timeout;
        Ok(())
    }

    /// The pipe's handle, for the owner check.
    pub(crate) fn raw_handle(&self) -> HANDLE {
        either!(&self.pipe, p => p.as_raw_handle() as HANDLE)
    }

    /// Read one byte ahead so `ImpersonateNamedPipeClient` is allowed, keeping it for the next
    /// read. Waits up to [`PRIME_WAIT`] for the client to say something.
    pub(crate) fn prime_for_impersonation(&self) -> io::Result<()> {
        let mut ahead = self.read_ahead.lock().expect("read-ahead lock");
        if ahead.is_some() {
            return Ok(());
        }
        let mut byte = [0u8; 1];
        let n = self.read_with(&mut byte, Some(crate::now() + PRIME_WAIT))?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the client closed without sending anything",
            ));
        }
        *ahead = Some(byte[0]);
        Ok(())
    }

    fn read_with(&self, buf: &mut [u8], deadline: Option<Instant>) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            block_until(deadline, async {
                either!(&self.pipe, p => p.readable().await)
            })?;
            match either!(&self.pipe, p => p.try_read(buf)) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE) => return Ok(0),
                Err(e) => return Err(e),
            }
        }
    }

    fn write_with(&self, buf: &[u8], deadline: Option<Instant>) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            block_until(deadline, async {
                either!(&self.pipe, p => p.writable().await)
            })?;
            match either!(&self.pipe, p => p.try_write(buf)) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE) => {
                    return Err(io::ErrorKind::BrokenPipe.into())
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn deadline_of(timeout: &Mutex<Option<Duration>>) -> Option<Instant> {
    timeout
        .lock()
        .expect("timeout lock")
        .map(|d| crate::now() + d)
}

impl io::Read for &PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(byte) = self.read_ahead.lock().expect("read-ahead lock").take() {
            buf[0] = byte;
            return Ok(1);
        }
        self.read_with(buf, deadline_of(&self.read_timeout))
    }
}

impl io::Write for &PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_with(buf, deadline_of(&self.write_timeout))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A connected pair on a private pipe name, for tests: the listener (kept alive), the client
/// end, and the server end.
#[cfg(test)]
pub(crate) fn test_pair(tag: &str) -> (PipeListener, PipeStream, PipeStream) {
    let path = test_path(tag);
    let listener = bind(&path).expect("bind");
    let client = PipeStream::connect(&path).expect("connect");
    let (server, ()) = listener.accept().expect("accept");
    (listener, client, server)
}

/// A pipe path no other test or process shares.
#[cfg(test)]
pub(crate) fn test_path(tag: &str) -> PathBuf {
    PathBuf::from(format!(
        r"C:\ikigai-ipc-test\{}-{tag}.pipe",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        SE_DACL_PROTECTED,
    };

    /// The DACL of the pipe instance `handle`: whether it is protected, its owner, and each ACE
    /// as (type, flags, SID).
    fn dacl_of(handle: HANDLE) -> (bool, String, Vec<(u8, u8, String)>) {
        let mut dacl = null_mut();
        let mut owner = null_mut();
        let mut sd: *mut c_void = null_mut();
        // SAFETY: out-params are valid; `sd` is freed below and `dacl` borrows from it.
        unsafe {
            let rc = GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            assert_eq!(rc, 0, "GetSecurityInfo failed: {rc}");
            let (mut control, mut revision) = (0u16, 0u32);
            assert_ne!(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision),
                0
            );
            let owner = crate::winowner::copy_sid(owner).to_sid_string();
            let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
            assert_ne!(
                GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ),
                0
            );
            let mut aces = Vec::new();
            for i in 0..info.AceCount {
                let mut ace: *mut c_void = null_mut();
                assert_ne!(GetAce(dacl, i, &mut ace), 0);
                // ACCESS_ALLOWED_ACE: header (type, flags, size: 4 bytes), mask (4), then the SID.
                let header = ace.cast::<u8>();
                let sid = crate::winowner::copy_sid(header.add(8).cast());
                aces.push((*header, *header.add(1), sid.to_sid_string()));
            }
            LocalFree(sd);
            (control & SE_DACL_PROTECTED != 0, owner, aces)
        }
    }

    #[test]
    fn the_pipes_dacl_grants_exactly_the_servers_own_user() {
        let path = test_path("dacl");
        let listener = bind(&path).expect("bind");
        let me = OwnerSid::current().unwrap().to_sid_string();
        let (protected, owner, aces) = dacl_of(listener.waiting_handle());
        assert!(protected, "the DACL must be protected: nothing inherited");
        assert_eq!(owner, me, "owned by the user, not the Administrators group");
        // ACCESS_ALLOWED_ACE_TYPE, no inheritance flags, one entry for the user's SID.
        assert_eq!(aces, vec![(0u8, 0u8, me)]);
    }

    #[test]
    fn every_instance_is_owner_only_not_just_the_first() {
        let path = test_path("instances");
        let listener = bind(&path).expect("bind");
        let _client = PipeStream::connect(&path).expect("connect");
        let (_server, ()) = listener.accept().expect("accept");
        // accept() refilled the waiting slot with a second instance.
        let me = OwnerSid::current().unwrap().to_sid_string();
        let (protected, _, aces) = dacl_of(listener.waiting_handle());
        assert!(protected);
        assert_eq!(aces, vec![(0u8, 0u8, me)]);
    }

    #[test]
    fn a_second_server_on_a_live_name_is_refused() {
        let path = test_path("squat");
        let _first = bind(&path).expect("bind");
        let err = bind(&path)
            .err()
            .expect("a live name must not be shared or replaced");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
    }

    #[test]
    fn a_missing_pipe_is_not_found() {
        let err = PipeStream::connect(&test_path("nobody-home"))
            .err()
            .expect("no server");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }

    #[test]
    fn bytes_round_trip_and_a_hang_up_is_end_of_stream() {
        let (_listener, client, server) = test_pair("bytes");
        (&client).write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        (&server).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        (&server).write_all(b"pong").unwrap();
        (&client).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        drop(client);
        assert_eq!(
            (&server).read(&mut buf).unwrap(),
            0,
            "EOF after the client leaves"
        );
    }

    #[test]
    fn a_silent_peer_times_out_on_read() {
        let (_listener, client, _server) = test_pair("timeout");
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let err = (&client).read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    }

    #[test]
    fn a_path_maps_to_one_pipe_name_and_a_pipe_name_is_kept() {
        let a = pipe_name(Path::new(r"C:\Users\Me\ikigai\kernel.sock"));
        let same = pipe_name(Path::new(r"c:\users\me\IKIGAI\kernel.sock"));
        let other = pipe_name(Path::new(r"C:\Users\Me\ikigai\other.sock"));
        assert_eq!(a, same, "Windows paths ignore case");
        assert_ne!(a, other);
        assert!(a.to_string_lossy().starts_with(r"\\.\pipe\ikigai-"));
        let literal = Path::new(r"\\.\pipe\mine");
        assert_eq!(pipe_name(literal), OsString::from(r"\\.\pipe\mine"));
    }

    #[test]
    fn the_default_path_is_per_user() {
        let path = default_socket_path().expect("default path");
        let me = OwnerSid::current().unwrap().to_sid_string();
        assert_eq!(path, PathBuf::from(format!(r"\\.\pipe\ikigai-{me}")));
    }
}
