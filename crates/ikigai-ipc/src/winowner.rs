//! The Windows owner proof: who is on the other end of a pipe instance?
//!
//! The Windows twin of the Unix door's `SO_PEERCRED` UID check (`serve_shared_on_with`
//! compares the peer's kernel-verified uid with its own). Here the identity is a user SID, and
//! there are two ways to read the client's:
//!
//! 1. **The client's process token** ([`OwnerSid::of_process`]): `GetNamedPipeClientProcessId`,
//!    `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `OpenProcessToken(TOKEN_QUERY)`, and
//!    `TokenUser`. This is the direct path, and it is all that is needed when the client runs
//!    as the server's own account.
//! 2. **Impersonation** ([`OwnerSid::of_pipe_client`]), the fallback. A standard (non-admin)
//!    account is not allowed to open ANOTHER account's process or token: `OpenProcess` or
//!    `OpenProcessToken` returns `ERROR_ACCESS_DENIED` (observed on Tamariz, the Windows
//!    spike host). That is exactly the case the owner check exists for, and "access denied"
//!    would leave the log unable to say WHO was refused. So the server impersonates the pipe
//!    client (`ImpersonateNamedPipeClient`; this crate's own clients offer only the
//!    identification level, so the server learns the identity and gains none of the rights),
//!    reads `TokenUser` off the thread token (`OpenThreadToken`), and always reverts
//!    (`RevertToSelf`, in a guard's `Drop`, so an error cannot skip it).
//!
//! Either way the SID is only ever COMPARED with the server's own ([`OwnerSid::admit_sid`]).
//! Any failure to identify the client, on both paths, is a [`Refusal`]: it never admits.
//!
//! ⚠ `ImpersonateNamedPipeClient` is documented to fail with `ERROR_CANNOT_IMPERSONATE` until
//! the server has read from the instance (it did not on the Windows 11 build tested, with a
//! same-account client, but a cross-account one has not been seen). So on that one error the
//! fallback reads a byte ahead (the client's hello, in this protocol) with
//! `PipeStream::prime_for_impersonation`, which keeps the byte and hands it back to the first
//! real read, so an admitted client loses nothing, and tries once more.
//!
//! The thread token is opened with `OpenAsSelf = TRUE` first (the access check runs as the
//! server). That check is against the impersonation token's DACL, which may deny a standard
//! account `TOKEN_QUERY` on another user's token, so on `ERROR_ACCESS_DENIED` it is tried again
//! with `OpenAsSelf = FALSE` (the check runs as the impersonated client, whose own token it is).
//! If both are denied the client is refused. A refusal line says which path identified the
//! client, or the Win32 errors when none did, so a live run shows which path worked.

use std::io;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, HANDLE,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    CopySid, EqualSid, GetLengthSid, GetTokenInformation, LookupAccountSidW, RevertToSelf,
    TokenUser, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::winpipe::PipeStream;

/// `ERROR_CANNOT_IMPERSONATE`: the server has not yet read from the instance.
const ERROR_CANNOT_IMPERSONATE: i32 = 1368;

/// Which path named a client, for the log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// The client's process token.
    ProcessToken,
    /// Impersonation, the thread token opened with `OpenAsSelf = TRUE`.
    ImpersonationAsSelf,
    /// Impersonation, the thread token opened with `OpenAsSelf = FALSE` (the `TRUE` open was
    /// denied).
    ImpersonationAsClient,
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Via::ProcessToken => "identified by its process token",
            Via::ImpersonationAsSelf => {
                "identified by impersonation, thread token opened as the server"
            }
            Via::ImpersonationAsClient => {
                "identified by impersonation, thread token opened as the client"
            }
        })
    }
}

/// A user SID, owned (a copy of the bytes, so it outlives the token it was read from).
#[derive(Clone)]
pub(crate) struct OwnerSid(Vec<u8>);

/// Why a client was turned away. `Display` names the account when it is known, else says why
/// it could not be known.
#[derive(Debug)]
pub(crate) struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

impl OwnerSid {
    /// The SID of the account this process runs as.
    pub(crate) fn current() -> io::Result<OwnerSid> {
        // SAFETY: the pseudo-handle needs no close; the token handle is closed by `token_sid`.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            token_sid(token)
        }
    }

    /// The SID of the account the process `pid` runs as (path 1).
    fn of_process(pid: u32) -> io::Result<OwnerSid> {
        // SAFETY: handles are closed on every path; out-params are valid.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut token: HANDLE = null_mut();
            let ok = OpenProcessToken(process, TOKEN_QUERY, &mut token);
            let err = io::Error::last_os_error();
            CloseHandle(process);
            if ok == 0 {
                return Err(err);
            }
            token_sid(token)
        }
    }

    /// The SID of the account on the other end of the pipe instance `pipe` (path 2, the
    /// fallback): impersonate it, read the thread token's `TokenUser`, revert.
    ///
    /// # Safety
    /// `pipe` must be a connected server-side pipe instance handle that has been read from.
    unsafe fn of_pipe_client(pipe: HANDLE) -> io::Result<(OwnerSid, Via)> {
        let _impersonating = Impersonating::begin(pipe)?;
        let mut token: HANDLE = null_mut();
        // OpenAsSelf = TRUE: the access check for opening the token runs as the SERVER, not as
        // the (possibly less privileged) client being read. It is made against the token's
        // DACL, which may deny a standard account TOKEN_QUERY on another user's token.
        let mut via = Via::ImpersonationAsSelf;
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 {
            let as_self = io::Error::last_os_error();
            if as_self.raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
                return Err(as_self);
            }
            // OpenAsSelf = FALSE: the check runs as the impersonated client, on its own token.
            via = Via::ImpersonationAsClient;
            if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) == 0 {
                let as_client = io::Error::last_os_error();
                return Err(io::Error::new(
                    as_client.kind(),
                    format!(
                        "opening the thread token as the server: {as_self}; \
                         as the client: {as_client}"
                    ),
                ));
            }
        }
        token_sid(token).map(|sid| (sid, via))
        // `_impersonating` drops here, after the token is read: RevertToSelf.
    }

    /// A SID from its string form (`S-1-5-18`), for tests.
    #[cfg(test)]
    pub(crate) fn from_string(sid: &str) -> io::Result<OwnerSid> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        let wide: Vec<u16> = sid.encode_utf16().chain([0]).collect();
        let mut p: PSID = null_mut();
        // SAFETY: `wide` is NUL-terminated; the SID is copied and the original freed.
        unsafe {
            if ConvertStringSidToSidW(wide.as_ptr(), &mut p) == 0 {
                return Err(io::Error::last_os_error());
            }
            let copy = copy_sid(p);
            LocalFree(p);
            Ok(copy)
        }
    }

    fn as_psid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }

    /// The SID in `S-1-...` form.
    pub(crate) fn to_sid_string(&self) -> String {
        let mut out: *mut u16 = null_mut();
        // SAFETY: `out` is allocated by the call and freed with `LocalFree`.
        unsafe {
            if ConvertSidToStringSidW(self.as_psid(), &mut out) == 0 {
                return "an unreadable SID".to_string();
            }
            let len = (0..).take_while(|&i| *out.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
            LocalFree(out.cast());
            s
        }
    }

    /// `DOMAIN\user` for this SID (`LookupAccountSid`), or `None` if it has no account here.
    pub(crate) fn account_name(&self) -> Option<String> {
        let (mut name_len, mut dom_len, mut kind) = (0u32, 0u32, 0i32);
        // SAFETY: the first call sizes the buffers, the second fills them.
        unsafe {
            LookupAccountSidW(
                null(),
                self.as_psid(),
                null_mut(),
                &mut name_len,
                null_mut(),
                &mut dom_len,
                &mut kind,
            );
            if name_len == 0 {
                return None;
            }
            let mut name = vec![0u16; name_len as usize];
            let mut dom = vec![0u16; dom_len.max(1) as usize];
            if LookupAccountSidW(
                null(),
                self.as_psid(),
                name.as_mut_ptr(),
                &mut name_len,
                dom.as_mut_ptr(),
                &mut dom_len,
                &mut kind,
            ) == 0
            {
                return None;
            }
            let name = String::from_utf16_lossy(&name[..name_len as usize]);
            Some(if dom_len == 0 {
                name
            } else {
                format!(
                    "{}\\{name}",
                    String::from_utf16_lossy(&dom[..dom_len as usize])
                )
            })
        }
    }

    /// The account in words for a log line: `DOMAIN\user (S-1-5-21-...)`, or the bare SID
    /// when it has no account name.
    pub(crate) fn describe(&self) -> String {
        match self.account_name() {
            Some(name) => format!("{name} ({})", self.to_sid_string()),
            None => self.to_sid_string(),
        }
    }

    fn same_as(&self, other: &OwnerSid) -> bool {
        // SAFETY: both are valid SIDs copied from a token.
        unsafe { EqualSid(self.as_psid(), other.as_psid()) != 0 }
    }

    /// The decision, apart from the pipe: admit `peer` only if it is this account, else a
    /// [`Refusal`] naming the peer's account and SID and the path (`via`) that identified it.
    pub(crate) fn admit_sid(&self, peer: &OwnerSid, via: Via) -> Result<(), Refusal> {
        if self.same_as(peer) {
            Ok(())
        } else {
            Err(Refusal(format!(
                "refused a connection from {} ({via}): not the owner of this pipe, {}",
                peer.describe(),
                self.describe()
            )))
        }
    }

    /// Admit the connected pipe instance `stream` if its client runs as this account.
    ///
    /// The client's process token first; if that cannot be read (a standard account may not
    /// open another account's process), the impersonation fallback. If neither identifies
    /// the client it is refused (fail closed), and the refusal gives both reasons.
    pub(crate) fn admit(&self, stream: &PipeStream) -> Result<(), Refusal> {
        let handle = stream.raw_handle();
        let mut pid = 0u32;
        // SAFETY: a valid pipe handle and a correctly-sized out-param.
        let by_process = if unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } == 0 {
            Err(format!("its process id: {}", io::Error::last_os_error()))
        } else {
            OwnerSid::of_process(pid).map_err(|e| format!("its process {pid}'s token: {e}"))
        };
        let (peer, via) = match by_process {
            Ok(peer) => (peer, Via::ProcessToken),
            Err(first) => self.identify_by_impersonation(stream, &first)?,
        };
        self.admit_sid(&peer, via)
    }

    /// Admit by the impersonation path only (the fallback of [`OwnerSid::admit`]); the
    /// tests run it against a same-account client, where the direct path would have sufficed.
    #[cfg(test)]
    pub(crate) fn admit_by_impersonation(&self, stream: &PipeStream) -> Result<(), Refusal> {
        let (peer, via) = self.identify_by_impersonation(stream, "(forced)")?;
        self.admit_sid(&peer, via)
    }

    /// The fallback: name the client by impersonating it (see the module docs).
    fn identify_by_impersonation(
        &self,
        stream: &PipeStream,
        first: &str,
    ) -> Result<(OwnerSid, Via), Refusal> {
        let unidentified = |why: String| {
            Refusal(format!(
                "refused a connection: could not identify the client account \
                 (could not read {first}; impersonation: {why}); neither path identified it"
            ))
        };
        // SAFETY (both calls): `stream` is a connected server instance.
        let mut attempt = unsafe { OwnerSid::of_pipe_client(stream.raw_handle()) };
        if matches!(&attempt, Err(e) if e.raw_os_error() == Some(ERROR_CANNOT_IMPERSONATE)) {
            // Not allowed until the server has read from the instance: read one byte ahead
            // (kept for the next real read), then try once more.
            stream
                .prime_for_impersonation()
                .map_err(|e| unidentified(format!("the client sent nothing to read: {e}")))?;
            attempt = unsafe { OwnerSid::of_pipe_client(stream.raw_handle()) };
        }
        attempt.map_err(|e| unidentified(e.to_string()))
    }
}

/// The thread is impersonating a pipe client until this drops. `Drop` reverts, on every path.
struct Impersonating;

impl Impersonating {
    /// # Safety
    /// `pipe` must be a connected server-side pipe instance handle that has been read from.
    unsafe fn begin(pipe: HANDLE) -> io::Result<Impersonating> {
        if ImpersonateNamedPipeClient(pipe) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Impersonating)
    }
}

impl Drop for Impersonating {
    fn drop(&mut self) {
        // SAFETY: reverting a thread's own impersonation.
        if unsafe { RevertToSelf() } == 0 {
            // A thread that is still the client cannot be allowed to carry on as the server.
            eprintln!("ikigai-ipc: RevertToSelf failed; aborting rather than run as the client");
            std::process::abort();
        }
    }
}

/// Read `TokenUser` from `token` (closing it) as an owned SID.
///
/// # Safety
/// `token` must be an open token handle with `TOKEN_QUERY`; it is closed here.
unsafe fn token_sid(token: HANDLE) -> io::Result<OwnerSid> {
    let mut len = 0u32;
    GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
    if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
        let e = io::Error::last_os_error();
        CloseHandle(token);
        return Err(e);
    }
    // u64 elements keep the buffer aligned for TOKEN_USER.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
    let err = io::Error::last_os_error();
    CloseHandle(token);
    if ok == 0 {
        return Err(err);
    }
    Ok(copy_sid((*(buf.as_ptr().cast::<TOKEN_USER>())).User.Sid))
}

/// # Safety
/// `sid` must point at a valid SID.
pub(crate) unsafe fn copy_sid(sid: PSID) -> OwnerSid {
    let len = GetLengthSid(sid);
    let mut bytes = vec![0u8; len as usize];
    CopySid(len, bytes.as_mut_ptr().cast(), sid);
    OwnerSid(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winpipe::test_pair;
    use std::io::{Read, Write};

    #[test]
    fn the_same_account_is_admitted() {
        let me = OwnerSid::current().unwrap();
        me.admit_sid(&me.clone(), Via::ProcessToken)
            .expect("own SID admitted");
    }

    #[test]
    fn a_foreign_sid_is_refused_and_named() {
        let me = OwnerSid::current().unwrap();
        // Well-known SYSTEM: resolves to an account name.
        let system = OwnerSid::from_string("S-1-5-18").unwrap();
        let msg = me
            .admit_sid(&system, Via::ProcessToken)
            .expect_err("SYSTEM is not the owner")
            .to_string();
        assert!(msg.contains("SYSTEM"), "names the account: {msg}");
        assert!(msg.contains("S-1-5-18"), "and the SID: {msg}");
        assert!(msg.contains("process token"), "and the path: {msg}");
        // Everyone (world) as well.
        let world = OwnerSid::from_string("S-1-1-0").unwrap();
        let msg = me
            .admit_sid(&world, Via::ImpersonationAsClient)
            .expect_err("Everyone is not the owner")
            .to_string();
        assert!(msg.contains("Everyone"), "names the account: {msg}");
        assert!(msg.contains("impersonation"), "and the path: {msg}");
    }

    #[test]
    fn an_unknown_sid_is_named_by_its_sid_string() {
        let me = OwnerSid::current().unwrap();
        let nobody = OwnerSid::from_string("S-1-5-21-1-2-3-424242").unwrap();
        let msg = me
            .admit_sid(&nobody, Via::ProcessToken)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("S-1-5-21-1-2-3-424242"), "{msg}");
    }

    #[test]
    fn a_same_account_client_is_admitted_by_its_process_token() {
        let (_listener, _client, server) = test_pair("direct");
        OwnerSid::current()
            .unwrap()
            .admit(&server)
            .expect("admitted by the direct path");
    }

    #[test]
    fn the_impersonation_fallback_identifies_the_client_and_gives_back_the_byte_it_read() {
        let (_listener, client, server) = test_pair("impersonate");
        (&client).write_all(b"hello").unwrap();
        let me = OwnerSid::current().unwrap();
        me.admit_by_impersonation(&server)
            .expect("the same account is identified by impersonation");
        // The thread is back to itself: no thread token is left behind.
        let mut token: HANDLE = null_mut();
        // SAFETY: a valid out-param; the handle (if any) is closed.
        let opened =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) != 0 };
        if opened {
            // SAFETY: just opened.
            unsafe { CloseHandle(token) };
        }
        assert!(!opened, "RevertToSelf must have run");
        // The primed byte is not lost to the protocol.
        let mut buf = [0u8; 5];
        (&server).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn a_client_that_cannot_be_identified_is_refused_never_admitted() {
        let path = crate::winpipe::test_path("unidentified");
        let listener = crate::winpipe::bind(&path).expect("bind");
        // An instance nobody has connected to has no client to identify, on either path.
        let nobody = listener.take_unconnected();
        let me = OwnerSid::current().unwrap();
        let msg = me
            .admit(&nobody)
            .expect_err("an unidentified client is refused")
            .to_string();
        assert!(msg.contains("could not identify"), "{msg}");
        let msg = me
            .admit_by_impersonation(&nobody)
            .expect_err("and by impersonation alone")
            .to_string();
        assert!(msg.contains("could not identify"), "{msg}");
    }
}
