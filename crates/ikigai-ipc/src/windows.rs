//! The Windows owner channel (carducci#119, windows-hub 1.1).
//!
//! The same shape as the Unix door: a blocking AF_UNIX socket (Windows 10+, via `uds_windows`),
//! one thread per connection. The two Unix checks have Windows equivalents:
//!
//! - **The boundary is the socket file's ACL** ([`bind`]): after the bind its DACL is replaced
//!   by a protected one with a single entry, full access for the owning account. No SYSTEM
//!   entry: nothing the owner channel does needs it, and an administrator can still take
//!   ownership of the file, which is the same reach root has over a `0600` file.
//!   [`default_socket_path`] also makes its directory owner-only before the socket is created,
//!   so the file never exists with a wider inherited ACL.
//! - **The owner proof is the peer's process token** ([`OwnerSid::admit`]): the peer pid
//!   (`SIO_AF_UNIX_GETPEERPID`), `OpenProcess` + `OpenProcessToken`, `TokenUser`, and the SID
//!   compared with the server's own. A mismatch (or a token that cannot be read: fail closed)
//!   is a [`Refusal`] that names the account, `DOMAIN\user` from `LookupAccountSid`, else the
//!   SID string.
//!
//! ⚠ The pid is read after the connection is made, so a peer that connects and exits before the
//! check could in principle have its pid reused. The ACL already limits who can connect at all;
//! this is the second layer, as the UID check is on Unix.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawSocket;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use uds_windows::{UnixListener, UnixStream};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE,
};
use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SOCKET, SOCKET_ERROR};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CopySid, EqualSid, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation,
    LookupAccountSidW, TokenUser, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `SIO_AF_UNIX_GETPEERPID` (`_WSAIOR(IOC_VENDOR, 256)`, af_unix.h): writes the peer's pid.
const SIO_AF_UNIX_GETPEERPID: u32 = 0x5800_0100;

/// A user SID, owned (a copy of the bytes, so it outlives the token it was read from).
#[derive(Clone)]
pub(crate) struct OwnerSid(Vec<u8>);

/// Why a peer was turned away. `Display` names the account.
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

    /// The SID of the account the process `pid` runs as.
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

    /// `DOMAIN\user` for this SID (`LookupAccountSid`), or its SID string if it has no account.
    pub(crate) fn account_name(&self) -> String {
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
                return self.to_sid_string();
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
                return self.to_sid_string();
            }
            let name = String::from_utf16_lossy(&name[..name_len as usize]);
            if dom_len == 0 {
                name
            } else {
                format!(
                    "{}\\{name}",
                    String::from_utf16_lossy(&dom[..dom_len as usize])
                )
            }
        }
    }

    fn same_as(&self, other: &OwnerSid) -> bool {
        // SAFETY: both are valid SIDs copied from a token.
        unsafe { EqualSid(self.as_psid(), other.as_psid()) != 0 }
    }

    /// The decision, apart from the socket: admit `peer` only if it is this account, else a
    /// [`Refusal`] naming the peer's account.
    pub(crate) fn admit_sid(&self, peer: &OwnerSid) -> Result<(), Refusal> {
        if self.same_as(peer) {
            Ok(())
        } else {
            Err(Refusal(format!(
                "refused a connection from {} ({}): not the owner of this socket, {}",
                peer.account_name(),
                peer.to_sid_string(),
                self.account_name()
            )))
        }
    }

    /// Admit the connected `stream` if its peer process runs as this account. A peer whose pid
    /// or token cannot be read is refused too (fail closed), and the refusal says why.
    pub(crate) fn admit(&self, stream: &UnixStream) -> Result<(), Refusal> {
        let pid = peer_pid(stream)
            .map_err(|e| Refusal(format!("refused a connection: its process id: {e}")))?;
        let peer = OwnerSid::of_process(pid).map_err(|e| {
            Refusal(format!(
                "refused a connection from process {pid}: its token could not be read: {e}"
            ))
        })?;
        self.admit_sid(&peer)
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
unsafe fn copy_sid(sid: PSID) -> OwnerSid {
    let len = GetLengthSid(sid);
    let mut bytes = vec![0u8; len as usize];
    CopySid(len, bytes.as_mut_ptr().cast(), sid);
    OwnerSid(bytes)
}

/// The connected peer's process id (`SIO_AF_UNIX_GETPEERPID`).
fn peer_pid(stream: &UnixStream) -> io::Result<u32> {
    let mut pid = 0u32;
    let mut returned = 0u32;
    // SAFETY: a valid socket and a correctly-sized out-param.
    let rc = unsafe {
        WSAIoctl(
            stream.as_raw_socket() as SOCKET,
            SIO_AF_UNIX_GETPEERPID,
            null(),
            0,
            (&mut pid as *mut u32).cast::<c_void>(),
            4,
            &mut returned,
            null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR || pid == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// Replace `path`'s DACL with a protected one holding a single entry: full access for `owner`.
pub(crate) fn restrict_to_owner(path: &Path, owner: &OwnerSid) -> io::Result<()> {
    let sddl: Vec<u16> = format!("D:P(A;;FA;;;{})", owner.to_sid_string())
        .encode_utf16()
        .chain([0])
        .collect();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: `sd` is allocated by the call and freed below; the DACL pointer borrows from it.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let (mut present, mut defaulted) = (0i32, 0i32);
        let mut dacl = null_mut();
        let mut result =
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            };
        if result.is_ok() {
            let mut name = wide(path);
            let rc = SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            );
            if rc != 0 {
                result = Err(io::Error::from_raw_os_error(rc as i32));
            }
        }
        LocalFree(sd);
        result
    }
}

/// Bind the server socket at `path` for the owning account only: a stale socket file is
/// removed, a live server's is refused ([`AddrInUse`](io::ErrorKind::AddrInUse)), a directory
/// is refused, and after the bind the file's DACL is narrowed to the owner (see the module
/// docs). The listener is listening when this returns.
///
/// ⚠ Unlike Unix, no `<path>.lock` orders two binders starting at once.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "{} exists and is not a socket; refusing to replace it",
                        path.display()
                    ),
                ));
            }
            // A socket file: a live server answers the dial, a dead one does not.
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "a kernel server is already listening on {}; stop it, or serve on \
                         another path",
                        path.display()
                    ),
                ));
            }
            std::fs::remove_file(path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("could not remove the stale socket {}: {e}", path.display()),
                )
            })?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    restrict_to_owner(path, &OwnerSid::current()?)?;
    Ok(listener)
}

/// The default per-user socket path: `%LOCALAPPDATA%\ikigai\kernel.sock`, the `ikigai`
/// directory made owner-only before any socket is created in it. `None` if it can't be.
pub fn default_socket_path() -> Option<PathBuf> {
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
    let dir = base.join("ikigai");
    std::fs::create_dir_all(&dir).ok()?;
    restrict_to_owner(&dir, &OwnerSid::current().ok()?).ok()?;
    Some(dir.join("kernel.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, ACL_SIZE_INFORMATION,
        OWNER_SECURITY_INFORMATION,
    };

    fn temp_socket(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ikigai-ipc-win-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("t.sock")
    }

    /// The SID strings of the ACEs in `path`'s DACL.
    fn dacl_sids(path: &Path) -> Vec<String> {
        let name = wide(path);
        let mut dacl = null_mut();
        let mut sd: *mut c_void = null_mut();
        // SAFETY: out-params are valid; `sd` is freed below and `dacl` borrows from it.
        unsafe {
            let rc = GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            assert_eq!(rc, 0, "GetNamedSecurityInfo failed: {rc}");
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
            let mut sids = Vec::new();
            for i in 0..info.AceCount {
                let mut ace: *mut c_void = null_mut();
                assert_ne!(GetAce(dacl, i, &mut ace), 0);
                // ACCESS_ALLOWED_ACE: header (4 bytes), mask (4 bytes), then the SID.
                let sid = copy_sid(ace.cast::<u8>().add(8).cast());
                sids.push(sid.to_sid_string());
            }
            LocalFree(sd);
            sids
        }
    }

    #[test]
    fn the_socket_files_dacl_grants_only_the_owner() {
        let path = temp_socket("dacl");
        let _listener = bind(&path).expect("bind");
        let me = OwnerSid::current().unwrap().to_sid_string();
        assert_eq!(dacl_sids(&path), vec![me]);
    }

    #[test]
    fn a_stale_socket_is_replaced_and_a_live_one_is_not() {
        let path = temp_socket("stale");
        let first = bind(&path).expect("bind");
        let err = bind(&path).expect_err("live socket must not be replaced");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        drop(first);
        bind(&path).expect("a dead socket is replaced");
    }

    #[test]
    fn the_same_account_is_admitted() {
        let me = OwnerSid::current().unwrap();
        me.admit_sid(&me.clone()).expect("own SID admitted");
    }

    #[test]
    fn a_foreign_sid_is_refused_and_named() {
        let me = OwnerSid::current().unwrap();
        // Well-known SYSTEM: resolves to an account name.
        let system = OwnerSid::from_string("S-1-5-18").unwrap();
        let msg = me
            .admit_sid(&system)
            .expect_err("SYSTEM is not the owner")
            .to_string();
        assert!(msg.contains("SYSTEM"), "names the account: {msg}");
        assert!(msg.contains("S-1-5-18"), "and the SID: {msg}");
        // Everyone (world) as well.
        let world = OwnerSid::from_string("S-1-1-0").unwrap();
        let msg = me
            .admit_sid(&world)
            .expect_err("Everyone is not the owner")
            .to_string();
        assert!(msg.contains("Everyone"), "names the account: {msg}");
    }

    #[test]
    fn an_unknown_sid_is_named_by_its_sid_string() {
        let me = OwnerSid::current().unwrap();
        let nobody = OwnerSid::from_string("S-1-5-21-1-2-3-424242").unwrap();
        let msg = me.admit_sid(&nobody).unwrap_err().to_string();
        assert!(msg.contains("S-1-5-21-1-2-3-424242"), "{msg}");
    }

    #[test]
    fn a_same_account_peer_stream_is_admitted_by_its_process_token() {
        let path = temp_socket("peer");
        let listener = bind(&path).expect("bind");
        let client = UnixStream::connect(&path).expect("connect");
        let (server_side, _) = listener.accept().expect("accept");
        assert_eq!(peer_pid(&server_side).unwrap(), std::process::id());
        OwnerSid::current()
            .unwrap()
            .admit(&server_side)
            .expect("admitted");
        drop(client);
    }
}
