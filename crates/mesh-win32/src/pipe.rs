#![allow(clippy::missing_errors_doc)]

use std::cell::Cell;
use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use data_encoding::{BASE32_NOPAD, HEXLOWER};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_PATH_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetTokenInformation, INHERITED_ACE, IsValidAcl, IsValidSid,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SecurityIdentification, TOKEN_QUERY, TOKEN_USER,
    TokenImpersonationLevel, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_EFFECTIVE_ONLY, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThread, INFINITE, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, WaitForSingleObject,
};

use crate::frame::{FRAME_HEADER_LENGTH, decode_frame_length, encode_frame};
use crate::windows::{access_allowed_ace_size_is_exact, current_user_sid, same_sid, sid_length};
use crate::{
    NativeError, NativeErrorCode, NativeOperation, StorageError, StorageErrorCode,
    ValidatedControlRoot, ValidatedDataRoot,
};

const PIPE_PREFIX: &str = r"\\.\pipe\CodexAgentMesh-v1-";
const PIPE_INSTANCES: u32 = 32;
const PIPE_BUFFER_SIZE: u32 = 64 * 1024;
const PATH_CAPACITY: usize = 32_768;
const INSTALL_ID_HEX_LENGTH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipeEndpoint {
    name: String,
    account_sid: String,
}

impl PipeEndpoint {
    pub fn for_current_user(install_id: &str) -> Result<Self, NativeError> {
        validate_install_id(install_id)?;
        let sid = current_user_sid().map_err(|error| {
            error.os_code().map_or_else(
                || {
                    NativeError::new(
                        NativeErrorCode::AuthenticationFailed,
                        NativeOperation::DeriveEndpoint,
                    )
                },
                |code| {
                    NativeError::with_os_code(
                        NativeErrorCode::AuthenticationFailed,
                        NativeOperation::DeriveEndpoint,
                        code,
                    )
                },
            )
        })?;
        let account_sid = sid_to_string(sid.as_ptr().cast_mut().cast())?;
        let name = derive_pipe_name(&account_sid, install_id)?;
        Ok(Self { name, account_sid })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn account_sid(&self) -> &str {
        &self.account_sid
    }
}

pub fn derive_pipe_name(account_sid: &str, install_id: &str) -> Result<String, NativeError> {
    validate_install_id(install_id)?;
    if account_sid.is_empty() || account_sid.as_bytes().contains(&0) {
        return Err(invalid_endpoint());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"codex-agent-mesh\0pipe-v1\0");
    hasher.update(account_sid.as_bytes());
    hasher.update(b"\0");
    hasher.update(install_id.as_bytes());
    let scope = BASE32_NOPAD.encode(&hasher.finalize()).to_ascii_lowercase();
    Ok(format!("{PIPE_PREFIX}{scope}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentityPolicy {
    expected_image: PathBuf,
    expected_sha256: [u8; 32],
}

impl PeerIdentityPolicy {
    /// Builds exact peer identity from the protected product control root.
    ///
    /// This is the production stable-slot constructor. It verifies the frozen
    /// `installs/<id>/bin/<sha256>/mesh-daemon.exe` layout and delegates path,
    /// reparse, exact file ACL, size, and digest proof to the validated control
    /// root before retaining the canonical absolute image path.
    pub fn from_control_slot(
        root: &ValidatedControlRoot,
        relative_image: &Path,
        expected_sha256: [u8; 32],
    ) -> Result<Self, NativeError> {
        validate_stable_runtime_layout(relative_image, expected_sha256)?;
        let expected_image = root
            .verify_artifact_file(relative_image, expected_sha256)
            .map_err(map_control_peer_error)?;
        Self::from_exact_image(expected_image, expected_sha256)
    }

    /// Build an exact process identity policy from a trusted install record.
    ///
    /// Both peers must name the same exact immutable `mesh-daemon.exe` runtime
    /// at its digest-addressed retained-slot path. A plugin-cache path,
    /// caller-selected executable name/path, or digest without its exact
    /// canonical path is not an admissible production policy.
    pub fn from_stable_slot(
        root: &ValidatedDataRoot,
        relative_image: &Path,
        expected_sha256: [u8; 32],
    ) -> Result<Self, NativeError> {
        validate_stable_runtime_layout(relative_image, expected_sha256)?;
        let expected_image = root
            .resolve_relative(relative_image)
            .map_err(|_| invalid_peer_policy())?;
        let policy = Self::from_exact_image(expected_image, expected_sha256)?;
        if sha256_file(&policy.expected_image)? != expected_sha256 {
            return Err(NativeError::new(
                NativeErrorCode::SetupDrifted,
                NativeOperation::InspectPeer,
            ));
        }
        Ok(policy)
    }

    fn from_exact_image(
        expected_image: impl AsRef<Path>,
        expected_sha256: [u8; 32],
    ) -> Result<Self, NativeError> {
        let expected_image = std::fs::canonicalize(expected_image)
            .map_err(|error| io_error(&error, NativeOperation::InspectPeer))?;
        if !expected_image.is_absolute() || !expected_image.is_file() {
            return Err(NativeError::new(
                NativeErrorCode::InvalidArgument,
                NativeOperation::InspectPeer,
            ));
        }
        Ok(Self {
            expected_image,
            expected_sha256,
        })
    }

    #[cfg(test)]
    fn for_current_executable() -> Result<Self, NativeError> {
        let image = std::env::current_exe()
            .map_err(|error| io_error(&error, NativeOperation::InspectPeer))?;
        let digest = sha256_file(&image)?;
        Self::from_exact_image(image, digest)
    }

    #[must_use]
    pub fn expected_image(&self) -> &Path {
        &self.expected_image
    }

    #[must_use]
    pub const fn expected_sha256(&self) -> &[u8; 32] {
        &self.expected_sha256
    }
}

fn validate_stable_runtime_layout(
    relative_image: &Path,
    expected_sha256: [u8; 32],
) -> Result<(), NativeError> {
    let components = relative_image.components().collect::<Vec<_>>();
    let digest = HEXLOWER.encode(&expected_sha256);
    let valid_layout = matches!(components.as_slice(), [
            std::path::Component::Normal(installs),
            std::path::Component::Normal(install_id),
            std::path::Component::Normal(bin),
            std::path::Component::Normal(digest_directory),
            std::path::Component::Normal(file_name),
        ] if *installs == "installs"
            && install_id.to_str().is_some_and(|value| validate_install_id(value).is_ok())
            && *bin == "bin"
            && *digest_directory == std::ffi::OsStr::new(&digest)
            && *file_name == std::ffi::OsStr::new("mesh-daemon.exe"));
    valid_layout.then_some(()).ok_or_else(invalid_peer_policy)
}

fn map_control_peer_error(error: StorageError) -> NativeError {
    let code = match error.code() {
        StorageErrorCode::Io if error.os_code() == Some(ERROR_ACCESS_DENIED) => {
            NativeErrorCode::SetupAccessDenied
        }
        _ => NativeErrorCode::SetupDrifted,
    };
    error.os_code().map_or_else(
        || NativeError::new(code, NativeOperation::InspectPeer),
        |os_code| NativeError::with_os_code(code, NativeOperation::InspectPeer, os_code),
    )
}

pub fn sha256_file(path: &Path) -> Result<[u8; 32], NativeError> {
    let mut file =
        File::open(path).map_err(|error| io_error(&error, NativeOperation::InspectPeer))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error(&error, NativeOperation::InspectPeer))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug)]
pub struct SecurePipeServer {
    handle: OwnedHandle,
    endpoint: PipeEndpoint,
    expected_user_sid: Vec<u8>,
    peer_policy: PeerIdentityPolicy,
}

impl SecurePipeServer {
    pub fn bind_first(
        endpoint: &PipeEndpoint,
        peer_policy: PeerIdentityPolicy,
    ) -> Result<Self, NativeError> {
        Self::bind(endpoint, peer_policy, true)
    }

    /// Bind another server instance while this proven instance remains live.
    ///
    /// This cannot be an associated constructor: `CreateNamedPipeW` without
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE` would otherwise let a caller create the
    /// first instance and bypass singleton ownership.
    pub fn bind_additional(&self) -> Result<Self, NativeError> {
        Self::bind(&self.endpoint, self.peer_policy.clone(), false)
    }

    fn bind(
        endpoint: &PipeEndpoint,
        peer_policy: PeerIdentityPolicy,
        first: bool,
    ) -> Result<Self, NativeError> {
        let expected_user_sid = current_user_sid_bytes(NativeOperation::CreatePipe)?;
        let descriptor = PipeSecurityDescriptor::current_user_only(&expected_user_sid)?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(mem::size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: descriptor.0.cast(),
            bInheritHandle: 0,
        };
        let name = wide_str(endpoint.name());
        let open_mode = PIPE_ACCESS_DUPLEX
            | FILE_FLAG_OVERLAPPED
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: the pipe name and absolute security descriptor remain live
        // for the synchronous call. The returned handle is checked and owned.
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                pipe_mode,
                PIPE_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                &raw mut attributes,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            let code = last_error();
            return Err(NativeError::with_os_code(
                if first {
                    NativeErrorCode::SingletonConflict
                } else {
                    NativeErrorCode::OsFailure
                },
                NativeOperation::CreatePipe,
                code,
            ));
        }
        let handle = OwnedHandle(raw);
        verify_pipe_dacl(handle.0, expected_user_sid.as_ptr().cast_mut().cast())?;
        Ok(Self {
            handle,
            endpoint: endpoint.clone(),
            expected_user_sid,
            peer_policy,
        })
    }

    pub fn accept(self, deadline: Instant) -> Result<SecurePipeConnection, NativeError> {
        connect_overlapped(self.handle.0, deadline)?;
        let peer_pid =
            authenticate_client(self.handle.0, &self.expected_user_sid, &self.peer_policy)?;
        Ok(SecurePipeConnection {
            inner: Arc::new(PipeConnectionInner {
                handle: self.handle,
                server_side: true,
                disconnected: AtomicBool::new(false),
            }),
            peer_pid,
            not_sync: PhantomData,
        })
    }
}

#[derive(Debug)]
pub struct SecurePipeClient;

impl SecurePipeClient {
    pub fn connect(
        endpoint: &PipeEndpoint,
        peer_policy: &PeerIdentityPolicy,
        deadline: Instant,
    ) -> Result<SecurePipeConnection, NativeError> {
        let name = wide_str(endpoint.name());
        let handle = loop {
            // SAFETY: name is NUL-terminated and live. The explicit SQOS flags
            // request Identification and EffectiveOnly before any server data.
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED
                        | SECURITY_SQOS_PRESENT
                        | SECURITY_IDENTIFICATION
                        | SECURITY_EFFECTIVE_ONLY,
                    ptr::null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                break OwnedHandle(raw);
            }
            let code = last_error();
            if !matches!(
                code,
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_PIPE_BUSY
            ) {
                return Err(os_native_error(code, NativeOperation::ConnectPipe));
            }
            if Instant::now() >= deadline {
                return Err(NativeError::with_os_code(
                    NativeErrorCode::IoTimeout,
                    NativeOperation::ConnectPipe,
                    code,
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let expected_user_sid = current_user_sid_bytes(NativeOperation::InspectPeer)?;
        let mut server_pid = 0_u32;
        // SAFETY: handle is a connected pipe and server_pid is a live output.
        if unsafe { GetNamedPipeServerProcessId(handle.0, &raw mut server_pid) } == 0 {
            return Err(last_native_error(NativeOperation::InspectPeer));
        }
        verify_process_identity(server_pid, &expected_user_sid, peer_policy)?;
        Ok(SecurePipeConnection {
            inner: Arc::new(PipeConnectionInner {
                handle,
                server_side: false,
                disconnected: AtomicBool::new(false),
            }),
            peer_pid: server_pid,
            not_sync: PhantomData,
        })
    }
}

/// An authenticated connected transport which may move between threads but
/// cannot be shared for concurrent unsplit I/O.
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<mesh_win32::SecurePipeConnection>();
/// ```
#[derive(Debug)]
pub struct SecurePipeConnection {
    inner: Arc<PipeConnectionInner>,
    peer_pid: u32,
    // The connected transport may move between threads, but callers must
    // consume it into typed halves before concurrent access.
    not_sync: PhantomData<Cell<()>>,
}

/// Consuming read side of a connected byte-mode named pipe.
#[derive(Debug)]
pub struct SecurePipeReadHalf {
    inner: Arc<PipeConnectionInner>,
}

/// Consuming write side of a connected byte-mode named pipe.
#[derive(Debug)]
pub struct SecurePipeWriteHalf {
    inner: Arc<PipeConnectionInner>,
}

#[derive(Debug)]
struct PipeConnectionInner {
    handle: OwnedHandle,
    server_side: bool,
    disconnected: AtomicBool,
}

// SAFETY: this inner is constructed only from connected named-pipe HANDLEs,
// which support one independent overlapped read and one independent overlapped
// write concurrently. Each operation owns its stack-local OVERLAPPED, event,
// and buffer until completion is drained, so sharing creates no Rust mutable
// alias. `OwnedHandle` retains the sole matching CloseHandle responsibility.
unsafe impl Sync for PipeConnectionInner {}

impl PipeConnectionInner {
    fn read_frame(&self, limit: usize, deadline: Instant) -> Result<Vec<u8>, NativeError> {
        let result = (|| {
            let mut header = [0_u8; FRAME_HEADER_LENGTH];
            read_exact_overlapped(self.handle.0, &mut header, deadline)?;
            let length = decode_frame_length(header, limit)?;
            let mut payload = vec![0_u8; length];
            read_exact_overlapped(self.handle.0, &mut payload, deadline)?;
            Ok(payload)
        })();
        if result.is_err() {
            // A timeout/error may follow a partial prefix or body. Byte-mode
            // framing has no safe resynchronization marker, so every failed
            // frame read poisons and aborts the whole duplex connection.
            self.abort();
        }
        result
    }

    fn write_frame(
        &self,
        payload: &[u8],
        limit: usize,
        deadline: Instant,
    ) -> Result<(), NativeError> {
        let frame = encode_frame(payload, limit)?;
        let result = write_all_overlapped(self.handle.0, &frame, deadline);
        if result.is_err() {
            self.abort();
        }
        result
    }

    fn abort(&self) {
        // SAFETY: the handle remains live through `self`. Cancelling all I/O is
        // the connection-wide wakeup used when either duplex half fails.
        unsafe { CancelIoEx(self.handle.0, ptr::null()) };
        self.disconnect_server_once();
    }

    fn disconnect_server_once(&self) {
        if self.server_side && !self.disconnected.swap(true, Ordering::AcqRel) {
            // SAFETY: this is the one server-side connected pipe handle. The
            // atomic flag assigns exactly-once DisconnectNamedPipe ownership
            // across both duplex halves and the unsplit connection.
            unsafe { DisconnectNamedPipe(self.handle.0) };
        }
    }
}

impl Drop for PipeConnectionInner {
    fn drop(&mut self) {
        self.disconnect_server_once();
    }
}

impl SecurePipeConnection {
    #[must_use]
    pub const fn peer_pid(&self) -> u32 {
        self.peer_pid
    }

    /// Consume either a server or client connection into one read owner and
    /// one write owner. The shared kernel handle stays live until both halves
    /// are dropped; server disconnect responsibility remains exactly once.
    #[must_use]
    pub fn into_duplex(self) -> (SecurePipeReadHalf, SecurePipeWriteHalf) {
        let reader = SecurePipeReadHalf {
            inner: Arc::clone(&self.inner),
        };
        let writer = SecurePipeWriteHalf {
            inner: Arc::clone(&self.inner),
        };
        (reader, writer)
    }

    pub fn read_frame(&self, limit: usize, deadline: Instant) -> Result<Vec<u8>, NativeError> {
        self.inner.read_frame(limit, deadline)
    }

    pub fn write_frame(
        &self,
        payload: &[u8],
        limit: usize,
        deadline: Instant,
    ) -> Result<(), NativeError> {
        self.inner.write_frame(payload, limit, deadline)
    }

    /// Cancel pending I/O and disconnect the server side, if any.
    pub fn abort(&self) {
        self.inner.abort();
    }
}

impl SecurePipeReadHalf {
    pub fn read_frame(&mut self, limit: usize, deadline: Instant) -> Result<Vec<u8>, NativeError> {
        self.inner.read_frame(limit, deadline)
    }

    pub fn abort(&self) {
        self.inner.abort();
    }
}

impl SecurePipeWriteHalf {
    pub fn write_frame(
        &mut self,
        payload: &[u8],
        limit: usize,
        deadline: Instant,
    ) -> Result<(), NativeError> {
        self.inner.write_frame(payload, limit, deadline)
    }

    pub fn abort(&self) {
        self.inner.abort();
    }
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

// SAFETY: a Windows kernel HANDLE may be used from another thread. This type
// owns one handle and exposes no simultaneous mutable access to OVERLAPPED state.
unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: constructors accept only successful handle-returning calls;
        // this wrapper owns exactly one matching CloseHandle.
        unsafe { CloseHandle(self.0) };
    }
}

struct PipeSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl PipeSecurityDescriptor {
    fn current_user_only(user_sid: &[u8]) -> Result<Self, NativeError> {
        let sid = sid_to_string(user_sid.as_ptr().cast_mut().cast())?;
        let sddl = wide_str(&format!("D:P(A;;GA;;;{sid})"));
        let mut descriptor = ptr::null_mut();
        // SAFETY: SDDL is NUL-terminated and output points to owned LocalAlloc
        // storage on success. No descriptor length is required by this caller.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(last_native_error(NativeOperation::CreatePipe));
        }
        Ok(Self(descriptor))
    }
}

impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: conversion allocated the descriptor with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

fn verify_pipe_dacl(handle: HANDLE, expected_sid: PSID) -> Result<(), NativeError> {
    let mut descriptor = ptr::null_mut();
    // SAFETY: handle is a live kernel pipe handle and descriptor is an output
    // receiving LocalAlloc storage. Individual components are queried below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(NativeError::with_os_code(
            NativeErrorCode::AccessDenied,
            NativeOperation::InspectPipeSecurity,
            status,
        ));
    }
    let descriptor = PipeSecurityDescriptor(descriptor);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor is live and both outputs are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision) }
        == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(pipe_acl_error());
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor and outputs are live. Null/unrestricted DACL is rejected.
    let got_dacl = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if got_dacl == 0 || present == 0 || dacl.is_null() {
        return Err(pipe_acl_error());
    }
    // SAFETY: the successful descriptor query returned a non-null,
    // descriptor-owned ACL pointer which remains live with `descriptor`.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(pipe_acl_error());
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and information has the declared size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(mem::size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size fits u32"),
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 1
    {
        return Err(pipe_acl_error());
    }
    let mut ace = ptr::null_mut();
    // SAFETY: the verified ACL contains exactly one ACE.
    if unsafe { GetAce(dacl, 0, &raw mut ace) } == 0 || ace.is_null() {
        return Err(pipe_acl_error());
    }
    // SAFETY: GetAce returns an ACE beginning with ACE_HEADER.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    if header.AceType != u8::try_from(ACCESS_ALLOWED_ACE_TYPE).expect("ACE type fits u8")
        || header.AceFlags & u8::try_from(INHERITED_ACE).expect("ACE flag fits u8") != 0
        || usize::from(header.AceSize) < mem::size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(pipe_acl_error());
    }
    // SAFETY: the accepted access-allowed ACE has its fixed leading layout.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    // The object manager maps the input SDDL's GENERIC_ALL bit to the exact
    // full-access file mask when applying it to a named pipe.
    if allowed.Mask != FILE_ALL_ACCESS {
        return Err(pipe_acl_error());
    }
    let sid = (&raw const allowed.SidStart).cast_mut().cast();
    // SAFETY: the fixed ACCESS_ALLOWED_ACE prefix and ACE size were checked;
    // IsValidSid validates the self-described tail before later SID reads.
    if unsafe { IsValidSid(sid) } == 0 || !same_sid(sid, expected_sid) {
        return Err(pipe_acl_error());
    }
    if !access_allowed_ace_size_is_exact(header.AceSize, sid) {
        return Err(pipe_acl_error());
    }
    Ok(())
}

fn authenticate_client(
    pipe: HANDLE,
    expected_user_sid: &[u8],
    peer_policy: &PeerIdentityPolicy,
) -> Result<u32, NativeError> {
    // SAFETY: pipe is connected. A successful call installs only an
    // identification-level token because the client used defensive SQOS.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(last_authentication_error());
    }
    let revert = RevertGuard { active: true };
    let mut token = ptr::null_mut();
    // SAFETY: current thread is impersonating and token is a valid output.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        return Err(last_authentication_error());
    }
    let token = OwnedHandle(token);
    if token_impersonation_level(token.0)? != SecurityIdentification {
        return Err(authentication_error());
    }
    let actual_sid = token_user_sid(token.0)?;
    if !same_sid(
        actual_sid.as_ptr().cast_mut().cast(),
        expected_user_sid.as_ptr().cast_mut().cast(),
    ) {
        return Err(authentication_error());
    }
    drop(token);
    revert.revert()?;
    let mut client_pid = 0_u32;
    // SAFETY: pipe is connected and client_pid is a live output.
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut client_pid) } == 0 {
        return Err(last_authentication_error());
    }
    verify_process_identity(client_pid, expected_user_sid, peer_policy)?;
    Ok(client_pid)
}

struct RevertGuard {
    active: bool,
}

impl RevertGuard {
    fn revert(mut self) -> Result<(), NativeError> {
        // SAFETY: this guard is created only after successful pipe-client
        // impersonation and is consumed at most once.
        if unsafe { RevertToSelf() } == 0 {
            return Err(last_authentication_error());
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for RevertGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: the guard remains active only while this thread is
            // impersonating. Continuing execution after failure to shed that
            // token is unsafe, so abort instead of silently reusing the thread.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
}

fn verify_process_identity(
    pid: u32,
    expected_user_sid: &[u8],
    policy: &PeerIdentityPolicy,
) -> Result<(), NativeError> {
    // SAFETY: PID is diagnostic input from the connected pipe. The returned
    // process handle, rather than the numeric PID, binds subsequent queries.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(last_authentication_error());
    }
    let process = OwnedHandle(process);
    let mut token = ptr::null_mut();
    // SAFETY: process is live and token is a valid output.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_authentication_error());
    }
    let token = OwnedHandle(token);
    let actual_sid = token_user_sid(token.0)?;
    if !same_sid(
        actual_sid.as_ptr().cast_mut().cast(),
        expected_user_sid.as_ptr().cast_mut().cast(),
    ) {
        return Err(authentication_error());
    }
    let actual_image = process_image_path(process.0)?;
    let canonical_image =
        std::fs::canonicalize(actual_image).map_err(|_| authentication_error())?;
    if !same_path(&canonical_image, &policy.expected_image)
        || sha256_file(&canonical_image)? != policy.expected_sha256
    {
        return Err(authentication_error());
    }
    Ok(())
}

fn token_user_sid(token: HANDLE) -> Result<Vec<u8>, NativeError> {
    let mut needed = 0_u32;
    // SAFETY: null-buffer query obtains required storage length.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut needed) };
    if needed == 0 {
        return Err(last_authentication_error());
    }
    let words = usize::try_from(needed)
        .ok()
        .and_then(|bytes| bytes.checked_add(mem::size_of::<usize>() - 1))
        .and_then(|bytes| bytes.checked_div(mem::size_of::<usize>()))
        .ok_or_else(authentication_error)?;
    let mut storage = vec![0_usize; words];
    // SAFETY: aligned storage holds at least needed writable bytes.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(last_authentication_error());
    }
    // SAFETY: successful TokenUser query initialized TOKEN_USER and its SID.
    let sid = unsafe { (&*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(authentication_error());
    }
    let length = sid_length(sid).map_err(|_| authentication_error())?;
    // SAFETY: valid SID exposes exactly length readable bytes.
    Ok(unsafe { slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

fn token_impersonation_level(token: HANDLE) -> Result<i32, NativeError> {
    let mut level = 0_i32;
    let mut returned = 0_u32;
    let length = u32::try_from(mem::size_of_val(&level)).expect("impersonation level fits u32");
    // SAFETY: `level` is correctly aligned writable storage of the exact size
    // required for TokenImpersonationLevel; `returned` is a live output.
    if unsafe {
        GetTokenInformation(
            token,
            TokenImpersonationLevel,
            (&raw mut level).cast(),
            length,
            &raw mut returned,
        )
    } == 0
        || returned != length
    {
        return Err(last_authentication_error());
    }
    Ok(level)
}

fn current_user_sid_bytes(operation: NativeOperation) -> Result<Vec<u8>, NativeError> {
    current_user_sid().map_err(|error| {
        error.os_code().map_or_else(
            || NativeError::new(NativeErrorCode::AuthenticationFailed, operation),
            |code| {
                NativeError::with_os_code(NativeErrorCode::AuthenticationFailed, operation, code)
            },
        )
    })
}

fn process_image_path(process: HANDLE) -> Result<PathBuf, NativeError> {
    let mut output = vec![0_u16; PATH_CAPACITY];
    let mut length = u32::try_from(output.len()).expect("path capacity fits u32");
    // SAFETY: process allows limited query; output and length are valid.
    if unsafe { QueryFullProcessImageNameW(process, 0, output.as_mut_ptr(), &raw mut length) } == 0
    {
        return Err(last_authentication_error());
    }
    output.truncate(usize::try_from(length).map_err(|_| authentication_error())?);
    Ok(PathBuf::from(OsString::from_wide(&output)))
}

fn connect_overlapped(handle: HANDLE, deadline: Instant) -> Result<(), NativeError> {
    let mut operation = OverlappedOperation::new()?;
    // SAFETY: handle is an overlapped server pipe and operation remains live
    // until immediate completion or cancellation has been drained.
    if unsafe { ConnectNamedPipe(handle, &raw mut operation.overlapped) } != 0 {
        return Ok(());
    }
    let code = last_error();
    if code == ERROR_PIPE_CONNECTED {
        return Ok(());
    }
    if code != ERROR_IO_PENDING {
        return Err(os_native_error(code, NativeOperation::ConnectPipe));
    }
    wait_overlapped(
        handle,
        &mut operation,
        deadline,
        NativeOperation::ConnectPipe,
    )
    .map(|_| ())
}

fn read_exact_overlapped(
    handle: HANDLE,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), NativeError> {
    while !buffer.is_empty() {
        let transferred = read_overlapped(handle, buffer, deadline)?;
        if transferred == 0 {
            return Err(NativeError::new(
                NativeErrorCode::ConnectionClosed,
                NativeOperation::ReadFrame,
            ));
        }
        buffer = &mut buffer[transferred..];
    }
    Ok(())
}

fn read_overlapped(
    handle: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, NativeError> {
    let mut operation = OverlappedOperation::new()?;
    let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    let mut immediate = 0_u32;
    // SAFETY: buffer and OVERLAPPED remain live through completion/cancel drain.
    if unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr(),
            length,
            &raw mut immediate,
            &raw mut operation.overlapped,
        )
    } != 0
    {
        return usize::try_from(immediate).map_err(|_| frame_io_error(NativeOperation::ReadFrame));
    }
    let code = last_error();
    if matches!(code, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
        return Err(NativeError::with_os_code(
            NativeErrorCode::ConnectionClosed,
            NativeOperation::ReadFrame,
            code,
        ));
    }
    if code != ERROR_IO_PENDING {
        return Err(os_native_error(code, NativeOperation::ReadFrame));
    }
    let transferred =
        wait_overlapped(handle, &mut operation, deadline, NativeOperation::ReadFrame)?;
    usize::try_from(transferred).map_err(|_| frame_io_error(NativeOperation::ReadFrame))
}

fn write_all_overlapped(
    handle: HANDLE,
    mut buffer: &[u8],
    deadline: Instant,
) -> Result<(), NativeError> {
    while !buffer.is_empty() {
        let transferred = write_overlapped(handle, buffer, deadline)?;
        if transferred == 0 {
            return Err(NativeError::new(
                NativeErrorCode::ConnectionClosed,
                NativeOperation::WriteFrame,
            ));
        }
        buffer = &buffer[transferred..];
    }
    Ok(())
}

fn write_overlapped(
    handle: HANDLE,
    buffer: &[u8],
    deadline: Instant,
) -> Result<usize, NativeError> {
    let mut operation = OverlappedOperation::new()?;
    let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    let mut immediate = 0_u32;
    // SAFETY: buffer and OVERLAPPED remain live through completion/cancel drain.
    if unsafe {
        WriteFile(
            handle,
            buffer.as_ptr(),
            length,
            &raw mut immediate,
            &raw mut operation.overlapped,
        )
    } != 0
    {
        return usize::try_from(immediate).map_err(|_| frame_io_error(NativeOperation::WriteFrame));
    }
    let code = last_error();
    if matches!(code, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
        return Err(NativeError::with_os_code(
            NativeErrorCode::ConnectionClosed,
            NativeOperation::WriteFrame,
            code,
        ));
    }
    if code != ERROR_IO_PENDING {
        return Err(os_native_error(code, NativeOperation::WriteFrame));
    }
    let transferred = wait_overlapped(
        handle,
        &mut operation,
        deadline,
        NativeOperation::WriteFrame,
    )?;
    usize::try_from(transferred).map_err(|_| frame_io_error(NativeOperation::WriteFrame))
}

struct OverlappedOperation {
    event: OwnedHandle,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    fn new() -> Result<Self, NativeError> {
        // SAFETY: null security/name pointers request an unnamed noninheritable event.
        let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if raw.is_null() {
            return Err(last_native_error(NativeOperation::ConnectPipe));
        }
        let event = OwnedHandle(raw);
        let overlapped = OVERLAPPED {
            hEvent: event.0,
            ..OVERLAPPED::default()
        };
        Ok(Self { event, overlapped })
    }
}

fn wait_overlapped(
    handle: HANDLE,
    operation: &mut OverlappedOperation,
    deadline: Instant,
    native_operation: NativeOperation,
) -> Result<u32, NativeError> {
    let timeout = remaining_millis(deadline)?;
    // SAFETY: event remains live in operation through the wait.
    let wait = unsafe { WaitForSingleObject(operation.event.0, timeout) };
    if wait == WAIT_TIMEOUT {
        // SAFETY: exact OVERLAPPED belongs to this handle and remains live. A
        // cancellation race is tolerated; the infinite wait below drains it.
        unsafe { CancelIoEx(handle, &raw const operation.overlapped) };
        // SAFETY: cancellation completion is always drained before returning.
        unsafe { WaitForSingleObject(operation.event.0, INFINITE) };
        let mut ignored = 0_u32;
        // SAFETY: operation is complete/cancelled and storage remains live.
        unsafe {
            GetOverlappedResult(handle, &raw const operation.overlapped, &raw mut ignored, 0)
        };
        return Err(NativeError::new(
            NativeErrorCode::IoTimeout,
            native_operation,
        ));
    }
    if wait != WAIT_OBJECT_0 {
        return Err(last_native_error(native_operation));
    }
    let mut transferred = 0_u32;
    // SAFETY: signaled event means operation completed and all pointers live.
    if unsafe {
        GetOverlappedResult(
            handle,
            &raw const operation.overlapped,
            &raw mut transferred,
            0,
        )
    } == 0
    {
        let code = last_error();
        if matches!(code, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
            return Err(NativeError::with_os_code(
                NativeErrorCode::ConnectionClosed,
                native_operation,
                code,
            ));
        }
        return Err(os_native_error(code, native_operation));
    }
    Ok(transferred)
}

fn remaining_millis(deadline: Instant) -> Result<u32, NativeError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(0);
    }
    let millis = remaining.as_millis().max(1).min(u128::from(u32::MAX - 1));
    u32::try_from(millis).map_err(|_| {
        NativeError::new(
            NativeErrorCode::InvalidArgument,
            NativeOperation::ConnectPipe,
        )
    })
}

fn sid_to_string(sid: PSID) -> Result<String, NativeError> {
    // SAFETY: callers provide a Windows-created or byte-for-byte cloned SID;
    // validate its self-described layout before conversion.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid_endpoint());
    }
    let mut output = ptr::null_mut();
    // SAFETY: sid is valid and output receives LocalAlloc UTF-16 storage.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut output) } == 0 || output.is_null() {
        return Err(last_native_error(NativeOperation::DeriveEndpoint));
    }
    let owned = OwnedLocalString(output);
    let mut length = 0_usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated allocation.
    while unsafe { *owned.0.add(length) } != 0 {
        length = length.checked_add(1).ok_or_else(invalid_endpoint)?;
    }
    // SAFETY: length was found within the NUL-terminated allocation.
    String::from_utf16(unsafe { slice::from_raw_parts(owned.0, length) })
        .map_err(|_| invalid_endpoint())
}

struct OwnedLocalString(*mut u16);

impl Drop for OwnedLocalString {
    fn drop(&mut self) {
        // SAFETY: SID conversion allocated this string with LocalAlloc.
        unsafe { LocalFree(self.0.cast()) };
    }
}

fn validate_install_id(install_id: &str) -> Result<(), NativeError> {
    if install_id.len() != INSTALL_ID_HEX_LENGTH
        || !install_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_endpoint());
    }
    Ok(())
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
    let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
    let (Ok(left_length), Ok(right_length)) =
        (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: both pointers address exactly the explicitly supplied UTF-16
    // lengths. Ordinal comparison is lossless for Windows path code units and
    // uses the platform's invariant case-insensitive path comparison rules.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_length, right.as_ptr(), right_length, 1)
            == CSTR_EQUAL
    }
}

fn wide_str(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error() -> u32 {
    // SAFETY: called immediately after a failing Win32 operation.
    unsafe { GetLastError() }
}

fn last_native_error(operation: NativeOperation) -> NativeError {
    os_native_error(last_error(), operation)
}

fn os_native_error(code: u32, operation: NativeOperation) -> NativeError {
    let category = if code == ERROR_ACCESS_DENIED {
        NativeErrorCode::AccessDenied
    } else {
        NativeErrorCode::OsFailure
    };
    NativeError::with_os_code(category, operation, code)
}

fn io_error(error: &std::io::Error, operation: NativeOperation) -> NativeError {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .map_or_else(
            || NativeError::new(NativeErrorCode::OsFailure, operation),
            |code| os_native_error(code, operation),
        )
}

const fn invalid_endpoint() -> NativeError {
    NativeError::new(
        NativeErrorCode::InvalidArgument,
        NativeOperation::DeriveEndpoint,
    )
}

const fn authentication_error() -> NativeError {
    NativeError::new(
        NativeErrorCode::AuthenticationFailed,
        NativeOperation::InspectPeer,
    )
}

const fn invalid_peer_policy() -> NativeError {
    NativeError::new(
        NativeErrorCode::InvalidArgument,
        NativeOperation::InspectPeer,
    )
}

fn last_authentication_error() -> NativeError {
    NativeError::with_os_code(
        NativeErrorCode::AuthenticationFailed,
        NativeOperation::InspectPeer,
        last_error(),
    )
}

const fn pipe_acl_error() -> NativeError {
    NativeError::new(
        NativeErrorCode::AccessDenied,
        NativeOperation::InspectPipeSecurity,
    )
}

const fn frame_io_error(operation: NativeOperation) -> NativeError {
    NativeError::new(NativeErrorCode::OsFailure, operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{REQUEST_FRAME_LIMIT, RESPONSE_FRAME_LIMIT};
    use std::sync::{Condvar, Mutex, mpsc};
    use std::thread;

    fn endpoint() -> PipeEndpoint {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).expect("random install id");
        let install_id = data_encoding::HEXLOWER.encode(&random);
        PipeEndpoint::for_current_user(&install_id).expect("endpoint")
    }

    #[test]
    fn pipe_name_is_deterministic_and_contains_no_scope_text() {
        let first =
            derive_pipe_name("S-1-5-21-123", "0123456789abcdef0123456789abcdef").expect("first");
        let second =
            derive_pipe_name("S-1-5-21-123", "0123456789abcdef0123456789abcdef").expect("second");
        assert_eq!(first, second);
        assert!(first.starts_with(PIPE_PREFIX));
        assert!(!first.contains("S-1-5-21"));
        assert!(!first.contains("0123456789abcdef"));
    }

    #[test]
    fn path_identity_is_lossless_and_windows_ordinal_case_insensitive() {
        assert!(same_path(
            Path::new(r"C:\CodexAgentMesh\DAEMON.exe"),
            Path::new(r"c:\codexagentmesh\daemon.EXE"),
        ));

        let left = PathBuf::from(OsString::from_wide(&[
            u16::from(b'C'),
            u16::from(b':'),
            0xd800,
        ]));
        let right = PathBuf::from(OsString::from_wide(&[
            u16::from(b'C'),
            u16::from(b':'),
            0xd801,
        ]));
        assert!(!same_path(&left, &right));
    }

    #[test]
    fn production_peer_policy_requires_the_digest_addressed_stable_slot() {
        let directory = tempfile::tempdir().expect("root");
        crate::protect_data_root(directory.path()).expect("protect root");
        let root = crate::validate_data_root(directory.path()).expect("validate root");
        let contents = b"stable peer fixture";
        let digest: [u8; 32] = Sha256::digest(contents).into();
        let relative = PathBuf::from("installs")
            .join("0123456789abcdef0123456789abcdef")
            .join("bin")
            .join(HEXLOWER.encode(&digest))
            .join("mesh-daemon.exe");
        std::fs::create_dir_all(
            root.path()
                .join(relative.parent().expect("stable slot parent")),
        )
        .expect("slot directories");
        std::fs::write(root.path().join(&relative), contents).expect("peer fixture");
        let policy =
            PeerIdentityPolicy::from_stable_slot(&root, &relative, digest).expect("policy");
        assert_eq!(policy.expected_sha256(), &digest);
        let wrong_executable = relative.with_file_name("mesh-helper.exe");
        assert_eq!(
            PeerIdentityPolicy::from_stable_slot(&root, &wrong_executable, digest)
                .expect_err("arbitrary executable name")
                .code(),
            NativeErrorCode::InvalidArgument
        );
        assert_eq!(
            PeerIdentityPolicy::from_stable_slot(
                &root,
                Path::new("plugin-cache/mesh-native.exe"),
                digest,
            )
            .expect_err("plugin cache path")
            .code(),
            NativeErrorCode::InvalidArgument
        );
    }

    #[test]
    fn production_peer_policy_accepts_only_a_verified_control_slot_artifact() {
        let directory = tempfile::tempdir().expect("control root");
        crate::protect_control_root(directory.path()).expect("protect control root");
        let root = crate::validate_control_root(directory.path()).expect("validate control root");
        let contents = b"stable control peer fixture";
        let digest: [u8; 32] = Sha256::digest(contents).into();
        let relative = PathBuf::from("installs")
            .join("0123456789abcdef0123456789abcdef")
            .join("bin")
            .join(HEXLOWER.encode(&digest))
            .join("mesh-daemon.exe");
        root.create_relative_directories(relative.parent().expect("runtime parent"))
            .expect("create protected runtime parent");
        let mut source = contents.as_slice();
        root.copy_reader_verified(&mut source, &relative, digest)
            .expect("copy protected stable artifact");

        let policy = PeerIdentityPolicy::from_control_slot(&root, &relative, digest)
            .expect("control-slot policy");
        assert_eq!(policy.expected_sha256(), &digest);
        assert_eq!(
            PeerIdentityPolicy::from_control_slot(&root, &relative, [0; 32])
                .expect_err("record digest drift")
                .code(),
            NativeErrorCode::InvalidArgument
        );
    }

    #[test]
    fn secure_pipe_round_trips_and_times_out() {
        let endpoint = endpoint();
        let policy = PeerIdentityPolicy::for_current_executable().expect("policy");
        let server = SecurePipeServer::bind_first(&endpoint, policy.clone()).expect("server");
        let server_thread = thread::spawn(move || {
            let connection = server
                .accept(Instant::now() + Duration::from_secs(2))
                .expect("accept");
            let request = connection
                .read_frame(REQUEST_FRAME_LIMIT, Instant::now() + Duration::from_secs(2))
                .expect("request");
            assert_eq!(request, b"request");
            connection
                .write_frame(
                    b"response",
                    RESPONSE_FRAME_LIMIT,
                    Instant::now() + Duration::from_secs(2),
                )
                .expect("response");
            assert_eq!(
                connection
                    .read_frame(
                        REQUEST_FRAME_LIMIT,
                        Instant::now() + Duration::from_millis(25)
                    )
                    .expect_err("timeout")
                    .code(),
                NativeErrorCode::IoTimeout
            );
        });
        let connection =
            SecurePipeClient::connect(&endpoint, &policy, Instant::now() + Duration::from_secs(2))
                .expect("connect");
        connection
            .write_frame(
                b"request",
                REQUEST_FRAME_LIMIT,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("request");
        assert_eq!(
            connection
                .read_frame(
                    RESPONSE_FRAME_LIMIT,
                    Instant::now() + Duration::from_secs(2)
                )
                .expect("response"),
            b"response"
        );
        server_thread.join().expect("server thread");
    }

    #[test]
    fn pipe_server_rejects_a_client_without_identification_sqos() {
        let endpoint = endpoint();
        let policy = PeerIdentityPolicy::for_current_executable().expect("policy");
        let server = SecurePipeServer::bind_first(&endpoint, policy).expect("server");
        let server_thread = thread::spawn(move || {
            let error = server
                .accept(Instant::now() + Duration::from_secs(2))
                .expect_err("default impersonation must not be admitted");
            assert_eq!(error.code(), NativeErrorCode::AuthenticationFailed);
            assert_eq!(error.operation(), NativeOperation::InspectPeer);
        });

        let name = wide_str(endpoint.name());
        let deadline = Instant::now() + Duration::from_secs(2);
        let client = loop {
            // SAFETY: name is NUL-terminated and live. This negative fixture
            // deliberately omits SECURITY_SQOS_PRESENT/IDENTIFICATION so the
            // server must reject the resulting impersonation token level.
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                break OwnedHandle(raw);
            }
            assert!(
                matches!(last_error(), ERROR_PIPE_BUSY | ERROR_FILE_NOT_FOUND),
                "unexpected raw client error"
            );
            assert!(Instant::now() < deadline, "raw client connection timed out");
            thread::sleep(Duration::from_millis(10));
        };
        server_thread.join().expect("server thread");
        drop(client);
    }

    #[test]
    fn consuming_server_split_disconnects_only_after_both_halves_drop() {
        let endpoint = endpoint();
        let policy = PeerIdentityPolicy::for_current_executable().expect("policy");
        let server = SecurePipeServer::bind_first(&endpoint, policy.clone()).expect("server");
        let response_received = Arc::new((Mutex::new(false), Condvar::new()));
        let server_response_received = Arc::clone(&response_received);
        let server_thread = thread::spawn(move || {
            let connection = server
                .accept(Instant::now() + Duration::from_secs(2))
                .expect("accept");
            let (mut reader, mut writer) = connection.into_duplex();
            let request = reader
                .read_frame(REQUEST_FRAME_LIMIT, Instant::now() + Duration::from_secs(2))
                .expect("split read");
            assert_eq!(request, b"request");
            drop(reader);
            writer
                .write_frame(
                    b"response after reader drop",
                    RESPONSE_FRAME_LIMIT,
                    Instant::now() + Duration::from_secs(2),
                )
                .expect("writer remains connected");
            let (lock, wake) = &*server_response_received;
            let mut received = lock.lock().expect("response gate");
            while !*received {
                received = wake.wait(received).expect("response gate wait");
            }
            drop(writer);
        });

        let client =
            SecurePipeClient::connect(&endpoint, &policy, Instant::now() + Duration::from_secs(2))
                .expect("connect");
        client
            .write_frame(
                b"request",
                REQUEST_FRAME_LIMIT,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("request");
        assert_eq!(
            client
                .read_frame(
                    RESPONSE_FRAME_LIMIT,
                    Instant::now() + Duration::from_secs(2),
                )
                .expect("response"),
            b"response after reader drop"
        );
        let (lock, wake) = &*response_received;
        *lock.lock().expect("response gate") = true;
        wake.notify_all();
        server_thread.join().expect("server thread");
        assert!(
            client
                .read_frame(
                    RESPONSE_FRAME_LIMIT,
                    Instant::now() + Duration::from_millis(100),
                )
                .is_err(),
            "final server-half drop closes the connection"
        );
    }

    #[test]
    fn partial_frame_timeout_poison_closes_connection() {
        let endpoint = endpoint();
        let policy = PeerIdentityPolicy::for_current_executable().expect("policy");
        let server = SecurePipeServer::bind_first(&endpoint, policy.clone()).expect("server");
        let (partial_written, partial_ready) = mpsc::sync_channel(0);
        let server_thread = thread::spawn(move || {
            let connection = server
                .accept(Instant::now() + Duration::from_secs(2))
                .expect("accept");
            partial_ready
                .recv_timeout(Duration::from_secs(2))
                .expect("partial prefix written");
            assert_eq!(
                connection
                    .read_frame(
                        REQUEST_FRAME_LIMIT,
                        Instant::now() + Duration::from_millis(50),
                    )
                    .expect_err("partial header must time out")
                    .code(),
                NativeErrorCode::IoTimeout
            );
            assert!(
                connection
                    .read_frame(
                        REQUEST_FRAME_LIMIT,
                        Instant::now() + Duration::from_millis(50),
                    )
                    .is_err(),
                "a timed-out partial frame is never resumed"
            );
        });
        let client =
            SecurePipeClient::connect(&endpoint, &policy, Instant::now() + Duration::from_secs(2))
                .expect("connect");
        write_all_overlapped(
            client.inner.handle.0,
            &[0, 0],
            Instant::now() + Duration::from_secs(2),
        )
        .expect("partial frame prefix");
        partial_written.send(()).expect("signal partial prefix");
        server_thread.join().expect("server thread");
    }

    #[test]
    fn additional_instance_requires_a_live_owned_instance() {
        let endpoint = endpoint();
        let policy = PeerIdentityPolicy::for_current_executable().expect("policy");
        let first = SecurePipeServer::bind_first(&endpoint, policy.clone()).expect("first");
        let additional = first.bind_additional().expect("additional");
        assert_eq!(
            SecurePipeServer::bind_first(&endpoint, policy)
                .expect_err("first-instance collision")
                .code(),
            NativeErrorCode::SingletonConflict
        );
        drop(first);
        let third = additional
            .bind_additional()
            .expect("live additional proves ownership");
        drop(additional);
        drop(third);
    }

    #[test]
    fn wrong_peer_digest_is_rejected() {
        let endpoint = endpoint();
        let policy = PeerIdentityPolicy::for_current_executable().expect("policy");
        let bad = PeerIdentityPolicy::from_exact_image(policy.expected_image(), [0; 32])
            .expect("bad policy fixture");
        let server = SecurePipeServer::bind_first(&endpoint, bad).expect("server");
        let server_thread = thread::spawn(move || {
            assert_eq!(
                server
                    .accept(Instant::now() + Duration::from_secs(2))
                    .expect_err("bad client digest")
                    .code(),
                NativeErrorCode::AuthenticationFailed
            );
        });
        let connection =
            SecurePipeClient::connect(&endpoint, &policy, Instant::now() + Duration::from_secs(2))
                .expect("server identity is valid");
        drop(connection);
        server_thread.join().expect("server thread");
    }
}
