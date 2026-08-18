//! Suspended process creation, receipt identity, and tree-kill primitives.
//!
//! This module is the only spawn path a provider supervisor may use. It does
//! not call `std::process::Command`, does not concatenate a caller command
//! string, and does not allocate a console or PTY. The child is created
//! `CREATE_SUSPENDED` with an explicit argument array, an allowlisted
//! environment block, and anonymous stdio pipes whose parent ends are never
//! inheritable.
//!
//! The caller must assign the still-suspended process to a
//! [`crate::NonBreakawayJob`], persist a [`ProcessIdentity`] receipt, and only
//! then resume the primary thread. Dropping a not-yet-resumed process
//! terminates it so adapter code cannot run after a failed commit.

#![allow(clippy::missing_errors_doc)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::mem;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, FILETIME, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    GetProcessTimes, INFINITE, InitializeProcThreadAttributeList, OpenProcess,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::{NativeError, NativeErrorCode, NativeOperation};

const PATH_CAPACITY: usize = 32_768;
const RECEIPT_VERSION: &str = "v1";
const JOB_KILL_EXIT_CODE: u32 = 1;
const STILL_ACTIVE: u32 = 259;

/// Commit-friendly identity of one created process.
///
/// A numeric PID is not a receipt: Windows reuses PIDs. The creation
/// `FILETIME` plus the queried image path bind the identifier to one
/// incarnation of that PID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pid: u32,
    creation_time: u64,
    image: PathBuf,
}

impl ProcessIdentity {
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn creation_time(&self) -> u64 {
        self.creation_time
    }

    #[must_use]
    pub fn image(&self) -> &Path {
        &self.image
    }

    /// Encodes `v1:{pid}:{creation_hex}:{image}` for the attempt `process_receipt`
    /// column. The image is the trailing field so colons in the path stay intact.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{RECEIPT_VERSION}:{}:{:016x}:{}",
            self.pid,
            self.creation_time,
            self.image.to_string_lossy()
        )
    }

    /// Parses a receipt produced by [`ProcessIdentity::encode`].
    pub fn decode(value: &str) -> Result<Self, NativeError> {
        let mut parts = value.splitn(4, ':');
        let version = parts.next().ok_or_else(invalid_receipt)?;
        let pid = parts.next().ok_or_else(invalid_receipt)?;
        let created = parts.next().ok_or_else(invalid_receipt)?;
        let image = parts.next().ok_or_else(invalid_receipt)?;
        if version != RECEIPT_VERSION || pid.is_empty() || created.is_empty() || image.is_empty() {
            return Err(invalid_receipt());
        }
        let pid = pid.parse::<u32>().map_err(|_| invalid_receipt())?;
        let creation_time = u64::from_str_radix(created, 16).map_err(|_| invalid_receipt())?;
        Ok(Self {
            pid,
            creation_time,
            image: PathBuf::from(image),
        })
    }
}

/// How [`OwnedProcess::wait_timeout`] finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessWait {
    Exited(u32),
    TimedOut,
}

/// Caller-supplied spawn inputs. The environment list is already allowlisted;
/// this module never reads or dumps the parent environment.
#[derive(Clone, Debug)]
pub struct ProcessSpawnSpec<'a> {
    pub executable: &'a Path,
    pub arguments: &'a [OsString],
    pub environment: &'a [(OsString, OsString)],
    pub current_dir: Option<&'a Path>,
}

/// A process created suspended, with exclusive parent stdio pipe ends.
///
/// The primary thread stays suspended until [`OwnedProcess::resume_primary_thread`].
/// Taking stdin/stdout/stderr transfers the parent pipe ends to the caller.
pub struct OwnedProcess {
    process: OwnedHandle,
    thread: Option<OwnedHandle>,
    identity: ProcessIdentity,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    resumed: bool,
}

impl OwnedProcess {
    #[must_use]
    pub const fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn resumed(&self) -> bool {
        self.resumed
    }

    pub fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    /// Resumes only the primary thread created with `CREATE_SUSPENDED`.
    pub fn resume_primary_thread(&mut self) -> Result<(), NativeError> {
        if self.resumed {
            return Ok(());
        }
        let thread = self.thread.as_ref().ok_or_else(|| {
            NativeError::new(
                NativeErrorCode::InvalidArgument,
                NativeOperation::ResumeThread,
            )
        })?;
        // SAFETY: `thread` is the primary thread handle from a successful
        // CreateProcessW with CREATE_SUSPENDED. ResumeThread is called once.
        let previous = unsafe { ResumeThread(thread.as_raw_handle().cast()) };
        if previous == u32::MAX {
            return Err(last_native_error(NativeOperation::ResumeThread));
        }
        self.resumed = true;
        self.thread = None;
        Ok(())
    }

    pub fn terminate(&self, exit_code: u32) -> Result<(), NativeError> {
        // SAFETY: `process` is an owned process handle. TerminateProcess does
        // not consume the handle.
        if unsafe { TerminateProcess(self.process.as_raw_handle().cast(), exit_code) } == 0 {
            return Err(last_native_error(NativeOperation::TerminateProcess));
        }
        Ok(())
    }

    pub fn wait_timeout(&self, timeout: Duration) -> Result<ProcessWait, NativeError> {
        let millis = duration_to_millis(timeout);
        // SAFETY: the process handle remains owned by this wrapper for the
        // duration of the wait. A timeout does not invalidate the handle.
        let status = unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), millis) };
        if status == WAIT_OBJECT_0 {
            let code = self
                .exit_code()?
                .ok_or_else(|| last_native_error(NativeOperation::InspectProcess))?;
            Ok(ProcessWait::Exited(code))
        } else if status == WAIT_TIMEOUT {
            Ok(ProcessWait::TimedOut)
        } else {
            Err(last_native_error(NativeOperation::InspectProcess))
        }
    }

    pub fn exit_code(&self) -> Result<Option<u32>, NativeError> {
        let mut code = 0_u32;
        // SAFETY: `process` is live and `code` is writable u32 storage.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &raw mut code) } == 0 {
            return Err(last_native_error(NativeOperation::InspectProcess));
        }
        if code == STILL_ACTIVE {
            Ok(None)
        } else {
            Ok(Some(code))
        }
    }

    pub fn is_running(&self) -> Result<bool, NativeError> {
        Ok(self.exit_code()?.is_none())
    }
}

impl AsRawHandle for OwnedProcess {
    fn as_raw_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.resumed {
            // A not-yet-resumed child has not executed adapter code. Kill it
            // so a forgotten handle cannot later be resumed by accident.
            let _ = self.terminate(JOB_KILL_EXIT_CODE);
        }
    }
}

/// Creates `executable` suspended with piped stdio and a private environment.
///
/// The child does not inherit the caller's stdout. No shell is invoked.
pub fn create_suspended_process(spec: &ProcessSpawnSpec<'_>) -> Result<OwnedProcess, NativeError> {
    if spec.executable.as_os_str().is_empty() {
        return Err(NativeError::new(
            NativeErrorCode::InvalidArgument,
            NativeOperation::CreateProcess,
        ));
    }
    let application = wide_os(spec.executable.as_os_str());
    let mut command_line = command_line(spec.executable.as_os_str(), spec.arguments)?;
    let mut environment = environment_block(spec.environment)?;
    let current_dir = spec.current_dir.map(|path| wide_os(path.as_os_str()));
    let mut stdio = StdioPipes::create()?;
    let mut process_info = PROCESS_INFORMATION {
        hProcess: ptr::null_mut(),
        hThread: ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };

    let created = with_startup_attributes(&stdio, |startup| {
        let directory = current_dir.as_ref().map_or(ptr::null(), Vec::as_ptr);
        // SAFETY: `application` and optional `directory` are NUL-terminated
        // wide strings that outlive the call. `command_line` is a mutable
        // NUL-terminated buffer as CreateProcessW requires. `environment` is
        // a UTF-16 block terminated by two NULs. `startup` is a completed
        // STARTUPINFOEXW whose handle list points at the three child pipe
        // ends. `process_info` is writable out-storage. Inherit is restricted
        // to that handle list; the caller's stdout is not listed.
        unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_mut_ptr().cast(),
                directory,
                (&raw mut startup.StartupInfo).cast(),
                &raw mut process_info,
            )
        }
    })?;
    if created == 0 {
        return Err(last_native_error(NativeOperation::CreateProcess));
    }
    stdio.close_child_ends();
    // SAFETY: CreateProcessW succeeded, so both returned handles are valid
    // and exclusively owned by this process. from_raw_handle takes that
    // ownership; we never CloseHandle them separately.
    let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess.cast()) };
    let thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread.cast()) };
    // Wrap before identity/stdio so any later failure Drop-kills the still
    // suspended child. Closing the raw handles alone would leak it.
    let mut child = OwnedProcess {
        process,
        thread: Some(thread),
        identity: ProcessIdentity {
            pid: process_info.dwProcessId,
            creation_time: 0,
            image: PathBuf::new(),
        },
        stdin: None,
        stdout: None,
        stderr: None,
        resumed: false,
    };
    child.identity = capture_identity(
        child.process.as_raw_handle().cast(),
        process_info.dwProcessId,
    )?;
    child.stdin = Some(file_from_handle(stdio.take_parent_stdin())?);
    child.stdout = Some(file_from_handle(stdio.take_parent_stdout())?);
    child.stderr = Some(file_from_handle(stdio.take_parent_stderr())?);
    Ok(child)
}

/// Returns whether `identity` still names a live process incarnation.
///
/// This is a fence, not a resume path. A live match is never adopted as a
/// leftover CLI; the supervisor must create a new process for a new attempt.
pub fn process_identity_is_live(identity: &ProcessIdentity) -> Result<bool, NativeError> {
    // SAFETY: the PID is untrusted numeric input. The returned handle, not
    // the PID, is what subsequent queries use. A null handle is checked.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        // SAFETY: called immediately after the failed OpenProcess.
        let code = unsafe { GetLastError() };
        if code == ERROR_ACCESS_DENIED {
            return Err(NativeError::with_os_code(
                NativeErrorCode::AccessDenied,
                NativeOperation::InspectProcess,
                code,
            ));
        }
        return Ok(false);
    }
    // SAFETY: OpenProcess succeeded; this handle is exclusively owned here.
    let process = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    let creation = process_creation_time(process.as_raw_handle().cast())?;
    if creation != identity.creation_time {
        return Ok(false);
    }
    let mut code = 0_u32;
    // SAFETY: `process` is live and `code` is writable u32 storage.
    if unsafe { GetExitCodeProcess(process.as_raw_handle().cast(), &raw mut code) } == 0 {
        return Err(last_native_error(NativeOperation::InspectProcess));
    }
    Ok(code == STILL_ACTIVE)
}

/// Returns whether `pid` currently has an active process.
///
/// This is a test/diagnostic fence, not a receipt. PID reuse means a yes
/// answer without a creation time is not identity proof.
pub fn process_id_is_active(pid: u32) -> Result<bool, NativeError> {
    // SAFETY: the PID is untrusted. A null handle is treated as not active.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Ok(false);
    }
    // SAFETY: OpenProcess succeeded; this handle is exclusively owned here.
    let process = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    let mut code = 0_u32;
    // SAFETY: `process` is live and `code` is writable u32 storage.
    if unsafe { GetExitCodeProcess(process.as_raw_handle().cast(), &raw mut code) } == 0 {
        return Err(last_native_error(NativeOperation::InspectProcess));
    }
    Ok(code == STILL_ACTIVE)
}

fn capture_identity(process: HANDLE, pid: u32) -> Result<ProcessIdentity, NativeError> {
    Ok(ProcessIdentity {
        pid,
        creation_time: process_creation_time(process)?,
        image: process_image_path(process)?,
    })
}

fn process_creation_time(process: HANDLE) -> Result<u64, NativeError> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: `process` allows limited query; all four FILETIME out-params
    // point at distinct live stack structs for the duration of the call.
    if unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(last_native_error(NativeOperation::InspectProcess));
    }
    Ok(filetime_to_u64(creation))
}

fn process_image_path(process: HANDLE) -> Result<PathBuf, NativeError> {
    let mut output = vec![0_u16; PATH_CAPACITY];
    let mut length = u32::try_from(output.len()).map_err(|_| {
        NativeError::new(NativeErrorCode::OsFailure, NativeOperation::InspectProcess)
    })?;
    // SAFETY: `process` allows limited query; `output` has `length` writable
    // UTF-16 units and the API writes at most that many.
    if unsafe { QueryFullProcessImageNameW(process, 0, output.as_mut_ptr(), &raw mut length) } == 0
    {
        return Err(last_native_error(NativeOperation::InspectProcess));
    }
    let length = usize::try_from(length).map_err(|_| {
        NativeError::new(NativeErrorCode::OsFailure, NativeOperation::InspectProcess)
    })?;
    output.truncate(length);
    Ok(PathBuf::from(OsString::from_wide(&output)))
}

fn filetime_to_u64(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn command_line(program: &OsStr, arguments: &[OsString]) -> Result<Vec<u16>, NativeError> {
    let mut command = Vec::new();
    append_quoted(&mut command, program);
    for argument in arguments {
        command.push(u16::from(b' '));
        append_quoted(&mut command, argument);
    }
    if command.contains(&0) {
        return Err(NativeError::new(
            NativeErrorCode::InvalidArgument,
            NativeOperation::CreateProcess,
        ));
    }
    command.push(0);
    Ok(command)
}

fn append_quoted(command: &mut Vec<u16>, value: &OsStr) {
    let encoded: Vec<u16> = value.encode_wide().collect();
    let quote = encoded.is_empty()
        || encoded.iter().any(|&unit| {
            unit == u16::from(b' ') || unit == u16::from(b'\t') || unit == u16::from(b'"')
        });
    if quote {
        command.push(u16::from(b'"'));
    }
    let mut backslashes = 0_usize;
    for &unit in &encoded {
        if unit == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        if unit == u16::from(b'"') {
            command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
        } else {
            command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        }
        backslashes = 0;
        command.push(unit);
    }
    if quote {
        command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
        command.push(u16::from(b'"'));
    } else {
        command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
    }
}

fn environment_block(pairs: &[(OsString, OsString)]) -> Result<Vec<u16>, NativeError> {
    let mut ordered = pairs.to_vec();
    ordered.sort_by(|left, right| {
        left.0
            .to_ascii_uppercase()
            .cmp(&right.0.to_ascii_uppercase())
    });
    let mut block = Vec::new();
    for (key, value) in ordered {
        if key.is_empty()
            || key
                .encode_wide()
                .any(|unit| unit == 0 || unit == u16::from(b'='))
        {
            return Err(NativeError::new(
                NativeErrorCode::InvalidArgument,
                NativeOperation::CreateProcess,
            ));
        }
        if value.encode_wide().any(|unit| unit == 0) {
            return Err(NativeError::new(
                NativeErrorCode::InvalidArgument,
                NativeOperation::CreateProcess,
            ));
        }
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    Ok(block)
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.last().is_none_or(|unit| *unit != 0) {
        wide.push(0);
    }
    wide
}

struct StdioPipes {
    parent_stdin: Option<HANDLE>,
    child_stdin: Option<HANDLE>,
    parent_stdout: Option<HANDLE>,
    child_stdout: Option<HANDLE>,
    parent_stderr: Option<HANDLE>,
    child_stderr: Option<HANDLE>,
}

impl StdioPipes {
    fn create() -> Result<Self, NativeError> {
        let (child_stdin, parent_stdin) = anonymous_pipe(true, false)?;
        let mut pipes = Self {
            parent_stdin: Some(parent_stdin),
            child_stdin: Some(child_stdin),
            parent_stdout: None,
            child_stdout: None,
            parent_stderr: None,
            child_stderr: None,
        };
        let (parent_stdout, child_stdout) = anonymous_pipe(false, true)?;
        pipes.parent_stdout = Some(parent_stdout);
        pipes.child_stdout = Some(child_stdout);
        let (parent_stderr, child_stderr) = anonymous_pipe(false, true)?;
        pipes.parent_stderr = Some(parent_stderr);
        pipes.child_stderr = Some(child_stderr);
        Ok(pipes)
    }

    fn child_handles(&self) -> Result<[HANDLE; 3], NativeError> {
        Ok([
            self.child_stdin.ok_or_else(missing_pipe)?,
            self.child_stdout.ok_or_else(missing_pipe)?,
            self.child_stderr.ok_or_else(missing_pipe)?,
        ])
    }

    fn close_child_ends(&mut self) {
        close_optional(&mut self.child_stdin);
        close_optional(&mut self.child_stdout);
        close_optional(&mut self.child_stderr);
    }

    fn take_parent_stdin(&mut self) -> HANDLE {
        self.parent_stdin.take().unwrap_or(ptr::null_mut())
    }

    fn take_parent_stdout(&mut self) -> HANDLE {
        self.parent_stdout.take().unwrap_or(ptr::null_mut())
    }

    fn take_parent_stderr(&mut self) -> HANDLE {
        self.parent_stderr.take().unwrap_or(ptr::null_mut())
    }
}

impl Drop for StdioPipes {
    fn drop(&mut self) {
        close_optional(&mut self.parent_stdin);
        close_optional(&mut self.child_stdin);
        close_optional(&mut self.parent_stdout);
        close_optional(&mut self.child_stdout);
        close_optional(&mut self.parent_stderr);
        close_optional(&mut self.child_stderr);
    }
}

fn anonymous_pipe(
    child_read_inheritable: bool,
    child_write_inheritable: bool,
) -> Result<(HANDLE, HANDLE), NativeError> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let mut attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: u32::try_from(mem::size_of::<
            windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
        >())
        .map_err(|_| {
            NativeError::new(NativeErrorCode::OsFailure, NativeOperation::CreateStdioPipe)
        })?,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` describes an unnamed pipe; both handle out-params
    // point at live HANDLE slots. Ends start non-inheritable so a concurrent
    // inherit-all CreateProcess cannot steal the parent ends.
    if unsafe { CreatePipe(&raw mut read, &raw mut write, &raw mut attributes, 0) } == 0 {
        return Err(last_native_error(NativeOperation::CreateStdioPipe));
    }
    if let Err(error) = set_inherit(read, child_read_inheritable) {
        close_raw(read);
        close_raw(write);
        return Err(error);
    }
    if let Err(error) = set_inherit(write, child_write_inheritable) {
        close_raw(read);
        close_raw(write);
        return Err(error);
    }
    Ok((read, write))
}

fn set_inherit(handle: HANDLE, inherit: bool) -> Result<(), NativeError> {
    let mask = if inherit { HANDLE_FLAG_INHERIT } else { 0 };
    // SAFETY: `handle` is a just-created pipe end owned by this process.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, mask) } == 0 {
        return Err(last_native_error(NativeOperation::CreateStdioPipe));
    }
    Ok(())
}

fn with_startup_attributes<T>(
    stdio: &StdioPipes,
    body: impl FnOnce(&mut STARTUPINFOEXW) -> T,
) -> Result<T, NativeError> {
    let startup_info_cb = u32::try_from(mem::size_of::<STARTUPINFOEXW>()).map_err(|_| {
        NativeError::new(NativeErrorCode::OsFailure, NativeOperation::CreateProcess)
    })?;
    let mut child_handles = stdio.child_handles()?;
    let mut bytes = 0_usize;
    // SAFETY: a null list with a live size pointer is the documented probe
    // that returns the required attribute-list length.
    let probed =
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &raw mut bytes) };
    if probed != 0 || bytes == 0 {
        return Err(last_native_error(NativeOperation::CreateProcess));
    }
    let words = bytes
        .checked_add(mem::size_of::<usize>() - 1)
        .and_then(|value| value.checked_div(mem::size_of::<usize>()))
        .ok_or_else(|| {
            NativeError::new(NativeErrorCode::OsFailure, NativeOperation::CreateProcess)
        })?;
    let mut storage = vec![0_usize; words];
    // SAFETY: `storage` is pointer-aligned and at least `bytes` long. The
    // API writes an attribute list into it that must be deleted later.
    if unsafe {
        InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &raw mut bytes)
    } == 0
    {
        return Err(last_native_error(NativeOperation::CreateProcess));
    }
    let list = AttributeList(storage.as_mut_ptr().cast());
    let list_size = mem::size_of_val(&child_handles);
    // SAFETY: `list` was initialized above. The handle array lives for the
    // CreateProcessW call that `body` performs; Drop deletes the list.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            list.0,
            0,
            usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST).unwrap_or(0x0002_0002),
            child_handles.as_mut_ptr().cast(),
            list_size,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if updated == 0 {
        return Err(last_native_error(NativeOperation::CreateProcess));
    }
    let mut startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: startup_info_cb,
            lpReserved: ptr::null_mut(),
            lpDesktop: ptr::null_mut(),
            lpTitle: ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: STARTF_USESTDHANDLES,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: ptr::null_mut(),
            hStdInput: child_handles[0],
            hStdOutput: child_handles[1],
            hStdError: child_handles[2],
        },
        lpAttributeList: list.0,
    };
    let result = body(&mut startup);
    drop(list);
    Ok(result)
}

struct AttributeList(windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST);

impl Drop for AttributeList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: InitializeProcThreadAttributeList succeeded and this
            // list has not been deleted yet.
            unsafe { DeleteProcThreadAttributeList(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

fn file_from_handle(handle: HANDLE) -> Result<File, NativeError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(NativeError::new(
            NativeErrorCode::OsFailure,
            NativeOperation::CreateStdioPipe,
        ));
    }
    // SAFETY: `handle` is an exclusively owned parent pipe end. File takes
    // ownership and will CloseHandle it exactly once.
    Ok(unsafe { File::from(OwnedHandle::from_raw_handle(handle.cast())) })
}

fn close_optional(handle: &mut Option<HANDLE>) {
    if let Some(value) = handle.take() {
        close_raw(value);
    }
}

fn close_raw(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        // SAFETY: the handle was created by this module and has not been
        // closed or transferred.
        unsafe { CloseHandle(handle) };
    }
}

fn duration_to_millis(timeout: Duration) -> u32 {
    if timeout == Duration::MAX {
        return INFINITE;
    }
    u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX)
}

fn last_native_error(operation: NativeOperation) -> NativeError {
    // SAFETY: called immediately after a failing Win32 operation.
    let code = unsafe { GetLastError() };
    NativeError::with_os_code(NativeErrorCode::OsFailure, operation, code)
}

fn invalid_receipt() -> NativeError {
    NativeError::new(
        NativeErrorCode::InvalidArgument,
        NativeOperation::InspectProcess,
    )
}

fn missing_pipe() -> NativeError {
    NativeError::new(NativeErrorCode::OsFailure, NativeOperation::CreateStdioPipe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NonBreakawayJob;
    use std::io::{Read, Write};
    use std::sync::OnceLock;
    use std::thread;

    const HELPER_SOURCE: &str = r#"
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--write-marker" => {
                index += 1;
                let path = args.get(index).expect("marker path");
                fs::write(path, b"ran\n").expect("write marker");
            }
            "--hang" => loop {
                thread::sleep(Duration::from_secs(60));
            },
            "--crash" => {
                index += 1;
                let code = args
                    .get(index)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(17);
                std::process::exit(code);
            }
            "--print" => {
                index += 1;
                if let Some(text) = args.get(index) {
                    println!("{text}");
                    io::stdout().flush().expect("flush");
                }
            }
            "--grandchild" => {
                let child = Command::new(env::current_exe().expect("exe"))
                    .arg("--hang")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("grandchild");
                println!("grandchild={}", child.id());
                io::stdout().flush().expect("flush grandchild pid");
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
            _ => {}
        }
        index += 1;
    }
}
"#;

    fn helper_exe() -> &'static Path {
        static HELPER: OnceLock<PathBuf> = OnceLock::new();
        HELPER.get_or_init(compile_helper)
    }

    fn compile_helper() -> PathBuf {
        let source_dir = tempfile::tempdir().expect("helper source dir");
        let source = source_dir.path().join("helper.rs");
        std::fs::write(&source, HELPER_SOURCE).expect("write helper source");
        let rustc = std::env::var_os("RUSTC").map_or_else(|| PathBuf::from("rustc"), PathBuf::from);
        let output = std::env::temp_dir().join(format!(
            "mesh-win32-process-helper-{}.exe",
            std::process::id()
        ));
        let status = std::process::Command::new(rustc)
            .arg("-O")
            .arg("-o")
            .arg(&output)
            .arg(&source)
            .status()
            .expect("spawn rustc");
        assert!(status.success(), "rustc failed to build process helper");
        // Keep the source directory until rustc returns; then leak the path.
        drop(source_dir);
        output
    }

    fn empty_env() -> Vec<(OsString, OsString)> {
        Vec::new()
    }

    fn spawn(args: &[&str]) -> OwnedProcess {
        let arguments: Vec<OsString> = args.iter().map(OsString::from).collect();
        create_suspended_process(&ProcessSpawnSpec {
            executable: helper_exe(),
            arguments: &arguments,
            environment: &empty_env(),
            current_dir: None,
        })
        .expect("create suspended helper")
    }

    fn wait_for_file(path: &Path) -> bool {
        for _ in 0..50 {
            if path.is_file() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        path.is_file()
    }

    fn pid_running(pid: u32) -> bool {
        // SAFETY: diagnostic OpenProcess on a test PID. A null handle means
        // the process is not queryable and is treated as not running.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut code = 0_u32;
        // SAFETY: handle is a successful OpenProcess result.
        let queried = unsafe { GetExitCodeProcess(handle, &raw mut code) };
        // SAFETY: this test owns the OpenProcess handle.
        unsafe { CloseHandle(handle) };
        queried != 0 && code == STILL_ACTIVE
    }

    #[test]
    fn receipt_round_trips_pid_creation_time_and_image() {
        let identity = ProcessIdentity {
            pid: 4242,
            creation_time: 0x0123_4567_89ab_cdef,
            image: PathBuf::from(r"C:\mesh\fake.exe"),
        };
        let encoded = identity.encode();
        assert!(encoded.starts_with("v1:4242:"));
        assert!(encoded.contains(r"C:\mesh\fake.exe"));
        assert_eq!(ProcessIdentity::decode(&encoded).expect("decode"), identity);
        assert!(ProcessIdentity::decode("v1:not-a-pid:00:C:\\x.exe").is_err());
        assert!(ProcessIdentity::decode("v1:1:zz:C:\\x.exe").is_err());
    }

    #[test]
    fn live_receipt_rejects_pid_reuse_with_wrong_creation_time() {
        let child = spawn(&["--hang"]);
        let live = child.identity().clone();
        assert!(process_identity_is_live(&live).expect("live receipt"));
        assert_eq!(
            ProcessIdentity::decode(&live.encode()).expect("round-trip"),
            live
        );
        let stale = ProcessIdentity {
            pid: live.pid(),
            creation_time: live.creation_time().wrapping_add(1),
            image: live.image().to_path_buf(),
        };
        assert!(
            !process_identity_is_live(&stale).expect("stale receipt"),
            "PID reuse without the same creation time must not match"
        );
        drop(child);
    }

    #[test]
    fn suspended_create_does_not_run_child_until_resume() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("marker.txt");
        let mut child = spawn(&["--write-marker", marker.to_str().expect("utf8 marker path")]);
        assert!(!child.resumed());
        assert!(child.is_running().expect("suspended child is live"));
        thread::sleep(Duration::from_millis(80));
        assert!(
            !marker.exists(),
            "suspended child must not write the marker"
        );
        let job = NonBreakawayJob::create().expect("job");
        job.assign_process(&child).expect("assign");
        assert!(job.contains_process(&child).expect("contains"));
        child.resume_primary_thread().expect("resume");
        assert!(child.resumed());
        assert!(wait_for_file(&marker), "resumed child writes the marker");
        let _ = child.wait_timeout(Duration::from_secs(2));
    }

    #[test]
    fn resume_after_job_assign_keeps_process_in_job() {
        let mut child = spawn(&["--print", "hello"]);
        let job = NonBreakawayJob::create().expect("job");
        job.assign_process(&child).expect("assign");
        child.resume_primary_thread().expect("resume");
        assert!(job.contains_process(&child).expect("contains after resume"));
        match child.wait_timeout(Duration::from_secs(2)).expect("wait") {
            ProcessWait::Exited(0) => {}
            other => panic!("unexpected wait result: {other:?}"),
        }
        assert!(!process_identity_is_live(child.identity()).expect("dead receipt"));
    }

    #[test]
    fn terminate_job_kills_child_and_grandchild() {
        let mut child = spawn(&["--grandchild"]);
        let mut stdout = child.take_stdout().expect("stdout");
        let job = NonBreakawayJob::create().expect("job");
        job.assign_process(&child).expect("assign");
        child.resume_primary_thread().expect("resume");
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        });
        for _ in 0..50 {
            if reader.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        job.terminate(1).expect("terminate job");
        let output = reader.join().expect("stdout thread");
        let pid = output
            .lines()
            .find_map(|line| line.strip_prefix("grandchild="))
            .and_then(|value| value.trim().parse::<u32>().ok())
            .expect("grandchild pid");
        thread::sleep(Duration::from_millis(100));
        assert!(!pid_running(pid), "grandchild must die with the job tree");
        assert!(!child.is_running().expect("child exit"));
        assert!(!process_identity_is_live(child.identity()).expect("identity"));
    }

    #[test]
    fn drop_without_resume_kills_suspended_process() {
        let identity = {
            let child = spawn(&["--hang"]);
            child.identity().clone()
        };
        thread::sleep(Duration::from_millis(50));
        assert!(
            !process_identity_is_live(&identity).expect("query"),
            "dropping a suspended process must terminate it"
        );
    }

    #[test]
    fn argument_with_spaces_is_passed_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("spaced marker.txt");
        let mut child = spawn(&["--write-marker", marker.to_str().expect("utf8")]);
        child.resume_primary_thread().expect("resume");
        assert!(wait_for_file(&marker));
        let _ = child.wait_timeout(Duration::from_secs(2));
    }

    #[test]
    fn stdin_pipe_is_writable_and_stdout_is_not_inherited() {
        let mut child = spawn(&["--print", "from-child"]);
        if let Some(mut stdin) = child.take_stdin() {
            let _ = stdin.write_all(b"ignored\n");
        }
        let mut stdout = child.take_stdout().expect("stdout");
        child.resume_primary_thread().expect("resume");
        let mut output = String::new();
        stdout.read_to_string(&mut output).expect("read stdout");
        assert!(output.contains("from-child"));
        let _ = child.wait_timeout(Duration::from_secs(2));
    }
}
