#![allow(clippy::missing_errors_doc)]

use std::ffi::c_void;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_OPEN_REPARSE_POINT, FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_ALWAYS,
    OPEN_EXISTING,
};

use crate::{NativeError, NativeErrorCode, NativeOperation};

/// A persistent lock file whose exclusive ownership is the lifetime of this handle.
///
/// The file is intentionally never deleted to recover from a crash. Windows
/// releases its no-share handle automatically when the owner exits.
#[derive(Debug)]
pub struct ExclusiveFileLock(HANDLE);

// SAFETY: kernel file handles may be transferred between threads. This type
// owns exactly one handle and exposes no operation with borrowed buffers.
unsafe impl Send for ExclusiveFileLock {}

impl ExclusiveFileLock {
    pub(crate) const fn handle(&self) -> HANDLE {
        self.0
    }

    pub(crate) fn acquire(path: &Path) -> Result<Self, NativeError> {
        Self::acquire_with_disposition(path, OPEN_ALWAYS)
    }

    pub(crate) fn acquire_existing(path: &Path) -> Result<Self, NativeError> {
        Self::acquire_with_disposition(path, OPEN_EXISTING)
    }

    fn acquire_with_disposition(path: &Path, disposition: u32) -> Result<Self, NativeError> {
        let path = wide(path);
        // SAFETY: path is NUL-terminated and live. Share mode zero is the lock;
        // OPEN_REPARSE_POINT ensures an attacker cannot redirect the handle.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                disposition,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let code = last_error();
            return Err(NativeError::with_os_code(
                if code == ERROR_SHARING_VIOLATION {
                    NativeErrorCode::SingletonConflict
                } else if code == ERROR_ACCESS_DENIED {
                    NativeErrorCode::AccessDenied
                } else {
                    NativeErrorCode::OsFailure
                },
                NativeOperation::AcquireLock,
                code,
            ));
        }
        let lock = Self(handle);
        let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: handle is live and information is the exact class buffer.
        if unsafe {
            GetFileInformationByHandleEx(
                lock.0,
                FileAttributeTagInfo,
                (&raw mut information).cast::<c_void>(),
                u32::try_from(mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                    .expect("attribute info size fits u32"),
            )
        } == 0
        {
            return Err(last_native_error());
        }
        if information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(NativeError::new(
                NativeErrorCode::AccessDenied,
                NativeOperation::AcquireLock,
            ));
        }
        Ok(lock)
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        // SAFETY: acquire accepted one successful handle and this type owns it.
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error() -> u32 {
    // SAFETY: called immediately after a failing Win32 operation.
    unsafe { GetLastError() }
}

fn last_native_error() -> NativeError {
    NativeError::with_os_code(
        NativeErrorCode::OsFailure,
        NativeOperation::AcquireLock,
        last_error(),
    )
}
