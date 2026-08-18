//! Audited current-user Known Folder discovery.
//!
//! The boundary deliberately asks Windows for `FOLDERID_LocalAppData`; it does
//! not consult environment variables, process current directory, or create the
//! returned directory. Callers remain responsible for choosing a fixed child.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable failure categories for Known Folder discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KnownFolderErrorCode {
    UnsupportedPlatform,
    OsFailure,
    InvalidResult,
}

/// A redaction-safe Known Folder error containing no discovered path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownFolderError {
    code: KnownFolderErrorCode,
    os_code: Option<u32>,
}

impl KnownFolderError {
    #[must_use]
    pub const fn unsupported_platform() -> Self {
        Self {
            code: KnownFolderErrorCode::UnsupportedPlatform,
            os_code: None,
        }
    }

    #[cfg(windows)]
    const fn os_failure(hresult: i32) -> Self {
        Self {
            code: KnownFolderErrorCode::OsFailure,
            os_code: Some(hresult.cast_unsigned()),
        }
    }

    #[cfg(windows)]
    const fn invalid_result() -> Self {
        Self {
            code: KnownFolderErrorCode::InvalidResult,
            os_code: None,
        }
    }

    #[must_use]
    pub const fn code(self) -> KnownFolderErrorCode {
        self.code
    }

    #[must_use]
    pub const fn os_code(self) -> Option<u32> {
        self.os_code
    }
}

impl Display for KnownFolderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "known-folder discovery failed with {:?}",
            self.code
        )?;
        if let Some(code) = self.os_code {
            write!(formatter, " (os error {code})")?;
        }
        Ok(())
    }
}

impl Error for KnownFolderError {}

#[cfg(windows)]
mod windows_impl {
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::{ptr, slice};

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    use windows_sys::core::PWSTR;

    use super::KnownFolderError;

    // Windows paths cannot contain more than 32,767 UTF-16 code units. The
    // extra bound also makes a missing terminator an explicit invalid result.
    const MAX_KNOWN_FOLDER_UTF16_UNITS: usize = 32_768;

    struct OwnedKnownFolderPath(PWSTR);

    impl Drop for OwnedKnownFolderPath {
        fn drop(&mut self) {
            // SAFETY: this wrapper is created only from the successful output
            // of SHGetKnownFolderPath, whose matching allocator contract is
            // CoTaskMemFree. It owns that pointer exactly once.
            unsafe { CoTaskMemFree(self.0.cast::<c_void>()) };
        }
    }

    /// Discover the current process user's `LocalAppData` directory.
    ///
    /// `token=null` selects the current user. `KF_FLAG_DEFAULT` does not ask
    /// the Shell to create a directory. On success Windows guarantees a
    /// NUL-terminated `CoTaskMem` allocation; this function bounds the scan,
    /// copies its UTF-16 code units losslessly into `OsString`, and frees the
    /// allocation on every subsequent success/error path.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe OS failure, or `InvalidResult` when the Shell
    /// returns a null, empty, relative, unterminated, or overlong value.
    pub fn current_user_local_app_data() -> Result<PathBuf, KnownFolderError> {
        let mut output = ptr::null_mut();
        let folder_id = FOLDERID_LocalAppData;
        // SAFETY: the folder ID is a static valid KNOWNFOLDERID, token=null
        // means current user, and `output` is a writable PWSTR out-pointer.
        let result = unsafe {
            SHGetKnownFolderPath(
                &raw const folder_id,
                KF_FLAG_DEFAULT as u32,
                ptr::null_mut(),
                &raw mut output,
            )
        };
        if result < 0 {
            if !output.is_null() {
                drop(OwnedKnownFolderPath(output));
            }
            return Err(KnownFolderError::os_failure(result));
        }
        if output.is_null() {
            return Err(KnownFolderError::invalid_result());
        }
        let output = OwnedKnownFolderPath(output);
        // SAFETY: the successful Shell call returned a readable,
        // NUL-terminated CoTaskMem string owned by `output`.
        let length = unsafe { terminated_length(output.0) }?;
        // SAFETY: SHGetKnownFolderPath guarantees a NUL-terminated allocation;
        // `terminated_length` found that terminator within the enforced bound.
        let units = unsafe { slice::from_raw_parts(output.0, length) };
        validate_path(PathBuf::from(OsString::from_wide(units)))
    }

    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated UTF-16 allocation, or to
    /// at least `MAX_KNOWN_FOLDER_UTF16_UNITS` readable code units.
    unsafe fn terminated_length(path: PWSTR) -> Result<usize, KnownFolderError> {
        for length in 0..MAX_KNOWN_FOLDER_UTF16_UNITS {
            // SAFETY: upheld by this function's caller contract; the index is
            // bounded by MAX_KNOWN_FOLDER_UTF16_UNITS.
            if unsafe { *path.add(length) } == 0 {
                return if length == 0 {
                    Err(KnownFolderError::invalid_result())
                } else {
                    Ok(length)
                };
            }
        }
        Err(KnownFolderError::invalid_result())
    }

    fn validate_path(path: PathBuf) -> Result<PathBuf, KnownFolderError> {
        if path.as_os_str().is_empty() || !path.is_absolute() {
            return Err(KnownFolderError::invalid_result());
        }
        Ok(path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn result_is_absolute_and_matches_an_independent_direct_call() {
            let discovered = current_user_local_app_data().expect("LocalAppData");
            assert!(discovered.is_absolute());
            assert!(!discovered.as_os_str().is_empty());

            let mut direct = ptr::null_mut();
            let folder_id = FOLDERID_LocalAppData;
            // SAFETY: independent direct invocation uses the documented static
            // folder ID, current-user null token, and writable output pointer.
            let result = unsafe {
                SHGetKnownFolderPath(
                    &raw const folder_id,
                    KF_FLAG_DEFAULT as u32,
                    ptr::null_mut(),
                    &raw mut direct,
                )
            };
            assert!(result >= 0, "direct Known Folder HRESULT {result}");
            assert!(!direct.is_null());
            let direct = OwnedKnownFolderPath(direct);
            // SAFETY: the successful direct call returned the documented
            // readable, NUL-terminated CoTaskMem string.
            let length = unsafe { terminated_length(direct.0) }.expect("direct terminated path");
            // SAFETY: the direct call has the same documented allocation and
            // the bounded scan located its terminator.
            let units = unsafe { slice::from_raw_parts(direct.0, length) };
            let direct_path = PathBuf::from(OsString::from_wide(units));
            assert_eq!(discovered, direct_path);
        }

        #[test]
        fn validation_rejects_empty_and_relative_results() {
            assert_eq!(
                validate_path(PathBuf::new()).expect_err("empty").code(),
                super::super::KnownFolderErrorCode::InvalidResult
            );
            assert_eq!(
                validate_path(PathBuf::from("relative"))
                    .expect_err("relative")
                    .code(),
                super::super::KnownFolderErrorCode::InvalidResult
            );

            let mut unterminated = vec![u16::from(b'x'); MAX_KNOWN_FOLDER_UTF16_UNITS];
            // SAFETY: this fixture contains exactly the maximum number of
            // readable units required by the helper contract and no NUL.
            let error = unsafe { terminated_length(unterminated.as_mut_ptr()) }
                .expect_err("missing terminator");
            assert_eq!(
                error.code(),
                super::super::KnownFolderErrorCode::InvalidResult
            );
        }
    }
}

#[cfg(windows)]
pub use windows_impl::current_user_local_app_data;
