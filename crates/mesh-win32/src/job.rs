#![allow(clippy::missing_errors_doc)]

use std::ffi::c_void;
use std::mem;
use std::os::windows::io::AsRawHandle;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};

use crate::{NativeError, NativeErrorCode, NativeOperation};

/// A job configured to kill members on close and to disallow both breakaway modes.
#[derive(Debug)]
pub struct NonBreakawayJob(HANDLE);

// SAFETY: job handles may be transferred between threads. The wrapper owns one
// handle, and all operations pass borrowed process handles synchronously.
unsafe impl Send for NonBreakawayJob {}

impl NonBreakawayJob {
    pub fn create() -> Result<Self, NativeError> {
        // SAFETY: null attributes/name create an unnamed noninheritable job.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(last_native_error(NativeOperation::CreateJob));
        }
        let job = Self(handle);
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let information_size =
            u32::try_from(mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(
                |_| NativeError::new(NativeErrorCode::OsFailure, NativeOperation::CreateJob),
            )?;
        // SAFETY: handle is a job and information is the exact class structure.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast::<c_void>(),
                information_size,
            )
        } == 0
        {
            return Err(last_native_error(NativeOperation::CreateJob));
        }
        let flags = job.limit_flags()?;
        if flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0
            || flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0
        {
            return Err(NativeError::new(
                NativeErrorCode::AccessDenied,
                NativeOperation::CreateJob,
            ));
        }
        Ok(job)
    }

    pub fn assign_process(&self, process: &impl AsRawHandle) -> Result<(), NativeError> {
        let handle = process.as_raw_handle().cast();
        // SAFETY: AsRawHandle is borrowed for this synchronous call. Windows
        // retains job membership independently, not the process handle pointer.
        if unsafe { AssignProcessToJobObject(self.0, handle) } == 0 {
            return Err(last_native_error(NativeOperation::AssignJob));
        }
        Ok(())
    }

    pub fn contains_process(&self, process: &impl AsRawHandle) -> Result<bool, NativeError> {
        let mut result = 0;
        // SAFETY: both handles are borrowed and result is a live output.
        if unsafe { IsProcessInJob(process.as_raw_handle().cast(), self.0, &raw mut result) } == 0 {
            return Err(last_native_error(NativeOperation::InspectJob));
        }
        Ok(result != 0)
    }

    /// Force-kills every process currently assigned to this job.
    pub fn terminate(&self, exit_code: u32) -> Result<(), NativeError> {
        // SAFETY: `self.0` is an owned job handle. TerminateJobObject applies
        // to the job, not to a borrowed process pointer, and does not retain
        // the caller's stack after return.
        if unsafe { TerminateJobObject(self.0, exit_code) } == 0 {
            return Err(last_native_error(NativeOperation::TerminateJob));
        }
        Ok(())
    }

    pub fn limit_flags(&self) -> Result<u32, NativeError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let information_size =
            u32::try_from(mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(
                |_| NativeError::new(NativeErrorCode::OsFailure, NativeOperation::InspectJob),
            )?;
        // SAFETY: job handle is live and information is the exact class buffer.
        if unsafe {
            QueryInformationJobObject(
                self.0,
                JobObjectExtendedLimitInformation,
                (&raw mut information).cast::<c_void>(),
                information_size,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_native_error(NativeOperation::InspectJob));
        }
        Ok(information.BasicLimitInformation.LimitFlags)
    }
}

impl Drop for NonBreakawayJob {
    fn drop(&mut self) {
        // SAFETY: create accepted one successful job handle and this type owns it.
        unsafe { CloseHandle(self.0) };
    }
}

fn last_native_error(operation: NativeOperation) -> NativeError {
    // SAFETY: called immediately after a failing Win32 operation.
    let code = unsafe { GetLastError() };
    NativeError::with_os_code(NativeErrorCode::OsFailure, operation, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_has_kill_on_close_and_no_breakaway_flags() {
        let job = NonBreakawayJob::create().expect("job");
        let flags = job.limit_flags().expect("flags");
        assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
        assert_eq!(
            flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
            0
        );
    }
}
