use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable, redaction-safe failure categories for native Windows primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NativeErrorCode {
    UnsupportedPlatform,
    InvalidArgument,
    AccessDenied,
    AuthenticationFailed,
    FrameInvalid,
    FrameTooLarge,
    IoTimeout,
    ConnectionClosed,
    SingletonConflict,
    SetupAbsent,
    SetupDisabled,
    SetupRemoving,
    SetupDrifted,
    SetupAccessDenied,
    TaskNotDisabled,
    TaskStillRunning,
    SecretInvalid,
    SecretProtectionFailed,
    OsFailure,
}

/// Stable operation labels which never contain caller-controlled data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NativeOperation {
    DeriveEndpoint,
    CreatePipe,
    ConnectPipe,
    InspectPipeSecurity,
    InspectPeer,
    VerifyAuthenticode,
    ReadFrame,
    WriteFrame,
    AuthenticateHandshake,
    AcquireLock,
    CreateJob,
    AssignJob,
    InspectJob,
    TerminateJob,
    CreateProcess,
    ResumeThread,
    TerminateProcess,
    InspectProcess,
    CreateStdioPipe,
    ConnectTaskScheduler,
    SetupTask,
    InspectTask,
    StartTask,
    DisableTask,
    StopTask,
    DeleteTask,
    RemoveTask,
    ProtectEndpointKey,
    UnprotectEndpointKey,
}

/// A native-boundary error containing only stable labels and an optional OS code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeError {
    code: NativeErrorCode,
    operation: NativeOperation,
    os_code: Option<u32>,
}

impl NativeError {
    #[must_use]
    pub const fn new(code: NativeErrorCode, operation: NativeOperation) -> Self {
        Self {
            code,
            operation,
            os_code: None,
        }
    }

    #[must_use]
    pub const fn with_os_code(
        code: NativeErrorCode,
        operation: NativeOperation,
        os_code: u32,
    ) -> Self {
        Self {
            code,
            operation,
            os_code: Some(os_code),
        }
    }

    #[must_use]
    pub const fn code(self) -> NativeErrorCode {
        self.code
    }

    #[must_use]
    pub const fn operation(self) -> NativeOperation {
        self.operation
    }

    #[must_use]
    pub const fn os_code(self) -> Option<u32> {
        self.os_code
    }
}

impl Display for NativeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native operation {:?} failed with {:?}",
            self.operation, self.code
        )?;
        if let Some(code) = self.os_code {
            write!(formatter, " (os error {code})")?;
        }
        Ok(())
    }
}

impl Error for NativeError {}
