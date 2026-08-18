use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable machine-readable categories returned by the storage boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StorageErrorCode {
    UnsupportedPlatform,
    InvalidPath,
    PathEscapesRoot,
    NotFound,
    ReparsePoint,
    NotDirectory,
    NotRegularFile,
    NotFixedVolume,
    NotNtfsVolume,
    InsecureAcl,
    DifferentVolume,
    AlreadyExists,
    SparseFile,
    CompressedFile,
    InsufficientAllocation,
    PublicationVerificationFailed,
    DigestMismatch,
    SizeOverflow,
    DirectorySyncUnsupported,
    /// The exact source and deterministic purge tombstone both exist.
    PurgeTreeConflict,
    /// An opened object no longer matches the directory entry that named it.
    IdentityChanged,
    /// A live handle did not grant delete sharing or otherwise blocked removal.
    SharingViolation,
    /// Windows denied access to the exact audited object.
    AccessDenied,
    /// The running purge controller resolves inside the tree it would remove.
    ControllerInsideControlRoot,
    /// A bounded purge traversal exceeded its depth, entry, or path limit.
    TraversalLimit,
    /// A fixed structural directory contained an entry outside its allowlist.
    UnexpectedEntry,
    InvalidProtectedKey,
    TooLarge,
    Io,
}

/// Stable operation labels. They deliberately contain no caller-controlled path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StorageOperation {
    ProtectDataRoot,
    ValidateDataRoot,
    ValidatePath,
    InspectVolume,
    InspectSecurity,
    CreateFile,
    WriteFile,
    FlushFile,
    PublishFile,
    ReplaceFile,
    VerifyPublication,
    CreateDirectory,
    RemoveFile,
    MeasureAllocation,
    QueryFreeSpace,
    SyncDirectory,
    CopyFile,
    CreateEndpointKeyFile,
    InspectEndpointKeyFile,
    ProtectControlRoot,
    ValidateControlRoot,
    CreateControlFile,
    ReadControlFile,
    ClassifyPurgeTree,
    StagePurgeTree,
    AuditPurgeTree,
    RemovePurgeTree,
    EnumerateControlDirectory,
    VerifyPurgeController,
    VerifyCleanPurgeAbsence,
    InspectExistingLock,
}

/// A redaction-safe error. Only a stable category, operation, and numeric OS
/// error are retained; input paths and file contents are never captured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageError {
    code: StorageErrorCode,
    operation: StorageOperation,
    os_code: Option<u32>,
}

impl StorageError {
    #[must_use]
    pub const fn new(code: StorageErrorCode, operation: StorageOperation) -> Self {
        Self {
            code,
            operation,
            os_code: None,
        }
    }

    #[must_use]
    pub const fn with_os_code(
        code: StorageErrorCode,
        operation: StorageOperation,
        os_code: u32,
    ) -> Self {
        Self {
            code,
            operation,
            os_code: Some(os_code),
        }
    }

    #[must_use]
    pub const fn code(self) -> StorageErrorCode {
        self.code
    }

    #[must_use]
    pub const fn operation(self) -> StorageOperation {
        self.operation
    }

    #[must_use]
    pub const fn os_code(self) -> Option<u32> {
        self.os_code
    }
}

impl Display for StorageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "storage operation {:?} failed with {:?}",
            self.operation, self.code
        )?;
        if let Some(code) = self.os_code {
            write!(formatter, " (os error {code})")?;
        }
        Ok(())
    }
}

impl Error for StorageError {}
