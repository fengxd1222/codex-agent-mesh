use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{
    CleanPurgeAbsenceReport, ControlDirectoryEntry, InstallPurgeTreePresence, KnownFolderError,
    NativeError, NativeErrorCode, NativeOperation, ProtectedEndpointKey, PurgeStageReport,
    PurgeTreeReport, StorageError, StorageErrorCode, StorageOperation,
};

pub const MAX_CONTROL_FILE_BYTES: usize = 1024 * 1024;

pub fn current_user_local_app_data() -> Result<PathBuf, KnownFolderError> {
    Err(KnownFolderError::unsupported_platform())
}

/// Placeholder type so downstream crates compile on unsupported hosts.
#[derive(Debug)]
pub struct ValidatedDataRoot {
    canonical_path: PathBuf,
}

#[derive(Debug)]
pub struct ValidatedControlRoot {
    canonical_path: PathBuf,
}

#[derive(Debug)]
pub struct ExclusiveFileLock;

impl ValidatedControlRoot {
    pub const MAX_EXECUTABLE_BYTES: u64 = crate::MAX_AUTHENTICODE_FILE_BYTES;

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn create_relative_directories(&self, _path: &Path) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::CreateDirectory))
    }

    pub fn create_protected_file(
        &self,
        _path: &Path,
        _contents: &[u8],
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::CreateControlFile))
    }

    pub fn read_protected_file(&self, _path: &Path) -> Result<Vec<u8>, StorageError> {
        Err(unsupported(StorageOperation::ReadControlFile))
    }

    pub fn copy_reader_verified<R: Read>(
        &self,
        _source: &mut R,
        _staging_relative_path: &Path,
        _expected_sha256: [u8; 32],
    ) -> Result<u64, StorageError> {
        Err(unsupported(StorageOperation::CopyFile))
    }

    pub fn verify_artifact_file(
        &self,
        _relative_path: &Path,
        _expected_sha256: [u8; 32],
    ) -> Result<PathBuf, StorageError> {
        Err(unsupported(StorageOperation::VerifyPublication))
    }

    pub fn create_endpoint_key_file(
        &self,
        _relative_path: &Path,
        _protected: &ProtectedEndpointKey,
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::CreateEndpointKeyFile))
    }

    pub fn read_endpoint_key_file(
        &self,
        _relative_path: &Path,
    ) -> Result<ProtectedEndpointKey, StorageError> {
        Err(unsupported(StorageOperation::InspectEndpointKeyFile))
    }

    pub fn publish_no_replace(&self, _staged: &Path, _final: &Path) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::PublishFile))
    }

    pub fn atomic_replace(&self, _staged: &Path, _final: &Path) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::ReplaceFile))
    }

    pub fn remove_regular_file(&self, _path: &Path) -> Result<bool, StorageError> {
        Err(unsupported(StorageOperation::RemoveFile))
    }

    pub fn classify_install_purge_tree(
        &self,
        _install_id: &str,
    ) -> Result<InstallPurgeTreePresence, StorageError> {
        Err(unsupported(StorageOperation::ClassifyPurgeTree))
    }

    pub fn stage_install_tree_for_purge(
        &self,
        _install_id: &str,
    ) -> Result<PurgeStageReport, StorageError> {
        Err(unsupported(StorageOperation::StagePurgeTree))
    }

    pub fn audit_and_remove_install_tree(
        &self,
        _install_id: &str,
    ) -> Result<PurgeTreeReport, StorageError> {
        Err(unsupported(StorageOperation::AuditPurgeTree))
    }

    pub fn enumerate_stable_control_directory(
        &self,
        _held_install_lock: &ExclusiveFileLock,
    ) -> Result<Vec<ControlDirectoryEntry>, StorageError> {
        Err(unsupported(StorageOperation::EnumerateControlDirectory))
    }

    pub fn validate_current_executable_outside_control_root(
        &self,
    ) -> Result<PathBuf, StorageError> {
        Err(unsupported(StorageOperation::VerifyPurgeController))
    }

    pub fn verify_clean_install_purge_absence(
        &self,
        _held_install_lock: &ExclusiveFileLock,
    ) -> Result<CleanPurgeAbsenceReport, StorageError> {
        Err(unsupported(StorageOperation::VerifyCleanPurgeAbsence))
    }

    pub fn sync_directory(&self, _path: &Path) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::SyncDirectory))
    }

    pub fn acquire_lifetime_lock(&self, _path: &Path) -> Result<ExclusiveFileLock, NativeError> {
        Err(NativeError::new(
            NativeErrorCode::UnsupportedPlatform,
            NativeOperation::AcquireLock,
        ))
    }

    pub fn acquire_existing_lifetime_lock(
        &self,
        _path: &Path,
    ) -> Result<ExclusiveFileLock, StorageError> {
        Err(unsupported(StorageOperation::InspectExistingLock))
    }
}

impl ValidatedDataRoot {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn create_flushed_file(
        &self,
        _relative_path: &Path,
        _contents: &[u8],
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::CreateFile))
    }

    pub fn create_flushed_zero_file(
        &self,
        _relative_path: &Path,
        _length: u64,
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::CreateFile))
    }

    pub fn publish_no_replace(
        &self,
        _staged_relative_path: &Path,
        _final_relative_path: &Path,
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::PublishFile))
    }

    pub fn atomic_replace(
        &self,
        _staged_relative_path: &Path,
        _final_relative_path: &Path,
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::ReplaceFile))
    }

    pub fn create_relative_directories(&self, _relative_path: &Path) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::CreateDirectory))
    }

    pub fn validate_relative_path_security(
        &self,
        _relative_path: &Path,
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::ValidatePath))
    }

    pub fn remove_regular_file(&self, _relative_path: &Path) -> Result<bool, StorageError> {
        Err(unsupported(StorageOperation::RemoveFile))
    }

    pub fn allocated_tree_bytes(&self) -> Result<u64, StorageError> {
        Err(unsupported(StorageOperation::MeasureAllocation))
    }

    pub fn volume_free_bytes(&self) -> Result<u64, StorageError> {
        Err(unsupported(StorageOperation::QueryFreeSpace))
    }

    pub fn sync_directory(&self, _relative_path: &Path) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::SyncDirectory))
    }

    pub fn copy_reader_verified<R: Read>(
        &self,
        _source: &mut R,
        _destination_relative_path: &Path,
        _expected_sha256: [u8; 32],
    ) -> Result<u64, StorageError> {
        Err(unsupported(StorageOperation::CopyFile))
    }

    pub fn create_endpoint_key_file(
        &self,
        _relative_path: &Path,
        _protected: &ProtectedEndpointKey,
    ) -> Result<(), StorageError> {
        Err(unsupported(StorageOperation::CreateEndpointKeyFile))
    }

    pub fn read_endpoint_key_file(
        &self,
        _relative_path: &Path,
    ) -> Result<ProtectedEndpointKey, StorageError> {
        Err(unsupported(StorageOperation::InspectEndpointKeyFile))
    }
}

pub fn protect_data_root(_path: &Path) -> Result<(), StorageError> {
    Err(unsupported(StorageOperation::ProtectDataRoot))
}

pub fn validate_data_root(_path: &Path) -> Result<ValidatedDataRoot, StorageError> {
    Err(unsupported(StorageOperation::ValidateDataRoot))
}

pub fn protect_control_root(_path: &Path) -> Result<(), StorageError> {
    Err(unsupported(StorageOperation::ProtectControlRoot))
}

pub fn validate_control_root(_path: &Path) -> Result<ValidatedControlRoot, StorageError> {
    Err(unsupported(StorageOperation::ValidateControlRoot))
}

pub fn open_or_create_product_control_root() -> Result<ValidatedControlRoot, StorageError> {
    Err(unsupported(StorageOperation::ValidateControlRoot))
}

const fn unsupported(operation: StorageOperation) -> StorageError {
    StorageError::new(StorageErrorCode::UnsupportedPlatform, operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_is_explicit() {
        let error = validate_data_root(Path::new("/tmp/mesh")).expect_err("must reject");
        assert_eq!(error.code(), StorageErrorCode::UnsupportedPlatform);
        let error = current_user_local_app_data().expect_err("known folder is Windows-only");
        assert_eq!(
            error.code(),
            crate::KnownFolderErrorCode::UnsupportedPlatform
        );
        let error = validate_control_root(Path::new("/tmp/control")).expect_err("Windows-only");
        assert_eq!(error.code(), StorageErrorCode::UnsupportedPlatform);
        assert_eq!(
            open_or_create_product_control_root()
                .expect_err("Windows-only")
                .code(),
            StorageErrorCode::UnsupportedPlatform
        );
    }
}
