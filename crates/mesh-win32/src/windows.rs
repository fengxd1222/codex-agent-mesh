//! Windows-only durable filesystem boundary.
//!
//! The unsafe calls in this module are limited to UTF-16 Win32 APIs.  Each
//! call receives NUL-terminated buffers that live for the duration of the call
//! and all returned status values are checked before their output is used.

#![allow(clippy::missing_errors_doc)]

use std::ffi::{OsString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::{mem, ptr, slice};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, SetLastError,
};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, INHERITED_ACE,
    IsValidAcl, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_COMPRESSED,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SPARSE_FILE, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfoEx, FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo, FileRenameInfo, GetCompressedFileSizeW, GetDiskFreeSpaceExW,
    GetDriveTypeW, GetFileAttributesW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationW, GetVolumePathNameW, INVALID_FILE_ATTRIBUTES,
    INVALID_FILE_SIZE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_EXISTING, READ_CONTROL, ReadFile, SetFileInformationByHandle,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

use sha2::{Digest, Sha256};

use crate::{
    CleanPurgeAbsenceReport, ControlDirectoryEntry, ControlDirectoryEntryKind,
    InstallPurgeTreePresence, ProtectedEndpointKey, PurgeStageReport, PurgeTreeReport,
    StorageError, StorageErrorCode, StorageOperation,
};

const PATH_CAPACITY: usize = 32_768;
const PATH_CAPACITY_U32: u32 = 32_768;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_FILE_EXISTS: u32 = 80;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const MAX_NTFS_COMPONENT_UTF16_UNITS: usize = 255;
const MAX_PURGE_DEPTH: usize = 64;
const MAX_PURGE_ENTRIES: u64 = 1_000_000;
const PURGE_ENUMERATION_BUFFER_BYTES: usize = 64 * 1024;
const INSTALL_ID_HEX_LENGTH: usize = 32;
const MAX_CONTROL_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_CONTROL_DIRECTORY_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CONTROL_FILE_BYTES: usize = 1024 * 1024;
const PRODUCT_CONTROL_ROOT_NAME: &str = "codex-agent-mesh";
const CONTROL_ROOT_ACE_FLAGS: u8 = 0x03;

/// A root which is an existing non-reparse directory on a local NTFS volume.
#[derive(Debug)]
pub struct ValidatedDataRoot {
    canonical_path: PathBuf,
    volume_root: PathBuf,
}

/// A current-user-only product/control root on validated local NTFS.
#[derive(Debug)]
pub struct ValidatedControlRoot {
    inner: ValidatedDataRoot,
}

impl ValidatedControlRoot {
    /// Maximum executable artifact accepted by the staging and verification
    /// APIs (512 MiB), shared with the Authenticode admission boundary.
    pub const MAX_EXECUTABLE_BYTES: u64 = crate::MAX_AUTHENTICODE_FILE_BYTES;

    #[must_use]
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn create_relative_directories(&self, relative_path: &Path) -> Result<(), StorageError> {
        self.create_relative_directories_with_hook(relative_path, |_, _| Ok(()))
    }

    fn create_relative_directories_with_hook(
        &self,
        relative_path: &Path,
        mut after_component: impl FnMut(&Path, bool) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        self.validate_live_root(StorageOperation::CreateDirectory)?;
        validate_relative_path(relative_path)?;
        let mut current = self.path().to_path_buf();
        let mut created = Vec::new();
        let result = (|| {
            for component in relative_path.components() {
                let Component::Normal(name) = component else {
                    return Err(StorageError::new(
                        StorageErrorCode::PathEscapesRoot,
                        StorageOperation::CreateDirectory,
                    ));
                };
                current.push(name);
                let created_here =
                    match existing_file_attributes(&current, StorageOperation::CreateDirectory)? {
                        Some(attributes) => {
                            verify_directory_attributes(
                                attributes,
                                StorageOperation::CreateDirectory,
                            )?;
                            false
                        }
                        None => match fs::create_dir(&current) {
                            Ok(()) => {
                                created.push(current.clone());
                                true
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                                false
                            }
                            Err(error) => {
                                return Err(io_error(StorageOperation::CreateDirectory, &error));
                            }
                        },
                    };
                ensure_control_directory_acl(&current, StorageOperation::CreateDirectory)?;
                after_component(&current, created_here)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            cleanup_created_directories(&created)?;
            return Err(error);
        }
        self.resolve_control_path(relative_path, true, StorageOperation::CreateDirectory)?;
        Ok(())
    }

    pub fn create_protected_file(
        &self,
        relative_path: &Path,
        contents: &[u8],
    ) -> Result<(), StorageError> {
        if contents.len() > MAX_CONTROL_FILE_BYTES {
            return Err(StorageError::new(
                StorageErrorCode::TooLarge,
                StorageOperation::CreateControlFile,
            ));
        }
        let path =
            self.resolve_control_path(relative_path, false, StorageOperation::CreateControlFile)?;
        with_created_file(&path, StorageOperation::CreateControlFile, |created| {
            apply_user_only_file_acl(&path, StorageOperation::CreateControlFile)?;
            verify_user_only_file_acl(&path, StorageOperation::CreateControlFile)?;
            created
                .file_mut()
                .write_all(contents)
                .map_err(|error| io_error(StorageOperation::CreateControlFile, &error))?;
            created
                .file_mut()
                .sync_all()
                .map_err(|error| io_error(StorageOperation::FlushFile, &error))?;
            created.close();
            self.resolve_control_path(relative_path, false, StorageOperation::ReadControlFile)?;
            verify_regular_non_reparse(&path, StorageOperation::ReadControlFile)?;
            verify_user_only_file_acl(&path, StorageOperation::ReadControlFile)?;
            let read_back = read_control_file_path(&path)?;
            if read_back != contents {
                return Err(StorageError::new(
                    StorageErrorCode::PublicationVerificationFailed,
                    StorageOperation::ReadControlFile,
                ));
            }
            Ok(())
        })
    }

    pub fn read_protected_file(&self, relative_path: &Path) -> Result<Vec<u8>, StorageError> {
        let path =
            self.resolve_control_path(relative_path, false, StorageOperation::ReadControlFile)?;
        verify_regular_non_reparse(&path, StorageOperation::ReadControlFile)?;
        verify_user_only_file_acl(&path, StorageOperation::ReadControlFile)?;
        read_control_file_path(&path)
    }

    /// Stream an already-open executable into a protected create-new staging
    /// file and verify the final on-disk bytes against `expected_sha256`.
    ///
    /// The exact current-user-only file ACL is installed before the first byte
    /// is written. The stream is rejected as soon as it would exceed
    /// [`Self::MAX_EXECUTABLE_BYTES`]. On every post-create failure, only the
    /// file created by this call is removed; a create-new collision is never
    /// opened for writing or cleanup.
    ///
    /// This boundary excludes other Windows users, but it cannot prevent a
    /// malicious process already running as the same user from racing path
    /// checks. Install orchestration must retain its lifecycle lock and
    /// revalidate the returned artifact immediately before each use.
    pub fn copy_reader_verified<R: Read>(
        &self,
        source: &mut R,
        staging_relative_path: &Path,
        expected_sha256: [u8; 32],
    ) -> Result<u64, StorageError> {
        self.copy_reader_verified_with_limit(
            source,
            staging_relative_path,
            expected_sha256,
            Self::MAX_EXECUTABLE_BYTES,
        )
    }

    fn copy_reader_verified_with_limit<R: Read>(
        &self,
        source: &mut R,
        staging_relative_path: &Path,
        expected_sha256: [u8; 32],
        maximum_bytes: u64,
    ) -> Result<u64, StorageError> {
        let destination =
            self.resolve_control_path(staging_relative_path, false, StorageOperation::CopyFile)?;
        with_created_file(&destination, StorageOperation::CopyFile, |created| {
            apply_user_only_file_acl(&destination, StorageOperation::CopyFile)?;
            verify_user_only_file_acl(&destination, StorageOperation::CopyFile)?;

            let mut digest = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            loop {
                let length = source
                    .read(&mut buffer)
                    .map_err(|error| io_error(StorageOperation::CopyFile, &error))?;
                if length == 0 {
                    break;
                }
                let length_u64 = u64::try_from(length).map_err(|_| {
                    StorageError::new(StorageErrorCode::SizeOverflow, StorageOperation::CopyFile)
                })?;
                total = total.checked_add(length_u64).ok_or_else(|| {
                    StorageError::new(StorageErrorCode::SizeOverflow, StorageOperation::CopyFile)
                })?;
                if total > maximum_bytes {
                    return Err(StorageError::new(
                        StorageErrorCode::TooLarge,
                        StorageOperation::CopyFile,
                    ));
                }
                created
                    .file_mut()
                    .write_all(&buffer[..length])
                    .map_err(|error| io_error(StorageOperation::CopyFile, &error))?;
                digest.update(&buffer[..length]);
            }
            created
                .file_mut()
                .sync_all()
                .map_err(|error| io_error(StorageOperation::FlushFile, &error))?;
            if digest.finalize().as_slice() != expected_sha256 {
                return Err(StorageError::new(
                    StorageErrorCode::DigestMismatch,
                    StorageOperation::CopyFile,
                ));
            }
            created.close();

            self.resolve_control_path(staging_relative_path, false, StorageOperation::CopyFile)?;
            verify_regular_non_reparse(&destination, StorageOperation::CopyFile)?;
            verify_user_only_file_acl(&destination, StorageOperation::CopyFile)?;
            verify_control_file_digest(
                &destination,
                expected_sha256,
                maximum_bytes,
                StorageOperation::CopyFile,
            )?;
            Ok(total)
        })
    }

    /// Verify a protected regular artifact beneath this root and return its
    /// canonical absolute path only after containment, ACL, size, and digest
    /// checks all succeed.
    ///
    /// The returned path is a convenience capability, not a stable file
    /// handle. A malicious process already running as the same user can race a
    /// later path-based open; callers must keep their lifecycle lock and
    /// revalidate at the use boundary.
    pub fn verify_artifact_file(
        &self,
        relative_path: &Path,
        expected_sha256: [u8; 32],
    ) -> Result<PathBuf, StorageError> {
        let path =
            self.resolve_control_path(relative_path, false, StorageOperation::VerifyPublication)?;
        verify_regular_non_reparse(&path, StorageOperation::VerifyPublication)?;
        verify_user_only_file_acl(&path, StorageOperation::VerifyPublication)?;
        verify_control_file_digest(
            &path,
            expected_sha256,
            Self::MAX_EXECUTABLE_BYTES,
            StorageOperation::VerifyPublication,
        )?;

        let canonical = fs::canonicalize(&path)
            .map_err(|error| io_error(StorageOperation::VerifyPublication, &error))?;
        if !same_path(&canonical, &path) {
            return Err(StorageError::new(
                StorageErrorCode::PathEscapesRoot,
                StorageOperation::VerifyPublication,
            ));
        }
        self.resolve_control_path(relative_path, false, StorageOperation::VerifyPublication)?;
        verify_regular_non_reparse(&canonical, StorageOperation::VerifyPublication)?;
        verify_user_only_file_acl(&canonical, StorageOperation::VerifyPublication)?;
        Ok(canonical)
    }

    /// Create a DPAPI endpoint-key envelope with the exact one-user file ACL.
    /// Existing files are never opened for writing or replaced.
    pub fn create_endpoint_key_file(
        &self,
        relative_path: &Path,
        protected: &ProtectedEndpointKey,
    ) -> Result<(), StorageError> {
        let path = self.resolve_control_path(
            relative_path,
            false,
            StorageOperation::CreateEndpointKeyFile,
        )?;
        with_created_file(&path, StorageOperation::CreateEndpointKeyFile, |created| {
            apply_endpoint_key_acl(&path)?;
            verify_endpoint_key_acl(&path)?;
            created
                .file_mut()
                .write_all(protected.as_bytes())
                .map_err(|error| io_error(StorageOperation::CreateEndpointKeyFile, &error))?;
            created
                .file_mut()
                .sync_all()
                .map_err(|error| io_error(StorageOperation::FlushFile, &error))?;
            created.close();
            self.resolve_control_path(
                relative_path,
                false,
                StorageOperation::InspectEndpointKeyFile,
            )?;
            verify_regular_non_reparse(&path, StorageOperation::InspectEndpointKeyFile)?;
            verify_endpoint_key_acl(&path)?;
            let read_back = read_bounded_file(
                &path,
                crate::MAX_PROTECTED_ENDPOINT_KEY_BYTES,
                StorageOperation::InspectEndpointKeyFile,
            )?;
            if read_back != protected.as_bytes() {
                return Err(StorageError::new(
                    StorageErrorCode::PublicationVerificationFailed,
                    StorageOperation::InspectEndpointKeyFile,
                ));
            }
            Ok(())
        })
    }

    /// Read a DPAPI endpoint-key envelope after bounded metadata, containment,
    /// regular-file, non-reparse, and exact one-user ACL verification.
    pub fn read_endpoint_key_file(
        &self,
        relative_path: &Path,
    ) -> Result<ProtectedEndpointKey, StorageError> {
        let path = self.resolve_control_path(
            relative_path,
            false,
            StorageOperation::InspectEndpointKeyFile,
        )?;
        verify_regular_non_reparse(&path, StorageOperation::InspectEndpointKeyFile)?;
        verify_endpoint_key_acl(&path)?;
        let bytes = read_bounded_file(
            &path,
            crate::MAX_PROTECTED_ENDPOINT_KEY_BYTES,
            StorageOperation::InspectEndpointKeyFile,
        )?;
        self.resolve_control_path(
            relative_path,
            false,
            StorageOperation::InspectEndpointKeyFile,
        )?;
        verify_regular_non_reparse(&path, StorageOperation::InspectEndpointKeyFile)?;
        verify_endpoint_key_acl(&path)?;
        ProtectedEndpointKey::from_bytes(bytes).map_err(|_| {
            StorageError::new(
                StorageErrorCode::InvalidProtectedKey,
                StorageOperation::InspectEndpointKeyFile,
            )
        })
    }

    pub fn publish_no_replace(
        &self,
        staged_relative_path: &Path,
        final_relative_path: &Path,
    ) -> Result<(), StorageError> {
        self.move_protected_file(staged_relative_path, final_relative_path, false)
    }

    pub fn atomic_replace(
        &self,
        staged_relative_path: &Path,
        final_relative_path: &Path,
    ) -> Result<(), StorageError> {
        self.move_protected_file(staged_relative_path, final_relative_path, true)
    }

    pub fn remove_regular_file(&self, relative_path: &Path) -> Result<bool, StorageError> {
        let path = self.resolve_control_path(relative_path, false, StorageOperation::RemoveFile)?;
        let Some(attributes) = existing_file_attributes(&path, StorageOperation::RemoveFile)?
        else {
            return Ok(false);
        };
        verify_regular_attributes(attributes, StorageOperation::RemoveFile)?;
        verify_user_only_file_acl(&path, StorageOperation::RemoveFile)?;
        fs::remove_file(path).map_err(|error| io_error(StorageOperation::RemoveFile, &error))?;
        Ok(true)
    }

    /// Classify the only two valid locations for one complete installation.
    ///
    /// `install_id` must be exactly 32 lower-case hexadecimal ASCII bytes. The
    /// source is always `installs/<install_id>` and the deterministic
    /// tombstone is always `purge/<install_id>`; callers cannot select either
    /// parent. If both exist, both are preserved and `PurgeTreeConflict` is
    /// returned.
    pub fn classify_install_purge_tree(
        &self,
        install_id: &str,
    ) -> Result<InstallPurgeTreePresence, StorageError> {
        validate_install_id(install_id, StorageOperation::ClassifyPurgeTree)?;
        self.validate_live_root(StorageOperation::ClassifyPurgeTree)?;
        let source = inspect_exact_purge_child(
            self,
            "installs",
            install_id,
            StorageOperation::ClassifyPurgeTree,
        )?;
        let tombstone = inspect_exact_purge_child(
            self,
            "purge",
            install_id,
            StorageOperation::ClassifyPurgeTree,
        )?;
        match (source, tombstone) {
            (true, true) => Err(StorageError::new(
                StorageErrorCode::PurgeTreeConflict,
                StorageOperation::ClassifyPurgeTree,
            )),
            (true, false) => Ok(InstallPurgeTreePresence::Source),
            (false, true) => Ok(InstallPurgeTreePresence::Tombstone),
            (false, false) => Ok(InstallPurgeTreePresence::Gone),
        }
    }

    /// Atomically move `installs/<id>` to `purge/<id>` on the validated NTFS
    /// volume without replacement.
    ///
    /// The exact source directory is renamed through its open handle. Its file
    /// identity and the destination parent volume are revalidated, and a
    /// pre-existing destination is never opened for replacement or cleanup.
    pub fn stage_install_tree_for_purge(
        &self,
        install_id: &str,
    ) -> Result<PurgeStageReport, StorageError> {
        validate_install_id(install_id, StorageOperation::StagePurgeTree)?;
        match self.classify_install_purge_tree(install_id)? {
            InstallPurgeTreePresence::Source => {}
            InstallPurgeTreePresence::Tombstone => {
                return Ok(PurgeStageReport {
                    directory_sync_supported: sync_purge_parents(self)?,
                });
            }
            InstallPurgeTreePresence::Gone => {
                return Err(StorageError::new(
                    StorageErrorCode::NotFound,
                    StorageOperation::StagePurgeTree,
                ));
            }
        }
        self.create_relative_directories(Path::new("purge"))?;
        if self.classify_install_purge_tree(install_id)? != InstallPurgeTreePresence::Source {
            return Err(StorageError::new(
                StorageErrorCode::PurgeTreeConflict,
                StorageOperation::StagePurgeTree,
            ));
        }

        let source_path = self.path().join("installs").join(install_id);
        let purge_parent_path = self.path().join("purge");
        let source =
            PurgeHandle::open_directory(&source_path, true, StorageOperation::StagePurgeTree)?;
        source.verify_control_acl(StorageOperation::StagePurgeTree)?;
        let purge_parent = PurgeHandle::open_directory(
            &purge_parent_path,
            false,
            StorageOperation::StagePurgeTree,
        )?;
        purge_parent.verify_control_acl(StorageOperation::StagePurgeTree)?;
        let source_identity = source.identity(StorageOperation::StagePurgeTree)?;
        let parent_identity = purge_parent.identity(StorageOperation::StagePurgeTree)?;
        if source_identity.volume_serial != parent_identity.volume_serial {
            return Err(StorageError::new(
                StorageErrorCode::DifferentVolume,
                StorageOperation::StagePurgeTree,
            ));
        }
        rename_handle_no_replace(
            &source,
            &purge_parent,
            install_id,
            StorageOperation::StagePurgeTree,
        )?;
        let source_identity_after = source.identity(StorageOperation::StagePurgeTree)?;
        if source_identity_after != source_identity {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::StagePurgeTree,
            ));
        }
        drop(purge_parent);
        drop(source);

        let presence = self.classify_install_purge_tree(install_id)?;
        if presence != InstallPurgeTreePresence::Tombstone {
            return Err(StorageError::new(
                StorageErrorCode::PublicationVerificationFailed,
                StorageOperation::StagePurgeTree,
            ));
        }
        let tombstone = PurgeHandle::open_directory(
            &self.path().join("purge").join(install_id),
            true,
            StorageOperation::StagePurgeTree,
        )?;
        tombstone.verify_control_acl(StorageOperation::StagePurgeTree)?;
        if tombstone.identity(StorageOperation::StagePurgeTree)? != source_identity {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::StagePurgeTree,
            ));
        }
        drop(tombstone);
        Ok(PurgeStageReport {
            directory_sync_supported: sync_purge_parents(self)?,
        })
    }

    /// Audit the entire deterministic tombstone without mutation, then unlink
    /// that exact audited tree bottom-up through revalidated handles.
    ///
    /// Control objects require the exact protected current-user ACL. The fixed
    /// direct child named `data`, when present, requires the data-root ACL and
    /// all of its descendants require the exact inherited data ACL. Sparse,
    /// compressed, read-only, and hard-linked regular entries are accepted
    /// under the explicit policies described by [`PurgeTreeReport`].
    ///
    /// The boundary narrows path-substitution races but cannot defend against a
    /// malicious peer already running as the same Windows user. The durability
    /// claim covers process crashes and reported I/O errors on local NTFS, not
    /// sudden power loss.
    pub fn audit_and_remove_install_tree(
        &self,
        install_id: &str,
    ) -> Result<PurgeTreeReport, StorageError> {
        self.audit_and_remove_install_tree_with_hook(install_id, || Ok(()))
    }

    fn audit_and_remove_install_tree_with_hook(
        &self,
        install_id: &str,
        after_first_audit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<PurgeTreeReport, StorageError> {
        validate_install_id(install_id, StorageOperation::AuditPurgeTree)?;
        match self.classify_install_purge_tree(install_id)? {
            InstallPurgeTreePresence::Tombstone => {}
            InstallPurgeTreePresence::Gone => {
                return Ok(PurgeTreeReport {
                    directory_sync_supported: sync_purge_parent(self)?,
                    ..PurgeTreeReport::default()
                });
            }
            InstallPurgeTreePresence::Source => {
                return Err(StorageError::new(
                    StorageErrorCode::NotFound,
                    StorageOperation::AuditPurgeTree,
                ));
            }
        }
        let tombstone = self.path().join("purge").join(install_id);
        let expected = ExpectedSids::current()?;
        let mut audited = PurgeTreeReport::default();
        let mut audited_fingerprint = PurgeFingerprint::default();
        audit_purge_directory(
            &tombstone,
            PurgeAclContract::TombstoneRoot,
            0,
            &expected,
            &mut audited,
            &mut audited_fingerprint,
        )?;
        after_first_audit()?;
        if self.classify_install_purge_tree(install_id)? != InstallPurgeTreePresence::Tombstone {
            return Err(StorageError::new(
                StorageErrorCode::PurgeTreeConflict,
                StorageOperation::AuditPurgeTree,
            ));
        }
        let mut reaudited = PurgeTreeReport::default();
        let mut reaudited_fingerprint = PurgeFingerprint::default();
        audit_purge_directory(
            &tombstone,
            PurgeAclContract::TombstoneRoot,
            0,
            &expected,
            &mut reaudited,
            &mut reaudited_fingerprint,
        )?;
        if reaudited != audited || reaudited_fingerprint != audited_fingerprint {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::AuditPurgeTree,
            ));
        }

        let mut removed = PurgeTreeReport::default();
        let mut removed_fingerprint = PurgeFingerprint::default();
        remove_purge_directory(
            &tombstone,
            PurgeAclContract::TombstoneRoot,
            0,
            &expected,
            &mut removed,
            &mut removed_fingerprint,
        )?;
        if removed != audited || removed_fingerprint != audited_fingerprint {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::RemovePurgeTree,
            ));
        }
        if existing_file_attributes(&tombstone, StorageOperation::RemovePurgeTree)?.is_some() {
            return Err(StorageError::new(
                StorageErrorCode::PublicationVerificationFailed,
                StorageOperation::RemovePurgeTree,
            ));
        }
        removed.directory_sync_supported = sync_purge_parent(self)?;
        Ok(removed)
    }

    /// Return every immediate child of the exact protected `slots/stable`
    /// directory without name filtering and without following reparse points.
    ///
    /// Regular file contents are read from the identity-checked handle and are
    /// individually bounded by [`MAX_CONTROL_FILE_BYTES`]. The complete result
    /// is also bounded, so an unexpected directory cannot force unbounded
    /// allocation before the caller fails closed.
    #[allow(clippy::too_many_lines)]
    pub fn enumerate_stable_control_directory(
        &self,
        held_install_lock: &crate::ExclusiveFileLock,
    ) -> Result<Vec<ControlDirectoryEntry>, StorageError> {
        let relative = Path::new(r"slots\stable");
        let path =
            self.resolve_control_path(relative, true, StorageOperation::EnumerateControlDirectory)?;
        let directory =
            PurgeHandle::open_directory(&path, false, StorageOperation::EnumerateControlDirectory)?;
        directory.verify_control_acl(StorageOperation::EnumerateControlDirectory)?;
        let directory_identity = directory.identity(StorageOperation::EnumerateControlDirectory)?;
        let held_lock = PurgeHandleRef(held_install_lock.handle());
        let held_lock_metadata = held_lock.metadata(StorageOperation::EnumerateControlDirectory)?;
        if held_lock_metadata.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
            || held_lock_metadata.logical_bytes != 0
        {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::EnumerateControlDirectory,
            ));
        }
        verify_user_only_handle_acl_flags(
            held_lock.raw(),
            0,
            StorageOperation::EnumerateControlDirectory,
        )?;
        let expected_lock_path = path.join("install.lock");
        let actual_lock_path =
            final_path_by_handle(held_lock.raw(), StorageOperation::EnumerateControlDirectory)?;
        if !same_path(&actual_lock_path, &expected_lock_path) {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::EnumerateControlDirectory,
            ));
        }
        let mut entries = Vec::new();
        let mut total_bytes = 0_usize;
        let mut saw_held_lock = false;
        for_each_directory_entry(
            &directory,
            StorageOperation::EnumerateControlDirectory,
            |entry| {
                if entries.len() >= MAX_CONTROL_DIRECTORY_ENTRIES {
                    return Err(StorageError::new(
                        StorageErrorCode::TraversalLimit,
                        StorageOperation::EnumerateControlDirectory,
                    ));
                }
                let child_path = path.join(&entry.name);
                let is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
                let is_reparse = entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
                if entry.name == "install.lock" {
                    if saw_held_lock
                        || is_directory
                        || is_reparse
                        || entry.file_id != held_lock_metadata.identity.file_index
                        || held_lock_metadata.identity.volume_serial
                            != directory_identity.volume_serial
                    {
                        return Err(StorageError::new(
                            StorageErrorCode::IdentityChanged,
                            StorageOperation::EnumerateControlDirectory,
                        ));
                    }
                    saw_held_lock = true;
                    entries.push(ControlDirectoryEntry {
                        name: entry.name,
                        kind: ControlDirectoryEntryKind::RegularFile,
                        reparse_point: false,
                        file_id: held_lock_metadata.identity.file_index,
                        contents: Some(Vec::new()),
                    });
                    return Ok(true);
                }
                let child = PurgeHandle::open_entry(
                    &child_path,
                    is_directory,
                    false,
                    !is_directory && !is_reparse,
                    StorageOperation::EnumerateControlDirectory,
                )?;
                let metadata = child.metadata(StorageOperation::EnumerateControlDirectory)?;
                if metadata.identity.volume_serial != directory_identity.volume_serial
                    || metadata.identity.file_index != entry.file_id
                    || (metadata.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != is_directory
                    || (metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0) != is_reparse
                {
                    return Err(StorageError::new(
                        StorageErrorCode::IdentityChanged,
                        StorageOperation::EnumerateControlDirectory,
                    ));
                }
                child.verify_control_acl(StorageOperation::EnumerateControlDirectory)?;
                let contents = if is_directory || is_reparse {
                    None
                } else {
                    let length = usize::try_from(metadata.logical_bytes).map_err(|_| {
                        StorageError::new(
                            StorageErrorCode::TooLarge,
                            StorageOperation::EnumerateControlDirectory,
                        )
                    })?;
                    if length > MAX_CONTROL_FILE_BYTES {
                        return Err(StorageError::new(
                            StorageErrorCode::TooLarge,
                            StorageOperation::EnumerateControlDirectory,
                        ));
                    }
                    total_bytes = total_bytes.checked_add(length).ok_or_else(|| {
                        StorageError::new(
                            StorageErrorCode::SizeOverflow,
                            StorageOperation::EnumerateControlDirectory,
                        )
                    })?;
                    if total_bytes > MAX_CONTROL_DIRECTORY_TOTAL_BYTES {
                        return Err(StorageError::new(
                            StorageErrorCode::TraversalLimit,
                            StorageOperation::EnumerateControlDirectory,
                        ));
                    }
                    Some(read_exact_control_handle(&child, length)?)
                };
                let final_metadata = child.metadata(StorageOperation::EnumerateControlDirectory)?;
                if final_metadata.identity != metadata.identity
                    || final_metadata.attributes != metadata.attributes
                    || final_metadata.logical_bytes != metadata.logical_bytes
                {
                    return Err(StorageError::new(
                        StorageErrorCode::IdentityChanged,
                        StorageOperation::EnumerateControlDirectory,
                    ));
                }
                entries.push(ControlDirectoryEntry {
                    name: entry.name,
                    kind: if is_directory {
                        ControlDirectoryEntryKind::Directory
                    } else {
                        ControlDirectoryEntryKind::RegularFile
                    },
                    reparse_point: is_reparse,
                    file_id: metadata.identity.file_index,
                    contents,
                });
                Ok(true)
            },
        )?;
        if directory.identity(StorageOperation::EnumerateControlDirectory)? != directory_identity {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::EnumerateControlDirectory,
            ));
        }
        if !saw_held_lock {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                StorageOperation::EnumerateControlDirectory,
            ));
        }
        Ok(entries)
    }

    /// Canonicalize the running executable and prove, using Windows ordinal
    /// case-insensitive component comparison, that it is outside this product
    /// control root. No deletion target is accepted from the caller.
    pub fn validate_current_executable_outside_control_root(
        &self,
    ) -> Result<PathBuf, StorageError> {
        self.validate_live_root(StorageOperation::VerifyPurgeController)?;
        let executable = std::env::current_exe()
            .map_err(|error| io_error(StorageOperation::VerifyPurgeController, &error))?;
        validate_ancestors_no_reparse(&executable, StorageOperation::VerifyPurgeController)?;
        verify_regular_non_reparse(&executable, StorageOperation::VerifyPurgeController)?;
        let canonical = fs::canonicalize(&executable)
            .map_err(|error| io_error(StorageOperation::VerifyPurgeController, &error))?;
        validate_ancestors_no_reparse(&canonical, StorageOperation::VerifyPurgeController)?;
        verify_regular_non_reparse(&canonical, StorageOperation::VerifyPurgeController)?;
        if path_is_same_or_descendant(&canonical, self.path()) {
            return Err(StorageError::new(
                StorageErrorCode::ControllerInsideControlRoot,
                StorageOperation::VerifyPurgeController,
            ));
        }
        Ok(canonical)
    }

    /// Verify the only valid record-absent post-purge structure without
    /// creating, deleting, or recursively adopting any entry.
    ///
    /// The product root may contain only `slots`, `installs`, and `purge`.
    /// `slots` must contain only `stable`, whose only entry must be the exact
    /// held `install.lock` capability. Optional `installs` and `purge`
    /// directories must be exact protected, non-reparse, and empty.
    pub fn verify_clean_install_purge_absence(
        &self,
        held_install_lock: &crate::ExclusiveFileLock,
    ) -> Result<CleanPurgeAbsenceReport, StorageError> {
        let operation = StorageOperation::VerifyCleanPurgeAbsence;
        self.validate_live_root(operation)?;
        let root = PurgeHandle::open_directory(self.path(), false, operation)?;
        root.verify_control_acl(operation)?;
        let mut saw_slots = false;
        let mut saw_installs = false;
        let mut saw_purge = false;
        for_each_directory_entry(&root, operation, |entry| {
            if entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(StorageError::new(StorageErrorCode::ReparsePoint, operation));
            }
            if entry.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(StorageError::new(
                    StorageErrorCode::UnexpectedEntry,
                    operation,
                ));
            }
            let child =
                PurgeHandle::open_directory(&self.path().join(&entry.name), false, operation)?;
            let metadata = child.metadata(operation)?;
            if metadata.identity.file_index != entry.file_id
                || metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || metadata.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(StorageError::new(
                    StorageErrorCode::IdentityChanged,
                    operation,
                ));
            }
            child.verify_control_acl(operation)?;
            match entry.name.to_str() {
                Some("slots") if !saw_slots => saw_slots = true,
                Some("installs") if !saw_installs => saw_installs = true,
                Some("purge") if !saw_purge => saw_purge = true,
                _ => {
                    return Err(StorageError::new(
                        StorageErrorCode::UnexpectedEntry,
                        operation,
                    ));
                }
            }
            Ok(true)
        })?;
        if !saw_slots {
            return Err(StorageError::new(
                StorageErrorCode::UnexpectedEntry,
                operation,
            ));
        }
        verify_slots_structure(self, operation)?;
        let stable_entries = self.enumerate_stable_control_directory(held_install_lock)?;
        if stable_entries.len() != 1
            || stable_entries[0].name != "install.lock"
            || stable_entries[0].kind != ControlDirectoryEntryKind::RegularFile
            || stable_entries[0].reparse_point
            || stable_entries[0].contents.as_deref() != Some(&[])
        {
            return Err(StorageError::new(
                StorageErrorCode::UnexpectedEntry,
                operation,
            ));
        }
        for (present, name) in [(saw_installs, "installs"), (saw_purge, "purge")] {
            if present {
                verify_empty_control_directory(self, name, operation)?;
            }
        }
        Ok(CleanPurgeAbsenceReport {
            installs_directory_present: saw_installs,
            purge_directory_present: saw_purge,
        })
    }

    pub fn sync_directory(&self, relative_path: &Path) -> Result<(), StorageError> {
        if relative_path.as_os_str().is_empty() {
            self.validate_live_root(StorageOperation::SyncDirectory)?;
        } else {
            self.resolve_control_path(relative_path, true, StorageOperation::SyncDirectory)?;
        }
        self.inner.sync_directory(relative_path)
    }

    pub fn acquire_lifetime_lock(
        &self,
        relative_path: &Path,
    ) -> Result<crate::ExclusiveFileLock, crate::NativeError> {
        let path = self
            .resolve_control_path(relative_path, false, StorageOperation::InspectSecurity)
            .map_err(storage_to_lock_error)?;
        match existing_file_attributes(&path, StorageOperation::InspectSecurity)
            .map_err(storage_to_lock_error)?
        {
            Some(_) => {}
            None => self
                .create_protected_file(relative_path, &[])
                .map_err(storage_to_lock_error)?,
        }
        let lock = crate::ExclusiveFileLock::acquire_existing(&path)?;
        verify_user_only_handle_acl(lock.handle(), StorageOperation::InspectSecurity)
            .map_err(storage_to_lock_error)?;
        self.resolve_control_path(relative_path, false, StorageOperation::InspectSecurity)
            .map_err(storage_to_lock_error)?;
        Ok(lock)
    }

    /// Acquire an already-existing exact protected lock without creating any
    /// root, directory, or file as a side effect.
    pub fn acquire_existing_lifetime_lock(
        &self,
        relative_path: &Path,
    ) -> Result<crate::ExclusiveFileLock, StorageError> {
        let operation = StorageOperation::InspectExistingLock;
        let path = self.resolve_control_path(relative_path, false, operation)?;
        let Some(attributes) = existing_file_attributes(&path, operation)? else {
            return Err(StorageError::new(StorageErrorCode::NotFound, operation));
        };
        verify_regular_attributes(attributes, operation)?;
        verify_user_only_file_acl(&path, operation)?;
        let lock = crate::ExclusiveFileLock::acquire_existing(&path)
            .map_err(|error| native_lock_to_storage(error, operation))?;
        verify_user_only_handle_acl(lock.handle(), operation)?;
        let held = PurgeHandleRef(lock.handle());
        let metadata = held.metadata(operation)?;
        if metadata.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                operation,
            ));
        }
        let final_path = final_path_by_handle(lock.handle(), operation)?;
        if !same_path(&final_path, &path) {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                operation,
            ));
        }
        let live_path = self.resolve_control_path(relative_path, false, operation)?;
        verify_regular_non_reparse(&live_path, operation)?;
        verify_user_only_file_acl(&live_path, operation)?;
        Ok(lock)
    }

    fn move_protected_file(
        &self,
        staged_relative_path: &Path,
        final_relative_path: &Path,
        replace: bool,
    ) -> Result<(), StorageError> {
        let staged = self.resolve_control_path(
            staged_relative_path,
            false,
            StorageOperation::VerifyPublication,
        )?;
        let final_path = self.resolve_control_path(
            final_relative_path,
            false,
            StorageOperation::VerifyPublication,
        )?;
        verify_regular_non_reparse(&staged, StorageOperation::VerifyPublication)?;
        verify_user_only_file_acl(&staged, StorageOperation::VerifyPublication)?;
        if replace {
            if let Some(attributes) =
                existing_file_attributes(&final_path, StorageOperation::VerifyPublication)?
            {
                verify_regular_attributes(attributes, StorageOperation::VerifyPublication)?;
                verify_user_only_file_acl(&final_path, StorageOperation::VerifyPublication)?;
            }
            self.inner
                .atomic_replace(staged_relative_path, final_relative_path)?;
        } else {
            self.inner
                .publish_no_replace(staged_relative_path, final_relative_path)?;
        }
        let final_path = self.resolve_control_path(
            final_relative_path,
            false,
            StorageOperation::VerifyPublication,
        )?;
        verify_regular_non_reparse(&final_path, StorageOperation::VerifyPublication)?;
        verify_user_only_file_acl(&final_path, StorageOperation::VerifyPublication)
    }

    fn validate_live_root(&self, operation: StorageOperation) -> Result<(), StorageError> {
        let live = validate_control_root(self.path())?;
        if !same_path(live.path(), self.path())
            || !same_path(&live.inner.volume_root, &self.inner.volume_root)
        {
            return Err(StorageError::new(
                StorageErrorCode::PathEscapesRoot,
                operation,
            ));
        }
        Ok(())
    }

    fn resolve_control_path(
        &self,
        relative_path: &Path,
        include_final_directory: bool,
        operation: StorageOperation,
    ) -> Result<PathBuf, StorageError> {
        self.validate_live_root(operation)?;
        let full_path = self.inner.resolve_relative(relative_path)?;
        let components = relative_path.components().collect::<Vec<_>>();
        let parent_count = if include_final_directory {
            components.len()
        } else {
            components.len().saturating_sub(1)
        };
        let mut current = self.path().to_path_buf();
        for component in components.into_iter().take(parent_count) {
            let Component::Normal(name) = component else {
                return Err(StorageError::new(
                    StorageErrorCode::PathEscapesRoot,
                    operation,
                ));
            };
            current.push(name);
            verify_directory_non_reparse(&current, operation)?;
            verify_control_directory_acl(&current, operation)?;
        }
        Ok(full_path)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

#[derive(Clone, Copy, Debug)]
struct HandleMetadata {
    identity: FileIdentity,
    attributes: u32,
    links: u32,
    logical_bytes: u64,
}

#[derive(Debug)]
struct PurgeHandle(HANDLE);

impl PurgeHandle {
    fn open_directory(
        path: &Path,
        delete_access: bool,
        operation: StorageOperation,
    ) -> Result<Self, StorageError> {
        Self::open(path, true, delete_access, false, operation)
    }

    fn open_entry(
        path: &Path,
        directory: bool,
        delete_access: bool,
        read_contents: bool,
        operation: StorageOperation,
    ) -> Result<Self, StorageError> {
        Self::open(path, directory, delete_access, read_contents, operation)
    }

    fn open(
        path: &Path,
        directory: bool,
        delete_access: bool,
        read_contents: bool,
        operation: StorageOperation,
    ) -> Result<Self, StorageError> {
        let mut access = READ_CONTROL | FILE_READ_ATTRIBUTES;
        if directory {
            access |= FILE_LIST_DIRECTORY;
        }
        if delete_access {
            access |= DELETE;
        }
        if read_contents {
            access |= GENERIC_READ;
        }
        // Omit delete sharing on destructive/audit handles. This both detects
        // existing non-delete-sharing users before pass two and prevents the
        // exact opened object from being renamed while its identity is used.
        let share = if delete_access {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        };
        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
        if directory {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }
        let path_wide = wide(path);
        // SAFETY: the path is NUL-terminated, no security/template pointers are
        // supplied, and the returned handle is immediately RAII-owned.
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                access,
                share,
                ptr::null(),
                OPEN_EXISTING,
                flags,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(purge_last_error(operation));
        }
        Ok(Self(handle))
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }

    fn metadata(&self, operation: StorageOperation) -> Result<HandleMetadata, StorageError> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the live handle is owned by self and information is writable.
        if unsafe { GetFileInformationByHandle(self.0, &raw mut information) } == 0 {
            return Err(purge_last_error(operation));
        }
        Ok(HandleMetadata {
            identity: FileIdentity {
                volume_serial: information.dwVolumeSerialNumber,
                file_index: (u64::from(information.nFileIndexHigh) << 32)
                    | u64::from(information.nFileIndexLow),
            },
            attributes: information.dwFileAttributes,
            links: information.nNumberOfLinks,
            logical_bytes: (u64::from(information.nFileSizeHigh) << 32)
                | u64::from(information.nFileSizeLow),
        })
    }

    fn identity(&self, operation: StorageOperation) -> Result<FileIdentity, StorageError> {
        Ok(self.metadata(operation)?.identity)
    }

    fn verify_control_acl(&self, operation: StorageOperation) -> Result<(), StorageError> {
        let metadata = self.metadata(operation)?;
        let expected_flags = if metadata.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            CONTROL_ROOT_ACE_FLAGS
        } else {
            0
        };
        verify_user_only_handle_acl_flags(self.0, expected_flags, operation)
    }

    fn mark_delete(&self, operation: StorageOperation) -> Result<(), StorageError> {
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        };
        // SAFETY: disposition has the exact ABI shape and the handle was opened
        // with DELETE access. The operation targets this handle's identity.
        if unsafe {
            SetFileInformationByHandle(
                self.0,
                FileDispositionInfoEx,
                (&raw const disposition).cast(),
                u32::try_from(mem::size_of::<FILE_DISPOSITION_INFO_EX>())
                    .expect("disposition size fits u32"),
            )
        } == 0
        {
            return Err(purge_last_error(operation));
        }
        Ok(())
    }
}

impl Drop for PurgeHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns a valid non-null handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Borrowed view of an independently owned no-share handle capability.
struct PurgeHandleRef(HANDLE);

impl PurgeHandleRef {
    const fn raw(&self) -> HANDLE {
        self.0
    }

    fn metadata(&self, operation: StorageOperation) -> Result<HandleMetadata, StorageError> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the borrowed handle remains owned and live for this call.
        if unsafe { GetFileInformationByHandle(self.0, &raw mut information) } == 0 {
            return Err(purge_last_error(operation));
        }
        Ok(HandleMetadata {
            identity: FileIdentity {
                volume_serial: information.dwVolumeSerialNumber,
                file_index: (u64::from(information.nFileIndexHigh) << 32)
                    | u64::from(information.nFileIndexLow),
            },
            attributes: information.dwFileAttributes,
            links: information.nNumberOfLinks,
            logical_bytes: (u64::from(information.nFileSizeHigh) << 32)
                | u64::from(information.nFileSizeLow),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PurgeAclContract {
    TombstoneRoot,
    Control,
    DataRoot,
    DataDescendant,
}

#[derive(Debug)]
struct EnumeratedEntry {
    name: OsString,
    attributes: u32,
    file_id: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PurgeFingerprint([u8; 32]);

impl PurgeFingerprint {
    fn add(&mut self, path: &Path, metadata: &HandleMetadata) {
        let mut digest = Sha256::new();
        for unit in path.as_os_str().encode_wide() {
            digest.update(unit.to_le_bytes());
        }
        digest.update(metadata.identity.volume_serial.to_le_bytes());
        digest.update(metadata.identity.file_index.to_le_bytes());
        digest.update(metadata.attributes.to_le_bytes());
        digest.update(metadata.links.to_le_bytes());
        digest.update(metadata.logical_bytes.to_le_bytes());
        let value: [u8; 32] = digest.finalize().into();
        for (target, source) in self.0.iter_mut().zip(value) {
            *target ^= source;
        }
    }
}

fn validate_install_id(install_id: &str, operation: StorageOperation) -> Result<(), StorageError> {
    if install_id.len() != INSTALL_ID_HEX_LENGTH
        || !install_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(StorageError::new(StorageErrorCode::InvalidPath, operation));
    }
    Ok(())
}

fn inspect_exact_purge_child(
    root: &ValidatedControlRoot,
    parent_name: &str,
    install_id: &str,
    operation: StorageOperation,
) -> Result<bool, StorageError> {
    let parent_path = root.path().join(parent_name);
    let Some(parent_attributes) = existing_file_attributes(&parent_path, operation)? else {
        return Ok(false);
    };
    verify_directory_attributes(parent_attributes, operation)?;
    let parent = PurgeHandle::open_directory(&parent_path, false, operation)?;
    parent.verify_control_acl(operation)?;
    let child_path = parent_path.join(install_id);
    let Some(child_attributes) = existing_file_attributes(&child_path, operation)? else {
        return Ok(false);
    };
    verify_directory_attributes(child_attributes, operation)?;
    let child = PurgeHandle::open_directory(&child_path, false, operation)?;
    child.verify_control_acl(operation)?;
    Ok(true)
}

fn verify_slots_structure(
    root: &ValidatedControlRoot,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let slots_path = root.path().join("slots");
    let slots = PurgeHandle::open_directory(&slots_path, false, operation)?;
    slots.verify_control_acl(operation)?;
    let slots_identity = slots.identity(operation)?;
    let mut saw_stable = false;
    for_each_directory_entry(&slots, operation, |entry| {
        if saw_stable || entry.name != "stable" {
            return Err(StorageError::new(
                StorageErrorCode::UnexpectedEntry,
                operation,
            ));
        }
        if entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(StorageError::new(StorageErrorCode::ReparsePoint, operation));
        }
        if entry.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(StorageError::new(StorageErrorCode::NotDirectory, operation));
        }
        let stable = PurgeHandle::open_directory(&slots_path.join("stable"), false, operation)?;
        let metadata = stable.metadata(operation)?;
        if metadata.identity.volume_serial != slots_identity.volume_serial
            || metadata.identity.file_index != entry.file_id
            || metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                operation,
            ));
        }
        stable.verify_control_acl(operation)?;
        saw_stable = true;
        Ok(true)
    })?;
    if !saw_stable {
        return Err(StorageError::new(
            StorageErrorCode::UnexpectedEntry,
            operation,
        ));
    }
    Ok(())
}

fn verify_empty_control_directory(
    root: &ValidatedControlRoot,
    name: &str,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let directory = PurgeHandle::open_directory(&root.path().join(name), false, operation)?;
    directory.verify_control_acl(operation)?;
    if first_directory_entry(&directory, operation)?.is_some() {
        return Err(StorageError::new(
            StorageErrorCode::UnexpectedEntry,
            operation,
        ));
    }
    Ok(())
}

fn rename_handle_no_replace(
    source: &PurgeHandle,
    destination_parent: &PurgeHandle,
    destination_name: &str,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let destination_path =
        final_path_by_handle(destination_parent.raw(), operation)?.join(destination_name);
    let name_wide = destination_path
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    let name_bytes = name_wide
        .len()
        .checked_mul(mem::size_of::<u16>())
        .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
    let header_bytes = mem::offset_of!(FILE_RENAME_INFO, FileName);
    let total_bytes = header_bytes
        .checked_add(name_bytes)
        .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
    let words = total_bytes.div_ceil(mem::size_of::<u64>());
    let mut buffer = vec![0_u64; words];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: buffer is u64-aligned and sized for the fixed header plus the
    // complete UTF-16 name. No replacement flag is set.
    unsafe {
        (*information).Anonymous.Flags = 0;
        (*information).RootDirectory = ptr::null_mut();
        (*information).FileNameLength = u32::try_from(name_bytes)
            .map_err(|_| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
        ptr::copy_nonoverlapping(
            name_wide.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            name_wide.len(),
        );
        if SetFileInformationByHandle(
            source.raw(),
            FileRenameInfo,
            information.cast(),
            u32::try_from(total_bytes)
                .map_err(|_| StorageError::new(StorageErrorCode::SizeOverflow, operation))?,
        ) == 0
        {
            let code = last_error();
            if matches!(code, ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) {
                return Err(StorageError::with_os_code(
                    StorageErrorCode::PurgeTreeConflict,
                    operation,
                    code,
                ));
            }
            return Err(purge_os_error(operation, code));
        }
    }
    Ok(())
}

fn sync_purge_parents(root: &ValidatedControlRoot) -> Result<bool, StorageError> {
    let mut supported = true;
    for relative in [Path::new("installs"), Path::new("purge")] {
        if existing_file_attributes(&root.path().join(relative), StorageOperation::SyncDirectory)?
            .is_none()
        {
            continue;
        }
        match root.sync_directory(relative) {
            Ok(()) => {}
            Err(error) if error.code() == StorageErrorCode::DirectorySyncUnsupported => {
                supported = false;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(supported)
}

fn sync_purge_parent(root: &ValidatedControlRoot) -> Result<bool, StorageError> {
    if existing_file_attributes(&root.path().join("purge"), StorageOperation::SyncDirectory)?
        .is_none()
    {
        return Ok(true);
    }
    match root.sync_directory(Path::new("purge")) {
        Ok(()) => Ok(true),
        Err(error) if error.code() == StorageErrorCode::DirectorySyncUnsupported => Ok(false),
        Err(error) => Err(error),
    }
}

fn audit_purge_directory(
    path: &Path,
    contract: PurgeAclContract,
    depth: usize,
    expected: &ExpectedSids,
    report: &mut PurgeTreeReport,
    fingerprint: &mut PurgeFingerprint,
) -> Result<(), StorageError> {
    ensure_purge_depth(depth, StorageOperation::AuditPurgeTree)?;
    let directory = PurgeHandle::open_directory(path, true, StorageOperation::AuditPurgeTree)?;
    let metadata = verify_purge_handle(
        &directory,
        true,
        None,
        contract,
        expected,
        StorageOperation::AuditPurgeTree,
    )?;
    fingerprint.add(path, &metadata);
    add_directory_report(report, &metadata, StorageOperation::AuditPurgeTree)?;
    for_each_directory_entry(&directory, StorageOperation::AuditPurgeTree, |entry| {
        ensure_purge_entry_capacity(report, StorageOperation::AuditPurgeTree)?;
        let child_path = path.join(&entry.name);
        ensure_purge_path_bound(&child_path, StorageOperation::AuditPurgeTree)?;
        let child_is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let child_contract = child_contract(contract, &entry.name);
        if child_is_directory {
            audit_purge_directory(
                &child_path,
                child_contract,
                depth + 1,
                expected,
                report,
                fingerprint,
            )?;
            let child =
                PurgeHandle::open_directory(&child_path, true, StorageOperation::AuditPurgeTree)?;
            verify_purge_handle(
                &child,
                true,
                Some(entry.file_id),
                child_contract,
                expected,
                StorageOperation::AuditPurgeTree,
            )?;
        } else {
            let child = PurgeHandle::open_entry(
                &child_path,
                false,
                true,
                false,
                StorageOperation::AuditPurgeTree,
            )?;
            let metadata = verify_purge_handle(
                &child,
                false,
                Some(entry.file_id),
                child_contract,
                expected,
                StorageOperation::AuditPurgeTree,
            )?;
            fingerprint.add(&child_path, &metadata);
            add_file_report(report, &metadata, StorageOperation::AuditPurgeTree)?;
        }
        Ok(true)
    })?;
    let final_metadata = directory.metadata(StorageOperation::AuditPurgeTree)?;
    if final_metadata.identity != metadata.identity {
        return Err(StorageError::new(
            StorageErrorCode::IdentityChanged,
            StorageOperation::AuditPurgeTree,
        ));
    }
    Ok(())
}

fn remove_purge_directory(
    path: &Path,
    contract: PurgeAclContract,
    depth: usize,
    expected: &ExpectedSids,
    report: &mut PurgeTreeReport,
    fingerprint: &mut PurgeFingerprint,
) -> Result<(), StorageError> {
    ensure_purge_depth(depth, StorageOperation::RemovePurgeTree)?;
    let directory = PurgeHandle::open_directory(path, true, StorageOperation::RemovePurgeTree)?;
    let initial = verify_purge_handle(
        &directory,
        true,
        None,
        contract,
        expected,
        StorageOperation::RemovePurgeTree,
    )?;
    while let Some(entry) = first_directory_entry(&directory, StorageOperation::RemovePurgeTree)? {
        ensure_purge_entry_capacity(report, StorageOperation::RemovePurgeTree)?;
        let child_path = path.join(&entry.name);
        ensure_purge_path_bound(&child_path, StorageOperation::RemovePurgeTree)?;
        let child_is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let child_contract = child_contract(contract, &entry.name);
        if child_is_directory {
            // The recursive open must still resolve to the exact enumerated
            // identity before any descendant is touched.
            let child =
                PurgeHandle::open_directory(&child_path, true, StorageOperation::RemovePurgeTree)?;
            verify_purge_handle(
                &child,
                true,
                Some(entry.file_id),
                child_contract,
                expected,
                StorageOperation::RemovePurgeTree,
            )?;
            drop(child);
            remove_purge_directory(
                &child_path,
                child_contract,
                depth + 1,
                expected,
                report,
                fingerprint,
            )?;
        } else {
            let child = PurgeHandle::open_entry(
                &child_path,
                false,
                true,
                false,
                StorageOperation::RemovePurgeTree,
            )?;
            let metadata = verify_purge_handle(
                &child,
                false,
                Some(entry.file_id),
                child_contract,
                expected,
                StorageOperation::RemovePurgeTree,
            )?;
            fingerprint.add(&child_path, &metadata);
            add_file_report(report, &metadata, StorageOperation::RemovePurgeTree)?;
            child.mark_delete(StorageOperation::RemovePurgeTree)?;
            drop(child);
        }
    }
    let final_metadata = verify_purge_handle(
        &directory,
        true,
        Some(initial.identity.file_index),
        contract,
        expected,
        StorageOperation::RemovePurgeTree,
    )?;
    if final_metadata.identity != initial.identity {
        return Err(StorageError::new(
            StorageErrorCode::IdentityChanged,
            StorageOperation::RemovePurgeTree,
        ));
    }
    fingerprint.add(path, &final_metadata);
    add_directory_report(report, &final_metadata, StorageOperation::RemovePurgeTree)?;
    directory.mark_delete(StorageOperation::RemovePurgeTree)?;
    drop(directory);
    Ok(())
}

fn verify_purge_handle(
    handle: &PurgeHandle,
    expected_directory: bool,
    expected_file_id: Option<u64>,
    contract: PurgeAclContract,
    expected: &ExpectedSids,
    operation: StorageOperation,
) -> Result<HandleMetadata, StorageError> {
    let metadata = handle.metadata(operation)?;
    if metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StorageError::new(StorageErrorCode::ReparsePoint, operation));
    }
    let actual_directory = metadata.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if actual_directory != expected_directory {
        return Err(StorageError::new(
            if expected_directory {
                StorageErrorCode::NotDirectory
            } else {
                StorageErrorCode::NotRegularFile
            },
            operation,
        ));
    }
    if expected_file_id.is_some_and(|file_id| metadata.identity.file_index != file_id) {
        return Err(StorageError::new(
            StorageErrorCode::IdentityChanged,
            operation,
        ));
    }
    match contract {
        PurgeAclContract::TombstoneRoot | PurgeAclContract::Control => {
            let flags = if actual_directory {
                CONTROL_ROOT_ACE_FLAGS
            } else {
                0
            };
            verify_user_only_handle_acl_flags(handle.raw(), flags, operation)?;
        }
        PurgeAclContract::DataRoot => {
            if !actual_directory {
                return Err(StorageError::new(StorageErrorCode::NotDirectory, operation));
            }
            verify_data_handle_acl(handle.raw(), expected, true, true, operation)?;
        }
        PurgeAclContract::DataDescendant => {
            verify_data_handle_acl(handle.raw(), expected, false, actual_directory, operation)?;
        }
    }
    Ok(metadata)
}

fn child_contract(parent: PurgeAclContract, name: &OsString) -> PurgeAclContract {
    match parent {
        PurgeAclContract::TombstoneRoot if same_path(Path::new(name), Path::new("data")) => {
            PurgeAclContract::DataRoot
        }
        PurgeAclContract::DataRoot | PurgeAclContract::DataDescendant => {
            PurgeAclContract::DataDescendant
        }
        PurgeAclContract::TombstoneRoot | PurgeAclContract::Control => PurgeAclContract::Control,
    }
}

fn add_directory_report(
    report: &mut PurgeTreeReport,
    metadata: &HandleMetadata,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    report.directories = report
        .directories
        .checked_add(1)
        .ok_or_else(|| StorageError::new(StorageErrorCode::TraversalLimit, operation))?;
    if metadata.attributes & FILE_ATTRIBUTE_READONLY != 0 {
        report.read_only_entries = report
            .read_only_entries
            .checked_add(1)
            .ok_or_else(|| StorageError::new(StorageErrorCode::TraversalLimit, operation))?;
    }
    Ok(())
}

fn add_file_report(
    report: &mut PurgeTreeReport,
    metadata: &HandleMetadata,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    report.files = report
        .files
        .checked_add(1)
        .ok_or_else(|| StorageError::new(StorageErrorCode::TraversalLimit, operation))?;
    report.logical_file_bytes = report
        .logical_file_bytes
        .checked_add(metadata.logical_bytes)
        .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
    for (present, counter) in [
        (metadata.links > 1, &mut report.hard_link_entries),
        (
            metadata.attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0,
            &mut report.sparse_files,
        ),
        (
            metadata.attributes & FILE_ATTRIBUTE_COMPRESSED != 0,
            &mut report.compressed_files,
        ),
        (
            metadata.attributes & FILE_ATTRIBUTE_READONLY != 0,
            &mut report.read_only_entries,
        ),
    ] {
        if present {
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| StorageError::new(StorageErrorCode::TraversalLimit, operation))?;
        }
    }
    Ok(())
}

fn ensure_purge_depth(depth: usize, operation: StorageOperation) -> Result<(), StorageError> {
    if depth > MAX_PURGE_DEPTH {
        return Err(StorageError::new(
            StorageErrorCode::TraversalLimit,
            operation,
        ));
    }
    Ok(())
}

fn ensure_purge_entry_capacity(
    report: &PurgeTreeReport,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let entries = report
        .directories
        .checked_add(report.files)
        .ok_or_else(|| StorageError::new(StorageErrorCode::TraversalLimit, operation))?;
    if entries >= MAX_PURGE_ENTRIES {
        return Err(StorageError::new(
            StorageErrorCode::TraversalLimit,
            operation,
        ));
    }
    Ok(())
}

fn ensure_purge_path_bound(path: &Path, operation: StorageOperation) -> Result<(), StorageError> {
    if path.as_os_str().encode_wide().count() >= PATH_CAPACITY {
        return Err(StorageError::new(
            StorageErrorCode::TraversalLimit,
            operation,
        ));
    }
    Ok(())
}

fn for_each_directory_entry(
    directory: &PurgeHandle,
    operation: StorageOperation,
    mut visit: impl FnMut(EnumeratedEntry) -> Result<bool, StorageError>,
) -> Result<(), StorageError> {
    let mut restart = true;
    loop {
        let mut buffer = vec![0_u64; PURGE_ENUMERATION_BUFFER_BYTES / mem::size_of::<u64>()];
        let information_class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        // SAFETY: buffer is aligned and writable for its declared byte size;
        // the live directory handle has FILE_LIST_DIRECTORY access.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                directory.raw(),
                information_class,
                buffer.as_mut_ptr().cast(),
                u32::try_from(PURGE_ENUMERATION_BUFFER_BYTES)
                    .expect("purge enumeration buffer fits u32"),
            )
        } != 0;
        if !succeeded {
            let code = last_error();
            if code == ERROR_NO_MORE_FILES {
                return Ok(());
            }
            return Err(purge_os_error(operation, code));
        }
        restart = false;
        let bytes = unsafe {
            slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), PURGE_ENUMERATION_BUFFER_BYTES)
        };
        let mut offset = 0_usize;
        loop {
            let header_bytes = mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            if offset
                .checked_add(header_bytes)
                .is_none_or(|end| end > bytes.len())
            {
                return Err(StorageError::new(StorageErrorCode::Io, operation));
            }
            // SAFETY: the bounds above cover the fixed header. Kernel buffers
            // may not satisfy Rust alignment, so read the record unaligned.
            let info = unsafe {
                ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<FILE_ID_BOTH_DIR_INFO>())
            };
            let name_bytes = usize::try_from(info.FileNameLength)
                .map_err(|_| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
            if name_bytes % mem::size_of::<u16>() != 0 {
                return Err(StorageError::new(StorageErrorCode::Io, operation));
            }
            let name_offset = offset
                .checked_add(header_bytes)
                .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
            let name_end = name_offset
                .checked_add(name_bytes)
                .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
            if name_end > bytes.len() {
                return Err(StorageError::new(StorageErrorCode::Io, operation));
            }
            let name_units = bytes[name_offset..name_end]
                .chunks_exact(mem::size_of::<u16>())
                .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
                .collect::<Vec<_>>();
            let name = OsString::from_wide(&name_units);
            if name != "." && name != ".." {
                validate_relative_path(Path::new(&name))?;
                if !visit(EnumeratedEntry {
                    name,
                    attributes: info.FileAttributes,
                    file_id: info.FileId.cast_unsigned(),
                })? {
                    return Ok(());
                }
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            let next = usize::try_from(info.NextEntryOffset)
                .map_err(|_| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
            if next < header_bytes {
                return Err(StorageError::new(StorageErrorCode::Io, operation));
            }
            offset = offset
                .checked_add(next)
                .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
        }
    }
}

fn first_directory_entry(
    directory: &PurgeHandle,
    operation: StorageOperation,
) -> Result<Option<EnumeratedEntry>, StorageError> {
    let mut first = None;
    for_each_directory_entry(directory, operation, |entry| {
        if first.is_none() {
            first = Some(entry);
        }
        Ok(false)
    })?;
    Ok(first)
}

fn purge_last_error(operation: StorageOperation) -> StorageError {
    purge_os_error(operation, last_error())
}

fn purge_os_error(operation: StorageOperation, code: u32) -> StorageError {
    let category = match code {
        ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => StorageErrorCode::SharingViolation,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => StorageErrorCode::IdentityChanged,
        ERROR_ACCESS_DENIED => StorageErrorCode::AccessDenied,
        _ => StorageErrorCode::Io,
    };
    StorageError::with_os_code(category, operation, code)
}

fn read_exact_control_handle(
    handle: &PurgeHandle,
    expected_length: usize,
) -> Result<Vec<u8>, StorageError> {
    let operation = StorageOperation::EnumerateControlDirectory;
    let mut bytes = vec![0_u8; expected_length];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        let requested =
            u32::try_from(remaining.min(64 * 1024)).expect("bounded control read chunk fits u32");
        let mut read = 0_u32;
        // SAFETY: the destination slice is writable for requested bytes, the
        // synchronous handle is live, and no OVERLAPPED structure is used.
        if unsafe {
            ReadFile(
                handle.raw(),
                bytes[offset..].as_mut_ptr(),
                requested,
                &raw mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(purge_last_error(operation));
        }
        if read == 0 {
            return Err(StorageError::new(
                StorageErrorCode::IdentityChanged,
                operation,
            ));
        }
        offset = offset
            .checked_add(usize::try_from(read).expect("u32 read count fits usize"))
            .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
    }
    let mut trailing = [0_u8; 1];
    let mut read = 0_u32;
    // SAFETY: one-byte destination and output count are writable; the handle
    // remains positioned immediately after the expected complete contents.
    if unsafe {
        ReadFile(
            handle.raw(),
            trailing.as_mut_ptr(),
            1,
            &raw mut read,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(purge_last_error(operation));
    }
    if read != 0 {
        return Err(StorageError::new(
            StorageErrorCode::IdentityChanged,
            operation,
        ));
    }
    Ok(bytes)
}

fn validate_ancestors_no_reparse(
    path: &Path,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let mut current = PathBuf::new();
    let mut reached_root = false;
    for component in path.components() {
        if matches!(component, Component::RootDir) {
            reached_root = true;
        }
        current.push(component.as_os_str());
        if !reached_root {
            continue;
        }
        if existing_file_attributes(&current, operation)?
            .is_some_and(|attributes| attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        {
            return Err(StorageError::new(StorageErrorCode::ReparsePoint, operation));
        }
    }
    Ok(())
}

fn final_path_by_handle(
    handle: HANDLE,
    operation: StorageOperation,
) -> Result<PathBuf, StorageError> {
    let mut buffer = vec![0_u16; PATH_CAPACITY];
    // SAFETY: buffer is writable for the declared capacity and the borrowed
    // handle remains live. Flags zero request normalized DOS-volume syntax.
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), PATH_CAPACITY_U32, 0) };
    if length == 0 {
        return Err(purge_last_error(operation));
    }
    let length = usize::try_from(length)
        .map_err(|_| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
    if length >= buffer.len() {
        return Err(StorageError::new(
            StorageErrorCode::TraversalLimit,
            operation,
        ));
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

fn cleanup_created_directories(created: &[PathBuf]) -> Result<(), StorageError> {
    for directory in created.iter().rev() {
        let Some(attributes) =
            existing_file_attributes(directory, StorageOperation::CreateDirectory)?
        else {
            continue;
        };
        verify_directory_attributes(attributes, StorageOperation::CreateDirectory)?;
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(StorageOperation::CreateDirectory, &error)),
        }
    }
    Ok(())
}

fn ensure_control_directory_acl(
    path: &Path,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    verify_directory_non_reparse(path, operation)?;
    if verify_control_directory_acl(path, operation).is_ok() {
        return Ok(());
    }
    let mut entries =
        fs::read_dir(path).map_err(|error| io_error(StorageOperation::CreateDirectory, &error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| io_error(StorageOperation::CreateDirectory, &error))?
        .is_some()
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    apply_user_only_directory_acl(path, operation)?;
    verify_control_directory_acl(path, operation)
}

struct CreatedFileGuard {
    path: PathBuf,
    file: Option<File>,
    armed: bool,
}

impl CreatedFileGuard {
    fn new(path: &Path, file: File) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(file),
            armed: true,
        }
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("created file remains open")
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn cleanup(&mut self) -> Result<(), StorageError> {
        self.close();
        let Some(attributes) = existing_file_attributes(&self.path, StorageOperation::RemoveFile)?
        else {
            self.armed = false;
            return Ok(());
        };
        verify_regular_attributes(attributes, StorageOperation::RemoveFile)?;
        fs::remove_file(&self.path)
            .map_err(|error| io_error(StorageOperation::RemoveFile, &error))?;
        self.armed = false;
        Ok(())
    }

    fn commit(mut self) {
        self.close();
        self.armed = false;
    }
}

impl Drop for CreatedFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
    }
}

fn with_created_file<T>(
    path: &Path,
    operation: StorageOperation,
    action: impl FnOnce(&mut CreatedFileGuard) -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| create_new_error(operation, &error))?;
    let mut created = CreatedFileGuard::new(path, file);
    match action(&mut created) {
        Ok(value) => {
            created.commit();
            Ok(value)
        }
        Err(error) => match created.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(cleanup_error),
        },
    }
}

impl ValidatedDataRoot {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn create_flushed_file(
        &self,
        relative_path: &Path,
        contents: &[u8],
    ) -> Result<(), StorageError> {
        let path = self.resolve_relative(relative_path)?;
        with_created_file(&path, StorageOperation::CreateFile, |created| {
            created
                .file_mut()
                .write_all(contents)
                .map_err(|error| io_error(StorageOperation::WriteFile, &error))?;
            created
                .file_mut()
                .sync_all()
                .map_err(|error| io_error(StorageOperation::FlushFile, &error))
        })
    }

    pub fn create_flushed_zero_file(
        &self,
        relative_path: &Path,
        length: u64,
    ) -> Result<(), StorageError> {
        let path = self.resolve_relative(relative_path)?;
        with_created_file(&path, StorageOperation::CreateFile, |created| {
            // `set_len` alone advances EOF but does not prove physical
            // allocation. Write every byte before flushing and checking the
            // sparse/compressed attributes and allocated clusters.
            let zeroes = [0_u8; 8 * 1024];
            let mut remaining = length;
            while remaining != 0 {
                let chunk = usize::try_from(remaining.min(zeroes.len() as u64)).map_err(|_| {
                    StorageError::new(StorageErrorCode::Io, StorageOperation::WriteFile)
                })?;
                created
                    .file_mut()
                    .write_all(&zeroes[..chunk])
                    .map_err(|error| io_error(StorageOperation::WriteFile, &error))?;
                remaining -= u64::try_from(chunk).map_err(|_| {
                    StorageError::new(StorageErrorCode::Io, StorageOperation::WriteFile)
                })?;
            }
            created
                .file_mut()
                .sync_all()
                .map_err(|error| io_error(StorageOperation::FlushFile, &error))?;
            verify_regular_non_reparse(&path, StorageOperation::CreateFile)?;
            let attributes = file_attributes(&path, StorageOperation::CreateFile)?;
            if attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0 {
                return Err(StorageError::new(
                    StorageErrorCode::SparseFile,
                    StorageOperation::CreateFile,
                ));
            }
            if attributes & FILE_ATTRIBUTE_COMPRESSED != 0 {
                return Err(StorageError::new(
                    StorageErrorCode::CompressedFile,
                    StorageOperation::CreateFile,
                ));
            }
            if length != 0 && allocated_file_bytes(&path, StorageOperation::CreateFile)? < length {
                return Err(StorageError::new(
                    StorageErrorCode::InsufficientAllocation,
                    StorageOperation::CreateFile,
                ));
            }
            Ok(())
        })
    }

    /// Create each missing directory component without ever following a
    /// reparse point. Existing components are accepted only when directories.
    pub fn create_relative_directories(&self, relative_path: &Path) -> Result<(), StorageError> {
        validate_relative_path(relative_path)?;
        let mut current = self.canonical_path.clone();
        for component in relative_path.components() {
            let Component::Normal(name) = component else {
                return Err(StorageError::new(
                    StorageErrorCode::PathEscapesRoot,
                    StorageOperation::CreateDirectory,
                ));
            };
            current.push(name);
            match existing_file_attributes(&current, StorageOperation::CreateDirectory)? {
                Some(attributes) => {
                    verify_directory_attributes(attributes, StorageOperation::CreateDirectory)?;
                }
                None => match fs::create_dir(&current) {
                    Ok(()) => {
                        verify_directory_non_reparse(&current, StorageOperation::CreateDirectory)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        verify_directory_non_reparse(&current, StorageOperation::CreateDirectory)?;
                    }
                    Err(error) => {
                        return Err(io_error(StorageOperation::CreateDirectory, &error));
                    }
                },
            }
        }
        Ok(())
    }

    /// Revalidate the root and the exact inherited ACL on every existing
    /// component of a relative path. A missing tail is accepted so callers can
    /// validate parents before create-new operations, then call this again to
    /// verify the newly created object.
    pub fn validate_relative_path_security(
        &self,
        relative_path: &Path,
    ) -> Result<(), StorageError> {
        validate_relative_path(relative_path)?;
        let live = validate_data_root(self.path())?;
        if !same_path(live.path(), self.path()) || !same_path(&live.volume_root, &self.volume_root)
        {
            return Err(StorageError::new(
                StorageErrorCode::PathEscapesRoot,
                StorageOperation::ValidatePath,
            ));
        }
        let expected = ExpectedSids::current()?;
        let components = relative_path.components().collect::<Vec<_>>();
        let mut current = self.canonical_path.clone();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(StorageError::new(
                    StorageErrorCode::PathEscapesRoot,
                    StorageOperation::ValidatePath,
                ));
            };
            current.push(name);
            let Some(attributes) =
                existing_file_attributes(&current, StorageOperation::ValidatePath)?
            else {
                return Ok(());
            };
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(StorageError::new(
                    StorageErrorCode::ReparsePoint,
                    StorageOperation::ValidatePath,
                ));
            }
            let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            if !is_directory && index + 1 != components.len() {
                return Err(StorageError::new(
                    StorageErrorCode::NotDirectory,
                    StorageOperation::ValidatePath,
                ));
            }
            verify_data_descendant_acl(
                &current,
                &expected,
                is_directory,
                StorageOperation::ValidatePath,
            )?;
        }
        Ok(())
    }

    /// Remove exactly one regular file. Missing files are reported as `false`.
    pub fn remove_regular_file(&self, relative_path: &Path) -> Result<bool, StorageError> {
        let path = self.resolve_relative(relative_path)?;
        let Some(attributes) = existing_file_attributes(&path, StorageOperation::RemoveFile)?
        else {
            return Ok(false);
        };
        verify_regular_attributes(attributes, StorageOperation::RemoveFile)?;
        fs::remove_file(path).map_err(|error| io_error(StorageOperation::RemoveFile, &error))?;
        Ok(true)
    }

    /// Sum allocated bytes of every regular file under this root.
    ///
    /// Reparse points and non-file/non-directory objects fail closed. Hard
    /// links are counted once per directory entry, matching path quota usage.
    pub fn allocated_tree_bytes(&self) -> Result<u64, StorageError> {
        let live = validate_data_root(self.path())?;
        if !same_path(live.path(), self.path()) || !same_path(&live.volume_root, &self.volume_root)
        {
            return Err(StorageError::new(
                StorageErrorCode::PathEscapesRoot,
                StorageOperation::MeasureAllocation,
            ));
        }
        allocated_tree_bytes(&self.canonical_path, &ExpectedSids::current()?)
    }

    /// Return bytes available to the current user on the validated volume.
    pub fn volume_free_bytes(&self) -> Result<u64, StorageError> {
        let volume = wide(&self.volume_root);
        let mut available = 0_u64;
        // SAFETY: the volume path is NUL-terminated and `available` is a valid
        // writable output. Optional total outputs are not requested.
        if unsafe {
            GetDiskFreeSpaceExW(
                volume.as_ptr(),
                &raw mut available,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(StorageError::with_os_code(
                StorageErrorCode::Io,
                StorageOperation::QueryFreeSpace,
                last_error(),
            ));
        }
        Ok(available)
    }

    /// Ask NTFS to flush a directory handle when the host supports it.
    ///
    /// Windows does not document `FlushFileBuffers` as a directory-handle
    /// operation. Hosts rejecting it return `DirectorySyncUnsupported`; no
    /// power-loss durability claim is made from this method.
    pub fn sync_directory(&self, relative_path: &Path) -> Result<(), StorageError> {
        let path = if relative_path.as_os_str().is_empty() {
            self.canonical_path.clone()
        } else {
            self.resolve_relative(relative_path)?
        };
        verify_directory_non_reparse(&path, StorageOperation::SyncDirectory)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .map_err(|error| io_error(StorageOperation::SyncDirectory, &error))?;
        directory.sync_all().map_err(|error| {
            let os_code = error
                .raw_os_error()
                .and_then(|value| u32::try_from(value).ok());
            if os_code.is_some_and(|code| {
                matches!(
                    code,
                    ERROR_ACCESS_DENIED
                        | ERROR_INVALID_HANDLE
                        | ERROR_INVALID_FUNCTION
                        | ERROR_NOT_SUPPORTED
                )
            }) {
                os_code.map_or_else(
                    || {
                        StorageError::new(
                            StorageErrorCode::DirectorySyncUnsupported,
                            StorageOperation::SyncDirectory,
                        )
                    },
                    |code| {
                        StorageError::with_os_code(
                            StorageErrorCode::DirectorySyncUnsupported,
                            StorageOperation::SyncDirectory,
                            code,
                        )
                    },
                )
            } else {
                io_error(StorageOperation::SyncDirectory, &error)
            }
        })
    }

    /// Stream an already-open source into a create-new file and verify the
    /// final on-disk bytes against the expected SHA-256 digest.
    pub fn copy_reader_verified<R: Read>(
        &self,
        source: &mut R,
        destination_relative_path: &Path,
        expected_sha256: [u8; 32],
    ) -> Result<u64, StorageError> {
        let destination = self.resolve_relative(destination_relative_path)?;
        copy_reader_verified(source, &destination, expected_sha256)
    }

    /// Create a DPAPI envelope file with an exact current-user-only ACL.
    /// Existing files are never opened for writing or replaced.
    pub fn create_endpoint_key_file(
        &self,
        relative_path: &Path,
        protected: &ProtectedEndpointKey,
    ) -> Result<(), StorageError> {
        let path = self.resolve_relative(relative_path)?;
        with_created_file(&path, StorageOperation::CreateEndpointKeyFile, |created| {
            apply_endpoint_key_acl(&path)?;
            verify_endpoint_key_acl(&path)?;
            created
                .file_mut()
                .write_all(protected.as_bytes())
                .map_err(|error| io_error(StorageOperation::CreateEndpointKeyFile, &error))?;
            created
                .file_mut()
                .sync_all()
                .map_err(|error| io_error(StorageOperation::FlushFile, &error))?;
            created.close();
            verify_regular_non_reparse(&path, StorageOperation::InspectEndpointKeyFile)?;
            verify_endpoint_key_acl(&path)?;
            let read_back = read_bounded_file(
                &path,
                crate::MAX_PROTECTED_ENDPOINT_KEY_BYTES,
                StorageOperation::InspectEndpointKeyFile,
            )?;
            if read_back != protected.as_bytes() {
                return Err(StorageError::new(
                    StorageErrorCode::PublicationVerificationFailed,
                    StorageOperation::InspectEndpointKeyFile,
                ));
            }
            Ok(())
        })
    }

    /// Read a bounded endpoint-key envelope only after exact ACL verification.
    pub fn read_endpoint_key_file(
        &self,
        relative_path: &Path,
    ) -> Result<ProtectedEndpointKey, StorageError> {
        let path = self.resolve_relative(relative_path)?;
        verify_regular_non_reparse(&path, StorageOperation::InspectEndpointKeyFile)?;
        verify_endpoint_key_acl(&path)?;
        let bytes = read_bounded_file(
            &path,
            crate::MAX_PROTECTED_ENDPOINT_KEY_BYTES,
            StorageOperation::InspectEndpointKeyFile,
        )?;
        ProtectedEndpointKey::from_bytes(bytes).map_err(|_| {
            StorageError::new(
                StorageErrorCode::InvalidProtectedKey,
                StorageOperation::InspectEndpointKeyFile,
            )
        })
    }

    pub fn publish_no_replace(
        &self,
        staged_relative_path: &Path,
        final_relative_path: &Path,
    ) -> Result<(), StorageError> {
        self.move_file(staged_relative_path, final_relative_path, false)
    }

    pub fn atomic_replace(
        &self,
        staged_relative_path: &Path,
        final_relative_path: &Path,
    ) -> Result<(), StorageError> {
        self.move_file(staged_relative_path, final_relative_path, true)
    }

    /// Acquire a persistent no-share file lock beneath this protected root.
    pub fn acquire_lifetime_lock(
        &self,
        relative_path: &Path,
    ) -> Result<crate::ExclusiveFileLock, crate::NativeError> {
        let path = self.resolve_relative(relative_path).map_err(|error| {
            error.os_code().map_or_else(
                || {
                    crate::NativeError::new(
                        crate::NativeErrorCode::AccessDenied,
                        crate::NativeOperation::AcquireLock,
                    )
                },
                |code| {
                    crate::NativeError::with_os_code(
                        crate::NativeErrorCode::AccessDenied,
                        crate::NativeOperation::AcquireLock,
                        code,
                    )
                },
            )
        })?;
        crate::ExclusiveFileLock::acquire(&path)
    }

    fn move_file(
        &self,
        staged_relative_path: &Path,
        final_relative_path: &Path,
        replace: bool,
    ) -> Result<(), StorageError> {
        let staged = self.resolve_relative(staged_relative_path)?;
        let final_path = self.resolve_relative(final_relative_path)?;
        verify_regular_non_reparse(&staged, StorageOperation::VerifyPublication)?;
        self.ensure_same_volume(&staged, &final_path)?;

        let staged_wide = wide(&staged);
        let final_wide = wide(&final_path);
        let flags = MOVEFILE_WRITE_THROUGH
            | if replace {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        // SAFETY: both buffers are NUL-terminated UTF-16 paths and outlive the
        // synchronous call.  No output pointers are supplied.
        let succeeded =
            unsafe { MoveFileExW(staged_wide.as_ptr(), final_wide.as_ptr(), flags) } != 0;
        if !succeeded {
            let os_code = last_error();
            if !replace && matches!(os_code, ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) {
                return Err(StorageError::with_os_code(
                    StorageErrorCode::AlreadyExists,
                    StorageOperation::PublishFile,
                    os_code,
                ));
            }
            return Err(StorageError::with_os_code(
                StorageErrorCode::Io,
                if replace {
                    StorageOperation::ReplaceFile
                } else {
                    StorageOperation::PublishFile
                },
                os_code,
            ));
        }
        verify_regular_non_reparse(&final_path, StorageOperation::VerifyPublication)
    }

    pub(crate) fn resolve_relative(&self, relative_path: &Path) -> Result<PathBuf, StorageError> {
        validate_relative_path(relative_path)?;
        let full_path = self.canonical_path.join(relative_path);
        // The root is canonical and relative paths contain only `Normal`
        // components, so this join cannot lexicaly leave the root.  Existing
        // components are checked again to reject junction/symlink traversal.
        validate_existing_components(&self.canonical_path, &full_path)?;
        Ok(full_path)
    }

    fn ensure_same_volume(&self, source: &Path, destination: &Path) -> Result<(), StorageError> {
        let source_root = volume_root(source, StorageOperation::InspectVolume)?;
        let destination_root = volume_root(destination, StorageOperation::InspectVolume)?;
        if !same_path(&source_root, &destination_root)
            || !same_path(&source_root, &self.volume_root)
        {
            return Err(StorageError::new(
                StorageErrorCode::DifferentVolume,
                StorageOperation::PublishFile,
            ));
        }
        Ok(())
    }
}

/// Installs the exact root-only descriptor before the daemon creates content.
///
/// `SetNamedSecurityInfoW` changes only the named root; it does not provide a
/// race-free, containment-proven way to rewrite arbitrary existing children.
/// Therefore setup deliberately rejects a nonempty root. The two inheritable
/// ACE flags protect descendants created after successful setup.
pub fn protect_data_root(path: &Path) -> Result<(), StorageError> {
    let root = validate_data_root_phase1(path)?;
    let sids = ExpectedSids::current()?;
    // Already-secure roots are restart-safe even after creating children: do
    // not rewrite descendants whose containment cannot be proven atomically.
    if verify_data_root_acl(
        &root.canonical_path,
        &sids,
        StorageOperation::ProtectDataRoot,
    )
    .is_ok()
    {
        return Ok(());
    }
    let mut entries = fs::read_dir(&root.canonical_path)
        .map_err(|error| io_error(StorageOperation::ProtectDataRoot, &error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| io_error(StorageOperation::ProtectDataRoot, &error))?
        .is_some()
    {
        return Err(StorageError::new(
            StorageErrorCode::InsecureAcl,
            StorageOperation::ProtectDataRoot,
        ));
    }
    let mut acl = OwnedAcl::new(&sids)?;
    acl.add_expected_aces(&sids)?;
    let path_wide = wide(&root.canonical_path);
    let security_information = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: path and ACL buffers are live, NUL-terminated where required,
    // and contain Win32-validated SID/ACL layouts for this synchronous call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            security_information,
            sids.user(),
            ptr::null_mut(),
            acl.as_ptr(),
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(StorageError::with_os_code(
            StorageErrorCode::InsecureAcl,
            StorageOperation::ProtectDataRoot,
            status,
        ));
    }
    verify_data_root_acl(
        &root.canonical_path,
        &sids,
        StorageOperation::ProtectDataRoot,
    )
}

pub fn validate_data_root(path: &Path) -> Result<ValidatedDataRoot, StorageError> {
    let root = validate_data_root_phase1(path)?;
    let sids = ExpectedSids::current()?;
    verify_data_root_acl(
        &root.canonical_path,
        &sids,
        StorageOperation::ValidateDataRoot,
    )?;
    Ok(root)
}

/// Install the exact current-user-only inheritable control-root descriptor.
///
/// An already exact root remains idempotent after children exist. An insecure
/// nonempty root is refused because descendant provenance cannot be repaired
/// safely by rewriting only the named root.
pub fn protect_control_root(path: &Path) -> Result<(), StorageError> {
    let root = validate_control_root_phase1(path)?;
    let expected_flags = CONTROL_ROOT_ACE_FLAGS;
    if verify_user_only_acl(
        root.inner.path(),
        expected_flags,
        StorageOperation::ProtectControlRoot,
    )
    .is_ok()
    {
        return Ok(());
    }
    let mut entries = fs::read_dir(root.inner.path())
        .map_err(|error| io_error(StorageOperation::ProtectControlRoot, &error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| io_error(StorageOperation::ProtectControlRoot, &error))?
        .is_some()
    {
        return Err(StorageError::new(
            StorageErrorCode::InsecureAcl,
            StorageOperation::ProtectControlRoot,
        ));
    }
    apply_user_only_directory_acl(root.inner.path(), StorageOperation::ProtectControlRoot)?;
    verify_user_only_acl(
        root.inner.path(),
        expected_flags,
        StorageOperation::ProtectControlRoot,
    )
}

pub fn validate_control_root(path: &Path) -> Result<ValidatedControlRoot, StorageError> {
    let root = validate_control_root_phase1(path)?;
    let expected_flags = CONTROL_ROOT_ACE_FLAGS;
    verify_user_only_acl(
        root.inner.path(),
        expected_flags,
        StorageOperation::ValidateControlRoot,
    )?;
    Ok(root)
}

/// Open the fixed per-user product control root beneath `LocalAppData`.
///
/// The literal child is not caller-selectable. This may create that one empty
/// child, then installs/verifies the exact control-root descriptor.
pub fn open_or_create_product_control_root() -> Result<ValidatedControlRoot, StorageError> {
    let local_app_data = crate::current_user_local_app_data().map_err(|error| {
        error.os_code().map_or_else(
            || StorageError::new(StorageErrorCode::Io, StorageOperation::ValidateControlRoot),
            |code| {
                StorageError::with_os_code(
                    StorageErrorCode::Io,
                    StorageOperation::ValidateControlRoot,
                    code,
                )
            },
        )
    })?;
    open_or_create_product_control_root_in(&local_app_data)
}

fn open_or_create_product_control_root_in(
    local_app_data: &Path,
) -> Result<ValidatedControlRoot, StorageError> {
    if !local_app_data.is_absolute() {
        return Err(StorageError::new(
            StorageErrorCode::InvalidPath,
            StorageOperation::ValidateControlRoot,
        ));
    }
    validate_supplied_ancestors(local_app_data)?;
    verify_directory_non_reparse(local_app_data, StorageOperation::ValidateControlRoot)?;
    let local_volume = volume_root(local_app_data, StorageOperation::InspectVolume)?;
    inspect_volume(&local_volume)?;
    let root = local_app_data.join(PRODUCT_CONTROL_ROOT_NAME);
    match existing_file_attributes(&root, StorageOperation::ValidateControlRoot)? {
        Some(attributes) => {
            verify_directory_attributes(attributes, StorageOperation::ValidateControlRoot)?;
        }
        None => match fs::create_dir(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_directory_non_reparse(&root, StorageOperation::ValidateControlRoot)?;
            }
            Err(error) => {
                return Err(io_error(StorageOperation::ValidateControlRoot, &error));
            }
        },
    }
    protect_control_root(&root)?;
    validate_control_root(&root)
}

fn validate_control_root_phase1(path: &Path) -> Result<ValidatedControlRoot, StorageError> {
    if !path.is_absolute() {
        return Err(StorageError::new(
            StorageErrorCode::InvalidPath,
            StorageOperation::ValidateControlRoot,
        ));
    }
    let inner = validate_data_root_phase1(path)?;
    Ok(ValidatedControlRoot { inner })
}

fn validate_data_root_phase1(path: &Path) -> Result<ValidatedDataRoot, StorageError> {
    let supplied_absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error(StorageOperation::ValidateDataRoot, &error))?
            .join(path)
    };
    // Canonicalization follows reparse points, so inspect the supplied lexical
    // path first. This deliberately rejects a root reached through any
    // junction or symbolic link instead of silently accepting its target.
    validate_supplied_ancestors(&supplied_absolute)?;
    let canonical_path = fs::canonicalize(path)
        .map_err(|error| io_error(StorageOperation::ValidateDataRoot, &error))?;
    let attributes = file_attributes(&canonical_path, StorageOperation::ValidateDataRoot)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StorageError::new(
            StorageErrorCode::ReparsePoint,
            StorageOperation::ValidateDataRoot,
        ));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(StorageError::new(
            StorageErrorCode::NotDirectory,
            StorageOperation::ValidateDataRoot,
        ));
    }
    validate_existing_components(&canonical_path, &canonical_path)?;
    let volume_root = volume_root(&canonical_path, StorageOperation::InspectVolume)?;
    inspect_volume(&volume_root)?;
    Ok(ValidatedDataRoot {
        canonical_path,
        volume_root,
    })
}

struct ExpectedSids {
    user: Vec<u8>,
    local_system: Vec<u8>,
    administrators: Vec<u8>,
}

impl ExpectedSids {
    fn current() -> Result<Self, StorageError> {
        Ok(Self {
            user: current_user_sid()?,
            local_system: well_known_sid(WinLocalSystemSid)?,
            administrators: well_known_sid(WinBuiltinAdministratorsSid)?,
        })
    }

    fn user(&self) -> PSID {
        self.user.as_ptr().cast_mut().cast()
    }

    fn all(&self) -> [PSID; 3] {
        [
            self.user(),
            self.local_system.as_ptr().cast_mut().cast(),
            self.administrators.as_ptr().cast_mut().cast(),
        ]
    }
}

struct OwnedToken(HANDLE);

impl Drop for OwnedToken {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only from a successful
        // OpenProcessToken call and owns exactly one closeable handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetNamedSecurityInfoW allocates this descriptor with
        // LocalAlloc. LocalFree is its documented matching release function.
        unsafe { LocalFree(self.0) };
    }
}

struct OwnedAcl {
    bytes: Vec<usize>,
}

impl OwnedAcl {
    fn new(sids: &ExpectedSids) -> Result<Self, StorageError> {
        Self::for_sids(&sids.all())
    }

    fn for_sids(sids: &[PSID]) -> Result<Self, StorageError> {
        Self::for_sids_operation(sids, StorageOperation::ProtectDataRoot)
    }

    fn for_sids_operation(
        sids: &[PSID],
        operation: StorageOperation,
    ) -> Result<Self, StorageError> {
        let ace_bytes = sids
            .iter()
            .copied()
            .try_fold(mem::size_of::<ACL>(), |total, sid| {
                let sid_length = sid_length(sid)?;
                let ace_length = mem::size_of::<ACCESS_ALLOWED_ACE>()
                    .checked_sub(mem::size_of::<u32>())
                    .and_then(|prefix| prefix.checked_add(sid_length))
                    .ok_or_else(|| StorageError::new(StorageErrorCode::InsecureAcl, operation))?;
                total
                    .checked_add(align_dword(ace_length))
                    .ok_or_else(|| StorageError::new(StorageErrorCode::InsecureAcl, operation))
            })?;
        let words = ace_bytes
            .checked_add(mem::size_of::<usize>() - 1)
            .and_then(|value| value.checked_div(mem::size_of::<usize>()))
            .ok_or_else(|| StorageError::new(StorageErrorCode::InsecureAcl, operation))?;
        let mut bytes = vec![0_usize; words];
        let length = u32::try_from(ace_bytes)
            .map_err(|_| StorageError::new(StorageErrorCode::InsecureAcl, operation))?;
        // SAFETY: allocation is suitably aligned and at least `length` bytes;
        // InitializeAcl writes only within the supplied ACL buffer.
        if unsafe {
            windows_sys::Win32::Security::InitializeAcl(
                bytes.as_mut_ptr().cast(),
                length,
                ACL_REVISION,
            )
        } == 0
        {
            return Err(last_error_acl(operation));
        }
        Ok(Self { bytes })
    }

    fn as_ptr(&self) -> *const ACL {
        self.bytes.as_ptr().cast()
    }

    fn add_expected_aces(&mut self, sids: &ExpectedSids) -> Result<(), StorageError> {
        self.add_aces(&sids.all(), OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
    }

    fn add_aces(&mut self, sids: &[PSID], ace_flags: u32) -> Result<(), StorageError> {
        self.add_aces_with_mask_operation(
            sids,
            ace_flags,
            FILE_ALL_ACCESS,
            StorageOperation::ProtectDataRoot,
        )
    }

    #[cfg(test)]
    fn add_aces_with_mask(
        &mut self,
        sids: &[PSID],
        ace_flags: u32,
        access_mask: u32,
    ) -> Result<(), StorageError> {
        self.add_aces_with_mask_operation(
            sids,
            ace_flags,
            access_mask,
            StorageOperation::ProtectDataRoot,
        )
    }

    fn add_aces_with_mask_operation(
        &mut self,
        sids: &[PSID],
        ace_flags: u32,
        access_mask: u32,
        operation: StorageOperation,
    ) -> Result<(), StorageError> {
        for sid in sids.iter().copied() {
            // SAFETY: `self` is a successfully initialized ACL with reserved
            // capacity for exactly these valid SIDs. AddAccessAllowedAceEx
            // copies the SID during this synchronous call.
            if unsafe {
                AddAccessAllowedAceEx(
                    self.bytes.as_mut_ptr().cast(),
                    ACL_REVISION,
                    ace_flags,
                    access_mask,
                    sid,
                )
            } == 0
            {
                return Err(last_error_acl(operation));
            }
        }
        Ok(())
    }
}

fn apply_endpoint_key_acl(path: &Path) -> Result<(), StorageError> {
    apply_user_only_file_acl(path, StorageOperation::CreateEndpointKeyFile)
}

fn apply_user_only_file_acl(path: &Path, operation: StorageOperation) -> Result<(), StorageError> {
    apply_user_only_acl(path, 0, operation)
}

fn apply_user_only_directory_acl(
    path: &Path,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    apply_user_only_acl(path, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, operation)
}

fn apply_user_only_acl(
    path: &Path,
    ace_flags: u32,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let user = current_user_sid()?;
    let user_sid = user.as_ptr().cast_mut().cast();
    let mut acl = OwnedAcl::for_sids_operation(&[user_sid], operation)?;
    acl.add_aces_with_mask_operation(&[user_sid], ace_flags, FILE_ALL_ACCESS, operation)?;
    let path_wide = wide(path);
    // SAFETY: path, SID storage, and ACL remain live for this synchronous
    // call. The protected DACL contains exactly the one user ACE constructed
    // above, and owner is set to the same token-derived user SID.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            user_sid,
            ptr::null_mut(),
            acl.as_ptr(),
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(StorageError::with_os_code(
            StorageErrorCode::InsecureAcl,
            operation,
            status,
        ));
    }
    Ok(())
}

fn verify_endpoint_key_acl(path: &Path) -> Result<(), StorageError> {
    verify_user_only_file_acl(path, StorageOperation::InspectEndpointKeyFile)
}

fn verify_user_only_file_acl(path: &Path, operation: StorageOperation) -> Result<(), StorageError> {
    verify_user_only_acl(path, 0, operation)
}

fn verify_control_directory_acl(
    path: &Path,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    verify_user_only_acl(path, CONTROL_ROOT_ACE_FLAGS, operation)
}

fn verify_user_only_acl(
    path: &Path,
    expected_ace_flags: u8,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let user = current_user_sid()?;
    let expected_user: PSID = user.as_ptr().cast_mut().cast();
    let path_wide = wide(path);
    let mut descriptor = ptr::null_mut();
    // SAFETY: path is NUL-terminated and descriptor is a valid out-pointer;
    // the returned descriptor is owned by the RAII wrapper below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(StorageError::with_os_code(
            StorageErrorCode::InsecureAcl,
            operation,
            status,
        ));
    }
    let descriptor = OwnedSecurityDescriptor(descriptor);
    verify_user_only_descriptor(descriptor.0, expected_user, expected_ace_flags, operation)
}

fn verify_user_only_handle_acl(
    handle: HANDLE,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    verify_user_only_handle_acl_flags(handle, 0, operation)
}

fn verify_user_only_handle_acl_flags(
    handle: HANDLE,
    expected_ace_flags: u8,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let user = current_user_sid()?;
    let expected_user: PSID = user.as_ptr().cast_mut().cast();
    let descriptor = security_descriptor_from_handle(handle, operation)?;
    verify_user_only_descriptor(descriptor.0, expected_user, expected_ace_flags, operation)
}

fn verify_data_handle_acl(
    handle: HANDLE,
    expected: &ExpectedSids,
    expected_protected: bool,
    is_directory: bool,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let inherited = if expected_protected {
        0
    } else {
        u8::try_from(INHERITED_ACE).expect("ACE inheritance flag fits u8")
    };
    let inheritance = if is_directory {
        u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            .expect("ACE inheritance flags fit u8")
    } else {
        0
    };
    let descriptor = security_descriptor_from_handle(handle, operation)?;
    verify_data_descriptor(
        descriptor.0,
        expected,
        expected_protected,
        inherited | inheritance,
        operation,
    )
}

fn security_descriptor_from_handle(
    handle: HANDLE,
    operation: StorageOperation,
) -> Result<OwnedSecurityDescriptor, StorageError> {
    let mut descriptor = ptr::null_mut();
    // SAFETY: handle is live and descriptor is a writable out-pointer. The
    // returned LocalAlloc descriptor is immediately RAII-owned.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(StorageError::with_os_code(
            StorageErrorCode::InsecureAcl,
            operation,
            status,
        ));
    }
    Ok(OwnedSecurityDescriptor(descriptor))
}

fn verify_user_only_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    expected_user: PSID,
    expected_ace_flags: u8,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let mut owner = ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: descriptor is valid and both outputs are writable.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
        || owner.is_null()
        || !same_sid(owner, expected_user)
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor and output pointers are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor and outputs are valid. Null/unset DACLs are rejected.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    } == 0
        || present == 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: DACL was validated and information is correctly sized/writable.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(mem::size_of::<ACL_SIZE_INFORMATION>()).expect("ACL size fits u32"),
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 1
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut ace = ptr::null_mut();
    // SAFETY: the exact one ACE exists and the output pointer is writable.
    if unsafe { GetAce(dacl, 0, &raw mut ace) } == 0 || ace.is_null() {
        return Err(last_error_acl(operation));
    }
    // SAFETY: GetAce returns an ACL-owned ACE with a leading header.
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let allowed_type = u8::try_from(ACCESS_ALLOWED_ACE_TYPE).expect("ACE type fits u8");
    if header.AceType != allowed_type
        || header.AceFlags != expected_ace_flags
        || usize::from(header.AceSize) < mem::size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    // SAFETY: the type and minimum fixed size were checked above.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if allowed.Mask != FILE_ALL_ACCESS {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let sid = (&raw const allowed.SidStart).cast_mut().cast();
    // SAFETY: validate the self-described SID before reading its length.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    if !access_allowed_ace_size_is_exact(header.AceSize, sid) || !same_sid(sid, expected_user) {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    Ok(())
}

pub(crate) fn current_user_sid() -> Result<Vec<u8>, StorageError> {
    let mut handle = ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle and `handle` is a valid
    // out-pointer for OpenProcessToken.
    if unsafe {
        windows_sys::Win32::System::Threading::OpenProcessToken(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            TOKEN_QUERY,
            &raw mut handle,
        )
    } == 0
    {
        return Err(last_error_acl(StorageOperation::InspectSecurity));
    }
    let token = OwnedToken(handle);
    let mut needed = 0_u32;
    // SAFETY: null buffer with zero length is the documented size-query form.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut needed) };
    if needed == 0 {
        return Err(last_error_acl(StorageOperation::InspectSecurity));
    }
    let words = usize::try_from(needed)
        .ok()
        .and_then(|bytes| bytes.checked_add(mem::size_of::<usize>() - 1))
        .and_then(|bytes| bytes.checked_div(mem::size_of::<usize>()))
        .ok_or_else(|| {
            StorageError::new(
                StorageErrorCode::InsecureAcl,
                StorageOperation::InspectSecurity,
            )
        })?;
    let mut storage = vec![0_usize; words];
    // SAFETY: storage is aligned and contains at least `needed` writable
    // bytes; Windows initializes a TOKEN_USER structure in that buffer.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(last_error_acl(StorageOperation::InspectSecurity));
    }
    // SAFETY: a successful GetTokenInformation(TokenUser) initialized the
    // leading TOKEN_USER and its Sid points into the supplied valid buffer.
    let sid = unsafe { (&*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    clone_sid(sid, StorageOperation::InspectSecurity)
}

pub(crate) fn well_known_sid(kind: i32) -> Result<Vec<u8>, StorageError> {
    let mut bytes = vec![0_u8; 68];
    let mut length = u32::try_from(bytes.len()).expect("SECURITY_MAX_SID_SIZE fits u32");
    // SAFETY: the buffer has SECURITY_MAX_SID_SIZE bytes, sufficient for a
    // well-known SID, and `length` supplies its capacity.
    if unsafe {
        CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &raw mut length,
        )
    } == 0
    {
        return Err(last_error_acl(StorageOperation::InspectSecurity));
    }
    bytes.truncate(usize::try_from(length).map_err(|_| {
        StorageError::new(
            StorageErrorCode::InsecureAcl,
            StorageOperation::InspectSecurity,
        )
    })?);
    Ok(bytes)
}

fn clone_sid(sid: PSID, _operation: StorageOperation) -> Result<Vec<u8>, StorageError> {
    let length = sid_length(sid)?;
    // SAFETY: sid comes from Windows and GetLengthSid returned its exact
    // readable byte length. The copy owns the identity after token release.
    Ok(unsafe { slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

pub(crate) fn sid_length(sid: PSID) -> Result<usize, StorageError> {
    // SAFETY: all callers supply SIDs created by Windows/token APIs.
    let length = unsafe { GetLengthSid(sid) };
    usize::try_from(length)
        .ok()
        .filter(|length| *length != 0)
        .ok_or_else(|| {
            StorageError::new(
                StorageErrorCode::InsecureAcl,
                StorageOperation::InspectSecurity,
            )
        })
}

/// Return true only when an access-allowed ACE ends exactly after its SID.
/// Callers must first validate the ACE type/minimum fixed layout and the SID.
pub(crate) fn access_allowed_ace_size_is_exact(ace_size: u16, sid: PSID) -> bool {
    let prefix = mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<u32>();
    sid_length(sid)
        .ok()
        .and_then(|length| prefix.checked_add(length))
        == Some(usize::from(ace_size))
}

fn align_dword(value: usize) -> usize {
    (value + 3) & !3
}

fn verify_data_root_acl(
    path: &Path,
    expected: &ExpectedSids,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let descriptor = data_security_descriptor(path, operation)?;
    let expected_flags = u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
        .expect("ACE inheritance flags fit u8");
    verify_data_descriptor(descriptor.0, expected, true, expected_flags, operation)
}

fn verify_data_descendant_acl(
    path: &Path,
    expected: &ExpectedSids,
    is_directory: bool,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let descriptor = data_security_descriptor(path, operation)?;
    let inherited = u8::try_from(INHERITED_ACE).expect("ACE inheritance flag fits u8");
    let inheritance = if is_directory {
        u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            .expect("ACE inheritance flags fit u8")
    } else {
        0
    };
    verify_data_descriptor(
        descriptor.0,
        expected,
        false,
        inherited | inheritance,
        operation,
    )
}

fn data_security_descriptor(
    path: &Path,
    operation: StorageOperation,
) -> Result<OwnedSecurityDescriptor, StorageError> {
    let path_wide = wide(path);
    let mut descriptor = ptr::null_mut();
    // SAFETY: path is NUL-terminated and descriptor is a valid out-pointer.
    // All auxiliary output pointers are null because the returned descriptor
    // is independently queried below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(StorageError::with_os_code(
            StorageErrorCode::InsecureAcl,
            operation,
            status,
        ));
    }
    Ok(OwnedSecurityDescriptor(descriptor))
}

fn verify_data_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    expected: &ExpectedSids,
    expected_protected: bool,
    expected_ace_flags: u8,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let mut owner = ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: descriptor is LocalAlloc-backed by GetNamedSecurityInfoW and
    // owner/defaulted are writable out-pointers.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
        || owner.is_null()
        || !same_sid(owner, expected.user())
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor and both output pointers are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
        || (control & SE_DACL_PROTECTED != 0) != expected_protected
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor and all outputs are valid. A present but null DACL is
    // explicitly rejected below because it grants unrestricted access.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    // SAFETY: DACL is descriptor-owned and was returned by the descriptor API.
    // Validate before using its count or asking for individual ACE pointers.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is a descriptor-owned valid ACL and information is a
    // correctly sized writable buffer.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(mem::size_of::<ACL_SIZE_INFORMATION>()).expect("ACL size fits u32"),
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 3
    {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    let mut seen = [false; 3];
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: `index` is bounded by GetAclInformation's AceCount and ace
        // is a valid out-pointer. The returned ACE remains descriptor-owned.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
            return Err(last_error_acl(operation));
        }
        // SAFETY: GetAce returns an ACL-owned ACE beginning with ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let allowed_type = u8::try_from(ACCESS_ALLOWED_ACE_TYPE).expect("ACE type fits u8");
        if header.AceType != allowed_type
            || header.AceFlags != expected_ace_flags
            || usize::from(header.AceSize) < mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
        }
        // SAFETY: accepted ACCESS_ALLOWED ACE has the fixed leading layout;
        // ACE sizing was checked before accessing its SID start field.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask != FILE_ALL_ACCESS {
            return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
        }
        let sid = (&raw const allowed.SidStart).cast_mut().cast();
        // SAFETY: sid starts at the checked fixed ACCESS_ALLOWED_ACE prefix;
        // IsValidSid validates its internal layout before GetLengthSid reads it.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
        }
        if !access_allowed_ace_size_is_exact(header.AceSize, sid) {
            return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
        }
        let matching = expected
            .all()
            .iter()
            .position(|candidate| same_sid(sid, *candidate));
        let Some(slot) = matching else {
            return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
        };
        if seen[slot] {
            return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
        }
        seen[slot] = true;
    }
    if !seen.into_iter().all(std::convert::identity) {
        return Err(StorageError::new(StorageErrorCode::InsecureAcl, operation));
    }
    Ok(())
}

pub(crate) fn same_sid(left: PSID, right: PSID) -> bool {
    // SAFETY: both pointers are non-owning values returned by Windows or
    // cloned from such values. Validate their self-described layouts before
    // asking EqualSid to inspect them.
    unsafe { IsValidSid(left) != 0 && IsValidSid(right) != 0 && EqualSid(left, right) != 0 }
}

fn last_error_acl(operation: StorageOperation) -> StorageError {
    StorageError::with_os_code(StorageErrorCode::InsecureAcl, operation, last_error())
}

fn validate_supplied_ancestors(path: &Path) -> Result<(), StorageError> {
    let mut current = PathBuf::new();
    let mut reached_root = false;
    for component in path.components() {
        if matches!(component, Component::RootDir) {
            reached_root = true;
        }
        current.push(component.as_os_str());
        // A Windows prefix by itself (`C:` or `\\?\C:`) is not an absolute
        // ancestor and may be interpreted relative to a drive cwd or rejected.
        // Begin querying only once the following root component is present.
        if !reached_root {
            continue;
        }
        let attributes = existing_file_attributes(&current, StorageOperation::ValidateDataRoot)?;
        if attributes.is_some_and(|value| value & FILE_ATTRIBUTE_REPARSE_POINT != 0) {
            return Err(StorageError::new(
                StorageErrorCode::ReparsePoint,
                StorageOperation::ValidateDataRoot,
            ));
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), StorageError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(StorageError::new(
            StorageErrorCode::PathEscapesRoot,
            StorageOperation::ValidatePath,
        ));
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(StorageError::new(
                StorageErrorCode::PathEscapesRoot,
                StorageOperation::ValidatePath,
            ));
        };
        let units = name.encode_wide().collect::<Vec<_>>();
        // Reject Win32's forbidden filename characters up front rather than
        // allowing CreateFile to fail later. `:` would address an alternate
        // data stream, and control characters are not normalized durable names.
        if units.is_empty()
            || units.len() > MAX_NTFS_COMPONENT_UTF16_UNITS
            || units.iter().copied().any(is_forbidden_win32_name_unit)
            || units
                .last()
                .is_some_and(|unit| *unit == u16::from(b'.') || *unit == u16::from(b' '))
            || is_reserved_dos_device_component(&units)
        {
            return Err(StorageError::new(
                StorageErrorCode::InvalidPath,
                StorageOperation::ValidatePath,
            ));
        }
    }
    Ok(())
}

const fn is_forbidden_win32_name_unit(unit: u16) -> bool {
    unit <= 0x001f
        || matches!(
            unit,
            0x0022 | 0x002a | 0x003a | 0x003c | 0x003e | 0x003f | 0x007c
        )
}

fn is_reserved_dos_device_component(units: &[u16]) -> bool {
    // Win32 recognizes these device aliases case-insensitively even when an
    // extension follows (for example `NUL.txt`). Trim spaces from the stem as
    // a conservative defense against namespace normalization ambiguity.
    let mut stem_end = units
        .iter()
        .position(|unit| *unit == u16::from(b'.'))
        .unwrap_or(units.len());
    while stem_end != 0 && units[stem_end - 1] == u16::from(b' ') {
        stem_end -= 1;
    }
    let stem = &units[..stem_end];
    let equals_ascii = |name: &[u8]| {
        stem.len() == name.len()
            && stem
                .iter()
                .copied()
                .map(ascii_uppercase_u16)
                .eq(name.iter().copied().map(u16::from))
    };
    if [
        b"CON".as_slice(),
        b"PRN".as_slice(),
        b"AUX".as_slice(),
        b"NUL".as_slice(),
        b"CLOCK$".as_slice(),
        b"CONIN$".as_slice(),
        b"CONOUT$".as_slice(),
    ]
    .into_iter()
    .any(equals_ascii)
    {
        return true;
    }
    if stem.len() != 4 {
        return false;
    }
    let prefix = &stem[..3];
    let prefix_equals = |name: &[u8; 3]| {
        prefix
            .iter()
            .copied()
            .map(ascii_uppercase_u16)
            .eq(name.iter().copied().map(u16::from))
    };
    if !prefix_equals(b"COM") && !prefix_equals(b"LPT") {
        return false;
    }
    matches!(stem[3], 0x0031..=0x0039 | 0x00b9 | 0x00b2 | 0x00b3)
}

fn validate_existing_components(root: &Path, target: &Path) -> Result<(), StorageError> {
    let relative = target.strip_prefix(root).map_err(|_| {
        StorageError::new(
            StorageErrorCode::PathEscapesRoot,
            StorageOperation::ValidatePath,
        )
    })?;
    let mut current = root.to_path_buf();
    reject_reparse(&current, StorageOperation::ValidatePath)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(StorageError::new(
                StorageErrorCode::PathEscapesRoot,
                StorageOperation::ValidatePath,
            ));
        };
        current.push(name);
        let attributes = existing_file_attributes(&current, StorageOperation::ValidatePath)?;
        if attributes.is_some_and(|value| value & FILE_ATTRIBUTE_REPARSE_POINT != 0) {
            return Err(StorageError::new(
                StorageErrorCode::ReparsePoint,
                StorageOperation::ValidatePath,
            ));
        }
    }
    Ok(())
}

fn reject_reparse(path: &Path, operation: StorageOperation) -> Result<(), StorageError> {
    if file_attributes(path, operation)? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StorageError::new(StorageErrorCode::ReparsePoint, operation));
    }
    Ok(())
}

fn verify_regular_non_reparse(
    path: &Path,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    let attributes = file_attributes(path, operation)?;
    verify_regular_attributes(attributes, operation)
}

fn verify_regular_attributes(
    attributes: u32,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StorageError::new(StorageErrorCode::ReparsePoint, operation));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(StorageError::new(
            StorageErrorCode::NotRegularFile,
            operation,
        ));
    }
    Ok(())
}

fn verify_directory_non_reparse(
    path: &Path,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    verify_directory_attributes(file_attributes(path, operation)?, operation)
}

fn verify_directory_attributes(
    attributes: u32,
    operation: StorageOperation,
) -> Result<(), StorageError> {
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StorageError::new(StorageErrorCode::ReparsePoint, operation));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(StorageError::new(StorageErrorCode::NotDirectory, operation));
    }
    Ok(())
}

fn allocated_tree_bytes(directory: &Path, expected: &ExpectedSids) -> Result<u64, StorageError> {
    let mut total = 0_u64;
    let mut pending = vec![(directory.to_path_buf(), true)];
    while let Some((directory, is_root)) = pending.pop() {
        verify_directory_non_reparse(&directory, StorageOperation::MeasureAllocation)?;
        if !is_root {
            verify_data_descendant_acl(
                &directory,
                expected,
                true,
                StorageOperation::MeasureAllocation,
            )?;
        }
        for entry in fs::read_dir(directory)
            .map_err(|error| io_error(StorageOperation::MeasureAllocation, &error))?
        {
            let entry =
                entry.map_err(|error| io_error(StorageOperation::MeasureAllocation, &error))?;
            let path = entry.path();
            let attributes = file_attributes(&path, StorageOperation::MeasureAllocation)?;
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(StorageError::new(
                    StorageErrorCode::ReparsePoint,
                    StorageOperation::MeasureAllocation,
                ));
            }
            if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                pending.push((path, false));
            } else {
                verify_data_descendant_acl(
                    &path,
                    expected,
                    false,
                    StorageOperation::MeasureAllocation,
                )?;
                let value = allocated_file_bytes(&path, StorageOperation::MeasureAllocation)?;
                total = total.checked_add(value).ok_or_else(|| {
                    StorageError::new(
                        StorageErrorCode::SizeOverflow,
                        StorageOperation::MeasureAllocation,
                    )
                })?;
            }
        }
    }
    Ok(total)
}

fn copy_reader_verified<R: Read>(
    source: &mut R,
    destination: &Path,
    expected_sha256: [u8; 32],
) -> Result<u64, StorageError> {
    with_created_file(destination, StorageOperation::CopyFile, |created| {
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let length = source
                .read(&mut buffer)
                .map_err(|error| io_error(StorageOperation::CopyFile, &error))?;
            if length == 0 {
                break;
            }
            created
                .file_mut()
                .write_all(&buffer[..length])
                .map_err(|error| io_error(StorageOperation::CopyFile, &error))?;
            digest.update(&buffer[..length]);
            total = total
                .checked_add(u64::try_from(length).map_err(|_| {
                    StorageError::new(StorageErrorCode::SizeOverflow, StorageOperation::CopyFile)
                })?)
                .ok_or_else(|| {
                    StorageError::new(StorageErrorCode::SizeOverflow, StorageOperation::CopyFile)
                })?;
        }
        created
            .file_mut()
            .sync_all()
            .map_err(|error| io_error(StorageOperation::FlushFile, &error))?;
        verify_regular_non_reparse(destination, StorageOperation::CopyFile)?;
        if digest.finalize().as_slice() != expected_sha256 {
            return Err(StorageError::new(
                StorageErrorCode::DigestMismatch,
                StorageOperation::CopyFile,
            ));
        }
        created.close();

        // Reopen and hash the published bytes independently; the streaming
        // hash alone proves the source stream, not final path content.
        let mut reopened = File::open(destination)
            .map_err(|error| io_error(StorageOperation::CopyFile, &error))?;
        verify_regular_non_reparse(destination, StorageOperation::CopyFile)?;
        let mut final_digest = Sha256::new();
        loop {
            let length = reopened
                .read(&mut buffer)
                .map_err(|error| io_error(StorageOperation::CopyFile, &error))?;
            if length == 0 {
                break;
            }
            final_digest.update(&buffer[..length]);
        }
        if final_digest.finalize().as_slice() != expected_sha256 {
            return Err(StorageError::new(
                StorageErrorCode::PublicationVerificationFailed,
                StorageOperation::CopyFile,
            ));
        }
        Ok(total)
    })
}

fn verify_control_file_digest(
    path: &Path,
    expected_sha256: [u8; 32],
    maximum_bytes: u64,
    operation: StorageOperation,
) -> Result<u64, StorageError> {
    let mut file = File::open(path).map_err(|error| io_error(operation, &error))?;
    let metadata_length = file
        .metadata()
        .map_err(|error| io_error(operation, &error))?
        .len();
    if metadata_length > maximum_bytes {
        return Err(StorageError::new(StorageErrorCode::TooLarge, operation));
    }

    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|error| io_error(operation, &error))?;
        if length == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(length)
                    .map_err(|_| StorageError::new(StorageErrorCode::SizeOverflow, operation))?,
            )
            .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
        if total > maximum_bytes {
            return Err(StorageError::new(StorageErrorCode::TooLarge, operation));
        }
        digest.update(&buffer[..length]);
    }
    if total != metadata_length || digest.finalize().as_slice() != expected_sha256 {
        return Err(StorageError::new(
            StorageErrorCode::DigestMismatch,
            operation,
        ));
    }
    Ok(total)
}

fn read_bounded_file(
    path: &Path,
    maximum: usize,
    operation: StorageOperation,
) -> Result<Vec<u8>, StorageError> {
    let mut file = File::open(path).map_err(|error| io_error(operation, &error))?;
    let metadata_length = file
        .metadata()
        .map_err(|error| io_error(operation, &error))?
        .len();
    if metadata_length == 0 || metadata_length > maximum as u64 {
        return Err(StorageError::new(
            StorageErrorCode::InvalidProtectedKey,
            operation,
        ));
    }
    let expected = usize::try_from(metadata_length)
        .map_err(|_| StorageError::new(StorageErrorCode::InvalidProtectedKey, operation))?;
    let capacity = maximum
        .checked_add(1)
        .ok_or_else(|| StorageError::new(StorageErrorCode::SizeOverflow, operation))?;
    let mut bytes = Vec::with_capacity(expected);
    Read::by_ref(&mut file)
        .take(
            u64::try_from(capacity)
                .map_err(|_| StorageError::new(StorageErrorCode::SizeOverflow, operation))?,
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(operation, &error))?;
    if bytes.len() != expected || bytes.len() > maximum {
        return Err(StorageError::new(
            StorageErrorCode::PublicationVerificationFailed,
            operation,
        ));
    }
    Ok(bytes)
}

fn read_control_file_path(path: &Path) -> Result<Vec<u8>, StorageError> {
    // Open only after the caller has checked type/reparse/ACL, then inspect
    // metadata before allocating any caller-influenced body capacity.
    let mut file =
        File::open(path).map_err(|error| io_error(StorageOperation::ReadControlFile, &error))?;
    let length = file
        .metadata()
        .map_err(|error| io_error(StorageOperation::ReadControlFile, &error))?
        .len();
    if length > MAX_CONTROL_FILE_BYTES as u64 {
        return Err(StorageError::new(
            StorageErrorCode::TooLarge,
            StorageOperation::ReadControlFile,
        ));
    }
    let expected = usize::try_from(length).map_err(|_| {
        StorageError::new(
            StorageErrorCode::TooLarge,
            StorageOperation::ReadControlFile,
        )
    })?;
    let mut bytes = Vec::with_capacity(expected);
    Read::by_ref(&mut file)
        .take((MAX_CONTROL_FILE_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(StorageOperation::ReadControlFile, &error))?;
    if bytes.len() != expected || bytes.len() > MAX_CONTROL_FILE_BYTES {
        return Err(StorageError::new(
            StorageErrorCode::PublicationVerificationFailed,
            StorageOperation::ReadControlFile,
        ));
    }
    verify_regular_non_reparse(path, StorageOperation::ReadControlFile)?;
    verify_user_only_file_acl(path, StorageOperation::ReadControlFile)?;
    Ok(bytes)
}

fn storage_to_lock_error(error: StorageError) -> crate::NativeError {
    error.os_code().map_or_else(
        || {
            crate::NativeError::new(
                crate::NativeErrorCode::AccessDenied,
                crate::NativeOperation::AcquireLock,
            )
        },
        |code| {
            crate::NativeError::with_os_code(
                crate::NativeErrorCode::AccessDenied,
                crate::NativeOperation::AcquireLock,
                code,
            )
        },
    )
}

fn native_lock_to_storage(error: crate::NativeError, operation: StorageOperation) -> StorageError {
    let code = match error.code() {
        crate::NativeErrorCode::SingletonConflict => StorageErrorCode::SharingViolation,
        crate::NativeErrorCode::AccessDenied => StorageErrorCode::AccessDenied,
        crate::NativeErrorCode::OsFailure
            if error.os_code().is_some_and(|code| {
                matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
            }) =>
        {
            StorageErrorCode::NotFound
        }
        _ => StorageErrorCode::Io,
    };
    error.os_code().map_or_else(
        || StorageError::new(code, operation),
        |os_code| StorageError::with_os_code(code, operation, os_code),
    )
}

fn inspect_volume(root: &Path) -> Result<(), StorageError> {
    let root_wide = wide(root);
    // SAFETY: `root_wide` is NUL-terminated and remains valid for the call.
    if unsafe { GetDriveTypeW(root_wide.as_ptr()) } != DRIVE_FIXED {
        return Err(StorageError::new(
            StorageErrorCode::NotFixedVolume,
            StorageOperation::InspectVolume,
        ));
    }
    let mut filesystem_name = [0_u16; 32];
    let mut flags = 0_u32;
    // SAFETY: all buffers are valid mutable arrays of the declared lengths;
    // unused optional outputs are null pointers.
    let succeeded = unsafe {
        GetVolumeInformationW(
            root_wide.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut flags,
            filesystem_name.as_mut_ptr(),
            32,
        )
    } != 0;
    if !succeeded {
        return Err(StorageError::with_os_code(
            StorageErrorCode::Io,
            StorageOperation::InspectVolume,
            last_error(),
        ));
    }
    let end = filesystem_name
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(filesystem_name.len());
    let is_ntfs = filesystem_name[..end]
        .iter()
        .copied()
        .map(ascii_uppercase_u16)
        .eq(['N' as u16, 'T' as u16, 'F' as u16, 'S' as u16]);
    if !is_ntfs {
        return Err(StorageError::new(
            StorageErrorCode::NotNtfsVolume,
            StorageOperation::InspectVolume,
        ));
    }
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(StorageError::new(
            StorageErrorCode::NotNtfsVolume,
            StorageOperation::InspectVolume,
        ));
    }
    Ok(())
}

fn volume_root(path: &Path, operation: StorageOperation) -> Result<PathBuf, StorageError> {
    let path_wide = wide(path);
    let mut output = vec![0_u16; PATH_CAPACITY];
    // SAFETY: the input is NUL-terminated and the output buffer has the
    // supplied capacity. GetVolumePathNameW writes only UTF-16 code units.
    if unsafe { GetVolumePathNameW(path_wide.as_ptr(), output.as_mut_ptr(), PATH_CAPACITY_U32) }
        == 0
    {
        return Err(StorageError::with_os_code(
            StorageErrorCode::Io,
            operation,
            last_error(),
        ));
    }
    let end = output
        .iter()
        .position(|character| *character == 0)
        .ok_or_else(|| StorageError::new(StorageErrorCode::Io, operation))?;
    let value = OsString::from_wide(&output[..end]);
    Ok(PathBuf::from(value))
}

fn file_attributes(path: &Path, operation: StorageOperation) -> Result<u32, StorageError> {
    existing_file_attributes(path, operation)?
        .ok_or_else(|| StorageError::new(StorageErrorCode::NotFound, operation))
}

fn allocated_file_bytes(path: &Path, operation: StorageOperation) -> Result<u64, StorageError> {
    let path_wide = wide(path);
    let mut high = 0_u32;
    // SAFETY: clearing the thread-local last error disambiguates a valid low
    // word of `INVALID_FILE_SIZE`; the NUL-terminated path and output live for
    // the synchronous query.
    let low = unsafe {
        SetLastError(0);
        GetCompressedFileSizeW(path_wide.as_ptr(), &raw mut high)
    };
    if low == INVALID_FILE_SIZE {
        let code = last_error();
        if code != 0 {
            return Err(StorageError::with_os_code(
                StorageErrorCode::Io,
                operation,
                code,
            ));
        }
    }
    Ok((u64::from(high) << 32) | u64::from(low))
}

fn existing_file_attributes(
    path: &Path,
    operation: StorageOperation,
) -> Result<Option<u32>, StorageError> {
    let path_wide = wide(path);
    // SAFETY: `path_wide` is NUL-terminated and remains valid for the call.
    let attributes = unsafe { GetFileAttributesW(path_wide.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        let os_code = last_error();
        if matches!(os_code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            return Ok(None);
        }
        return Err(StorageError::with_os_code(
            StorageErrorCode::Io,
            operation,
            os_code,
        ));
    }
    Ok(Some(attributes))
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
    let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
    let (Ok(left_length), Ok(right_length)) =
        (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: the pointers address exactly the supplied UTF-16 code-unit
    // lengths. Ordinal case-insensitive comparison is lossless for Windows
    // paths, including ill-formed UTF-16 which Rust preserves in OsString.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_length, right.as_ptr(), right_length, 1)
            == CSTR_EQUAL
    }
}

fn path_is_same_or_descendant(path: &Path, root: &Path) -> bool {
    let mut candidate = Some(path);
    while let Some(current) = candidate {
        if same_path(current, root) {
            return true;
        }
        candidate = current.parent();
    }
    false
}

const fn ascii_uppercase_u16(character: u16) -> u16 {
    if character >= b'a' as u16 && character <= b'z' as u16 {
        character - (b'a' as u16 - b'A' as u16)
    } else {
        character
    }
}

fn wide(value: &Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error() -> u32 {
    // SAFETY: GetLastError takes no inputs and returns the current thread's
    // error value immediately after the failing Win32 call.
    unsafe { GetLastError() }
}

fn io_error(operation: StorageOperation, error: &std::io::Error) -> StorageError {
    let os_code = error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok());
    match os_code {
        Some(code) => StorageError::with_os_code(StorageErrorCode::Io, operation, code),
        None => StorageError::new(StorageErrorCode::Io, operation),
    }
}

fn create_new_error(operation: StorageOperation, error: &std::io::Error) -> StorageError {
    let os_code = error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok());
    if os_code.is_some_and(|code| matches!(code, ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS)) {
        return os_code.map_or_else(
            || StorageError::new(StorageErrorCode::AlreadyExists, operation),
            |code| StorageError::with_os_code(StorageErrorCode::AlreadyExists, operation, code),
        );
    }
    io_error(operation, error)
}

use std::os::windows::ffi::OsStringExt;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use windows_sys::Win32::Security::WinWorldSid;

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().expect("temporary directory")
    }

    fn protected_root(directory: &tempfile::TempDir) -> ValidatedDataRoot {
        protect_data_root(directory.path()).expect("protect test root");
        validate_data_root(directory.path()).expect("validate protected test root")
    }

    fn protected_control_root(directory: &tempfile::TempDir) -> ValidatedControlRoot {
        protect_control_root(directory.path()).expect("protect control root");
        validate_control_root(directory.path()).expect("validate control root")
    }

    fn replace_test_dacl(path: &Path, sids: &[PSID], ace_flags: u32) {
        replace_test_dacl_mask(path, sids, ace_flags, FILE_ALL_ACCESS);
    }

    fn replace_test_dacl_mask(path: &Path, sids: &[PSID], ace_flags: u32, access_mask: u32) {
        let mut acl = OwnedAcl::for_sids(sids).expect("test ACL capacity");
        acl.add_aces_with_mask(sids, ace_flags, access_mask)
            .expect("test ACEs");
        let path_wide = wide(path);
        // SAFETY: the test's path and ACL remain live through this synchronous
        // call; the fixture intentionally changes only the root DACL.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path_wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl.as_ptr(),
                ptr::null(),
            )
        };
        assert_eq!(status, 0, "install malformed ACL fixture");
    }

    #[test]
    fn validates_a_local_ntfs_root() {
        let directory = root();
        let validated = protected_root(&directory);
        assert!(validated.path().is_absolute());
    }

    #[test]
    fn rejects_default_or_inherited_acl_before_setup() {
        let directory = root();
        assert_eq!(
            validate_data_root(directory.path())
                .expect_err("unprotected root")
                .code(),
            StorageErrorCode::InsecureAcl
        );
    }

    #[test]
    fn protection_is_idempotent_after_a_child_exists() {
        let directory = root();
        protect_data_root(directory.path()).expect("first protect");
        fs::write(directory.path().join("existing-child"), b"x").expect("child fixture");
        protect_data_root(directory.path()).expect("second protect");
        validate_data_root(directory.path()).expect("validated root");
    }

    #[test]
    fn rejects_removed_extra_or_wrong_inheritance_aces() {
        let sids = ExpectedSids::current().expect("expected SIDs");
        let expected = sids.all();
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let everyone_sid = everyone.as_ptr().cast_mut().cast();
        for (case_index, (fixture, ace_flags)) in [
            (&expected[..2], OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
            (
                &[expected[0], expected[1], expected[2], everyone_sid][..],
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            ),
            (&expected[..], OBJECT_INHERIT_ACE),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = root();
            let validated = protected_root(&directory);
            replace_test_dacl(validated.path(), fixture, ace_flags);
            assert_eq!(
                verify_data_root_acl(validated.path(), &sids, StorageOperation::ValidateDataRoot)
                    .expect_err(match case_index {
                        0 => "removed ACE fixture",
                        1 => "extra ACE fixture",
                        _ => "wrong inheritance fixture",
                    })
                    .code(),
                StorageErrorCode::InsecureAcl
            );
            assert!(validate_data_root(validated.path()).is_err());
        }
    }

    #[test]
    fn protection_refuses_to_claim_existing_descendants_are_safe() {
        let directory = root();
        fs::write(directory.path().join("preexisting"), b"x").expect("fixture file");
        assert_eq!(
            protect_data_root(directory.path())
                .expect_err("nonempty root")
                .code(),
            StorageErrorCode::InsecureAcl
        );
    }

    #[test]
    fn rejects_path_escapes() {
        let directory = root();
        let validated = protected_root(&directory);
        for path in [
            Path::new("."),
            Path::new("..\\outside"),
            Path::new(r"C:\\outside"),
        ] {
            assert_eq!(
                validated
                    .create_flushed_file(path, b"x")
                    .expect_err("must reject")
                    .code(),
                StorageErrorCode::PathEscapesRoot
            );
        }
        for path in [
            PathBuf::from(OsString::from_wide(&[
                u16::from(b'n'),
                u16::from(b'u'),
                u16::from(b'l'),
                0,
                u16::from(b'x'),
            ])),
            PathBuf::from("file:stream"),
            PathBuf::from("trailing."),
            PathBuf::from("trailing "),
            PathBuf::from("less<than"),
            PathBuf::from("greater>than"),
            PathBuf::from("double\"quote"),
            PathBuf::from("pipe|name"),
            PathBuf::from("question?mark"),
            PathBuf::from("star*name"),
            PathBuf::from(OsString::from_wide(&[
                u16::from(b'a'),
                0x0001,
                u16::from(b'b'),
            ])),
            PathBuf::from(OsString::from_wide(&[
                u16::from(b'a'),
                0x001f,
                u16::from(b'b'),
            ])),
        ] {
            assert_eq!(
                validated
                    .create_flushed_file(&path, b"x")
                    .expect_err("ambiguous Windows name")
                    .code(),
                StorageErrorCode::InvalidPath
            );
        }
    }

    #[test]
    fn volume_path_identity_is_lossless_and_ordinal_case_insensitive() {
        assert!(same_path(
            Path::new(r"C:\CodexAgentMesh\BLOBS"),
            Path::new(r"c:\codexagentmesh\blobs"),
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
    fn relative_components_enforce_ntfs_utf16_unit_limit() {
        let maximum = "a".repeat(MAX_NTFS_COMPONENT_UTF16_UNITS);
        validate_relative_path(Path::new(&maximum)).expect("255 UTF-16 units");
        let oversized = "a".repeat(MAX_NTFS_COMPONENT_UTF16_UNITS + 1);
        assert_eq!(
            validate_relative_path(Path::new(&oversized))
                .expect_err("256 UTF-16 units")
                .code(),
            StorageErrorCode::InvalidPath
        );

        // Non-BMP characters occupy two UTF-16 code units each.
        let astral_maximum = "😀".repeat(MAX_NTFS_COMPONENT_UTF16_UNITS / 2);
        validate_relative_path(Path::new(&astral_maximum)).expect("254 UTF-16 units");
        let astral_oversized = "😀".repeat(MAX_NTFS_COMPONENT_UTF16_UNITS.div_ceil(2));
        assert_eq!(
            validate_relative_path(Path::new(&astral_oversized))
                .expect_err("256 UTF-16 units")
                .code(),
            StorageErrorCode::InvalidPath
        );
    }

    #[test]
    fn rejects_reserved_dos_devices_but_accepts_similar_regular_names() {
        for path in [
            "CON",
            "prn.txt",
            "Aux.LOG",
            "NUL.json",
            "clock$",
            "conin$",
            "CONOUT$.txt",
            "com1",
            "COM9.bin",
            "COM¹.txt",
            "lpt1",
            "LpT9.txt",
            "LPT².log",
            "safe\\NUL.txt",
            "CON .txt",
        ] {
            assert_eq!(
                validate_relative_path(Path::new(path))
                    .expect_err("reserved DOS device")
                    .code(),
                StorageErrorCode::InvalidPath,
                "fixture {path}"
            );
        }

        let directory = root();
        let validated = protected_root(&directory);
        for path in [
            "console",
            "printer.txt",
            "auxiliary",
            "nulled.txt",
            "clock.txt",
            "com0",
            "com10",
            "lpt0",
            "lpt10.log",
            "data.con",
        ] {
            validated
                .create_flushed_file(Path::new(path), b"regular")
                .expect("ordinary file name");
            assert!(validated.path().join(path).is_file(), "fixture {path}");
        }
    }

    #[test]
    fn creates_a_flushed_non_sparse_zero_file() {
        let directory = root();
        let validated = protected_root(&directory);
        validated
            .create_flushed_zero_file(Path::new("reserve.bin"), 8192)
            .expect("reserve");
        let contents = fs::read(validated.path().join("reserve.bin")).expect("read reserve");
        assert_eq!(contents.len(), 8192);
        assert!(contents.iter().all(|byte| *byte == 0));
        assert_eq!(
            file_attributes(
                &validated.path().join("reserve.bin"),
                StorageOperation::CreateFile
            )
            .expect("attrs")
                & FILE_ATTRIBUTE_SPARSE_FILE,
            0
        );
        assert!(
            allocated_file_bytes(
                &validated.path().join("reserve.bin"),
                StorageOperation::CreateFile,
            )
            .expect("allocated bytes")
                >= 8192
        );
    }

    #[test]
    fn publishes_without_replacing_and_replaces_atomically() {
        let directory = root();
        let validated = protected_root(&directory);
        validated
            .create_flushed_file(Path::new("staged"), b"one")
            .expect("stage");
        validated
            .publish_no_replace(Path::new("staged"), Path::new("final"))
            .expect("publish");
        assert_eq!(
            fs::read(validated.path().join("final")).expect("final"),
            b"one"
        );

        validated
            .create_flushed_file(Path::new("again"), b"two")
            .expect("stage again");
        assert_eq!(
            validated
                .publish_no_replace(Path::new("again"), Path::new("final"))
                .expect_err("collision")
                .code(),
            StorageErrorCode::AlreadyExists
        );
        validated
            .atomic_replace(Path::new("again"), Path::new("final"))
            .expect("replace");
        assert_eq!(
            fs::read(validated.path().join("final")).expect("replacement"),
            b"two"
        );
    }

    #[test]
    fn lifetime_lock_contends_by_handle_and_never_deletes_the_file() {
        let directory = root();
        let validated = protected_root(&directory);
        let lock = validated
            .acquire_lifetime_lock(Path::new("daemon.lock"))
            .expect("first lock");
        assert_eq!(
            validated
                .acquire_lifetime_lock(Path::new("daemon.lock"))
                .expect_err("contended lock")
                .code(),
            crate::NativeErrorCode::SingletonConflict
        );
        drop(lock);
        assert!(validated.path().join("daemon.lock").is_file());
        validated
            .acquire_lifetime_lock(Path::new("daemon.lock"))
            .expect("reacquired after handle release");
    }

    #[test]
    fn rejects_a_reparse_component_when_symlink_creation_is_available() {
        let directory = root();
        let outside = root();
        let link = directory.path().join("link");
        if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &link) {
            // Developer Mode or SeCreateSymbolicLinkPrivilege is not enabled.
            eprintln!("skipped: cannot create Windows symlink ({error})");
            return;
        }
        let validated = protected_root(&directory);
        assert_eq!(
            validated
                .create_flushed_file(Path::new("link\\escape"), b"x")
                .expect_err("reparse")
                .code(),
            StorageErrorCode::ReparsePoint
        );
    }

    #[test]
    fn rejects_a_data_root_reached_through_a_reparse_point() {
        let directory = root();
        let target = root();
        let link = directory.path().join("linked-root");
        if let Err(error) = std::os::windows::fs::symlink_dir(target.path(), &link) {
            // Developer Mode or SeCreateSymbolicLinkPrivilege is not enabled.
            eprintln!("skipped: cannot create Windows symlink ({error})");
            return;
        }
        assert_eq!(
            validate_data_root(&link).expect_err("reparse root").code(),
            StorageErrorCode::ReparsePoint
        );
    }

    #[test]
    fn rejects_different_volumes_when_the_host_has_a_second_volume() {
        let directory = root();
        let validated = protected_root(&directory);
        let fixture = (b'D'..=b'Z')
            .map(|letter| PathBuf::from(format!("{}:\\\\", char::from(letter))))
            .find(|candidate| {
                candidate.is_dir()
                    && volume_root(candidate, StorageOperation::InspectVolume)
                        .is_ok_and(|root| !same_path(&root, &validated.volume_root))
            });
        let Some(other_volume) = fixture else {
            eprintln!("skipped: no mounted second volume fixture");
            return;
        };
        assert_eq!(
            validated
                .ensure_same_volume(validated.path(), &other_volume)
                .expect_err("different volume")
                .code(),
            StorageErrorCode::DifferentVolume
        );
    }

    #[test]
    fn creates_only_real_relative_directory_chains() {
        let directory = root();
        let validated = protected_root(&directory);
        validated
            .create_relative_directories(Path::new(r"install\slot-a\blobs"))
            .expect("create chain");
        validated
            .create_relative_directories(Path::new(r"install\slot-a\blobs"))
            .expect("idempotent real directories");
        fs::write(validated.path().join("regular"), b"x").expect("fixture file");
        assert_eq!(
            validated
                .create_relative_directories(Path::new(r"regular\child"))
                .expect_err("file is not directory")
                .code(),
            StorageErrorCode::NotDirectory
        );
        assert_eq!(
            validated
                .create_relative_directories(Path::new(r"safe\NUL.txt"))
                .expect_err("device alias")
                .code(),
            StorageErrorCode::InvalidPath
        );
    }

    #[test]
    fn data_descendant_paths_require_exact_inherited_acls() {
        let directory = root();
        let validated = protected_root(&directory);
        validated
            .create_relative_directories(Path::new(r"nested\child"))
            .expect("inherited directory chain");
        validated
            .create_flushed_file(Path::new(r"nested\child\blob"), b"bytes")
            .expect("inherited file");
        for relative in [
            Path::new("nested"),
            Path::new(r"nested\child"),
            Path::new(r"nested\child\blob"),
            Path::new(r"nested\child\not-created-yet"),
        ] {
            validated
                .validate_relative_path_security(relative)
                .expect("exact inherited descendant ACL");
        }
        validated
            .allocated_tree_bytes()
            .expect("secure tree allocation scan");

        let sids = ExpectedSids::current().expect("expected SIDs");
        replace_test_dacl(&validated.path().join(r"nested\child\blob"), &sids.all(), 0);
        assert_eq!(
            validated
                .validate_relative_path_security(Path::new(r"nested\child\blob"))
                .expect_err("protected explicit file ACL is not inherited evidence")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert_eq!(
            validated
                .allocated_tree_bytes()
                .expect_err("allocation scan rejects file ACL drift")
                .code(),
            StorageErrorCode::InsecureAcl
        );
    }

    #[test]
    fn data_descendant_directory_acl_drift_fences_children() {
        let directory = root();
        let validated = protected_root(&directory);
        validated
            .create_relative_directories(Path::new(r"nested\child"))
            .expect("inherited directory chain");
        let sids = ExpectedSids::current().expect("expected SIDs");
        replace_test_dacl(
            &validated.path().join("nested"),
            &sids.all(),
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        );
        assert_eq!(
            validated
                .validate_relative_path_security(Path::new(r"nested\child"))
                .expect_err("protected explicit directory ACL is not inherited evidence")
                .code(),
            StorageErrorCode::InsecureAcl
        );
    }

    #[test]
    fn copy_verifies_digest_and_cleans_up_only_its_created_file() {
        let directory = root();
        let validated = protected_root(&directory);
        let contents = b"verified streaming copy";
        let expected: [u8; 32] = Sha256::digest(contents).into();
        let mut source = &contents[..];
        assert_eq!(
            validated
                .copy_reader_verified(&mut source, Path::new("blob"), expected)
                .expect("copy"),
            contents.len() as u64
        );
        assert_eq!(
            fs::read(validated.path().join("blob")).expect("blob"),
            contents
        );

        let mut mismatch_source = &contents[..];
        assert_eq!(
            validated
                .copy_reader_verified(&mut mismatch_source, Path::new("mismatch"), [0; 32])
                .expect_err("digest mismatch")
                .code(),
            StorageErrorCode::DigestMismatch
        );
        assert!(!validated.path().join("mismatch").exists());
        assert!(validated.path().join("blob").exists());

        let mut collision_source = &contents[..];
        assert_eq!(
            validated
                .copy_reader_verified(&mut collision_source, Path::new("blob"), expected)
                .expect_err("create-new collision")
                .code(),
            StorageErrorCode::AlreadyExists
        );
        assert_eq!(
            fs::read(validated.path().join("blob")).expect("original"),
            contents
        );
    }

    #[test]
    fn exact_removal_allocation_free_space_and_directory_sync_are_typed() {
        let directory = root();
        let validated = protected_root(&directory);
        validated
            .create_relative_directories(Path::new("nested"))
            .expect("directory");
        validated
            .create_flushed_zero_file(Path::new(r"nested\allocated"), 8192)
            .expect("allocated fixture");
        assert!(validated.allocated_tree_bytes().expect("allocation") >= 8192);
        assert!(validated.volume_free_bytes().expect("free bytes") > 0);
        assert_eq!(
            validated
                .remove_regular_file(Path::new("nested"))
                .expect_err("never remove a directory")
                .code(),
            StorageErrorCode::NotRegularFile
        );
        assert!(
            validated
                .remove_regular_file(Path::new(r"nested\allocated"))
                .expect("remove exact file")
        );
        assert!(
            !validated
                .remove_regular_file(Path::new(r"nested\allocated"))
                .expect("missing is idempotent")
        );

        if let Err(error) = validated.sync_directory(Path::new("nested")) {
            assert_eq!(
                error.code(),
                StorageErrorCode::DirectorySyncUnsupported,
                "unexpected directory sync failure: {error}"
            );
        }
    }

    #[test]
    fn endpoint_key_file_is_flushed_user_only_and_never_overwritten() {
        const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";
        let directory = root();
        let validated = protected_root(&directory);
        let key = crate::EndpointKey::from_bytes([0x42; crate::AUTH_TAG_LENGTH]);
        let protected = crate::protect_endpoint_key(&key, INSTALL_ID).expect("protect");
        validated
            .create_endpoint_key_file(Path::new("endpoint.key"), &protected)
            .expect("create protected key file");
        verify_endpoint_key_acl(&validated.path().join("endpoint.key")).expect("exact key ACL");
        let read_back = validated
            .read_endpoint_key_file(Path::new("endpoint.key"))
            .expect("read protected key");
        assert_eq!(read_back, protected);
        assert_eq!(
            validated
                .create_endpoint_key_file(Path::new("endpoint.key"), &protected)
                .expect_err("must not overwrite")
                .code(),
            StorageErrorCode::AlreadyExists
        );
    }

    #[test]
    fn endpoint_key_file_refuses_extra_inherited_and_changed_aces() {
        const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";
        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let user_sid: PSID = user.as_ptr().cast_mut().cast();
        let everyone_sid: PSID = everyone.as_ptr().cast_mut().cast();
        let inherited_directory = root();
        let inherited_root = protected_root(&inherited_directory);
        let inherited_key = crate::EndpointKey::from_bytes([8; crate::AUTH_TAG_LENGTH]);
        let inherited_protected =
            crate::protect_endpoint_key(&inherited_key, INSTALL_ID).expect("protect");
        inherited_root
            .create_flushed_file(Path::new("inherited.key"), inherited_protected.as_bytes())
            .expect("ordinary inherited file");
        assert_eq!(
            inherited_root
                .read_endpoint_key_file(Path::new("inherited.key"))
                .expect_err("inherited parent ACL")
                .code(),
            StorageErrorCode::InsecureAcl
        );

        for (case, (sids, flags, mask)) in [
            (&[user_sid, everyone_sid][..], 0, FILE_ALL_ACCESS),
            (&[user_sid][..], 0, FILE_ALL_ACCESS & !1),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = root();
            let validated = protected_root(&directory);
            let key = crate::EndpointKey::from_bytes([7; crate::AUTH_TAG_LENGTH]);
            let protected = crate::protect_endpoint_key(&key, INSTALL_ID).expect("protect");
            validated
                .create_endpoint_key_file(Path::new("endpoint.key"), &protected)
                .expect("create key");
            let path = validated.path().join("endpoint.key");
            replace_test_dacl_mask(&path, sids, flags, mask);
            assert_eq!(
                validated
                    .read_endpoint_key_file(Path::new("endpoint.key"))
                    .expect_err(match case {
                        0 => "extra key ACE",
                        _ => "changed key ACE mask",
                    })
                    .code(),
                StorageErrorCode::InsecureAcl
            );
        }
    }

    #[test]
    fn exact_ace_size_rejects_trailing_padding() {
        let user = current_user_sid().expect("user SID");
        let sid: PSID = user.as_ptr().cast_mut().cast();
        let exact = (mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<u32>())
            .checked_add(sid_length(sid).expect("SID length"))
            .and_then(|length| u16::try_from(length).ok())
            .expect("ACE size");
        assert!(access_allowed_ace_size_is_exact(exact, sid));
        assert!(!access_allowed_ace_size_is_exact(exact + 4, sid));
        assert!(!access_allowed_ace_size_is_exact(exact - 1, sid));
    }

    #[test]
    fn create_new_guard_cleans_partial_files_but_preserves_collisions() {
        let directory = root();
        let validated = protected_root(&directory);
        let partial = validated.path().join("partial");
        let error = with_created_file(&partial, StorageOperation::CreateFile, |created| {
            created
                .file_mut()
                .write_all(b"partial bytes")
                .expect("inject partial write");
            Err::<(), _>(StorageError::new(
                StorageErrorCode::Io,
                StorageOperation::WriteFile,
            ))
        })
        .expect_err("injected post-create failure");
        assert_eq!(error.operation(), StorageOperation::WriteFile);
        assert!(!partial.exists());

        let collision = validated.path().join("collision");
        fs::write(&collision, b"keep me").expect("collision fixture");
        let invoked = std::cell::Cell::new(false);
        let error = with_created_file(&collision, StorageOperation::CreateFile, |_created| {
            invoked.set(true);
            Ok(())
        })
        .expect_err("create-new collision");
        assert_eq!(error.code(), StorageErrorCode::AlreadyExists);
        assert!(!invoked.get());
        assert_eq!(
            fs::read(collision).expect("preserved collision"),
            b"keep me"
        );
    }

    #[test]
    fn control_root_requires_exact_current_user_inheritable_acl() {
        let unprotected = root();
        assert_eq!(
            validate_control_root(unprotected.path())
                .expect_err("default inherited ACL")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        let directory = root();
        let control = protected_control_root(&directory);
        validate_control_root(control.path()).expect("canonical path round trip");
        verify_user_only_acl(
            control.path(),
            CONTROL_ROOT_ACE_FLAGS,
            StorageOperation::ValidateControlRoot,
        )
        .expect("exact control ACL");
        fs::write(control.path().join("child"), b"x").expect("child");
        protect_control_root(control.path()).expect("idempotent with child");

        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let user_sid: PSID = user.as_ptr().cast_mut().cast();
        let everyone_sid: PSID = everyone.as_ptr().cast_mut().cast();
        for (sids, flags, mask) in [
            (
                &[user_sid, everyone_sid][..],
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
            ),
            (
                &[everyone_sid][..],
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
            ),
            (&[user_sid][..], OBJECT_INHERIT_ACE, FILE_ALL_ACCESS),
            (
                &[user_sid][..],
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS & !1,
            ),
        ] {
            let fixture = root();
            let control = protected_control_root(&fixture);
            replace_test_dacl_mask(control.path(), sids, flags, mask);
            assert_eq!(
                validate_control_root(fixture.path())
                    .expect_err("control ACL drift")
                    .code(),
                StorageErrorCode::InsecureAcl
            );
        }
    }

    #[test]
    fn insecure_nonempty_control_root_is_never_rewritten() {
        let directory = root();
        fs::write(directory.path().join("unknown"), b"x").expect("child");
        assert_eq!(
            protect_control_root(directory.path())
                .expect_err("unsafe rewrite")
                .code(),
            StorageErrorCode::InsecureAcl
        );
    }

    #[test]
    fn control_directory_chain_tightens_only_empty_insecure_directories() {
        let directory = root();
        let control = protected_control_root(&directory);
        let inherited_empty = control.path().join("inherited-empty");
        fs::create_dir(&inherited_empty).expect("inherited empty directory");
        assert_eq!(
            verify_control_directory_acl(&inherited_empty, StorageOperation::CreateDirectory)
                .expect_err("inherited ACL is not exact")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        control
            .create_relative_directories(Path::new("inherited-empty"))
            .expect("tighten empty directory");
        verify_control_directory_acl(&inherited_empty, StorageOperation::CreateDirectory)
            .expect("exact child ACL");

        let inherited_nonempty = control.path().join("inherited-nonempty");
        fs::create_dir(&inherited_nonempty).expect("inherited nonempty directory");
        fs::write(inherited_nonempty.join("unknown"), b"preserve").expect("unknown child");
        assert_eq!(
            control
                .create_relative_directories(Path::new("inherited-nonempty"))
                .expect_err("never rewrite insecure nonempty directory")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert_eq!(
            fs::read(inherited_nonempty.join("unknown")).expect("preserved child"),
            b"preserve"
        );
        assert!(
            verify_control_directory_acl(&inherited_nonempty, StorageOperation::CreateDirectory)
                .is_err(),
            "failed tightening must not silently rewrite the directory"
        );
    }

    #[test]
    fn failed_control_directory_creation_cleans_only_components_it_created() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new("preexisting"))
            .expect("preexisting exact directory");
        let preexisting = control.path().join("preexisting");
        let owned = preexisting.join("owned");
        let error = control
            .create_relative_directories_with_hook(
                Path::new(r"preexisting\owned"),
                |path, created_here| {
                    if created_here && path.ends_with("owned") {
                        return Err(StorageError::new(
                            StorageErrorCode::Io,
                            StorageOperation::CreateDirectory,
                        ));
                    }
                    Ok(())
                },
            )
            .expect_err("injected post-create failure");
        assert_eq!(error.code(), StorageErrorCode::Io);
        assert!(
            preexisting.is_dir(),
            "collision/preexisting directory remains"
        );
        assert!(
            !owned.exists(),
            "only this call's empty directory is removed"
        );
        verify_control_directory_acl(&preexisting, StorageOperation::CreateDirectory)
            .expect("preexisting ACL remains exact");
    }

    #[test]
    fn control_directory_drift_is_rejected_and_not_repaired_when_nonempty() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"slots\stable"))
            .expect("secure directory chain");
        fs::write(control.path().join(r"slots\stable\unknown"), b"preserve")
            .expect("unknown child");
        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let sids = [
            user.as_ptr().cast_mut().cast(),
            everyone.as_ptr().cast_mut().cast(),
        ];
        let stable = control.path().join(r"slots\stable");
        replace_test_dacl(&stable, &sids, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        assert_eq!(
            control
                .create_relative_directories(Path::new(r"slots\stable"))
                .expect_err("extra child ACE")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert_eq!(
            fs::read(stable.join("unknown")).expect("preserved child"),
            b"preserve"
        );
        assert!(verify_control_directory_acl(&stable, StorageOperation::CreateDirectory).is_err());
    }

    #[test]
    fn every_control_file_operation_rechecks_root_and_parent_acl() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"slots\stable"))
            .expect("secure directory chain");
        control
            .create_protected_file(Path::new(r"slots\stable\record"), b"record")
            .expect("protected record");
        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let sids = [
            user.as_ptr().cast_mut().cast(),
            everyone.as_ptr().cast_mut().cast(),
        ];
        replace_test_dacl(
            &control.path().join(r"slots\stable"),
            &sids,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        );
        assert_eq!(
            control
                .read_protected_file(Path::new(r"slots\stable\record"))
                .expect_err("parent ACL drift")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert_eq!(
            control
                .create_protected_file(Path::new(r"slots\stable\new"), b"new")
                .expect_err("parent ACL drift before create")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert!(!control.path().join(r"slots\stable\new").exists());

        let root_drift = root();
        let control = protected_control_root(&root_drift);
        control
            .create_protected_file(Path::new("record"), b"record")
            .expect("root record");
        replace_test_dacl(
            control.path(),
            &sids,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        );
        assert_eq!(
            control
                .read_protected_file(Path::new("record"))
                .expect_err("root ACL drift")
                .code(),
            StorageErrorCode::InsecureAcl
        );
    }

    #[test]
    fn concurrent_control_directory_creation_accepts_only_the_exact_result() {
        let directory = root();
        let control = Arc::new(protected_control_root(&directory));
        let barrier = Arc::new(Barrier::new(3));
        let workers = (0..2)
            .map(|_| {
                let control = Arc::clone(&control);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    control.create_relative_directories(Path::new(r"slots\stable"))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for worker in workers {
            worker
                .join()
                .expect("worker panicked")
                .expect("create chain");
        }
        for child in ["slots", r"slots\stable"] {
            verify_control_directory_acl(
                &control.path().join(child),
                StorageOperation::CreateDirectory,
            )
            .expect("exact concurrent result");
        }
    }

    #[test]
    fn fixed_product_child_uses_only_the_literal_name_in_a_temp_base() {
        let local_app_data = root();
        let control = open_or_create_product_control_root_in(local_app_data.path())
            .expect("fixed product root");
        assert_eq!(
            control.path().file_name(),
            Some(std::ffi::OsStr::new(PRODUCT_CONTROL_ROOT_NAME))
        );
        assert_eq!(
            fs::read_dir(local_app_data.path())
                .expect("children")
                .count(),
            1
        );
    }

    #[test]
    fn control_files_are_bounded_protected_and_replaceable() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"installs\slot"))
            .expect("directories");
        control
            .create_protected_file(Path::new(r"installs\slot\record.new"), b"one")
            .expect("stage");
        verify_user_only_file_acl(
            &control.path().join(r"installs\slot\record.new"),
            StorageOperation::ReadControlFile,
        )
        .expect("file ACL");
        control
            .publish_no_replace(
                Path::new(r"installs\slot\record.new"),
                Path::new(r"installs\slot\record"),
            )
            .expect("publish");
        control
            .create_protected_file(Path::new(r"installs\slot\record.new"), b"two")
            .expect("new stage");
        control
            .atomic_replace(
                Path::new(r"installs\slot\record.new"),
                Path::new(r"installs\slot\record"),
            )
            .expect("replace");
        assert_eq!(
            control
                .read_protected_file(Path::new(r"installs\slot\record"))
                .expect("read"),
            b"two"
        );
        assert_eq!(
            control
                .create_protected_file(Path::new(r"installs\slot\record"), b"collision")
                .expect_err("collision")
                .code(),
            StorageErrorCode::AlreadyExists
        );
        assert_eq!(
            control
                .read_protected_file(Path::new(r"installs\slot\record"))
                .expect("preserved"),
            b"two"
        );
        let oversized = vec![0; MAX_CONTROL_FILE_BYTES + 1];
        assert_eq!(
            control
                .create_protected_file(Path::new("oversized"), &oversized)
                .expect_err("oversized")
                .code(),
            StorageErrorCode::TooLarge
        );
        assert_eq!(
            control
                .create_protected_file(Path::new(r"..\escape"), b"x")
                .expect_err("escape")
                .code(),
            StorageErrorCode::PathEscapesRoot
        );
        fs::write(control.path().join("inherited-stage"), b"unsafe").expect("unsafe stage");
        assert_eq!(
            control
                .publish_no_replace(Path::new("inherited-stage"), Path::new("must-not-publish"))
                .expect_err("staged ACL must be exact")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert!(!control.path().join("must-not-publish").exists());
    }

    #[test]
    fn control_artifact_copy_is_bounded_verified_and_collision_safe() {
        struct FailAfterBytes {
            bytes: Option<&'static [u8]>,
        }

        impl Read for FailAfterBytes {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if let Some(bytes) = self.bytes.take() {
                    buffer[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("injected read failure"))
                }
            }
        }

        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"installs\one\bin"))
            .expect("artifact parent");
        let relative = Path::new(r"installs\one\bin\runtime.stage");
        let contents = b"verified executable bytes";
        let expected: [u8; 32] = Sha256::digest(contents).into();
        let mut source = &contents[..];
        assert_eq!(
            control
                .copy_reader_verified(&mut source, relative, expected)
                .expect("protected streaming copy"),
            contents.len() as u64
        );
        let absolute = control
            .verify_artifact_file(relative, expected)
            .expect("verified absolute artifact");
        assert!(absolute.is_absolute());
        assert!(same_path(
            &absolute,
            &fs::canonicalize(control.path().join(relative)).expect("canonical fixture")
        ));
        verify_user_only_file_acl(&absolute, StorageOperation::VerifyPublication)
            .expect("exact artifact ACL");

        let mut collision_source = &b"replacement"[..];
        assert_eq!(
            control
                .copy_reader_verified(&mut collision_source, relative, expected)
                .expect_err("create-new collision")
                .code(),
            StorageErrorCode::AlreadyExists
        );
        assert_eq!(fs::read(&absolute).expect("collision preserved"), contents);

        let mismatch = Path::new(r"installs\one\bin\mismatch.stage");
        let mut mismatch_source = &contents[..];
        assert_eq!(
            control
                .copy_reader_verified(&mut mismatch_source, mismatch, [0; 32])
                .expect_err("digest mismatch")
                .code(),
            StorageErrorCode::DigestMismatch
        );
        assert!(!control.path().join(mismatch).exists());

        let oversized = Path::new(r"installs\one\bin\oversized.stage");
        let mut oversized_source = &b"ninebytes"[..];
        assert_eq!(
            control
                .copy_reader_verified_with_limit(&mut oversized_source, oversized, [0; 32], 8,)
                .expect_err("streaming size bound")
                .code(),
            StorageErrorCode::TooLarge
        );
        assert!(!control.path().join(oversized).exists());

        let failed = Path::new(r"installs\one\bin\failed.stage");
        let mut failed_source = FailAfterBytes {
            bytes: Some(b"partial"),
        };
        assert_eq!(
            control
                .copy_reader_verified(&mut failed_source, failed, expected)
                .expect_err("injected read failure")
                .code(),
            StorageErrorCode::Io
        );
        assert!(!control.path().join(failed).exists());
    }

    #[test]
    fn control_artifact_verification_rejects_corruption_acl_drift_and_reparse() {
        let directory = root();
        let outside = root();
        let control = protected_control_root(&directory);
        let contents = b"expected runtime";
        let expected: [u8; 32] = Sha256::digest(contents).into();

        control
            .create_protected_file(Path::new("corrupt.exe"), b"changed runtime")
            .expect("corrupt fixture");
        assert_eq!(
            control
                .verify_artifact_file(Path::new("corrupt.exe"), expected)
                .expect_err("digest corruption")
                .code(),
            StorageErrorCode::DigestMismatch
        );

        control
            .create_protected_file(Path::new("oversized.exe"), &[])
            .expect("oversized artifact fixture");
        OpenOptions::new()
            .write(true)
            .open(control.path().join("oversized.exe"))
            .expect("open oversized artifact")
            .set_len(ValidatedControlRoot::MAX_EXECUTABLE_BYTES + 1)
            .expect("set oversized artifact metadata");
        assert_eq!(
            control
                .verify_artifact_file(Path::new("oversized.exe"), expected)
                .expect_err("artifact metadata bound")
                .code(),
            StorageErrorCode::TooLarge
        );

        fs::write(control.path().join("inherited.exe"), contents).expect("inherited fixture");
        assert_eq!(
            control
                .verify_artifact_file(Path::new("inherited.exe"), expected)
                .expect_err("inherited ACL")
                .code(),
            StorageErrorCode::InsecureAcl
        );

        let outside_file = outside.path().join("outside.exe");
        fs::write(&outside_file, contents).expect("outside fixture");
        let link = control.path().join("runtime-link.exe");
        if let Err(error) = std::os::windows::fs::symlink_file(&outside_file, &link) {
            eprintln!("skipped reparse fixture: cannot create Windows symlink ({error})");
            return;
        }
        assert_eq!(
            control
                .verify_artifact_file(Path::new("runtime-link.exe"), expected)
                .expect_err("reparse artifact")
                .code(),
            StorageErrorCode::ReparsePoint
        );
    }

    #[test]
    fn control_endpoint_key_is_exact_bounded_and_never_overwritten() {
        const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"installs\one\secrets"))
            .expect("key parent");
        let relative = Path::new(r"installs\one\secrets\endpoint-key.dpapi");
        let key = crate::EndpointKey::from_bytes([0x55; crate::AUTH_TAG_LENGTH]);
        let protected = crate::protect_endpoint_key(&key, INSTALL_ID).expect("protect");
        control
            .create_endpoint_key_file(relative, &protected)
            .expect("create endpoint key");
        verify_endpoint_key_acl(&control.path().join(relative)).expect("exact endpoint-key ACL");
        assert_eq!(
            control
                .read_endpoint_key_file(relative)
                .expect("full bounded readback"),
            protected
        );
        assert_eq!(
            control
                .create_endpoint_key_file(relative, &protected)
                .expect_err("non-overwrite collision")
                .code(),
            StorageErrorCode::AlreadyExists
        );

        OpenOptions::new()
            .write(true)
            .open(control.path().join(relative))
            .expect("open bounded fixture")
            .set_len((crate::MAX_PROTECTED_ENDPOINT_KEY_BYTES as u64) + 1)
            .expect("oversized metadata fixture");
        assert_eq!(
            control
                .read_endpoint_key_file(relative)
                .expect_err("metadata bound before allocation")
                .code(),
            StorageErrorCode::InvalidProtectedKey
        );

        let inherited = Path::new(r"installs\one\secrets\inherited.dpapi");
        fs::write(control.path().join(inherited), protected.as_bytes())
            .expect("inherited key fixture");
        assert_eq!(
            control
                .read_endpoint_key_file(inherited)
                .expect_err("wrong endpoint-key ACL")
                .code(),
            StorageErrorCode::InsecureAcl
        );
    }

    #[test]
    fn control_read_rejects_oversized_metadata_before_allocation() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_protected_file(Path::new("oversized"), &[])
            .expect("empty protected file");
        OpenOptions::new()
            .write(true)
            .open(control.path().join("oversized"))
            .expect("open fixture")
            .set_len((MAX_CONTROL_FILE_BYTES as u64) + 1)
            .expect("set oversized metadata");
        assert_eq!(
            control
                .read_protected_file(Path::new("oversized"))
                .expect_err("metadata bound")
                .code(),
            StorageErrorCode::TooLarge
        );
    }

    #[test]
    fn control_read_rejects_inherited_extra_and_wrong_file_aces() {
        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let user_sid: PSID = user.as_ptr().cast_mut().cast();
        let everyone_sid: PSID = everyone.as_ptr().cast_mut().cast();

        let inherited_directory = root();
        let inherited_control = protected_control_root(&inherited_directory);
        fs::write(inherited_control.path().join("inherited"), b"x").expect("inherited file");
        assert_eq!(
            inherited_control
                .read_protected_file(Path::new("inherited"))
                .expect_err("inherited file ACL")
                .code(),
            StorageErrorCode::InsecureAcl
        );

        for (sids, mask) in [
            (&[user_sid, everyone_sid][..], FILE_ALL_ACCESS),
            (&[user_sid][..], FILE_ALL_ACCESS & !1),
        ] {
            let directory = root();
            let control = protected_control_root(&directory);
            control
                .create_protected_file(Path::new("record"), b"x")
                .expect("protected file");
            replace_test_dacl_mask(&control.path().join("record"), sids, 0, mask);
            assert_eq!(
                control
                    .read_protected_file(Path::new("record"))
                    .expect_err("file ACL drift")
                    .code(),
                StorageErrorCode::InsecureAcl
            );
        }
    }

    #[test]
    fn control_removal_requires_exact_file_acl_and_preserves_untrusted_targets() {
        let directory = root();
        let control = protected_control_root(&directory);
        let inherited = control.path().join("inherited");
        fs::write(&inherited, b"preserve inherited").expect("inherited fixture");
        assert_eq!(
            control
                .remove_regular_file(Path::new("inherited"))
                .expect_err("inherited target ACL")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert_eq!(
            fs::read(&inherited).expect("inherited target preserved"),
            b"preserve inherited"
        );

        control
            .create_protected_file(Path::new("extra"), b"preserve extra")
            .expect("protected fixture");
        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let sids = [
            user.as_ptr().cast_mut().cast(),
            everyone.as_ptr().cast_mut().cast(),
        ];
        let extra = control.path().join("extra");
        replace_test_dacl(&extra, &sids, 0);
        assert_eq!(
            control
                .remove_regular_file(Path::new("extra"))
                .expect_err("extra target ACE")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert_eq!(
            fs::read(&extra).expect("extra target preserved"),
            b"preserve extra"
        );

        control
            .create_protected_file(Path::new("trusted"), b"remove")
            .expect("trusted fixture");
        assert!(
            control
                .remove_regular_file(Path::new("trusted"))
                .expect("remove trusted target")
        );
        assert!(
            !control
                .remove_regular_file(Path::new("trusted"))
                .expect("missing target is false")
        );
    }

    #[test]
    fn control_replace_refuses_and_preserves_an_untrusted_existing_final() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_protected_file(Path::new("staged"), b"new")
            .expect("trusted stage");
        control
            .create_protected_file(Path::new("final"), b"preserve")
            .expect("initial trusted final");
        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let sids = [
            user.as_ptr().cast_mut().cast(),
            everyone.as_ptr().cast_mut().cast(),
        ];
        replace_test_dacl(&control.path().join("final"), &sids, 0);
        assert_eq!(
            control
                .atomic_replace(Path::new("staged"), Path::new("final"))
                .expect_err("untrusted final")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert_eq!(
            fs::read(control.path().join("final")).expect("final preserved"),
            b"preserve"
        );
        assert_eq!(
            fs::read(control.path().join("staged")).expect("stage preserved"),
            b"new"
        );
    }

    #[test]
    fn control_root_rejects_reparse_hops_when_available() {
        let directory = root();
        let outside = root();
        let control = protected_control_root(&directory);
        let link = control.path().join("link");
        if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &link) {
            eprintln!("skipped: cannot create Windows symlink ({error})");
            return;
        }
        assert_eq!(
            control
                .create_protected_file(Path::new(r"link\escape"), b"x")
                .expect_err("reparse hop")
                .code(),
            StorageErrorCode::ReparsePoint
        );
    }

    #[test]
    fn control_lock_is_persistent_protected_and_contended() {
        let directory = root();
        let control = protected_control_root(&directory);
        let lock = control
            .acquire_lifetime_lock(Path::new("control.lock"))
            .expect("first lock");
        assert_eq!(
            control
                .acquire_lifetime_lock(Path::new("control.lock"))
                .expect_err("contention")
                .code(),
            crate::NativeErrorCode::SingletonConflict
        );
        drop(lock);
        verify_user_only_file_acl(
            &control.path().join("control.lock"),
            StorageOperation::InspectSecurity,
        )
        .expect("lock ACL");
        control
            .acquire_lifetime_lock(Path::new("control.lock"))
            .expect("reacquire");
        assert!(control.path().join("control.lock").exists());
    }

    #[test]
    fn existing_lock_acquisition_never_creates_and_revalidates_exact_handle() {
        let directory = root();
        let control = protected_control_root(&directory);
        let relative = Path::new(r"slots\stable\install.lock");
        control
            .create_relative_directories(Path::new(r"slots\stable"))
            .expect("slot parents");
        assert_eq!(
            control
                .acquire_existing_lifetime_lock(relative)
                .expect_err("missing existing lock")
                .code(),
            StorageErrorCode::NotFound
        );
        assert!(
            !control.path().join(relative).exists(),
            "no create side effect"
        );
        control
            .create_protected_file(relative, b"")
            .expect("publish exact lock file");
        let lock = control
            .acquire_existing_lifetime_lock(relative)
            .expect("acquire existing lock");
        assert_eq!(
            control
                .acquire_existing_lifetime_lock(relative)
                .expect_err("no-share contention")
                .code(),
            StorageErrorCode::SharingViolation
        );
        drop(lock);
        control
            .acquire_existing_lifetime_lock(relative)
            .expect("reacquire after release");
    }

    const PURGE_TEST_INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";

    fn populated_install_tree(control: &ValidatedControlRoot) -> (PathBuf, tempfile::TempDir) {
        let install = PathBuf::from("installs").join(PURGE_TEST_INSTALL_ID);
        control
            .create_relative_directories(&install.join(r"bin\Unicode 子").join("x".repeat(200)))
            .expect("protected mixed control directories");
        control
            .create_protected_file(&install.join(r"bin\mesh-daemon.exe"), b"runtime")
            .expect("protected runtime");
        control
            .create_protected_file(&install.join(r"run.lock"), b"")
            .expect("protected lock fixture");

        let data_path = control.path().join(&install).join("data");
        fs::create_dir(&data_path).expect("data root directory");
        protect_data_root(&data_path).expect("protect data root");
        let data = validate_data_root(&data_path).expect("validate data root");
        data.create_relative_directories(Path::new(r"blobs\nested"))
            .expect("data descendants");
        data.create_flushed_file(Path::new(r"blobs\nested\result.bin"), b"durable result")
            .expect("data file");
        data.create_flushed_file(Path::new("linked.bin"), b"outside hard-link sentinel")
            .expect("hard link source");
        data.create_flushed_file(Path::new("readonly.bin"), b"read only")
            .expect("read-only source");
        let readonly = data_path.join("readonly.bin");
        let mut permissions = fs::metadata(&readonly)
            .expect("read-only metadata")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&readonly, permissions).expect("set read-only attribute");

        let outside = root();
        fs::hard_link(
            data_path.join("linked.bin"),
            outside.path().join("sentinel.bin"),
        )
        .expect("outside hard link");
        (install, outside)
    }

    #[test]
    fn purge_tree_stages_audits_and_removes_mixed_control_and_data_acl_tree() {
        let directory = root();
        let control = protected_control_root(&directory);
        let (source, outside) = populated_install_tree(&control);
        assert_eq!(
            control
                .classify_install_purge_tree(PURGE_TEST_INSTALL_ID)
                .expect("source classification"),
            InstallPurgeTreePresence::Source
        );

        control
            .stage_install_tree_for_purge(PURGE_TEST_INSTALL_ID)
            .expect("stage no-replace tombstone");
        assert!(!control.path().join(&source).exists());
        assert!(
            control
                .path()
                .join("purge")
                .join(PURGE_TEST_INSTALL_ID)
                .exists()
        );

        let report = control
            .audit_and_remove_install_tree(PURGE_TEST_INSTALL_ID)
            .expect("audit then remove exact tree");
        assert!(
            report.directories >= 6,
            "root/control/data descendants counted"
        );
        assert_eq!(report.files, 5);
        assert_eq!(report.hard_link_entries, 1);
        assert_eq!(report.read_only_entries, 1);
        assert!(report.logical_file_bytes >= 30);
        assert_eq!(
            control
                .classify_install_purge_tree(PURGE_TEST_INSTALL_ID)
                .expect("gone classification"),
            InstallPurgeTreePresence::Gone
        );
        assert_eq!(
            fs::read(outside.path().join("sentinel.bin")).expect("outside sentinel survives"),
            b"outside hard-link sentinel"
        );
    }

    #[test]
    fn purge_source_and_tombstone_conflict_preserves_both_trees() {
        let directory = root();
        let control = protected_control_root(&directory);
        let (source, _outside) = populated_install_tree(&control);
        let tombstone = PathBuf::from("purge").join(PURGE_TEST_INSTALL_ID);
        control
            .create_relative_directories(&tombstone)
            .expect("colliding tombstone");
        for operation in [
            control
                .classify_install_purge_tree(PURGE_TEST_INSTALL_ID)
                .map(drop),
            control
                .stage_install_tree_for_purge(PURGE_TEST_INSTALL_ID)
                .map(drop),
            control
                .audit_and_remove_install_tree(PURGE_TEST_INSTALL_ID)
                .map(drop),
        ] {
            assert_eq!(
                operation.expect_err("both trees are drift").code(),
                StorageErrorCode::PurgeTreeConflict
            );
        }
        assert!(control.path().join(source).exists());
        assert!(control.path().join(tombstone).exists());
    }

    #[test]
    fn purge_audit_refuses_reparse_and_preserves_outside_sentinel_and_tombstone() {
        let directory = root();
        let control = protected_control_root(&directory);
        let (_source, outside) = populated_install_tree(&control);
        control
            .stage_install_tree_for_purge(PURGE_TEST_INSTALL_ID)
            .expect("stage");
        let sentinel = outside.path().join("sentinel-target.txt");
        fs::write(&sentinel, b"outside").expect("outside sentinel");
        let link = control
            .path()
            .join("purge")
            .join(PURGE_TEST_INSTALL_ID)
            .join("escape-link");
        if let Err(error) = std::os::windows::fs::symlink_file(&sentinel, &link) {
            eprintln!("skipped reparse fixture: cannot create Windows symlink ({error})");
            return;
        }
        assert_eq!(
            control
                .audit_and_remove_install_tree(PURGE_TEST_INSTALL_ID)
                .expect_err("reparse must fail before deletion")
                .code(),
            StorageErrorCode::ReparsePoint
        );
        assert_eq!(fs::read(&sentinel).expect("outside preserved"), b"outside");
        assert!(link.exists());
        assert!(
            control
                .path()
                .join("purge")
                .join(PURGE_TEST_INSTALL_ID)
                .exists()
        );
    }

    #[test]
    fn purge_audit_detects_share_blocker_before_mutation_then_converges() {
        let directory = root();
        let control = protected_control_root(&directory);
        let (_source, _outside) = populated_install_tree(&control);
        control
            .stage_install_tree_for_purge(PURGE_TEST_INSTALL_ID)
            .expect("stage");
        let tombstone = control.path().join("purge").join(PURGE_TEST_INSTALL_ID);
        let blocked = tombstone.join(r"data\blobs\nested\result.bin");
        let held_file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&blocked)
            .expect("non-delete-sharing blocker");
        assert_eq!(
            control
                .audit_and_remove_install_tree(PURGE_TEST_INSTALL_ID)
                .expect_err("sharing blocker")
                .code(),
            StorageErrorCode::SharingViolation
        );
        assert!(blocked.exists(), "audit pass made no mutation");
        assert!(tombstone.join("run.lock").exists());
        drop(held_file);
        control
            .audit_and_remove_install_tree(PURGE_TEST_INSTALL_ID)
            .expect("retry converges after blocker release");
        assert!(!tombstone.exists());
    }

    #[test]
    fn purge_second_audit_detects_file_identity_drift_before_deletion() {
        let directory = root();
        let control = protected_control_root(&directory);
        let (_source, _outside) = populated_install_tree(&control);
        control
            .stage_install_tree_for_purge(PURGE_TEST_INSTALL_ID)
            .expect("stage");
        let relative = PathBuf::from("purge")
            .join(PURGE_TEST_INSTALL_ID)
            .join("run.lock");
        assert_eq!(
            control
                .audit_and_remove_install_tree_with_hook(PURGE_TEST_INSTALL_ID, || {
                    if !control.remove_regular_file(&relative)? {
                        return Err(StorageError::new(
                            StorageErrorCode::IdentityChanged,
                            StorageOperation::AuditPurgeTree,
                        ));
                    }
                    control.create_protected_file(&relative, b"")
                })
                .expect_err("replacement between audit and deletion")
                .code(),
            StorageErrorCode::IdentityChanged
        );
        assert!(control.path().join(&relative).exists());
        assert!(
            control
                .path()
                .join("purge")
                .join(PURGE_TEST_INSTALL_ID)
                .join(r"data\blobs\nested\result.bin")
                .exists(),
            "second audit failed before any recursive deletion"
        );
    }

    #[test]
    fn purge_tree_api_rejects_noncanonical_install_identity_before_access() {
        let directory = root();
        let control = protected_control_root(&directory);
        for invalid in [
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdeg",
            r"..\0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(
                control
                    .classify_install_purge_tree(invalid)
                    .expect_err("canonical lower-hex32 only")
                    .code(),
                StorageErrorCode::InvalidPath
            );
        }
    }

    #[test]
    fn stable_control_enumeration_uses_exact_held_install_lock_capability() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"slots\stable\unknown-directory"))
            .expect("slot directories");
        control
            .create_protected_file(Path::new(r"slots\stable\install.json"), b"record")
            .expect("record");
        control
            .create_protected_file(
                Path::new(r"slots\stable\install.0123456789abcdef.new"),
                b"stage",
            )
            .expect("stage");
        let lock = control
            .acquire_lifetime_lock(Path::new(r"slots\stable\install.lock"))
            .expect("install lock");
        let entries = control
            .enumerate_stable_control_directory(&lock)
            .expect("unfiltered enumeration with held capability");
        assert_eq!(entries.len(), 4);
        let by_name = entries
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            by_name[&OsString::from("install.json")].contents.as_deref(),
            Some(b"record".as_slice())
        );
        assert_eq!(
            by_name[&OsString::from("install.lock")].contents.as_deref(),
            Some([].as_slice())
        );
        assert_eq!(
            by_name[&OsString::from("unknown-directory")].kind,
            ControlDirectoryEntryKind::Directory
        );

        drop(lock);
        let wrong_lock = control
            .acquire_lifetime_lock(Path::new(r"slots\stable\other.lock"))
            .expect("wrong held capability");
        assert_eq!(
            control
                .enumerate_stable_control_directory(&wrong_lock)
                .expect_err("name alone cannot forge install lock")
                .code(),
            StorageErrorCode::IdentityChanged
        );
    }

    #[test]
    fn purge_controller_containment_is_component_aware_and_case_insensitive() {
        assert!(path_is_same_or_descendant(
            Path::new(r"c:\USERS\Example\Product\bin\mesh.exe"),
            Path::new(r"C:\Users\example\product")
        ));
        assert!(path_is_same_or_descendant(
            Path::new(r"c:\users\example\product"),
            Path::new(r"C:\Users\Example\Product")
        ));
        assert!(!path_is_same_or_descendant(
            Path::new(r"C:\Users\Example\Product-cache\mesh.exe"),
            Path::new(r"C:\Users\Example\Product")
        ));
        let directory = root();
        let control = protected_control_root(&directory);
        assert!(
            control
                .validate_current_executable_outside_control_root()
                .expect("test executable is outside temp product root")
                .is_absolute()
        );
    }

    #[test]
    fn clean_record_absence_accepts_only_empty_structural_roots_and_held_lock() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"slots\stable"))
            .expect("slot structure");
        control
            .create_relative_directories(Path::new("installs"))
            .expect("empty installs");
        control
            .create_relative_directories(Path::new("purge"))
            .expect("empty purge");
        let lock = control
            .acquire_lifetime_lock(Path::new(r"slots\stable\install.lock"))
            .expect("held install lock");
        assert_eq!(
            control
                .verify_clean_install_purge_absence(&lock)
                .expect("clean absence"),
            CleanPurgeAbsenceReport {
                installs_directory_present: true,
                purge_directory_present: true,
            }
        );

        control
            .create_relative_directories(Path::new(r"installs\foreign-install"))
            .expect("foreign identity-bearing child");
        assert_eq!(
            control
                .verify_clean_install_purge_absence(&lock)
                .expect_err("foreign child must block already-absent success")
                .code(),
            StorageErrorCode::UnexpectedEntry
        );
        assert!(control.path().join(r"installs\foreign-install").exists());
    }

    #[test]
    fn clean_record_absence_rejects_unknown_slot_and_acl_drift_without_mutation() {
        let directory = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"slots\stable\unknown"))
            .expect("unknown slot child");
        control
            .create_relative_directories(Path::new("purge"))
            .expect("purge structure");
        let lock = control
            .acquire_lifetime_lock(Path::new(r"slots\stable\install.lock"))
            .expect("held install lock");
        assert_eq!(
            control
                .verify_clean_install_purge_absence(&lock)
                .expect_err("unknown stable child")
                .code(),
            StorageErrorCode::UnexpectedEntry
        );
        fs::remove_dir(control.path().join(r"slots\stable\unknown"))
            .expect("remove test-only unknown directory");
        let user = current_user_sid().expect("user SID");
        let everyone = well_known_sid(WinWorldSid).expect("world SID");
        let sids = [
            user.as_ptr().cast_mut().cast(),
            everyone.as_ptr().cast_mut().cast(),
        ];
        replace_test_dacl(
            &control.path().join("purge"),
            &sids,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        );
        assert_eq!(
            control
                .verify_clean_install_purge_absence(&lock)
                .expect_err("purge ACL drift")
                .code(),
            StorageErrorCode::InsecureAcl
        );
        assert!(control.path().join("purge").exists());
    }

    #[test]
    fn clean_record_absence_rejects_reparse_structural_root_when_available() {
        let directory = root();
        let outside = root();
        let control = protected_control_root(&directory);
        control
            .create_relative_directories(Path::new(r"slots\stable"))
            .expect("slot structure");
        let lock = control
            .acquire_lifetime_lock(Path::new(r"slots\stable\install.lock"))
            .expect("held install lock");
        let purge = control.path().join("purge");
        if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &purge) {
            eprintln!("skipped structural reparse fixture: {error}");
            return;
        }
        assert_eq!(
            control
                .verify_clean_install_purge_absence(&lock)
                .expect_err("reparse structural root")
                .code(),
            StorageErrorCode::ReparsePoint
        );
        assert!(outside.path().exists());
        assert!(purge.exists());
    }
}
