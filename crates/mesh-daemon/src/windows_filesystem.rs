//! Production durable-filesystem adapter for the validated Windows data root.
//!
//! Every operation is rooted in one canonical [`mesh_win32::ValidatedDataRoot`].
//! Absolute paths supplied by storage are accepted only when they name that
//! exact root or a lexical descendant; the Win32 boundary then revalidates the
//! live root and every existing component before touching the filesystem.

use std::{
    io,
    path::{Path, PathBuf},
};

use mesh_win32::{StorageError, StorageErrorCode, ValidatedDataRoot};

use crate::storage::DurableFilesystem;

const STORAGE_MODE: &str = "WINDOWS_LOCAL_NTFS_VALIDATED";

/// A production filesystem capability bound to one canonical local NTFS root.
#[derive(Debug)]
pub(crate) struct WindowsFilesystem {
    root: ValidatedDataRoot,
}

impl WindowsFilesystem {
    /// Validate and retain exactly one canonical data root.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the root is not the exact protected local
    /// NTFS directory contract or an existing descendant is a reparse point.
    pub(crate) fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = mesh_win32::validate_data_root(root.as_ref()).map_err(to_io_error)?;
        // Refuse an existing reparse point anywhere below the root before
        // SQLite opens a database or sidecar through a caller-owned path.
        root.allocated_tree_bytes().map_err(to_io_error)?;
        Ok(Self { root })
    }

    /// The exact canonical root retained by this capability.
    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        self.root.path()
    }

    fn live_root(&self) -> io::Result<ValidatedDataRoot> {
        let live = mesh_win32::validate_data_root(self.root.path()).map_err(to_io_error)?;
        if live.path() != self.root.path() {
            return Err(path_mismatch());
        }
        Ok(live)
    }

    fn require_exact_root(&self, path: &Path) -> io::Result<ValidatedDataRoot> {
        if path != self.root.path() {
            return Err(path_mismatch());
        }
        self.live_root()
    }

    fn descendant_relative(&self, path: &Path) -> io::Result<PathBuf> {
        let relative = path
            .strip_prefix(self.root.path())
            .map_err(|_| path_mismatch())?;
        if relative.as_os_str().is_empty() {
            return Err(path_mismatch());
        }
        Ok(relative.to_path_buf())
    }

    fn directory_relative(&self, path: &Path) -> io::Result<Option<PathBuf>> {
        if path == self.root.path() {
            return Ok(None);
        }
        self.descendant_relative(path).map(Some)
    }
}

impl DurableFilesystem for WindowsFilesystem {
    fn validate_data_root(&self, root: &Path) -> io::Result<()> {
        let live = self.require_exact_root(root)?;
        // This is deliberately a full startup scan. It rejects reparse points
        // in existing descendants before rusqlite is allowed to open a file.
        live.allocated_tree_bytes().map_err(to_io_error)?;
        Ok(())
    }

    fn storage_mode(&self) -> &'static str {
        STORAGE_MODE
    }

    fn create_relative_directories(&self, path: &Path) -> io::Result<()> {
        let relative = self.directory_relative(path)?;
        let live = self.live_root()?;
        if let Some(relative) = relative {
            live.validate_relative_path_security(&relative)
                .map_err(to_io_error)?;
            live.create_relative_directories(&relative)
                .map_err(to_io_error)?;
            live.validate_relative_path_security(&relative)
                .map_err(to_io_error)?;
        }
        Ok(())
    }

    fn allocated_bytes(&self, root: &Path) -> io::Result<u64> {
        self.require_exact_root(root)?
            .allocated_tree_bytes()
            .map_err(to_io_error)
    }

    fn free_bytes(&self, root: &Path) -> io::Result<u64> {
        self.require_exact_root(root)?
            .volume_free_bytes()
            .map_err(to_io_error)
    }

    fn create_reserve(&self, path: &Path, bytes: u64) -> io::Result<()> {
        let relative = self.descendant_relative(path)?;
        let live = self.live_root()?;
        live.validate_relative_path_security(&relative)
            .map_err(to_io_error)?;
        live.create_flushed_zero_file(&relative, bytes)
            .map_err(to_io_error)?;
        live.validate_relative_path_security(&relative)
            .map_err(to_io_error)
    }

    fn release_reserve(&self, path: &Path) -> io::Result<()> {
        let relative = self.descendant_relative(path)?;
        let parent = path.parent().ok_or_else(path_mismatch)?;
        let parent_relative = self.directory_relative(parent)?;
        let live = self.live_root()?;
        live.validate_relative_path_security(&relative)
            .map_err(to_io_error)?;
        if live.remove_regular_file(&relative).map_err(to_io_error)? {
            if let Some(parent_relative) = parent_relative.as_deref() {
                live.validate_relative_path_security(parent_relative)
                    .map_err(to_io_error)?;
            }
            optional_directory_sync(
                live.sync_directory(parent_relative.as_deref().unwrap_or(Path::new(""))),
            )?;
        }
        Ok(())
    }

    fn atomic_publish(&self, staged: &Path, destination: &Path) -> io::Result<()> {
        let staged_relative = self.descendant_relative(staged)?;
        let destination_relative = self.descendant_relative(destination)?;
        let live = self.live_root()?;
        live.validate_relative_path_security(&staged_relative)
            .map_err(to_io_error)?;
        live.validate_relative_path_security(&destination_relative)
            .map_err(to_io_error)?;
        live.atomic_replace(&staged_relative, &destination_relative)
            .map_err(to_io_error)?;
        live.validate_relative_path_security(&destination_relative)
            .map_err(to_io_error)
    }

    fn sync_parent(&self, parent: &Path) -> io::Result<()> {
        let relative = self.directory_relative(parent)?;
        let live = self.live_root()?;
        if let Some(relative) = relative.as_deref() {
            live.validate_relative_path_security(relative)
                .map_err(to_io_error)?;
        }
        optional_directory_sync(live.sync_directory(relative.as_deref().unwrap_or(Path::new(""))))
    }
}

fn optional_directory_sync(result: Result<(), StorageError>) -> io::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.code() == StorageErrorCode::DirectorySyncUnsupported => Ok(()),
        Err(error) => Err(to_io_error(error)),
    }
}

fn path_mismatch() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "path does not belong to the validated data-root capability",
    )
}

fn to_io_error(error: StorageError) -> io::Error {
    // Directory-handle flushing is not a documented Windows operation. Keep
    // that typed boundary result even when the host reports access denied or
    // invalid handle, so callers do not mistake it for ACL drift.
    if error.code() == StorageErrorCode::DirectorySyncUnsupported {
        return io::Error::new(io::ErrorKind::Unsupported, error);
    }
    if let Some(raw) = error.os_code().and_then(|code| i32::try_from(code).ok()) {
        return io::Error::from_raw_os_error(raw);
    }
    let kind = match error.code() {
        StorageErrorCode::UnsupportedPlatform
        | StorageErrorCode::NotFixedVolume
        | StorageErrorCode::NotNtfsVolume => io::ErrorKind::Unsupported,
        StorageErrorCode::InvalidPath | StorageErrorCode::NotRegularFile => {
            io::ErrorKind::InvalidInput
        }
        StorageErrorCode::PathEscapesRoot
        | StorageErrorCode::ReparsePoint
        | StorageErrorCode::InsecureAcl
        | StorageErrorCode::DifferentVolume => io::ErrorKind::PermissionDenied,
        StorageErrorCode::NotFound => io::ErrorKind::NotFound,
        StorageErrorCode::NotDirectory => io::ErrorKind::NotADirectory,
        StorageErrorCode::AlreadyExists => io::ErrorKind::AlreadyExists,
        StorageErrorCode::SparseFile
        | StorageErrorCode::CompressedFile
        | StorageErrorCode::PublicationVerificationFailed
        | StorageErrorCode::DigestMismatch
        | StorageErrorCode::InvalidProtectedKey => io::ErrorKind::InvalidData,
        StorageErrorCode::InsufficientAllocation => io::ErrorKind::StorageFull,
        StorageErrorCode::SizeOverflow | StorageErrorCode::TooLarge => io::ErrorKind::FileTooLarge,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write as _, sync::Arc};

    use rusqlite::Connection;

    use super::*;
    use crate::{storage::Storage, writer::WriterHandle};

    fn protected_root() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary data root");
        mesh_win32::protect_data_root(directory.path()).expect("protect data root");
        directory
    }

    #[test]
    fn production_open_records_exact_windows_storage_mode() {
        let directory = protected_root();
        let writer =
            WriterHandle::start_windows(directory.path().to_path_buf(), "install", 1, None)
                .expect("start production writer");
        writer.shutdown().expect("shutdown writer");
        let connection = Connection::open(directory.path().join("mesh.sqlite3"))
            .expect("open initialized database");
        let mode: String = connection
            .query_row(
                "SELECT storage_mode FROM storage_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("read storage mode");
        assert_eq!(mode, STORAGE_MODE);
        for relative in ["blobs/.staging", "blobs/sha256", "backups"] {
            assert!(directory.path().join(relative).is_dir());
        }
    }

    #[test]
    fn production_writer_publishes_a_blob_and_reopens_it() {
        let directory = protected_root();
        let writer =
            WriterHandle::start_windows(directory.path().to_path_buf(), "install", 1, None)
                .expect("start production writer");
        let digest = writer
            .publish_blob(b"published through the Windows adapter".to_vec(), 2)
            .expect("publish blob");
        writer.shutdown().expect("shutdown first writer");

        let reopened =
            WriterHandle::start_windows(directory.path().to_path_buf(), "install", 3, None)
                .expect("reopen production writer");
        assert_eq!(
            reopened
                .publish_blob(b"published through the Windows adapter".to_vec(), 4)
                .expect("verify existing published blob"),
            digest
        );
        reopened.shutdown().expect("shutdown reopened writer");
        assert!(
            directory
                .path()
                .join("blobs/sha256")
                .join(&digest[0..2])
                .join(&digest[2..4])
                .join(digest)
                .is_file()
        );
    }

    #[test]
    fn reserve_is_create_new_allocated_and_released_exactly() {
        let directory = protected_root();
        let filesystem = WindowsFilesystem::new(directory.path()).expect("validated filesystem");
        let reserve = filesystem.root().join("critical.reserve");
        filesystem
            .create_reserve(&reserve, 8192)
            .expect("create reserve");
        assert_eq!(
            fs::metadata(&reserve).expect("reserve metadata").len(),
            8192
        );
        assert!(
            filesystem
                .allocated_bytes(filesystem.root())
                .expect("measure allocated reserve")
                >= 8192
        );
        assert_eq!(
            filesystem
                .create_reserve(&reserve, 8192)
                .expect_err("reserve is create-new")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        if let Err(error) = filesystem.release_reserve(&reserve) {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        }
        assert!(!reserve.exists());
        filesystem
            .release_reserve(&reserve)
            .expect("missing reserve is idempotent");
    }

    #[test]
    fn publish_replaces_only_guarded_same_root_paths() {
        let directory = protected_root();
        let filesystem = WindowsFilesystem::new(directory.path()).expect("validated filesystem");
        let destination = filesystem.root().join("final");
        let staged = filesystem.root().join("staged");
        let mut first = fs::File::create(&staged).expect("first staged fixture");
        first.write_all(b"old").expect("write first stage");
        first.sync_all().expect("flush first stage");
        drop(first);
        filesystem
            .atomic_publish(&staged, &destination)
            .expect("write-through initial publish");
        assert_eq!(fs::read(&destination).expect("first publish"), b"old");

        let mut replacement = fs::File::create(&staged).expect("replacement fixture");
        replacement.write_all(b"new").expect("write replacement");
        replacement.sync_all().expect("flush replacement");
        drop(replacement);
        filesystem
            .atomic_publish(&staged, &destination)
            .expect("write-through replace");
        assert_eq!(fs::read(destination).expect("published bytes"), b"new");
        assert!(!staged.exists());
    }

    #[test]
    fn rejects_mismatched_root_and_descendant_reparse_when_available() {
        let directory = protected_root();
        let other = protected_root();
        let filesystem =
            Arc::new(WindowsFilesystem::new(directory.path()).expect("validated filesystem"));
        assert_eq!(
            filesystem
                .create_relative_directories(&directory.path().join("safe/../escape"))
                .expect_err("parent component escapes guarded descendant")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            filesystem
                .create_relative_directories(Path::new("relative"))
                .expect_err("caller cwd is never consulted")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            filesystem
                .allocated_bytes(other.path())
                .expect_err("alternate root")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(
            Storage::open_with_filesystem(other.path(), "install", 1, filesystem, None,).is_err()
        );

        let outside = tempfile::tempdir().expect("outside directory");
        let link = directory.path().join("linked");
        if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &link) {
            eprintln!("skipped reparse assertion: cannot create Windows symlink ({error})");
            return;
        }
        assert_eq!(
            WindowsFilesystem::new(directory.path())
                .expect_err("startup scan rejects descendant reparse")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn storage_full_os_code_is_preserved_for_emergency_classification() {
        let error = to_io_error(StorageError::with_os_code(
            StorageErrorCode::Io,
            mesh_win32::StorageOperation::WriteFile,
            112,
        ));
        assert_eq!(error.raw_os_error(), Some(112));
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert!(Storage::is_storage_pressure(
            &crate::storage::StorageError::Io(error)
        ));
    }

    #[test]
    fn only_the_exact_directory_sync_capability_error_is_nonfatal() {
        assert!(
            optional_directory_sync(Err(StorageError::with_os_code(
                StorageErrorCode::DirectorySyncUnsupported,
                mesh_win32::StorageOperation::SyncDirectory,
                5,
            )))
            .is_ok()
        );

        let other = optional_directory_sync(Err(StorageError::with_os_code(
            StorageErrorCode::Io,
            mesh_win32::StorageOperation::SyncDirectory,
            5,
        )))
        .expect_err("ordinary sync errors remain fatal");
        assert_eq!(other.raw_os_error(), Some(5));
    }
}
