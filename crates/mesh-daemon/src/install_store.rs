//! Atomic persistence for the one stable installation record.
//!
//! The only public production constructor fixes the record beneath the
//! current user's audited product control root.  Callers cannot choose the
//! slot, file name, or an alternate environment-derived root.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use mesh_win32::{
    ControlDirectoryEntryKind, ExclusiveFileLock, NativeError, NativeErrorCode, StorageError,
    StorageErrorCode, ValidatedControlRoot, open_or_create_product_control_root,
};
use rand::Rng;
use thiserror::Error;

use crate::install_record::InstallState;
use crate::install_record::{InstallRecord, InstallRecordStore};

const SLOT_DIRECTORY: &str = r"slots\stable";
const RECORD_PATH: &str = r"slots\stable\install.json";
/// The non-deleted cross-process purge anchor. The purge controller acquires
/// this exact existing lock for clean-absence verification without creating
/// any file or directory.
pub const LOCK_PATH: &str = r"slots\stable\install.lock";
const STAGE_ATTEMPTS: usize = 8;

/// A protected stable-slot staging file observed by the audited native
/// directory-enumeration boundary.  The store validates both its exact name and
/// serialized record before it can be removed during purge finalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurgeStageEntry {
    relative_path: PathBuf,
    serialized_record: Vec<u8>,
}

/// Immediate protected-directory entry classification returned by the audited
/// audited stable-slot enumeration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurgeSlotEntryKind {
    RegularFile,
    Directory,
    ReparsePoint,
    Other,
}

/// One immediate `slots\\stable` directory entry.  The enumerator reports
/// every entry, including malformed names and non-regular entries, so the
/// record store—not an adapter—owns the finalization allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurgeSlotEntry {
    relative_path: PathBuf,
    kind: PurgeSlotEntryKind,
    bytes: Option<Vec<u8>>,
}

impl PurgeSlotEntry {
    /// Captures one entry reported by the protected enumeration boundary.
    #[must_use]
    pub fn new(relative_path: PathBuf, kind: PurgeSlotEntryKind, bytes: Option<Vec<u8>>) -> Self {
        Self {
            relative_path,
            kind,
            bytes,
        }
    }
}

impl PurgeStageEntry {
    /// Constructs one observed stable-slot staging sibling.
    ///
    /// The caller must have obtained the bytes from a protected, non-reparse
    /// regular-file enumeration.  The Win32 enumeration seam is intentionally
    /// not present yet; this narrow value boundary keeps that future work out
    /// of the pure lifecycle/store layer.
    #[must_use]
    pub fn new(relative_path: PathBuf, serialized_record: Vec<u8>) -> Self {
        Self {
            relative_path,
            serialized_record,
        }
    }
}

/// Injected protected-directory enumeration for record-last purge finalization.
///
/// Its production implementation is [`NativeStableSlotEnumerator`], backed by
/// handle-based enumeration of exactly `slots\\stable`, refusing reparse
/// points and returning every immediate `slots\\stable` entry with exact bytes
/// for the record and every candidate staging regular file.
/// It must not filter malformed or foreign entries: the store needs those to
/// fail closed.
pub trait PurgeStageEnumerator {
    /// Returns every immediate stable-slot entry currently present.
    ///
    /// The exact no-share `install.lock` capability lets the native enumerator
    /// identify that already-open entry by handle/file ID. It must not reopen
    /// the lock by name or weaken its share mode.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe integrity, access, or storage error when the
    /// audited native enumeration cannot complete.
    fn enumerate_stable_slot_entries(
        &self,
        held_install_lock: &ExclusiveFileLock,
    ) -> Result<Vec<PurgeSlotEntry>, InstallStoreError>;
}

/// Production [`PurgeStageEnumerator`] backed by the audited Win32 handle-based
/// enumeration of the exact protected `slots\stable` directory.
///
/// The native boundary returns every unfiltered immediate entry with
/// identity-checked bytes for regular files and never follows reparse points.
/// This adapter only translates the trusted native report into the store's
/// value types; it owns no filesystem policy itself.
pub struct NativeStableSlotEnumerator<'root> {
    root: &'root ValidatedControlRoot,
}

impl<'root> NativeStableSlotEnumerator<'root> {
    /// Binds enumeration to one validated current-user control root.
    #[must_use]
    pub fn new(root: &'root ValidatedControlRoot) -> Self {
        Self { root }
    }
}

impl PurgeStageEnumerator for NativeStableSlotEnumerator<'_> {
    fn enumerate_stable_slot_entries(
        &self,
        held_install_lock: &ExclusiveFileLock,
    ) -> Result<Vec<PurgeSlotEntry>, InstallStoreError> {
        let entries = self
            .root
            .enumerate_stable_control_directory(held_install_lock)
            .map_err(map_storage_error)?;
        entries
            .into_iter()
            .map(|entry| {
                let kind = if entry.reparse_point {
                    PurgeSlotEntryKind::ReparsePoint
                } else {
                    match entry.kind {
                        ControlDirectoryEntryKind::Directory => PurgeSlotEntryKind::Directory,
                        ControlDirectoryEntryKind::RegularFile => PurgeSlotEntryKind::RegularFile,
                    }
                };
                Ok(PurgeSlotEntry::new(
                    Path::new(SLOT_DIRECTORY).join(&entry.name),
                    kind,
                    entry.contents,
                ))
            })
            .collect()
    }
}

/// Exact record snapshot captured under the persistent setup/purge fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallRecordSnapshot {
    record: InstallRecord,
    serialized_record: Vec<u8>,
}

impl InstallRecordSnapshot {
    #[must_use]
    pub fn record(&self) -> &InstallRecord {
        &self.record
    }

    #[must_use]
    pub fn serialized_record(&self) -> &[u8] {
        &self.serialized_record
    }
}

/// Redaction-safe errors from the stable installation-record store.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InstallStoreError {
    #[error("installation record compare-and-swap conflict")]
    CompareAndSwapConflict,
    #[error("installation record is invalid")]
    InvalidRecord,
    #[error("installation record storage operation failed")]
    Storage,
    #[error("installation record lock operation failed")]
    Lock,
    #[error("installation record access was denied")]
    AccessDenied,
    #[error("installation record integrity verification failed")]
    Integrity,
    #[error("ordinary installation traffic is not admitted")]
    OrdinaryTrafficUnavailable,
    #[error("ordinary installation traffic admission is busy")]
    AdmissionBusy,
    #[error("installation record changed after traffic admission")]
    AdmissionChanged,
    #[error("installation record purge precondition was not met")]
    PurgePrecondition,
    #[error("installation record purge staging evidence drifted")]
    PurgeStageDrift,
}

/// Persisted store for the literal `slots\\stable\\install.json` record.
pub struct StableInstallRecordStore {
    root: ValidatedControlRoot,
}

/// Scoped admission for creating one stable ordinary-traffic child.
///
/// The current native boundary exposes only a no-share file lock. Therefore
/// these guards conservatively serialize ordinary bootstrap processes across
/// the installation, while sharing the exact same lock with setup/remove CAS.
/// Holding this value keeps the admission fence live; dropping it releases the
/// fence. Call [`Self::revalidate_for_spawn`] immediately before process
/// creation so out-of-protocol record replacement is detected fail-closed.
pub struct OrdinaryTrafficGuard<'store> {
    store: &'store StableInstallRecordStore,
    record: InstallRecord,
    serialized_record: Vec<u8>,
    _lock: ExclusiveFileLock,
}

/// Scoped admission for forwarding a public control command to the retained
/// runtime.
///
/// Unlike ordinary bridge traffic, control convergence remains useful while
/// removal is in progress or after runtime data has been retained. The guard
/// therefore admits any complete, valid `ACTIVE`, `REMOVING`, or `RETAINED`
/// record. The command-specific lifecycle allowlist is enforced by the narrow
/// control-mode boundary in `windows_install`.
pub struct RetainedControlGuard<'store> {
    store: &'store StableInstallRecordStore,
    record: InstallRecord,
    serialized_record: Vec<u8>,
    _lock: ExclusiveFileLock,
}

/// Exclusive setup convergence fence for the stable installation slot.
///
/// Holding this guard prevents setup, removal CAS, and ordinary child admission
/// from interleaving with the complete verify/effect/checkpoint sequence. The
/// guard exposes only record operations which reuse the already-held lock.
pub struct SetupConvergenceGuard<'store> {
    store: &'store StableInstallRecordStore,
    lock: ExclusiveFileLock,
}

impl SetupConvergenceGuard<'_> {
    /// Reads the current record while the stable-slot setup fence is held.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe integrity, access, or storage error.
    pub fn load(&self) -> Result<Option<InstallRecord>, InstallStoreError> {
        self.store
            .read_current()
            .map(|current| current.map(|(record, _)| record))
    }

    /// Reads the protected record and its exact durable serialization while the
    /// caller owns `install.lock`. This is the only supported source for the
    /// expected bytes consumed by record-last purge deletion.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe integrity, access, or storage error.
    pub fn load_with_bytes(&self) -> Result<Option<InstallRecordSnapshot>, InstallStoreError> {
        self.store.read_current().map(|current| {
            current.map(|(record, serialized_record)| InstallRecordSnapshot {
                record,
                serialized_record,
            })
        })
    }

    /// Publishes one strict successor while reusing the held setup fence.
    ///
    /// # Errors
    ///
    /// Returns a typed conflict, validation, integrity, access, or storage
    /// error. An error never weakens or releases the held fence.
    pub fn compare_and_swap(
        &self,
        expected_revision: u64,
        next: &InstallRecord,
    ) -> Result<(), InstallStoreError> {
        self.store.compare_and_swap_locked(expected_revision, next)
    }

    /// Removes the last remaining installation identity after an audited purge.
    ///
    /// This is intentionally available only while the caller owns the durable
    /// `install.lock` through this guard.  It never creates a slot, accepts a
    /// caller-selected record path, or permits a successor to `PURGING`.
    /// The caller supplies the exact bytes captured after publishing `PURGING`;
    /// those bytes and the decoded record are re-read immediately before the
    /// protected record is deleted.
    ///
    /// Before deletion all matching `install.<hex16>.new` siblings are
    /// enumerated. Any malformed, foreign, or non-lineage stage blocks final
    /// identity removal. Valid same-lineage stages are removed only while this
    /// guard remains live.
    ///
    /// # Errors
    ///
    /// Returns a typed purge-precondition, stage-drift, integrity, access, or
    /// storage error without deleting the record when any check fails.
    pub fn compare_and_delete_purging<E: PurgeStageEnumerator>(
        &self,
        expected_revision: u64,
        expected_serialized_record: &[u8],
        stages: &E,
    ) -> Result<(), InstallStoreError> {
        self.store.compare_and_delete_purging_locked(
            expected_revision,
            expected_serialized_record,
            stages,
            &self.lock,
        )
    }
}

impl OrdinaryTrafficGuard<'_> {
    /// Returns the exact complete `ACTIVE` record admitted under the guard.
    #[must_use]
    pub fn record(&self) -> &InstallRecord {
        &self.record
    }

    /// Re-reads and byte-compares the record while the cross-process fence is
    /// still held. This is the last check at the stable-child spawn boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed admission, integrity, access, or storage error. A
    /// changed/missing record never degrades to a boolean or stale snapshot.
    pub fn revalidate_for_spawn(&self) -> Result<&InstallRecord, InstallStoreError> {
        match self.store.read_current()? {
            Some((record, bytes))
                if record == self.record
                    && bytes == self.serialized_record
                    && record.admits_ordinary_traffic() =>
            {
                Ok(&self.record)
            }
            Some(_) | None => Err(InstallStoreError::AdmissionChanged),
        }
    }
}

impl RetainedControlGuard<'_> {
    /// Returns the exact complete retained-runtime record admitted under the
    /// shared installation fence.
    #[must_use]
    pub fn record(&self) -> &InstallRecord {
        &self.record
    }

    /// Re-reads and byte-compares the protected record at the process-creation
    /// boundary while the shared installation fence is still held.
    ///
    /// # Errors
    ///
    /// Returns a typed admission, integrity, access, or storage error. Any
    /// serialized-byte drift fails closed even when the decoded value matches.
    pub fn revalidate_for_spawn(&self) -> Result<&InstallRecord, InstallStoreError> {
        match self.store.read_current()? {
            Some((record, bytes))
                if record == self.record
                    && bytes == self.serialized_record
                    && admits_retained_control(&record) =>
            {
                Ok(&self.record)
            }
            Some(_) | None => Err(InstallStoreError::AdmissionChanged),
        }
    }
}

impl StableInstallRecordStore {
    /// Opens the literal per-user product control root selected by the Win32
    /// boundary. No caller path, environment variable, or working directory is
    /// consulted.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe storage error when the audited control root
    /// cannot be opened or prepared.
    pub fn open() -> Result<Self, InstallStoreError> {
        let root = open_or_create_product_control_root().map_err(map_storage_error)?;
        Self::from_validated_control_root(root)
    }

    /// Builds a store from an already validated root.
    ///
    /// This crate-private boundary is intended for tests and internal dependency
    /// injection. External production callers can only use [`Self::open`], so
    /// the Known Folder root cannot be replaced by a caller-selected path.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe storage error if the fixed slot cannot be
    /// created under the supplied validated root.
    pub(crate) fn from_validated_control_root(
        root: ValidatedControlRoot,
    ) -> Result<Self, InstallStoreError> {
        root.create_relative_directories(Path::new(SLOT_DIRECTORY))
            .map_err(map_storage_error)?;
        Ok(Self { root })
    }

    /// Acquires a scoped, fail-closed ordinary-traffic admission guard.
    ///
    /// The guard owns the same persistent no-share lock used by installation
    /// CAS, so setup/remove cannot change lifecycle state until the caller has
    /// created the stable child and drops the guard.
    ///
    /// # Errors
    ///
    /// Returns a typed error for contention, access denial, invalid state,
    /// integrity failure, or native storage failure.
    pub fn acquire_ordinary_traffic_guard(
        &self,
    ) -> Result<OrdinaryTrafficGuard<'_>, InstallStoreError> {
        let lock = self
            .root
            .acquire_lifetime_lock(Path::new(LOCK_PATH))
            .map_err(map_admission_lock_error)?;
        let Some((record, serialized_record)) = self.read_current()? else {
            return Err(InstallStoreError::OrdinaryTrafficUnavailable);
        };
        if !record.admits_ordinary_traffic() {
            return Err(InstallStoreError::OrdinaryTrafficUnavailable);
        }
        Ok(OrdinaryTrafficGuard {
            store: self,
            record,
            serialized_record,
            _lock: lock,
        })
    }

    /// Acquires the shared persistent installation fence for one public
    /// cache-to-stable control handoff.
    ///
    /// The returned guard admits only complete `ACTIVE`, `REMOVING`, or
    /// `RETAINED` records and must remain alive through process creation.
    ///
    /// # Errors
    ///
    /// Returns a typed error for contention, access denial, invalid lifecycle,
    /// integrity failure, or native storage failure.
    pub fn acquire_retained_control_guard(
        &self,
    ) -> Result<RetainedControlGuard<'_>, InstallStoreError> {
        let lock = self
            .root
            .acquire_lifetime_lock(Path::new(LOCK_PATH))
            .map_err(map_admission_lock_error)?;
        let Some((record, serialized_record)) = self.read_current()? else {
            return Err(InstallStoreError::OrdinaryTrafficUnavailable);
        };
        if !admits_retained_control(&record) {
            return Err(InstallStoreError::OrdinaryTrafficUnavailable);
        }
        Ok(RetainedControlGuard {
            store: self,
            record,
            serialized_record,
            _lock: lock,
        })
    }

    /// Acquires the exclusive fence for one complete setup convergence run.
    ///
    /// The caller must keep the returned guard alive while validating retained
    /// evidence, creating external artifacts, and publishing every checkpoint.
    /// This prevents removal and ordinary child creation from crossing the
    /// verification-to-publication boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed busy, access, or native lock/storage error.
    pub fn acquire_setup_guard(&self) -> Result<SetupConvergenceGuard<'_>, InstallStoreError> {
        let lock = self
            .root
            .acquire_lifetime_lock(Path::new(LOCK_PATH))
            .map_err(map_setup_lock_error)?;
        Ok(SetupConvergenceGuard { store: self, lock })
    }

    fn read_current(&self) -> Result<Option<(InstallRecord, Vec<u8>)>, InstallStoreError> {
        let bytes = match self.root.read_protected_file(Path::new(RECORD_PATH)) {
            Ok(bytes) => bytes,
            Err(error) if error.code() == StorageErrorCode::NotFound => return Ok(None),
            Err(error) => return Err(map_storage_error(error)),
        };
        let record = decode_record(&bytes)?;
        Ok(Some((record, bytes)))
    }

    fn create_verified_stage(&self, bytes: &[u8]) -> Result<std::path::PathBuf, InstallStoreError> {
        self.create_verified_stage_with(bytes, stage_path)
    }

    fn create_verified_stage_with<F>(
        &self,
        bytes: &[u8],
        mut next_stage: F,
    ) -> Result<std::path::PathBuf, InstallStoreError>
    where
        F: FnMut() -> std::path::PathBuf,
    {
        for _ in 0..STAGE_ATTEMPTS {
            let stage = next_stage();
            match self.root.create_protected_file(&stage, bytes) {
                Ok(()) => {
                    let observed = self
                        .root
                        .read_protected_file(&stage)
                        .map_err(map_storage_error)?;
                    if observed != bytes || decode_record(&observed).is_err() {
                        let _ = self.root.remove_regular_file(&stage);
                        return Err(InstallStoreError::Integrity);
                    }
                    return Ok(stage);
                }
                Err(error) if error.code() == StorageErrorCode::AlreadyExists => {}
                Err(error) => return Err(map_storage_error(error)),
            }
        }
        Err(InstallStoreError::Storage)
    }

    fn sync_slot_directory(&self) -> Result<(), InstallStoreError> {
        match self.root.sync_directory(Path::new(SLOT_DIRECTORY)) {
            Ok(()) => Ok(()),
            // The Windows boundary deliberately reports unsupported directory
            // flushing as a typed condition. The store still performs the
            // attempt, but v0.1 makes no power-loss claim.
            Err(error) if error.code() == StorageErrorCode::DirectorySyncUnsupported => Ok(()),
            Err(error) => Err(map_storage_error(error)),
        }
    }

    fn compare_and_swap_locked(
        &self,
        expected_revision: u64,
        next: &InstallRecord,
    ) -> Result<(), InstallStoreError> {
        next.validate()
            .map_err(|_| InstallStoreError::InvalidRecord)?;

        let current = self.read_current()?;
        match current.as_ref() {
            None => {
                if expected_revision != 0 {
                    return Err(InstallStoreError::CompareAndSwapConflict);
                }
                next.validate_initial()
                    .map_err(|_| InstallStoreError::InvalidRecord)?;
            }
            Some((record, _)) => {
                if record.revision != expected_revision {
                    return Err(InstallStoreError::CompareAndSwapConflict);
                }
                let expected_next_revision = record
                    .revision
                    .checked_add(1)
                    .ok_or(InstallStoreError::InvalidRecord)?;
                if next.revision != expected_next_revision {
                    return Err(InstallStoreError::CompareAndSwapConflict);
                }
                record
                    .validate_successor(next)
                    .map_err(|_| InstallStoreError::InvalidRecord)?;
            }
        }

        let bytes = serde_json::to_vec(next).map_err(|_| InstallStoreError::InvalidRecord)?;
        if bytes.len() > mesh_win32::MAX_CONTROL_FILE_BYTES || decode_record(&bytes).is_err() {
            return Err(InstallStoreError::InvalidRecord);
        }
        let stage = self.create_verified_stage(&bytes)?;
        let publication = if current.is_some() {
            self.root.atomic_replace(&stage, Path::new(RECORD_PATH))
        } else {
            self.root.publish_no_replace(&stage, Path::new(RECORD_PATH))
        };
        if let Err(error) = publication {
            let _ = self.root.remove_regular_file(&stage);
            return Err(map_storage_error(error));
        }

        let result = self.read_current().and_then(|observed| match observed {
            Some((record, observed_bytes)) if record == *next && observed_bytes == bytes => Ok(()),
            _ => Err(InstallStoreError::Integrity),
        });
        if result.is_err() {
            // The stage was moved during publication, so this can only remove
            // a fresh collision-free staging file if a future boundary leaves
            // one behind. It can never delete the stable record.
            let _ = self.root.remove_regular_file(&stage);
        }
        result?;
        self.sync_slot_directory()
    }

    fn compare_and_delete_purging_locked<E: PurgeStageEnumerator>(
        &self,
        expected_revision: u64,
        expected_serialized_record: &[u8],
        stages: &E,
        held_install_lock: &ExclusiveFileLock,
    ) -> Result<(), InstallStoreError> {
        let Some((record, current_bytes)) = self.read_current()? else {
            return Err(InstallStoreError::PurgePrecondition);
        };
        if record.state != InstallState::Purging
            || record.revision != expected_revision
            || current_bytes != expected_serialized_record
        {
            return Err(InstallStoreError::PurgePrecondition);
        }

        let entries = stages.enumerate_stable_slot_entries(held_install_lock)?;
        let mut seen = HashSet::with_capacity(entries.len());
        let mut saw_record = false;
        let mut saw_lock = false;
        let mut stages = Vec::new();
        for entry in entries {
            if !seen.insert(entry.relative_path.clone()) {
                return Err(InstallStoreError::PurgeStageDrift);
            }
            if entry.relative_path == Path::new(RECORD_PATH) {
                if entry.kind != PurgeSlotEntryKind::RegularFile
                    || entry.bytes.as_deref() != Some(expected_serialized_record)
                {
                    return Err(InstallStoreError::PurgeStageDrift);
                }
                saw_record = true;
            } else if entry.relative_path == Path::new(LOCK_PATH) {
                if entry.kind != PurgeSlotEntryKind::RegularFile {
                    return Err(InstallStoreError::PurgeStageDrift);
                }
                saw_lock = true;
            } else if is_install_record_stage_path(&entry.relative_path) {
                if entry.kind != PurgeSlotEntryKind::RegularFile {
                    return Err(InstallStoreError::PurgeStageDrift);
                }
                let Some(bytes) = entry.bytes else {
                    return Err(InstallStoreError::PurgeStageDrift);
                };
                stages.push(PurgeStageEntry::new(entry.relative_path, bytes));
            } else {
                return Err(InstallStoreError::PurgeStageDrift);
            }
        }
        if !saw_record || !saw_lock {
            return Err(InstallStoreError::PurgeStageDrift);
        }
        for stage in &stages {
            validate_purge_stage(&record, expected_serialized_record, stage)?;
        }
        for stage in &stages {
            let removed = self
                .root
                .remove_regular_file(&stage.relative_path)
                .map_err(map_storage_error)?;
            if !removed {
                return Err(InstallStoreError::PurgeStageDrift);
            }
        }

        // Re-read after secondary identity cleanup.  This is deliberately an
        // exact serialized-byte comparison, not semantic equality: pretty
        // printing or replacement while a caller holds a stale guard is drift.
        let Some((rechecked, rechecked_bytes)) = self.read_current()? else {
            return Err(InstallStoreError::PurgePrecondition);
        };
        if rechecked != record || rechecked_bytes != expected_serialized_record {
            return Err(InstallStoreError::PurgePrecondition);
        }
        let removed = self
            .root
            .remove_regular_file(Path::new(RECORD_PATH))
            .map_err(map_storage_error)?;
        if !removed {
            return Err(InstallStoreError::PurgePrecondition);
        }
        self.sync_slot_directory()?;
        if self.read_current()?.is_some() {
            return Err(InstallStoreError::Integrity);
        }
        Ok(())
    }
}

fn admits_retained_control(record: &InstallRecord) -> bool {
    matches!(
        record.state,
        InstallState::Active | InstallState::Removing | InstallState::Retained
    ) && record.validate().is_ok()
        && record.is_active_complete()
}

impl InstallRecordStore for StableInstallRecordStore {
    type Error = InstallStoreError;

    fn load(&self) -> Result<Option<InstallRecord>, Self::Error> {
        self.read_current()
            .map(|current| current.map(|(record, _)| record))
    }

    fn compare_and_swap(
        &self,
        expected_revision: u64,
        next: &InstallRecord,
    ) -> Result<(), Self::Error> {
        let _lock = self
            .root
            .acquire_lifetime_lock(Path::new(LOCK_PATH))
            .map_err(map_cas_lock_error)?;
        self.compare_and_swap_locked(expected_revision, next)
    }
}

fn decode_record(bytes: &[u8]) -> Result<InstallRecord, InstallStoreError> {
    if bytes.len() > mesh_win32::MAX_CONTROL_FILE_BYTES {
        return Err(InstallStoreError::Integrity);
    }
    let record = serde_json::from_slice(bytes).map_err(|_| InstallStoreError::Integrity)?;
    Ok(record)
}

fn stage_path() -> std::path::PathBuf {
    let nonce = rand::rng().random::<u64>();
    Path::new(SLOT_DIRECTORY).join(format!("install.{nonce:016x}.new"))
}

fn is_install_record_stage_path(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if parent != Path::new(SLOT_DIRECTORY) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let Some(hex) = name
        .strip_prefix("install.")
        .and_then(|value| value.strip_suffix(".new"))
    else {
        return false;
    };
    hex.len() == 16
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_purge_stage(
    purging: &InstallRecord,
    expected_serialized_record: &[u8],
    stage: &PurgeStageEntry,
) -> Result<(), InstallStoreError> {
    if !is_install_record_stage_path(&stage.relative_path) {
        return Err(InstallStoreError::PurgeStageDrift);
    }
    let staged =
        decode_record(&stage.serialized_record).map_err(|_| InstallStoreError::PurgeStageDrift)?;
    if staged.install_id != purging.install_id
        || staged.consumer_id != purging.consumer_id
        || staged.created_at_us != purging.created_at_us
        || staged.revision > purging.revision
        || staged.updated_at_us > purging.updated_at_us
        || staged.product_relative_path != purging.product_relative_path
        || staged.data_relative_path != purging.data_relative_path
        || staged.data_schema_version != purging.data_schema_version
        || staged.protected_key != purging.protected_key
        || staged.runtime != purging.runtime
        || staged.scheduled_task != purging.scheduled_task
    {
        return Err(InstallStoreError::PurgeStageDrift);
    }
    // A same-revision stage can only be the exact final record staging file;
    // accepting another semantic shape here would permit a forged successor
    // that happens to share the stable IDs and evidence fields.
    if staged.revision == purging.revision && stage.serialized_record != expected_serialized_record
    {
        return Err(InstallStoreError::PurgeStageDrift);
    }
    Ok(())
}

fn map_storage_error(error: StorageError) -> InstallStoreError {
    match error.code() {
        StorageErrorCode::InvalidPath
        | StorageErrorCode::PathEscapesRoot
        | StorageErrorCode::ReparsePoint
        | StorageErrorCode::InsecureAcl
        | StorageErrorCode::NotFound
        | StorageErrorCode::NotDirectory
        | StorageErrorCode::NotRegularFile
        | StorageErrorCode::PublicationVerificationFailed
        | StorageErrorCode::DigestMismatch
        | StorageErrorCode::IdentityChanged
        | StorageErrorCode::UnexpectedEntry
        | StorageErrorCode::TraversalLimit
        | StorageErrorCode::TooLarge => InstallStoreError::Integrity,
        StorageErrorCode::AccessDenied => InstallStoreError::AccessDenied,
        StorageErrorCode::Io if error.os_code() == Some(5) => InstallStoreError::AccessDenied,
        _ => InstallStoreError::Storage,
    }
}

fn map_cas_lock_error(error: NativeError) -> InstallStoreError {
    match error.code() {
        NativeErrorCode::SingletonConflict => InstallStoreError::CompareAndSwapConflict,
        NativeErrorCode::AccessDenied | NativeErrorCode::SetupAccessDenied => {
            InstallStoreError::AccessDenied
        }
        _ => InstallStoreError::Lock,
    }
}

fn map_admission_lock_error(error: NativeError) -> InstallStoreError {
    match error.code() {
        NativeErrorCode::SingletonConflict => InstallStoreError::AdmissionBusy,
        NativeErrorCode::AccessDenied | NativeErrorCode::SetupAccessDenied => {
            InstallStoreError::AccessDenied
        }
        _ => InstallStoreError::Lock,
    }
}

fn map_setup_lock_error(error: NativeError) -> InstallStoreError {
    match error.code() {
        NativeErrorCode::SingletonConflict => InstallStoreError::AdmissionBusy,
        NativeErrorCode::AccessDenied | NativeErrorCode::SetupAccessDenied => {
            InstallStoreError::AccessDenied
        }
        _ => InstallStoreError::Lock,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use mesh_win32::{protect_control_root, validate_control_root};
    use tempfile::TempDir;

    use super::*;
    use crate::install_record::{
        InstallCheckpoint, InstallState, ProtectedKeyArtifact, RelativeWindowsPath,
        RuntimeArtifact, RuntimeArtifactFormat, ScheduledTaskEvidence, ScheduledTaskPath,
        Sha256Digest, SignerStatus, StableId,
    };

    const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";
    const CONSUMER_ID: &str = "fedcba9876543210fedcba9876543210";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn record(revision: u64, updated_at_us: i64) -> InstallRecord {
        InstallRecord {
            format_version: 1,
            install_id: StableId::new(INSTALL_ID).expect("fixture install id"),
            consumer_id: StableId::new(CONSUMER_ID).expect("fixture consumer id"),
            state: InstallState::Installing,
            revision,
            product_relative_path: Some(
                RelativeWindowsPath::new(format!("installs\\{INSTALL_ID}"))
                    .expect("fixture product path"),
            ),
            data_relative_path: None,
            data_schema_version: None,
            protected_key: None,
            runtime: None,
            scheduled_task: None,
            created_at_us: 10,
            updated_at_us,
        }
    }

    fn digest() -> Sha256Digest {
        Sha256Digest::new(DIGEST).expect("fixture digest")
    }

    fn active_record() -> InstallRecord {
        record(1, 10)
            .checkpoint(
                1,
                InstallCheckpoint {
                    protected_key: Some(ProtectedKeyArtifact {
                        relative_path: RelativeWindowsPath::new(format!(
                            "installs\\{INSTALL_ID}\\secrets\\endpoint-key.dpapi"
                        ))
                        .expect("fixture key path"),
                        sha256: digest(),
                    }),
                    ..InstallCheckpoint::default()
                },
                11,
            )
            .expect("key checkpoint")
            .checkpoint(
                2,
                InstallCheckpoint {
                    runtime: Some(RuntimeArtifact {
                        relative_path: RelativeWindowsPath::new(format!(
                            "installs\\{INSTALL_ID}\\bin\\{DIGEST}\\mesh-daemon.exe"
                        ))
                        .expect("fixture runtime path"),
                        sha256: digest(),
                        version: "0.1.0".into(),
                        signer_status: SignerStatus::UnsignedDevelopment,
                        artifact_format: RuntimeArtifactFormat::MeshDaemonExeV1,
                    }),
                    ..InstallCheckpoint::default()
                },
                12,
            )
            .expect("runtime checkpoint")
            .checkpoint(
                3,
                InstallCheckpoint {
                    data_relative_path: Some(
                        RelativeWindowsPath::new(format!("installs\\{INSTALL_ID}\\data"))
                            .expect("fixture data path"),
                    ),
                    data_schema_version: Some(1),
                    ..InstallCheckpoint::default()
                },
                13,
            )
            .expect("data checkpoint")
            .checkpoint(
                4,
                InstallCheckpoint {
                    scheduled_task: Some(ScheduledTaskEvidence {
                        task_path: ScheduledTaskPath::new("\\CodexAgentMesh-daemon-01234567")
                            .expect("fixture task path"),
                        definition_sha256: digest(),
                    }),
                    ..InstallCheckpoint::default()
                },
                14,
            )
            .expect("task checkpoint")
            .transition(5, InstallState::Active, 15)
            .expect("active transition")
    }

    fn publish_active(store: &StableInstallRecordStore) -> InstallRecord {
        let initial = record(1, 10);
        store
            .compare_and_swap(0, &initial)
            .expect("publish initial record");
        let active = active_record();
        let mut current = initial;
        for next in [
            active_record_at_revision(2),
            active_record_at_revision(3),
            active_record_at_revision(4),
            active_record_at_revision(5),
            active.clone(),
        ] {
            store
                .compare_and_swap(current.revision, &next)
                .expect("publish installation step");
            current = next;
        }
        active
    }

    fn active_record_at_revision(revision: u64) -> InstallRecord {
        let active = active_record();
        let mut current = record(1, 10);
        let checkpoints = [
            InstallCheckpoint {
                protected_key: active.protected_key.clone(),
                ..InstallCheckpoint::default()
            },
            InstallCheckpoint {
                runtime: active.runtime.clone(),
                ..InstallCheckpoint::default()
            },
            InstallCheckpoint {
                data_relative_path: active.data_relative_path.clone(),
                data_schema_version: active.data_schema_version,
                ..InstallCheckpoint::default()
            },
            InstallCheckpoint {
                scheduled_task: active.scheduled_task.clone(),
                ..InstallCheckpoint::default()
            },
        ];
        let checkpoint_count = usize::try_from(revision - 1).expect("fixture revision fits usize");
        for checkpoint in checkpoints.into_iter().take(checkpoint_count) {
            current = current
                .checkpoint(current.revision, checkpoint, current.updated_at_us + 1)
                .expect("fixture checkpoint");
        }
        current
    }

    struct FixtureStages {
        entries: Vec<PurgeSlotEntry>,
    }

    impl PurgeStageEnumerator for FixtureStages {
        fn enumerate_stable_slot_entries(
            &self,
            _held_install_lock: &ExclusiveFileLock,
        ) -> Result<Vec<PurgeSlotEntry>, InstallStoreError> {
            Ok(self.entries.clone())
        }
    }

    fn purging_record(active: &InstallRecord) -> InstallRecord {
        active
            .transition(active.revision, InstallState::Removing, 16)
            .expect("removing fixture")
            .transition(active.revision + 1, InstallState::Retained, 17)
            .expect("retained fixture")
            .transition(active.revision + 2, InstallState::Purging, 18)
            .expect("purging fixture")
    }

    fn write_stage(store: &StableInstallRecordStore, name: &str, bytes: Vec<u8>) -> PurgeSlotEntry {
        let relative_path = Path::new(SLOT_DIRECTORY).join(name);
        store
            .root
            .create_protected_file(&relative_path, &bytes)
            .expect("create protected stage fixture");
        PurgeSlotEntry::new(relative_path, PurgeSlotEntryKind::RegularFile, Some(bytes))
    }

    fn stable_entries(
        store: &StableInstallRecordStore,
        mut extra: Vec<PurgeSlotEntry>,
    ) -> Vec<PurgeSlotEntry> {
        let record_path = Path::new(RECORD_PATH).to_path_buf();
        let lock_path = Path::new(LOCK_PATH).to_path_buf();
        let record_bytes = store
            .root
            .read_protected_file(&record_path)
            .expect("record bytes");
        let mut entries = vec![
            PurgeSlotEntry::new(
                record_path,
                PurgeSlotEntryKind::RegularFile,
                Some(record_bytes),
            ),
            PurgeSlotEntry::new(lock_path, PurgeSlotEntryKind::RegularFile, None),
        ];
        entries.append(&mut extra);
        entries
    }

    fn store() -> (TempDir, StableInstallRecordStore) {
        let directory = tempfile::tempdir().expect("temporary control root");
        protect_control_root(directory.path()).expect("protect test root");
        let root = validate_control_root(directory.path()).expect("validate test root");
        let store = StableInstallRecordStore::from_validated_control_root(root)
            .expect("create fixed test slot");
        (directory, store)
    }

    #[test]
    fn absent_record_creates_revision_one_and_round_trips() {
        let (_directory, store) = store();
        let first = record(1, 10);
        assert_eq!(store.load().expect("absent load"), None);
        store.compare_and_swap(0, &first).expect("first write");
        assert_eq!(store.load().expect("reopen record"), Some(first));
    }

    #[test]
    fn update_requires_the_current_revision_and_preserves_identity() {
        let (_directory, store) = store();
        store
            .compare_and_swap(0, &record(1, 10))
            .expect("first write");
        let second = active_record_at_revision(2);
        store.compare_and_swap(1, &second).expect("update");
        assert_eq!(store.load().expect("read update"), Some(second));

        assert_eq!(
            store.compare_and_swap(1, &active_record_at_revision(3)),
            Err(InstallStoreError::CompareAndSwapConflict)
        );
        assert_eq!(
            store.load().expect("unchanged after stale"),
            Some(active_record_at_revision(2))
        );
    }

    #[test]
    fn next_revision_identity_and_timestamp_mismatches_do_not_mutate() {
        let (_directory, store) = store();
        store
            .compare_and_swap(0, &record(1, 10))
            .expect("first write");

        assert_eq!(
            store.compare_and_swap(1, &record(3, 11)),
            Err(InstallStoreError::CompareAndSwapConflict)
        );
        let mut changed_identity = record(2, 11);
        changed_identity.install_id =
            StableId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("fixture different identity");
        assert_eq!(
            store.compare_and_swap(1, &changed_identity),
            Err(InstallStoreError::InvalidRecord)
        );
        assert_eq!(
            store.compare_and_swap(1, &record(2, 9)),
            Err(InstallStoreError::InvalidRecord)
        );
        assert_eq!(store.load().expect("unchanged record"), Some(record(1, 10)));
    }

    #[test]
    fn store_rejects_invalid_first_records_and_illegal_successors() {
        let (_directory, store) = store();
        let mut missing_product = record(1, 10);
        missing_product.product_relative_path = None;
        assert_eq!(
            store.compare_and_swap(0, &missing_product),
            Err(InstallStoreError::InvalidRecord)
        );
        assert_eq!(store.load().expect("slot remains absent"), None);

        let initial = record(1, 10);
        store.compare_and_swap(0, &initial).expect("initial write");
        let mut broken = record(2, 11);
        broken.state = InstallState::Broken;
        store
            .compare_and_swap(1, &broken)
            .expect("INSTALLING may become BROKEN");

        let reinstall = record(3, 12);
        assert_eq!(
            store.compare_and_swap(2, &reinstall),
            Err(InstallStoreError::InvalidRecord)
        );
        assert_eq!(
            store.load().expect("illegal successor retained"),
            Some(broken)
        );
    }

    #[test]
    fn unknown_corrupt_oversized_and_temp_siblings_fail_closed_or_are_ignored() {
        {
            let (_directory, store) = store();
            store
                .root
                .create_protected_file(Path::new(RECORD_PATH), br#"{"unknown":true}"#)
                .expect("corrupt fixture");
            assert_eq!(store.load(), Err(InstallStoreError::Integrity));
        }

        {
            let (_directory, store) = store();
            store
                .root
                .create_protected_file(Path::new(r"slots\stable\install.leftover.new"), b"ignored")
                .expect("leftover temp");
            assert_eq!(store.load().expect("ignore temp sibling"), None);
        }

        let (_directory, store) = store();
        store
            .root
            .create_protected_file(Path::new(RECORD_PATH), b"{}")
            .expect("protected oversized fixture");
        std::fs::OpenOptions::new()
            .write(true)
            .open(store.root.path().join(RECORD_PATH))
            .expect("open fixture")
            .set_len((mesh_win32::MAX_CONTROL_FILE_BYTES as u64) + 1)
            .expect("make oversized fixture");
        assert_eq!(store.load(), Err(InstallStoreError::Integrity));
    }

    #[test]
    fn concurrent_same_revision_compare_and_swap_has_one_winner() {
        let (_directory, store) = store();
        let store = Arc::new(store);
        let contenders = 50;
        let barrier = Arc::new(Barrier::new(contenders));
        let mut workers = Vec::with_capacity(contenders);
        for _ in 0..contenders {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                store.compare_and_swap(0, &record(1, 10))
            }));
        }
        let successes = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker did not panic"))
            .filter_map(Result::ok)
            .count();
        assert_eq!(successes, 1);
        assert_eq!(
            store.load().expect("valid final record"),
            Some(record(1, 10))
        );
    }

    #[test]
    fn ordinary_traffic_guard_fences_remove_through_spawn_revalidation() {
        let (_directory, store) = store();
        let active = publish_active(&store);
        let guard = store
            .acquire_ordinary_traffic_guard()
            .expect("active admission guard");
        assert_eq!(guard.record(), &active);
        assert_eq!(
            guard.revalidate_for_spawn().expect("spawn revalidation"),
            &active
        );
        assert!(matches!(
            store.acquire_ordinary_traffic_guard(),
            Err(InstallStoreError::AdmissionBusy)
        ));

        let removing = active
            .transition(active.revision, InstallState::Removing, 16)
            .expect("removing transition");
        assert_eq!(
            store.compare_and_swap(active.revision, &removing),
            Err(InstallStoreError::CompareAndSwapConflict)
        );
        drop(guard);
        store
            .compare_and_swap(active.revision, &removing)
            .expect("remove proceeds after spawn scope");
    }

    #[test]
    fn setup_guard_owns_verify_effect_checkpoint_fence() {
        let (_directory, store) = store();
        let guard = store
            .acquire_setup_guard()
            .expect("exclusive setup convergence guard");
        assert_eq!(guard.load().expect("guarded absent load"), None);
        assert!(matches!(
            store.acquire_setup_guard(),
            Err(InstallStoreError::AdmissionBusy)
        ));
        assert!(matches!(
            store.acquire_ordinary_traffic_guard(),
            Err(InstallStoreError::AdmissionBusy)
        ));
        assert_eq!(
            store.compare_and_swap(0, &record(1, 10)),
            Err(InstallStoreError::CompareAndSwapConflict)
        );

        guard
            .compare_and_swap(0, &record(1, 10))
            .expect("guarded checkpoint reuses held lock");
        assert_eq!(guard.load().expect("guarded reopen"), Some(record(1, 10)));
        drop(guard);

        store
            .compare_and_swap(1, &active_record_at_revision(2))
            .expect("ordinary CAS resumes after setup guard drops");
    }

    #[test]
    fn ordinary_traffic_guard_denies_non_active_and_detects_spawn_point_change() {
        let (_directory, installing_store) = store();
        installing_store
            .compare_and_swap(0, &record(1, 10))
            .expect("initial write");
        assert!(matches!(
            installing_store.acquire_ordinary_traffic_guard(),
            Err(InstallStoreError::OrdinaryTrafficUnavailable)
        ));

        let (_directory, store) = store();
        let active = publish_active(&store);
        let guard = store
            .acquire_ordinary_traffic_guard()
            .expect("active admission guard");
        let removing = active
            .transition(active.revision, InstallState::Removing, 16)
            .expect("removing fixture");
        std::fs::write(
            store.root.path().join(RECORD_PATH),
            serde_json::to_vec(&removing).expect("serialize replacement"),
        )
        .expect("out-of-protocol replacement fixture");
        assert_eq!(
            guard.revalidate_for_spawn(),
            Err(InstallStoreError::AdmissionChanged)
        );
    }

    #[test]
    fn retained_control_guard_admits_complete_control_lifecycles_only() {
        for state in [
            InstallState::Active,
            InstallState::Removing,
            InstallState::Retained,
        ] {
            let (_directory, store) = store();
            let active = publish_active(&store);
            let expected = match state {
                InstallState::Active => active,
                InstallState::Removing => {
                    let removing = active
                        .transition(active.revision, InstallState::Removing, 16)
                        .expect("removing fixture");
                    store
                        .compare_and_swap(active.revision, &removing)
                        .expect("publish removing");
                    removing
                }
                InstallState::Retained => {
                    let removing = active
                        .transition(active.revision, InstallState::Removing, 16)
                        .expect("removing fixture");
                    store
                        .compare_and_swap(active.revision, &removing)
                        .expect("publish removing");
                    let retained = removing
                        .transition(removing.revision, InstallState::Retained, 17)
                        .expect("retained fixture");
                    store
                        .compare_and_swap(removing.revision, &retained)
                        .expect("publish retained");
                    retained
                }
                InstallState::Installing | InstallState::Purging | InstallState::Broken => {
                    unreachable!()
                }
            };
            let guard = store
                .acquire_retained_control_guard()
                .expect("eligible retained control guard");
            assert_eq!(guard.record(), &expected);
            assert_eq!(
                guard.revalidate_for_spawn().expect("exact bytes"),
                &expected
            );
        }

        for state in [InstallState::Installing, InstallState::Broken] {
            let (_directory, store) = store();
            let initial = record(1, 10);
            store
                .compare_and_swap(0, &initial)
                .expect("publish initial");
            if state == InstallState::Broken {
                let mut broken = record(2, 11);
                broken.state = InstallState::Broken;
                store
                    .compare_and_swap(initial.revision, &broken)
                    .expect("publish broken");
            }
            assert!(matches!(
                store.acquire_retained_control_guard(),
                Err(InstallStoreError::OrdinaryTrafficUnavailable)
            ));
        }
    }

    #[test]
    fn retained_control_spawn_revalidation_rejects_serialized_byte_drift() {
        let (_directory, store) = store();
        let active = publish_active(&store);
        let guard = store
            .acquire_retained_control_guard()
            .expect("retained control guard");
        let removing = active
            .transition(active.revision, InstallState::Removing, 16)
            .expect("removing fixture");
        assert_eq!(
            store.compare_and_swap(active.revision, &removing),
            Err(InstallStoreError::CompareAndSwapConflict),
            "install.lock must remain held through the spawn boundary"
        );
        let semantically_identical = serde_json::to_vec_pretty(&active).expect("pretty record");
        std::fs::write(store.root.path().join(RECORD_PATH), semantically_identical)
            .expect("out-of-protocol byte replacement");
        assert_eq!(
            guard.revalidate_for_spawn(),
            Err(InstallStoreError::AdmissionChanged)
        );
    }

    #[test]
    fn native_and_storage_failures_keep_safe_machine_readable_taxonomy() {
        assert_eq!(
            map_cas_lock_error(NativeError::new(
                NativeErrorCode::SingletonConflict,
                mesh_win32::NativeOperation::AcquireLock,
            )),
            InstallStoreError::CompareAndSwapConflict
        );
        assert_eq!(
            map_admission_lock_error(NativeError::new(
                NativeErrorCode::SingletonConflict,
                mesh_win32::NativeOperation::AcquireLock,
            )),
            InstallStoreError::AdmissionBusy
        );
        assert_eq!(
            map_cas_lock_error(NativeError::new(
                NativeErrorCode::AccessDenied,
                mesh_win32::NativeOperation::AcquireLock,
            )),
            InstallStoreError::AccessDenied
        );
        assert_eq!(
            map_storage_error(StorageError::new(
                StorageErrorCode::InsecureAcl,
                mesh_win32::StorageOperation::InspectSecurity,
            )),
            InstallStoreError::Integrity
        );
        assert_eq!(
            map_storage_error(StorageError::new(
                StorageErrorCode::PublicationVerificationFailed,
                mesh_win32::StorageOperation::VerifyPublication,
            )),
            InstallStoreError::Integrity
        );
    }

    #[test]
    fn staging_collision_is_preserved_and_the_next_create_new_name_is_used() {
        let (_directory, store) = store();
        let collision = Path::new(r"slots\stable\install.0000000000000001.new").to_path_buf();
        let chosen = Path::new(r"slots\stable\install.0000000000000002.new").to_path_buf();
        store
            .root
            .create_protected_file(&collision, b"existing")
            .expect("collision fixture");
        let mut candidates = [collision.clone(), chosen.clone()].into_iter();
        let bytes = serde_json::to_vec(&record(1, 10)).expect("serializable fixture");
        let stage = store
            .create_verified_stage_with(&bytes, || candidates.next().expect("bounded candidates"))
            .expect("second fresh stage");
        assert_eq!(stage, chosen);
        assert_eq!(
            store
                .root
                .read_protected_file(&collision)
                .expect("collision retained"),
            b"existing"
        );
        assert!(
            store
                .root
                .remove_regular_file(&stage)
                .expect("remove owned stage")
        );
    }

    #[test]
    fn guarded_record_last_purge_deletes_only_exact_purging_record_and_valid_stages() {
        let (_directory, store) = store();
        let active = publish_active(&store);
        let purging = purging_record(&active);
        let removing = active
            .transition(active.revision, InstallState::Removing, 16)
            .expect("removing");
        store
            .compare_and_swap(active.revision, &removing)
            .expect("publish removing");
        let retained = removing
            .transition(removing.revision, InstallState::Retained, 17)
            .expect("retained");
        store
            .compare_and_swap(removing.revision, &retained)
            .expect("publish retained");
        store
            .compare_and_swap(retained.revision, &purging)
            .expect("publish purge fence");
        assert!(matches!(
            store.acquire_ordinary_traffic_guard(),
            Err(InstallStoreError::OrdinaryTrafficUnavailable)
        ));
        assert!(matches!(
            store.acquire_retained_control_guard(),
            Err(InstallStoreError::OrdinaryTrafficUnavailable)
        ));
        let stage = write_stage(
            &store,
            "install.0000000000000001.new",
            serde_json::to_vec(&retained).expect("serialize same-lineage stage"),
        );

        let guard = store
            .acquire_setup_guard()
            .expect("purge holds install lock");
        let snapshot = guard
            .load_with_bytes()
            .expect("purge snapshot")
            .expect("purging record exists");
        assert_eq!(snapshot.record(), &purging);
        guard
            .compare_and_delete_purging(
                purging.revision,
                snapshot.serialized_record(),
                &FixtureStages {
                    entries: stable_entries(&store, vec![stage]),
                },
            )
            .expect("record-last purge finalization");
        assert_eq!(guard.load().expect("read absence"), None);
        assert!(!store.root.path().join(RECORD_PATH).exists());
        assert!(
            !store
                .root
                .path()
                .join(r"slots\stable\install.0000000000000001.new")
                .exists()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn purge_finalization_rejects_stale_record_and_stage_drift_without_deletion() {
        let (_directory, store) = store();
        let active = publish_active(&store);
        let removing = active
            .transition(active.revision, InstallState::Removing, 16)
            .expect("removing");
        store
            .compare_and_swap(active.revision, &removing)
            .expect("publish removing");
        let retained = removing
            .transition(removing.revision, InstallState::Retained, 17)
            .expect("retained");
        store
            .compare_and_swap(removing.revision, &retained)
            .expect("publish retained");
        let purging = retained
            .transition(retained.revision, InstallState::Purging, 18)
            .expect("purging");
        store
            .compare_and_swap(retained.revision, &purging)
            .expect("publish purging");
        let malformed = write_stage(&store, "install.not-hex.new", b"not-json".to_vec());
        let malformed_path = malformed.relative_path.clone();
        let guard = store.acquire_setup_guard().expect("purge lock");
        let snapshot = guard
            .load_with_bytes()
            .expect("purge snapshot")
            .expect("purging record exists");

        assert_eq!(
            guard.compare_and_delete_purging(
                purging.revision - 1,
                snapshot.serialized_record(),
                &FixtureStages {
                    entries: stable_entries(&store, vec![]),
                },
            ),
            Err(InstallStoreError::PurgePrecondition)
        );
        assert_eq!(
            guard.compare_and_delete_purging(
                purging.revision,
                b"different bytes",
                &FixtureStages {
                    entries: stable_entries(&store, vec![]),
                },
            ),
            Err(InstallStoreError::PurgePrecondition)
        );
        assert_eq!(
            guard.compare_and_delete_purging(
                purging.revision,
                snapshot.serialized_record(),
                &FixtureStages {
                    entries: stable_entries(&store, vec![malformed]),
                },
            ),
            Err(InstallStoreError::PurgeStageDrift)
        );
        assert_eq!(guard.load().expect("record remains"), Some(purging.clone()));
        assert!(store.root.path().join(RECORD_PATH).exists());
        assert!(
            store
                .root
                .path()
                .join(r"slots\stable\install.not-hex.new")
                .exists()
        );
        assert!(
            store
                .root
                .remove_regular_file(&malformed_path)
                .expect("remove malformed fixture before independent foreign test")
        );

        let mut foreign = retained;
        foreign.consumer_id =
            StableId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("foreign consumer fixture");
        let foreign_stage = write_stage(
            &store,
            "install.0000000000000002.new",
            serde_json::to_vec(&foreign).expect("serialize foreign stage"),
        );
        assert_eq!(
            guard.compare_and_delete_purging(
                purging.revision,
                snapshot.serialized_record(),
                &FixtureStages {
                    entries: stable_entries(&store, vec![foreign_stage]),
                },
            ),
            Err(InstallStoreError::PurgeStageDrift)
        );
        assert_eq!(
            guard.load().expect("foreign stage preserves record"),
            Some(purging.clone())
        );
        assert!(
            store
                .root
                .remove_regular_file(
                    &Path::new(SLOT_DIRECTORY).join("install.0000000000000002.new")
                )
                .expect("remove foreign fixture before independent unexpected-entry test")
        );

        let same_revision_reencoded = write_stage(
            &store,
            "install.0000000000000003.new",
            serde_json::to_vec_pretty(&purging).expect("pretty same-revision stage"),
        );
        assert_eq!(
            guard.compare_and_delete_purging(
                purging.revision,
                snapshot.serialized_record(),
                &FixtureStages {
                    entries: stable_entries(&store, vec![same_revision_reencoded]),
                },
            ),
            Err(InstallStoreError::PurgeStageDrift)
        );
        assert!(
            store
                .root
                .remove_regular_file(
                    &Path::new(SLOT_DIRECTORY).join("install.0000000000000003.new")
                )
                .expect("remove reencoded fixture before independent unexpected-entry test")
        );

        let unexpected_path = Path::new(SLOT_DIRECTORY).join("unrelated.tmp");
        store
            .root
            .create_protected_file(&unexpected_path, b"unexpected")
            .expect("unexpected stable-slot entry");
        assert_eq!(
            guard.compare_and_delete_purging(
                purging.revision,
                snapshot.serialized_record(),
                &FixtureStages {
                    entries: stable_entries(
                        &store,
                        vec![PurgeSlotEntry::new(
                            unexpected_path,
                            PurgeSlotEntryKind::RegularFile,
                            Some(b"unexpected".to_vec()),
                        )],
                    ),
                },
            ),
            Err(InstallStoreError::PurgeStageDrift)
        );
    }

    #[test]
    fn purge_finalization_requires_the_setup_guard_lock() {
        let (_directory, store) = store();
        let guard = store.acquire_setup_guard().expect("first guard");
        assert!(matches!(
            store.acquire_setup_guard(),
            Err(InstallStoreError::AdmissionBusy)
        ));
        drop(guard);
    }
}
