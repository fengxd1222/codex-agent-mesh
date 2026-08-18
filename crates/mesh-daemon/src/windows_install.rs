//! Windows evidence implementation for the stable-slot setup state machine.
//!
//! This module deliberately owns no lifecycle transitions.
//! [`crate::install_control::converge_setup`]
//! owns record ordering and CAS; this type returns a checkpoint only after the
//! corresponding on-disk or Task Scheduler evidence has been read back and
//! verified. The supported durability claim is process termination and
//! reported I/O failure on local NTFS, not sudden power loss.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use crate::{
    install_control::{InstallControlError, SetupPlatform},
    install_record::{
        InstallRecord, InstallState, ProtectedKeyArtifact, RelativeWindowsPath, RuntimeArtifact,
        ScheduledTaskEvidence, Sha256Digest,
    },
};

#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
use mesh_win32::ScheduledTaskSpec;

#[cfg(windows)]
use crate::install_record::{
    INSTALL_RECORD_FORMAT_VERSION, RuntimeArtifactFormat, ScheduledTaskPath, SignerStatus, StableId,
};

const PRODUCT_DIRECTORY: &str = "installs";
const RUNTIME_FILE_NAME: &str = "mesh-daemon.exe";
const ENDPOINT_KEY_FILE_NAME: &str = "endpoint-key.dpapi";
const DATA_DIRECTORY_NAME: &str = "data";
#[cfg(windows)]
const STABLE_SLOT: &str = "stable";
#[cfg(windows)]
const ARTIFACT_STAGE_ATTEMPTS: usize = 8;

/// Fully verified, record-derived purge preflight capability.
///
/// Construction is intentionally limited to complete pre-purge lifecycle
/// states. Once `PURGING` is durable the source artifacts may already be
/// renamed or deleted, so resume must use destructive convergence observations
/// instead of attempting to reconstruct this capability.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct CompletePurgeArtifacts {
    task_spec: ScheduledTaskSpec,
}

#[cfg(windows)]
impl CompletePurgeArtifacts {
    #[must_use]
    pub(crate) fn task_spec(&self) -> &ScheduledTaskSpec {
        &self.task_spec
    }
}

/// Fixed public control command which may be forwarded from a plugin-cache
/// image to the exact retained runtime.
///
/// Callers cannot supply an executable, raw argument, working directory,
/// environment, or shell policy through this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableControlMode {
    /// Read-only installation inspection.
    Status,
    /// Start the exact active installation.
    Start,
    /// Retain data while converging owned task removal.
    Remove,
    /// Local-only explicit purge spelling. Public dispatch always routes this
    /// to the external purge controller in the calling process; it is never
    /// forwarded to or accepted by the retained stable runtime.
    RemoveAndPurge,
}

impl StableControlMode {
    #[must_use]
    pub const fn operation(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Start => "start",
            Self::Remove | Self::RemoveAndPurge => "remove",
        }
    }

    const fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Status => &["status", "--install-slot", "stable"],
            Self::Start => &["start", "--install-slot", "stable"],
            Self::Remove => &["remove", "--install-slot", "stable"],
            Self::RemoveAndPurge => &["remove", "--install-slot", "stable", "--purge-data"],
        }
    }

    #[must_use]
    pub const fn admits(self, state: InstallState) -> bool {
        match self {
            Self::Status | Self::Remove | Self::RemoveAndPurge => matches!(
                state,
                InstallState::Active | InstallState::Removing | InstallState::Retained
            ),
            Self::Start => matches!(state, InstallState::Active),
        }
    }
}

/// Result of the verified cache-to-stable process-creation boundary.
#[cfg(windows)]
pub enum StableControlLaunch {
    /// The current image is already the exact retained runtime.
    CurrentRuntime,
    /// A retained child was created with inherited standard I/O.
    Spawned(std::process::Child),
}

/// Redaction-safe failure classification for a stable control launch.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StableControlLaunchError {
    /// Trust, lifecycle, protected-record, path, digest, or signer verification
    /// failed before process creation.
    Verification(InstallControlError),
    /// The verified process could not be created.
    Spawn,
}

/// These values are embedded by the official release build. They are never
/// accepted from command-line arguments, environment variables at run time, or
/// the persisted install record.
#[cfg(windows)]
const OFFICIAL_SIGNER_CERTIFICATE_SHA256: Option<&str> =
    option_env!("CODEX_AGENT_MESH_SIGNER_CERTIFICATE_SHA256");

#[cfg(windows)]
fn is_exact_retained_runtime(current: &Path, retained: &Path) -> bool {
    current == retained
}
#[cfg(windows)]
mod platform {
    use std::{
        fs::{self, File},
        io::Read,
        os::windows::process::CommandExt,
        process::{Child, Command, Stdio},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use mesh_win32::{
        AuthenticodePolicy, AuthenticodeVerification, EndpointKey, NativeError, NativeErrorCode,
        ScheduledTaskController, ScheduledTaskSpec, ScheduledTaskState, StorageError,
        StorageErrorCode, ValidatedControlRoot, open_or_create_product_control_root,
        protect_data_root, protect_endpoint_key, unprotect_endpoint_key, validate_data_root,
        verify_authenticode,
    };
    use rand::RngCore;
    use rusqlite::{Connection, OpenFlags};
    use sha2::{Digest, Sha256};

    use super::{
        ARTIFACT_STAGE_ATTEMPTS, CompletePurgeArtifacts, INSTALL_RECORD_FORMAT_VERSION,
        InstallControlError, InstallRecord, OFFICIAL_SIGNER_CERTIFICATE_SHA256, Path, PathBuf,
        ProtectedKeyArtifact, RelativeWindowsPath, RuntimeArtifact, RuntimeArtifactFormat,
        STABLE_SLOT, ScheduledTaskEvidence, ScheduledTaskPath, SetupPlatform, Sha256Digest,
        SignerStatus, StableControlLaunch, StableControlLaunchError, StableControlMode, StableId,
        data_path, decode_lower_hex_32, digest_hex, digest_value, hex_lower,
        is_exact_retained_runtime, key_path, product_path, runtime_path, runtime_stage_path,
        sha256_bytes,
    };
    use crate::{
        install_store::{OrdinaryTrafficGuard, RetainedControlGuard},
        reader::ReaderPool,
        storage::{
            CURRENT_DATA_SCHEMA_VERSION, EMPTY_CONFIG_V1_DIGEST, MESH_SQLITE_APPLICATION_ID,
            StorageError as DbError,
        },
        writer::WriterHandle,
    };

    const SETUP_READ_TIMEOUT: Duration = Duration::from_secs(5);
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum RuntimeTrust {
        Official {
            expected_signer_certificate_sha256: [u8; 32],
        },
        UnsignedDevelopment,
    }

    impl RuntimeTrust {
        const fn policy(self) -> AuthenticodePolicy {
            match self {
                Self::Official {
                    expected_signer_certificate_sha256,
                } => AuthenticodePolicy::Official {
                    expected_signer_certificate_sha256,
                },
                Self::UnsignedDevelopment => AuthenticodePolicy::UnsignedDevelopment,
            }
        }

        const fn signer_status(self) -> SignerStatus {
            match self {
                Self::Official { .. } => SignerStatus::Signed,
                Self::UnsignedDevelopment => SignerStatus::UnsignedDevelopment,
            }
        }
    }

    fn purge_runtime_trust(record: &InstallRecord) -> Result<RuntimeTrust, InstallControlError> {
        let signer_status = record
            .runtime
            .as_ref()
            .ok_or(InstallControlError::Drifted)?
            .signer_status;
        match signer_status {
            SignerStatus::Signed => {
                let expected_signer_certificate_sha256 = OFFICIAL_SIGNER_CERTIFICATE_SHA256
                    .ok_or(InstallControlError::Drifted)
                    .and_then(decode_lower_hex_32)?;
                if expected_signer_certificate_sha256 == [0; 32] {
                    return Err(InstallControlError::Drifted);
                }
                Ok(RuntimeTrust::Official {
                    expected_signer_certificate_sha256,
                })
            }
            SignerStatus::UnsignedDevelopment => Ok(RuntimeTrust::UnsignedDevelopment),
        }
    }

    fn validate_purge_controller_record(
        record: &InstallRecord,
    ) -> Result<RuntimeTrust, InstallControlError> {
        record
            .validate()
            .map_err(|_| InstallControlError::Drifted)?;
        if !matches!(
            record.state,
            crate::install_record::InstallState::Active
                | crate::install_record::InstallState::Removing
                | crate::install_record::InstallState::Retained
                | crate::install_record::InstallState::Purging
        ) || !record.is_active_complete()
        {
            return Err(InstallControlError::Drifted);
        }
        WindowsSetupPlatform::verify_record_identity(record)?;
        let protected_key = record
            .protected_key
            .as_ref()
            .ok_or(InstallControlError::Drifted)?;
        let runtime = record
            .runtime
            .as_ref()
            .ok_or(InstallControlError::Drifted)?;
        let data_relative = record
            .data_relative_path
            .as_ref()
            .ok_or(InstallControlError::Drifted)?;
        if protected_key.relative_path != key_path(record.install_id.as_str())?
            || data_relative != &data_path(record.install_id.as_str())?
            || purgeable_data_schema_version(record.data_schema_version).is_err()
            || runtime.relative_path != runtime_path(record.install_id.as_str(), &runtime.sha256)?
            || runtime.artifact_format != RuntimeArtifactFormat::MeshDaemonExeV1
        {
            return Err(InstallControlError::Drifted);
        }
        purge_runtime_trust(record)
    }

    pub(super) fn validate_purge_preflight_record(
        record: &InstallRecord,
    ) -> Result<RuntimeTrust, InstallControlError> {
        let trust = validate_purge_controller_record(record)?;
        if record.state == crate::install_record::InstallState::Purging {
            return Err(InstallControlError::Drifted);
        }
        Ok(trust)
    }

    pub(super) fn admit_external_purge_controller_verification(
        record: &InstallRecord,
        verification: AuthenticodeVerification,
    ) -> Result<(), InstallControlError> {
        let trust = validate_purge_controller_record(record)?;
        if !verification_matches(trust, verification) {
            return Err(InstallControlError::Drifted);
        }
        Ok(())
    }

    /// Verifies the running purge controller without equating it to the frozen
    /// retained runtime. The path comes only from `current_exe`; signer policy
    /// comes only from the persisted signer class plus the compiled official
    /// leaf pin.
    pub(crate) fn verify_external_purge_controller(
        root: &ValidatedControlRoot,
        record: &InstallRecord,
    ) -> Result<(), InstallControlError> {
        let trust = validate_purge_controller_record(record)?;
        let executable = root
            .validate_current_executable_outside_control_root()
            .map_err(map_control_storage_error)?;
        let verification =
            verify_authenticode(&executable, trust.policy()).map_err(map_native_error)?;
        admit_external_purge_controller_verification(record, verification)?;
        Ok(())
    }

    /// Revalidates all frozen install artifacts before publishing `PURGING`.
    ///
    /// This does not query Task Scheduler. It returns the exact record-derived
    /// [`ScheduledTaskSpec`] after comparing the durable task evidence; the
    /// control layer owns the lifecycle-specific present/absent status check.
    pub(crate) fn verify_complete_purge_artifacts(
        root: &ValidatedControlRoot,
        record: &InstallRecord,
    ) -> Result<CompletePurgeArtifacts, InstallControlError> {
        let trust = validate_purge_preflight_record(record)?;
        let protected_key = record
            .protected_key
            .as_ref()
            .ok_or(InstallControlError::Drifted)?;
        let key_relative_path = key_path(record.install_id.as_str())?;
        let envelope = root
            .read_endpoint_key_file(Path::new(key_relative_path.as_str()))
            .map_err(map_control_storage_error)?;
        verify_recorded_digest(&protected_key.sha256, sha256_bytes(envelope.as_bytes()))?;
        let _key = unprotect_endpoint_key(&envelope, record.install_id.as_str())
            .map_err(map_native_error)?;

        let runtime = record
            .runtime
            .as_ref()
            .ok_or(InstallControlError::Drifted)?;
        let runtime_digest = decode_lower_hex_32(runtime.sha256.as_str())?;
        let runtime_relative_path = runtime_path(record.install_id.as_str(), &runtime.sha256)?;
        let runtime_path = root
            .verify_artifact_file(Path::new(runtime_relative_path.as_str()), runtime_digest)
            .map_err(map_control_storage_error)?;
        let runtime_verification =
            verify_authenticode(&runtime_path, trust.policy()).map_err(map_native_error)?;
        if !verification_matches(trust, runtime_verification) {
            return Err(InstallControlError::Drifted);
        }

        let data_relative_path = data_path(record.install_id.as_str())?;
        let data_path = root.path().join(data_relative_path.as_str());
        validate_data_root(&data_path)
            .and_then(|validated| validated.allocated_tree_bytes().map(|_| validated))
            .map_err(map_control_storage_error)?;
        verify_purge_database_evidence(
            &data_path,
            record.install_id.as_str(),
            purgeable_data_schema_version(record.data_schema_version)?,
        )?;

        let task_spec =
            ScheduledTaskSpec::new(record.install_id.as_str(), &runtime_path, runtime_digest)
                .map_err(map_native_error)?;
        let task = record
            .scheduled_task
            .as_ref()
            .ok_or(InstallControlError::Drifted)?;
        verify_task_evidence(task, &task_spec)?;

        Ok(CompletePurgeArtifacts { task_spec })
    }

    #[derive(Debug)]
    struct BundleRuntime {
        canonical_path: PathBuf,
        sha256: [u8; 32],
        trust: RuntimeTrust,
    }

    /// Production Windows implementation of the ordered setup evidence boundary.
    ///
    /// The control root always comes from the current-user Known Folder API.
    /// Official construction consumes only identities embedded by the release
    /// build. Development construction is a separate, explicit type path whose
    /// resulting record can never claim `Signed`.
    #[derive(Debug)]
    pub struct WindowsSetupPlatform {
        root: ValidatedControlRoot,
        bundle: BundleRuntime,
        tasks: Option<ScheduledTaskController>,
    }

    impl WindowsSetupPlatform {
        /// Opens setup for an official release identity embedded at compile time.
        pub fn open_official_current_executable() -> Result<Self, InstallControlError> {
            let signer_sha256 = OFFICIAL_SIGNER_CERTIFICATE_SHA256
                .ok_or(InstallControlError::Drifted)
                .and_then(decode_lower_hex_32)?;
            if signer_sha256 == [0; 32] {
                return Err(InstallControlError::Drifted);
            }
            Self::open_current_executable(RuntimeTrust::Official {
                expected_signer_certificate_sha256: signer_sha256,
            })
        }

        /// Opens setup for a deliberately unsigned local/development build.
        ///
        /// This is not a fallback from failed official verification: callers
        /// must choose the development path explicitly before setup begins.
        pub fn open_unsigned_development_current_executable() -> Result<Self, InstallControlError> {
            Self::open_current_executable(RuntimeTrust::UnsignedDevelopment)
        }

        fn open_current_executable(trust: RuntimeTrust) -> Result<Self, InstallControlError> {
            let source = std::env::current_exe()
                .and_then(fs::canonicalize)
                .map_err(map_io_error)?;
            verify_authenticode(&source, trust.policy()).map_err(map_native_error)?;
            // A file cannot contain a fixed hash of its own final signed bytes
            // without making that hash self-referential. Authenticode plus the
            // compiled leaf-certificate pin authenticates the bundle; setup
            // computes the final SHA-256 here and durably binds it into the
            // protected install record for all later path/pipe verification.
            let observed_sha256 = sha256_bounded_file(&source)?;
            let root = open_or_create_product_control_root().map_err(map_control_storage_error)?;
            Ok(Self {
                root,
                bundle: BundleRuntime {
                    canonical_path: source,
                    sha256: observed_sha256,
                    trust,
                },
                tasks: None,
            })
        }

        /// Fully verifies an admitted `ACTIVE` record and creates the retained
        /// bridge process while the caller's ordinary-traffic guard remains live.
        ///
        /// The record is byte-revalidated, then the runtime is re-opened through
        /// the validated control root immediately before `CreateProcess`. The
        /// caller retains ownership of `guard` and may drop it after this method
        /// returns successfully.
        pub fn spawn_stable_bridge(
            &mut self,
            guard: &OrdinaryTrafficGuard<'_>,
        ) -> Result<Child, InstallControlError> {
            // The cache trampoline must never unprotect the endpoint key. It
            // verifies every non-secret retained artifact and the protected
            // envelope itself; only the exact stable child may decrypt it.
            let admitted = guard.record();
            if !admitted.admits_ordinary_traffic() {
                return Err(InstallControlError::Unavailable);
            }
            Self::verify_record_identity(admitted)?;
            self.read_verified_key_envelope(admitted)?;
            self.verify_runtime_record(admitted)?;
            self.verify_data_record(admitted)?;
            self.verify_task_present(admitted)?;
            let record = guard.revalidate_for_spawn().map_err(map_store_error)?;
            let runtime = self.verify_runtime_record(record)?;
            // Revalidation above returns a path capability, not a permanently
            // held handle. Verify once more at the exact process-use boundary.
            let runtime = self.verify_runtime_record(record).and_then(|path| {
                if path == runtime {
                    Ok(path)
                } else {
                    Err(InstallControlError::Drifted)
                }
            })?;

            Command::new(runtime)
                .args(["bridge", "--stdio", "--install-slot", STABLE_SLOT])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .map_err(map_io_error)
        }

        /// Verifies and launches one allowlisted public control command in the
        /// exact retained runtime while `guard` holds the shared install fence.
        ///
        /// Only protected record and executable identity are required here;
        /// the stable command owns task/data/key diagnosis and convergence.
        /// This cache boundary never unprotects the endpoint key or connects to
        /// the daemon pipe.
        pub fn spawn_stable_control(
            &self,
            guard: &RetainedControlGuard<'_>,
            mode: StableControlMode,
        ) -> Result<StableControlLaunch, StableControlLaunchError> {
            let admitted = guard.record();
            if !mode.admits(admitted.state) {
                return Err(StableControlLaunchError::Verification(
                    InstallControlError::Unavailable,
                ));
            }
            Self::verify_record_identity(admitted)
                .map_err(StableControlLaunchError::Verification)?;
            self.verify_runtime_record(admitted)
                .map_err(StableControlLaunchError::Verification)?;

            let record = guard
                .revalidate_for_spawn()
                .map_err(map_store_error)
                .map_err(StableControlLaunchError::Verification)?;
            if !mode.admits(record.state) {
                return Err(StableControlLaunchError::Verification(
                    InstallControlError::Unavailable,
                ));
            }
            // Re-open and byte-verify at the exact process-use boundary.
            let runtime = self
                .verify_runtime_record(record)
                .map_err(StableControlLaunchError::Verification)?;
            guard
                .revalidate_for_spawn()
                .map_err(map_store_error)
                .map_err(StableControlLaunchError::Verification)?;
            if !runtime.is_absolute() {
                return Err(StableControlLaunchError::Verification(
                    InstallControlError::Drifted,
                ));
            }
            if is_exact_retained_runtime(&self.bundle.canonical_path, &runtime) {
                return Ok(StableControlLaunch::CurrentRuntime);
            }

            let mut command = Command::new(runtime);
            command
                .args(mode.arguments())
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .creation_flags(CREATE_NO_WINDOW);
            command
                .spawn()
                .map(StableControlLaunch::Spawned)
                .map_err(|_| StableControlLaunchError::Spawn)
        }

        /// Proves that the current process image is the exact retained runtime
        /// named by a fully verified `ACTIVE` record.
        ///
        /// Internal `bridge` and `daemon` modes must call this before opening
        /// secrets, storage, or IPC. Equal bytes at a plugin-cache path are not
        /// sufficient: both canonical paths must be exactly the retained path.
        pub fn verify_current_is_stable(
            &mut self,
            record: &InstallRecord,
        ) -> Result<PathBuf, InstallControlError> {
            self.verify_active(record)?;
            let retained = self.verify_runtime_record(record)?;
            let current = std::env::current_exe()
                .and_then(fs::canonicalize)
                .map_err(map_io_error)?;
            if current != self.bundle.canonical_path || current != retained {
                return Err(InstallControlError::Drifted);
            }
            Ok(current)
        }

        fn task_controller(&mut self) -> Result<&ScheduledTaskController, InstallControlError> {
            if self.tasks.is_none() {
                self.tasks = Some(ScheduledTaskController::connect().map_err(map_native_error)?);
            }
            self.tasks
                .as_ref()
                .ok_or(InstallControlError::StorageUnavailable)
        }

        fn verify_record_identity(record: &InstallRecord) -> Result<(), InstallControlError> {
            let expected_product = product_path(record.install_id.as_str())?;
            if record.product_relative_path.as_ref() != Some(&expected_product) {
                return Err(InstallControlError::Drifted);
            }
            Ok(())
        }

        fn read_verified_key_envelope(
            &self,
            record: &InstallRecord,
        ) -> Result<mesh_win32::ProtectedEndpointKey, InstallControlError> {
            let evidence = record
                .protected_key
                .as_ref()
                .ok_or(InstallControlError::Drifted)?;
            if evidence.relative_path != key_path(record.install_id.as_str())? {
                return Err(InstallControlError::Drifted);
            }
            let envelope = self
                .root
                .read_endpoint_key_file(Path::new(evidence.relative_path.as_str()))
                .map_err(map_control_storage_error)?;
            let digest = sha256_bytes(envelope.as_bytes());
            if digest_hex(digest) != evidence.sha256.as_str() {
                return Err(InstallControlError::Drifted);
            }
            Ok(envelope)
        }

        fn verify_key_record(&self, record: &InstallRecord) -> Result<(), InstallControlError> {
            let envelope = self.read_verified_key_envelope(record)?;
            let _key = unprotect_endpoint_key(&envelope, record.install_id.as_str())
                .map_err(map_native_error)?;
            Ok(())
        }

        fn verify_runtime_record(
            &self,
            record: &InstallRecord,
        ) -> Result<PathBuf, InstallControlError> {
            let evidence = record
                .runtime
                .as_ref()
                .ok_or(InstallControlError::Drifted)?;
            let expected_digest = digest_value(self.bundle.sha256)?;
            let expected_path = runtime_path(record.install_id.as_str(), &expected_digest)?;
            if evidence.relative_path != expected_path
                || evidence.sha256 != expected_digest
                || evidence.version != env!("CARGO_PKG_VERSION")
                || evidence.signer_status != self.bundle.trust.signer_status()
                || evidence.artifact_format != RuntimeArtifactFormat::MeshDaemonExeV1
            {
                return Err(InstallControlError::Drifted);
            }
            let path = self
                .root
                .verify_artifact_file(
                    Path::new(evidence.relative_path.as_str()),
                    self.bundle.sha256,
                )
                .map_err(map_control_storage_error)?;
            let verified =
                verify_authenticode(&path, self.bundle.trust.policy()).map_err(map_native_error)?;
            if !verification_matches(self.bundle.trust, verified) {
                return Err(InstallControlError::Drifted);
            }
            Ok(path)
        }

        fn verify_data_record(&self, record: &InstallRecord) -> Result<(), InstallControlError> {
            let relative = record
                .data_relative_path
                .as_ref()
                .ok_or(InstallControlError::Drifted)?;
            if relative != &data_path(record.install_id.as_str())?
                || record.data_schema_version != Some(CURRENT_DATA_SCHEMA_VERSION)
            {
                return Err(InstallControlError::Drifted);
            }
            let path = self.root.path().join(relative.as_str());
            validate_data_root(&path)
                .and_then(|root| root.allocated_tree_bytes().map(|_| root))
                .map_err(map_control_storage_error)?;
            verify_database_evidence(&path, record.install_id.as_str())
        }

        fn task_spec(
            &self,
            record: &InstallRecord,
        ) -> Result<ScheduledTaskSpec, InstallControlError> {
            let runtime = self.verify_runtime_record(record)?;
            ScheduledTaskSpec::new(record.install_id.as_str(), runtime, self.bundle.sha256)
                .map_err(map_native_error)
        }

        fn verify_task_present(
            &mut self,
            record: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            let spec = self.task_spec(record)?;
            let evidence = record
                .scheduled_task
                .as_ref()
                .ok_or(InstallControlError::Drifted)?;
            verify_task_evidence(evidence, &spec)?;
            let status = self
                .task_controller()?
                .status(&spec)
                .map_err(map_native_error)?;
            if !matches!(
                status.state,
                ScheduledTaskState::Ready | ScheduledTaskState::Running
            ) || status.actual_definition_digest != Some(*spec.expected_definition_digest())
            {
                return Err(map_task_state(status.state));
            }
            Ok(())
        }

        fn verify_task_absent(
            &mut self,
            record: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            let spec = self.task_spec(record)?;
            let evidence = record
                .scheduled_task
                .as_ref()
                .ok_or(InstallControlError::Drifted)?;
            verify_task_evidence(evidence, &spec)?;
            let status = self
                .task_controller()?
                .status(&spec)
                .map_err(map_native_error)?;
            if status.state != ScheduledTaskState::Absent {
                return Err(InstallControlError::Drifted);
            }
            Ok(())
        }

        fn verify_task_present_or_absent(
            &mut self,
            record: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            let spec = self.task_spec(record)?;
            let evidence = record
                .scheduled_task
                .as_ref()
                .ok_or(InstallControlError::Drifted)?;
            verify_task_evidence(evidence, &spec)?;
            let status = self
                .task_controller()?
                .status(&spec)
                .map_err(map_native_error)?;
            match status.state {
                ScheduledTaskState::Absent => Ok(()),
                ScheduledTaskState::Ready | ScheduledTaskState::Running
                    if status.actual_definition_digest
                        == Some(*spec.expected_definition_digest()) =>
                {
                    Ok(())
                }
                other => Err(map_task_state(other)),
            }
        }

        fn verify_prefix(&mut self, record: &InstallRecord) -> Result<(), InstallControlError> {
            Self::verify_record_identity(record)?;
            // The revision-one product directory is the first external setup
            // effect. It is safe to create/repair only while INSTALLING; ACTIVE
            // and RETAINED verification never call this helper.
            self.root
                .create_relative_directories(Path::new(
                    record
                        .product_relative_path
                        .as_ref()
                        .ok_or(InstallControlError::Drifted)?
                        .as_str(),
                ))
                .map_err(map_control_storage_error)?;
            if record.protected_key.is_some() {
                self.verify_key_record(record)?;
            }
            if record.runtime.is_some() {
                self.verify_runtime_record(record)?;
            }
            if record.data_relative_path.is_some() {
                self.verify_data_record(record)?;
            }
            if record.scheduled_task.is_some() {
                // After a task checkpoint but before ACTIVE, a crash or a
                // retained reinstall may leave the exact task absent. Only
                // complete_installing is allowed to recreate it.
                self.verify_task_present_or_absent(record)?;
            }
            Ok(())
        }

        fn ensure_exact_key(
            &self,
            record: &InstallRecord,
        ) -> Result<ProtectedKeyArtifact, InstallControlError> {
            let relative = key_path(record.install_id.as_str())?;
            let parent = Path::new(relative.as_str())
                .parent()
                .ok_or(InstallControlError::Drifted)?;
            self.root
                .create_relative_directories(parent)
                .map_err(map_control_storage_error)?;

            match self.read_uncheckpointed_key(record, &relative) {
                Ok(evidence) => return Ok(evidence),
                Err(InstallControlError::Unavailable) => {}
                Err(_) => {
                    // Only an uncheckpointed, exact regular file with the
                    // expected protected ACL can be removed. Reparse/ACL/path
                    // drift makes remove_regular_file fail closed.
                    if !self
                        .root
                        .remove_regular_file(Path::new(relative.as_str()))
                        .map_err(map_control_storage_error)?
                    {
                        return Err(InstallControlError::Drifted);
                    }
                }
            }

            let key = EndpointKey::generate().map_err(map_native_error)?;
            let envelope =
                protect_endpoint_key(&key, record.install_id.as_str()).map_err(map_native_error)?;
            match self
                .root
                .create_endpoint_key_file(Path::new(relative.as_str()), &envelope)
            {
                Ok(()) => {}
                Err(error) if error.code() == StorageErrorCode::AlreadyExists => {}
                Err(error) => return Err(map_control_storage_error(error)),
            }
            self.read_uncheckpointed_key(record, &relative)
        }

        fn read_uncheckpointed_key(
            &self,
            record: &InstallRecord,
            relative: &RelativeWindowsPath,
        ) -> Result<ProtectedKeyArtifact, InstallControlError> {
            let envelope = match self
                .root
                .read_endpoint_key_file(Path::new(relative.as_str()))
            {
                Ok(envelope) => envelope,
                Err(error) if error.code() == StorageErrorCode::NotFound => {
                    return Err(InstallControlError::Unavailable);
                }
                Err(error) => return Err(map_control_storage_error(error)),
            };
            let _key = unprotect_endpoint_key(&envelope, record.install_id.as_str())
                .map_err(map_native_error)?;
            Ok(ProtectedKeyArtifact {
                relative_path: relative.clone(),
                sha256: digest_value(sha256_bytes(envelope.as_bytes()))?,
            })
        }

        fn reverify_bundle(&self) -> Result<(), InstallControlError> {
            let verified =
                verify_authenticode(&self.bundle.canonical_path, self.bundle.trust.policy())
                    .map_err(map_native_error)?;
            if !verification_matches(self.bundle.trust, verified)
                || sha256_bounded_file(&self.bundle.canonical_path)? != self.bundle.sha256
            {
                return Err(InstallControlError::Drifted);
            }
            Ok(())
        }

        fn ensure_exact_runtime(
            &self,
            record: &InstallRecord,
        ) -> Result<RuntimeArtifact, InstallControlError> {
            self.reverify_bundle()?;
            let digest = digest_value(self.bundle.sha256)?;
            let relative = runtime_path(record.install_id.as_str(), &digest)?;
            let parent = Path::new(relative.as_str())
                .parent()
                .ok_or(InstallControlError::Drifted)?;
            self.root
                .create_relative_directories(parent)
                .map_err(map_control_storage_error)?;

            let existing = match self
                .root
                .verify_artifact_file(Path::new(relative.as_str()), self.bundle.sha256)
            {
                Ok(path) => {
                    let signature = verify_authenticode(&path, self.bundle.trust.policy())
                        .map_err(map_native_error)?;
                    if !verification_matches(self.bundle.trust, signature) {
                        return Err(InstallControlError::Drifted);
                    }
                    true
                }
                Err(error) if error.code() == StorageErrorCode::NotFound => false,
                Err(error) => return Err(map_control_storage_error(error)),
            };
            if !existing {
                let mut published = false;
                for _ in 0..ARTIFACT_STAGE_ATTEMPTS {
                    let stage = runtime_stage_path(record.install_id.as_str(), &digest)?;
                    let mut source =
                        File::open(&self.bundle.canonical_path).map_err(map_io_error)?;
                    match self.root.copy_reader_verified(
                        &mut source,
                        Path::new(stage.as_str()),
                        self.bundle.sha256,
                    ) {
                        Ok(_) => {}
                        Err(error) if error.code() == StorageErrorCode::AlreadyExists => continue,
                        Err(error) => return Err(map_control_storage_error(error)),
                    }
                    let staged_absolute = self
                        .root
                        .verify_artifact_file(Path::new(stage.as_str()), self.bundle.sha256)
                        .map_err(map_control_storage_error)?;
                    let signature =
                        verify_authenticode(&staged_absolute, self.bundle.trust.policy())
                            .map_err(map_native_error)?;
                    if !verification_matches(self.bundle.trust, signature) {
                        let _ = self.root.remove_regular_file(Path::new(stage.as_str()));
                        return Err(InstallControlError::Drifted);
                    }
                    match self
                        .root
                        .publish_no_replace(Path::new(stage.as_str()), Path::new(relative.as_str()))
                    {
                        Ok(()) => {}
                        Err(error) if error.code() == StorageErrorCode::AlreadyExists => {}
                        Err(error) => {
                            let _ = self.root.remove_regular_file(Path::new(stage.as_str()));
                            return Err(map_control_storage_error(error));
                        }
                    }
                    // On a no-replace collision, this removes only our still-
                    // owned staging file. A successful publish moved it, so the
                    // result is simply NotFound/false.
                    let _ = self.root.remove_regular_file(Path::new(stage.as_str()));
                    self.verify_runtime_path(&relative)?;
                    published = true;
                    break;
                }
                if !published {
                    return Err(InstallControlError::StorageUnavailable);
                }
            }

            sync_directory_best_effort(&self.root, parent)?;
            self.verify_runtime_path(&relative)?;
            Ok(RuntimeArtifact {
                relative_path: relative,
                sha256: digest,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                signer_status: self.bundle.trust.signer_status(),
                artifact_format: RuntimeArtifactFormat::MeshDaemonExeV1,
            })
        }

        fn verify_runtime_path(
            &self,
            relative: &RelativeWindowsPath,
        ) -> Result<PathBuf, InstallControlError> {
            let absolute = self
                .root
                .verify_artifact_file(Path::new(relative.as_str()), self.bundle.sha256)
                .map_err(map_control_storage_error)?;
            let signature = verify_authenticode(&absolute, self.bundle.trust.policy())
                .map_err(map_native_error)?;
            if !verification_matches(self.bundle.trust, signature) {
                return Err(InstallControlError::Drifted);
            }
            Ok(absolute)
        }

        fn ensure_exact_data(
            &self,
            record: &InstallRecord,
        ) -> Result<(RelativeWindowsPath, u32), InstallControlError> {
            let relative = data_path(record.install_id.as_str())?;
            let absolute = self.root.path().join(relative.as_str());
            match fs::symlink_metadata(&absolute) {
                Ok(_) => {
                    if validate_data_root(&absolute).is_err() {
                        // Restart convergence permits repairing only the exact
                        // empty, uncheckpointed directory. The native boundary
                        // refuses nonempty or reparse roots.
                        protect_data_root(&absolute).map_err(map_control_storage_error)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.root
                        .create_relative_directories(Path::new(relative.as_str()))
                        .map_err(map_control_storage_error)?;
                    protect_data_root(&absolute).map_err(map_control_storage_error)?;
                }
                Err(error) => return Err(map_io_error(error)),
            }
            validate_data_root(&absolute).map_err(map_control_storage_error)?;

            let now = system_now_us()?;
            let writer = WriterHandle::start_windows(
                absolute.clone(),
                record.install_id.as_str(),
                now,
                None,
            )
            .map_err(map_db_error)?;
            let seed_result = writer.ensure_empty_config_v1(now).map_err(map_db_error);
            let shutdown_result = writer.shutdown().map_err(map_db_error);
            seed_result?;
            shutdown_result?;
            verify_database_evidence(&absolute, record.install_id.as_str())?;
            Ok((relative, CURRENT_DATA_SCHEMA_VERSION))
        }

        fn ensure_exact_task(
            &mut self,
            record: &InstallRecord,
        ) -> Result<ScheduledTaskEvidence, InstallControlError> {
            let spec = self.task_spec(record)?;
            let status = self
                .task_controller()?
                .status(&spec)
                .map_err(map_native_error)?;
            let status = match status.state {
                ScheduledTaskState::Absent => self
                    .task_controller()?
                    .setup(&spec)
                    .map_err(map_native_error)?,
                ScheduledTaskState::Ready | ScheduledTaskState::Running => status,
                other => return Err(map_task_state(other)),
            };
            if !matches!(
                status.state,
                ScheduledTaskState::Ready | ScheduledTaskState::Running
            ) || status.actual_definition_digest != Some(*spec.expected_definition_digest())
            {
                return Err(map_task_state(status.state));
            }
            task_evidence(&spec)
        }
    }

    impl SetupPlatform for WindowsSetupPlatform {
        fn now_us(&self) -> Result<i64, InstallControlError> {
            system_now_us()
        }

        fn initial_record(&mut self) -> Result<InstallRecord, InstallControlError> {
            let now = system_now_us()?;
            let install_id = random_stable_id()?;
            let consumer_id = random_stable_id()?;
            Ok(InstallRecord {
                format_version: INSTALL_RECORD_FORMAT_VERSION,
                install_id: install_id.clone(),
                consumer_id,
                state: crate::install_record::InstallState::Installing,
                revision: 1,
                product_relative_path: Some(product_path(install_id.as_str())?),
                data_relative_path: None,
                data_schema_version: None,
                protected_key: None,
                runtime: None,
                scheduled_task: None,
                created_at_us: now,
                updated_at_us: now,
            })
        }

        fn verify_active(&mut self, record: &InstallRecord) -> Result<(), InstallControlError> {
            Self::verify_record_identity(record)?;
            self.verify_key_record(record)?;
            self.verify_runtime_record(record)?;
            self.verify_data_record(record)?;
            self.verify_task_present(record)
        }

        fn verify_retained(&mut self, record: &InstallRecord) -> Result<(), InstallControlError> {
            Self::verify_record_identity(record)?;
            self.verify_key_record(record)?;
            self.verify_runtime_record(record)?;
            self.verify_data_record(record)?;
            self.verify_task_absent(record)
        }

        fn verify_installing_prefix(
            &mut self,
            record: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            self.verify_prefix(record)
        }

        fn ensure_key(
            &mut self,
            record: &InstallRecord,
        ) -> Result<ProtectedKeyArtifact, InstallControlError> {
            self.ensure_exact_key(record)
        }

        fn ensure_runtime(
            &mut self,
            record: &InstallRecord,
        ) -> Result<RuntimeArtifact, InstallControlError> {
            self.ensure_exact_runtime(record)
        }

        fn ensure_data(
            &mut self,
            record: &InstallRecord,
        ) -> Result<(RelativeWindowsPath, u32), InstallControlError> {
            self.ensure_exact_data(record)
        }

        fn ensure_task(
            &mut self,
            record: &InstallRecord,
        ) -> Result<ScheduledTaskEvidence, InstallControlError> {
            self.ensure_exact_task(record)
        }

        fn complete_installing(
            &mut self,
            record: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            Self::verify_record_identity(record)?;
            self.verify_key_record(record)?;
            self.verify_runtime_record(record)?;
            self.verify_data_record(record)?;
            let spec = self.task_spec(record)?;
            let evidence = record
                .scheduled_task
                .as_ref()
                .ok_or(InstallControlError::Drifted)?;
            verify_task_evidence(evidence, &spec)?;
            let status = self
                .task_controller()?
                .status(&spec)
                .map_err(map_native_error)?;
            if status.state == ScheduledTaskState::Absent {
                self.task_controller()?
                    .setup(&spec)
                    .map_err(map_native_error)?;
            }
            self.verify_task_present(record)
        }
    }

    fn purgeable_data_schema_version(version: Option<u32>) -> Result<u32, InstallControlError> {
        match version {
            Some(version) if (1..=CURRENT_DATA_SCHEMA_VERSION).contains(&version) => Ok(version),
            _ => Err(InstallControlError::Drifted),
        }
    }

    fn verify_database_evidence(root: &Path, install_id: &str) -> Result<(), InstallControlError> {
        verify_database_identity(root, install_id, CURRENT_DATA_SCHEMA_VERSION)?;
        let config = ReaderPool::open(root)
            .and_then(|reader| reader.empty_config(SETUP_READ_TIMEOUT))
            .map_err(map_db_error)?;
        if config.config_digest != EMPTY_CONFIG_V1_DIGEST
            || config
                .value
                .get("config_version")
                .and_then(serde_json::Value::as_u64)
                != Some(1)
        {
            return Err(InstallControlError::Drifted);
        }
        Ok(())
    }

    /// Purge only needs to prove the tree is this install's mesh database at
    /// the recorded schema. Setup still requires the current schema plus the
    /// empty config-v1 row; an older retained database is not runnable.
    fn verify_purge_database_evidence(
        root: &Path,
        install_id: &str,
        recorded_schema: u32,
    ) -> Result<(), InstallControlError> {
        verify_database_identity(root, install_id, recorded_schema)
    }

    fn verify_database_identity(
        root: &Path,
        install_id: &str,
        expected_schema: u32,
    ) -> Result<(), InstallControlError> {
        let database = root.join("mesh.sqlite3");
        let connection = Connection::open_with_flags(
            &database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| InstallControlError::StorageUnavailable)?;
        connection
            .busy_timeout(SETUP_READ_TIMEOUT)
            .map_err(|_| InstallControlError::StorageUnavailable)?;
        let application_id: i64 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(|_| InstallControlError::StorageUnavailable)?;
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| InstallControlError::StorageUnavailable)?;
        let meta: (i64, i64, String) = connection
            .query_row(
                "SELECT schema_version, application_id, install_id FROM storage_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| InstallControlError::Drifted)?;
        if application_id != i64::from(MESH_SQLITE_APPLICATION_ID)
            || meta.1 != i64::from(MESH_SQLITE_APPLICATION_ID)
            || user_version != i64::from(expected_schema)
            || meta.0 != i64::from(expected_schema)
            || meta.2 != install_id
        {
            return Err(InstallControlError::Drifted);
        }
        Ok(())
    }

    fn task_evidence(
        spec: &ScheduledTaskSpec,
    ) -> Result<ScheduledTaskEvidence, InstallControlError> {
        Ok(ScheduledTaskEvidence {
            task_path: ScheduledTaskPath::new(spec.task_path())
                .map_err(|_| InstallControlError::Drifted)?,
            definition_sha256: digest_value(*spec.expected_definition_digest())?,
        })
    }

    fn verify_task_evidence(
        evidence: &ScheduledTaskEvidence,
        spec: &ScheduledTaskSpec,
    ) -> Result<(), InstallControlError> {
        verify_task_evidence_values(
            evidence,
            &spec.task_path(),
            *spec.expected_definition_digest(),
        )
    }

    pub(super) fn verify_task_evidence_values(
        evidence: &ScheduledTaskEvidence,
        expected_path: &str,
        expected_definition_digest: [u8; 32],
    ) -> Result<(), InstallControlError> {
        let expected = ScheduledTaskEvidence {
            task_path: ScheduledTaskPath::new(expected_path)
                .map_err(|_| InstallControlError::Drifted)?,
            definition_sha256: digest_value(expected_definition_digest)?,
        };
        if evidence != &expected {
            return Err(InstallControlError::Drifted);
        }
        Ok(())
    }

    pub(super) fn verify_recorded_digest(
        expected: &Sha256Digest,
        observed: [u8; 32],
    ) -> Result<(), InstallControlError> {
        if expected.as_str() != digest_hex(observed) {
            return Err(InstallControlError::Drifted);
        }
        Ok(())
    }

    const fn verification_matches(
        trust: RuntimeTrust,
        verification: AuthenticodeVerification,
    ) -> bool {
        matches!(
            (trust, verification),
            (
                RuntimeTrust::Official { .. },
                AuthenticodeVerification::OfficialSigned { .. }
            ) | (
                RuntimeTrust::UnsignedDevelopment,
                AuthenticodeVerification::UnsignedDevelopment
            )
        )
    }

    fn random_stable_id() -> Result<StableId, InstallControlError> {
        let mut bytes = [0_u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        StableId::new(hex_lower(&bytes)).map_err(|_| InstallControlError::StorageUnavailable)
    }

    fn sha256_bounded_file(path: &Path) -> Result<[u8; 32], InstallControlError> {
        let mut file = File::open(path).map_err(map_io_error)?;
        let length = file.metadata().map_err(map_io_error)?.len();
        if length == 0 || length > ValidatedControlRoot::MAX_EXECUTABLE_BYTES {
            return Err(InstallControlError::Drifted);
        }
        let mut digest = Sha256::new();
        let mut observed = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let count = file.read(&mut buffer).map_err(map_io_error)?;
            if count == 0 {
                break;
            }
            observed = observed
                .checked_add(u64::try_from(count).map_err(|_| InstallControlError::Drifted)?)
                .ok_or(InstallControlError::Drifted)?;
            if observed > ValidatedControlRoot::MAX_EXECUTABLE_BYTES {
                return Err(InstallControlError::Drifted);
            }
            digest.update(&buffer[..count]);
        }
        if observed != length {
            return Err(InstallControlError::Drifted);
        }
        Ok(digest.finalize().into())
    }

    fn system_now_us() -> Result<i64, InstallControlError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| InstallControlError::InvalidClock)?;
        i64::try_from(elapsed.as_micros()).map_err(|_| InstallControlError::InvalidClock)
    }

    fn sync_directory_best_effort(
        root: &ValidatedControlRoot,
        relative: &Path,
    ) -> Result<(), InstallControlError> {
        match root.sync_directory(relative) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == StorageErrorCode::DirectorySyncUnsupported => Ok(()),
            Err(error) => Err(map_control_storage_error(error)),
        }
    }

    fn map_task_state(state: ScheduledTaskState) -> InstallControlError {
        match state {
            ScheduledTaskState::AccessDenied => InstallControlError::AccessDenied,
            ScheduledTaskState::Absent | ScheduledTaskState::Disabled => {
                InstallControlError::Unavailable
            }
            ScheduledTaskState::Drifted => InstallControlError::Drifted,
            _ => InstallControlError::StorageUnavailable,
        }
    }

    fn map_native_error(error: NativeError) -> InstallControlError {
        match error.code() {
            NativeErrorCode::AccessDenied | NativeErrorCode::SetupAccessDenied => {
                InstallControlError::AccessDenied
            }
            NativeErrorCode::SingletonConflict => InstallControlError::Busy,
            NativeErrorCode::SetupRemoving => InstallControlError::Removing,
            NativeErrorCode::SetupAbsent | NativeErrorCode::SetupDisabled => {
                InstallControlError::Unavailable
            }
            NativeErrorCode::InvalidArgument
            | NativeErrorCode::AuthenticationFailed
            | NativeErrorCode::SetupDrifted
            | NativeErrorCode::SecretInvalid
            | NativeErrorCode::SecretProtectionFailed => InstallControlError::Drifted,
            _ => InstallControlError::StorageUnavailable,
        }
    }

    fn map_control_storage_error(error: StorageError) -> InstallControlError {
        match error.code() {
            StorageErrorCode::AccessDenied => InstallControlError::AccessDenied,
            StorageErrorCode::Io if error.os_code() == Some(5) => InstallControlError::AccessDenied,
            StorageErrorCode::InvalidPath
            | StorageErrorCode::PathEscapesRoot
            | StorageErrorCode::NotFound
            | StorageErrorCode::ReparsePoint
            | StorageErrorCode::NotDirectory
            | StorageErrorCode::NotRegularFile
            | StorageErrorCode::NotFixedVolume
            | StorageErrorCode::NotNtfsVolume
            | StorageErrorCode::InsecureAcl
            | StorageErrorCode::DifferentVolume
            | StorageErrorCode::SparseFile
            | StorageErrorCode::CompressedFile
            | StorageErrorCode::InsufficientAllocation
            | StorageErrorCode::PublicationVerificationFailed
            | StorageErrorCode::DigestMismatch
            | StorageErrorCode::SizeOverflow
            | StorageErrorCode::PurgeTreeConflict
            | StorageErrorCode::IdentityChanged
            | StorageErrorCode::SharingViolation
            | StorageErrorCode::ControllerInsideControlRoot
            | StorageErrorCode::TraversalLimit
            | StorageErrorCode::UnexpectedEntry
            | StorageErrorCode::InvalidProtectedKey
            | StorageErrorCode::TooLarge => InstallControlError::Drifted,
            StorageErrorCode::AlreadyExists => InstallControlError::ConcurrentChange,
            _ => InstallControlError::StorageUnavailable,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn map_db_error(error: DbError) -> InstallControlError {
        match error {
            DbError::InvalidRoot(_)
            | DbError::Quarantined(_)
            | DbError::BlobCorruption(_)
            | DbError::MigrationMismatch(_)
            | DbError::InvalidRequest => InstallControlError::Drifted,
            _ => InstallControlError::StorageUnavailable,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn map_io_error(error: std::io::Error) -> InstallControlError {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            InstallControlError::AccessDenied
        } else {
            InstallControlError::StorageUnavailable
        }
    }

    fn map_store_error(error: crate::install_store::InstallStoreError) -> InstallControlError {
        use crate::install_store::InstallStoreError;
        match error {
            InstallStoreError::AccessDenied => InstallControlError::AccessDenied,
            InstallStoreError::AdmissionBusy | InstallStoreError::CompareAndSwapConflict => {
                InstallControlError::Busy
            }
            InstallStoreError::OrdinaryTrafficUnavailable => InstallControlError::Unavailable,
            InstallStoreError::InvalidRecord
            | InstallStoreError::Integrity
            | InstallStoreError::AdmissionChanged
            | InstallStoreError::PurgePrecondition
            | InstallStoreError::PurgeStageDrift => InstallControlError::Drifted,
            InstallStoreError::Storage | InstallStoreError::Lock => {
                InstallControlError::StorageUnavailable
            }
        }
    }
}

#[cfg(windows)]
pub use platform::WindowsSetupPlatform;
#[cfg(windows)]
pub(crate) use platform::{verify_complete_purge_artifacts, verify_external_purge_controller};

/// Explicit unsupported-platform implementation. This keeps accidental use on
/// macOS/Linux machine-readable instead of silently selecting portable setup.
#[cfg(not(windows))]
#[derive(Debug, Default, Eq, PartialEq)]
pub struct WindowsSetupPlatform;

#[cfg(not(windows))]
impl WindowsSetupPlatform {
    pub fn open_official_current_executable() -> Result<Self, InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    pub fn open_unsigned_development_current_executable() -> Result<Self, InstallControlError> {
        Err(InstallControlError::Unavailable)
    }
}

#[cfg(not(windows))]
impl SetupPlatform for WindowsSetupPlatform {
    fn now_us(&self) -> Result<i64, InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn initial_record(&mut self) -> Result<InstallRecord, InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn verify_active(&mut self, _record: &InstallRecord) -> Result<(), InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn verify_retained(&mut self, _record: &InstallRecord) -> Result<(), InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn verify_installing_prefix(
        &mut self,
        _record: &InstallRecord,
    ) -> Result<(), InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn ensure_key(
        &mut self,
        _record: &InstallRecord,
    ) -> Result<ProtectedKeyArtifact, InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn ensure_runtime(
        &mut self,
        _record: &InstallRecord,
    ) -> Result<RuntimeArtifact, InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn ensure_data(
        &mut self,
        _record: &InstallRecord,
    ) -> Result<(RelativeWindowsPath, u32), InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn ensure_task(
        &mut self,
        _record: &InstallRecord,
    ) -> Result<ScheduledTaskEvidence, InstallControlError> {
        Err(InstallControlError::Unavailable)
    }

    fn complete_installing(&mut self, _record: &InstallRecord) -> Result<(), InstallControlError> {
        Err(InstallControlError::Unavailable)
    }
}

fn product_path(install_id: &str) -> Result<RelativeWindowsPath, InstallControlError> {
    RelativeWindowsPath::new(format!(r"{PRODUCT_DIRECTORY}\{install_id}"))
        .map_err(|_| InstallControlError::Drifted)
}

fn key_path(install_id: &str) -> Result<RelativeWindowsPath, InstallControlError> {
    RelativeWindowsPath::new(format!(
        r"{PRODUCT_DIRECTORY}\{install_id}\secrets\{ENDPOINT_KEY_FILE_NAME}"
    ))
    .map_err(|_| InstallControlError::Drifted)
}

fn data_path(install_id: &str) -> Result<RelativeWindowsPath, InstallControlError> {
    RelativeWindowsPath::new(format!(
        r"{PRODUCT_DIRECTORY}\{install_id}\{DATA_DIRECTORY_NAME}"
    ))
    .map_err(|_| InstallControlError::Drifted)
}

fn runtime_path(
    install_id: &str,
    digest: &Sha256Digest,
) -> Result<RelativeWindowsPath, InstallControlError> {
    RelativeWindowsPath::new(format!(
        r"{PRODUCT_DIRECTORY}\{install_id}\bin\{}\{RUNTIME_FILE_NAME}",
        digest.as_str()
    ))
    .map_err(|_| InstallControlError::Drifted)
}

#[cfg(windows)]
fn runtime_stage_path(
    install_id: &str,
    digest: &Sha256Digest,
) -> Result<RelativeWindowsPath, InstallControlError> {
    let nonce = rand::random::<u64>();
    RelativeWindowsPath::new(format!(
        r"{PRODUCT_DIRECTORY}\{install_id}\bin\{}\mesh-daemon.{nonce:016x}.new",
        digest.as_str()
    ))
    .map_err(|_| InstallControlError::Drifted)
}

#[cfg(windows)]
fn digest_value(bytes: [u8; 32]) -> Result<Sha256Digest, InstallControlError> {
    Sha256Digest::new(digest_hex(bytes)).map_err(|_| InstallControlError::Drifted)
}

#[cfg(windows)]
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

#[cfg(windows)]
fn digest_hex(bytes: [u8; 32]) -> String {
    hex_lower(&bytes)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], InstallControlError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InstallControlError::Drifted);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, InstallControlError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(InstallControlError::Drifted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::storage::MESH_SQLITE_APPLICATION_ID;

    const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn official_embedded_identity_decoder_is_exact_lower_hex() {
        let decoded = decode_lower_hex_32(DIGEST).expect("valid digest");
        assert_eq!(hex_lower(&decoded), DIGEST);
        for invalid in [
            "",
            "0123",
            "A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(
                decode_lower_hex_32(invalid),
                Err(InstallControlError::Drifted)
            );
        }
    }

    #[test]
    fn frozen_evidence_paths_have_the_exact_stable_shape() {
        let digest = Sha256Digest::new(DIGEST).expect("digest");
        assert_eq!(
            product_path(INSTALL_ID).expect("product").as_str(),
            format!(r"installs\{INSTALL_ID}")
        );
        assert_eq!(
            key_path(INSTALL_ID).expect("key").as_str(),
            format!(r"installs\{INSTALL_ID}\secrets\endpoint-key.dpapi")
        );
        assert_eq!(
            data_path(INSTALL_ID).expect("data").as_str(),
            format!(r"installs\{INSTALL_ID}\data")
        );
        assert_eq!(
            runtime_path(INSTALL_ID, &digest).expect("runtime").as_str(),
            format!(r"installs\{INSTALL_ID}\bin\{DIGEST}\mesh-daemon.exe")
        );
    }

    #[test]
    fn stable_control_modes_have_fixed_arguments_and_lifecycle_allowlists() {
        assert_eq!(
            StableControlMode::Status.arguments(),
            ["status", "--install-slot", "stable"]
        );
        assert_eq!(
            StableControlMode::Start.arguments(),
            ["start", "--install-slot", "stable"]
        );
        assert_eq!(
            StableControlMode::Remove.arguments(),
            ["remove", "--install-slot", "stable"]
        );
        assert_eq!(
            StableControlMode::RemoveAndPurge.arguments(),
            ["remove", "--install-slot", "stable", "--purge-data"]
        );

        for state in [
            crate::install_record::InstallState::Active,
            crate::install_record::InstallState::Removing,
            crate::install_record::InstallState::Retained,
        ] {
            assert!(StableControlMode::Status.admits(state));
            assert!(StableControlMode::Remove.admits(state));
        }
        assert!(StableControlMode::Start.admits(crate::install_record::InstallState::Active));
        for state in [
            crate::install_record::InstallState::Installing,
            crate::install_record::InstallState::Removing,
            crate::install_record::InstallState::Retained,
            crate::install_record::InstallState::Broken,
        ] {
            assert!(!StableControlMode::Start.admits(state));
        }
    }

    #[cfg(windows)]
    #[test]
    fn stable_control_recursion_requires_exact_retained_path() {
        let retained = Path::new(
            r"C:\control\installs\0123456789abcdef0123456789abcdef\bin\digest\mesh-daemon.exe",
        );
        assert!(is_exact_retained_runtime(retained, retained));
        assert!(!is_exact_retained_runtime(
            Path::new(r"C:\plugin-cache\mesh-daemon.exe"),
            retained
        ));
    }

    #[cfg(windows)]
    #[test]
    fn sqlite_application_id_is_exact_ascii_mesh() {
        assert_eq!(
            i64::from(MESH_SQLITE_APPLICATION_ID),
            i64::from(u32::from_be_bytes(*b"MESH"))
        );
    }

    #[cfg(windows)]
    fn complete_purge_record(
        state: crate::install_record::InstallState,
        runtime_digest: &str,
    ) -> InstallRecord {
        let runtime_digest = Sha256Digest::new(runtime_digest).expect("runtime digest");
        InstallRecord {
            format_version: INSTALL_RECORD_FORMAT_VERSION,
            install_id: StableId::new(INSTALL_ID).expect("install id"),
            consumer_id: StableId::new("fedcba9876543210fedcba9876543210").expect("consumer id"),
            state,
            revision: 7,
            product_relative_path: Some(product_path(INSTALL_ID).expect("product path")),
            data_relative_path: Some(data_path(INSTALL_ID).expect("data path")),
            data_schema_version: Some(crate::storage::CURRENT_DATA_SCHEMA_VERSION),
            protected_key: Some(ProtectedKeyArtifact {
                relative_path: key_path(INSTALL_ID).expect("key path"),
                sha256: Sha256Digest::new(DIGEST).expect("key digest"),
            }),
            runtime: Some(RuntimeArtifact {
                relative_path: runtime_path(INSTALL_ID, &runtime_digest).expect("runtime path"),
                sha256: runtime_digest,
                // A retained runtime may be older than the external purge
                // controller. Preflight validates this bounded value but does
                // not equate it to the current crate version.
                version: "0.0.1-retained".to_owned(),
                signer_status: SignerStatus::UnsignedDevelopment,
                artifact_format: RuntimeArtifactFormat::MeshDaemonExeV1,
            }),
            scheduled_task: Some(ScheduledTaskEvidence {
                task_path: ScheduledTaskPath::new(r"\CodexAgentMesh-daemon-fixture")
                    .expect("task path"),
                definition_sha256: Sha256Digest::new(DIGEST).expect("task digest"),
            }),
            created_at_us: 1,
            updated_at_us: 7,
        }
    }

    #[cfg(windows)]
    #[test]
    fn purge_preflight_admits_only_complete_pre_purge_states() {
        use crate::install_record::InstallState;

        for admitted in [
            InstallState::Active,
            InstallState::Removing,
            InstallState::Retained,
        ] {
            let record = complete_purge_record(admitted, DIGEST);
            assert!(record.validate().is_ok());
            assert_eq!(
                platform::validate_purge_preflight_record(&record),
                Ok(platform::RuntimeTrust::UnsignedDevelopment)
            );
        }
        for rejected in [
            InstallState::Installing,
            InstallState::Purging,
            InstallState::Broken,
        ] {
            let record = complete_purge_record(rejected, DIGEST);
            assert!(record.validate().is_ok());
            assert_eq!(
                platform::validate_purge_preflight_record(&record),
                Err(InstallControlError::Drifted)
            );
        }

        let purging = complete_purge_record(InstallState::Purging, DIGEST);
        assert_eq!(
            platform::admit_external_purge_controller_verification(
                &purging,
                mesh_win32::AuthenticodeVerification::UnsignedDevelopment,
            ),
            Ok(()),
            "PURGING resume revalidates only the external controller and frozen record"
        );
        for rejected in [InstallState::Installing, InstallState::Broken] {
            let record = complete_purge_record(rejected, DIGEST);
            assert_eq!(
                platform::admit_external_purge_controller_verification(
                    &record,
                    mesh_win32::AuthenticodeVerification::UnsignedDevelopment,
                ),
                Err(InstallControlError::Drifted)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn external_controller_admission_is_independent_of_retained_runtime_digest_and_version() {
        let first = complete_purge_record(
            crate::install_record::InstallState::Retained,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let mut second = complete_purge_record(
            crate::install_record::InstallState::Retained,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        second.runtime.as_mut().expect("runtime").version = "99.0.0-newer".to_owned();

        for record in [&first, &second] {
            assert_eq!(
                platform::admit_external_purge_controller_verification(
                    record,
                    mesh_win32::AuthenticodeVerification::UnsignedDevelopment,
                ),
                Ok(())
            );
        }
        assert_eq!(
            platform::admit_external_purge_controller_verification(
                &first,
                mesh_win32::AuthenticodeVerification::OfficialSigned {
                    signer_certificate_sha256: [0x11; 32],
                },
            ),
            Err(InstallControlError::Drifted)
        );
    }

    #[cfg(windows)]
    #[test]
    fn external_controller_uses_current_executable_outside_a_temporary_control_root() {
        use sha2::{Digest, Sha256};

        let directory = tempfile::tempdir().expect("temporary control root");
        mesh_win32::protect_control_root(directory.path()).expect("protect temporary root");
        let root = mesh_win32::validate_control_root(directory.path()).expect("validate root");
        let record = complete_purge_record(
            crate::install_record::InstallState::Purging,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        platform::verify_external_purge_controller(&root, &record)
            .expect("unsigned test controller outside temporary product root");
        let executable =
            std::fs::canonicalize(std::env::current_exe().expect("current executable"))
                .expect("canonical executable");
        assert_ne!(
            <[u8; 32]>::from(Sha256::digest(
                std::fs::read(executable).expect("read controller")
            )),
            decode_lower_hex_32(record.runtime.as_ref().expect("runtime").sha256.as_str())
                .expect("retained digest"),
            "the external controller must not be equated to retained runtime bytes"
        );
    }

    #[cfg(windows)]
    #[test]
    fn purge_record_paths_fail_closed_before_filesystem_access() {
        let baseline = complete_purge_record(crate::install_record::InstallState::Retained, DIGEST);

        let mut product = baseline.clone();
        product.product_relative_path = Some(
            RelativeWindowsPath::new(r"installs\fedcba9876543210fedcba9876543210")
                .expect("safe but foreign product path"),
        );
        let mut key = baseline.clone();
        key.protected_key.as_mut().expect("key").relative_path =
            RelativeWindowsPath::new(format!(r"installs\{INSTALL_ID}\secrets\other.dpapi"))
                .expect("safe but foreign key path");
        let mut data = baseline.clone();
        data.data_relative_path = Some(
            RelativeWindowsPath::new(format!(r"installs\{INSTALL_ID}\other-data"))
                .expect("safe but foreign data path"),
        );
        let mut runtime = baseline.clone();
        runtime.runtime.as_mut().expect("runtime").relative_path =
            RelativeWindowsPath::new(format!(r"installs\{INSTALL_ID}\bin\{DIGEST}\other.exe"))
                .expect("safe but foreign runtime path");
        let mut schema = baseline;
        schema.data_schema_version = Some(crate::storage::CURRENT_DATA_SCHEMA_VERSION + 1);

        for drifted in [&product, &key, &data, &runtime, &schema] {
            assert_eq!(
                platform::validate_purge_preflight_record(drifted),
                Err(InstallControlError::Drifted)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn purge_admits_older_recorded_schema_and_rejects_future() {
        let mut older =
            complete_purge_record(crate::install_record::InstallState::Retained, DIGEST);
        older.data_schema_version = Some(1);
        platform::validate_purge_preflight_record(&older)
            .expect("schema 1 remains a complete older install");

        let mut four = complete_purge_record(crate::install_record::InstallState::Active, DIGEST);
        four.data_schema_version = Some(4);
        platform::validate_purge_preflight_record(&four)
            .expect("schema 4 remains a complete older install");

        let mut missing =
            complete_purge_record(crate::install_record::InstallState::Retained, DIGEST);
        missing.data_schema_version = None;
        assert_eq!(
            platform::validate_purge_preflight_record(&missing),
            Err(InstallControlError::Drifted)
        );
        let mut future =
            complete_purge_record(crate::install_record::InstallState::Retained, DIGEST);
        future.data_schema_version = Some(crate::storage::CURRENT_DATA_SCHEMA_VERSION + 1);
        assert_eq!(
            platform::validate_purge_preflight_record(&future),
            Err(InstallControlError::Drifted)
        );
    }

    #[cfg(windows)]
    #[test]
    fn purge_key_and_task_digest_drift_fail_closed() {
        let expected = Sha256Digest::new(DIGEST).expect("digest");
        assert_eq!(
            platform::verify_recorded_digest(&expected, [0x01; 32]),
            Err(InstallControlError::Drifted)
        );
        assert_eq!(
            platform::verify_recorded_digest(&expected, decode_lower_hex_32(DIGEST).unwrap()),
            Ok(())
        );

        let evidence = ScheduledTaskEvidence {
            task_path: ScheduledTaskPath::new(r"\CodexAgentMesh-daemon-fixture")
                .expect("task path"),
            definition_sha256: expected,
        };
        let digest = decode_lower_hex_32(DIGEST).expect("digest bytes");
        assert_eq!(
            platform::verify_task_evidence_values(
                &evidence,
                r"\CodexAgentMesh-daemon-fixture",
                digest,
            ),
            Ok(())
        );
        assert_eq!(
            platform::verify_task_evidence_values(
                &evidence,
                r"\CodexAgentMesh-daemon-other",
                digest,
            ),
            Err(InstallControlError::Drifted)
        );
        assert_eq!(
            platform::verify_task_evidence_values(
                &evidence,
                r"\CodexAgentMesh-daemon-fixture",
                [0x33; 32],
            ),
            Err(InstallControlError::Drifted)
        );
    }

    #[cfg(windows)]
    #[test]
    fn complete_purge_artifacts_verify_in_temporary_root_without_task_scheduler() {
        use std::fs::File;

        use mesh_win32::{
            EndpointKey, ScheduledTaskSpec, protect_control_root, protect_data_root,
            protect_endpoint_key, validate_control_root,
        };
        use sha2::{Digest, Sha256};

        let directory = tempfile::tempdir().expect("temporary control root");
        protect_control_root(directory.path()).expect("protect temporary root");
        let root = validate_control_root(directory.path()).expect("validate control root");
        let key_relative = key_path(INSTALL_ID).expect("key path");
        let data_relative = data_path(INSTALL_ID).expect("data path");
        root.create_relative_directories(
            Path::new(key_relative.as_str())
                .parent()
                .expect("key parent"),
        )
        .expect("create key parent");

        let key = EndpointKey::generate().expect("endpoint key");
        let envelope = protect_endpoint_key(&key, INSTALL_ID).expect("protect endpoint key");
        root.create_endpoint_key_file(Path::new(key_relative.as_str()), &envelope)
            .expect("create endpoint envelope");
        let key_digest: [u8; 32] = Sha256::digest(envelope.as_bytes()).into();

        let current = std::env::current_exe().expect("current executable");
        let runtime_bytes = std::fs::read(&current).expect("read runtime fixture");
        let runtime_digest: [u8; 32] = Sha256::digest(&runtime_bytes).into();
        let runtime_digest_value = digest_value(runtime_digest).expect("runtime digest");
        let runtime_relative =
            runtime_path(INSTALL_ID, &runtime_digest_value).expect("runtime path");
        root.create_relative_directories(
            Path::new(runtime_relative.as_str())
                .parent()
                .expect("runtime parent"),
        )
        .expect("create runtime parent");
        let mut runtime_source = File::open(&current).expect("open runtime fixture");
        root.copy_reader_verified(
            &mut runtime_source,
            Path::new(runtime_relative.as_str()),
            runtime_digest,
        )
        .expect("publish runtime fixture");

        root.create_relative_directories(Path::new(data_relative.as_str()))
            .expect("create data root");
        let data_absolute = root.path().join(data_relative.as_str());
        protect_data_root(&data_absolute).expect("protect data root");
        let writer =
            crate::writer::WriterHandle::start_windows(data_absolute.clone(), INSTALL_ID, 1, None)
                .expect("initialize storage");
        writer.ensure_empty_config_v1(1).expect("seed config");
        writer.shutdown().expect("close storage");

        let runtime_absolute = root
            .verify_artifact_file(Path::new(runtime_relative.as_str()), runtime_digest)
            .expect("verify runtime fixture");
        let task_spec = ScheduledTaskSpec::new(INSTALL_ID, &runtime_absolute, runtime_digest)
            .expect("task spec");
        let mut record = complete_purge_record(
            crate::install_record::InstallState::Retained,
            runtime_digest_value.as_str(),
        );
        record.protected_key = Some(ProtectedKeyArtifact {
            relative_path: key_relative.clone(),
            sha256: digest_value(key_digest).expect("key digest"),
        });
        record.scheduled_task = Some(ScheduledTaskEvidence {
            task_path: ScheduledTaskPath::new(task_spec.task_path()).expect("task path"),
            definition_sha256: digest_value(*task_spec.expected_definition_digest())
                .expect("task definition digest"),
        });

        let artifacts = platform::verify_complete_purge_artifacts(&root, &record)
            .expect("complete record-derived artifacts");
        assert_eq!(
            artifacts.task_spec().expected_definition_digest(),
            task_spec.expected_definition_digest()
        );

        let mut key_drift = record.clone();
        let mut wrong_key_digest = key_digest;
        wrong_key_digest[0] ^= 1;
        key_drift.protected_key.as_mut().expect("key").sha256 =
            digest_value(wrong_key_digest).expect("foreign digest");
        assert_eq!(
            platform::verify_complete_purge_artifacts(&root, &key_drift).map(|_| ()),
            Err(InstallControlError::Drifted)
        );
        let mut task_drift = record;
        let mut wrong_task_digest = *task_spec.expected_definition_digest();
        wrong_task_digest[0] ^= 1;
        task_drift
            .scheduled_task
            .as_mut()
            .expect("task")
            .definition_sha256 = digest_value(wrong_task_digest).expect("foreign digest");
        assert_eq!(
            platform::verify_complete_purge_artifacts(&root, &task_drift).map(|_| ()),
            Err(InstallControlError::Drifted)
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_never_selects_portable_setup() {
        assert_eq!(
            WindowsSetupPlatform::open_unsigned_development_current_executable(),
            Err(InstallControlError::Unavailable)
        );
    }
}
