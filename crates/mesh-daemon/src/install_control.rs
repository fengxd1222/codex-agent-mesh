//! Restart-safe orchestration for the one stable installation slot.
//!
//! The platform implementation owns Windows evidence. This module owns only
//! the durable ordering: one external effect is verified, one checkpoint is
//! compare-and-swapped, and `ACTIVE` is published last.

#![allow(clippy::missing_errors_doc)]

use thiserror::Error;

use crate::{
    ErrorCode,
    install_record::{
        InstallCheckpoint, InstallRecord, InstallRecordError, InstallState, ProtectedKeyArtifact,
        RelativeWindowsPath, RuntimeArtifact, ScheduledTaskEvidence,
    },
    install_store::{InstallStoreError, SetupConvergenceGuard, StableInstallRecordStore},
};

const MAX_CONVERGENCE_STEPS: usize = 64;

/// Redaction-safe failure from stable-slot control orchestration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InstallControlError {
    #[error("stable installation is being removed")]
    Removing,
    #[error("stable installation evidence drifted")]
    Drifted,
    #[error("stable installation access was denied")]
    AccessDenied,
    #[error("stable installation is busy")]
    Busy,
    #[error("stable installation storage is unavailable")]
    StorageUnavailable,
    #[error("stable installation clock is invalid")]
    InvalidClock,
    #[error("stable installation is absent or disabled")]
    Unavailable,
    #[error("stable installation changed concurrently")]
    ConcurrentChange,
}

impl InstallControlError {
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::Removing => ErrorCode::SetupRemoving,
            Self::Drifted => ErrorCode::SetupDrifted,
            Self::AccessDenied => ErrorCode::SetupAccessDenied,
            Self::Busy | Self::ConcurrentChange => ErrorCode::SingletonConflict,
            Self::StorageUnavailable => ErrorCode::StorageUnavailable,
            Self::InvalidClock => ErrorCode::ValidationFailed,
            Self::Unavailable => ErrorCode::SetupDisabled,
        }
    }
}

/// Record operations available only while the setup convergence fence is held.
pub trait SetupRecordGuard {
    fn load_record(&self) -> Result<Option<InstallRecord>, InstallControlError>;
    fn compare_and_swap_record(
        &self,
        expected_revision: u64,
        next: &InstallRecord,
    ) -> Result<(), InstallControlError>;
}

/// Store capable of acquiring one exclusive setup convergence fence.
pub trait SetupRecordStore {
    type Guard<'store>: SetupRecordGuard
    where
        Self: 'store;

    fn acquire_setup_guard(&self) -> Result<Self::Guard<'_>, InstallControlError>;
}

impl SetupRecordStore for StableInstallRecordStore {
    type Guard<'store> = SetupConvergenceGuard<'store>;

    fn acquire_setup_guard(&self) -> Result<Self::Guard<'_>, InstallControlError> {
        StableInstallRecordStore::acquire_setup_guard(self).map_err(map_store_error)
    }
}

impl SetupRecordGuard for SetupConvergenceGuard<'_> {
    fn load_record(&self) -> Result<Option<InstallRecord>, InstallControlError> {
        self.load().map_err(map_store_error)
    }

    fn compare_and_swap_record(
        &self,
        expected_revision: u64,
        next: &InstallRecord,
    ) -> Result<(), InstallControlError> {
        self.compare_and_swap(expected_revision, next)
            .map_err(map_store_error)
    }
}

/// Platform evidence required by the ordered setup state machine.
///
/// Every `ensure_*` method must either return independently revalidated durable
/// evidence or fail without claiming its checkpoint. Existing evidence is
/// verified again before the next effect. `complete_installing` is the one
/// place an exact absent Scheduled Task may be recreated for a complete
/// `INSTALLING` record (including a same-runtime retained reinstall).
pub trait SetupPlatform {
    fn now_us(&self) -> Result<i64, InstallControlError>;
    fn initial_record(&mut self) -> Result<InstallRecord, InstallControlError>;
    fn verify_active(&mut self, record: &InstallRecord) -> Result<(), InstallControlError>;
    fn verify_retained(&mut self, record: &InstallRecord) -> Result<(), InstallControlError>;
    fn verify_installing_prefix(
        &mut self,
        record: &InstallRecord,
    ) -> Result<(), InstallControlError>;
    fn ensure_key(
        &mut self,
        record: &InstallRecord,
    ) -> Result<ProtectedKeyArtifact, InstallControlError>;
    fn ensure_runtime(
        &mut self,
        record: &InstallRecord,
    ) -> Result<RuntimeArtifact, InstallControlError>;
    fn ensure_data(
        &mut self,
        record: &InstallRecord,
    ) -> Result<(RelativeWindowsPath, u32), InstallControlError>;
    fn ensure_task(
        &mut self,
        record: &InstallRecord,
    ) -> Result<ScheduledTaskEvidence, InstallControlError>;
    fn complete_installing(&mut self, record: &InstallRecord) -> Result<(), InstallControlError>;
}

/// Converges setup to one fully verified `ACTIVE` record.
///
/// The production store holds its cross-process setup fence for this entire
/// call. A CAS conflict under that fence is therefore integrity drift, not a
/// setup winner to adopt. External evidence may be adopted only by the
/// corresponding platform method after it verifies the durable prefix.
pub fn converge_setup<S: SetupRecordStore, P: SetupPlatform>(
    store: &S,
    platform: &mut P,
) -> Result<InstallRecord, InstallControlError> {
    let guard = store.acquire_setup_guard()?;
    converge_setup_guarded(&guard, platform)
}

fn converge_setup_guarded<G: SetupRecordGuard, P: SetupPlatform>(
    guard: &G,
    platform: &mut P,
) -> Result<InstallRecord, InstallControlError> {
    for _ in 0..MAX_CONVERGENCE_STEPS {
        let Some(record) = guard.load_record()? else {
            let initial = platform.initial_record()?;
            match guard.compare_and_swap_record(0, &initial) {
                Ok(()) => continue,
                Err(InstallControlError::ConcurrentChange) => {
                    return Err(InstallControlError::Drifted);
                }
                Err(error) => return Err(error),
            }
        };
        record
            .validate()
            .map_err(|_| InstallControlError::Drifted)?;
        // Reject a regressed/invalid clock before asking the platform to make
        // another externally visible setup effect.
        checked_now(&record, platform.now_us()?)?;
        match record.state {
            InstallState::Active => {
                platform.verify_active(&record)?;
                return Ok(record);
            }
            InstallState::Removing | InstallState::Purging => {
                return Err(InstallControlError::Removing);
            }
            InstallState::Broken => return Err(InstallControlError::Drifted),
            InstallState::Retained => {
                platform.verify_retained(&record)?;
                let next = transition(&record, InstallState::Installing, platform.now_us()?)?;
                persist_guarded(guard, record.revision, &next)?;
            }
            InstallState::Installing => {
                platform.verify_installing_prefix(&record)?;
                let checkpoint = if record.protected_key.is_none() {
                    InstallCheckpoint {
                        protected_key: Some(platform.ensure_key(&record)?),
                        ..InstallCheckpoint::default()
                    }
                } else if record.runtime.is_none() {
                    InstallCheckpoint {
                        runtime: Some(platform.ensure_runtime(&record)?),
                        ..InstallCheckpoint::default()
                    }
                } else if record.data_relative_path.is_none() {
                    let (path, version) = platform.ensure_data(&record)?;
                    InstallCheckpoint {
                        data_relative_path: Some(path),
                        data_schema_version: Some(version),
                        ..InstallCheckpoint::default()
                    }
                } else if record.scheduled_task.is_none() {
                    InstallCheckpoint {
                        scheduled_task: Some(platform.ensure_task(&record)?),
                        ..InstallCheckpoint::default()
                    }
                } else {
                    platform.complete_installing(&record)?;
                    let next = transition(&record, InstallState::Active, platform.now_us()?)?;
                    persist_guarded(guard, record.revision, &next)?;
                    continue;
                };
                let next = record
                    .checkpoint(
                        record.revision,
                        checkpoint,
                        checked_now(&record, platform.now_us()?)?,
                    )
                    .map_err(map_record_error)?;
                persist_guarded(guard, record.revision, &next)?;
            }
        }
    }
    Err(InstallControlError::Busy)
}

fn transition(
    record: &InstallRecord,
    state: InstallState,
    now_us: i64,
) -> Result<InstallRecord, InstallControlError> {
    record
        .transition(record.revision, state, checked_now(record, now_us)?)
        .map_err(map_record_error)
}

fn checked_now(record: &InstallRecord, now_us: i64) -> Result<i64, InstallControlError> {
    if now_us < 0 || now_us < record.updated_at_us {
        return Err(InstallControlError::InvalidClock);
    }
    Ok(now_us)
}

fn persist_guarded<G: SetupRecordGuard>(
    guard: &G,
    expected_revision: u64,
    next: &InstallRecord,
) -> Result<(), InstallControlError> {
    match guard.compare_and_swap_record(expected_revision, next) {
        Ok(()) => Ok(()),
        // A legitimate peer cannot mutate the record while this caller owns
        // the cross-process setup fence. A CAS conflict therefore proves
        // out-of-protocol path replacement or store drift; never adopt it as a
        // concurrent setup winner.
        Err(InstallControlError::ConcurrentChange) => Err(InstallControlError::Drifted),
        Err(error) => Err(error),
    }
}

const fn map_store_error(error: InstallStoreError) -> InstallControlError {
    match error {
        InstallStoreError::CompareAndSwapConflict => InstallControlError::ConcurrentChange,
        InstallStoreError::AccessDenied => InstallControlError::AccessDenied,
        InstallStoreError::AdmissionBusy => InstallControlError::Busy,
        InstallStoreError::InvalidRecord
        | InstallStoreError::Integrity
        | InstallStoreError::AdmissionChanged
        | InstallStoreError::PurgePrecondition
        | InstallStoreError::PurgeStageDrift => InstallControlError::Drifted,
        InstallStoreError::OrdinaryTrafficUnavailable => InstallControlError::Unavailable,
        InstallStoreError::Storage | InstallStoreError::Lock => {
            InstallControlError::StorageUnavailable
        }
    }
}

const fn map_record_error(_error: InstallRecordError) -> InstallControlError {
    InstallControlError::Drifted
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use super::*;
    use crate::install_record::{
        INSTALL_RECORD_FORMAT_VERSION, RuntimeArtifactFormat, ScheduledTaskPath, Sha256Digest,
        SignerStatus, StableId,
    };

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const CONSUMER: &str = "fedcba9876543210fedcba9876543210";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct FakeStore {
        record: RefCell<Option<InstallRecord>>,
        conflicts: RefCell<usize>,
        revisions: RefCell<Vec<u64>>,
    }

    impl FakeStore {
        fn with_record(record: InstallRecord) -> Self {
            Self {
                record: RefCell::new(Some(record)),
                ..Self::default()
            }
        }
    }

    impl SetupRecordStore for FakeStore {
        type Guard<'store> = &'store FakeStore;

        fn acquire_setup_guard(&self) -> Result<Self::Guard<'_>, InstallControlError> {
            Ok(self)
        }
    }

    impl SetupRecordGuard for &FakeStore {
        fn load_record(&self) -> Result<Option<InstallRecord>, InstallControlError> {
            Ok(self.record.borrow().clone())
        }

        fn compare_and_swap_record(
            &self,
            expected_revision: u64,
            next: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            let mut conflicts = self.conflicts.borrow_mut();
            if *conflicts != 0 {
                *conflicts -= 1;
                return Err(InstallControlError::ConcurrentChange);
            }
            let mut current = self.record.borrow_mut();
            let observed = current.as_ref().map_or(0, |record| record.revision);
            if observed != expected_revision {
                return Err(InstallControlError::ConcurrentChange);
            }
            *current = Some(next.clone());
            self.revisions.borrow_mut().push(next.revision);
            Ok(())
        }
    }

    struct FakePlatform {
        now: i64,
        calls: Vec<&'static str>,
        failures: VecDeque<(&'static str, InstallControlError)>,
    }

    impl Default for FakePlatform {
        fn default() -> Self {
            Self {
                now: 1,
                calls: Vec::new(),
                failures: VecDeque::new(),
            }
        }
    }

    impl FakePlatform {
        fn call(&mut self, name: &'static str) -> Result<(), InstallControlError> {
            self.calls.push(name);
            self.now += 1;
            if let Some(failure) = self.failures.pop_front_if(|failure| failure.0 == name) {
                return Err(failure.1);
            }
            Ok(())
        }
    }

    impl SetupPlatform for FakePlatform {
        fn now_us(&self) -> Result<i64, InstallControlError> {
            Ok(self.now)
        }

        fn initial_record(&mut self) -> Result<InstallRecord, InstallControlError> {
            self.call("initial")?;
            Ok(initial(self.now))
        }

        fn verify_active(&mut self, _record: &InstallRecord) -> Result<(), InstallControlError> {
            self.call("verify_active")
        }

        fn verify_retained(&mut self, _record: &InstallRecord) -> Result<(), InstallControlError> {
            self.call("verify_retained")
        }

        fn verify_installing_prefix(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            self.call("verify_prefix")
        }

        fn ensure_key(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<ProtectedKeyArtifact, InstallControlError> {
            self.call("key")?;
            Ok(key())
        }

        fn ensure_runtime(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<RuntimeArtifact, InstallControlError> {
            self.call("runtime")?;
            Ok(runtime())
        }

        fn ensure_data(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<(RelativeWindowsPath, u32), InstallControlError> {
            self.call("data")?;
            Ok((path(&format!(r"installs\{ID}\data")), 4))
        }

        fn ensure_task(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<ScheduledTaskEvidence, InstallControlError> {
            self.call("task")?;
            Ok(task())
        }

        fn complete_installing(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            self.call("complete")
        }
    }

    fn path(value: &str) -> RelativeWindowsPath {
        RelativeWindowsPath::new(value).expect("valid fixture path")
    }

    fn digest() -> Sha256Digest {
        Sha256Digest::new(DIGEST).expect("valid fixture digest")
    }

    fn initial(now: i64) -> InstallRecord {
        InstallRecord {
            format_version: INSTALL_RECORD_FORMAT_VERSION,
            install_id: StableId::new(ID).unwrap(),
            consumer_id: StableId::new(CONSUMER).unwrap(),
            state: InstallState::Installing,
            revision: 1,
            product_relative_path: Some(path(&format!(r"installs\{ID}"))),
            data_relative_path: None,
            data_schema_version: None,
            protected_key: None,
            runtime: None,
            scheduled_task: None,
            created_at_us: now,
            updated_at_us: now,
        }
    }

    fn key() -> ProtectedKeyArtifact {
        ProtectedKeyArtifact {
            relative_path: path(&format!(r"installs\{ID}\secrets\endpoint-key.dpapi")),
            sha256: digest(),
        }
    }

    fn runtime() -> RuntimeArtifact {
        RuntimeArtifact {
            relative_path: path(&format!(r"installs\{ID}\bin\{DIGEST}\mesh-daemon.exe")),
            sha256: digest(),
            version: "0.1.0".into(),
            signer_status: SignerStatus::UnsignedDevelopment,
            artifact_format: RuntimeArtifactFormat::MeshDaemonExeV1,
        }
    }

    fn task() -> ScheduledTaskEvidence {
        ScheduledTaskEvidence {
            task_path: ScheduledTaskPath::new(r"\CodexAgentMesh-fixture").unwrap(),
            definition_sha256: digest(),
        }
    }

    fn complete_record(state: InstallState, revision: u64, now: i64) -> InstallRecord {
        InstallRecord {
            state,
            revision,
            protected_key: Some(key()),
            runtime: Some(runtime()),
            data_relative_path: Some(path(&format!(r"installs\{ID}\data"))),
            data_schema_version: Some(4),
            scheduled_task: Some(task()),
            updated_at_us: now,
            ..initial(1)
        }
    }

    #[test]
    fn absent_setup_checkpoints_one_effect_at_a_time_and_activates_last() {
        let store = FakeStore::default();
        let mut platform = FakePlatform::default();
        let active = converge_setup(&store, &mut platform).unwrap();
        assert_eq!(active.state, InstallState::Active);
        assert_eq!(active.revision, 6);
        assert_eq!(*store.revisions.borrow(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(
            platform.calls,
            [
                "initial",
                "verify_prefix",
                "key",
                "verify_prefix",
                "runtime",
                "verify_prefix",
                "data",
                "verify_prefix",
                "task",
                "verify_prefix",
                "complete",
                "verify_active"
            ]
        );
    }

    #[test]
    fn setup_resumes_each_durable_prefix_without_repeating_prior_effects() {
        let prefixes = [
            (1, vec![]),
            (2, vec!["key"]),
            (3, vec!["key", "runtime"]),
            (4, vec!["key", "runtime", "data"]),
            (5, vec!["key", "runtime", "data", "task"]),
        ];
        for (revision, present) in prefixes {
            let mut record = initial(1);
            if present.contains(&"key") {
                record.protected_key = Some(key());
            }
            if present.contains(&"runtime") {
                record.runtime = Some(runtime());
            }
            if present.contains(&"data") {
                record.data_relative_path = Some(path(&format!(r"installs\{ID}\data")));
                record.data_schema_version = Some(4);
            }
            if present.contains(&"task") {
                record.scheduled_task = Some(task());
            }
            record.revision = revision;
            record.updated_at_us = i64::try_from(revision).unwrap();
            let store = FakeStore::with_record(record);
            let mut platform = FakePlatform {
                now: i64::try_from(revision).unwrap(),
                ..FakePlatform::default()
            };
            let active = converge_setup(&store, &mut platform).unwrap();
            assert_eq!(active.state, InstallState::Active);
            for prior in present {
                assert!(!platform.calls.contains(&prior), "repeated {prior}");
            }
        }
    }

    #[test]
    fn active_setup_is_read_only_and_retained_reinstall_preserves_evidence() {
        let active_store = FakeStore::with_record(complete_record(InstallState::Active, 6, 6));
        let mut active_platform = FakePlatform {
            now: 6,
            ..FakePlatform::default()
        };
        assert_eq!(
            converge_setup(&active_store, &mut active_platform)
                .unwrap()
                .revision,
            6
        );
        assert_eq!(active_platform.calls, ["verify_active"]);
        assert!(active_store.revisions.borrow().is_empty());

        let retained = complete_record(InstallState::Retained, 8, 8);
        let retained_evidence = retained.clone();
        let retained_store = FakeStore::with_record(retained);
        let mut retained_platform = FakePlatform {
            now: 8,
            ..FakePlatform::default()
        };
        let reactivated = converge_setup(&retained_store, &mut retained_platform).unwrap();
        assert_eq!(reactivated.state, InstallState::Active);
        assert_eq!(reactivated.revision, 10);
        assert_eq!(reactivated.runtime, retained_evidence.runtime);
        assert_eq!(reactivated.protected_key, retained_evidence.protected_key);
        assert_eq!(
            retained_platform.calls,
            [
                "verify_retained",
                "verify_prefix",
                "complete",
                "verify_active"
            ]
        );
    }

    #[test]
    fn removing_purging_broken_and_platform_failure_never_publish_active() {
        for (state, expected) in [
            (InstallState::Removing, InstallControlError::Removing),
            (InstallState::Purging, InstallControlError::Removing),
            (InstallState::Broken, InstallControlError::Drifted),
        ] {
            let store = FakeStore::with_record(complete_record(state, 7, 7));
            let mut platform = FakePlatform {
                now: 7,
                ..FakePlatform::default()
            };
            assert_eq!(converge_setup(&store, &mut platform), Err(expected));
            assert_eq!(store.record.borrow().as_ref().unwrap().state, state);
        }

        let store = FakeStore::with_record(initial(1));
        let mut platform = FakePlatform::default();
        platform
            .failures
            .push_back(("runtime", InstallControlError::Drifted));
        assert_eq!(
            converge_setup(&store, &mut platform),
            Err(InstallControlError::Drifted)
        );
        let record = store.record.borrow().clone().unwrap();
        assert_eq!(record.state, InstallState::Installing);
        assert!(record.protected_key.is_some());
        assert!(record.runtime.is_none());
    }

    #[test]
    fn guarded_cas_conflict_and_a_regressed_clock_fail_closed() {
        let store = FakeStore::default();
        *store.conflicts.borrow_mut() = 1;
        let mut platform = FakePlatform::default();
        assert_eq!(
            converge_setup(&store, &mut platform),
            Err(InstallControlError::Drifted)
        );
        assert_eq!(*store.record.borrow(), None);

        let store = FakeStore::with_record(initial(10));
        let mut platform = FakePlatform::default();
        assert_eq!(
            converge_setup(&store, &mut platform),
            Err(InstallControlError::InvalidClock)
        );
        assert_eq!(store.record.borrow().as_ref().unwrap().revision, 1);
    }
}
