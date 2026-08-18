//! Public Windows control commands for the one stable installation slot.
//!
//! This module keeps command output bounded and secret-free while separating
//! lifecycle ordering from native evidence. `status` is deliberately read-only;
//! setup, start, and removal use the same persistent installation fence as
//! ordinary bridge admission.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    cli::{EXIT_LIFECYCLE, EXIT_RUNTIME, EXIT_SUCCESS, EXIT_TIMEOUT},
    install_control::{InstallControlError, SetupRecordGuard},
    install_record::{InstallRecord, InstallState, SignerStatus},
    windows_install::StableControlMode,
};

const MAX_CONTROL_JSON_BYTES: usize = 64 * 1024;
const START_TIMEOUT: Duration = Duration::from_secs(15);
const REMOVE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// One complete public-command result. Callers print only [`Self::body`] to
/// stdout and return [`Self::exit_code`] as the process exit status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlCommandOutput {
    pub exit_code: u8,
    pub body: Value,
}

/// Typed public-control dispatch result for the process entry point.
///
/// A forwarded child inherited stdout and has already completed, so the caller
/// must return its exit without printing another local object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlDispatchResult {
    /// Print the bounded local JSON object and return its exit code.
    Local(ControlCommandOutput),
    /// Print nothing locally; the inherited-stdio child owned stdout.
    ForwardedExit(u8),
}

impl ControlDispatchResult {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Local(output) => output.exit_code,
            Self::ForwardedExit(exit_code) => *exit_code,
        }
    }
}

impl ControlCommandOutput {
    fn success(body: Value) -> Self {
        Self::bounded(EXIT_SUCCESS, body)
    }

    fn failure(operation: &'static str, failure: ControlFailure) -> Self {
        Self::bounded(
            failure.exit_code(),
            json!({
                "kind": "control_result",
                "operation": operation,
                "ok": false,
                "error": {
                    "code": failure.code(),
                    "message": failure.message(),
                }
            }),
        )
    }

    fn bounded(exit_code: u8, body: Value) -> Self {
        if serde_json::to_vec(&body).is_ok_and(|bytes| bytes.len() <= MAX_CONTROL_JSON_BYTES) {
            return Self { exit_code, body };
        }
        Self {
            exit_code: EXIT_RUNTIME,
            body: json!({
                "kind": "control_result",
                "operation": "control",
                "ok": false,
                "error": {
                    "code": "CONTROL_OUTPUT_INVALID",
                    "message": "control output could not be encoded safely"
                }
            }),
        }
    }

    /// Serializes the already-bounded machine-readable stdout object.
    #[must_use]
    pub fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.body).unwrap_or_else(|_| {
            br#"{"error":{"code":"CONTROL_OUTPUT_INVALID","message":"control output could not be encoded safely"},"kind":"control_result","ok":false,"operation":"control"}"#.to_vec()
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlFailure {
    Absent,
    Installing,
    Removing,
    Retained,
    Broken,
    Disabled,
    Drifted,
    AccessDenied,
    Busy,
    StartTimeout,
    DrainTimeout,
    Storage,
    Integrity,
    /// The purge controller must run from an external control executable;
    /// the retained stable image can never delete its own install tree.
    ExternalControllerRequired,
    /// A purge drain or tree handle could not be acquired within its bound.
    PurgeBusy,
    /// The owned daemon handle did not drain within its purge bound.
    PurgeDrainTimeout,
    StableRuntimeRequired,
    SpawnFailed,
    ChildWaitFailed,
    ChildExitInvalid,
}

impl ControlFailure {
    const fn exit_code(self) -> u8 {
        match self {
            Self::StartTimeout
            | Self::DrainTimeout
            | Self::PurgeBusy
            | Self::PurgeDrainTimeout
            | Self::SpawnFailed => EXIT_TIMEOUT,
            Self::Storage | Self::Integrity | Self::ChildWaitFailed | Self::ChildExitInvalid => {
                EXIT_RUNTIME
            }
            _ => EXIT_LIFECYCLE,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Absent => "SETUP_ABSENT",
            Self::Installing => "SETUP_INSTALLING",
            // The v0.1 contract deliberately freezes `SETUP_REMOVING` as the
            // deterministic no-effect alias for any removal/purge-fenced
            // lifecycle. Read-only status still reports `lifecycle: PURGING`.
            Self::Removing => "SETUP_REMOVING",
            Self::Retained => "SETUP_RETAINED",
            Self::Broken => "SETUP_BROKEN",
            Self::Disabled => "SETUP_DISABLED",
            Self::Drifted => "SETUP_DRIFTED",
            Self::AccessDenied => "SETUP_ACCESS_DENIED",
            Self::Busy => "SINGLETON_CONFLICT",
            Self::StartTimeout => "DAEMON_START_TIMEOUT",
            Self::DrainTimeout => "DAEMON_DRAIN_TIMEOUT",
            Self::Storage => "STORAGE_UNAVAILABLE",
            Self::Integrity => "CONTROL_INTEGRITY_FAILED",
            Self::ExternalControllerRequired => "PURGE_EXTERNAL_CONTROLLER_REQUIRED",
            Self::PurgeBusy => "PURGE_BUSY",
            Self::PurgeDrainTimeout => "PURGE_DRAIN_TIMEOUT",
            Self::StableRuntimeRequired => "STABLE_RUNTIME_REQUIRED",
            Self::SpawnFailed => "STABLE_CONTROL_SPAWN_FAILED",
            Self::ChildWaitFailed => "STABLE_CONTROL_WAIT_FAILED",
            Self::ChildExitInvalid => "STABLE_CONTROL_EXIT_INVALID",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Absent => "stable installation is absent",
            Self::Installing => "stable installation setup is incomplete",
            Self::Removing => "stable installation is being removed or purged",
            Self::Retained => "stable installation is retained but inactive",
            Self::Broken => "stable installation is marked broken",
            Self::Disabled => "owned scheduled task is disabled or unavailable",
            Self::Drifted => "stable installation evidence drifted",
            Self::AccessDenied => "stable installation access was denied",
            Self::Busy => "stable installation control is busy",
            Self::StartTimeout => "authenticated daemon readiness timed out",
            Self::DrainTimeout => "owned daemon or scheduled task did not drain in time",
            Self::Storage => "stable installation storage is unavailable",
            Self::Integrity => "stable installation integrity verification failed",
            Self::ExternalControllerRequired => {
                "data purge must run from an external control executable outside the installation tree"
            }
            Self::PurgeBusy => "installation data purge is busy; retry the exact purge command",
            Self::PurgeDrainTimeout => {
                "owned daemon handle did not drain within the purge bound; retry the exact purge command"
            }
            Self::StableRuntimeRequired => {
                "operation must run from the exact retained stable runtime"
            }
            Self::SpawnFailed => "retained stable control process could not be created",
            Self::ChildWaitFailed => "retained stable control process could not be waited",
            Self::ChildExitInvalid => "retained stable control process returned an invalid exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TaskStateView {
    Unknown,
    Absent,
    Ready,
    Running,
    Disabled,
    Drifted,
    AccessDenied,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct TaskEvidenceView {
    state: TaskStateView,
    expected_definition_sha256: Option<String>,
    actual_definition_sha256: Option<String>,
    running_instances: Option<u32>,
    last_task_result: Option<i32>,
}

impl TaskEvidenceView {
    fn unknown(record: &InstallRecord) -> Self {
        Self {
            state: TaskStateView::Unknown,
            expected_definition_sha256: record
                .scheduled_task
                .as_ref()
                .map(|task| task.definition_sha256.as_str().to_owned()),
            actual_definition_sha256: None,
            running_instances: None,
            last_task_result: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct HealthEvidenceView {
    authenticated: bool,
    daemon_state: Option<&'static str>,
    daemon_generation: Option<u64>,
    diagnostic: Option<&'static str>,
}

impl HealthEvidenceView {
    const fn unavailable(diagnostic: &'static str) -> Self {
        Self {
            authenticated: false,
            daemon_state: None,
            daemon_generation: None,
            diagnostic: Some(diagnostic),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct RecordEvidenceView {
    lifecycle: &'static str,
    revision: Option<u64>,
    install_id: Option<String>,
    consumer_id: Option<String>,
    runtime_expected_sha256: Option<String>,
    runtime_actual_sha256: Option<String>,
    runtime_integrity: &'static str,
    task: TaskEvidenceView,
    health: HealthEvidenceView,
}

fn lifecycle(state: InstallState) -> &'static str {
    match state {
        InstallState::Installing => "INSTALLING",
        InstallState::Active => "ACTIVE",
        InstallState::Removing => "REMOVING",
        InstallState::Retained => "RETAINED",
        InstallState::Purging => "PURGING",
        InstallState::Broken => "BROKEN",
    }
}

trait ControlPlatform {
    fn now_us(&self) -> Result<i64, ControlFailure>;
    fn runtime_actual_digest(
        &mut self,
        record: &InstallRecord,
    ) -> Result<Option<String>, ControlFailure>;
    fn task_status(&mut self, record: &InstallRecord) -> Result<TaskEvidenceView, ControlFailure>;
    fn require_current_stable(&mut self, record: &InstallRecord) -> Result<(), ControlFailure>;
    fn authenticated_health(
        &mut self,
        record: &InstallRecord,
        deadline: Instant,
    ) -> Result<Option<HealthEvidenceView>, ControlFailure>;
    fn acquire_startup_lock(&mut self, record: &InstallRecord) -> Result<bool, ControlFailure>;
    fn request_start_guarded(&mut self, record: &InstallRecord) -> Result<(), ControlFailure>;
    fn acquire_daemon_lock(&mut self, record: &InstallRecord) -> Result<bool, ControlFailure>;
    fn disable_task(&mut self, record: &InstallRecord) -> Result<TaskEvidenceView, ControlFailure>;
    fn stop_task(&mut self, record: &InstallRecord) -> Result<TaskEvidenceView, ControlFailure>;
    fn delete_task(&mut self, record: &InstallRecord) -> Result<(), ControlFailure>;
    fn sleep(&mut self, duration: Duration);
}

fn validate_record(record: &InstallRecord) -> Result<(), ControlFailure> {
    record.validate().map_err(|_| ControlFailure::Drifted)
}

fn active_record(record: &InstallRecord) -> Result<(), ControlFailure> {
    validate_record(record)?;
    match record.state {
        InstallState::Active if record.is_active_complete() => Ok(()),
        InstallState::Installing => Err(ControlFailure::Installing),
        InstallState::Removing | InstallState::Purging => Err(ControlFailure::Removing),
        InstallState::Retained => Err(ControlFailure::Retained),
        InstallState::Broken => Err(ControlFailure::Broken),
        InstallState::Active => Err(ControlFailure::Drifted),
    }
}

fn control_runtime_signer(record: &InstallRecord) -> Result<SignerStatus, ControlFailure> {
    record
        .runtime
        .as_ref()
        .map(|runtime| runtime.signer_status)
        .ok_or(ControlFailure::Drifted)
}

fn control_trampoline_eligible(mode: StableControlMode, record: Option<&InstallRecord>) -> bool {
    record.is_some_and(|record| {
        record.validate().is_ok() && record.is_active_complete() && mode.admits(record.state)
    })
}

fn dispatch_remove_with<F, L>(purge_data: bool, forward: F, local_purge: L) -> ControlDispatchResult
where
    F: FnOnce() -> ControlDispatchResult,
    L: FnOnce() -> ControlCommandOutput,
{
    if purge_data {
        ControlDispatchResult::Local(local_purge())
    } else {
        forward()
    }
}

fn exact_startable_task(task: &TaskEvidenceView) -> Result<(), ControlFailure> {
    match task.state {
        TaskStateView::Ready | TaskStateView::Running
            if task.expected_definition_sha256 == task.actual_definition_sha256 =>
        {
            Ok(())
        }
        TaskStateView::Disabled | TaskStateView::Absent => Err(ControlFailure::Disabled),
        TaskStateView::AccessDenied => Err(ControlFailure::AccessDenied),
        TaskStateView::Drifted => Err(ControlFailure::Drifted),
        TaskStateView::Unknown
        | TaskStateView::Failed
        | TaskStateView::Ready
        | TaskStateView::Running => Err(ControlFailure::Integrity),
    }
}

fn task_failure_view(record: &InstallRecord, failure: ControlFailure) -> TaskEvidenceView {
    let mut view = TaskEvidenceView::unknown(record);
    view.state = match failure {
        ControlFailure::Disabled => TaskStateView::Disabled,
        ControlFailure::AccessDenied => TaskStateView::AccessDenied,
        ControlFailure::Drifted => TaskStateView::Drifted,
        _ => TaskStateView::Failed,
    };
    view
}

fn status_view_with<P: ControlPlatform>(
    record: &InstallRecord,
    platform: &mut P,
    probe_authenticated_health: bool,
) -> RecordEvidenceView {
    let runtime = platform.runtime_actual_digest(record);
    let runtime_integrity = if runtime.is_ok() { "EXACT" } else { "BROKEN" };
    let task = platform
        .task_status(record)
        .unwrap_or_else(|failure| task_failure_view(record, failure));
    let health = if probe_authenticated_health {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(250))
            .unwrap_or_else(Instant::now);
        match platform.authenticated_health(record, deadline) {
            Ok(Some(health)) => health,
            Ok(None) => HealthEvidenceView::unavailable("NOT_RUNNING"),
            Err(ControlFailure::StableRuntimeRequired) => {
                HealthEvidenceView::unavailable("STABLE_RUNTIME_REQUIRED")
            }
            Err(_) => HealthEvidenceView::unavailable("HEALTH_UNAVAILABLE"),
        }
    } else {
        HealthEvidenceView::unavailable("NOT_PROBED")
    };
    RecordEvidenceView {
        lifecycle: lifecycle(record.state),
        revision: Some(record.revision),
        install_id: Some(record.install_id.as_str().to_owned()),
        consumer_id: Some(record.consumer_id.as_str().to_owned()),
        runtime_expected_sha256: record
            .runtime
            .as_ref()
            .map(|item| item.sha256.as_str().to_owned()),
        runtime_actual_sha256: runtime.ok().flatten(),
        runtime_integrity,
        task,
        health,
    }
}

fn wait_for_health<P: ControlPlatform>(
    platform: &mut P,
    record: &InstallRecord,
    deadline: Instant,
) -> Result<HealthEvidenceView, ControlFailure> {
    loop {
        if Instant::now() >= deadline {
            return Err(ControlFailure::StartTimeout);
        }
        if let Some(health) = platform.authenticated_health(record, deadline)?
            && health.authenticated
        {
            return Ok(health);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        platform.sleep(POLL_INTERVAL.min(remaining));
    }
}

fn start_with<P: ControlPlatform>(
    record: &InstallRecord,
    platform: &mut P,
) -> Result<HealthEvidenceView, ControlFailure> {
    active_record(record)?;
    platform.require_current_stable(record)?;
    let task = platform.task_status(record)?;
    exact_startable_task(&task)?;
    let deadline = Instant::now()
        .checked_add(START_TIMEOUT)
        .ok_or(ControlFailure::Integrity)?;
    if let Some(health) = platform.authenticated_health(record, deadline)?
        && health.authenticated
    {
        return Ok(health);
    }
    if !platform.acquire_startup_lock(record)? {
        return wait_for_health(platform, record, deadline);
    }
    // This boundary reacquires the shared install fence, revalidates the exact
    // ACTIVE record and task, and performs RunEx at most once before releasing
    // the fence. The startup lock remains owned by `platform` until return.
    platform.request_start_guarded(record)?;
    wait_for_health(platform, record, deadline)
}

fn transition_record(
    record: &InstallRecord,
    state: InstallState,
    now_us: i64,
) -> Result<InstallRecord, ControlFailure> {
    record
        .transition(record.revision, state, now_us)
        .map_err(|_| ControlFailure::Drifted)
}

/// Converges ordinary task removal for one verified stable-slot record.
///
/// This helper is intentionally ordinary-removal only. Explicit purge runs
/// through the separate external purge controller and never mutates lifecycle
/// state through this path.
fn remove_with<G: SetupRecordGuard, P: ControlPlatform>(
    guard: &G,
    platform: &mut P,
) -> Result<InstallRecord, ControlFailure> {
    remove_with_controller(guard, platform, true)
}

fn remove_with_controller<G: SetupRecordGuard, P: ControlPlatform>(
    guard: &G,
    platform: &mut P,
    require_current_stable: bool,
) -> Result<InstallRecord, ControlFailure> {
    let Some(mut record) = guard.load_record().map_err(map_install_control_error)? else {
        return Err(ControlFailure::Absent);
    };
    validate_record(&record)?;
    if record.state == InstallState::Installing {
        return Err(ControlFailure::Installing);
    }
    if record.state == InstallState::Purging {
        return Err(ControlFailure::Removing);
    }
    if record.state == InstallState::Broken {
        return Err(ControlFailure::Broken);
    }
    if require_current_stable {
        platform.require_current_stable(&record)?;
    }
    let (resumed, already_retained) = match record.state {
        InstallState::Active => {
            let next = transition_record(&record, InstallState::Removing, platform.now_us()?)?;
            guard
                .compare_and_swap_record(record.revision, &next)
                .map_err(map_guarded_control_error)?;
            record = next;
            (false, false)
        }
        InstallState::Removing => (true, false),
        InstallState::Retained => (true, true),
        InstallState::Installing | InstallState::Purging | InstallState::Broken => {
            unreachable!("handled above")
        }
    };

    let mut task = platform.task_status(&record)?;
    if already_retained && task.state != TaskStateView::Absent {
        return Err(ControlFailure::Drifted);
    }
    match task.state {
        TaskStateView::Ready | TaskStateView::Running => {
            exact_startable_task(&task)?;
            task = platform.disable_task(&record)?;
        }
        TaskStateView::Disabled => {}
        TaskStateView::Absent if resumed => {}
        TaskStateView::Absent | TaskStateView::Drifted => return Err(ControlFailure::Drifted),
        TaskStateView::AccessDenied => return Err(ControlFailure::AccessDenied),
        TaskStateView::Unknown | TaskStateView::Failed => return Err(ControlFailure::Integrity),
    }

    if task.state == TaskStateView::Absent {
        let drain_deadline = Instant::now()
            .checked_add(REMOVE_DRAIN_TIMEOUT)
            .ok_or(ControlFailure::Integrity)?;
        while Instant::now() < drain_deadline {
            if platform.acquire_daemon_lock(&record)? {
                break;
            }
            platform.sleep(POLL_INTERVAL);
        }
        if !platform.acquire_daemon_lock(&record)? {
            return Err(ControlFailure::DrainTimeout);
        }
    } else {
        if task.state != TaskStateView::Disabled {
            return Err(ControlFailure::Drifted);
        }
        let drain_deadline = Instant::now()
            .checked_add(REMOVE_DRAIN_TIMEOUT)
            .ok_or(ControlFailure::Integrity)?;
        while Instant::now() < drain_deadline {
            if platform.acquire_daemon_lock(&record)? {
                break;
            }
            platform.sleep(POLL_INTERVAL);
        }
        if !platform.acquire_daemon_lock(&record)? {
            task = platform.stop_task(&record)?;
            let stop_deadline = Instant::now()
                .checked_add(REMOVE_DRAIN_TIMEOUT)
                .ok_or(ControlFailure::Integrity)?;
            while task.running_instances.unwrap_or(1) != 0 && Instant::now() < stop_deadline {
                platform.sleep(POLL_INTERVAL);
                task = platform.task_status(&record)?;
            }
            if task.running_instances.unwrap_or(1) != 0 {
                return Err(ControlFailure::DrainTimeout);
            }
            while Instant::now() < stop_deadline {
                if platform.acquire_daemon_lock(&record)? {
                    break;
                }
                platform.sleep(POLL_INTERVAL);
            }
            if !platform.acquire_daemon_lock(&record)? {
                return Err(ControlFailure::DrainTimeout);
            }
        }
        platform.delete_task(&record)?;
        let absent = platform.task_status(&record)?;
        if absent.state != TaskStateView::Absent {
            return Err(ControlFailure::Drifted);
        }
    }

    if already_retained {
        return Ok(record);
    }
    let retained = transition_record(&record, InstallState::Retained, platform.now_us()?)?;
    guard
        .compare_and_swap_record(record.revision, &retained)
        .map_err(map_guarded_control_error)?;
    Ok(retained)
}

fn finish_forwarded_after_releasing_guard<G, F>(
    guard: G,
    mode: StableControlMode,
    wait: F,
) -> ControlDispatchResult
where
    F: FnOnce() -> Result<Option<i32>, ()>,
{
    // The persistent install fence protects verification through CreateProcess,
    // not the lifetime of the stable command. Release it before waiting so the
    // child can acquire the same fence for local start/remove convergence.
    drop(guard);
    match wait() {
        Ok(Some(exit_code)) => match u8::try_from(exit_code) {
            Ok(exit_code) => ControlDispatchResult::ForwardedExit(exit_code),
            Err(_) => ControlDispatchResult::Local(ControlCommandOutput::failure(
                mode.operation(),
                ControlFailure::ChildExitInvalid,
            )),
        },
        Ok(None) => ControlDispatchResult::Local(ControlCommandOutput::failure(
            mode.operation(),
            ControlFailure::ChildExitInvalid,
        )),
        Err(()) => ControlDispatchResult::Local(ControlCommandOutput::failure(
            mode.operation(),
            ControlFailure::ChildWaitFailed,
        )),
    }
}

#[cfg(windows)]
fn stable_control_launch_failure(
    mode: StableControlMode,
    error: crate::windows_install::StableControlLaunchError,
) -> ControlDispatchResult {
    let failure = match error {
        crate::windows_install::StableControlLaunchError::Verification(error) => {
            map_install_control_error(error)
        }
        crate::windows_install::StableControlLaunchError::Spawn => ControlFailure::SpawnFailed,
    };
    ControlDispatchResult::Local(ControlCommandOutput::failure(mode.operation(), failure))
}

const fn map_install_control_error(error: InstallControlError) -> ControlFailure {
    match error {
        InstallControlError::Removing => ControlFailure::Removing,
        InstallControlError::Drifted | InstallControlError::ConcurrentChange => {
            ControlFailure::Drifted
        }
        InstallControlError::AccessDenied => ControlFailure::AccessDenied,
        InstallControlError::Busy => ControlFailure::Busy,
        InstallControlError::StorageUnavailable | InstallControlError::InvalidClock => {
            ControlFailure::Storage
        }
        InstallControlError::Unavailable => ControlFailure::Disabled,
    }
}

const fn map_guarded_control_error(error: InstallControlError) -> ControlFailure {
    match error {
        // A legitimate peer cannot mutate the record while the no-share setup
        // fence is held. A conflict therefore proves out-of-protocol drift.
        InstallControlError::ConcurrentChange => ControlFailure::Drifted,
        other => map_install_control_error(other),
    }
}

#[cfg(windows)]
mod production {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use mesh_win32::{
        AuthenticodePolicy, AuthenticodeVerification, ExclusiveFileLock, InstallPurgeTreePresence,
        NativeError, NativeErrorCode, PeerIdentityPolicy, PipeEndpoint, ScheduledTaskController,
        ScheduledTaskSpec, ScheduledTaskState, SecurePipeClient, StorageError, StorageErrorCode,
        ValidatedControlRoot, WireLimitsV1, current_user_local_app_data,
        open_or_create_product_control_root, unprotect_endpoint_key, validate_control_root,
        verify_authenticode,
    };

    use super::{
        ControlCommandOutput, ControlDispatchResult, ControlFailure, ControlPlatform, Duration,
        HealthEvidenceView, InstallControlError, InstallRecord, InstallState, Instant,
        SignerStatus, StableControlMode, TaskEvidenceView, TaskStateView, control_runtime_signer,
        control_trampoline_eligible, dispatch_remove_with, exact_startable_task,
        finish_forwarded_after_releasing_guard, json, lifecycle, map_install_control_error,
        remove_with, remove_with_controller, stable_control_launch_failure, start_with,
        status_view_with,
    };
    use crate::{
        install_control::converge_setup,
        install_purge::{
            PurgeConvergenceError, PurgeEnvironment, PurgeObservation, PurgeOutcome,
            PurgeRecordState, PurgeTreeState, converge_purge,
        },
        install_record::InstallRecordStore,
        install_store::{InstallStoreError, NativeStableSlotEnumerator, StableInstallRecordStore},
        protocol_client::authenticate_client,
        protocol_handshake::DaemonState,
        storage::CURRENT_DATA_SCHEMA_VERSION,
        windows_install::{
            StableControlLaunch, WindowsSetupPlatform, verify_complete_purge_artifacts,
            verify_external_purge_controller,
        },
    };

    const PRODUCT_CONTROL_ROOT_NAME: &str = "codex-agent-mesh";
    const RECORD_PATH: &str = r"slots\stable\install.json";
    const RUN_DIRECTORY: &str = "run";
    const STARTUP_LOCK_NAME: &str = "startup.lock";
    const DAEMON_LOCK_NAME: &str = "daemon.lock";
    const HEALTH_CONNECT_SLICE: Duration = Duration::from_millis(100);
    const OFFICIAL_SIGNER_CERTIFICATE_SHA256: Option<&str> =
        option_env!("CODEX_AGENT_MESH_SIGNER_CERTIFICATE_SHA256");

    enum ReadOnlyRecord {
        Absent,
        Broken,
        Present {
            root: ValidatedControlRoot,
            record: Box<InstallRecord>,
        },
    }

    struct WindowsControlPlatform {
        root: ValidatedControlRoot,
        tasks: Option<ScheduledTaskController>,
        startup_lock: Option<ExclusiveFileLock>,
        daemon_lock: Option<ExclusiveFileLock>,
    }

    impl WindowsControlPlatform {
        fn new(root: ValidatedControlRoot) -> Self {
            Self {
                root,
                tasks: None,
                startup_lock: None,
                daemon_lock: None,
            }
        }

        fn open_mutating() -> Result<Self, ControlFailure> {
            let root = open_or_create_product_control_root().map_err(map_storage_error)?;
            Ok(Self::new(root))
        }

        fn tasks(&mut self) -> Result<&ScheduledTaskController, ControlFailure> {
            if self.tasks.is_none() {
                self.tasks = Some(ScheduledTaskController::connect().map_err(map_native_error)?);
            }
            self.tasks.as_ref().ok_or(ControlFailure::Storage)
        }

        fn runtime_digest(record: &InstallRecord) -> Result<[u8; 32], ControlFailure> {
            let text = record
                .runtime
                .as_ref()
                .ok_or(ControlFailure::Drifted)?
                .sha256
                .as_str();
            decode_lower_hex_32(text)
        }

        fn runtime_path(&self, record: &InstallRecord) -> Result<PathBuf, ControlFailure> {
            let runtime = record.runtime.as_ref().ok_or(ControlFailure::Drifted)?;
            let digest = Self::runtime_digest(record)?;
            let path = self
                .root
                .verify_artifact_file(Path::new(runtime.relative_path.as_str()), digest)
                .map_err(map_storage_error)?;
            let verification =
                verify_authenticode(&path, signature_policy(record)?).map_err(map_native_error)?;
            let matches = matches!(
                (
                    record.runtime.as_ref().map(|item| item.signer_status),
                    verification
                ),
                (
                    Some(SignerStatus::Signed),
                    AuthenticodeVerification::OfficialSigned { .. }
                ) | (
                    Some(SignerStatus::UnsignedDevelopment),
                    AuthenticodeVerification::UnsignedDevelopment
                )
            );
            if !matches {
                return Err(ControlFailure::Drifted);
            }
            Ok(path)
        }

        fn task_spec(&self, record: &InstallRecord) -> Result<ScheduledTaskSpec, ControlFailure> {
            let path = self.runtime_path(record)?;
            ScheduledTaskSpec::new(
                record.install_id.as_str(),
                path,
                Self::runtime_digest(record)?,
            )
            .map_err(map_native_error)
        }

        fn exact_task_status(
            &mut self,
            record: &InstallRecord,
        ) -> Result<(ScheduledTaskSpec, mesh_win32::ScheduledTaskStatus), ControlFailure> {
            let spec = self.task_spec(record)?;
            let evidence = record
                .scheduled_task
                .as_ref()
                .ok_or(ControlFailure::Drifted)?;
            if evidence.task_path.as_str() != spec.task_path()
                || evidence.definition_sha256.as_str()
                    != lower_hex(spec.expected_definition_digest())
            {
                return Err(ControlFailure::Drifted);
            }
            let status = self.tasks()?.status(&spec).map_err(map_native_error)?;
            Ok((spec, status))
        }

        fn run_path(record: &InstallRecord, name: &str) -> Result<PathBuf, ControlFailure> {
            let product = record
                .product_relative_path
                .as_ref()
                .ok_or(ControlFailure::Drifted)?;
            Ok(Path::new(product.as_str()).join(RUN_DIRECTORY).join(name))
        }

        fn ensure_run_directory(&self, record: &InstallRecord) -> Result<(), ControlFailure> {
            let product = record
                .product_relative_path
                .as_ref()
                .ok_or(ControlFailure::Drifted)?;
            self.root
                .create_relative_directories(&Path::new(product.as_str()).join(RUN_DIRECTORY))
                .map_err(map_storage_error)
        }
    }

    /// External, local-only controller for explicit `remove --purge-data`.
    ///
    /// This type owns no lifecycle transitions: it supplies production effects
    /// to [`converge_purge`], whose bounded observation loop is the only
    /// caller. The control root is validated without creating anything, so a
    /// clean absent product root stays absent.
    struct WindowsPurgeController {
        root: Option<ValidatedControlRoot>,
        tasks: Option<ScheduledTaskController>,
    }

    impl WindowsPurgeController {
        fn open() -> Result<Self, ControlFailure> {
            let local = current_user_local_app_data().map_err(|_| ControlFailure::Storage)?;
            let root_path = local.join(PRODUCT_CONTROL_ROOT_NAME);
            let root = match fs::symlink_metadata(&root_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(map_io_error(&error)),
                Ok(_) => Some(validate_control_root(&root_path).map_err(map_storage_error)?),
            };
            Ok(Self { root, tasks: None })
        }

        fn required_root(&self) -> Result<&ValidatedControlRoot, ControlFailure> {
            self.root.as_ref().ok_or(ControlFailure::Absent)
        }

        /// Revalidates the live root into an owned capability so later `&mut`
        /// borrows of the controller never alias a held root reference.
        fn validated_root(&self) -> Result<ValidatedControlRoot, ControlFailure> {
            validate_control_root(self.required_root()?.path()).map_err(map_storage_error)
        }

        fn tasks(&mut self) -> Result<&ScheduledTaskController, ControlFailure> {
            if self.tasks.is_none() {
                self.tasks = Some(ScheduledTaskController::connect().map_err(map_native_error)?);
            }
            self.tasks.as_ref().ok_or(ControlFailure::Storage)
        }

        /// Builds a store from a freshly revalidated live root. The store
        /// constructor only idempotently prepares `slots\stable`, which
        /// already exists whenever a record is present.
        fn store(&self) -> Result<StableInstallRecordStore, ControlFailure> {
            StableInstallRecordStore::from_validated_control_root(self.validated_root()?)
                .map_err(map_store_error)
        }

        fn platform(&self) -> Result<WindowsControlPlatform, ControlFailure> {
            Ok(WindowsControlPlatform::new(self.validated_root()?))
        }

        fn load_record(&self) -> Result<Option<(InstallRecord, Vec<u8>)>, ControlFailure> {
            let bytes = match self
                .required_root()?
                .read_protected_file(Path::new(RECORD_PATH))
            {
                Ok(bytes) => bytes,
                Err(error) if error.code() == StorageErrorCode::NotFound => return Ok(None),
                Err(error) => return Err(map_storage_error(error)),
            };
            if bytes.len() > mesh_win32::MAX_CONTROL_FILE_BYTES {
                return Err(ControlFailure::Drifted);
            }
            let record: InstallRecord =
                serde_json::from_slice(&bytes).map_err(|_| ControlFailure::Drifted)?;
            Ok(Some((record, bytes)))
        }

        /// The purge controller must itself be an external control executable
        /// whose signer class matches the persisted record; a retained image
        /// inside the target tree could never delete that tree.
        fn verify_external_controller(&self, record: &InstallRecord) -> Result<(), ControlFailure> {
            let root = self.required_root()?;
            match root.validate_current_executable_outside_control_root() {
                Ok(_) => {}
                Err(error) if error.code() == StorageErrorCode::ControllerInsideControlRoot => {
                    return Err(ControlFailure::ExternalControllerRequired);
                }
                Err(error) => return Err(map_storage_error(error)),
            }
            verify_external_purge_controller(root, record).map_err(map_install_control_error)
        }
    }

    impl PurgeEnvironment for WindowsPurgeController {
        type Error = ControlFailure;

        fn observe(&mut self) -> Result<PurgeObservation, ControlFailure> {
            let Some(root) = &self.root else {
                return Ok(PurgeObservation {
                    record: PurgeRecordState::Absent,
                    tree: PurgeTreeState::Gone,
                });
            };
            let Some((record, _)) = self.load_record()? else {
                return Ok(PurgeObservation {
                    record: PurgeRecordState::Absent,
                    tree: PurgeTreeState::Gone,
                });
            };
            let state = match record.state {
                InstallState::Installing => PurgeRecordState::Installing,
                InstallState::Active => PurgeRecordState::Active,
                InstallState::Removing => PurgeRecordState::Removing,
                InstallState::Retained => PurgeRecordState::Retained,
                InstallState::Purging => PurgeRecordState::Purging,
                InstallState::Broken => PurgeRecordState::Broken,
            };
            let tree = match root.classify_install_purge_tree(record.install_id.as_str()) {
                Ok(InstallPurgeTreePresence::Source) => PurgeTreeState::Source,
                Ok(InstallPurgeTreePresence::Tombstone) => PurgeTreeState::Tombstone,
                Ok(InstallPurgeTreePresence::Gone) => PurgeTreeState::Gone,
                Err(error) => return Err(map_purge_storage_error(error)),
            };
            Ok(PurgeObservation {
                record: state,
                tree,
            })
        }

        fn verify_clean_absence(&mut self) -> Result<(), ControlFailure> {
            let Some(root) = &self.root else {
                return Ok(());
            };
            let lock = root
                .acquire_existing_lifetime_lock(Path::new(crate::install_store::LOCK_PATH))
                .map_err(map_purge_storage_error)?;
            root.verify_clean_install_purge_absence(&lock)
                .map_err(map_purge_storage_error)?;
            drop(lock);
            Ok(())
        }

        fn preflight_complete_record(
            &mut self,
            state: PurgeRecordState,
        ) -> Result<(), ControlFailure> {
            let expected = match state {
                PurgeRecordState::Active => InstallState::Active,
                PurgeRecordState::Removing => InstallState::Removing,
                PurgeRecordState::Retained => InstallState::Retained,
                PurgeRecordState::Absent
                | PurgeRecordState::Installing
                | PurgeRecordState::Purging
                | PurgeRecordState::Broken => return Err(ControlFailure::Drifted),
            };
            let Some((record, _)) = self.load_record()? else {
                return Err(ControlFailure::Drifted);
            };
            if record.state != expected {
                return Err(ControlFailure::Drifted);
            }
            self.verify_external_controller(&record)?;
            let artifacts = verify_complete_purge_artifacts(self.required_root()?, &record)
                .map_err(map_install_control_error)?;
            let status = self
                .tasks()?
                .status(artifacts.task_spec())
                .map_err(map_native_error)?;
            task_matches_purge_preflight(state, artifacts.task_spec(), &status)
        }

        fn converge_retained(&mut self) -> Result<(), ControlFailure> {
            let store = self.store()?;
            let guard = store.acquire_setup_guard().map_err(map_store_error)?;
            let mut platform = self.platform()?;
            remove_with_controller(&guard, &mut platform, false)?;
            Ok(())
        }

        fn publish_purging_and_stage_source(&mut self) -> Result<(), ControlFailure> {
            let root = self.validated_root()?;
            let store = self.store()?;
            let guard = store.acquire_setup_guard().map_err(map_store_error)?;
            let Some(snapshot) = guard.load_with_bytes().map_err(map_store_error)? else {
                return Err(ControlFailure::Drifted);
            };
            let record = snapshot.record().clone();
            if record.state != InstallState::Retained {
                return Err(ControlFailure::Drifted);
            }
            self.verify_external_controller(&record)?;
            let artifacts = verify_complete_purge_artifacts(&root, &record)
                .map_err(map_install_control_error)?;
            let status = self
                .tasks()?
                .status(artifacts.task_spec())
                .map_err(map_native_error)?;
            if status.state != ScheduledTaskState::Absent {
                return Err(ControlFailure::Drifted);
            }
            // Prove daemon absence and retain that in-tree handle through the
            // rename so no old daemon still owns the tree being staged.
            let mut platform = self.platform()?;
            if !platform.acquire_daemon_lock(&record)? {
                return Err(ControlFailure::PurgeDrainTimeout);
            }
            let purging = record
                .transition(record.revision, InstallState::Purging, platform.now_us()?)
                .map_err(|_| ControlFailure::Drifted)?;
            guard
                .compare_and_swap(record.revision, &purging)
                .map_err(map_store_error)?;
            let published = guard
                .load_with_bytes()
                .map_err(map_store_error)?
                .ok_or(ControlFailure::Drifted)?;
            if published.record() != &purging {
                return Err(ControlFailure::Drifted);
            }
            drop(guard);
            // Drain pre-existing startup actors without lock inversion, then
            // reacquire the installation fence while still holding startup.
            if !platform.acquire_startup_lock(&purging)? {
                return Err(ControlFailure::PurgeBusy);
            }
            let guard = store.acquire_setup_guard().map_err(map_store_error)?;
            let Some(reobserved) = guard.load_with_bytes().map_err(map_store_error)? else {
                return Err(ControlFailure::Drifted);
            };
            if reobserved.record() != &purging
                || reobserved.serialized_record() != published.serialized_record()
            {
                return Err(ControlFailure::Drifted);
            }
            // Drop every in-tree lock handle before the destructive rename.
            platform.startup_lock.take();
            platform.daemon_lock.take();
            root.stage_install_tree_for_purge(purging.install_id.as_str())
                .map_err(map_purge_storage_error)?;
            drop(guard);
            Ok(())
        }

        fn preflight_purging_resume(&mut self, tree: PurgeTreeState) -> Result<(), ControlFailure> {
            let Some((record, _)) = self.load_record()? else {
                return Err(ControlFailure::Drifted);
            };
            if record.state != InstallState::Purging {
                return Err(ControlFailure::Drifted);
            }
            self.verify_external_controller(&record)?;
            let expected = match tree {
                PurgeTreeState::Source => InstallPurgeTreePresence::Source,
                PurgeTreeState::Tombstone => InstallPurgeTreePresence::Tombstone,
                PurgeTreeState::Gone => InstallPurgeTreePresence::Gone,
                PurgeTreeState::Both => return Err(ControlFailure::Drifted),
            };
            if self
                .required_root()?
                .classify_install_purge_tree(record.install_id.as_str())
                .map_err(map_purge_storage_error)?
                != expected
            {
                return Err(ControlFailure::Drifted);
            }
            Ok(())
        }

        fn resume_purging_source(&mut self) -> Result<(), ControlFailure> {
            let root = self.validated_root()?;
            let store = self.store()?;
            let Some((record, first_bytes)) = self.load_record()? else {
                return Err(ControlFailure::Drifted);
            };
            if record.state != InstallState::Purging {
                return Err(ControlFailure::Drifted);
            }
            let mut platform = self.platform()?;
            if !platform.acquire_startup_lock(&record)? {
                return Err(ControlFailure::PurgeBusy);
            }
            if !platform.acquire_daemon_lock(&record)? {
                return Err(ControlFailure::PurgeDrainTimeout);
            }
            let guard = store.acquire_setup_guard().map_err(map_store_error)?;
            let Some(snapshot) = guard.load_with_bytes().map_err(map_store_error)? else {
                return Err(ControlFailure::Drifted);
            };
            if snapshot.record() != &record
                || snapshot.serialized_record() != first_bytes.as_slice()
            {
                return Err(ControlFailure::Drifted);
            }
            self.verify_external_controller(snapshot.record())?;
            platform.startup_lock.take();
            platform.daemon_lock.take();
            root.stage_install_tree_for_purge(record.install_id.as_str())
                .map_err(map_purge_storage_error)?;
            drop(guard);
            Ok(())
        }

        fn audit_and_delete_tombstone(&mut self) -> Result<(), ControlFailure> {
            let root = self.validated_root()?;
            let store = self.store()?;
            let guard = store.acquire_setup_guard().map_err(map_store_error)?;
            let Some(snapshot) = guard.load_with_bytes().map_err(map_store_error)? else {
                return Err(ControlFailure::Drifted);
            };
            let record = snapshot.record();
            if record.state != InstallState::Purging {
                return Err(ControlFailure::Drifted);
            }
            self.verify_external_controller(record)?;
            if root
                .classify_install_purge_tree(record.install_id.as_str())
                .map_err(map_purge_storage_error)?
                != InstallPurgeTreePresence::Tombstone
            {
                return Err(ControlFailure::Drifted);
            }
            root.audit_and_remove_install_tree(record.install_id.as_str())
                .map_err(map_purge_storage_error)?;
            drop(guard);
            Ok(())
        }

        fn finalize_record_last(&mut self) -> Result<(), ControlFailure> {
            let root = self.validated_root()?;
            let store = self.store()?;
            let guard = store.acquire_setup_guard().map_err(map_store_error)?;
            let Some(snapshot) = guard.load_with_bytes().map_err(map_store_error)? else {
                return Err(ControlFailure::Drifted);
            };
            let record = snapshot.record();
            if record.state != InstallState::Purging {
                return Err(ControlFailure::Drifted);
            }
            self.verify_external_controller(record)?;
            if root
                .classify_install_purge_tree(record.install_id.as_str())
                .map_err(map_purge_storage_error)?
                != InstallPurgeTreePresence::Gone
            {
                return Err(ControlFailure::Drifted);
            }
            let enumerator = NativeStableSlotEnumerator::new(&root);
            guard
                .compare_and_delete_purging(
                    record.revision,
                    snapshot.serialized_record(),
                    &enumerator,
                )
                .map_err(map_store_error)?;
            drop(guard);
            Ok(())
        }
    }

    /// Lifecycle-specific exact-task rule frozen by the purge contract:
    /// ACTIVE requires the exact owned task; REMOVING accepts that exact task
    /// or prior exact absence; RETAINED requires absence. Drifted or colliding
    /// tasks always block before any purge mutation.
    fn task_matches_purge_preflight(
        state: PurgeRecordState,
        spec: &ScheduledTaskSpec,
        status: &mesh_win32::ScheduledTaskStatus,
    ) -> Result<(), ControlFailure> {
        let exact_digest =
            status.actual_definition_digest == Some(*spec.expected_definition_digest());
        let admitted = match (state, status.state) {
            (PurgeRecordState::Active, ScheduledTaskState::Ready | ScheduledTaskState::Running) => {
                exact_digest
            }
            (
                PurgeRecordState::Removing | PurgeRecordState::Retained,
                ScheduledTaskState::Absent,
            ) => true,
            (
                PurgeRecordState::Removing,
                ScheduledTaskState::Ready
                | ScheduledTaskState::Running
                | ScheduledTaskState::Disabled,
            ) => exact_digest,
            (_, ScheduledTaskState::AccessDenied) => return Err(ControlFailure::AccessDenied),
            _ => false,
        };
        if admitted {
            Ok(())
        } else {
            Err(ControlFailure::Drifted)
        }
    }

    /// Purge-specific native error classification: sharing violations during
    /// tree rename/delete are bounded busy conditions, a controller inside the
    /// target tree is its own stable public outcome, and tree/identity drift
    /// stays `SETUP_DRIFTED` instead of degrading to a generic storage error.
    fn map_purge_storage_error(error: StorageError) -> ControlFailure {
        match error.code() {
            StorageErrorCode::SharingViolation => ControlFailure::PurgeBusy,
            StorageErrorCode::ControllerInsideControlRoot => {
                ControlFailure::ExternalControllerRequired
            }
            StorageErrorCode::AccessDenied => ControlFailure::AccessDenied,
            StorageErrorCode::PurgeTreeConflict
            | StorageErrorCode::IdentityChanged
            | StorageErrorCode::UnexpectedEntry
            | StorageErrorCode::TraversalLimit => ControlFailure::Drifted,
            _ => map_storage_error(error),
        }
    }

    fn absent_status() -> ControlCommandOutput {
        ControlCommandOutput::success(json!({
            "kind": "control_result",
            "operation": "status",
            "ok": true,
            "lifecycle": "ABSENT",
            "record": null,
            "task": { "state": "UNKNOWN" },
            "health": { "authenticated": false, "diagnostic": "NOT_PROBED" }
        }))
    }

    fn broken_status() -> ControlCommandOutput {
        ControlCommandOutput::success(json!({
            "kind": "control_result",
            "operation": "status",
            "ok": true,
            "lifecycle": "BROKEN",
            "record": null,
            "task": { "state": "UNKNOWN" },
            "health": { "authenticated": false, "diagnostic": "RECORD_INVALID" }
        }))
    }

    const fn lifecycle_failure(state: crate::install_record::InstallState) -> ControlFailure {
        match state {
            crate::install_record::InstallState::Installing => ControlFailure::Installing,
            crate::install_record::InstallState::Active => ControlFailure::Drifted,
            crate::install_record::InstallState::Removing
            | crate::install_record::InstallState::Purging => ControlFailure::Removing,
            crate::install_record::InstallState::Retained => ControlFailure::Retained,
            crate::install_record::InstallState::Broken => ControlFailure::Broken,
        }
    }

    fn local_control(mode: StableControlMode) -> ControlCommandOutput {
        match mode {
            StableControlMode::Status => status(true),
            StableControlMode::Start => start(),
            StableControlMode::Remove => remove(false),
            StableControlMode::RemoveAndPurge => remove(true),
        }
    }

    fn open_control_platform(
        signer_status: SignerStatus,
    ) -> Result<WindowsSetupPlatform, InstallControlError> {
        match signer_status {
            SignerStatus::Signed => WindowsSetupPlatform::open_official_current_executable(),
            SignerStatus::UnsignedDevelopment => {
                WindowsSetupPlatform::open_unsigned_development_current_executable()
            }
        }
    }

    fn dispatch_control(mode: StableControlMode) -> ControlDispatchResult {
        let inspected = match read_record_without_creation() {
            Ok(inspected) => inspected,
            Err(failure) => {
                return ControlDispatchResult::Local(ControlCommandOutput::failure(
                    mode.operation(),
                    failure,
                ));
            }
        };
        match inspected {
            ReadOnlyRecord::Absent => {
                return ControlDispatchResult::Local(match mode {
                    StableControlMode::Status => absent_status(),
                    _ => ControlCommandOutput::failure(mode.operation(), ControlFailure::Absent),
                });
            }
            ReadOnlyRecord::Broken => {
                return ControlDispatchResult::Local(match mode {
                    StableControlMode::Status => broken_status(),
                    _ => ControlCommandOutput::failure(mode.operation(), ControlFailure::Broken),
                });
            }
            ReadOnlyRecord::Present { root, record }
                if !control_trampoline_eligible(mode, Some(&record)) =>
            {
                return ControlDispatchResult::Local(match mode {
                    StableControlMode::Status => status_present(root, &record, false),
                    _ => ControlCommandOutput::failure(
                        mode.operation(),
                        lifecycle_failure(record.state),
                    ),
                });
            }
            ReadOnlyRecord::Present { .. } => {}
        }

        let store = match StableInstallRecordStore::open() {
            Ok(store) => store,
            Err(error) => {
                return ControlDispatchResult::Local(ControlCommandOutput::failure(
                    mode.operation(),
                    map_store_error(error),
                ));
            }
        };
        let guard = match store.acquire_retained_control_guard() {
            Ok(guard) => guard,
            Err(error) => {
                return ControlDispatchResult::Local(ControlCommandOutput::failure(
                    mode.operation(),
                    map_store_error(error),
                ));
            }
        };
        if !mode.admits(guard.record().state) {
            return ControlDispatchResult::Local(ControlCommandOutput::failure(
                mode.operation(),
                lifecycle_failure(guard.record().state),
            ));
        }
        // The signer class is read only from the validated protected record.
        // Its matching constructor independently verifies the current cache
        // image, so an unsigned image cannot inherit official trust and a
        // signed image cannot enter the explicit development path.
        let signer_status = match control_runtime_signer(guard.record()) {
            Ok(signer_status) => signer_status,
            Err(failure) => {
                return ControlDispatchResult::Local(ControlCommandOutput::failure(
                    mode.operation(),
                    failure,
                ));
            }
        };
        let platform = match open_control_platform(signer_status) {
            Ok(platform) => platform,
            Err(error) => {
                return ControlDispatchResult::Local(ControlCommandOutput::failure(
                    mode.operation(),
                    map_install_control_error(error),
                ));
            }
        };
        match platform.spawn_stable_control(&guard, mode) {
            Ok(StableControlLaunch::CurrentRuntime) => {
                drop(guard);
                ControlDispatchResult::Local(local_control(mode))
            }
            Ok(StableControlLaunch::Spawned(mut child)) => {
                finish_forwarded_after_releasing_guard(guard, mode, || {
                    child.wait().map(|status| status.code()).map_err(|_| ())
                })
            }
            Err(error) => stable_control_launch_failure(mode, error),
        }
    }

    #[must_use]
    pub fn dispatch_status() -> ControlDispatchResult {
        dispatch_control(StableControlMode::Status)
    }

    #[must_use]
    pub fn dispatch_start() -> ControlDispatchResult {
        dispatch_control(StableControlMode::Start)
    }

    #[must_use]
    pub fn dispatch_remove(purge_data: bool) -> ControlDispatchResult {
        dispatch_remove_with(
            purge_data,
            || dispatch_control(StableControlMode::Remove),
            || remove(true),
        )
    }

    impl ControlPlatform for WindowsControlPlatform {
        fn now_us(&self) -> Result<i64, ControlFailure> {
            let elapsed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ControlFailure::Storage)?;
            i64::try_from(elapsed.as_micros()).map_err(|_| ControlFailure::Storage)
        }

        fn runtime_actual_digest(
            &mut self,
            record: &InstallRecord,
        ) -> Result<Option<String>, ControlFailure> {
            self.runtime_path(record)?;
            Ok(record
                .runtime
                .as_ref()
                .map(|runtime| runtime.sha256.as_str().to_owned()))
        }

        fn task_status(
            &mut self,
            record: &InstallRecord,
        ) -> Result<TaskEvidenceView, ControlFailure> {
            let (_, status) = self.exact_task_status(record)?;
            Ok(task_view(&status))
        }

        fn require_current_stable(&mut self, record: &InstallRecord) -> Result<(), ControlFailure> {
            let expected = self.runtime_path(record)?;
            let current = std::env::current_exe()
                .and_then(fs::canonicalize)
                .map_err(|error| map_io_error(&error))?;
            if current != expected {
                return Err(ControlFailure::StableRuntimeRequired);
            }
            Ok(())
        }

        fn authenticated_health(
            &mut self,
            record: &InstallRecord,
            deadline: Instant,
        ) -> Result<Option<HealthEvidenceView>, ControlFailure> {
            if Instant::now() >= deadline {
                return Ok(None);
            }
            self.require_current_stable(record)?;
            let runtime = record.runtime.as_ref().ok_or(ControlFailure::Drifted)?;
            let digest = Self::runtime_digest(record)?;
            let policy = PeerIdentityPolicy::from_control_slot(
                &self.root,
                Path::new(runtime.relative_path.as_str()),
                digest,
            )
            .map_err(map_native_error)?;
            let endpoint = PipeEndpoint::for_current_user(record.install_id.as_str())
                .map_err(map_native_error)?;
            let envelope = self
                .root
                .read_endpoint_key_file(Path::new(
                    record
                        .protected_key
                        .as_ref()
                        .ok_or(ControlFailure::Drifted)?
                        .relative_path
                        .as_str(),
                ))
                .map_err(map_storage_error)?;
            let key = unprotect_endpoint_key(&envelope, record.install_id.as_str())
                .map_err(map_native_error)?;
            let slice = Instant::now()
                .checked_add(HEALTH_CONNECT_SLICE)
                .ok_or(ControlFailure::Integrity)?
                .min(deadline);
            let connection = match SecurePipeClient::connect(&endpoint, &policy, slice) {
                Ok(connection) => connection,
                Err(error) if error.code() == NativeErrorCode::IoTimeout => return Ok(None),
                Err(error) => return Err(map_native_error(error)),
            };
            let client = authenticate_client(
                connection,
                &key,
                record.install_id.as_str().to_owned(),
                env!("CARGO_PKG_VERSION").to_owned(),
                WireLimitsV1::protocol_v1_0().response_frame_bytes,
            )
            .map_err(|_| ControlFailure::Integrity)?;
            let health = client.health();
            if health.install_id() != record.install_id.as_str()
                || health.consumer_id() != record.consumer_id.as_str()
                || health.daemon_version() != env!("CARGO_PKG_VERSION")
                || health.data_schema_version() != u64::from(CURRENT_DATA_SCHEMA_VERSION)
                || !matches!(health.state(), DaemonState::Ready | DaemonState::Running)
                || Instant::now() > deadline
            {
                return Err(ControlFailure::Integrity);
            }
            Ok(Some(HealthEvidenceView {
                authenticated: true,
                daemon_state: Some(match health.state() {
                    DaemonState::Ready => "READY",
                    DaemonState::Running => "RUNNING",
                }),
                daemon_generation: Some(health.daemon_generation()),
                diagnostic: None,
            }))
        }

        fn acquire_startup_lock(&mut self, record: &InstallRecord) -> Result<bool, ControlFailure> {
            if self.startup_lock.is_some() {
                return Ok(true);
            }
            self.ensure_run_directory(record)?;
            match self
                .root
                .acquire_lifetime_lock(&Self::run_path(record, STARTUP_LOCK_NAME)?)
            {
                Ok(lock) => {
                    self.startup_lock = Some(lock);
                    Ok(true)
                }
                Err(error) if error.code() == NativeErrorCode::SingletonConflict => Ok(false),
                Err(error) => Err(map_native_error(error)),
            }
        }

        fn request_start_guarded(&mut self, record: &InstallRecord) -> Result<(), ControlFailure> {
            let store = StableInstallRecordStore::open().map_err(map_store_error)?;
            let guard = store
                .acquire_ordinary_traffic_guard()
                .map_err(map_store_error)?;
            if guard.record() != record {
                return Err(ControlFailure::Drifted);
            }
            let (spec, status) = self.exact_task_status(record)?;
            exact_startable_task(&task_view(&status))?;
            guard.revalidate_for_spawn().map_err(map_store_error)?;
            self.tasks()?.request_start(&spec).map_err(map_native_error)
        }

        fn acquire_daemon_lock(&mut self, record: &InstallRecord) -> Result<bool, ControlFailure> {
            if self.daemon_lock.is_some() {
                return Ok(true);
            }
            self.ensure_run_directory(record)?;
            match self
                .root
                .acquire_lifetime_lock(&Self::run_path(record, DAEMON_LOCK_NAME)?)
            {
                Ok(lock) => {
                    self.daemon_lock = Some(lock);
                    Ok(true)
                }
                Err(error) if error.code() == NativeErrorCode::SingletonConflict => Ok(false),
                Err(error) => Err(map_native_error(error)),
            }
        }

        fn disable_task(
            &mut self,
            record: &InstallRecord,
        ) -> Result<TaskEvidenceView, ControlFailure> {
            let (spec, _) = self.exact_task_status(record)?;
            let status = self
                .tasks()?
                .disable_exact(&spec)
                .map_err(map_native_error)?;
            Ok(task_view(&status))
        }

        fn stop_task(
            &mut self,
            record: &InstallRecord,
        ) -> Result<TaskEvidenceView, ControlFailure> {
            let (spec, _) = self.exact_task_status(record)?;
            let status = self.tasks()?.stop_exact(&spec).map_err(map_native_error)?;
            Ok(task_view(&status))
        }

        fn delete_task(&mut self, record: &InstallRecord) -> Result<(), ControlFailure> {
            let (spec, _) = self.exact_task_status(record)?;
            self.tasks()?
                .delete_exact(&spec)
                .map_err(map_native_error)?;
            Ok(())
        }

        fn sleep(&mut self, duration: Duration) {
            std::thread::sleep(duration);
        }
    }

    /// Explicit official setup. Missing or mismatched compile-time leaf pin
    /// fails closed; this function never falls back to unsigned development.
    #[must_use]
    pub fn setup_official() -> ControlCommandOutput {
        setup_with(WindowsSetupPlatform::open_official_current_executable())
    }

    /// Explicit unsigned local-development setup. Its record signer status is
    /// distinct and can never be reported as an official signed release.
    #[must_use]
    pub fn setup_unsigned_development() -> ControlCommandOutput {
        setup_with(WindowsSetupPlatform::open_unsigned_development_current_executable())
    }

    fn setup_with(
        platform: Result<WindowsSetupPlatform, InstallControlError>,
    ) -> ControlCommandOutput {
        let mut platform = match platform {
            Ok(platform) => platform,
            Err(error) => {
                return ControlCommandOutput::failure("setup", map_install_control_error(error));
            }
        };
        let store = match StableInstallRecordStore::open() {
            Ok(store) => store,
            Err(error) => return ControlCommandOutput::failure("setup", map_store_error(error)),
        };
        match converge_setup(&store, &mut platform) {
            Ok(record) => ControlCommandOutput::success(json!({
                "kind": "control_result",
                "operation": "setup",
                "ok": true,
                "lifecycle": lifecycle(record.state),
                "revision": record.revision,
                "install_id": record.install_id.as_str(),
                "consumer_id": record.consumer_id.as_str(),
                "signer_status": record.runtime.as_ref().map(|runtime| runtime.signer_status),
            })),
            Err(error) => ControlCommandOutput::failure("setup", map_install_control_error(error)),
        }
    }

    /// Performs a read-only inspection. Missing roots/records are `ABSENT` and
    /// malformed protected records are `BROKEN`; neither case creates paths.
    #[must_use]
    pub fn status(probe_authenticated_health: bool) -> ControlCommandOutput {
        match read_record_without_creation() {
            Ok(ReadOnlyRecord::Absent) => absent_status(),
            Ok(ReadOnlyRecord::Broken) => broken_status(),
            Ok(ReadOnlyRecord::Present { root, record }) => {
                status_present(root, &record, probe_authenticated_health)
            }
            Err(failure) => ControlCommandOutput::failure("status", failure),
        }
    }

    fn status_present(
        root: ValidatedControlRoot,
        record: &InstallRecord,
        probe_authenticated_health: bool,
    ) -> ControlCommandOutput {
        if record.state == InstallState::Purging {
            return purging_status(&root, record);
        }
        let mut platform = WindowsControlPlatform::new(root);
        let view = status_view_with(record, &mut platform, probe_authenticated_health);
        ControlCommandOutput::success(json!({
            "kind": "control_result",
            "operation": "status",
            "ok": true,
            "lifecycle": lifecycle(record.state),
            "record": view,
        }))
    }

    /// Lifecycle-aware PURGING status. After the deterministic rename the
    /// recorded runtime/data paths are intentionally gone, so this view never
    /// labels that a BROKEN record, probes authenticated health, or invents
    /// actual digests. It reports expected evidence plus the observed
    /// source/tombstone deletion phase.
    fn purging_status(root: &ValidatedControlRoot, record: &InstallRecord) -> ControlCommandOutput {
        let (purge_tree, purge_phase, drifted) =
            match root.classify_install_purge_tree(record.install_id.as_str()) {
                Ok(InstallPurgeTreePresence::Source) => ("SOURCE", "DRAIN_AND_STAGE", false),
                Ok(InstallPurgeTreePresence::Tombstone) => ("TOMBSTONE", "DELETE_TREE", false),
                Ok(InstallPurgeTreePresence::Gone) => ("GONE", "FINALIZE_RECORD", false),
                Err(_) => ("DRIFT", "DRIFT", true),
            };
        ControlCommandOutput::success(json!({
            "kind": "control_result",
            "operation": "status",
            "ok": true,
            "lifecycle": "PURGING",
            "record": {
                "lifecycle": "PURGING",
                "revision": record.revision,
                "install_id": record.install_id.as_str(),
                "consumer_id": record.consumer_id.as_str(),
                "runtime_expected_sha256": record
                    .runtime
                    .as_ref()
                    .map(|runtime| runtime.sha256.as_str()),
                "runtime_actual_sha256": null,
                "runtime_integrity": if drifted { "DRIFT" } else { "NOT_PROBED_PURGING" },
                "purge_tree": purge_tree,
                "purge_phase": purge_phase,
                "task": {
                    "state": "UNKNOWN",
                    "expected_definition_sha256": record
                        .scheduled_task
                        .as_ref()
                        .map(|task| task.definition_sha256.as_str()),
                    "actual_definition_sha256": null,
                    "running_instances": null,
                    "last_task_result": null,
                },
                "health": { "authenticated": false, "diagnostic": "NOT_PROBED_PURGING" }
            }
        }))
    }

    /// Starts only the exact active Scheduled Task and succeeds only after a
    /// mutually authenticated health postcondition.
    #[must_use]
    pub fn start() -> ControlCommandOutput {
        let store = match StableInstallRecordStore::open() {
            Ok(store) => store,
            Err(error) => return ControlCommandOutput::failure("start", map_store_error(error)),
        };
        let record = match InstallRecordStore::load(&store) {
            Ok(Some(record)) => record,
            Ok(None) => return ControlCommandOutput::failure("start", ControlFailure::Absent),
            Err(error) => return ControlCommandOutput::failure("start", map_store_error(error)),
        };
        let mut platform = match WindowsControlPlatform::open_mutating() {
            Ok(platform) => platform,
            Err(failure) => return ControlCommandOutput::failure("start", failure),
        };
        match start_with(&record, &mut platform) {
            Ok(health) => ControlCommandOutput::success(json!({
                "kind": "control_result",
                "operation": "start",
                "ok": true,
                "lifecycle": "ACTIVE",
                "health": health,
            })),
            Err(failure) => ControlCommandOutput::failure("start", failure),
        }
    }

    /// Converges exact task removal while retaining identity, key, runtime, and
    /// data. Explicit purge runs through the separate external purge controller
    /// and deletes the exact install identity last.
    #[must_use]
    pub fn remove(purge_data: bool) -> ControlCommandOutput {
        if purge_data {
            return purge_data_control();
        }
        let store = match StableInstallRecordStore::open() {
            Ok(store) => store,
            Err(error) => return ControlCommandOutput::failure("remove", map_store_error(error)),
        };
        let guard = match store.acquire_setup_guard() {
            Ok(guard) => guard,
            Err(error) => return ControlCommandOutput::failure("remove", map_store_error(error)),
        };
        let mut platform = match WindowsControlPlatform::open_mutating() {
            Ok(platform) => platform,
            Err(failure) => return ControlCommandOutput::failure("remove", failure),
        };
        match remove_with(&guard, &mut platform) {
            Ok(record) => ControlCommandOutput::success(json!({
                "kind": "control_result",
                "operation": "remove",
                "ok": true,
                "lifecycle": lifecycle(record.state),
                "revision": record.revision,
                "retained_data": true,
                "purged_data": false,
            })),
            Err(failure) => ControlCommandOutput::failure("remove", failure),
        }
    }

    /// Runs the restart-convergent explicit purge. The current executable must
    /// be an external control artifact; the stable retained image can never
    /// delete its own install tree, so purge never forwards to it.
    fn purge_data_control() -> ControlCommandOutput {
        let mut controller = match WindowsPurgeController::open() {
            Ok(controller) => controller,
            Err(failure) => return ControlCommandOutput::failure("remove", failure),
        };
        match converge_purge(&mut controller) {
            Ok(outcome) => purge_success_output(outcome),
            Err(PurgeConvergenceError::Effect(failure)) => {
                ControlCommandOutput::failure("remove", failure)
            }
            Err(PurgeConvergenceError::Drift | PurgeConvergenceError::DidNotConverge) => {
                ControlCommandOutput::failure("remove", ControlFailure::Drifted)
            }
        }
    }

    /// Frozen purge success objects. Deleted install/consumer IDs are never
    /// returned to the caller.
    fn purge_success_output(outcome: PurgeOutcome) -> ControlCommandOutput {
        match outcome {
            PurgeOutcome::Purged => ControlCommandOutput::success(json!({
                "kind": "control_result",
                "operation": "remove",
                "ok": true,
                "lifecycle": "ABSENT",
                "retained_data": false,
                "purged_data": true,
            })),
            PurgeOutcome::AlreadyAbsent => ControlCommandOutput::success(json!({
                "kind": "control_result",
                "operation": "remove",
                "ok": true,
                "lifecycle": "ABSENT",
                "retained_data": false,
                "purged_data": true,
                "already_absent": true,
            })),
        }
    }

    fn read_record_without_creation() -> Result<ReadOnlyRecord, ControlFailure> {
        let local = current_user_local_app_data().map_err(|_| ControlFailure::Storage)?;
        let root_path = local.join(PRODUCT_CONTROL_ROOT_NAME);
        match fs::symlink_metadata(&root_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ReadOnlyRecord::Absent);
            }
            Err(error) => return Err(map_io_error(&error)),
            Ok(_) => {}
        }
        let root = validate_control_root(&root_path).map_err(map_storage_error)?;
        let bytes = match root.read_protected_file(Path::new(RECORD_PATH)) {
            Ok(bytes) => bytes,
            Err(error) if error.code() == StorageErrorCode::NotFound => {
                return Ok(ReadOnlyRecord::Absent);
            }
            Err(error) => return Err(map_storage_error(error)),
        };
        match serde_json::from_slice::<InstallRecord>(&bytes) {
            Ok(record) => Ok(ReadOnlyRecord::Present {
                root,
                record: Box::new(record),
            }),
            Err(_) => Ok(ReadOnlyRecord::Broken),
        }
    }

    fn signature_policy(record: &InstallRecord) -> Result<AuthenticodePolicy, ControlFailure> {
        match record
            .runtime
            .as_ref()
            .ok_or(ControlFailure::Drifted)?
            .signer_status
        {
            SignerStatus::Signed => {
                let pin = OFFICIAL_SIGNER_CERTIFICATE_SHA256
                    .ok_or(ControlFailure::Drifted)
                    .and_then(decode_lower_hex_32)?;
                if pin == [0; 32] {
                    return Err(ControlFailure::Drifted);
                }
                Ok(AuthenticodePolicy::Official {
                    expected_signer_certificate_sha256: pin,
                })
            }
            SignerStatus::UnsignedDevelopment => Ok(AuthenticodePolicy::UnsignedDevelopment),
        }
    }

    fn task_view(status: &mesh_win32::ScheduledTaskStatus) -> TaskEvidenceView {
        TaskEvidenceView {
            state: match status.state {
                ScheduledTaskState::Absent => TaskStateView::Absent,
                ScheduledTaskState::Ready => TaskStateView::Ready,
                ScheduledTaskState::Running => TaskStateView::Running,
                ScheduledTaskState::Disabled => TaskStateView::Disabled,
                ScheduledTaskState::Drifted => TaskStateView::Drifted,
                ScheduledTaskState::AccessDenied => TaskStateView::AccessDenied,
                _ => TaskStateView::Failed,
            },
            expected_definition_sha256: Some(lower_hex(&status.expected_definition_digest)),
            actual_definition_sha256: status
                .actual_definition_digest
                .as_ref()
                .map(|digest| lower_hex(digest)),
            running_instances: Some(status.running_instances),
            last_task_result: status.last_task_result,
        }
    }

    fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], ControlFailure> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ControlFailure::Drifted);
        }
        let mut output = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        Ok(output)
    }

    const fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => 0,
        }
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn map_native_error(error: NativeError) -> ControlFailure {
        match error.code() {
            NativeErrorCode::AccessDenied | NativeErrorCode::SetupAccessDenied => {
                ControlFailure::AccessDenied
            }
            NativeErrorCode::SingletonConflict => ControlFailure::Busy,
            NativeErrorCode::IoTimeout | NativeErrorCode::TaskStillRunning => {
                ControlFailure::DrainTimeout
            }
            NativeErrorCode::SetupAbsent => ControlFailure::Absent,
            NativeErrorCode::SetupDisabled => ControlFailure::Disabled,
            NativeErrorCode::SetupRemoving => ControlFailure::Removing,
            NativeErrorCode::SetupDrifted
            | NativeErrorCode::InvalidArgument
            | NativeErrorCode::AuthenticationFailed
            | NativeErrorCode::SecretInvalid
            | NativeErrorCode::SecretProtectionFailed
            | NativeErrorCode::TaskNotDisabled => ControlFailure::Drifted,
            _ => ControlFailure::Storage,
        }
    }

    fn map_storage_error(error: StorageError) -> ControlFailure {
        match error.code() {
            StorageErrorCode::Io if error.os_code() == Some(5) => ControlFailure::AccessDenied,
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
            | StorageErrorCode::InvalidProtectedKey
            | StorageErrorCode::TooLarge => ControlFailure::Drifted,
            StorageErrorCode::AlreadyExists => ControlFailure::Busy,
            _ => ControlFailure::Storage,
        }
    }

    fn map_store_error(error: InstallStoreError) -> ControlFailure {
        match error {
            InstallStoreError::CompareAndSwapConflict
            | InstallStoreError::InvalidRecord
            | InstallStoreError::Integrity
            | InstallStoreError::AdmissionChanged
            | InstallStoreError::PurgePrecondition
            | InstallStoreError::PurgeStageDrift => ControlFailure::Drifted,
            InstallStoreError::AccessDenied => ControlFailure::AccessDenied,
            InstallStoreError::AdmissionBusy => ControlFailure::Busy,
            InstallStoreError::OrdinaryTrafficUnavailable => ControlFailure::Disabled,
            InstallStoreError::Storage | InstallStoreError::Lock => ControlFailure::Storage,
        }
    }

    fn map_io_error(error: &std::io::Error) -> ControlFailure {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            ControlFailure::AccessDenied
        } else {
            ControlFailure::Storage
        }
    }

    #[cfg(test)]
    mod tests {
        use mesh_win32::{protect_control_root, validate_control_root};
        use serde_json::Value;
        use sha2::{Digest, Sha256};

        use super::super::{EXIT_SUCCESS, MAX_CONTROL_JSON_BYTES};
        use super::*;
        use crate::install_record::{
            INSTALL_RECORD_FORMAT_VERSION, ProtectedKeyArtifact, RelativeWindowsPath,
            RuntimeArtifact, RuntimeArtifactFormat, ScheduledTaskEvidence, ScheduledTaskPath,
            Sha256Digest, SignerStatus, StableId,
        };

        const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";
        const CONSUMER_ID: &str = "fedcba9876543210fedcba9876543210";
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        fn digest() -> Sha256Digest {
            Sha256Digest::new(DIGEST).expect("fixture digest")
        }

        fn path(value: impl Into<String>) -> RelativeWindowsPath {
            RelativeWindowsPath::new(value).expect("valid fixture path")
        }

        fn purging_record() -> InstallRecord {
            InstallRecord {
                format_version: INSTALL_RECORD_FORMAT_VERSION,
                install_id: StableId::new(INSTALL_ID).expect("fixture install id"),
                consumer_id: StableId::new(CONSUMER_ID).expect("fixture consumer id"),
                state: InstallState::Purging,
                revision: 24,
                product_relative_path: Some(path(format!(r"installs\{INSTALL_ID}"))),
                data_relative_path: Some(path(format!(r"installs\{INSTALL_ID}\data"))),
                data_schema_version: Some(CURRENT_DATA_SCHEMA_VERSION),
                protected_key: Some(ProtectedKeyArtifact {
                    relative_path: path(format!(
                        r"installs\{INSTALL_ID}\secrets\endpoint-key.dpapi"
                    )),
                    sha256: digest(),
                }),
                runtime: Some(RuntimeArtifact {
                    relative_path: path(format!(
                        r"installs\{INSTALL_ID}\bin\{DIGEST}\mesh-daemon.exe"
                    )),
                    sha256: digest(),
                    version: "0.1.0".to_owned(),
                    signer_status: SignerStatus::UnsignedDevelopment,
                    artifact_format: RuntimeArtifactFormat::MeshDaemonExeV1,
                }),
                scheduled_task: Some(ScheduledTaskEvidence {
                    task_path: ScheduledTaskPath::new(r"\CodexAgentMesh-fixture")
                        .expect("valid task path"),
                    definition_sha256: digest(),
                }),
                created_at_us: 1,
                updated_at_us: 24,
            }
        }

        fn protected_root() -> (tempfile::TempDir, ValidatedControlRoot) {
            let directory = tempfile::tempdir().expect("temporary control root");
            protect_control_root(directory.path()).expect("protect temporary root");
            let root = validate_control_root(directory.path()).expect("validate temporary root");
            (directory, root)
        }

        fn publish_purging(root: &ValidatedControlRoot) -> Vec<u8> {
            root.create_relative_directories(Path::new(r"slots\stable"))
                .expect("stable slot");
            let bytes = serde_json::to_vec(&purging_record()).expect("serialize purging record");
            root.create_protected_file(Path::new(RECORD_PATH), &bytes)
                .expect("publish purging fixture");
            bytes
        }

        #[test]
        fn purge_controller_observes_record_and_tree_classification() {
            let (_directory, root) = protected_root();
            publish_purging(&root);
            let mut controller = WindowsPurgeController {
                root: Some(root),
                tasks: None,
            };
            assert_eq!(
                controller.observe().expect("gone observation"),
                PurgeObservation {
                    record: PurgeRecordState::Purging,
                    tree: PurgeTreeState::Gone,
                }
            );
            {
                let root = controller.root.as_ref().expect("root present");
                root.create_relative_directories(Path::new(&format!(r"installs\{INSTALL_ID}")))
                    .expect("source tree fixture");
            }
            assert_eq!(
                controller.observe().expect("source observation"),
                PurgeObservation {
                    record: PurgeRecordState::Purging,
                    tree: PurgeTreeState::Source,
                }
            );
        }

        #[test]
        fn purging_status_reports_expected_evidence_without_invented_digests() {
            let (_directory, root) = protected_root();
            publish_purging(&root);
            let output = purging_status(&root, &purging_record());
            assert_eq!(output.exit_code, EXIT_SUCCESS);
            assert_eq!(
                output.body["lifecycle"],
                Value::String("PURGING".to_owned())
            );
            let record = &output.body["record"];
            assert_eq!(
                record["runtime_expected_sha256"],
                Value::String(DIGEST.to_owned())
            );
            assert!(record["runtime_actual_sha256"].is_null());
            assert_eq!(
                record["runtime_integrity"],
                Value::String("NOT_PROBED_PURGING".to_owned())
            );
            assert_eq!(record["purge_tree"], Value::String("GONE".to_owned()));
            assert_eq!(
                record["purge_phase"],
                Value::String("FINALIZE_RECORD".to_owned())
            );
            assert_eq!(
                record["health"]["diagnostic"],
                Value::String("NOT_PROBED_PURGING".to_owned())
            );
            assert_eq!(record["task"]["state"], Value::String("UNKNOWN".to_owned()));
            assert!(record["task"]["actual_definition_sha256"].is_null());
        }

        #[test]
        fn purge_success_outputs_are_bounded_and_never_return_deleted_identity() {
            for (outcome, already_absent) in [
                (PurgeOutcome::Purged, false),
                (PurgeOutcome::AlreadyAbsent, true),
            ] {
                let output = purge_success_output(outcome);
                assert_eq!(output.exit_code, EXIT_SUCCESS);
                assert_eq!(output.body["lifecycle"], Value::String("ABSENT".to_owned()));
                assert_eq!(output.body["retained_data"], Value::Bool(false));
                assert_eq!(output.body["purged_data"], Value::Bool(true));
                assert_eq!(
                    output.body["already_absent"],
                    if already_absent {
                        Value::Bool(true)
                    } else {
                        Value::Null
                    }
                );
                assert!(output.body.get("install_id").is_none());
                assert!(output.body.get("consumer_id").is_none());
                assert!(output.to_json_bytes().len() <= MAX_CONTROL_JSON_BYTES);
            }
        }

        #[test]
        fn task_preflight_rule_follows_the_frozen_lifecycle_checkpoints() {
            let (directory, _root) = protected_root();
            let runtime = directory.path().join("controller-fixture.exe");
            let bytes = b"external purge controller fixture bytes";
            std::fs::write(&runtime, bytes).expect("write runtime fixture");
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            let spec =
                ScheduledTaskSpec::new(INSTALL_ID, &runtime, digest).expect("task spec fixture");
            let exact = Some(*spec.expected_definition_digest());
            for (state, task_state, actual, expected) in [
                (
                    PurgeRecordState::Active,
                    ScheduledTaskState::Ready,
                    exact,
                    Ok(()),
                ),
                (
                    PurgeRecordState::Active,
                    ScheduledTaskState::Absent,
                    None,
                    Err(ControlFailure::Drifted),
                ),
                (
                    PurgeRecordState::Removing,
                    ScheduledTaskState::Absent,
                    None,
                    Ok(()),
                ),
                (
                    PurgeRecordState::Removing,
                    ScheduledTaskState::Disabled,
                    exact,
                    Ok(()),
                ),
                (
                    PurgeRecordState::Removing,
                    ScheduledTaskState::Ready,
                    None,
                    Err(ControlFailure::Drifted),
                ),
                (
                    PurgeRecordState::Retained,
                    ScheduledTaskState::Absent,
                    None,
                    Ok(()),
                ),
                (
                    PurgeRecordState::Retained,
                    ScheduledTaskState::Ready,
                    exact,
                    Err(ControlFailure::Drifted),
                ),
            ] {
                let status = mesh_win32::ScheduledTaskStatus {
                    state: task_state,
                    last_task_result: None,
                    running_instances: 0,
                    expected_definition_digest: *spec.expected_definition_digest(),
                    actual_definition_digest: actual,
                };
                assert_eq!(
                    task_matches_purge_preflight(state, &spec, &status),
                    expected,
                    "{state:?} {task_state:?}"
                );
            }
            let denied = mesh_win32::ScheduledTaskStatus {
                state: ScheduledTaskState::AccessDenied,
                last_task_result: None,
                running_instances: 0,
                expected_definition_digest: *spec.expected_definition_digest(),
                actual_definition_digest: None,
            };
            assert_eq!(
                task_matches_purge_preflight(PurgeRecordState::Retained, &spec, &denied),
                Err(ControlFailure::AccessDenied)
            );
        }
    }
}

#[cfg(windows)]
pub use production::{
    dispatch_remove, dispatch_start, dispatch_status, remove, setup_official,
    setup_unsigned_development, start, status,
};

#[cfg(not(windows))]
fn unsupported(operation: &'static str) -> ControlCommandOutput {
    ControlCommandOutput::failure(operation, ControlFailure::Storage)
}

#[cfg(not(windows))]
pub fn setup_official() -> ControlCommandOutput {
    unsupported("setup")
}

#[cfg(not(windows))]
pub fn setup_unsigned_development() -> ControlCommandOutput {
    unsupported("setup")
}

#[cfg(not(windows))]
pub fn status(_probe_authenticated_health: bool) -> ControlCommandOutput {
    unsupported("status")
}

#[cfg(not(windows))]
pub fn start() -> ControlCommandOutput {
    unsupported("start")
}

#[cfg(not(windows))]
pub fn remove(_purge_data: bool) -> ControlCommandOutput {
    unsupported("remove")
}

#[cfg(not(windows))]
#[must_use]
pub fn dispatch_status() -> ControlDispatchResult {
    ControlDispatchResult::Local(status(false))
}

#[cfg(not(windows))]
#[must_use]
pub fn dispatch_start() -> ControlDispatchResult {
    ControlDispatchResult::Local(start())
}

#[cfg(not(windows))]
#[must_use]
pub fn dispatch_remove(purge_data: bool) -> ControlDispatchResult {
    ControlDispatchResult::Local(remove(purge_data))
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
    };

    use super::*;
    use crate::install_record::{
        INSTALL_RECORD_FORMAT_VERSION, ProtectedKeyArtifact, RelativeWindowsPath, RuntimeArtifact,
        RuntimeArtifactFormat, ScheduledTaskEvidence, ScheduledTaskPath, Sha256Digest,
        SignerStatus, StableId,
    };

    const INSTALL_ID: &str = "0123456789abcdef0123456789abcdef";
    const CONSUMER_ID: &str = "fedcba9876543210fedcba9876543210";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct FakeGuard {
        record: RefCell<Option<InstallRecord>>,
        loads: Cell<usize>,
        swaps: Cell<usize>,
    }

    impl FakeGuard {
        fn new(record: Option<InstallRecord>) -> Self {
            Self {
                record: RefCell::new(record),
                loads: Cell::new(0),
                swaps: Cell::new(0),
            }
        }
    }

    impl SetupRecordGuard for FakeGuard {
        fn load_record(&self) -> Result<Option<InstallRecord>, InstallControlError> {
            self.loads.set(self.loads.get() + 1);
            Ok(self.record.borrow().clone())
        }

        fn compare_and_swap_record(
            &self,
            expected_revision: u64,
            next: &InstallRecord,
        ) -> Result<(), InstallControlError> {
            let mut current = self.record.borrow_mut();
            if current.as_ref().map(|record| record.revision) != Some(expected_revision) {
                return Err(InstallControlError::ConcurrentChange);
            }
            self.swaps.set(self.swaps.get() + 1);
            *current = Some(next.clone());
            Ok(())
        }
    }

    struct FakePlatform {
        now: Cell<i64>,
        task_statuses: VecDeque<Result<TaskEvidenceView, ControlFailure>>,
        health: VecDeque<Result<Option<HealthEvidenceView>, ControlFailure>>,
        startup_winner: bool,
        daemon_lock: VecDeque<Result<bool, ControlFailure>>,
        disable_result: Result<TaskEvidenceView, ControlFailure>,
        stop_result: Result<TaskEvidenceView, ControlFailure>,
        stable_result: Result<(), ControlFailure>,
        request_starts: usize,
        disables: usize,
        stops: usize,
        deletes: usize,
        startup_locks: usize,
        daemon_locks: usize,
        health_calls: usize,
        sleeps: usize,
    }

    impl Default for FakePlatform {
        fn default() -> Self {
            Self {
                now: Cell::new(100),
                task_statuses: VecDeque::new(),
                health: VecDeque::new(),
                startup_winner: true,
                daemon_lock: VecDeque::from([Ok(true)]),
                disable_result: Ok(task(TaskStateView::Disabled, 0)),
                stop_result: Ok(task(TaskStateView::Disabled, 0)),
                stable_result: Ok(()),
                request_starts: 0,
                disables: 0,
                stops: 0,
                deletes: 0,
                startup_locks: 0,
                daemon_locks: 0,
                health_calls: 0,
                sleeps: 0,
            }
        }
    }

    impl ControlPlatform for FakePlatform {
        fn now_us(&self) -> Result<i64, ControlFailure> {
            let now = self.now.get();
            self.now.set(now + 1);
            Ok(now)
        }

        fn runtime_actual_digest(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<Option<String>, ControlFailure> {
            Ok(Some(DIGEST.to_owned()))
        }

        fn task_status(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<TaskEvidenceView, ControlFailure> {
            self.task_statuses
                .pop_front()
                .unwrap_or_else(|| Ok(task(TaskStateView::Ready, 0)))
        }

        fn require_current_stable(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<(), ControlFailure> {
            self.stable_result
        }

        fn authenticated_health(
            &mut self,
            _record: &InstallRecord,
            _deadline: Instant,
        ) -> Result<Option<HealthEvidenceView>, ControlFailure> {
            self.health_calls += 1;
            self.health.pop_front().unwrap_or(Ok(None))
        }

        fn acquire_startup_lock(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<bool, ControlFailure> {
            self.startup_locks += 1;
            Ok(self.startup_winner)
        }

        fn request_start_guarded(&mut self, _record: &InstallRecord) -> Result<(), ControlFailure> {
            self.request_starts += 1;
            Ok(())
        }

        fn acquire_daemon_lock(&mut self, _record: &InstallRecord) -> Result<bool, ControlFailure> {
            self.daemon_locks += 1;
            self.daemon_lock.pop_front().unwrap_or(Ok(true))
        }

        fn disable_task(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<TaskEvidenceView, ControlFailure> {
            self.disables += 1;
            self.disable_result.clone()
        }

        fn stop_task(
            &mut self,
            _record: &InstallRecord,
        ) -> Result<TaskEvidenceView, ControlFailure> {
            self.stops += 1;
            self.stop_result.clone()
        }

        fn delete_task(&mut self, _record: &InstallRecord) -> Result<(), ControlFailure> {
            self.deletes += 1;
            Ok(())
        }

        fn sleep(&mut self, _duration: Duration) {
            self.sleeps += 1;
        }
    }

    fn path(value: impl Into<String>) -> RelativeWindowsPath {
        RelativeWindowsPath::new(value).expect("valid path")
    }

    fn digest() -> Sha256Digest {
        Sha256Digest::new(DIGEST).expect("valid digest")
    }

    fn record(state: InstallState, revision: u64) -> InstallRecord {
        InstallRecord {
            format_version: INSTALL_RECORD_FORMAT_VERSION,
            install_id: StableId::new(INSTALL_ID).expect("valid install id"),
            consumer_id: StableId::new(CONSUMER_ID).expect("valid consumer id"),
            state,
            revision,
            product_relative_path: Some(path(format!(r"installs\{INSTALL_ID}"))),
            data_relative_path: Some(path(format!(r"installs\{INSTALL_ID}\data"))),
            data_schema_version: Some(4),
            protected_key: Some(ProtectedKeyArtifact {
                relative_path: path(format!(r"installs\{INSTALL_ID}\secrets\endpoint-key.dpapi")),
                sha256: digest(),
            }),
            runtime: Some(RuntimeArtifact {
                relative_path: path(format!(
                    r"installs\{INSTALL_ID}\bin\{DIGEST}\mesh-daemon.exe"
                )),
                sha256: digest(),
                version: "0.1.0".to_owned(),
                signer_status: SignerStatus::UnsignedDevelopment,
                artifact_format: RuntimeArtifactFormat::MeshDaemonExeV1,
            }),
            scheduled_task: Some(ScheduledTaskEvidence {
                task_path: ScheduledTaskPath::new(r"\CodexAgentMesh-fixture")
                    .expect("valid task path"),
                definition_sha256: digest(),
            }),
            created_at_us: 1,
            updated_at_us: i64::try_from(revision).expect("small revision"),
        }
    }

    fn task(state: TaskStateView, running_instances: u32) -> TaskEvidenceView {
        TaskEvidenceView {
            state,
            expected_definition_sha256: Some(DIGEST.to_owned()),
            actual_definition_sha256: Some(DIGEST.to_owned()),
            running_instances: Some(running_instances),
            last_task_result: Some(0),
        }
    }

    fn healthy() -> HealthEvidenceView {
        HealthEvidenceView {
            authenticated: true,
            daemon_state: Some("RUNNING"),
            daemon_generation: Some(7),
            diagnostic: None,
        }
    }

    #[test]
    fn cold_start_winner_requests_task_once_and_requires_authenticated_health() {
        let mut platform = FakePlatform {
            task_statuses: VecDeque::from([Ok(task(TaskStateView::Ready, 0))]),
            health: VecDeque::from([Ok(None), Ok(Some(healthy()))]),
            ..FakePlatform::default()
        };
        let health = start_with(&record(InstallState::Active, 6), &mut platform)
            .expect("authenticated startup");
        assert!(health.authenticated);
        assert_eq!(platform.request_starts, 1);
        assert_eq!(platform.startup_locks, 1);
    }

    #[test]
    fn concurrent_start_loser_waits_without_a_second_runex() {
        let mut platform = FakePlatform {
            task_statuses: VecDeque::from([Ok(task(TaskStateView::Running, 1))]),
            health: VecDeque::from([Ok(None), Ok(Some(healthy()))]),
            startup_winner: false,
            ..FakePlatform::default()
        };
        start_with(&record(InstallState::Active, 6), &mut platform)
            .expect("winner health observed");
        assert_eq!(platform.request_starts, 0);
        assert_eq!(platform.startup_locks, 1);
    }

    #[test]
    fn status_without_health_probe_has_no_mutating_side_effects() {
        let mut platform = FakePlatform {
            task_statuses: VecDeque::from([Ok(task(TaskStateView::Ready, 0))]),
            ..FakePlatform::default()
        };
        let view = status_view_with(&record(InstallState::Active, 6), &mut platform, false);
        assert_eq!(view.lifecycle, "ACTIVE");
        assert_eq!(platform.health_calls, 0);
        assert_eq!(platform.request_starts, 0);
        assert_eq!(platform.disables, 0);
        assert_eq!(platform.stops, 0);
        assert_eq!(platform.deletes, 0);
        assert_eq!(platform.startup_locks, 0);
        assert_eq!(platform.daemon_locks, 0);
    }

    #[test]
    fn removal_crash_after_disable_resumes_from_removing_without_reenable() {
        let guard = FakeGuard::new(Some(record(InstallState::Active, 6)));
        let mut first = FakePlatform {
            task_statuses: VecDeque::from([Ok(task(TaskStateView::Ready, 1))]),
            daemon_lock: VecDeque::from([Err(ControlFailure::Storage)]),
            ..FakePlatform::default()
        };
        assert_eq!(
            remove_with(&guard, &mut first),
            Err(ControlFailure::Storage)
        );
        assert_eq!(first.disables, 1);
        assert_eq!(
            guard.record.borrow().as_ref().map(|item| item.state),
            Some(InstallState::Removing)
        );

        let mut resumed = FakePlatform {
            task_statuses: VecDeque::from([
                Ok(task(TaskStateView::Disabled, 0)),
                Ok(task(TaskStateView::Absent, 0)),
            ]),
            ..FakePlatform::default()
        };
        let retained = remove_with(&guard, &mut resumed).expect("resume removal");
        assert_eq!(retained.state, InstallState::Retained);
        assert_eq!(resumed.disables, 0);
        assert_eq!(resumed.deletes, 1);
    }

    #[test]
    fn task_ownership_drift_is_preserved_in_removing_for_inspection() {
        let guard = FakeGuard::new(Some(record(InstallState::Active, 6)));
        let mut platform = FakePlatform {
            task_statuses: VecDeque::from([Ok(task(TaskStateView::Drifted, 0))]),
            ..FakePlatform::default()
        };
        assert_eq!(
            remove_with(&guard, &mut platform),
            Err(ControlFailure::Drifted)
        );
        assert_eq!(platform.disables, 0);
        assert_eq!(platform.deletes, 0);
        assert_eq!(
            guard.record.borrow().as_ref().map(|item| item.state),
            Some(InstallState::Removing)
        );
    }

    #[test]
    fn resumed_absent_task_still_requires_daemon_lock_evidence() {
        let guard = FakeGuard::new(Some(record(InstallState::Removing, 7)));
        let mut platform = FakePlatform {
            task_statuses: VecDeque::from([Ok(task(TaskStateView::Absent, 0))]),
            ..FakePlatform::default()
        };
        let retained = remove_with(&guard, &mut platform).expect("safe retained state");
        assert_eq!(retained.state, InstallState::Retained);
        assert!(platform.daemon_locks >= 1);
        assert_eq!(platform.deletes, 0);
    }

    #[test]
    fn retained_state_refuses_a_recreated_or_drifted_task() {
        let guard = FakeGuard::new(Some(record(InstallState::Retained, 8)));
        let mut platform = FakePlatform {
            task_statuses: VecDeque::from([Ok(task(TaskStateView::Ready, 0))]),
            ..FakePlatform::default()
        };
        assert_eq!(
            remove_with(&guard, &mut platform),
            Err(ControlFailure::Drifted)
        );
        assert_eq!(guard.swaps.get(), 0);
        assert_eq!(platform.disables, 0);
        assert_eq!(platform.deletes, 0);
    }

    #[test]
    fn purge_failures_use_the_frozen_exit_classes_and_codes() {
        let required = ControlFailure::ExternalControllerRequired;
        assert_eq!(required.exit_code(), EXIT_LIFECYCLE);
        assert_eq!(required.code(), "PURGE_EXTERNAL_CONTROLLER_REQUIRED");
        for timeout in [ControlFailure::PurgeBusy, ControlFailure::PurgeDrainTimeout] {
            assert_eq!(timeout.exit_code(), EXIT_TIMEOUT);
        }
        assert_eq!(ControlFailure::PurgeBusy.code(), "PURGE_BUSY");
        assert_eq!(
            ControlFailure::PurgeDrainTimeout.code(),
            "PURGE_DRAIN_TIMEOUT"
        );
    }

    #[test]
    fn command_output_is_bounded_machine_readable_json() {
        let output =
            ControlCommandOutput::failure("remove", ControlFailure::ExternalControllerRequired);
        let bytes = output.to_json_bytes();
        assert!(bytes.len() <= MAX_CONTROL_JSON_BYTES);
        let value: Value = serde_json::from_slice(&bytes).expect("valid JSON object");
        assert!(value.is_object());
        assert_eq!(output.exit_code, EXIT_LIFECYCLE);
    }

    #[test]
    fn absent_incomplete_and_broken_status_stay_cache_local() {
        assert!(!control_trampoline_eligible(
            StableControlMode::Status,
            None
        ));
        assert!(!control_trampoline_eligible(
            StableControlMode::Status,
            Some(&record(InstallState::Installing, 6))
        ));
        assert!(!control_trampoline_eligible(
            StableControlMode::Status,
            Some(&record(InstallState::Broken, 6))
        ));
        for state in [
            InstallState::Active,
            InstallState::Removing,
            InstallState::Retained,
        ] {
            assert!(control_trampoline_eligible(
                StableControlMode::Status,
                Some(&record(state, 6))
            ));
        }
        assert!(control_trampoline_eligible(
            StableControlMode::Start,
            Some(&record(InstallState::Active, 6))
        ));
        assert!(!control_trampoline_eligible(
            StableControlMode::Start,
            Some(&record(InstallState::Removing, 7))
        ));
    }

    #[test]
    fn record_signer_selects_explicit_unsigned_without_a_cargo_feature() {
        let mut unsigned = record(InstallState::Active, 6);
        assert_eq!(
            control_runtime_signer(&unsigned),
            Ok(SignerStatus::UnsignedDevelopment)
        );
        unsigned
            .runtime
            .as_mut()
            .expect("runtime fixture")
            .signer_status = SignerStatus::Signed;
        assert_eq!(control_runtime_signer(&unsigned), Ok(SignerStatus::Signed));
    }

    #[test]
    fn forwarded_wait_releases_install_fence_and_emits_no_local_output() {
        struct DropProbe<'a>(&'a Cell<bool>);
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let dropped = Cell::new(false);
        let result = finish_forwarded_after_releasing_guard(
            DropProbe(&dropped),
            StableControlMode::Status,
            || {
                assert!(dropped.get(), "install fence must drop before wait");
                Ok(Some(10))
            },
        );
        assert_eq!(result, ControlDispatchResult::ForwardedExit(10));
        assert_eq!(result.exit_code(), 10);
    }

    #[test]
    fn forwarded_spawn_wait_and_invalid_exit_failures_are_bounded_and_typed() {
        #[cfg(windows)]
        let ControlDispatchResult::Local(spawned) = stable_control_launch_failure(
            StableControlMode::Start,
            crate::windows_install::StableControlLaunchError::Spawn,
        ) else {
            panic!("spawn failure must map to local bounded JSON");
        };
        #[cfg(not(windows))]
        let spawned = ControlCommandOutput::failure("start", ControlFailure::SpawnFailed);
        assert_eq!(spawned.exit_code, EXIT_TIMEOUT);
        assert_eq!(
            spawned.body["error"]["code"],
            Value::String("STABLE_CONTROL_SPAWN_FAILED".to_owned())
        );

        for (wait, expected_code) in [
            (Err(()), "STABLE_CONTROL_WAIT_FAILED"),
            (Ok(None), "STABLE_CONTROL_EXIT_INVALID"),
            (Ok(Some(256)), "STABLE_CONTROL_EXIT_INVALID"),
            (Ok(Some(-1)), "STABLE_CONTROL_EXIT_INVALID"),
        ] {
            let result =
                finish_forwarded_after_releasing_guard((), StableControlMode::Remove, || wait);
            let ControlDispatchResult::Local(output) = result else {
                panic!("invalid child outcome must be local bounded JSON");
            };
            assert_eq!(output.exit_code, EXIT_RUNTIME);
            assert_eq!(output.body["operation"], Value::String("remove".to_owned()));
            assert_eq!(
                output.body["error"]["code"],
                Value::String(expected_code.to_owned())
            );
            assert!(output.to_json_bytes().len() <= MAX_CONTROL_JSON_BYTES);
        }
    }

    #[test]
    fn purge_dispatch_does_not_touch_forwarding_path() {
        let forwarded = Cell::new(0_u8);
        let local = Cell::new(0_u8);
        let result = dispatch_remove_with(
            true,
            || {
                forwarded.set(forwarded.get() + 1);
                ControlDispatchResult::ForwardedExit(0)
            },
            || {
                local.set(local.get() + 1);
                ControlCommandOutput::failure("remove", ControlFailure::ExternalControllerRequired)
            },
        );
        assert_eq!(forwarded.get(), 0, "store/spawn path must remain untouched");
        assert_eq!(local.get(), 1);
        let ControlDispatchResult::Local(output) = result else {
            panic!("purge must stay local");
        };
        assert_eq!(
            output.body["error"]["code"],
            "PURGE_EXTERNAL_CONTROLLER_REQUIRED"
        );
    }
}
