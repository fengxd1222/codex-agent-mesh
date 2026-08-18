//! Provider process supervisor: receipt-before-resume and tree ownership.
//!
//! This module is the only daemon path that creates an attempt process. The
//! production CLI and [`crate::daemon_runtime`] do not call it; tests (and a
//! later scheduler loop) invoke the explicit API below.
//!
//! Sequence, in this order:
//!
//! 1. The caller has already reserved the slot (`claim_dispatch_slot` →
//!    `PREPARING` / `PRE_DISPATCH`).
//! 2. Create the process **suspended**.
//! 3. Assign it to a fresh [`mesh_win32::NonBreakawayJob`].
//! 4. Commit [`DispatchPhase::SpawnPrepared`] with the generation-bound
//!    process receipt. This is the last retry-safe phase.
//! 5. Attach bounded stdout/stderr spools (child still suspended).
//! 6. Commit [`DispatchPhase::ProcessStarted`]. This is the post-dispatch
//!    fence; a crash here is `NEEDS_ATTENTION` even if resume never ran.
//! 7. Resume the primary thread, unless a test fail-point aborts at step 4.
//!
//! A crash between steps 4 and 6 cannot run adapter code. After step 6 a
//! crash is post-dispatch. Dropping the supervisor or its job kills the
//! tree (`KILL_ON_JOB_CLOSE`). Restart never reattaches.

#![allow(clippy::missing_errors_doc, clippy::too_many_arguments)]

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mesh_win32::{
    NativeError, NonBreakawayJob, OwnedProcess, ProcessIdentity, ProcessSpawnSpec, ProcessWait,
    create_suspended_process, process_identity_is_live,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::{DispatchPhase, TaskState};
use crate::process::{
    AttemptSpools, DEFAULT_PROVIDER_ENV_NAMES, DEFAULT_SPOOL_QUOTA_BYTES, SpoolQuota,
    build_allowlisted_environment,
};
use crate::reader::ReaderPool;
use crate::storage::{DispatchOutcome, ResultDelivery, StorageError};
use crate::writer::WriterHandle;

const JOB_KILL_EXIT_CODE: u32 = 1;
const CANCEL_LINE: &[u8] = b"{\"type\":\"cancel\"}\n";
const SPOOL_POLL: Duration = Duration::from_millis(50);
const BLOB_PUBLISH_CAP: u64 = 256 * 1024;

/// Where to stop the spawn sequence. Production callers use [`ResumeGate::Resume`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeGate {
    /// Commit `SPAWN_PREPARED`, then `PROCESS_STARTED`, then resume.
    Resume,
    /// Commit `SPAWN_PREPARED` and abort without resume. Adapter code cannot run.
    AbortBeforeResume,
}

/// Inputs for one already-claimed dispatch slot.
pub struct SpawnRequest {
    pub task_id: String,
    pub generation: i64,
    pub attempt_id: String,
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub env_allowlist: Vec<String>,
    pub extra_env: Vec<(OsString, OsString)>,
    pub current_dir: Option<PathBuf>,
    pub data_root: PathBuf,
    pub spool_quota_bytes: u64,
    pub now_us: i64,
    pub consumer_id: String,
}

impl SpawnRequest {
    #[must_use]
    pub fn spool_quota_or_default(&self) -> u64 {
        if self.spool_quota_bytes == 0 {
            DEFAULT_SPOOL_QUOTA_BYTES
        } else {
            self.spool_quota_bytes
        }
    }
}

/// Result of [`ProcessSupervisor::spawn`].
pub enum SpawnOutcome {
    Started(Box<SupervisedAttempt>),
    AbortedBeforeResume { receipt: ProcessIdentity },
}

/// A live attempt process owned by a non-breakaway job.
pub struct SupervisedAttempt {
    writer: WriterHandle,
    consumer_id: String,
    task_id: String,
    generation: i64,
    job: NonBreakawayJob,
    process: OwnedProcess,
    stdin: Option<std::fs::File>,
    spools: AttemptSpools,
    data_root: PathBuf,
    finalized: bool,
}

/// Explicit supervisor used by tests and (later) the scheduler loop.
pub struct ProcessSupervisor {
    writer: WriterHandle,
}

impl ProcessSupervisor {
    #[must_use]
    pub const fn new(writer: WriterHandle) -> Self {
        Self { writer }
    }

    /// Creates the process suspended, assigns the job, commits the receipt,
    /// then optionally resumes. The slot must already be `PRE_DISPATCH`.
    pub fn spawn(
        &self,
        request: SpawnRequest,
        gate: ResumeGate,
    ) -> Result<SpawnOutcome, SupervisorError> {
        let environment = build_environment(&request);
        let mut process = create_suspended_process(&ProcessSpawnSpec {
            executable: &request.executable,
            arguments: &request.arguments,
            environment: &environment,
            current_dir: request.current_dir.as_deref(),
        })?;
        let job = NonBreakawayJob::create()?;
        job.assign_process(&process)?;
        let receipt = process.identity().encode();
        let identity = process.identity().clone();
        let prepared = self.writer.record_dispatch_phase(
            format!("spawn-prepared:{}:{}", request.task_id, request.generation),
            request.task_id.clone(),
            request.generation,
            DispatchPhase::SpawnPrepared,
            Some(receipt),
            request.now_us,
        );
        match prepared {
            Ok(_) => {}
            Err(StorageError::StaleGeneration) => {
                let _ = process.terminate(JOB_KILL_EXIT_CODE);
                return Err(SupervisorError::StaleCallback);
            }
            Err(error) => {
                let _ = process.terminate(JOB_KILL_EXIT_CODE);
                return Err(SupervisorError::Storage(error));
            }
        }
        if gate == ResumeGate::AbortBeforeResume {
            let _ = process.terminate(JOB_KILL_EXIT_CODE);
            return Ok(SpawnOutcome::AbortedBeforeResume { receipt: identity });
        }
        // Drain before resume so the child cannot fill the pipe unseen, and
        // so a spool-setup failure stays at retry-safe `SPAWN_PREPARED`.
        let stdout = process.take_stdout().ok_or(SupervisorError::MissingStdio)?;
        let stderr = process.take_stderr().ok_or(SupervisorError::MissingStdio)?;
        let stdin = process.take_stdin();
        let attempt_root = request.data_root.join("attempts").join(&request.attempt_id);
        let spools = AttemptSpools::start(
            &attempt_root,
            stdout,
            stderr,
            SpoolQuota::new(request.spool_quota_or_default()),
        )?;
        // Durable post-dispatch fence *before* ResumeThread. Recovery treats
        // `SPAWN_PREPARED` as retry-safe; adapter code must not be able to
        // run in that phase.
        let started = self.writer.record_dispatch_phase(
            format!("process-started:{}:{}", request.task_id, request.generation),
            request.task_id.clone(),
            request.generation,
            DispatchPhase::ProcessStarted,
            None,
            request.now_us.saturating_add(1),
        );
        if let Err(error) = started {
            let _ = process.terminate(JOB_KILL_EXIT_CODE);
            return match error {
                StorageError::StaleGeneration => Err(SupervisorError::StaleCallback),
                other => Err(SupervisorError::Storage(other)),
            };
        }
        if let Err(error) = process.resume_primary_thread() {
            let _ = job.terminate(JOB_KILL_EXIT_CODE);
            return Err(error.into());
        }
        Ok(SpawnOutcome::Started(Box::new(SupervisedAttempt {
            writer: self.writer.clone(),
            consumer_id: request.consumer_id,
            task_id: request.task_id,
            generation: request.generation,
            job,
            process,
            stdin,
            spools,
            data_root: request.data_root,
            finalized: false,
        })))
    }
}

impl SupervisedAttempt {
    #[must_use]
    pub const fn identity(&self) -> &ProcessIdentity {
        self.process.identity()
    }

    #[must_use]
    pub const fn job(&self) -> &NonBreakawayJob {
        &self.job
    }

    #[must_use]
    pub const fn process(&self) -> &OwnedProcess {
        &self.process
    }

    #[must_use]
    pub fn stdout_spool_path(&self) -> &Path {
        &self.spools.stdout_path
    }

    #[must_use]
    pub fn stderr_spool_path(&self) -> &Path {
        &self.spools.stderr_path
    }

    #[must_use]
    pub fn quota_exceeded(&self) -> bool {
        self.spools.quota().exceeded()
    }

    /// Waits until the process exits, the quota trips, or `timeout` elapses.
    pub fn wait(&mut self, timeout: Duration) -> Result<Option<u32>, SupervisorError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.spools.quota().exceeded() {
                let _ = self.job.terminate(JOB_KILL_EXIT_CODE);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let slice = remaining.min(SPOOL_POLL);
            match self.process.wait_timeout(slice)? {
                ProcessWait::Exited(code) => return Ok(Some(code)),
                ProcessWait::TimedOut => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Forwards one already-committed decision line. Does not take stdin, so a
    /// later cancel can still write a cancel line if the child is still reading.
    pub fn write_stdin_line(&mut self, bytes: &[u8]) -> Result<(), SupervisorError> {
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(SupervisorError::MissingStdio);
        };
        stdin
            .write_all(bytes)
            .map_err(|_| SupervisorError::StdinForward)?;
        if !bytes.ends_with(b"\n") {
            stdin
                .write_all(b"\n")
                .map_err(|_| SupervisorError::StdinForward)?;
        }
        stdin.flush().map_err(|_| SupervisorError::StdinForward)?;
        Ok(())
    }

    /// Commits cancel first, then asks the child to stop, then kills the tree.
    ///
    /// A task that is already terminal-success is left untouched. If cancel
    /// commits first, a later exit-0 cannot overwrite it.
    pub fn cancel(
        &mut self,
        command_key: &str,
        graceful: Duration,
        now_us: i64,
    ) -> Result<CancelOutcome, SupervisorError> {
        if self.task_is_terminal()? {
            return Ok(CancelOutcome::AlreadyTerminal);
        }
        self.writer.request_cancel(
            self.consumer_id.clone(),
            command_key,
            format!("cancel:{}:{}", self.task_id, self.generation).into_bytes(),
            self.task_id.clone(),
            now_us,
        )?;
        if self.task_is_terminal()? {
            return Ok(CancelOutcome::AlreadyTerminal);
        }
        self.request_graceful_shutdown();
        let exited = self.wait(graceful)?;
        if exited.is_none() {
            let _ = self.job.terminate(JOB_KILL_EXIT_CODE);
            let _ = self.wait(Duration::from_secs(2))?;
        }
        self.reap_spools();
        self.commit_cancelled(now_us.saturating_add(1))?;
        Ok(CancelOutcome::Cancelled)
    }

    /// Finalizes from an observed exit. Does not guess no-effect from the code.
    ///
    /// If cancel already committed, success is ignored.
    pub fn finalize_exit(
        &mut self,
        exit_code: u32,
        now_us: i64,
    ) -> Result<ResultDelivery, SupervisorError> {
        self.reap_spools();
        if self.task_is_cancel_requested()? {
            return self.commit_cancelled(now_us);
        }
        if self.task_is_terminal()? {
            return Err(SupervisorError::AlreadyTerminal);
        }
        let terminal = if self.spools.quota().exceeded() {
            TaskState::Failed
        } else if exit_code == 0 {
            TaskState::Succeeded
        } else {
            TaskState::Failed
        };
        // Success/failure cannot walk CANCEL_REQUESTED -> FINALIZING -> SUCCEEDED.
        self.transition_to_finalizing(
            "finalizing",
            now_us,
            &[TaskState::Preparing, TaskState::Running],
        )?;
        let digest = result_digest(exit_code, terminal, self.spools.quota().written());
        self.publish_spool_prefix(now_us.saturating_add(1));
        let delivery = self.writer.finalize(
            self.consumer_id.clone(),
            format!("finalize:{}:{}", self.task_id, self.generation),
            format!("finalize:{}:{}:{exit_code}", self.task_id, self.generation).into_bytes(),
            self.task_id.clone(),
            self.generation,
            terminal.as_str(),
            digest,
            now_us.saturating_add(2),
        )?;
        self.finalized = true;
        Ok(delivery)
    }

    fn request_graceful_shutdown(&mut self) {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(CANCEL_LINE);
            let _ = stdin.flush();
        }
    }

    fn reap_spools(&mut self) {
        let _ = self.spools.join();
    }

    fn commit_cancelled(&mut self, now_us: i64) -> Result<ResultDelivery, SupervisorError> {
        if self.finalized {
            return Err(SupervisorError::AlreadyTerminal);
        }
        self.transition_to_finalizing(
            "finalizing-cancel",
            now_us,
            &[
                TaskState::Preparing,
                TaskState::Running,
                TaskState::CancelRequested,
            ],
        )?;
        let digest = result_digest(
            JOB_KILL_EXIT_CODE,
            TaskState::Cancelled,
            self.spools.quota().written(),
        );
        let delivery = self.writer.finalize(
            self.consumer_id.clone(),
            format!("finalize-cancel:{}:{}", self.task_id, self.generation),
            format!("finalize-cancel:{}:{}", self.task_id, self.generation).into_bytes(),
            self.task_id.clone(),
            self.generation,
            TaskState::Cancelled.as_str(),
            digest,
            now_us.saturating_add(1),
        )?;
        self.finalized = true;
        Ok(delivery)
    }

    fn transition_to_finalizing(
        &self,
        operation_kind: &str,
        now_us: i64,
        from: &[TaskState],
    ) -> Result<(), SupervisorError> {
        let from = from
            .iter()
            .map(|state| state.as_str().to_owned())
            .collect::<Vec<_>>();
        match self.writer.transition(
            format!("{operation_kind}:{}:{}", self.task_id, self.generation),
            self.task_id.clone(),
            self.generation,
            from,
            TaskState::Finalizing.as_str(),
            now_us,
        ) {
            Ok(_) | Err(StorageError::StaleGeneration) => Ok(()),
            Err(StorageError::TerminalImmutable) => Err(SupervisorError::AlreadyTerminal),
            Err(error) => Err(SupervisorError::Storage(error)),
        }
    }

    fn publish_spool_prefix(&self, now_us: i64) {
        for path in [&self.spools.stdout_path, &self.spools.stderr_path] {
            let Ok(mut file) = std::fs::File::open(path) else {
                continue;
            };
            let mut bytes = vec![0_u8; usize::try_from(BLOB_PUBLISH_CAP).unwrap_or(usize::MAX)];
            let Ok(read) = std::io::Read::read(&mut file, &mut bytes) else {
                continue;
            };
            bytes.truncate(read);
            if !bytes.is_empty() {
                let _ = self.writer.publish_blob(bytes, now_us);
            }
        }
    }

    fn task_is_terminal(&self) -> Result<bool, SupervisorError> {
        Ok(self.task_state()?.is_some_and(TaskState::is_terminal))
    }

    fn task_is_cancel_requested(&self) -> Result<bool, SupervisorError> {
        Ok(self.task_state()? == Some(TaskState::CancelRequested))
    }

    fn task_state(&self) -> Result<Option<TaskState>, SupervisorError> {
        let reader = ReaderPool::open(&self.data_root)?;
        let snapshot = reader.snapshot(&self.task_id, &self.consumer_id, Duration::from_secs(2))?;
        let state = snapshot.task.value["state"]
            .as_str()
            .and_then(|value| value.parse().ok());
        Ok(state)
    }
}

impl Drop for SupervisedAttempt {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = self.job.terminate(JOB_KILL_EXIT_CODE);
        }
    }
}

/// Outcome of [`SupervisedAttempt::cancel`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelOutcome {
    Cancelled,
    AlreadyTerminal,
}

/// Redaction-safe supervisor failure. No env values, secrets, or raw paths.
#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("native process operation failed")]
    Native(#[from] NativeError),
    #[error("durable storage mutation failed")]
    Storage(#[from] StorageError),
    #[error("stale generation or attempt callback was ignored")]
    StaleCallback,
    #[error("attempt stdio pipes were missing")]
    MissingStdio,
    #[error("committed decision could not be forwarded to provider stdin")]
    StdinForward,
    #[error("task is already terminal")]
    AlreadyTerminal,
    #[error("attempt spool failed")]
    Spool(#[from] crate::process::ProcessSupportError),
}

fn build_environment(request: &SpawnRequest) -> Vec<(OsString, OsString)> {
    let names: Vec<&str> = if request.env_allowlist.is_empty() {
        DEFAULT_PROVIDER_ENV_NAMES.to_vec()
    } else {
        request.env_allowlist.iter().map(String::as_str).collect()
    };
    build_allowlisted_environment(&names, &request.extra_env)
}

fn result_digest(exit_code: u32, state: TaskState, spool_bytes: u64) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{}:{exit_code}:{spool_bytes}", state.as_str()).as_bytes())
    )
}

/// Records a dispatch phase only when the generation still matches.
pub fn record_phase_fenced(
    writer: &WriterHandle,
    operation_id: impl Into<String>,
    task_id: impl Into<String>,
    generation: i64,
    phase: DispatchPhase,
    process_receipt: Option<String>,
    now_us: i64,
) -> Result<bool, SupervisorError> {
    match writer.record_dispatch_phase(
        operation_id,
        task_id,
        generation,
        phase,
        process_receipt,
        now_us,
    ) {
        Ok(replayed) => Ok(replayed),
        Err(StorageError::StaleGeneration) => Err(SupervisorError::StaleCallback),
        Err(error) => Err(SupervisorError::Storage(error)),
    }
}

/// Confirms a persisted receipt still names a live process. Never reattaches.
pub fn receipt_is_live(encoded: &str) -> Result<bool, SupervisorError> {
    let identity = ProcessIdentity::decode(encoded)?;
    Ok(process_identity_is_live(&identity)?)
}

pub use crate::storage::AttemptSpec;

/// Claims a slot then spawns. Convenience for tests.
pub fn claim_and_spawn(
    writer: &WriterHandle,
    request: SpawnRequest,
    spec: crate::storage::AttemptSpec,
    limits: crate::scheduler::SchedulerLimits,
    gate: ResumeGate,
) -> Result<(DispatchOutcome, SpawnOutcome), SupervisorError> {
    let claimed = writer.claim_dispatch_slot(
        format!("claim:{}:{}", request.task_id, request.generation),
        request.task_id.clone(),
        request.generation,
        spec,
        limits,
        request.now_us.saturating_sub(1).max(1),
    )?;
    let supervisor = ProcessSupervisor::new(writer.clone());
    let spawned = supervisor.spawn(request, gate)?;
    Ok((claimed, spawned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RecoveryDecision;
    use crate::reader::ReaderPool;
    use crate::scheduler::{AdapterInstanceId, SchedulerLimits};
    use crate::storage::{AttemptSpec, DispatchOutcome};
    use mesh_win32::process_id_is_active;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::OnceLock;
    use std::thread;
    use std::time::Duration;

    const DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn aid() -> String {
        AdapterInstanceId::new("fake", "default", "default", DIGEST)
            .expect("adapter id")
            .encode()
    }

    fn spec() -> AttemptSpec {
        AttemptSpec {
            adapter_instance_id: aid(),
            config_digest: DIGEST.into(),
            ..AttemptSpec::default()
        }
    }

    fn fake_adapter_exe() -> PathBuf {
        static EXE: OnceLock<PathBuf> = OnceLock::new();
        EXE.get_or_init(locate_or_build_fake_adapter).clone()
    }

    fn locate_or_build_fake_adapter() -> PathBuf {
        if let Some(path) = find_fake_adapter() {
            return path;
        }
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        let isolated = workspace.join("target").join("mesh-fake-adapter-test");
        let cargo = std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from);
        let status = Command::new(cargo)
            .args(["build", "-p", "mesh-fake-adapter", "--offline"])
            .env("CARGO_TARGET_DIR", &isolated)
            .current_dir(&workspace)
            .status()
            .expect("spawn cargo to build mesh-fake-adapter");
        if !status.success() {
            let status = Command::new(
                std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from),
            )
            .args(["build", "-p", "mesh-fake-adapter"])
            .env("CARGO_TARGET_DIR", &isolated)
            .current_dir(&workspace)
            .status()
            .expect("spawn cargo online");
            assert!(status.success(), "failed to build mesh-fake-adapter");
        }
        find_under(&isolated).expect("built mesh-fake-adapter")
    }

    fn find_fake_adapter() -> Option<PathBuf> {
        let name = "mesh-fake-adapter.exe";
        if let Ok(current) = std::env::current_exe() {
            let mut dir = current.parent()?.to_path_buf();
            for _ in 0..5 {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
                dir.pop();
            }
        }
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for root in [
            workspace.join("target"),
            workspace.join("target").join("mesh-fake-adapter-test"),
        ] {
            if let Some(path) = find_under(&root) {
                return Some(path);
            }
        }
        None
    }

    fn find_under(root: &Path) -> Option<PathBuf> {
        let name = "mesh-fake-adapter.exe";
        for profile in ["debug", "release"] {
            let candidate = root.join(profile).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    fn setup() -> (
        tempfile::TempDir,
        WriterHandle,
        ReaderPool,
        ProcessSupervisor,
    ) {
        let root = tempfile::tempdir().expect("tempdir");
        let writer =
            WriterHandle::start_portable(root.path().to_path_buf(), "install", 1).expect("writer");
        let reader = ReaderPool::open(root.path()).expect("reader");
        let supervisor = ProcessSupervisor::new(writer.clone());
        (root, writer, reader, supervisor)
    }

    fn submit_and_claim(
        writer: &WriterHandle,
        task_id: &str,
        now_us: i64,
    ) -> crate::storage::Attempt {
        writer
            .submit_for_scheduling(
                "c",
                "submit",
                format!("k-{task_id}"),
                format!("body-{task_id}").into_bytes(),
                task_id,
                None,
                0,
                Some(&aid()),
                now_us,
            )
            .expect("submit");
        match writer
            .claim_dispatch_slot(
                format!("claim-{task_id}"),
                task_id,
                0,
                spec(),
                SchedulerLimits::DEFAULT,
                now_us + 1,
            )
            .expect("claim")
        {
            DispatchOutcome::Dispatched(attempt) => attempt,
            DispatchOutcome::Blocked(blocked) => panic!("blocked: {blocked:?}"),
        }
    }

    fn spawn_script(
        supervisor: &ProcessSupervisor,
        writer: &WriterHandle,
        root: &Path,
        task_id: &str,
        script: &str,
        gate: ResumeGate,
        quota: u64,
        cwd: Option<PathBuf>,
    ) -> SpawnOutcome {
        let attempt = submit_and_claim(writer, task_id, 10);
        let request = SpawnRequest {
            task_id: task_id.to_owned(),
            generation: 0,
            attempt_id: attempt.attempt_id,
            executable: fake_adapter_exe(),
            arguments: vec![OsString::from("--json"), OsString::from(script)],
            env_allowlist: Vec::new(),
            extra_env: Vec::new(),
            current_dir: cwd,
            data_root: root.to_path_buf(),
            spool_quota_bytes: quota,
            now_us: 20,
            consumer_id: "c".into(),
        };
        supervisor.spawn(request, gate).expect("spawn")
    }

    fn phase_of(reader: &ReaderPool, task_id: &str) -> String {
        reader
            .snapshot(task_id, "c", Duration::from_secs(2))
            .expect("snapshot")
            .attempt
            .expect("attempt")
            .dispatch_phase
    }

    fn state_of(reader: &ReaderPool, task_id: &str) -> String {
        reader
            .snapshot(task_id, "c", Duration::from_secs(2))
            .expect("snapshot")
            .task
            .value["state"]
            .as_str()
            .expect("state")
            .to_owned()
    }

    #[test]
    fn abort_before_resume_leaves_spawn_prepared_and_no_marker() {
        let (root, writer, reader, supervisor) = setup();
        let cwd = root.path().join("work");
        fs::create_dir_all(&cwd).expect("cwd");
        let marker = cwd.join("marker.txt");
        let script = r#"[{"type":"write_marker","path":"marker.txt"},{"type":"terminal","state":"SUCCEEDED"}]"#;
        let outcome = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "abort",
            script,
            ResumeGate::AbortBeforeResume,
            0,
            Some(cwd),
        );
        match outcome {
            SpawnOutcome::AbortedBeforeResume { receipt } => {
                assert!(!process_identity_is_live(&receipt).expect("live query"));
            }
            SpawnOutcome::Started(_) => panic!("must abort before resume"),
        }
        assert_eq!(phase_of(&reader, "abort"), "SPAWN_PREPARED");
        thread::sleep(Duration::from_millis(80));
        assert!(
            !marker.exists(),
            "child must not write the marker before resume"
        );
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn abort_before_resume_reconciles_as_retry_safe() {
        let (root, writer, reader, supervisor) = setup();
        let cwd = root.path().join("work");
        fs::create_dir_all(&cwd).expect("cwd");
        let aborted = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "abort-rec",
            r#"[{"type":"write_marker","path":"marker.txt"},{"type":"terminal","state":"SUCCEEDED"}]"#,
            ResumeGate::AbortBeforeResume,
            0,
            Some(cwd),
        );
        match aborted {
            SpawnOutcome::AbortedBeforeResume { .. } => {}
            SpawnOutcome::Started(_) => panic!("must abort before resume"),
        }
        assert_eq!(phase_of(&reader, "abort-rec"), "SPAWN_PREPARED");
        let decisions = writer
            .reconcile_nonterminal("c", 80)
            .expect("reconcile abort");
        assert!(
            decisions.iter().any(|(task_id, decision)| {
                task_id == "abort-rec" && *decision == RecoveryDecision::RetrySafe
            }),
            "SPAWN_PREPARED without resume must stay retry-safe: {decisions:?}"
        );
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn process_started_without_resume_proof_needs_attention() {
        let (root, writer, reader, supervisor) = setup();
        let hang = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "started-rec",
            r#"[{"type":"hang"}]"#,
            ResumeGate::Resume,
            0,
            None,
        );
        let started = match hang {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        assert_eq!(phase_of(&reader, "started-rec"), "PROCESS_STARTED");
        drop(started);
        let decisions = writer
            .reconcile_nonterminal("c", 81)
            .expect("reconcile started");
        assert!(
            decisions.iter().any(|(task_id, decision)| {
                task_id == "started-rec" && *decision == RecoveryDecision::NeedsAttention
            }),
            "PROCESS_STARTED without resume proof must need attention: {decisions:?}"
        );
        assert_eq!(state_of(&reader, "started-rec"), "NEEDS_ATTENTION");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn resume_records_process_started_and_assigns_job() {
        let (root, writer, reader, supervisor) = setup();
        let script = r#"[{"type":"lifecycle","state":"RUNNING"},{"type":"delay","milliseconds":200},{"type":"terminal","state":"SUCCEEDED"}]"#;
        let outcome = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "started",
            script,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut attempt = match outcome {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must resume"),
        };
        assert_eq!(phase_of(&reader, "started"), "PROCESS_STARTED");
        assert!(
            attempt
                .job()
                .contains_process(attempt.process())
                .expect("contains")
        );
        let code = attempt.wait(Duration::from_secs(5)).expect("wait");
        assert_eq!(code, Some(0));
        attempt.finalize_exit(0, 40).expect("finalize");
        assert_eq!(state_of(&reader, "started"), "SUCCEEDED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn job_close_kills_fake_process_and_grandchild() {
        let (root, writer, _reader, supervisor) = setup();
        let script = r#"[{"type":"spawn_grandchild"},{"type":"hang"}]"#;
        let outcome = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "tree",
            script,
            ResumeGate::Resume,
            0,
            None,
        );
        let attempt = match outcome {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        let stdout = attempt.stdout_spool_path().to_path_buf();
        let identity = attempt.identity().clone();
        let grandchild = wait_for_grandchild_pid(&stdout);
        drop(attempt);
        thread::sleep(Duration::from_millis(150));
        assert!(!process_identity_is_live(&identity).expect("parent dead"));
        assert!(
            !process_id_is_active(grandchild).unwrap_or(true),
            "grandchild must die with the job"
        );
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn graceful_cancel_stops_waiting_child() {
        let (root, writer, reader, supervisor) = setup();
        let script = r#"[{"type":"approval","operation":"write_file"},{"type":"terminal","state":"SUCCEEDED"}]"#;
        let outcome = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "graceful",
            script,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut attempt = match outcome {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        let result = attempt
            .cancel("cancel-graceful", Duration::from_secs(3), 50)
            .expect("cancel");
        assert_eq!(result, CancelOutcome::Cancelled);
        assert_eq!(state_of(&reader, "graceful"), "CANCELLED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn forced_cancel_kills_hanging_tree_after_deadline() {
        let (root, writer, reader, supervisor) = setup();
        let script = r#"[{"type":"spawn_grandchild"},{"type":"hang"}]"#;
        let outcome = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "forced",
            script,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut attempt = match outcome {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        let stdout = attempt.stdout_spool_path().to_path_buf();
        let grandchild = wait_for_grandchild_pid(&stdout);
        let result = attempt
            .cancel("cancel-forced", Duration::from_millis(150), 60)
            .expect("cancel");
        assert_eq!(result, CancelOutcome::Cancelled);
        assert_eq!(state_of(&reader, "forced"), "CANCELLED");
        assert!(
            !process_id_is_active(grandchild).unwrap_or(true),
            "forced cancel must kill the grandchild"
        );
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn stale_generation_callback_cannot_advance_or_finalize() {
        let (root, writer, reader, supervisor) = setup();
        let script =
            r#"[{"type":"delay","milliseconds":400},{"type":"terminal","state":"SUCCEEDED"}]"#;
        let outcome = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "stale",
            script,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut attempt = match outcome {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        let stale_phase = writer.record_dispatch_phase(
            "stale-phase",
            "stale",
            9,
            DispatchPhase::ProviderObserved,
            None,
            70,
        );
        assert!(matches!(stale_phase, Err(StorageError::StaleGeneration)));
        let stale_final = writer.finalize(
            "c",
            "stale-final",
            b"stale-final".to_vec(),
            "stale",
            9,
            "SUCCEEDED",
            DIGEST,
            71,
        );
        assert!(matches!(stale_final, Err(StorageError::StaleGeneration)));
        assert_eq!(phase_of(&reader, "stale"), "PROCESS_STARTED");
        let code = attempt.wait(Duration::from_secs(5)).expect("wait");
        attempt.finalize_exit(code.unwrap_or(1), 80).expect("ok");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn spool_quota_kills_noisy_child_without_unbounded_memory() {
        let (root, writer, reader, supervisor) = setup();
        let script = r#"[{"type":"flood","bytes":1048576}]"#;
        let outcome = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "flood",
            script,
            ResumeGate::Resume,
            4_096,
            None,
        );
        let mut attempt = match outcome {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        let code = attempt.wait(Duration::from_secs(5)).expect("wait");
        assert!(attempt.quota_exceeded());
        let on_disk = fs::metadata(attempt.stdout_spool_path())
            .expect("stdout")
            .len();
        assert!(on_disk <= 4_096, "spool must honor the quota");
        attempt
            .finalize_exit(code.unwrap_or(1), 90)
            .expect("finalize");
        assert_eq!(state_of(&reader, "flood"), "FAILED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn scripted_success_crash_and_delay_sequences() {
        let (root, writer, reader, supervisor) = setup();
        let success = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "ok",
            r#"[{"type":"lifecycle","state":"RUNNING"},{"type":"text","text":"done"},{"type":"terminal","state":"SUCCEEDED"}]"#,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut success = match success {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("ok"),
        };
        assert_eq!(
            success.wait(Duration::from_secs(5)).expect("ok wait"),
            Some(0)
        );
        success.finalize_exit(0, 100).expect("ok final");
        assert_eq!(state_of(&reader, "ok"), "SUCCEEDED");

        let crash = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "crash",
            r#"[{"type":"lifecycle","state":"RUNNING"},{"type":"crash","code":17}]"#,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut crash = match crash {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("crash"),
        };
        assert_eq!(
            crash.wait(Duration::from_secs(5)).expect("crash wait"),
            Some(17)
        );
        crash.finalize_exit(17, 110).expect("crash final");
        assert_eq!(state_of(&reader, "crash"), "FAILED");

        let delayed = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "delay",
            r#"[{"type":"delay","milliseconds":80},{"type":"terminal","state":"SUCCEEDED"}]"#,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut delayed = match delayed {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("delay"),
        };
        assert_eq!(
            delayed.wait(Duration::from_secs(5)).expect("delay wait"),
            Some(0)
        );
        delayed.finalize_exit(0, 120).expect("delay final");
        assert_eq!(state_of(&reader, "delay"), "SUCCEEDED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn cancel_after_success_is_noop_and_exit_zero_cannot_overwrite_cancel() {
        let (root, writer, reader, supervisor) = setup();
        let success = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "done-first",
            r#"[{"type":"terminal","state":"SUCCEEDED"}]"#,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut success = match success {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("start"),
        };
        let code = success
            .wait(Duration::from_secs(5))
            .expect("wait")
            .unwrap_or(1);
        success.finalize_exit(code, 130).expect("success");
        assert_eq!(
            success
                .cancel("late-cancel", Duration::from_millis(10), 131)
                .expect("late cancel"),
            CancelOutcome::AlreadyTerminal
        );
        assert_eq!(state_of(&reader, "done-first"), "SUCCEEDED");

        let hang = spawn_script(
            &supervisor,
            &writer,
            root.path(),
            "cancel-first",
            r#"[{"type":"hang"}]"#,
            ResumeGate::Resume,
            0,
            None,
        );
        let mut hang = match hang {
            SpawnOutcome::Started(attempt) => attempt,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("hang"),
        };
        hang.cancel("first-cancel", Duration::from_millis(50), 140)
            .expect("cancel first");
        let overwritten = writer.finalize(
            "c",
            "late-success",
            b"late-success".to_vec(),
            "cancel-first",
            0,
            "SUCCEEDED",
            DIGEST,
            141,
        );
        assert!(matches!(
            overwritten,
            Err(StorageError::TerminalImmutable | StorageError::StaleGeneration)
        ));
        assert_eq!(state_of(&reader, "cancel-first"), "CANCELLED");
        writer.shutdown().expect("shutdown");
    }

    fn wait_for_grandchild_pid(spool: &Path) -> u32 {
        for _ in 0..100 {
            if let Ok(text) = fs::read_to_string(spool)
                && let Some(pid) = text.lines().find_map(parse_grandchild_pid)
            {
                return pid;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("grandchild pid was not observed in the stdout spool");
    }

    fn parse_grandchild_pid(line: &str) -> Option<u32> {
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        if value.get("type")?.as_str()? == "spawn_grandchild" {
            value
                .get("pid")?
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
        } else {
            None
        }
    }
}
