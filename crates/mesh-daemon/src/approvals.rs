//! Durable one-shot approval / interaction orchestration.
//!
//! Storage already persists the one-shot record and digest/nonce fences.
//! This module owns the design §4.5 effects around those fences:
//!
//! * commit the answer before any process is spawned or written;
//! * preflight deny/expiry cancel before dispatch (`CANCELLED`);
//! * preflight approve re-claims a slot the wait itself does not hold;
//! * runtime answers are forwarded to a live process after the commit;
//! * timeout never implies consent, and a crash after a forwarded approval
//!   is `NEEDS_ATTENTION` rather than an automatic replay.

#![allow(
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::time::Duration;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::{
    DispatchPhase, InteractionCapabilityClass, InteractionResponseKind, TaskState,
};
use crate::reader::ReaderPool;
use crate::scheduler::SchedulerLimits;
use crate::storage::{
    Attempt, AttemptSpec, DispatchOutcome, Interaction, InteractionResponseEvidence,
    ResultDelivery, StorageError,
};
use crate::supervisor::{SupervisedAttempt, SupervisorError};
use crate::writer::WriterHandle;

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(2);

/// Orchestrates one-shot interactions on top of the sole writer.
#[derive(Clone)]
pub struct ApprovalOrchestrator {
    writer: WriterHandle,
    reader: ReaderPool,
    consumer_id: String,
}

/// Inputs for one `respond_interaction` command plus the preflight reclaim spec.
pub struct InteractionAnswer {
    pub task_id: String,
    pub command_key: String,
    pub canonical_command_bytes: Vec<u8>,
    pub interaction_id: String,
    pub nonce: String,
    pub generation: i64,
    pub operation_digest: String,
    pub policy_digest: String,
    pub config_digest: String,
    pub response_kind: InteractionResponseKind,
    pub canonical_response_bytes: Vec<u8>,
    pub now_us: i64,
    pub spec: AttemptSpec,
    pub limits: SchedulerLimits,
}

/// Outcome of a newly committed or replayed one-shot answer.
#[derive(Debug)]
pub enum AppliedInteraction {
    /// Same command key and canonical bytes after reconnect.
    Replayed {
        evidence: InteractionResponseEvidence,
    },
    /// Preflight approve: slot re-claimed, caller may spawn.
    PreflightApproved { attempt: Attempt },
    /// Preflight deny: cancelled before any process existed.
    PreflightDenied { delivery: ResultDelivery },
    /// Runtime answer committed, then optionally forwarded to stdin.
    Runtime {
        kind: InteractionResponseKind,
        forwarded: bool,
    },
}

/// Outcome of a deadline expiry. Timeout never becomes an approval.
#[derive(Debug)]
pub enum ExpiredInteraction {
    PreflightCancelled { delivery: ResultDelivery },
    RuntimeNeedsAttention { delivery: ResultDelivery },
}

/// Redaction-safe orchestration failure.
#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("durable storage mutation failed")]
    Storage(#[from] StorageError),
    #[error("process supervisor failed")]
    Supervisor(#[from] SupervisorError),
    #[error("preflight approval could not reclaim a dispatch slot")]
    SlotBlocked,
}

impl ApprovalOrchestrator {
    #[must_use]
    pub fn new(writer: WriterHandle, reader: ReaderPool, consumer_id: impl Into<String>) -> Self {
        Self {
            writer,
            reader,
            consumer_id: consumer_id.into(),
        }
    }

    /// Opens one pending interaction bound to the current attempt/generation.
    pub fn open_pending(
        &self,
        operation_id: impl Into<String>,
        task_id: impl Into<String>,
        attempt_id: impl Into<String>,
        generation: i64,
        operation_digest: impl Into<String>,
        policy_digest: impl Into<String>,
        config_digest: impl Into<String>,
        capability_class: InteractionCapabilityClass,
        config_version: i64,
        policy_version: i64,
        expires_at: i64,
        now_us: i64,
    ) -> Result<Interaction, ApprovalError> {
        Ok(self.writer.open_interaction(
            operation_id,
            task_id,
            attempt_id,
            generation,
            operation_digest,
            policy_digest,
            config_digest,
            capability_class,
            config_version,
            policy_version,
            expires_at,
            now_us,
        )?)
    }

    /// Commits the one-shot answer, then applies the preflight or runtime effect.
    ///
    /// A live process is optional. Preflight never writes stdin or spawns; a
    /// successful preflight approve only returns [`AppliedInteraction::PreflightApproved`]
    /// so the caller can spawn through [`crate::supervisor::ProcessSupervisor`].
    /// A reconnect with the same command key never re-forwards stdin. Missing
    /// preflight cancel/reclaim from a crash between commit and effect is
    /// completed idempotently.
    pub fn apply_response(
        &self,
        answer: InteractionAnswer,
        live: Option<&mut SupervisedAttempt>,
    ) -> Result<AppliedInteraction, ApprovalError> {
        let interaction_id = answer.interaction_id.clone();
        let replayed = self.writer.respond_interaction(
            self.consumer_id.clone(),
            answer.command_key.clone(),
            answer.canonical_command_bytes.clone(),
            answer.interaction_id.clone(),
            answer.nonce.clone(),
            answer.generation,
            answer.operation_digest.clone(),
            answer.policy_digest.clone(),
            answer.config_digest.clone(),
            answer.response_kind,
            answer.canonical_response_bytes.clone(),
            answer.now_us,
        )?;
        let phase = self.dispatch_phase(&answer.task_id)?;
        if phase.effect_is_proven_absent() {
            let before = self.task_state(&answer.task_id)?;
            let applied = self.apply_preflight(answer)?;
            if replayed
                && matches!(
                    (&applied, before),
                    (
                        AppliedInteraction::PreflightApproved { .. },
                        TaskState::Running
                    ) | (
                        AppliedInteraction::PreflightDenied { .. },
                        TaskState::Cancelled
                    )
                )
            {
                let evidence = self.writer.interaction_response(interaction_id)?;
                return Ok(AppliedInteraction::Replayed { evidence });
            }
            return Ok(applied);
        }
        if replayed {
            let evidence = self.writer.interaction_response(interaction_id)?;
            return Ok(AppliedInteraction::Replayed { evidence });
        }
        let forwarded = if let Some(attempt) = live {
            attempt.write_stdin_line(&answer.canonical_response_bytes)?;
            true
        } else {
            false
        };
        Ok(AppliedInteraction::Runtime {
            kind: answer.response_kind,
            forwarded,
        })
    }

    /// Expires a still-pending interaction. Timeout never implies consent.
    ///
    /// Runtime or uncertain waits keep [`WriterHandle::expire_interaction`]
    /// (`NEEDS_ATTENTION`). A preflight wait with no process uses the explicit
    /// cancel path.
    pub fn expire_pending(
        &self,
        operation_id: impl Into<String>,
        task_id: &str,
        interaction_id: impl Into<String>,
        generation: i64,
        now_us: i64,
        live: Option<&mut SupervisedAttempt>,
    ) -> Result<ExpiredInteraction, ApprovalError> {
        let interaction_id = interaction_id.into();
        let phase = self.dispatch_phase(task_id)?;
        if phase.effect_is_proven_absent() {
            let delivery = self.writer.expire_preflight_interaction(
                self.consumer_id.clone(),
                operation_id,
                interaction_id,
                generation,
                now_us,
            )?;
            return Ok(ExpiredInteraction::PreflightCancelled { delivery });
        }
        let delivery = self.writer.expire_interaction(
            self.consumer_id.clone(),
            operation_id,
            interaction_id,
            generation,
            now_us,
        )?;
        if let Some(attempt) = live {
            let _ = attempt.job().terminate(1);
        }
        Ok(ExpiredInteraction::RuntimeNeedsAttention { delivery })
    }

    fn apply_preflight(
        &self,
        answer: InteractionAnswer,
    ) -> Result<AppliedInteraction, ApprovalError> {
        if answer.response_kind == InteractionResponseKind::Deny {
            let delivery = self.cancel_before_dispatch(
                &answer.task_id,
                answer.generation,
                &answer.interaction_id,
                answer.now_us,
            )?;
            return Ok(AppliedInteraction::PreflightDenied { delivery });
        }
        match self.writer.reclaim_preflight_dispatch_slot(
            format!("reclaim-preflight:{}:{}", answer.task_id, answer.generation),
            answer.task_id,
            answer.generation,
            answer.spec,
            answer.limits,
            answer.now_us.saturating_add(1),
        )? {
            DispatchOutcome::Dispatched(attempt) => {
                Ok(AppliedInteraction::PreflightApproved { attempt })
            }
            DispatchOutcome::Blocked(_) => Err(ApprovalError::SlotBlocked),
        }
    }

    fn cancel_before_dispatch(
        &self,
        task_id: &str,
        generation: i64,
        interaction_id: &str,
        now_us: i64,
    ) -> Result<ResultDelivery, ApprovalError> {
        match self.writer.transition(
            format!("preflight-deny-finalizing:{task_id}:{generation}"),
            task_id.to_owned(),
            generation,
            vec![
                TaskState::Running.as_str().to_owned(),
                TaskState::WaitingApproval.as_str().to_owned(),
            ],
            TaskState::Finalizing.as_str(),
            now_us,
        ) {
            Ok(_) | Err(StorageError::TerminalImmutable | StorageError::StaleGeneration) => {}
            Err(error) => return Err(error.into()),
        }
        let digest = format!(
            "{:x}",
            Sha256::digest(format!("preflight-deny:{interaction_id}").as_bytes())
        );
        Ok(self.writer.finalize(
            self.consumer_id.clone(),
            format!("preflight-deny:{task_id}:{generation}"),
            format!("preflight-deny:{task_id}:{generation}:{interaction_id}").into_bytes(),
            task_id.to_owned(),
            generation,
            TaskState::Cancelled.as_str(),
            digest,
            now_us.saturating_add(1),
        )?)
    }

    fn task_state(&self, task_id: &str) -> Result<TaskState, ApprovalError> {
        let snapshot = self
            .reader
            .snapshot(task_id, &self.consumer_id, SNAPSHOT_TIMEOUT)?;
        snapshot.task.value["state"]
            .as_str()
            .and_then(|state| state.parse().ok())
            .ok_or_else(|| StorageError::Quarantined("task snapshot missing state".into()).into())
    }

    fn dispatch_phase(&self, task_id: &str) -> Result<DispatchPhase, ApprovalError> {
        let snapshot = self
            .reader
            .snapshot(task_id, &self.consumer_id, SNAPSHOT_TIMEOUT)?;
        let phase = snapshot
            .attempt
            .as_ref()
            .ok_or(StorageError::StaleGeneration)?
            .dispatch_phase
            .parse::<DispatchPhase>()
            .map_err(|_| StorageError::Quarantined("unknown persisted dispatch phase".into()))?;
        Ok(phase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RecoveryDecision;
    use crate::scheduler::AdapterInstanceId;
    use crate::supervisor::{ProcessSupervisor, ResumeGate, SpawnOutcome, SpawnRequest};
    use mesh_win32::process_identity_is_live;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;
    use std::thread;
    use std::time::Duration;

    const OPERATION_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const POLICY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CONFIG_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const OTHER_DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn aid() -> String {
        AdapterInstanceId::new("fake", "default", "default", OTHER_DIGEST)
            .expect("adapter id")
            .encode()
    }

    fn spec() -> AttemptSpec {
        AttemptSpec {
            adapter_instance_id: aid(),
            config_digest: OTHER_DIGEST.into(),
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
        for profile in ["debug", "release"] {
            let candidate = workspace.join("target").join(profile).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        find_under(&workspace.join("target"))
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
        ApprovalOrchestrator,
        ProcessSupervisor,
    ) {
        let root = tempfile::tempdir().expect("tempdir");
        let writer =
            WriterHandle::start_portable(root.path().to_path_buf(), "install", 1).expect("writer");
        let reader = ReaderPool::open(root.path()).expect("reader");
        let approvals = ApprovalOrchestrator::new(writer.clone(), reader.clone(), "c");
        let supervisor = ProcessSupervisor::new(writer.clone());
        (root, writer, reader, approvals, supervisor)
    }

    fn submit_and_claim(writer: &WriterHandle, task_id: &str, now_us: i64) -> Attempt {
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

    fn open_approval(
        approvals: &ApprovalOrchestrator,
        task_id: &str,
        attempt_id: &str,
        expires_at: i64,
        now_us: i64,
    ) -> Interaction {
        approvals
            .open_pending(
                format!("open-{task_id}"),
                task_id,
                attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                expires_at,
                now_us,
            )
            .expect("open")
    }

    fn interaction_response_command(
        command_key: &str,
        task_id: &str,
        interaction_id: &str,
        generation: i64,
        operation_digest: &str,
        policy_digest: &str,
        config_digest: &str,
        nonce: &str,
        response: &serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>) {
        let response_bytes = crate::canonicalize(response)
            .expect("interaction response must be canonical")
            .into_bytes();
        let command = serde_json::json!({
            "version": 1,
            "kind": "command",
            "action": "interaction_response",
            "command_key": command_key,
            "task_id": task_id,
            "interaction_id": interaction_id,
            "generation": generation,
            "operation_digest": operation_digest,
            "policy_digest": policy_digest,
            "config_digest": config_digest,
            "nonce": nonce,
            "response": response,
        });
        let command_bytes = crate::canonicalize(&command)
            .expect("interaction command must be canonical")
            .into_bytes();
        (command_bytes, response_bytes)
    }

    fn answer_for(
        interaction: &Interaction,
        command_key: &str,
        response: &serde_json::Value,
        now_us: i64,
    ) -> InteractionAnswer {
        let kind = match response["kind"].as_str() {
            Some("approve") => InteractionResponseKind::Approve,
            Some("deny") => InteractionResponseKind::Deny,
            Some("text") => InteractionResponseKind::Text,
            other => panic!("unknown response kind {other:?}"),
        };
        let (command, bytes) = interaction_response_command(
            command_key,
            &interaction.task_id,
            &interaction.interaction_id,
            interaction.generation,
            OPERATION_DIGEST,
            POLICY_DIGEST,
            CONFIG_DIGEST,
            &interaction.nonce,
            response,
        );
        InteractionAnswer {
            task_id: interaction.task_id.clone(),
            command_key: command_key.into(),
            canonical_command_bytes: command,
            interaction_id: interaction.interaction_id.clone(),
            nonce: interaction.nonce.clone(),
            generation: interaction.generation,
            operation_digest: OPERATION_DIGEST.into(),
            policy_digest: POLICY_DIGEST.into(),
            config_digest: CONFIG_DIGEST.into(),
            response_kind: kind,
            canonical_response_bytes: bytes,
            now_us,
            spec: spec(),
            limits: SchedulerLimits::DEFAULT,
        }
    }

    fn spawn_request(
        root: &Path,
        task_id: &str,
        attempt_id: &str,
        script: &str,
        now_us: i64,
    ) -> SpawnRequest {
        SpawnRequest {
            task_id: task_id.to_owned(),
            generation: 0,
            attempt_id: attempt_id.to_owned(),
            executable: fake_adapter_exe(),
            arguments: vec![OsString::from("--json"), OsString::from(script)],
            env_allowlist: Vec::new(),
            extra_env: Vec::new(),
            current_dir: None,
            data_root: root.to_path_buf(),
            spool_quota_bytes: 0,
            now_us,
            consumer_id: "c".into(),
        }
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

    fn phase_of(reader: &ReaderPool, task_id: &str) -> String {
        reader
            .snapshot(task_id, "c", Duration::from_secs(2))
            .expect("snapshot")
            .attempt
            .expect("attempt")
            .dispatch_phase
    }

    fn last_seq(reader: &ReaderPool, task_id: &str) -> i64 {
        reader
            .snapshot(task_id, "c", Duration::from_secs(2))
            .expect("snapshot")
            .task
            .cursor
            .last_committed_seq
    }

    fn wait_for_spool_line(spool: &Path, needle: &str) {
        for _ in 0..200 {
            if let Ok(text) = fs::read_to_string(spool)
                && text.contains(needle)
            {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("stdout spool never contained {needle}");
    }

    #[test]
    fn approvals_preflight_approve_then_spawn_succeeds() {
        let (root, writer, reader, approvals, supervisor) = setup();
        let attempt = submit_and_claim(&writer, "pre-ok", 10);
        let interaction = open_approval(&approvals, "pre-ok", &attempt.attempt_id, 10_000, 12);
        assert_eq!(state_of(&reader, "pre-ok"), "WAITING_APPROVAL");
        assert_eq!(phase_of(&reader, "pre-ok"), "PRE_DISPATCH");
        let applied = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "approve-pre-ok",
                    &serde_json::json!({"kind":"approve"}),
                    13,
                ),
                None,
            )
            .expect("approve");
        let reclaimed = match applied {
            AppliedInteraction::PreflightApproved { attempt } => attempt,
            other => panic!("expected preflight approve: {other:?}"),
        };
        assert_eq!(reclaimed.attempt_id, attempt.attempt_id);
        let script =
            r#"[{"type":"lifecycle","state":"RUNNING"},{"type":"terminal","state":"SUCCEEDED"}]"#;
        let outcome = supervisor
            .spawn(
                spawn_request(root.path(), "pre-ok", &attempt.attempt_id, script, 20),
                ResumeGate::Resume,
            )
            .expect("spawn");
        let mut live = match outcome {
            SpawnOutcome::Started(live) => live,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        assert_eq!(live.wait(Duration::from_secs(5)).expect("wait"), Some(0));
        live.finalize_exit(0, 30).expect("finalize");
        assert_eq!(state_of(&reader, "pre-ok"), "SUCCEEDED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_preflight_deny_never_creates_process_and_cancels() {
        let (root, writer, reader, approvals, _supervisor) = setup();
        let attempt = submit_and_claim(&writer, "pre-deny", 10);
        let interaction = open_approval(&approvals, "pre-deny", &attempt.attempt_id, 10_000, 12);
        let applied = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "deny-pre",
                    &serde_json::json!({"kind":"deny"}),
                    13,
                ),
                None,
            )
            .expect("deny");
        match applied {
            AppliedInteraction::PreflightDenied { delivery } => {
                assert_eq!(delivery.terminal_state, "CANCELLED");
            }
            other => panic!("expected preflight deny: {other:?}"),
        }
        assert_eq!(state_of(&reader, "pre-deny"), "CANCELLED");
        assert_eq!(phase_of(&reader, "pre-deny"), "PRE_DISPATCH");
        let spool = root.path().join("attempts").join(&attempt.attempt_id);
        assert!(
            !spool.exists(),
            "preflight deny must not create an attempt spool"
        );
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_preflight_expiry_cancels_without_process() {
        let (root, writer, reader, approvals, _supervisor) = setup();
        let attempt = submit_and_claim(&writer, "pre-exp", 10);
        let interaction = open_approval(&approvals, "pre-exp", &attempt.attempt_id, 5_000, 12);
        let too_early = approvals.expire_pending(
            "expire-early",
            "pre-exp",
            interaction.interaction_id.clone(),
            0,
            4_999,
            None,
        );
        assert!(
            matches!(
                too_early,
                Err(ApprovalError::Storage(StorageError::InteractionConflict))
            ),
            "timeout before the deadline must not approve or cancel: {too_early:?}"
        );
        assert_eq!(state_of(&reader, "pre-exp"), "WAITING_APPROVAL");
        let expired = approvals
            .expire_pending(
                "expire-pre",
                "pre-exp",
                interaction.interaction_id.clone(),
                0,
                5_000,
                None,
            )
            .expect("expire");
        match expired {
            ExpiredInteraction::PreflightCancelled { delivery } => {
                assert_eq!(delivery.terminal_state, "CANCELLED");
            }
            ExpiredInteraction::RuntimeNeedsAttention { delivery } => {
                panic!("expected preflight cancel, got runtime {delivery:?}")
            }
        }
        assert_eq!(state_of(&reader, "pre-exp"), "CANCELLED");
        assert_eq!(phase_of(&reader, "pre-exp"), "PRE_DISPATCH");
        assert!(
            !root
                .path()
                .join("attempts")
                .join(&attempt.attempt_id)
                .exists()
        );
        let replay = approvals
            .expire_pending(
                "expire-pre",
                "pre-exp",
                interaction.interaction_id,
                0,
                51,
                None,
            )
            .expect("replay expire");
        match replay {
            ExpiredInteraction::PreflightCancelled { delivery } => {
                assert_eq!(delivery.terminal_state, "CANCELLED");
            }
            ExpiredInteraction::RuntimeNeedsAttention { delivery } => {
                panic!("expected expire replay, got runtime {delivery:?}")
            }
        }
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_runtime_commits_then_forwards_and_child_continues() {
        let (root, writer, reader, approvals, supervisor) = setup();
        let attempt = submit_and_claim(&writer, "rt-ok", 10);
        let script = r#"[{"type":"approval","operation":"write_file"},{"type":"terminal","state":"SUCCEEDED"}]"#;
        let outcome = supervisor
            .spawn(
                spawn_request(root.path(), "rt-ok", &attempt.attempt_id, script, 20),
                ResumeGate::Resume,
            )
            .expect("spawn");
        let mut live = match outcome {
            SpawnOutcome::Started(live) => live,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        wait_for_spool_line(live.stdout_spool_path(), "\"type\":\"approval\"");
        let interaction = open_approval(&approvals, "rt-ok", &attempt.attempt_id, 10_000, 21);
        assert_eq!(state_of(&reader, "rt-ok"), "WAITING_APPROVAL");
        assert_eq!(phase_of(&reader, "rt-ok"), "PROCESS_STARTED");
        let applied = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "approve-rt",
                    &serde_json::json!({"kind":"approve"}),
                    22,
                ),
                Some(&mut live),
            )
            .expect("approve");
        match applied {
            AppliedInteraction::Runtime { kind, forwarded } => {
                assert_eq!(kind, InteractionResponseKind::Approve);
                assert!(forwarded);
            }
            other => panic!("expected runtime forward: {other:?}"),
        }
        let evidence = writer
            .interaction_response(interaction.interaction_id.clone())
            .expect("committed before forward");
        assert_eq!(evidence.response_kind, InteractionResponseKind::Approve);
        assert_eq!(live.wait(Duration::from_secs(5)).expect("wait"), Some(0));
        live.finalize_exit(0, 30).expect("finalize");
        assert_eq!(state_of(&reader, "rt-ok"), "SUCCEEDED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_runtime_expiry_and_kill_after_forwarded_approve_need_attention() {
        let (root, writer, reader, approvals, supervisor) = setup();
        let waiting = submit_and_claim(&writer, "rt-exp", 10);
        let hang_script = r#"[{"type":"approval","operation":"write_file"},{"type":"hang"}]"#;
        let outcome = supervisor
            .spawn(
                spawn_request(root.path(), "rt-exp", &waiting.attempt_id, hang_script, 20),
                ResumeGate::Resume,
            )
            .expect("spawn expire");
        let mut waiting_live = match outcome {
            SpawnOutcome::Started(live) => live,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        wait_for_spool_line(waiting_live.stdout_spool_path(), "\"type\":\"approval\"");
        let pending = open_approval(&approvals, "rt-exp", &waiting.attempt_id, 5_000, 21);
        let expired = approvals
            .expire_pending(
                "expire-rt",
                "rt-exp",
                pending.interaction_id,
                0,
                5_000,
                Some(&mut waiting_live),
            )
            .expect("runtime expire");
        match expired {
            ExpiredInteraction::RuntimeNeedsAttention { delivery } => {
                assert_eq!(delivery.terminal_state, "NEEDS_ATTENTION");
            }
            ExpiredInteraction::PreflightCancelled { delivery } => {
                panic!("expected runtime attention, got preflight {delivery:?}")
            }
        }
        assert_eq!(state_of(&reader, "rt-exp"), "NEEDS_ATTENTION");
        drop(waiting_live);

        let approved = submit_and_claim(&writer, "rt-kill", 100);
        let outcome = supervisor
            .spawn(
                spawn_request(
                    root.path(),
                    "rt-kill",
                    &approved.attempt_id,
                    hang_script,
                    110,
                ),
                ResumeGate::Resume,
            )
            .expect("spawn kill");
        let mut approved_live = match outcome {
            SpawnOutcome::Started(live) => live,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        wait_for_spool_line(approved_live.stdout_spool_path(), "\"type\":\"approval\"");
        let interaction = open_approval(&approvals, "rt-kill", &approved.attempt_id, 10_000, 111);
        let applied = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "approve-then-kill",
                    &serde_json::json!({"kind":"approve"}),
                    112,
                ),
                Some(&mut approved_live),
            )
            .expect("forward approve");
        assert!(matches!(
            applied,
            AppliedInteraction::Runtime {
                forwarded: true,
                ..
            }
        ));
        let identity = approved_live.identity().clone();
        drop(approved_live);
        thread::sleep(Duration::from_millis(80));
        assert!(!process_identity_is_live(&identity).expect("live query"));
        let decisions = writer
            .reconcile_nonterminal("c", 120)
            .expect("reconcile after forwarded approve");
        assert!(
            decisions.iter().any(|(task_id, decision)| {
                task_id == "rt-kill" && *decision == RecoveryDecision::NeedsAttention
            }),
            "crash after a forwarded approval must not auto-retry: {decisions:?}"
        );
        assert_eq!(state_of(&reader, "rt-kill"), "NEEDS_ATTENTION");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_stale_generation_wrong_nonce_digest_change_and_second_answer_conflict() {
        let (_root, writer, reader, approvals, _supervisor) = setup();
        let attempt = submit_and_claim(&writer, "fence", 10);
        let interaction = open_approval(&approvals, "fence", &attempt.attempt_id, 10_000, 12);
        let seq_before = last_seq(&reader, "fence");

        let mut stale = answer_for(
            &interaction,
            "stale-gen",
            &serde_json::json!({"kind":"approve"}),
            13,
        );
        stale.generation = 9;
        let (command, bytes) = interaction_response_command(
            "stale-gen",
            "fence",
            &interaction.interaction_id,
            9,
            OPERATION_DIGEST,
            POLICY_DIGEST,
            CONFIG_DIGEST,
            &interaction.nonce,
            &serde_json::json!({"kind":"approve"}),
        );
        stale.canonical_command_bytes = command;
        stale.canonical_response_bytes = bytes;
        assert!(matches!(
            approvals.apply_response(stale, None),
            Err(ApprovalError::Storage(StorageError::InteractionConflict))
        ));

        let mut nonce = answer_for(
            &interaction,
            "bad-nonce",
            &serde_json::json!({"kind":"approve"}),
            14,
        );
        nonce.nonce = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        let (command, bytes) = interaction_response_command(
            "bad-nonce",
            "fence",
            &interaction.interaction_id,
            0,
            OPERATION_DIGEST,
            POLICY_DIGEST,
            CONFIG_DIGEST,
            &nonce.nonce,
            &serde_json::json!({"kind":"approve"}),
        );
        nonce.canonical_command_bytes = command;
        nonce.canonical_response_bytes = bytes;
        assert!(matches!(
            approvals.apply_response(nonce, None),
            Err(ApprovalError::Storage(StorageError::InteractionConflict))
        ));

        let mut digest = answer_for(
            &interaction,
            "bad-digest",
            &serde_json::json!({"kind":"approve"}),
            15,
        );
        digest.operation_digest = OTHER_DIGEST.into();
        let (command, bytes) = interaction_response_command(
            "bad-digest",
            "fence",
            &interaction.interaction_id,
            0,
            OTHER_DIGEST,
            POLICY_DIGEST,
            CONFIG_DIGEST,
            &interaction.nonce,
            &serde_json::json!({"kind":"approve"}),
        );
        digest.canonical_command_bytes = command;
        digest.canonical_response_bytes = bytes;
        assert!(matches!(
            approvals.apply_response(digest, None),
            Err(ApprovalError::Storage(StorageError::InteractionConflict))
        ));

        assert_eq!(state_of(&reader, "fence"), "WAITING_APPROVAL");
        assert_eq!(last_seq(&reader, "fence"), seq_before);

        let first = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "first",
                    &serde_json::json!({"kind":"approve"}),
                    16,
                ),
                None,
            )
            .expect("first answer");
        assert!(matches!(
            first,
            AppliedInteraction::PreflightApproved { .. }
        ));
        let seq_after = last_seq(&reader, "fence");
        let second = approvals.apply_response(
            answer_for(
                &interaction,
                "second",
                &serde_json::json!({"kind":"deny"}),
                17,
            ),
            None,
        );
        assert!(matches!(
            second,
            Err(ApprovalError::Storage(StorageError::InteractionConflict))
        ));
        assert_eq!(last_seq(&reader, "fence"), seq_after);
        let evidence = writer
            .interaction_response(interaction.interaction_id)
            .expect("original answer");
        assert_eq!(evidence.response_kind, InteractionResponseKind::Approve);
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_identical_command_key_replay_after_reconnect_returns_original() {
        let (root, writer, _reader, approvals, _supervisor) = setup();
        let attempt = submit_and_claim(&writer, "replay", 10);
        let interaction = open_approval(&approvals, "replay", &attempt.attempt_id, 10_000, 12);
        let first_answer = answer_for(
            &interaction,
            "same-key",
            &serde_json::json!({"kind":"approve"}),
            13,
        );
        let first = approvals.apply_response(first_answer, None).expect("first");
        assert!(matches!(
            first,
            AppliedInteraction::PreflightApproved { .. }
        ));
        let original = writer
            .interaction_response(interaction.interaction_id.clone())
            .expect("original");

        let changed = answer_for(
            &interaction,
            "same-key",
            &serde_json::json!({"kind":"deny"}),
            14,
        );
        assert!(matches!(
            approvals.apply_response(changed, None),
            Err(ApprovalError::Storage(StorageError::IdempotencyConflict))
        ));

        writer.shutdown().expect("shutdown");
        let writer =
            WriterHandle::start_portable(root.path().to_path_buf(), "install", 20).expect("reopen");
        let reader = ReaderPool::open(root.path()).expect("reader");
        let approvals = ApprovalOrchestrator::new(writer.clone(), reader, "c");
        let replayed = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "same-key",
                    &serde_json::json!({"kind":"approve"}),
                    21,
                ),
                None,
            )
            .expect("reconnect replay");
        match replayed {
            AppliedInteraction::Replayed { evidence } => {
                assert_eq!(evidence.response_kind, original.response_kind);
                assert_eq!(evidence.bytes, original.bytes);
            }
            other => panic!("expected replay: {other:?}"),
        }
        let after = writer
            .interaction_response(interaction.interaction_id)
            .expect("still original");
        assert_eq!(after.bytes, original.bytes);
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_expiry_then_late_approve_is_conflict() {
        let (_root, writer, reader, approvals, _supervisor) = setup();
        let attempt = submit_and_claim(&writer, "late", 10);
        let interaction = open_approval(&approvals, "late", &attempt.attempt_id, 5_000, 12);
        approvals
            .expire_pending(
                "expire-late",
                "late",
                interaction.interaction_id.clone(),
                0,
                5_000,
                None,
            )
            .expect("expire");
        assert_eq!(state_of(&reader, "late"), "CANCELLED");
        let late = approvals.apply_response(
            answer_for(
                &interaction,
                "late-approve",
                &serde_json::json!({"kind":"approve"}),
                41,
            ),
            None,
        );
        assert!(matches!(
            late,
            Err(ApprovalError::Storage(StorageError::InteractionConflict))
        ));
        assert_eq!(state_of(&reader, "late"), "CANCELLED");
        writer.shutdown().expect("shutdown");
    }

    fn commit_answer(writer: &WriterHandle, answer: &InteractionAnswer) {
        writer
            .respond_interaction(
                "c",
                answer.command_key.clone(),
                answer.canonical_command_bytes.clone(),
                answer.interaction_id.clone(),
                answer.nonce.clone(),
                answer.generation,
                answer.operation_digest.clone(),
                answer.policy_digest.clone(),
                answer.config_digest.clone(),
                answer.response_kind,
                answer.canonical_response_bytes.clone(),
                answer.now_us,
            )
            .expect("commit answer");
    }

    #[test]
    fn approvals_replay_after_committed_preflight_deny_cancels() {
        let (_root, writer, reader, approvals, _supervisor) = setup();
        let attempt = submit_and_claim(&writer, "deny-crash", 10);
        let interaction = open_approval(&approvals, "deny-crash", &attempt.attempt_id, 10_000, 12);
        let answer = answer_for(
            &interaction,
            "deny-crash-key",
            &serde_json::json!({"kind":"deny"}),
            13,
        );
        commit_answer(&writer, &answer);
        assert_eq!(state_of(&reader, "deny-crash"), "RUNNING");
        let applied = approvals
            .apply_response(answer, None)
            .expect("complete deny after commit");
        match applied {
            AppliedInteraction::PreflightDenied { delivery } => {
                assert_eq!(delivery.terminal_state, "CANCELLED");
            }
            other => panic!("expected preflight deny completion: {other:?}"),
        }
        assert_eq!(state_of(&reader, "deny-crash"), "CANCELLED");
        let replay = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "deny-crash-key",
                    &serde_json::json!({"kind":"deny"}),
                    14,
                ),
                None,
            )
            .expect("deny replay");
        assert!(matches!(replay, AppliedInteraction::Replayed { .. }));
        assert_eq!(state_of(&reader, "deny-crash"), "CANCELLED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_reconcile_does_not_retry_preflight_deny_or_pending_wait() {
        let (_root, writer, reader, approvals, _supervisor) = setup();
        let waiting = submit_and_claim(&writer, "still-wait", 10);
        open_approval(&approvals, "still-wait", &waiting.attempt_id, 10_000, 12);
        let denied = submit_and_claim(&writer, "deny-rec", 20);
        let interaction = open_approval(&approvals, "deny-rec", &denied.attempt_id, 10_000, 22);
        commit_answer(
            &writer,
            &answer_for(
                &interaction,
                "deny-rec-key",
                &serde_json::json!({"kind":"deny"}),
                23,
            ),
        );
        assert_eq!(state_of(&reader, "deny-rec"), "RUNNING");
        let decisions = writer
            .reconcile_nonterminal("c", 30)
            .expect("reconcile must not fail mid-approval");
        assert!(
            decisions.iter().any(|(task_id, decision)| {
                task_id == "deny-rec" && *decision == RecoveryDecision::FinalizeCancellation
            }),
            "committed preflight deny must cancel, not retry: {decisions:?}"
        );
        assert!(
            decisions.iter().all(|(task_id, _)| task_id != "still-wait"),
            "pending preflight wait must not be retried or expired: {decisions:?}"
        );
        assert_eq!(state_of(&reader, "deny-rec"), "CANCELLED");
        assert_eq!(state_of(&reader, "still-wait"), "WAITING_APPROVAL");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_preflight_slot_block_releases_occupancy_then_retry_can_spawn() {
        let (_root, writer, reader, approvals, _supervisor) = setup();
        let waiting = submit_and_claim(&writer, "slot-wait", 10);
        let interaction = open_approval(&approvals, "slot-wait", &waiting.attempt_id, 10_000, 12);
        let occupying = submit_and_claim(&writer, "slot-hold", 20);
        assert_eq!(
            reader
                .occupancy(Duration::from_secs(2))
                .expect("occupancy")
                .occupied(&aid()),
            1
        );
        let first = approvals.apply_response(
            answer_for(
                &interaction,
                "slot-approve",
                &serde_json::json!({"kind":"approve"}),
                21,
            ),
            None,
        );
        assert!(
            matches!(first, Err(ApprovalError::SlotBlocked)),
            "same adapter already occupies the per-adapter slot: {first:?}"
        );
        assert_eq!(state_of(&reader, "slot-wait"), "WAITING_APPROVAL");
        assert_eq!(
            reader
                .occupancy(Duration::from_secs(2))
                .expect("occupancy after block")
                .occupied(&aid()),
            1,
            "refused reclaim must not leave the approved task occupying"
        );

        writer
            .transition(
                "release-hold-finalizing",
                occupying.task_id.clone(),
                0,
                vec![TaskState::Preparing.as_str().to_owned()],
                TaskState::Finalizing.as_str(),
                30,
            )
            .expect("release occupier");
        writer
            .finalize(
                "c",
                "release-hold",
                b"release-hold".to_vec(),
                occupying.task_id.clone(),
                0,
                TaskState::Cancelled.as_str(),
                format!("{:x}", Sha256::digest(b"release-hold")),
                31,
            )
            .expect("cancel occupier");
        assert_eq!(
            reader
                .occupancy(Duration::from_secs(2))
                .expect("occupancy after release")
                .global,
            0
        );

        let retried = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "slot-approve",
                    &serde_json::json!({"kind":"approve"}),
                    32,
                ),
                None,
            )
            .expect("reclaim after slot frees");
        assert!(
            matches!(retried, AppliedInteraction::PreflightApproved { .. }),
            "retry after a freed slot must be allowed to spawn: {retried:?}"
        );
        assert_eq!(state_of(&reader, "slot-wait"), "RUNNING");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn approvals_runtime_deny_is_forwarded_and_does_not_invent_success() {
        let (root, writer, reader, approvals, supervisor) = setup();
        let attempt = submit_and_claim(&writer, "rt-deny", 10);
        let script = r#"[{"type":"approval","operation":"write_file"},{"type":"terminal","state":"SUCCEEDED"}]"#;
        let outcome = supervisor
            .spawn(
                spawn_request(root.path(), "rt-deny", &attempt.attempt_id, script, 20),
                ResumeGate::Resume,
            )
            .expect("spawn");
        let mut live = match outcome {
            SpawnOutcome::Started(live) => live,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must start"),
        };
        wait_for_spool_line(live.stdout_spool_path(), "\"type\":\"approval\"");
        let interaction = open_approval(&approvals, "rt-deny", &attempt.attempt_id, 10_000, 21);
        let applied = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "deny-rt",
                    &serde_json::json!({"kind":"deny"}),
                    22,
                ),
                Some(&mut live),
            )
            .expect("forward deny");
        match applied {
            AppliedInteraction::Runtime { kind, forwarded } => {
                assert_eq!(kind, InteractionResponseKind::Deny);
                assert!(forwarded);
            }
            other => panic!("expected runtime deny forward: {other:?}"),
        }
        assert_ne!(state_of(&reader, "rt-deny"), "SUCCEEDED");
        assert_eq!(
            writer
                .interaction_response(interaction.interaction_id)
                .expect("committed deny")
                .response_kind,
            InteractionResponseKind::Deny
        );
        assert_eq!(live.wait(Duration::from_secs(5)).expect("wait"), Some(0));
        live.finalize_exit(0, 30).expect("provider may continue");
        assert_eq!(state_of(&reader, "rt-deny"), "SUCCEEDED");
        writer.shutdown().expect("shutdown");
    }

    #[test]
    fn current_directory_escape_accepts_orchestrator_approval() {
        use crate::domain::{EffectProfile, IsolationLevel, WorkspaceMode};
        use crate::worktree::{CurrentDirectoryRequest, WorktreeManager};

        let (root, writer, _reader, approvals, _supervisor) = setup();
        let cwd = tempfile::tempdir().expect("cwd");
        let attempt = submit_and_claim(&writer, "escape-ok", 10);
        let interaction = open_approval(&approvals, "escape-ok", &attempt.attempt_id, 10_000, 12);
        let applied = approvals
            .apply_response(
                answer_for(
                    &interaction,
                    "approve-escape",
                    &serde_json::json!({"kind": "approve"}),
                    13,
                ),
                None,
            )
            .expect("preflight approve");
        assert!(matches!(
            applied,
            AppliedInteraction::PreflightApproved { .. }
        ));
        let evidence = writer
            .interaction_response(interaction.interaction_id)
            .expect("durable approval evidence");
        let manager = WorktreeManager::new(root.path(), writer.clone()).expect("worktree manager");
        let settings: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/v1/golden/config-allow-current-directory.json"
        ))
        .expect("opt-in config");
        let admitted = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &settings,
                approval: Some(&evidence),
            })
            .expect("escape hatch");
        assert_eq!(admitted.isolation, IsolationLevel::BestEffort);
        assert_ne!(admitted.isolation, IsolationLevel::Enforced);
        assert!(
            !admitted.cwd.starts_with(manager.worktrees_root()),
            "orchestrated hatch must not create a mesh worktree"
        );
        writer.shutdown().expect("shutdown");
    }
}
