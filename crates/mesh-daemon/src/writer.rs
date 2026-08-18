//! Bounded, sole-writer actor facade for every durable mutation.

#![allow(clippy::missing_errors_doc, clippy::too_many_arguments)]

use std::{
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc},
    thread,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    domain::{
        DispatchPhase, InteractionCapabilityClass, InteractionResponseKind, RecoveryDecision,
        ReviewVerdict,
    },
    improvement::{
        CanaryAdmission, CanaryDecision, CandidateCommandResult, CandidateDecision,
        CandidateProposal, EvaluationDecision, ImprovementEngine, ImprovementPolicy,
        ObservationDecision, ObservationInput, RollbackCommandResult,
    },
    scheduler::SchedulerLimits,
    storage::{
        Attempt, AttemptSpec, BackupManifest, DispatchOutcome, DurableFilesystem, EmergencyState,
        GcCandidate, GcDeletionPlan, Interaction, InteractionResponseEvidence, QuotaPolicy, Result,
        ResultDelivery, Storage, StorageError, Submission,
    },
};

#[cfg(test)]
use crate::storage::PortableFilesystem;

const MAILBOX_CAPACITY: usize = 128;

type StorageOperation = Box<dyn FnOnce(&mut Storage) + Send + 'static>;

enum Command {
    Execute(StorageOperation),
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterPhase {
    Running,
    ShuttingDown,
    Stopped,
}

struct WriterLifecycle {
    phase: Mutex<WriterPhase>,
    changed: Condvar,
}

impl WriterLifecycle {
    fn new() -> Self {
        Self {
            phase: Mutex::new(WriterPhase::Running),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, WriterPhase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn begin_shutdown(&self) -> bool {
        let mut phase = self.lock();
        if *phase != WriterPhase::Running {
            return false;
        }
        *phase = WriterPhase::ShuttingDown;
        self.changed.notify_all();
        true
    }

    fn wait_until_stopped(&self) {
        let mut phase = self.lock();
        while *phase != WriterPhase::Stopped {
            phase = self
                .changed
                .wait(phase)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn mark_stopped(&self) {
        let mut phase = self.lock();
        *phase = WriterPhase::Stopped;
        self.changed.notify_all();
    }
}

/// Cloneable client to the daemon's only read-write `SQLite` connection.
#[derive(Clone)]
pub struct WriterHandle {
    sender: mpsc::SyncSender<Command>,
    lifecycle: Arc<WriterLifecycle>,
}

impl WriterHandle {
    /// Start the sole writer with the production validated Windows filesystem.
    #[cfg(windows)]
    pub fn start_windows(
        root: PathBuf,
        install_id: &str,
        now_us: i64,
        quota: Option<QuotaPolicy>,
    ) -> Result<Self> {
        let filesystem = Arc::new(crate::windows_filesystem::WindowsFilesystem::new(root)?);
        let canonical_root = filesystem.root().to_path_buf();
        Self::start(canonical_root, install_id, now_us, filesystem, quota)
    }

    pub(crate) fn start(
        root: PathBuf,
        install_id: &str,
        now_us: i64,
        filesystem: Arc<dyn DurableFilesystem>,
        quota: Option<QuotaPolicy>,
    ) -> Result<Self> {
        let mut storage =
            Storage::open_with_filesystem(root, install_id, now_us, filesystem, quota)?;
        storage.ensure_default_improvement_engine(now_us)?;
        let (sender, receiver) = mpsc::sync_channel(MAILBOX_CAPACITY);
        let lifecycle = Arc::new(WriterLifecycle::new());
        let actor_lifecycle = Arc::clone(&lifecycle);
        thread::Builder::new()
            .name("mesh-storage-writer".into())
            .spawn(move || {
                let result = panic::catch_unwind(AssertUnwindSafe(|| run(storage, &receiver)));
                // `run` owns `Storage`, so both its normal return and unwind
                // drop SQLite before publishing the terminal lifecycle state.
                actor_lifecycle.mark_stopped();
                if let Err(payload) = result {
                    panic::resume_unwind(payload);
                }
            })
            .map_err(StorageError::Io)?;
        Ok(Self { sender, lifecycle })
    }

    #[cfg(test)]
    pub(crate) fn start_portable(root: PathBuf, install_id: &str, now_us: i64) -> Result<Self> {
        Self::start(root, install_id, now_us, Arc::new(PortableFilesystem), None)
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        *self.lifecycle.lock() == WriterPhase::Running
    }

    pub fn shutdown(&self) -> Result<()> {
        if self.lifecycle.begin_shutdown() {
            // Calls admitted before the state transition have already enqueued
            // under the same lifecycle lock. A blocking send lets them drain
            // without reopening admission when the bounded mailbox is full.
            let _ = self.sender.send(Command::Shutdown);
        }
        self.lifecycle.wait_until_stopped();
        Ok(())
    }

    fn call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Storage) -> Result<T> + Send + 'static,
    {
        let (send, receive) = mpsc::sync_channel(1);
        let command = Command::Execute(Box::new(move |storage| {
            let result = operation(storage);
            let result = if let Err(error) = result {
                if Storage::is_storage_pressure(&error) {
                    storage.latch_detected_storage_pressure();
                    Err(StorageError::StorageEmergency)
                } else {
                    Err(error)
                }
            } else {
                result
            };
            let _ = send.send(result);
        }));
        let send_result = {
            // This lock linearizes admission with shutdown. Once shutdown
            // changes the phase, no clone can enqueue behind its command.
            let phase = self.lifecycle.lock();
            if *phase != WriterPhase::Running {
                return Err(stopped());
            }
            self.sender.try_send(command)
        };
        send_result.map_err(|error| {
            if matches!(error, mpsc::TrySendError::Full(_)) {
                StorageError::WriterBackpressure
            } else {
                stopped()
            }
        })?;
        receive.recv().map_err(|_| stopped())?
    }

    pub fn submit(
        &self,
        consumer_id: impl Into<String>,
        method: impl Into<String>,
        command_key: impl Into<String>,
        canonical_request_bytes: impl Into<Vec<u8>>,
        task_id: impl Into<String>,
        retry_of_task_id: Option<String>,
        now_us: i64,
    ) -> Result<Submission> {
        self.submit_for_scheduling(
            consumer_id,
            method,
            command_key,
            canonical_request_bytes,
            task_id,
            retry_of_task_id,
            0,
            None,
            now_us,
        )
    }

    /// Submits with the persisted scheduler inputs: `priority` (higher
    /// dispatches earlier, `0..=9`) and the durable `adapter_instance_id`
    /// (agent family plus local account/profile/config identity — see
    /// [`crate::scheduler::AdapterInstanceId`]). A missing adapter instance
    /// means routing has not assigned one yet; the first
    /// `claim_dispatch_slot` may assign it, after which it is immutable.
    pub fn submit_for_scheduling(
        &self,
        consumer_id: impl Into<String>,
        method: impl Into<String>,
        command_key: impl Into<String>,
        canonical_request_bytes: impl Into<Vec<u8>>,
        task_id: impl Into<String>,
        retry_of_task_id: Option<String>,
        priority: u8,
        adapter_instance_id: Option<&str>,
        now_us: i64,
    ) -> Result<Submission> {
        let consumer_id = consumer_id.into();
        let method = method.into();
        let command_key = command_key.into();
        let canonical_request_bytes = canonical_request_bytes.into();
        let task_id = task_id.into();
        let adapter_instance_id = adapter_instance_id.map(str::to_owned);
        self.call(move |storage| {
            storage.submit_with_request(
                &consumer_id,
                &method,
                &command_key,
                &canonical_request_bytes,
                &task_id,
                retry_of_task_id.as_deref(),
                priority,
                adapter_instance_id.as_deref(),
                now_us,
            )
        })
    }

    /// The single writer-owned dispatch decision. See
    /// [`crate::scheduler`] for the occupancy, limits, and restart contracts.
    ///
    /// In one transaction this verifies generation/state `QUEUED` or elapsed
    /// `RETRY_WAIT`, recomputes occupancy from the same `SQLite` rows, and
    /// transitions the task to `PREPARING` with a new attempt only when both
    /// limits allow. A refusal leaves the task queued and returns typed
    /// `DispatchBlocked` evidence. Replaying the same `operation_id` with the
    /// same decision inputs returns the original attempt.
    pub fn claim_dispatch_slot(
        &self,
        operation_id: impl Into<String>,
        task_id: impl Into<String>,
        generation: i64,
        spec: AttemptSpec,
        limits: SchedulerLimits,
        now_us: i64,
    ) -> Result<DispatchOutcome> {
        let operation_id = operation_id.into();
        let task_id = task_id.into();
        self.call(move |storage| {
            storage.claim_dispatch_slot(&operation_id, &task_id, generation, &spec, limits, now_us)
        })
    }

    /// Re-checks occupancy for an answered preflight approval before spawn.
    pub fn reclaim_preflight_dispatch_slot(
        &self,
        operation_id: impl Into<String>,
        task_id: impl Into<String>,
        generation: i64,
        spec: AttemptSpec,
        limits: SchedulerLimits,
        now_us: i64,
    ) -> Result<DispatchOutcome> {
        let operation_id = operation_id.into();
        let task_id = task_id.into();
        self.call(move |storage| {
            storage.reclaim_preflight_dispatch_slot(
                &operation_id,
                &task_id,
                generation,
                &spec,
                limits,
                now_us,
            )
        })
    }

    /// Ensures the immutable empty M3 configuration is durably seeded through
    /// the sole storage writer actor.
    pub fn ensure_empty_config_v1(&self, now_us: i64) -> Result<()> {
        self.call(move |storage| storage.ensure_empty_config_v1(now_us))
    }

    pub fn ensure_improvement_engine(
        &self,
        policy: ImprovementPolicy,
        now_us: i64,
    ) -> Result<ImprovementEngine> {
        self.call(move |storage| storage.ensure_improvement_engine(policy, now_us))
    }

    pub fn set_improvement_enabled(&self, enabled: bool, now_us: i64) -> Result<()> {
        self.call(move |storage| storage.set_improvement_enabled(enabled, now_us))
    }

    pub fn improvement_observe(&self, input: ObservationInput) -> Result<ObservationDecision> {
        self.call(move |storage| storage.improvement_observe(&input))
    }

    pub fn improvement_open_case(
        &self,
        input: ObservationInput,
        now_us: i64,
    ) -> Result<Option<String>> {
        self.call(move |storage| storage.improvement_open_case(&input, now_us))
    }

    pub fn improvement_propose_candidate(
        &self,
        proposal: CandidateProposal,
        now_us: i64,
    ) -> Result<Option<CandidateDecision>> {
        self.call(move |storage| storage.improvement_propose_candidate(proposal, now_us))
    }

    pub fn improvement_assign_canary(
        &self,
        case_id: impl Into<String>,
        admission: CanaryAdmission,
    ) -> Result<CanaryDecision> {
        let case_id = case_id.into();
        self.call(move |storage| storage.improvement_assign_canary(&case_id, admission))
    }

    pub fn improvement_evaluate(
        &self,
        case_id: impl Into<String>,
        now_us: i64,
    ) -> Result<EvaluationDecision> {
        let case_id = case_id.into();
        self.call(move |storage| storage.improvement_evaluate(&case_id, now_us))
    }

    pub fn improvement_propose_command(
        &self,
        consumer_id: impl Into<String>,
        command_key: impl Into<String>,
        canonical_command: impl Into<Vec<u8>>,
        proposal: CandidateProposal,
        now_us: i64,
    ) -> Result<CandidateCommandResult> {
        let consumer_id = consumer_id.into();
        let command_key = command_key.into();
        let canonical_command = canonical_command.into();
        self.call(move |storage| {
            storage.improvement_propose_command(
                &consumer_id,
                &command_key,
                &canonical_command,
                proposal,
                now_us,
            )
        })
    }

    pub fn improvement_rollback_command(
        &self,
        consumer_id: impl Into<String>,
        command_key: impl Into<String>,
        canonical_command: impl Into<Vec<u8>>,
        case_id: impl Into<String>,
        target_config_version: i64,
        now_us: i64,
    ) -> Result<RollbackCommandResult> {
        let consumer_id = consumer_id.into();
        let command_key = command_key.into();
        let canonical_command = canonical_command.into();
        let case_id = case_id.into();
        self.call(move |storage| {
            storage.improvement_rollback_command(
                &consumer_id,
                &command_key,
                &canonical_command,
                &case_id,
                target_config_version,
                now_us,
            )
        })
    }

    pub fn begin_attempt(
        &self,
        consumer_id: impl Into<String>,
        command_key: impl Into<String>,
        canonical_request_bytes: impl Into<Vec<u8>>,
        task_id: impl Into<String>,
        generation: i64,
        spec: AttemptSpec,
        now_us: i64,
    ) -> Result<Attempt> {
        let consumer_id = consumer_id.into();
        let command_key = command_key.into();
        let request_digest = hash(canonical_request_bytes.into());
        let task_id = task_id.into();
        self.call(move |storage| {
            storage.begin_attempt_with_spec(
                &consumer_id,
                &command_key,
                &request_digest,
                &task_id,
                generation,
                &spec,
                now_us,
            )
        })
    }

    pub fn transition(
        &self,
        operation_id: impl Into<String>,
        task_id: impl Into<String>,
        generation: i64,
        from: Vec<String>,
        to: impl Into<String>,
        now_us: i64,
    ) -> Result<i64> {
        let operation_id = operation_id.into();
        let task_id = task_id.into();
        let to = to.into();
        self.call(move |storage| {
            let allowed = from.iter().map(String::as_str).collect::<Vec<_>>();
            storage.transition(&operation_id, &task_id, generation, &allowed, &to, now_us)
        })
    }

    pub fn record_adapter_event(
        &self,
        operation_id: impl Into<String>,
        task_id: impl Into<String>,
        generation: i64,
        kind: impl Into<String>,
        payload: Value,
        now_us: i64,
    ) -> Result<i64> {
        let operation_id = operation_id.into();
        let task_id = task_id.into();
        let kind = kind.into();
        self.call(move |storage| {
            storage.record_adapter_event(
                &operation_id,
                &task_id,
                generation,
                &kind,
                &payload,
                now_us,
            )
        })
    }

    pub fn record_dispatch_phase(
        &self,
        operation_id: impl Into<String>,
        task_id: impl Into<String>,
        generation: i64,
        phase: DispatchPhase,
        process_receipt: Option<String>,
        now_us: i64,
    ) -> Result<bool> {
        let operation_id = operation_id.into();
        let task_id = task_id.into();
        self.call(move |storage| {
            storage.record_dispatch_phase(
                &operation_id,
                &task_id,
                generation,
                phase,
                process_receipt.as_deref(),
                now_us,
            )
        })
    }

    pub fn record_resumable_session(
        &self,
        task_id: impl Into<String>,
        generation: i64,
        provider_session: impl Into<String>,
        capability_digest: impl Into<String>,
        now_us: i64,
    ) -> Result<()> {
        let task_id = task_id.into();
        let provider_session = provider_session.into();
        let capability_digest = capability_digest.into();
        self.call(move |storage| {
            storage.record_resumable_session(
                &task_id,
                generation,
                &provider_session,
                &capability_digest,
                now_us,
            )
        })
    }

    pub fn open_interaction(
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
    ) -> Result<Interaction> {
        let operation_id = operation_id.into();
        let task_id = task_id.into();
        let attempt_id = attempt_id.into();
        let operation_digest = operation_digest.into();
        let policy_digest = policy_digest.into();
        let config_digest = config_digest.into();
        self.call(move |storage| {
            storage.open_interaction(
                &operation_id,
                &task_id,
                &attempt_id,
                generation,
                &operation_digest,
                &policy_digest,
                &config_digest,
                capability_class,
                config_version,
                policy_version,
                expires_at,
                now_us,
            )
        })
    }

    pub fn respond_interaction(
        &self,
        consumer_id: impl Into<String>,
        command_key: impl Into<String>,
        canonical_request_bytes: impl Into<Vec<u8>>,
        interaction_id: impl Into<String>,
        nonce: impl Into<String>,
        expected_generation: i64,
        expected_operation_digest: impl Into<String>,
        expected_policy_digest: impl Into<String>,
        expected_config_digest: impl Into<String>,
        response_kind: InteractionResponseKind,
        canonical_response_bytes: impl Into<Vec<u8>>,
        now_us: i64,
    ) -> Result<bool> {
        let consumer_id = consumer_id.into();
        let command_key = command_key.into();
        let canonical_request_bytes = canonical_request_bytes.into();
        let interaction_id = interaction_id.into();
        let nonce = nonce.into();
        let expected_operation_digest = expected_operation_digest.into();
        let expected_policy_digest = expected_policy_digest.into();
        let expected_config_digest = expected_config_digest.into();
        let canonical_response_bytes = canonical_response_bytes.into();
        self.call(move |storage| {
            storage.respond_interaction(
                &consumer_id,
                &command_key,
                &canonical_request_bytes,
                &interaction_id,
                &nonce,
                expected_generation,
                &expected_operation_digest,
                &expected_policy_digest,
                &expected_config_digest,
                response_kind,
                &canonical_response_bytes,
                now_us,
            )
        })
    }

    /// Returns detached, integrity-verified interaction response evidence.
    pub fn interaction_response(
        &self,
        interaction_id: impl Into<String>,
    ) -> Result<InteractionResponseEvidence> {
        let interaction_id = interaction_id.into();
        self.call(move |storage| storage.interaction_response(&interaction_id))
    }

    pub fn request_cancel(
        &self,
        consumer_id: impl Into<String>,
        command_key: impl Into<String>,
        canonical_request_bytes: impl Into<Vec<u8>>,
        task_id: impl Into<String>,
        now_us: i64,
    ) -> Result<bool> {
        let consumer_id = consumer_id.into();
        let command_key = command_key.into();
        let request_digest = hash(canonical_request_bytes.into());
        let task_id = task_id.into();
        self.call(move |storage| {
            storage.request_cancel(
                &consumer_id,
                &command_key,
                &request_digest,
                &task_id,
                now_us,
            )
        })
    }

    pub fn expire_interaction(
        &self,
        consumer_id: impl Into<String>,
        operation_id: impl Into<String>,
        interaction_id: impl Into<String>,
        generation: i64,
        now_us: i64,
    ) -> Result<ResultDelivery> {
        let consumer_id = consumer_id.into();
        let operation_id = operation_id.into();
        let interaction_id = interaction_id.into();
        self.call(move |storage| {
            storage.expire_interaction(
                &consumer_id,
                &operation_id,
                &interaction_id,
                generation,
                now_us,
            )
        })
    }

    /// Expires a pending preflight interaction and finalizes `CANCELLED`.
    pub fn expire_preflight_interaction(
        &self,
        consumer_id: impl Into<String>,
        operation_id: impl Into<String>,
        interaction_id: impl Into<String>,
        generation: i64,
        now_us: i64,
    ) -> Result<ResultDelivery> {
        let consumer_id = consumer_id.into();
        let operation_id = operation_id.into();
        let interaction_id = interaction_id.into();
        self.call(move |storage| {
            storage.expire_preflight_interaction(
                &consumer_id,
                &operation_id,
                &interaction_id,
                generation,
                now_us,
            )
        })
    }

    pub fn schedule_safe_retry(
        &self,
        operation_id: impl Into<String>,
        task_id: impl Into<String>,
        generation: i64,
        retry_at: i64,
        now_us: i64,
    ) -> Result<i64> {
        let operation_id = operation_id.into();
        let task_id = task_id.into();
        self.call(move |storage| {
            storage.schedule_safe_retry(&operation_id, &task_id, generation, retry_at, now_us)
        })
    }

    pub fn finalize(
        &self,
        consumer_id: impl Into<String>,
        command_key: impl Into<String>,
        canonical_request_bytes: impl Into<Vec<u8>>,
        task_id: impl Into<String>,
        generation: i64,
        terminal_state: impl Into<String>,
        result_digest: impl Into<String>,
        now_us: i64,
    ) -> Result<ResultDelivery> {
        let consumer_id = consumer_id.into();
        let command_key = command_key.into();
        let request_digest = hash(canonical_request_bytes.into());
        let task_id = task_id.into();
        let terminal_state = terminal_state.into();
        let result_digest = result_digest.into();
        self.call(move |storage| {
            storage.finalize(
                &consumer_id,
                &command_key,
                &request_digest,
                &task_id,
                generation,
                &terminal_state,
                &result_digest,
                now_us,
            )
        })
    }

    pub fn review_and_ack(
        &self,
        consumer_id: impl Into<String>,
        command_key: impl Into<String>,
        canonical_request_bytes: impl Into<Vec<u8>>,
        delivery: ResultDelivery,
        verdict: ReviewVerdict,
        diagnosis: Option<String>,
        now_us: i64,
    ) -> Result<bool> {
        let consumer_id = consumer_id.into();
        let command_key = command_key.into();
        let canonical_request_bytes = canonical_request_bytes.into();
        self.call(move |storage| {
            storage.review_and_ack(
                &consumer_id,
                &command_key,
                &canonical_request_bytes,
                &delivery,
                verdict,
                diagnosis.as_deref(),
                now_us,
            )
        })
    }

    pub fn publish_blob(&self, bytes: Vec<u8>, now_us: i64) -> Result<String> {
        self.call(move |storage| storage.publish_blob(&bytes, now_us))
    }

    pub fn register_worktree(
        &self,
        worktree_id: impl Into<String>,
        task_id: impl Into<String>,
        path: impl Into<String>,
        now_us: i64,
    ) -> Result<()> {
        let worktree_id = worktree_id.into();
        let task_id = task_id.into();
        let path = path.into();
        self.call(move |storage| storage.register_worktree(&worktree_id, &task_id, &path, now_us))
    }

    pub fn reference_blob(
        &self,
        owner_kind: impl Into<String>,
        owner_id: impl Into<String>,
        field: impl Into<String>,
        digest: impl Into<String>,
        now_us: i64,
    ) -> Result<()> {
        let owner_kind = owner_kind.into();
        let owner_id = owner_id.into();
        let field = field.into();
        let digest = digest.into();
        self.call(move |storage| {
            storage.reference_blob(&owner_kind, &owner_id, &field, &digest, now_us)
        })
    }

    pub fn current_lease_epoch(&self) -> Result<i64> {
        self.call(|storage| storage.current_lease_epoch())
    }

    pub fn acquire_lease(
        &self,
        lease_id: impl Into<String>,
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
        epoch: i64,
        now_us: i64,
    ) -> Result<()> {
        let lease_id = lease_id.into();
        let resource_kind = resource_kind.into();
        let resource_id = resource_id.into();
        self.call(move |storage| {
            storage.acquire_lease(&lease_id, &resource_kind, &resource_id, epoch, now_us)
        })
    }

    pub fn release_lease(&self, lease_id: impl Into<String>, epoch: i64) -> Result<bool> {
        let lease_id = lease_id.into();
        self.call(move |storage| storage.release_lease(&lease_id, epoch))
    }

    pub fn mark_retention_gc(&self, now_us: i64) -> Result<Vec<GcCandidate>> {
        self.call(move |storage| storage.mark_retention_gc(now_us))
    }

    pub fn prepare_gc_deletion(
        &self,
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Result<GcDeletionPlan> {
        let resource_kind = resource_kind.into();
        let resource_id = resource_id.into();
        self.call(move |storage| storage.prepare_gc_deletion(&resource_kind, &resource_id))
    }

    pub fn finish_gc_deletion(
        &self,
        candidate: GcCandidate,
        success: bool,
        error_digest: Option<String>,
        now_us: i64,
    ) -> Result<()> {
        self.call(move |storage| {
            storage.finish_gc_deletion(&candidate, success, error_digest.as_deref(), now_us)
        })
    }

    pub fn reconcile_nonterminal(
        &self,
        consumer_id: impl Into<String>,
        now_us: i64,
    ) -> Result<Vec<(String, RecoveryDecision)>> {
        let consumer_id = consumer_id.into();
        self.call(move |storage| storage.reconcile_nonterminal(&consumer_id, now_us))
    }

    pub fn latch_emergency(&self, now_us: i64) -> Result<EmergencyState> {
        self.call(move |storage| storage.latch_emergency(now_us))
    }

    pub fn recover_emergency(&self, now_us: i64) -> Result<()> {
        self.call(move |storage| storage.recover_emergency(now_us))
    }

    pub fn create_backup(
        &self,
        binary_version: impl Into<String>,
        now_us: i64,
    ) -> Result<BackupManifest> {
        let binary_version = binary_version.into();
        self.call(move |storage| storage.create_backup(&binary_version, now_us))
    }

    pub fn verify_restore_allowed(&self, manifest: BackupManifest) -> Result<()> {
        self.call(move |storage| storage.verify_restore_allowed(&manifest))
    }

    pub fn checkpoint_passive(&self) -> Result<(i64, i64, i64)> {
        self.call(Storage::checkpoint_passive)
    }
}

fn run(mut storage: Storage, receiver: &mpsc::Receiver<Command>) {
    while let Ok(command) = receiver.recv() {
        match command {
            Command::Execute(operation) => operation(&mut storage),
            Command::Shutdown => return,
        }
    }
}

fn stopped() -> StorageError {
    StorageError::Quarantined("storage writer stopped".into())
}

fn hash(bytes: Vec<u8>) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{reader::ReaderPool, storage::EMPTY_CONFIG_V1_DIGEST};
    use serde_json::Value;
    use std::{fs, io, path::Path, sync::Mutex, time::Duration};

    const OPERATION_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const POLICY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CONFIG_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn canonical(value: &Value) -> Vec<u8> {
        crate::canonicalize(value).unwrap().into_bytes()
    }

    fn text_response_command(
        command_key: &str,
        interaction: &Interaction,
        text: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let response = serde_json::json!({"kind": "text", "text": text});
        let response_bytes = canonical(&response);
        let command = serde_json::json!({
            "version": 1,
            "kind": "command",
            "action": "interaction_response",
            "command_key": command_key,
            "task_id": interaction.task_id,
            "interaction_id": interaction.interaction_id,
            "generation": interaction.generation,
            "operation_digest": OPERATION_DIGEST,
            "policy_digest": POLICY_DIGEST,
            "config_digest": CONFIG_DIGEST,
            "nonce": interaction.nonce,
            "response": response,
        });
        (canonical(&command), response_bytes)
    }

    fn assert_reopened_text_response(
        root: std::path::PathBuf,
        interaction_id: String,
        expected: &[u8],
    ) {
        let reopened = WriterHandle::start_portable(root, "install", 8).unwrap();
        let evidence = reopened.interaction_response(interaction_id).unwrap();
        assert_eq!(evidence.response_kind, InteractionResponseKind::Text);
        assert_eq!(evidence.bytes, expected);
        reopened.shutdown().unwrap();
    }

    #[derive(Default)]
    struct PressureFilesystem {
        used: Mutex<u64>,
        released: Mutex<usize>,
        fail_publish: bool,
    }

    impl DurableFilesystem for PressureFilesystem {
        fn validate_data_root(&self, _root: &Path) -> io::Result<()> {
            Ok(())
        }
        fn storage_mode(&self) -> &'static str {
            "WINDOWS_LOCAL_NTFS_VALIDATED"
        }
        fn create_relative_directories(&self, path: &Path) -> io::Result<()> {
            fs::create_dir_all(path)
        }
        fn allocated_bytes(&self, _root: &Path) -> io::Result<u64> {
            Ok(*self.used.lock().unwrap())
        }
        fn free_bytes(&self, _root: &Path) -> io::Result<u64> {
            Ok(u64::MAX)
        }
        fn create_reserve(&self, _path: &Path, _bytes: u64) -> io::Result<()> {
            Ok(())
        }
        fn release_reserve(&self, _path: &Path) -> io::Result<()> {
            *self.released.lock().unwrap() += 1;
            Ok(())
        }
        fn atomic_publish(&self, staged: &Path, destination: &Path) -> io::Result<()> {
            if self.fail_publish {
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
            fs::rename(staged, destination)
        }
        fn sync_parent(&self, _parent: &Path) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bounded_actor_serializes_duplicate_submissions() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root, "install", 1).unwrap();
        assert!(
            !writer
                .submit("c", "submit", "key", b"canonical".to_vec(), "task", None, 2)
                .unwrap()
                .replayed
        );
        assert!(
            writer
                .submit(
                    "c",
                    "submit",
                    "key",
                    b"canonical".to_vec(),
                    "other",
                    None,
                    3
                )
                .unwrap()
                .replayed
        );
        assert!(writer.is_healthy());
        assert!(writer.checkpoint_passive().is_ok());
        writer.shutdown().unwrap();
        assert!(!writer.is_healthy());
    }

    #[test]
    fn writer_bootstraps_empty_config_for_reopened_reader() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        writer.ensure_empty_config_v1(2_000).unwrap();
        writer.shutdown().unwrap();

        let config = ReaderPool::open(&root)
            .unwrap()
            .empty_config(Duration::from_secs(1))
            .unwrap();
        assert_eq!(config.config_digest, EMPTY_CONFIG_V1_DIGEST);
    }

    #[test]
    fn writer_empty_config_bootstrap_is_idempotent_without_retimestamping() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        writer.ensure_empty_config_v1(2_000).unwrap();
        writer.ensure_empty_config_v1(3_000).unwrap();
        writer.shutdown().unwrap();

        let connection = rusqlite::Connection::open(root.join("mesh.sqlite3")).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT version,config_digest,created_at FROM config_versions",
                    [],
                    |row| Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?
                    )),
                )
                .unwrap(),
            (1, EMPTY_CONFIG_V1_DIGEST.into(), 2_000)
        );
    }

    #[test]
    fn writer_empty_config_bootstrap_quarantines_drift_without_rewriting_rows() {
        let cases = [
            vec![(1, "wrong-digest", 2_000)],
            vec![(2, EMPTY_CONFIG_V1_DIGEST, 2_000)],
            vec![
                (1, EMPTY_CONFIG_V1_DIGEST, 2_000),
                (2, EMPTY_CONFIG_V1_DIGEST, 2_001),
            ],
            vec![(1, EMPTY_CONFIG_V1_DIGEST, -1)],
        ];
        for expected in cases {
            let expected = expected
                .into_iter()
                .map(|(version, digest, created_at)| {
                    (i64::from(version), digest.to_owned(), i64::from(created_at))
                })
                .collect::<Vec<_>>();
            let root = tempfile::tempdir().unwrap().keep();
            let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
            writer.shutdown().unwrap();
            let connection = rusqlite::Connection::open(root.join("mesh.sqlite3")).unwrap();
            for (version, digest, created_at) in &expected {
                connection
                    .execute(
                        "INSERT INTO config_versions(version,config_digest,created_at) VALUES(?1,?2,?3)",
                        rusqlite::params![version, digest, created_at],
                    )
                    .unwrap();
            }
            drop(connection);

            let writer = WriterHandle::start_portable(root.clone(), "install", 2).unwrap();
            assert!(matches!(
                writer.ensure_empty_config_v1(3_000),
                Err(StorageError::Quarantined(_))
            ));
            writer.shutdown().unwrap();

            let connection = rusqlite::Connection::open(root.join("mesh.sqlite3")).unwrap();
            let mut statement = connection
                .prepare(
                    "SELECT version,config_digest,created_at FROM config_versions ORDER BY version",
                )
                .unwrap();
            let actual = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn writer_empty_config_bootstrap_rejects_unsafe_time() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        assert!(matches!(
            writer.ensure_empty_config_v1(-1),
            Err(StorageError::InvalidRequest)
        ));
        writer.shutdown().unwrap();
        let connection = rusqlite::Connection::open(root.join("mesh.sqlite3")).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM config_versions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn shutdown_fences_clone_calls_and_drains_accepted_work() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        let accepted_writer = writer.clone();
        let (entered_send, entered_receive) = mpsc::sync_channel(0);
        let (release_send, release_receive) = mpsc::sync_channel(0);
        let accepted = thread::spawn(move || {
            accepted_writer.call(move |_| {
                entered_send.send(()).unwrap();
                release_receive.recv().unwrap();
                Ok(())
            })
        });
        entered_receive.recv().unwrap();

        let shutdown_writer = writer.clone();
        let shutdown = thread::spawn(move || shutdown_writer.shutdown());
        {
            let mut phase = writer.lifecycle.lock();
            while *phase == WriterPhase::Running {
                phase = writer
                    .lifecycle
                    .changed
                    .wait(phase)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            assert_eq!(*phase, WriterPhase::ShuttingDown);
        }

        assert!(!writer.is_healthy());
        assert!(matches!(
            writer.checkpoint_passive(),
            Err(StorageError::Quarantined(_))
        ));

        let concurrent_writer = writer.clone();
        let concurrent_shutdown = thread::spawn(move || concurrent_writer.shutdown());
        release_send.send(()).unwrap();

        accepted.join().unwrap().unwrap();
        shutdown.join().unwrap().unwrap();
        concurrent_shutdown.join().unwrap().unwrap();
        writer.shutdown().unwrap();

        let reopened = WriterHandle::start_portable(root, "install", 2).unwrap();
        reopened.shutdown().unwrap();
    }

    #[test]
    fn writer_preserves_quota_admission_but_fences_real_disk_full() {
        let root = tempfile::tempdir().unwrap().keep();
        let quota = QuotaPolicy {
            quota_bytes: 1024 * 1024 * 1024,
            reserve_bytes: 64 * 1024 * 1024,
            max_global_concurrency: 3,
        };
        let quota_fs = Arc::new(PressureFilesystem {
            used: Mutex::new(quota.quota_bytes),
            ..PressureFilesystem::default()
        });
        let writer =
            WriterHandle::start(root.clone(), "install", 1, quota_fs.clone(), Some(quota)).unwrap();
        assert!(matches!(
            writer.submit("c", "submit", "k", b"r".to_vec(), "t", None, 2),
            Err(StorageError::QuotaExceeded)
        ));
        assert_eq!(*quota_fs.released.lock().unwrap(), 0);
        writer.shutdown().unwrap();

        let disk_root = tempfile::tempdir().unwrap().keep();
        let disk_fs = Arc::new(PressureFilesystem {
            fail_publish: true,
            ..PressureFilesystem::default()
        });
        let writer =
            WriterHandle::start(disk_root, "install-2", 1, disk_fs.clone(), Some(quota)).unwrap();
        assert!(matches!(
            writer.publish_blob(b"bytes".to_vec(), 2),
            Err(StorageError::StorageEmergency)
        ));
        assert_eq!(*disk_fs.released.lock().unwrap(), 1);
        assert!(matches!(
            writer.submit("c", "submit", "k", b"r".to_vec(), "t", None, 3),
            Err(StorageError::StorageEmergency)
        ));
        writer.shutdown().unwrap();
    }

    #[test]
    fn writer_charges_the_full_canonical_request_before_creating_rows() {
        let quota = QuotaPolicy {
            quota_bytes: 1024 * 1024 * 1024,
            reserve_bytes: 64 * 1024 * 1024,
            max_global_concurrency: 3,
        };
        let body = b"canonical-body".to_vec();
        let declared = u64::try_from(body.len()).unwrap() + 4096;
        let root = tempfile::tempdir().unwrap().keep();
        let admitted = Arc::new(PressureFilesystem {
            used: Mutex::new(quota.quota_bytes - quota.reserve_bytes - declared),
            ..PressureFilesystem::default()
        });
        let writer = WriterHandle::start(root, "admit", 1, admitted, Some(quota)).unwrap();
        assert!(
            writer
                .submit("c", "submit", "k", body.clone(), "task", None, 2)
                .is_ok()
        );
        writer.shutdown().unwrap();

        let root = tempfile::tempdir().unwrap().keep();
        let rejected = Arc::new(PressureFilesystem {
            used: Mutex::new(quota.quota_bytes - quota.reserve_bytes - declared + 1),
            ..PressureFilesystem::default()
        });
        let writer = WriterHandle::start(root.clone(), "reject", 1, rejected, Some(quota)).unwrap();
        assert!(matches!(
            writer.submit("c", "submit", "k", body, "task", None, 2),
            Err(StorageError::QuotaExceeded)
        ));
        writer.shutdown().unwrap();
        let connection = rusqlite::Connection::open(root.join("mesh.sqlite3")).unwrap();
        for table in ["tasks", "command_dedup", "task_requests"] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{table}"
            );
        }
    }

    #[test]
    fn committed_submit_replays_before_quota_admission_but_new_work_is_rejected() {
        let quota = QuotaPolicy {
            quota_bytes: 1024 * 1024 * 1024,
            reserve_bytes: 64 * 1024 * 1024,
            max_global_concurrency: 3,
        };
        let root = tempfile::tempdir().unwrap().keep();
        let filesystem = Arc::new(PressureFilesystem::default());
        let writer =
            WriterHandle::start(root, "install", 1, filesystem.clone(), Some(quota)).unwrap();
        let first = writer
            .submit("c", "submit", "key", b"body".to_vec(), "task", None, 2)
            .unwrap();
        *filesystem.used.lock().unwrap() = quota.quota_bytes;
        let replay = writer
            .submit("c", "submit", "key", b"body".to_vec(), "different", None, 3)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.task_id, first.task_id);
        assert!(matches!(
            writer.submit("c", "submit", "key", b"other".to_vec(), "other", None, 3),
            Err(StorageError::IdempotencyConflict)
        ));
        assert!(matches!(
            writer.submit("c", "submit", "new", b"body".to_vec(), "other", None, 3),
            Err(StorageError::QuotaExceeded)
        ));
        writer.shutdown().unwrap();
    }

    #[test]
    fn writer_persists_interaction_response_evidence_across_reopen_and_replay() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        writer
            .submit("c", "submit", "task-key", b"task".to_vec(), "task", None, 2)
            .unwrap();
        let attempt = writer
            .begin_attempt(
                "c",
                "begin",
                b"begin".to_vec(),
                "task",
                0,
                AttemptSpec::default(),
                3,
            )
            .unwrap();
        let interaction = writer
            .open_interaction(
                "open",
                "task",
                attempt.attempt_id.clone(),
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Input,
                2,
                3,
                100,
                4,
            )
            .unwrap();
        let (response_command, response_bytes) =
            text_response_command("response", &interaction, "exact text");
        assert!(
            !writer
                .respond_interaction(
                    "c",
                    "response",
                    response_command.clone(),
                    interaction.interaction_id.clone(),
                    interaction.nonce.clone(),
                    0,
                    OPERATION_DIGEST,
                    POLICY_DIGEST,
                    CONFIG_DIGEST,
                    InteractionResponseKind::Text,
                    response_bytes.clone(),
                    5,
                )
                .unwrap()
        );
        assert!(
            writer
                .respond_interaction(
                    "c",
                    "response",
                    response_command.clone(),
                    interaction.interaction_id.clone(),
                    interaction.nonce.clone(),
                    0,
                    OPERATION_DIGEST,
                    POLICY_DIGEST,
                    CONFIG_DIGEST,
                    InteractionResponseKind::Text,
                    response_bytes.clone(),
                    6,
                )
                .unwrap()
        );
        assert!(matches!(
            writer.respond_interaction(
                "c",
                "response",
                response_command,
                interaction.interaction_id.clone(),
                interaction.nonce.clone(),
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionResponseKind::Text,
                canonical(&serde_json::json!({"kind": "text", "text": "different text"})),
                7,
            ),
            Err(StorageError::IdempotencyConflict)
        ));
        assert_eq!(
            writer
                .interaction_response(interaction.interaction_id.clone())
                .unwrap()
                .bytes,
            response_bytes
        );
        writer.shutdown().unwrap();
        assert_reopened_text_response(root, interaction.interaction_id, &response_bytes);
    }
}
