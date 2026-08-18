//! Durable `SQLite` and content-addressed blob primitives.
//!
//! This module is deliberately transport-free: callers submit fully validated,
//! canonical request bytes and only this owner mutates task projections.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_arguments,
    // Reconciliation intentionally keeps every recovery decision in one
    // auditable transaction-flow owner.
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{
    AttemptState, DispatchPhase, InteractionCapabilityClass, InteractionResponseKind,
    InteractionState, RecoveryDecision, ReviewVerdict, TaskState,
};
use crate::improvement::{
    CanaryAdmission, CanaryDecision, CandidateCommandResult, CandidateDecision, CandidateProposal,
    EvaluationDecision, ImprovementEngine, ImprovementPolicy, ObservationDecision,
    ObservationInput, RollbackCommandResult,
};

pub(crate) const MESH_SQLITE_APPLICATION_ID: i32 = 0x4d45_5348; // MESH
/// Current durable `SQLite` schema recorded in installation evidence.
pub const CURRENT_DATA_SCHEMA_VERSION: u32 = 7;
const SCHEMA_VERSION: i64 = CURRENT_DATA_SCHEMA_VERSION as i64;
/// The sole M3 configuration admitted before adapter configuration exists.
///
/// Readers and setup import this value rather than carrying parallel literals.
pub const EMPTY_CONFIG_V1_DIGEST: &str =
    "22a01f7ccf852d7b2032c4c2c0f25df516d9f07e81d0107a3b2036055cfff16b";
const MAX_SAFE_TIME_US: i64 = 9_007_199_254_740_991_000;
const MAX_CANONICAL_TASK_REQUEST_BYTES: usize = 1024 * 1024;
/// Canonical interaction responses are exact bounded evidence, not a digest-only
/// hint. Protocol text is limited to 32 Ki Unicode scalar values; canonical JSON
/// may encode each as a six-byte `\\u00xx` escape, plus a fixed object envelope.
/// This deliberately covers every schema-valid response while still bounding a
/// corrupt `SQLite` blob far below the 1 MiB command limit.
const MAX_INTERACTION_RESPONSE_BYTES: usize = 6 * 32 * 1024 + 128;
const MAX_DIAGNOSIS_CHARS: usize = 8192;
const TASK_SUBMISSION_ROW_OVERHEAD_BYTES: u64 = 4096;
const DAY_US: i64 = 86_400_000_000;
const LEASE_TTL_US: i64 = 60_000_000;
const LEASE_HEARTBEAT_US: i64 = 20_000_000;
const GC_BATCH_ROWS: usize = 100;
const GC_BATCH_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage root must be an existing local directory: {0}")]
    InvalidRoot(PathBuf),
    #[error("storage integrity quarantine: {0}")]
    Quarantined(String),
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("task is missing or its generation/state is stale")]
    StaleGeneration,
    #[error("terminal task is immutable")]
    TerminalImmutable,
    #[error("result acknowledgement does not match the durable result tuple")]
    AckMismatch,
    #[error("result was already reviewed differently")]
    AlreadyReviewed,
    #[error("cursor expired; oldest={oldest_available_seq}, last={last_committed_seq}")]
    CursorExpired {
        oldest_available_seq: i64,
        last_committed_seq: i64,
    },
    #[error("blob corruption at {0}")]
    BlobCorruption(String),
    #[error("interaction is stale, expired, or already answered")]
    InteractionConflict,
    #[error("storage mutation is fenced while emergency mode is active")]
    StorageEmergency,
    #[error("storage quota would be exceeded")]
    QuotaExceeded,
    #[error("canonical durable evidence must be nonempty and within its configured bound")]
    InvalidRequest,
    #[error("validated response cannot fit the negotiated output limit")]
    OutputLimitExceeded,
    #[error("reader query deadline exceeded")]
    QueryDeadline,
    #[error("reader pool is saturated")]
    ReaderSaturated,
    #[error("storage writer mailbox is saturated")]
    WriterBackpressure,
    #[error("WAL hard-pressure threshold fences new dispatch")]
    WalPressure,
    #[error("migration checksum or backup manifest mismatch: {0}")]
    MigrationMismatch(String),
    #[error("restore refused after post-upgrade mutation epoch changed")]
    RestoreRefused,
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub task_id: String,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRequest {
    pub task_id: String,
    pub digest: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultDelivery {
    pub task_id: String,
    pub result_id: String,
    pub result_version: i64,
    pub ack_token: String,
    pub terminal_event_seq: i64,
    pub terminal_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPage {
    pub events: Vec<(i64, String, String)>,
    pub last_committed_seq: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub attempt_id: String,
    pub task_id: String,
    pub generation: i64,
    pub ordinal: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptSpec {
    pub effect_profile: String,
    pub isolation_level: String,
    pub retry_class: String,
    pub adapter_instance_id: String,
    pub adapter_version: String,
    pub config_version: i64,
    pub config_digest: String,
    pub worktree_id: Option<String>,
}

impl Default for AttemptSpec {
    fn default() -> Self {
        Self {
            effect_profile: "READ_ONLY".into(),
            isolation_level: "NONE".into(),
            retry_class: "NEVER".into(),
            adapter_instance_id: "unassigned".into(),
            adapter_version: "unknown".into(),
            config_version: 1,
            config_digest: "unset".into(),
            worktree_id: None,
        }
    }
}

/// Authoritative persisted scheduler occupancy, recomputed from `SQLite` rows.
///
/// Only the sole writer mutates the rows this projection derives from. Both
/// the writer's `claim_dispatch_slot` transaction and the reader pool's
/// `occupancy` query use the same predicate (`read_occupancy`), so a stale
/// recomputation can never disagree with an in-flight claim.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Occupancy {
    /// Process-bearing attempts across all adapter instances.
    pub global: u32,
    /// Process-bearing attempts per `adapter_instance_id`.
    pub per_adapter: BTreeMap<String, u32>,
}

impl Occupancy {
    #[must_use]
    pub fn occupied(&self, adapter_instance_id: &str) -> u32 {
        self.per_adapter
            .get(adapter_instance_id)
            .copied()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.global == 0
    }
}

/// Why a durable dispatch claim could not reserve a slot right now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchBlockReason {
    /// The global process-bearing limit is already reached.
    GlobalLimit,
    /// The per-adapter-instance limit for the task's adapter is reached.
    AdapterLimit,
    /// The task is in `RETRY_WAIT` and its persisted timer has not elapsed.
    RetryTimerPending,
    /// The durable task has no adapter instance identity assigned yet, so no
    /// routing decision exists. Only the scheduler plan produces this reason;
    /// `claim_dispatch_slot` always carries a validated identity.
    AdapterUnassigned,
}

impl DispatchBlockReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GlobalLimit => "GLOBAL_LIMIT",
            Self::AdapterLimit => "ADAPTER_LIMIT",
            Self::RetryTimerPending => "RETRY_TIMER_PENDING",
            Self::AdapterUnassigned => "ADAPTER_UNASSIGNED",
        }
    }
}

/// Typed refusal evidence for a claim that could not reserve a slot. The task
/// projection is left untouched; the scheduler may retry the same decision
/// later with a new operation id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchBlocked {
    pub reason: DispatchBlockReason,
    pub global_limit: u32,
    pub global_occupied: u32,
    pub per_adapter_limit: u32,
    pub adapter_occupied: u32,
    pub adapter_instance_id: String,
}

/// Outcome of the single writer-owned dispatch decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    /// Slot reserved: the task transitioned `QUEUED`/`RETRY_WAIT` ->
    /// `PREPARING` with a new attempt in the same transaction as the
    /// occupancy check.
    Dispatched(Attempt),
    /// Limits or the retry timer prevented dispatch; the task remains queued.
    Blocked(DispatchBlocked),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interaction {
    pub interaction_id: String,
    pub task_id: String,
    pub attempt_id: String,
    pub adapter_instance_id: String,
    pub generation: i64,
    pub nonce: String,
    pub capability_class: InteractionCapabilityClass,
    pub config_version: i64,
    pub policy_version: i64,
}

/// Detached, integrity-verified evidence for an answered interaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InteractionResponseEvidence {
    pub interaction_id: String,
    pub consumer_id: String,
    pub response_kind: InteractionResponseKind,
    pub response_digest: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcCandidate {
    pub resource_kind: String,
    pub resource_id: String,
    pub byte_length: u64,
    pub fence_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcDeletionPlan {
    pub candidate: GcCandidate,
    pub exact_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyState {
    Normal,
    Latched,
    ReserveReleased,
}

#[derive(Clone, Copy, Debug)]
pub struct QuotaPolicy {
    pub quota_bytes: u64,
    pub reserve_bytes: u64,
    pub max_global_concurrency: u32,
}

impl QuotaPolicy {
    pub fn validate(self) -> Result<Self> {
        let minimum = (64 * 1024 * 1024_u64)
            .max(8 * 1024 * 1024_u64 * u64::from(self.max_global_concurrency));
        let maximum = (512 * 1024 * 1024_u64).min(self.quota_bytes / 10);
        if self.quota_bytes == 0 || self.reserve_bytes < minimum || self.reserve_bytes > maximum {
            return Err(StorageError::QuotaExceeded);
        }
        Ok(self)
    }
}

/// Platform-independent durable filesystem contract. `mesh-win32` supplies the
/// stronger ACL, fixed-local-NTFS, write-through rename and directory flush gate.
pub(crate) trait DurableFilesystem: Send + Sync {
    fn validate_data_root(&self, root: &Path) -> std::io::Result<()>;
    fn storage_mode(&self) -> &'static str;
    fn create_relative_directories(&self, path: &Path) -> std::io::Result<()>;
    fn allocated_bytes(&self, root: &Path) -> std::io::Result<u64>;
    fn free_bytes(&self, root: &Path) -> std::io::Result<u64>;
    fn create_reserve(&self, path: &Path, bytes: u64) -> std::io::Result<()>;
    fn release_reserve(&self, path: &Path) -> std::io::Result<()>;
    fn atomic_publish(&self, staged: &Path, destination: &Path) -> std::io::Result<()>;
    fn sync_parent(&self, parent: &Path) -> std::io::Result<()>;
}

#[derive(Debug, Default)]
#[cfg(test)]
pub(crate) struct PortableFilesystem;

#[cfg(test)]
impl DurableFilesystem for PortableFilesystem {
    fn validate_data_root(&self, _root: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn storage_mode(&self) -> &'static str {
        "PORTABLE_TEST"
    }
    fn create_relative_directories(&self, path: &Path) -> std::io::Result<()> {
        fs::create_dir_all(path)
    }
    fn allocated_bytes(&self, root: &Path) -> std::io::Result<u64> {
        directory_bytes(root)
    }

    fn free_bytes(&self, _root: &Path) -> std::io::Result<u64> {
        // Platform-specific physical free-space measurement is an explicit M3
        // gate. Admission still enforces the application-owned quota here.
        Ok(u64::MAX)
    }

    fn create_reserve(&self, path: &Path, bytes: u64) -> std::io::Result<()> {
        let staged = path.with_extension("reserve.tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)?;
        let zeros = vec![0_u8; 1024 * 1024].into_boxed_slice();
        let mut remaining = bytes;
        while remaining > 0 {
            let count = usize::try_from(remaining.min(zeros.len() as u64)).unwrap_or(zeros.len());
            file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        file.sync_all()?;
        fs::rename(&staged, path)?;
        self.sync_parent(path.parent().unwrap_or_else(|| Path::new(".")))
    }

    fn release_reserve(&self, path: &Path) -> std::io::Result<()> {
        if path.exists() {
            fs::remove_file(path)?;
            self.sync_parent(path.parent().unwrap_or_else(|| Path::new(".")))?;
        }
        Ok(())
    }

    fn atomic_publish(&self, staged: &Path, destination: &Path) -> std::io::Result<()> {
        if destination.exists() {
            fs::remove_file(destination)?;
        }
        fs::rename(staged, destination)
    }

    fn sync_parent(&self, parent: &Path) -> std::io::Result<()> {
        let _ = parent;
        // Directory metadata flushing is not portable through std. The injected
        // Windows implementation is the release gate for FlushFileBuffers.
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupManifest {
    pub backup_id: String,
    pub snapshot_file: String,
    pub source_schema: i64,
    pub database_sha256: String,
    pub binary_version: String,
    pub install_id: String,
    pub mutation_epoch: i64,
}

type InteractionRow = (
    String,
    i64,
    String,
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
);
type AckRow = (
    String,
    String,
    i64,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type InteractionResponseMetadataRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
);
type ReviewReplayRow = (
    String,
    String,
    i64,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type LoadedInteractionRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

struct ParsedInteractionResponseCommand {
    command_key: String,
    task_id: String,
    interaction_id: String,
    generation: i64,
    operation_digest: String,
    policy_digest: String,
    config_digest: String,
    nonce: String,
    response_kind: InteractionResponseKind,
    response_bytes: Vec<u8>,
}

struct ParsedReviewAckCommand {
    command_key: String,
    task_id: String,
    result_id: String,
    result_version: i64,
    ack_token: String,
    verdict: ReviewVerdict,
    diagnosis: Option<String>,
}

struct ImprovementCommandCommit {
    consumer_id: String,
    method: &'static str,
    command_key: String,
    request_digest: String,
    response_locator: String,
    response_json: String,
    response_digest: String,
}

/// Single-writer storage owner. It must be kept behind the daemon writer actor;
/// it intentionally does not expose SQL callbacks.
pub(crate) struct Storage {
    root: PathBuf,
    conn: Connection,
    filesystem: Arc<dyn DurableFilesystem>,
    quota: Option<QuotaPolicy>,
    emergency: EmergencyState,
}

impl Storage {
    pub(crate) fn is_storage_pressure(error: &StorageError) -> bool {
        match error {
            StorageError::Sql(error) => matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DiskFull)
            ),
            StorageError::Io(error) => {
                matches!(error.kind(), std::io::ErrorKind::StorageFull)
                    || matches!(error.raw_os_error(), Some(28 | 112))
            }
            _ => false,
        }
    }

    /// Best-effort fail-closed pressure path used by the single writer actor.
    /// It never invents a terminal result because generic I/O failure has no
    /// provider-effect evidence.
    pub(crate) fn latch_detected_storage_pressure(&mut self) {
        let now_us = self
            .conn
            .query_row(
                "SELECT updated_at FROM storage_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        // `latch_emergency` sets the in-memory fence before trying to release
        // the reserve. If release or its audit commit also fails, restart sees
        // a missing reserve when release succeeded; otherwise this actor stays
        // fenced. No-space conditions cannot always persist extra evidence.
        let _ = self.latch_emergency(now_us);
    }
    #[cfg(test)]
    pub(crate) fn open(root: impl AsRef<Path>, install_id: &str, now_us: i64) -> Result<Self> {
        Self::open_with_filesystem(root, install_id, now_us, Arc::new(PortableFilesystem), None)
    }

    pub(crate) fn open_with_filesystem(
        root: impl AsRef<Path>,
        install_id: &str,
        now_us: i64,
        filesystem: Arc<dyn DurableFilesystem>,
        quota: Option<QuotaPolicy>,
    ) -> Result<Self> {
        let root = validate_data_root(root.as_ref())?;
        filesystem.validate_data_root(&root)?;
        filesystem.create_relative_directories(&root.join("blobs/.staging"))?;
        filesystem.create_relative_directories(&root.join("blobs/sha256"))?;
        filesystem.create_relative_directories(&root.join("backups"))?;
        let database_path = root.join("mesh.sqlite3");
        let database_existed = database_path.is_file();
        let mut conn = Connection::open(&database_path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        if database_existed {
            let application_id: i64 =
                conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
            if application_id != i64::from(MESH_SQLITE_APPLICATION_ID) {
                return Err(StorageError::Quarantined(
                    "foreign SQLite application id".into(),
                ));
            }
        } else {
            conn.pragma_update(None, "application_id", MESH_SQLITE_APPLICATION_ID)?;
        }
        migrate(&mut conn, install_id, now_us)?;
        verify_migration_checksums(&conn)?;
        conn.execute(
            "UPDATE storage_meta SET storage_mode=?1 WHERE singleton=1",
            [filesystem.storage_mode()],
        )?;
        conn.execute(
            "UPDATE storage_meta SET lease_epoch=lease_epoch+1,updated_at=?1 WHERE singleton=1",
            [now_us],
        )?;
        let quota = quota.map(QuotaPolicy::validate).transpose()?;
        let emergency = if let Some(policy) = quota {
            let reserve = root.join("critical.reserve");
            let stored_state: String = conn.query_row(
                "SELECT emergency_state FROM storage_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            if reserve.is_file()
                && reserve.metadata()?.len() == policy.reserve_bytes
                && stored_state == "NORMAL"
            {
                EmergencyState::Normal
            } else if !database_existed && !reserve.exists() {
                filesystem.create_reserve(&reserve, policy.reserve_bytes)?;
                EmergencyState::Normal
            } else {
                EmergencyState::Latched
            }
        } else {
            EmergencyState::Normal
        };
        let mut storage = Self {
            root,
            conn,
            filesystem,
            quota,
            emergency,
        };
        storage.startup_integrity_check(now_us)?;
        // SQLite creates the database and WAL/SHM sidecars by path. Re-run the
        // injected platform validation before publishing a usable Storage so
        // every newly inherited descendant is checked as well as preexisting
        // startup content.
        storage.filesystem.validate_data_root(&storage.root)?;
        Ok(storage)
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Atomically stores the request, command tombstone, task projection, and initial event.
    ///
    /// `priority` (higher dispatches earlier) and `adapter_instance_id` are
    /// persisted scheduler inputs. An empty/missing adapter instance means
    /// routing has not assigned one yet; the first `claim_dispatch_slot` may
    /// assign it, after which the identity is immutable for that task.
    pub(crate) fn submit_with_request(
        &mut self,
        consumer_id: &str,
        method: &str,
        command_key: &str,
        canonical_request: &[u8],
        task_id: &str,
        retry_of_task_id: Option<&str>,
        priority: u8,
        adapter_instance_id: Option<&str>,
        now_us: i64,
    ) -> Result<Submission> {
        if canonical_request.is_empty()
            || canonical_request.len() > MAX_CANONICAL_TASK_REQUEST_BYTES
        {
            return Err(StorageError::InvalidRequest);
        }
        let declared = u64::try_from(canonical_request.len())
            .map_err(|_| StorageError::InvalidRequest)?
            .checked_add(TASK_SUBMISSION_ROW_OVERHEAD_BYTES)
            .ok_or(StorageError::QuotaExceeded)?;
        let request_digest = format!("{:x}", Sha256::digest(canonical_request));
        self.submit_inner(
            consumer_id,
            method,
            command_key,
            &request_digest,
            Some(canonical_request),
            declared,
            task_id,
            retry_of_task_id,
            priority,
            adapter_instance_id,
            now_us,
        )
    }

    /// Installs the immutable M3 empty configuration when, and only when, no
    /// configuration evidence has ever been committed. Existing evidence is
    /// never repaired, upgraded, or deleted by this bootstrap path.
    pub(crate) fn ensure_empty_config_v1(&mut self, now_us: i64) -> Result<()> {
        if !(0..=MAX_SAFE_TIME_US).contains(&now_us) {
            return Err(StorageError::InvalidRequest);
        }
        self.ensure_mutation_allowed(false)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 =
            tx.query_row("SELECT COUNT(*) FROM config_versions", [], |row| row.get(0))?;
        match count {
            0 => {
                tx.execute(
                    "INSERT INTO config_versions(version,config_digest,created_at) VALUES(1,?1,?2)",
                    params![EMPTY_CONFIG_V1_DIGEST, now_us],
                )?;
                bump_mutation_epoch(&tx, now_us)?;
            }
            1 => {
                let (version, digest, created_at): (i64, String, i64) = tx.query_row(
                    "SELECT version,config_digest,created_at FROM config_versions",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                if version != 1
                    || digest != EMPTY_CONFIG_V1_DIGEST
                    || !(0..=MAX_SAFE_TIME_US).contains(&created_at)
                {
                    return Err(StorageError::Quarantined(
                        "invalid empty config v1 evidence".into(),
                    ));
                }
            }
            _ => {
                return Err(StorageError::Quarantined(
                    "ambiguous empty config v1 evidence".into(),
                ));
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn ensure_improvement_engine(
        &mut self,
        policy: ImprovementPolicy,
        now_us: i64,
    ) -> Result<ImprovementEngine> {
        validate_improvement_time(now_us)?;
        if let Some(engine) = load_improvement_engine(&self.conn)? {
            if engine.policy() != &policy {
                return Err(StorageError::IdempotencyConflict);
            }
            return Ok(engine);
        }
        self.ensure_mutation_allowed(false)?;
        let engine = ImprovementEngine::new(policy);
        self.persist_improvement_engine(&engine, "INITIALIZED", now_us, None)?;
        Ok(engine)
    }

    pub(crate) fn ensure_default_improvement_engine(&mut self, now_us: i64) -> Result<()> {
        validate_improvement_time(now_us)?;
        if load_improvement_engine(&self.conn)?.is_none() {
            self.ensure_mutation_allowed(false)?;
            self.persist_improvement_engine(
                &ImprovementEngine::new(ImprovementPolicy::default()),
                "INITIALIZED",
                now_us,
                None,
            )?;
        }
        Ok(())
    }

    pub(crate) fn set_improvement_enabled(&mut self, enabled: bool, now_us: i64) -> Result<()> {
        self.mutate_improvement("FEATURE_FLAG_CHANGED", now_us, |engine| {
            engine.set_enabled(enabled);
        })
    }

    pub(crate) fn improvement_observe(
        &mut self,
        input: &ObservationInput,
    ) -> Result<ObservationDecision> {
        let now_us = input.reviewed_at_us;
        self.mutate_improvement("OBSERVATION_RECORDED", now_us, |engine| {
            engine.observe(input.clone())
        })
    }

    pub(crate) fn improvement_open_case(
        &mut self,
        input: &ObservationInput,
        now_us: i64,
    ) -> Result<Option<String>> {
        self.mutate_improvement("CASE_OPENED", now_us, |engine| {
            engine.open_eligible_case(input, now_us)
        })
    }

    pub(crate) fn improvement_propose_candidate(
        &mut self,
        proposal: CandidateProposal,
        now_us: i64,
    ) -> Result<Option<CandidateDecision>> {
        self.mutate_improvement("CANDIDATE_PROPOSED", now_us, |engine| {
            engine.propose_candidate(proposal, now_us)
        })
    }

    pub(crate) fn improvement_assign_canary(
        &mut self,
        case_id: &str,
        admission: CanaryAdmission,
    ) -> Result<CanaryDecision> {
        let now_us = admission.now_us;
        self.mutate_improvement("CANARY_ASSIGNED", now_us, |engine| {
            engine.assign_canary(case_id, admission)
        })
    }

    pub(crate) fn improvement_evaluate(
        &mut self,
        case_id: &str,
        now_us: i64,
    ) -> Result<EvaluationDecision> {
        self.mutate_improvement("CANARY_EVALUATED", now_us, |engine| {
            engine.evaluate(case_id, now_us)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn improvement_propose_command(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        canonical_command: &[u8],
        proposal: CandidateProposal,
        now_us: i64,
    ) -> Result<CandidateCommandResult> {
        validate_improvement_propose_command(canonical_command, command_key, &proposal)?;
        let response_locator = proposal.case_id.clone();
        let case_id = response_locator.clone();
        self.improvement_command(
            consumer_id,
            "improvement_propose",
            command_key,
            canonical_command,
            &response_locator,
            "CANDIDATE_PROPOSED",
            now_us,
            move |engine| {
                let decision = engine
                    .propose_candidate(proposal, now_us)
                    .ok_or(StorageError::InvalidRequest)?;
                let case = engine
                    .case_snapshot(&case_id)
                    .ok_or(StorageError::InvalidRequest)?;
                let candidate_config_version = engine.candidate_config_version(&case_id);
                Ok(CandidateCommandResult {
                    decision,
                    case,
                    candidate_config_version,
                })
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn improvement_rollback_command(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        canonical_command: &[u8],
        case_id: &str,
        target_config_version: i64,
        now_us: i64,
    ) -> Result<RollbackCommandResult> {
        validate_improvement_rollback_command(
            canonical_command,
            command_key,
            case_id,
            target_config_version,
        )?;
        let owned_case_id = case_id.to_owned();
        self.improvement_command(
            consumer_id,
            "improvement_rollback",
            command_key,
            canonical_command,
            case_id,
            "ROLLBACK_REQUESTED",
            now_us,
            move |engine| {
                let decision =
                    engine.request_rollback(&owned_case_id, target_config_version, now_us);
                if matches!(decision, EvaluationDecision::WaitingForSamples { .. }) {
                    Err(StorageError::InvalidRequest)
                } else {
                    let case = engine
                        .case_snapshot(&owned_case_id)
                        .ok_or(StorageError::InvalidRequest)?;
                    let candidate_config_version = engine.candidate_config_version(&owned_case_id);
                    Ok(RollbackCommandResult {
                        decision,
                        case,
                        candidate_config_version,
                    })
                }
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn improvement_command<T>(
        &mut self,
        consumer_id: &str,
        method: &'static str,
        command_key: &str,
        canonical_command: &[u8],
        response_locator: &str,
        audit_action: &str,
        now_us: i64,
        mutation: impl FnOnce(&mut ImprovementEngine) -> Result<T>,
    ) -> Result<T>
    where
        T: Serialize + DeserializeOwned,
    {
        validate_improvement_time(now_us)?;
        if canonical_command.is_empty()
            || canonical_command.len() > MAX_CANONICAL_TASK_REQUEST_BYTES
        {
            return Err(StorageError::InvalidRequest);
        }
        let request_digest = hash_bytes(canonical_command);
        if let Some(replayed) = improvement_command_replay::<T>(
            &self.conn,
            consumer_id,
            method,
            command_key,
            &request_digest,
            response_locator,
        )? {
            return Ok(replayed);
        }
        self.ensure_mutation_allowed(false)?;
        let mut engine = load_improvement_engine(&self.conn)?.ok_or_else(|| {
            StorageError::Quarantined("improvement engine is not initialized".into())
        })?;
        let before = engine
            .snapshot_json()
            .map_err(|_| StorageError::Quarantined("invalid improvement snapshot".into()))?;
        let result = mutation(&mut engine)?;
        let response_json = serde_json::to_string(&result)
            .map_err(|_| StorageError::Quarantined("invalid improvement response".into()))?;
        let command = ImprovementCommandCommit {
            consumer_id: consumer_id.into(),
            method,
            command_key: command_key.into(),
            request_digest,
            response_locator: response_locator.into(),
            response_digest: hash_bytes(response_json.as_bytes()),
            response_json,
        };
        let after = engine
            .snapshot_json()
            .map_err(|_| StorageError::Quarantined("invalid improvement snapshot".into()))?;
        if before == after {
            // Feature-disabled/no-op decisions still need a durable command
            // tombstone for replay, but must not advance the improvement
            // snapshot or audit revision.
            self.persist_improvement_command_only(&engine, &command, now_us)?;
        } else {
            self.persist_improvement_engine(&engine, audit_action, now_us, Some(&command))?;
        }
        Ok(result)
    }

    fn persist_improvement_command_only(
        &mut self,
        engine: &ImprovementEngine,
        command: &ImprovementCommandCommit,
        now_us: i64,
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO command_dedup(consumer_id,method,command_key,request_digest,response_locator,response_json,response_digest,committed_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                command.consumer_id,
                command.method,
                command.command_key,
                command.request_digest,
                command.response_locator,
                command.response_json,
                command.response_digest,
                now_us
            ],
        )?;
        verify_improvement_projection(&tx, engine)?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(())
    }

    fn mutate_improvement<T>(
        &mut self,
        action: &str,
        now_us: i64,
        mutation: impl FnOnce(&mut ImprovementEngine) -> T,
    ) -> Result<T> {
        validate_improvement_time(now_us)?;
        self.ensure_mutation_allowed(false)?;
        let mut engine = load_improvement_engine(&self.conn)?.ok_or_else(|| {
            StorageError::Quarantined("improvement engine is not initialized".into())
        })?;
        let before = engine
            .snapshot_json()
            .map_err(|_| StorageError::Quarantined("invalid improvement snapshot".into()))?;
        let result = mutation(&mut engine);
        let after = engine
            .snapshot_json()
            .map_err(|_| StorageError::Quarantined("invalid improvement snapshot".into()))?;
        if before != after {
            self.persist_improvement_engine(&engine, action, now_us, None)?;
        }
        Ok(result)
    }

    fn persist_improvement_engine(
        &mut self,
        engine: &ImprovementEngine,
        action: &str,
        now_us: i64,
        command: Option<&ImprovementCommandCommit>,
    ) -> Result<()> {
        let state_json = engine
            .snapshot_json()
            .map_err(|_| StorageError::Quarantined("invalid improvement snapshot".into()))?;
        let state_digest = hash_bytes(state_json.as_bytes());
        let projection = engine.durable_projection();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision: i64 = tx
            .query_row(
                "SELECT revision FROM improvement_engine_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0_i64)
            .checked_add(1)
            .ok_or_else(|| StorageError::Quarantined("improvement revision overflow".into()))?;
        // The final snapshot enforces one active case. Clear old active rows
        // inside this transaction first so replacing an expired case cannot
        // trip the partial unique index based on row-update order.
        tx.execute(
            "UPDATE improvement_cases SET state='ROLLED_BACK' WHERE state IN ('OBSERVING','CANARY')",
            [],
        )?;
        for case in projection.cases {
            tx.execute(
                "INSERT INTO improvement_cases(case_id,component,state,created_at,candidate_id,parent_config_version,canary_started_at,rollback_count)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(case_id) DO UPDATE SET state=excluded.state,candidate_id=excluded.candidate_id,
                   canary_started_at=excluded.canary_started_at,rollback_count=excluded.rollback_count",
                params![
                    case.case_id,
                    case.component,
                    case.state.as_str(),
                    case.created_at_us,
                    case.candidate_id,
                    case.parent_config_version,
                    case.canary_started_at_us,
                    case.rollback_count
                ],
            )?;
        }
        for candidate in projection.candidates {
            let value_json = candidate.value.to_string();
            tx.execute(
                "INSERT OR IGNORE INTO improvement_candidates(candidate_id,case_id,component,knob,value_json,parent_config_version,rollback_config_version,candidate_config_version,candidate_config_digest,fixture_gate_passed,fixture_hard_failure,created_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    candidate.candidate_id,
                    candidate.case_id,
                    candidate.component,
                    candidate.knob.as_str(),
                    value_json,
                    candidate.parent_config_version,
                    candidate.rollback_config_version,
                    candidate.candidate_config_version,
                    candidate.candidate_config_digest,
                    candidate.fixture_gate_passed,
                    candidate.fixture_hard_failure,
                    now_us
                ],
            )?;
            let stored_candidate: (String, String, String, i64, i64, i64, String, bool, bool) = tx
                .query_row(
                    "SELECT case_id,component,knob,parent_config_version,rollback_config_version,
                            candidate_config_version,candidate_config_digest,fixture_gate_passed,fixture_hard_failure
                     FROM improvement_candidates WHERE candidate_id=?1 AND value_json=?2",
                    params![candidate.candidate_id, value_json],
                    |row| {
                        Ok((
                            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                            row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    StorageError::Quarantined("immutable improvement candidate drift".into())
                })?;
            if stored_candidate
                != (
                    candidate.case_id.clone(),
                    candidate.component.clone(),
                    candidate.knob.as_str().into(),
                    candidate.parent_config_version,
                    candidate.rollback_config_version,
                    candidate.candidate_config_version,
                    candidate.candidate_config_digest.clone(),
                    candidate.fixture_gate_passed,
                    candidate.fixture_hard_failure,
                )
            {
                return Err(StorageError::Quarantined(
                    "immutable improvement candidate drift".into(),
                ));
            }
            tx.execute(
                "INSERT OR IGNORE INTO improvement_config_versions(version,digest,component,parent_version,rollback_version,candidate_id,created_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    candidate.candidate_config_version,
                    candidate.candidate_config_digest,
                    candidate.component,
                    candidate.parent_config_version,
                    candidate.rollback_config_version,
                    candidate.candidate_id,
                    now_us
                ],
            )?;
            let stored_config: Option<(String, String, i64, i64, String)> = tx
                .query_row(
                    "SELECT digest,component,parent_version,rollback_version,candidate_id
                     FROM improvement_config_versions WHERE version=?1",
                    [candidate.candidate_config_version],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?;
            if stored_config
                != Some((
                    candidate.candidate_config_digest,
                    candidate.component,
                    candidate.parent_config_version,
                    candidate.rollback_config_version,
                    candidate.candidate_id,
                ))
            {
                return Err(StorageError::Quarantined(
                    "immutable improvement config drift".into(),
                ));
            }
        }
        for assignment in projection.assignments {
            tx.execute(
                "INSERT OR IGNORE INTO canary_assignments(task_id,case_id,candidate,config_version,config_digest,assigned_at)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    assignment.task_id,
                    assignment.case_id,
                    assignment.candidate,
                    assignment.config_version,
                    assignment.config_digest,
                    now_us
                ],
            )?;
            let stored_assignment: Option<(String, bool, i64, String)> = tx
                .query_row(
                    "SELECT case_id,candidate,config_version,config_digest FROM canary_assignments WHERE task_id=?1",
                    [&assignment.task_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            if stored_assignment
                != Some((
                    assignment.case_id,
                    assignment.candidate,
                    assignment.config_version,
                    assignment.config_digest,
                ))
            {
                return Err(StorageError::Quarantined(
                    "immutable canary assignment drift".into(),
                ));
            }
        }
        for (component, version) in projection.active_config_versions {
            tx.execute(
                "INSERT INTO improvement_active_configs(component,config_version,updated_at) VALUES(?1,?2,?3)
                 ON CONFLICT(component) DO UPDATE SET config_version=excluded.config_version,updated_at=excluded.updated_at",
                params![component, version, now_us],
            )?;
        }
        tx.execute(
            "INSERT INTO improvement_engine_state(singleton,revision,state_json,state_digest,created_at,updated_at)
             VALUES(1,?1,?2,?3,?4,?4)
             ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,state_json=excluded.state_json,
               state_digest=excluded.state_digest,updated_at=excluded.updated_at",
            params![revision, state_json, state_digest, now_us],
        )?;
        tx.execute(
            "INSERT INTO improvement_audit(revision,action,state_digest,created_at) VALUES(?1,?2,?3,?4)",
            params![revision, action, state_digest, now_us],
        )?;
        if let Some(command) = command {
            tx.execute(
                "INSERT INTO command_dedup(consumer_id,method,command_key,request_digest,response_locator,response_json,response_digest,committed_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    command.consumer_id,
                    command.method,
                    command.command_key,
                    command.request_digest,
                    command.response_locator,
                    command.response_json,
                    command.response_digest,
                    now_us
                ],
            )?;
        }
        verify_improvement_projection(&tx, engine)?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(())
    }

    /// Test-only legacy helper. Production writes must use `submit_with_request`.
    #[cfg(test)]
    pub(crate) fn submit(
        &mut self,
        consumer_id: &str,
        method: &str,
        command_key: &str,
        request_digest: &str,
        task_id: &str,
        retry_of_task_id: Option<&str>,
        now_us: i64,
    ) -> Result<Submission> {
        self.submit_inner(
            consumer_id,
            method,
            command_key,
            request_digest,
            None,
            TASK_SUBMISSION_ROW_OVERHEAD_BYTES,
            task_id,
            retry_of_task_id,
            0,
            None,
            now_us,
        )
    }

    fn submit_inner(
        &mut self,
        consumer_id: &str,
        method: &str,
        command_key: &str,
        request_digest: &str,
        canonical_request: Option<&[u8]>,
        declared_maximum: u64,
        task_id: &str,
        retry_of_task_id: Option<&str>,
        priority: u8,
        adapter_instance_id: Option<&str>,
        now_us: i64,
    ) -> Result<Submission> {
        let stored_adapter = match adapter_instance_id {
            None | Some("") => String::new(),
            Some(value) => {
                if crate::scheduler::AdapterInstanceId::parse(value).is_err() {
                    return Err(StorageError::InvalidRequest);
                }
                value.to_owned()
            }
        };
        // The sole writer owns this transaction, so a committed dedup row is
        // stable while resolved. Replays/conflicts allocate no durable bytes.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored, response)) = tx.query_row(
            "SELECT request_digest,response_locator FROM command_dedup WHERE consumer_id=?1 AND method=?2 AND command_key=?3",
            params![consumer_id, method, command_key], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ).optional()? {
            if stored != request_digest { return Err(StorageError::IdempotencyConflict); }
            if let Some(bytes) = canonical_request {
                verify_task_request_tx(&tx, &response, request_digest, bytes)?;
            }
            tx.commit()?;
            return Ok(Submission { task_id: response, replayed: true });
        }
        tx.commit()?;
        // Only genuinely new work is subject to pressure admission.
        self.ensure_mutation_allowed(false)?;
        self.ensure_capacity(declared_maximum)?;
        // The daemon actor is the sole SQLite writer, so the committed dedup
        // miss remains valid across this filesystem admission check.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx
            .query_row(
                "SELECT 1 FROM tasks WHERE task_id=?1",
                [task_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(StorageError::IdempotencyConflict);
        }
        if let Some(parent) = retry_of_task_id {
            let terminal: Option<String> = tx
                .query_row("SELECT state FROM tasks WHERE task_id=?1 UNION ALL SELECT terminal_state FROM task_tombstones WHERE task_id=?1 LIMIT 1", [parent], |r| r.get(0))
                .optional()?;
            if !terminal.as_deref().is_some_and(is_terminal) {
                return Err(StorageError::TerminalImmutable);
            }
        }
        tx.execute("INSERT INTO tasks(task_id,request_digest,retry_of_task_id,state,generation,last_event_seq,projection_event_seq,priority,adapter_instance_id,created_at,updated_at) VALUES(?1,?2,?3,'QUEUED',0,0,0,?4,?5,?6,?6)", params![task_id, request_digest, retry_of_task_id, i64::from(priority), stored_adapter, now_us])?;
        if let Some(bytes) = canonical_request {
            tx.execute("INSERT INTO task_requests(task_id,request_digest,request_bytes,byte_length,created_at) VALUES(?1,?2,?3,?4,?5)", params![task_id, request_digest, bytes, i64::try_from(bytes.len()).map_err(|_| StorageError::QuotaExceeded)?, now_us])?;
        }
        append_event(
            &tx,
            task_id,
            0,
            "state_changed",
            &state_event_payload("QUEUED"),
            now_us,
        )?;
        tx.execute("INSERT INTO command_dedup(consumer_id,method,command_key,request_digest,response_locator,committed_at) VALUES(?1,?2,?3,?4,?5,?6)", params![consumer_id,method,command_key,request_digest,task_id,now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(Submission {
            task_id: task_id.into(),
            replayed: false,
        })
    }

    pub(crate) fn begin_attempt_with_spec(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        request_digest: &str,
        task_id: &str,
        generation: i64,
        spec: &AttemptSpec,
        now_us: i64,
    ) -> Result<Attempt> {
        self.ensure_mutation_allowed(false)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_attempt_assignment(&tx, task_id, spec)?;
        if let Some(locator) = command_replay(
            &tx,
            consumer_id,
            "begin_attempt",
            command_key,
            request_digest,
        )? {
            let attempt = load_attempt(&tx, &locator)?;
            verify_existing_attempt_config(&tx, &attempt.attempt_id, spec)?;
            tx.commit()?;
            return Ok(attempt);
        }
        let (state, stored_generation, ordinal): (String, i64, i64) = tx.query_row(
            "SELECT state,generation,COALESCE((SELECT MAX(a.ordinal) FROM attempts a WHERE a.task_id=t.task_id),0)+1 FROM tasks t WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if stored_generation != generation || !matches!(state.as_str(), "QUEUED" | "RETRY_WAIT") {
            return Err(StorageError::StaleGeneration);
        }
        let attempt = Attempt {
            attempt_id: Uuid::new_v4().to_string(),
            task_id: task_id.to_owned(),
            generation,
            ordinal,
        };
        tx.execute(
            "INSERT INTO attempts(attempt_id,task_id,generation,ordinal,state,dispatch_phase,effect_profile,isolation_level,retry_class,adapter_instance_id,adapter_version,config_version,config_digest,worktree_id,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15)",
            params![
                attempt.attempt_id,
                task_id,
                generation,
                ordinal,
                AttemptState::Preparing.as_str(),
                DispatchPhase::PreDispatch.as_str(),
                spec.effect_profile,
                spec.isolation_level,
                spec.retry_class,
                spec.adapter_instance_id,
                spec.adapter_version,
                spec.config_version,
                spec.config_digest,
                spec.worktree_id,
                now_us
            ],
        )?;
        tx.execute(
            "UPDATE tasks SET state='PREPARING',updated_at=?1 WHERE task_id=?2 AND generation=?3",
            params![now_us, task_id, generation],
        )?;
        append_event(
            &tx,
            task_id,
            generation,
            "attempt_started",
            &serde_json::json!({"attempt_id": attempt.attempt_id, "ordinal": ordinal}).to_string(),
            now_us,
        )?;
        store_command(
            &tx,
            consumer_id,
            "begin_attempt",
            command_key,
            request_digest,
            &attempt.attempt_id,
            now_us,
        )?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(attempt)
    }

    #[cfg(test)]
    pub(crate) fn begin_attempt(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        request_digest: &str,
        task_id: &str,
        generation: i64,
        now_us: i64,
    ) -> Result<Attempt> {
        self.begin_attempt_with_spec(
            consumer_id,
            command_key,
            request_digest,
            task_id,
            generation,
            &AttemptSpec::default(),
            now_us,
        )
    }

    /// The single writer-owned dispatch decision.
    ///
    /// Within one `IMMEDIATE` transaction this fences `(task_id, generation,
    /// state)` against `QUEUED` or an elapsed `RETRY_WAIT`, recomputes
    /// occupancy from the same transaction, reserves a slot only when both
    /// limits allow, and transitions the task to `PREPARING` with a new
    /// attempt. A refusal leaves the durable task projection untouched; the
    /// scheduler may retry the decision later with a new operation id.
    ///
    /// The operation is internally idempotent: replaying the same
    /// `operation_id` with an identical decision digest returns the original
    /// attempt without re-running the occupancy check. A task's
    /// `adapter_instance_id` is immutable once assigned: a claim carrying a
    /// different adapter identity is fenced with `StaleGeneration`.
    pub(crate) fn claim_dispatch_slot(
        &mut self,
        operation_id: &str,
        task_id: &str,
        generation: i64,
        spec: &AttemptSpec,
        limits: crate::scheduler::SchedulerLimits,
        now_us: i64,
    ) -> Result<DispatchOutcome> {
        if !(0..=MAX_SAFE_TIME_US).contains(&now_us) || operation_id.is_empty() {
            return Err(StorageError::InvalidRequest);
        }
        if limits.validate().is_err() {
            return Err(StorageError::InvalidRequest);
        }
        if crate::scheduler::AdapterInstanceId::parse(&spec.adapter_instance_id).is_err() {
            return Err(StorageError::InvalidRequest);
        }
        // Dispatch admission is fenced by storage emergency and WAL pressure,
        // exactly like any other reservation of new work.
        self.ensure_mutation_allowed(false)?;
        let operation_digest = digest_fields(&[
            task_id,
            &generation.to_string(),
            &spec.adapter_instance_id,
            &spec.adapter_version,
            &spec.config_version.to_string(),
            &spec.config_digest,
            &spec.effect_profile,
            &spec.isolation_level,
            &spec.retry_class,
            spec.worktree_id.as_deref().unwrap_or(""),
        ]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_attempt_assignment(&tx, task_id, spec)?;
        if let Some(locator) = internal_operation_replay(&tx, operation_id, &operation_digest)? {
            let attempt = load_attempt(&tx, &locator)?;
            verify_existing_attempt_config(&tx, &attempt.attempt_id, spec)?;
            tx.commit()?;
            return Ok(DispatchOutcome::Dispatched(attempt));
        }
        let row: Option<(String, i64, Option<i64>, String)> = tx
            .query_row(
                "SELECT state,generation,retry_at,adapter_instance_id FROM tasks WHERE task_id=?1",
                [task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((state, stored_generation, retry_at, stored_adapter)) = row else {
            return Err(StorageError::StaleGeneration);
        };
        if stored_generation != generation {
            return Err(StorageError::StaleGeneration);
        }
        let ready = match state.as_str() {
            "QUEUED" => true,
            "RETRY_WAIT" => retry_at.is_none_or(|at| at <= now_us),
            _ => false,
        };
        if !ready {
            if state == TaskState::RetryWait.as_str() {
                tx.commit()?;
                return Ok(DispatchOutcome::Blocked(DispatchBlocked {
                    reason: DispatchBlockReason::RetryTimerPending,
                    global_limit: limits.global,
                    global_occupied: 0,
                    per_adapter_limit: limits.per_adapter,
                    adapter_occupied: 0,
                    adapter_instance_id: spec.adapter_instance_id.clone(),
                }));
            }
            return Err(StorageError::StaleGeneration);
        }
        if !stored_adapter.is_empty() && stored_adapter != spec.adapter_instance_id {
            // No cross-provider fallback: a task's adapter instance identity
            // cannot change between attempts.
            return Err(StorageError::StaleGeneration);
        }
        let occupancy = read_occupancy(&tx)?;
        if occupancy.global >= limits.global {
            tx.commit()?;
            return Ok(DispatchOutcome::Blocked(DispatchBlocked {
                reason: DispatchBlockReason::GlobalLimit,
                global_limit: limits.global,
                global_occupied: occupancy.global,
                per_adapter_limit: limits.per_adapter,
                adapter_occupied: occupancy.occupied(&spec.adapter_instance_id),
                adapter_instance_id: spec.adapter_instance_id.clone(),
            }));
        }
        let adapter_occupied = occupancy.occupied(&spec.adapter_instance_id);
        if adapter_occupied >= limits.per_adapter {
            tx.commit()?;
            return Ok(DispatchOutcome::Blocked(DispatchBlocked {
                reason: DispatchBlockReason::AdapterLimit,
                global_limit: limits.global,
                global_occupied: occupancy.global,
                per_adapter_limit: limits.per_adapter,
                adapter_occupied,
                adapter_instance_id: spec.adapter_instance_id.clone(),
            }));
        }
        let ordinal: i64 = tx.query_row(
            "SELECT COALESCE((SELECT MAX(a.ordinal) FROM attempts a WHERE a.task_id=t.task_id),0)+1 FROM tasks t WHERE task_id=?1",
            [task_id],
            |row| row.get(0),
        )?;
        let attempt = Attempt {
            attempt_id: Uuid::new_v4().to_string(),
            task_id: task_id.to_owned(),
            generation,
            ordinal,
        };
        tx.execute(
            "INSERT INTO attempts(attempt_id,task_id,generation,ordinal,state,dispatch_phase,effect_profile,isolation_level,retry_class,adapter_instance_id,adapter_version,config_version,config_digest,worktree_id,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15)",
            params![
                attempt.attempt_id,
                task_id,
                generation,
                ordinal,
                AttemptState::Preparing.as_str(),
                DispatchPhase::PreDispatch.as_str(),
                spec.effect_profile,
                spec.isolation_level,
                spec.retry_class,
                spec.adapter_instance_id,
                spec.adapter_version,
                spec.config_version,
                spec.config_digest,
                spec.worktree_id,
                now_us
            ],
        )?;
        tx.execute(
            "UPDATE tasks SET state='PREPARING',adapter_instance_id=?1,updated_at=?2 WHERE task_id=?3 AND generation=?4 AND state IN ('QUEUED','RETRY_WAIT')",
            params![spec.adapter_instance_id, now_us, task_id, generation],
        )?;
        append_event(
            &tx,
            task_id,
            generation,
            "attempt_started",
            &serde_json::json!({"attempt_id": attempt.attempt_id, "ordinal": ordinal}).to_string(),
            now_us,
        )?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'claim_dispatch_slot',?5,?6)", params![operation_id, operation_digest, task_id, generation, attempt.attempt_id, now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(DispatchOutcome::Dispatched(attempt))
    }

    /// Re-reserves occupancy for an already-answered preflight approval.
    ///
    /// Preflight `WAITING_APPROVAL` does not hold a slot. `respond_interaction`
    /// then moves the task to `RUNNING`, which occupies again. This method
    /// re-checks the same occupancy predicate as [`Self::claim_dispatch_slot`]
    /// against that existing attempt and refuses to spawn when the wait window
    /// let other work fill both limits. It never creates a new attempt.
    pub(crate) fn reclaim_preflight_dispatch_slot(
        &mut self,
        operation_id: &str,
        task_id: &str,
        generation: i64,
        spec: &AttemptSpec,
        limits: crate::scheduler::SchedulerLimits,
        now_us: i64,
    ) -> Result<DispatchOutcome> {
        if !(0..=MAX_SAFE_TIME_US).contains(&now_us) || operation_id.is_empty() {
            return Err(StorageError::InvalidRequest);
        }
        if limits.validate().is_err() {
            return Err(StorageError::InvalidRequest);
        }
        if crate::scheduler::AdapterInstanceId::parse(&spec.adapter_instance_id).is_err() {
            return Err(StorageError::InvalidRequest);
        }
        self.ensure_mutation_allowed(false)?;
        let operation_digest = digest_fields(&[
            task_id,
            &generation.to_string(),
            &spec.adapter_instance_id,
            &spec.adapter_version,
            &spec.config_version.to_string(),
            &spec.config_digest,
            spec.worktree_id.as_deref().unwrap_or(""),
            "reclaim_preflight",
        ]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_attempt_assignment(&tx, task_id, spec)?;
        if let Some(locator) = internal_operation_replay(&tx, operation_id, &operation_digest)? {
            let attempt = load_attempt(&tx, &locator)?;
            verify_existing_attempt_config(&tx, &attempt.attempt_id, spec)?;
            tx.commit()?;
            return Ok(DispatchOutcome::Dispatched(attempt));
        }
        let row: Option<ReclaimAttemptRow> = tx
            .query_row(
                "SELECT t.state,t.generation,a.attempt_id,a.dispatch_phase,a.adapter_instance_id,
                        a.adapter_version,a.config_version,a.config_digest
                 FROM tasks t JOIN attempts a ON a.task_id=t.task_id AND a.generation=t.generation
                 WHERE t.task_id=?1",
                [task_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            state,
            stored_generation,
            attempt_id,
            phase,
            stored_adapter,
            stored_adapter_version,
            stored_config_version,
            stored_config_digest,
        )) = row
        else {
            return Err(StorageError::StaleGeneration);
        };
        if stored_generation != generation
            || !matches!(state.as_str(), "RUNNING" | "WAITING_APPROVAL")
            || stored_adapter != spec.adapter_instance_id
            || stored_adapter_version != spec.adapter_version
            || stored_config_version != spec.config_version
            || stored_config_digest != spec.config_digest
            || !matches!(phase.as_str(), "PRE_DISPATCH" | "SPAWN_PREPARED")
        {
            return Err(StorageError::StaleGeneration);
        }
        let approved: Option<String> = tx
            .query_row(
                "SELECT i.interaction_id FROM pending_interactions i
                 JOIN interaction_responses r ON r.interaction_id=i.interaction_id
                 WHERE i.task_id=?1 AND i.generation=?2 AND i.state='ANSWERED'
                   AND r.response_kind='approve'
                 ORDER BY i.updated_at DESC, i.interaction_id LIMIT 1",
                params![task_id, generation],
                |row| row.get(0),
            )
            .optional()?;
        if approved.is_none() {
            return Err(StorageError::StaleGeneration);
        }
        let occupancy = read_occupancy(&tx)?;
        let self_occupies = state == TaskState::Running.as_str();
        let adapter_occupied = occupancy.occupied(&spec.adapter_instance_id);
        let global_blocked = if self_occupies {
            occupancy.global > limits.global
        } else {
            occupancy.global >= limits.global
        };
        let adapter_blocked = if self_occupies {
            adapter_occupied > limits.per_adapter
        } else {
            adapter_occupied >= limits.per_adapter
        };
        if global_blocked || adapter_blocked {
            if self_occupies {
                // `respond_interaction` already moved the task to RUNNING, which
                // occupies. Roll back to preflight WAITING_APPROVAL so a refused
                // reclaim cannot leak a slot or exceed the durable limits.
                tx.execute(
                    "UPDATE tasks SET state='WAITING_APPROVAL',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='RUNNING'",
                    params![now_us, task_id, generation],
                )?;
                tx.execute(
                    "UPDATE attempts SET state='WAITING_APPROVAL',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='RUNNING'",
                    params![now_us, task_id, generation],
                )?;
                append_event(
                    &tx,
                    task_id,
                    generation,
                    "state_changed",
                    &state_event_payload(TaskState::WaitingApproval.as_str()),
                    now_us,
                )?;
                bump_mutation_epoch(&tx, now_us)?;
            }
            tx.commit()?;
            return Ok(DispatchOutcome::Blocked(DispatchBlocked {
                reason: if global_blocked {
                    DispatchBlockReason::GlobalLimit
                } else {
                    DispatchBlockReason::AdapterLimit
                },
                global_limit: limits.global,
                global_occupied: occupancy.global,
                per_adapter_limit: limits.per_adapter,
                adapter_occupied,
                adapter_instance_id: spec.adapter_instance_id.clone(),
            }));
        }
        if !self_occupies {
            tx.execute(
                "UPDATE tasks SET state='RUNNING',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='WAITING_APPROVAL'",
                params![now_us, task_id, generation],
            )?;
            tx.execute(
                "UPDATE attempts SET state='RUNNING',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='WAITING_APPROVAL'",
                params![now_us, task_id, generation],
            )?;
            append_event(
                &tx,
                task_id,
                generation,
                "state_changed",
                &state_event_payload(TaskState::Running.as_str()),
                now_us,
            )?;
        }
        let attempt = load_attempt(&tx, &attempt_id)?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'reclaim_preflight_slot',?5,?6)", params![operation_id, operation_digest, task_id, generation, attempt.attempt_id, now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(DispatchOutcome::Dispatched(attempt))
    }

    pub(crate) fn record_dispatch_phase(
        &mut self,
        operation_id: &str,
        task_id: &str,
        generation: i64,
        phase: DispatchPhase,
        process_receipt: Option<&str>,
        now_us: i64,
    ) -> Result<bool> {
        self.ensure_mutation_allowed(true)?;
        let operation_digest = digest_fields(&[
            task_id,
            &generation.to_string(),
            phase.as_str(),
            process_receipt.unwrap_or(""),
        ]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if internal_operation_replay(&tx, operation_id, &operation_digest)?.is_some() {
            tx.commit()?;
            return Ok(true);
        }
        let stored_phase: String = tx
            .query_row(
                "SELECT a.dispatch_phase FROM attempts a JOIN tasks t ON t.task_id=a.task_id WHERE a.task_id=?1 AND a.generation=?2 AND t.generation=?2 AND t.state IN ('PREPARING','RUNNING')",
                params![task_id, generation],
                |row| row.get(0),
            )
            .map_err(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    StorageError::StaleGeneration
                } else {
                    error.into()
                }
            })?;
        let current_phase = stored_phase
            .parse::<DispatchPhase>()
            .map_err(|_| StorageError::Quarantined("unknown persisted dispatch phase".into()))?;
        if !current_phase.can_advance_to(phase) {
            return Err(StorageError::StaleGeneration);
        }
        let changed = tx.execute(
            "UPDATE attempts SET dispatch_phase=?1,process_receipt=COALESCE(?2,process_receipt),state=CASE WHEN ?1 IN ('PROCESS_STARTED','PROVIDER_OBSERVED') THEN 'RUNNING' ELSE state END,updated_at=?3 WHERE task_id=?4 AND generation=?5 AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION') AND EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=attempts.task_id AND t.generation=?5 AND t.state IN ('PREPARING','RUNNING'))",
            params![phase.as_str(), process_receipt, now_us, task_id, generation],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleGeneration);
        }
        if matches!(
            phase,
            DispatchPhase::ProcessStarted | DispatchPhase::ProviderObserved
        ) {
            tx.execute("UPDATE tasks SET state='RUNNING',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='PREPARING'", params![now_us, task_id, generation])?;
        }
        append_event(
            &tx,
            task_id,
            generation,
            "dispatch_phase",
            &serde_json::json!({"phase": phase.as_str()}).to_string(),
            now_us,
        )?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'dispatch_phase','',?5)", params![operation_id, operation_digest, task_id, generation, now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(false)
    }

    /// Persists one normalized adapter event. This is the live observation
    /// path: dashboard SSE and `wait_task` read only these durable rows.
    pub(crate) fn record_adapter_event(
        &mut self,
        operation_id: &str,
        task_id: &str,
        generation: i64,
        kind: &str,
        payload: &Value,
        now_us: i64,
    ) -> Result<i64> {
        if !matches!(
            kind,
            "text_delta" | "warning" | "protocol_error" | "usage" | "tool_proposal"
        ) {
            return Err(StorageError::InvalidRequest);
        }
        if !payload.is_object() {
            return Err(StorageError::InvalidRequest);
        }
        self.ensure_mutation_allowed(true)?;
        let payload_text = payload.to_string();
        let operation_digest =
            digest_fields(&[task_id, &generation.to_string(), kind, &payload_text]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) = internal_operation_replay(&tx, operation_id, &operation_digest)? {
            tx.commit()?;
            return locator
                .parse::<i64>()
                .map_err(|_| StorageError::Quarantined("adapter event replay locator".into()));
        }
        let exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM tasks WHERE task_id=?1 AND generation=?2 AND state IN ('PREPARING','RUNNING','WAITING_APPROVAL','CANCEL_REQUESTED','FINALIZING')",
            params![task_id, generation],
            |row| row.get(0),
        )?;
        if exists != 1 {
            return Err(StorageError::StaleGeneration);
        }
        let seq = append_event(&tx, task_id, generation, kind, &payload_text, now_us)?;
        tx.execute(
            "INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'adapter_event',?5,?6)",
            params![operation_id, operation_digest, task_id, generation, seq.to_string(), now_us],
        )?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(seq)
    }

    /// Persists evidence produced by an adapter capability probe. Recovery is
    /// deliberately fail-closed unless this binding survives alongside the
    /// provider session and process receipt.
    pub(crate) fn record_resumable_session(
        &mut self,
        task_id: &str,
        generation: i64,
        provider_session: &str,
        capability_digest: &str,
        now_us: i64,
    ) -> Result<()> {
        self.ensure_mutation_allowed(true)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (adapter_id, adapter_version, config_digest, receipt, phase):
            (String, String, String, Option<String>, String) = tx.query_row(
            "SELECT adapter_instance_id,adapter_version,config_digest,process_receipt,dispatch_phase FROM attempts WHERE task_id=?1 AND generation=?2",
            params![task_id, generation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
        if receipt.is_none()
            || phase != DispatchPhase::ProviderObserved.as_str()
            || provider_session.is_empty()
            || capability_digest.is_empty()
        {
            return Err(StorageError::StaleGeneration);
        }
        let proof = digest_fields(&[
            &adapter_id,
            &adapter_version,
            &config_digest,
            capability_digest,
        ]);
        let changed = tx.execute(
            "UPDATE attempts SET provider_session=?1,resumable_capability_digest=?2,resume_proof_digest=?3,updated_at=?4 WHERE task_id=?5 AND generation=?6 AND state='RUNNING'",
            params![provider_session, capability_digest, proof, now_us, task_id, generation],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleGeneration);
        }
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn expire_interaction(
        &mut self,
        consumer_id: &str,
        operation_id: &str,
        interaction_id: &str,
        generation: i64,
        now_us: i64,
    ) -> Result<ResultDelivery> {
        self.ensure_mutation_allowed(true)?;
        let operation_digest = digest_fields(&[interaction_id, &generation.to_string()]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) = internal_operation_replay(&tx, operation_id, &operation_digest)? {
            let task_id: String = tx.query_row(
                "SELECT task_id FROM internal_operations WHERE operation_id=?1",
                [operation_id],
                |row| row.get(0),
            )?;
            tx.commit()?;
            if locator != "pending-result" {
                let delivery_tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let delivery = load_delivery(&delivery_tx, consumer_id, &locator)?;
                delivery_tx.commit()?;
                return Ok(delivery);
            }
            let request_digest = digest_fields(&[interaction_id, "expired-result"]);
            let delivery = self.finalize(
                consumer_id,
                &format!("interaction-expired:{interaction_id}"),
                &request_digest,
                &task_id,
                generation,
                TaskState::NeedsAttention.as_str(),
                &digest_fields(&["interaction-timeout", interaction_id]),
                now_us,
            )?;
            self.conn.execute("UPDATE internal_operations SET response_locator=?1 WHERE operation_id=?2 AND response_locator='pending-result'", params![delivery.result_id, operation_id])?;
            return Ok(delivery);
        }
        let task_id: String = tx.query_row(
            "SELECT i.task_id FROM pending_interactions i JOIN tasks t ON t.task_id=i.task_id WHERE i.interaction_id=?1 AND i.generation=?2 AND i.state='PENDING' AND i.expires_at<=?3 AND t.generation=?2 AND t.state='WAITING_APPROVAL'",
            params![interaction_id, generation, now_us],
            |row| row.get(0),
        ).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { StorageError::InteractionConflict } else { error.into() })?;
        append_event(
            &tx,
            &task_id,
            generation,
            "interaction_decided",
            &interaction_decided_event_payload(interaction_id, "EXPIRED", None),
            now_us,
        )?;
        tx.execute(
            "UPDATE pending_interactions SET state='EXPIRED',updated_at=?1 WHERE interaction_id=?2",
            params![now_us, interaction_id],
        )?;
        tx.execute("UPDATE attempts SET state='FINALIZING',updated_at=?1 WHERE task_id=?2 AND generation=?3", params![now_us, task_id, generation])?;
        tx.execute(
            "UPDATE tasks SET state='FINALIZING',updated_at=?1 WHERE task_id=?2 AND generation=?3",
            params![now_us, task_id, generation],
        )?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'interaction_expired','pending-result',?5)", params![operation_id, operation_digest, task_id, generation, now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        let request_digest = digest_fields(&[interaction_id, "expired-result"]);
        let delivery = self.finalize(
            consumer_id,
            &format!("interaction-expired:{interaction_id}"),
            &request_digest,
            &task_id,
            generation,
            TaskState::NeedsAttention.as_str(),
            &digest_fields(&["interaction-timeout", interaction_id]),
            now_us,
        )?;
        self.conn.execute("UPDATE internal_operations SET response_locator=?1 WHERE operation_id=?2 AND response_locator='pending-result'", params![delivery.result_id, operation_id])?;
        Ok(delivery)
    }

    /// Expires a still-pending preflight interaction and cancels the task.
    ///
    /// [`Self::expire_interaction`] stays the runtime/uncertain path and still
    /// finalizes `NEEDS_ATTENTION`. This method is only legal while the attempt
    /// is retry-safe (`PRE_DISPATCH` / `SPAWN_PREPARED`) so no process existed
    /// that could have observed the wait.
    pub(crate) fn expire_preflight_interaction(
        &mut self,
        consumer_id: &str,
        operation_id: &str,
        interaction_id: &str,
        generation: i64,
        now_us: i64,
    ) -> Result<ResultDelivery> {
        self.ensure_mutation_allowed(true)?;
        let operation_digest =
            digest_fields(&[interaction_id, &generation.to_string(), "preflight"]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) = internal_operation_replay(&tx, operation_id, &operation_digest)? {
            let task_id: String = tx.query_row(
                "SELECT task_id FROM internal_operations WHERE operation_id=?1",
                [operation_id],
                |row| row.get(0),
            )?;
            tx.commit()?;
            if locator != "pending-result" {
                let delivery_tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let delivery = load_delivery(&delivery_tx, consumer_id, &locator)?;
                delivery_tx.commit()?;
                return Ok(delivery);
            }
            let request_digest = digest_fields(&[interaction_id, "preflight-expired-result"]);
            let delivery = self.finalize(
                consumer_id,
                &format!("interaction-preflight-expired:{interaction_id}"),
                &request_digest,
                &task_id,
                generation,
                TaskState::Cancelled.as_str(),
                &digest_fields(&["interaction-preflight-timeout", interaction_id]),
                now_us,
            )?;
            self.conn.execute("UPDATE internal_operations SET response_locator=?1 WHERE operation_id=?2 AND response_locator='pending-result'", params![delivery.result_id, operation_id])?;
            return Ok(delivery);
        }
        let task_id: String = tx
            .query_row(
                "SELECT i.task_id FROM pending_interactions i
             JOIN tasks t ON t.task_id=i.task_id
             JOIN attempts a ON a.task_id=i.task_id AND a.generation=i.generation
             WHERE i.interaction_id=?1 AND i.generation=?2 AND i.state='PENDING'
               AND i.expires_at<=?3 AND t.generation=?2 AND t.state='WAITING_APPROVAL'
               AND a.dispatch_phase IN ('PRE_DISPATCH','SPAWN_PREPARED')",
                params![interaction_id, generation, now_us],
                |row| row.get(0),
            )
            .map_err(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    StorageError::InteractionConflict
                } else {
                    error.into()
                }
            })?;
        append_event(
            &tx,
            &task_id,
            generation,
            "interaction_decided",
            &interaction_decided_event_payload(interaction_id, "EXPIRED", None),
            now_us,
        )?;
        tx.execute(
            "UPDATE pending_interactions SET state='EXPIRED',updated_at=?1 WHERE interaction_id=?2",
            params![now_us, interaction_id],
        )?;
        tx.execute("UPDATE attempts SET state='FINALIZING',updated_at=?1 WHERE task_id=?2 AND generation=?3", params![now_us, task_id, generation])?;
        tx.execute(
            "UPDATE tasks SET state='FINALIZING',updated_at=?1 WHERE task_id=?2 AND generation=?3",
            params![now_us, task_id, generation],
        )?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'interaction_preflight_expired','pending-result',?5)", params![operation_id, operation_digest, task_id, generation, now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        let request_digest = digest_fields(&[interaction_id, "preflight-expired-result"]);
        let delivery = self.finalize(
            consumer_id,
            &format!("interaction-preflight-expired:{interaction_id}"),
            &request_digest,
            &task_id,
            generation,
            TaskState::Cancelled.as_str(),
            &digest_fields(&["interaction-preflight-timeout", interaction_id]),
            now_us,
        )?;
        self.conn.execute("UPDATE internal_operations SET response_locator=?1 WHERE operation_id=?2 AND response_locator='pending-result'", params![delivery.result_id, operation_id])?;
        Ok(delivery)
    }

    pub(crate) fn open_interaction(
        &mut self,
        operation_id: &str,
        task_id: &str,
        attempt_id: &str,
        generation: i64,
        operation_digest: &str,
        policy_digest: &str,
        config_digest: &str,
        capability_class: InteractionCapabilityClass,
        config_version: i64,
        policy_version: i64,
        expires_at: i64,
        now_us: i64,
    ) -> Result<Interaction> {
        self.ensure_mutation_allowed(true)?;
        if !is_lower_sha256(operation_digest)
            || !is_lower_sha256(policy_digest)
            || !is_lower_sha256(config_digest)
            || config_version <= 0
            || policy_version <= 0
        {
            return Err(StorageError::InvalidRequest);
        }
        let internal_digest = digest_fields(&[
            task_id,
            attempt_id,
            &generation.to_string(),
            operation_digest,
            policy_digest,
            config_digest,
            capability_class.as_str(),
            &config_version.to_string(),
            &policy_version.to_string(),
            &expires_at.to_string(),
        ]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) = internal_operation_replay(&tx, operation_id, &internal_digest)? {
            let interaction = load_interaction(&tx, &locator)?;
            tx.commit()?;
            return Ok(interaction);
        }
        let adapter_instance_id: Option<String> = tx.query_row(
            "SELECT a.adapter_instance_id FROM attempts a JOIN tasks t ON t.task_id=a.task_id WHERE a.attempt_id=?1 AND a.task_id=?2 AND a.generation=?3 AND t.generation=?3 AND t.state IN ('PREPARING','RUNNING')",
            params![attempt_id, task_id, generation],
            |row| row.get(0),
        ).optional()?;
        let Some(adapter_instance_id) = adapter_instance_id else {
            return Err(StorageError::StaleGeneration);
        };
        if adapter_instance_id.is_empty() {
            return Err(StorageError::Quarantined(
                "interaction attempt has no adapter instance id".into(),
            ));
        }
        let interaction = Interaction {
            interaction_id: Uuid::new_v4().to_string(),
            task_id: task_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            adapter_instance_id,
            generation,
            nonce: random_token(),
            capability_class,
            config_version,
            policy_version,
        };
        tx.execute("INSERT INTO pending_interactions(interaction_id,task_id,attempt_id,generation,operation_digest,policy_digest,config_digest,capability_class,config_version,policy_version,nonce,expires_at,state,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14)", params![interaction.interaction_id, task_id, attempt_id, generation, operation_digest, policy_digest, config_digest, capability_class.as_str(), config_version, policy_version, interaction.nonce, expires_at, InteractionState::Pending.as_str(), now_us])?;
        tx.execute("UPDATE tasks SET state='WAITING_APPROVAL',updated_at=?1 WHERE task_id=?2 AND generation=?3", params![now_us, task_id, generation])?;
        tx.execute(
            "UPDATE attempts SET state='WAITING_APPROVAL',updated_at=?1 WHERE attempt_id=?2",
            params![now_us, attempt_id],
        )?;
        append_event(
            &tx,
            task_id,
            generation,
            "interaction_requested",
            &interaction_requested_event_payload(&interaction.interaction_id),
            now_us,
        )?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'open_interaction',?5,?6)", params![operation_id, internal_digest, task_id, generation, interaction.interaction_id, now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(interaction)
    }

    pub(crate) fn respond_interaction(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        canonical_command_bytes: &[u8],
        interaction_id: &str,
        nonce: &str,
        expected_generation: i64,
        expected_operation_digest: &str,
        expected_policy_digest: &str,
        expected_config_digest: &str,
        response_kind: InteractionResponseKind,
        canonical_response_bytes: &[u8],
        now_us: i64,
    ) -> Result<bool> {
        self.ensure_mutation_allowed(true)?;
        let parsed_command = parse_interaction_response_command(canonical_command_bytes)?;
        let parsed_response_kind = parse_canonical_interaction_response(canonical_response_bytes)?;
        if parsed_command.command_key != command_key
            || parsed_command.task_id.is_empty()
            || parsed_command.interaction_id != interaction_id
            || parsed_command.generation != expected_generation
            || parsed_command.operation_digest != expected_operation_digest
            || parsed_command.policy_digest != expected_policy_digest
            || parsed_command.config_digest != expected_config_digest
            || parsed_command.nonce != nonce
            || parsed_command.response_kind != response_kind
            || parsed_command.response_bytes != canonical_response_bytes
            || parsed_response_kind != response_kind
        {
            return Err(StorageError::IdempotencyConflict);
        }
        let request_digest = hash_bytes(canonical_command_bytes);
        let response_digest = hash_bytes(canonical_response_bytes);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) = command_replay(
            &tx,
            consumer_id,
            "interaction_response",
            command_key,
            &request_digest,
        )? {
            verify_interaction_response_replay_tx(&tx, &locator, consumer_id, &parsed_command)?;
            tx.commit()?;
            return Ok(true);
        }
        let row: Option<InteractionRow> = tx.query_row(
            "SELECT task_id,generation,nonce,operation_digest,policy_digest,config_digest,expires_at,state,capability_class,config_version,policy_version FROM pending_interactions WHERE interaction_id=?1",
            [interaction_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?)),
        ).optional()?;
        let Some((
            task_id,
            generation,
            stored_nonce,
            operation_digest,
            policy_digest,
            config_digest,
            expires_at,
            state,
            capability_class,
            config_version,
            policy_version,
        )) = row
        else {
            return Err(StorageError::InteractionConflict);
        };
        let (Some(capability_class), Some(config_version), Some(policy_version)) =
            (capability_class, config_version, policy_version)
        else {
            return Err(StorageError::Quarantined(format!(
                "interaction has incomplete v4 metadata: {interaction_id}"
            )));
        };
        if capability_class
            .parse::<InteractionCapabilityClass>()
            .is_err()
            || config_version <= 0
            || policy_version <= 0
        {
            return Err(StorageError::Quarantined(format!(
                "interaction has invalid v4 metadata: {interaction_id}"
            )));
        }
        if parsed_command.task_id != task_id
            || state != InteractionState::Pending.as_str()
            || expires_at <= now_us
            || generation != expected_generation
            || !constant_time_eq(stored_nonce.as_bytes(), nonce.as_bytes())
            || !constant_time_eq(
                operation_digest.as_bytes(),
                expected_operation_digest.as_bytes(),
            )
            || !constant_time_eq(policy_digest.as_bytes(), expected_policy_digest.as_bytes())
            || !constant_time_eq(config_digest.as_bytes(), expected_config_digest.as_bytes())
        {
            return Err(StorageError::InteractionConflict);
        }
        tx.execute("UPDATE pending_interactions SET state='ANSWERED',updated_at=?1 WHERE interaction_id=?2 AND state='PENDING'", params![now_us, interaction_id])?;
        tx.execute("INSERT INTO interaction_responses(interaction_id,consumer_id,decision_digest,response_kind,response_bytes,byte_length,response_digest,committed_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![interaction_id, consumer_id, response_digest, response_kind.as_str(), canonical_response_bytes, i64::try_from(canonical_response_bytes.len()).map_err(|_| StorageError::InvalidRequest)?, response_digest, now_us])?;
        tx.execute("UPDATE tasks SET state='RUNNING',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='WAITING_APPROVAL'", params![now_us, task_id, generation])?;
        tx.execute("UPDATE attempts SET state='RUNNING',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='WAITING_APPROVAL'", params![now_us, task_id, generation])?;
        append_event(
            &tx,
            &task_id,
            generation,
            "interaction_decided",
            &interaction_decided_event_payload(
                interaction_id,
                response_kind.event_status(),
                Some(response_kind),
            ),
            now_us,
        )?;
        store_command(
            &tx,
            consumer_id,
            "interaction_response",
            command_key,
            &request_digest,
            interaction_id,
            now_us,
        )?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(false)
    }

    pub(crate) fn request_cancel(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        request_digest: &str,
        task_id: &str,
        now_us: i64,
    ) -> Result<bool> {
        self.ensure_mutation_allowed(true)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if command_replay(&tx, consumer_id, "cancel", command_key, request_digest)?.is_some() {
            tx.commit()?;
            return Ok(true);
        }
        let (state, generation): (String, i64) = tx.query_row(
            "SELECT state,generation FROM tasks WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let current = state
            .parse::<TaskState>()
            .map_err(|_| StorageError::Quarantined("unknown task state".into()))?;
        if !current.is_terminal() && current != TaskState::CancelRequested {
            if !current.allows(TaskState::CancelRequested) {
                return Err(StorageError::StaleGeneration);
            }
            let mut statement = tx.prepare(
                "SELECT interaction_id FROM pending_interactions
                 WHERE task_id=?1 AND generation=?2 AND state='PENDING' ORDER BY interaction_id",
            )?;
            let pending = statement
                .query_map(params![task_id, generation], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            drop(statement);
            // The cancellation decisions precede the task state event in the
            // same transaction, so replay never has to invent what happened to
            // a one-shot interaction when a provider is cancelled.
            for interaction_id in pending {
                append_event(
                    &tx,
                    task_id,
                    generation,
                    "interaction_decided",
                    &interaction_decided_event_payload(&interaction_id, "CANCELLED", None),
                    now_us,
                )?;
            }
            tx.execute("UPDATE tasks SET state='CANCEL_REQUESTED',cancel_requested_at=?1,updated_at=?1 WHERE task_id=?2 AND generation=?3", params![now_us, task_id, generation])?;
            tx.execute("UPDATE attempts SET state='CANCEL_REQUESTED',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')", params![now_us, task_id, generation])?;
            tx.execute("UPDATE pending_interactions SET state='CANCELLED',updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='PENDING'", params![now_us, task_id, generation])?;
            append_event(
                &tx,
                task_id,
                generation,
                "state_changed",
                &state_event_payload("CANCEL_REQUESTED"),
                now_us,
            )?;
        }
        store_command(
            &tx,
            consumer_id,
            "cancel",
            command_key,
            request_digest,
            task_id,
            now_us,
        )?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(false)
    }

    pub(crate) fn schedule_safe_retry(
        &mut self,
        operation_id: &str,
        task_id: &str,
        generation: i64,
        retry_at: i64,
        now_us: i64,
    ) -> Result<i64> {
        self.ensure_mutation_allowed(false)?;
        let operation_digest =
            digest_fields(&[task_id, &generation.to_string(), &retry_at.to_string()]);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = internal_operation_replay(&tx, operation_id, &operation_digest)? {
            tx.commit()?;
            return existing
                .parse()
                .map_err(|_| StorageError::Quarantined("invalid retry generation".into()));
        }
        let phase: String = tx.query_row("SELECT a.dispatch_phase FROM attempts a JOIN tasks t ON t.task_id=a.task_id WHERE a.task_id=?1 AND a.generation=?2 AND t.generation=?2 AND t.state IN ('PREPARING','RETRY_WAIT')", params![task_id, generation], |row| row.get(0))?;
        if !matches!(phase.as_str(), "PRE_DISPATCH" | "SPAWN_PREPARED") {
            return Err(StorageError::StaleGeneration);
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(StorageError::StaleGeneration)?;
        tx.execute("UPDATE attempts SET state='RETRY_WAIT',ended_at=?1,updated_at=?1 WHERE task_id=?2 AND generation=?3", params![now_us, task_id, generation])?;
        tx.execute("UPDATE tasks SET generation=?1,state='RETRY_WAIT',retry_at=?2,updated_at=?3 WHERE task_id=?4 AND generation=?5", params![next_generation, retry_at, now_us, task_id, generation])?;
        append_event(
            &tx,
            task_id,
            next_generation,
            "retry_scheduled",
            &serde_json::json!({"prior_generation": generation, "retry_at_ms": retry_at.max(0) / 1000}).to_string(),
            now_us,
        )?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'safe_retry',?5,?6)", params![operation_id, operation_digest, task_id, generation, next_generation.to_string(), now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(next_generation)
    }

    /// Advances a nonterminal task only if its generation and current state match.
    pub(crate) fn transition(
        &mut self,
        operation_id: &str,
        task_id: &str,
        generation: i64,
        from: &[&str],
        to: &str,
        now_us: i64,
    ) -> Result<i64> {
        let operation_digest =
            digest_fields(&[task_id, &generation.to_string(), &from.join("\0"), to]);
        let next = to
            .parse::<TaskState>()
            .map_err(|_| StorageError::StaleGeneration)?;
        self.ensure_mutation_allowed(next == TaskState::Finalizing)?;
        if next.is_terminal() {
            return Err(StorageError::TerminalImmutable);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) = internal_operation_replay(&tx, operation_id, &operation_digest)? {
            tx.commit()?;
            return locator
                .parse()
                .map_err(|_| StorageError::Quarantined("invalid transition replay".into()));
        }
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM tasks WHERE task_id=?1 AND generation=?2",
                params![task_id, generation],
                |r| r.get(0),
            )
            .optional()?;
        let Some(state) = state else {
            return Err(StorageError::StaleGeneration);
        };
        if is_terminal(&state) {
            return Err(StorageError::TerminalImmutable);
        }
        let current = state
            .parse::<TaskState>()
            .map_err(|_| StorageError::Quarantined("unknown persisted task state".into()))?;
        if !from.contains(&current.as_str()) || !current.allows(next) {
            return Err(StorageError::StaleGeneration);
        }
        tx.execute(
            "UPDATE tasks SET state=?1,updated_at=?2 WHERE task_id=?3 AND generation=?4",
            params![to, now_us, task_id, generation],
        )?;
        let seq = append_event(
            &tx,
            task_id,
            generation,
            "state_changed",
            &state_event_payload(to),
            now_us,
        )?;
        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'transition',?5,?6)", params![operation_id, operation_digest, task_id, generation, seq.to_string(), now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(seq)
    }

    /// Finalizes once. Result, event, projection, and random-token outbox are one transaction.
    pub(crate) fn finalize(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        request_digest: &str,
        task_id: &str,
        generation: i64,
        terminal_state: &str,
        result_digest: &str,
        now_us: i64,
    ) -> Result<ResultDelivery> {
        self.ensure_mutation_allowed(true)?;
        let terminal = terminal_state
            .parse::<TaskState>()
            .map_err(|_| StorageError::StaleGeneration)?;
        if !terminal.is_terminal() {
            return Err(StorageError::StaleGeneration);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) =
            command_replay(&tx, consumer_id, "finalize", command_key, request_digest)?
        {
            let delivery = load_delivery(&tx, consumer_id, &locator)?;
            tx.commit()?;
            return Ok(delivery);
        }
        let row: Option<(String, Option<i64>)> = tx
            .query_row(
                "SELECT state,cancel_requested_at FROM tasks WHERE task_id=?1 AND generation=?2",
                params![task_id, generation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((state, cancel_requested_at)) = row else {
            return Err(StorageError::StaleGeneration);
        };
        let current = state
            .parse::<TaskState>()
            .map_err(|_| StorageError::Quarantined("unknown task state".into()))?;
        if current.is_terminal() {
            return Err(StorageError::TerminalImmutable);
        }
        if !current.allows(terminal) {
            return Err(StorageError::StaleGeneration);
        }
        // CANCEL_REQUESTED is durable intent. FINALIZING after that intent
        // still cannot become SUCCEEDED, FAILED, or NEEDS_ATTENTION.
        if cancel_requested_at.is_some() && terminal != TaskState::Cancelled {
            return Err(StorageError::StaleGeneration);
        }
        let result_id = Uuid::new_v4().to_string();
        let ack_token = random_token();
        let mut statement = tx.prepare(
            "SELECT interaction_id,expires_at FROM pending_interactions
             WHERE task_id=?1 AND generation=?2 AND state='PENDING' ORDER BY interaction_id",
        )?;
        let pending = statement
            .query_map(params![task_id, generation], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for (interaction_id, expires_at) in pending {
            let status = if expires_at <= now_us {
                "EXPIRED"
            } else {
                "CANCELLED"
            };
            append_event(
                &tx,
                task_id,
                generation,
                "interaction_decided",
                &interaction_decided_event_payload(&interaction_id, status, None),
                now_us,
            )?;
        }
        let seq = append_event(
            &tx,
            task_id,
            generation,
            "terminal",
            &terminal_event_payload(terminal_state, &result_id),
            now_us,
        )?;
        tx.execute("INSERT INTO results(task_id,result_version,result_id,terminal_event_seq,result_digest,created_at) VALUES(?1,1,?2,?3,?4,?5)", params![task_id,result_id,seq,result_digest,now_us])?;
        tx.execute("INSERT INTO result_outbox(consumer_id,task_id,result_version,result_id,ack_token,terminal_event_seq,created_at) VALUES(?1,?2,1,?3,?4,?5,?6)", params![consumer_id,task_id,result_id,ack_token,seq,now_us])?;
        tx.execute("UPDATE tasks SET state=?1,result_version=1,terminal_event_seq=?2,terminal_at=?3,updated_at=?3 WHERE task_id=?4 AND generation=?5", params![terminal_state,seq,now_us,task_id,generation])?;
        tx.execute("UPDATE attempts SET state=?1,ended_at=?2,updated_at=?2 WHERE task_id=?3 AND generation=?4", params![terminal_state, now_us, task_id, generation])?;
        tx.execute("UPDATE pending_interactions SET state=CASE WHEN expires_at<=?1 THEN 'EXPIRED' ELSE 'CANCELLED' END,updated_at=?1 WHERE task_id=?2 AND generation=?3 AND state='PENDING'", params![now_us, task_id, generation])?;
        tx.execute("UPDATE worktrees SET terminal_state=?1,terminal_at=?2,state='RETAINED' WHERE task_id=?3", params![terminal_state, now_us, task_id])?;
        store_command(
            &tx,
            consumer_id,
            "finalize",
            command_key,
            request_digest,
            &result_id,
            now_us,
        )?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(ResultDelivery {
            task_id: task_id.into(),
            result_id,
            result_version: 1,
            ack_token,
            terminal_event_seq: seq,
            terminal_state: terminal_state.into(),
        })
    }

    /// Exact token/version review acknowledgement. Polling never calls this method.
    pub(crate) fn review_and_ack(
        &mut self,
        consumer_id: &str,
        command_key: &str,
        canonical_review_command: &[u8],
        delivery: &ResultDelivery,
        verdict: ReviewVerdict,
        diagnosis: Option<&str>,
        now_us: i64,
    ) -> Result<bool> {
        self.ensure_mutation_allowed(true)?;
        let parsed_command = parse_review_ack_command(canonical_review_command)?;
        if parsed_command.command_key != command_key
            || parsed_command.task_id != delivery.task_id
            || parsed_command.result_id != delivery.result_id
            || parsed_command.result_version != delivery.result_version
            || !constant_time_eq(
                parsed_command.ack_token.as_bytes(),
                delivery.ack_token.as_bytes(),
            )
            || parsed_command.verdict != verdict
            || parsed_command.diagnosis.as_deref() != diagnosis
        {
            return Err(StorageError::IdempotencyConflict);
        }
        let review_digest = hash_bytes(canonical_review_command);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(locator) =
            command_replay(&tx, consumer_id, "review_ack", command_key, &review_digest)?
        {
            if locator != delivery.result_id {
                return Err(StorageError::IdempotencyConflict);
            }
            verify_review_replay_tx(
                &tx,
                consumer_id,
                delivery,
                &review_digest,
                verdict,
                diagnosis,
            )?;
            tx.commit()?;
            self.record_review_observation(delivery, verdict, diagnosis, now_us)?;
            return Ok(true);
        }
        let row: Option<AckRow> = tx.query_row(
            "SELECT o.result_id,o.ack_token,o.terminal_event_seq,t.state,o.acked_at,r.review_digest,r.verdict,r.diagnosis_ref FROM result_outbox o JOIN tasks t ON t.task_id=o.task_id LEFT JOIN reviews r ON r.review_id=o.review_id WHERE o.consumer_id=?1 AND o.task_id=?2 AND o.result_version=?3",
            params![consumer_id,delivery.task_id,delivery.result_version], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
        ).optional()?;
        let Some((
            result_id,
            token,
            terminal_event_seq,
            terminal_state,
            acked_at,
            existing,
            existing_verdict,
            existing_diagnosis,
        )) = row
        else {
            return Err(StorageError::AckMismatch);
        };
        if result_id != delivery.result_id
            || terminal_event_seq != delivery.terminal_event_seq
            || terminal_state != delivery.terminal_state
            || !constant_time_eq(token.as_bytes(), delivery.ack_token.as_bytes())
        {
            return Err(StorageError::AckMismatch);
        }
        if acked_at.is_some() {
            if existing.as_deref() != Some(review_digest.as_str())
                || existing_verdict.as_deref() != Some(verdict.as_str())
                || existing_diagnosis.as_deref() != diagnosis
            {
                return Err(StorageError::AlreadyReviewed);
            }
        } else {
            let review_id = Uuid::new_v4().to_string();
            // The legacy column name predates public review semantics. It now
            // stores the lossless, schema-bounded `diagnosis` text (not a
            // blob reference or a display-normalized summary).
            tx.execute("INSERT INTO reviews(review_id,consumer_id,task_id,result_version,review_digest,verdict,diagnosis_ref,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![review_id,consumer_id,delivery.task_id,delivery.result_version,review_digest,verdict.as_str(),diagnosis,now_us])?;
            tx.execute("UPDATE result_outbox SET acked_at=?1,review_id=?2 WHERE consumer_id=?3 AND task_id=?4 AND result_version=?5", params![now_us,review_id,consumer_id,delivery.task_id,delivery.result_version])?;
            let terminal_at: i64 = tx.query_row(
                "SELECT terminal_at FROM tasks WHERE task_id=?1",
                [&delivery.task_id],
                |row| row.get(0),
            )?;
            let blob_eligible = terminal_at
                .saturating_add(14 * DAY_US)
                .max(now_us.saturating_add(7 * DAY_US));
            tx.execute(
                "UPDATE blob_refs SET eligible_at=?1 WHERE owner_id IN (?2,?3)",
                params![blob_eligible, delivery.task_id, delivery.result_id],
            )?;
            tx.execute("UPDATE worktrees SET acked_at=?1,state=CASE WHEN state='ACTIVE' THEN 'RETAINED' ELSE state END WHERE task_id=?2", params![now_us, delivery.task_id])?;
        }
        tx.execute("INSERT INTO command_dedup(consumer_id,method,command_key,request_digest,response_locator,committed_at) VALUES(?1,'review_ack',?2,?3,?4,?5)", params![consumer_id,command_key,review_digest,delivery.result_id,now_us])?;
        tx.execute("INSERT INTO audit_log(kind,task_id,generation,details_digest,created_at) SELECT 'RESULT_ACKED',?1,generation,?2,?3 FROM tasks WHERE task_id=?1", params![delivery.task_id, review_digest, now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        self.record_review_observation(delivery, verdict, diagnosis, now_us)?;
        Ok(false)
    }

    fn record_review_observation(
        &mut self,
        delivery: &ResultDelivery,
        verdict: ReviewVerdict,
        diagnosis: Option<&str>,
        reviewed_at_us: i64,
    ) -> Result<()> {
        let Some(engine) = load_improvement_engine(&self.conn)? else {
            return Ok(());
        };
        if !engine.policy().enabled {
            return Ok(());
        }
        let row: Option<ReviewObservationRow> = self
            .conn
            .query_row(
                "SELECT t.state,a.adapter_instance_id,a.adapter_version,a.config_version,
                        a.config_digest,a.adapter_instance_id,a.created_at,a.ended_at
                 FROM tasks t JOIN attempts a
                   ON a.task_id=t.task_id AND a.generation=t.generation
                 WHERE t.task_id=?1",
                [&delivery.task_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            terminal_state,
            adapter_instance_id,
            adapter_version,
            config_version,
            config_digest,
            component,
            attempt_started,
            attempt_ended,
        )) = row
        else {
            return Ok(());
        };
        if adapter_instance_id.is_empty() || config_digest.is_empty() {
            return Ok(());
        }
        let success =
            terminal_state == TaskState::Succeeded.as_str() && verdict == ReviewVerdict::Accepted;
        let failure_signature = if success {
            None
        } else {
            let failure_class = if verdict == ReviewVerdict::Rejected {
                "review_rejected"
            } else {
                match terminal_state.as_str() {
                    "FAILED" => "terminal_failed",
                    "CANCELLED" => "terminal_cancelled",
                    "NEEDS_ATTENTION" => "terminal_needs_attention",
                    _ => "terminal_unknown",
                }
            };
            let version_bucket =
                format!("version-{:x}", Sha256::digest(adapter_version.as_bytes()));
            let diagnosis_code = format!(
                "diag-{:x}",
                Sha256::digest(diagnosis.unwrap_or_default().as_bytes())
            );
            Some(crate::improvement::FailureSignature {
                protocol_stage: "terminal".into(),
                failure_class: failure_class.into(),
                version_bucket,
                diagnostic_code: diagnosis_code,
            })
        };
        let latency_us = attempt_ended
            .and_then(|ended| ended.checked_sub(attempt_started))
            .and_then(|value| u64::try_from(value).ok());
        let token_cost = usage_token_cost(&self.conn, &delivery.task_id)?;
        let safety_violations: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE task_id=?1 AND kind='safety_violation'",
            [&delivery.task_id],
            |row| row.get(0),
        )?;
        let input = ObservationInput {
            task_id: delivery.task_id.clone(),
            component,
            cohort: crate::improvement::Cohort {
                adapter_instance_id,
                adapter_version,
                config_version,
                config_digest,
            },
            reviewed_at_us,
            success,
            failure_signature,
            latency_us,
            token_cost,
            safety_violations,
        };
        self.mutate_improvement("OBSERVATION_RECORDED", reviewed_at_us, |engine| {
            let decision = engine.observe(input.clone());
            if matches!(decision, ObservationDecision::Eligible { .. }) {
                let _ = engine.open_eligible_case(&input, reviewed_at_us);
            }
            decision
        })?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn unacked(&self, consumer_id: &str) -> Result<Vec<ResultDelivery>> {
        let mut statement = self.conn.prepare("SELECT o.task_id,o.result_id,o.result_version,o.ack_token,r.terminal_event_seq,t.state FROM result_outbox o JOIN results r ON r.task_id=o.task_id AND r.result_version=o.result_version JOIN tasks t ON t.task_id=o.task_id WHERE o.consumer_id=?1 AND o.acked_at IS NULL ORDER BY o.created_at")?;
        let rows = statement.query_map([consumer_id], |r| {
            Ok(ResultDelivery {
                task_id: r.get(0)?,
                result_id: r.get(1)?,
                result_version: r.get(2)?,
                ack_token: r.get(3)?,
                terminal_event_seq: r.get(4)?,
                terminal_state: r.get(5)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn register_worktree(
        &mut self,
        worktree_id: &str,
        task_id: &str,
        path: &str,
        now_us: i64,
    ) -> Result<()> {
        self.ensure_mutation_allowed(false)?;
        let canonical = Path::new(path).canonicalize()?;
        if !canonical.starts_with(&self.root) {
            return Err(StorageError::InvalidRoot(canonical));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO worktrees(worktree_id,task_id,path,state,created_at) VALUES(?1,?2,?3,'ACTIVE',?4)", params![worktree_id, task_id, canonical.to_string_lossy(), now_us])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn events_after(
        &self,
        task_id: &str,
        after_seq: i64,
        limit: usize,
    ) -> Result<EventPage> {
        let live: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT evicted_through_seq,last_event_seq FROM tasks WHERE task_id=?1",
                [task_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (evicted, last) = match live {
            Some(bounds) => bounds,
            None => self.conn.query_row(
                "SELECT evicted_through_seq,last_event_seq FROM task_tombstones WHERE task_id=?1",
                [task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?,
        };
        if after_seq < evicted {
            return Err(StorageError::CursorExpired {
                oldest_available_seq: evicted + 1,
                last_committed_seq: last,
            });
        }
        let mut st = self.conn.prepare("SELECT event_seq,kind,payload FROM events WHERE task_id=?1 AND event_seq>?2 ORDER BY event_seq LIMIT ?3")?;
        let values = st
            .query_map(
                params![
                    task_id,
                    after_seq,
                    i64::try_from(limit.min(200)).expect("bounded event page")
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(EventPage {
            events: values,
            last_committed_seq: last,
        })
    }

    #[cfg(test)]
    pub(crate) fn compact_events_through(&mut self, task_id: &str, through: i64) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last: i64 = tx.query_row(
            "SELECT last_event_seq FROM tasks WHERE task_id=?1",
            [task_id],
            |r| r.get(0),
        )?;
        let bounded = through.min(last);
        tx.execute(
            "DELETE FROM events WHERE task_id=?1 AND event_seq<=?2",
            params![task_id, bounded],
        )?;
        tx.execute(
            "UPDATE tasks SET evicted_through_seq=MAX(evicted_through_seq,?1) WHERE task_id=?2",
            params![bounded, task_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn publish_blob(&mut self, bytes: &[u8], now_us: i64) -> Result<String> {
        self.ensure_mutation_allowed(false)?;
        self.ensure_capacity(bytes.len() as u64)?;
        let digest = format!("{:x}", Sha256::digest(bytes));
        let byte_length = i64::try_from(bytes.len()).map_err(|_| StorageError::QuotaExceeded)?;
        let final_path = blob_path(&self.root, &digest);
        if final_path.exists() {
            verify_blob(&final_path, &digest, bytes.len() as u64)?;
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("INSERT OR IGNORE INTO blob_objects(hash,byte_length,published_at,last_verified_at) VALUES(?1,?2,?3,?3)",params![digest,byte_length,now_us])?;
            bump_mutation_epoch(&tx, now_us)?;
            tx.commit()?;
            return Ok(digest);
        }
        self.filesystem
            .create_relative_directories(final_path.parent().expect("blob parent"))?;
        let staging_id = Uuid::new_v4().to_string();
        let stage_name = format!("{staging_id}.part");
        let stage = self.root.join("blobs/.staging").join(&stage_name);
        self.conn.execute("INSERT INTO blob_staging(staging_id,file_name,expected_hash,byte_length,state,created_at) VALUES(?1,?2,?3,?4,'WRITING',?5)", params![staging_id, stage_name, digest, byte_length, now_us])?;
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&stage)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        verify_blob(&stage, &digest, bytes.len() as u64)?;
        match self.filesystem.atomic_publish(&stage, &final_path) {
            Ok(()) => {}
            Err(_error) if final_path.exists() => {
                verify_blob(&final_path, &digest, bytes.len() as u64)?;
                fs::remove_file(&stage)?;
            }
            Err(error) => return Err(error.into()),
        }
        self.filesystem
            .sync_parent(final_path.parent().expect("blob parent"))?;
        verify_blob(&final_path, &digest, bytes.len() as u64)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT OR IGNORE INTO blob_objects(hash,byte_length,published_at,last_verified_at) VALUES(?1,?2,?3,?3)",params![digest,byte_length,now_us])?;
        tx.execute(
            "DELETE FROM blob_staging WHERE staging_id=?1 AND expected_hash=?2",
            params![staging_id, digest],
        )?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(digest)
    }

    pub(crate) fn reference_blob(
        &mut self,
        owner_kind: &str,
        owner_id: &str,
        field: &str,
        digest: &str,
        now_us: i64,
    ) -> Result<()> {
        self.ensure_mutation_allowed(false)?;
        if !valid_digest(digest) {
            return Err(StorageError::BlobCorruption("invalid digest".into()));
        }
        let bytes = self.read_blob(digest)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO blob_refs(owner_kind,owner_id,field,hash) VALUES(?1,?2,?3,?4) ON CONFLICT(owner_kind,owner_id,field) DO UPDATE SET hash=excluded.hash",params![owner_kind,owner_id,field,digest])?;
        tx.execute("UPDATE blob_objects SET byte_length=?1,last_verified_at=last_verified_at WHERE hash=?2",params![i64::try_from(bytes.len()).map_err(|_| StorageError::QuotaExceeded)?,digest])?;
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn verify_mandatory_blob_refs(&self) -> Result<()> {
        let mut statement=self.conn.prepare("SELECT DISTINCT b.hash,b.byte_length FROM blob_objects b JOIN blob_refs r ON r.hash=b.hash")?;
        for row in statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (digest, size) = row?;
            verify_blob(
                &blob_path(&self.root, &digest),
                &digest,
                u64::try_from(size).map_err(|_| StorageError::BlobCorruption(digest.clone()))?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn acquire_lease(
        &mut self,
        lease_id: &str,
        resource_kind: &str,
        resource_id: &str,
        epoch: i64,
        now_us: i64,
    ) -> Result<()> {
        self.ensure_mutation_allowed(true)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_epoch: i64 = tx.query_row(
            "SELECT lease_epoch FROM storage_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if epoch != current_epoch || now_us < 0 {
            return Err(StorageError::StaleGeneration);
        }
        let prior: Option<(i64, i64)> = tx
            .query_row(
                "SELECT heartbeat_at,expires_at FROM reader_leases WHERE lease_id=?1 AND lease_epoch=?2",
                params![lease_id, epoch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((heartbeat_at, expires_at)) = prior
            && (now_us > expires_at || now_us > heartbeat_at.saturating_add(LEASE_HEARTBEAT_US))
        {
            return Err(StorageError::StaleGeneration);
        }
        let expires_at = now_us.saturating_add(LEASE_TTL_US);
        if tx.query_row("SELECT 1 FROM gc_intents WHERE resource_kind=?1 AND resource_id=?2 AND state='MARKED'",params![resource_kind,resource_id],|r|r.get::<_,i64>(0)).optional()?.is_some(){return Err(StorageError::Quarantined("resource is fenced for GC".into()));}
        tx.execute("INSERT INTO reader_leases(lease_id,lease_epoch,owner_id,issued_at,heartbeat_at,expires_at) VALUES(?1,?2,?1,?3,?3,?4) ON CONFLICT(lease_id) DO UPDATE SET lease_epoch=excluded.lease_epoch,heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at",params![lease_id,epoch,now_us,expires_at])?;
        tx.execute("INSERT OR IGNORE INTO reader_lease_items(lease_id,resource_kind,resource_id) VALUES(?1,?2,?3)",params![lease_id,resource_kind,resource_id])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn current_lease_epoch(&self) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT lease_epoch FROM storage_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(crate) fn release_lease(&mut self, lease_id: &str, epoch: i64) -> Result<bool> {
        self.ensure_mutation_allowed(true)?;
        let changed = self.conn.execute(
            "DELETE FROM reader_leases WHERE lease_id=?1 AND lease_epoch=?2",
            params![lease_id, epoch],
        )?;
        Ok(changed == 1)
    }
    pub(crate) fn mark_retention_gc(&mut self, now_us: i64) -> Result<Vec<GcCandidate>> {
        self.ensure_mutation_allowed(false)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM reader_leases WHERE expires_at<=?1", [now_us])?;

        compact_eligible_tasks(&tx, now_us)?;
        let mut candidates = Vec::new();
        {
            let mut statement = tx.prepare(
                "SELECT b.hash,b.byte_length FROM blob_objects b
                 WHERE ((NOT EXISTS(SELECT 1 FROM blob_refs r WHERE r.hash=b.hash) AND b.published_at<=?1-?3)
                        OR (EXISTS(SELECT 1 FROM blob_refs r WHERE r.hash=b.hash) AND NOT EXISTS(SELECT 1 FROM blob_refs r WHERE r.hash=b.hash AND (r.eligible_at IS NULL OR r.eligible_at>?1))))
                   AND NOT EXISTS(SELECT 1 FROM reader_lease_items i JOIN reader_leases l ON l.lease_id=i.lease_id WHERE i.resource_kind='blob' AND i.resource_id=b.hash AND l.expires_at>?1)
                   AND NOT EXISTS(SELECT 1 FROM gc_intents g WHERE g.resource_kind='blob' AND g.resource_id=b.hash AND g.state='MARKED')
                 ORDER BY b.published_at LIMIT ?2",
            )?;
            let mut bytes = 0_u64;
            for row in statement.query_map(
                params![
                    now_us,
                    i64::try_from(GC_BATCH_ROWS).expect("bounded GC rows"),
                    DAY_US
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )? {
                let (id, length) = row?;
                let length =
                    u64::try_from(length).map_err(|_| StorageError::BlobCorruption(id.clone()))?;
                if !candidates.is_empty() && bytes.saturating_add(length) > GC_BATCH_BYTES {
                    break;
                }
                bytes = bytes.saturating_add(length);
                candidates.push(GcCandidate {
                    resource_kind: "blob".into(),
                    resource_id: id,
                    byte_length: length,
                    fence_token: random_token(),
                });
            }
        }
        if candidates.len() < GC_BATCH_ROWS {
            let mut statement = tx.prepare(
                "SELECT w.worktree_id,0 FROM worktrees w
                 WHERE w.state='RETAINED' AND w.terminal_at IS NOT NULL
                   AND ((w.terminal_state='SUCCEEDED' AND w.acked_at IS NOT NULL AND w.acked_at<=?1)
                        OR (w.terminal_state IN ('FAILED','CANCELLED','NEEDS_ATTENTION') AND w.terminal_at<=?2))
                   AND NOT EXISTS(SELECT 1 FROM reader_lease_items i JOIN reader_leases l ON l.lease_id=i.lease_id WHERE i.resource_kind='worktree' AND i.resource_id=w.worktree_id AND l.expires_at>?3)
                   AND NOT EXISTS(SELECT 1 FROM gc_intents g WHERE g.resource_kind='worktree' AND g.resource_id=w.worktree_id AND g.state='MARKED')
                 ORDER BY w.terminal_at LIMIT ?4",
            )?;
            let success_cutoff = now_us.saturating_sub(7 * DAY_US);
            let non_success_cutoff = now_us.saturating_sub(30 * DAY_US);
            let remaining = i64::try_from(GC_BATCH_ROWS.saturating_sub(candidates.len()))
                .expect("bounded GC rows");
            for row in statement.query_map(
                params![success_cutoff, non_success_cutoff, now_us, remaining],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )? {
                let (id, _) = row?;
                candidates.push(GcCandidate {
                    resource_kind: "worktree".into(),
                    resource_id: id,
                    byte_length: 0,
                    fence_token: random_token(),
                });
            }
        }
        for candidate in &candidates {
            tx.execute("INSERT INTO gc_intents(resource_kind,resource_id,state,byte_length,fence_token,eligible_at,marked_at) VALUES(?1,?2,'MARKED',?3,?4,?5,?5)", params![candidate.resource_kind, candidate.resource_id, i64::try_from(candidate.byte_length).map_err(|_| StorageError::Quarantined("GC byte length exceeds SQLite range".into()))?, candidate.fence_token, now_us])?;
            tx.execute(
                "INSERT INTO audit_log(kind,details_digest,created_at) VALUES('GC_MARKED',?1,?2)",
                params![
                    digest_fields(&[&candidate.resource_kind, &candidate.resource_id]),
                    now_us
                ],
            )?;
            if candidate.resource_kind == "worktree" {
                tx.execute(
                    "UPDATE worktrees SET state='GC_MARKED' WHERE worktree_id=?1",
                    [&candidate.resource_id],
                )?;
            }
        }
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(candidates)
    }

    pub(crate) fn prepare_gc_deletion(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<GcDeletionPlan> {
        let (byte_length, fence_token): (i64, String) = self.conn.query_row(
            "SELECT byte_length,fence_token FROM gc_intents WHERE resource_kind=?1 AND resource_id=?2 AND state='MARKED'",
            params![resource_kind, resource_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let exact_path = match resource_kind {
            "blob" if valid_digest(resource_id) => blob_path(&self.root, resource_id),
            "worktree" => {
                let stored: String = self.conn.query_row(
                    "SELECT path FROM worktrees WHERE worktree_id=?1 AND state='GC_MARKED'",
                    [resource_id],
                    |row| row.get(0),
                )?;
                let path = PathBuf::from(stored);
                if !path.starts_with(&self.root) {
                    return Err(StorageError::Quarantined(
                        "GC path escaped data root".into(),
                    ));
                }
                path
            }
            _ => return Err(StorageError::Quarantined("unknown GC resource".into())),
        };
        Ok(GcDeletionPlan {
            candidate: GcCandidate {
                resource_kind: resource_kind.to_owned(),
                resource_id: resource_id.to_owned(),
                byte_length: u64::try_from(byte_length)
                    .map_err(|_| StorageError::Quarantined("negative GC length".into()))?,
                fence_token,
            },
            exact_path,
        })
    }

    pub(crate) fn finish_gc_deletion(
        &mut self,
        candidate: &GcCandidate,
        success: bool,
        error_digest: Option<&str>,
        now_us: i64,
    ) -> Result<()> {
        self.ensure_mutation_allowed(false)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let matches: Option<i64> = tx.query_row("SELECT 1 FROM gc_intents WHERE resource_kind=?1 AND resource_id=?2 AND state='MARKED' AND fence_token=?3", params![candidate.resource_kind, candidate.resource_id, candidate.fence_token], |row| row.get(0)).optional()?;
        if matches.is_none() {
            return Err(StorageError::StaleGeneration);
        }
        if success {
            match candidate.resource_kind.as_str() {
                "blob" => {
                    tx.execute(
                        "DELETE FROM blob_refs WHERE hash=?1",
                        [&candidate.resource_id],
                    )?;
                    tx.execute(
                        "DELETE FROM blob_objects WHERE hash=?1",
                        [&candidate.resource_id],
                    )?;
                }
                "worktree" => {
                    tx.execute("UPDATE worktrees SET state='DELETED' WHERE worktree_id=?1 AND state='GC_MARKED'", [&candidate.resource_id])?;
                }
                _ => return Err(StorageError::Quarantined("unknown GC resource".into())),
            }
            tx.execute("UPDATE gc_intents SET state='DELETED',finished_at=?1,attempts=attempts+1 WHERE resource_kind=?2 AND resource_id=?3 AND fence_token=?4", params![now_us, candidate.resource_kind, candidate.resource_id, candidate.fence_token])?;
            tx.execute(
                "INSERT INTO audit_log(kind,details_digest,created_at) VALUES('GC_DELETED',?1,?2)",
                params![
                    digest_fields(&[&candidate.resource_kind, &candidate.resource_id]),
                    now_us
                ],
            )?;
        } else {
            tx.execute("UPDATE gc_intents SET state='FAILED',finished_at=?1,error_digest=?2,attempts=attempts+1 WHERE resource_kind=?3 AND resource_id=?4 AND fence_token=?5", params![now_us, error_digest.unwrap_or("unknown"), candidate.resource_kind, candidate.resource_id, candidate.fence_token])?;
            tx.execute(
                "INSERT INTO audit_log(kind,details_digest,created_at) VALUES('GC_FAILED',?1,?2)",
                params![error_digest.unwrap_or("unknown"), now_us],
            )?;
        }
        bump_mutation_epoch(&tx, now_us)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn reconcile_nonterminal(
        &mut self,
        consumer_id: &str,
        now_us: i64,
    ) -> Result<Vec<(String, RecoveryDecision)>> {
        self.ensure_mutation_allowed(true)?;
        let mut statement = self.conn.prepare(
            "SELECT t.task_id,t.state,t.generation,t.cancel_requested_at,a.dispatch_phase,a.provider_session,a.process_receipt,a.adapter_instance_id,a.adapter_version,a.config_digest,a.resumable_capability_digest,a.resume_proof_digest,a.effect_profile
             FROM tasks t LEFT JOIN attempts a ON a.task_id=t.task_id AND a.generation=t.generation
             WHERE t.state NOT IN ('QUEUED','RETRY_WAIT','SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')
             ORDER BY t.created_at",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut decisions = Vec::new();
        for (
            task_id,
            state,
            generation,
            cancel_requested_at,
            phase,
            session,
            receipt,
            adapter_id,
            adapter_version,
            config_digest,
            capability,
            proof,
            effect_profile,
        ) in rows
        {
            let expected_proof = match (
                adapter_id.as_deref(),
                adapter_version.as_deref(),
                config_digest.as_deref(),
                capability.as_deref(),
            ) {
                (
                    Some(adapter_id),
                    Some(adapter_version),
                    Some(config_digest),
                    Some(capability),
                ) => Some(digest_fields(&[
                    adapter_id,
                    adapter_version,
                    config_digest,
                    capability,
                ])),
                _ => None,
            };
            let resume_proven = matches!(phase.as_deref(), Some("PROVIDER_OBSERVED"))
                && receipt.is_some()
                && session.as_deref().is_some_and(|value| !value.is_empty())
                && capability.as_deref().is_some_and(|value| !value.is_empty())
                && proof.as_deref() == expected_proof.as_deref();
            let answered_kind = latest_answered_response_kind(&self.conn, &task_id, generation)?;
            let current_directory = effect_profile.as_deref() == Some("CURRENT_DIRECTORY");
            let pre_dispatch = matches!(phase.as_deref(), Some("PRE_DISPATCH" | "SPAWN_PREPARED"));
            let decision = if state == TaskState::CancelRequested.as_str() {
                RecoveryDecision::FinalizeCancellation
            } else if state == TaskState::Finalizing.as_str() {
                // A committed cancel request still wins after the FINALIZING
                // handoff. Other FINALIZING crashes stay uncertain.
                if cancel_requested_at.is_some() {
                    RecoveryDecision::FinalizeCancellation
                } else {
                    RecoveryDecision::NeedsAttention
                }
            } else if resume_proven {
                RecoveryDecision::ResumeSession
            } else if current_directory && !pre_dispatch {
                // Automatic retry is forbidden after process start for this
                // effect profile. A proven same-attempt resume is handled above.
                RecoveryDecision::NeedsAttention
            } else if pre_dispatch {
                match (state.as_str(), answered_kind.as_deref()) {
                    (_, Some("deny")) => RecoveryDecision::FinalizeCancellation,
                    ("WAITING_APPROVAL", None | Some("approve" | "text"))
                    | ("RUNNING", Some("approve" | "text")) => {
                        // Still waiting, or the one-shot already reserved this
                        // attempt. Auto-retry would increment generation and
                        // treat a deny as consent to spawn.
                        continue;
                    }
                    _ => RecoveryDecision::RetrySafe,
                }
            } else {
                RecoveryDecision::NeedsAttention
            };
            match decision {
                RecoveryDecision::RetrySafe => {
                    let operation = format!("recovery-retry:{task_id}:{generation}");
                    self.schedule_safe_retry(&operation, &task_id, generation, now_us, now_us)?;
                }
                RecoveryDecision::ResumeSession => {
                    let digest =
                        digest_fields(&[&task_id, &generation.to_string(), "resume-session"]);
                    let tx = self
                        .conn
                        .transaction_with_behavior(TransactionBehavior::Immediate)?;
                    if internal_operation_replay(
                        &tx,
                        &format!("recovery-resume:{task_id}:{generation}"),
                        &digest,
                    )?
                    .is_none()
                    {
                        append_event(
                            &tx,
                            &task_id,
                            generation,
                            "recovery_required",
                            r#"{"action":"resume_session"}"#,
                            now_us,
                        )?;
                        tx.execute("INSERT INTO internal_operations(operation_id,operation_digest,task_id,generation,kind,response_locator,committed_at) VALUES(?1,?2,?3,?4,'recovery_resume','',?5)", params![format!("recovery-resume:{task_id}:{generation}"), digest, task_id, generation, now_us])?;
                        tx.commit()?;
                    }
                }
                RecoveryDecision::FinalizeCancellation | RecoveryDecision::NeedsAttention => {
                    let target = if decision == RecoveryDecision::FinalizeCancellation {
                        TaskState::Cancelled
                    } else {
                        TaskState::NeedsAttention
                    };
                    // A crash may occur after the durable transition to
                    // FINALIZING but before terminalization. Replaying that
                    // transition would be invalid; the terminal tuple is the
                    // remaining idempotent recovery operation.
                    if state != TaskState::Finalizing.as_str() {
                        let operation = format!("recovery-finalizing:{task_id}:{generation}");
                        self.transition(
                            &operation,
                            &task_id,
                            generation,
                            &[&state],
                            TaskState::Finalizing.as_str(),
                            now_us,
                        )?;
                    }
                    let request =
                        digest_fields(&[&task_id, &generation.to_string(), target.as_str()]);
                    self.finalize(
                        consumer_id,
                        &format!("recovery-result:{task_id}:{generation}"),
                        &request,
                        &task_id,
                        generation,
                        target.as_str(),
                        &digest_fields(&["minimal-recovery-result", target.as_str()]),
                        now_us,
                    )?;
                }
            }
            decisions.push((task_id, decision));
        }
        Ok(decisions)
    }

    pub(crate) fn create_backup(
        &mut self,
        binary_version: &str,
        now_us: i64,
    ) -> Result<BackupManifest> {
        self.ensure_mutation_allowed(false)?;
        self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        let (install_id, mutation_epoch): (String, i64) = self.conn.query_row(
            "SELECT install_id,mutation_epoch FROM storage_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let backup_id = Uuid::new_v4().to_string();
        let staged_db = self
            .root
            .join("backups")
            .join(format!("{backup_id}.sqlite3.tmp"));
        let final_db = self
            .root
            .join("backups")
            .join(format!("{backup_id}.sqlite3"));
        self.conn.backup(rusqlite::MAIN_DB, &staged_db, None)?;
        let check =
            Connection::open_with_flags(&staged_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let quick: String = check.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if quick != "ok" {
            return Err(StorageError::Quarantined(
                "backup quick_check failed".into(),
            ));
        }
        drop(check);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&staged_db)?
            .sync_all()?;
        self.filesystem.atomic_publish(&staged_db, &final_db)?;
        self.filesystem
            .sync_parent(final_db.parent().expect("backup parent"))?;
        let database_sha256 = hash_file(&final_db)?;
        let manifest = BackupManifest {
            backup_id: backup_id.clone(),
            snapshot_file: final_db
                .file_name()
                .expect("backup filename")
                .to_string_lossy()
                .into_owned(),
            source_schema: SCHEMA_VERSION,
            database_sha256: database_sha256.clone(),
            binary_version: binary_version.to_owned(),
            install_id,
            mutation_epoch,
        };
        let manifest_staged = self
            .root
            .join("backups")
            .join(format!("{backup_id}.manifest.json.tmp"));
        let manifest_path = self
            .root
            .join("backups")
            .join(format!("{backup_id}.manifest.json"));
        {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&manifest_staged)?;
            serde_json::to_writer(&mut file, &manifest)
                .map_err(|error| StorageError::MigrationMismatch(error.to_string()))?;
            file.sync_all()?;
        }
        self.filesystem
            .atomic_publish(&manifest_staged, &manifest_path)?;
        self.filesystem
            .sync_parent(manifest_path.parent().expect("backup parent"))?;
        self.conn.execute("INSERT INTO migration_backups(backup_id,manifest_path,source_schema,database_sha256,mutation_epoch,created_at) VALUES(?1,?2,?3,?4,?5,?6)", params![backup_id, manifest_path.to_string_lossy(), SCHEMA_VERSION, database_sha256, mutation_epoch, now_us])?;
        Ok(manifest)
    }

    pub(crate) fn verify_restore_allowed(&self, manifest: &BackupManifest) -> Result<()> {
        let (install_id, mutation_epoch): (String, i64) = self.conn.query_row(
            "SELECT install_id,mutation_epoch FROM storage_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let snapshot_component = Path::new(&manifest.snapshot_file);
        if snapshot_component.components().count() != 1
            || !matches!(
                snapshot_component.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(StorageError::RestoreRefused);
        }
        let snapshot = self.root.join("backups").join(snapshot_component);
        if manifest.install_id != install_id
            || manifest.mutation_epoch != mutation_epoch
            || manifest.source_schema != SCHEMA_VERSION
            || !snapshot.starts_with(self.root.join("backups"))
            || !snapshot.is_file()
            || hash_file(&snapshot)? != manifest.database_sha256
        {
            return Err(StorageError::RestoreRefused);
        }
        let stored: Option<(String, i64, String)> = self.conn.query_row(
            "SELECT database_sha256,source_schema,manifest_path FROM migration_backups WHERE backup_id=?1",
            [&manifest.backup_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let Some((digest, schema, manifest_path)) = stored else {
            return Err(StorageError::RestoreRefused);
        };
        let expected_manifest = self
            .root
            .join("backups")
            .join(format!("{}.manifest.json", manifest.backup_id));
        let published_manifest: BackupManifest =
            serde_json::from_reader(File::open(&expected_manifest)?)
                .map_err(|error| StorageError::MigrationMismatch(error.to_string()))?;
        if digest != manifest.database_sha256
            || schema != manifest.source_schema
            || Path::new(&manifest_path) != expected_manifest
            || published_manifest != *manifest
        {
            return Err(StorageError::RestoreRefused);
        }
        Ok(())
    }

    pub(crate) fn checkpoint_passive(&mut self) -> Result<(i64, i64, i64)> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(Into::into)
    }

    pub(crate) fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = blob_path(&self.root, digest);
        let metadata = fs::metadata(&path)?;
        verify_blob(&path, digest, metadata.len())?;
        Ok(fs::read(path)?)
    }

    /// Returns response evidence only after checking the durable row's declared
    /// length and digest. This keeps callers from treating an answered
    /// interaction as an invented approval or input value after restart.
    pub(crate) fn interaction_response(
        &self,
        interaction_id: &str,
    ) -> Result<InteractionResponseEvidence> {
        load_interaction_response_evidence(&self.conn, interaction_id)
    }

    /// Recovery verifies immutable terminal tuple cardinality and never invents an ACK token.
    pub(crate) fn integrity_check(&self) -> Result<()> {
        let quick: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if quick != "ok" {
            return Err(StorageError::Quarantined(quick));
        }
        let mut st=self.conn.prepare("SELECT t.task_id,
            (SELECT COUNT(*) FROM results r WHERE r.task_id=t.task_id),
            (SELECT COUNT(*) FROM result_outbox o WHERE o.task_id=t.task_id),
            (SELECT COUNT(*) FROM events e WHERE e.task_id=t.task_id AND e.event_seq=t.terminal_event_seq)
            FROM tasks t WHERE t.state IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')")?;
        let bad = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .find_map(|v| match v {
                Ok((_id, 1, 1, 1)) => None,
                Ok((id, ..)) => Some(Err(StorageError::Quarantined(format!(
                    "partial terminal tuple for {id}"
                )))),
                Err(e) => Some(Err(e.into())),
            });
        bad.unwrap_or(Ok(()))?;
        let mut terminal_events = self.conn.prepare(
            "SELECT t.task_id,t.state,t.terminal_event_seq,r.result_id,r.terminal_event_seq,
                    o.result_id,o.terminal_event_seq,e.kind,e.payload
             FROM tasks t
             JOIN results r ON r.task_id=t.task_id AND r.result_version=1
             JOIN result_outbox o ON o.task_id=t.task_id AND o.result_version=1
             JOIN events e ON e.task_id=t.task_id AND e.event_seq=t.terminal_event_seq
             WHERE t.state IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')",
        )?;
        for row in terminal_events.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })? {
            let (
                task_id,
                terminal_state,
                terminal_event_seq,
                result_id,
                result_event_seq,
                outbox_result_id,
                outbox_event_seq,
                kind,
                payload,
            ) = row?;
            let value: serde_json::Value = serde_json::from_str(&payload).map_err(|_| {
                StorageError::Quarantined(format!("invalid terminal event payload: {task_id}"))
            })?;
            let Some(object) = value.as_object() else {
                return Err(StorageError::Quarantined(format!(
                    "terminal event payload is not an object: {task_id}"
                )));
            };
            if kind != "terminal"
                || object.len() != 2
                || object.get("state").and_then(serde_json::Value::as_str)
                    != Some(terminal_state.as_str())
                || object.get("result_id").and_then(serde_json::Value::as_str)
                    != Some(result_id.as_str())
                || result_event_seq != terminal_event_seq
                || outbox_event_seq != terminal_event_seq
                || outbox_result_id != result_id
            {
                return Err(StorageError::Quarantined(format!(
                    "terminal event/result tuple mismatch: {task_id}"
                )));
            }
        }
        Ok(())
    }

    fn ensure_mutation_allowed(&self, emergency_safe: bool) -> Result<()> {
        if self.emergency != EmergencyState::Normal && !emergency_safe {
            return Err(StorageError::StorageEmergency);
        }
        if !emergency_safe && self.wal_bytes() >= 128 * 1024 * 1024 {
            return Err(StorageError::WalPressure);
        }
        Ok(())
    }

    fn wal_bytes(&self) -> u64 {
        self.root
            .join("mesh.sqlite3-wal")
            .metadata()
            .map_or(0, |metadata| metadata.len())
    }

    fn ensure_capacity(&self, declared_maximum: u64) -> Result<()> {
        let Some(policy) = self.quota else {
            return Ok(());
        };
        let used = self.filesystem.allocated_bytes(&self.root)?;
        let free = self.filesystem.free_bytes(&self.root)?;
        if used.saturating_add(declared_maximum)
            > policy.quota_bytes.saturating_sub(policy.reserve_bytes)
            || free.saturating_sub(declared_maximum) < policy.reserve_bytes
        {
            return Err(StorageError::QuotaExceeded);
        }
        Ok(())
    }

    pub(crate) fn latch_emergency(&mut self, now_us: i64) -> Result<EmergencyState> {
        if self.emergency == EmergencyState::ReserveReleased {
            return Ok(self.emergency);
        }
        self.emergency = EmergencyState::Latched;
        if self.quota.is_some() {
            self.filesystem
                .release_reserve(&self.root.join("critical.reserve"))?;
            self.emergency = EmergencyState::ReserveReleased;
            self.conn.execute("UPDATE storage_meta SET emergency_state='RESERVE_RELEASED',updated_at=?1 WHERE singleton=1", [now_us])?;
            self.conn.execute("INSERT INTO audit_log(kind,details_digest,created_at) VALUES('RESERVE_RELEASED','storage-emergency',?1)", [now_us])?;
        } else {
            self.conn.execute(
                "UPDATE storage_meta SET emergency_state='LATCHED',updated_at=?1 WHERE singleton=1",
                [now_us],
            )?;
        }
        Ok(self.emergency)
    }

    pub(crate) fn recover_emergency(&mut self, now_us: i64) -> Result<()> {
        let Some(policy) = self.quota else {
            self.emergency = EmergencyState::Normal;
            return Ok(());
        };
        self.integrity_check()?;
        self.checkpoint_passive()?;
        let used = self.filesystem.allocated_bytes(&self.root)?;
        let free = self.filesystem.free_bytes(&self.root)?;
        if used.saturating_add(policy.reserve_bytes) > policy.quota_bytes
            || free < policy.reserve_bytes.saturating_mul(2)
        {
            return Err(StorageError::QuotaExceeded);
        }
        self.filesystem
            .create_reserve(&self.root.join("critical.reserve"), policy.reserve_bytes)?;
        self.conn.execute(
            "UPDATE storage_meta SET emergency_state='NORMAL',updated_at=?1 WHERE singleton=1",
            [now_us],
        )?;
        self.conn.execute("INSERT INTO audit_log(kind,details_digest,created_at) VALUES('RESERVE_RECREATED','storage-recovered',?1)", [now_us])?;
        self.emergency = EmergencyState::Normal;
        Ok(())
    }

    fn startup_integrity_check(&mut self, now_us: i64) -> Result<()> {
        verify_migration_checksums(&self.conn)?;
        self.integrity_check()?;
        let foreign: Option<String> = self
            .conn
            .query_row(
                "SELECT 'foreign-key violation' FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(reason) = foreign {
            return Err(StorageError::Quarantined(reason));
        }
        self.recover_staged_blobs(now_us)?;
        self.verify_mandatory_blob_refs()?;
        self.verify_mandatory_task_requests()?;
        self.verify_interaction_evidence()?;
        self.verify_review_evidence()?;
        let _ = load_improvement_engine(&self.conn)?;
        self.replay_projections(now_us)?;
        Ok(())
    }

    fn verify_mandatory_task_requests(&self) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT t.task_id,t.request_digest,r.request_digest,r.byte_length
             FROM tasks t LEFT JOIN task_requests r ON r.task_id=t.task_id
             WHERE t.state NOT IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')",
        )?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })? {
            let (task_id, expected_digest, digest, length) = row?;
            let Some((digest, length)) = digest.zip(length) else {
                return Err(StorageError::Quarantined(format!(
                    "missing canonical task request for {task_id}"
                )));
            };
            if length <= 0
                || usize::try_from(length)
                    .ok()
                    .is_none_or(|value| value > MAX_CANONICAL_TASK_REQUEST_BYTES)
            {
                return Err(StorageError::Quarantined(format!(
                    "canonical task request integrity mismatch for {task_id}"
                )));
            }
            let bytes: Vec<u8> = self.conn.query_row(
                "SELECT request_bytes FROM task_requests WHERE task_id=?1",
                [&task_id],
                |row| row.get(0),
            )?;
            if digest != expected_digest
                || length
                    != i64::try_from(bytes.len()).map_err(|_| {
                        StorageError::Quarantined("task request length overflow".into())
                    })?
                || format!("{:x}", Sha256::digest(&bytes)) != digest
            {
                return Err(StorageError::Quarantined(format!(
                    "canonical task request integrity mismatch for {task_id}"
                )));
            }
        }
        Ok(())
    }

    /// v4 intentionally adds nullable columns so old rows can be migrated
    /// without manufacturing capability or response defaults. Any legacy or
    /// corrupt interaction that lacks complete evidence is therefore fenced at
    /// startup rather than resumed as a semantic response.
    fn verify_interaction_evidence(&self) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT i.interaction_id,i.state,i.capability_class,i.config_version,i.policy_version,a.adapter_instance_id
             FROM pending_interactions i
             JOIN attempts a ON a.attempt_id=i.attempt_id AND a.task_id=i.task_id AND a.generation=i.generation",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for (interaction_id, state, capability_class, config_version, policy_version, adapter_id) in
            rows
        {
            validate_interaction_metadata(
                &interaction_id,
                capability_class.as_deref(),
                config_version,
                policy_version,
                &adapter_id,
            )?;
            let has_response: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM interaction_responses WHERE interaction_id=?1)",
                [&interaction_id],
                |row| row.get(0),
            )?;
            if state == InteractionState::Answered.as_str() {
                if !has_response {
                    return Err(StorageError::Quarantined(format!(
                        "answered interaction has no response evidence: {interaction_id}"
                    )));
                }
                let evidence = load_interaction_response_evidence(&self.conn, &interaction_id)?;
                verify_interaction_response_command_binding(&self.conn, &evidence)?;
            } else if has_response {
                return Err(StorageError::Quarantined(format!(
                    "non-answered interaction has response evidence: {interaction_id}"
                )));
            }
        }
        Ok(())
    }

    fn verify_review_evidence(&self) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT o.consumer_id,o.task_id,o.result_version,o.result_id,o.ack_token,o.acked_at,o.review_id,
                    r.consumer_id,r.task_id,r.result_version,r.review_digest,r.verdict,r.diagnosis_ref
             FROM result_outbox o
             LEFT JOIN reviews r ON r.review_id=o.review_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for (
            consumer_id,
            task_id,
            result_version,
            result_id,
            ack_token,
            acked_at,
            review_id,
            review_consumer,
            review_task,
            review_version,
            review_digest,
            verdict,
            diagnosis_ref,
        ) in rows
        {
            if acked_at.is_none() {
                if review_id.is_some()
                    || review_consumer.is_some()
                    || review_task.is_some()
                    || review_version.is_some()
                    || review_digest.is_some()
                    || verdict.is_some()
                    || diagnosis_ref.is_some()
                {
                    return Err(StorageError::Quarantined(format!(
                        "unacknowledged result has review evidence: {result_id}"
                    )));
                }
                continue;
            }
            let Some(review_id) = review_id else {
                return Err(StorageError::Quarantined(format!(
                    "acknowledged result has no review id: {result_id}"
                )));
            };
            let (
                Some(review_consumer),
                Some(review_task),
                Some(review_version),
                Some(review_digest),
                Some(verdict),
            ) = (
                review_consumer,
                review_task,
                review_version,
                review_digest,
                verdict,
            )
            else {
                return Err(StorageError::Quarantined(format!(
                    "acknowledged result has incomplete review evidence: {result_id}"
                )));
            };
            if review_consumer != consumer_id
                || review_task != task_id
                || review_version != result_version
                || review_id.is_empty()
                || !is_lower_sha256(&review_digest)
                || verdict.parse::<ReviewVerdict>().is_err()
            {
                return Err(StorageError::Quarantined(format!(
                    "invalid review evidence for result: {result_id}"
                )));
            }
            validate_diagnosis(diagnosis_ref.as_deref()).map_err(|_| {
                StorageError::Quarantined(format!(
                    "invalid lossless diagnosis for result: {result_id}"
                ))
            })?;
            self.verify_review_command_binding(
                &consumer_id,
                &task_id,
                result_version,
                &result_id,
                &ack_token,
                &review_digest,
                &verdict,
                diagnosis_ref.as_deref(),
            )?;
        }
        Ok(())
    }

    /// Review commands are represented by their canonical digest in the dedup
    /// table. Reconstructing the strict command from the immutable outbox tuple
    /// and lossless review semantics makes an incomplete or divergent legacy
    /// row quarantine at startup instead of being treated as a valid ACK.
    fn verify_review_command_binding(
        &self,
        consumer_id: &str,
        task_id: &str,
        result_version: i64,
        result_id: &str,
        ack_token: &str,
        review_digest: &str,
        verdict: &str,
        diagnosis: Option<&str>,
    ) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT command_key,request_digest FROM command_dedup
             WHERE consumer_id=?1 AND method='review_ack' AND response_locator=?2",
        )?;
        let bindings = statement
            .query_map(params![consumer_id, result_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let [(command_key, request_digest)] = bindings.as_slice() else {
            return Err(StorageError::Quarantined(format!(
                "review has ambiguous command binding: {result_id}"
            )));
        };
        if request_digest != review_digest || !is_lower_sha256(request_digest) {
            return Err(StorageError::Quarantined(format!(
                "review command digest is invalid: {result_id}"
            )));
        }
        let mut command = serde_json::json!({
            "version": 1,
            "kind": "command",
            "action": "review_ack",
            "command_key": command_key,
            "task_id": task_id,
            "result_id": result_id,
            "result_version": result_version,
            "ack_token": ack_token,
            "verdict": verdict,
        });
        if let Some(diagnosis) = diagnosis {
            command
                .as_object_mut()
                .expect("JSON object literal")
                .insert("diagnosis".into(), Value::String(diagnosis.to_owned()));
        }
        let canonical = crate::canonicalize(&command).map_err(|_| {
            StorageError::Quarantined(format!(
                "review cannot reconstruct canonical command: {result_id}"
            ))
        })?;
        let parsed = parse_review_ack_command(canonical.as_bytes()).map_err(|_| {
            StorageError::Quarantined(format!(
                "review reconstructs an invalid command: {result_id}"
            ))
        })?;
        if parsed.command_key != *command_key
            || parsed.task_id != task_id
            || parsed.result_id != result_id
            || parsed.result_version != result_version
            || !constant_time_eq(parsed.ack_token.as_bytes(), ack_token.as_bytes())
            || parsed.verdict.as_str() != verdict
            || parsed.diagnosis.as_deref() != diagnosis
            || hash_bytes(canonical.as_bytes()) != review_digest
        {
            return Err(StorageError::Quarantined(format!(
                "review command digest disagrees with semantic evidence: {result_id}"
            )));
        }
        Ok(())
    }

    fn recover_staged_blobs(&mut self, now_us: i64) -> Result<()> {
        let mut statement = self.conn.prepare("SELECT staging_id,file_name,expected_hash,byte_length FROM blob_staging ORDER BY created_at")?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for (staging_id, file_name, digest, length) in rows {
            let staged = self.root.join("blobs/.staging").join(file_name);
            let final_path = blob_path(&self.root, &digest);
            let expected =
                u64::try_from(length).map_err(|_| StorageError::BlobCorruption(digest.clone()))?;
            if final_path.is_file() {
                verify_blob(&final_path, &digest, expected)?;
                let tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute("INSERT OR IGNORE INTO blob_objects(hash,byte_length,published_at,last_verified_at) VALUES(?1,?2,?3,?3)", params![digest, length, now_us])?;
                tx.execute("DELETE FROM blob_staging WHERE staging_id=?1", [staging_id])?;
                tx.commit()?;
            } else if staged.is_file() {
                verify_blob(&staged, &digest, expected)?;
                self.filesystem
                    .create_relative_directories(final_path.parent().expect("blob parent"))?;
                self.filesystem.atomic_publish(&staged, &final_path)?;
                self.filesystem
                    .sync_parent(final_path.parent().expect("blob parent"))?;
                let tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute("INSERT OR IGNORE INTO blob_objects(hash,byte_length,published_at,last_verified_at) VALUES(?1,?2,?3,?3)", params![digest, length, now_us])?;
                tx.execute("DELETE FROM blob_staging WHERE staging_id=?1", [staging_id])?;
                tx.commit()?;
            } else {
                self.conn
                    .execute("DELETE FROM blob_staging WHERE staging_id=?1", [staging_id])?;
            }
        }
        Ok(())
    }

    fn replay_projections(&mut self, now_us: i64) -> Result<()> {
        let mut statement = self.conn.prepare("SELECT task_id,state,generation,last_event_seq,projection_event_seq,evicted_through_seq FROM tasks WHERE state NOT IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION') OR task_id IN (SELECT task_id FROM result_outbox WHERE acked_at IS NULL)")?;
        let tasks = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for (task_id, state, generation, last, projected, evicted) in tasks {
            if evicted != 0 {
                if projected != last {
                    return Err(StorageError::Quarantined(
                        "projection drift with incomplete event log".into(),
                    ));
                }
                continue;
            }
            let derived = derive_projection(&self.conn, &task_id)?;
            if derived.1 != generation || derived.2 != last {
                return Err(StorageError::Quarantined(
                    "event generation or sequence drift".into(),
                ));
            }
            let current = state
                .parse::<TaskState>()
                .map_err(|_| StorageError::Quarantined("unknown task projection".into()))?;
            if current == derived.0 && projected == last {
                continue;
            }
            if current.is_terminal() || derived.0.is_terminal() {
                return Err(StorageError::Quarantined(
                    "terminal tuple projection cannot be repaired".into(),
                ));
            }
            self.conn.execute(
                "UPDATE tasks SET state=?1,projection_event_seq=?2,updated_at=?3 WHERE task_id=?4",
                params![derived.0.as_str(), last, now_us, task_id],
            )?;
            self.conn.execute("INSERT INTO audit_log(kind,task_id,generation,details_digest,created_at) VALUES('PROJECTION_REPAIRED',?1,?2,?3,?4)", params![task_id, generation, digest_fields(&[state.as_str(), derived.0.as_str()]), now_us])?;
        }
        Ok(())
    }
}

fn compact_eligible_tasks(tx: &rusqlite::Transaction<'_>, now_us: i64) -> Result<()> {
    let cutoff = now_us.saturating_sub(90 * DAY_US);
    let compactable = {
        let mut statement = tx.prepare(
            "SELECT t.task_id,t.request_digest,t.state,t.last_event_seq,t.evicted_through_seq
             FROM tasks t JOIN result_outbox o ON o.task_id=t.task_id AND o.result_version=1
             WHERE o.acked_at IS NOT NULL AND t.terminal_at<=?1
               AND NOT EXISTS(SELECT 1 FROM reader_lease_items i JOIN reader_leases l ON l.lease_id=i.lease_id WHERE i.resource_kind='task' AND i.resource_id=t.task_id AND l.expires_at>?2)
               AND NOT EXISTS(SELECT 1 FROM worktrees w WHERE w.task_id=t.task_id AND w.state!='DELETED')
             ORDER BY t.terminal_at LIMIT 100",
        )?;
        statement
            .query_map(params![cutoff, now_us], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (task_id, request_digest, state, last, evicted) in compactable {
        let result: Option<(String, String)> = tx
            .query_row(
                "SELECT result_id,result_digest FROM results WHERE task_id=?1 AND result_version=1",
                [&task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        tx.execute("INSERT OR IGNORE INTO task_tombstones(task_id,request_digest,terminal_state,last_event_seq,evicted_through_seq,result_digest,summary,compacted_at) VALUES(?1,?2,?3,?4,MAX(?4,?5),?6,?3,?7)", params![task_id, request_digest, state, last, evicted, result.as_ref().map(|value| value.1.as_str()), now_us])?;
        tx.execute("DELETE FROM blob_refs WHERE owner_id=?1", [&task_id])?;
        // Request bodies are task-scoped and removed only with eligible,
        // acknowledged terminal compaction; command-key tombstones remain.
        tx.execute("DELETE FROM task_requests WHERE task_id=?1", [&task_id])?;
        if let Some((result_id, _)) = result {
            tx.execute("DELETE FROM blob_refs WHERE owner_id=?1", [result_id])?;
        }
        tx.execute(
            "DELETE FROM internal_operations WHERE task_id=?1",
            [&task_id],
        )?;
        tx.execute("DELETE FROM result_outbox WHERE task_id=?1", [&task_id])?;
        tx.execute("DELETE FROM reviews WHERE task_id=?1", [&task_id])?;
        tx.execute("DELETE FROM results WHERE task_id=?1", [&task_id])?;
        tx.execute("DELETE FROM events WHERE task_id=?1", [&task_id])?;
        tx.execute("DELETE FROM interaction_responses WHERE interaction_id IN (SELECT interaction_id FROM pending_interactions WHERE task_id=?1)", [&task_id])?;
        tx.execute(
            "DELETE FROM pending_interactions WHERE task_id=?1",
            [&task_id],
        )?;
        tx.execute("DELETE FROM attempts WHERE task_id=?1", [&task_id])?;
        tx.execute(
            "DELETE FROM worktrees WHERE task_id=?1 AND state='DELETED'",
            [&task_id],
        )?;
        tx.execute("DELETE FROM tasks WHERE task_id=?1", [&task_id])?;
        tx.execute("INSERT INTO audit_log(kind,task_id,details_digest,created_at) VALUES('TASK_COMPACTED',?1,?2,?3)", params![task_id, digest_fields(&[state.as_str(), &last.to_string()]), now_us])?;
    }
    Ok(())
}

fn verify_task_request_tx(
    tx: &rusqlite::Transaction<'_>,
    task_id: &str,
    digest: &str,
    expected_bytes: &[u8],
) -> Result<()> {
    let row: Option<(String, Vec<u8>, i64)> = tx
        .query_row(
            "SELECT request_digest,request_bytes,byte_length FROM task_requests WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((stored_digest, bytes, length)) = row else {
        let compacted: Option<String> = tx
            .query_row(
                "SELECT request_digest FROM task_tombstones WHERE task_id=?1",
                [task_id],
                |row| row.get(0),
            )
            .optional()?;
        if compacted.as_deref() == Some(digest)
            && format!("{:x}", Sha256::digest(expected_bytes)) == digest
        {
            // Request bytes are deliberately removed only with terminal
            // retention; the command tombstone remains replayable forever.
            return Ok(());
        }
        return Err(StorageError::Quarantined(
            "missing canonical task request".into(),
        ));
    };
    if stored_digest != digest
        || bytes != expected_bytes
        || length
            != i64::try_from(bytes.len())
                .map_err(|_| StorageError::Quarantined("task request length overflow".into()))?
        || format!("{:x}", Sha256::digest(&bytes)) != digest
    {
        return Err(StorageError::Quarantined(
            "canonical task request integrity mismatch".into(),
        ));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// SHA-256 evidence is serialized in its one canonical, lower-case hex form.
/// Accepting upper-case hex would make tampered rows semantically equivalent to
/// a different durable spelling and defeat byte-for-byte command binding.
fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Decodes canonical JSON without accepting a semantically equivalent but
/// differently encoded byte sequence. The original bytes are evidence and are
/// therefore the authority for their digest and replay identity.
fn parse_canonical_json(bytes: &[u8], maximum_bytes: usize) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(StorageError::InvalidRequest);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| StorageError::InvalidRequest)?;
    let canonical = crate::canonicalize(&value).map_err(|_| StorageError::InvalidRequest)?;
    if canonical.as_bytes() != bytes {
        return Err(StorageError::InvalidRequest);
    }
    Ok(value)
}

fn required_string(object: &serde_json::Map<String, Value>, key: &str) -> Result<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(StorageError::InvalidRequest)
}

fn required_i64(object: &serde_json::Map<String, Value>, key: &str) -> Result<i64> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(StorageError::InvalidRequest)
}

fn parse_interaction_response_value(value: &Value) -> Result<InteractionResponseKind> {
    let object = value.as_object().ok_or(StorageError::InvalidRequest)?;
    let kind = required_string(object, "kind")?;
    match kind.as_str() {
        "approve" if object.len() == 1 => Ok(InteractionResponseKind::Approve),
        "deny"
            if object.len() == 1
                || (object.len() == 2
                    && object
                        .get("reason")
                        .and_then(Value::as_str)
                        .is_some_and(|reason| reason.chars().count() <= 4096)) =>
        {
            Ok(InteractionResponseKind::Deny)
        }
        "text"
            if object.len() == 2
                && object
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| {
                        let length = text.chars().count();
                        (1..=32 * 1024).contains(&length)
                    }) =>
        {
            Ok(InteractionResponseKind::Text)
        }
        _ => Err(StorageError::InvalidRequest),
    }
}

fn parse_canonical_interaction_response(bytes: &[u8]) -> Result<InteractionResponseKind> {
    let value = parse_canonical_json(bytes, MAX_INTERACTION_RESPONSE_BYTES)?;
    parse_interaction_response_value(&value)
}

fn parse_interaction_response_command(bytes: &[u8]) -> Result<ParsedInteractionResponseCommand> {
    let value = parse_canonical_json(bytes, MAX_CANONICAL_TASK_REQUEST_BYTES)?;
    crate::decode_v1(value.clone()).map_err(|_| StorageError::InvalidRequest)?;
    let object = value.as_object().ok_or(StorageError::InvalidRequest)?;
    let response = object.get("response").ok_or(StorageError::InvalidRequest)?;
    let response_kind = parse_interaction_response_value(response)?;
    let response_bytes = crate::canonicalize(response)
        .map_err(|_| StorageError::InvalidRequest)?
        .into_bytes();
    if response_bytes.is_empty() || response_bytes.len() > MAX_INTERACTION_RESPONSE_BYTES {
        return Err(StorageError::InvalidRequest);
    }
    Ok(ParsedInteractionResponseCommand {
        command_key: required_string(object, "command_key")?,
        task_id: required_string(object, "task_id")?,
        interaction_id: required_string(object, "interaction_id")?,
        generation: required_i64(object, "generation")?,
        operation_digest: required_string(object, "operation_digest")?,
        policy_digest: required_string(object, "policy_digest")?,
        config_digest: required_string(object, "config_digest")?,
        nonce: required_string(object, "nonce")?,
        response_kind,
        response_bytes,
    })
}

fn validate_diagnosis(diagnosis: Option<&str>) -> Result<()> {
    if diagnosis.is_some_and(|text| text.chars().count() > MAX_DIAGNOSIS_CHARS) {
        return Err(StorageError::InvalidRequest);
    }
    Ok(())
}

fn parse_review_ack_command(bytes: &[u8]) -> Result<ParsedReviewAckCommand> {
    let value = parse_canonical_json(bytes, MAX_CANONICAL_TASK_REQUEST_BYTES)?;
    crate::decode_v1(value.clone()).map_err(|_| StorageError::InvalidRequest)?;
    let object = value.as_object().ok_or(StorageError::InvalidRequest)?;
    let diagnosis = match object.get("diagnosis") {
        Some(Value::String(text)) => Some(text.clone()),
        None => None,
        Some(_) => return Err(StorageError::InvalidRequest),
    };
    validate_diagnosis(diagnosis.as_deref())?;
    let verdict = required_string(object, "verdict")?
        .parse::<ReviewVerdict>()
        .map_err(|_| StorageError::InvalidRequest)?;
    Ok(ParsedReviewAckCommand {
        command_key: required_string(object, "command_key")?,
        task_id: required_string(object, "task_id")?,
        result_id: required_string(object, "result_id")?,
        result_version: required_i64(object, "result_version")?,
        ack_token: required_string(object, "ack_token")?,
        verdict,
        diagnosis,
    })
}

fn validate_interaction_metadata(
    interaction_id: &str,
    capability_class: Option<&str>,
    config_version: Option<i64>,
    policy_version: Option<i64>,
    adapter_instance_id: &str,
) -> Result<()> {
    if capability_class.is_none_or(|value| value.parse::<InteractionCapabilityClass>().is_err())
        || config_version.is_none_or(|version| version <= 0)
        || policy_version.is_none_or(|version| version <= 0)
        || adapter_instance_id.is_empty()
    {
        return Err(StorageError::Quarantined(format!(
            "invalid durable interaction metadata: {interaction_id}"
        )));
    }
    Ok(())
}

fn validate_interaction_response_metadata(
    interaction_id: &str,
    state: &str,
    consumer_id: Option<String>,
    decision_digest: Option<String>,
    response_kind: Option<String>,
    byte_length: Option<i64>,
    response_digest: Option<String>,
) -> Result<(String, InteractionResponseKind, usize, String)> {
    if state != InteractionState::Answered.as_str() {
        return Err(StorageError::Quarantined(format!(
            "response evidence belongs to a non-answered interaction: {interaction_id}"
        )));
    }
    let (
        Some(consumer_id),
        Some(decision_digest),
        Some(response_kind),
        Some(byte_length),
        Some(response_digest),
    ) = (
        consumer_id,
        decision_digest,
        response_kind,
        byte_length,
        response_digest,
    )
    else {
        return Err(StorageError::Quarantined(format!(
            "answered interaction has incomplete response evidence: {interaction_id}"
        )));
    };
    let byte_length = usize::try_from(byte_length)
        .ok()
        .filter(|length| (1..=MAX_INTERACTION_RESPONSE_BYTES).contains(length));
    let Some(byte_length) = byte_length else {
        return Err(StorageError::Quarantined(format!(
            "interaction response length is out of bounds: {interaction_id}"
        )));
    };
    let response_kind = response_kind
        .parse::<InteractionResponseKind>()
        .map_err(|_| {
            StorageError::Quarantined(format!(
                "invalid interaction response kind: {interaction_id}"
            ))
        })?;
    if consumer_id.is_empty()
        || decision_digest != response_digest
        || !is_lower_sha256(&response_digest)
    {
        return Err(StorageError::Quarantined(format!(
            "interaction response metadata mismatch: {interaction_id}"
        )));
    }
    Ok((consumer_id, response_kind, byte_length, response_digest))
}

fn build_interaction_response_evidence(
    interaction_id: &str,
    consumer_id: String,
    response_kind: InteractionResponseKind,
    byte_length: usize,
    response_digest: String,
    bytes: Option<Vec<u8>>,
) -> Result<InteractionResponseEvidence> {
    let Some(bytes) = bytes else {
        return Err(StorageError::Quarantined(format!(
            "interaction response bytes are missing: {interaction_id}"
        )));
    };
    if bytes.len() != byte_length || hash_bytes(&bytes) != response_digest {
        return Err(StorageError::Quarantined(format!(
            "interaction response integrity mismatch: {interaction_id}"
        )));
    }
    let decoded_kind = parse_canonical_interaction_response(&bytes).map_err(|_| {
        StorageError::Quarantined(format!(
            "interaction response bytes are not canonical protocol evidence: {interaction_id}"
        ))
    })?;
    if decoded_kind != response_kind {
        return Err(StorageError::Quarantined(format!(
            "interaction response kind disagrees with canonical evidence: {interaction_id}"
        )));
    }
    Ok(InteractionResponseEvidence {
        interaction_id: interaction_id.to_owned(),
        consumer_id,
        response_kind,
        response_digest,
        bytes,
    })
}

fn load_interaction_response_evidence(
    conn: &Connection,
    interaction_id: &str,
) -> Result<InteractionResponseEvidence> {
    let row: Option<InteractionResponseMetadataRow> = conn
        .query_row(
            "SELECT i.state,r.consumer_id,r.decision_digest,r.response_kind,r.byte_length,r.response_digest
             FROM pending_interactions i LEFT JOIN interaction_responses r ON r.interaction_id=i.interaction_id
             WHERE i.interaction_id=?1",
            [interaction_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((state, consumer_id, decision_digest, response_kind, byte_length, response_digest)) =
        row
    else {
        return Err(StorageError::InteractionConflict);
    };
    let (consumer_id, response_kind, byte_length, response_digest) =
        validate_interaction_response_metadata(
            interaction_id,
            &state,
            consumer_id,
            decision_digest,
            response_kind,
            byte_length,
            response_digest,
        )?;
    let bytes = conn
        .query_row(
            "SELECT response_bytes FROM interaction_responses WHERE interaction_id=?1",
            [interaction_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten();
    build_interaction_response_evidence(
        interaction_id,
        consumer_id,
        response_kind,
        byte_length,
        response_digest,
        bytes,
    )
}

/// Command dedup stores a digest rather than a second copy of the response
/// command. For answered interactions the command can be reconstructed exactly
/// from immutable interaction fields and the lossless response evidence; this
/// proves that the digest was not attached to a different semantic command.
fn verify_interaction_response_command_binding(
    conn: &Connection,
    evidence: &InteractionResponseEvidence,
) -> Result<()> {
    let context: Option<(String, i64, String, String, String, String)> = conn
        .query_row(
            "SELECT task_id,generation,nonce,operation_digest,policy_digest,config_digest
             FROM pending_interactions WHERE interaction_id=?1",
            [&evidence.interaction_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((task_id, generation, nonce, operation_digest, policy_digest, config_digest)) =
        context
    else {
        return Err(StorageError::Quarantined(format!(
            "answered interaction lacks durable context: {}",
            evidence.interaction_id
        )));
    };
    let mut statement = conn.prepare(
        "SELECT command_key,request_digest FROM command_dedup
         WHERE consumer_id=?1 AND method='interaction_response' AND response_locator=?2",
    )?;
    let bindings = statement
        .query_map(
            params![evidence.consumer_id, evidence.interaction_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);
    let [(command_key, request_digest)] = bindings.as_slice() else {
        return Err(StorageError::Quarantined(format!(
            "answered interaction has ambiguous command binding: {}",
            evidence.interaction_id
        )));
    };
    if !is_lower_sha256(request_digest) {
        return Err(StorageError::Quarantined(format!(
            "answered interaction has invalid command digest: {}",
            evidence.interaction_id
        )));
    }
    let response: Value = serde_json::from_slice(&evidence.bytes).map_err(|_| {
        StorageError::Quarantined(format!(
            "answered interaction has undecodable response evidence: {}",
            evidence.interaction_id
        ))
    })?;
    let command = serde_json::json!({
        "version": 1,
        "kind": "command",
        "action": "interaction_response",
        "command_key": command_key,
        "task_id": task_id,
        "interaction_id": evidence.interaction_id,
        "generation": generation,
        "operation_digest": operation_digest,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "nonce": nonce,
        "response": response,
    });
    let canonical = crate::canonicalize(&command).map_err(|_| {
        StorageError::Quarantined(format!(
            "answered interaction cannot reconstruct canonical command: {}",
            evidence.interaction_id
        ))
    })?;
    let parsed = parse_interaction_response_command(canonical.as_bytes()).map_err(|_| {
        StorageError::Quarantined(format!(
            "answered interaction reconstructs an invalid command: {}",
            evidence.interaction_id
        ))
    })?;
    if parsed.response_kind != evidence.response_kind
        || parsed.response_bytes != evidence.bytes
        || hash_bytes(canonical.as_bytes()) != *request_digest
    {
        return Err(StorageError::Quarantined(format!(
            "answered interaction command digest disagrees with evidence: {}",
            evidence.interaction_id
        )));
    }
    Ok(())
}

fn verify_interaction_response_replay_tx(
    tx: &rusqlite::Transaction<'_>,
    interaction_id: &str,
    consumer_id: &str,
    command: &ParsedInteractionResponseCommand,
) -> Result<()> {
    let row: Option<InteractionResponseMetadataRow> = tx
        .query_row(
            "SELECT i.state,r.consumer_id,r.decision_digest,r.response_kind,r.byte_length,r.response_digest
             FROM pending_interactions i LEFT JOIN interaction_responses r ON r.interaction_id=i.interaction_id
             WHERE i.interaction_id=?1",
            [interaction_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((
        state,
        stored_consumer,
        decision_digest,
        response_kind,
        byte_length,
        response_digest,
    )) = row
    else {
        return Err(StorageError::Quarantined(
            "interaction-response command points to a missing interaction".into(),
        ));
    };
    let (stored_consumer, response_kind, byte_length, response_digest) =
        validate_interaction_response_metadata(
            interaction_id,
            &state,
            stored_consumer,
            decision_digest,
            response_kind,
            byte_length,
            response_digest,
        )?;
    let bytes = tx
        .query_row(
            "SELECT response_bytes FROM interaction_responses WHERE interaction_id=?1",
            [interaction_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten();
    let evidence = build_interaction_response_evidence(
        interaction_id,
        stored_consumer,
        response_kind,
        byte_length,
        response_digest,
        bytes,
    )?;
    let context: Option<(String, i64, String, String, String, String)> = tx
        .query_row(
            "SELECT task_id,generation,nonce,operation_digest,policy_digest,config_digest
             FROM pending_interactions WHERE interaction_id=?1",
            [interaction_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((task_id, generation, nonce, operation_digest, policy_digest, config_digest)) =
        context
    else {
        return Err(StorageError::Quarantined(
            "interaction-response command has no durable interaction context".into(),
        ));
    };
    if evidence.consumer_id != consumer_id
        || command.interaction_id != interaction_id
        || command.task_id != task_id
        || command.generation != generation
        || command.nonce != nonce
        || command.operation_digest != operation_digest
        || command.policy_digest != policy_digest
        || command.config_digest != config_digest
        || evidence.response_kind != command.response_kind
        || evidence.bytes != command.response_bytes
    {
        return Err(StorageError::IdempotencyConflict);
    }
    Ok(())
}

fn verify_review_replay_tx(
    tx: &rusqlite::Transaction<'_>,
    consumer_id: &str,
    delivery: &ResultDelivery,
    review_digest: &str,
    verdict: ReviewVerdict,
    diagnosis_ref: Option<&str>,
) -> Result<()> {
    let row: Option<ReviewReplayRow> = tx
        .query_row(
            "SELECT o.result_id,o.ack_token,o.terminal_event_seq,t.state,o.acked_at,r.review_digest,r.verdict,r.diagnosis_ref
             FROM result_outbox o JOIN tasks t ON t.task_id=o.task_id
             LEFT JOIN reviews r ON r.review_id=o.review_id
             WHERE o.consumer_id=?1 AND o.task_id=?2 AND o.result_version=?3",
            params![consumer_id, delivery.task_id, delivery.result_version],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        )
        .optional()?;
    let Some((
        result_id,
        token,
        event_seq,
        terminal_state,
        acked_at,
        stored_digest,
        stored_verdict,
        stored_diagnosis,
    )) = row
    else {
        return Err(StorageError::Quarantined(
            "review command points to a missing result delivery".into(),
        ));
    };
    if result_id != delivery.result_id
        || event_seq != delivery.terminal_event_seq
        || terminal_state != delivery.terminal_state
        || !constant_time_eq(token.as_bytes(), delivery.ack_token.as_bytes())
        || acked_at.is_none()
    {
        return Err(StorageError::Quarantined(
            "review command points to an invalid result delivery".into(),
        ));
    }
    if stored_digest.as_deref() != Some(review_digest)
        || stored_verdict.as_deref() != Some(verdict.as_str())
        || stored_diagnosis.as_deref() != diagnosis_ref
    {
        return Err(StorageError::IdempotencyConflict);
    }
    Ok(())
}

#[cfg(test)]
fn directory_bytes(root: &Path) -> std::io::Result<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() && !entry.file_type()?.is_symlink() {
            total = total.saturating_add(directory_bytes(&entry.path())?);
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn command_replay(
    tx: &rusqlite::Transaction<'_>,
    consumer_id: &str,
    method: &str,
    command_key: &str,
    request_digest: &str,
) -> Result<Option<String>> {
    let row = tx.query_row("SELECT request_digest,response_locator FROM command_dedup WHERE consumer_id=?1 AND method=?2 AND command_key=?3", params![consumer_id, method, command_key], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).optional()?;
    match row {
        Some((stored, locator)) if stored == request_digest => Ok(Some(locator)),
        Some(_) => Err(StorageError::IdempotencyConflict),
        None => Ok(None),
    }
}

fn store_command(
    tx: &rusqlite::Transaction<'_>,
    consumer_id: &str,
    method: &str,
    command_key: &str,
    request_digest: &str,
    response_locator: &str,
    now_us: i64,
) -> Result<()> {
    tx.execute("INSERT INTO command_dedup(consumer_id,method,command_key,request_digest,response_locator,committed_at) VALUES(?1,?2,?3,?4,?5,?6)", params![consumer_id, method, command_key, request_digest, response_locator, now_us])?;
    Ok(())
}

fn internal_operation_replay(
    tx: &rusqlite::Transaction<'_>,
    operation_id: &str,
    operation_digest: &str,
) -> Result<Option<String>> {
    let row = tx.query_row("SELECT operation_digest,response_locator FROM internal_operations WHERE operation_id=?1", [operation_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).optional()?;
    match row {
        Some((stored, locator)) if stored == operation_digest => Ok(Some(locator)),
        Some(_) => Err(StorageError::IdempotencyConflict),
        None => Ok(None),
    }
}

fn load_attempt(tx: &rusqlite::Transaction<'_>, attempt_id: &str) -> Result<Attempt> {
    tx.query_row(
        "SELECT attempt_id,task_id,generation,ordinal FROM attempts WHERE attempt_id=?1",
        [attempt_id],
        |row| {
            Ok(Attempt {
                attempt_id: row.get(0)?,
                task_id: row.get(1)?,
                generation: row.get(2)?,
                ordinal: row.get(3)?,
            })
        },
    )
    .map_err(Into::into)
}

fn verify_attempt_assignment(
    tx: &rusqlite::Transaction<'_>,
    task_id: &str,
    spec: &AttemptSpec,
) -> Result<()> {
    let assignment: Option<(String, i64, String)> = tx
        .query_row(
            "SELECT case_id,config_version,config_digest FROM canary_assignments WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((case_id, config_version, config_digest)) = assignment else {
        return Ok(());
    };
    if config_version != spec.config_version || config_digest != spec.config_digest {
        return Err(StorageError::IdempotencyConflict);
    }
    let engine = load_improvement_engine(tx)?.ok_or_else(|| {
        StorageError::Quarantined("improvement engine missing for canary assignment".into())
    })?;
    let case = engine
        .case_snapshot(&case_id)
        .ok_or_else(|| StorageError::Quarantined("canary case missing".into()))?;
    if case.cohort.adapter_instance_id != spec.adapter_instance_id
        || case.cohort.adapter_version != spec.adapter_version
    {
        return Err(StorageError::IdempotencyConflict);
    }
    Ok(())
}

fn verify_existing_attempt_config(
    tx: &rusqlite::Transaction<'_>,
    attempt_id: &str,
    spec: &AttemptSpec,
) -> Result<()> {
    let stored: (String, String, i64, String) = tx.query_row(
        "SELECT adapter_instance_id,adapter_version,config_version,config_digest FROM attempts WHERE attempt_id=?1",
        [attempt_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if stored
        != (
            spec.adapter_instance_id.clone(),
            spec.adapter_version.clone(),
            spec.config_version,
            spec.config_digest.clone(),
        )
    {
        return Err(StorageError::IdempotencyConflict);
    }
    Ok(())
}

fn load_interaction(tx: &rusqlite::Transaction<'_>, interaction_id: &str) -> Result<Interaction> {
    let row: LoadedInteractionRow = tx.query_row(
        "SELECT i.interaction_id,i.task_id,i.attempt_id,a.adapter_instance_id,i.generation,i.nonce,
                i.capability_class,i.config_version,i.policy_version
         FROM pending_interactions i JOIN attempts a ON a.attempt_id=i.attempt_id AND a.task_id=i.task_id AND a.generation=i.generation
         WHERE i.interaction_id=?1",
        [interaction_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        },
    )?;
    let (
        interaction_id,
        task_id,
        attempt_id,
        adapter_instance_id,
        generation,
        nonce,
        capability_class,
        config_version,
        policy_version,
    ) = row;
    validate_interaction_metadata(
        &interaction_id,
        capability_class.as_deref(),
        config_version,
        policy_version,
        &adapter_instance_id,
    )?;
    let capability_class = capability_class
        .ok_or_else(|| StorageError::Quarantined("missing interaction capability class".into()))?
        .parse()
        .map_err(|_| StorageError::Quarantined("invalid interaction capability class".into()))?;
    let config_version = config_version
        .ok_or_else(|| StorageError::Quarantined("missing interaction config version".into()))?;
    let policy_version = policy_version
        .ok_or_else(|| StorageError::Quarantined("missing interaction policy version".into()))?;
    Ok(Interaction {
        interaction_id,
        task_id,
        attempt_id,
        adapter_instance_id,
        generation,
        nonce,
        capability_class,
        config_version,
        policy_version,
    })
}

fn latest_answered_response_kind(
    conn: &Connection,
    task_id: &str,
    generation: i64,
) -> Result<Option<String>> {
    conn.query_row(
        "SELECT r.response_kind FROM pending_interactions i
         JOIN interaction_responses r ON r.interaction_id=i.interaction_id
         WHERE i.task_id=?1 AND i.generation=?2 AND i.state='ANSWERED'
         ORDER BY i.updated_at DESC, i.interaction_id LIMIT 1",
        params![task_id, generation],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn load_delivery(
    tx: &rusqlite::Transaction<'_>,
    consumer_id: &str,
    result_id: &str,
) -> Result<ResultDelivery> {
    tx.query_row("SELECT o.task_id,o.result_id,o.result_version,o.ack_token,o.terminal_event_seq,t.state FROM result_outbox o JOIN tasks t ON t.task_id=o.task_id WHERE o.consumer_id=?1 AND o.result_id=?2", params![consumer_id, result_id], |row| Ok(ResultDelivery { task_id: row.get(0)?, result_id: row.get(1)?, result_version: row.get(2)?, ack_token: row.get(3)?, terminal_event_seq: row.get(4)?, terminal_state: row.get(5)? })).map_err(Into::into)
}

fn bump_mutation_epoch(tx: &rusqlite::Transaction<'_>, now_us: i64) -> Result<()> {
    tx.execute("UPDATE storage_meta SET mutation_epoch=mutation_epoch+1,updated_at=MAX(updated_at,?1) WHERE singleton=1", [now_us])?;
    Ok(())
}

fn validate_improvement_time(now_us: i64) -> Result<()> {
    if (0..=MAX_SAFE_TIME_US).contains(&now_us) {
        Ok(())
    } else {
        Err(StorageError::InvalidRequest)
    }
}

fn validate_improvement_propose_command(
    canonical_command: &[u8],
    command_key: &str,
    proposal: &CandidateProposal,
) -> Result<()> {
    let expected = json!({
        "version": 1,
        "kind": "command",
        "action": "improvement_propose",
        "command_key": command_key,
        "case_id": &proposal.case_id,
        "knob": proposal.knob.as_str(),
        "value": &proposal.value,
        "hypothesis": &proposal.hypothesis,
        "fixtures": proposal.fixtures.iter().map(|fixture| json!({
            "fixture_id": &fixture.fixture_id,
            "passed": fixture.passed,
            "hard_invariant_failures": fixture.hard_invariant_failures,
        })).collect::<Vec<_>>(),
    });
    let canonical_expected =
        crate::canonicalize(&expected).map_err(|_| StorageError::InvalidRequest)?;
    if canonical_expected.as_bytes() != canonical_command {
        return Err(StorageError::InvalidRequest);
    }
    Ok(())
}

fn validate_improvement_rollback_command(
    canonical_command: &[u8],
    command_key: &str,
    case_id: &str,
    target_config_version: i64,
) -> Result<()> {
    let expected = json!({
        "version": 1,
        "kind": "command",
        "action": "improvement_rollback",
        "command_key": command_key,
        "case_id": case_id,
        "target_config_version": target_config_version,
    });
    let canonical_expected =
        crate::canonicalize(&expected).map_err(|_| StorageError::InvalidRequest)?;
    if canonical_expected.as_bytes() != canonical_command {
        return Err(StorageError::InvalidRequest);
    }
    Ok(())
}

fn improvement_command_replay<T: DeserializeOwned>(
    connection: &Connection,
    consumer_id: &str,
    method: &str,
    command_key: &str,
    request_digest: &str,
    response_locator: &str,
) -> Result<Option<T>> {
    let row: Option<(String, String, Option<String>, Option<String>)> = connection
        .query_row(
            "SELECT request_digest,response_locator,response_json,response_digest FROM command_dedup
             WHERE consumer_id=?1 AND method=?2 AND command_key=?3",
            params![consumer_id, method, command_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((stored_digest, stored_locator, response_json, stored_response_digest)) = row else {
        return Ok(None);
    };
    if stored_digest != request_digest || stored_locator != response_locator {
        return Err(StorageError::IdempotencyConflict);
    }
    let response_json = response_json.ok_or_else(|| {
        StorageError::Quarantined("improvement command replay lacks response evidence".into())
    })?;
    if stored_response_digest.as_deref() != Some(hash_bytes(response_json.as_bytes()).as_str()) {
        return Err(StorageError::Quarantined(
            "improvement command response integrity mismatch".into(),
        ));
    }
    let value = serde_json::from_str(&response_json)
        .map_err(|_| StorageError::Quarantined("improvement command response is invalid".into()))?;
    Ok(Some(value))
}

type ImprovementCaseProjection = (String, String, i64, Option<String>, i64, Option<i64>, u32);
type ReviewObservationRow = (
    String,
    String,
    String,
    i64,
    String,
    String,
    i64,
    Option<i64>,
);
type ReclaimAttemptRow = (String, i64, String, String, String, String, i64, String);
type ImprovementCandidateProjection = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    String,
    bool,
    bool,
);

pub(crate) fn load_improvement_engine(
    connection: &Connection,
) -> Result<Option<ImprovementEngine>> {
    let row: Option<(i64, String, String)> = connection
        .query_row(
            "SELECT revision,state_json,state_digest FROM improvement_engine_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((revision, state_json, state_digest)) = row else {
        return Ok(None);
    };
    if revision < 1
        || !is_lower_sha256(&state_digest)
        || hash_bytes(state_json.as_bytes()) != state_digest
    {
        return Err(StorageError::Quarantined(
            "improvement snapshot integrity mismatch".into(),
        ));
    }
    let engine = ImprovementEngine::from_snapshot_json(&state_json)
        .map_err(|_| StorageError::Quarantined("invalid improvement snapshot".into()))?;
    verify_improvement_projection(connection, &engine)?;
    Ok(Some(engine))
}

fn verify_improvement_projection(
    connection: &Connection,
    engine: &ImprovementEngine,
) -> Result<()> {
    let projection = engine.durable_projection();
    let (revision, state_digest): (i64, String) = connection.query_row(
        "SELECT revision,state_digest FROM improvement_engine_state WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let audit: Option<(i64, String, i64)> = connection
        .query_row(
            "SELECT revision,state_digest,(SELECT COUNT(*) FROM improvement_audit)
             FROM improvement_audit ORDER BY revision DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if audit != Some((revision, state_digest, revision)) {
        return Err(StorageError::Quarantined(
            "improvement audit revision drift".into(),
        ));
    }

    let case_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM improvement_cases", [], |row| {
            row.get(0)
        })?;
    if usize::try_from(case_count).ok() != Some(projection.cases.len()) {
        return Err(StorageError::Quarantined(
            "improvement case projection drift".into(),
        ));
    }
    for case in &projection.cases {
        let stored: Option<ImprovementCaseProjection> =
            connection
                .query_row(
                    "SELECT component,state,created_at,candidate_id,parent_config_version,canary_started_at,rollback_count
                     FROM improvement_cases WHERE case_id=?1",
                    [&case.case_id],
                    |row| {
                        Ok((
                            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                            row.get(5)?, row.get(6)?,
                        ))
                    },
                )
                .optional()?;
        if stored
            != Some((
                case.component.clone(),
                case.state.as_str().into(),
                case.created_at_us,
                case.candidate_id.clone(),
                case.parent_config_version,
                case.canary_started_at_us,
                case.rollback_count,
            ))
        {
            return Err(StorageError::Quarantined(
                "improvement case projection drift".into(),
            ));
        }
    }

    let candidate_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM improvement_candidates", [], |row| {
            row.get(0)
        })?;
    let config_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM improvement_config_versions",
        [],
        |row| row.get(0),
    )?;
    if usize::try_from(candidate_count).ok() != Some(projection.candidates.len())
        || config_count != candidate_count
    {
        return Err(StorageError::Quarantined(
            "improvement candidate projection drift".into(),
        ));
    }
    for candidate in &projection.candidates {
        let stored: Option<ImprovementCandidateProjection> =
            connection
                .query_row(
                    "SELECT case_id,component,knob,value_json,parent_config_version,rollback_config_version,
                            candidate_config_version,candidate_config_digest,fixture_gate_passed,fixture_hard_failure
                     FROM improvement_candidates WHERE candidate_id=?1",
                    [&candidate.candidate_id],
                    |row| {
                        Ok((
                            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                            row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                        ))
                    },
                )
                .optional()?;
        if stored
            != Some((
                candidate.case_id.clone(),
                candidate.component.clone(),
                candidate.knob.as_str().into(),
                candidate.value.to_string(),
                candidate.parent_config_version,
                candidate.rollback_config_version,
                candidate.candidate_config_version,
                candidate.candidate_config_digest.clone(),
                candidate.fixture_gate_passed,
                candidate.fixture_hard_failure,
            ))
        {
            return Err(StorageError::Quarantined(
                "improvement candidate projection drift".into(),
            ));
        }
        let config: Option<(String, String, i64, i64, String)> = connection
            .query_row(
                "SELECT digest,component,parent_version,rollback_version,candidate_id
                 FROM improvement_config_versions WHERE version=?1",
                [candidate.candidate_config_version],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if config
            != Some((
                candidate.candidate_config_digest.clone(),
                candidate.component.clone(),
                candidate.parent_config_version,
                candidate.rollback_config_version,
                candidate.candidate_id.clone(),
            ))
        {
            return Err(StorageError::Quarantined(
                "improvement config projection drift".into(),
            ));
        }
    }

    let assignment_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM canary_assignments", [], |row| {
            row.get(0)
        })?;
    if usize::try_from(assignment_count).ok() != Some(projection.assignments.len()) {
        return Err(StorageError::Quarantined(
            "canary assignment projection drift".into(),
        ));
    }
    for assignment in &projection.assignments {
        let stored: Option<(String, bool, i64, String)> = connection
            .query_row(
                "SELECT case_id,candidate,config_version,config_digest FROM canary_assignments WHERE task_id=?1",
                [&assignment.task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if stored
            != Some((
                assignment.case_id.clone(),
                assignment.candidate,
                assignment.config_version,
                assignment.config_digest.clone(),
            ))
        {
            return Err(StorageError::Quarantined(
                "canary assignment projection drift".into(),
            ));
        }
    }

    let active_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM improvement_active_configs",
        [],
        |row| row.get(0),
    )?;
    if usize::try_from(active_count).ok() != Some(projection.active_config_versions.len()) {
        return Err(StorageError::Quarantined(
            "active improvement config projection drift".into(),
        ));
    }
    for (component, version) in &projection.active_config_versions {
        let stored: Option<i64> = connection
            .query_row(
                "SELECT config_version FROM improvement_active_configs WHERE component=?1",
                [component],
                |row| row.get(0),
            )
            .optional()?;
        if stored != Some(*version) {
            return Err(StorageError::Quarantined(
                "active improvement config projection drift".into(),
            ));
        }
    }
    Ok(())
}

fn digest_fields(fields: &[&str]) -> String {
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

/// The single occupancy predicate shared by the writer's claim transaction and
/// the reader pool's recomputation.
///
/// Counts only process-bearing or slot-reserved states: `PREPARING`, `RUNNING`,
/// `FINALIZING`, `CANCEL_REQUESTED`, and runtime `WAITING_APPROVAL` (an
/// approval wait whose attempt has a started process). Preflight
/// `WAITING_APPROVAL` (no process yet), `QUEUED`, and timer-only `RETRY_WAIT`
/// do not consume a slot. A `CANCEL_REQUESTED` task cancelled from `QUEUED`
/// has no attempt row and is excluded by the join, because it owns no process.
pub(crate) const OCCUPANCY_SQL: &str = r"
SELECT a.adapter_instance_id,COUNT(*)
FROM attempts a
JOIN tasks t ON t.task_id=a.task_id AND t.generation=a.generation
WHERE t.state IN ('PREPARING','RUNNING','FINALIZING','CANCEL_REQUESTED')
   OR (t.state='WAITING_APPROVAL' AND a.dispatch_phase IN ('PROCESS_STARTED','PROVIDER_OBSERVED'))
GROUP BY a.adapter_instance_id";

/// Deterministically recomputes occupancy from the passed transaction. No
/// process-evidence guessing: only committed `SQLite` rows participate.
pub(crate) fn read_occupancy(tx: &rusqlite::Transaction<'_>) -> Result<Occupancy> {
    let mut statement = tx.prepare(OCCUPANCY_SQL)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(statement);
    let mut occupancy = Occupancy::default();
    for (adapter, count) in rows {
        let count = u32::try_from(count)
            .map_err(|_| StorageError::Quarantined("occupancy count overflow".into()))?;
        *occupancy.per_adapter.entry(adapter).or_insert(0) += count;
        occupancy.global = occupancy
            .global
            .checked_add(count)
            .ok_or_else(|| StorageError::Quarantined("occupancy overflow".into()))?;
    }
    Ok(occupancy)
}

fn verify_migration_checksums(conn: &Connection) -> Result<()> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
        row.get(0)
    })?;
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if count != SCHEMA_VERSION || user_version != SCHEMA_VERSION {
        return Err(StorageError::MigrationMismatch(
            "migration cardinality".into(),
        ));
    }
    let stored: String = conn.query_row(
        "SELECT checksum FROM schema_migrations WHERE version=1",
        [],
        |row| row.get(0),
    )?;
    if stored != migration_1_checksum() {
        return Err(StorageError::MigrationMismatch("migration 1".into()));
    }
    let stored: String = conn.query_row(
        "SELECT checksum FROM schema_migrations WHERE version=2",
        [],
        |row| row.get(0),
    )?;
    if stored != migration_2_checksum() {
        return Err(StorageError::MigrationMismatch("migration 2".into()));
    }
    let stored: String = conn.query_row(
        "SELECT checksum FROM schema_migrations WHERE version=3",
        [],
        |row| row.get(0),
    )?;
    if stored != migration_3_checksum() {
        return Err(StorageError::MigrationMismatch("migration 3".into()));
    }
    let stored: String = conn.query_row(
        "SELECT checksum FROM schema_migrations WHERE version=4",
        [],
        |row| row.get(0),
    )?;
    if stored != migration_4_checksum() {
        return Err(StorageError::MigrationMismatch("migration 4".into()));
    }
    let stored: String = conn.query_row(
        "SELECT checksum FROM schema_migrations WHERE version=5",
        [],
        |row| row.get(0),
    )?;
    if stored != migration_5_checksum() {
        return Err(StorageError::MigrationMismatch("migration 5".into()));
    }
    let stored: String = conn.query_row(
        "SELECT checksum FROM schema_migrations WHERE version=6",
        [],
        |row| row.get(0),
    )?;
    if stored != migration_6_checksum() {
        return Err(StorageError::MigrationMismatch("migration 6".into()));
    }
    let stored: String = conn.query_row(
        "SELECT checksum FROM schema_migrations WHERE version=7",
        [],
        |row| row.get(0),
    )?;
    if stored != migration_7_checksum() {
        return Err(StorageError::MigrationMismatch("migration 7".into()));
    }
    Ok(())
}

fn derive_projection(conn: &Connection, task_id: &str) -> Result<(TaskState, i64, i64)> {
    let mut state = TaskState::Queued;
    let mut generation = 0_i64;
    let mut last = 0_i64;
    let mut statement = conn.prepare(
        "SELECT event_seq,generation,kind,payload FROM events WHERE task_id=?1 ORDER BY event_seq",
    )?;
    let rows = statement.query_map([task_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (seq, event_generation, kind, payload) = row?;
        if seq != last + 1 {
            return Err(StorageError::Quarantined("event sequence gap".into()));
        }
        last = seq;
        generation = event_generation;
        state = match kind.as_str() {
            "state_changed" | "terminal" => serde_json::from_str::<serde_json::Value>(&payload)
                .ok()
                .and_then(|value| value["state"].as_str().and_then(|value| value.parse().ok()))
                .ok_or_else(|| StorageError::Quarantined("invalid state event payload".into()))?,
            "SUBMITTED" | "QUEUED" => TaskState::Queued,
            "attempt_started" | "ATTEMPT_STARTED" | "PREPARING" => TaskState::Preparing,
            "interaction_requested" | "INTERACTION_OPENED" | "WAITING_APPROVAL" => {
                TaskState::WaitingApproval
            }
            "interaction_decided"
            | "dispatch_phase"
            | "INTERACTION_ANSWERED"
            | "DISPATCH_PHASE"
            | "RUNNING" => TaskState::Running,
            "CANCEL_REQUESTED" => TaskState::CancelRequested,
            "RETRY_SCHEDULED" | "RETRY_WAIT" => TaskState::RetryWait,
            "FINALIZING" => TaskState::Finalizing,
            "SUCCEEDED" => TaskState::Succeeded,
            "FAILED" => TaskState::Failed,
            "CANCELLED" => TaskState::Cancelled,
            "NEEDS_ATTENTION" => TaskState::NeedsAttention,
            _ => state,
        };
    }
    Ok((state, generation, last))
}

fn validate_data_root(root: &Path) -> Result<PathBuf> {
    if !root.exists() || !root.is_dir() {
        return Err(StorageError::InvalidRoot(root.to_path_buf()));
    }
    let canonical = root.canonicalize()?;
    if fs::symlink_metadata(&canonical)?.file_type().is_symlink() {
        return Err(StorageError::InvalidRoot(canonical));
    }
    Ok(canonical)
}

fn is_terminal(state: &str) -> bool {
    matches!(
        state,
        "SUCCEEDED" | "FAILED" | "CANCELLED" | "NEEDS_ATTENTION"
    )
}
fn random_token() -> String {
    let mut b = [0_u8; 32];
    rand::rng().fill_bytes(&mut b);
    let mut token = String::with_capacity(64);
    for byte in b {
        write!(&mut token, "{byte:02x}").expect("writing to String is infallible");
    }
    token
}
fn blob_path(root: &Path, digest: &str) -> PathBuf {
    if !valid_digest(digest) {
        return root.join("blobs/invalid");
    }
    root.join("blobs/sha256")
        .join(&digest[0..2])
        .join(&digest[2..4])
        .join(digest)
}

fn valid_digest(digest: &str) -> bool {
    is_lower_sha256(digest)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let width = left.len().max(right.len());
    for index in 0..width {
        difference |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    difference == 0
}
fn verify_blob(path: &Path, digest: &str, length: u64) -> Result<()> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0; 8192];
    let mut n = 0;
    loop {
        let c = f.read(&mut buf)?;
        if c == 0 {
            break;
        }
        n += c as u64;
        h.update(&buf[..c]);
    }
    if n != length || format!("{:x}", h.finalize()) != digest {
        return Err(StorageError::BlobCorruption(digest.to_owned()));
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Restores a verified migration snapshot while the daemon is stopped.
///
/// The injected platform filesystem must provide replace-existing atomic
/// publication. The current database is preserved as a verified rescue copy.
#[cfg(test)]
pub(crate) fn restore_backup_offline(
    root: &Path,
    manifest: &BackupManifest,
    expected_install_id: &str,
    filesystem: &dyn DurableFilesystem,
) -> Result<PathBuf> {
    let root = validate_data_root(root)?;
    filesystem.validate_data_root(&root)?;
    let current_path = root.join("mesh.sqlite3");
    let current = Connection::open(&current_path)?;
    let app: i64 = current.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let (schema, install_id, epoch): (i64, String, i64) = current.query_row(
        "SELECT schema_version,install_id,mutation_epoch FROM storage_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if app != i64::from(MESH_SQLITE_APPLICATION_ID)
        || schema != manifest.source_schema
        || install_id != expected_install_id
        || install_id != manifest.install_id
        || epoch != manifest.mutation_epoch
    {
        return Err(StorageError::RestoreRefused);
    }
    let snapshot_component = Path::new(&manifest.snapshot_file);
    if snapshot_component.components().count() != 1
        || !matches!(
            snapshot_component.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(StorageError::RestoreRefused);
    }
    let snapshot = root.join("backups").join(snapshot_component);
    let manifest_path = root
        .join("backups")
        .join(format!("{}.manifest.json", manifest.backup_id));
    let published: BackupManifest = serde_json::from_reader(File::open(&manifest_path)?)
        .map_err(|error| StorageError::MigrationMismatch(error.to_string()))?;
    let recorded: Option<(String, i64)> = current.query_row(
        "SELECT database_sha256,mutation_epoch FROM migration_backups WHERE backup_id=?1 AND manifest_path=?2",
        params![manifest.backup_id, manifest_path.to_string_lossy()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    if published != *manifest
        || recorded != Some((manifest.database_sha256.clone(), manifest.mutation_epoch))
        || hash_file(&snapshot)? != manifest.database_sha256
    {
        return Err(StorageError::RestoreRefused);
    }
    let snapshot_connection =
        Connection::open_with_flags(&snapshot, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let quick: String =
        snapshot_connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(StorageError::RestoreRefused);
    }
    drop(snapshot_connection);
    current.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    let rescue = root
        .join("backups")
        .join(format!("rescue-{}.sqlite3", Uuid::new_v4()));
    current.backup(rusqlite::MAIN_DB, &rescue, None)?;
    drop(current);
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&rescue)?
        .sync_all()?;

    let staged = root.join("mesh.sqlite3.restore.tmp");
    fs::copy(&snapshot, &staged)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&staged)?
        .sync_all()?;
    if hash_file(&staged)? != manifest.database_sha256 {
        return Err(StorageError::RestoreRefused);
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = root.join(format!("mesh.sqlite3{suffix}"));
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    filesystem.atomic_publish(&staged, &current_path)?;
    filesystem.sync_parent(&root)?;
    Ok(rescue)
}

fn append_event(
    tx: &rusqlite::Transaction<'_>,
    task_id: &str,
    generation: i64,
    kind: &str,
    payload: &str,
    now: i64,
) -> Result<i64> {
    let seq:i64=tx.query_row("UPDATE tasks SET last_event_seq=last_event_seq+1,projection_event_seq=last_event_seq+1 WHERE task_id=?1 RETURNING last_event_seq",[task_id],|r|r.get(0))?;
    tx.execute("INSERT INTO events(task_id,event_seq,event_id,generation,kind,payload,committed_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![task_id,seq,Uuid::new_v4().to_string(),generation,kind,payload,now])?;
    Ok(seq)
}

fn state_event_payload(state: &str) -> String {
    serde_json::json!({"state": state}).to_string()
}

fn usage_token_cost(connection: &Connection, task_id: &str) -> Result<Option<u64>> {
    let mut statement = connection.prepare(
        "SELECT payload FROM events WHERE task_id=?1 AND kind='usage' ORDER BY event_seq",
    )?;
    let mut rows = statement.query([task_id])?;
    let mut total = 0_u64;
    let mut count = 0_usize;
    while let Some(row) = rows.next()? {
        let payload: String = row.get(0)?;
        let value: Value = match serde_json::from_str(&payload) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let Some(object) = value.as_object() else {
            return Ok(None);
        };
        let Some(input) = object.get("input_tokens").and_then(Value::as_u64) else {
            return Ok(None);
        };
        let Some(output) = object.get("output_tokens").and_then(Value::as_u64) else {
            return Ok(None);
        };
        total = match total
            .checked_add(input)
            .and_then(|value| value.checked_add(output))
        {
            Some(value) => value,
            None => return Ok(None),
        };
        count += 1;
    }
    Ok((count != 0).then_some(total))
}

fn terminal_event_payload(state: &str, result_id: &str) -> String {
    serde_json::json!({"state": state, "result_id": result_id}).to_string()
}

fn interaction_requested_event_payload(interaction_id: &str) -> String {
    serde_json::json!({"interaction_id": interaction_id}).to_string()
}

fn interaction_decided_event_payload(
    interaction_id: &str,
    status: &str,
    response_kind: Option<InteractionResponseKind>,
) -> String {
    match response_kind {
        Some(response_kind) => serde_json::json!({
            "interaction_id": interaction_id,
            "status": status,
            "response_kind": response_kind.as_str(),
        })
        .to_string(),
        None => serde_json::json!({"interaction_id": interaction_id, "status": status}).to_string(),
    }
}

const MIGRATION_1_SQL: &str = r"
CREATE TABLE storage_meta(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL,
  application_id INTEGER NOT NULL, install_id TEXT NOT NULL,
  lease_epoch INTEGER NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),
  mutation_epoch INTEGER NOT NULL DEFAULT 0 CHECK(mutation_epoch>=0),
  storage_mode TEXT NOT NULL DEFAULT 'PORTABLE_TEST' CHECK(storage_mode IN ('PORTABLE_TEST','WINDOWS_LOCAL_NTFS_VALIDATED')),
  required_feature_bits INTEGER NOT NULL DEFAULT 0 CHECK(required_feature_bits>=0),
  emergency_state TEXT NOT NULL DEFAULT 'NORMAL' CHECK(emergency_state IN ('NORMAL','LATCHED','RESERVE_RELEASED')),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, binary_version TEXT NOT NULL DEFAULT '0.1.0', destructive INTEGER NOT NULL DEFAULT 0 CHECK(destructive IN (0,1)), applied_at INTEGER NOT NULL) STRICT;
CREATE TABLE command_dedup(
  consumer_id TEXT NOT NULL, method TEXT NOT NULL, command_key TEXT NOT NULL,
  request_digest TEXT NOT NULL, response_locator TEXT NOT NULL, committed_at INTEGER NOT NULL,
  response_kind TEXT NOT NULL DEFAULT 'LOCATOR', outcome TEXT NOT NULL DEFAULT 'COMMITTED', response_json TEXT,
  PRIMARY KEY(consumer_id,method,command_key)
) WITHOUT ROWID, STRICT;
CREATE TABLE tasks(
  task_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
  retry_of_task_id TEXT,
  state TEXT NOT NULL CHECK(state IN ('QUEUED','PREPARING','RUNNING','WAITING_APPROVAL','RETRY_WAIT','CANCEL_REQUESTED','FINALIZING','SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')),
  generation INTEGER NOT NULL CHECK(generation>=0), last_event_seq INTEGER NOT NULL DEFAULT 0 CHECK(last_event_seq>=0),
  projection_event_seq INTEGER NOT NULL DEFAULT 0 CHECK(projection_event_seq>=0 AND projection_event_seq<=last_event_seq),
  evicted_through_seq INTEGER NOT NULL DEFAULT 0 CHECK(evicted_through_seq>=0 AND evicted_through_seq<=last_event_seq),
  result_version INTEGER CHECK(result_version IS NULL OR result_version=1), terminal_event_seq INTEGER,
  terminal_at INTEGER, cancel_requested_at INTEGER, retry_at INTEGER,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  CHECK(
    (state IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION') AND result_version=1 AND terminal_event_seq IS NOT NULL AND terminal_at IS NOT NULL)
    OR
    (state NOT IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION') AND result_version IS NULL AND terminal_event_seq IS NULL AND terminal_at IS NULL)
  )
) STRICT;
CREATE TABLE events(
  task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
  event_seq INTEGER NOT NULL CHECK(event_seq>0), event_id TEXT NOT NULL UNIQUE,
  generation INTEGER NOT NULL CHECK(generation>=0), kind TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)),
  committed_at INTEGER NOT NULL, PRIMARY KEY(task_id,event_seq)
) WITHOUT ROWID, STRICT;
CREATE TABLE attempts(
  attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
  generation INTEGER NOT NULL CHECK(generation>=0), ordinal INTEGER NOT NULL CHECK(ordinal>0),
  state TEXT NOT NULL CHECK(state IN ('PREPARING','RUNNING','WAITING_APPROVAL','RETRY_WAIT','CANCEL_REQUESTED','FINALIZING','SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')),
  dispatch_phase TEXT NOT NULL CHECK(dispatch_phase IN ('PRE_DISPATCH','SPAWN_PREPARED','PROCESS_STARTED','PROVIDER_OBSERVED')),
  process_receipt TEXT, provider_session TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, ended_at INTEGER,
  effect_profile TEXT NOT NULL DEFAULT 'READ_ONLY', isolation_level TEXT NOT NULL DEFAULT 'NONE',
  retry_class TEXT NOT NULL DEFAULT 'NEVER', adapter_instance_id TEXT NOT NULL DEFAULT '',
  adapter_version TEXT NOT NULL DEFAULT '', config_digest TEXT NOT NULL DEFAULT '', worktree_id TEXT,
  UNIQUE(task_id,generation), UNIQUE(task_id,ordinal), UNIQUE(attempt_id,task_id,generation)
) STRICT;
CREATE TABLE pending_interactions(
  interaction_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, attempt_id TEXT NOT NULL, generation INTEGER NOT NULL,
  operation_digest TEXT NOT NULL, policy_digest TEXT NOT NULL DEFAULT '', config_digest TEXT NOT NULL DEFAULT '',
  nonce TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('PENDING','ANSWERED','EXPIRED','CANCELLED')),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  FOREIGN KEY(attempt_id,task_id,generation) REFERENCES attempts(attempt_id,task_id,generation) ON DELETE CASCADE
) STRICT;
CREATE TABLE interaction_responses(
  interaction_id TEXT NOT NULL REFERENCES pending_interactions(interaction_id) ON DELETE RESTRICT,
  consumer_id TEXT NOT NULL, decision_digest TEXT NOT NULL, committed_at INTEGER NOT NULL,
  PRIMARY KEY(interaction_id,consumer_id), UNIQUE(interaction_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE results(
  task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
  result_version INTEGER NOT NULL CHECK(result_version=1), result_id TEXT NOT NULL UNIQUE,
  terminal_event_seq INTEGER NOT NULL, result_digest TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY(task_id,result_version), FOREIGN KEY(task_id,terminal_event_seq) REFERENCES events(task_id,event_seq) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;
CREATE TABLE reviews(
  review_id TEXT PRIMARY KEY, consumer_id TEXT NOT NULL, task_id TEXT NOT NULL,
  result_version INTEGER NOT NULL CHECK(result_version=1), review_digest TEXT NOT NULL,
  verdict TEXT NOT NULL DEFAULT 'UNSPECIFIED', diagnosis_ref TEXT, created_at INTEGER NOT NULL,
  UNIQUE(consumer_id,task_id,result_version),
  FOREIGN KEY(task_id,result_version) REFERENCES results(task_id,result_version) ON DELETE RESTRICT
) STRICT;
CREATE TABLE result_outbox(
  consumer_id TEXT NOT NULL, task_id TEXT NOT NULL, result_version INTEGER NOT NULL CHECK(result_version=1),
  result_id TEXT NOT NULL, ack_token TEXT NOT NULL CHECK(length(ack_token)=64), terminal_event_seq INTEGER NOT NULL,
  created_at INTEGER NOT NULL, acked_at INTEGER, review_id TEXT UNIQUE REFERENCES reviews(review_id) ON DELETE RESTRICT,
  PRIMARY KEY(consumer_id,task_id,result_version), UNIQUE(consumer_id,result_id),
  FOREIGN KEY(task_id,result_version) REFERENCES results(task_id,result_version) ON DELETE RESTRICT,
  FOREIGN KEY(task_id,terminal_event_seq) REFERENCES events(task_id,event_seq) ON DELETE RESTRICT
) WITHOUT ROWID, STRICT;
CREATE TABLE internal_operations(
  operation_id TEXT PRIMARY KEY, operation_digest TEXT NOT NULL, task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
  generation INTEGER NOT NULL CHECK(generation>=0), kind TEXT NOT NULL, response_locator TEXT NOT NULL, committed_at INTEGER NOT NULL
) STRICT;
CREATE TABLE task_tombstones(
  task_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, terminal_state TEXT NOT NULL,
  last_event_seq INTEGER NOT NULL, evicted_through_seq INTEGER NOT NULL,
  result_digest TEXT, summary TEXT, compacted_at INTEGER NOT NULL
) STRICT;
CREATE TABLE blob_objects(hash TEXT PRIMARY KEY CHECK(length(hash)=64), byte_length INTEGER NOT NULL CHECK(byte_length>=0),
  media_type TEXT NOT NULL DEFAULT 'application/octet-stream', schema_id TEXT NOT NULL DEFAULT 'opaque-v1', redaction_profile TEXT NOT NULL DEFAULT 'default-v1',
  published_at INTEGER NOT NULL, last_verified_at INTEGER NOT NULL) STRICT;
CREATE TABLE blob_refs(
  owner_kind TEXT NOT NULL, owner_id TEXT NOT NULL, field TEXT NOT NULL,
  hash TEXT NOT NULL REFERENCES blob_objects(hash) ON DELETE RESTRICT, eligible_at INTEGER,
  PRIMARY KEY(owner_kind,owner_id,field)
) WITHOUT ROWID, STRICT;
CREATE TABLE blob_staging(
  staging_id TEXT PRIMARY KEY, file_name TEXT NOT NULL UNIQUE, expected_hash TEXT NOT NULL CHECK(length(expected_hash)=64),
  byte_length INTEGER NOT NULL CHECK(byte_length>=0), state TEXT NOT NULL CHECK(state IN ('WRITING','PUBLISHED')),
  created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE reader_leases(lease_id TEXT PRIMARY KEY, lease_epoch INTEGER NOT NULL, owner_id TEXT NOT NULL DEFAULT '', issued_at INTEGER NOT NULL DEFAULT 0, heartbeat_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE reader_lease_items(
  lease_id TEXT NOT NULL REFERENCES reader_leases(lease_id) ON DELETE CASCADE,
  resource_kind TEXT NOT NULL, resource_id TEXT NOT NULL,
  PRIMARY KEY(lease_id,resource_kind,resource_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE gc_intents(
  resource_kind TEXT NOT NULL, resource_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('MARKED','DELETED','FAILED')), byte_length INTEGER NOT NULL DEFAULT 0,
  fence_token TEXT NOT NULL CHECK(length(fence_token)=64),
  eligible_at INTEGER NOT NULL DEFAULT 0, deadline_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
  marked_at INTEGER NOT NULL, finished_at INTEGER, error_digest TEXT,
  PRIMARY KEY(resource_kind,resource_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE worktrees(
  worktree_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE RESTRICT,
  path TEXT NOT NULL UNIQUE, terminal_state TEXT, terminal_at INTEGER, acked_at INTEGER,
  state TEXT NOT NULL CHECK(state IN ('ACTIVE','RETAINED','GC_MARKED','DELETED')), created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE audit_log(
  audit_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, task_id TEXT, generation INTEGER,
  details_digest TEXT NOT NULL, created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE migration_backups(
  backup_id TEXT PRIMARY KEY, manifest_path TEXT NOT NULL UNIQUE, source_schema INTEGER NOT NULL,
  database_sha256 TEXT NOT NULL, mutation_epoch INTEGER NOT NULL, created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE config_versions(version INTEGER PRIMARY KEY,config_digest TEXT NOT NULL,created_at INTEGER NOT NULL) STRICT;
CREATE TABLE improvement_cases(case_id TEXT PRIMARY KEY,component TEXT NOT NULL,state TEXT NOT NULL,created_at INTEGER NOT NULL) STRICT;
CREATE TRIGGER terminal_tasks_are_immutable BEFORE UPDATE OF state,generation,result_version,terminal_event_seq,terminal_at ON tasks
WHEN OLD.state IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')
BEGIN SELECT RAISE(ABORT,'terminal task is immutable'); END;
CREATE TRIGGER terminal_attempts_are_immutable BEFORE UPDATE OF state,generation,dispatch_phase,process_receipt,provider_session,ended_at ON attempts
WHEN OLD.state IN ('SUCCEEDED','FAILED','CANCELLED','NEEDS_ATTENTION')
BEGIN SELECT RAISE(ABORT,'terminal attempt is immutable'); END;
CREATE INDEX events_task_committed ON events(task_id,event_seq);
CREATE INDEX attempts_nonterminal ON attempts(state,task_id,generation);
CREATE INDEX outbox_unacked ON result_outbox(consumer_id,acked_at,created_at);
CREATE INDEX leases_expiry ON reader_leases(expires_at);
CREATE INDEX blob_refs_hash ON blob_refs(hash);
";

fn migration_1_checksum() -> String {
    format!("sha256:{:x}", Sha256::digest(MIGRATION_1_SQL.as_bytes()))
}

const MIGRATION_2_SQL: &str = r"
ALTER TABLE attempts ADD COLUMN resumable_capability_digest TEXT;
ALTER TABLE attempts ADD COLUMN resume_proof_digest TEXT;
";

fn migration_2_checksum() -> String {
    format!("sha256:{:x}", Sha256::digest(MIGRATION_2_SQL.as_bytes()))
}

const MIGRATION_3_SQL: &str = r"
CREATE TABLE task_requests(
  task_id TEXT PRIMARY KEY REFERENCES tasks(task_id) ON DELETE RESTRICT,
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
  request_bytes BLOB NOT NULL, byte_length INTEGER NOT NULL CHECK(byte_length>0),
  created_at INTEGER NOT NULL
) STRICT;
";

fn migration_3_checksum() -> String {
    format!("sha256:{:x}", Sha256::digest(MIGRATION_3_SQL.as_bytes()))
}

const MIGRATION_4_SQL: &str = r"
ALTER TABLE pending_interactions ADD COLUMN capability_class TEXT;
ALTER TABLE pending_interactions ADD COLUMN config_version INTEGER;
ALTER TABLE pending_interactions ADD COLUMN policy_version INTEGER;
ALTER TABLE interaction_responses ADD COLUMN response_kind TEXT;
ALTER TABLE interaction_responses ADD COLUMN response_bytes BLOB;
ALTER TABLE interaction_responses ADD COLUMN byte_length INTEGER;
ALTER TABLE interaction_responses ADD COLUMN response_digest TEXT;
";

fn migration_4_checksum() -> String {
    format!("sha256:{:x}", Sha256::digest(MIGRATION_4_SQL.as_bytes()))
}

const MIGRATION_5_SQL: &str = r"
ALTER TABLE tasks ADD COLUMN priority INTEGER NOT NULL DEFAULT 0 CHECK(priority BETWEEN 0 AND 9);
ALTER TABLE tasks ADD COLUMN adapter_instance_id TEXT NOT NULL DEFAULT '';
";

fn migration_5_checksum() -> String {
    format!("sha256:{:x}", Sha256::digest(MIGRATION_5_SQL.as_bytes()))
}

const MIGRATION_6_SQL: &str = r"
ALTER TABLE improvement_cases ADD COLUMN candidate_id TEXT;
ALTER TABLE improvement_cases ADD COLUMN parent_config_version INTEGER NOT NULL DEFAULT 1 CHECK(parent_config_version>=0);
ALTER TABLE improvement_cases ADD COLUMN canary_started_at INTEGER;
ALTER TABLE improvement_cases ADD COLUMN rollback_count INTEGER NOT NULL DEFAULT 0 CHECK(rollback_count>=0);
CREATE TABLE improvement_engine_state(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL CHECK(revision>=1),
  state_json TEXT NOT NULL CHECK(json_valid(state_json)), state_digest TEXT NOT NULL CHECK(length(state_digest)=64),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE improvement_candidates(
  candidate_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES improvement_cases(case_id) ON DELETE RESTRICT,
  component TEXT NOT NULL, knob TEXT NOT NULL, value_json TEXT NOT NULL CHECK(json_valid(value_json)),
  parent_config_version INTEGER NOT NULL CHECK(parent_config_version>=0),
  rollback_config_version INTEGER NOT NULL CHECK(rollback_config_version>=0),
  candidate_config_version INTEGER NOT NULL UNIQUE CHECK(candidate_config_version>=1),
  candidate_config_digest TEXT NOT NULL UNIQUE CHECK(length(candidate_config_digest)=64),
  fixture_gate_passed INTEGER NOT NULL CHECK(fixture_gate_passed IN (0,1)),
  fixture_hard_failure INTEGER NOT NULL CHECK(fixture_hard_failure IN (0,1)), created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE improvement_config_versions(
  version INTEGER PRIMARY KEY CHECK(version>=1), digest TEXT NOT NULL UNIQUE CHECK(length(digest)=64),
  component TEXT NOT NULL, parent_version INTEGER NOT NULL CHECK(parent_version>=0),
  rollback_version INTEGER NOT NULL CHECK(rollback_version>=0), candidate_id TEXT NOT NULL UNIQUE
    REFERENCES improvement_candidates(candidate_id) ON DELETE RESTRICT, created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE canary_assignments(
  task_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES improvement_cases(case_id) ON DELETE RESTRICT,
  candidate INTEGER NOT NULL CHECK(candidate IN (0,1)), config_version INTEGER NOT NULL CHECK(config_version>=0),
  config_digest TEXT NOT NULL, assigned_at INTEGER NOT NULL
) STRICT;
CREATE TABLE improvement_active_configs(
  component TEXT PRIMARY KEY, config_version INTEGER NOT NULL CHECK(config_version>=0), updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE improvement_audit(
  audit_id INTEGER PRIMARY KEY, revision INTEGER NOT NULL UNIQUE CHECK(revision>=1), action TEXT NOT NULL,
  state_digest TEXT NOT NULL CHECK(length(state_digest)=64), created_at INTEGER NOT NULL
) STRICT;
CREATE TRIGGER improvement_case_state_insert BEFORE INSERT ON improvement_cases
WHEN NEW.state NOT IN ('OBSERVING','CANARY','PROMOTED','ROLLED_BACK','FROZEN')
BEGIN SELECT RAISE(ABORT,'invalid improvement state'); END;
CREATE TRIGGER improvement_case_state_update BEFORE UPDATE OF state ON improvement_cases
WHEN NEW.state NOT IN ('OBSERVING','CANARY','PROMOTED','ROLLED_BACK','FROZEN')
BEGIN SELECT RAISE(ABORT,'invalid improvement state'); END;
CREATE UNIQUE INDEX improvement_one_active_component ON improvement_cases(component)
WHERE state IN ('OBSERVING','CANARY');
";

fn migration_6_checksum() -> String {
    format!("sha256:{:x}", Sha256::digest(MIGRATION_6_SQL.as_bytes()))
}

const MIGRATION_7_SQL: &str = r"
ALTER TABLE attempts ADD COLUMN config_version INTEGER NOT NULL DEFAULT 1 CHECK(config_version>=1);
ALTER TABLE command_dedup ADD COLUMN response_digest TEXT;
";

fn migration_7_checksum() -> String {
    format!("sha256:{:x}", Sha256::digest(MIGRATION_7_SQL.as_bytes()))
}

fn migrate(conn: &mut Connection, install_id: &str, now: i64) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    let existing: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if existing > SCHEMA_VERSION {
        return Err(StorageError::Quarantined(
            "database schema is newer than this binary".into(),
        ));
    }
    if existing == 0 {
        tx.execute_batch(MIGRATION_1_SQL)?;
        tx.execute(
            "INSERT INTO storage_meta(singleton,schema_version,application_id,install_id,lease_epoch,mutation_epoch,emergency_state,created_at,updated_at) VALUES(1,?1,?2,?3,0,0,'NORMAL',?4,?4)",
            params![1_i64, MESH_SQLITE_APPLICATION_ID, install_id, now],
        )?;
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(1,?1,?2)",
            params![migration_1_checksum(), now],
        )?;
        tx.pragma_update(None, "user_version", 1_i64)?;
    }
    if existing <= 1 {
        tx.execute_batch(MIGRATION_2_SQL)?;
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(2,?1,?2)",
            params![migration_2_checksum(), now],
        )?;
        tx.execute(
            "UPDATE storage_meta SET schema_version=2 WHERE singleton=1",
            [],
        )?;
        tx.pragma_update(None, "user_version", 2_i64)?;
    }
    if existing <= 2 {
        tx.execute_batch(MIGRATION_3_SQL)?;
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(3,?1,?2)",
            params![migration_3_checksum(), now],
        )?;
        tx.execute(
            "UPDATE storage_meta SET schema_version=3 WHERE singleton=1",
            [],
        )?;
        tx.pragma_update(None, "user_version", 3_i64)?;
    }
    if existing <= 3 {
        tx.execute_batch(MIGRATION_4_SQL)?;
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(4,?1,?2)",
            params![migration_4_checksum(), now],
        )?;
        tx.execute(
            "UPDATE storage_meta SET schema_version=4 WHERE singleton=1",
            [],
        )?;
        tx.pragma_update(None, "user_version", 4_i64)?;
    }
    if existing <= 4 {
        tx.execute_batch(MIGRATION_5_SQL)?;
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(5,?1,?2)",
            params![migration_5_checksum(), now],
        )?;
        tx.execute(
            "UPDATE storage_meta SET schema_version=5 WHERE singleton=1",
            [],
        )?;
        tx.pragma_update(None, "user_version", 5_i64)?;
    }
    if existing <= 5 {
        tx.execute_batch(MIGRATION_6_SQL)?;
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(6,?1,?2)",
            params![migration_6_checksum(), now],
        )?;
        tx.execute(
            "UPDATE storage_meta SET schema_version=6 WHERE singleton=1",
            [],
        )?;
        tx.pragma_update(None, "user_version", 6_i64)?;
    }
    if existing <= 6 {
        tx.execute_batch(MIGRATION_7_SQL)?;
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(7,?1,?2)",
            params![migration_7_checksum(), now],
        )?;
        tx.execute(
            "UPDATE storage_meta SET schema_version=7 WHERE singleton=1",
            [],
        )?;
        tx.pragma_update(None, "user_version", 7_i64)?;
    }
    let (app, stored_install, required_features): (i64, String, i64) = tx.query_row(
        "SELECT application_id,install_id,required_feature_bits FROM storage_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if app != i64::from(MESH_SQLITE_APPLICATION_ID)
        || stored_install != install_id
        || required_features != 0
    {
        return Err(StorageError::Quarantined(
            "foreign application database or install identity".into(),
        ));
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::Command, sync::Mutex, time::Duration};

    const OPERATION_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const POLICY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CONFIG_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const OTHER_OPERATION_DIGEST: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const OTHER_CONFIG_DIGEST: &str =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
    fn store() -> Storage {
        let t = temp();
        let p = t.keep();
        Storage::open(p, "install", 1).unwrap()
    }

    fn canonical(value: &Value) -> Vec<u8> {
        crate::canonicalize(value).unwrap().into_bytes()
    }

    fn interaction_response_command(
        command_key: &str,
        interaction: &Interaction,
        response: &Value,
    ) -> (Vec<u8>, Vec<u8>, InteractionResponseKind) {
        let response_bytes = canonical(response);
        let response_kind = parse_interaction_response_value(response).unwrap();
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
        (canonical(&command), response_bytes, response_kind)
    }

    fn review_ack_command(
        command_key: &str,
        delivery: &ResultDelivery,
        verdict: ReviewVerdict,
        diagnosis: Option<&str>,
    ) -> Vec<u8> {
        let mut command = serde_json::json!({
            "version": 1,
            "kind": "command",
            "action": "review_ack",
            "command_key": command_key,
            "task_id": delivery.task_id,
            "result_id": delivery.result_id,
            "result_version": delivery.result_version,
            "ack_token": delivery.ack_token,
            "verdict": verdict.as_str(),
        });
        if let Some(diagnosis) = diagnosis {
            command
                .as_object_mut()
                .unwrap()
                .insert("diagnosis".into(), Value::String(diagnosis.to_owned()));
        }
        canonical(&command)
    }
    fn ready_to_finalize(storage: &mut Storage, task_id: &str, now: i64) {
        storage
            .begin_attempt("c", &format!("begin-{task_id}"), "begin", task_id, 0, now)
            .unwrap();
        storage
            .transition(
                &format!("finalizing-{task_id}"),
                task_id,
                0,
                &["PREPARING"],
                "FINALIZING",
                now + 1,
            )
            .unwrap();
    }

    fn acknowledged_task_with_artifacts() -> (Storage, String) {
        let mut storage = store();
        storage
            .submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        let attempt = storage
            .begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        let interaction = storage
            .open_interaction(
                "open",
                "task",
                &attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                100,
                3,
            )
            .unwrap();
        let (response_command, response_bytes, response_kind) = interaction_response_command(
            "response",
            &interaction,
            &serde_json::json!({"kind": "approve"}),
        );
        storage
            .respond_interaction(
                "c",
                "response",
                &response_command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                response_kind,
                &response_bytes,
                5,
            )
            .unwrap();
        let worktree = storage.root.join("worktree");
        fs::create_dir(&worktree).unwrap();
        storage
            .register_worktree("worktree", "task", worktree.to_str().unwrap(), 5)
            .unwrap();
        storage
            .transition("finalizing", "task", 0, &["RUNNING"], "FINALIZING", 6)
            .unwrap();
        let delivery = storage
            .finalize(
                "c",
                "finish",
                "finish",
                "task",
                0,
                "SUCCEEDED",
                "result",
                10,
            )
            .unwrap();
        let blob = storage.publish_blob(b"result body", 11).unwrap();
        storage
            .reference_blob("result", &delivery.result_id, "body", &blob, 11)
            .unwrap();
        let review_command = review_ack_command("ack", &delivery, ReviewVerdict::Accepted, None);
        storage
            .review_and_ack(
                "c",
                "ack",
                &review_command,
                &delivery,
                ReviewVerdict::Accepted,
                None,
                12,
            )
            .unwrap();
        (storage, blob)
    }
    #[test]
    fn dedup_conflict_and_terminal_tuple() {
        let mut s = store();
        let a = s.submit("c", "submit", "k", "d", "t", None, 2).unwrap();
        assert!(!a.replayed);
        assert!(
            s.submit("c", "submit", "k", "other", "t2", None, 3)
                .is_err()
        );
        ready_to_finalize(&mut s, "t", 4);
        let r = s
            .finalize("c", "finish", "finish", "t", 0, "SUCCEEDED", "digest", 6)
            .unwrap();
        s.integrity_check().unwrap();
        assert_eq!(s.unacked("c").unwrap(), vec![r]);
    }
    #[test]
    fn ack_is_exact_and_idempotent() {
        let mut s = store();
        s.submit("c", "submit", "k", "d", "t", None, 1).unwrap();
        ready_to_finalize(&mut s, "t", 2);
        let r = s
            .finalize("c", "finish", "finish", "t", 0, "FAILED", "d", 4)
            .unwrap();
        let command = review_ack_command("a", &r, ReviewVerdict::Accepted, None);
        assert!(
            !s.review_and_ack("c", "a", &command, &r, ReviewVerdict::Accepted, None, 3)
                .unwrap()
        );
        let second_command = review_ack_command("a2", &r, ReviewVerdict::Accepted, None);
        assert!(
            s.review_and_ack(
                "c",
                "a2",
                &second_command,
                &r,
                ReviewVerdict::Accepted,
                None,
                4
            )
            .is_err()
        );
        assert!(
            s.review_and_ack("c", "a", &command, &r, ReviewVerdict::Accepted, None, 4)
                .unwrap()
        );
    }

    #[test]
    fn review_semantics_are_bound_to_canonical_command_and_verified_on_reopen() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        {
            let mut storage = Storage::open(&root, "install", 1).unwrap();
            storage
                .submit_with_request("c", "submit", "k", b"task", "task", None, 0, None, 2)
                .unwrap();
            ready_to_finalize(&mut storage, "task", 3);
            let delivery = storage
                .finalize("c", "finish", "finish", "task", 0, "SUCCEEDED", "result", 5)
                .unwrap();
            let diagnosis = "根因\nsecond line";
            let command = review_ack_command(
                "review",
                &delivery,
                ReviewVerdict::Rejected,
                Some(diagnosis),
            );
            assert!(
                !storage
                    .review_and_ack(
                        "c",
                        "review",
                        &command,
                        &delivery,
                        ReviewVerdict::Rejected,
                        Some(diagnosis),
                        6,
                    )
                    .unwrap()
            );
            assert!(matches!(
                storage.review_and_ack(
                    "c",
                    "review",
                    &command,
                    &delivery,
                    ReviewVerdict::Accepted,
                    Some(diagnosis),
                    7,
                ),
                Err(StorageError::IdempotencyConflict)
            ));
            assert!(
                storage
                    .review_and_ack(
                        "c",
                        "review",
                        &command,
                        &delivery,
                        ReviewVerdict::Rejected,
                        Some(diagnosis),
                        7,
                    )
                    .unwrap()
            );
            let other_command =
                review_ack_command("other-key", &delivery, ReviewVerdict::Accepted, None);
            assert!(matches!(
                storage.review_and_ack(
                    "c",
                    "other-key",
                    &other_command,
                    &delivery,
                    ReviewVerdict::Accepted,
                    None,
                    8,
                ),
                Err(StorageError::AlreadyReviewed)
            ));
            let row: (String, String, Option<String>) = storage
                .conn
                .query_row(
                    "SELECT review_digest,verdict,diagnosis_ref FROM reviews WHERE task_id='task'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(row.0, hash_bytes(&command));
            assert_eq!(row.1, "REJECTED");
            assert_eq!(row.2.as_deref(), Some(diagnosis));
        }
        let reopened = Storage::open(&root, "install", 9).unwrap();
        let stored_diagnosis: Option<String> = reopened
            .conn
            .query_row(
                "SELECT diagnosis_ref FROM reviews WHERE task_id='task'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_diagnosis.as_deref(), Some("根因\nsecond line"));
        drop(reopened);
        let connection = Connection::open(root.join("mesh.sqlite3")).unwrap();
        connection
            .execute("UPDATE reviews SET verdict='UNSPECIFIED'", [])
            .unwrap();
        drop(connection);
        assert!(matches!(
            Storage::open(&root, "install", 10),
            Err(StorageError::Quarantined(_))
        ));
    }

    #[test]
    fn review_ack_derives_one_normalized_observation_from_persisted_attempt() {
        let mut storage = store();
        storage
            .ensure_improvement_engine(
                ImprovementPolicy {
                    enabled: true,
                    ..ImprovementPolicy::default()
                },
                1,
            )
            .unwrap();
        storage
            .submit(
                "consumer",
                "mesh.delegate_task",
                "submit",
                "request",
                "observed-task",
                None,
                2,
            )
            .unwrap();
        let spec = AttemptSpec {
            adapter_instance_id: "adapter-main".into(),
            adapter_version: "1.0.0".into(),
            config_version: 1,
            config_digest: CONFIG_DIGEST.into(),
            ..AttemptSpec::default()
        };
        storage
            .begin_attempt_with_spec("consumer", "begin", "request", "observed-task", 0, &spec, 3)
            .unwrap();
        storage
            .transition(
                "finalizing-observed-task",
                "observed-task",
                0,
                &["PREPARING"],
                "FINALIZING",
                5,
            )
            .unwrap();
        let delivery = storage
            .finalize(
                "consumer",
                "finish",
                "finish-request",
                "observed-task",
                0,
                "FAILED",
                "result-observed",
                6,
            )
            .unwrap();
        let command = review_ack_command(
            "review-observed",
            &delivery,
            ReviewVerdict::Rejected,
            Some("provider returned an invalid response"),
        );
        storage
            .review_and_ack(
                "consumer",
                "review-observed",
                &command,
                &delivery,
                ReviewVerdict::Rejected,
                Some("provider returned an invalid response"),
                7,
            )
            .unwrap();
        let snapshot = load_improvement_engine(&storage.conn)
            .unwrap()
            .unwrap()
            .snapshot_json()
            .unwrap();
        assert!(snapshot.contains("observed-task"));
        assert!(!snapshot.contains("provider returned an invalid response"));
        assert!(snapshot.contains("diag-"));
    }

    #[test]
    fn ack_rejects_a_delivery_with_a_stale_terminal_tuple_member() {
        let mut s = store();
        s.submit("c", "submit", "k", "d", "t", None, 1).unwrap();
        ready_to_finalize(&mut s, "t", 2);
        let delivery = s
            .finalize("c", "finish", "finish", "t", 0, "FAILED", "d", 4)
            .unwrap();
        let mut wrong_sequence = delivery.clone();
        wrong_sequence.terminal_event_seq += 1;
        let wrong_sequence_command =
            review_ack_command("ack", &wrong_sequence, ReviewVerdict::Accepted, None);
        assert!(matches!(
            s.review_and_ack(
                "c",
                "ack",
                &wrong_sequence_command,
                &wrong_sequence,
                ReviewVerdict::Accepted,
                None,
                5,
            ),
            Err(StorageError::AckMismatch)
        ));
        let mut wrong_state = delivery.clone();
        wrong_state.terminal_state = "SUCCEEDED".into();
        let wrong_state_command =
            review_ack_command("ack-2", &wrong_state, ReviewVerdict::Accepted, None);
        assert!(matches!(
            s.review_and_ack(
                "c",
                "ack-2",
                &wrong_state_command,
                &wrong_state,
                ReviewVerdict::Accepted,
                None,
                5,
            ),
            Err(StorageError::AckMismatch)
        ));
        let command = review_ack_command("ack-3", &delivery, ReviewVerdict::Accepted, None);
        assert!(
            !s.review_and_ack(
                "c",
                "ack-3",
                &command,
                &delivery,
                ReviewVerdict::Accepted,
                None,
                5,
            )
            .unwrap()
        );
    }
    #[test]
    fn cursor_compaction_has_exact_boundary() {
        let mut s = store();
        s.submit("c", "submit", "k", "d", "t", None, 1).unwrap();
        s.begin_attempt("c", "begin", "begin", "t", 0, 2).unwrap();
        s.compact_events_through("t", 1).unwrap();
        assert!(matches!(
            s.events_after("t", 0, 2),
            Err(StorageError::CursorExpired { .. })
        ));
        assert_eq!(s.events_after("t", 1, 2).unwrap().events.len(), 1);
    }
    #[test]
    fn blob_is_verified() {
        let mut s = store();
        let d = s.publish_blob(b"hello", 1).unwrap();
        assert_eq!(s.read_blob(&d).unwrap(), b"hello");
        fs::write(blob_path(s.root(), &d), b"bad").unwrap();
        assert!(s.read_blob(&d).is_err());
    }

    #[test]
    fn referenced_blob_is_verified_and_shared_without_refcount_mutation() {
        let mut s = store();
        let digest = s.publish_blob(b"shared", 1).unwrap();
        s.reference_blob("result", "one", "body", &digest, 2)
            .unwrap();
        s.reference_blob("result", "two", "body", &digest, 2)
            .unwrap();
        s.verify_mandatory_blob_refs().unwrap();
        fs::remove_file(blob_path(s.root(), &digest)).unwrap();
        assert!(matches!(
            s.verify_mandatory_blob_refs(),
            Err(StorageError::Io(_))
        ));
    }

    #[test]
    fn marked_gc_fences_new_leases_and_live_leases_fence_gc() {
        let mut s = store();
        let digest = s.publish_blob(b"lease", 1).unwrap();
        let epoch = s.current_lease_epoch().unwrap();
        let issued = DAY_US;
        s.acquire_lease("l", "blob", &digest, epoch, issued)
            .unwrap();
        assert!(
            s.mark_retention_gc(issued + LEASE_TTL_US - 1)
                .unwrap()
                .is_empty()
        );
        let candidates = s.mark_retention_gc(issued + LEASE_TTL_US).unwrap();
        assert_eq!(candidates.len(), 1);
        assert!(
            s.acquire_lease("later", "blob", &digest, epoch, issued + LEASE_TTL_US + 100)
                .is_err()
        );
        assert_eq!(
            s.prepare_gc_deletion("blob", &digest).unwrap().candidate,
            candidates[0]
        );
    }

    #[test]
    fn lease_uses_fixed_ttl_and_rejects_late_heartbeat_or_old_epoch() {
        let mut s = store();
        let digest = s.publish_blob(b"lease", 1).unwrap();
        let epoch = s.current_lease_epoch().unwrap();
        s.acquire_lease("l", "blob", &digest, epoch, 100).unwrap();
        s.acquire_lease("l", "blob", &digest, epoch, 100 + LEASE_HEARTBEAT_US)
            .unwrap();
        assert!(matches!(
            s.acquire_lease(
                "l",
                "blob",
                &digest,
                epoch,
                100 + LEASE_HEARTBEAT_US * 2 + 1
            ),
            Err(StorageError::StaleGeneration)
        ));
        assert!(matches!(
            s.acquire_lease("old", "blob", &digest, epoch - 1, 101),
            Err(StorageError::StaleGeneration)
        ));
    }

    #[test]
    fn pressure_errors_are_classified_fail_closed() {
        assert!(!Storage::is_storage_pressure(&StorageError::QuotaExceeded));
        assert!(Storage::is_storage_pressure(&StorageError::Io(
            std::io::Error::from(std::io::ErrorKind::StorageFull)
        )));
        assert!(!Storage::is_storage_pressure(
            &StorageError::StaleGeneration
        ));
    }

    #[test]
    fn terminal_event_payload_is_json_and_digest_paths_never_panic() {
        let mut s = store();
        s.submit("c", "submit", "k", "d", "t", None, 1).unwrap();
        ready_to_finalize(&mut s, "t", 2);
        let delivery = s
            .finalize("c", "finish", "finish", "t", 0, "SUCCEEDED", "d", 4)
            .unwrap();
        let page = s.events_after("t", 0, 10).unwrap();
        let terminal = page
            .events
            .iter()
            .find(|event| event.1 == "terminal")
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&terminal.2).unwrap()["result_id"],
            delivery.result_id
        );
        assert!(s.read_blob("not-a-digest").is_err());
    }

    #[test]
    fn terminal_event_result_id_mismatch_is_quarantined_on_reopen() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        {
            let mut storage = Storage::open(&root, "install", 1).unwrap();
            storage
                .submit_with_request("c", "submit", "k", b"task", "task", None, 0, None, 2)
                .unwrap();
            ready_to_finalize(&mut storage, "task", 3);
            storage
                .finalize("c", "finish", "finish", "task", 0, "SUCCEEDED", "result", 5)
                .unwrap();
        }
        let connection = Connection::open(root.join("mesh.sqlite3")).unwrap();
        connection
            .execute(
                "UPDATE events SET payload='{\"state\":\"SUCCEEDED\",\"result_id\":\"wrong\"}' WHERE task_id='task' AND kind='terminal'",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            Storage::open(&root, "install", 6),
            Err(StorageError::Quarantined(_))
        ));
    }

    #[test]
    fn state_machine_generation_fences_stale_callbacks_and_terminal_retry_links() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "parent", None, 1)
            .unwrap();
        s.begin_attempt("c", "begin", "begin", "parent", 0, 2)
            .unwrap();
        s.record_dispatch_phase(
            "prepared",
            "parent",
            0,
            DispatchPhase::SpawnPrepared,
            None,
            3,
        )
        .unwrap();
        assert_eq!(
            s.schedule_safe_retry("retry", "parent", 0, 10, 4).unwrap(),
            1
        );
        assert!(matches!(
            s.record_dispatch_phase(
                "late",
                "parent",
                0,
                DispatchPhase::ProcessStarted,
                Some("old"),
                5
            ),
            Err(StorageError::StaleGeneration)
        ));
        s.begin_attempt("c", "begin-2", "begin-2", "parent", 1, 10)
            .unwrap();
        s.transition("finalizing", "parent", 1, &["PREPARING"], "FINALIZING", 11)
            .unwrap();
        let delivery = s
            .finalize("c", "finish", "finish", "parent", 1, "FAILED", "result", 12)
            .unwrap();
        let review_command = review_ack_command("ack", &delivery, ReviewVerdict::Accepted, None);
        s.review_and_ack(
            "c",
            "ack",
            &review_command,
            &delivery,
            ReviewVerdict::Accepted,
            None,
            13,
        )
        .unwrap();
        s.mark_retention_gc(12 + 90 * DAY_US).unwrap();
        assert!(matches!(
            s.events_after("parent", 0, 1),
            Err(StorageError::CursorExpired { .. })
        ));
        let linked = s
            .submit(
                "c",
                "retry_task",
                "terminal-retry",
                "request-2",
                "child",
                Some("parent"),
                14 + 90 * DAY_US,
            )
            .unwrap();
        assert_eq!(linked.task_id, "child");
        assert!(
            s.submit(
                "c",
                "retry_task",
                "terminal-retry-conflict",
                "request-3",
                "orphan",
                Some("missing"),
                15 + 90 * DAY_US
            )
            .is_err()
        );
    }

    #[test]
    fn dispatch_phase_evidence_cannot_regress_or_revive_cancelled_work() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "t", None, 1)
            .unwrap();
        s.begin_attempt("c", "begin", "begin", "t", 0, 2).unwrap();
        s.record_dispatch_phase(
            "started",
            "t",
            0,
            DispatchPhase::ProcessStarted,
            Some("receipt"),
            3,
        )
        .unwrap();
        assert!(matches!(
            s.record_dispatch_phase("rewind", "t", 0, DispatchPhase::SpawnPrepared, None, 4,),
            Err(StorageError::StaleGeneration)
        ));
        s.request_cancel("c", "cancel", "cancel", "t", 5).unwrap();
        assert!(matches!(
            s.record_dispatch_phase(
                "late-provider",
                "t",
                0,
                DispatchPhase::ProviderObserved,
                Some("late-receipt"),
                6,
            ),
            Err(StorageError::StaleGeneration)
        ));
    }

    #[test]
    fn cancellation_records_exact_interaction_decision_before_task_state() {
        let mut storage = store();
        storage
            .submit_with_request("c", "submit", "k", b"task", "task", None, 0, None, 1)
            .unwrap();
        let attempt = storage
            .begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        let interaction = storage
            .open_interaction(
                "open",
                "task",
                &attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                100,
                3,
            )
            .unwrap();
        storage
            .request_cancel("c", "cancel", "canonical-cancel", "task", 4)
            .unwrap();
        let events = storage.events_after("task", 0, 10).unwrap().events;
        let decided = events
            .iter()
            .position(|event| event.1 == "interaction_decided")
            .unwrap();
        let cancelled = events
            .iter()
            .position(|event| {
                event.1 == "state_changed"
                    && serde_json::from_str::<serde_json::Value>(&event.2).unwrap()["state"]
                        == "CANCEL_REQUESTED"
            })
            .unwrap();
        assert!(decided < cancelled);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&events[decided].2).unwrap(),
            serde_json::json!({
                "interaction_id": interaction.interaction_id,
                "status": "CANCELLED",
            })
        );
    }

    #[test]
    fn state_machine_interaction_requires_generation_policy_config_and_operation() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        let attempt = s
            .begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        let interaction = s
            .open_interaction(
                "open",
                "task",
                &attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                7,
                11,
                100,
                3,
            )
            .unwrap();
        assert_eq!(
            interaction.capability_class,
            InteractionCapabilityClass::Approval
        );
        assert_eq!(interaction.config_version, 7);
        assert_eq!(interaction.policy_version, 11);
        assert_eq!(interaction.adapter_instance_id, "unassigned");
        assert_eq!(
            s.open_interaction(
                "open",
                "task",
                &attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                7,
                11,
                100,
                3,
            )
            .unwrap(),
            interaction
        );
        assert!(matches!(
            s.open_interaction(
                "open",
                "task",
                &attempt.attempt_id,
                0,
                OTHER_OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                7,
                11,
                100,
                3
            ),
            Err(StorageError::IdempotencyConflict)
        ));
        let (wrong_command, wrong_response, wrong_kind) = interaction_response_command(
            "response-wrong",
            &interaction,
            &serde_json::json!({"kind": "approve"}),
        );
        let wrong_command = {
            let mut value: Value = serde_json::from_slice(&wrong_command).unwrap();
            value["config_digest"] = Value::String(OTHER_CONFIG_DIGEST.into());
            canonical(&value)
        };
        assert!(matches!(
            s.respond_interaction(
                "c",
                "response-wrong",
                &wrong_command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                OTHER_CONFIG_DIGEST,
                wrong_kind,
                &wrong_response,
                4
            ),
            Err(StorageError::InteractionConflict)
        ));
        let (response_command, response_bytes, response_kind) = interaction_response_command(
            "response",
            &interaction,
            &serde_json::json!({"kind": "approve"}),
        );
        assert!(
            !s.respond_interaction(
                "c",
                "response",
                &response_command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                response_kind,
                &response_bytes,
                4
            )
            .unwrap()
        );
        assert!(
            s.respond_interaction(
                "c",
                "response",
                &response_command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                response_kind,
                &response_bytes,
                5
            )
            .unwrap()
        );
        let response = s.interaction_response(&interaction.interaction_id).unwrap();
        assert_eq!(response.response_kind, InteractionResponseKind::Approve);
        assert_eq!(response.bytes, response_bytes);
        assert_eq!(response.response_digest, hash_bytes(&response_bytes));
        let event = s
            .events_after("task", 0, 10)
            .unwrap()
            .events
            .into_iter()
            .find(|event| event.1 == "interaction_decided")
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&event.2).unwrap(),
            serde_json::json!({
                "interaction_id": interaction.interaction_id,
                "status": "APPROVED",
                "response_kind": "approve",
            })
        );
        assert!(matches!(
            s.respond_interaction(
                "c",
                "response",
                &response_command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                response_kind,
                &canonical(&serde_json::json!({"kind": "deny"})),
                5,
            ),
            Err(StorageError::IdempotencyConflict)
        ));
        let (second_command, second_response, second_kind) = interaction_response_command(
            "second",
            &interaction,
            &serde_json::json!({"kind": "deny", "reason": "no"}),
        );
        assert!(matches!(
            s.respond_interaction(
                "c",
                "second",
                &second_command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                second_kind,
                &second_response,
                5
            ),
            Err(StorageError::InteractionConflict)
        ));
    }

    #[test]
    fn state_machine_interaction_timeout_is_durable_and_idempotent() {
        let mut storage = store();
        storage
            .submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        let attempt = storage
            .begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        let interaction = storage
            .open_interaction(
                "open",
                "task",
                &attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Input,
                2,
                3,
                5,
                3,
            )
            .unwrap();
        assert!(matches!(
            storage.expire_interaction("c", "expire", &interaction.interaction_id, 0, 4),
            Err(StorageError::InteractionConflict)
        ));
        let delivery = storage
            .expire_interaction("c", "expire", &interaction.interaction_id, 0, 5)
            .unwrap();
        assert_eq!(delivery.terminal_state, "NEEDS_ATTENTION");
        assert_eq!(
            storage
                .expire_interaction("c", "expire", &interaction.interaction_id, 0, 6)
                .unwrap(),
            delivery
        );
    }

    #[test]
    fn interaction_response_rejects_noncanonical_or_semantically_divergent_evidence() {
        let mut storage = store();
        storage
            .submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        let attempt = storage
            .begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        let interaction = storage
            .open_interaction(
                "open",
                "task",
                &attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Input,
                1,
                1,
                100,
                3,
            )
            .unwrap();
        let (command, response, kind) = interaction_response_command(
            "response",
            &interaction,
            &serde_json::json!({"kind": "text", "text": "payload"}),
        );
        assert!(matches!(
            storage.respond_interaction(
                "c",
                "response",
                &command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionResponseKind::Approve,
                &response,
                4,
            ),
            Err(StorageError::IdempotencyConflict)
        ));
        assert!(matches!(
            storage.respond_interaction(
                "c",
                "response",
                &command,
                &interaction.interaction_id,
                &interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                kind,
                br#"{"text":"payload","kind":"text"}"#,
                5,
            ),
            Err(StorageError::InvalidRequest)
        ));
    }

    #[test]
    fn interaction_response_evidence_reopens_and_corrupt_or_legacy_rows_fail_closed() {
        for fault in [
            "missing",
            "oversized",
            "digest",
            "uppercase_digest",
            "kind_mismatch",
            "legacy_metadata",
        ] {
            let temp = temp();
            let root = temp.path().to_path_buf();
            let interaction_id = {
                let mut storage = Storage::open(&root, "install", 1).unwrap();
                storage
                    .submit_with_request("c", "submit", "k", b"task", "task", None, 0, None, 2)
                    .unwrap();
                let attempt = storage
                    .begin_attempt("c", "begin", "begin", "task", 0, 3)
                    .unwrap();
                let interaction = storage
                    .open_interaction(
                        "open",
                        "task",
                        &attempt.attempt_id,
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
                let empty_response = serde_json::json!({"kind": "text", "text": ""});
                let empty_response_bytes = canonical(&empty_response);
                let empty_command = serde_json::json!({
                    "version": 1,
                    "kind": "command",
                    "action": "interaction_response",
                    "command_key": "empty-response",
                    "task_id": interaction.task_id,
                    "interaction_id": interaction.interaction_id,
                    "generation": interaction.generation,
                    "operation_digest": OPERATION_DIGEST,
                    "policy_digest": POLICY_DIGEST,
                    "config_digest": CONFIG_DIGEST,
                    "nonce": interaction.nonce,
                    "response": empty_response,
                });
                assert!(matches!(
                    storage.respond_interaction(
                        "c",
                        "empty-response",
                        &canonical(&empty_command),
                        &interaction.interaction_id,
                        &interaction.nonce,
                        0,
                        OPERATION_DIGEST,
                        POLICY_DIGEST,
                        CONFIG_DIGEST,
                        InteractionResponseKind::Text,
                        &empty_response_bytes,
                        5,
                    ),
                    Err(StorageError::InvalidRequest)
                ));
                let (response_command, response_bytes, response_kind) =
                    interaction_response_command(
                        "response",
                        &interaction,
                        &serde_json::json!({"kind": "text", "text": "exact persisted input"}),
                    );
                assert!(
                    !storage
                        .respond_interaction(
                            "c",
                            "response",
                            &response_command,
                            &interaction.interaction_id,
                            &interaction.nonce,
                            0,
                            OPERATION_DIGEST,
                            POLICY_DIGEST,
                            CONFIG_DIGEST,
                            response_kind,
                            &response_bytes,
                            6,
                        )
                        .unwrap()
                );
                interaction.interaction_id
            };
            let reopened = Storage::open(&root, "install", 7).unwrap();
            assert_eq!(
                reopened
                    .interaction_response(&interaction_id)
                    .unwrap()
                    .bytes,
                canonical(&serde_json::json!({"kind": "text", "text": "exact persisted input"}))
            );
            drop(reopened);
            let connection = Connection::open(root.join("mesh.sqlite3")).unwrap();
            match fault {
                "missing" => {
                    connection
                        .execute(
                            "DELETE FROM interaction_responses WHERE interaction_id=?1",
                            [&interaction_id],
                        )
                        .unwrap();
                }
                "oversized" => {
                    connection
                        .execute(
                            "UPDATE interaction_responses SET byte_length=?1 WHERE interaction_id=?2",
                            params![i64::try_from(MAX_INTERACTION_RESPONSE_BYTES + 1).unwrap(), interaction_id],
                        )
                        .unwrap();
                }
                "digest" => {
                    connection
                        .execute(
                            "UPDATE interaction_responses SET response_digest='0' WHERE interaction_id=?1",
                            [&interaction_id],
                        )
                        .unwrap();
                }
                "uppercase_digest" => {
                    connection
                        .execute(
                            "UPDATE interaction_responses SET response_digest=?1 WHERE interaction_id=?2",
                            params!["A".repeat(64), interaction_id],
                        )
                        .unwrap();
                }
                "kind_mismatch" => {
                    connection
                        .execute(
                            "UPDATE interaction_responses SET response_kind='approve' WHERE interaction_id=?1",
                            [&interaction_id],
                        )
                        .unwrap();
                }
                "legacy_metadata" => {
                    connection
                        .execute(
                            "UPDATE pending_interactions SET config_version=NULL WHERE interaction_id=?1",
                            [&interaction_id],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            drop(connection);
            assert!(matches!(
                Storage::open(&root, "install", 8),
                Err(StorageError::Quarantined(_))
            ));
        }
    }

    #[test]
    fn canonical_text_response_byte_bound_covers_schema_maximum_without_becoming_unbounded() {
        for text in ["😀".repeat(32 * 1024), "\u{0001}".repeat(32 * 1024)] {
            let temp = temp();
            let root = temp.path().to_path_buf();
            let (interaction_id, expected_bytes) = {
                let mut storage = Storage::open(&root, "install", 1).unwrap();
                storage
                    .submit_with_request("c", "submit", "k", b"task", "task", None, 0, None, 2)
                    .unwrap();
                let attempt = storage
                    .begin_attempt("c", "begin", "begin", "task", 0, 3)
                    .unwrap();
                let interaction = storage
                    .open_interaction(
                        "open",
                        "task",
                        &attempt.attempt_id,
                        0,
                        OPERATION_DIGEST,
                        POLICY_DIGEST,
                        CONFIG_DIGEST,
                        InteractionCapabilityClass::Input,
                        1,
                        1,
                        100,
                        4,
                    )
                    .unwrap();
                let (command, response, kind) = interaction_response_command(
                    "response",
                    &interaction,
                    &serde_json::json!({"kind": "text", "text": text}),
                );
                assert!(response.len() <= MAX_INTERACTION_RESPONSE_BYTES);
                storage
                    .respond_interaction(
                        "c",
                        "response",
                        &command,
                        &interaction.interaction_id,
                        &interaction.nonce,
                        0,
                        OPERATION_DIGEST,
                        POLICY_DIGEST,
                        CONFIG_DIGEST,
                        kind,
                        &response,
                        5,
                    )
                    .unwrap();
                (interaction.interaction_id, response)
            };
            let reopened = Storage::open(&root, "install", 6).unwrap();
            assert_eq!(
                reopened
                    .interaction_response(&interaction_id)
                    .unwrap()
                    .bytes,
                expected_bytes
            );
        }

        let invalid = serde_json::json!({
            "kind": "text",
            "text": "x".repeat(32 * 1024 + 1),
        });
        assert!(matches!(
            parse_canonical_interaction_response(&canonical(&invalid)),
            Err(StorageError::InvalidRequest)
        ));
    }

    #[test]
    fn recovery_ambiguous_dispatch_creates_one_attention_tuple() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        s.begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        s.record_dispatch_phase(
            "started",
            "task",
            0,
            DispatchPhase::ProcessStarted,
            Some("receipt"),
            3,
        )
        .unwrap();
        let decisions = s.reconcile_nonterminal("c", 4).unwrap();
        assert_eq!(
            decisions,
            vec![("task".into(), RecoveryDecision::NeedsAttention)]
        );
        assert_eq!(s.unacked("c").unwrap().len(), 1);
        assert!(s.reconcile_nonterminal("c", 5).unwrap().is_empty());
        s.integrity_check().unwrap();
    }

    #[test]
    fn current_directory_escape_after_dispatch_needs_attention() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        s.begin_attempt_with_spec(
            "c",
            "begin",
            "begin",
            "task",
            0,
            &AttemptSpec {
                effect_profile: "CURRENT_DIRECTORY".into(),
                isolation_level: "BEST_EFFORT".into(),
                retry_class: "AMBIGUOUS_AFTER_DISPATCH".into(),
                ..AttemptSpec::default()
            },
            2,
        )
        .unwrap();
        s.record_dispatch_phase(
            "started",
            "task",
            0,
            DispatchPhase::ProcessStarted,
            Some("receipt"),
            3,
        )
        .unwrap();
        let decisions = s.reconcile_nonterminal("c", 4).unwrap();
        assert_eq!(
            decisions,
            vec![("task".into(), RecoveryDecision::NeedsAttention)]
        );
        let delivery = s.unacked("c").unwrap().pop().unwrap();
        assert_eq!(delivery.terminal_state, "NEEDS_ATTENTION");
        assert!(s.reconcile_nonterminal("c", 5).unwrap().is_empty());
        let isolation: String = s
            .conn
            .query_row(
                "SELECT isolation_level FROM attempts WHERE task_id='task'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(isolation, "BEST_EFFORT");
        assert_ne!(isolation, "ENFORCED");
    }

    #[test]
    fn current_directory_escape_pre_dispatch_stays_retry_safe() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        s.begin_attempt_with_spec(
            "c",
            "begin",
            "begin",
            "task",
            0,
            &AttemptSpec {
                effect_profile: "CURRENT_DIRECTORY".into(),
                isolation_level: "BEST_EFFORT".into(),
                retry_class: "AMBIGUOUS_AFTER_DISPATCH".into(),
                ..AttemptSpec::default()
            },
            2,
        )
        .unwrap();
        let decisions = s.reconcile_nonterminal("c", 3).unwrap();
        assert_eq!(
            decisions,
            vec![("task".into(), RecoveryDecision::RetrySafe)]
        );
        assert!(s.unacked("c").unwrap().is_empty());
        let retry_state: String = s
            .conn
            .query_row("SELECT state FROM tasks WHERE task_id='task'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retry_state, "RETRY_WAIT");
        assert!(s.reconcile_nonterminal("c", 4).unwrap().is_empty());
        let still_retry: String = s
            .conn
            .query_row("SELECT state FROM tasks WHERE task_id='task'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(still_retry, "RETRY_WAIT");
        assert!(s.unacked("c").unwrap().is_empty());
    }

    #[test]
    fn cancel_requested_blocks_success_after_finalizing() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        s.begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        s.record_dispatch_phase(
            "started",
            "task",
            0,
            DispatchPhase::ProcessStarted,
            Some("receipt"),
            3,
        )
        .unwrap();
        s.request_cancel("c", "cancel", "cancel", "task", 4)
            .unwrap();
        s.transition(
            "finalizing",
            "task",
            0,
            &["CANCEL_REQUESTED"],
            "FINALIZING",
            5,
        )
        .unwrap();
        assert!(matches!(
            s.finalize(
                "c",
                "late-success",
                "late-success",
                "task",
                0,
                "SUCCEEDED",
                "digest",
                6
            ),
            Err(StorageError::StaleGeneration)
        ));
        assert!(matches!(
            s.finalize(
                "c",
                "late-fail",
                "late-fail",
                "task",
                0,
                "FAILED",
                "digest",
                7
            ),
            Err(StorageError::StaleGeneration)
        ));
        assert!(matches!(
            s.finalize(
                "c",
                "late-attention",
                "late-attention",
                "task",
                0,
                "NEEDS_ATTENTION",
                "digest",
                8
            ),
            Err(StorageError::StaleGeneration)
        ));
        let delivery = s
            .finalize(
                "c",
                "cancel-result",
                "cancel-result",
                "task",
                0,
                "CANCELLED",
                "digest",
                9,
            )
            .unwrap();
        assert_eq!(delivery.terminal_state, "CANCELLED");
    }

    #[test]
    fn recovery_leaves_retry_wait_for_the_timer() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        s.begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        assert_eq!(
            s.reconcile_nonterminal("c", 3).unwrap(),
            vec![("task".into(), RecoveryDecision::RetrySafe)]
        );
        let (state, generation): (String, i64) = s
            .conn
            .query_row(
                "SELECT state,generation FROM tasks WHERE task_id='task'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "RETRY_WAIT");
        assert_eq!(generation, 1);
        assert!(s.reconcile_nonterminal("c", 4).unwrap().is_empty());
        let (still_state, still_generation): (String, i64) = s
            .conn
            .query_row(
                "SELECT state,generation FROM tasks WHERE task_id='task'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(still_state, "RETRY_WAIT");
        assert_eq!(still_generation, 1);
        assert!(s.unacked("c").unwrap().is_empty());
    }

    #[test]
    fn recovery_finalizes_queued_cancel_without_an_attempt() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        s.request_cancel("c", "cancel", "cancel", "task", 2)
            .unwrap();
        assert_eq!(
            s.reconcile_nonterminal("c", 3).unwrap(),
            vec![("task".into(), RecoveryDecision::FinalizeCancellation)]
        );
        let delivery = s.unacked("c").unwrap().pop().unwrap();
        assert_eq!(delivery.terminal_state, "CANCELLED");
        assert!(s.reconcile_nonterminal("c", 4).unwrap().is_empty());
    }

    #[test]
    fn recovery_finalizing_after_cancel_stays_cancelled() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        s.begin_attempt("c", "begin", "begin", "task", 0, 2)
            .unwrap();
        s.record_dispatch_phase(
            "started",
            "task",
            0,
            DispatchPhase::ProcessStarted,
            Some("receipt"),
            3,
        )
        .unwrap();
        s.request_cancel("c", "cancel", "cancel", "task", 4)
            .unwrap();
        s.transition(
            "finalizing",
            "task",
            0,
            &["CANCEL_REQUESTED"],
            "FINALIZING",
            5,
        )
        .unwrap();
        assert_eq!(
            s.reconcile_nonterminal("c", 6).unwrap(),
            vec![("task".into(), RecoveryDecision::FinalizeCancellation)]
        );
        let delivery = s.unacked("c").unwrap().pop().unwrap();
        assert_eq!(delivery.terminal_state, "CANCELLED");
        assert!(s.reconcile_nonterminal("c", 7).unwrap().is_empty());
    }

    #[test]
    fn recovery_finishes_a_crash_after_finalizing_transition() {
        let mut s = store();
        s.submit("c", "submit", "k", "d", "t", None, 1).unwrap();
        s.begin_attempt("c", "begin", "begin", "t", 0, 2).unwrap();
        s.transition("finalizing", "t", 0, &["PREPARING"], "FINALIZING", 3)
            .unwrap();
        assert_eq!(
            s.reconcile_nonterminal("c", 4).unwrap(),
            vec![("t".into(), RecoveryDecision::NeedsAttention)]
        );
        let delivery = s.unacked("c").unwrap().pop().unwrap();
        assert_eq!(delivery.terminal_state, "NEEDS_ATTENTION");
        assert!(s.reconcile_nonterminal("c", 5).unwrap().is_empty());
    }

    #[test]
    fn recovery_requires_bound_resumable_capability_proof() {
        let mut s = store();
        s.submit("c", "submit", "k", "d", "t", None, 1).unwrap();
        s.begin_attempt("c", "begin", "begin", "t", 0, 2).unwrap();
        s.record_dispatch_phase(
            "observed",
            "t",
            0,
            DispatchPhase::ProviderObserved,
            Some("receipt"),
            3,
        )
        .unwrap();
        s.conn
            .execute(
                "UPDATE attempts SET provider_session='unproven' WHERE task_id='t'",
                [],
            )
            .unwrap();
        assert_eq!(
            s.reconcile_nonterminal("c", 4).unwrap(),
            vec![("t".into(), RecoveryDecision::NeedsAttention)]
        );

        let mut s = store();
        s.submit("c", "submit", "k", "d", "t", None, 1).unwrap();
        s.begin_attempt("c", "begin", "begin", "t", 0, 2).unwrap();
        s.record_dispatch_phase(
            "observed",
            "t",
            0,
            DispatchPhase::ProviderObserved,
            Some("receipt"),
            3,
        )
        .unwrap();
        s.record_resumable_session("t", 0, "session", "capability", 4)
            .unwrap();
        assert_eq!(
            s.reconcile_nonterminal("c", 5).unwrap(),
            vec![("t".into(), RecoveryDecision::ResumeSession)]
        );
    }

    #[test]
    fn recovery_projection_repairs_only_complete_nonterminal_logs() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        {
            let mut s = Storage::open(&root, "install", 1).unwrap();
            s.submit_with_request("c", "submit", "k", b"request", "task", None, 0, None, 2)
                .unwrap();
            s.begin_attempt("c", "begin", "begin", "task", 0, 3)
                .unwrap();
            s.conn
                .execute(
                    "UPDATE tasks SET state='QUEUED',projection_event_seq=0 WHERE task_id='task'",
                    [],
                )
                .unwrap();
        }
        let repaired = Storage::open(&root, "install", 4).unwrap();
        let state: String = repaired
            .conn
            .query_row("SELECT state FROM tasks WHERE task_id='task'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(state, "PREPARING");
    }

    #[test]
    fn recovery_partial_terminal_tuple_is_quarantined_not_repaired() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        {
            let mut s = Storage::open(&root, "install", 1).unwrap();
            s.submit("c", "submit", "k", "request", "task", None, 2)
                .unwrap();
            ready_to_finalize(&mut s, "task", 3);
            s.finalize("c", "finish", "finish", "task", 0, "SUCCEEDED", "result", 5)
                .unwrap();
        }
        let connection = Connection::open(root.join("mesh.sqlite3")).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        connection.execute("DELETE FROM result_outbox", []).unwrap();
        drop(connection);
        assert!(matches!(
            Storage::open(&root, "install", 6),
            Err(StorageError::Quarantined(_))
        ));
    }

    #[test]
    fn migration_backup_checksum_and_mutation_epoch_are_fenced() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        let mut s = Storage::open(&root, "install", 1).unwrap();
        let manifest = s.create_backup("test-binary", 2).unwrap();
        s.verify_restore_allowed(&manifest).unwrap();
        s.submit("c", "submit", "k", "request", "task", None, 3)
            .unwrap();
        assert!(matches!(
            s.verify_restore_allowed(&manifest),
            Err(StorageError::RestoreRefused)
        ));
        s.conn
            .execute(
                "UPDATE schema_migrations SET checksum='changed' WHERE version=1",
                [],
            )
            .unwrap();
        drop(s);
        assert!(matches!(
            Storage::open(&root, "install", 4),
            Err(StorageError::MigrationMismatch(_))
        ));
    }

    #[test]
    fn migration_5_persists_scheduler_columns_with_defaults() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        let mut s = Storage::open(&root, "install", 1).unwrap();
        let version: i64 = s
            .conn
            .query_row(
                "SELECT schema_version FROM storage_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(version, i64::from(CURRENT_DATA_SCHEMA_VERSION));
        s.submit_with_request("c", "submit", "k", b"request", "task", None, 0, None, 2)
            .unwrap();
        let (priority, adapter): (i64, String) = s
            .conn
            .query_row(
                "SELECT priority,adapter_instance_id FROM tasks WHERE task_id='task'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(priority, 0);
        assert_eq!(adapter, "");
        // The out-of-range CHECK is part of the migration, not a code-path
        // nicety.
        assert!(
            s.conn
                .execute("UPDATE tasks SET priority=10 WHERE task_id='task'", [])
                .is_err()
        );
        drop(s);
        // Reopening verifies the committed v5 checksum row.
        Storage::open(&root, "install", 3).unwrap();
    }

    #[test]
    fn improvement_snapshot_reopens_and_projection_tamper_quarantines() {
        use crate::improvement::{
            CandidateKnob, CandidateProposal, Cohort, FailureSignature, FixtureOutcome,
            ImprovementPolicy, ObservationInput,
        };
        let temp = temp();
        let root = temp.path().to_path_buf();
        let mut storage = Storage::open(&root, "install", 1).unwrap();
        let policy = ImprovementPolicy {
            enabled: true,
            ..ImprovementPolicy::default()
        };
        storage
            .ensure_improvement_engine(policy.clone(), 1)
            .unwrap();
        assert!(matches!(
            storage.ensure_improvement_engine(ImprovementPolicy::default(), 2),
            Err(StorageError::IdempotencyConflict)
        ));
        let cohort = Cohort {
            adapter_instance_id: "adapter".into(),
            adapter_version: "1.0".into(),
            config_version: 1,
            config_digest: CONFIG_DIGEST.into(),
        };
        let make_observation = |task_id: &str, at: i64| ObservationInput {
            task_id: task_id.into(),
            component: "prompt".into(),
            cohort: cohort.clone(),
            reviewed_at_us: at,
            success: false,
            failure_signature: Some(FailureSignature {
                protocol_stage: "terminal".into(),
                failure_class: "quality".into(),
                version_bucket: "1".into(),
                diagnostic_code: "BAD".into(),
            }),
            latency_us: Some(100),
            token_cost: Some(100),
            safety_violations: 0,
        };
        for index in 0..3 {
            let observation = make_observation(&format!("task-{index}"), i64::from(index + 2));
            storage.improvement_observe(&observation).unwrap();
        }
        let trigger = make_observation("task-2", 4);
        let case_id = storage.improvement_open_case(&trigger, 4).unwrap().unwrap();
        let fixtures = (0..10)
            .map(|index| FixtureOutcome {
                fixture_id: format!("fixture-{index}"),
                passed: true,
                hard_invariant_failures: 0,
            })
            .collect();
        storage
            .improvement_propose_candidate(
                CandidateProposal {
                    case_id: case_id.clone(),
                    knob: CandidateKnob::Quality,
                    value: serde_json::Value::String("high".into()),
                    hypothesis: "bounded quality".into(),
                    fixtures,
                },
                5,
            )
            .unwrap();
        let snapshot = load_improvement_engine(&storage.conn).unwrap().unwrap();
        let candidate_id = snapshot
            .case_snapshot(&case_id)
            .unwrap()
            .candidate_id
            .unwrap();
        drop(storage);
        let reopened = Storage::open(&root, "install", 6).unwrap();
        let reopened_engine = load_improvement_engine(&reopened.conn).unwrap().unwrap();
        assert_eq!(
            reopened_engine.case_state(&case_id),
            Some(crate::improvement::ImprovementState::Canary)
        );
        drop(reopened);
        let connection = rusqlite::Connection::open(root.join("mesh.sqlite3")).unwrap();
        connection
            .execute(
                "UPDATE improvement_candidates SET candidate_config_digest=?1 WHERE candidate_id=?2",
                rusqlite::params!["0".repeat(64), candidate_id],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            Storage::open(&root, "install", 7),
            Err(StorageError::Quarantined(_))
        ));
    }

    #[test]
    fn disabled_improvement_command_is_replayable_without_revision_or_audit_mutation() {
        use crate::improvement::{
            CandidateDecision, CandidateKnob, CandidateProposal, Cohort, FailureSignature,
            FixtureOutcome, ImprovementPolicy, ObservationInput,
        };
        let temp = temp();
        let root = temp.path().to_path_buf();
        let mut storage = Storage::open(&root, "install", 1).unwrap();
        storage
            .ensure_improvement_engine(
                ImprovementPolicy {
                    enabled: true,
                    ..ImprovementPolicy::default()
                },
                1,
            )
            .unwrap();
        let cohort = Cohort {
            adapter_instance_id: "adapter".into(),
            adapter_version: "1.0".into(),
            config_version: 1,
            config_digest: CONFIG_DIGEST.into(),
        };
        let observation = |task_id: &str, reviewed_at_us: i64| ObservationInput {
            task_id: task_id.into(),
            component: "quality".into(),
            cohort: cohort.clone(),
            reviewed_at_us,
            success: false,
            failure_signature: Some(FailureSignature {
                protocol_stage: "terminal".into(),
                failure_class: "quality".into(),
                version_bucket: "1".into(),
                diagnostic_code: "BAD".into(),
            }),
            latency_us: Some(100),
            token_cost: Some(100),
            safety_violations: 0,
        };
        for index in 0..3 {
            storage
                .improvement_observe(&observation(&format!("task-{index}"), i64::from(index) + 2))
                .unwrap();
        }
        let trigger = observation("task-2", 4);
        let case_id = storage.improvement_open_case(&trigger, 4).unwrap().unwrap();
        let proposal = CandidateProposal {
            case_id: case_id.clone(),
            knob: CandidateKnob::Quality,
            value: Value::String("high".into()),
            hypothesis: "bounded quality".into(),
            fixtures: (0..10)
                .map(|index| FixtureOutcome {
                    fixture_id: format!("fixture-{index}"),
                    passed: true,
                    hard_invariant_failures: 0,
                })
                .collect(),
        };
        let command_key = "disabled-improvement-command";
        let command = canonical(&json!({
            "version": 1,
            "kind": "command",
            "action": "improvement_propose",
            "command_key": command_key,
            "case_id": case_id,
            "knob": "quality",
            "value": "high",
            "hypothesis": "bounded quality",
            "fixtures": (0..10).map(|index| json!({
                "fixture_id": format!("fixture-{index}"),
                "passed": true,
                "hard_invariant_failures": 0,
            })).collect::<Vec<_>>(),
        }));
        storage.set_improvement_enabled(false, 5).unwrap();
        let before: (i64, i64) = storage
            .conn
            .query_row(
                "SELECT revision,(SELECT COUNT(*) FROM improvement_audit) FROM improvement_engine_state WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let first = storage
            .improvement_propose_command("consumer", command_key, &command, proposal.clone(), 6)
            .unwrap();
        assert!(matches!(first.decision, CandidateDecision::FeatureDisabled));
        let after: (i64, i64) = storage
            .conn
            .query_row(
                "SELECT revision,(SELECT COUNT(*) FROM improvement_audit) FROM improvement_engine_state WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(after, before);
        let replay = storage
            .improvement_propose_command("consumer", command_key, &command, proposal.clone(), 7)
            .unwrap();
        assert_eq!(replay, first);
        let mut reopened = Storage::open(&root, "install", 8).unwrap();
        let reopened_revision: i64 = reopened
            .conn
            .query_row(
                "SELECT revision FROM improvement_engine_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reopened_revision, before.0);
        let mut mismatched = proposal;
        mismatched.value = Value::String("standard".into());
        assert!(matches!(
            reopened.improvement_propose_command(
                "consumer",
                "mismatched-command",
                &command,
                mismatched,
                9,
            ),
            Err(StorageError::InvalidRequest)
        ));
    }

    #[test]
    fn migration_offline_restore_keeps_rescue_and_restores_verified_snapshot() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        let manifest = {
            let mut storage = Storage::open(&root, "install", 1).unwrap();
            let manifest = storage.create_backup("test-binary", 2).unwrap();
            storage.conn.execute("INSERT INTO config_versions(version,config_digest,created_at) VALUES(1,'post-backup',3)", []).unwrap();
            manifest
        };
        let rescue =
            restore_backup_offline(&root, &manifest, "install", &PortableFilesystem).unwrap();
        assert!(rescue.is_file());
        let restored = Storage::open(&root, "install", 4).unwrap();
        assert_eq!(
            restored
                .conn
                .query_row("SELECT COUNT(*) FROM config_versions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[derive(Default)]
    struct FakeFilesystem {
        used: Mutex<u64>,
        free: Mutex<u64>,
        reserve_created: Mutex<usize>,
        reserve_released: Mutex<usize>,
    }

    impl DurableFilesystem for FakeFilesystem {
        fn validate_data_root(&self, _root: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn storage_mode(&self) -> &'static str {
            "WINDOWS_LOCAL_NTFS_VALIDATED"
        }
        fn create_relative_directories(&self, path: &Path) -> std::io::Result<()> {
            fs::create_dir_all(path)
        }
        fn allocated_bytes(&self, _root: &Path) -> std::io::Result<u64> {
            Ok(*self.used.lock().unwrap())
        }
        fn free_bytes(&self, _root: &Path) -> std::io::Result<u64> {
            Ok(*self.free.lock().unwrap())
        }
        fn create_reserve(&self, _path: &Path, _bytes: u64) -> std::io::Result<()> {
            *self.reserve_created.lock().unwrap() += 1;
            Ok(())
        }
        fn release_reserve(&self, _path: &Path) -> std::io::Result<()> {
            *self.reserve_released.lock().unwrap() += 1;
            Ok(())
        }
        fn atomic_publish(&self, staged: &Path, destination: &Path) -> std::io::Result<()> {
            fs::rename(staged, destination)
        }
        fn sync_parent(&self, _parent: &Path) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn quota_and_reserve_emergency_use_injected_durable_filesystem() {
        let temp = temp();
        let filesystem = Arc::new(FakeFilesystem::default());
        *filesystem.used.lock().unwrap() = 1;
        *filesystem.free.lock().unwrap() = 2 * 1024 * 1024 * 1024;
        let quota = QuotaPolicy {
            quota_bytes: 1024 * 1024 * 1024,
            reserve_bytes: 64 * 1024 * 1024,
            max_global_concurrency: 3,
        };
        let mut s = Storage::open_with_filesystem(
            temp.path(),
            "install",
            1,
            filesystem.clone(),
            Some(quota),
        )
        .unwrap();
        assert_eq!(
            s.latch_emergency(2).unwrap(),
            EmergencyState::ReserveReleased
        );
        assert!(matches!(
            s.submit("c", "submit", "k", "request", "task", None, 3),
            Err(StorageError::StorageEmergency)
        ));
        s.recover_emergency(4).unwrap();
        assert_eq!(*filesystem.reserve_released.lock().unwrap(), 1);
        assert_eq!(*filesystem.reserve_created.lock().unwrap(), 2);
    }

    #[test]
    fn retention_exact_boundaries_compact_full_graph_and_keep_tombstone() {
        let (mut s, blob) = acknowledged_task_with_artifacts();

        assert!(s.mark_retention_gc(12 + 7 * DAY_US - 1).unwrap().is_empty());
        let worktree_candidates = s.mark_retention_gc(12 + 7 * DAY_US).unwrap();
        assert_eq!(worktree_candidates.len(), 1);
        let worktree_plan = s.prepare_gc_deletion("worktree", "worktree").unwrap();
        fs::remove_dir(&worktree_plan.exact_path).unwrap();
        s.finish_gc_deletion(&worktree_plan.candidate, true, None, 12 + 7 * DAY_US)
            .unwrap();

        assert!(
            s.mark_retention_gc(10 + 14 * DAY_US - 1)
                .unwrap()
                .is_empty()
        );
        let blob_candidates = s.mark_retention_gc(10 + 14 * DAY_US).unwrap();
        assert_eq!(blob_candidates.len(), 1);
        let blob_plan = s.prepare_gc_deletion("blob", &blob).unwrap();
        fs::remove_file(&blob_plan.exact_path).unwrap();
        s.finish_gc_deletion(&blob_plan.candidate, true, None, 10 + 14 * DAY_US)
            .unwrap();

        s.mark_retention_gc(10 + 90 * DAY_US - 1).unwrap();
        assert_eq!(
            s.conn
                .query_row(
                    "SELECT COUNT(*) FROM tasks WHERE task_id='task'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        s.mark_retention_gc(10 + 90 * DAY_US).unwrap();
        assert_eq!(
            s.conn
                .query_row(
                    "SELECT COUNT(*) FROM tasks WHERE task_id='task'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(s.conn.query_row("SELECT COUNT(*) FROM task_tombstones WHERE task_id='task' AND result_digest='result'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(
            s.conn
                .query_row("SELECT COUNT(*) FROM attempts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            s.conn
                .query_row("SELECT COUNT(*) FROM pending_interactions", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            0
        );
    }

    #[test]
    fn retention_gc_marks_an_overdue_worktree_before_compacting_its_task() {
        let (mut s, _) = acknowledged_task_with_artifacts();
        // The task is old enough for result compaction, but a GC run was not
        // performed at the earlier successful-worktree deadline.
        let candidates = s.mark_retention_gc(90 * DAY_US + 10).unwrap();
        assert!(candidates.iter().any(|candidate| {
            candidate.resource_kind == "worktree" && candidate.resource_id == "worktree"
        }));
    }

    struct FailPublishFilesystem(Mutex<bool>);

    impl DurableFilesystem for FailPublishFilesystem {
        fn validate_data_root(&self, _root: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn storage_mode(&self) -> &'static str {
            "WINDOWS_LOCAL_NTFS_VALIDATED"
        }
        fn create_relative_directories(&self, path: &Path) -> std::io::Result<()> {
            fs::create_dir_all(path)
        }
        fn allocated_bytes(&self, root: &Path) -> std::io::Result<u64> {
            directory_bytes(root)
        }
        fn free_bytes(&self, _root: &Path) -> std::io::Result<u64> {
            Ok(u64::MAX)
        }
        fn create_reserve(&self, _path: &Path, _bytes: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn release_reserve(&self, _path: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn atomic_publish(&self, staged: &Path, destination: &Path) -> std::io::Result<()> {
            let mut fail = self.0.lock().unwrap();
            if *fail {
                *fail = false;
                return Err(std::io::Error::other("injected publish fault"));
            }
            fs::rename(staged, destination)
        }
        fn sync_parent(&self, _parent: &Path) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn recovery_blob_publish_fault_converges_from_durable_staging_row() {
        let temp = temp();
        let root = temp.path().to_path_buf();
        let filesystem = Arc::new(FailPublishFilesystem(Mutex::new(true)));
        let mut failed =
            Storage::open_with_filesystem(&root, "install", 1, filesystem, None).unwrap();
        assert!(failed.publish_blob(b"recoverable", 2).is_err());
        drop(failed);
        let reopened = Storage::open(&root, "install", 3).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"recoverable"));
        assert_eq!(reopened.read_blob(&digest).unwrap(), b"recoverable");
        assert_eq!(
            reopened
                .conn
                .query_row("SELECT COUNT(*) FROM blob_staging", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn schema_contract_rejects_terminal_attempt_mutation_and_has_required_columns() {
        let mut s = store();
        s.submit("c", "submit", "k", "request", "task", None, 1)
            .unwrap();
        ready_to_finalize(&mut s, "task", 2);
        s.finalize("c", "finish", "finish", "task", 0, "FAILED", "result", 4)
            .unwrap();
        assert!(
            s.conn
                .execute(
                    "UPDATE attempts SET dispatch_phase='PROVIDER_OBSERVED' WHERE task_id='task'",
                    []
                )
                .is_err()
        );
        for (table, column) in [
            ("storage_meta", "storage_mode"),
            ("command_dedup", "response_kind"),
            ("command_dedup", "response_digest"),
            ("attempts", "effect_profile"),
            ("attempts", "config_version"),
            ("reviews", "diagnosis_ref"),
            ("pending_interactions", "capability_class"),
            ("pending_interactions", "config_version"),
            ("pending_interactions", "policy_version"),
            ("interaction_responses", "response_kind"),
            ("interaction_responses", "response_bytes"),
            ("interaction_responses", "byte_length"),
            ("interaction_responses", "response_digest"),
            ("reader_leases", "heartbeat_at"),
            ("gc_intents", "deadline_at"),
            ("blob_objects", "redaction_profile"),
        ] {
            let query = format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1");
            assert_eq!(
                s.conn
                    .query_row(&query, [column], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1,
                "missing {table}.{column}"
            );
        }
    }

    #[test]
    #[ignore = "invoked as the dedicated helper process"]
    fn recovery_process_helper() {
        let root = PathBuf::from(std::env::var("MESH_M2_HELPER_ROOT").unwrap());
        let mut s = Storage::open(root, "install", 1).unwrap();
        match std::env::var("MESH_M2_HELPER_ACTION").unwrap().as_str() {
            "dispatch-and-wait" => {
                s.submit_with_request("c", "submit", "k", b"request", "task", None, 0, None, 2)
                    .unwrap();
                s.begin_attempt("c", "begin", "begin", "task", 0, 3)
                    .unwrap();
                s.record_dispatch_phase(
                    "started",
                    "task",
                    0,
                    DispatchPhase::ProcessStarted,
                    Some("receipt"),
                    4,
                )
                .unwrap();
                fs::write(s.root.join("helper.ready"), b"ready").unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            "recover" => {
                assert_eq!(
                    s.reconcile_nonterminal("c", 5).unwrap(),
                    vec![("task".into(), RecoveryDecision::NeedsAttention)]
                );
                assert_eq!(s.unacked("c").unwrap().len(), 1);
            }
            action => panic!("unknown helper action {action}"),
        }
    }

    #[test]
    fn recovery_helper_process_kill_and_reopen_converges() {
        let temp = temp();
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(&executable)
            .args([
                "--ignored",
                "--exact",
                "storage::tests::recovery_process_helper",
            ])
            .env("MESH_M2_HELPER_ROOT", temp.path())
            .env("MESH_M2_HELPER_ACTION", "dispatch-and-wait")
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if temp.path().join("helper.ready").is_file() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(temp.path().join("helper.ready").is_file());
        child.kill().unwrap();
        child.wait().unwrap();
        let status = Command::new(&executable)
            .args([
                "--ignored",
                "--exact",
                "storage::tests::recovery_process_helper",
            ])
            .env("MESH_M2_HELPER_ROOT", temp.path())
            .env("MESH_M2_HELPER_ACTION", "recover")
            .status()
            .unwrap();
        assert!(status.success());
        let reopened = Storage::open(temp.path(), "install", 6).unwrap();
        assert_eq!(reopened.unacked("c").unwrap().len(), 1);
    }
}
