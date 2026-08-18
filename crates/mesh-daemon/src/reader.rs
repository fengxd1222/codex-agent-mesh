//! Bounded, detached read projections for the durable control plane.
//!
//! This module deliberately does not "heal" incomplete database rows.  A router
//! can only expose a value after it has been reconstructed from one `SQLite` read
//! snapshot and passed through the authoritative protocol validator.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    canonicalize, decode_v1, decode_wire_v1,
    domain::TaskState,
    improvement::ImprovementEngine,
    protocol_strict_json::parse_strict_json,
    scheduler::QueuedCandidate,
    storage::{
        Occupancy, Result, ResultDelivery, StorageError, TaskRequest, load_improvement_engine,
        read_occupancy,
    },
};

pub use crate::storage::EMPTY_CONFIG_V1_DIGEST;

pub const MAX_READERS: usize = 8;
pub(crate) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_CANONICAL_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_INTERACTION_RESPONSE_BYTES: usize = 6 * 32 * 1024 + 128;
const MAX_EVENT_PAYLOAD_BYTES: usize = 6 * 262_144 + 1024;
const DEFAULT_EVENT_PAGE_BUDGET: usize = mesh_win32::RESPONSE_FRAME_LIMIT - 64 * 1024;
/// A schema-validated event plus durable fields which the v1 schema does not
/// currently surface (generation and original committed microseconds).
#[derive(Clone, Debug, PartialEq)]
pub struct PublicEvent {
    pub event_id: String,
    pub task_id: String,
    pub seq: i64,
    pub generation: i64,
    pub committed_at_us: i64,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CursorBounds {
    pub oldest_available_seq: i64,
    pub last_committed_seq: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskRead {
    pub value: Value,
    pub cursor: CursorBounds,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AttemptRead {
    pub value: Value,
    pub ordinal: i64,
    pub dispatch_phase: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InteractionRead {
    pub value: Value,
    pub interaction_id: String,
    pub task_id: String,
    pub generation: i64,
    pub operation_digest: String,
    pub policy_digest: String,
    pub config_digest: String,
    pub nonce: String,
    pub response_kind: Option<String>,
    pub updated_at_us: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResultRead {
    pub value: Value,
    pub terminal_event_seq: i64,
    /// Exact writer input for idempotent review+ACK. It is emitted only after
    /// the full task/result/outbox/event tuple has been verified.
    pub delivery: ResultDelivery,
    pub review: Option<ReviewRead>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReviewRead {
    pub verdict: String,
    pub reviewed_at_ms: i64,
    pub diagnosis: Option<String>,
}

/// The only configuration projection admitted before adapter configuration is
/// implemented. Its digest is bound to the committed empty config-v1 fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct ConfigRead {
    pub value: Value,
    pub config_digest: String,
}

/// Read-only task row for listing surfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSummary {
    pub task_id: String,
    pub state: String,
    pub generation: i64,
    pub last_event_seq: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InteractionResponseRead {
    kind: String,
    committed_at_us: i64,
}

/// A complete detached view used by inspect/cancel/send-input/review routes.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskSnapshot {
    pub task: TaskRead,
    pub attempt: Option<AttemptRead>,
    pub interaction: Option<InteractionRead>,
    pub result: Option<ResultRead>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicEventPage {
    pub task_id: String,
    pub requested_after_seq: i64,
    pub events: Vec<PublicEvent>,
    pub next_seq: i64,
    pub cursor: CursorBounds,
    pub terminal_result: Option<ResultRead>,
}

/// One persisted SSE poll: the event page and terminal state observed from
/// the same read transaction. The dashboard uses this to avoid closing a
/// stream between an event append and the corresponding terminal projection.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicEventPoll {
    pub page: PublicEventPage,
    pub terminal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalPressure {
    Normal,
    CheckpointPassive,
    DiagnoseReaders,
    FenceDispatch,
}

#[must_use]
pub fn wal_pressure(bytes: u64) -> WalPressure {
    if bytes >= 128 * 1024 * 1024 {
        WalPressure::FenceDispatch
    } else if bytes >= 64 * 1024 * 1024 {
        WalPressure::DiagnoseReaders
    } else if bytes >= 32 * 1024 * 1024 {
        WalPressure::CheckpointPassive
    } else {
        WalPressure::Normal
    }
}

#[derive(Clone)]
pub struct ReaderPool {
    database: PathBuf,
    permits: Arc<(Mutex<usize>, Condvar)>,
}

impl ReaderPool {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let database = root.as_ref().join("mesh.sqlite3");
        if !database.is_file() {
            return Err(StorageError::InvalidRoot(database));
        }
        Ok(Self {
            database,
            permits: Arc::new((Mutex::new(MAX_READERS), Condvar::new())),
        })
    }

    /// Reads an exact public task projection for one durable consumer.
    pub fn snapshot(
        &self,
        task_id: &str,
        consumer_id: &str,
        timeout: Duration,
    ) -> Result<TaskSnapshot> {
        self.with_snapshot(timeout, |tx| load_snapshot(tx, task_id, consumer_id))
    }

    /// Reads the authoritative persisted scheduler occupancy.
    ///
    /// This is the same `SQLite` predicate the writer's
    /// `claim_dispatch_slot` transaction evaluates, so the value is a
    /// committed-state projection even when it is a moment stale.
    pub fn occupancy(&self, timeout: Duration) -> Result<Occupancy> {
        self.with_snapshot(timeout, read_occupancy)
    }

    /// Returns the most recent tasks (newest first) for read-only surfaces.
    /// The limit is clamped to the same 1..=200 page bound as event paging.
    pub fn task_summaries(&self, limit: usize, timeout: Duration) -> Result<Vec<TaskSummary>> {
        if !(1..=200).contains(&limit) {
            return Err(StorageError::InvalidRequest);
        }
        let limit = i64::try_from(limit).expect("dashboard task limit fits i64");
        self.with_snapshot(timeout, move |tx| {
            let mut statement = tx
                .prepare(
                    "SELECT task_id,state,generation,last_event_seq,created_at,updated_at
                     FROM tasks
                     ORDER BY created_at DESC, task_id DESC
                     LIMIT ?1",
                )
                .map_err(map_query_error)?;
            let rows = statement
                .query_map([limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(map_query_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_query_error)?;
            rows.into_iter()
                .map(
                    |(task_id, state, generation, last_event_seq, created_at, updated_at)| {
                        if !(0..=MAX_SAFE_INTEGER).contains(&generation)
                            || !(0..=MAX_SAFE_INTEGER).contains(&last_event_seq)
                        {
                            return Err(StorageError::Quarantined(
                                "task summary has invalid counters".into(),
                            ));
                        }
                        Ok(TaskSummary {
                            task_id,
                            state,
                            generation,
                            last_event_seq,
                            created_at_ms: us_to_ms(created_at)?,
                            updated_at_ms: us_to_ms(updated_at)?,
                        })
                    },
                )
                .collect()
        })
    }

    /// Returns every `QUEUED`/`RETRY_WAIT` task in canonical scheduler order
    /// (higher `priority` first, then FIFO by `created_at`, then `task_id`),
    /// together with the durable adapter identity when one is assigned.
    ///
    /// The adapter identity prefers the task-level immutable column and falls
    /// back to the latest attempt for rows admitted before scheduling input
    /// was persisted. Candidates without an identity cannot be dispatched and
    /// are surfaced as such by [`crate::scheduler::plan_dispatch`].
    pub fn dispatch_candidates(&self, timeout: Duration) -> Result<Vec<QueuedCandidate>> {
        self.with_snapshot(timeout, |tx| {
            let mut statement = tx
                .prepare(
                    "SELECT t.task_id,t.state,t.generation,t.priority,t.created_at,t.retry_at,
                            t.adapter_instance_id,
                            (SELECT a.adapter_instance_id FROM attempts a
                              WHERE a.task_id=t.task_id ORDER BY a.ordinal DESC LIMIT 1)
                     FROM tasks t
                     WHERE t.state IN ('QUEUED','RETRY_WAIT')
                     ORDER BY t.priority DESC, t.created_at, t.task_id",
                )
                .map_err(map_query_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                })
                .map_err(map_query_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_query_error)?;
            drop(statement);
            rows.into_iter()
                .map(
                    |(
                        task_id,
                        state,
                        generation,
                        priority,
                        created_at,
                        retry_at,
                        task_adapter,
                        attempt_adapter,
                    )| {
                        let state = state.parse::<TaskState>().map_err(|_| {
                            StorageError::Quarantined("unknown queued task state".into())
                        })?;
                        if !matches!(state, TaskState::Queued | TaskState::RetryWait) {
                            return Err(StorageError::Quarantined(
                                "dispatch candidate has non-queued state".into(),
                            ));
                        }
                        let priority = u8::try_from(priority).map_err(|_| {
                            StorageError::Quarantined(
                                "dispatch candidate priority out of range".into(),
                            )
                        })?;
                        if generation < 0 || created_at < 0 {
                            return Err(StorageError::Quarantined(
                                "invalid dispatch candidate fields".into(),
                            ));
                        }
                        let adapter_instance_id =
                            match (task_adapter.as_str(), attempt_adapter.as_deref()) {
                                ("", Some(value)) if !value.is_empty() => Some(value.to_owned()),
                                ("", _) => None,
                                (value, _) => Some(value.to_owned()),
                            };
                        Ok(QueuedCandidate {
                            task_id,
                            generation,
                            state,
                            priority,
                            created_at,
                            retry_at,
                            adapter_instance_id,
                        })
                    },
                )
                .collect()
        })
    }

    /// Reads up to 200 schema-validated events and the matching terminal tuple.
    /// Bounds and rows are observed in the same deferred read transaction.
    pub fn public_events_after(
        &self,
        task_id: &str,
        after_seq: i64,
        limit: usize,
        timeout: Duration,
        consumer_id: Option<&str>,
    ) -> Result<PublicEventPage> {
        self.public_events_after_bounded(
            task_id,
            after_seq,
            limit,
            DEFAULT_EVENT_PAGE_BUDGET,
            timeout,
            consumer_id,
        )
    }

    /// Reads an event page which fits the caller's negotiated event-array
    /// budget. `next_seq` advances only across events actually returned.
    pub fn public_events_after_bounded(
        &self,
        task_id: &str,
        after_seq: i64,
        limit: usize,
        maximum_encoded_event_bytes: usize,
        timeout: Duration,
        consumer_id: Option<&str>,
    ) -> Result<PublicEventPage> {
        validate_event_page_request(after_seq, limit, maximum_encoded_event_bytes)?;
        self.with_snapshot(timeout, |tx| {
            load_event_page(
                tx,
                task_id,
                after_seq,
                limit,
                maximum_encoded_event_bytes,
                consumer_id,
            )
        })
    }

    /// Reads the task projection and its event page from one detached snapshot.
    /// The stable install consumer is required only for the result/review view;
    /// callers decide which delivery fields are safe to expose.
    #[allow(clippy::too_many_arguments)]
    pub fn public_task_detail(
        &self,
        task_id: &str,
        consumer_id: &str,
        after_seq: i64,
        limit: usize,
        maximum_encoded_event_bytes: usize,
        timeout: Duration,
    ) -> Result<(TaskSnapshot, PublicEventPage)> {
        validate_event_page_request(after_seq, limit, maximum_encoded_event_bytes)?;
        self.with_snapshot(timeout, |tx| {
            let snapshot = load_snapshot(tx, task_id, consumer_id)?;
            let page = load_event_page(
                tx,
                task_id,
                after_seq,
                limit,
                maximum_encoded_event_bytes,
                None,
            )?;
            Ok((snapshot, page))
        })
    }

    /// Reads one event page and the task terminal state from one detached
    /// `SQLite` snapshot for replayable SSE polling.
    pub fn public_event_poll(
        &self,
        task_id: &str,
        after_seq: i64,
        limit: usize,
        maximum_encoded_event_bytes: usize,
        timeout: Duration,
    ) -> Result<PublicEventPoll> {
        validate_event_page_request(after_seq, limit, maximum_encoded_event_bytes)?;
        self.with_snapshot(timeout, |tx| {
            let page = load_event_page(
                tx,
                task_id,
                after_seq,
                limit,
                maximum_encoded_event_bytes,
                None,
            )?;
            let task = load_task(tx, task_id)?;
            let terminal = matches!(
                task.value.get("state").and_then(Value::as_str),
                Some("SUCCEEDED" | "FAILED" | "CANCELLED" | "NEEDS_ATTENTION")
            );
            Ok(PublicEventPoll { page, terminal })
        })
    }

    /// Reads one exact interaction locator rather than substituting the latest
    /// interaction for an idempotent command replay.
    pub fn interaction_by_id(
        &self,
        task_id: &str,
        interaction_id: &str,
        consumer_id: &str,
        timeout: Duration,
    ) -> Result<InteractionRead> {
        self.with_snapshot(timeout, |tx| {
            load_interaction_by_id(tx, task_id, interaction_id, Some(consumer_id))?
                .ok_or(StorageError::InteractionConflict)
        })
    }

    /// Reads the frozen empty adapter config admitted by M3.
    pub fn empty_config(&self, timeout: Duration) -> Result<ConfigRead> {
        self.with_snapshot(timeout, load_empty_config)
    }

    /// Reads the complete detached improvement ledger snapshot. The writer
    /// verifies its digest and updates normalized projections atomically.
    pub fn improvement_engine(&self, timeout: Duration) -> Result<Option<ImprovementEngine>> {
        self.with_snapshot(timeout, |tx| load_improvement_engine(tx))
    }

    /// Returns a detached, integrity-verified canonical task request.
    pub fn task_request(&self, task_id: &str, timeout: Duration) -> Result<TaskRequest> {
        self.with_snapshot(timeout, |tx| load_task_request(tx, task_id))
    }

    fn with_snapshot<T>(
        &self,
        timeout: Duration,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let started = Instant::now();
        let deadline = started
            .checked_add(timeout)
            .ok_or(StorageError::QueryDeadline)?;
        let _permit = self.acquire(timeout)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(StorageError::QueryDeadline);
        }
        let mut connection = Connection::open_with_flags(
            &self.database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(map_query_error)?;
        if Instant::now() >= deadline {
            return Err(StorageError::QueryDeadline);
        }
        connection
            .busy_timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(2)),
            )
            .map_err(map_query_error)?;
        connection
            .pragma_update(None, "query_only", "ON")
            .map_err(map_query_error)?;
        let _ = connection.progress_handler(1_000, Some(move || Instant::now() >= deadline));
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(map_query_error)?;
        let result = operation(&tx).map_err(normalize_query_error);
        // Explicitly finish the snapshot before returning detached data.  A
        // read-only rollback is the normal close path and cannot commit state.
        drop(tx);
        if Instant::now() >= deadline {
            return Err(StorageError::QueryDeadline);
        }
        result
    }

    fn acquire(&self, timeout: Duration) -> Result<Permit> {
        let (lock, wake) = &*self.permits;
        let available = lock
            .lock()
            .map_err(|_| StorageError::Quarantined("reader pool poisoned".into()))?;
        let (mut available, status) = wake
            .wait_timeout_while(available, timeout, |value| *value == 0)
            .map_err(|_| StorageError::Quarantined("reader pool poisoned".into()))?;
        if status.timed_out() && *available == 0 {
            return Err(StorageError::ReaderSaturated);
        }
        *available -= 1;
        Ok(Permit(Arc::clone(&self.permits)))
    }
}

// Keeping the cursor checks, row preflight, schema validation, and page-budget
// accounting together makes it auditable that `next_seq` cannot skip evidence.
fn validate_event_page_request(
    after_seq: i64,
    limit: usize,
    maximum_encoded_event_bytes: usize,
) -> Result<()> {
    if !(0..=MAX_SAFE_INTEGER).contains(&after_seq)
        || !(1..=200).contains(&limit)
        || maximum_encoded_event_bytes == 0
        || maximum_encoded_event_bytes > mesh_win32::RESPONSE_FRAME_LIMIT
    {
        return Err(StorageError::InvalidRequest);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_event_page(
    tx: &Transaction<'_>,
    task_id: &str,
    after_seq: i64,
    limit: usize,
    maximum_encoded_event_bytes: usize,
    consumer_id: Option<&str>,
) -> Result<PublicEventPage> {
    let cursor = load_cursor(tx, task_id)?;
    let evicted_through = cursor
        .oldest_available_seq
        .checked_sub(1)
        .ok_or_else(|| StorageError::Quarantined("invalid cursor lower bound".into()))?;
    if after_seq < evicted_through {
        return Err(StorageError::CursorExpired {
            oldest_available_seq: cursor.oldest_available_seq,
            last_committed_seq: cursor.last_committed_seq,
        });
    }
    if after_seq > cursor.last_committed_seq {
        return Err(StorageError::InvalidRequest);
    }

    let mut statement = tx
        .prepare(
            "SELECT event_id,event_seq,generation,kind,committed_at,\
                    length(CAST(payload AS BLOB)),payload \
             FROM events WHERE task_id=?1 AND event_seq>?2 \
             ORDER BY event_seq LIMIT ?3",
        )
        .map_err(map_query_error)?;
    let mut rows = statement
        .query(rusqlite::params![
            task_id,
            after_seq,
            i64::try_from(limit).expect("protocol page bound fits i64")
        ])
        .map_err(map_query_error)?;
    let mut events = Vec::with_capacity(limit);
    let mut encoded_bytes = 0_usize;
    let mut budget_stopped = false;
    while let Some(row) = rows.next().map_err(map_query_error)? {
        let id = row_string(row, 0, "event id")?;
        let seq = row_i64(row, 1, "event sequence")?;
        let generation = row_i64(row, 2, "event generation")?;
        let kind = row_string(row, 3, "event kind")?;
        let committed_at = row_i64(row, 4, "event timestamp")?;
        let payload_length = row_i64(row, 5, "event payload length")?;
        let expected_seq = after_seq
            .checked_add(
                i64::try_from(events.len())
                    .expect("event page bound fits i64")
                    .checked_add(1)
                    .expect("event page increment fits i64"),
            )
            .ok_or_else(|| StorageError::Quarantined("event sequence overflow".into()))?;
        if seq != expected_seq || seq > cursor.last_committed_seq {
            return Err(StorageError::Quarantined(
                "event sequence is not a contiguous committed prefix".into(),
            ));
        }
        let payload_length = usize::try_from(payload_length)
            .ok()
            .filter(|length| *length <= MAX_EVENT_PAYLOAD_BYTES)
            .ok_or_else(|| StorageError::Quarantined("event payload is oversized".into()))?;
        if payload_length > maximum_encoded_event_bytes {
            if events.is_empty() {
                return Err(StorageError::OutputLimitExceeded);
            }
            budget_stopped = true;
            break;
        }
        let payload = row_string(row, 6, "event payload")?;
        if payload.len() != payload_length {
            return Err(StorageError::Quarantined(
                "event payload length changed inside its snapshot".into(),
            ));
        }
        let event = public_event(&id, task_id, seq, generation, &kind, &payload, committed_at)?;
        let event_bytes = serde_json::to_vec(&event.value)
            .map_err(|_| StorageError::Quarantined("event cannot be encoded".into()))?
            .len();
        let additional = event_bytes
            .checked_add(usize::from(!events.is_empty()))
            .ok_or_else(|| StorageError::Quarantined("event page size overflow".into()))?;
        if encoded_bytes
            .checked_add(additional)
            .is_none_or(|total| total > maximum_encoded_event_bytes)
        {
            if events.is_empty() {
                return Err(StorageError::OutputLimitExceeded);
            }
            budget_stopped = true;
            break;
        }
        encoded_bytes += additional;
        events.push(event);
    }
    drop(rows);
    drop(statement);

    let remaining = cursor
        .last_committed_seq
        .checked_sub(after_seq)
        .ok_or_else(|| StorageError::Quarantined("invalid event cursor relation".into()))?;
    let expected_count = usize::try_from(remaining.min(i64::try_from(limit).expect("bounded")))
        .map_err(|_| StorageError::Quarantined("event count overflow".into()))?;
    if !budget_stopped && events.len() != expected_count {
        return Err(StorageError::Quarantined(
            "committed event page contains a missing row".into(),
        ));
    }
    let next_seq = events.last().map_or(after_seq, |event| event.seq);
    let terminal_result = match consumer_id {
        Some(consumer) => load_result(tx, task_id, consumer)?,
        None => None,
    };
    Ok(PublicEventPage {
        task_id: task_id.into(),
        requested_after_seq: after_seq,
        events,
        next_seq,
        cursor,
        terminal_result,
    })
}

fn load_task_request(tx: &Transaction<'_>, task_id: &str) -> Result<TaskRequest> {
    type Metadata = (String, Option<String>, Option<i64>, Option<i64>);
    let (task_digest, digest, declared_length, sqlite_length): Metadata = tx
        .query_row(
            "SELECT t.request_digest,r.request_digest,r.byte_length,\
                    length(r.request_bytes) \
             FROM tasks t LEFT JOIN task_requests r ON r.task_id=t.task_id \
             WHERE t.task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(map_query_error)?;
    let (Some(digest), Some(declared_length), Some(sqlite_length)) =
        (digest, declared_length, sqlite_length)
    else {
        return Err(StorageError::Quarantined(
            "missing canonical task request".into(),
        ));
    };
    let length = usize::try_from(declared_length)
        .ok()
        .filter(|length| (1..=MAX_CANONICAL_REQUEST_BYTES).contains(length))
        .ok_or_else(|| StorageError::Quarantined("task request length is invalid".into()))?;
    if sqlite_length != declared_length || digest != task_digest || !is_lower_sha256(&digest) {
        return Err(StorageError::Quarantined(
            "canonical task request metadata mismatch".into(),
        ));
    }
    let bytes: Vec<u8> = tx
        .query_row(
            "SELECT request_bytes FROM task_requests WHERE task_id=?1",
            [task_id],
            |row| row.get(0),
        )
        .map_err(map_query_error)?;
    if bytes.len() != length || format!("{:x}", Sha256::digest(&bytes)) != digest {
        return Err(StorageError::Quarantined(
            "canonical task request integrity mismatch".into(),
        ));
    }
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| StorageError::Quarantined("task request is not UTF-8".into()))?;
    let value = parse_strict_json(source)
        .map_err(|_| StorageError::Quarantined("task request is not strict JSON".into()))?;
    decode_v1(value.clone())
        .map_err(|_| StorageError::Quarantined("task request fails protocol v1".into()))?;
    if value.get("kind").and_then(Value::as_str) != Some("task_request")
        || canonicalize(&value)
            .map_err(|_| StorageError::Quarantined("task request cannot be canonicalized".into()))?
            .as_bytes()
            != bytes
    {
        return Err(StorageError::Quarantined(
            "task request bytes are not canonical task evidence".into(),
        ));
    }
    Ok(TaskRequest {
        task_id: task_id.into(),
        digest,
        bytes,
    })
}

fn load_empty_config(tx: &Transaction<'_>) -> Result<ConfigRead> {
    let mut statement = tx
        .prepare(
            "SELECT version,config_digest,created_at \
             FROM config_versions ORDER BY version DESC LIMIT 2",
        )
        .map_err(map_query_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(map_query_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(map_query_error)?;
    let [(version, digest, created_at)] = rows.as_slice() else {
        return Err(StorageError::Quarantined(
            "missing or unknown empty config v1".into(),
        ));
    };
    if *version != 1 || digest != EMPTY_CONFIG_V1_DIGEST || *created_at < 0 {
        return Err(StorageError::Quarantined(
            "missing or unknown empty config v1".into(),
        ));
    }
    let value = json!({"kind":"list_agents_result","agents":[],"config_version":1});
    validate_wire_result("mesh.list_agents", &value)?;
    Ok(ConfigRead {
        value,
        config_digest: EMPTY_CONFIG_V1_DIGEST.into(),
    })
}

fn load_snapshot(tx: &Transaction<'_>, task_id: &str, consumer_id: &str) -> Result<TaskSnapshot> {
    let task = load_task(tx, task_id)?;
    let generation = task.value["generation"]
        .as_i64()
        .ok_or_else(|| StorageError::Quarantined("invalid task generation".into()))?;
    let attempt = load_attempt(tx, task_id, generation)?;
    let interaction = load_pending_interaction(tx, task_id, generation)?;
    let result = load_result(tx, task_id, consumer_id)?;
    Ok(TaskSnapshot {
        task,
        attempt,
        interaction,
        result,
    })
}

fn load_cursor(tx: &Transaction<'_>, task_id: &str) -> Result<CursorBounds> {
    let live: Option<(i64, i64)> = tx
        .query_row(
            "SELECT evicted_through_seq,last_event_seq FROM tasks WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_query_error)?;
    let (evicted, last) = match live {
        Some(row) => row,
        None => tx
            .query_row(
                "SELECT evicted_through_seq,last_event_seq FROM task_tombstones WHERE task_id=?1",
                [task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(map_query_error)?,
    };
    if !(0..=MAX_SAFE_INTEGER).contains(&evicted)
        || !(0..=MAX_SAFE_INTEGER).contains(&last)
        || last < evicted
    {
        return Err(StorageError::Quarantined("invalid cursor bounds".into()));
    }
    let oldest_available_seq = evicted
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| StorageError::Quarantined("cursor lower bound overflow".into()))?;
    Ok(CursorBounds {
        oldest_available_seq,
        last_committed_seq: last,
    })
}

fn load_task(tx: &Transaction<'_>, task_id: &str) -> Result<TaskRead> {
    let (state, generation, last): (String, i64, i64) = tx
        .query_row(
            "SELECT state,generation,last_event_seq FROM tasks WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(map_query_error)?;
    let mut value = json!({"version":1,"kind":"task_snapshot","task_id":task_id,"state":state,"generation":generation,"last_event_seq":last});
    if let Some(attempt_id) = tx
        .query_row(
            "SELECT attempt_id FROM attempts WHERE task_id=?1 AND generation=?2",
            rusqlite::params![task_id, generation],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(map_query_error)?
    {
        value["attempt_id"] = Value::String(attempt_id);
    }
    validate(value.clone(), "task snapshot")?;
    Ok(TaskRead {
        value,
        cursor: load_cursor(tx, task_id)?,
    })
}

fn load_attempt(
    tx: &Transaction<'_>,
    task_id: &str,
    generation: i64,
) -> Result<Option<AttemptRead>> {
    let row: Option<(String, String, i64, String, String, i64)> = tx.query_row("SELECT attempt_id,state,generation,adapter_instance_id,dispatch_phase,ordinal FROM attempts WHERE task_id=?1 AND generation=?2", rusqlite::params![task_id, generation], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).optional().map_err(map_query_error)?;
    row.map(|(id,state,generation,adapter,phase,ordinal)| {
        if !(1..=MAX_SAFE_INTEGER).contains(&ordinal)
            || !matches!(phase.as_str(), "PRE_DISPATCH" | "SPAWN_PREPARED" | "PROCESS_STARTED" | "PROVIDER_OBSERVED")
        {
            return Err(StorageError::Quarantined("attempt has invalid private projection fields".into()));
        }
        let value=json!({"version":1,"kind":"attempt_snapshot","attempt_id":id,"task_id":task_id,"generation":generation,"state":state,"adapter_instance_id":adapter});
        validate(value.clone(), "attempt snapshot")?;
        Ok(AttemptRead { value, ordinal, dispatch_phase: phase })
    }).transpose()
}

fn load_pending_interaction(
    tx: &Transaction<'_>,
    task_id: &str,
    generation: i64,
) -> Result<Option<InteractionRead>> {
    let mut statement = tx
        .prepare(
            "SELECT interaction_id FROM pending_interactions \
             WHERE task_id=?1 AND generation=?2 AND state='PENDING' \
             ORDER BY created_at,interaction_id LIMIT 2",
        )
        .map_err(map_query_error)?;
    let ids = statement
        .query_map(rusqlite::params![task_id, generation], |row| {
            row.get::<_, String>(0)
        })
        .map_err(map_query_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(map_query_error)?;
    match ids.as_slice() {
        [] => Ok(None),
        [interaction_id] => load_interaction_by_id(tx, task_id, interaction_id, None),
        _ => Err(StorageError::Quarantined(
            "task has multiple pending interactions".into(),
        )),
    }
}

// This deliberately reconstructs the entire interaction/response/command tuple
// inside one snapshot instead of accepting a convenient partial projection.
#[allow(clippy::too_many_lines)]
fn load_interaction_by_id(
    tx: &Transaction<'_>,
    task_id: &str,
    interaction_id: &str,
    expected_consumer: Option<&str>,
) -> Result<Option<InteractionRead>> {
    type Core = (
        String,
        String,
        Option<String>,
        i64,
        String,
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<i64>,
        String,
        i64,
        String,
        i64,
        i64,
    );
    let core: Option<Core> = tx
        .query_row(
            "SELECT i.interaction_id,i.attempt_id,a.adapter_instance_id,i.generation,\
                    i.operation_digest,i.policy_digest,i.config_digest,\
                    i.capability_class,i.config_version,i.policy_version,\
                    i.nonce,i.expires_at,i.state,i.created_at,i.updated_at \
             FROM pending_interactions i LEFT JOIN attempts a \
               ON a.attempt_id=i.attempt_id AND a.task_id=i.task_id \
              AND a.generation=i.generation \
             WHERE i.task_id=?1 AND i.interaction_id=?2",
            rusqlite::params![task_id, interaction_id],
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                ))
            },
        )
        .optional()
        .map_err(map_query_error)?;
    let Some((
        id,
        attempt,
        adapter,
        generation,
        operation,
        policy,
        config,
        class,
        config_version,
        policy_version,
        nonce,
        expires,
        state,
        created,
        updated,
    )) = core
    else {
        return Ok(None);
    };
    let (Some(adapter), Some(class), Some(config_version), Some(policy_version)) =
        (adapter, class, config_version, policy_version)
    else {
        return Err(StorageError::Quarantined(format!(
            "interaction has incomplete binding metadata: {id}"
        )));
    };
    let response = load_interaction_response(tx, &id, &state, expected_consumer)?;
    let (status, response_kind) = match (state.as_str(), response) {
        ("PENDING", None) => ("PENDING", None),
        ("EXPIRED", None) => ("EXPIRED", None),
        ("CANCELLED", None) => ("CANCELLED", None),
        ("ANSWERED", Some(response)) if response.committed_at_us != updated => {
            return Err(StorageError::Quarantined(format!(
                "interaction update time disagrees with response evidence: {id}"
            )));
        }
        ("ANSWERED", Some(response)) if response.kind == "approve" => {
            ("APPROVED", Some(response.kind))
        }
        ("ANSWERED", Some(response)) if response.kind == "deny" => ("DENIED", Some(response.kind)),
        ("ANSWERED", Some(response)) if response.kind == "text" => {
            ("PROVIDED", Some(response.kind))
        }
        ("ANSWERED", None) => {
            return Err(StorageError::Quarantined(format!(
                "answered interaction lacks exact response evidence: {id}"
            )));
        }
        _ => {
            return Err(StorageError::Quarantined(format!(
                "interaction state and response evidence disagree: {id}"
            )));
        }
    };
    let _ = us_to_ms(updated)?;
    let value = json!({
        "version":1,"kind":"interaction","interaction_id":id,"task_id":task_id,
        "attempt_id":attempt,"adapter_instance_id":adapter,"generation":generation,
        "capability_class":class,"operation_digest":operation,"policy_digest":policy,
        "config_digest":config,"config_version":config_version,
        "policy_version":policy_version,"created_at_ms":us_to_ms(created)?,
        "expires_at_ms":us_to_ms(expires)?,"nonce":nonce,"status":status
    });
    validate(value.clone(), "interaction")?;
    Ok(Some(InteractionRead {
        value,
        interaction_id: id,
        task_id: task_id.into(),
        generation,
        operation_digest: operation,
        policy_digest: policy,
        config_digest: config,
        nonce,
        response_kind,
        updated_at_us: updated,
    }))
}

#[allow(clippy::too_many_lines)]
fn load_interaction_response(
    tx: &Transaction<'_>,
    interaction_id: &str,
    state: &str,
    expected_consumer: Option<&str>,
) -> Result<Option<InteractionResponseRead>> {
    // The v4 migration deliberately left semantic response columns nullable so
    // legacy rows could be quarantined instead of receiving invented defaults.
    // Read them as nullable here; asking rusqlite for `String`/`i64` directly
    // would leak corrupt evidence as an unclassified SQL type error.
    type Metadata = (
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        i64,
        Option<i64>,
    );
    let metadata: Option<Metadata> = tx
        .query_row(
            "SELECT consumer_id,decision_digest,response_kind,byte_length,\
                    response_digest,committed_at,length(response_bytes) \
             FROM interaction_responses WHERE interaction_id=?1",
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
                ))
            },
        )
        .optional()
        .map_err(map_query_error)?;
    if state != "ANSWERED" {
        return if metadata.is_none() {
            Ok(None)
        } else {
            Err(StorageError::Quarantined(format!(
                "response evidence belongs to a non-answered interaction: {interaction_id}"
            )))
        };
    }
    let Some((
        consumer,
        decision_digest,
        response_kind,
        declared_length,
        response_digest,
        committed_at,
        sqlite_length,
    )) = metadata
    else {
        return Err(StorageError::Quarantined(format!(
            "answered interaction lacks response evidence: {interaction_id}"
        )));
    };
    let (Some(response_kind), Some(declared_length), Some(response_digest), Some(sqlite_length)) = (
        response_kind,
        declared_length,
        response_digest,
        sqlite_length,
    ) else {
        return Err(StorageError::Quarantined(format!(
            "answered interaction has incomplete response evidence: {interaction_id}"
        )));
    };
    if expected_consumer.is_some_and(|expected| expected != consumer)
        || consumer.is_empty()
        || decision_digest != response_digest
        || !is_lower_sha256(&response_digest)
        || sqlite_length != declared_length
        || us_to_ms(committed_at).is_err()
    {
        return Err(StorageError::Quarantined(format!(
            "interaction response metadata mismatch: {interaction_id}"
        )));
    }
    let length = usize::try_from(declared_length)
        .ok()
        .filter(|length| (1..=MAX_INTERACTION_RESPONSE_BYTES).contains(length))
        .ok_or_else(|| {
            StorageError::Quarantined(format!(
                "interaction response length is invalid: {interaction_id}"
            ))
        })?;
    let bytes: Vec<u8> = tx
        .query_row(
            "SELECT response_bytes FROM interaction_responses WHERE interaction_id=?1",
            [interaction_id],
            |row| row.get(0),
        )
        .map_err(map_query_error)?;
    if bytes.len() != length || format!("{:x}", Sha256::digest(&bytes)) != response_digest {
        return Err(StorageError::Quarantined(format!(
            "interaction response bytes do not match their digest: {interaction_id}"
        )));
    }
    let (decoded_kind, response_value) = decode_canonical_interaction_response(&bytes)?;
    if decoded_kind != response_kind {
        return Err(StorageError::Quarantined(format!(
            "interaction response kind disagrees with canonical evidence: {interaction_id}"
        )));
    }
    verify_interaction_command_binding(
        tx,
        interaction_id,
        &consumer,
        &response_value,
        &decoded_kind,
    )?;
    Ok(Some(InteractionResponseRead {
        kind: decoded_kind,
        committed_at_us: committed_at,
    }))
}

fn decode_canonical_interaction_response(bytes: &[u8]) -> Result<(String, Value)> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| StorageError::Quarantined("interaction response is not UTF-8".into()))?;
    let value = parse_strict_json(source)
        .map_err(|_| StorageError::Quarantined("interaction response is not strict JSON".into()))?;
    if canonicalize(&value)
        .map_err(|_| StorageError::Quarantined("interaction response is not canonical".into()))?
        .as_bytes()
        != bytes
    {
        return Err(StorageError::Quarantined(
            "interaction response is not canonical".into(),
        ));
    }
    let object = value
        .as_object()
        .ok_or_else(|| StorageError::Quarantined("interaction response is not an object".into()))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let valid = match kind {
        "approve" => object.len() == 1,
        "deny" => {
            object.len() == 1
                || (object.len() == 2
                    && object
                        .get("reason")
                        .and_then(Value::as_str)
                        .is_some_and(|reason| reason.chars().count() <= 4096))
        }
        "text" => {
            object.len() == 2
                && object
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| (1..=32 * 1024).contains(&text.chars().count()))
        }
        _ => false,
    };
    if !valid {
        return Err(StorageError::Quarantined(
            "interaction response has invalid protocol semantics".into(),
        ));
    }
    Ok((kind.to_owned(), value))
}

fn verify_interaction_command_binding(
    tx: &Transaction<'_>,
    interaction_id: &str,
    consumer_id: &str,
    response: &Value,
    response_kind: &str,
) -> Result<()> {
    type Context = (String, i64, String, String, String, String);
    type Binding = (String, String, String, String, Option<String>);
    let context: Context = tx
        .query_row(
            "SELECT task_id,generation,nonce,operation_digest,policy_digest,config_digest \
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
        .map_err(map_query_error)?;
    let mut statement = tx
        .prepare(
            "SELECT command_key,request_digest,response_kind,outcome,response_json \
             FROM command_dedup \
             WHERE consumer_id=?1 AND method='interaction_response' \
                AND response_locator=?2",
        )
        .map_err(map_query_error)?;
    let bindings = statement
        .query_map(rusqlite::params![consumer_id, interaction_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(map_query_error)?
        .collect::<std::result::Result<Vec<Binding>, _>>()
        .map_err(map_query_error)?;
    let [(command_key, request_digest, response_kind_marker, outcome, response_json)] =
        bindings.as_slice()
    else {
        return Err(StorageError::Quarantined(format!(
            "interaction has ambiguous command binding: {interaction_id}"
        )));
    };
    if response_kind_marker != "LOCATOR" || outcome != "COMMITTED" || response_json.is_some() {
        return Err(StorageError::Quarantined(format!(
            "interaction has invalid command outcome evidence: {interaction_id}"
        )));
    }
    let (task_id, generation, nonce, operation, policy, config) = context;
    let command = json!({
        "version":1,"kind":"command","action":"interaction_response",
        "command_key":command_key,"task_id":task_id,"interaction_id":interaction_id,
        "generation":generation,"operation_digest":operation,"policy_digest":policy,
        "config_digest":config,"nonce":nonce,"response":response
    });
    decode_v1(command.clone()).map_err(|_| {
        StorageError::Quarantined(format!(
            "interaction reconstructs an invalid command: {interaction_id}"
        ))
    })?;
    let canonical = canonicalize(&command).map_err(|_| {
        StorageError::Quarantined(format!(
            "interaction command cannot be canonicalized: {interaction_id}"
        ))
    })?;
    if !is_lower_sha256(request_digest)
        || format!("{:x}", Sha256::digest(canonical.as_bytes())) != *request_digest
        || response.get("kind").and_then(Value::as_str) != Some(response_kind)
    {
        return Err(StorageError::Quarantined(format!(
            "interaction command digest disagrees with evidence: {interaction_id}"
        )));
    }
    Ok(())
}

// Terminal task, result, outbox, event, and optional review are one integrity
// tuple. Keeping their comparisons adjacent is safer than hiding partial joins.
#[allow(clippy::too_many_lines)]
fn load_result(
    tx: &Transaction<'_>,
    task_id: &str,
    consumer_id: &str,
) -> Result<Option<ResultRead>> {
    type TaskTerminal = (String, i64, i64, i64, Option<i64>, Option<i64>, Option<i64>);
    type Outbox = (String, String, i64, i64, Option<i64>, Option<String>);
    let task: Option<TaskTerminal> = tx
        .query_row(
            "SELECT state,generation,last_event_seq,projection_event_seq,
                    result_version,terminal_event_seq,terminal_at
             FROM tasks WHERE task_id=?1",
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
                ))
            },
        )
        .optional()
        .map_err(map_query_error)?;
    let Some((
        state,
        task_generation,
        last_event_seq,
        projection_event_seq,
        task_version,
        task_event_seq,
        terminal_at,
    )) = task
    else {
        return Ok(None);
    };
    let terminal = matches!(
        state.as_str(),
        "SUCCEEDED" | "FAILED" | "CANCELLED" | "NEEDS_ATTENTION"
    );
    if !terminal {
        if task_version.is_some()
            || task_event_seq.is_some()
            || terminal_at.is_some()
            || table_count(tx, "results", task_id)? != 0
            || table_count(tx, "result_outbox", task_id)? != 0
        {
            return Err(StorageError::Quarantined(
                "nonterminal task has terminal result evidence".into(),
            ));
        }
        return Ok(None);
    }
    let (Some(version), Some(event_seq), Some(terminal_at)) =
        (task_version, task_event_seq, terminal_at)
    else {
        return Err(StorageError::Quarantined(
            "terminal task lacks its result projection".into(),
        ));
    };
    if version != 1
        || !(0..=MAX_SAFE_INTEGER).contains(&task_generation)
        || !(1..=MAX_SAFE_INTEGER).contains(&event_seq)
        || last_event_seq != event_seq
        || projection_event_seq != event_seq
        || table_count(tx, "results", task_id)? != 1
        || table_count(tx, "result_outbox", task_id)? != 1
    {
        return Err(StorageError::Quarantined(
            "terminal task has invalid tuple cardinality".into(),
        ));
    }
    let (result_id, result_event_seq, result_digest, result_created): (String, i64, String, i64) =
        tx.query_row(
            "SELECT result_id,terminal_event_seq,result_digest,created_at \
             FROM results WHERE task_id=?1 AND result_version=?2",
            rusqlite::params![task_id, version],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(map_query_error)?;
    let outbox: Option<Outbox> = tx
        .query_row(
            "SELECT result_id,ack_token,terminal_event_seq,created_at,acked_at,review_id \
             FROM result_outbox WHERE consumer_id=?1 AND task_id=?2 AND result_version=?3",
            rusqlite::params![consumer_id, task_id, version],
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
        .optional()
        .map_err(map_query_error)?;
    let Some((outbox_result_id, ack_token, outbox_event_seq, outbox_created, acked_at, review_id)) =
        outbox
    else {
        return Err(StorageError::Quarantined(
            "terminal result lacks its consumer outbox tuple".into(),
        ));
    };
    if result_event_seq != event_seq
        || outbox_event_seq != event_seq
        || outbox_result_id != result_id
        || result_created != outbox_created
        || !is_lower_sha256(&result_digest)
        || !is_lower_sha256(&ack_token)
        || terminal_at != result_created
        || us_to_ms(result_created).is_err()
    {
        return Err(StorageError::Quarantined(
            "terminal task/result/outbox tuple mismatch".into(),
        ));
    }
    verify_terminal_event(
        tx,
        task_id,
        event_seq,
        task_generation,
        terminal_at,
        &state,
        &result_id,
    )?;
    let review = load_review(
        tx,
        consumer_id,
        task_id,
        version,
        &result_id,
        &ack_token,
        acked_at,
        review_id.as_deref(),
    )?;
    let value = json!({
        "version":1,"kind":"result","result_id":result_id,"task_id":task_id,
        "state":state,"result_version":version,"ack_token":ack_token,
        "ack_status":if acked_at.is_some(){"ACKNOWLEDGED"}else{"PENDING"}
    });
    validate(value.clone(), "terminal result")?;
    let delivery = ResultDelivery {
        task_id: task_id.into(),
        result_id,
        result_version: version,
        ack_token,
        terminal_event_seq: event_seq,
        terminal_state: state,
    };
    Ok(Some(ResultRead {
        value,
        terminal_event_seq: event_seq,
        delivery,
        review,
    }))
}

fn table_count(tx: &Transaction<'_>, table: &str, task_id: &str) -> Result<i64> {
    let sql = match table {
        "results" => "SELECT COUNT(*) FROM results WHERE task_id=?1",
        "result_outbox" => "SELECT COUNT(*) FROM result_outbox WHERE task_id=?1",
        _ => {
            return Err(StorageError::Quarantined(
                "invalid internal table selector".into(),
            ));
        }
    };
    tx.query_row(sql, [task_id], |row| row.get(0))
        .map_err(map_query_error)
}

fn verify_terminal_event(
    tx: &Transaction<'_>,
    task_id: &str,
    event_seq: i64,
    task_generation: i64,
    terminal_at: i64,
    state: &str,
    result_id: &str,
) -> Result<()> {
    type EventRow = (String, i64, String, i64, i64);
    let row: EventRow = tx
        .query_row(
            "SELECT event_id,generation,kind,length(CAST(payload AS BLOB)),committed_at \
             FROM events WHERE task_id=?1 AND event_seq=?2",
            rusqlite::params![task_id, event_seq],
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
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::Quarantined("terminal event is missing".into())
            }
            other => map_query_error(other),
        })?;
    let payload_length = usize::try_from(row.3)
        .ok()
        .filter(|length| *length <= MAX_EVENT_PAYLOAD_BYTES)
        .ok_or_else(|| StorageError::Quarantined("terminal event payload is oversized".into()))?;
    let payload: String = tx
        .query_row(
            "SELECT payload FROM events WHERE task_id=?1 AND event_seq=?2",
            rusqlite::params![task_id, event_seq],
            |row| row.get(0),
        )
        .map_err(map_query_error)?;
    if payload.len() != payload_length {
        return Err(StorageError::Quarantined(
            "terminal event payload length changed inside its snapshot".into(),
        ));
    }
    let event = public_event(&row.0, task_id, event_seq, row.1, &row.2, &payload, row.4)?;
    if row.1 != task_generation
        || row.4 != terminal_at
        || event.value["event_type"] != "terminal"
        || event.value["payload"]["state"] != state
        || event.value["payload"]["result_id"] != result_id
    {
        return Err(StorageError::Quarantined(
            "terminal event disagrees with result identity".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn load_review(
    tx: &Transaction<'_>,
    consumer_id: &str,
    task_id: &str,
    result_version: i64,
    result_id: &str,
    ack_token: &str,
    acked_at: Option<i64>,
    review_id: Option<&str>,
) -> Result<Option<ReviewRead>> {
    match (acked_at, review_id) {
        (None, None) => {
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM reviews \
                     WHERE task_id=?1 AND result_version=?2",
                    rusqlite::params![task_id, result_version],
                    |row| row.get(0),
                )
                .map_err(map_query_error)?;
            if count != 0 {
                return Err(StorageError::Quarantined(
                    "unacknowledged result has review evidence".into(),
                ));
            }
            Ok(None)
        }
        (Some(acked_at), Some(review_id)) => {
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM reviews WHERE task_id=?1 AND result_version=?2",
                    rusqlite::params![task_id, result_version],
                    |row| row.get(0),
                )
                .map_err(map_query_error)?;
            if count != 1 {
                return Err(StorageError::Quarantined(
                    "acknowledged result has ambiguous review evidence".into(),
                ));
            }
            let (review_consumer, review_task, review_version, digest, verdict, diagnosis, created): (
                String,
                String,
                i64,
                String,
                String,
                Option<String>,
                i64,
            ) = tx
                .query_row(
                    "SELECT consumer_id,task_id,result_version,review_digest,verdict,\
                            diagnosis_ref,created_at \
                     FROM reviews WHERE review_id=?1",
                    [review_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => {
                        StorageError::Quarantined("acknowledged result lacks review row".into())
                    }
                    other => map_query_error(other),
                })?;
            if review_consumer != consumer_id
                || review_task != task_id
                || review_version != result_version
                || created != acked_at
                || !is_lower_sha256(&digest)
                || !matches!(verdict.as_str(), "ACCEPTED" | "REJECTED")
                || diagnosis
                    .as_deref()
                    .is_some_and(|text| text.chars().count() > 8192)
            {
                return Err(StorageError::Quarantined(
                    "acknowledged result has invalid review evidence".into(),
                ));
            }
            let reviewed_at_ms = us_to_ms(created)?;
            verify_review_command_binding(
                tx,
                consumer_id,
                task_id,
                result_version,
                result_id,
                ack_token,
                &digest,
                &verdict,
                diagnosis.as_deref(),
            )?;
            Ok(Some(ReviewRead {
                verdict,
                reviewed_at_ms,
                diagnosis,
            }))
        }
        _ => Err(StorageError::Quarantined(
            "ACK and review evidence are only valid as one tuple".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_review_command_binding(
    tx: &Transaction<'_>,
    consumer_id: &str,
    task_id: &str,
    result_version: i64,
    result_id: &str,
    ack_token: &str,
    review_digest: &str,
    verdict: &str,
    diagnosis: Option<&str>,
) -> Result<()> {
    type Binding = (String, String, String, String, Option<String>);
    let mut statement = tx
        .prepare(
            "SELECT command_key,request_digest,response_kind,outcome,response_json \
             FROM command_dedup \
             WHERE consumer_id=?1 AND method='review_ack' AND response_locator=?2",
        )
        .map_err(map_query_error)?;
    let bindings = statement
        .query_map(rusqlite::params![consumer_id, result_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(map_query_error)?
        .collect::<std::result::Result<Vec<Binding>, _>>()
        .map_err(map_query_error)?;
    let [(command_key, request_digest, response_kind, outcome, response_json)] =
        bindings.as_slice()
    else {
        return Err(StorageError::Quarantined(
            "review has ambiguous command binding".into(),
        ));
    };
    if request_digest != review_digest
        || response_kind != "LOCATOR"
        || outcome != "COMMITTED"
        || response_json.is_some()
    {
        return Err(StorageError::Quarantined(
            "review command outcome metadata mismatch".into(),
        ));
    }
    let mut command = json!({
        "version":1,"kind":"command","action":"review_ack",
        "command_key":command_key,"task_id":task_id,"result_id":result_id,
        "result_version":result_version,"ack_token":ack_token,"verdict":verdict
    });
    if let Some(diagnosis) = diagnosis {
        command
            .as_object_mut()
            .expect("JSON object literal")
            .insert("diagnosis".into(), Value::String(diagnosis.into()));
    }
    decode_v1(command.clone())
        .map_err(|_| StorageError::Quarantined("review reconstructs invalid command".into()))?;
    let canonical = canonicalize(&command)
        .map_err(|_| StorageError::Quarantined("review cannot be canonicalized".into()))?;
    if format!("{:x}", Sha256::digest(canonical.as_bytes())) != review_digest {
        return Err(StorageError::Quarantined(
            "review command digest disagrees with semantic evidence".into(),
        ));
    }
    Ok(())
}

fn public_event(
    id: &str,
    task_id: &str,
    seq: i64,
    generation: i64,
    kind: &str,
    payload: &str,
    committed_at: i64,
) -> Result<PublicEvent> {
    if !(1..=MAX_SAFE_INTEGER).contains(&seq) || !(0..=MAX_SAFE_INTEGER).contains(&generation) {
        return Err(StorageError::Quarantined(format!(
            "event has invalid sequence or generation: {id}"
        )));
    }
    let mut payload: Value = parse_strict_json(payload)
        .map_err(|_| StorageError::Quarantined(format!("event has invalid JSON payload: {id}")))?;
    redact_event_free_text(kind, &mut payload);
    let value = json!({"version":1,"kind":"event","event_id":id,"task_id":task_id,"seq":seq,"occurred_at_ms":us_to_ms(committed_at)?,"event_type":kind,"payload":payload});
    validate(value.clone(), "event")?;
    Ok(PublicEvent {
        event_id: id.into(),
        task_id: task_id.into(),
        seq,
        generation,
        committed_at_us: committed_at,
        value,
    })
}

fn redact_event_free_text(kind: &str, payload: &mut Value) {
    let field = match kind {
        "text_delta" => "text",
        "warning" => "warning",
        "protocol_error" => "message",
        _ => return,
    };
    let Some(text) = payload.get(field).and_then(Value::as_str) else {
        return;
    };
    let (redacted, _) = crate::adapters::sanitize_raw(&Value::String(text.to_owned()));
    if let Some(object) = payload.as_object_mut() {
        object.insert(field.to_owned(), redacted);
    }
}

fn us_to_ms(value: i64) -> Result<i64> {
    let milliseconds = value / 1000;
    if value < 0 || milliseconds > MAX_SAFE_INTEGER {
        Err(StorageError::Quarantined(
            "persisted timestamp is outside protocol bounds".into(),
        ))
    } else {
        Ok(milliseconds)
    }
}

fn row_string(row: &rusqlite::Row<'_>, index: usize, label: &str) -> Result<String> {
    row.get(index)
        .map_err(|_| StorageError::Quarantined(format!("invalid persisted {label}")))
}

fn row_i64(row: &rusqlite::Row<'_>, index: usize, label: &str) -> Result<i64> {
    row.get(index)
        .map_err(|_| StorageError::Quarantined(format!("invalid persisted {label}")))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_wire_result(method: &str, result: &Value) -> Result<()> {
    let value = json!({"jsonrpc":"2.0","id":0,"result":result});
    decode_wire_v1(value).map(|_| ()).map_err(|_| {
        StorageError::Quarantined(format!("{method} result fails protocol v1 validation"))
    })
}

fn validate(value: Value, label: &str) -> Result<()> {
    decode_v1(value)
        .map(|_| ())
        .map_err(|_| StorageError::Quarantined(format!("{label} fails protocol v1 validation")))
}
fn normalize_query_error(error: StorageError) -> StorageError {
    match error {
        StorageError::Sql(error) => map_query_error(error),
        other => other,
    }
}
fn map_query_error(error: rusqlite::Error) -> StorageError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::OperationInterrupted
            | rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked,
        ) => StorageError::QueryDeadline,
        _ => StorageError::Sql(error),
    }
}
struct Permit(Arc<(Mutex<usize>, Condvar)>);
impl Drop for Permit {
    fn drop(&mut self) {
        let (lock, wake) = &*self.0;
        if let Ok(mut value) = lock.lock() {
            *value += 1;
            wake.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{DispatchPhase, InteractionCapabilityClass, ReviewVerdict},
        storage::{AttemptSpec, Interaction, ResultDelivery},
        writer::WriterHandle,
    };

    const D: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const P: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    fn canonical(value: &Value) -> Vec<u8> {
        crate::canonicalize(value).unwrap().into_bytes()
    }
    fn setup() -> (tempfile::TempDir, WriterHandle, ReaderPool) {
        let temp = tempfile::tempdir().unwrap();
        let writer = WriterHandle::start_portable(temp.path().to_path_buf(), "install", 1).unwrap();
        let reader = ReaderPool::open(temp.path()).unwrap();
        (temp, writer, reader)
    }

    fn canonical_task_request() -> Vec<u8> {
        let value: Value = serde_json::from_str(include_str!(
            "../../../protocol/v1/golden/task-request.json"
        ))
        .unwrap();
        canonical(&value)
    }

    fn submit_valid(writer: &WriterHandle, task_id: &str, now_us: i64) {
        writer
            .submit(
                "c",
                format!("submit-{task_id}"),
                format!("key-{task_id}"),
                canonical_task_request(),
                task_id,
                None,
                now_us,
            )
            .unwrap();
    }

    fn begin_attempt(writer: &WriterHandle, task_id: &str, now_us: i64) -> String {
        writer
            .begin_attempt(
                "c",
                format!("begin-{task_id}"),
                format!("begin-{task_id}").into_bytes(),
                task_id,
                0,
                AttemptSpec {
                    adapter_instance_id: "agent-1".into(),
                    config_digest: C.into(),
                    ..AttemptSpec::default()
                },
                now_us,
            )
            .unwrap()
            .attempt_id
    }

    fn open_approval(
        writer: &WriterHandle,
        task_id: &str,
        attempt_id: &str,
        operation_id: &str,
        now_us: i64,
    ) -> Interaction {
        writer
            .open_interaction(
                operation_id,
                task_id,
                attempt_id,
                0,
                D,
                P,
                C,
                InteractionCapabilityClass::Approval,
                1,
                1,
                now_us + 10_000,
                now_us,
            )
            .unwrap()
    }

    fn answer_approval(writer: &WriterHandle, interaction: &Interaction, command_key: &str) {
        let response = json!({"kind":"approve"});
        let command = json!({
            "version":1,"kind":"command","action":"interaction_response",
            "command_key":command_key,"task_id":interaction.task_id,
            "interaction_id":interaction.interaction_id,"generation":0,
            "operation_digest":D,"policy_digest":P,"config_digest":C,
            "nonce":interaction.nonce,"response":response
        });
        writer
            .respond_interaction(
                "c",
                command_key,
                canonical(&command),
                interaction.interaction_id.clone(),
                interaction.nonce.clone(),
                0,
                D,
                P,
                C,
                crate::domain::InteractionResponseKind::Approve,
                canonical(&response),
                5,
            )
            .unwrap();
    }

    fn finalize_task(writer: &WriterHandle, task_id: &str) -> ResultDelivery {
        let _ = begin_attempt(writer, task_id, 3);
        writer
            .record_dispatch_phase(
                format!("started-{task_id}"),
                task_id,
                0,
                DispatchPhase::ProcessStarted,
                Some(format!("pid-{task_id}")),
                4,
            )
            .unwrap();
        writer
            .transition(
                format!("finalizing-{task_id}"),
                task_id,
                0,
                vec!["RUNNING".into()],
                "FINALIZING",
                6,
            )
            .unwrap();
        writer
            .finalize(
                "c",
                format!("final-{task_id}"),
                format!("final-{task_id}").into_bytes(),
                task_id,
                0,
                "SUCCEEDED",
                D,
                7,
            )
            .unwrap()
    }
    #[test]
    fn pressure_has_hard_thresholds() {
        assert_eq!(wal_pressure(32 * 1024 * 1024 - 1), WalPressure::Normal);
        assert_eq!(wal_pressure(128 * 1024 * 1024), WalPressure::FenceDispatch);
    }
    #[test]
    fn public_event_preserves_id_timestamp_and_validates() {
        let (_root, w, r) = setup();
        w.submit("c","submit","k",canonical(&json!({"version":1,"kind":"task_request","task_id":"task","instruction":"x","adapter":"auto","idempotency_key":"k"})),"task",None,2_345).unwrap();
        let page = r
            .public_events_after("task", 0, 200, Duration::from_secs(1), Some("c"))
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].committed_at_us, 2_345);
        assert!(!page.events[0].event_id.is_empty());
        assert_eq!(page.events[0].value["occurred_at_ms"], 2);
        w.shutdown().unwrap();
    }
    #[test]
    fn public_event_redacts_sensitive_free_text() {
        for (kind, field) in [
            ("text_delta", "text"),
            ("warning", "warning"),
            ("protocol_error", "message"),
        ] {
            let mut payload = json!({field: "provider echoed sk-sensitive-value"});
            if kind == "protocol_error" {
                payload["code"] = Value::String("provider_error".into());
            }
            let event = public_event(
                "event-redacted",
                "task-redacted",
                1,
                0,
                kind,
                &payload.to_string(),
                1_000,
            )
            .expect("valid redacted event");
            assert_eq!(event.value["payload"][field], "[redacted]");
            assert!(!event.value.to_string().contains("sk-sensitive-value"));
        }
    }
    #[test]
    fn snapshot_handles_null_attempt_interaction_and_result() {
        let (_root, w, r) = setup();
        w.submit("c", "submit", "k", b"body".to_vec(), "task", None, 2)
            .unwrap();
        let snapshot = r.snapshot("task", "c", Duration::from_secs(1)).unwrap();
        assert!(
            snapshot.attempt.is_none()
                && snapshot.interaction.is_none()
                && snapshot.result.is_none()
        );
        w.shutdown().unwrap();
    }
    #[test]
    fn snapshot_exposes_interaction_and_terminal_review() {
        let (_root, w, r) = setup();
        w.submit("c", "submit", "k", b"body".to_vec(), "task", None, 2)
            .unwrap();
        let attempt = w
            .begin_attempt(
                "c",
                "b",
                b"b".to_vec(),
                "task",
                0,
                AttemptSpec {
                    adapter_instance_id: "agent-1".into(),
                    config_digest: C.into(),
                    ..AttemptSpec::default()
                },
                3,
            )
            .unwrap();
        let interaction = w
            .open_interaction(
                "open",
                "task",
                attempt.attempt_id.clone(),
                0,
                D,
                P,
                C,
                InteractionCapabilityClass::Approval,
                1,
                1,
                20_000,
                4,
            )
            .unwrap();
        let snapshot = r.snapshot("task", "c", Duration::from_secs(1)).unwrap();
        assert_eq!(snapshot.interaction.unwrap().value["status"], "PENDING");
        let response = canonical(&json!({"kind":"approve"}));
        let response_command = canonical(&json!({
            "version":1,"kind":"command","action":"interaction_response",
            "command_key":"respond","task_id":"task","interaction_id":interaction.interaction_id,
            "generation":0,"operation_digest":D,"policy_digest":P,"config_digest":C,
            "nonce":interaction.nonce,"response":{"kind":"approve"}
        }));
        w.respond_interaction(
            "c",
            "respond",
            response_command,
            interaction.interaction_id,
            interaction.nonce,
            0,
            D,
            P,
            C,
            crate::domain::InteractionResponseKind::Approve,
            response,
            5,
        )
        .unwrap();
        w.transition(
            "finalizing",
            "task",
            0,
            vec!["RUNNING".into()],
            "FINALIZING",
            6,
        )
        .unwrap();
        let delivery = w
            .finalize(
                "c",
                "final",
                b"final".to_vec(),
                "task",
                0,
                "CANCELLED",
                D,
                7,
            )
            .unwrap();
        let command = canonical(
            &json!({"version":1,"kind":"command","action":"review_ack","command_key":"review","task_id":"task","result_id":delivery.result_id,"result_version":1,"ack_token":delivery.ack_token,"verdict":"ACCEPTED"}),
        );
        w.review_and_ack(
            "c",
            "review",
            command,
            delivery,
            ReviewVerdict::Accepted,
            None,
            7,
        )
        .unwrap();
        let snapshot = r.snapshot("task", "c", Duration::from_secs(1)).unwrap();
        let result = snapshot.result.unwrap();
        assert_eq!(result.value["ack_status"], "ACKNOWLEDGED");
        assert_eq!(result.review.unwrap().verdict, "ACCEPTED");
        w.shutdown().unwrap();
    }
    #[test]
    fn corrupt_event_and_incomplete_interaction_fail_closed() {
        let (root, w, r) = setup();
        w.submit("c", "submit", "k", b"body".to_vec(), "task", None, 2)
            .unwrap();
        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute("UPDATE events SET payload='{}' WHERE task_id='task'", [])
            .unwrap();
        drop(db);
        assert!(matches!(
            r.public_events_after("task", 0, 1, Duration::from_secs(1), Some("c")),
            Err(StorageError::Quarantined(_))
        ));
        w.shutdown().unwrap();
    }
    #[test]
    fn cursor_boundary_and_saturation_are_bounded() {
        let (_root, w, r) = setup();
        w.submit("c", "submit", "k", b"body".to_vec(), "task", None, 2)
            .unwrap();
        assert!(matches!(
            r.public_events_after("task", -1, 1, Duration::from_secs(1), None),
            Err(StorageError::InvalidRequest)
        ));
        let permits = (0..MAX_READERS)
            .map(|_| r.acquire(Duration::from_millis(1)).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            r.acquire(Duration::from_millis(1)),
            Err(StorageError::ReaderSaturated)
        ));
        drop(permits);
        w.shutdown().unwrap();
    }

    #[test]
    fn cursor_rejects_future_gaps_invalid_limits_and_output_overflow() {
        let (root, w, r) = setup();
        submit_valid(&w, "task", 2);
        w.transition("prepare", "task", 0, vec!["QUEUED".into()], "PREPARING", 3)
            .unwrap();

        for limit in [0, 201] {
            assert!(matches!(
                r.public_events_after("task", 0, limit, Duration::from_secs(1), None),
                Err(StorageError::InvalidRequest)
            ));
        }
        assert!(matches!(
            r.public_events_after("task", 3, 1, Duration::from_secs(1), None),
            Err(StorageError::InvalidRequest)
        ));
        assert!(matches!(
            r.public_events_after_bounded(
                "task",
                0,
                1,
                mesh_win32::RESPONSE_FRAME_LIMIT + 1,
                Duration::from_secs(1),
                None,
            ),
            Err(StorageError::InvalidRequest)
        ));
        assert!(matches!(
            r.public_events_after_bounded("task", 0, 1, 1, Duration::from_secs(1), None),
            Err(StorageError::OutputLimitExceeded)
        ));

        let full = r
            .public_events_after("task", 0, 2, Duration::from_secs(1), None)
            .unwrap();
        let first_size = serde_json::to_vec(&full.events[0].value).unwrap().len();
        let short = r
            .public_events_after_bounded("task", 0, 2, first_size, Duration::from_secs(1), None)
            .unwrap();
        assert_eq!(short.events.len(), 1);
        assert_eq!(short.next_seq, 1);

        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute(
            "DELETE FROM events WHERE task_id='task' AND event_seq=1",
            [],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            r.public_events_after("task", 0, 2, Duration::from_secs(1), None),
            Err(StorageError::Quarantined(_))
        ));
        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute(
            "UPDATE tasks SET evicted_through_seq=?1,last_event_seq=?1 WHERE task_id='task'",
            [MAX_SAFE_INTEGER],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            r.snapshot("task", "c", Duration::from_secs(1)),
            Err(StorageError::Quarantined(_))
        ));
        w.shutdown().unwrap();
    }

    #[test]
    fn task_request_requires_exact_canonical_schema_evidence() {
        let (root, w, r) = setup();
        submit_valid(&w, "task", 2);
        let request = r.task_request("task", Duration::from_secs(1)).unwrap();
        assert_eq!(request.bytes, canonical_task_request());

        let corrupt = br#"{"version":1,"version":1}"#.to_vec();
        let digest = format!("{:x}", Sha256::digest(&corrupt));
        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute(
            "UPDATE task_requests SET request_digest=?1,request_bytes=?2,byte_length=?3 \
             WHERE task_id='task'",
            rusqlite::params![digest, corrupt, 25_i64],
        )
        .unwrap();
        db.execute(
            "UPDATE tasks SET request_digest=?1 WHERE task_id='task'",
            [digest],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            r.task_request("task", Duration::from_secs(1)),
            Err(StorageError::Quarantined(_))
        ));

        submit_valid(&w, "oversized", 3);
        let oversized = vec![b'x'; MAX_CANONICAL_REQUEST_BYTES + 1];
        let oversized_digest = format!("{:x}", Sha256::digest(&oversized));
        let oversized_length = i64::try_from(oversized.len()).unwrap();
        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute(
            "UPDATE task_requests SET request_digest=?1,request_bytes=?2,byte_length=?3 \
             WHERE task_id='oversized'",
            rusqlite::params![oversized_digest, oversized, oversized_length],
        )
        .unwrap();
        db.execute(
            "UPDATE tasks SET request_digest=?1 WHERE task_id='oversized'",
            [oversized_digest],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            r.task_request("oversized", Duration::from_secs(1)),
            Err(StorageError::Quarantined(_))
        ));
        w.shutdown().unwrap();
    }

    #[test]
    fn config_projection_accepts_only_the_frozen_empty_config() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../protocol/v1/digest-vectors.json")).unwrap();
        let config_vector = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "config-v1")
            .unwrap();
        assert_eq!(config_vector["digest"], EMPTY_CONFIG_V1_DIGEST);
        let (root, w, r) = setup();
        assert!(matches!(
            r.empty_config(Duration::from_secs(1)),
            Err(StorageError::Quarantined(_))
        ));
        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO config_versions(version,config_digest,created_at) VALUES(1,?1,1)",
            [EMPTY_CONFIG_V1_DIGEST],
        )
        .unwrap();
        assert_eq!(
            r.empty_config(Duration::from_secs(1)).unwrap().value,
            json!({"kind":"list_agents_result","agents":[],"config_version":1})
        );
        db.execute(
            "INSERT INTO config_versions(version,config_digest,created_at) VALUES(2,?1,2)",
            [EMPTY_CONFIG_V1_DIGEST],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            r.empty_config(Duration::from_secs(1)),
            Err(StorageError::Quarantined(_))
        ));
        w.shutdown().unwrap();
    }

    #[test]
    fn exact_interaction_read_verifies_response_and_command_binding() {
        let (root, w, r) = setup();
        submit_valid(&w, "task", 2);
        let attempt = begin_attempt(&w, "task", 3);
        let first = open_approval(&w, "task", &attempt, "open-1", 4);
        answer_approval(&w, &first, "respond-1");
        let first_read = r
            .interaction_by_id("task", &first.interaction_id, "c", Duration::from_secs(1))
            .unwrap();
        assert_eq!(first_read.value["status"], "APPROVED");
        assert!(matches!(
            r.interaction_by_id(
                "task",
                &first.interaction_id,
                "other",
                Duration::from_secs(1),
            ),
            Err(StorageError::Quarantined(_))
        ));

        let second = open_approval(&w, "task", &attempt, "open-2", 6);
        assert_eq!(
            r.interaction_by_id("task", &first.interaction_id, "c", Duration::from_secs(1),)
                .unwrap()
                .value["status"],
            "APPROVED"
        );
        assert_eq!(
            r.snapshot("task", "c", Duration::from_secs(1))
                .unwrap()
                .interaction
                .unwrap()
                .value["interaction_id"],
            second.interaction_id
        );

        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute(
            "UPDATE interaction_responses SET response_digest=?1 \
             WHERE interaction_id=?2",
            rusqlite::params![P, first.interaction_id],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            r.interaction_by_id("task", &first.interaction_id, "c", Duration::from_secs(1),),
            Err(StorageError::Quarantined(_))
        ));
        w.shutdown().unwrap();
    }

    #[test]
    fn exact_interaction_read_rejects_temporal_and_state_mismatch() {
        for corruption in ["timestamp", "state"] {
            let (root, w, r) = setup();
            submit_valid(&w, "task", 2);
            let attempt = begin_attempt(&w, "task", 3);
            let interaction = open_approval(&w, "task", &attempt, "open", 4);
            answer_approval(&w, &interaction, "respond");
            let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
            match corruption {
                "timestamp" => {
                    db.execute(
                        "UPDATE pending_interactions SET updated_at=6 WHERE interaction_id=?1",
                        [&interaction.interaction_id],
                    )
                    .unwrap();
                }
                "state" => {
                    db.execute(
                        "UPDATE pending_interactions SET state='PENDING' WHERE interaction_id=?1",
                        [&interaction.interaction_id],
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            drop(db);
            assert!(matches!(
                r.interaction_by_id(
                    "task",
                    &interaction.interaction_id,
                    "c",
                    Duration::from_secs(1),
                ),
                Err(StorageError::Quarantined(_))
            ));
            w.shutdown().unwrap();
        }
    }

    #[test]
    fn exact_interaction_read_quarantines_nullable_response_evidence() {
        for missing in ["kind", "bytes", "length", "digest"] {
            let (root, w, r) = setup();
            submit_valid(&w, "task", 2);
            let attempt = begin_attempt(&w, "task", 3);
            let interaction = open_approval(&w, "task", &attempt, "open", 4);
            answer_approval(&w, &interaction, "respond");
            let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
            let sql = match missing {
                "kind" => {
                    "UPDATE interaction_responses SET response_kind=NULL WHERE interaction_id=?1"
                }
                "bytes" => {
                    "UPDATE interaction_responses SET response_bytes=NULL WHERE interaction_id=?1"
                }
                "length" => {
                    "UPDATE interaction_responses SET byte_length=NULL WHERE interaction_id=?1"
                }
                "digest" => {
                    "UPDATE interaction_responses SET response_digest=NULL WHERE interaction_id=?1"
                }
                _ => unreachable!(),
            };
            db.execute(sql, [&interaction.interaction_id]).unwrap();
            drop(db);
            assert!(matches!(
                r.interaction_by_id(
                    "task",
                    &interaction.interaction_id,
                    "c",
                    Duration::from_secs(1),
                ),
                Err(StorageError::Quarantined(_))
            ));
            w.shutdown().unwrap();
        }
    }

    #[test]
    fn snapshot_deadline_includes_reader_permit_wait() {
        let (_root, w, r) = setup();
        submit_valid(&w, "task", 2);
        let mut permits = (0..MAX_READERS)
            .map(|_| r.acquire(Duration::from_millis(1)).unwrap())
            .collect::<Vec<_>>();
        let delayed = permits.pop().unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(delayed);
        });
        let started = Instant::now();
        let result = r.with_snapshot(Duration::from_millis(300), |_tx| {
            std::thread::sleep(Duration::from_millis(250));
            Ok(())
        });
        assert!(matches!(result, Err(StorageError::QueryDeadline)));
        assert!(started.elapsed() < Duration::from_millis(600));
        release.join().unwrap();
        drop(permits);
        w.shutdown().unwrap();
    }

    #[test]
    fn terminal_projection_rejects_broken_result_outbox_review_and_event_tuples() {
        for corruption in [
            "missing_result",
            "outbox",
            "ack_without_review",
            "terminal_event",
            "terminal_timestamp",
            "projection_sequence",
        ] {
            let (root, w, r) = setup();
            submit_valid(&w, "task", 2);
            let delivery = finalize_task(&w, "task");
            let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
            // Corruption fixtures bypass relational guards to model a damaged
            // file reopened by the fail-closed reader.
            db.pragma_update(None, "foreign_keys", "OFF").unwrap();
            match corruption {
                "missing_result" => {
                    db.execute("DELETE FROM results WHERE task_id='task'", [])
                        .unwrap();
                }
                "outbox" => {
                    db.execute(
                        "UPDATE result_outbox SET result_id='wrong' WHERE task_id='task'",
                        [],
                    )
                    .unwrap();
                }
                "ack_without_review" => {
                    db.execute(
                        "UPDATE result_outbox SET acked_at=8 WHERE task_id='task'",
                        [],
                    )
                    .unwrap();
                }
                "terminal_event" => {
                    db.execute(
                        "UPDATE events SET payload=?1 WHERE task_id='task' AND event_seq=?2",
                        rusqlite::params![
                            json!({"state":"SUCCEEDED","result_id":"wrong"}).to_string(),
                            delivery.terminal_event_seq
                        ],
                    )
                    .unwrap();
                }
                "terminal_timestamp" => {
                    db.execute(
                        "UPDATE events SET committed_at=8 \
                         WHERE task_id='task' AND event_seq=?1",
                        [delivery.terminal_event_seq],
                    )
                    .unwrap();
                }
                "projection_sequence" => {
                    db.execute(
                        "UPDATE tasks SET projection_event_seq=terminal_event_seq-1 \
                         WHERE task_id='task'",
                        [],
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            drop(db);
            assert!(matches!(
                r.snapshot("task", "c", Duration::from_secs(1)),
                Err(StorageError::Quarantined(_))
            ));
            w.shutdown().unwrap();
        }
    }

    #[test]
    fn terminal_projection_rejects_review_identity_drift() {
        let (root, w, r) = setup();
        submit_valid(&w, "task", 2);
        let delivery = finalize_task(&w, "task");
        let command = canonical(&json!({
            "version":1,"kind":"command","action":"review_ack","command_key":"review",
            "task_id":"task","result_id":delivery.result_id,"result_version":1,
            "ack_token":delivery.ack_token,"verdict":"ACCEPTED"
        }));
        w.review_and_ack(
            "c",
            "review",
            command,
            delivery,
            ReviewVerdict::Accepted,
            None,
            8,
        )
        .unwrap();
        assert!(
            r.snapshot("task", "c", Duration::from_secs(1))
                .unwrap()
                .result
                .unwrap()
                .review
                .is_some()
        );

        let db = Connection::open(root.path().join("mesh.sqlite3")).unwrap();
        db.execute(
            "UPDATE reviews SET consumer_id='other' WHERE task_id='task'",
            [],
        )
        .unwrap();
        drop(db);
        assert!(matches!(
            r.snapshot("task", "c", Duration::from_secs(1)),
            Err(StorageError::Quarantined(_))
        ));
        w.shutdown().unwrap();
    }
}
