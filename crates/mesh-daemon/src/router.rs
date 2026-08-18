//! Exact M3 task-method routing from authenticated RPC requests to durable
//! reader/writer boundaries.
//!
//! This module deliberately owns no provider, scheduler, or process state.
//! Until those components exist, `delegate_task` durably accepts a task but
//! does not invent an adapter assignment or execution progress.

#![allow(clippy::missing_errors_doc)]

use std::{
    net::SocketAddr,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    EffectClass, ErrorCode, LifecycleEvidence, RetryClass,
    adapters::registry::AdapterRegistry,
    canonicalize, classify_retry,
    dashboard::SessionStore,
    domain::{InteractionResponseKind, ReviewVerdict},
    improvement::{
        CandidateDecision, CandidateKnob, CandidateProposal, CaseSnapshot, EvaluationDecision,
        FixtureOutcome,
    },
    protocol_handshake::{
        PendingRequest, RpcEffectClass, RpcErrorSpec, RpcLifecycle, RpcMethod, RpcResponse,
        RpcRetryClass, SessionError,
    },
    reader::{ReaderPool, TaskSnapshot},
    storage::StorageError,
    writer::WriterHandle,
};

#[cfg(windows)]
use crate::dispatcher::DispatchWake;

const CONFIG_VERSION_V1: u64 = 1;
const DIAGNOSTIC_REF: &str = "router";
const DASHBOARD_NOTICE: &str = "Bootstrap URL is single-use and must not be logged or persisted.";

/// Explicit dashboard bootstrap material exposed only by authenticated
/// `inspect_task` responses. The token-bearing URL is never durable and this
/// type deliberately has no `Debug` implementation.
pub(crate) struct DashboardAccess {
    base_url: String,
    sessions: Arc<SessionStore>,
}

impl DashboardAccess {
    #[must_use]
    pub(crate) fn new(address: SocketAddr, sessions: Arc<SessionStore>) -> Self {
        Self {
            base_url: format!("http://{address}"),
            sessions,
        }
    }

    fn projection(&self) -> Value {
        let bootstrap_token = self.sessions.mint_bootstrap();
        let bootstrap_url = format!("{}/bootstrap?token={bootstrap_token}", self.base_url);
        json!({
            "base_url": self.base_url,
            "bootstrap_url": bootstrap_url,
            "notice": DASHBOARD_NOTICE,
        })
    }
}

/// Supplies the durable timestamp used by writer commands. Production uses the
/// wall clock; tests inject a deterministic source.
pub trait RouterClock: Send + Sync {
    fn now_us(&self) -> Result<i64, RouterError>;
}

/// Production wall-clock source with safe-integer bounds.
pub struct SystemRouterClock;

impl RouterClock for SystemRouterClock {
    fn now_us(&self) -> Result<i64, RouterError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RouterError::clock())?;
        let micros = i64::try_from(elapsed.as_micros()).map_err(|_| RouterError::clock())?;
        if micros > 9_007_199_254_740_991_000 {
            return Err(RouterError::clock());
        }
        Ok(micros)
    }
}

/// Waits only between detached reader snapshots, so long polling cannot retain
/// a `SQLite` handle or reader-pool permit.
pub trait RouterSleeper: Send + Sync {
    fn sleep(&self, duration: Duration);
}

/// Production bounded sleeper.
pub struct ThreadRouterSleeper;

impl RouterSleeper for ThreadRouterSleeper {
    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// Stable, redaction-safe router failure. It intentionally contains no SQL,
/// filesystem, provider, authentication, or input text.
pub struct RouterError {
    spec: RpcErrorSpec,
}

impl std::fmt::Debug for RouterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RouterError(redacted)")
    }
}

impl RouterError {
    fn new(
        code: ErrorCode,
        effect: EffectClass,
        lifecycle: LifecycleEvidence,
        evidence: &str,
        message: &str,
    ) -> Self {
        let retry = classify_retry(code, effect, lifecycle);
        Self {
            spec: RpcErrorSpec::new(
                -32_000,
                code,
                map_retry(retry),
                map_effect(effect),
                map_lifecycle(lifecycle),
                evidence.into(),
                message.into(),
                DIAGNOSTIC_REF.into(),
            ),
        }
    }

    fn validation() -> Self {
        Self::new(
            ErrorCode::ValidationFailed,
            EffectClass::NoEffect,
            LifecycleEvidence::BeforeProcessCreation,
            "router_validation",
            "request parameters are inconsistent",
        )
    }

    fn deadline() -> Self {
        Self::new(
            ErrorCode::IpcIoTimeout,
            EffectClass::NoEffect,
            LifecycleEvidence::BeforeProcessCreation,
            "router_deadline",
            "request deadline elapsed",
        )
    }

    fn clock() -> Self {
        Self::new(
            ErrorCode::StorageUnavailable,
            EffectClass::NoEffect,
            LifecycleEvidence::BeforeProcessCreation,
            "router_clock",
            "durable clock is unavailable",
        )
    }

    #[allow(clippy::needless_pass_by_value)]
    fn from_storage(error: StorageError) -> Self {
        match error {
            StorageError::IdempotencyConflict => Self::new(
                ErrorCode::IdempotencyConflict,
                EffectClass::NoEffect,
                LifecycleEvidence::BeforeProcessCreation,
                "storage_idempotency",
                "command key conflicts with committed request",
            ),
            StorageError::CursorExpired { .. } => Self::new(
                ErrorCode::CursorExpired,
                EffectClass::NoEffect,
                LifecycleEvidence::BeforeProcessCreation,
                "storage_cursor",
                "requested cursor is no longer retained",
            ),
            StorageError::OutputLimitExceeded => Self::new(
                ErrorCode::OutputLimitExceeded,
                EffectClass::NoEffect,
                LifecycleEvidence::BeforeProcessCreation,
                "storage_output_limit",
                "durable response exceeds negotiated output limit",
            ),
            StorageError::InvalidRequest
            | StorageError::StaleGeneration
            | StorageError::TerminalImmutable
            | StorageError::AckMismatch
            | StorageError::AlreadyReviewed
            | StorageError::InteractionConflict => Self::validation(),
            StorageError::QuotaExceeded
            | StorageError::WriterBackpressure
            | StorageError::WalPressure
            | StorageError::QueryDeadline
            | StorageError::ReaderSaturated => Self::new(
                ErrorCode::StorageUnavailable,
                EffectClass::NoEffect,
                LifecycleEvidence::BeforeProcessCreation,
                "storage_admission",
                "durable storage admission is unavailable",
            ),
            StorageError::InvalidRoot(_)
            | StorageError::Quarantined(_)
            | StorageError::BlobCorruption(_)
            | StorageError::MigrationMismatch(_)
            | StorageError::RestoreRefused => Self::new(
                ErrorCode::StorageUnavailable,
                EffectClass::NoEffect,
                LifecycleEvidence::BeforeProcessCreation,
                "storage_integrity",
                "durable storage integrity is unavailable",
            ),
            StorageError::StorageEmergency | StorageError::Sql(_) | StorageError::Io(_) => {
                Self::new(
                    ErrorCode::StorageUnavailable,
                    EffectClass::UnknownEffect,
                    LifecycleEvidence::Unknown,
                    "storage_unavailable",
                    "durable storage is unavailable",
                )
            }
        }
    }

    fn adapter_unavailable() -> Self {
        Self::new(
            ErrorCode::AdapterUnavailable,
            EffectClass::NoEffect,
            LifecycleEvidence::BeforeProcessCreation,
            "adapter_unavailable",
            "no enabled adapter matches the requested role",
        )
    }

    #[cfg(test)]
    fn error_code(&self) -> ErrorCode {
        self.spec.code()
    }
}

/// Stateless projection router. The consumer is startup evidence, not supplied
/// by an RPC caller; it scopes all command idempotency and protected reads.
pub struct Router<C = SystemRouterClock, S = ThreadRouterSleeper> {
    reader: ReaderPool,
    writer: WriterHandle,
    consumer_id: String,
    clock: C,
    sleeper: S,
    dashboard: Option<DashboardAccess>,
    registry: Option<AdapterRegistry>,
    #[cfg(windows)]
    dispatch_wake: Option<DispatchWake>,
}

impl Router<SystemRouterClock> {
    #[must_use]
    pub fn new(reader: ReaderPool, writer: WriterHandle, consumer_id: String) -> Self {
        Self {
            reader,
            writer,
            consumer_id,
            clock: SystemRouterClock,
            sleeper: ThreadRouterSleeper,
            dashboard: None,
            registry: None,
            #[cfg(windows)]
            dispatch_wake: None,
        }
    }
}

impl<C: RouterClock> Router<C, ThreadRouterSleeper> {
    #[must_use]
    pub fn with_clock(
        reader: ReaderPool,
        writer: WriterHandle,
        consumer_id: String,
        clock: C,
    ) -> Self {
        Self {
            reader,
            writer,
            consumer_id,
            clock,
            sleeper: ThreadRouterSleeper,
            dashboard: None,
            registry: None,
            #[cfg(windows)]
            dispatch_wake: None,
        }
    }
}

impl<C: RouterClock, S: RouterSleeper> Router<C, S> {
    #[must_use]
    pub fn with_clock_and_sleeper(
        reader: ReaderPool,
        writer: WriterHandle,
        consumer_id: String,
        clock: C,
        sleeper: S,
    ) -> Self {
        Self {
            reader,
            writer,
            consumer_id,
            clock,
            sleeper,
            dashboard: None,
            registry: None,
            #[cfg(windows)]
            dispatch_wake: None,
        }
    }

    /// Attaches ephemeral bootstrap material for authenticated inspection.
    #[must_use]
    pub(crate) fn with_dashboard(mut self, dashboard: DashboardAccess) -> Self {
        self.dashboard = Some(dashboard);
        self
    }

    /// Attaches the production adapter registry used by `list_agents`.
    #[must_use]
    pub fn with_registry(mut self, registry: AdapterRegistry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Wakes the production dispatcher after a durable task is admitted.
    #[cfg(windows)]
    #[must_use]
    pub fn with_dispatch_wake(mut self, wake: DispatchWake) -> Self {
        self.dispatch_wake = Some(wake);
        self
    }

    /// Consumes the connection-bound request capability and returns a response
    /// bound to exactly that request ID and method.
    pub fn route(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
        if Instant::now() >= request.deadline() {
            return request.error(&RouterError::deadline().spec);
        }
        match self.dispatch(request.method(), request.params(), request.deadline()) {
            Ok(result) => request.success(&result),
            Err(error) => request.error(&error.spec),
        }
    }

    /// Testable method-level boundary. `PendingRequest` schema validation and
    /// capability binding happen before this function; it only returns values
    /// that `PendingRequest::success` validates against the authoritative schema.
    pub fn dispatch(
        &self,
        method: RpcMethod,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        if Instant::now() >= deadline {
            return Err(RouterError::deadline());
        }
        match method {
            RpcMethod::Health => Err(RouterError::validation()),
            RpcMethod::ListAgents => self.list_agents(deadline),
            RpcMethod::DelegateTask => self.delegate_task(params, deadline),
            RpcMethod::InspectTask => self.inspect_task(params, deadline),
            RpcMethod::WaitTask => self.wait_task(params, deadline),
            RpcMethod::SendTaskInput => self.send_task_input(params, deadline),
            RpcMethod::CancelTask => self.cancel_task(params, deadline),
            RpcMethod::ReviewTask => self.review_task(params, deadline),
            RpcMethod::ImprovementCase => self.improvement_case(params, deadline),
        }
    }

    fn list_agents(&self, deadline: Instant) -> Result<Value, RouterError> {
        self.remaining(deadline)?;
        let _config = self
            .reader
            .empty_config(self.remaining(deadline)?)
            .map_err(RouterError::from_storage)?;
        match &self.registry {
            Some(registry) => {
                let version = u64::try_from(registry.load_settings().config_version.max(1))
                    .unwrap_or(CONFIG_VERSION_V1);
                let mut value = registry.routing_projection();
                let object = value.as_object_mut().expect("routing projection");
                object.insert("kind".into(), json!("list_agents_result"));
                object.insert(
                    "agents".into(),
                    Value::Array(registry.list_protocol_values()),
                );
                object.insert("config_version".into(), json!(version));
                Ok(value)
            }
            None => Ok(json!({
                "kind": "list_agents_result",
                "agents": [],
                "config_version": CONFIG_VERSION_V1
            })),
        }
    }

    fn delegate_task(
        &self,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        let command = canonical_bytes(params)?;
        let command_key = text(params, "command_key")?;
        let retry_of_task_id = optional_text(params, "retry_of_task_id")?.map(str::to_owned);
        // Persisted scheduler inputs. Both are optional in the v1 task
        // request: priority defaults to FIFO (0) and the adapter instance may
        // be assigned later by the first scheduling claim.
        let priority = u8::try_from(params.get("priority").and_then(Value::as_u64).unwrap_or(0))
            .map_err(|_| RouterError::validation())?;
        let requested_adapter = optional_text(params, "adapter_instance_id")?;
        let assigned_adapter = self.assign_adapter(params, requested_adapter)?;
        let now_us = self.clock.now_us()?;
        self.remaining(deadline)?;
        let submission = self
            .writer
            .submit_for_scheduling(
                &self.consumer_id,
                "mesh.delegate_task",
                command_key,
                command,
                Uuid::new_v4().to_string(),
                retry_of_task_id,
                priority,
                assigned_adapter.as_deref(),
                now_us,
            )
            .map_err(RouterError::from_storage)?;
        #[cfg(windows)]
        if let Some(wake) = &self.dispatch_wake {
            wake.notify();
        }
        let snapshot = self.snapshot(&submission.task_id, deadline)?;
        let request = self
            .reader
            .task_request(&submission.task_id, self.remaining(deadline)?)
            .map_err(RouterError::from_storage)?;
        Ok(
            json!({"kind":"delegate_task_result","task":snapshot.task.value,"request_digest":request.digest}),
        )
    }

    fn inspect_task(
        &self,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        let task_id = text(params, "task_id")?;
        let snapshot = self.snapshot(task_id, deadline)?;
        let mut value = snapshot_value("inspect_task_result", &snapshot);
        if let Some(dashboard) = &self.dashboard {
            value
                .as_object_mut()
                .expect("snapshot projection is an object")
                .insert("dashboard".to_owned(), dashboard.projection());
        }
        Ok(value)
    }

    fn wait_task(
        &self,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        let task_id = text(params, "task_id")?;
        let after_seq = integer(params, "after_seq")?;
        let limit =
            usize::try_from(integer(params, "limit")?).map_err(|_| RouterError::validation())?;
        let wait_ms =
            u64::try_from(integer(params, "wait_ms")?).map_err(|_| RouterError::validation())?;
        let until = wait_until(params)?;
        let wait_deadline = Instant::now()
            .checked_add(Duration::from_millis(wait_ms))
            .ok_or_else(RouterError::deadline)?;
        // `wait_ms` bounds how long we poll for later events. The first
        // detached read still uses the request deadline so a short wait
        // cannot turn a slow empty snapshot into a transport error.
        let poll_deadline = deadline.min(wait_deadline);
        let mut last_page = None;
        let mut initial_read = true;
        let page = loop {
            // `public_events_after` finishes its transaction before returning;
            // sleeping below therefore holds neither a reader permit nor WAL
            // snapshot while awaiting a later durable commit.
            let read_deadline = if initial_read {
                deadline
            } else {
                poll_deadline
            };
            initial_read = false;
            let remaining = match self.remaining(read_deadline) {
                Ok(remaining) => remaining,
                Err(error) => match last_page.take() {
                    Some(page) => break page,
                    None => return Err(error),
                },
            };
            let page = match self.reader.public_events_after(
                task_id,
                after_seq,
                limit,
                remaining,
                Some(&self.consumer_id),
            ) {
                Ok(page) => page,
                Err(StorageError::QueryDeadline)
                    if Instant::now() >= poll_deadline && last_page.is_some() =>
                {
                    break last_page.take().ok_or_else(RouterError::deadline)?;
                }
                Err(error) => return Err(RouterError::from_storage(error)),
            };
            let snapshot = if matches!(until, WaitUntil::Attention) && wait_ms != 0 {
                self.snapshot(task_id, read_deadline).ok()
            } else {
                None
            };
            if wait_ready(&page, snapshot.as_ref(), until, wait_ms) {
                break page;
            }
            if Instant::now() >= poll_deadline {
                break page;
            }
            last_page = Some(page);
            let remaining = self.remaining(poll_deadline)?;
            self.sleeper.sleep(remaining.min(Duration::from_millis(10)));
            if poll_deadline.saturating_duration_since(Instant::now()) <= Duration::from_millis(1) {
                break last_page.take().ok_or_else(RouterError::deadline)?;
            }
        };
        Ok(
            json!({"kind":"wait_task_result","task_id":page.task_id,"requested_after_seq":page.requested_after_seq,"events":page.events.into_iter().map(|event| event.value).collect::<Vec<_>>(),"next_seq":page.next_seq,"oldest_available_seq":page.cursor.oldest_available_seq,"last_committed_seq":page.cursor.last_committed_seq,"terminal_result":page.terminal_result.map(|result| result.value)}),
        )
    }

    fn send_task_input(
        &self,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        let command = canonical_bytes(params)?;
        let task_id = text(params, "task_id")?;
        let interaction_id = text(params, "interaction_id")?;
        let response = object(params, "response")?;
        let response_bytes = canonical_bytes(response)?;
        let response_kind = text(response, "kind")?
            .parse::<InteractionResponseKind>()
            .map_err(|_| RouterError::validation())?;
        let now_us = self.clock.now_us()?;
        self.remaining(deadline)?;
        self.writer
            .respond_interaction(
                &self.consumer_id,
                text(params, "command_key")?,
                command,
                interaction_id,
                text(params, "nonce")?,
                integer(params, "generation")?,
                text(params, "operation_digest")?,
                text(params, "policy_digest")?,
                text(params, "config_digest")?,
                response_kind,
                response_bytes,
                now_us,
            )
            .map_err(RouterError::from_storage)?;
        let interaction = self
            .reader
            .interaction_by_id(
                task_id,
                text(params, "interaction_id")?,
                &self.consumer_id,
                self.remaining(deadline)?,
            )
            .map_err(RouterError::from_storage)?;
        let snapshot = self.snapshot(task_id, deadline)?;
        Ok(
            json!({"kind":"send_task_input_result","interaction":interaction.value,"task":snapshot.task.value}),
        )
    }

    fn cancel_task(
        &self,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        let command = canonical_bytes(params)?;
        let task_id = text(params, "task_id")?;
        self.remaining(deadline)?;
        self.writer
            .request_cancel(
                &self.consumer_id,
                text(params, "command_key")?,
                command,
                task_id,
                self.clock.now_us()?,
            )
            .map_err(RouterError::from_storage)?;
        let snapshot = self.snapshot(task_id, deadline)?;
        Ok(json!({"kind":"cancel_task_result","task":snapshot.task.value}))
    }

    fn review_task(
        &self,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        let command = canonical_bytes(params)?;
        let task_id = text(params, "task_id")?;
        let existing = self.snapshot(task_id, deadline)?;
        let durable_delivery = existing
            .result
            .as_ref()
            .map(|result| result.delivery.clone())
            .ok_or_else(RouterError::validation)?;
        // The durable tuple is the authority: each caller-supplied member must
        // agree before the writer can ACK. In particular, no terminal state or
        // event sequence is taken from untrusted RPC parameters.
        if durable_delivery.task_id != task_id
            || durable_delivery.result_id != text(params, "result_id")?
            || durable_delivery.result_version != integer(params, "result_version")?
            || durable_delivery.ack_token != text(params, "ack_token")?
        {
            return Err(RouterError::validation());
        }
        let delivery = durable_delivery;
        let verdict = text(params, "verdict")?
            .parse::<ReviewVerdict>()
            .map_err(|_| RouterError::validation())?;
        let diagnosis = optional_text(params, "diagnosis")?.map(str::to_owned);
        self.remaining(deadline)?;
        self.writer
            .review_and_ack(
                &self.consumer_id,
                text(params, "command_key")?,
                command,
                delivery,
                verdict,
                diagnosis,
                self.clock.now_us()?,
            )
            .map_err(RouterError::from_storage)?;
        let snapshot = self.snapshot(task_id, deadline)?;
        let result = snapshot.result.ok_or_else(RouterError::validation)?;
        let review = result.review.ok_or_else(RouterError::validation)?;
        Ok(
            json!({"kind":"review_task_result","result":result.value,"verdict":review.verdict,"reviewed_at_ms":review.reviewed_at_ms}),
        )
    }

    fn improvement_case(
        &self,
        params: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Value, RouterError> {
        let case_id = text(params, "case_id")?;
        match text(params, "action")? {
            "inspect" => {
                let engine = self
                    .reader
                    .improvement_engine(self.remaining(deadline)?)
                    .map_err(RouterError::from_storage)?
                    .ok_or_else(RouterError::validation)?;
                let case = engine
                    .case_snapshot(case_id)
                    .ok_or_else(RouterError::validation)?;
                Ok(improvement_result(
                    engine.policy().enabled,
                    "INSPECTED",
                    &case,
                    engine.candidate_config_version(case_id),
                ))
            }
            "improvement_propose" => {
                let command = canonical_bytes(params)?;
                let knob = parse_candidate_knob(text(params, "knob")?)?;
                let fixtures = params
                    .get("fixtures")
                    .and_then(Value::as_array)
                    .ok_or_else(RouterError::validation)?
                    .iter()
                    .map(|fixture| {
                        let fixture = fixture.as_object().ok_or_else(RouterError::validation)?;
                        Ok(FixtureOutcome {
                            fixture_id: text(fixture, "fixture_id")?.to_owned(),
                            passed: fixture
                                .get("passed")
                                .and_then(Value::as_bool)
                                .ok_or_else(RouterError::validation)?,
                            hard_invariant_failures: u32::try_from(integer(
                                fixture,
                                "hard_invariant_failures",
                            )?)
                            .map_err(|_| RouterError::validation())?,
                        })
                    })
                    .collect::<Result<Vec<_>, RouterError>>()?;
                self.remaining(deadline)?;
                let result = self
                    .writer
                    .improvement_propose_command(
                        &self.consumer_id,
                        text(params, "command_key")?,
                        command,
                        CandidateProposal {
                            case_id: case_id.to_owned(),
                            knob,
                            value: Value::String(text(params, "value")?.to_owned()),
                            hypothesis: text(params, "hypothesis")?.to_owned(),
                            fixtures,
                        },
                        self.clock.now_us()?,
                    )
                    .map_err(RouterError::from_storage)?;
                let (feature_enabled, outcome) = match result.decision {
                    CandidateDecision::FeatureDisabled => (false, "FEATURE_DISABLED"),
                    CandidateDecision::Canary { .. } => (true, "CANARY"),
                    CandidateDecision::FixtureRejected { .. } => (true, "FIXTURE_REJECTED"),
                };
                Ok(improvement_result(
                    feature_enabled,
                    outcome,
                    &result.case,
                    result.candidate_config_version,
                ))
            }
            "improvement_rollback" => {
                let command = canonical_bytes(params)?;
                self.remaining(deadline)?;
                let result = self
                    .writer
                    .improvement_rollback_command(
                        &self.consumer_id,
                        text(params, "command_key")?,
                        command,
                        case_id,
                        integer(params, "target_config_version")?,
                        self.clock.now_us()?,
                    )
                    .map_err(RouterError::from_storage)?;
                let (feature_enabled, outcome) = evaluation_outcome(&result.decision);
                Ok(improvement_result(
                    feature_enabled,
                    outcome,
                    &result.case,
                    result.candidate_config_version,
                ))
            }
            _ => Err(RouterError::validation()),
        }
    }

    fn assign_adapter(
        &self,
        params: &Map<String, Value>,
        requested: Option<&str>,
    ) -> Result<Option<String>, RouterError> {
        let Some(registry) = &self.registry else {
            return Ok(requested.map(str::to_owned));
        };
        if let Some(requested) = requested {
            let enabled = registry.list_admissions().into_iter().any(|record| {
                record.adapter_instance_id == requested && record.status.as_str() == "ENABLED"
            });
            return enabled
                .then(|| Some(requested.to_owned()))
                .ok_or_else(RouterError::adapter_unavailable);
        }
        let role = text(params, "role")?;
        registry
            .enabled_for_role(role)
            .map(|record| Some(record.adapter_instance_id))
            .ok_or_else(RouterError::adapter_unavailable)
    }

    fn snapshot(&self, task_id: &str, deadline: Instant) -> Result<TaskSnapshot, RouterError> {
        self.reader
            .snapshot(task_id, &self.consumer_id, self.remaining(deadline)?)
            .map_err(RouterError::from_storage)
    }

    #[allow(clippy::unused_self)]
    fn remaining(&self, deadline: Instant) -> Result<Duration, RouterError> {
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(RouterError::deadline)
    }
}

fn snapshot_value(kind: &str, snapshot: &TaskSnapshot) -> Value {
    json!({"kind":kind,"task":snapshot.task.value.clone(),"attempt":snapshot.attempt.as_ref().map(|attempt| attempt.value.clone()),"pending_interaction":snapshot.interaction.as_ref().map(|interaction| interaction.value.clone()),"terminal_result":snapshot.result.as_ref().map(|result| result.value.clone()),"cursor":{"oldest_available_seq":snapshot.task.cursor.oldest_available_seq,"last_committed_seq":snapshot.task.cursor.last_committed_seq}})
}

fn improvement_result(
    feature_enabled: bool,
    outcome: &str,
    case: &CaseSnapshot,
    candidate_config_version: Option<i64>,
) -> Value {
    let mut projected = json!({
        "version": 1,
        "kind": "improvement_case",
        "case_id": case.case_id,
        "status": case.state.as_str(),
        "component": case.component,
        "parent_config_version": case.parent_config_version,
        "rollback_count": case.rollback_count,
    });
    if let Some(version) = candidate_config_version {
        projected
            .as_object_mut()
            .expect("improvement case projection is an object")
            .insert("candidate_config_version".into(), Value::from(version));
    }
    json!({
        "kind": "improvement_case_result",
        "feature_enabled": feature_enabled,
        "outcome": outcome,
        "case": projected,
    })
}

fn parse_candidate_knob(value: &str) -> Result<CandidateKnob, RouterError> {
    match value {
        "prompt_composition" => Ok(CandidateKnob::PromptComposition),
        "context_selection" => Ok(CandidateKnob::ContextSelection),
        "same_agent_transport_priority" => Ok(CandidateKnob::SameAgentTransportPriority),
        "quality" => Ok(CandidateKnob::Quality),
        "effort" => Ok(CandidateKnob::Effort),
        _ => Err(RouterError::validation()),
    }
}

const fn evaluation_outcome(decision: &EvaluationDecision) -> (bool, &'static str) {
    match decision {
        EvaluationDecision::FeatureDisabled => (false, "FEATURE_DISABLED"),
        EvaluationDecision::WaitingForTime => (true, "WAITING_FOR_TIME"),
        EvaluationDecision::WaitingForSamples { .. } => (true, "WAITING_FOR_SAMPLES"),
        EvaluationDecision::MissingMetrics => (true, "MISSING_METRICS"),
        EvaluationDecision::Promoted { .. } => (true, "PROMOTED"),
        EvaluationDecision::RolledBack { .. } => (true, "ROLLED_BACK"),
        EvaluationDecision::Frozen { .. } => (true, "FROZEN"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitUntil {
    Events,
    Attention,
}

fn wait_until(params: &Map<String, Value>) -> Result<WaitUntil, RouterError> {
    match params.get("until") {
        None => Ok(WaitUntil::Events),
        Some(Value::String(value)) if value == "events" => Ok(WaitUntil::Events),
        Some(Value::String(value)) if value == "attention" => Ok(WaitUntil::Attention),
        _ => Err(RouterError::validation()),
    }
}

fn wait_ready(
    page: &crate::reader::PublicEventPage,
    snapshot: Option<&TaskSnapshot>,
    until: WaitUntil,
    wait_ms: u64,
) -> bool {
    if wait_ms == 0 || page.terminal_result.is_some() {
        return true;
    }
    match until {
        WaitUntil::Events => !page.events.is_empty(),
        WaitUntil::Attention => snapshot.is_some_and(snapshot_needs_attention),
    }
}

fn snapshot_needs_attention(snapshot: &TaskSnapshot) -> bool {
    if snapshot.interaction.is_some() || snapshot.result.is_some() {
        return true;
    }
    matches!(
        snapshot.task.value.get("state").and_then(Value::as_str),
        Some("WAITING_APPROVAL" | "NEEDS_ATTENTION" | "SUCCEEDED" | "FAILED" | "CANCELLED")
    )
}

fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, RouterError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(RouterError::validation)
}
fn optional_text<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, RouterError> {
    object
        .get(field)
        .map(|value| value.as_str().ok_or_else(RouterError::validation))
        .transpose()
}
fn object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, RouterError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(RouterError::validation)
}
fn integer(object: &Map<String, Value>, field: &str) -> Result<i64, RouterError> {
    object
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(RouterError::validation)
}
fn canonical_bytes(object: &Map<String, Value>) -> Result<Vec<u8>, RouterError> {
    canonicalize(&Value::Object(object.clone()))
        .map(String::into_bytes)
        .map_err(|_| RouterError::validation())
}

const fn map_retry(value: RetryClass) -> RpcRetryClass {
    match value {
        RetryClass::SafePreDispatch => RpcRetryClass::SafePreDispatch,
        RetryClass::SafeProvenNoEffect => RpcRetryClass::SafeProvenNoEffect,
        RetryClass::DeterministicFailure => RpcRetryClass::DeterministicFailure,
        RetryClass::AmbiguousAfterDispatch => RpcRetryClass::AmbiguousAfterDispatch,
    }
}
const fn map_effect(value: EffectClass) -> RpcEffectClass {
    match value {
        EffectClass::NoEffect => RpcEffectClass::NoEffect,
        EffectClass::PossibleEffect => RpcEffectClass::PossibleEffect,
        EffectClass::UnknownEffect => RpcEffectClass::UnknownEffect,
    }
}
const fn map_lifecycle(value: LifecycleEvidence) -> RpcLifecycle {
    match value {
        LifecycleEvidence::BeforeProcessCreation => RpcLifecycle::BeforeProcessCreation,
        LifecycleEvidence::ProcessDeadNoEffectProof => RpcLifecycle::ProcessDeadNoEffectProof,
        LifecycleEvidence::AfterProcessCreation => RpcLifecycle::AfterProcessCreation,
        LifecycleEvidence::Unknown => RpcLifecycle::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    struct FixedClock;

    impl RouterClock for FixedClock {
        fn now_us(&self) -> Result<i64, RouterError> {
            Ok(10_000)
        }
    }

    fn request(command_key: &str) -> Map<String, Value> {
        json!({
            "version": 1,
            "kind": "task_request",
            "command_key": command_key,
            "role": "implementation",
            "objective": "write a bounded test",
            "context_refs": [],
            "quality": "standard",
            "effort": "medium",
            "timeout_seconds": 60,
            "priority": 1,
            "workspace": {
                "path": "D:/work",
                "base_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "mode": "read_only"
            },
            "effect_profile": "READ_ONLY",
            "permission_policy": "default"
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn router() -> (Router<FixedClock>, WriterHandle) {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        writer.ensure_empty_config_v1(2).unwrap();
        let reader = ReaderPool::open(root).unwrap();
        (
            Router::with_clock(reader, writer.clone(), "consumer".into(), FixedClock),
            writer,
        )
    }

    #[test]
    fn list_agents_is_an_honest_empty_projection_before_adapter_registry_exists() {
        let (router, writer) = router();
        let value = router
            .dispatch(
                RpcMethod::ListAgents,
                &Map::new(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            value,
            json!({"kind":"list_agents_result","agents":[],"config_version":1})
        );
        writer.shutdown().unwrap();
    }

    #[test]
    fn list_agents_uses_the_settings_backed_registry() {
        let settings_root = tempfile::tempdir().unwrap();
        let (router, writer) = router();
        let router = router.with_registry(crate::adapters::registry::AdapterRegistry::new(
            crate::settings::SettingsStore::new(settings_root.path()),
        ));
        let value = router
            .dispatch(
                RpcMethod::ListAgents,
                &Map::new(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(value["kind"], "list_agents_result");
        let agents = value["agents"].as_array().expect("agents");
        assert!(!agents.is_empty());
        assert!(agents.len() <= 4);
        for agent in agents {
            assert_eq!(agent["kind"], "adapter_capabilities");
            assert_eq!(agent["status"], "UNAVAILABLE");
        }
        writer.shutdown().unwrap();
    }

    #[test]
    fn delegate_task_fails_closed_when_the_role_has_no_enabled_adapter() {
        let settings_root = tempfile::tempdir().unwrap();
        let (router, writer) = router();
        let router = router.with_registry(crate::adapters::registry::AdapterRegistry::new(
            crate::settings::SettingsStore::new(settings_root.path()),
        ));
        let error = router
            .dispatch(
                RpcMethod::DelegateTask,
                &request("delegate-missing-adapter"),
                Instant::now() + Duration::from_secs(1),
            )
            .expect_err("disabled adapters must not admit work");
        assert_eq!(error.error_code(), crate::ErrorCode::AdapterUnavailable);
        writer.shutdown().unwrap();
    }

    #[test]
    fn delegate_inspect_wait_and_cancel_use_only_durable_evidence() {
        let (router, writer) = router();
        let delegated = router
            .dispatch(
                RpcMethod::DelegateTask,
                &request("delegate-1"),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let task_id = delegated["task"]["task_id"].as_str().unwrap().to_owned();
        assert_eq!(delegated["kind"], "delegate_task_result");
        assert!(delegated["request_digest"].as_str().is_some());

        let inspect_params = json!({"task_id": task_id}).as_object().unwrap().clone();
        let inspected = router
            .dispatch(
                RpcMethod::InspectTask,
                &inspect_params,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(inspected["task"]["state"], "QUEUED");
        assert!(inspected.get("dashboard").is_none());

        let wait_params = json!({"task_id": task_id, "after_seq": 0, "limit": 10, "wait_ms": 0})
            .as_object()
            .unwrap()
            .clone();
        let waited = router
            .dispatch(
                RpcMethod::WaitTask,
                &wait_params,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(waited["requested_after_seq"], 0);
        assert_eq!(waited["events"].as_array().unwrap().len(), 1);

        let cancel = json!({"version":1,"kind":"command","action":"cancel","command_key":"cancel-1","task_id":task_id}).as_object().unwrap().clone();
        let cancelled = router
            .dispatch(
                RpcMethod::CancelTask,
                &cancel,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(cancelled["task"]["state"], "CANCEL_REQUESTED");
        writer.shutdown().unwrap();
    }

    #[test]
    fn inspect_explicitly_exposes_dashboard_bootstrap_without_token_in_notice_or_base_url() {
        let (router, writer) = router();
        let sessions = Arc::new(SessionStore::new());
        let address = "127.0.0.1:43127".parse().expect("loopback address");
        let router = router.with_dashboard(DashboardAccess::new(address, Arc::clone(&sessions)));
        let delegated = router
            .dispatch(
                RpcMethod::DelegateTask,
                &request("delegate-dashboard"),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let task_id = delegated["task"]["task_id"].as_str().unwrap();
        let params = json!({"task_id": task_id}).as_object().unwrap().clone();
        let first = router
            .dispatch(
                RpcMethod::InspectTask,
                &params,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let second = router
            .dispatch(
                RpcMethod::InspectTask,
                &params,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(first["dashboard"]["base_url"], "http://127.0.0.1:43127");
        let first_url = first["dashboard"]["bootstrap_url"].as_str().unwrap();
        let second_url = second["dashboard"]["bootstrap_url"].as_str().unwrap();
        assert_ne!(first_url, second_url, "every inspect mints a fresh token");
        let first_token = first_url.rsplit_once("token=").unwrap().1;
        let second_token = second_url.rsplit_once("token=").unwrap().1;
        assert!(sessions.exchange_bootstrap(first_token).is_some());
        assert!(sessions.exchange_bootstrap(first_token).is_none());
        assert!(sessions.exchange_bootstrap(second_token).is_some());
        assert!(
            !first["dashboard"]["base_url"]
                .as_str()
                .unwrap()
                .contains(first_token)
        );
        assert!(
            !first["dashboard"]["notice"]
                .as_str()
                .unwrap()
                .contains(first_token)
        );
        assert!(
            crate::decode_wire_v1(json!({
                "jsonrpc": "2.0",
                "id": 6,
                "result": first,
            }))
            .is_ok()
        );
        writer.shutdown().unwrap();
    }

    #[test]
    fn deadline_prevents_new_durable_mutation() {
        let (router, writer) = router();
        let result = router.dispatch(RpcMethod::DelegateTask, &request("late"), Instant::now());
        assert!(result.is_err());
        writer.shutdown().unwrap();
    }

    #[test]
    fn wait_zero_returns_empty_page_immediately_and_nonzero_wait_expires_honestly() {
        let (router, writer) = router();
        // The transport deadline is deliberately generous: under a fully
        // loaded parallel test run the durable reader/writer round trip can
        // exceed one second while the wait_ms semantics themselves must stay
        // exact.
        let deadline = Instant::now() + Duration::from_secs(30);
        let delegated = router
            .dispatch(RpcMethod::DelegateTask, &request("delegate-wait"), deadline)
            .unwrap();
        let task_id = delegated["task"]["task_id"].as_str().unwrap();
        let zero = json!({"task_id":task_id,"after_seq":1,"limit":1,"wait_ms":0})
            .as_object()
            .unwrap()
            .clone();
        let zero_page = router
            .dispatch(RpcMethod::WaitTask, &zero, deadline)
            .unwrap();
        assert!(zero_page["events"].as_array().unwrap().is_empty());

        let timeout = json!({"task_id":task_id,"after_seq":1,"limit":1,"wait_ms":5})
            .as_object()
            .unwrap()
            .clone();
        let started = Instant::now();
        let timeout_page = router
            .dispatch(RpcMethod::WaitTask, &timeout, deadline)
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(5));
        assert!(timeout_page["events"].as_array().unwrap().is_empty());

        let attention = json!({
            "task_id": task_id,
            "after_seq": 0,
            "limit": 10,
            "wait_ms": 20,
            "until": "attention"
        })
        .as_object()
        .unwrap()
        .clone();
        let started = Instant::now();
        let attention_page = router
            .dispatch(RpcMethod::WaitTask, &attention, deadline)
            .unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(20),
            "attention wait must not return on the create event alone"
        );
        assert!(attention_page["terminal_result"].is_null());
        writer.shutdown().unwrap();
    }

    #[test]
    fn expired_cancel_is_rejected_before_writer_admission() {
        let (router, writer) = router();
        let delegated = router
            .dispatch(
                RpcMethod::DelegateTask,
                &request("delegate-expired-cancel"),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let task_id = delegated["task"]["task_id"].as_str().unwrap();
        let cancel = json!({"version":1,"kind":"command","action":"cancel","command_key":"expired-cancel","task_id":task_id})
            .as_object()
            .unwrap()
            .clone();
        assert!(
            router
                .dispatch(RpcMethod::CancelTask, &cancel, Instant::now())
                .is_err()
        );
        let inspect = json!({"task_id":task_id}).as_object().unwrap().clone();
        let snapshot = router
            .dispatch(
                RpcMethod::InspectTask,
                &inspect,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(snapshot["task"]["state"], "QUEUED");
        writer.shutdown().unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn improvement_case_is_durable_replayable_and_exposes_feature_off() {
        let (router, writer) = router();
        writer.set_improvement_enabled(true, 3).unwrap();
        let cohort = crate::improvement::Cohort {
            adapter_instance_id: "adapter-main".into(),
            adapter_version: "1.0.0".into(),
            config_version: 1,
            config_digest: "a".repeat(64),
        };
        for index in 0..3 {
            let input = crate::improvement::ObservationInput {
                task_id: format!("reviewed-{index}"),
                component: "adapter-main".into(),
                cohort: cohort.clone(),
                reviewed_at_us: 10 + index,
                success: false,
                failure_signature: Some(crate::improvement::FailureSignature {
                    protocol_stage: "terminal".into(),
                    failure_class: "terminal_failed".into(),
                    version_bucket: "version-1".into(),
                    diagnostic_code: "diag-1".into(),
                }),
                latency_us: Some(10),
                token_cost: Some(10),
                safety_violations: 0,
            };
            writer.improvement_observe(input.clone()).unwrap();
            if index == 2 {
                writer.improvement_open_case(input, 20).unwrap();
            }
        }
        let engine = router
            .reader
            .improvement_engine(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let case_id = engine
            .case_snapshot(
                &engine
                    .durable_projection()
                    .cases
                    .first()
                    .expect("case")
                    .case_id,
            )
            .unwrap()
            .case_id;
        let fixtures: Vec<Value> = (0..10)
            .map(|index| {
                json!({
                    "fixture_id": format!("fixture-{index}"),
                    "passed": true,
                    "hard_invariant_failures": 0
                })
            })
            .collect();
        let params = json!({
            "version": 1,
            "kind": "command",
            "action": "improvement_propose",
            "command_key": "improvement-command-1",
            "case_id": case_id,
            "knob": "quality",
            "value": "high",
            "hypothesis": "bounded quality improves this failure cohort",
            "fixtures": fixtures,
        })
        .as_object()
        .unwrap()
        .clone();
        let first = router
            .dispatch(
                RpcMethod::ImprovementCase,
                &params,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(first["outcome"], "CANARY");
        assert_eq!(first["feature_enabled"], true);
        assert!(
            crate::decode_wire_v1(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": first.clone(),
            }))
            .is_ok()
        );
        let mut conflict = params.clone();
        conflict.insert("value".into(), Value::String("standard".into()));
        assert!(
            router
                .dispatch(
                    RpcMethod::ImprovementCase,
                    &conflict,
                    Instant::now() + Duration::from_secs(1),
                )
                .is_err()
        );

        writer.set_improvement_enabled(false, 30).unwrap();
        let replay = router
            .dispatch(
                RpcMethod::ImprovementCase,
                &params,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(replay, first, "replay returns the original response");

        let mut disabled = params.clone();
        disabled.insert(
            "command_key".into(),
            Value::String("improvement-command-2".into()),
        );
        let disabled_result = router
            .dispatch(
                RpcMethod::ImprovementCase,
                &disabled,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(disabled_result["outcome"], "FEATURE_DISABLED");
        assert_eq!(disabled_result["feature_enabled"], false);
        writer.shutdown().unwrap();
    }
}
