//! Persisted, restart-safe scheduler decisions for the M4 durable core.
//!
//! This module owns the *decision layer* only. All scheduling state lives in
//! `SQLite` (`tasks`, `attempts`); this module never keeps occupancy or queue
//! order in memory. The authoritative slot reservation is
//! [`crate::writer::WriterHandle::claim_dispatch_slot`], which recomputes
//! occupancy inside the same transaction that transitions a task out of
//! `QUEUED`. [`plan_dispatch`] is a pure projection used to choose *which*
//! claims to attempt next; a claim can still be refused by the writer if the
//! durable state moved between the read and the write. A plan round is
//! therefore read-candidates -> plan -> claim, repeated until the plan is
//! empty or every claim is refused.
//!
//! # Limits
//!
//! * `global` (default 3, `1..=MAX_GLOBAL_LIMIT`): maximum process-bearing
//!   attempts across all adapters.
//! * `per_adapter` (default 1, `1..=MAX_PER_ADAPTER_LIMIT`): maximum
//!   process-bearing attempts for one `adapter_instance_id`.
//!
//! # Occupancy states
//!
//! An attempt consumes a slot only while it is process-bearing or has a
//! reserved slot:
//!
//! | task state | consumes a slot |
//! | --- | --- |
//! | `QUEUED` | no |
//! | `RETRY_WAIT` (timer only) | no |
//! | `PREPARING` (slot reserved by claim) | yes |
//! | `WAITING_APPROVAL` preflight (no process yet) | no |
//! | `WAITING_APPROVAL` runtime (process started) | yes |
//! | `RUNNING` | yes |
//! | `FINALIZING` | yes |
//! | `CANCEL_REQUESTED` (from a process-bearing state) | yes |
//!
//! The preflight/runtime distinction is decided by the attempt's
//! `dispatch_phase` (`PROCESS_STARTED`/`PROVIDER_OBSERVED` means runtime).
//! Because a preflight `WAITING_APPROVAL` does not hold a slot, the process
//! supervisor must re-acquire a slot (a fresh claim on the resumed attempt)
//! before launching a process after an approval is answered; this is enforced
//! in the process-ownership layer, not here.
//!
//! # FIFO within priority, bounded bypass
//!
//! Candidates are ordered by `priority` (higher dispatches first), then FIFO
//! by `created_at`, then `task_id` as a deterministic tiebreak. If the head
//! candidate is blocked on its per-adapter limit, later candidates whose
//! adapter has a free slot may be dispatched so one busy adapter cannot stall
//! the queue. At most [`SchedulerPolicy::bypass_bound`] blocked heads are
//! bypassed per plan round (default [`DEFAULT_BYPASS_BOUND`]); the scan stops
//! at the next blocked head, so starvation behind a long run of blocked heads
//! is bounded. Timer-pending `RETRY_WAIT` candidates and candidates with no
//! assigned adapter are skipped without consuming bypass budget because they
//! are never blocked on a resource conflict: a timer wait is time-ordered and
//! an unassigned adapter can never be dispatched regardless of position.
//!
//! # Adapter instance identity
//!
//! An [`AdapterInstanceId`] is **agent family plus local account/profile and
//! configuration identity** — never a bare `claude`/`grok`/`kimi` string. It
//! encodes four components, separated by `:`:
//!
//! 1. `family`: the agent family (`claude`, `grok`, `kimi`, or `fake`),
//! 2. `account`: the local account identity (e.g. a short hash of the Windows
//!    account SID or the CLI account name),
//! 3. `profile`: the CLI profile/config selector (use `default` when none),
//! 4. `config_digest`: the 64-hex digest of the adapter configuration version
//!    that produced this routing.
//!
//! Two tasks share an adapter instance (and therefore one per-adapter slot)
//! iff all four components match. The encoded string fits the protocol `id`
//! bounds (max 128 chars, `[A-Za-z0-9][A-Za-z0-9._:-]*`). Once assigned, a
//! task's adapter instance is immutable (no cross-provider fallback).
//!
//! # Restart reconciliation
//!
//! [`recompute_occupancy`] is the deterministic occupancy recomputation entry
//! point for daemon startup. `daemon_runtime` must invoke it **after**
//! `WriterHandle::reconcile_nonterminal` completes and **before** dispatch is
//! enabled, feeding the result into the first [`plan_dispatch`] round. It
//! performs no process-evidence guessing: it reads the same `SQLite`
//! predicate the writer uses inside `claim_dispatch_slot`, so a stale
//! recomputation can never over-admit work — the claim transaction re-checks
//! the limits authoritatively against the current durable rows.

#![allow(clippy::missing_errors_doc)]

use std::{collections::BTreeMap, fmt, time::Duration};

use crate::{
    domain::TaskState,
    reader::ReaderPool,
    storage::{DispatchBlockReason, Occupancy, Result as StorageResult},
};

pub const DEFAULT_GLOBAL_LIMIT: u32 = 3;
pub const DEFAULT_PER_ADAPTER_LIMIT: u32 = 1;
/// Upper bounds match the protocol safe-settings `concurrency` schema.
pub const MAX_GLOBAL_LIMIT: u32 = 16;
pub const MAX_PER_ADAPTER_LIMIT: u32 = 4;
/// Per-round bypass bound: at most this many adapter-blocked heads are
/// skipped in one [`plan_dispatch`] call before the scan stops.
pub const DEFAULT_BYPASS_BOUND: usize = 4;
pub const MAX_BYPASS_BOUND: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitsError {
    GlobalOutOfRange { value: u32 },
    PerAdapterOutOfRange { value: u32 },
    BypassBoundOutOfRange { value: usize },
}

impl fmt::Display for LimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GlobalOutOfRange { value } => write!(
                formatter,
                "global concurrency limit {value} is outside 1..={MAX_GLOBAL_LIMIT}"
            ),
            Self::PerAdapterOutOfRange { value } => write!(
                formatter,
                "per-adapter concurrency limit {value} is outside 1..={MAX_PER_ADAPTER_LIMIT}"
            ),
            Self::BypassBoundOutOfRange { value } => write!(
                formatter,
                "bypass bound {value} is outside 1..={MAX_BYPASS_BOUND}"
            ),
        }
    }
}

impl std::error::Error for LimitsError {}

/// Global and per-adapter-instance concurrency limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerLimits {
    pub global: u32,
    pub per_adapter: u32,
}

impl SchedulerLimits {
    pub const DEFAULT: Self = Self {
        global: DEFAULT_GLOBAL_LIMIT,
        per_adapter: DEFAULT_PER_ADAPTER_LIMIT,
    };

    pub fn validate(self) -> Result<Self, LimitsError> {
        if !(1..=MAX_GLOBAL_LIMIT).contains(&self.global) {
            return Err(LimitsError::GlobalOutOfRange { value: self.global });
        }
        if !(1..=MAX_PER_ADAPTER_LIMIT).contains(&self.per_adapter) {
            return Err(LimitsError::PerAdapterOutOfRange {
                value: self.per_adapter,
            });
        }
        Ok(self)
    }
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Full scheduling policy for one planning round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerPolicy {
    pub limits: SchedulerLimits,
    pub bypass_bound: usize,
}

impl SchedulerPolicy {
    pub fn validate(self) -> Result<Self, LimitsError> {
        self.limits.validate()?;
        if !(1..=MAX_BYPASS_BOUND).contains(&self.bypass_bound) {
            return Err(LimitsError::BypassBoundOutOfRange {
                value: self.bypass_bound,
            });
        }
        Ok(self)
    }
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        Self {
            limits: SchedulerLimits::DEFAULT,
            bypass_bound: DEFAULT_BYPASS_BOUND,
        }
    }
}

/// Canonical durable adapter instance identity. See the module docs for the
/// exact four-component semantics; a bare agent family name is not valid.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AdapterInstanceId {
    family: String,
    account: String,
    profile: String,
    config_digest: String,
}

/// Why an adapter instance id string is not a valid durable identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterInstanceIdError(pub String);

impl fmt::Display for AdapterInstanceIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid adapter instance id: {}", self.0)
    }
}

impl std::error::Error for AdapterInstanceIdError {}

impl AdapterInstanceId {
    /// Encoded ids must fit the protocol `id` pattern
    /// (`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`). Component bounds are chosen so
    /// the longest valid encoding stays within 128 chars:
    /// 12 + 16 + 16 + 64 hex + 3 separators = 111.
    pub const SEPARATOR: char = ':';
    const MAX_FAMILY_CHARS: usize = 12;
    const MAX_ACCOUNT_CHARS: usize = 16;
    const MAX_PROFILE_CHARS: usize = 16;

    /// Builds an identity from agent family, local account identity, CLI
    /// profile selector, and the config digest of the routing configuration.
    /// Longer account/profile identities must be shortened to a stable hash
    /// by the caller.
    pub fn new(
        family: &str,
        account: &str,
        profile: &str,
        config_digest: &str,
    ) -> Result<Self, AdapterInstanceIdError> {
        if !is_family(family) || family.len() > Self::MAX_FAMILY_CHARS {
            return Err(AdapterInstanceIdError(
                "family must be 1..=12 lowercase alphanumerics or dashes".into(),
            ));
        }
        if !is_selector(account) || account.is_empty() || account.len() > Self::MAX_ACCOUNT_CHARS {
            return Err(AdapterInstanceIdError(
                "account must be 1..=16 selector characters ([A-Za-z0-9._-])".into(),
            ));
        }
        if !is_selector(profile) || profile.is_empty() || profile.len() > Self::MAX_PROFILE_CHARS {
            return Err(AdapterInstanceIdError(
                "profile must be 1..=16 selector characters ([A-Za-z0-9._-])".into(),
            ));
        }
        if !config_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || config_digest.len() != 64
        {
            return Err(AdapterInstanceIdError(
                "config_digest must be exactly 64 lowercase hex characters".into(),
            ));
        }
        Ok(Self {
            family: family.to_owned(),
            account: account.to_owned(),
            profile: profile.to_owned(),
            config_digest: config_digest.to_owned(),
        })
    }

    /// Parses the canonical `family:account:profile:config_digest` encoding.
    pub fn parse(value: &str) -> Result<Self, AdapterInstanceIdError> {
        let components: Vec<&str> = value.split(Self::SEPARATOR).collect();
        if components.len() != 4 {
            return Err(AdapterInstanceIdError(format!(
                "expected exactly 4 components separated by '{}', got {}",
                Self::SEPARATOR,
                components.len()
            )));
        }
        Self::new(components[0], components[1], components[2], components[3])
    }

    /// Canonical durable string form; `parse(encode(id)) == id` always holds.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{}{}{}{}{}{}{}",
            self.family,
            Self::SEPARATOR,
            self.account,
            Self::SEPARATOR,
            self.profile,
            Self::SEPARATOR,
            self.config_digest
        )
    }

    #[must_use]
    pub fn family(&self) -> &str {
        &self.family
    }

    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }
}

impl fmt::Display for AdapterInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encode())
    }
}

fn is_family(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_selector(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// A durable `QUEUED`/`RETRY_WAIT` task read by the reader pool, with the
/// scheduler inputs persisted at admission. FIFO ordering is derived from
/// `priority`/`created_at`/`task_id` by [`plan_dispatch`]; the reader returns
/// candidates in the same canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedCandidate {
    pub task_id: String,
    pub generation: i64,
    pub state: TaskState,
    /// Higher priority dispatches earlier (`0..=9`).
    pub priority: u8,
    pub created_at: i64,
    /// Persisted retry timer for `RETRY_WAIT`; the task is ready once
    /// `retry_at <= now`. `None` (or missing) means immediately ready.
    pub retry_at: Option<i64>,
    /// Durable adapter identity; `None` means routing has not assigned one,
    /// and the task cannot be dispatched until it is assigned.
    pub adapter_instance_id: Option<String>,
}

/// One admission in the ordered dispatch plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedDispatch {
    pub task_id: String,
    pub generation: i64,
    pub priority: u8,
    pub adapter_instance_id: String,
}

/// One candidate the plan could not admit, with a typed reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedBlock {
    pub task_id: String,
    pub generation: i64,
    pub reason: DispatchBlockReason,
    pub adapter_instance_id: Option<String>,
}

/// The ordered result of one planning round. `dispatch` is the claim order;
/// `blocked` preserves the scan order for diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DispatchPlan {
    pub dispatch: Vec<PlannedDispatch>,
    pub blocked: Vec<PlannedBlock>,
}

/// Deterministic occupancy recomputation entry point for daemon startup.
///
/// `daemon_runtime` must call this **after**
/// [`crate::writer::WriterHandle::reconcile_nonterminal`] completes and
/// **before** dispatch is enabled, then feed the result into the first
/// [`plan_dispatch`] round. It performs no process-evidence guessing: it
/// reads the same `SQLite` predicate the writer uses inside
/// `claim_dispatch_slot`, so a stale recomputation can never over-admit work.
pub fn recompute_occupancy(reader: &ReaderPool, timeout: Duration) -> StorageResult<Occupancy> {
    reader.occupancy(timeout)
}

/// Pure, restart-safe dispatch decision.
///
/// Every decision derives from the caller-supplied durable state: the
/// persisted candidate fields, the persisted occupancy, the policy, and
/// `now_us` for retry timers. Nothing is held across calls, so the same
/// inputs always produce the same plan. See the module docs for the exact
/// FIFO-within-priority and bounded-bypass rules.
///
/// # Errors
///
/// Returns [`LimitsError`] when the policy is out of bounds. The function is
/// otherwise infallible: refusals are typed per candidate in the plan.
pub fn plan_dispatch(
    candidates: &[QueuedCandidate],
    occupancy: &Occupancy,
    policy: SchedulerPolicy,
    now_us: i64,
) -> Result<DispatchPlan, LimitsError> {
    policy.validate()?;
    let mut ordered = candidates.to_vec();
    ordered.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.created_at.cmp(&right.created_at))
            .then_with(|| left.task_id.cmp(&right.task_id))
    });
    let mut remaining_global = policy.limits.global.saturating_sub(occupancy.global);
    let mut remaining_adapter: BTreeMap<&str, u32> = BTreeMap::new();
    let mut bypassed = 0_usize;
    let mut plan = DispatchPlan::default();
    for candidate in &ordered {
        let Some(adapter) = candidate.adapter_instance_id.as_deref() else {
            // Never dispatchable regardless of position: skip freely.
            plan.blocked.push(PlannedBlock {
                task_id: candidate.task_id.clone(),
                generation: candidate.generation,
                reason: DispatchBlockReason::AdapterUnassigned,
                adapter_instance_id: None,
            });
            continue;
        };
        if candidate.state == TaskState::RetryWait
            && candidate.retry_at.is_some_and(|at| at > now_us)
        {
            // Timer wait is time-ordered, not a resource conflict: skip
            // without consuming the bypass budget.
            plan.blocked.push(PlannedBlock {
                task_id: candidate.task_id.clone(),
                generation: candidate.generation,
                reason: DispatchBlockReason::RetryTimerPending,
                adapter_instance_id: Some(adapter.to_owned()),
            });
            continue;
        }
        let adapter_left = remaining_adapter.entry(adapter).or_insert_with(|| {
            policy
                .limits
                .per_adapter
                .saturating_sub(occupancy.occupied(adapter))
        });
        if *adapter_left == 0 {
            plan.blocked.push(PlannedBlock {
                task_id: candidate.task_id.clone(),
                generation: candidate.generation,
                reason: DispatchBlockReason::AdapterLimit,
                adapter_instance_id: Some(adapter.to_owned()),
            });
            bypassed += 1;
            if bypassed >= policy.bypass_bound {
                break;
            }
            continue;
        }
        if remaining_global == 0 {
            plan.blocked.push(PlannedBlock {
                task_id: candidate.task_id.clone(),
                generation: candidate.generation,
                reason: DispatchBlockReason::GlobalLimit,
                adapter_instance_id: Some(adapter.to_owned()),
            });
            break;
        }
        remaining_global -= 1;
        *adapter_left -= 1;
        plan.dispatch.push(PlannedDispatch {
            task_id: candidate.task_id.clone(),
            generation: candidate.generation,
            priority: candidate.priority,
            adapter_instance_id: adapter.to_owned(),
        });
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{DispatchPhase, InteractionCapabilityClass},
        storage::{AttemptSpec, DispatchOutcome, StorageError},
        writer::WriterHandle,
    };
    use std::time::Duration;

    const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const POLICY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const OPERATION_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn aid(family: &str) -> String {
        AdapterInstanceId::new(family, "default", "default", DIGEST)
            .unwrap()
            .encode()
    }

    fn candidate(
        task_id: &str,
        priority: u8,
        created_at: i64,
        adapter: Option<&str>,
    ) -> QueuedCandidate {
        QueuedCandidate {
            task_id: task_id.into(),
            generation: 0,
            state: TaskState::Queued,
            priority,
            created_at,
            retry_at: None,
            adapter_instance_id: adapter.map(str::to_owned),
        }
    }

    fn spec(adapter: &str) -> AttemptSpec {
        AttemptSpec {
            adapter_instance_id: adapter.into(),
            config_digest: DIGEST.into(),
            ..AttemptSpec::default()
        }
    }

    // --- Pure decision function -------------------------------------------------

    #[test]
    fn plan_orders_by_priority_then_fifo_and_respects_global_cap() {
        let occupancy = Occupancy::default();
        let candidates = vec![
            candidate("low-late", 0, 10, Some(&aid("claude"))),
            candidate("mid-early", 5, 1, Some(&aid("grok"))),
            candidate("high", 9, 20, Some(&aid("kimi"))),
            candidate("low-early", 0, 2, Some(&aid("kimi"))),
        ];
        let plan = plan_dispatch(
            &candidates,
            &occupancy,
            SchedulerPolicy {
                limits: SchedulerLimits {
                    global: 2,
                    per_adapter: 1,
                },
                bypass_bound: 4,
            },
            1_000,
        )
        .unwrap();
        // Only 2 global slots were available; the next candidate is blocked
        // on its (exhausted) adapter and the scan then stops on the global
        // limit with typed blocks.
        let ordered: Vec<_> = plan.dispatch.iter().map(|d| d.task_id.as_str()).collect();
        assert_eq!(ordered, ["high", "mid-early"]);
        assert_eq!(plan.dispatch[0].priority, 9);
        assert_eq!(plan.dispatch[1].priority, 5);
        assert_eq!(plan.blocked.len(), 2);
        assert_eq!(plan.blocked[0].task_id, "low-early");
        assert_eq!(plan.blocked[0].reason, DispatchBlockReason::AdapterLimit);
        assert_eq!(plan.blocked[1].task_id, "low-late");
        assert_eq!(plan.blocked[1].reason, DispatchBlockReason::GlobalLimit);
    }

    #[test]
    fn plan_bypasses_adapter_blocked_head_and_admits_later_adapters() {
        let mut occupancy = Occupancy {
            global: 1,
            ..Occupancy::default()
        };
        occupancy.per_adapter.insert(aid("claude"), 1);
        let candidates = vec![
            candidate("claude-head", 0, 1, Some(&aid("claude"))),
            candidate("grok-free", 0, 2, Some(&aid("grok"))),
        ];
        let plan =
            plan_dispatch(&candidates, &occupancy, SchedulerPolicy::default(), 1_000).unwrap();
        assert_eq!(plan.dispatch.len(), 1);
        assert_eq!(plan.dispatch[0].task_id, "grok-free");
        assert_eq!(plan.blocked[0].task_id, "claude-head");
        assert_eq!(plan.blocked[0].reason, DispatchBlockReason::AdapterLimit);
    }

    #[test]
    fn plan_bypass_is_bounded_per_round() {
        let mut occupancy = Occupancy::default();
        occupancy.per_adapter.insert(aid("claude"), 1);
        let candidates = vec![
            candidate("blocked-1", 0, 1, Some(&aid("claude"))),
            candidate("blocked-2", 0, 2, Some(&aid("claude"))),
            candidate("blocked-3", 0, 3, Some(&aid("claude"))),
            candidate("grok-free", 0, 4, Some(&aid("grok"))),
        ];
        let policy = SchedulerPolicy {
            limits: SchedulerLimits::DEFAULT,
            bypass_bound: 2,
        };
        let plan = plan_dispatch(&candidates, &occupancy, policy, 1_000).unwrap();
        // Two blocked heads were bypassed; the scan stops at the third, so
        // the later free-adapter candidate is not reached in this round.
        assert!(plan.dispatch.is_empty());
        assert_eq!(plan.blocked.len(), 2);
        assert!(
            plan.blocked
                .iter()
                .all(|b| b.reason == DispatchBlockReason::AdapterLimit)
        );

        let plan = plan_dispatch(
            &candidates,
            &occupancy,
            SchedulerPolicy {
                limits: SchedulerLimits::DEFAULT,
                bypass_bound: 4,
            },
            1_000,
        )
        .unwrap();
        assert_eq!(plan.dispatch.len(), 1);
        assert_eq!(plan.dispatch[0].task_id, "grok-free");
    }

    #[test]
    fn plan_skips_timer_pending_retry_without_budget_and_admits_behind_it() {
        let mut occupancy = Occupancy {
            global: 1,
            ..Occupancy::default()
        };
        occupancy.per_adapter.insert(aid("claude"), 1);
        let mut pending = candidate("timer-pending", 0, 1, Some(&aid("claude")));
        pending.state = TaskState::RetryWait;
        pending.retry_at = Some(2_000);
        let candidates = vec![
            pending,
            candidate("claude-blocked", 0, 2, Some(&aid("claude"))),
            candidate("grok-free", 0, 3, Some(&aid("grok"))),
        ];
        // bypass_bound = 2: the timer skip must not consume the budget, so
        // the single budget credit is spent on the adapter-blocked head and
        // the free adapter behind it is still reached.
        let plan = plan_dispatch(
            &candidates,
            &occupancy,
            SchedulerPolicy {
                limits: SchedulerLimits::DEFAULT,
                bypass_bound: 2,
            },
            1_000,
        )
        .unwrap();
        assert_eq!(plan.dispatch.len(), 1);
        assert_eq!(plan.dispatch[0].task_id, "grok-free");
        assert!(
            plan.blocked
                .iter()
                .any(|b| b.reason == DispatchBlockReason::RetryTimerPending)
        );
        assert!(
            plan.blocked
                .iter()
                .any(|b| b.reason == DispatchBlockReason::AdapterLimit)
        );
    }

    #[test]
    fn plan_never_admits_unassigned_adapters_but_does_not_stall_behind_them() {
        let candidates = vec![
            candidate("unassigned", 0, 1, None),
            candidate("assigned", 0, 2, Some(&aid("grok"))),
        ];
        let plan = plan_dispatch(
            &candidates,
            &Occupancy::default(),
            SchedulerPolicy::default(),
            1_000,
        )
        .unwrap();
        assert_eq!(plan.dispatch.len(), 1);
        assert_eq!(plan.dispatch[0].task_id, "assigned");
        assert_eq!(
            plan.blocked[0].reason,
            DispatchBlockReason::AdapterUnassigned
        );
    }

    #[test]
    fn plan_stops_at_global_exhaustion_without_reordering() {
        let occupancy = Occupancy {
            global: 3,
            ..Occupancy::default()
        };
        let candidates = vec![
            candidate("first", 0, 1, Some(&aid("claude"))),
            candidate("second", 0, 2, Some(&aid("grok"))),
        ];
        let plan =
            plan_dispatch(&candidates, &occupancy, SchedulerPolicy::default(), 1_000).unwrap();
        assert!(plan.dispatch.is_empty());
        assert_eq!(plan.blocked.len(), 1);
        assert_eq!(plan.blocked[0].task_id, "first");
        assert_eq!(plan.blocked[0].reason, DispatchBlockReason::GlobalLimit);
    }

    #[test]
    fn policy_validation_rejects_out_of_range_values() {
        assert!(
            SchedulerLimits {
                global: 0,
                per_adapter: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            SchedulerLimits {
                global: 17,
                per_adapter: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            SchedulerLimits {
                global: 3,
                per_adapter: 0
            }
            .validate()
            .is_err()
        );
        assert!(
            SchedulerLimits {
                global: 3,
                per_adapter: 5
            }
            .validate()
            .is_err()
        );
        assert!(
            SchedulerPolicy {
                limits: SchedulerLimits::DEFAULT,
                bypass_bound: 0
            }
            .validate()
            .is_err()
        );
        assert!(
            SchedulerPolicy {
                limits: SchedulerLimits::DEFAULT,
                bypass_bound: MAX_BYPASS_BOUND
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn adapter_instance_id_round_trips_and_rejects_bare_families() {
        let id = AdapterInstanceId::new("claude", "acct1", "default", DIGEST).unwrap();
        assert_eq!(id.family(), "claude");
        assert_eq!(id.encode(), format!("claude:acct1:default:{DIGEST}"));
        assert_eq!(AdapterInstanceId::parse(&id.encode()).unwrap(), id);
        assert_eq!(id.to_string(), id.encode());
        // A bare family string is routing identity, not an instance identity.
        assert!(AdapterInstanceId::parse("claude").is_err());
        assert!(AdapterInstanceId::parse(&format!("claude:acct:prof:{DIGEST}x")).is_err());
        assert!(AdapterInstanceId::parse("claude:acct:prof:short").is_err());
        assert!(AdapterInstanceId::parse("Claude:acct:prof:DIGEST").is_err());
    }

    // --- Writer/reader integration (durable state) ------------------------------

    #[test]
    fn claim_global_limit_persists_across_restart() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        for (task, adapter) in [
            ("t1", "claude"),
            ("t2", "grok"),
            ("t3", "kimi"),
            ("t4", "claude"),
        ] {
            writer
                .submit_for_scheduling(
                    "c",
                    "submit",
                    format!("k-{task}"),
                    format!("body-{task}").into_bytes(),
                    task,
                    None,
                    0,
                    Some(&aid(adapter)),
                    2,
                )
                .unwrap();
        }
        for (index, (task, adapter)) in [("t1", "claude"), ("t2", "grok"), ("t3", "kimi")]
            .into_iter()
            .enumerate()
        {
            match writer
                .claim_dispatch_slot(
                    format!("claim-{task}"),
                    task,
                    0,
                    spec(&aid(adapter)),
                    SchedulerLimits::DEFAULT,
                    10 + i64::try_from(index).unwrap(),
                )
                .unwrap()
            {
                DispatchOutcome::Dispatched(_) => {}
                DispatchOutcome::Blocked(blocked) => panic!("unexpected block: {blocked:?}"),
            }
        }
        let blocked = writer
            .claim_dispatch_slot(
                "claim-t4",
                "t4",
                0,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                20,
            )
            .unwrap();
        assert!(matches!(blocked, DispatchOutcome::Blocked(_)));
        let DispatchOutcome::Blocked(blocked) = blocked else {
            unreachable!()
        };
        assert_eq!(blocked.reason, DispatchBlockReason::GlobalLimit);
        assert_eq!((blocked.global_occupied, blocked.global_limit), (3, 3));

        writer.shutdown().unwrap();

        // Restart: occupancy is recomputed from SQLite, never from memory.
        let writer = WriterHandle::start_portable(root.clone(), "install", 30).unwrap();
        let reader = ReaderPool::open(&root).unwrap();
        let occupancy = recompute_occupancy(&reader, Duration::from_secs(1)).unwrap();
        assert_eq!(occupancy.global, 3);
        assert_eq!(occupancy.occupied(&aid("claude")), 1);
        assert_eq!(occupancy.occupied(&aid("grok")), 1);
        assert_eq!(occupancy.occupied(&aid("kimi")), 1);

        // The claim fence re-checks the same durable limits after restart.
        let still_blocked = writer
            .claim_dispatch_slot(
                "claim-t4",
                "t4",
                0,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                31,
            )
            .unwrap();
        assert!(matches!(still_blocked, DispatchOutcome::Blocked(_)));
        writer.shutdown().unwrap();
    }

    #[test]
    fn claim_enforces_per_adapter_limit_and_admits_other_adapters() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        for (task, adapter) in [("t1", "claude"), ("t2", "claude"), ("t3", "grok")] {
            writer
                .submit_for_scheduling(
                    "c",
                    "submit",
                    format!("k-{task}"),
                    format!("body-{task}").into_bytes(),
                    task,
                    None,
                    0,
                    Some(&aid(adapter)),
                    2,
                )
                .unwrap();
        }
        let DispatchOutcome::Dispatched(attempt) = writer
            .claim_dispatch_slot(
                "claim-t1",
                "t1",
                0,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                10,
            )
            .unwrap()
        else {
            panic!("t1 must claim");
        };
        assert_eq!(attempt.ordinal, 1);

        let DispatchOutcome::Blocked(blocked) = writer
            .claim_dispatch_slot(
                "claim-t2",
                "t2",
                0,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                11,
            )
            .unwrap()
        else {
            panic!("t2 must be blocked");
        };
        assert_eq!(blocked.reason, DispatchBlockReason::AdapterLimit);
        assert_eq!(blocked.adapter_instance_id, aid("claude"));
        assert_eq!(blocked.adapter_occupied, 1);
        assert_eq!(blocked.global_occupied, 1);

        // A different adapter instance has a free slot.
        let DispatchOutcome::Dispatched(attempt) = writer
            .claim_dispatch_slot(
                "claim-t3",
                "t3",
                0,
                spec(&aid("grok")),
                SchedulerLimits::DEFAULT,
                12,
            )
            .unwrap()
        else {
            panic!("t3 must claim");
        };
        assert_eq!(attempt.ordinal, 1);

        // The blocked task is still QUEUED: a refusal leaves no attempt row.
        let reader = ReaderPool::open(&root).unwrap();
        let candidates = reader.dispatch_candidates(Duration::from_secs(1)).unwrap();
        let t2 = candidates.iter().find(|c| c.task_id == "t2").unwrap();
        assert_eq!(t2.state, TaskState::Queued);
        writer.shutdown().unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn occupancy_counts_process_bearing_states_only() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        let reader = ReaderPool::open(&root).unwrap();
        let limits = SchedulerLimits {
            global: 16,
            per_adapter: 4,
        };

        let submit = |writer: &WriterHandle, task: &str, adapter: &str| {
            writer
                .submit_for_scheduling(
                    "c",
                    "submit",
                    format!("k-{task}"),
                    format!("body-{task}").into_bytes(),
                    task,
                    None,
                    0,
                    Some(&aid(adapter)),
                    2,
                )
                .unwrap();
        };

        // QUEUED tasks never consume slots.
        for (task, adapter) in [("q1", "claude"), ("q2", "claude"), ("q3", "grok")] {
            submit(&writer, task, adapter);
        }
        assert!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );

        // PREPARING consumes.
        submit(&writer, "prep", "claude");
        let DispatchOutcome::Dispatched(prep_attempt) = writer
            .claim_dispatch_slot("claim-prep", "prep", 0, spec(&aid("claude")), limits, 10)
            .unwrap()
        else {
            panic!("prep must claim");
        };
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            1
        );

        // Preflight WAITING_APPROVAL (no process) does not consume.
        writer
            .open_interaction(
                "open-preflight",
                "prep",
                &prep_attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                10_000,
                11,
            )
            .unwrap();
        assert!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );

        // Runtime WAITING_APPROVAL (process started) consumes.
        submit(&writer, "runtime", "grok");
        let DispatchOutcome::Dispatched(runtime_attempt) = writer
            .claim_dispatch_slot(
                "claim-runtime",
                "runtime",
                0,
                spec(&aid("grok")),
                limits,
                12,
            )
            .unwrap()
        else {
            panic!("runtime must claim");
        };
        writer
            .record_dispatch_phase(
                "phase-runtime",
                "runtime",
                0,
                DispatchPhase::ProcessStarted,
                None,
                13,
            )
            .unwrap();
        writer
            .open_interaction(
                "open-runtime",
                "runtime",
                &runtime_attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                10_000,
                14,
            )
            .unwrap();
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            1
        );

        // RUNNING consumes.
        submit(&writer, "running", "kimi");
        writer
            .claim_dispatch_slot(
                "claim-running",
                "running",
                0,
                spec(&aid("kimi")),
                limits,
                15,
            )
            .unwrap();
        writer
            .record_dispatch_phase(
                "phase-running",
                "running",
                0,
                DispatchPhase::ProcessStarted,
                None,
                16,
            )
            .unwrap();
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            2
        );

        // FINALIZING consumes.
        submit(&writer, "finalizing", "grok");
        writer
            .claim_dispatch_slot("claim-fin", "finalizing", 0, spec(&aid("grok")), limits, 17)
            .unwrap();
        writer
            .transition(
                "to-fin",
                "finalizing",
                0,
                vec!["PREPARING".to_string()],
                "FINALIZING",
                18,
            )
            .unwrap();
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            3
        );

        // CANCEL_REQUESTED from a process-bearing state consumes...
        submit(&writer, "cancelling", "kimi");
        writer
            .claim_dispatch_slot(
                "claim-cancel",
                "cancelling",
                0,
                spec(&aid("kimi")),
                limits,
                19,
            )
            .unwrap();
        writer
            .transition(
                "to-cancel",
                "cancelling",
                0,
                vec!["PREPARING".to_string()],
                "CANCEL_REQUESTED",
                20,
            )
            .unwrap();
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            4
        );
        // ...while a queued cancellation owns no process and does not.
        submit(&writer, "queued-cancel", "grok");
        writer
            .request_cancel(
                "c",
                "cancel-queued",
                b"cancel".to_vec(),
                "queued-cancel",
                21,
            )
            .unwrap();
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            4
        );

        // Timer-only RETRY_WAIT releases the slot.
        submit(&writer, "retrying", "claude");
        writer
            .claim_dispatch_slot(
                "claim-retrying",
                "retrying",
                0,
                spec(&aid("claude")),
                limits,
                22,
            )
            .unwrap();
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            5
        );
        writer
            .schedule_safe_retry("retry-retrying", "retrying", 0, 10_000, 23)
            .unwrap();
        assert_eq!(
            recompute_occupancy(&reader, Duration::from_secs(1))
                .unwrap()
                .global,
            4
        );
        writer.shutdown().unwrap();
    }

    #[test]
    fn claim_retry_wait_respects_timer_fences_and_adapter_immutability() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root, "install", 1).unwrap();
        writer
            .submit_for_scheduling(
                "c",
                "submit",
                "k",
                b"body".to_vec(),
                "t",
                None,
                0,
                Some(&aid("claude")),
                2,
            )
            .unwrap();
        let DispatchOutcome::Dispatched(first) = writer
            .claim_dispatch_slot(
                "claim-1",
                "t",
                0,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                10,
            )
            .unwrap()
        else {
            panic!("first claim");
        };
        let next_generation = writer
            .schedule_safe_retry("retry", "t", 0, 20_000, 11)
            .unwrap();
        assert_eq!(next_generation, 1);

        // Timer pending: typed refusal, no attempt created.
        let DispatchOutcome::Blocked(blocked) = writer
            .claim_dispatch_slot(
                "claim-2",
                "t",
                1,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                12,
            )
            .unwrap()
        else {
            panic!("timer must block");
        };
        assert_eq!(blocked.reason, DispatchBlockReason::RetryTimerPending);

        // A different adapter identity is fenced (no cross-provider
        // fallback), checked once the timer has elapsed so the identity fence
        // is exercised on an otherwise-ready task.
        assert!(matches!(
            writer.claim_dispatch_slot(
                "claim-3",
                "t",
                1,
                spec(&aid("grok")),
                SchedulerLimits::DEFAULT,
                20_000
            ),
            Err(StorageError::StaleGeneration)
        ));

        // Elapsed timer: dispatched as a new attempt at the next generation.
        let DispatchOutcome::Dispatched(second) = writer
            .claim_dispatch_slot(
                "claim-4",
                "t",
                1,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                20_000,
            )
            .unwrap()
        else {
            panic!("elapsed timer must claim");
        };
        assert_ne!(second.attempt_id, first.attempt_id);
        assert_eq!(second.ordinal, 2);
        assert_eq!(second.generation, 1);

        // The claim decision is internally idempotent under replay.
        let DispatchOutcome::Dispatched(replayed) = writer
            .claim_dispatch_slot(
                "claim-4",
                "t",
                1,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                20_001,
            )
            .unwrap()
        else {
            panic!("replay must return the original attempt");
        };
        assert_eq!(replayed, second);
        writer.shutdown().unwrap();
    }

    #[test]
    fn claim_rejects_stale_generation_and_invalid_identity_at_admission() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        writer
            .submit_for_scheduling(
                "c",
                "submit",
                "k",
                b"body".to_vec(),
                "t",
                None,
                0,
                Some(&aid("claude")),
                2,
            )
            .unwrap();
        // Stale generation fence.
        assert!(matches!(
            writer.claim_dispatch_slot(
                "claim",
                "t",
                7,
                spec(&aid("claude")),
                SchedulerLimits::DEFAULT,
                10
            ),
            Err(StorageError::StaleGeneration)
        ));
        // A bare family string is not an adapter instance identity.
        assert!(matches!(
            writer.claim_dispatch_slot(
                "claim",
                "t",
                0,
                spec("claude"),
                SchedulerLimits::DEFAULT,
                10
            ),
            Err(StorageError::InvalidRequest)
        ));
        // Submission rejects an invalid durable adapter identity too.
        assert!(matches!(
            writer.submit_for_scheduling(
                "c",
                "submit",
                "k2",
                b"body2".to_vec(),
                "t2",
                None,
                0,
                Some("grok"),
                3,
            ),
            Err(StorageError::InvalidRequest)
        ));
        writer.shutdown().unwrap();
    }

    #[test]
    fn reader_candidates_derive_order_and_identity_from_durable_state() {
        let root = tempfile::tempdir().unwrap().keep();
        let writer = WriterHandle::start_portable(root.clone(), "install", 1).unwrap();
        for (task, priority, created_at, adapter) in [
            ("low", 0, 3, Some(aid("claude"))),
            ("high", 9, 4, Some(aid("grok"))),
            ("mid-a", 5, 1, None),
            ("mid-b", 5, 2, Some(aid("kimi"))),
        ] {
            writer
                .submit_for_scheduling(
                    "c",
                    "submit",
                    format!("k-{task}"),
                    format!("body-{task}").into_bytes(),
                    task,
                    None,
                    priority,
                    adapter.as_deref(),
                    created_at,
                )
                .unwrap();
        }
        let reader = ReaderPool::open(&root).unwrap();
        let candidates = reader.dispatch_candidates(Duration::from_secs(1)).unwrap();
        let order: Vec<&str> = candidates.iter().map(|c| c.task_id.as_str()).collect();
        assert_eq!(order, ["high", "mid-a", "mid-b", "low"]);
        let mid_a = candidates.iter().find(|c| c.task_id == "mid-a").unwrap();
        assert_eq!(mid_a.adapter_instance_id, None);
        let mid_b = candidates.iter().find(|c| c.task_id == "mid-b").unwrap();
        assert_eq!(
            mid_b.adapter_instance_id.as_deref(),
            Some(aid("kimi").as_str())
        );
        assert_eq!(mid_b.priority, 5);
        writer.shutdown().unwrap();
    }
}
