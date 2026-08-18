//! Guarded, deterministic policy-improvement contracts.
//!
//! The improvement loop changes immutable configuration data only. It never
//! edits executable code, provider identity, permissions, isolation, retry, or
//! redaction policy. Durable mutation and cohort queries remain owned by the
//! sole storage writer; this module owns validation and deterministic scoring.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const ELIGIBILITY_OCCURRENCES: usize = 3;
pub const ELIGIBILITY_WINDOW: usize = 20;
pub const MIN_FIXTURE_OUTCOMES: usize = 10;
pub const CANARY_PERCENT: u8 = 20;
pub const MIN_CANARY_SAMPLES_PER_ARM: usize = 20;
pub const COOLDOWN_US: i64 = 7 * 86_400_000_000;
pub const MIN_CANARY_AGE_US: i64 = 7 * 86_400_000_000;
pub const CASE_EXPIRY_US: i64 = 30 * 86_400_000_000;

const MAX_TOKEN_LENGTH: usize = 128;
const MAX_HYPOTHESIS_LENGTH: usize = 2_048;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImprovementState {
    Observing,
    Canary,
    Promoted,
    RolledBack,
    Frozen,
}

impl ImprovementState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observing => "OBSERVING",
            Self::Canary => "CANARY",
            Self::Promoted => "PROMOTED",
            Self::RolledBack => "ROLLED_BACK",
            Self::Frozen => "FROZEN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKnob {
    PromptComposition,
    ContextSelection,
    SameAgentTransportPriority,
    Quality,
    Effort,
}

impl CandidateKnob {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PromptComposition => "prompt_composition",
            Self::ContextSelection => "context_selection",
            Self::SameAgentTransportPriority => "same_agent_transport_priority",
            Self::Quality => "quality",
            Self::Effort => "effort",
        }
    }
}

/// Runtime policy derived from safe settings. The default keeps all mutation
/// disabled; callers must explicitly opt in and supply bounded profile IDs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImprovementPolicy {
    pub enabled: bool,
    pub prompt_profiles: BTreeSet<String>,
    pub context_profiles: BTreeSet<String>,
    pub transport_profiles: BTreeSet<String>,
    pub allowed_quality: BTreeSet<String>,
    pub allowed_effort: BTreeSet<String>,
}

impl Default for ImprovementPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            prompt_profiles: BTreeSet::new(),
            context_profiles: BTreeSet::new(),
            transport_profiles: BTreeSet::new(),
            allowed_quality: ["low", "standard", "high"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            allowed_effort: ["low", "medium", "high"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureSignature {
    pub protocol_stage: String,
    pub failure_class: String,
    pub version_bucket: String,
    pub diagnostic_code: String,
}

impl FailureSignature {
    pub(crate) fn normalized_key(&self) -> Option<String> {
        let fields = [
            self.protocol_stage.as_str(),
            self.failure_class.as_str(),
            self.version_bucket.as_str(),
            self.diagnostic_code.as_str(),
        ];
        fields.iter().all(|field| valid_token(field)).then(|| {
            let mut hasher = Sha256::new();
            for field in fields {
                hasher.update(field.as_bytes());
                hasher.update([0]);
            }
            format!("{:x}", hasher.finalize())
        })
    }
}

/// Comparable adapter/config identity. A task can only be compared with
/// reviewed tasks carrying the exact same cohort values.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Cohort {
    pub adapter_instance_id: String,
    pub adapter_version: String,
    pub config_version: i64,
    pub config_digest: String,
}

impl Cohort {
    fn validate(&self) -> bool {
        valid_token(&self.adapter_instance_id)
            && valid_token(&self.adapter_version)
            && self.config_version >= 0
            && is_lower_sha256(&self.config_digest)
    }
}

/// Complete evidence available to the deterministic engine after a result has
/// been reviewed. Storage adapters should derive `success` and `cohort` from
/// persisted task/attempt rows rather than trusting client input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservationInput {
    pub task_id: String,
    pub component: String,
    pub cohort: Cohort,
    pub reviewed_at_us: i64,
    pub success: bool,
    pub failure_signature: Option<FailureSignature>,
    pub latency_us: Option<u64>,
    pub token_cost: Option<u64>,
    pub safety_violations: u32,
}

impl ObservationInput {
    fn validate(&self) -> bool {
        valid_token(&self.task_id)
            && valid_token(&self.component)
            && self.cohort.validate()
            && self.reviewed_at_us >= 0
            && self
                .failure_signature
                .as_ref()
                .is_none_or(|signature| signature.normalized_key().is_some())
            && (self.success == self.failure_signature.is_none())
            && self
                .latency_us
                .is_none_or(|value| i64::try_from(value).is_ok())
            && self
                .token_cost
                .is_none_or(|value| i64::try_from(value).is_ok())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FixtureOutcome {
    pub fixture_id: String,
    pub passed: bool,
    pub hard_invariant_failures: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CandidateProposal {
    pub case_id: String,
    pub knob: CandidateKnob,
    pub value: Value,
    pub hypothesis: String,
    pub fixtures: Vec<FixtureOutcome>,
}

impl CandidateProposal {
    pub(crate) fn validate(&self, policy: &ImprovementPolicy) -> Option<CandidateValidation> {
        if !valid_token(&self.case_id)
            || self.hypothesis.is_empty()
            || self.hypothesis.chars().count() > MAX_HYPOTHESIS_LENGTH
            || self.fixtures.len() < MIN_FIXTURE_OUTCOMES
        {
            return None;
        }
        let mut fixture_ids = BTreeSet::new();
        if self.fixtures.iter().any(|fixture| {
            !valid_token(&fixture.fixture_id) || !fixture_ids.insert(fixture.fixture_id.as_str())
        }) {
            return None;
        }
        let value = self.value.as_str()?;
        if !valid_token(value) {
            return None;
        }
        let allowlist = match self.knob {
            CandidateKnob::PromptComposition => &policy.prompt_profiles,
            CandidateKnob::ContextSelection => &policy.context_profiles,
            CandidateKnob::SameAgentTransportPriority => &policy.transport_profiles,
            CandidateKnob::Quality => &policy.allowed_quality,
            CandidateKnob::Effort => &policy.allowed_effort,
        };
        if !allowlist.contains(value) {
            return None;
        }
        let hard_failure = self
            .fixtures
            .iter()
            .any(|fixture| fixture.hard_invariant_failures != 0);
        let all_passed = self.fixtures.iter().all(|fixture| fixture.passed);
        Some(CandidateValidation {
            fixture_gate_passed: all_passed && !hard_failure,
            hard_failure,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateValidation {
    pub fixture_gate_passed: bool,
    pub hard_failure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationDecision {
    FeatureDisabled,
    Invalid,
    ConflictingReplay,
    Recorded {
        comparable_tasks: usize,
        matching_failures: usize,
    },
    Eligible {
        case_id: String,
        comparable_tasks: usize,
        matching_failures: usize,
    },
    ActiveCase {
        case_id: String,
    },
    CoolingDown,
    Frozen,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateSnapshot {
    pub candidate_id: String,
    pub case_id: String,
    pub component: String,
    pub knob: CandidateKnob,
    pub value: Value,
    pub parent_config_version: i64,
    pub rollback_config_version: i64,
    pub candidate_config_version: i64,
    pub candidate_config_digest: String,
    pub fixture_gate_passed: bool,
    pub fixture_hard_failure: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaseSnapshot {
    pub case_id: String,
    pub component: String,
    pub cohort: Cohort,
    pub signature: String,
    pub created_at_us: i64,
    pub state: ImprovementState,
    pub candidate_id: Option<String>,
    pub parent_config_version: i64,
    pub canary_started_at_us: Option<i64>,
    pub rollback_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CandidateDecision {
    FeatureDisabled,
    Canary {
        candidate_config_version: i64,
        candidate_config_digest: String,
    },
    FixtureRejected {
        hard_invariant_failure: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateCommandResult {
    pub decision: CandidateDecision,
    pub case: CaseSnapshot,
    pub candidate_config_version: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanaryAssignment {
    pub case_id: String,
    pub task_id: String,
    pub candidate: bool,
    pub config_version: i64,
    pub config_digest: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanaryAdmission {
    pub task_id: String,
    pub cohort: Cohort,
    pub opted_in: bool,
    pub read_only: bool,
    pub is_new: bool,
    pub now_us: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanaryDecision {
    FeatureDisabled,
    NotEligible,
    Assigned(CanaryAssignment),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EvaluationDecision {
    FeatureDisabled,
    WaitingForTime,
    WaitingForSamples {
        candidate: usize,
        control: usize,
    },
    MissingMetrics,
    Promoted {
        config_version: i64,
    },
    RolledBack {
        config_version: i64,
        rollback_count: u32,
    },
    Frozen {
        config_version: i64,
        rollback_count: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackCommandResult {
    pub decision: EvaluationDecision,
    pub case: CaseSnapshot,
    pub candidate_config_version: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredObservation {
    input: ObservationInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CaseRecord {
    case_id: String,
    component: String,
    cohort: Cohort,
    signature: String,
    created_at_us: i64,
    state: ImprovementState,
    candidate_id: Option<String>,
    parent_config_version: i64,
    canary_started_at_us: Option<i64>,
    rollback_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CandidateRecord {
    candidate_id: String,
    case_id: String,
    component: String,
    knob: CandidateKnob,
    value: Value,
    parent_config_version: i64,
    rollback_config_version: i64,
    candidate_config_version: i64,
    candidate_config_digest: String,
    fixture_gate_passed: bool,
    fixture_hard_failure: bool,
}

/// In-memory deterministic reference implementation for the M7 lifecycle.
///
/// The daemon storage layer can persist these records one transaction at a
/// time. Keeping the policy decisions here makes threshold, clock, and replay
/// behavior independently testable without `SQLite` or provider integrations.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImprovementEngine {
    policy: ImprovementPolicy,
    observations: BTreeMap<String, StoredObservation>,
    cases: BTreeMap<String, CaseRecord>,
    candidates: BTreeMap<String, CandidateRecord>,
    assignments: BTreeMap<String, CanaryAssignment>,
    active_config_versions: BTreeMap<String, i64>,
    cooldown_until: BTreeMap<String, i64>,
    rollback_counts: BTreeMap<String, u32>,
    next_config_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableCase {
    pub case_id: String,
    pub component: String,
    pub state: ImprovementState,
    pub created_at_us: i64,
    pub candidate_id: Option<String>,
    pub parent_config_version: i64,
    pub canary_started_at_us: Option<i64>,
    pub rollback_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableCandidate {
    pub candidate_id: String,
    pub case_id: String,
    pub component: String,
    pub knob: CandidateKnob,
    pub value: Value,
    pub parent_config_version: i64,
    pub rollback_config_version: i64,
    pub candidate_config_version: i64,
    pub candidate_config_digest: String,
    pub fixture_gate_passed: bool,
    pub fixture_hard_failure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableProjection {
    pub cases: Vec<DurableCase>,
    pub candidates: Vec<DurableCandidate>,
    pub assignments: Vec<CanaryAssignment>,
    pub active_config_versions: Vec<(String, i64)>,
}

impl ImprovementEngine {
    #[must_use]
    pub fn new(policy: ImprovementPolicy) -> Self {
        Self {
            policy,
            observations: BTreeMap::new(),
            cases: BTreeMap::new(),
            candidates: BTreeMap::new(),
            assignments: BTreeMap::new(),
            active_config_versions: BTreeMap::new(),
            cooldown_until: BTreeMap::new(),
            rollback_counts: BTreeMap::new(),
            next_config_version: 1,
        }
    }

    #[must_use]
    pub fn policy(&self) -> &ImprovementPolicy {
        &self.policy
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.policy.enabled = enabled;
    }

    pub(crate) fn snapshot_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub(crate) fn from_snapshot_json(source: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(source)
    }

    pub(crate) fn durable_projection(&self) -> DurableProjection {
        DurableProjection {
            cases: self
                .cases
                .values()
                .map(|case| DurableCase {
                    case_id: case.case_id.clone(),
                    component: case.component.clone(),
                    state: case.state,
                    created_at_us: case.created_at_us,
                    candidate_id: case.candidate_id.clone(),
                    parent_config_version: case.parent_config_version,
                    canary_started_at_us: case.canary_started_at_us,
                    rollback_count: case.rollback_count,
                })
                .collect(),
            candidates: self
                .candidates
                .values()
                .map(|candidate| DurableCandidate {
                    candidate_id: candidate.candidate_id.clone(),
                    case_id: candidate.case_id.clone(),
                    component: candidate.component.clone(),
                    knob: candidate.knob,
                    value: candidate.value.clone(),
                    parent_config_version: candidate.parent_config_version,
                    rollback_config_version: candidate.rollback_config_version,
                    candidate_config_version: candidate.candidate_config_version,
                    candidate_config_digest: candidate.candidate_config_digest.clone(),
                    fixture_gate_passed: candidate.fixture_gate_passed,
                    fixture_hard_failure: candidate.fixture_hard_failure,
                })
                .collect(),
            assignments: self.assignments.values().cloned().collect(),
            active_config_versions: self
                .active_config_versions
                .iter()
                .map(|(component, version)| (component.clone(), *version))
                .collect(),
        }
    }

    /// Records one reviewed task. Replaying a task is a no-op and never counts
    /// a retry twice. Feature-off mode performs no observation mutation.
    pub fn observe(&mut self, input: ObservationInput) -> ObservationDecision {
        if !self.policy.enabled {
            return ObservationDecision::FeatureDisabled;
        }
        if !input.validate() {
            return ObservationDecision::Invalid;
        }
        self.expire(input.reviewed_at_us);
        if let Some(existing) = self.observations.get(&input.task_id) {
            if existing.input == input {
                return self.eligibility_for(&existing.input);
            }
            return ObservationDecision::ConflictingReplay;
        }
        if let Some(assignment) = self.assignments.get(&input.task_id) {
            let Some(case) = self.cases.get(&assignment.case_id) else {
                return ObservationDecision::Invalid;
            };
            if input.component != case.component
                || input.cohort.adapter_instance_id != case.cohort.adapter_instance_id
                || input.cohort.adapter_version != case.cohort.adapter_version
                || input.cohort.config_version != assignment.config_version
                || input.cohort.config_digest != assignment.config_digest
            {
                return ObservationDecision::Invalid;
            }
        }
        let task_id = input.task_id.clone();
        self.next_config_version = self.next_config_version.max(input.cohort.config_version);
        self.observations
            .insert(task_id.clone(), StoredObservation { input });
        self.eligibility_for(&self.observations[&task_id].input)
    }

    fn eligibility_for(&self, input: &ObservationInput) -> ObservationDecision {
        let Some(signature) = input
            .failure_signature
            .as_ref()
            .and_then(FailureSignature::normalized_key)
        else {
            return ObservationDecision::Recorded {
                comparable_tasks: 1,
                matching_failures: 0,
            };
        };
        if self
            .cases
            .values()
            .any(|case| case.component == input.component && case.state == ImprovementState::Frozen)
        {
            return ObservationDecision::Frozen;
        }
        if let Some(case) = self.cases.values().find(|case| {
            case.component == input.component
                && matches!(
                    case.state,
                    ImprovementState::Observing | ImprovementState::Canary
                )
        }) {
            return ObservationDecision::ActiveCase {
                case_id: case.case_id.clone(),
            };
        }
        if self
            .cooldown_until
            .get(&input.component)
            .is_some_and(|until| *until > input.reviewed_at_us)
        {
            return ObservationDecision::CoolingDown;
        }
        let comparable = self.comparable_observations(&input.component, &input.cohort);
        let matching = comparable
            .iter()
            .filter(|observation| {
                observation
                    .input
                    .failure_signature
                    .as_ref()
                    .and_then(FailureSignature::normalized_key)
                    .as_deref()
                    == Some(signature.as_str())
            })
            .count();
        if matching < ELIGIBILITY_OCCURRENCES {
            return ObservationDecision::Recorded {
                comparable_tasks: comparable.len(),
                matching_failures: matching,
            };
        }
        let case_id = deterministic_case_id(
            &input.component,
            &input.cohort.adapter_instance_id,
            &input.cohort.adapter_version,
            input.cohort.config_version,
            &input.cohort.config_digest,
            &signature,
            &input.task_id,
        );
        ObservationDecision::Eligible {
            case_id,
            comparable_tasks: comparable.len(),
            matching_failures: matching,
        }
    }

    /// Opens the one active case for an eligible signature. It is deliberately
    /// separate from `observe` so storage can commit observation and case rows
    /// atomically while retaining an inspectable eligibility decision.
    pub fn open_eligible_case(&mut self, input: &ObservationInput, now_us: i64) -> Option<String> {
        if !self.policy.enabled || !input.validate() {
            return None;
        }
        self.expire(now_us);
        let decision = self.eligibility_for(input);
        let ObservationDecision::Eligible { case_id, .. } = decision else {
            return None;
        };
        let signature = input
            .failure_signature
            .as_ref()
            .and_then(FailureSignature::normalized_key)?;
        self.active_config_versions
            .entry(input.component.clone())
            .or_insert(input.cohort.config_version);
        self.cases.insert(
            case_id.clone(),
            CaseRecord {
                case_id: case_id.clone(),
                component: input.component.clone(),
                cohort: input.cohort.clone(),
                signature,
                created_at_us: now_us,
                state: ImprovementState::Observing,
                candidate_id: None,
                parent_config_version: input.cohort.config_version,
                canary_started_at_us: None,
                rollback_count: *self.rollback_counts.get(&input.component).unwrap_or(&0),
            },
        );
        Some(case_id)
    }

    #[must_use]
    pub fn case_state(&self, case_id: &str) -> Option<ImprovementState> {
        self.cases.get(case_id).map(|case| case.state)
    }

    #[must_use]
    pub fn case_snapshot(&self, case_id: &str) -> Option<CaseSnapshot> {
        self.cases.get(case_id).map(|case| CaseSnapshot {
            case_id: case.case_id.clone(),
            component: case.component.clone(),
            cohort: case.cohort.clone(),
            signature: case.signature.clone(),
            created_at_us: case.created_at_us,
            state: case.state,
            candidate_id: case.candidate_id.clone(),
            parent_config_version: case.parent_config_version,
            canary_started_at_us: case.canary_started_at_us,
            rollback_count: case.rollback_count,
        })
    }

    #[must_use]
    pub fn candidate_snapshot(&self, case_id: &str) -> Option<CandidateSnapshot> {
        let candidate_id = self.cases.get(case_id)?.candidate_id.as_ref()?;
        let candidate = self.candidates.get(candidate_id)?;
        Some(CandidateSnapshot {
            candidate_id: candidate.candidate_id.clone(),
            case_id: candidate.case_id.clone(),
            component: candidate.component.clone(),
            knob: candidate.knob,
            value: candidate.value.clone(),
            parent_config_version: candidate.parent_config_version,
            rollback_config_version: candidate.rollback_config_version,
            candidate_config_version: candidate.candidate_config_version,
            candidate_config_digest: candidate.candidate_config_digest.clone(),
            fixture_gate_passed: candidate.fixture_gate_passed,
            fixture_hard_failure: candidate.fixture_hard_failure,
        })
    }

    #[must_use]
    pub fn active_config_version(&self, component: &str) -> Option<i64> {
        self.active_config_versions.get(component).copied()
    }

    #[must_use]
    pub fn candidate_config_version(&self, case_id: &str) -> Option<i64> {
        self.cases
            .get(case_id)
            .and_then(|case| case.candidate_id.as_ref())
            .and_then(|candidate| self.candidates.get(candidate))
            .map(|candidate| candidate.candidate_config_version)
    }

    pub fn propose_candidate(
        &mut self,
        proposal: CandidateProposal,
        now_us: i64,
    ) -> Option<CandidateDecision> {
        if !self.policy.enabled {
            return Some(CandidateDecision::FeatureDisabled);
        }
        let case = self.cases.get_mut(&proposal.case_id)?;
        if case.state != ImprovementState::Observing
            || now_us.saturating_sub(case.created_at_us) >= CASE_EXPIRY_US
        {
            return None;
        }
        let validation = proposal.validate(&self.policy)?;
        let candidate_digest_hex = format!(
            "{:x}",
            Sha256::digest(
                json!({"case": proposal.case_id, "knob": proposal.knob.as_str(), "value": proposal.value})
                    .to_string()
                    .as_bytes(),
            )
        );
        let candidate_id = format!("cand-{}", &candidate_digest_hex[..32]);
        if self.candidates.contains_key(&candidate_id) {
            return Some(if validation.fixture_gate_passed {
                CandidateDecision::Canary {
                    candidate_config_version: self.candidates[&candidate_id]
                        .candidate_config_version,
                    candidate_config_digest: self.candidates[&candidate_id]
                        .candidate_config_digest
                        .clone(),
                }
            } else {
                CandidateDecision::FixtureRejected {
                    hard_invariant_failure: validation.hard_failure,
                }
            });
        }
        self.next_config_version = self.next_config_version.saturating_add(1);
        let candidate_version = self.next_config_version;
        let digest = candidate_digest(
            case.parent_config_version,
            &case.component,
            proposal.knob,
            &proposal.value,
        );
        self.candidates.insert(
            candidate_id.clone(),
            CandidateRecord {
                candidate_id: candidate_id.clone(),
                case_id: proposal.case_id.clone(),
                component: case.component.clone(),
                knob: proposal.knob,
                value: proposal.value,
                parent_config_version: case.parent_config_version,
                rollback_config_version: case.parent_config_version,
                candidate_config_version: candidate_version,
                candidate_config_digest: digest.clone(),
                fixture_gate_passed: validation.fixture_gate_passed,
                fixture_hard_failure: validation.hard_failure,
            },
        );
        case.candidate_id = Some(candidate_id);
        if !validation.fixture_gate_passed {
            case.state = ImprovementState::RolledBack;
            self.cooldown_until
                .insert(case.component.clone(), now_us.saturating_add(COOLDOWN_US));
            return Some(CandidateDecision::FixtureRejected {
                hard_invariant_failure: validation.hard_failure,
            });
        }
        case.state = ImprovementState::Canary;
        case.canary_started_at_us = Some(now_us);
        Some(CandidateDecision::Canary {
            candidate_config_version: candidate_version,
            candidate_config_digest: digest,
        })
    }

    pub fn assign_canary(&mut self, case_id: &str, admission: CanaryAdmission) -> CanaryDecision {
        if !self.policy.enabled {
            return CanaryDecision::FeatureDisabled;
        }
        let CanaryAdmission {
            task_id,
            cohort,
            opted_in,
            read_only,
            is_new,
            now_us,
        } = admission;
        if let Some(existing) = self.assignments.get(&task_id) {
            if existing.case_id == case_id {
                let mut replay = existing.clone();
                replay.replayed = true;
                return CanaryDecision::Assigned(replay);
            }
            return CanaryDecision::NotEligible;
        }
        let Some(case) = self.cases.get(case_id) else {
            return CanaryDecision::NotEligible;
        };
        if case.state != ImprovementState::Canary
            || now_us.saturating_sub(case.created_at_us) >= CASE_EXPIRY_US
            || !opted_in
            || !read_only
            || !is_new
            || cohort != case.cohort
        {
            return CanaryDecision::NotEligible;
        }
        let Some(candidate_id) = case.candidate_id.as_ref() else {
            return CanaryDecision::NotEligible;
        };
        let Some(candidate) = self.candidates.get(candidate_id) else {
            return CanaryDecision::NotEligible;
        };
        let is_candidate = stable_canary_bucket(case_id, &task_id) < CANARY_PERCENT;
        let (config_version, config_digest) = if is_candidate {
            (
                candidate.candidate_config_version,
                candidate.candidate_config_digest.clone(),
            )
        } else {
            (
                candidate.rollback_config_version,
                case.cohort.config_digest.clone(),
            )
        };
        let assignment = CanaryAssignment {
            case_id: case_id.into(),
            task_id: task_id.clone(),
            candidate: is_candidate,
            config_version,
            config_digest,
            replayed: false,
        };
        self.assignments.insert(task_id, assignment.clone());
        CanaryDecision::Assigned(assignment)
    }

    pub fn evaluate(&mut self, case_id: &str, now_us: i64) -> EvaluationDecision {
        if !self.policy.enabled {
            return EvaluationDecision::FeatureDisabled;
        }
        self.expire(now_us);
        let Some(case) = self.cases.get(case_id).cloned() else {
            return EvaluationDecision::WaitingForSamples {
                candidate: 0,
                control: 0,
            };
        };
        match case.state {
            ImprovementState::Promoted => EvaluationDecision::Promoted {
                config_version: self
                    .candidate_config_version(case_id)
                    .unwrap_or(case.parent_config_version),
            },
            ImprovementState::RolledBack => EvaluationDecision::RolledBack {
                config_version: case.parent_config_version,
                rollback_count: case.rollback_count,
            },
            ImprovementState::Frozen => EvaluationDecision::Frozen {
                config_version: case.parent_config_version,
                rollback_count: case.rollback_count,
            },
            ImprovementState::Observing => EvaluationDecision::WaitingForSamples {
                candidate: 0,
                control: 0,
            },
            ImprovementState::Canary => self.evaluate_canary(case, now_us),
        }
    }

    pub fn request_rollback(
        &mut self,
        case_id: &str,
        target_config_version: i64,
        now_us: i64,
    ) -> EvaluationDecision {
        if !self.policy.enabled {
            return EvaluationDecision::FeatureDisabled;
        }
        self.expire(now_us);
        let Some(case) = self.cases.get(case_id).cloned() else {
            return EvaluationDecision::WaitingForSamples {
                candidate: 0,
                control: 0,
            };
        };
        if target_config_version != case.parent_config_version {
            return EvaluationDecision::WaitingForSamples {
                candidate: 0,
                control: 0,
            };
        }
        match case.state {
            ImprovementState::Canary | ImprovementState::Promoted => {
                self.rollback_case(&case, now_us)
            }
            ImprovementState::RolledBack => EvaluationDecision::RolledBack {
                config_version: case.parent_config_version,
                rollback_count: case.rollback_count,
            },
            ImprovementState::Frozen => EvaluationDecision::Frozen {
                config_version: case.parent_config_version,
                rollback_count: case.rollback_count,
            },
            ImprovementState::Observing => EvaluationDecision::WaitingForSamples {
                candidate: 0,
                control: 0,
            },
        }
    }

    fn evaluate_canary(&mut self, case: CaseRecord, now_us: i64) -> EvaluationDecision {
        let Some(_candidate_id) = case.candidate_id.as_ref() else {
            return EvaluationDecision::WaitingForSamples {
                candidate: 0,
                control: 0,
            };
        };
        let mut candidate = ArmMetrics::default();
        let mut control = ArmMetrics::default();
        for assignment in self
            .assignments
            .values()
            .filter(|assignment| assignment.case_id == case.case_id)
        {
            let Some(observation) = self.observations.get(&assignment.task_id) else {
                continue;
            };
            let arm = if assignment.candidate {
                &mut candidate
            } else {
                &mut control
            };
            arm.samples += 1;
            arm.successes += usize::from(observation.input.success);
            arm.safety_violations += u64::from(observation.input.safety_violations);
            match observation.input.latency_us {
                Some(value) => arm.latency_sum += u128::from(value),
                None => arm.missing_metrics = true,
            }
            match observation.input.token_cost {
                Some(value) => arm.token_sum += u128::from(value),
                None => arm.missing_metrics = true,
            }
        }
        if candidate.safety_violations != 0 {
            return self.rollback_case(&case, now_us);
        }
        if candidate.samples < MIN_CANARY_SAMPLES_PER_ARM
            || control.samples < MIN_CANARY_SAMPLES_PER_ARM
        {
            return EvaluationDecision::WaitingForSamples {
                candidate: candidate.samples,
                control: control.samples,
            };
        }
        if candidate.missing_metrics || control.missing_metrics {
            return EvaluationDecision::MissingMetrics;
        }
        if case
            .canary_started_at_us
            .is_none_or(|started| now_us.saturating_sub(started) < MIN_CANARY_AGE_US)
        {
            return EvaluationDecision::WaitingForTime;
        }
        match compare_arms(&candidate, &control) {
            MetricGate::Pass => {
                if let Some(current) = self.cases.get_mut(&case.case_id) {
                    current.state = ImprovementState::Promoted;
                }
                let version = self
                    .candidate_config_version(&case.case_id)
                    .unwrap_or(case.parent_config_version);
                self.active_config_versions
                    .insert(case.component.clone(), version);
                self.cooldown_until
                    .insert(case.component, now_us.saturating_add(COOLDOWN_US));
                EvaluationDecision::Promoted {
                    config_version: version,
                }
            }
            MetricGate::Missing => EvaluationDecision::MissingMetrics,
            MetricGate::SafetyViolation
            | MetricGate::QualityRegression
            | MetricGate::ResourceRegression => self.rollback_case(&case, now_us),
        }
    }

    fn rollback_case(&mut self, case: &CaseRecord, now_us: i64) -> EvaluationDecision {
        let count = self
            .rollback_counts
            .entry(case.component.clone())
            .or_insert(case.rollback_count);
        *count = count.saturating_add(1);
        let count = *count;
        let frozen = count >= 2;
        if let Some(current) = self.cases.get_mut(&case.case_id) {
            current.rollback_count = count;
            current.state = if frozen {
                ImprovementState::Frozen
            } else {
                ImprovementState::RolledBack
            };
        }
        self.active_config_versions
            .insert(case.component.clone(), case.parent_config_version);
        self.cooldown_until
            .insert(case.component.clone(), now_us.saturating_add(COOLDOWN_US));
        if frozen {
            EvaluationDecision::Frozen {
                config_version: case.parent_config_version,
                rollback_count: count,
            }
        } else {
            EvaluationDecision::RolledBack {
                config_version: case.parent_config_version,
                rollback_count: count,
            }
        }
    }

    fn comparable_observations<'a>(
        &'a self,
        component: &str,
        cohort: &Cohort,
    ) -> Vec<&'a StoredObservation> {
        let mut values: Vec<_> = self
            .observations
            .values()
            .filter(|observation| {
                observation.input.component == component && &observation.input.cohort == cohort
            })
            .collect();
        values.sort_by(|left, right| {
            right
                .input
                .reviewed_at_us
                .cmp(&left.input.reviewed_at_us)
                .then_with(|| left.input.task_id.cmp(&right.input.task_id))
        });
        values.truncate(ELIGIBILITY_WINDOW);
        values
    }

    fn expire(&mut self, now_us: i64) {
        let expired: Vec<_> = self
            .cases
            .values()
            .filter(|case| {
                matches!(
                    case.state,
                    ImprovementState::Observing | ImprovementState::Canary
                ) && now_us.saturating_sub(case.created_at_us) >= CASE_EXPIRY_US
            })
            .map(|case| (case.case_id.clone(), case.component.clone()))
            .collect();
        for (case_id, component) in expired {
            if let Some(case) = self.cases.get_mut(&case_id) {
                case.state = ImprovementState::RolledBack;
            }
            self.cooldown_until
                .insert(component, now_us.saturating_add(COOLDOWN_US));
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArmMetrics {
    pub samples: usize,
    pub successes: usize,
    pub latency_sum: u128,
    pub token_sum: u128,
    pub missing_metrics: bool,
    pub safety_violations: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetricGate {
    Pass,
    QualityRegression,
    ResourceRegression,
    Missing,
    SafetyViolation,
}

pub(crate) fn compare_arms(candidate: &ArmMetrics, control: &ArmMetrics) -> MetricGate {
    if candidate.safety_violations != 0 {
        return MetricGate::SafetyViolation;
    }
    if candidate.missing_metrics || control.missing_metrics {
        return MetricGate::Missing;
    }
    if candidate.samples == 0 || control.samples == 0 {
        return MetricGate::QualityRegression;
    }
    // Compare exact integer ratios: candidate success must exceed control by
    // at least ten percentage points, without floating-point boundary drift.
    let candidate_success = candidate.successes as u128;
    let control_success = control.successes as u128;
    let candidate_samples = candidate.samples as u128;
    let control_samples = control.samples as u128;
    if 10 * candidate_success * control_samples
        < 10 * control_success * candidate_samples + candidate_samples * control_samples
    {
        return MetricGate::QualityRegression;
    }
    if regresses_over_ten_percent(
        candidate.latency_sum,
        candidate_samples,
        control.latency_sum,
        control_samples,
    ) || regresses_over_ten_percent(
        candidate.token_sum,
        candidate_samples,
        control.token_sum,
        control_samples,
    ) {
        return MetricGate::ResourceRegression;
    }
    MetricGate::Pass
}

fn regresses_over_ten_percent(
    candidate_sum: u128,
    candidate_samples: u128,
    control_sum: u128,
    control_samples: u128,
) -> bool {
    10 * candidate_sum * control_samples > 11 * control_sum * candidate_samples
}

#[must_use]
pub fn stable_canary_bucket(case_id: &str, task_id: &str) -> u8 {
    let digest = Sha256::digest(
        json!({"case_id": case_id, "task_id": task_id})
            .to_string()
            .as_bytes(),
    );
    let number = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    u8::try_from(number % 100).unwrap_or_default()
}

pub(crate) fn deterministic_case_id(
    component: &str,
    adapter_instance_id: &str,
    adapter_version: &str,
    config_version: i64,
    config_digest: &str,
    signature: &str,
    trigger_task_id: &str,
) -> String {
    let digest = Sha256::digest(
        json!({
            "adapter_instance_id": adapter_instance_id,
            "adapter_version": adapter_version,
            "component": component,
            "config_version": config_version,
            "config_digest": config_digest,
            "signature": signature,
            "trigger_task_id": trigger_task_id,
        })
        .to_string()
        .as_bytes(),
    );
    let hex = format!("{digest:x}");
    format!("imp-{}", &hex[..32])
}

pub(crate) fn candidate_digest(
    parent_version: i64,
    component: &str,
    knob: CandidateKnob,
    value: &Value,
) -> String {
    let record = json!({
        "component": component,
        "knob": knob.as_str(),
        "parent_version": parent_version,
        "value": value,
    });
    format!("{:x}", Sha256::digest(record.to_string().as_bytes()))
}

pub(crate) fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_LENGTH
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000_000;

    fn policy() -> ImprovementPolicy {
        ImprovementPolicy {
            enabled: true,
            prompt_profiles: ["prompt-v2".to_owned()].into_iter().collect(),
            context_profiles: ["context-v2".to_owned()].into_iter().collect(),
            transport_profiles: ["acp-first".to_owned()].into_iter().collect(),
            ..ImprovementPolicy::default()
        }
    }

    fn cohort(config_version: i64) -> Cohort {
        Cohort {
            adapter_instance_id: "claude-main".into(),
            adapter_version: "1.2.3".into(),
            config_version,
            config_digest: "a".repeat(64),
        }
    }

    fn admission(
        task_id: impl Into<String>,
        cohort: Cohort,
        opted_in: bool,
        read_only: bool,
        is_new: bool,
        now_us: i64,
    ) -> CanaryAdmission {
        CanaryAdmission {
            task_id: task_id.into(),
            cohort,
            opted_in,
            read_only,
            is_new,
            now_us,
        }
    }

    fn assigned_cohort(assignment: &CanaryAssignment) -> Cohort {
        let mut cohort = cohort(assignment.config_version);
        cohort.config_digest = assignment.config_digest.clone();
        cohort
    }

    fn signature(code: &str) -> FailureSignature {
        FailureSignature {
            protocol_stage: "terminal".into(),
            failure_class: "quality".into(),
            version_bucket: "1.x".into(),
            diagnostic_code: code.into(),
        }
    }

    fn failure(task_id: &str, reviewed_at_us: i64, cohort: Cohort) -> ObservationInput {
        ObservationInput {
            task_id: task_id.into(),
            component: "prompt-composer".into(),
            cohort,
            reviewed_at_us,
            success: false,
            failure_signature: Some(signature("BAD_CONTEXT")),
            latency_us: Some(100),
            token_cost: Some(100),
            safety_violations: 0,
        }
    }

    fn eligible_case(engine: &mut ImprovementEngine, start: i64) -> (String, ObservationInput) {
        for index in 0..3 {
            let trigger = failure(
                &format!("eligibility-{start}-{index}"),
                start + i64::from(index),
                cohort(1),
            );
            let decision = engine.observe(trigger.clone());
            if matches!(decision, ObservationDecision::Eligible { .. }) {
                let case_id = engine
                    .open_eligible_case(&trigger, start + i64::from(index))
                    .expect("eligible case");
                return (case_id, trigger);
            }
        }
        panic!("three matching observations must become eligible")
    }

    fn fixtures(hard_failure: bool) -> Vec<FixtureOutcome> {
        (0..MIN_FIXTURE_OUTCOMES)
            .map(|index| FixtureOutcome {
                fixture_id: format!("fixture-{index}"),
                passed: true,
                hard_invariant_failures: u32::from(hard_failure && index == 4),
            })
            .collect()
    }

    fn start_canary(engine: &mut ImprovementEngine, start: i64) -> String {
        let (case_id, _) = eligible_case(engine, start);
        let decision = engine
            .propose_candidate(
                CandidateProposal {
                    case_id: case_id.clone(),
                    knob: CandidateKnob::Quality,
                    value: Value::String("high".into()),
                    hypothesis: "raise bounded quality for this cohort".into(),
                    fixtures: fixtures(false),
                },
                start + 3,
            )
            .expect("valid candidate");
        assert!(matches!(decision, CandidateDecision::Canary { .. }));
        case_id
    }

    fn add_canary_outcomes(
        engine: &mut ImprovementEngine,
        case_id: &str,
        start: i64,
        missing_metric: bool,
    ) {
        let mut candidate_count = 0_usize;
        let mut control_count = 0_usize;
        for index in 0..10_000 {
            if candidate_count >= MIN_CANARY_SAMPLES_PER_ARM
                && control_count >= MIN_CANARY_SAMPLES_PER_ARM
            {
                break;
            }
            let task_id = format!("canary-task-{start}-{index}");
            let CanaryDecision::Assigned(assignment) = engine.assign_canary(
                case_id,
                admission(
                    task_id.clone(),
                    cohort(1),
                    true,
                    true,
                    true,
                    start + i64::from(index),
                ),
            ) else {
                panic!("eligible assignment");
            };
            let arm_index = if assignment.candidate {
                if candidate_count >= MIN_CANARY_SAMPLES_PER_ARM {
                    continue;
                }
                let value = candidate_count;
                candidate_count += 1;
                value
            } else {
                if control_count >= MIN_CANARY_SAMPLES_PER_ARM {
                    continue;
                }
                let value = control_count;
                control_count += 1;
                value
            };
            let success = if assignment.candidate {
                arm_index < 18
            } else {
                arm_index < 16
            };
            let observation = ObservationInput {
                task_id,
                component: "prompt-composer".into(),
                cohort: assigned_cohort(&assignment),
                reviewed_at_us: start + i64::from(index),
                success,
                failure_signature: (!success).then(|| signature("BAD_CONTEXT")),
                latency_us: (!missing_metric || arm_index != 0).then_some(100),
                token_cost: Some(100),
                safety_violations: 0,
            };
            assert!(!matches!(
                engine.observe(observation),
                ObservationDecision::Invalid | ObservationDecision::ConflictingReplay
            ));
        }
        assert_eq!(candidate_count, MIN_CANARY_SAMPLES_PER_ARM);
        assert_eq!(control_count, MIN_CANARY_SAMPLES_PER_ARM);
    }

    fn arm(samples: usize, successes: usize, latency: u128, tokens: u128) -> ArmMetrics {
        ArmMetrics {
            samples,
            successes,
            latency_sum: latency,
            token_sum: tokens,
            ..ArmMetrics::default()
        }
    }

    #[test]
    fn default_policy_is_disabled() {
        let mut engine = ImprovementEngine::new(ImprovementPolicy::default());
        let input = failure("disabled", 0, cohort(1));
        assert_eq!(
            engine.observe(input.clone()),
            ObservationDecision::FeatureDisabled
        );
        engine.set_enabled(true);
        assert_eq!(
            engine.observe(input),
            ObservationDecision::Recorded {
                comparable_tasks: 1,
                matching_failures: 1
            }
        );
    }

    #[test]
    fn canary_bucket_is_stable_and_bounded() {
        let first = stable_canary_bucket("case", "task");
        assert_eq!(first, stable_canary_bucket("case", "task"));
        assert!(first < 100);
    }

    #[test]
    fn fixture_gate_vetoes_one_hard_failure() {
        let policy = ImprovementPolicy {
            enabled: true,
            allowed_quality: ["high".to_owned()].into_iter().collect(),
            ..ImprovementPolicy::default()
        };
        let fixtures = (0..MIN_FIXTURE_OUTCOMES)
            .map(|index| FixtureOutcome {
                fixture_id: format!("fixture-{index}"),
                passed: true,
                hard_invariant_failures: u32::from(index == 4),
            })
            .collect();
        let proposal = CandidateProposal {
            case_id: "case".into(),
            knob: CandidateKnob::Quality,
            value: Value::String("high".into()),
            hypothesis: "bounded quality change".into(),
            fixtures,
        };
        let validation = proposal.validate(&policy).unwrap();
        assert!(validation.hard_failure);
        assert!(!validation.fixture_gate_passed);
    }

    #[test]
    fn metrics_require_ten_points_and_limit_resource_regression() {
        assert_eq!(
            compare_arms(&arm(20, 18, 2_200, 2_200), &arm(20, 16, 2_000, 2_000)),
            MetricGate::Pass
        );
        assert_eq!(
            compare_arms(&arm(20, 17, 2_000, 2_000), &arm(20, 16, 2_000, 2_000)),
            MetricGate::QualityRegression
        );
        assert_eq!(
            compare_arms(&arm(20, 18, 2_201, 2_000), &arm(20, 16, 2_000, 2_000)),
            MetricGate::ResourceRegression
        );
    }

    #[test]
    fn eligibility_counts_distinct_tasks_in_the_last_twenty_only() {
        let mut engine = ImprovementEngine::new(policy());
        let first = failure("same-task", 0, cohort(1));
        assert!(matches!(
            engine.observe(first.clone()),
            ObservationDecision::Recorded {
                matching_failures: 1,
                ..
            }
        ));
        assert!(matches!(
            engine.observe(first),
            ObservationDecision::Recorded {
                matching_failures: 1,
                ..
            }
        ));
        for index in 0..18 {
            let mut other = failure(&format!("other-{index}"), index + 1, cohort(1));
            other.failure_signature = Some(signature("OTHER"));
            engine.observe(other);
        }
        engine.observe(failure("same-signature-2", 30, cohort(1)));
        assert!(matches!(
            engine.observe(failure("same-signature-3", 31, cohort(1))),
            ObservationDecision::Recorded {
                comparable_tasks: 20,
                matching_failures: 2
            }
        ));
    }

    #[test]
    fn cohort_identity_prevents_cross_version_eligibility() {
        let mut engine = ImprovementEngine::new(policy());
        engine.observe(failure("v1-a", 0, cohort(1)));
        engine.observe(failure("v1-b", 1, cohort(1)));
        assert!(matches!(
            engine.observe(failure("v2-a", 2, cohort(2))),
            ObservationDecision::Recorded {
                comparable_tasks: 1,
                matching_failures: 1
            }
        ));
    }

    #[test]
    fn one_active_case_blocks_another_signature_for_the_component() {
        let mut engine = ImprovementEngine::new(policy());
        let (case_id, _) = eligible_case(&mut engine, 0);
        let mut other = failure("other-signature", 10, cohort(1));
        other.failure_signature = Some(signature("OTHER"));
        assert_eq!(
            engine.observe(other),
            ObservationDecision::ActiveCase { case_id }
        );
    }

    #[test]
    fn candidate_is_one_allowlisted_knob_with_immutable_lineage() {
        let mut engine = ImprovementEngine::new(policy());
        let case_id = start_canary(&mut engine, 0);
        let candidate = engine.candidate_snapshot(&case_id).unwrap();
        assert_eq!(candidate.knob, CandidateKnob::Quality);
        assert_eq!(candidate.parent_config_version, 1);
        assert_eq!(candidate.rollback_config_version, 1);
        assert_eq!(candidate.candidate_config_version, 2);
        assert!(candidate.fixture_gate_passed);
        assert_eq!(engine.case_state(&case_id), Some(ImprovementState::Canary));
    }

    #[test]
    fn fixture_count_and_hard_invariant_veto_candidate() {
        let mut engine = ImprovementEngine::new(policy());
        let (case_id, _) = eligible_case(&mut engine, 0);
        let mut too_few = fixtures(false);
        too_few.pop();
        assert!(
            engine
                .propose_candidate(
                    CandidateProposal {
                        case_id: case_id.clone(),
                        knob: CandidateKnob::Quality,
                        value: Value::String("high".into()),
                        hypothesis: "not enough fixtures".into(),
                        fixtures: too_few,
                    },
                    3,
                )
                .is_none()
        );
        assert_eq!(
            engine.case_state(&case_id),
            Some(ImprovementState::Observing)
        );
        assert_eq!(
            engine.propose_candidate(
                CandidateProposal {
                    case_id: case_id.clone(),
                    knob: CandidateKnob::Quality,
                    value: Value::String("high".into()),
                    hypothesis: "hard failure must veto".into(),
                    fixtures: fixtures(true),
                },
                4,
            ),
            Some(CandidateDecision::FixtureRejected {
                hard_invariant_failure: true
            })
        );
        assert_eq!(
            engine.case_state(&case_id),
            Some(ImprovementState::RolledBack)
        );
    }

    #[test]
    fn assignment_is_stable_twenty_percent_and_rejects_unsafe_tasks() {
        let mut engine = ImprovementEngine::new(policy());
        let case_id = start_canary(&mut engine, 0);
        assert_eq!(
            engine.assign_canary(
                &case_id,
                admission("write", cohort(1), true, false, true, 10),
            ),
            CanaryDecision::NotEligible
        );
        assert_eq!(
            engine.assign_canary(&case_id, admission("old", cohort(1), true, true, false, 10),),
            CanaryDecision::NotEligible
        );
        assert_eq!(
            engine.assign_canary(
                &case_id,
                admission("optout", cohort(1), false, true, true, 10),
            ),
            CanaryDecision::NotEligible
        );
        let first = engine.assign_canary(
            &case_id,
            admission("stable-task", cohort(1), true, true, true, 10),
        );
        let second = engine.assign_canary(
            &case_id,
            admission("stable-task", cohort(1), true, true, true, 11),
        );
        let (CanaryDecision::Assigned(first), CanaryDecision::Assigned(second)) = (first, second)
        else {
            panic!("stable assignments");
        };
        assert_eq!(first.config_version, second.config_version);
        assert_eq!(first.candidate, second.candidate);
        assert!(second.replayed);

        let selected = (0..10_000)
            .filter(|index| stable_canary_bucket(&case_id, &format!("sample-{index}")) < 20)
            .count();
        assert!((1_850..=2_150).contains(&selected));
    }

    #[test]
    fn promotion_waits_for_samples_time_and_complete_metrics() {
        let mut engine = ImprovementEngine::new(policy());
        let case_id = start_canary(&mut engine, 0);
        assert_eq!(
            engine.evaluate(&case_id, 7 * DAY),
            EvaluationDecision::WaitingForSamples {
                candidate: 0,
                control: 0
            }
        );
        add_canary_outcomes(&mut engine, &case_id, 100, false);
        assert_eq!(
            engine.evaluate(&case_id, 6 * DAY),
            EvaluationDecision::WaitingForTime
        );
        assert_eq!(
            engine.evaluate(&case_id, 7 * DAY + 3),
            EvaluationDecision::Promoted { config_version: 2 }
        );
        assert_eq!(engine.active_config_version("prompt-composer"), Some(2));
        assert_eq!(
            engine.evaluate(&case_id, 8 * DAY),
            EvaluationDecision::Promoted { config_version: 2 }
        );

        let mut missing = ImprovementEngine::new(policy());
        let missing_case = start_canary(&mut missing, 0);
        add_canary_outcomes(&mut missing, &missing_case, 100, true);
        assert_eq!(
            missing.evaluate(&missing_case, 7 * DAY + 3),
            EvaluationDecision::MissingMetrics
        );
        assert_eq!(
            missing.case_state(&missing_case),
            Some(ImprovementState::Canary)
        );
    }

    #[test]
    fn expiry_and_cooldown_use_exact_clock_boundaries() {
        let mut engine = ImprovementEngine::new(policy());
        let (case_id, _) = eligible_case(&mut engine, 0);
        let expires_at = engine.case_snapshot(&case_id).unwrap().created_at_us + CASE_EXPIRY_US;
        assert_eq!(
            engine.case_state(&case_id),
            Some(ImprovementState::Observing)
        );
        assert_eq!(
            engine.observe(failure("expiry-trigger", expires_at, cohort(1))),
            ObservationDecision::CoolingDown
        );
        assert_eq!(
            engine.case_state(&case_id),
            Some(ImprovementState::RolledBack)
        );
        assert_eq!(
            engine.observe(failure(
                "cooldown-minus-one",
                expires_at + COOLDOWN_US - 1,
                cohort(1)
            )),
            ObservationDecision::CoolingDown
        );
        assert!(matches!(
            engine.observe(failure(
                "cooldown-exact",
                expires_at + COOLDOWN_US,
                cohort(1)
            )),
            ObservationDecision::Eligible { .. }
        ));
    }

    #[test]
    fn safety_rollback_is_idempotent_and_second_rollback_freezes_component() {
        let mut engine = ImprovementEngine::new(policy());
        let first_case = start_canary(&mut engine, 0);
        let first_assignment = (0..1_000)
            .find_map(|index| {
                let task = format!("unsafe-first-{index}");
                match engine.assign_canary(
                    &first_case,
                    admission(task, cohort(1), true, true, true, 10 + index),
                ) {
                    CanaryDecision::Assigned(assignment) if assignment.candidate => {
                        Some(assignment)
                    }
                    _ => None,
                }
            })
            .unwrap();
        let mut unsafe_observation = failure(
            &first_assignment.task_id,
            100,
            assigned_cohort(&first_assignment),
        );
        unsafe_observation.safety_violations = 1;
        engine.observe(unsafe_observation);
        assert_eq!(
            engine.evaluate(&first_case, 101),
            EvaluationDecision::RolledBack {
                config_version: 1,
                rollback_count: 1
            }
        );
        assert_eq!(
            engine.evaluate(&first_case, 102),
            EvaluationDecision::RolledBack {
                config_version: 1,
                rollback_count: 1
            }
        );

        let second_start = COOLDOWN_US + 200;
        let second_case = start_canary(&mut engine, second_start);
        let second_assignment = (0..1_000)
            .find_map(|index| {
                let task = format!("unsafe-second-{index}");
                match engine.assign_canary(
                    &second_case,
                    admission(task, cohort(1), true, true, true, second_start + 10 + index),
                ) {
                    CanaryDecision::Assigned(assignment) if assignment.candidate => {
                        Some(assignment)
                    }
                    _ => None,
                }
            })
            .unwrap();
        let mut unsafe_observation = failure(
            &second_assignment.task_id,
            second_start + 2_000,
            assigned_cohort(&second_assignment),
        );
        unsafe_observation.safety_violations = 1;
        engine.observe(unsafe_observation);
        assert_eq!(
            engine.evaluate(&second_case, second_start + 2_001),
            EvaluationDecision::Frozen {
                config_version: 1,
                rollback_count: 2
            }
        );
        assert_eq!(
            engine.case_state(&second_case),
            Some(ImprovementState::Frozen)
        );
        assert_eq!(
            engine.observe(failure("after-freeze", second_start + 3_000, cohort(1))),
            ObservationDecision::Frozen
        );
    }

    #[test]
    fn conflicting_task_replay_and_assignment_cohort_drift_fail_closed() {
        let mut engine = ImprovementEngine::new(policy());
        let input = failure("replay", 0, cohort(1));
        engine.observe(input.clone());
        let mut changed = input;
        changed.token_cost = Some(101);
        assert_eq!(
            engine.observe(changed),
            ObservationDecision::ConflictingReplay
        );

        let case_id = start_canary(&mut engine, 10);
        let CanaryDecision::Assigned(assignment) = engine.assign_canary(
            &case_id,
            admission("drift", cohort(1), true, true, true, 20),
        ) else {
            panic!("assignment");
        };
        let mut drift = failure("drift", 21, assigned_cohort(&assignment));
        drift.cohort.adapter_version = "different".into();
        assert_eq!(engine.observe(drift), ObservationDecision::Invalid);
    }

    #[test]
    fn cloned_replay_state_does_not_double_promote_or_change_assignment() {
        let mut engine = ImprovementEngine::new(policy());
        let case_id = start_canary(&mut engine, 0);
        let assignment = engine.assign_canary(
            &case_id,
            admission("fixed-attempt", cohort(1), true, true, true, 10),
        );
        add_canary_outcomes(&mut engine, &case_id, 100, false);
        assert!(matches!(
            engine.evaluate(&case_id, 7 * DAY + 3),
            EvaluationDecision::Promoted { .. }
        ));
        let mut reopened = engine.clone();
        assert_eq!(
            reopened.evaluate(&case_id, 8 * DAY),
            EvaluationDecision::Promoted { config_version: 2 }
        );
        let replay = reopened.assign_canary(
            &case_id,
            admission("fixed-attempt", cohort(1), true, true, true, 8 * DAY),
        );
        let (CanaryDecision::Assigned(before), CanaryDecision::Assigned(after)) =
            (assignment, replay)
        else {
            panic!("fixed assignment replay");
        };
        assert_eq!(before.config_version, after.config_version);
        assert!(after.replayed);
    }
}
