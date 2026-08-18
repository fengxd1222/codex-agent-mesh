//! Typed durable-domain states and transition rules.

#![allow(clippy::missing_errors_doc)]

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskState {
    Queued,
    Preparing,
    Running,
    WaitingApproval,
    RetryWait,
    CancelRequested,
    Finalizing,
    Succeeded,
    Failed,
    Cancelled,
    NeedsAttention,
}

impl TaskState {
    pub const ALL: [Self; 11] = [
        Self::Queued,
        Self::Preparing,
        Self::Running,
        Self::WaitingApproval,
        Self::RetryWait,
        Self::CancelRequested,
        Self::Finalizing,
        Self::Succeeded,
        Self::Failed,
        Self::Cancelled,
        Self::NeedsAttention,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Preparing => "PREPARING",
            Self::Running => "RUNNING",
            Self::WaitingApproval => "WAITING_APPROVAL",
            Self::RetryWait => "RETRY_WAIT",
            Self::CancelRequested => "CANCEL_REQUESTED",
            Self::Finalizing => "FINALIZING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::NeedsAttention => "NEEDS_ATTENTION",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::NeedsAttention
        )
    }

    #[must_use]
    pub const fn allows(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Queued | Self::RetryWait,
                Self::Preparing | Self::CancelRequested
            ) | (
                Self::Preparing,
                Self::Running
                    | Self::WaitingApproval
                    | Self::RetryWait
                    | Self::CancelRequested
                    | Self::Finalizing
            ) | (
                Self::Running,
                Self::WaitingApproval | Self::RetryWait | Self::CancelRequested | Self::Finalizing
            ) | (
                Self::WaitingApproval,
                Self::Running | Self::CancelRequested | Self::Finalizing
            ) | (Self::CancelRequested, Self::Finalizing)
                | (
                    Self::Finalizing,
                    Self::Succeeded | Self::Failed | Self::Cancelled | Self::NeedsAttention
                )
        )
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TaskState {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|state| state.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptState {
    Preparing,
    Running,
    WaitingApproval,
    RetryWait,
    CancelRequested,
    Finalizing,
    Succeeded,
    Failed,
    Cancelled,
    NeedsAttention,
}

impl AttemptState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "PREPARING",
            Self::Running => "RUNNING",
            Self::WaitingApproval => "WAITING_APPROVAL",
            Self::RetryWait => "RETRY_WAIT",
            Self::CancelRequested => "CANCEL_REQUESTED",
            Self::Finalizing => "FINALIZING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::NeedsAttention => "NEEDS_ATTENTION",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DispatchPhase {
    PreDispatch,
    SpawnPrepared,
    ProcessStarted,
    ProviderObserved,
}

impl DispatchPhase {
    pub const ALL: [Self; 4] = [
        Self::PreDispatch,
        Self::SpawnPrepared,
        Self::ProcessStarted,
        Self::ProviderObserved,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreDispatch => "PRE_DISPATCH",
            Self::SpawnPrepared => "SPAWN_PREPARED",
            Self::ProcessStarted => "PROCESS_STARTED",
            Self::ProviderObserved => "PROVIDER_OBSERVED",
        }
    }

    #[must_use]
    pub const fn effect_is_proven_absent(self) -> bool {
        matches!(self, Self::PreDispatch | Self::SpawnPrepared)
    }

    /// Dispatch evidence is monotonic. In particular, an old callback may not
    /// rewrite observed process evidence back to a retry-safe phase.
    #[must_use]
    pub const fn can_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::PreDispatch,
                Self::SpawnPrepared | Self::ProcessStarted | Self::ProviderObserved
            ) | (
                Self::SpawnPrepared,
                Self::ProcessStarted | Self::ProviderObserved
            ) | (Self::ProcessStarted, Self::ProviderObserved)
        )
    }
}

impl FromStr for DispatchPhase {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|phase| phase.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InteractionState {
    Pending,
    Answered,
    Expired,
    Cancelled,
}

/// The provider capability class that caused a durable interaction.
///
/// These values are deliberately lower-case because they are persisted as the
/// public interaction vocabulary, rather than as a display-only projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InteractionCapabilityClass {
    Approval,
    Input,
}

impl InteractionCapabilityClass {
    pub const ALL: [Self; 2] = [Self::Approval, Self::Input];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Input => "input",
        }
    }
}

impl FromStr for InteractionCapabilityClass {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

/// A one-shot command response kind. The exact canonical response bytes are
/// stored separately; this enum prevents a caller from inventing a status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InteractionResponseKind {
    Approve,
    Deny,
    Text,
}

impl InteractionResponseKind {
    pub const ALL: [Self; 3] = [Self::Approve, Self::Deny, Self::Text];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Text => "text",
        }
    }

    #[must_use]
    pub const fn event_status(self) -> &'static str {
        match self {
            Self::Approve => "APPROVED",
            Self::Deny => "DENIED",
            Self::Text => "PROVIDED",
        }
    }
}

impl FromStr for InteractionResponseKind {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

/// Requested provider effect profile. Isolation is recorded separately.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectProfile {
    ReadOnly,
    IsolatedWorktree,
    CurrentDirectory,
    ExternalSideEffects,
}

impl EffectProfile {
    pub const ALL: [Self; 4] = [
        Self::ReadOnly,
        Self::IsolatedWorktree,
        Self::CurrentDirectory,
        Self::ExternalSideEffects,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "READ_ONLY",
            Self::IsolatedWorktree => "ISOLATED_WORKTREE",
            Self::CurrentDirectory => "CURRENT_DIRECTORY",
            Self::ExternalSideEffects => "EXTERNAL_SIDE_EFFECTS",
        }
    }
}

impl FromStr for EffectProfile {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

/// Actual isolation reported for an attempt. Worktrees are never `ENFORCED`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IsolationLevel {
    Enforced,
    ProtocolMediated,
    BestEffort,
    None,
}

impl IsolationLevel {
    pub const ALL: [Self; 4] = [
        Self::Enforced,
        Self::ProtocolMediated,
        Self::BestEffort,
        Self::None,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "ENFORCED",
            Self::ProtocolMediated => "PROTOCOL_MEDIATED",
            Self::BestEffort => "BEST_EFFORT",
            Self::None => "NONE",
        }
    }
}

impl FromStr for IsolationLevel {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|level| level.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

/// Task-request workspace mode. Never inferred from a failed worktree admit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    ReadOnly,
    IsolatedWorktree,
    CurrentDirectory,
}

impl WorkspaceMode {
    pub const ALL: [Self; 3] = [
        Self::ReadOnly,
        Self::IsolatedWorktree,
        Self::CurrentDirectory,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::IsolatedWorktree => "isolated_worktree",
            Self::CurrentDirectory => "current_directory",
        }
    }
}

impl FromStr for WorkspaceMode {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

/// The persisted review decision for the immutable result version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewVerdict {
    Accepted,
    Rejected,
}

impl ReviewVerdict {
    pub const ALL: [Self; 2] = [Self::Accepted, Self::Rejected];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::Rejected => "REJECTED",
        }
    }
}

impl FromStr for ReviewVerdict {
    type Err = DomainParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|verdict| verdict.as_str() == value)
            .ok_or_else(|| DomainParseError(value.to_owned()))
    }
}

impl InteractionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Answered => "ANSWERED",
            Self::Expired => "EXPIRED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    RetrySafe,
    ResumeSession,
    NeedsAttention,
    FinalizeCancellation,
}

#[derive(Debug, Error)]
#[error("unknown durable-domain value: {0}")]
pub struct DomainParseError(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_is_closed_and_terminal_states_are_immutable() {
        for from in TaskState::ALL {
            for to in TaskState::ALL {
                if from.is_terminal() {
                    assert!(!from.allows(to));
                }
            }
            assert_eq!(from.to_string().parse::<TaskState>().unwrap(), from);
        }
        assert!(TaskState::Running.allows(TaskState::Finalizing));
        assert!(!TaskState::Running.allows(TaskState::Succeeded));
        assert_eq!(
            EffectProfile::CurrentDirectory
                .as_str()
                .parse::<EffectProfile>()
                .unwrap(),
            EffectProfile::CurrentDirectory
        );
        assert_eq!(
            IsolationLevel::BestEffort
                .as_str()
                .parse::<IsolationLevel>()
                .unwrap(),
            IsolationLevel::BestEffort
        );
        assert_ne!(
            IsolationLevel::BestEffort.as_str(),
            IsolationLevel::Enforced.as_str()
        );
        assert_eq!(
            WorkspaceMode::CurrentDirectory
                .as_str()
                .parse::<WorkspaceMode>()
                .unwrap(),
            WorkspaceMode::CurrentDirectory
        );
    }
}
