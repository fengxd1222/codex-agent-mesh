//! Durable, secret-free installation identity and lifecycle record.
//!
//! This module deliberately has no filesystem or DPAPI implementation.  The
//! durable store and the audited Windows boundary own those concerns; this
//! module owns the serializable contract and its deterministic state changes.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

pub const INSTALL_RECORD_FORMAT_VERSION: u16 = 1;
const MAX_VERSION_LEN: usize = 128;
const MAX_RELATIVE_PATH_LEN: usize = 512;
const MAX_TASK_PATH_LEN: usize = 512;
const MAX_WINDOWS_COMPONENT_UTF16_LEN: usize = 255;

/// Stable, lower-case hexadecimal installation or consumer identity.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StableId(String);

impl StableId {
    /// Validates one 128-bit lower-case hexadecimal identity.
    ///
    /// # Errors
    ///
    /// Returns [`InstallRecordError::InvalidIdentity`] for any other shape.
    pub fn new(value: impl Into<String>) -> Result<Self, InstallRecordError> {
        let value = value.into();
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InstallRecordError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StableId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableId(..)")
    }
}

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A lower-case SHA-256 hexadecimal digest, without a prefix.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Constructs a lower-case SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`InstallRecordError::InvalidDigest`] unless `value` is hex64.
    pub fn new(value: impl Into<String>) -> Result<Self, InstallRecordError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InstallRecordError::InvalidDigest);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(..)")
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A normalized, relative Windows path beneath the product root.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RelativeWindowsPath(String);

impl RelativeWindowsPath {
    /// Constructs a normalized relative Windows path.
    ///
    /// # Errors
    ///
    /// Returns [`InstallRecordError::InvalidRelativePath`] for unsafe syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, InstallRecordError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_RELATIVE_PATH_LEN
            || value.contains('/')
            || value.starts_with('\\')
            || value.contains(':')
        {
            return Err(InstallRecordError::InvalidRelativePath);
        }
        if value
            .split('\\')
            .any(|part| !is_safe_windows_component(part))
        {
            return Err(InstallRecordError::InvalidRelativePath);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RelativeWindowsPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelativeWindowsPath(..)")
    }
}

impl<'de> Deserialize<'de> for RelativeWindowsPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// An exact root-qualified Task Scheduler path, separate from product files.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ScheduledTaskPath(String);

impl ScheduledTaskPath {
    /// Constructs a strict Task Scheduler path with exactly one leading slash.
    ///
    /// # Errors
    ///
    /// Returns [`InstallRecordError::InvalidScheduledTaskPath`] for unsafe syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, InstallRecordError> {
        let value = value.into();
        let Some(rest) = value.strip_prefix('\\') else {
            return Err(InstallRecordError::InvalidScheduledTaskPath);
        };
        if rest.is_empty()
            || value.len() > MAX_TASK_PATH_LEN
            || value.starts_with("\\\\")
            || value.contains('/')
            || value.contains('\0')
            || value.contains(':')
            || rest
                .split('\\')
                .any(|part| !is_safe_windows_component(part))
        {
            return Err(InstallRecordError::InvalidScheduledTaskPath);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ScheduledTaskPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScheduledTaskPath(..)")
    }
}

impl<'de> Deserialize<'de> for ScheduledTaskPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallState {
    Installing,
    Active,
    Removing,
    Retained,
    /// Destructive purge has crossed its durable fence.  It has no record
    /// successor: successful purge deletes the exact record last.
    Purging,
    Broken,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Signed,
    UnsignedDevelopment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifact {
    pub relative_path: RelativeWindowsPath,
    pub sha256: Sha256Digest,
    pub version: String,
    pub signer_status: SignerStatus,
    pub artifact_format: RuntimeArtifactFormat,
}

/// The single executable format admitted by the M3 stable runtime slot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeArtifactFormat {
    MeshDaemonExeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedKeyArtifact {
    /// Relative path to DPAPI-protected bytes; this record contains no key bytes.
    pub relative_path: RelativeWindowsPath,
    pub sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledTaskEvidence {
    /// Exact root-qualified logical Task Scheduler path.
    pub task_path: ScheduledTaskPath,
    pub definition_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstallRecord {
    pub format_version: u16,
    pub install_id: StableId,
    pub consumer_id: StableId,
    pub state: InstallState,
    pub revision: u64,
    pub product_relative_path: Option<RelativeWindowsPath>,
    pub data_relative_path: Option<RelativeWindowsPath>,
    pub data_schema_version: Option<u32>,
    pub protected_key: Option<ProtectedKeyArtifact>,
    /// One immutable executable identity shared by bridge and daemon modes.
    pub runtime: Option<RuntimeArtifact>,
    pub scheduled_task: Option<ScheduledTaskEvidence>,
    pub created_at_us: i64,
    pub updated_at_us: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallRecordWire {
    format_version: u16,
    install_id: StableId,
    consumer_id: StableId,
    state: InstallState,
    revision: u64,
    product_relative_path: Option<RelativeWindowsPath>,
    data_relative_path: Option<RelativeWindowsPath>,
    data_schema_version: Option<u32>,
    protected_key: Option<ProtectedKeyArtifact>,
    runtime: Option<RuntimeArtifact>,
    scheduled_task: Option<ScheduledTaskEvidence>,
    created_at_us: i64,
    updated_at_us: i64,
}

impl TryFrom<InstallRecordWire> for InstallRecord {
    type Error = InstallRecordError;
    fn try_from(wire: InstallRecordWire) -> Result<Self, Self::Error> {
        let record = Self {
            format_version: wire.format_version,
            install_id: wire.install_id,
            consumer_id: wire.consumer_id,
            state: wire.state,
            revision: wire.revision,
            product_relative_path: wire.product_relative_path,
            data_relative_path: wire.data_relative_path,
            data_schema_version: wire.data_schema_version,
            protected_key: wire.protected_key,
            runtime: wire.runtime,
            scheduled_task: wire.scheduled_task,
            created_at_us: wire.created_at_us,
            updated_at_us: wire.updated_at_us,
        };
        record.validate()?;
        Ok(record)
    }
}

impl<'de> Deserialize<'de> for InstallRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        InstallRecordWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl InstallRecord {
    /// Validates an untrusted persisted record before it is admitted to use.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when a required invariant is absent.
    pub fn validate(&self) -> Result<(), InstallRecordError> {
        if self.format_version != INSTALL_RECORD_FORMAT_VERSION {
            return Err(InstallRecordError::UnsupportedFormat);
        }
        if self.revision == 0 || self.created_at_us < 0 || self.updated_at_us < self.created_at_us {
            return Err(InstallRecordError::InvalidTimestampOrRevision);
        }
        validate_optional_version(self.data_schema_version)?;
        if let Some(artifact) = &self.runtime {
            validate_version(&artifact.version)?;
        }
        self.validate_evidence_paths()?;
        self.validate_evidence_order()?;
        if matches!(
            self.state,
            InstallState::Active
                | InstallState::Removing
                | InstallState::Retained
                | InstallState::Purging
        ) && !self.is_active_complete()
        {
            return Err(InstallRecordError::ActiveRecordIncomplete);
        }
        Ok(())
    }

    /// Validates the only record shape which may create an absent stable slot.
    ///
    /// Revision one durably binds the retained identities and their exact
    /// product directory before any key, runtime, data, or Scheduled Task
    /// evidence exists. This prevents callers from bypassing setup ordering by
    /// publishing a pre-completed or otherwise ambiguous first record.
    pub(crate) fn validate_initial(&self) -> Result<(), InstallRecordError> {
        self.validate()?;
        if self.state != InstallState::Installing
            || self.revision != 1
            || self.created_at_us != self.updated_at_us
            || self.product_relative_path.is_none()
            || self.data_relative_path.is_some()
            || self.data_schema_version.is_some()
            || self.protected_key.is_some()
            || self.runtime.is_some()
            || self.scheduled_task.is_some()
        {
            return Err(InstallRecordError::InvalidInitialRecord);
        }
        Ok(())
    }

    /// Proves that `next` is exactly one legal checkpoint or state transition.
    ///
    /// Persisting arbitrary individually-valid structs would otherwise let a
    /// caller bypass the frozen lifecycle (notably `ACTIVE -> INSTALLING`) or
    /// rewrite retained evidence. The store calls this while holding its CAS
    /// lock and compares the fully derived record byte-for-byte.
    pub(crate) fn validate_successor(&self, next: &Self) -> Result<(), InstallRecordError> {
        self.validate()?;
        next.validate()?;
        let derived = if self.state == next.state {
            self.checkpoint(
                self.revision,
                InstallCheckpoint {
                    product_relative_path: changed(
                        self.product_relative_path.as_ref(),
                        next.product_relative_path.as_ref(),
                    ),
                    data_relative_path: changed(
                        self.data_relative_path.as_ref(),
                        next.data_relative_path.as_ref(),
                    ),
                    data_schema_version: changed(
                        self.data_schema_version.as_ref(),
                        next.data_schema_version.as_ref(),
                    ),
                    protected_key: changed(
                        self.protected_key.as_ref(),
                        next.protected_key.as_ref(),
                    ),
                    runtime: changed(self.runtime.as_ref(), next.runtime.as_ref()),
                    scheduled_task: changed(
                        self.scheduled_task.as_ref(),
                        next.scheduled_task.as_ref(),
                    ),
                },
                next.updated_at_us,
            )?
        } else {
            self.transition(self.revision, next.state, next.updated_at_us)?
        };
        if derived != *next {
            return Err(InstallRecordError::EvidenceConflict);
        }
        Ok(())
    }

    /// Checks that installation evidence is exactly a prefix of the durable
    /// setup sequence.  This makes the first missing operation derivable after
    /// a crash instead of allowing individually-valid but ambiguous records.
    fn validate_evidence_order(&self) -> Result<(), InstallRecordError> {
        if self.product_relative_path.is_none()
            || self.data_relative_path.is_some() != self.data_schema_version.is_some()
            || (self.protected_key.is_none()
                && (self.runtime.is_some()
                    || self.data_relative_path.is_some()
                    || self.scheduled_task.is_some()))
            || (self.runtime.is_none()
                && (self.data_relative_path.is_some() || self.scheduled_task.is_some()))
            || (self.data_relative_path.is_none() && self.scheduled_task.is_some())
        {
            return Err(InstallRecordError::InvalidEvidenceOrder);
        }
        Ok(())
    }

    fn validate_evidence_paths(&self) -> Result<(), InstallRecordError> {
        let install_root = format!("installs\\{}", self.install_id.as_str());
        if self
            .product_relative_path
            .as_ref()
            .is_some_and(|path| path.as_str() != install_root)
        {
            return Err(InstallRecordError::EvidencePathMismatch);
        }
        if self
            .data_relative_path
            .as_ref()
            .is_some_and(|path| path.as_str() != format!("{install_root}\\data"))
        {
            return Err(InstallRecordError::EvidencePathMismatch);
        }
        if self.protected_key.as_ref().is_some_and(|artifact| {
            artifact.relative_path.as_str()
                != format!("{install_root}\\secrets\\endpoint-key.dpapi")
        }) {
            return Err(InstallRecordError::EvidencePathMismatch);
        }
        if self.runtime.as_ref().is_some_and(|artifact| {
            artifact.relative_path.as_str()
                != format!(
                    "{install_root}\\bin\\{}\\mesh-daemon.exe",
                    artifact.sha256.as_str()
                )
        }) {
            return Err(InstallRecordError::EvidencePathMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_active_complete(&self) -> bool {
        self.product_relative_path.is_some()
            && self.data_relative_path.is_some()
            && self.data_schema_version.is_some()
            && self.protected_key.is_some()
            && self.runtime.is_some()
            && self.scheduled_task.is_some()
    }

    /// Whether this complete record admits normal daemon/bridge traffic.
    #[must_use]
    pub fn admits_ordinary_traffic(&self) -> bool {
        self.state == InstallState::Active && self.validate().is_ok() && self.is_active_complete()
    }

    /// Applies an append-only installation checkpoint using compare-and-swap.
    ///
    /// # Errors
    ///
    /// Returns a stable error for stale, invalid, or time-regressing updates.
    pub fn checkpoint(
        &self,
        expected_revision: u64,
        checkpoint: InstallCheckpoint,
        updated_at_us: i64,
    ) -> Result<Self, InstallRecordError> {
        self.ensure_cas(expected_revision, updated_at_us)?;
        if self.state != InstallState::Installing {
            return Err(InstallRecordError::CheckpointRequiresInstalling);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(InstallRecordError::RevisionExhausted)?;

        let is_key_step = self.protected_key.is_none()
            && checkpoint.protected_key.is_some()
            && checkpoint.product_relative_path.is_none()
            && checkpoint.runtime.is_none()
            && checkpoint.data_relative_path.is_none()
            && checkpoint.data_schema_version.is_none()
            && checkpoint.scheduled_task.is_none();
        let is_runtime_step = self.protected_key.is_some()
            && self.runtime.is_none()
            && checkpoint.runtime.is_some()
            && checkpoint.product_relative_path.is_none()
            && checkpoint.protected_key.is_none()
            && checkpoint.data_relative_path.is_none()
            && checkpoint.data_schema_version.is_none()
            && checkpoint.scheduled_task.is_none();
        let is_data_step = self.runtime.is_some()
            && self.data_relative_path.is_none()
            && self.data_schema_version.is_none()
            && checkpoint.data_relative_path.is_some()
            && checkpoint.data_schema_version.is_some()
            && checkpoint.product_relative_path.is_none()
            && checkpoint.protected_key.is_none()
            && checkpoint.runtime.is_none()
            && checkpoint.scheduled_task.is_none();
        let is_task_step = self.data_relative_path.is_some()
            && self.data_schema_version.is_some()
            && self.scheduled_task.is_none()
            && checkpoint.scheduled_task.is_some()
            && checkpoint.product_relative_path.is_none()
            && checkpoint.protected_key.is_none()
            && checkpoint.runtime.is_none()
            && checkpoint.data_relative_path.is_none()
            && checkpoint.data_schema_version.is_none();
        if !(is_key_step || is_runtime_step || is_data_step || is_task_step) {
            return Err(InstallRecordError::InvalidCheckpointStep);
        }

        let mut next = self.clone();
        if is_key_step {
            next.protected_key = checkpoint.protected_key;
        } else if is_runtime_step {
            next.runtime = checkpoint.runtime;
        } else if is_data_step {
            next.data_relative_path = checkpoint.data_relative_path;
            next.data_schema_version = checkpoint.data_schema_version;
        } else {
            next.scheduled_task = checkpoint.scheduled_task;
        }
        next.revision = next_revision;
        next.updated_at_us = updated_at_us;
        next.validate()?;
        Ok(next)
    }

    /// Performs a pure, deterministic state transition. Evidence is never removed.
    ///
    /// # Errors
    ///
    /// Returns a stable error for stale, illegal, incomplete, or time-regressing
    /// updates.
    pub fn transition(
        &self,
        expected_revision: u64,
        next_state: InstallState,
        updated_at_us: i64,
    ) -> Result<Self, InstallRecordError> {
        self.ensure_cas(expected_revision, updated_at_us)?;
        if !is_legal_transition(self.state, next_state) {
            return Err(InstallRecordError::IllegalTransition);
        }
        let mut next = self.clone();
        next.state = next_state;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(InstallRecordError::RevisionExhausted)?;
        next.updated_at_us = updated_at_us;
        next.validate()?;
        Ok(next)
    }

    fn ensure_cas(
        &self,
        expected_revision: u64,
        updated_at_us: i64,
    ) -> Result<(), InstallRecordError> {
        self.validate()?;
        if self.revision != expected_revision {
            return Err(InstallRecordError::StaleRevision);
        }
        if updated_at_us < self.updated_at_us {
            return Err(InstallRecordError::TimestampRegressed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstallCheckpoint {
    pub product_relative_path: Option<RelativeWindowsPath>,
    pub data_relative_path: Option<RelativeWindowsPath>,
    pub data_schema_version: Option<u32>,
    pub protected_key: Option<ProtectedKeyArtifact>,
    pub runtime: Option<RuntimeArtifact>,
    pub scheduled_task: Option<ScheduledTaskEvidence>,
}

/// Minimal future durable-store boundary. Implementations must make the CAS atomic.
pub trait InstallRecordStore {
    type Error;
    /// Reads the currently retained record.
    ///
    /// # Errors
    ///
    /// Returns the durable store's stable error without exposing record secrets.
    fn load(&self) -> Result<Option<InstallRecord>, Self::Error>;
    /// Atomically stores `next` only when `expected_revision` is current.
    ///
    /// `expected_revision == 0` means expected absence and is reserved for the
    /// first write, whose record revision must be one.
    ///
    /// # Errors
    ///
    /// Returns the durable store's stable error on storage or CAS failure.
    fn compare_and_swap(
        &self,
        expected_revision: u64,
        next: &InstallRecord,
    ) -> Result<(), Self::Error>;
}

/// Clock boundary for the future durable record owner.
pub trait InstallRecordClock {
    fn now_us(&self) -> i64;
}

/// Identity source boundary; implementations must return a validated fresh ID.
pub trait InstallIdSource {
    type Error;
    /// Produces a fresh validated installation identity.
    ///
    /// # Errors
    ///
    /// Returns the source's stable generation error.
    fn next_install_id(&self) -> Result<StableId, Self::Error>;
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InstallRecordError {
    #[error("install record identity must be lower-case hex32")]
    InvalidIdentity,
    #[error("install record digest must be lower-case sha256 hex64")]
    InvalidDigest,
    #[error("install record path must be a normalized relative Windows path")]
    InvalidRelativePath,
    #[error("install record format is unsupported")]
    UnsupportedFormat,
    #[error("install record revision or timestamp is invalid")]
    InvalidTimestampOrRevision,
    #[error("first install record does not match the frozen setup boundary")]
    InvalidInitialRecord,
    #[error("install record revision space is exhausted")]
    RevisionExhausted,
    #[error("install record version is invalid")]
    InvalidVersion,
    #[error("active install record is incomplete")]
    ActiveRecordIncomplete,
    #[error("install record revision is stale")]
    StaleRevision,
    #[error("install record timestamp regressed")]
    TimestampRegressed,
    #[error("install record state transition is illegal")]
    IllegalTransition,
    #[error("installation checkpoint requires INSTALLING state")]
    CheckpointRequiresInstalling,
    #[error("installation evidence is not a prefix of the setup sequence")]
    InvalidEvidenceOrder,
    #[error("installation checkpoint must publish exactly the next setup step")]
    InvalidCheckpointStep,
    #[error("installation evidence conflicts with retained evidence")]
    EvidenceConflict,
    #[error("installation evidence path is not bound to this install identity")]
    EvidencePathMismatch,
    #[error("scheduled task path is invalid")]
    InvalidScheduledTaskPath,
}

fn validate_version(version: &str) -> Result<(), InstallRecordError> {
    if version.is_empty() || version.len() > MAX_VERSION_LEN || version.contains('\0') {
        return Err(InstallRecordError::InvalidVersion);
    }
    Ok(())
}

fn validate_optional_version(version: Option<u32>) -> Result<(), InstallRecordError> {
    if version == Some(0) {
        return Err(InstallRecordError::InvalidVersion);
    }
    Ok(())
}

const fn is_legal_transition(current: InstallState, next: InstallState) -> bool {
    matches!(
        (current, next),
        (
            InstallState::Installing,
            InstallState::Active | InstallState::Broken
        ) | (InstallState::Active, InstallState::Removing)
            | (
                InstallState::Removing,
                InstallState::Retained | InstallState::Broken
            )
            | (
                InstallState::Retained,
                InstallState::Installing | InstallState::Purging
            )
    )
}

fn changed<T: Clone + Eq>(current: Option<&T>, next: Option<&T>) -> Option<T> {
    (current != next).then(|| next.cloned()).flatten()
}

fn is_safe_windows_component(component: &str) -> bool {
    if component.is_empty()
        || component.encode_utf16().count() > MAX_WINDOWS_COMPONENT_UTF16_LEN
        || component == "."
        || component == ".."
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character <= '\u{001f}' || matches!(character, '<' | '>' | '"' | ':' | '|' | '?' | '*')
        })
    {
        return false;
    }
    let basename = component
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if matches!(
        basename.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) {
        return false;
    }
    let mut characters = basename.chars();
    let prefix: String = characters.by_ref().take(3).collect();
    let number = characters.next();
    let no_suffix = characters.next().is_none();
    !(no_suffix
        && matches!(prefix.as_str(), "COM" | "LPT")
        && matches!(
            number,
            Some('1'..='9' | '\u{00b9}' | '\u{00b2}' | '\u{00b3}')
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const CONSUMER: &str = "fedcba9876543210fedcba9876543210";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn path(value: &str) -> RelativeWindowsPath {
        RelativeWindowsPath::new(value).unwrap()
    }
    fn digest() -> Sha256Digest {
        Sha256Digest::new(DIGEST).unwrap()
    }
    fn partial() -> InstallRecord {
        InstallRecord {
            format_version: 1,
            install_id: StableId::new(ID).unwrap(),
            consumer_id: StableId::new(CONSUMER).unwrap(),
            state: InstallState::Installing,
            revision: 1,
            product_relative_path: Some(path(&format!("installs\\{ID}"))),
            data_relative_path: None,
            data_schema_version: None,
            protected_key: None,
            runtime: None,
            scheduled_task: None,
            created_at_us: 10,
            updated_at_us: 10,
        }
    }
    fn key_checkpoint() -> InstallCheckpoint {
        InstallCheckpoint {
            protected_key: Some(ProtectedKeyArtifact {
                relative_path: path(&format!("installs\\{ID}\\secrets\\endpoint-key.dpapi")),
                sha256: digest(),
            }),
            ..InstallCheckpoint::default()
        }
    }
    fn runtime_checkpoint() -> InstallCheckpoint {
        InstallCheckpoint {
            runtime: Some(RuntimeArtifact {
                relative_path: path(&format!("installs\\{ID}\\bin\\{DIGEST}\\mesh-daemon.exe")),
                sha256: digest(),
                version: "0.1.0".into(),
                signer_status: SignerStatus::UnsignedDevelopment,
                artifact_format: RuntimeArtifactFormat::MeshDaemonExeV1,
            }),
            ..InstallCheckpoint::default()
        }
    }
    fn data_checkpoint() -> InstallCheckpoint {
        InstallCheckpoint {
            data_relative_path: Some(path(&format!("installs\\{ID}\\data"))),
            data_schema_version: Some(1),
            ..InstallCheckpoint::default()
        }
    }
    fn task_checkpoint() -> InstallCheckpoint {
        InstallCheckpoint {
            scheduled_task: Some(ScheduledTaskEvidence {
                task_path: ScheduledTaskPath::new("\\CodexAgentMesh-daemon-01234567").unwrap(),
                definition_sha256: digest(),
            }),
            ..InstallCheckpoint::default()
        }
    }
    fn complete_installing() -> InstallRecord {
        partial()
            .checkpoint(1, key_checkpoint(), 11)
            .unwrap()
            .checkpoint(2, runtime_checkpoint(), 12)
            .unwrap()
            .checkpoint(3, data_checkpoint(), 13)
            .unwrap()
            .checkpoint(4, task_checkpoint(), 14)
            .unwrap()
    }
    fn active_record() -> InstallRecord {
        complete_installing()
            .transition(5, InstallState::Active, 15)
            .unwrap()
    }

    #[test]
    fn strict_deserialization_and_round_trip_are_fixture_stable() {
        let active = active_record();
        let json = serde_json::to_string(&active).unwrap();
        let serialized = serde_json::from_str::<serde_json::Value>(&json).unwrap();
        let protected_key = serialized["protected_key"].as_object().unwrap();
        let expected_key_path = format!("installs\\{ID}\\secrets\\endpoint-key.dpapi");
        assert_eq!(protected_key.len(), 2);
        assert_eq!(
            protected_key
                .get("relative_path")
                .and_then(serde_json::Value::as_str),
            Some(expected_key_path.as_str())
        );
        assert_eq!(
            protected_key
                .get("sha256")
                .and_then(serde_json::Value::as_str),
            Some(DIGEST)
        );
        assert!(!protected_key.contains_key("key_bytes"));
        assert!(!protected_key.contains_key("plaintext"));
        assert_eq!(
            serde_json::from_str::<InstallRecord>(&json).unwrap(),
            active
        );
        assert!(
            serde_json::from_str::<InstallRecord>(
                &json.replace("\"revision\":6", "\"revision\":6,\"extra\":true")
            )
            .is_err()
        );
    }

    #[test]
    fn ids_digests_and_paths_are_strictly_bounded() {
        assert!(StableId::new("A123456789abcdef0123456789abcdef").is_err());
        assert!(Sha256Digest::new("a").is_err());
        for bad in [
            "",
            "\\root",
            "C:\\root",
            "a/b",
            "a\\..\\b",
            "a\\\\b",
            "a:stream",
            "a<name",
            "a>name",
            "a\"name",
            "a|name",
            "a?name",
            "a*name",
            "a\u{0001}name",
            "\\\\server\\share",
            "dir\\name. ",
            "dir\\CON.txt",
            "dir\\CONIN$",
            "dir\\conout$.log",
            "dir\\CON .txt",
            "dir\\COM¹.txt",
            "AUX",
            "lpt9.log",
        ] {
            assert!(RelativeWindowsPath::new(bad).is_err(), "{bad}");
        }
        assert!(RelativeWindowsPath::new("a\\b").is_ok());
        assert!(RelativeWindowsPath::new("a".repeat(MAX_WINDOWS_COMPONENT_UTF16_LEN)).is_ok());
        assert!(RelativeWindowsPath::new("a".repeat(MAX_WINDOWS_COMPONENT_UTF16_LEN + 1)).is_err());
        assert!(RelativeWindowsPath::new("😀".repeat(127)).is_ok());
        assert!(RelativeWindowsPath::new("😀".repeat(128)).is_err());
        assert!(ScheduledTaskPath::new("\\CodexAgentMesh-daemon-01234567").is_ok());
        assert!(ScheduledTaskPath::new(format!("\\{}", "a".repeat(255))).is_ok());
        assert!(ScheduledTaskPath::new(format!("\\{}", "a".repeat(256))).is_err());
        for bad in [
            "Codex",
            "\\\\Codex",
            "\\",
            "\\Codex\\",
            "\\CON",
            "\\Codex/Task",
            "\\Codex\\Task. ",
            "\\Codex\\a?name",
            "\\Codex\\a\u{0002}name",
        ] {
            assert!(ScheduledTaskPath::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn active_requires_every_usable_artifact() {
        assert_eq!(
            partial().transition(1, InstallState::Active, 11),
            Err(InstallRecordError::ActiveRecordIncomplete)
        );
    }

    #[test]
    fn deserialization_rejects_incomplete_active_and_invalid_record_invariants() {
        let mut active = partial();
        active.state = InstallState::Active;
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&active).unwrap())
                .is_err()
        );
        let mut invalid = partial();
        invalid.revision = 0;
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&invalid).unwrap())
                .is_err()
        );
        invalid = partial();
        invalid.updated_at_us = 9;
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&invalid).unwrap())
                .is_err()
        );
        let valid = active_record();
        let invalid_version = serde_json::to_string(&valid)
            .unwrap()
            .replace("\"version\":\"0.1.0\"", "\"version\":\"\"");
        assert!(serde_json::from_str::<InstallRecord>(&invalid_version).is_err());

        let mut retained = partial();
        retained.state = InstallState::Retained;
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&retained).unwrap())
                .is_err()
        );
    }

    #[test]
    fn serde_rejects_evidence_paths_bound_to_another_install() {
        let active = active_record();
        let foreign_root = format!("installs\\{CONSUMER}");

        let mut wrong_product = active.clone();
        wrong_product.product_relative_path = Some(path(&foreign_root));
        assert_eq!(
            wrong_product.validate(),
            Err(InstallRecordError::EvidencePathMismatch)
        );
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&wrong_product).unwrap())
                .is_err()
        );

        let mut wrong_data = active.clone();
        wrong_data.data_relative_path = Some(path(&format!("{foreign_root}\\data")));
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&wrong_data).unwrap())
                .is_err()
        );

        let mut wrong_key = active.clone();
        wrong_key.protected_key.as_mut().unwrap().relative_path =
            path(&format!("{foreign_root}\\secrets\\endpoint-key.dpapi"));
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&wrong_key).unwrap())
                .is_err()
        );

        let mut wrong_runtime = active;
        wrong_runtime.runtime.as_mut().unwrap().relative_path =
            path(&format!("{foreign_root}\\bin\\{DIGEST}\\mesh-daemon.exe"));
        assert!(
            serde_json::from_str::<InstallRecord>(&serde_json::to_string(&wrong_runtime).unwrap())
                .is_err()
        );
    }

    #[test]
    fn transitions_cas_and_timestamps_are_fenced() {
        let active = active_record();
        assert_eq!(
            active.transition(5, InstallState::Removing, 16),
            Err(InstallRecordError::StaleRevision)
        );
        assert_eq!(
            active.transition(6, InstallState::Removing, 14),
            Err(InstallRecordError::TimestampRegressed)
        );
        assert_eq!(
            active.transition(6, InstallState::Installing, 16),
            Err(InstallRecordError::IllegalTransition)
        );
        let removing = active.transition(6, InstallState::Removing, 16).unwrap();
        assert_eq!(removing.state, InstallState::Removing);
        assert_eq!(
            removing.transition(7, InstallState::Active, 17),
            Err(InstallRecordError::IllegalTransition)
        );
    }

    #[test]
    fn initial_and_successor_validation_cannot_bypass_the_lifecycle() {
        let initial = partial();
        initial.validate_initial().unwrap();

        let mut missing_product = initial.clone();
        missing_product.product_relative_path = None;
        assert_eq!(
            missing_product.validate_initial(),
            Err(InstallRecordError::InvalidEvidenceOrder)
        );

        let installing = complete_installing();
        let first_checkpoint = initial.checkpoint(1, key_checkpoint(), 11).unwrap();
        initial.validate_successor(&first_checkpoint).unwrap();
        let second_checkpoint = first_checkpoint
            .checkpoint(2, runtime_checkpoint(), 12)
            .unwrap();
        first_checkpoint
            .validate_successor(&second_checkpoint)
            .unwrap();
        let third_checkpoint = second_checkpoint
            .checkpoint(3, data_checkpoint(), 13)
            .unwrap();
        second_checkpoint
            .validate_successor(&third_checkpoint)
            .unwrap();
        third_checkpoint.validate_successor(&installing).unwrap();
        let active = installing.transition(5, InstallState::Active, 15).unwrap();
        installing.validate_successor(&active).unwrap();

        let mut hot_upgrade = active.clone();
        hot_upgrade.state = InstallState::Installing;
        hot_upgrade.revision += 1;
        hot_upgrade.updated_at_us += 1;
        assert_eq!(
            active.validate_successor(&hot_upgrade),
            Err(InstallRecordError::IllegalTransition)
        );
    }

    #[test]
    fn revision_exhaustion_fails_closed() {
        let mut exhausted = partial();
        exhausted.revision = u64::MAX;
        assert_eq!(
            exhausted.checkpoint(u64::MAX, InstallCheckpoint::default(), 11),
            Err(InstallRecordError::RevisionExhausted)
        );
        assert_eq!(
            exhausted.transition(u64::MAX, InstallState::Active, 11),
            Err(InstallRecordError::RevisionExhausted)
        );
    }

    #[test]
    fn removing_is_an_admission_fence_and_identity_evidence_survive() {
        let active = active_record();
        let removing = active.transition(6, InstallState::Removing, 16).unwrap();
        let retained = removing.transition(7, InstallState::Retained, 17).unwrap();
        assert_eq!(retained.install_id, active.install_id);
        assert_eq!(retained.consumer_id, active.consumer_id);
        assert_eq!(retained.runtime, active.runtime);
        assert_eq!(retained.scheduled_task, active.scheduled_task);
        assert!(!removing.admits_ordinary_traffic());
        assert!(!retained.admits_ordinary_traffic());
        assert!(active.admits_ordinary_traffic());
    }

    #[test]
    fn retained_reinstall_preserves_the_one_runtime_identity() {
        let active = active_record();
        let retained = active
            .transition(6, InstallState::Removing, 16)
            .unwrap()
            .transition(7, InstallState::Retained, 17)
            .unwrap();
        let installing = retained
            .transition(8, InstallState::Installing, 18)
            .unwrap();
        let reactivated = installing.transition(9, InstallState::Active, 19).unwrap();
        assert_eq!(reactivated.runtime, active.runtime);

        let mut changed_runtime = runtime_checkpoint();
        changed_runtime.runtime.as_mut().unwrap().sha256 =
            Sha256Digest::new("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
                .unwrap();
        assert_eq!(
            installing.checkpoint(9, changed_runtime, 19),
            Err(InstallRecordError::InvalidCheckpointStep)
        );
    }

    #[test]
    fn purging_is_complete_terminal_record_state() {
        let active = active_record();
        let retained = active
            .transition(6, InstallState::Removing, 16)
            .expect("remove fixture")
            .transition(7, InstallState::Retained, 17)
            .expect("retain fixture");
        let purging = retained
            .transition(8, InstallState::Purging, 18)
            .expect("the sole purge transition");

        assert!(
            serde_json::to_string(&purging)
                .unwrap()
                .contains("\"PURGING\"")
        );
        assert!(purging.is_active_complete());
        assert!(!purging.admits_ordinary_traffic());
        assert_eq!(
            purging.transition(9, InstallState::Installing, 19),
            Err(InstallRecordError::IllegalTransition)
        );
        assert_eq!(
            purging.transition(9, InstallState::Retained, 19),
            Err(InstallRecordError::IllegalTransition)
        );
        assert_eq!(
            purging.checkpoint(9, InstallCheckpoint::default(), 19),
            Err(InstallRecordError::CheckpointRequiresInstalling)
        );
        assert_eq!(
            active.transition(6, InstallState::Purging, 16),
            Err(InstallRecordError::IllegalTransition)
        );
    }

    #[test]
    fn serialized_installing_checkpoints_converge_after_restart() {
        let mut record = partial();
        for checkpoint in [
            key_checkpoint(),
            runtime_checkpoint(),
            data_checkpoint(),
            task_checkpoint(),
        ] {
            record = record
                .checkpoint(record.revision, checkpoint, record.updated_at_us + 1)
                .unwrap();
            record = serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
            record.validate().unwrap();
        }
        assert!(
            record
                .transition(
                    record.revision,
                    InstallState::Active,
                    record.updated_at_us + 1
                )
                .is_ok()
        );
    }

    #[test]
    fn checkpoint_and_successor_reject_skips_and_multi_step_publications() {
        let initial = partial();
        let mut key_and_runtime = key_checkpoint();
        key_and_runtime.runtime = runtime_checkpoint().runtime;
        assert_eq!(
            initial.checkpoint(1, key_and_runtime, 11),
            Err(InstallRecordError::InvalidCheckpointStep)
        );
        assert_eq!(
            initial.checkpoint(1, runtime_checkpoint(), 11),
            Err(InstallRecordError::InvalidCheckpointStep)
        );

        let key = initial.checkpoint(1, key_checkpoint(), 11).unwrap();
        let mut skipped_runtime = key.clone();
        skipped_runtime.data_relative_path = data_checkpoint().data_relative_path;
        skipped_runtime.data_schema_version = Some(1);
        skipped_runtime.revision = 3;
        skipped_runtime.updated_at_us = 12;
        assert_eq!(
            skipped_runtime.validate(),
            Err(InstallRecordError::InvalidEvidenceOrder)
        );
        assert_eq!(
            key.validate_successor(&skipped_runtime),
            Err(InstallRecordError::InvalidEvidenceOrder)
        );

        let runtime = key.checkpoint(2, runtime_checkpoint(), 12).unwrap();
        let mut data_and_task = runtime.clone();
        data_and_task.data_relative_path = data_checkpoint().data_relative_path;
        data_and_task.data_schema_version = Some(1);
        data_and_task.scheduled_task = task_checkpoint().scheduled_task;
        data_and_task.revision = 4;
        data_and_task.updated_at_us = 13;
        data_and_task.validate().unwrap();
        assert_eq!(
            runtime.validate_successor(&data_and_task),
            Err(InstallRecordError::InvalidCheckpointStep)
        );
    }

    #[test]
    fn checkpoints_are_installing_only_and_cannot_drift_retained_locations() {
        let installing = partial();
        assert_eq!(
            installing.checkpoint(
                1,
                InstallCheckpoint {
                    product_relative_path: Some(path("other-product")),
                    ..InstallCheckpoint::default()
                },
                11
            ),
            Err(InstallRecordError::InvalidCheckpointStep)
        );
        let key = installing.checkpoint(1, key_checkpoint(), 11).unwrap();
        assert_eq!(
            key.checkpoint(
                2,
                InstallCheckpoint {
                    protected_key: key.protected_key.clone(),
                    runtime: runtime_checkpoint().runtime,
                    ..InstallCheckpoint::default()
                },
                12
            ),
            Err(InstallRecordError::InvalidCheckpointStep)
        );
        let runtime = key.checkpoint(2, runtime_checkpoint(), 12).unwrap();
        assert_eq!(
            runtime.checkpoint(
                3,
                InstallCheckpoint {
                    data_relative_path: Some(path(&format!("installs\\{ID}\\data"))),
                    ..InstallCheckpoint::default()
                },
                13,
            ),
            Err(InstallRecordError::InvalidCheckpointStep)
        );
        let data = runtime.checkpoint(3, data_checkpoint(), 13).unwrap();
        let installing_complete = data.checkpoint(4, task_checkpoint(), 14).unwrap();
        let active = installing_complete
            .transition(5, InstallState::Active, 15)
            .unwrap();
        assert_eq!(
            active.checkpoint(6, InstallCheckpoint::default(), 16),
            Err(InstallRecordError::CheckpointRequiresInstalling)
        );
        assert_eq!(
            active.transition(6, InstallState::Installing, 16),
            Err(InstallRecordError::IllegalTransition)
        );
    }

    #[test]
    fn only_installing_and_removing_can_fail_into_broken() {
        let installing = partial();
        assert_eq!(
            installing
                .transition(1, InstallState::Broken, 11)
                .unwrap()
                .state,
            InstallState::Broken
        );
        let active = active_record();
        assert_eq!(
            active.transition(6, InstallState::Broken, 16),
            Err(InstallRecordError::IllegalTransition)
        );
        let removing = active.transition(6, InstallState::Removing, 16).unwrap();
        assert_eq!(
            removing
                .transition(7, InstallState::Broken, 17)
                .unwrap()
                .state,
            InstallState::Broken
        );
        let broken = installing.transition(1, InstallState::Broken, 11).unwrap();
        assert_eq!(
            broken.transition(2, InstallState::Installing, 12),
            Err(InstallRecordError::IllegalTransition)
        );
    }
}
