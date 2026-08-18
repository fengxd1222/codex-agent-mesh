//! Opt-in live adapter contract evidence.
//!
//! A live contract record is machine-local evidence that one specific
//! executable digest/version completed the opt-in live checks on this
//! machine. Records are never committed to the repository and never part
//! of offline CI; a PASS only lifts an otherwise fixture-proven admission
//! from DEGRADED to ENABLED when the digest, version, and fixture bundle
//! all still match. Any mismatch — including a binary that changed after
//! the record was written — keeps the admission degraded.

use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::adapters::{AdapterError, sanitize_raw};
use crate::protocol_strict_json::parse_strict_json;

/// Checks every adapter must pass before a record admits anything.
pub const CORE_CHECKS: &[&str] = &["handshake", "stream_updates", "terminal"];

/// The full check vocabulary a record may carry.
const ALLOWED_CHECKS: &[&str] = &["handshake", "stream_updates", "terminal", "cancel"];

const ALLOWED_ADAPTERS: &[&str] = &["claude", "grok", "kimi"];
const ALLOWED_TRANSPORTS: &[&str] = &["acp", "stream_json"];
const MAX_REASON_CHARS: usize = 4096;

/// One recorded live contract run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveContractRecord {
    pub adapter: String,
    pub executable_digest: String,
    pub executable_version: String,
    pub transport: String,
    pub fixture_bundle_id: String,
    pub checks: Vec<String>,
    pub outcome: String,
    pub reason: String,
    pub checked_at_us: i64,
}

impl LiveContractRecord {
    /// Strict, sanitized JSON body for the evidence file.
    pub fn encode(&self) -> Result<Vec<u8>, AdapterError> {
        validate(self)?;
        let value = serde_json::json!({
            "version": 1,
            "kind": "live_contract_record",
            "adapter": self.adapter,
            "executable_digest": self.executable_digest,
            "executable_version": self.executable_version,
            "transport": self.transport,
            "fixture_bundle_id": self.fixture_bundle_id,
            "checks": self.checks,
            "outcome": self.outcome,
            "reason": self.reason,
            "checked_at_us": self.checked_at_us,
        });
        let mut bytes = serde_json::to_vec(&value).map_err(|_| AdapterError::ProtocolMalformed)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Decodes and validates one evidence file body.
    pub fn decode(bytes: &[u8]) -> Result<Self, AdapterError> {
        let text = std::str::from_utf8(bytes).map_err(|_| AdapterError::ProtocolMalformed)?;
        let trimmed = text.trim_end();
        let value = parse_strict_json(trimmed).map_err(|_| AdapterError::ProtocolMalformed)?;
        let record = Self {
            adapter: string_field(&value, "adapter")?,
            executable_digest: string_field(&value, "executable_digest")?,
            executable_version: string_field(&value, "executable_version")?,
            transport: string_field(&value, "transport")?,
            fixture_bundle_id: string_field(&value, "fixture_bundle_id")?,
            checks: value
                .get("checks")
                .and_then(Value::as_array)
                .ok_or(AdapterError::ProtocolMalformed)?
                .iter()
                .map(|check| check.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or(AdapterError::ProtocolMalformed)?,
            outcome: string_field(&value, "outcome")?,
            reason: string_field(&value, "reason")?,
            checked_at_us: value
                .get("checked_at_us")
                .and_then(Value::as_i64)
                .ok_or(AdapterError::ProtocolMalformed)?,
        };
        validate(&record)?;
        Ok(record)
    }
}

/// Whether a record is a passing contract for exactly this executable,
/// version, and fixture bundle. Everything else stays degraded.
#[must_use]
pub fn record_admits(
    record: &LiveContractRecord,
    adapter: &str,
    executable_digest: &str,
    executable_version: &str,
    fixture_bundle_id: &str,
) -> bool {
    record.adapter == adapter
        && record.executable_digest == executable_digest
        && record.executable_version == executable_version
        && record.fixture_bundle_id == fixture_bundle_id
        && record.outcome == "PASS"
        && CORE_CHECKS
            .iter()
            .all(|check| record.checks.iter().any(|recorded| recorded == check))
}

/// Evidence file path for one adapter under an evidence directory.
#[must_use]
pub fn evidence_path(dir: &Path, adapter: &str) -> PathBuf {
    dir.join(format!("{adapter}.json"))
}

/// Loads and validates the record file, then applies [`record_admits`].
/// Missing, unreadable, or invalid evidence never admits.
#[must_use]
pub fn load_admitting(
    dir: &Path,
    adapter: &str,
    executable_digest: &str,
    executable_version: &str,
    fixture_bundle_id: &str,
) -> bool {
    let Ok(bytes) = std::fs::read(evidence_path(dir, adapter)) else {
        return false;
    };
    LiveContractRecord::decode(&bytes).is_ok_and(|record| {
        record_admits(
            &record,
            adapter,
            executable_digest,
            executable_version,
            fixture_bundle_id,
        )
    })
}

/// Sanitized bounded reason text from any captured failure detail.
#[must_use]
pub fn sanitize_reason(reason: &str) -> String {
    let (sanitized, _) = sanitize_raw(&Value::from(reason.to_owned()));
    sanitized
        .as_str()
        .unwrap_or_default()
        .chars()
        .take(MAX_REASON_CHARS)
        .collect()
}

/// Evidence digest binding one record to its content.
#[must_use]
pub fn record_digest(record: &LiveContractRecord) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}:{}:{}:{}",
                record.adapter, record.executable_digest, record.outcome, record.checked_at_us
            )
            .as_bytes()
        )
    )
}

/// In-flight result of one live contract run. Test-only: the persisted
/// artifact is always the validated [`LiveContractRecord`].
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct LiveRun {
    pub checks: Vec<&'static str>,
    pub failure: Option<String>,
    pub executable_version: String,
    pub executable_digest: String,
}

#[cfg(test)]
impl LiveRun {
    pub(crate) fn new(executable_digest: String, executable_version: String) -> Self {
        Self {
            checks: Vec::new(),
            failure: None,
            executable_version,
            executable_digest,
        }
    }

    pub(crate) fn failing(reason: String) -> Self {
        Self {
            checks: Vec::new(),
            failure: Some(reason),
            executable_version: "unproven".into(),
            executable_digest: "0".repeat(64),
        }
    }
}

fn validate(record: &LiveContractRecord) -> Result<(), AdapterError> {
    if !ALLOWED_ADAPTERS.contains(&record.adapter.as_str()) {
        return Err(AdapterError::ProtocolMalformed);
    }
    if !is_hex64(&record.executable_digest) {
        return Err(AdapterError::ProtocolMalformed);
    }
    if record.executable_version.is_empty()
        || record.executable_version.len() > 32
        || !record
            .executable_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(AdapterError::ProtocolMalformed);
    }
    if !ALLOWED_TRANSPORTS.contains(&record.transport.as_str()) {
        return Err(AdapterError::ProtocolMalformed);
    }
    if record.fixture_bundle_id.is_empty() || record.fixture_bundle_id.len() > 128 {
        return Err(AdapterError::ProtocolMalformed);
    }
    let mut unique_checks = record.checks.clone();
    unique_checks.sort();
    unique_checks.dedup();
    if unique_checks.len() != record.checks.len()
        || record
            .checks
            .iter()
            .any(|check| !ALLOWED_CHECKS.contains(&check.as_str()))
        || (record.outcome == "PASS" && record.checks.is_empty())
    {
        return Err(AdapterError::ProtocolMalformed);
    }
    if !matches!(record.outcome.as_str(), "PASS" | "FAIL") {
        return Err(AdapterError::ProtocolMalformed);
    }
    if record.reason.chars().count() > MAX_REASON_CHARS {
        return Err(AdapterError::ProtocolMalformed);
    }
    if record.checked_at_us <= 0 {
        return Err(AdapterError::ProtocolMalformed);
    }
    if record.outcome == "PASS" && !record.reason.is_empty() {
        return Err(AdapterError::ProtocolMalformed);
    }
    Ok(())
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn string_field(value: &Value, field: &str) -> Result<String, AdapterError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(AdapterError::ProtocolMalformed)
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::*;

    fn passing_record() -> LiveContractRecord {
        LiveContractRecord {
            adapter: "grok".into(),
            executable_digest: "a".repeat(64),
            executable_version: "1.0.4".into(),
            transport: "acp".into(),
            fixture_bundle_id: "grok-acp-1.0.4-v1".into(),
            checks: CORE_CHECKS.iter().map(|check| (*check).into()).collect(),
            outcome: "PASS".into(),
            reason: String::new(),
            checked_at_us: 1_000,
        }
    }

    #[test]
    fn live_contract_record_round_trips_strictly() {
        let record = passing_record();
        let bytes = record.encode().expect("encode");
        assert_eq!(*bytes.last().expect("newline"), b'\n');
        let decoded = LiveContractRecord::decode(&bytes).expect("decode");
        assert_eq!(decoded, record);
    }

    #[test]
    fn live_contract_record_rejects_drifted_shapes() {
        let mut record = passing_record();
        record.executable_digest = "nothex".into();
        assert_eq!(record.encode().err(), Some(AdapterError::ProtocolMalformed));
        let mut unknown_check = passing_record();
        unknown_check.checks.push("exfiltrate".into());
        assert!(unknown_check.encode().is_err());
        let mut pass_with_reason = passing_record();
        pass_with_reason.reason = "still failing".into();
        assert!(pass_with_reason.encode().is_err());
        let mut bad_outcome = passing_record();
        bad_outcome.outcome = "MAYBE".into();
        assert!(bad_outcome.encode().is_err());
        assert!(LiveContractRecord::decode(b"{ not json").is_err());
    }

    #[test]
    fn live_contract_admission_requires_exact_identity_and_core_checks() {
        let record = passing_record();
        let digest = "a".repeat(64);
        assert!(record_admits(
            &record,
            "grok",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
        // Binary changed, version drifted, wrong adapter/bundle: never admit.
        let other = "b".repeat(64);
        assert!(!record_admits(
            &record,
            "grok",
            &other,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
        assert!(!record_admits(
            &record,
            "grok",
            &digest,
            "1.0.5",
            "grok-acp-1.0.4-v1"
        ));
        assert!(!record_admits(
            &record,
            "kimi",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
        assert!(!record_admits(
            &record,
            "grok",
            &digest,
            "1.0.4",
            "grok-acp-9.9.9-v1"
        ));
        let mut failed = passing_record();
        failed.outcome = "FAIL".into();
        failed.reason = "initialize result missing".into();
        assert!(!record_admits(
            &failed,
            "grok",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
        let mut partial = passing_record();
        partial.checks.retain(|check| check != "terminal");
        assert!(!record_admits(
            &partial,
            "grok",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
    }

    #[test]
    fn live_contract_load_admitting_handles_missing_and_invalid_files() {
        let root = tempfile::tempdir().expect("tempdir");
        let digest = "a".repeat(64);
        assert!(!load_admitting(
            root.path(),
            "grok",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
        let record = passing_record();
        std::fs::write(
            evidence_path(root.path(), "grok"),
            record.encode().expect("encode"),
        )
        .expect("write evidence");
        assert!(load_admitting(
            root.path(),
            "grok",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
        assert!(!load_admitting(
            root.path(),
            "kimi",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
        std::fs::write(evidence_path(root.path(), "grok"), b"garbage").expect("corrupt");
        assert!(!load_admitting(
            root.path(),
            "grok",
            &digest,
            "1.0.4",
            "grok-acp-1.0.4-v1"
        ));
    }

    #[test]
    fn live_contract_reason_is_sanitized_and_bounded() {
        let reason = sanitize_reason("C:\\Users\\someone\\repo exploded");
        assert_eq!(reason, "[redacted]");
        let long = sanitize_reason(&"x".repeat(10_000));
        assert!(long.chars().count() <= MAX_REASON_CHARS);
        assert!(record_digest(&passing_record()).len() == 64);
    }
}
