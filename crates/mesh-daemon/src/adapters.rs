//! Provider adapter boundary: admission, quality/effort, and event normalize.
//!
//! Shared task, retry, and scheduler semantics stay in their existing modules.
//! A provider process is launched only through [`crate::supervisor`].

#![allow(clippy::missing_errors_doc)]

pub mod acp;
pub mod claude;
pub mod grok;
pub mod kimi;
pub mod live_contract;
pub mod registry;

#[cfg(all(test, windows))]
pub(crate) mod live_contract_tests;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::TaskState;
use crate::protocol_strict_json::parse_strict_json;
use crate::{EffectClass, ErrorCode, LifecycleEvidence, RetryClass, classify_retry, decode_v1};

/// Committed Claude stream-json fixture bundle for this release.
pub const CLAUDE_FIXTURE_BUNDLE_ID: &str = "claude-stream-json-2.1.220-v1";

/// Committed Grok ACP fixture bundle for this release.
pub const GROK_FIXTURE_BUNDLE_ID: &str = "grok-acp-1.0.4-v1";

/// Committed Kimi ACP fixture bundle for this release.
pub const KIMI_FIXTURE_BUNDLE_ID: &str = "kimi-acp-0.28.1-v1";

/// Conservative v0.1 proven-version matrix: each adapter admits exactly one
/// recorded version; any other installed version stays degraded and never
/// claims fixture-proven capabilities. Must stay in lockstep with each
/// `protocol/v1/fixtures/<adapter>/bundle.json` `proven_version`.
pub const PROVEN_VERSION_MATRIX: &[(&str, &str)] =
    &[("claude", "2.1.220"), ("grok", "1.0.4"), ("kimi", "0.28.1")];

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const REDACTED: &str = "[redacted]";
const MAX_RAW_LINE_BYTES: usize = 65_536;

const SENSITIVE_KEYS: &[&str] = &[
    "advisor",
    "anthropic_model",
    "api_key",
    "account_id",
    "credential",
    "fallback_model",
    "model",
    "model_name",
    "organization_id",
    "password",
    "prompt",
    "secret",
    "token",
    "user_id",
];

/// Redaction-safe adapter failure. No secrets, env values, or raw paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdapterError {
    #[error("adapter executable digest is unavailable")]
    DigestUnavailable,
    #[error("adapter admission is stale")]
    AdmissionStale,
    #[error("adapter is unavailable")]
    Unavailable,
    #[error("request contained a model name field")]
    ModelNameRejected,
    #[error("adapter request is invalid")]
    InvalidRequest,
    #[error("adapter output was malformed")]
    ProtocolMalformed,
    #[error("required capability is not admitted")]
    CapabilityNotAdmitted,
}

/// Mesh quality request values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Quality {
    Low,
    Standard,
    High,
}

impl Quality {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Standard => "standard",
            Self::High => "high",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AdapterError> {
        match value {
            "low" => Ok(Self::Low),
            "standard" => Ok(Self::Standard),
            "high" => Ok(Self::High),
            _ => Err(AdapterError::InvalidRequest),
        }
    }
}

/// Mesh effort request values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effort {
    Low,
    Medium,
    High,
}

impl Effort {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(value: &str) -> Result<Self, AdapterError> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(AdapterError::InvalidRequest),
        }
    }
}

/// Why an effective quality or effort value was selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingSource {
    Exact,
    ProviderDefault,
}

/// Requested versus effective quality and effort after adapter mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualityEffortMapping {
    pub requested_quality: Quality,
    pub effective_quality: Quality,
    pub quality_source: MappingSource,
    pub requested_effort: Effort,
    pub effective_effort: Effort,
    pub effort_source: MappingSource,
}

/// Public adapter health. `Enabled` requires a current live contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionStatus {
    Enabled,
    Degraded,
    Unavailable,
}

impl AdmissionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "ENABLED",
            Self::Degraded => "DEGRADED",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

/// Transport recorded on an admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterTransport {
    StreamJson,
    Acp,
}

impl AdapterTransport {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StreamJson => "stream_json",
            Self::Acp => "acp",
        }
    }
}

/// Admitted capability tokens from the protocol enum.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AdapterCapability {
    Streaming,
    Cancellation,
    Approvals,
    Input,
    SessionResume,
    Usage,
    Artifacts,
}

impl AdapterCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::Cancellation => "cancellation",
            Self::Approvals => "approvals",
            Self::Input => "input",
            Self::SessionResume => "session_resume",
            Self::Usage => "usage",
            Self::Artifacts => "artifacts",
        }
    }
}

/// Permission health on the public capabilities record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionHealth {
    Supported,
    Degraded,
    Unsupported,
}

impl PermissionHealth {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::Degraded => "DEGRADED",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

/// ACP sidecar remains off unless a required capability is missing and pinned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcpSidecarPolicy {
    pub enabled: bool,
    pub pinned_version: Option<String>,
}

impl AcpSidecarPolicy {
    pub const DISABLED: Self = Self {
        enabled: false,
        pinned_version: None,
    };
}

/// Durable admission proof for one local executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRecord {
    pub adapter: &'static str,
    pub adapter_instance_id: String,
    pub status: AdmissionStatus,
    pub executable_path: String,
    pub executable_digest: String,
    pub executable_version: String,
    pub transport: AdapterTransport,
    pub capabilities: Vec<AdapterCapability>,
    pub supported_interactions: Vec<&'static str>,
    pub permission_health: PermissionHealth,
    pub degradation_reason: String,
    pub fixture_bundle_id: String,
    pub acp_sidecar: AcpSidecarPolicy,
    pub live_contract_passed: bool,
}

impl AdmissionRecord {
    /// Public v1 `adapter_capabilities` record. Extra admission fields stay internal.
    pub fn to_protocol_value(&self) -> Result<Map<String, Value>, AdapterError> {
        let capabilities: Vec<Value> = self
            .capabilities
            .iter()
            .map(|capability| Value::from(capability.as_str()))
            .collect();
        let interactions: Vec<Value> = self
            .supported_interactions
            .iter()
            .map(|name| Value::from(*name))
            .collect();
        let value = serde_json::json!({
            "version": 1,
            "kind": "adapter_capabilities",
            "adapter_instance_id": self.adapter_instance_id,
            "adapter": self.adapter,
            "status": self.status.as_str(),
            "executable_path": self.executable_path,
            "executable_digest": self.executable_digest,
            "executable_version": self.executable_version,
            "transport": self.transport.as_str(),
            "capabilities": capabilities,
            "supported_interactions": interactions,
            "permission_health": self.permission_health.as_str(),
            "degradation_reason": self.degradation_reason,
        });
        decode_v1(value).map_err(|_| AdapterError::ProtocolMalformed)
    }

    #[must_use]
    pub fn admits(&self, capability: AdapterCapability) -> bool {
        !matches!(self.status, AdmissionStatus::Unavailable)
            && self.capabilities.contains(&capability)
    }
}

/// Normalized provider event plus a sanitized raw blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedEvent {
    pub kind: NormalizedKind,
    pub raw_digest: String,
    pub raw: Value,
}

/// Event kinds that map onto the existing protocol `event_type` set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedKind {
    StateChanged {
        state: TaskState,
    },
    TextDelta {
        text: String,
    },
    ToolProposal {
        operation_digest: String,
        interaction_id: String,
    },
    InteractionRequested {
        interaction_id: String,
    },
    InteractionDecided {
        interaction_id: String,
        approved: bool,
    },
    Usage {
        input_tokens: u64,
        output_tokens: u64,
    },
    Warning {
        warning: String,
    },
    ProtocolError {
        code: String,
        message: String,
    },
    Terminal {
        state: TaskState,
    },
}

/// SHA-256 of a local file. Missing or unreadable files fail closed.
pub fn digest_file(path: &Path) -> Result<String, AdapterError> {
    let mut file = File::open(path).map_err(|_| AdapterError::DigestUnavailable)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AdapterError::DigestUnavailable)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[must_use]
pub fn zero_digest() -> &'static str {
    ZERO_DIGEST
}

/// Rejects any model-name field before mapping or launch.
pub fn reject_model_fields(value: &Value) -> Result<(), AdapterError> {
    match value {
        Value::Object(fields) => {
            for (key, nested) in fields {
                if is_model_key(key) {
                    return Err(AdapterError::ModelNameRejected);
                }
                reject_model_fields(nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for nested in values {
                reject_model_fields(nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Re-hashes the binary and refuses a stale probe record.
pub fn confirm_admission(
    admission: &AdmissionRecord,
    executable: &Path,
) -> Result<(), AdapterError> {
    if matches!(admission.status, AdmissionStatus::Unavailable) {
        return Err(AdapterError::Unavailable);
    }
    let digest = digest_file(executable)?;
    if digest != admission.executable_digest {
        return Err(AdapterError::AdmissionStale);
    }
    Ok(())
}

/// Dispatch is allowed only for an admitted, non-unavailable capability set.
pub fn require_capabilities(
    admission: &AdmissionRecord,
    required: &[AdapterCapability],
) -> Result<(), AdapterError> {
    if matches!(admission.status, AdmissionStatus::Unavailable) {
        return Err(AdapterError::Unavailable);
    }
    if required
        .iter()
        .all(|capability| admission.capabilities.contains(capability))
    {
        Ok(())
    } else {
        Err(AdapterError::CapabilityNotAdmitted)
    }
}

/// Classifies a provider exit using the shared retry taxonomy.
#[must_use]
pub fn classify_adapter_exit(
    saw_valid_terminal: bool,
    evidence: LifecycleEvidence,
) -> (ErrorCode, EffectClass, RetryClass) {
    if matches!(evidence, LifecycleEvidence::BeforeProcessCreation) {
        let code = ErrorCode::AdapterUnavailable;
        let effect = EffectClass::NoEffect;
        return (code, effect, classify_retry(code, effect, evidence));
    }
    if saw_valid_terminal {
        let code = ErrorCode::Cancelled;
        let effect = EffectClass::PossibleEffect;
        return (code, effect, classify_retry(code, effect, evidence));
    }
    let code = ErrorCode::ProtocolMalformed;
    let effect = EffectClass::UnknownEffect;
    (code, effect, classify_retry(code, effect, evidence))
}

/// Sanitizes a decoded JSON value and returns its content digest.
#[must_use]
pub fn sanitize_raw(value: &Value) -> (Value, String) {
    let sanitized = sanitize_value(value);
    let digest = format!("{:x}", Sha256::digest(sanitized.to_string().as_bytes()));
    (sanitized, digest)
}

/// Sanitizes one provider stdout line. Non-JSON becomes a bounded preview object.
#[must_use]
pub fn sanitize_raw_line(line: &str) -> (Value, String) {
    let trimmed = line.trim();
    if trimmed.len() > MAX_RAW_LINE_BYTES {
        let value = serde_json::json!({
            "kind": "truncated",
            "bytes": trimmed.len()
        });
        return sanitize_raw(&value);
    }
    if let Ok(parsed) = parse_strict_json(trimmed) {
        sanitize_raw(&parsed)
    } else {
        let preview = sanitize_text(&trimmed.chars().take(128).collect::<String>());
        sanitize_raw(&serde_json::json!({
            "kind": "non_json",
            "preview": preview
        }))
    }
}

/// Binds a normalized kind onto a schema-valid v1 event.
pub fn bind_protocol_event(
    kind: &NormalizedKind,
    task_id: &str,
    event_id: &str,
    seq: u64,
    result_id: Option<&str>,
) -> Result<Map<String, Value>, AdapterError> {
    let (event_type, payload, severity) = match kind {
        NormalizedKind::StateChanged { state } => (
            "state_changed",
            serde_json::json!({ "state": state.as_str() }),
            None,
        ),
        NormalizedKind::TextDelta { text } => {
            ("text_delta", serde_json::json!({ "text": text }), None)
        }
        NormalizedKind::ToolProposal {
            operation_digest,
            interaction_id,
        } => (
            "tool_proposal",
            serde_json::json!({
                "operation_digest": operation_digest,
                "interaction_id": interaction_id
            }),
            None,
        ),
        NormalizedKind::InteractionRequested { interaction_id } => (
            "interaction_requested",
            serde_json::json!({ "interaction_id": interaction_id }),
            None,
        ),
        NormalizedKind::InteractionDecided {
            interaction_id,
            approved,
        } => {
            let (status, response_kind) = if *approved {
                ("APPROVED", "approve")
            } else {
                ("DENIED", "deny")
            };
            (
                "interaction_decided",
                serde_json::json!({
                    "interaction_id": interaction_id,
                    "status": status,
                    "response_kind": response_kind
                }),
                None,
            )
        }
        NormalizedKind::Usage {
            input_tokens,
            output_tokens,
        } => (
            "usage",
            serde_json::json!({
                "input_tokens": input_tokens,
                "output_tokens": output_tokens
            }),
            None,
        ),
        NormalizedKind::Warning { warning } => (
            "warning",
            serde_json::json!({ "warning": warning }),
            Some("WARNING"),
        ),
        NormalizedKind::ProtocolError { code, message } => (
            "protocol_error",
            serde_json::json!({ "code": code, "message": message }),
            Some("ERROR"),
        ),
        NormalizedKind::Terminal { state } => {
            let result_id = result_id.ok_or(AdapterError::InvalidRequest)?;
            (
                "terminal",
                serde_json::json!({
                    "state": state.as_str(),
                    "result_id": result_id
                }),
                None,
            )
        }
    };
    let mut value = serde_json::json!({
        "version": 1,
        "kind": "event",
        "event_id": event_id,
        "task_id": task_id,
        "seq": seq,
        "event_type": event_type,
        "payload": payload
    });
    if let Some(severity) = severity {
        value
            .as_object_mut()
            .ok_or(AdapterError::ProtocolMalformed)?
            .insert("severity".into(), Value::from(severity));
    }
    decode_v1(value).map_err(|_| AdapterError::ProtocolMalformed)
}

fn is_model_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "model" | "model_name" | "fallback_model" | "advisor" | "anthropic_model"
    )
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| lower == *sensitive || lower.ends_with(&format!("_{sensitive}")))
        || is_model_key(key)
        // Live captures proved providers report model identity under keys
        // like `modelUsage`, `modelState`, and `currentModelId`; every key
        // mentioning a model is redacted in persisted raw blobs.
        // `configOptions` (kimi session/new) carries model selection
        // surfaces such as currentValue/options lists and is redacted
        // wholesale.
        || lower.contains("model")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("configoption")
}

fn sanitize_value(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut sanitized = Map::new();
            for (key, nested) in fields {
                if is_sensitive_key(key) {
                    sanitized.insert(key.clone(), Value::from(REDACTED));
                } else {
                    sanitized.insert(key.clone(), sanitize_value(nested));
                }
            }
            Value::Object(sanitized)
        }
        Value::Array(values) => Value::Array(values.iter().map(sanitize_value).collect()),
        Value::String(text) => Value::from(sanitize_text(text)),
        other => other.clone(),
    }
}

fn sanitize_text(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains(":\\users\\")
        || lower.contains("/users/")
        || lower.contains("/home/")
        || lower.contains("sk-")
        || lower.contains("-----begin ")
        // Any drive-letter absolute path (for example `D:\project\...` or
        // an executable under `%LOCALAPPDATA%`) is machine-specific.
        || contains_drive_path(text)
    {
        REDACTED.to_owned()
    } else {
        text.to_owned()
    }
}

fn contains_drive_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .windows(3)
        .any(|window| window[0].is_ascii_alphabetic() && window[1] == b':' && window[2] == b'\\')
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
mod tests {
    use super::*;

    #[test]
    fn adapters_reject_model_name_fields() {
        assert_eq!(
            reject_model_fields(&serde_json::json!({"model": "sonnet"})),
            Err(AdapterError::ModelNameRejected)
        );
        assert_eq!(
            reject_model_fields(&serde_json::json!({"fallback_model": "haiku"})),
            Err(AdapterError::ModelNameRejected)
        );
        assert!(reject_model_fields(&serde_json::json!({"quality": "high"})).is_ok());
    }

    #[test]
    fn adapters_sanitize_model_and_path_blobs() {
        let (sanitized, digest) = sanitize_raw(&serde_json::json!({
            "model": "secret-model",
            "cwd": "C:\\Users\\someone\\repo",
            "text": "deterministic output"
        }));
        assert_eq!(sanitized["model"], REDACTED);
        assert_eq!(sanitized["cwd"], REDACTED);
        assert_eq!(sanitized["text"], "deterministic output");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn adapters_sanitize_live_model_and_drive_path_shapes() {
        // Shapes observed in real initialize/result captures.
        let (sanitized, _) = sanitize_raw(&serde_json::json!({
            "modelUsage": {"grok-4.6": 1},
            "modelState": {"currentModelId": "grok-4.6"},
            "apiKeySource": "none",
            "cwd": r"D:\project\repo",
            "executable": r"C:\Users\someone\bin\kimi.exe",
            "text": "deterministic output"
        }));
        assert_eq!(sanitized["modelUsage"], REDACTED);
        assert_eq!(sanitized["modelState"], REDACTED);
        assert_eq!(sanitized["apiKeySource"], REDACTED);
        assert_eq!(sanitized["cwd"], REDACTED);
        assert_eq!(sanitized["executable"], REDACTED);
        assert_eq!(sanitized["text"], "deterministic output");
        // Token-count fields must survive the broadened model redaction.
        let (usage, _) = sanitize_raw(&serde_json::json!({
            "input_tokens": 10,
            "output_tokens": 20
        }));
        assert_eq!(usage["input_tokens"], 10);
        assert_eq!(usage["output_tokens"], 20);
    }

    #[test]
    fn adapters_exit_zero_without_terminal_is_not_success() {
        let (code, effect, retry) =
            classify_adapter_exit(false, LifecycleEvidence::AfterProcessCreation);
        assert_eq!(code, ErrorCode::ProtocolMalformed);
        assert_eq!(effect, EffectClass::UnknownEffect);
        assert_eq!(retry, RetryClass::AmbiguousAfterDispatch);
        let (code, _, retry) =
            classify_adapter_exit(false, LifecycleEvidence::BeforeProcessCreation);
        assert_eq!(code, ErrorCode::AdapterUnavailable);
        assert_eq!(retry, RetryClass::SafePreDispatch);
    }

    #[test]
    fn adapters_proven_version_matrix_matches_every_fixture_bundle() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/v1/fixtures");
        for (adapter, proven) in PROVEN_VERSION_MATRIX {
            let source = std::fs::read_to_string(root.join(adapter).join("bundle.json"))
                .unwrap_or_else(|_| panic!("bundle for {adapter}"));
            let bundle: Value = serde_json::from_str(&source)
                .unwrap_or_else(|_| panic!("bundle json for {adapter}"));
            assert_eq!(
                bundle["proven_version"], *proven,
                "fixture bundle for {adapter} drifted from PROVEN_VERSION_MATRIX"
            );
            assert_eq!(bundle["adapter"], *adapter);
        }
    }
}
