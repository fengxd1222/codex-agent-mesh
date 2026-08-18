//! Offline Claude Code adapter: stream-json transport and fixture admission.
//!
//! ACP is left disabled. Stream-json fixtures prove permission and decode;
//! a sidecar is not enabled speculatively.

#![allow(clippy::module_name_repetitions)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::adapters::{
    AcpSidecarPolicy, AdapterCapability, AdapterError, AdapterTransport, AdmissionRecord,
    AdmissionStatus, CLAUDE_FIXTURE_BUNDLE_ID, Effort, MappingSource, NormalizedEvent,
    NormalizedKind, PermissionHealth, Quality, QualityEffortMapping, confirm_admission,
    digest_file, reject_model_fields, require_capabilities, sanitize_raw, sanitize_raw_line,
    zero_digest,
};
use crate::domain::{InteractionResponseKind, TaskState};
use crate::protocol_strict_json::parse_strict_json;
use crate::scheduler::AdapterInstanceId;

const ADAPTER: &str = "claude";
const PROVEN_VERSION: &str = "2.1.220";
const DEFAULT_DISPLAY_PATH: &str = "claude.exe";
const DEFAULT_ACCOUNT: &str = "local";
const DEFAULT_PROFILE: &str = "default";

const BUNDLE_JSON: &str = include_str!("../../../../protocol/v1/fixtures/claude/bundle.json");
const VERSION_FIXTURE: &str =
    include_str!("../../../../protocol/v1/fixtures/claude/version-2.1.220.txt");
const HELP_FIXTURE: &str = include_str!("../../../../protocol/v1/fixtures/claude/help-2.1.220.txt");
const STREAM_SUCCESS_JSON: &str =
    include_str!("../../../../protocol/v1/fixtures/claude/stream-success.json");
const PERMISSION_JSON: &str =
    include_str!("../../../../protocol/v1/fixtures/claude/permission-roundtrip.json");
const MALFORMED_JSON: &str = include_str!("../../../../protocol/v1/fixtures/claude/malformed.json");

/// Captured probe evidence. Version and help must be supplied by the caller;
/// this module does not spawn `claude` outside [`crate::supervisor`].
#[derive(Clone, Debug)]
pub struct ClaudeProbeEvidence {
    pub executable: PathBuf,
    pub display_path: String,
    pub version_stdout: Option<String>,
    pub help_stdout: Option<String>,
    pub live_contract_passed: bool,
    pub account: String,
    pub profile: String,
}

impl ClaudeProbeEvidence {
    #[must_use]
    pub fn fixture_aligned(executable: PathBuf) -> Self {
        Self {
            executable,
            display_path: DEFAULT_DISPLAY_PATH.into(),
            version_stdout: Some(VERSION_FIXTURE.to_owned()),
            help_stdout: Some(HELP_FIXTURE.to_owned()),
            live_contract_passed: false,
            account: DEFAULT_ACCOUNT.into(),
            profile: DEFAULT_PROFILE.into(),
        }
    }
}

/// Inputs for a stream-json launch plan. No model-name field exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeLaunchRequest {
    pub objective: String,
    pub quality: Quality,
    pub effort: Effort,
    pub session_id: Option<String>,
}

/// Supervisor-ready argv after admission is re-checked.
#[derive(Clone, Debug)]
pub struct ClaudeSpawnPlan {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub mapping: QualityEffortMapping,
}

/// Offline probe. Missing digest, version, or fixture proof is never healthy.
#[must_use]
pub fn probe_claude(evidence: &ClaudeProbeEvidence) -> AdmissionRecord {
    let digest = digest_file(&evidence.executable).unwrap_or_else(|_| zero_digest().to_owned());
    let parsed_version = evidence
        .version_stdout
        .as_deref()
        .and_then(parse_claude_version);
    let help_has_stream = evidence
        .help_stdout
        .as_deref()
        .is_some_and(|help| help.contains("stream-json"));
    let file_ok = evidence.executable.is_file() && digest != zero_digest();
    let version_aligned = parsed_version.as_deref() == Some(PROVEN_VERSION);
    let version = parsed_version
        .clone()
        .unwrap_or_else(|| "unproven".to_owned());
    let mut record = base_admission(evidence, digest, version);
    if !file_ok || parsed_version.is_none() || !fixture_bundle_is_current() {
        record.status = AdmissionStatus::Unavailable;
        record.degradation_reason = unavailable_reason(file_ok, parsed_version.is_some());
        return record;
    }
    assign_proven_capabilities(&mut record, help_has_stream, version_aligned);
    assign_probe_status(
        &mut record,
        evidence.live_contract_passed,
        version_aligned,
        help_has_stream,
    );
    record
}

/// Claude has `--effort` and no quality control. Quality never selects a model.
#[must_use]
pub fn map_quality_effort(quality: Quality, effort: Effort) -> QualityEffortMapping {
    QualityEffortMapping {
        requested_quality: quality,
        effective_quality: Quality::Standard,
        quality_source: if quality == Quality::Standard {
            MappingSource::Exact
        } else {
            MappingSource::ProviderDefault
        },
        requested_effort: effort,
        effective_effort: effort,
        effort_source: MappingSource::Exact,
    }
}

/// Builds supervisor argv after a digest re-check. Never emits a model flag.
pub fn plan_claude_spawn(
    executable: &Path,
    admission: &AdmissionRecord,
    request: &ClaudeLaunchRequest,
    extras: &Value,
) -> Result<ClaudeSpawnPlan, AdapterError> {
    reject_model_fields(extras)?;
    if request.objective.trim().is_empty() {
        return Err(AdapterError::InvalidRequest);
    }
    if request.session_id.is_some() && !admission.admits(AdapterCapability::SessionResume) {
        return Err(AdapterError::CapabilityNotAdmitted);
    }
    confirm_admission(admission, executable)?;
    require_capabilities(admission, &[AdapterCapability::Streaming])?;
    let mapping = map_quality_effort(request.quality, request.effort);
    // One-shot print: the objective is the argv after `--`. Do not pass
    // `--input-format stream-json` or the process waits on stdin forever.
    // `--bare` skips project hooks/plugins so a repo cwd cannot stall the run.
    let mut arguments = vec![
        OsString::from("--print"),
        OsString::from("--bare"),
        OsString::from("--output-format"),
        OsString::from("stream-json"),
        OsString::from("--verbose"),
        OsString::from("--include-partial-messages"),
        OsString::from("--effort"),
        OsString::from(mapping.effective_effort.as_str()),
        OsString::from("--"),
        OsString::from(&request.objective),
    ];
    if let Some(session_id) = &request.session_id {
        arguments.insert(0, OsString::from("--resume"));
        arguments.insert(1, OsString::from(session_id));
    }
    if arguments
        .iter()
        .any(|argument| argument.to_string_lossy().eq_ignore_ascii_case("--model"))
    {
        return Err(AdapterError::ModelNameRejected);
    }
    Ok(ClaudeSpawnPlan {
        executable: executable.to_path_buf(),
        arguments,
        mapping,
    })
}

/// Decodes one stream-json line into zero or more normalized events.
#[must_use]
pub fn decode_stream_json_line(line: &str) -> Vec<NormalizedEvent> {
    let (raw, raw_digest) = sanitize_raw_line(line);
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(parsed) = parse_strict_json(trimmed) else {
        return vec![NormalizedEvent {
            kind: NormalizedKind::ProtocolError {
                code: "malformed_frame".into(),
                message: "Adapter emitted a malformed frame.".into(),
            },
            raw_digest,
            raw,
        }];
    };
    let kinds = classify_claude_event(&parsed);
    if kinds.is_empty() {
        let event_type = parsed.get("type").and_then(Value::as_str).unwrap_or("");
        if matches!(
            event_type,
            "system" | "stream_event" | "assistant" | "user" | "progress"
        ) {
            return Vec::new();
        }
        return vec![NormalizedEvent {
            kind: NormalizedKind::Warning {
                warning: "Adapter reported a deterministic warning.".into(),
            },
            raw_digest,
            raw,
        }];
    }
    kinds
        .into_iter()
        .map(|kind| NormalizedEvent {
            kind,
            raw_digest: raw_digest.clone(),
            raw: raw.clone(),
        })
        .collect()
}

/// Decodes a committed fixture array of stream-json objects or raw strings.
pub fn decode_stream_json_fixture(source: &str) -> Result<Vec<NormalizedEvent>, AdapterError> {
    let value: Value = serde_json::from_str(source).map_err(|_| AdapterError::ProtocolMalformed)?;
    let items = value.as_array().ok_or(AdapterError::ProtocolMalformed)?;
    let mut events = Vec::new();
    for item in items {
        match item {
            Value::String(line) => events.extend(decode_stream_json_line(line)),
            other => {
                let encoded =
                    serde_json::to_string(other).map_err(|_| AdapterError::ProtocolMalformed)?;
                events.extend(decode_stream_json_line(&encoded));
            }
        }
    }
    Ok(events)
}

/// Encodes a one-shot permission decision for Claude stdin.
pub fn encode_permission_response(
    request_id: &str,
    kind: InteractionResponseKind,
) -> Result<Vec<u8>, AdapterError> {
    if request_id.is_empty() || !is_protocol_id(request_id) {
        return Err(AdapterError::InvalidRequest);
    }
    let behavior = match kind {
        InteractionResponseKind::Approve => "allow",
        InteractionResponseKind::Deny => "deny",
        InteractionResponseKind::Text => return Err(AdapterError::InvalidRequest),
    };
    let value = serde_json::json!({
        "type": "control_response",
        "response": {
            "subtype": "success",
            "request_id": request_id,
            "behavior": behavior
        }
    });
    let mut bytes = serde_json::to_vec(&value).map_err(|_| AdapterError::ProtocolMalformed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Extracts a permission request id from a decoded `control_request` object.
pub fn permission_request_id(value: &Value) -> Option<&str> {
    value
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| is_protocol_id(id))
}

#[must_use]
pub fn stream_success_fixture() -> &'static str {
    STREAM_SUCCESS_JSON
}

#[must_use]
pub fn permission_roundtrip_fixture() -> &'static str {
    PERMISSION_JSON
}

#[must_use]
pub fn malformed_fixture() -> &'static str {
    MALFORMED_JSON
}

#[must_use]
pub fn version_fixture() -> &'static str {
    VERSION_FIXTURE
}

#[must_use]
pub fn help_fixture() -> &'static str {
    HELP_FIXTURE
}

#[must_use]
pub fn claude_config_digest() -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("claude:{CLAUDE_FIXTURE_BUNDLE_ID}:stream_json").as_bytes())
    )
}

fn fixture_bundle_is_current() -> bool {
    serde_json::from_str::<Value>(BUNDLE_JSON).is_ok_and(|value| {
        value.get("id").and_then(Value::as_str) == Some(CLAUDE_FIXTURE_BUNDLE_ID)
            && value.get("acp_sidecar").and_then(Value::as_str) == Some("disabled")
            && value.get("proven_version").and_then(Value::as_str) == Some(PROVEN_VERSION)
    })
}

fn parse_claude_version(stdout: &str) -> Option<String> {
    for token in stdout.split(|byte: char| !byte.is_ascii_digit() && byte != '.') {
        let mut parts = token.split('.');
        let Some(major) = parts.next() else { continue };
        let Some(minor) = parts.next() else { continue };
        let Some(patch) = parts.next() else { continue };
        if parts.next().is_some()
            || major.is_empty()
            || minor.is_empty()
            || patch.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
            || !patch.bytes().all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        return Some(format!("{major}.{minor}.{patch}"));
    }
    None
}

fn classify_claude_event(value: &Value) -> Vec<NormalizedKind> {
    let event_type = value.get("type").and_then(Value::as_str).unwrap_or("");
    match event_type {
        "system" => match value.get("subtype").and_then(Value::as_str) {
            Some("init") => vec![NormalizedKind::StateChanged {
                state: TaskState::Running,
            }],
            Some("status") => value
                .get("status")
                .and_then(Value::as_str)
                .filter(|status| !status.is_empty())
                .map(|status| {
                    vec![NormalizedKind::Warning {
                        warning: format!("status: {status}"),
                    }]
                })
                .unwrap_or_default(),
            Some("api_retry") => vec![NormalizedKind::Warning {
                warning: "Adapter reported a deterministic warning.".into(),
            }],
            _ => Vec::new(),
        },
        "assistant" => classify_assistant(value),
        "user" => classify_user(value),
        "stream_event" => classify_stream_event(value.get("event")),
        "control_request" => classify_control_request(value).unwrap_or_default(),
        "result" => classify_result(value),
        _ => Vec::new(),
    }
}

fn classify_stream_event(event: Option<&Value>) -> Vec<NormalizedKind> {
    let Some(event) = event else {
        return Vec::new();
    };
    match event.get("type").and_then(Value::as_str) {
        Some("content_block_delta") => {
            let Some(delta) = event.get("delta") else {
                return Vec::new();
            };
            match delta.get("type").and_then(Value::as_str) {
                Some("text_delta") => nonempty_text(delta.get("text"))
                    .into_iter()
                    .map(|text| NormalizedKind::TextDelta { text })
                    .collect(),
                Some("thinking_delta") => nonempty_text(delta.get("thinking"))
                    .into_iter()
                    .map(|text| NormalizedKind::Warning {
                        warning: format!("thinking: {text}"),
                    })
                    .collect(),
                _ => Vec::new(),
            }
        }
        Some("content_block_start") => {
            let block = event.get("content_block");
            match block
                .and_then(|item| item.get("type"))
                .and_then(Value::as_str)
            {
                Some("tool_use") => block
                    .and_then(|item| item.get("name"))
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .map(|name| {
                        vec![NormalizedKind::Warning {
                            warning: format!("tool: {name}"),
                        }]
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

fn classify_user(value: &Value) -> Vec<NormalizedKind> {
    let Some(content) = value.pointer("/message/content").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut kinds = Vec::new();
    for block in content {
        if block.get("type").and_then(Value::as_str) != Some("tool_result") {
            continue;
        }
        let preview = tool_result_preview(block.get("content"));
        if !preview.is_empty() {
            kinds.push(NormalizedKind::Warning {
                warning: format!("tool result: {preview}"),
            });
        }
    }
    kinds
}

fn tool_result_preview(content: Option<&Value>) -> String {
    let raw = match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| {
                item.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| item.as_str())
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    };
    collapse_preview(&raw, 160)
}

fn collapse_preview(text: &str, max_chars: usize) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        return collapsed;
    }
    let mut preview: String = collapsed
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect();
    preview.push('…');
    preview
}

fn classify_assistant(value: &Value) -> Vec<NormalizedKind> {
    let mut kinds = Vec::new();
    let Some(content) = value.pointer("/message/content").and_then(Value::as_array) else {
        return kinds;
    };
    for block in content {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = nonempty_text(block.get("text")) {
                    kinds.push(NormalizedKind::TextDelta { text });
                }
            }
            Some("thinking") => {
                if let Some(text) = nonempty_text(block.get("thinking")) {
                    kinds.push(NormalizedKind::Warning {
                        warning: format!("thinking: {text}"),
                    });
                }
            }
            Some("tool_use") => {
                if let Some(kind) = tool_proposal_from_block(block) {
                    kinds.push(kind);
                }
                if let Some(line) = tool_use_line(block) {
                    kinds.push(NormalizedKind::Warning { warning: line });
                }
            }
            _ => {}
        }
    }
    kinds
}

fn classify_control_request(value: &Value) -> Option<Vec<NormalizedKind>> {
    let request = value.get("request")?;
    if request.get("subtype").and_then(Value::as_str) != Some("can_use_tool") {
        return None;
    }
    let interaction_id = value.get("request_id").and_then(Value::as_str)?;
    if !is_protocol_id(interaction_id) {
        return None;
    }
    let tool_name = request
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let input = request.get("input").cloned().unwrap_or(Value::Null);
    let operation = serde_json::json!({
        "tool_name": tool_name,
        "input": input
    });
    let (sanitized, operation_digest) = sanitize_raw(&operation);
    let _ = sanitized;
    Some(vec![
        NormalizedKind::ToolProposal {
            operation_digest,
            interaction_id: interaction_id.to_owned(),
        },
        NormalizedKind::InteractionRequested {
            interaction_id: interaction_id.to_owned(),
        },
    ])
}

fn classify_result(value: &Value) -> Vec<NormalizedKind> {
    let mut kinds = Vec::new();
    if let Some(usage) = value.get("usage") {
        let input_tokens = usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let output_tokens = usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        kinds.push(NormalizedKind::Usage {
            input_tokens,
            output_tokens,
        });
    }
    let subtype = value.get("subtype").and_then(Value::as_str).unwrap_or("");
    let is_error = value
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let state = if subtype.contains("cancel") {
        TaskState::Cancelled
    } else if subtype == "success" && !is_error {
        TaskState::Succeeded
    } else {
        TaskState::Failed
    };
    kinds.push(NormalizedKind::Terminal { state });
    kinds
}

fn tool_use_line(block: &Value) -> Option<String> {
    let name = block
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())?;
    let input = block.get("input");
    let detail = input
        .and_then(|value| value.get("command").and_then(Value::as_str))
        .or_else(|| input.and_then(|value| value.get("path").and_then(Value::as_str)))
        .or_else(|| input.and_then(|value| value.get("file_path").and_then(Value::as_str)))
        .or_else(|| input.and_then(|value| value.get("query").and_then(Value::as_str)))
        .unwrap_or("");
    let detail = collapse_preview(detail, 120);
    if detail.is_empty() {
        Some(format!("tool: {name}"))
    } else {
        Some(format!("tool: {name} {detail}"))
    }
}

fn tool_proposal_from_block(block: &Value) -> Option<NormalizedKind> {
    let tool_use_id = block.get("id").and_then(Value::as_str)?;
    if !is_protocol_id(tool_use_id) {
        return None;
    }
    let operation = serde_json::json!({
        "tool_name": block.get("name").and_then(Value::as_str).unwrap_or(""),
        "input": block.get("input").cloned().unwrap_or(Value::Null)
    });
    let (_, operation_digest) = sanitize_raw(&operation);
    Some(NormalizedKind::ToolProposal {
        operation_digest,
        interaction_id: tool_use_id.to_owned(),
    })
}

fn nonempty_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn is_protocol_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphanumeric())
        && value.len() <= 128
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

/// Request and encoded answers from the offline permission fixture.
pub struct PermissionFixture {
    pub request: Value,
    pub approve: Map<String, Value>,
    pub deny: Map<String, Value>,
}

/// Decodes the committed permission fixture into request and answers.
pub fn decode_permission_fixture() -> Result<PermissionFixture, AdapterError> {
    let value: Value =
        serde_json::from_str(PERMISSION_JSON).map_err(|_| AdapterError::ProtocolMalformed)?;
    Ok(PermissionFixture {
        request: value
            .get("request")
            .cloned()
            .ok_or(AdapterError::ProtocolMalformed)?,
        approve: value
            .get("approve")
            .and_then(Value::as_object)
            .cloned()
            .ok_or(AdapterError::ProtocolMalformed)?,
        deny: value
            .get("deny")
            .and_then(Value::as_object)
            .cloned()
            .ok_or(AdapterError::ProtocolMalformed)?,
    })
}

fn base_admission(
    evidence: &ClaudeProbeEvidence,
    digest: String,
    version: String,
) -> AdmissionRecord {
    let display_path = if evidence.display_path.is_empty() {
        DEFAULT_DISPLAY_PATH.to_owned()
    } else {
        evidence.display_path.clone()
    };
    AdmissionRecord {
        adapter: ADAPTER,
        adapter_instance_id: instance_id(evidence),
        status: AdmissionStatus::Unavailable,
        executable_path: display_path,
        executable_digest: digest,
        executable_version: version,
        transport: AdapterTransport::StreamJson,
        capabilities: Vec::new(),
        supported_interactions: Vec::new(),
        permission_health: PermissionHealth::Unsupported,
        degradation_reason: String::new(),
        fixture_bundle_id: CLAUDE_FIXTURE_BUNDLE_ID.into(),
        acp_sidecar: AcpSidecarPolicy::DISABLED,
        live_contract_passed: evidence.live_contract_passed,
    }
}

fn instance_id(evidence: &ClaudeProbeEvidence) -> String {
    let config_digest = claude_config_digest();
    let account = selector_component(&evidence.account, DEFAULT_ACCOUNT);
    let profile = selector_component(&evidence.profile, DEFAULT_PROFILE);
    match AdapterInstanceId::new(ADAPTER, &account, &profile, &config_digest) {
        Ok(id) => id.encode(),
        Err(_) => format!("{ADAPTER}:{DEFAULT_ACCOUNT}:{DEFAULT_PROFILE}:{config_digest}"),
    }
}

fn selector_component(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return default.to_owned();
    }
    if trimmed.len() <= 16
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return trimmed.to_owned();
    }
    format!("{:x}", Sha256::digest(trimmed.as_bytes()))
        .chars()
        .take(16)
        .collect()
}

fn unavailable_reason(file_ok: bool, version_ok: bool) -> String {
    if !file_ok {
        "executable digest missing"
    } else if !version_ok {
        "version proof missing"
    } else {
        "fixture bundle missing"
    }
    .into()
}

fn assign_proven_capabilities(
    record: &mut AdmissionRecord,
    help_has_stream: bool,
    version_aligned: bool,
) {
    if help_has_stream && version_aligned {
        record.capabilities.extend([
            AdapterCapability::Streaming,
            AdapterCapability::Cancellation,
            AdapterCapability::Approvals,
            AdapterCapability::Usage,
        ]);
        record.supported_interactions.push("approval");
        record.permission_health = PermissionHealth::Supported;
    } else if help_has_stream {
        record.capabilities.push(AdapterCapability::Streaming);
    }
}

fn assign_probe_status(
    record: &mut AdmissionRecord,
    live_contract_passed: bool,
    version_aligned: bool,
    help_has_stream: bool,
) {
    if live_contract_passed
        && version_aligned
        && help_has_stream
        && record.permission_health == PermissionHealth::Supported
    {
        record.status = AdmissionStatus::Enabled;
        record.degradation_reason.clear();
        return;
    }
    record.status = AdmissionStatus::Degraded;
    record.degradation_reason = if !version_aligned {
        format!("unproven version; fixture bundle applies to {PROVEN_VERSION}")
    } else if !help_has_stream {
        "stream-json flag not proven from help".into()
    } else {
        "local live contract not recorded".into()
    };
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::adapters::{
        bind_protocol_event, classify_adapter_exit, confirm_admission, reject_model_fields,
    };
    use crate::decode_v1;
    use crate::{EffectClass, ErrorCode, LifecycleEvidence, RetryClass};
    use serde_json::json;
    use std::fs;

    fn write_exe(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, bytes).expect("write probe file");
        path
    }

    #[test]
    fn claude_missing_proof_is_unavailable_not_healthy() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = root.path().join("missing-claude");
        let admission = probe_claude(&ClaudeProbeEvidence {
            executable: missing,
            display_path: DEFAULT_DISPLAY_PATH.into(),
            version_stdout: None,
            help_stdout: None,
            live_contract_passed: false,
            account: DEFAULT_ACCOUNT.into(),
            profile: DEFAULT_PROFILE.into(),
        });
        assert_eq!(admission.status, AdmissionStatus::Unavailable);
        assert_ne!(admission.status, AdmissionStatus::Enabled);
        assert!(!admission.acp_sidecar.enabled);
        assert!(admission.capabilities.is_empty());
    }

    #[test]
    fn claude_fixture_probe_is_degraded_without_live_contract() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "claude-probe.bin", b"claude-fixture-binary");
        let admission = probe_claude(&ClaudeProbeEvidence::fixture_aligned(exe.clone()));
        assert_eq!(admission.status, AdmissionStatus::Degraded);
        assert_eq!(
            admission.degradation_reason,
            "local live contract not recorded"
        );
        assert_eq!(admission.executable_version, PROVEN_VERSION);
        assert_eq!(admission.transport, AdapterTransport::StreamJson);
        assert_eq!(admission.permission_health, PermissionHealth::Supported);
        assert!(admission.admits(AdapterCapability::Streaming));
        assert!(admission.admits(AdapterCapability::Approvals));
        assert!(!admission.admits(AdapterCapability::SessionResume));
        assert!(!admission.acp_sidecar.enabled);
        assert_eq!(admission.fixture_bundle_id, CLAUDE_FIXTURE_BUNDLE_ID);
        assert_eq!(
            admission.executable_digest,
            digest_file(&exe).expect("digest")
        );
        let protocol = admission.to_protocol_value().expect("protocol");
        assert_eq!(protocol["status"], "DEGRADED");
        assert_eq!(protocol["transport"], "stream_json");
    }

    #[test]
    fn claude_unproven_version_does_not_claim_permission() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "claude-other.bin", b"other");
        let mut evidence = ClaudeProbeEvidence::fixture_aligned(exe);
        evidence.version_stdout = Some("2.0.0".into());
        let admission = probe_claude(&evidence);
        assert_eq!(admission.status, AdmissionStatus::Degraded);
        assert_eq!(admission.permission_health, PermissionHealth::Unsupported);
        assert!(admission.admits(AdapterCapability::Streaming));
        assert!(!admission.admits(AdapterCapability::Approvals));
        assert!(!admission.admits(AdapterCapability::Cancellation));
        assert_ne!(admission.status, AdmissionStatus::Enabled);
    }

    #[test]
    fn claude_enabled_requires_live_contract_and_full_proof() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "claude-live.bin", b"live-proof");
        let mut evidence = ClaudeProbeEvidence::fixture_aligned(exe);
        evidence.live_contract_passed = true;
        let admission = probe_claude(&evidence);
        assert_eq!(admission.status, AdmissionStatus::Enabled);
        assert!(admission.live_contract_passed);
        assert!(admission.degradation_reason.is_empty());
    }

    #[test]
    fn claude_digest_change_invalidates_admission() {
        let root = tempfile::tempdir().expect("tempdir");
        let first = write_exe(&root, "claude-a.bin", b"first");
        let second = write_exe(&root, "claude-b.bin", b"second");
        let admission = probe_claude(&ClaudeProbeEvidence::fixture_aligned(first));
        assert_eq!(
            confirm_admission(&admission, &second),
            Err(AdapterError::AdmissionStale)
        );
        let request = ClaudeLaunchRequest {
            objective: "summarize local protocol".into(),
            quality: Quality::Standard,
            effort: Effort::Medium,
            session_id: None,
        };
        assert_eq!(
            plan_claude_spawn(&second, &admission, &request, &json!({})).err(),
            Some(AdapterError::AdmissionStale)
        );
    }

    #[test]
    fn claude_quality_effort_reports_requested_versus_effective() {
        let mapped = map_quality_effort(Quality::High, Effort::Low);
        assert_eq!(mapped.requested_quality, Quality::High);
        assert_eq!(mapped.effective_quality, Quality::Standard);
        assert_eq!(mapped.quality_source, MappingSource::ProviderDefault);
        assert_eq!(mapped.requested_effort, Effort::Low);
        assert_eq!(mapped.effective_effort, Effort::Low);
        assert_eq!(mapped.effort_source, MappingSource::Exact);
        let exact = map_quality_effort(Quality::Standard, Effort::High);
        assert_eq!(exact.quality_source, MappingSource::Exact);
        assert_eq!(exact.effective_effort, Effort::High);
    }

    #[test]
    fn claude_launch_args_are_stream_json_and_reject_model() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "claude-args.bin", b"args");
        let admission = probe_claude(&ClaudeProbeEvidence::fixture_aligned(exe.clone()));
        let request = ClaudeLaunchRequest {
            objective: "summarize local protocol".into(),
            quality: Quality::High,
            effort: Effort::High,
            session_id: None,
        };
        let plan = plan_claude_spawn(&exe, &admission, &request, &json!({})).expect("plan");
        let args: Vec<String> = plan
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--print".into()));
        assert!(args.contains(&"--bare".into()));
        assert!(!args.contains(&"--input-format".into()));
        assert!(args.contains(&"stream-json".into()));
        assert!(args.contains(&"--effort".into()));
        assert!(args.contains(&"high".into()));
        assert!(args.contains(&"summarize local protocol".into()));
        let objective_at = args
            .iter()
            .position(|argument| argument == "summarize local protocol")
            .expect("objective");
        assert_eq!(args[objective_at - 1], "--");
        assert!(!args.iter().any(|argument| argument.contains("model")));
        assert!(!args.contains(&"--dangerously-skip-permissions".into()));
        let flagged = ClaudeLaunchRequest {
            objective: "--dangerously-skip-permissions".into(),
            ..request.clone()
        };
        let flagged_plan =
            plan_claude_spawn(&exe, &admission, &flagged, &json!({})).expect("flag-safe plan");
        let flagged_args: Vec<String> = flagged_plan
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        let skip_at = flagged_args
            .iter()
            .position(|argument| argument == "--dangerously-skip-permissions")
            .expect("literal objective");
        assert_eq!(flagged_args[skip_at - 1], "--");
        assert_eq!(plan.mapping.effective_quality, Quality::Standard);
        assert_eq!(
            plan_claude_spawn(&exe, &admission, &request, &json!({"model": "sonnet"})).err(),
            Some(AdapterError::ModelNameRejected)
        );
        let resume = ClaudeLaunchRequest {
            session_id: Some("session-fixture-001".into()),
            ..request
        };
        assert_eq!(
            plan_claude_spawn(&exe, &admission, &resume, &json!({})).err(),
            Some(AdapterError::CapabilityNotAdmitted)
        );
    }

    #[test]
    fn claude_normalizes_stream_json_fixture_and_keeps_sanitized_raw() {
        let events = decode_stream_json_fixture(STREAM_SUCCESS_JSON).expect("decode");
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::StateChanged { state } if state == TaskState::Running))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::TextDelta { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::ToolProposal { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::InteractionRequested { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Terminal { state } if state == TaskState::Succeeded))
        );
        let usage = decode_stream_json_line(
            r#"{"type":"result","subtype":"success","usage":{"input_tokens":10,"output_tokens":20}}"#,
        );
        assert!(
            usage
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Usage { input_tokens, output_tokens } if input_tokens == 10 && output_tokens == 20))
        );
        let hooks = decode_stream_json_line(
            r#"{"type":"system","subtype":"hook_started","hook_name":"SessionStart"}"#,
        );
        assert!(hooks.is_empty());
        let thinking = decode_stream_json_line(
            r#"{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"Look at README"}}}"#,
        );
        assert!(thinking.iter().any(|event| matches!(
            &event.kind,
            NormalizedKind::Warning { warning } if warning == "thinking: Look at README"
        )));
        let skipped =
            decode_stream_json_line(r#"{"type":"stream_event","event":{"type":"message_stop"}}"#);
        assert!(skipped.is_empty());
        let tool = decode_stream_json_line(
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"call-1","name":"Bash","input":{"command":"ls"}}]}}"#,
        );
        assert!(tool.iter().any(|event| matches!(
            &event.kind,
            NormalizedKind::Warning { warning } if warning == "tool: Bash ls"
        )));
        for event in &events {
            assert_eq!(event.raw_digest.len(), 64);
            assert!(reject_model_fields(&event.raw).is_ok());
            assert!(event.raw.get("model").is_none() || event.raw["model"] == "[redacted]");
        }
        let bound = bind_protocol_event(
            &NormalizedKind::TextDelta {
                text: "deterministic output".into(),
            },
            "task-001",
            "event-002",
            2,
            None,
        )
        .expect("bind");
        assert_eq!(bound["event_type"], "text_delta");
    }

    #[test]
    fn claude_malformed_output_is_protocol_error_with_sanitized_raw() {
        let events = decode_stream_json_fixture(MALFORMED_JSON).expect("decode");
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::ProtocolError { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Warning { .. }))
        );
        let error = events
            .iter()
            .find(|event| matches!(event.kind, NormalizedKind::ProtocolError { .. }))
            .expect("protocol error");
        assert_eq!(error.raw["kind"], "non_json");
        let bound =
            bind_protocol_event(&error.kind, "task-001", "event-008", 8, None).expect("bind");
        assert_eq!(bound["event_type"], "protocol_error");
    }

    #[test]
    fn claude_permission_roundtrip_fixture_is_offline() {
        let fixture = decode_permission_fixture().expect("fixture");
        assert_eq!(fixture.request["type"], "control_request");
        let events =
            decode_stream_json_line(&serde_json::to_string(&fixture.request).expect("encode"));
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::InteractionRequested { .. }))
        );
        let request_id = permission_request_id(&fixture.request).expect("request id");
        let approve = encode_permission_response(request_id, InteractionResponseKind::Approve)
            .expect("approve");
        let deny =
            encode_permission_response(request_id, InteractionResponseKind::Deny).expect("deny");
        let approve_value: Value =
            serde_json::from_slice(&approve[..approve.len() - 1]).expect("json");
        let deny_value: Value = serde_json::from_slice(&deny[..deny.len() - 1]).expect("json");
        assert_eq!(approve_value["response"]["behavior"], "allow");
        assert_eq!(deny_value["response"]["behavior"], "deny");
        assert_eq!(approve_value["type"], fixture.approve["type"]);
        assert_eq!(deny_value["type"], fixture.deny["type"]);
        assert_eq!(
            encode_permission_response(request_id, InteractionResponseKind::Text).err(),
            Some(AdapterError::InvalidRequest)
        );
    }

    #[test]
    fn claude_acp_sidecar_stays_disabled() {
        const { assert!(!AcpSidecarPolicy::DISABLED.enabled) };
        let bundle: Value = serde_json::from_str(BUNDLE_JSON).expect("bundle");
        assert_eq!(bundle["acp_sidecar"], "disabled");
        assert!(AcpSidecarPolicy::DISABLED.pinned_version.is_none());
    }

    #[test]
    fn claude_golden_capabilities_match_offline_degraded_shape() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/golden/adapter-capabilities-claude-degraded.json"
        ))
        .expect("golden");
        decode_v1(golden.clone()).expect("golden decodes");
        assert_eq!(golden["adapter"], "claude");
        assert_eq!(golden["status"], "DEGRADED");
        assert_eq!(golden["transport"], "stream_json");
        assert_eq!(
            golden["adapter_instance_id"],
            format!("claude:local:default:{}", claude_config_digest())
        );
    }

    #[test]
    fn claude_exit_zero_without_terminal_stays_ambiguous() {
        let (code, effect, retry) =
            classify_adapter_exit(false, LifecycleEvidence::AfterProcessCreation);
        assert_eq!(code, ErrorCode::ProtocolMalformed);
        assert_eq!(effect, EffectClass::UnknownEffect);
        assert_eq!(retry, RetryClass::AmbiguousAfterDispatch);
    }

    #[test]
    fn claude_result_is_error_is_not_success() {
        let events =
            decode_stream_json_line(r#"{"type":"result","subtype":"success","is_error":true}"#);
        assert!(events.iter().any(|event| matches!(
            event.kind,
            NormalizedKind::Terminal { state } if state == TaskState::Failed
        )));
    }

    #[test]
    fn claude_instance_id_hashes_invalid_account_instead_of_defaulting() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "claude-id.bin", b"id");
        let mut evidence = ClaudeProbeEvidence::fixture_aligned(exe);
        evidence.account = "user@example.com".into();
        let admission = probe_claude(&evidence);
        assert!(admission.adapter_instance_id.starts_with("claude:"));
        assert!(!admission.adapter_instance_id.starts_with("claude:local:"));
        assert_ne!(
            admission.adapter_instance_id,
            format!("claude:local:default:{}", claude_config_digest())
        );
    }
}

#[cfg(all(test, windows))]
#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
mod launch_tests {
    use super::*;
    use crate::scheduler::AdapterInstanceId;
    use crate::storage::{AttemptSpec, DispatchOutcome};
    use crate::supervisor::{ProcessSupervisor, ResumeGate, SpawnOutcome, SpawnRequest};
    use crate::writer::WriterHandle;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;
    use std::thread;
    use std::time::Duration;

    fn fake_adapter_exe() -> PathBuf {
        static EXE: OnceLock<PathBuf> = OnceLock::new();
        EXE.get_or_init(locate_or_build_fake_adapter).clone()
    }

    fn locate_or_build_fake_adapter() -> PathBuf {
        if let Some(path) = find_fake_adapter() {
            return path;
        }
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let isolated = workspace.join("target").join("mesh-fake-adapter-test");
        let cargo = std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from);
        let status = Command::new(cargo)
            .args(["build", "-p", "mesh-fake-adapter", "--offline"])
            .env("CARGO_TARGET_DIR", &isolated)
            .current_dir(&workspace)
            .status()
            .expect("spawn cargo to build mesh-fake-adapter");
        if !status.success() {
            let status = Command::new(
                std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from),
            )
            .args(["build", "-p", "mesh-fake-adapter"])
            .env("CARGO_TARGET_DIR", &isolated)
            .current_dir(&workspace)
            .status()
            .expect("spawn cargo online");
            assert!(status.success(), "failed to build mesh-fake-adapter");
        }
        find_under(&isolated).expect("built mesh-fake-adapter")
    }

    fn find_fake_adapter() -> Option<PathBuf> {
        let name = "mesh-fake-adapter.exe";
        if let Ok(current) = std::env::current_exe() {
            let mut dir = current.parent()?.to_path_buf();
            for _ in 0..5 {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
                dir.pop();
            }
        }
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for root in [
            workspace.join("target"),
            workspace.join("target").join("mesh-fake-adapter-test"),
        ] {
            if let Some(path) = find_under(&root) {
                return Some(path);
            }
        }
        None
    }

    fn find_under(root: &Path) -> Option<PathBuf> {
        let name = "mesh-fake-adapter.exe";
        for profile in ["debug", "release"] {
            let candidate = root.join(profile).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    fn wait_for_spool_line(spool: &Path, needle: &str) {
        for _ in 0..200 {
            if let Ok(text) = fs::read_to_string(spool)
                && text.contains(needle)
            {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("stdout spool never contained {needle}");
    }

    fn stream_json_script() -> serde_json::Value {
        serde_json::json!([
            {
                "type": "raw",
                "line": "{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"session-fixture-001\"}"
            },
            {
                "type": "raw",
                "line": "{\"type\":\"result\",\"subtype\":\"success\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}"
            }
        ])
    }

    fn claim_claude_attempt(writer: &WriterHandle, version: &str) -> String {
        let aid = AdapterInstanceId::new("claude", "local", "default", &claude_config_digest())
            .expect("id")
            .encode();
        writer
            .submit_for_scheduling(
                "c",
                "submit",
                "k-claude-launch",
                b"body-claude-launch".to_vec(),
                "task-claude-launch",
                None,
                0,
                Some(&aid),
                10,
            )
            .expect("submit");
        let spec = AttemptSpec {
            adapter_instance_id: aid,
            config_digest: claude_config_digest(),
            adapter_version: version.to_owned(),
            ..AttemptSpec::default()
        };
        match writer
            .claim_dispatch_slot(
                "claim-claude-launch",
                "task-claude-launch",
                0,
                spec,
                crate::scheduler::SchedulerLimits::DEFAULT,
                11,
            )
            .expect("claim")
        {
            DispatchOutcome::Dispatched(attempt) => attempt.attempt_id,
            DispatchOutcome::Blocked(blocked) => panic!("blocked: {blocked:?}"),
        }
    }

    #[test]
    fn claude_supervisor_launch_uses_confirmed_digest_and_decodes_stream() {
        let exe = fake_adapter_exe();
        let mut evidence = ClaudeProbeEvidence::fixture_aligned(exe.clone());
        evidence.display_path = "mesh-fake-adapter.exe".into();
        let admission = probe_claude(&evidence);
        confirm_admission(&admission, &exe).expect("digest still matches");
        let request = ClaudeLaunchRequest {
            objective: "summarize local protocol".into(),
            quality: Quality::Standard,
            effort: Effort::Medium,
            session_id: None,
        };
        let planned =
            plan_claude_spawn(&exe, &admission, &request, &serde_json::json!({})).expect("plan");
        assert_eq!(planned.executable, exe);

        let root = tempfile::tempdir().expect("tempdir");
        let writer =
            WriterHandle::start_portable(root.path().to_path_buf(), "install", 1).expect("writer");
        let attempt_id = claim_claude_attempt(&writer, &admission.executable_version);
        let supervisor = ProcessSupervisor::new(writer);
        let outcome = supervisor
            .spawn(
                SpawnRequest {
                    task_id: "task-claude-launch".into(),
                    generation: 0,
                    attempt_id,
                    executable: exe,
                    arguments: vec![
                        OsString::from("--json"),
                        OsString::from(stream_json_script().to_string()),
                    ],
                    env_allowlist: Vec::new(),
                    extra_env: Vec::new(),
                    current_dir: None,
                    data_root: root.path().to_path_buf(),
                    spool_quota_bytes: 0,
                    now_us: 20,
                    consumer_id: "c".into(),
                },
                ResumeGate::Resume,
            )
            .expect("spawn");
        let mut live = match outcome {
            SpawnOutcome::Started(live) => live,
            SpawnOutcome::AbortedBeforeResume { .. } => panic!("must resume"),
        };
        wait_for_spool_line(live.stdout_spool_path(), "session-fixture-001");
        let spool = fs::read_to_string(live.stdout_spool_path()).expect("spool");
        let decoded: Vec<_> = spool.lines().flat_map(decode_stream_json_line).collect();
        assert!(
            decoded
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::StateChanged { .. }))
        );
        assert!(
            decoded
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Terminal { state } if state == TaskState::Succeeded))
        );
        let _ = live.wait(Duration::from_secs(2));
    }
}
