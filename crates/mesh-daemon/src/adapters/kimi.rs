//! Offline Kimi CLI adapter: negotiated `kimi acp` transport with a
//! same-agent streaming-JSON fallback.
//!
//! The fallback is selected only before dispatch. Kimi exposes no quality
//! or effort control on either surface, so both request fields report
//! provider defaults. Approval automation flags (`--yolo`, `--auto`) and
//! model selection (`-m`) are proven to exist in the help fixture and are
//! never passed: permission round trips must stay durable mesh
//! interactions. Session/load is documented and appears in the recorded
//! initialize negotiation, but session resume stays unadmitted until a
//! live contract records the exact round trip.

#![allow(clippy::module_name_repetitions)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::adapters::acp::{
    self, AcpHandshakeScript, AcpServerCapabilities, METHOD_INITIALIZE, METHOD_SESSION_NEW,
};
use crate::adapters::{
    AcpSidecarPolicy, AdapterCapability, AdapterError, AdapterTransport, AdmissionRecord,
    AdmissionStatus, Effort, KIMI_FIXTURE_BUNDLE_ID, MappingSource, PermissionHealth, Quality,
    QualityEffortMapping, confirm_admission, digest_file, reject_model_fields,
    require_capabilities, zero_digest,
};
use crate::scheduler::AdapterInstanceId;
use serde_json::{Map, Value};

const ADAPTER: &str = "kimi";
const PROVEN_VERSION: &str = "0.28.1";
const DEFAULT_DISPLAY_PATH: &str = "kimi.exe";
const DEFAULT_ACCOUNT: &str = "local";
const DEFAULT_PROFILE: &str = "default";

const BUNDLE_JSON: &str = include_str!("../../../../protocol/v1/fixtures/kimi/bundle.json");
const VERSION_FIXTURE: &str =
    include_str!("../../../../protocol/v1/fixtures/kimi/version-0.28.1.txt");
const HELP_FIXTURE: &str = include_str!("../../../../protocol/v1/fixtures/kimi/help-0.28.1.txt");
const ACP_HELP_FIXTURE: &str =
    include_str!("../../../../protocol/v1/fixtures/kimi/acp-help-0.28.1.txt");
const ACP_SUCCESS_JSON: &str =
    include_str!("../../../../protocol/v1/fixtures/kimi/acp-session-success.json");
const PERMISSION_JSON: &str =
    include_str!("../../../../protocol/v1/fixtures/kimi/acp-permission-roundtrip.json");
const MALFORMED_JSON: &str = include_str!("../../../../protocol/v1/fixtures/kimi/malformed.json");

/// Captured probe evidence. Version/help text is supplied by the caller;
/// this module does not spawn `kimi` outside [`crate::supervisor`].
#[derive(Clone, Debug)]
pub struct KimiProbeEvidence {
    pub executable: PathBuf,
    pub display_path: String,
    pub version_stdout: Option<String>,
    pub help_stdout: Option<String>,
    pub acp_help_stdout: Option<String>,
    pub live_contract_passed: bool,
    pub account: String,
    pub profile: String,
}

impl KimiProbeEvidence {
    #[must_use]
    pub fn fixture_aligned(executable: PathBuf) -> Self {
        Self {
            executable,
            display_path: DEFAULT_DISPLAY_PATH.into(),
            version_stdout: Some(VERSION_FIXTURE.to_owned()),
            help_stdout: Some(HELP_FIXTURE.to_owned()),
            acp_help_stdout: Some(ACP_HELP_FIXTURE.to_owned()),
            live_contract_passed: false,
            account: DEFAULT_ACCOUNT.into(),
            profile: DEFAULT_PROFILE.into(),
        }
    }
}

/// Offline probe result: the public admission plus the capabilities parsed
/// from the recorded `initialize` negotiation fixture.
#[derive(Clone, Debug)]
pub struct KimiProbe {
    pub admission: AdmissionRecord,
    pub negotiated: AcpServerCapabilities,
}

/// Which proven transport a launch will use. Chosen only before dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KimiTransportSelection {
    Acp,
    StreamJsonFallback,
}

/// Inputs for one kimi launch. No model-name field exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KimiLaunchRequest {
    pub objective: String,
    pub quality: Quality,
    pub effort: Effort,
    pub workspace: String,
    pub session_id: Option<String>,
}

/// Supervisor-ready argv plus the ordered ACP stdin script, when applicable.
#[derive(Clone, Debug)]
pub struct KimiSpawnPlan {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub transport: KimiTransportSelection,
    pub mapping: QualityEffortMapping,
    pub acp_script: Option<AcpHandshakeScript>,
}

/// Offline probe with negotiated capability discovery. Missing digest,
/// version, or fixture proof is never healthy.
#[must_use]
pub fn probe_kimi(evidence: &KimiProbeEvidence) -> KimiProbe {
    let negotiated = negotiated_capabilities();
    let digest = digest_file(&evidence.executable).unwrap_or_else(|_| zero_digest().to_owned());
    let parsed_version = evidence
        .version_stdout
        .as_deref()
        .and_then(parse_kimi_version);
    let help_has_fallback = evidence
        .help_stdout
        .as_deref()
        .is_some_and(|help| help.contains("stream-json"));
    let acp_proven = evidence
        .acp_help_stdout
        .as_deref()
        .is_some_and(|help| help.contains("Agent Client Protocol"));
    let file_ok = evidence.executable.is_file() && digest != zero_digest();
    let version_aligned = parsed_version.as_deref() == Some(PROVEN_VERSION);
    let version = parsed_version
        .clone()
        .unwrap_or_else(|| "unproven".to_owned());
    let mut record = base_admission(evidence, digest, version);
    if !file_ok || parsed_version.is_none() || !fixture_bundle_is_current() {
        record.status = AdmissionStatus::Unavailable;
        record.degradation_reason = unavailable_reason(file_ok, parsed_version.is_some());
        return KimiProbe {
            admission: record,
            negotiated,
        };
    }
    if acp_proven {
        record.transport = AdapterTransport::Acp;
        assign_acp_capabilities(&mut record, version_aligned);
        assign_probe_status(&mut record, evidence.live_contract_passed, version_aligned);
    } else if help_has_fallback {
        record.transport = AdapterTransport::StreamJson;
        record.capabilities.push(AdapterCapability::Streaming);
        record.status = AdmissionStatus::Degraded;
        record.degradation_reason =
            "acp entry not proven; headless stream-json fallback only".into();
    } else {
        record.status = AdmissionStatus::Unavailable;
        record.degradation_reason = "no proven transport surface".into();
    }
    KimiProbe {
        admission: record,
        negotiated,
    }
}

/// Selects the transport for one launch. Pre-dispatch only.
pub fn select_kimi_transport(
    admission: &AdmissionRecord,
    prefer_fallback: bool,
) -> Result<KimiTransportSelection, AdapterError> {
    if matches!(admission.status, AdmissionStatus::Unavailable) {
        return Err(AdapterError::Unavailable);
    }
    if prefer_fallback {
        if admission.transport == AdapterTransport::StreamJson
            || admission.admits(AdapterCapability::Streaming)
        {
            return Ok(KimiTransportSelection::StreamJsonFallback);
        }
        return Err(AdapterError::CapabilityNotAdmitted);
    }
    if admission.transport == AdapterTransport::Acp
        && admission.admits(AdapterCapability::Streaming)
    {
        return Ok(KimiTransportSelection::Acp);
    }
    Err(AdapterError::CapabilityNotAdmitted)
}

/// Kimi exposes no quality or effort control; every request reports the
/// provider default alongside the requested value.
#[must_use]
pub fn map_kimi_quality_effort(quality: Quality, effort: Effort) -> QualityEffortMapping {
    QualityEffortMapping {
        requested_quality: quality,
        effective_quality: Quality::Standard,
        quality_source: if quality == Quality::Standard {
            MappingSource::Exact
        } else {
            MappingSource::ProviderDefault
        },
        requested_effort: effort,
        effective_effort: Effort::Medium,
        effort_source: if effort == Effort::Medium {
            MappingSource::Exact
        } else {
            MappingSource::ProviderDefault
        },
    }
}

/// Builds the supervisor argv (and ACP stdin script) after re-checking
/// admission. Never emits a model, `--yolo`, or `--auto` flag.
pub fn plan_kimi_spawn(
    executable: &Path,
    admission: &AdmissionRecord,
    request: &KimiLaunchRequest,
    selection: KimiTransportSelection,
    extras: &Value,
) -> Result<KimiSpawnPlan, AdapterError> {
    reject_model_fields(extras)?;
    if request.objective.trim().is_empty() || request.workspace.trim().is_empty() {
        return Err(AdapterError::InvalidRequest);
    }
    if request.session_id.is_some() && !admission.admits(AdapterCapability::SessionResume) {
        return Err(AdapterError::CapabilityNotAdmitted);
    }
    confirm_admission(admission, executable)?;
    require_capabilities(admission, &[AdapterCapability::Streaming])?;
    if select_kimi_transport(
        admission,
        matches!(selection, KimiTransportSelection::StreamJsonFallback),
    )
    .is_err()
    {
        return Err(AdapterError::CapabilityNotAdmitted);
    }
    let mapping = map_kimi_quality_effort(request.quality, request.effort);
    let (arguments, acp_script) = match selection {
        KimiTransportSelection::Acp => (
            vec![OsString::from("acp")],
            Some(build_handshake_script(&request.workspace)?),
        ),
        KimiTransportSelection::StreamJsonFallback => {
            // `--prompt` takes the objective as a flag value; a leading dash
            // would be parsed as an option. Reject instead of forwarding.
            if request.objective.starts_with('-') {
                return Err(AdapterError::InvalidRequest);
            }
            (
                vec![
                    OsString::from("--prompt"),
                    OsString::from(&request.objective),
                    OsString::from("--output-format"),
                    OsString::from("stream-json"),
                ],
                None,
            )
        }
    };
    let forbidden = ["--yolo", "-y", "--auto", "--model", "-m"];
    if arguments.iter().any(|argument| {
        let text = argument.to_string_lossy();
        forbidden.contains(&text.as_ref())
    }) {
        return Err(AdapterError::InvalidRequest);
    }
    Ok(KimiSpawnPlan {
        executable: executable.to_path_buf(),
        arguments,
        transport: selection,
        mapping,
        acp_script,
    })
}

/// Kimi ACP and its stream-json fallback share the session-update decoder.
#[must_use]
pub fn decode_kimi_line(line: &str) -> Vec<crate::adapters::NormalizedEvent> {
    acp::decode_acp_line(line)
}

/// Decodes a committed fixture array of ACP frames or raw lines.
pub fn decode_kimi_fixture(
    source: &str,
) -> Result<Vec<crate::adapters::NormalizedEvent>, AdapterError> {
    acp::decode_acp_fixture(source)
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

#[must_use]
pub fn acp_success_fixture() -> &'static str {
    ACP_SUCCESS_JSON
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
pub fn acp_help_fixture() -> &'static str {
    ACP_HELP_FIXTURE
}

#[must_use]
pub fn kimi_config_digest() -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("kimi:{KIMI_FIXTURE_BUNDLE_ID}:acp").as_bytes())
    )
}

fn negotiated_capabilities() -> AcpServerCapabilities {
    let value: Value = serde_json::from_str(ACP_SUCCESS_JSON).unwrap_or(Value::Null);
    value
        .as_array()
        .and_then(|frames| {
            frames.iter().find(|frame| {
                frame.get("result").is_some_and(|result| {
                    result.get("serverCapabilities").is_some()
                        || result.get("agentCapabilities").is_some()
                })
            })
        })
        .and_then(acp::parse_initialize_result)
        .unwrap_or_default()
}

fn build_handshake_script(workspace: &str) -> Result<AcpHandshakeScript, AdapterError> {
    let initialize_params = serde_json::json!({
        "protocolVersion": 1,
        "clientCapabilities": {
            "fs": { "readTextFile": false, "writeTextFile": false },
            "terminal": false
        }
    });
    let session_new_params = serde_json::json!({
        "cwd": workspace,
        "mcpServers": []
    });
    Ok(AcpHandshakeScript {
        initialize: acp::encode_request(1, METHOD_INITIALIZE, &initialize_params)?,
        session_new: acp::encode_request(2, METHOD_SESSION_NEW, &session_new_params)?,
    })
}

fn fixture_bundle_is_current() -> bool {
    serde_json::from_str::<Value>(BUNDLE_JSON).is_ok_and(|value| {
        value.get("id").and_then(Value::as_str) == Some(KIMI_FIXTURE_BUNDLE_ID)
            && value.get("proven_version").and_then(Value::as_str) == Some(PROVEN_VERSION)
            && value.get("transport").and_then(Value::as_str) == Some("acp")
            && value.get("fallback_transport").and_then(Value::as_str) == Some("stream_json")
    })
}

fn parse_kimi_version(stdout: &str) -> Option<String> {
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

fn base_admission(
    evidence: &KimiProbeEvidence,
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
        transport: AdapterTransport::Acp,
        capabilities: Vec::new(),
        supported_interactions: Vec::new(),
        permission_health: PermissionHealth::Unsupported,
        degradation_reason: String::new(),
        fixture_bundle_id: KIMI_FIXTURE_BUNDLE_ID.into(),
        acp_sidecar: AcpSidecarPolicy::DISABLED,
        live_contract_passed: evidence.live_contract_passed,
    }
}

fn instance_id(evidence: &KimiProbeEvidence) -> String {
    let config_digest = kimi_config_digest();
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

fn assign_acp_capabilities(record: &mut AdmissionRecord, version_aligned: bool) {
    // Cancellation is NOT admitted: the live matrix proved kimi 0.28.1
    // answers session/cancel with "Method not found" even though the
    // documented method list includes it. Only a proven cancel round trip
    // can re-admit this capability.
    if version_aligned {
        record
            .capabilities
            .extend([AdapterCapability::Streaming, AdapterCapability::Approvals]);
        record.supported_interactions.push("approval");
        record.permission_health = PermissionHealth::Supported;
    } else {
        record.capabilities.push(AdapterCapability::Streaming);
    }
}

fn assign_probe_status(
    record: &mut AdmissionRecord,
    live_contract_passed: bool,
    version_aligned: bool,
) {
    if live_contract_passed
        && version_aligned
        && record.permission_health == PermissionHealth::Supported
    {
        record.status = AdmissionStatus::Enabled;
        record.degradation_reason.clear();
        return;
    }
    record.status = AdmissionStatus::Degraded;
    record.degradation_reason = if version_aligned {
        "local live contract not recorded".into()
    } else {
        format!("unproven version; fixture bundle applies to {PROVEN_VERSION}")
    };
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::adapters::NormalizedKind;
    use crate::domain::{InteractionResponseKind, TaskState};
    use serde_json::json;
    use std::fs;

    fn write_exe(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, bytes).expect("write probe file");
        path
    }

    fn launch_request(objective: &str) -> KimiLaunchRequest {
        KimiLaunchRequest {
            objective: objective.into(),
            quality: Quality::Standard,
            effort: Effort::Medium,
            workspace: "workspace".into(),
            session_id: None,
        }
    }

    #[test]
    fn kimi_missing_proof_is_unavailable_not_healthy() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = root.path().join("missing-kimi");
        let probe = probe_kimi(&KimiProbeEvidence {
            executable: missing,
            display_path: DEFAULT_DISPLAY_PATH.into(),
            version_stdout: None,
            help_stdout: None,
            acp_help_stdout: None,
            live_contract_passed: false,
            account: DEFAULT_ACCOUNT.into(),
            profile: DEFAULT_PROFILE.into(),
        });
        assert_eq!(probe.admission.status, AdmissionStatus::Unavailable);
        assert!(probe.admission.capabilities.is_empty());
        assert!(!probe.admission.acp_sidecar.enabled);
    }

    #[test]
    fn kimi_fixture_probe_is_degraded_and_negotiates_capabilities() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "kimi-probe.bin", b"kimi-fixture-binary");
        let probe = probe_kimi(&KimiProbeEvidence::fixture_aligned(exe.clone()));
        let admission = probe.admission;
        assert_eq!(admission.status, AdmissionStatus::Degraded);
        assert_eq!(
            admission.degradation_reason,
            "local live contract not recorded"
        );
        assert_eq!(admission.executable_version, PROVEN_VERSION);
        assert_eq!(admission.transport, AdapterTransport::Acp);
        assert_eq!(admission.permission_health, PermissionHealth::Supported);
        assert!(admission.admits(AdapterCapability::Streaming));
        assert!(admission.admits(AdapterCapability::Approvals));
        assert!(!admission.admits(AdapterCapability::Cancellation));
        // The recorded negotiation reports loadSession, but session resume
        // stays unadmitted until a live contract records the round trip.
        assert!(probe.negotiated.load_session);
        assert!(!admission.admits(AdapterCapability::SessionResume));
        let protocol = admission.to_protocol_value().expect("protocol");
        assert_eq!(protocol["status"], "DEGRADED");
        assert_eq!(protocol["transport"], "acp");
    }

    #[test]
    fn kimi_without_acp_proof_falls_back_degraded() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "kimi-headless.bin", b"headless");
        let mut evidence = KimiProbeEvidence::fixture_aligned(exe);
        evidence.acp_help_stdout = None;
        let probe = probe_kimi(&evidence);
        assert_eq!(probe.admission.transport, AdapterTransport::StreamJson);
        assert_eq!(probe.admission.status, AdmissionStatus::Degraded);
        assert!(probe.admission.admits(AdapterCapability::Streaming));
        assert!(!probe.admission.admits(AdapterCapability::Approvals));
        assert_eq!(
            select_kimi_transport(&probe.admission, false).err(),
            Some(AdapterError::CapabilityNotAdmitted)
        );
        assert!(matches!(
            select_kimi_transport(&probe.admission, true).expect("fallback"),
            KimiTransportSelection::StreamJsonFallback
        ));
    }

    #[test]
    fn kimi_enabled_requires_live_contract_and_full_proof() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "kimi-live.bin", b"live-proof");
        let mut evidence = KimiProbeEvidence::fixture_aligned(exe);
        evidence.live_contract_passed = true;
        let probe = probe_kimi(&evidence);
        assert_eq!(probe.admission.status, AdmissionStatus::Enabled);
        assert!(probe.admission.degradation_reason.is_empty());
    }

    #[test]
    fn kimi_digest_change_invalidates_admission() {
        let root = tempfile::tempdir().expect("tempdir");
        let first = write_exe(&root, "kimi-a.bin", b"first");
        let second = write_exe(&root, "kimi-b.bin", b"second");
        let probe = probe_kimi(&KimiProbeEvidence::fixture_aligned(first));
        assert_eq!(
            plan_kimi_spawn(
                &second,
                &probe.admission,
                &launch_request("review the long context"),
                KimiTransportSelection::Acp,
                &json!({}),
            )
            .err(),
            Some(AdapterError::AdmissionStale)
        );
    }

    #[test]
    fn kimi_quality_effort_reports_provider_defaults() {
        let mapped = map_kimi_quality_effort(Quality::High, Effort::Low);
        assert_eq!(mapped.requested_quality, Quality::High);
        assert_eq!(mapped.effective_quality, Quality::Standard);
        assert_eq!(mapped.quality_source, MappingSource::ProviderDefault);
        assert_eq!(mapped.effective_effort, Effort::Medium);
        assert_eq!(mapped.effort_source, MappingSource::ProviderDefault);
        let aligned = map_kimi_quality_effort(Quality::Standard, Effort::Medium);
        assert_eq!(aligned.quality_source, MappingSource::Exact);
        assert_eq!(aligned.effort_source, MappingSource::Exact);
    }

    #[test]
    fn kimi_acp_spawn_plan_is_acp_entry_with_script() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "kimi-acp.bin", b"acp");
        let probe = probe_kimi(&KimiProbeEvidence::fixture_aligned(exe.clone()));
        let plan = plan_kimi_spawn(
            &exe,
            &probe.admission,
            &launch_request("review the long context"),
            KimiTransportSelection::Acp,
            &json!({}),
        )
        .expect("plan");
        let args: Vec<String> = plan
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, vec!["acp".to_owned()]);
        let script = plan.acp_script.expect("script");
        for line in [&script.initialize, &script.session_new] {
            assert_eq!(*line.last().expect("newline"), b'\n');
        }
        // The prompt line is built at runtime with the negotiated sessionId.
        let prompt =
            acp::encode_session_prompt(3, "session-fixture-001", "review the long context")
                .expect("prompt line");
        assert!(String::from_utf8_lossy(&prompt).contains("review the long context"));
        assert_eq!(
            plan_kimi_spawn(
                &exe,
                &probe.admission,
                &launch_request("objective"),
                KimiTransportSelection::Acp,
                &json!({"model": "kimi-latest"}),
            )
            .err(),
            Some(AdapterError::ModelNameRejected)
        );
        let resume = KimiLaunchRequest {
            session_id: Some("session-fixture-001".into()),
            ..launch_request("objective")
        };
        assert_eq!(
            plan_kimi_spawn(
                &exe,
                &probe.admission,
                &resume,
                KimiTransportSelection::Acp,
                &json!({})
            )
            .err(),
            Some(AdapterError::CapabilityNotAdmitted)
        );
    }

    #[test]
    fn kimi_fallback_spawn_plan_passes_proven_flags_only() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "kimi-fb.bin", b"fb");
        let probe = probe_kimi(&KimiProbeEvidence::fixture_aligned(exe.clone()));
        let plan = plan_kimi_spawn(
            &exe,
            &probe.admission,
            &launch_request("review the long context"),
            KimiTransportSelection::StreamJsonFallback,
            &json!({}),
        )
        .expect("plan");
        let args: Vec<String> = plan
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "--prompt".to_owned(),
                "review the long context".to_owned(),
                "--output-format".to_owned(),
                "stream-json".to_owned(),
            ]
        );
        assert!(plan.acp_script.is_none());
        assert!(!args.iter().any(|argument| argument.contains("yolo")));
        assert!(!args.iter().any(|argument| argument.contains("auto")));
        assert!(!args.iter().any(|argument| argument.contains("model")));
        assert_eq!(
            plan_kimi_spawn(
                &exe,
                &probe.admission,
                &launch_request("--yolo"),
                KimiTransportSelection::StreamJsonFallback,
                &json!({}),
            )
            .err(),
            Some(AdapterError::InvalidRequest)
        );
    }

    #[test]
    fn kimi_normalizes_acp_fixture_and_keeps_sanitized_raw() {
        let events = decode_kimi_fixture(ACP_SUCCESS_JSON).expect("decode");
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::TextDelta { text } if text == "deterministic review output"))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::ToolProposal { interaction_id, .. } if interaction_id == "toolu-fixture-001"))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Terminal { state } if state == TaskState::Succeeded))
        );
        for event in &events {
            assert_eq!(event.raw_digest.len(), 64);
            assert!(reject_model_fields(&event.raw).is_ok());
        }
    }

    #[test]
    fn kimi_malformed_fixture_produces_sanitized_errors_and_warnings() {
        let events = decode_kimi_fixture(MALFORMED_JSON).expect("decode");
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::ProtocolError { code, .. } if code == "jsonrpc_-32700"))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Warning { .. }))
        );
        // The bare headless frame exercises the fallback decoder path.
        // Fixtures themselves must stay free of sensitive strings, so the
        // redaction contract for bare frames is proven by the inline line
        // below; committed fixture text is preserved verbatim in raw.
        let bare = events
            .iter()
            .find(|event| matches!(&event.kind, NormalizedKind::TextDelta { .. }))
            .expect("bare frame text delta");
        assert!(
            matches!(&bare.kind, NormalizedKind::TextDelta { text } if text == "bare frame malformed tail")
        );
        assert_eq!(
            bare.raw["update"]["content"]["text"],
            serde_json::Value::from("bare frame malformed tail")
        );
        let leaked = decode_kimi_line(
            r#"{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"/home/someone/repo leaked"}}}"#,
        );
        assert!(
            matches!(&leaked[0].kind, NormalizedKind::TextDelta { text } if text == "/home/someone/repo leaked")
        );
        assert_eq!(
            leaked[0].raw["update"]["content"]["text"],
            serde_json::Value::from("[redacted]")
        );
    }

    #[test]
    fn kimi_permission_roundtrip_fixture_is_offline() {
        let fixture = decode_permission_fixture().expect("fixture");
        let request = acp::permission_request(&fixture.request).expect("request");
        assert_eq!(request.request_id, "10");
        let events = decode_kimi_line(&serde_json::to_string(&fixture.request).expect("encode"));
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::InteractionRequested { interaction_id } if interaction_id == "10"))
        );
        let approve = acp::encode_permission_response(
            &request.request_id,
            &request.option_ids[0],
            InteractionResponseKind::Approve,
        )
        .expect("approve");
        let deny = acp::encode_permission_response(
            &request.request_id,
            &request.option_ids[1],
            InteractionResponseKind::Deny,
        )
        .expect("deny");
        assert_eq!(
            serde_json::from_slice::<Value>(&approve[..approve.len() - 1]).expect("json"),
            Value::Object(fixture.approve)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&deny[..deny.len() - 1]).expect("json"),
            Value::Object(fixture.deny)
        );
    }

    #[test]
    fn kimi_golden_capabilities_match_offline_degraded_shape() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/golden/adapter-capabilities-kimi-degraded.json"
        ))
        .expect("golden");
        crate::decode_v1(golden.clone()).expect("golden decodes");
        assert_eq!(golden["adapter"], "kimi");
        assert_eq!(golden["status"], "DEGRADED");
        assert_eq!(golden["transport"], "acp");
        let golden: Value = golden;
        assert_eq!(
            golden["capabilities"],
            serde_json::json!(["streaming", "approvals"])
        );
        assert_eq!(
            golden["adapter_instance_id"],
            format!("kimi:local:default:{}", kimi_config_digest())
        );
    }

    #[test]
    fn kimi_instance_id_hashes_invalid_account_instead_of_defaulting() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "kimi-id.bin", b"id");
        let mut evidence = KimiProbeEvidence::fixture_aligned(exe);
        evidence.account = "user@example.com".into();
        let probe = probe_kimi(&evidence);
        assert!(probe.admission.adapter_instance_id.starts_with("kimi:"));
        assert!(
            !probe
                .admission
                .adapter_instance_id
                .starts_with("kimi:local:")
        );
    }
}
