//! Offline Grok CLI adapter: negotiated `grok agent stdio` ACP transport
//! with a same-agent streaming-JSON fallback.
//!
//! The fallback is selected only before dispatch: both transports are
//! evaluated while planning the spawn, and no API in this module can switch
//! a transport after a process exists. Grok 1.0.4 has no auto-update
//! suppression flag; managed updates are an explicit `grok update` command
//! the mesh never invokes, so no update flag is passed. ACP-side effort
//! flags are accepted silently without validation by 1.0.4 (`grok agent
//! --effort <bogus> stdio` exits 0), so the ACP path reports provider
//! defaults instead of passing an unvalidated value; the headless
//! fallback validates `--reasoning-effort` at parse time
//! (`xhigh|high|medium|low`), which is the only proven effort surface.

#![allow(clippy::module_name_repetitions)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::adapters::acp::{self, AcpHandshakeScript, METHOD_INITIALIZE, METHOD_SESSION_NEW};
use crate::adapters::{
    AcpSidecarPolicy, AdapterCapability, AdapterError, AdapterTransport, AdmissionRecord,
    AdmissionStatus, Effort, GROK_FIXTURE_BUNDLE_ID, MappingSource, PermissionHealth, Quality,
    QualityEffortMapping, confirm_admission, digest_file, reject_model_fields,
    require_capabilities, zero_digest,
};
use crate::scheduler::AdapterInstanceId;
use serde_json::{Map, Value};

const ADAPTER: &str = "grok";
const PROVEN_VERSION: &str = "1.0.4";
const DEFAULT_DISPLAY_PATH: &str = "grok.exe";
const DEFAULT_ACCOUNT: &str = "local";
const DEFAULT_PROFILE: &str = "default";

const BUNDLE_JSON: &str = include_str!("../../../../protocol/v1/fixtures/grok/bundle.json");
const VERSION_FIXTURE: &str =
    include_str!("../../../../protocol/v1/fixtures/grok/version-1.0.4.txt");
const HELP_FIXTURE: &str = include_str!("../../../../protocol/v1/fixtures/grok/help-1.0.4.txt");
const STDIO_HELP_FIXTURE: &str =
    include_str!("../../../../protocol/v1/fixtures/grok/agent-stdio-help-1.0.4.txt");
const ACP_SUCCESS_JSON: &str =
    include_str!("../../../../protocol/v1/fixtures/grok/acp-session-success.json");
const PERMISSION_JSON: &str =
    include_str!("../../../../protocol/v1/fixtures/grok/acp-permission-roundtrip.json");
const MALFORMED_JSON: &str = include_str!("../../../../protocol/v1/fixtures/grok/malformed.json");

/// Captured probe evidence. Version/help text is supplied by the caller;
/// this module does not spawn `grok` outside [`crate::supervisor`].
#[derive(Clone, Debug)]
pub struct GrokProbeEvidence {
    pub executable: PathBuf,
    pub display_path: String,
    pub version_stdout: Option<String>,
    pub help_stdout: Option<String>,
    pub agent_stdio_help_stdout: Option<String>,
    pub live_contract_passed: bool,
    pub account: String,
    pub profile: String,
}

impl GrokProbeEvidence {
    #[must_use]
    pub fn fixture_aligned(executable: PathBuf) -> Self {
        Self {
            executable,
            display_path: DEFAULT_DISPLAY_PATH.into(),
            version_stdout: Some(VERSION_FIXTURE.to_owned()),
            help_stdout: Some(HELP_FIXTURE.to_owned()),
            agent_stdio_help_stdout: Some(STDIO_HELP_FIXTURE.to_owned()),
            live_contract_passed: false,
            account: DEFAULT_ACCOUNT.into(),
            profile: DEFAULT_PROFILE.into(),
        }
    }
}

/// Which proven transport a launch will use. Chosen only before dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrokTransportSelection {
    Acp,
    StreamJsonFallback,
}

/// Inputs for one grok launch. No model-name field exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrokLaunchRequest {
    pub objective: String,
    pub quality: Quality,
    pub effort: Effort,
    pub workspace: String,
    pub session_id: Option<String>,
}

/// Supervisor-ready argv plus the ordered ACP stdin script, when applicable.
#[derive(Clone, Debug)]
pub struct GrokSpawnPlan {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub transport: GrokTransportSelection,
    pub mapping: QualityEffortMapping,
    pub acp_script: Option<AcpHandshakeScript>,
}

/// Runtime probe. ACP stdio is the preferred surface; headless
/// `streaming-json` is admitted only when that entry is missing.
#[must_use]
pub fn probe_grok(evidence: &GrokProbeEvidence) -> AdmissionRecord {
    let digest = digest_file(&evidence.executable).unwrap_or_else(|_| zero_digest().to_owned());
    let parsed_version = evidence
        .version_stdout
        .as_deref()
        .and_then(parse_grok_version);
    let help_has_fallback = evidence
        .help_stdout
        .as_deref()
        .is_some_and(|help| help.contains("streaming-json"));
    let stdio_proven = evidence
        .agent_stdio_help_stdout
        .as_deref()
        .is_some_and(|help| help.contains("grok agent stdio"));
    let file_ok = evidence.executable.is_file() && digest != zero_digest();
    let version = parsed_version
        .clone()
        .unwrap_or_else(|| "unproven".to_owned());
    let mut record = base_admission(evidence, digest, version);
    if !file_ok || parsed_version.is_none() || !fixture_bundle_is_current() {
        record.status = AdmissionStatus::Unavailable;
        record.degradation_reason = unavailable_reason(file_ok, parsed_version.is_some());
        return record;
    }
    if stdio_proven {
        record.transport = AdapterTransport::Acp;
        assign_acp_capabilities(&mut record);
        record.status = AdmissionStatus::Enabled;
        record.degradation_reason.clear();
    } else if help_has_fallback {
        record.transport = AdapterTransport::StreamJson;
        record.capabilities.push(AdapterCapability::Streaming);
        record.status = AdmissionStatus::Enabled;
        record.degradation_reason.clear();
    } else {
        record.status = AdmissionStatus::Unavailable;
        record.degradation_reason = "no proven transport surface".into();
    }
    record
}

/// Selects the transport for one launch. Pre-dispatch only.
pub fn select_grok_transport(
    admission: &AdmissionRecord,
    prefer_fallback: bool,
) -> Result<GrokTransportSelection, AdapterError> {
    if matches!(admission.status, AdmissionStatus::Unavailable) {
        return Err(AdapterError::Unavailable);
    }
    if prefer_fallback {
        if admission.transport == AdapterTransport::StreamJson {
            return Ok(GrokTransportSelection::StreamJsonFallback);
        }
        if admission.admits(AdapterCapability::Streaming) {
            return Ok(GrokTransportSelection::StreamJsonFallback);
        }
        return Err(AdapterError::CapabilityNotAdmitted);
    }
    if admission.transport == AdapterTransport::Acp
        && admission.admits(AdapterCapability::Streaming)
    {
        return Ok(GrokTransportSelection::Acp);
    }
    Err(AdapterError::CapabilityNotAdmitted)
}

/// Grok quality is not controllable. Effort maps exactly on the proven
/// headless fallback surface (`--reasoning-effort` validates
/// low/medium/high) and stays a provider default on ACP, where 1.0.4
/// accepts effort values silently without validating them.
#[must_use]
pub fn map_grok_quality_effort(
    selection: GrokTransportSelection,
    quality: Quality,
    effort: Effort,
) -> QualityEffortMapping {
    let effort_exact = matches!(selection, GrokTransportSelection::StreamJsonFallback);
    QualityEffortMapping {
        requested_quality: quality,
        effective_quality: Quality::Standard,
        quality_source: if quality == Quality::Standard {
            MappingSource::Exact
        } else {
            MappingSource::ProviderDefault
        },
        requested_effort: effort,
        effective_effort: if effort_exact { effort } else { Effort::Medium },
        effort_source: if effort_exact {
            MappingSource::Exact
        } else {
            MappingSource::ProviderDefault
        },
    }
}

/// Builds the supervisor argv (and ACP stdin script) after re-checking
/// admission. Never emits a model, auto-approve, or update flag.
pub fn plan_grok_spawn(
    executable: &Path,
    admission: &AdmissionRecord,
    request: &GrokLaunchRequest,
    selection: GrokTransportSelection,
    extras: &Value,
) -> Result<GrokSpawnPlan, AdapterError> {
    reject_model_fields(extras)?;
    if request.objective.trim().is_empty() || request.workspace.trim().is_empty() {
        return Err(AdapterError::InvalidRequest);
    }
    if request.session_id.is_some() && !admission.admits(AdapterCapability::SessionResume) {
        return Err(AdapterError::CapabilityNotAdmitted);
    }
    confirm_admission(admission, executable)?;
    require_capabilities(admission, &[AdapterCapability::Streaming])?;
    if select_grok_transport(
        admission,
        matches!(selection, GrokTransportSelection::StreamJsonFallback),
    )
    .is_err()
    {
        return Err(AdapterError::CapabilityNotAdmitted);
    }
    let mapping = map_grok_quality_effort(selection, request.quality, request.effort);
    let (arguments, acp_script) = match selection {
        GrokTransportSelection::Acp => (
            vec![OsString::from("agent"), OsString::from("stdio")],
            Some(build_handshake_script(&request.workspace)?),
        ),
        GrokTransportSelection::StreamJsonFallback => {
            // `grok -p` takes the objective as a flag value; grok has no
            // `--` separator for it, so a leading dash would be parsed as
            // a flag. Reject instead of forwarding.
            if request.objective.starts_with('-') {
                return Err(AdapterError::InvalidRequest);
            }
            let mut arguments = vec![
                OsString::from("-p"),
                OsString::from(&request.objective),
                OsString::from("--output-format"),
                OsString::from("streaming-json"),
            ];
            arguments.push(OsString::from("--reasoning-effort"));
            arguments.push(OsString::from(mapping.effective_effort.as_str()));
            (arguments, None)
        }
    };
    let forbidden = ["--always-approve", "--model", "-m", "--effort"];
    if arguments.iter().any(|argument| {
        let text = argument.to_string_lossy();
        forbidden.contains(&text.as_ref())
    }) {
        return Err(AdapterError::InvalidRequest);
    }
    Ok(GrokSpawnPlan {
        executable: executable.to_path_buf(),
        arguments,
        transport: selection,
        mapping,
        acp_script,
    })
}

/// Grok ACP and its streaming fallback emit the same session-update frames;
/// one decoder serves both transports.
#[must_use]
pub fn decode_grok_line(line: &str) -> Vec<crate::adapters::NormalizedEvent> {
    acp::decode_acp_line(line)
}

/// Decodes a committed fixture array of ACP frames or raw lines.
pub fn decode_grok_fixture(
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
pub fn agent_stdio_help_fixture() -> &'static str {
    STDIO_HELP_FIXTURE
}

#[must_use]
pub fn grok_config_digest() -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("grok:{GROK_FIXTURE_BUNDLE_ID}:acp").as_bytes())
    )
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
        value.get("id").and_then(Value::as_str) == Some(GROK_FIXTURE_BUNDLE_ID)
            && value.get("proven_version").and_then(Value::as_str) == Some(PROVEN_VERSION)
            && value.get("transport").and_then(Value::as_str) == Some("acp")
            && value.get("fallback_transport").and_then(Value::as_str) == Some("stream_json")
    })
}

fn parse_grok_version(stdout: &str) -> Option<String> {
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
    evidence: &GrokProbeEvidence,
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
        fixture_bundle_id: GROK_FIXTURE_BUNDLE_ID.into(),
        acp_sidecar: AcpSidecarPolicy::DISABLED,
        live_contract_passed: evidence.live_contract_passed,
    }
}

fn instance_id(evidence: &GrokProbeEvidence) -> String {
    let config_digest = grok_config_digest();
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

fn assign_acp_capabilities(record: &mut AdmissionRecord) {
    // Cancellation is NOT admitted: live captures answered session/cancel
    // with "Method not found". Mesh-level tree termination stays available.
    record
        .capabilities
        .extend([AdapterCapability::Streaming, AdapterCapability::Approvals]);
    record.supported_interactions.push("approval");
    record.permission_health = PermissionHealth::Supported;
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

    fn launch_request(objective: &str) -> GrokLaunchRequest {
        GrokLaunchRequest {
            objective: objective.into(),
            quality: Quality::Standard,
            effort: Effort::Medium,
            workspace: "workspace".into(),
            session_id: None,
        }
    }

    #[test]
    fn grok_missing_proof_is_unavailable_not_healthy() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = root.path().join("missing-grok");
        let admission = probe_grok(&GrokProbeEvidence {
            executable: missing,
            display_path: DEFAULT_DISPLAY_PATH.into(),
            version_stdout: None,
            help_stdout: None,
            agent_stdio_help_stdout: None,
            live_contract_passed: false,
            account: DEFAULT_ACCOUNT.into(),
            profile: DEFAULT_PROFILE.into(),
        });
        assert_eq!(admission.status, AdmissionStatus::Unavailable);
        assert!(admission.capabilities.is_empty());
        assert!(!admission.acp_sidecar.enabled);
    }

    #[test]
    fn grok_fixture_probe_enables_acp_stdio_without_live_contract() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "grok-probe.bin", b"grok-fixture-binary");
        let admission = probe_grok(&GrokProbeEvidence::fixture_aligned(exe.clone()));
        assert_eq!(admission.status, AdmissionStatus::Enabled);
        assert!(!admission.live_contract_passed);
        assert!(admission.degradation_reason.is_empty());
        assert_eq!(admission.executable_version, PROVEN_VERSION);
        assert_eq!(admission.transport, AdapterTransport::Acp);
        assert_eq!(admission.permission_health, PermissionHealth::Supported);
        assert!(admission.admits(AdapterCapability::Streaming));
        assert!(admission.admits(AdapterCapability::Approvals));
        assert!(!admission.admits(AdapterCapability::Cancellation));
        assert!(!admission.admits(AdapterCapability::SessionResume));
        assert_eq!(admission.fixture_bundle_id, GROK_FIXTURE_BUNDLE_ID);
        let protocol = admission.to_protocol_value().expect("protocol");
        assert_eq!(protocol["status"], "ENABLED");
        assert_eq!(protocol["transport"], "acp");
    }

    #[test]
    fn grok_without_stdio_proof_enables_headless_fallback() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "grok-headless.bin", b"headless");
        let mut evidence = GrokProbeEvidence::fixture_aligned(exe);
        evidence.agent_stdio_help_stdout = None;
        let admission = probe_grok(&evidence);
        assert_eq!(admission.transport, AdapterTransport::StreamJson);
        assert_eq!(admission.status, AdmissionStatus::Enabled);
        assert!(admission.admits(AdapterCapability::Streaming));
        assert!(!admission.admits(AdapterCapability::Approvals));
        assert_eq!(admission.permission_health, PermissionHealth::Unsupported);
        assert_eq!(
            select_grok_transport(&admission, false).err(),
            Some(AdapterError::CapabilityNotAdmitted)
        );
        assert!(matches!(
            select_grok_transport(&admission, true).expect("fallback"),
            GrokTransportSelection::StreamJsonFallback
        ));
    }

    #[test]
    fn grok_unproven_version_still_uses_acp_stdio_surface() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "grok-other.bin", b"other");
        let mut evidence = GrokProbeEvidence::fixture_aligned(exe);
        evidence.version_stdout = Some("grok 1.2.0 (abcdef)".into());
        let admission = probe_grok(&evidence);
        assert_eq!(admission.status, AdmissionStatus::Enabled);
        assert_eq!(admission.executable_version, "1.2.0");
        assert_eq!(admission.permission_health, PermissionHealth::Supported);
        assert!(admission.admits(AdapterCapability::Streaming));
        assert!(admission.admits(AdapterCapability::Approvals));
        assert!(!admission.admits(AdapterCapability::Cancellation));
    }

    #[test]
    fn grok_live_contract_flag_is_independent_of_enabled() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "grok-live.bin", b"live-proof");
        let mut evidence = GrokProbeEvidence::fixture_aligned(exe);
        evidence.live_contract_passed = true;
        let admission = probe_grok(&evidence);
        assert_eq!(admission.status, AdmissionStatus::Enabled);
        assert!(admission.live_contract_passed);
        assert!(admission.degradation_reason.is_empty());
    }

    #[test]
    fn grok_digest_change_invalidates_admission() {
        let root = tempfile::tempdir().expect("tempdir");
        let first = write_exe(&root, "grok-a.bin", b"first");
        let second = write_exe(&root, "grok-b.bin", b"second");
        let admission = probe_grok(&GrokProbeEvidence::fixture_aligned(first));
        assert_eq!(
            confirm_admission(&admission, &second),
            Err(AdapterError::AdmissionStale)
        );
        assert_eq!(
            plan_grok_spawn(
                &second,
                &admission,
                &launch_request("research the surface"),
                GrokTransportSelection::Acp,
                &json!({}),
            )
            .err(),
            Some(AdapterError::AdmissionStale)
        );
    }

    #[test]
    fn grok_quality_effort_reports_requested_versus_effective() {
        let acp = map_grok_quality_effort(GrokTransportSelection::Acp, Quality::High, Effort::High);
        assert_eq!(acp.effective_quality, Quality::Standard);
        assert_eq!(acp.quality_source, MappingSource::ProviderDefault);
        assert_eq!(acp.effective_effort, Effort::Medium);
        assert_eq!(acp.effort_source, MappingSource::ProviderDefault);
        let fallback = map_grok_quality_effort(
            GrokTransportSelection::StreamJsonFallback,
            Quality::Standard,
            Effort::High,
        );
        assert_eq!(fallback.quality_source, MappingSource::Exact);
        assert_eq!(fallback.effective_effort, Effort::High);
        assert_eq!(fallback.effort_source, MappingSource::Exact);
    }

    #[test]
    fn grok_acp_spawn_plan_is_stdio_entry_with_script() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "grok-acp.bin", b"acp");
        let admission = probe_grok(&GrokProbeEvidence::fixture_aligned(exe.clone()));
        let plan = plan_grok_spawn(
            &exe,
            &admission,
            &launch_request("research the protocol surface"),
            GrokTransportSelection::Acp,
            &json!({}),
        )
        .expect("plan");
        let args: Vec<String> = plan
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, vec!["agent".to_owned(), "stdio".to_owned()]);
        let script = plan.acp_script.expect("script");
        for line in [&script.initialize, &script.session_new] {
            assert_eq!(*line.last().expect("newline"), b'\n');
        }
        // The prompt line is built at runtime with the negotiated sessionId.
        let prompt =
            acp::encode_session_prompt(3, "session-fixture-001", "research the protocol surface")
                .expect("prompt line");
        assert!(String::from_utf8_lossy(&prompt).contains("research the protocol surface"));
        assert_eq!(plan.mapping.effective_effort, Effort::Medium);
        assert_eq!(
            plan_grok_spawn(
                &exe,
                &admission,
                &launch_request("objective"),
                GrokTransportSelection::Acp,
                &json!({"model": "grok-4"}),
            )
            .err(),
            Some(AdapterError::ModelNameRejected)
        );
        let resume = GrokLaunchRequest {
            session_id: Some("session-fixture-001".into()),
            ..launch_request("objective")
        };
        assert_eq!(
            plan_grok_spawn(
                &exe,
                &admission,
                &resume,
                GrokTransportSelection::Acp,
                &json!({})
            )
            .err(),
            Some(AdapterError::CapabilityNotAdmitted)
        );
    }

    #[test]
    fn grok_fallback_spawn_plan_passes_proven_flags_only() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "grok-fb.bin", b"fb");
        let admission = probe_grok(&GrokProbeEvidence::fixture_aligned(exe.clone()));
        let mut request = launch_request("research the protocol surface");
        request.effort = Effort::High;
        let plan = plan_grok_spawn(
            &exe,
            &admission,
            &request,
            GrokTransportSelection::StreamJsonFallback,
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
                "-p".to_owned(),
                "research the protocol surface".to_owned(),
                "--output-format".to_owned(),
                "streaming-json".to_owned(),
                "--reasoning-effort".to_owned(),
                "high".to_owned(),
            ]
        );
        assert!(plan.acp_script.is_none());
        assert!(!args.iter().any(|argument| argument.contains("model")));
        assert!(
            !args
                .iter()
                .any(|argument| argument.contains("always-approve"))
        );
        assert!(!args.iter().any(|argument| argument.contains("update")));
        // A leading dash would be parsed as a flag by grok's -p value slot.
        assert_eq!(
            plan_grok_spawn(
                &exe,
                &admission,
                &launch_request("--always-approve"),
                GrokTransportSelection::StreamJsonFallback,
                &json!({}),
            )
            .err(),
            Some(AdapterError::InvalidRequest)
        );
    }

    #[test]
    fn grok_normalizes_acp_fixture_and_keeps_sanitized_raw() {
        let events = decode_grok_fixture(ACP_SUCCESS_JSON).expect("decode");
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::StateChanged { state } if state == TaskState::Preparing))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::StateChanged { state } if state == TaskState::Running))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::TextDelta { text } if text == "deterministic output"))
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
    fn grok_malformed_fixture_produces_sanitized_errors_and_warnings() {
        let events = decode_grok_fixture(MALFORMED_JSON).expect("decode");
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::ProtocolError { code, .. } if code == "jsonrpc_-32600"))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::ProtocolError { code, .. } if code == "malformed_frame"))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Warning { .. }))
        );
        // Normalized provider text is preserved; the persisted raw blob is
        // redacted (same contract as the Claude stream-json adapter).
        let leaked = decode_grok_line(
            r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"C:\\Users\\someone\\repo leaked"}}}}"#,
        );
        assert!(
            matches!(&leaked[0].kind, NormalizedKind::TextDelta { text } if text == "C:\\Users\\someone\\repo leaked")
        );
        assert_eq!(
            leaked[0].raw["params"]["update"]["content"]["text"],
            serde_json::Value::from("[redacted]")
        );
    }

    #[test]
    fn grok_permission_roundtrip_fixture_is_offline() {
        let fixture = decode_permission_fixture().expect("fixture");
        let request = acp::permission_request(&fixture.request).expect("request");
        assert_eq!(request.request_id, "10");
        let events = decode_grok_line(&serde_json::to_string(&fixture.request).expect("encode"));
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
    fn grok_golden_capabilities_match_offline_degraded_shape() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/golden/adapter-capabilities-grok-degraded.json"
        ))
        .expect("golden");
        crate::decode_v1(golden.clone()).expect("golden decodes");
        assert_eq!(golden["adapter"], "grok");
        assert_eq!(golden["status"], "DEGRADED");
        assert_eq!(golden["transport"], "acp");
        let golden: Value = golden;
        assert_eq!(
            golden["capabilities"],
            serde_json::json!(["streaming", "approvals"])
        );
        assert_eq!(
            golden["adapter_instance_id"],
            format!("grok:local:default:{}", grok_config_digest())
        );
    }

    #[test]
    fn grok_fixture_bundle_records_auto_update_contract() {
        let bundle: Value = serde_json::from_str(BUNDLE_JSON).expect("bundle");
        assert_eq!(
            bundle["auto_update"],
            "managed_update_is_explicit_command_only_in_1_0_4"
        );
        assert_eq!(
            bundle["fallback_effort_values"],
            json!(["low", "medium", "high"])
        );
        assert_eq!(bundle["acp_sidecar"], "disabled");
    }

    #[test]
    fn grok_instance_id_hashes_invalid_account_instead_of_defaulting() {
        let root = tempfile::tempdir().expect("tempdir");
        let exe = write_exe(&root, "grok-id.bin", b"id");
        let mut evidence = GrokProbeEvidence::fixture_aligned(exe);
        evidence.account = "user@example.com".into();
        let admission = probe_grok(&evidence);
        assert!(admission.adapter_instance_id.starts_with("grok:"));
        assert!(!admission.adapter_instance_id.starts_with("grok:local:"));
    }
}
