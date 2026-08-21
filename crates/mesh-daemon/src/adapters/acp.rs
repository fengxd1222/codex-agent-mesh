//! Shared ACP (Agent Client Protocol) framing for provider adapters.
//!
//! Grok (`grok agent stdio`) and Kimi (`kimi acp`) speak newline-delimited
//! JSON-RPC 2.0 ACP over stdio. This module owns the wire shapes that are
//! identical across providers; per-provider admission, probes, and spawn
//! plans stay in their adapter modules. A provider process itself is
//! launched only through [`crate::supervisor`].

use serde_json::{Map, Value};

use crate::adapters::{
    AdapterError, NormalizedEvent, NormalizedKind, sanitize_raw, sanitize_raw_line,
};
use crate::domain::{InteractionResponseKind, TaskState};
use crate::protocol_strict_json::parse_strict_json;

pub const METHOD_INITIALIZE: &str = "initialize";
pub const METHOD_AUTHENTICATE: &str = "authenticate";
pub const METHOD_SESSION_NEW: &str = "session/new";
pub const METHOD_SESSION_PROMPT: &str = "session/prompt";
pub const METHOD_SESSION_CANCEL: &str = "session/cancel";
pub const METHOD_SESSION_UPDATE: &str = "session/update";
pub const METHOD_SESSION_REQUEST_PERMISSION: &str = "session/request_permission";

/// Server capabilities reported by a negotiated `initialize` result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AcpServerCapabilities {
    pub protocol_version: Option<i64>,
    pub load_session: bool,
    pub has_auth_methods: bool,
}

/// Client-side ACP handshake lines for one launch. The orchestrator writes
/// them to provider stdin only after the supervisor committed the process
/// receipt, waiting for each response first. The `session/prompt` and
/// `session/cancel` lines are built at runtime because they must carry the
/// sessionId returned by `session/new`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcpHandshakeScript {
    pub initialize: Vec<u8>,
    pub session_new: Vec<u8>,
}

/// Encodes the runtime `session/prompt` line for one admitted session.
pub fn encode_session_prompt(
    id: u64,
    session_id: &str,
    objective: &str,
) -> Result<Vec<u8>, AdapterError> {
    if !is_protocol_id(session_id) || objective.trim().is_empty() {
        return Err(AdapterError::InvalidRequest);
    }
    encode_request(
        id,
        METHOD_SESSION_PROMPT,
        &serde_json::json!({
            "sessionId": session_id,
            "prompt": [ { "type": "text", "text": objective } ]
        }),
    )
}

/// A decoded `session/request_permission` server request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcpPermissionRequest {
    pub request_id: String,
    pub option_ids: Vec<String>,
}

/// Encodes one client JSON-RPC request line for provider stdin.
pub fn encode_request(id: u64, method: &str, params: &Value) -> Result<Vec<u8>, AdapterError> {
    validate_method(method)?;
    let value = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    finish_line(&value)
}

/// Encodes a `session/cancel` request line.
pub fn encode_cancel(id: u64, session_id: &str) -> Result<Vec<u8>, AdapterError> {
    if !is_protocol_id(session_id) {
        return Err(AdapterError::InvalidRequest);
    }
    encode_request(
        id,
        METHOD_SESSION_CANCEL,
        &serde_json::json!({ "sessionId": session_id }),
    )
}

/// Encodes the one-shot answer to a `session/request_permission` request.
///
/// ACP answers select one of the offered `optionId` values; the option id
/// comes from the recorded provider request, never invented here.
pub fn encode_permission_response(
    request_id: &str,
    option_id: &str,
    kind: InteractionResponseKind,
) -> Result<Vec<u8>, AdapterError> {
    if !is_protocol_id(request_id) {
        return Err(AdapterError::InvalidRequest);
    }
    let outcome = match kind {
        InteractionResponseKind::Approve | InteractionResponseKind::Deny => {
            if !is_protocol_id(option_id) {
                return Err(AdapterError::InvalidRequest);
            }
            serde_json::json!({ "outcome": "selected", "optionId": option_id })
        }
        InteractionResponseKind::Text => return Err(AdapterError::InvalidRequest),
    };
    let value = serde_json::json!({
        "jsonrpc": "2.0",
        "id": serde_json::Value::from(request_id.parse::<u64>().map_err(|_| {
            // ACP permission ids are numeric JSON-RPC ids in the recorded
            // fixtures; non-numeric ids cannot be answered on this wire.
            AdapterError::InvalidRequest
        })?),
        "result": { "outcome": outcome },
    });
    finish_line(&value)
}

/// Extracts the request id and offered option ids from a decoded
/// `session/request_permission` frame.
pub fn permission_request(value: &Value) -> Option<AcpPermissionRequest> {
    if value.get("method").and_then(Value::as_str) != Some(METHOD_SESSION_REQUEST_PERMISSION) {
        return None;
    }
    let request_id = id_field_as_string(value.get("id"))?;
    let options = value.pointer("/params/options")?.as_array()?;
    let option_ids = options
        .iter()
        .filter_map(|option| option.get("optionId"))
        .filter_map(Value::as_str)
        .filter(|id| is_protocol_id(id))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if option_ids.is_empty() {
        return None;
    }
    Some(AcpPermissionRequest {
        request_id,
        option_ids,
    })
}

/// Parses a negotiated `initialize` result into capability evidence.
///
/// Live captures proved grok 1.0.4 and kimi 0.28.1 report capabilities
/// under `agentCapabilities` with `authMethods` on the result object,
/// while the recorded spec shape uses `serverCapabilities`; both parse.
#[must_use]
pub fn parse_initialize_result(value: &Value) -> Option<AcpServerCapabilities> {
    let result = value.get("result")?;
    let server = result
        .get("serverCapabilities")
        .or_else(|| result.get("agentCapabilities"))?;
    let protocol_version = result.get("protocolVersion").and_then(Value::as_i64);
    let load_session = server
        .get("loadSession")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_auth_methods = [Some(result), Some(server)]
        .into_iter()
        .flatten()
        .any(|scope| {
            scope
                .get("authMethods")
                .and_then(Value::as_array)
                .is_some_and(|methods| !methods.is_empty())
        });
    Some(AcpServerCapabilities {
        protocol_version,
        load_session,
        has_auth_methods,
    })
}

/// How one decoded frame projects onto mesh events.
#[derive(Clone, Debug, Eq, PartialEq)]
enum FrameClassification {
    /// Client-to-server requests in recorded transcripts and known provider
    /// shapes with no mesh projection: nothing to report.
    Skip,
    /// An unknown provider shape that must stay visible as a warning.
    Warning,
    Events(Vec<NormalizedKind>),
}

/// Decodes one ACP stdio line into zero or more normalized events.
///
/// Accepts JSON-RPC framed notifications/requests/responses and the bare
/// `{"sessionId":..,"update":..}` update shape used by headless
/// streaming-json modes that emit "agent native ACP session updates".
#[must_use]
pub fn decode_acp_line(line: &str) -> Vec<NormalizedEvent> {
    let (raw, raw_digest) = sanitize_raw_line(line);
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(parsed) = parse_strict_json(trimmed) else {
        return vec![malformed_event(raw, raw_digest)];
    };
    let Some(object) = parsed.as_object() else {
        return vec![malformed_event(raw, raw_digest)];
    };
    match classify_frame(object) {
        FrameClassification::Skip => Vec::new(),
        FrameClassification::Warning => vec![NormalizedEvent {
            kind: NormalizedKind::Warning {
                warning: "Adapter reported a deterministic warning.".into(),
            },
            raw_digest,
            raw,
        }],
        FrameClassification::Events(kinds) => kinds
            .into_iter()
            .map(|kind| NormalizedEvent {
                kind,
                raw_digest: raw_digest.clone(),
                raw: raw.clone(),
            })
            .collect(),
    }
}

/// Decodes a committed fixture array of ACP frames or raw lines.
pub fn decode_acp_fixture(source: &str) -> Result<Vec<NormalizedEvent>, AdapterError> {
    let value: Value = serde_json::from_str(source).map_err(|_| AdapterError::ProtocolMalformed)?;
    let items = value.as_array().ok_or(AdapterError::ProtocolMalformed)?;
    let mut events = Vec::new();
    for item in items {
        match item {
            Value::String(line) => events.extend(decode_acp_line(line)),
            other => {
                let encoded =
                    serde_json::to_string(other).map_err(|_| AdapterError::ProtocolMalformed)?;
                events.extend(decode_acp_line(&encoded));
            }
        }
    }
    Ok(events)
}

fn classify_frame(object: &Map<String, Value>) -> FrameClassification {
    if let Some(method) = object.get("method").and_then(Value::as_str) {
        return match method {
            METHOD_SESSION_UPDATE => {
                classify_update(object.get("params").and_then(|params| params.get("update")))
            }
            METHOD_SESSION_REQUEST_PERMISSION => classify_permission_request(object)
                .map_or(FrameClassification::Warning, |kinds| {
                    FrameClassification::Events(kinds)
                }),
            // Client-to-server requests appear inside recorded transcripts.
            METHOD_INITIALIZE
            | METHOD_SESSION_NEW
            | METHOD_SESSION_PROMPT
            | METHOD_SESSION_CANCEL => FrameClassification::Skip,
            // Vendor extension notifications (grok emits `_x.ai/...`
            // frames throughout a session). Most are bookkeeping; retry
            // and prompt-complete failures must surface.
            _ if method.starts_with('_') => classify_vendor_frame(method, object),
            _ => FrameClassification::Warning,
        };
    }
    if let Some(result) = object.get("result") {
        return classify_result(result);
    }
    if let Some(error) = object.get("error") {
        return FrameClassification::Events(vec![protocol_error_kind(error)]);
    }
    // Bare headless update frame without the JSON-RPC envelope.
    if let Some(update) = object.get("update") {
        return classify_update(Some(update));
    }
    FrameClassification::Warning
}

fn classify_update(update: Option<&Value>) -> FrameClassification {
    let Some(update) = update else {
        return FrameClassification::Skip;
    };
    match update.get("sessionUpdate").and_then(Value::as_str) {
        Some("agent_message_chunk") => match text_from_content(update.get("content")) {
            Some(text) => FrameClassification::Events(vec![NormalizedKind::TextDelta { text }]),
            None => FrameClassification::Skip,
        },
        Some("tool_call") => tool_proposal(update).map_or(FrameClassification::Skip, |kind| {
            FrameClassification::Events(vec![kind])
        }),
        // Live captures proved providers also emit reasoning echoes
        // (`agent_thought_chunk`), the client prompt echo
        // (`user_message_chunk`), and bookkeeping updates; none of them
        // are agent progress events.
        Some(
            "plan"
            | "available_commands_update"
            | "tool_call_update"
            | "agent_thought_chunk"
            | "user_message_chunk"
            | "session_info_update",
        ) => FrameClassification::Skip,
        _ => FrameClassification::Warning,
    }
}

fn classify_permission_request(object: &Map<String, Value>) -> Option<Vec<NormalizedKind>> {
    let request = permission_request(&Value::Object(object.clone()))?;
    let params = object.get("params");
    let operation = serde_json::json!({
        "method": METHOD_SESSION_REQUEST_PERMISSION,
        "options": params
            .and_then(|params| params.get("options"))
            .cloned()
            .unwrap_or(Value::Null),
        "kind": params
            .and_then(|params| params.get("kind"))
            .cloned()
            .unwrap_or(Value::Null)
    });
    let (_, operation_digest) = sanitize_raw(&operation);
    Some(vec![
        NormalizedKind::ToolProposal {
            operation_digest,
            interaction_id: request.request_id.clone(),
        },
        NormalizedKind::InteractionRequested {
            interaction_id: request.request_id,
        },
    ])
}

fn classify_result(result: &Value) -> FrameClassification {
    if result.get("stopReason").is_some() {
        let state = match result.get("stopReason").and_then(Value::as_str) {
            Some("end_turn") => TaskState::Succeeded,
            Some(reason) if reason.starts_with("cancel") => TaskState::Cancelled,
            _ => TaskState::Failed,
        };
        return FrameClassification::Events(vec![NormalizedKind::Terminal { state }]);
    }
    if result.get("sessionId").is_some() {
        return FrameClassification::Events(vec![NormalizedKind::StateChanged {
            state: TaskState::Running,
        }]);
    }
    if result.get("serverCapabilities").is_some() || result.get("protocolVersion").is_some() {
        return FrameClassification::Events(vec![NormalizedKind::StateChanged {
            state: TaskState::Preparing,
        }]);
    }
    FrameClassification::Skip
}

/// Builds a schema-valid `protocol_error` kind from a JSON-RPC error
/// object. Numeric codes become stable `jsonrpc_<code>` strings (the
/// protocol id pattern rejects a leading minus), and the provider message
/// is sanitized before it can be persisted as event payload.
fn protocol_error_kind(error: &Value) -> NormalizedKind {
    let (sanitized, _) = sanitize_raw(&serde_json::json!({
        "code": error.get("code").cloned().unwrap_or(Value::Null),
        "message": error.get("message").cloned().unwrap_or(Value::Null),
        "data": error.get("data").cloned().unwrap_or(Value::Null),
    }));
    let code = match sanitized.get("code") {
        Some(Value::Number(number)) => format!("jsonrpc_{number}"),
        _ => "jsonrpc_error".into(),
    };
    let message = sanitized
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Adapter reported a protocol error.");
    let data = sanitized.get("data").and_then(Value::as_str).unwrap_or("");
    let message = if data.is_empty() {
        message.to_owned()
    } else {
        format!("{message}: {data}")
    };
    NormalizedKind::ProtocolError { code, message }
}

fn classify_vendor_frame(method: &str, object: &Map<String, Value>) -> FrameClassification {
    let params = object.get("params");
    if method.ends_with("/prompt_complete") {
        let stop = params
            .and_then(|value| value.get("stopReason"))
            .and_then(Value::as_str);
        if matches!(stop, Some("error")) {
            let message = params
                .and_then(|value| value.get("agentResult"))
                .and_then(Value::as_str)
                .unwrap_or("provider prompt failed");
            return FrameClassification::Events(vec![NormalizedKind::ProtocolError {
                code: "provider_http".into(),
                message: message.into(),
            }]);
        }
        return FrameClassification::Skip;
    }
    let update = params.and_then(|value| value.get("update")).or(params);
    match update
        .and_then(|value| value.get("sessionUpdate"))
        .and_then(Value::as_str)
    {
        Some("retry_state") => {
            let kind = update
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str);
            let reason = update
                .and_then(|value| value.get("reason").or_else(|| value.get("message")))
                .and_then(Value::as_str)
                .unwrap_or("provider retry");
            if kind == Some("failed") {
                FrameClassification::Events(vec![NormalizedKind::ProtocolError {
                    code: "provider_http".into(),
                    message: reason.into(),
                }])
            } else {
                FrameClassification::Events(vec![NormalizedKind::Warning {
                    warning: format!("retry: {reason}"),
                }])
            }
        }
        _ => FrameClassification::Skip,
    }
}

fn tool_proposal(update: &Value) -> Option<NormalizedKind> {
    let tool_call_id = update.get("toolCallId").and_then(Value::as_str)?;
    if !is_protocol_id(tool_call_id) {
        return None;
    }
    let operation = serde_json::json!({
        "title": update.get("title").and_then(Value::as_str).unwrap_or(""),
        "kind": update.get("kind").and_then(Value::as_str).unwrap_or("")
    });
    let (_, operation_digest) = sanitize_raw(&operation);
    Some(NormalizedKind::ToolProposal {
        operation_digest,
        interaction_id: tool_call_id.to_owned(),
    })
}

fn text_from_content(content: Option<&Value>) -> Option<String> {
    let text = content?.get("text").and_then(Value::as_str)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn malformed_event(raw: Value, raw_digest: String) -> NormalizedEvent {
    NormalizedEvent {
        kind: NormalizedKind::ProtocolError {
            code: "malformed_frame".into(),
            message: "Adapter emitted a malformed frame.".into(),
        },
        raw_digest,
        raw,
    }
}

fn validate_method(method: &str) -> Result<(), AdapterError> {
    match method {
        METHOD_INITIALIZE
        | METHOD_AUTHENTICATE
        | METHOD_SESSION_NEW
        | METHOD_SESSION_PROMPT
        | METHOD_SESSION_CANCEL => Ok(()),
        _ => Err(AdapterError::InvalidRequest),
    }
}

fn finish_line(value: &Value) -> Result<Vec<u8>, AdapterError> {
    if parse_strict_json(&value.to_string()).is_err() {
        return Err(AdapterError::ProtocolMalformed);
    }
    let mut bytes = serde_json::to_vec(value).map_err(|_| AdapterError::ProtocolMalformed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn id_field_as_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => {
            if is_protocol_id(text) {
                Some(text.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_protocol_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= 128
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::*;
    use crate::adapters::bind_protocol_event;

    #[test]
    fn acp_initialize_round_trip_parses_server_capabilities() {
        let frame = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"serverCapabilities":{"loadSession":true,"promptCapabilities":{}}}}"#;
        let capabilities = parse_initialize_result(&parse_strict_json(frame).expect("strict json"))
            .expect("capabilities");
        assert_eq!(capabilities.protocol_version, Some(1));
        assert!(capabilities.load_session);
        assert!(!capabilities.has_auth_methods);
        let events = decode_acp_line(frame);
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::StateChanged { state } if state == TaskState::Preparing))
        );
    }

    #[test]
    fn acp_initialize_accepts_live_agent_capabilities_shape() {
        // Real grok 1.0.4 / kimi 0.28.1 captures report capabilities under
        // `agentCapabilities` with authMethods on the result object.
        let grok = parse_initialize_result(
            &parse_strict_json(
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true,"sessionCapabilities":{"resume":{}}},"authMethods":[{"id":"cached_token"}]}}"#,
            )
            .expect("strict json"),
        )
        .expect("grok capabilities");
        assert!(grok.load_session);
        assert!(grok.has_auth_methods);
        assert_eq!(grok.protocol_version, Some(1));
        let kimi = parse_initialize_result(&parse_strict_json(
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true},"agentInfo":{"name":"Kimi Code CLI","version":"0.28.1"}}}"#,
        )
        .expect("strict json"))
        .expect("kimi capabilities");
        assert!(kimi.load_session);
        assert!(!kimi.has_auth_methods);
    }

    #[test]
    fn acp_session_new_result_maps_to_running() {
        let events = decode_acp_line(
            r#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"session-fixture-001"}}"#,
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::StateChanged { state } if state == TaskState::Running))
        );
    }

    #[test]
    fn acp_grok_retry_and_prompt_failure_surface() {
        let retrying = decode_acp_line(
            r#"{"jsonrpc":"2.0","method":"_x.ai/session_notification","params":{"sessionId":"s","update":{"sessionUpdate":"retry_state","type":"retrying","attempt":1,"max_retries":15,"reason":"request error: cli-chat-proxy"}}}"#,
        );
        assert!(matches!(
            &retrying[0].kind,
            NormalizedKind::Warning { warning } if warning.contains("cli-chat-proxy")
        ));
        let failed = decode_acp_line(
            r#"{"jsonrpc":"2.0","method":"_x.ai/session_notification","params":{"sessionId":"s","update":{"sessionUpdate":"retry_state","type":"failed","error_type":"http","message":"reqwest error stream"}}}"#,
        );
        assert!(matches!(
            &failed[0].kind,
            NormalizedKind::ProtocolError { code, message }
                if code == "provider_http" && message.contains("reqwest")
        ));
        let complete = decode_acp_line(
            r#"{"jsonrpc":"2.0","method":"_x.ai/session/prompt_complete","params":{"sessionId":"s","promptId":"p","stopReason":"error","agentResult":"reqwest error stream: cli-chat-proxy"}}"#,
        );
        assert!(matches!(
            &complete[0].kind,
            NormalizedKind::ProtocolError { code, message }
                if code == "provider_http" && message.contains("cli-chat-proxy")
        ));
        let rpc = decode_acp_line(
            r#"{"jsonrpc":"2.0","id":4,"error":{"code":-32603,"message":"Internal error","data":"reqwest error stream: cli-chat-proxy"}}"#,
        );
        assert!(matches!(
            &rpc[0].kind,
            NormalizedKind::ProtocolError { code, message }
                if code.contains("32603") && message.contains("cli-chat-proxy")
        ));
    }

    #[test]
    fn acp_agent_message_chunk_maps_to_text_delta() {
        let events = decode_acp_line(
            r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"deterministic output"}}}}"#,
        );
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0].kind, NormalizedKind::TextDelta { text } if text == "deterministic output")
        );
    }

    #[test]
    fn acp_tool_call_maps_to_tool_proposal() {
        let events = decode_acp_line(
            r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"tool_call","toolCallId":"toolu-fixture-001","title":"Read README.md","kind":"read"}}}"#,
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::ToolProposal { interaction_id, .. } if interaction_id == "toolu-fixture-001"))
        );
        assert_eq!(events[0].raw_digest.len(), 64);
    }

    #[test]
    fn acp_prompt_stop_reason_maps_terminal_state() {
        let end_turn =
            decode_acp_line(r#"{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}"#);
        assert!(
            end_turn
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Terminal { state } if state == TaskState::Succeeded))
        );
        let cancelled =
            decode_acp_line(r#"{"jsonrpc":"2.0","id":3,"result":{"stopReason":"cancelled"}}"#);
        assert!(
            cancelled
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Terminal { state } if state == TaskState::Cancelled))
        );
        let maxed =
            decode_acp_line(r#"{"jsonrpc":"2.0","id":3,"result":{"stopReason":"max_tokens"}}"#);
        assert!(
            maxed
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Terminal { state } if state == TaskState::Failed))
        );
    }

    #[test]
    fn acp_error_response_maps_to_protocol_error() {
        let events = decode_acp_line(
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32600,"message":"invalid request"}}"#,
        );
        assert!(
            matches!(&events[0].kind, NormalizedKind::ProtocolError { code, message }
                if code == "jsonrpc_-32600" && message == "invalid request")
        );
        let bound =
            bind_protocol_event(&events[0].kind, "task-001", "event-001", 1, None).expect("bind");
        assert_eq!(bound["event_type"], "protocol_error");
    }

    #[test]
    fn acp_unknown_update_maps_to_warning_not_error() {
        let events = decode_acp_line(
            r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"unknown_shape"}}}"#,
        );
        assert!(matches!(events[0].kind, NormalizedKind::Warning { .. }));
    }

    #[test]
    fn acp_malformed_line_is_sanitized_protocol_error() {
        let events = decode_acp_line("not-json");
        assert!(
            matches!(&events[0].kind, NormalizedKind::ProtocolError { code, .. } if code == "malformed_frame")
        );
        assert_eq!(events[0].raw["kind"], "non_json");
    }

    #[test]
    fn acp_bare_update_frame_decodes_without_envelope() {
        let events = decode_acp_line(
            r#"{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"bare frame"}}}"#,
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::TextDelta { text } if text == "bare frame"))
        );
    }

    #[test]
    fn acp_permission_request_and_response_round_trip() {
        let frame = r#"{"jsonrpc":"2.0","id":10,"method":"session/request_permission","params":{"sessionId":"s","options":[{"optionId":"allow","name":"Allow","kind":"enable_once"},{"optionId":"deny","name":"Deny","kind":"reject_once"}],"kind":"execute_once"}}"#;
        let parsed = parse_strict_json(frame).expect("strict json");
        let request = permission_request(&parsed).expect("request");
        assert_eq!(request.request_id, "10");
        assert_eq!(request.option_ids, vec!["allow", "deny"]);
        let events = decode_acp_line(frame);
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.kind, NormalizedKind::InteractionRequested { interaction_id } if interaction_id == "10"))
        );
        let approve = encode_permission_response("10", "allow", InteractionResponseKind::Approve)
            .expect("approve");
        let deny =
            encode_permission_response("10", "deny", InteractionResponseKind::Deny).expect("deny");
        let approve_value: Value =
            serde_json::from_slice(&approve[..approve.len() - 1]).expect("json");
        let deny_value: Value = serde_json::from_slice(&deny[..deny.len() - 1]).expect("json");
        assert_eq!(
            approve_value["result"]["outcome"]["optionId"],
            Value::from("allow")
        );
        assert_eq!(
            deny_value["result"]["outcome"]["optionId"],
            Value::from("deny")
        );
        assert_eq!(
            encode_permission_response("10", "", InteractionResponseKind::Approve).err(),
            Some(AdapterError::InvalidRequest)
        );
        assert_eq!(
            encode_permission_response("10", "allow", InteractionResponseKind::Text).err(),
            Some(AdapterError::InvalidRequest)
        );
        assert_eq!(
            encode_permission_response("not-an-id!", "allow", InteractionResponseKind::Approve)
                .err(),
            Some(AdapterError::InvalidRequest)
        );
    }

    #[test]
    fn acp_request_encoding_is_strict_newline_json() {
        let bytes = encode_request(
            1,
            METHOD_INITIALIZE,
            &serde_json::json!({"protocolVersion": 1}),
        )
        .expect("encode");
        assert_eq!(*bytes.last().expect("newline"), b'\n');
        let decoded =
            parse_strict_json(std::str::from_utf8(&bytes[..bytes.len() - 1]).expect("utf8"))
                .expect("strict");
        assert_eq!(decoded["jsonrpc"], "2.0");
        assert_eq!(decoded["id"], 1);
        assert_eq!(decoded["method"], "initialize");
        assert_eq!(
            encode_request(1, "session/evil", &serde_json::json!({})).err(),
            Some(AdapterError::InvalidRequest)
        );
        let cancel = encode_cancel(4, "session-fixture-001").expect("cancel");
        let decoded =
            parse_strict_json(std::str::from_utf8(&cancel[..cancel.len() - 1]).expect("utf8"))
                .expect("strict");
        assert_eq!(decoded["method"], "session/cancel");
        assert_eq!(
            decoded["params"]["sessionId"],
            Value::from("session-fixture-001")
        );
        assert_eq!(
            encode_cancel(4, "bad session").err(),
            Some(AdapterError::InvalidRequest)
        );
    }

    #[test]
    fn acp_client_request_frames_are_not_provider_events() {
        // Client-to-server requests (initialize/session/new/session/prompt)
        // appear in recorded fixtures; they must not surface as fake
        // progress events.
        let events = decode_acp_line(
            r#"{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"workspace"}}"#,
        );
        assert!(events.is_empty());
    }
}
