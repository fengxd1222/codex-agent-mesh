//! Versioned, transport-independent protocol contracts for the daemon.

#![forbid(unsafe_code)]

pub mod adapters;
#[cfg(windows)]
pub mod approvals;
pub mod cli;
#[cfg(all(test, windows))]
mod crash_matrix;
pub mod daemon_runtime;
pub mod dashboard;
#[cfg(windows)]
pub mod dispatcher;
pub mod domain;
pub mod follow;
pub mod improvement;
pub mod install_control;
pub mod install_purge;
pub mod install_record;
pub mod install_store;
pub mod process;
pub mod protocol_client;
pub mod protocol_frame;
pub mod protocol_handshake;
pub mod protocol_strict_json;
pub mod reader;
pub mod router;
pub mod scheduler;
pub mod settings;
pub mod storage;
#[cfg(windows)]
pub mod supervisor;
pub mod windows_control;
#[cfg(windows)]
mod windows_filesystem;
#[cfg(windows)]
pub mod windows_install;
pub mod windows_runtime;
pub mod worktree;
pub mod writer;

use std::{collections::BTreeMap, sync::LazyLock};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u64 = 1;

static PROTOCOL_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../protocol/v1/schema.json"))
        .expect("committed protocol schema must be valid JSON")
});

static PROTOCOL_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::draft202012::new(&PROTOCOL_SCHEMA)
        .expect("committed protocol schema must be valid Draft 2020-12")
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    SafePreDispatch,
    SafeProvenNoEffect,
    DeterministicFailure,
    AmbiguousAfterDispatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectClass {
    NoEffect,
    PossibleEffect,
    UnknownEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEvidence {
    BeforeProcessCreation,
    ProcessDeadNoEffectProof,
    AfterProcessCreation,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    VersionUnsupported,
    ValidationFailed,
    IdempotencyConflict,
    AdapterUnavailable,
    ProtocolMalformed,
    OutputLimitExceeded,
    Cancelled,
    ApprovalExpired,
    StorageUnavailable,
    AmbiguousAfterDispatch,
    IpcAuthenticationFailed,
    IpcFrameInvalid,
    IpcFrameTooLarge,
    IpcIoTimeout,
    DaemonStartTimeout,
    SingletonConflict,
    SetupAbsent,
    SetupDisabled,
    SetupRemoving,
    SetupDrifted,
    SetupAccessDenied,
    CursorExpired,
    ResponseUnknown,
}

pub const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode::VersionUnsupported,
    ErrorCode::ValidationFailed,
    ErrorCode::IdempotencyConflict,
    ErrorCode::AdapterUnavailable,
    ErrorCode::ProtocolMalformed,
    ErrorCode::OutputLimitExceeded,
    ErrorCode::Cancelled,
    ErrorCode::ApprovalExpired,
    ErrorCode::StorageUnavailable,
    ErrorCode::AmbiguousAfterDispatch,
    ErrorCode::IpcAuthenticationFailed,
    ErrorCode::IpcFrameInvalid,
    ErrorCode::IpcFrameTooLarge,
    ErrorCode::IpcIoTimeout,
    ErrorCode::DaemonStartTimeout,
    ErrorCode::SingletonConflict,
    ErrorCode::SetupAbsent,
    ErrorCode::SetupDisabled,
    ErrorCode::SetupRemoving,
    ErrorCode::SetupDrifted,
    ErrorCode::SetupAccessDenied,
    ErrorCode::CursorExpired,
    ErrorCode::ResponseUnknown,
];

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VersionUnsupported => "VERSION_UNSUPPORTED",
            Self::ValidationFailed => "VALIDATION_FAILED",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::AdapterUnavailable => "ADAPTER_UNAVAILABLE",
            Self::ProtocolMalformed => "PROTOCOL_MALFORMED",
            Self::OutputLimitExceeded => "OUTPUT_LIMIT_EXCEEDED",
            Self::Cancelled => "CANCELLED",
            Self::ApprovalExpired => "APPROVAL_EXPIRED",
            Self::StorageUnavailable => "STORAGE_UNAVAILABLE",
            Self::AmbiguousAfterDispatch => "AMBIGUOUS_AFTER_DISPATCH",
            Self::IpcAuthenticationFailed => "IPC_AUTHENTICATION_FAILED",
            Self::IpcFrameInvalid => "IPC_FRAME_INVALID",
            Self::IpcFrameTooLarge => "IPC_FRAME_TOO_LARGE",
            Self::IpcIoTimeout => "IPC_IO_TIMEOUT",
            Self::DaemonStartTimeout => "DAEMON_START_TIMEOUT",
            Self::SingletonConflict => "SINGLETON_CONFLICT",
            Self::SetupAbsent => "SETUP_ABSENT",
            Self::SetupDisabled => "SETUP_DISABLED",
            Self::SetupRemoving => "SETUP_REMOVING",
            Self::SetupDrifted => "SETUP_DRIFTED",
            Self::SetupAccessDenied => "SETUP_ACCESS_DENIED",
            Self::CursorExpired => "CURSOR_EXPIRED",
            Self::ResponseUnknown => "RESPONSE_UNKNOWN",
        }
    }

    const fn is_deterministic(self) -> bool {
        matches!(
            self,
            Self::VersionUnsupported
                | Self::ValidationFailed
                | Self::IdempotencyConflict
                | Self::Cancelled
                | Self::ApprovalExpired
                | Self::IpcAuthenticationFailed
                | Self::IpcFrameInvalid
                | Self::IpcFrameTooLarge
                | Self::SingletonConflict
                | Self::SetupAbsent
                | Self::SetupDisabled
                | Self::SetupDrifted
                | Self::SetupAccessDenied
                | Self::CursorExpired
        )
    }
}

/// Retry classification is conservative: an error label alone cannot prove
/// safety after launch, while deterministic inputs never become retryable merely
/// because no provider process was created.
#[must_use]
pub const fn classify_retry(
    code: ErrorCode,
    effect: EffectClass,
    evidence: LifecycleEvidence,
) -> RetryClass {
    if code.is_deterministic() {
        return RetryClass::DeterministicFailure;
    }
    match (effect, evidence) {
        (_, LifecycleEvidence::BeforeProcessCreation) => RetryClass::SafePreDispatch,
        (EffectClass::NoEffect, LifecycleEvidence::ProcessDeadNoEffectProof) => {
            RetryClass::SafeProvenNoEffect
        }
        _ => RetryClass::AmbiguousAfterDispatch,
    }
}

/// Current-directory writes cannot be treated as no-effect after process start.
#[must_use]
pub const fn classify_retry_for_attempt(
    code: ErrorCode,
    effect: EffectClass,
    evidence: LifecycleEvidence,
    effect_profile: crate::domain::EffectProfile,
) -> RetryClass {
    if matches!(
        effect_profile,
        crate::domain::EffectProfile::CurrentDirectory
    ) && !matches!(evidence, LifecycleEvidence::BeforeProcessCreation)
    {
        return RetryClass::AmbiguousAfterDispatch;
    }
    classify_retry(code, effect, evidence)
}

/// Optional safe-settings opt-in. Absent or any value other than `true` is false.
///
/// Accepts a decoded `config` record or the `settings` object itself. A
/// `config` record is consulted only through its `settings` object; a wrapper
/// field is never treated as opt-in.
#[must_use]
pub fn allow_current_directory(value: &serde_json::Value) -> bool {
    let settings = match value {
        serde_json::Value::Object(object)
            if object.get("kind") == Some(&serde_json::Value::from("config")) =>
        {
            match object.get("settings") {
                Some(settings @ serde_json::Value::Object(_)) => settings,
                _ => return false,
            }
        }
        other => other,
    };
    settings.get("allow_current_directory") == Some(&serde_json::Value::Bool(true))
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: &'static str,
}

/// Decodes a complete v1 record with the committed Draft 2020-12 schema.
///
/// # Errors
///
/// Returns a stable validation or version error for incompatible or malformed
/// records. The schema is compiled once and embedded in the daemon binary.
#[allow(clippy::needless_pass_by_value)]
pub fn decode_v1(value: Value) -> Result<Map<String, Value>, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError {
        code: ErrorCode::ValidationFailed,
        message: "protocol record must be an object",
    })?;

    if object
        .get("version")
        .is_some_and(|version| version != &Value::from(PROTOCOL_VERSION))
    {
        return Err(ProtocolError {
            code: ErrorCode::VersionUnsupported,
            message: "protocol version must be exactly 1",
        });
    }
    if !matches!(object.get("kind"), Some(Value::String(kind)) if !kind.is_empty()) {
        return Err(ProtocolError {
            code: ErrorCode::ValidationFailed,
            message: "protocol record kind is required",
        });
    }

    if !PROTOCOL_VALIDATOR.is_valid(&value) {
        return Err(ProtocolError {
            code: ErrorCode::ValidationFailed,
            message: "protocol record does not match schema v1",
        });
    }

    Ok(object.clone())
}

/// Decodes one strict internal JSON-RPC wire message.
///
/// # Errors
///
/// Returns a stable validation error when the message is not an admitted v1
/// handshake, health, tool request, success response, or structured error.
#[allow(clippy::needless_pass_by_value)]
pub fn decode_wire_v1(value: Value) -> Result<Map<String, Value>, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError {
        code: ErrorCode::ValidationFailed,
        message: "wire message must be an object",
    })?;
    if object.get("jsonrpc") != Some(&Value::from("2.0")) || !PROTOCOL_VALIDATOR.is_valid(&value) {
        return Err(ProtocolError {
            code: ErrorCode::ValidationFailed,
            message: "wire message does not match schema v1",
        });
    }
    Ok(object.clone())
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        Value::Object(values) => {
            let ordered: BTreeMap<_, _> = values
                .iter()
                .map(|(key, value)| (key.clone(), canonical_value(value)))
                .collect();
            Value::Object(ordered.into_iter().collect())
        }
        primitive => primitive.clone(),
    }
}

/// Serializes restricted canonical JSON using UTF-8 byte key order.
///
/// This is intentionally not RFC 8785. Rust strings are Unicode scalar values;
/// TypeScript additionally rejects lone UTF-16 surrogates. Both sides accept
/// only non-negative-zero safe integers.
///
/// # Errors
///
/// Returns an error for fractional or unsafe integer values, or JSON encoding
/// failures.
pub fn canonicalize(value: &Value) -> Result<String, serde_json::Error> {
    fn validate_numbers(value: &Value) -> Result<(), serde_json::Error> {
        match value {
            Value::Number(number) => {
                let safe_signed = number.as_i64().is_some_and(|integer| {
                    (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&integer)
                });
                let safe_unsigned = number
                    .as_u64()
                    .is_some_and(|integer| integer <= 9_007_199_254_740_991);
                if !safe_signed && !safe_unsigned {
                    return Err(serde_json::Error::io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "canonical JSON requires safe integers only",
                    )));
                }
            }
            Value::Array(values) => {
                for nested in values {
                    validate_numbers(nested)?;
                }
            }
            Value::Object(values) => {
                for nested in values.values() {
                    validate_numbers(nested)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::String(_) => {}
        }
        Ok(())
    }

    validate_numbers(value)?;
    serde_json::to_string(&canonical_value(value))
}

/// Hashes a canonical protocol value with SHA-256.
///
/// # Errors
///
/// Propagates canonicalization failures.
pub fn digest(value: &Value) -> Result<String, serde_json::Error> {
    let canonical = canonicalize(value)?;
    Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeAdapterEvent {
    Lifecycle {
        state: String,
    },
    Text {
        text: Option<String>,
        bytes: Option<u64>,
    },
    Terminal {
        state: String,
    },
    Approval {
        operation: String,
    },
    Cancelled,
    Delay {
        milliseconds: u64,
    },
    Raw {
        line: String,
    },
    Crash {
        code: i32,
    },
}

/// Runs a deterministic fake-adapter sequence without a provider process.
///
/// # Errors
///
/// Returns the scripted crash code when the sequence reaches a crash event.
pub fn run_fake_sequence(events: &[FakeAdapterEvent]) -> Result<Vec<FakeAdapterEvent>, i32> {
    let mut emitted = Vec::new();
    for event in events {
        match event {
            FakeAdapterEvent::Delay { .. } => {}
            FakeAdapterEvent::Crash { code } => return Err(*code),
            event => emitted.push(event.clone()),
        }
    }
    Ok(emitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        value: Value,
        canonical: String,
        digest: String,
    }

    #[derive(serde::Deserialize)]
    struct FrameVector {
        name: String,
        prefix_hex: Option<String>,
        payload_hex: Option<String>,
        declared_length: Option<u32>,
        valid: bool,
        error: Option<String>,
    }

    fn decode_hex(source: &str) -> Vec<u8> {
        source
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("valid hex")
            })
            .collect()
    }

    #[test]
    fn protocol_schema_is_valid_draft_2020_12() {
        jsonschema::draft202012::meta::validate(&PROTOCOL_SCHEMA)
            .expect("protocol schema must satisfy its meta-schema");
    }

    #[test]
    fn protocol_vectors_match_typescript_contract() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../../protocol/v1/digest-vectors.json"))
                .expect("valid shared vectors");
        for vector in vectors {
            assert_eq!(
                canonicalize(&vector.value).unwrap(),
                vector.canonical,
                "{}",
                vector.name
            );
            assert_eq!(
                digest(&vector.value).unwrap(),
                vector.digest,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn protocol_frame_boundary_consumes_every_shared_vector() {
        let vectors: Vec<FrameVector> =
            serde_json::from_str(include_str!("../../../protocol/v1/frame-vectors.json"))
                .expect("valid shared frame vectors");
        for vector in vectors {
            if let Some(length) = vector.declared_length {
                let result = crate::protocol_frame::validate_frame_length(length, 1_048_576);
                assert_eq!(result.is_ok(), vector.valid, "{}", vector.name);
                if let (Err(error), Some(expected)) = (result, vector.error.as_deref()) {
                    assert_eq!(error.as_str(), expected, "{}", vector.name);
                }
                continue;
            }
            let mut frame = decode_hex(vector.prefix_hex.as_deref().expect("prefix hex"));
            frame.extend(decode_hex(vector.payload_hex.as_deref().unwrap_or("")));
            let error = crate::protocol_frame::decode_wire_frame(&frame, 1_048_576)
                .expect_err("source vector must fail");
            assert_eq!(
                error.code.as_str(),
                vector.error.as_deref().expect("expected error"),
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn protocol_decoder_rejects_unknown_versions() {
        let error = decode_v1(serde_json::json!({"version": 2, "kind": "event"}))
            .expect_err("v2 must not reach v1 consumers");
        assert_eq!(error.code, ErrorCode::VersionUnsupported);
    }

    #[test]
    fn protocol_shared_golden_and_negative_records_match_rust_boundary() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/v1");
        let mut goldens: Vec<_> = std::fs::read_dir(root.join("golden"))
            .expect("golden corpus directory")
            .map(|entry| entry.expect("golden directory entry").path())
            .filter(|path| path.extension().is_some_and(|value| value == "json"))
            .collect();
        goldens.sort();
        let mut observed_event_types = std::collections::BTreeSet::new();
        for path in goldens {
            let source = std::fs::read_to_string(&path).expect("read golden JSON");
            let value: Value = serde_json::from_str(&source).expect("valid golden JSON");
            if value.get("kind") == Some(&Value::from("event")) {
                observed_event_types.insert(
                    value["event_type"]
                        .as_str()
                        .expect("golden event discriminator")
                        .to_owned(),
                );
            }
            let result = if value.get("jsonrpc") == Some(&Value::from("2.0")) {
                decode_wire_v1(value)
            } else {
                decode_v1(value)
            };
            assert!(result.is_ok(), "{}", path.display());
        }
        let expected_event_types: std::collections::BTreeSet<_> =
            PROTOCOL_SCHEMA["$defs"]["eventBase"]["properties"]["event_type"]["enum"]
                .as_array()
                .expect("event discriminator enum")
                .iter()
                .map(|value| value.as_str().expect("event discriminator").to_owned())
                .collect();
        assert_eq!(observed_event_types, expected_event_types);

        let invalid_source = std::fs::read_to_string(root.join("negative/invalid-records.json"))
            .expect("negative corpus");
        let invalid: Vec<Value> =
            serde_json::from_str(&invalid_source).expect("valid negative fixture JSON");
        for record in invalid {
            let name = record
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("negative");
            let value = record["value"].clone();
            let result = if value.get("jsonrpc") == Some(&Value::from("2.0")) {
                decode_wire_v1(value)
            } else {
                decode_v1(value)
            };
            assert!(result.is_err(), "{name}");
        }

        let invalid_wire_source =
            std::fs::read_to_string(root.join("negative/invalid-wire-json.json"))
                .expect("invalid wire source corpus");
        let invalid_wire: Vec<Value> =
            serde_json::from_str(&invalid_wire_source).expect("valid source corpus JSON");
        for record in invalid_wire {
            let source = record["source"].as_str().expect("source string");
            assert!(
                crate::protocol_strict_json::parse_strict_json(source).is_err(),
                "{}",
                record["name"].as_str().unwrap_or("invalid wire source")
            );
        }
    }

    #[test]
    fn protocol_canonicalization_rejects_non_integer_domain() {
        assert!(canonicalize(&serde_json::json!(1.5)).is_err());
        assert!(canonicalize(&serde_json::json!(9_007_199_254_740_992_u64)).is_err());
        assert!(canonicalize(&serde_json::json!(-0.0)).is_err());
        assert!(serde_json::from_str::<Value>(r#""\ud800""#).is_err());
    }

    #[test]
    fn protocol_retry_requires_evidence_not_an_error_label() {
        assert_eq!(
            classify_retry(
                ErrorCode::AdapterUnavailable,
                EffectClass::UnknownEffect,
                LifecycleEvidence::AfterProcessCreation
            ),
            RetryClass::AmbiguousAfterDispatch
        );
        assert_eq!(
            classify_retry(
                ErrorCode::AdapterUnavailable,
                EffectClass::UnknownEffect,
                LifecycleEvidence::BeforeProcessCreation
            ),
            RetryClass::SafePreDispatch
        );
        assert_eq!(
            classify_retry(
                ErrorCode::ValidationFailed,
                EffectClass::NoEffect,
                LifecycleEvidence::BeforeProcessCreation
            ),
            RetryClass::DeterministicFailure
        );
        assert_eq!(
            classify_retry(
                ErrorCode::ResponseUnknown,
                EffectClass::UnknownEffect,
                LifecycleEvidence::AfterProcessCreation
            ),
            RetryClass::AmbiguousAfterDispatch
        );
        assert_eq!(
            classify_retry(
                ErrorCode::SetupRemoving,
                EffectClass::NoEffect,
                LifecycleEvidence::BeforeProcessCreation
            ),
            RetryClass::SafePreDispatch
        );
        assert_eq!(
            classify_retry_for_attempt(
                ErrorCode::AdapterUnavailable,
                EffectClass::NoEffect,
                LifecycleEvidence::ProcessDeadNoEffectProof,
                crate::domain::EffectProfile::CurrentDirectory
            ),
            RetryClass::AmbiguousAfterDispatch
        );
        assert_eq!(
            classify_retry_for_attempt(
                ErrorCode::AdapterUnavailable,
                EffectClass::UnknownEffect,
                LifecycleEvidence::BeforeProcessCreation,
                crate::domain::EffectProfile::CurrentDirectory
            ),
            RetryClass::SafePreDispatch
        );
        assert_eq!(
            classify_retry_for_attempt(
                ErrorCode::AdapterUnavailable,
                EffectClass::NoEffect,
                LifecycleEvidence::ProcessDeadNoEffectProof,
                crate::domain::EffectProfile::IsolatedWorktree
            ),
            RetryClass::SafeProvenNoEffect
        );
    }

    #[test]
    fn protocol_allow_current_directory_is_absent_on_frozen_config() {
        const FROZEN_DIGEST: &str =
            "22a01f7ccf852d7b2032c4c2c0f25df516d9f07e81d0107a3b2036055cfff16b";
        let frozen: Value =
            serde_json::from_str(include_str!("../../../protocol/v1/golden/config.json"))
                .expect("frozen config golden");
        let opted_in: Value = serde_json::from_str(include_str!(
            "../../../protocol/v1/golden/config-allow-current-directory.json"
        ))
        .expect("opt-in config golden");
        assert!(decode_v1(frozen.clone()).is_ok());
        assert!(decode_v1(opted_in.clone()).is_ok());
        assert!(!allow_current_directory(&frozen));
        assert!(!allow_current_directory(&frozen["settings"]));
        assert!(allow_current_directory(&opted_in));
        assert!(allow_current_directory(&opted_in["settings"]));
        assert!(!allow_current_directory(&serde_json::json!({
            "allow_current_directory": false
        })));
        assert!(!allow_current_directory(&serde_json::json!({
            "kind": "config",
            "allow_current_directory": true
        })));
        assert!(!allow_current_directory(&serde_json::json!({
            "allow_current_directory": "yes"
        })));
        assert_eq!(
            digest(&frozen).expect("frozen golden digest"),
            FROZEN_DIGEST
        );
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../../protocol/v1/digest-vectors.json"))
                .expect("valid shared vectors");
        let config_v1 = vectors
            .into_iter()
            .find(|vector| vector.name == "config-v1")
            .expect("config-v1 digest vector");
        assert_eq!(config_v1.digest, FROZEN_DIGEST);
        assert_eq!(
            digest(&config_v1.value).expect("config-v1 vector digest"),
            FROZEN_DIGEST
        );
        assert!(!allow_current_directory(&config_v1.value));
    }

    #[test]
    fn protocol_rust_error_codes_match_shared_taxonomy() {
        let taxonomy: Value =
            serde_json::from_str(include_str!("../../../protocol/v1/error-taxonomy.json"))
                .expect("valid error taxonomy JSON");
        let mut expected: Vec<_> = taxonomy["error_codes"]
            .as_array()
            .expect("taxonomy error_codes array")
            .iter()
            .map(|value| value.as_str().expect("string error code"))
            .collect();
        let mut actual: Vec<_> = ERROR_CODES.iter().map(|code| code.as_str()).collect();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn fake_adapter_handles_terminal_and_crash_sequences() {
        let completed = run_fake_sequence(&[FakeAdapterEvent::Terminal {
            state: "SUCCEEDED".into(),
        }]);
        assert!(completed.is_ok());
        assert_eq!(
            run_fake_sequence(&[FakeAdapterEvent::Crash { code: 137 }]),
            Err(137)
        );
    }

    #[test]
    fn fake_adapter_delay_is_clock_free_and_duplicate_cancel_approval_are_observable() {
        let events = [
            FakeAdapterEvent::Delay { milliseconds: 25 },
            FakeAdapterEvent::Approval {
                operation: "write_file".into(),
            },
            FakeAdapterEvent::Cancelled,
            FakeAdapterEvent::Terminal {
                state: "SUCCEEDED".into(),
            },
            FakeAdapterEvent::Terminal {
                state: "SUCCEEDED".into(),
            },
        ];
        let emitted = run_fake_sequence(&events).expect("no scripted crash");
        assert_eq!(emitted.len(), 4);
        assert!(matches!(emitted[0], FakeAdapterEvent::Approval { .. }));
        assert!(matches!(emitted[1], FakeAdapterEvent::Cancelled));
        assert!(matches!(emitted[2], FakeAdapterEvent::Terminal { .. }));
        assert!(matches!(emitted[3], FakeAdapterEvent::Terminal { .. }));
    }
}
