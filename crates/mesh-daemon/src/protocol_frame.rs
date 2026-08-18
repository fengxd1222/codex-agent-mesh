//! Strict JSON boundaries for native payloads and complete length-prefixed frames.

use serde_json::{Map, Value};

use crate::{ErrorCode, ProtocolError, decode_wire_v1, protocol_strict_json::parse_strict_json};

/// Checks a declared little-endian payload length before any payload allocation.
///
/// # Errors
///
/// Returns the stable framing code for zero or oversized payloads.
pub const fn validate_frame_length(
    length: u32,
    maximum_payload_bytes: u32,
) -> Result<(), ErrorCode> {
    if length == 0 {
        return Err(ErrorCode::IpcFrameInvalid);
    }
    if length > maximum_payload_bytes {
        return Err(ErrorCode::IpcFrameTooLarge);
    }
    Ok(())
}

/// Decodes payload bytes returned by `mesh_win32::SecurePipeConnection::read_frame`.
///
/// The native transport has already consumed and checked the four-byte length
/// prefix. This function therefore never interprets the first four payload bytes
/// as another prefix.
///
/// # Errors
///
/// Returns a stable framing or protocol validation error without partial output.
pub fn decode_wire_payload(
    payload: &[u8],
    maximum_payload_bytes: u32,
) -> Result<Map<String, Value>, ProtocolError> {
    decode_wire_v1(decode_strict_payload(payload, maximum_payload_bytes)?)
}

/// Parses one bounded payload as strict JSON without selecting a wire version.
///
/// This narrow pre-schema boundary exists only so the handshake can recognize a
/// structurally valid hello whose offered protocol versions have no overlap.
/// All admitted messages must still pass [`decode_wire_payload`] afterwards.
pub(crate) fn decode_strict_payload(
    payload: &[u8],
    maximum_payload_bytes: u32,
) -> Result<Value, ProtocolError> {
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError {
        code: ErrorCode::IpcFrameTooLarge,
        message: "payload length overflows",
    })?;
    validate_frame_length(length, maximum_payload_bytes).map_err(|code| ProtocolError {
        code,
        message: "payload length is invalid",
    })?;
    let source = std::str::from_utf8(payload).map_err(|_| ProtocolError {
        code: ErrorCode::IpcFrameInvalid,
        message: "payload is not strict UTF-8",
    })?;
    parse_strict_json(source).map_err(|_| ProtocolError {
        code: ErrorCode::IpcFrameInvalid,
        message: "payload is not strict JSON",
    })
}

/// Decodes one complete frame containing a four-byte little-endian length prefix.
///
/// # Errors
///
/// Returns a stable framing or protocol validation error without partial output.
pub fn decode_complete_wire_frame(
    frame: &[u8],
    maximum_payload_bytes: u32,
) -> Result<Map<String, Value>, ProtocolError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ProtocolError {
            code: ErrorCode::IpcFrameInvalid,
            message: "frame header is truncated",
        })?;
    let length = u32::from_le_bytes(prefix);
    validate_frame_length(length, maximum_payload_bytes).map_err(|code| ProtocolError {
        code,
        message: "frame length is invalid",
    })?;
    let expected = usize::try_from(length)
        .ok()
        .and_then(|value| value.checked_add(4))
        .ok_or(ProtocolError {
            code: ErrorCode::IpcFrameTooLarge,
            message: "frame length overflows",
        })?;
    if frame.len() != expected {
        return Err(ProtocolError {
            code: ErrorCode::IpcFrameInvalid,
            message: "frame length mismatch",
        });
    }
    decode_wire_payload(&frame[4..], maximum_payload_bytes)
}

/// Backward-compatible name for callers that hold a complete prefixed frame.
///
/// # Errors
///
/// Delegates to [`decode_complete_wire_frame`].
pub fn decode_wire_frame(
    frame: &[u8],
    maximum_payload_bytes: u32,
) -> Result<Map<String, Value>, ProtocolError> {
    decode_complete_wire_frame(frame, maximum_payload_bytes)
}

/// Serializes and validates one outgoing wire payload before transport framing.
///
/// # Errors
///
/// Rejects non-schema records and payloads outside the supplied bound.
pub fn encode_wire_payload(
    value: &Value,
    maximum_payload_bytes: u32,
) -> Result<Vec<u8>, ProtocolError> {
    decode_wire_v1(value.clone())?;
    let payload = serde_json::to_vec(value).map_err(|_| ProtocolError {
        code: ErrorCode::IpcFrameInvalid,
        message: "wire response cannot be encoded",
    })?;
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError {
        code: ErrorCode::IpcFrameTooLarge,
        message: "payload length overflows",
    })?;
    validate_frame_length(length, maximum_payload_bytes).map_err(|code| ProtocolError {
        code,
        message: "payload length is invalid",
    })?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn health_request() -> Value {
        json!({"jsonrpc":"2.0","id":3,"method":"mesh.health","params":{}})
    }

    #[test]
    fn payload_and_complete_frame_decoders_are_distinct() {
        let payload = serde_json::to_vec(&health_request()).expect("payload");
        let mut complete = u32::try_from(payload.len())
            .expect("bounded")
            .to_le_bytes()
            .to_vec();
        complete.extend_from_slice(&payload);

        assert!(decode_wire_payload(&payload, 1_048_576).is_ok());
        assert!(decode_complete_wire_frame(&complete, 1_048_576).is_ok());
        assert!(decode_wire_payload(&complete, 1_048_576).is_err());
        assert!(decode_complete_wire_frame(&payload, 1_048_576).is_err());

        let split_at = 7;
        assert!(
            decode_complete_wire_frame(&complete[..split_at], 1_048_576).is_err(),
            "a partial transport read is not a complete frame"
        );
        let mut coalesced = complete.clone();
        coalesced.extend_from_slice(&complete);
        assert!(
            decode_complete_wire_frame(&coalesced, 1_048_576).is_err(),
            "two coalesced frames must be split by the framed transport"
        );
    }

    #[test]
    fn payload_rejects_duplicate_keys_invalid_utf8_and_bounds() {
        let duplicate = br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"mesh.health","params":{}}"#;
        assert_eq!(
            decode_wire_payload(duplicate, 1_048_576)
                .expect_err("duplicate key")
                .code,
            ErrorCode::IpcFrameInvalid
        );
        assert_eq!(
            decode_wire_payload(&[0xff], 1_048_576)
                .expect_err("invalid UTF-8")
                .code,
            ErrorCode::IpcFrameInvalid
        );
        assert_eq!(
            decode_wire_payload(&[], 1_048_576)
                .expect_err("empty payload")
                .code,
            ErrorCode::IpcFrameInvalid
        );
        assert_eq!(
            decode_wire_payload(&vec![b' '; 1_048_577], 1_048_576)
                .expect_err("oversized payload")
                .code,
            ErrorCode::IpcFrameTooLarge
        );
    }

    #[test]
    fn outgoing_payload_honors_one_and_eight_mib_boundaries() {
        let value = health_request();
        assert!(encode_wire_payload(&value, 1_048_576).is_ok());
        assert!(encode_wire_payload(&value, 8_388_608).is_ok());
        assert_eq!(
            encode_wire_payload(&value, 1).expect_err("too small").code,
            ErrorCode::IpcFrameTooLarge
        );
        assert_eq!(validate_frame_length(1_048_576, 1_048_576), Ok(()));
        assert_eq!(
            validate_frame_length(1_048_577, 1_048_576),
            Err(ErrorCode::IpcFrameTooLarge)
        );
        assert_eq!(validate_frame_length(8_388_608, 8_388_608), Ok(()));
        assert_eq!(
            validate_frame_length(8_388_609, 8_388_608),
            Err(ErrorCode::IpcFrameTooLarge)
        );
    }
}
